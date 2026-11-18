"""RM-183: bounded, submission-bound review history; no document-store I/O.

All entry points run under administration's existing local lock. Assessment receipts repair the
only cross-row writes (submit and return). The adapter verifies every write by readback.
"""
import copy
import json
import re

from . import compliance as c
from .ports import TenantStoreError
from .policy import TenantPolicyContext, authorize_tenant_operation

KIND = "framework_assessment_review"
REVIEW = "compliance_assessments:review"
COMMENT_MAX = 2000
EVENT_MAX = 500
ROW_BYTES_MAX = 512 * 1024  # one cap, transport-safe; a write keeps a 1 KiB mutation reserve
CONTEXT_BYTES_MAX = 1024 * 1024
_REVISION = re.compile(r"[1-9][0-9]*\Z")
_ACTIONS = {"submit", "comment", "approve", "return"}


def valid_ids(ids):
  return (len(ids) == 4 and all(isinstance(i, str) and i.strip() for i in ids)
          and (ids[2] == c.DEFAULT_ID or c.ASSESSMENT_ID.fullmatch(ids[2]))
          and bool(_REVISION.fullmatch(ids[3])) and len(ids[3]) <= 6)


def _size(value):
  return len(json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8"))


def _event_valid(event, revision):
  if (not isinstance(event, dict)
      or set(event) != {"actor", "action", "time", "revision", "request_id", "control_id", "comment", "self_approved"}
      or event.get("action") not in _ACTIONS or event.get("revision") != revision
      or type(event.get("revision")) is not int
      or not all(isinstance(event.get(k), str) and 0 < len(event[k]) <= 200 for k in ("actor", "time", "request_id"))
      or type(event.get("self_approved")) is not bool):
    return False
  if event["action"] == "comment":
    return (isinstance(event["control_id"], str) and 0 < len(event["control_id"]) <= 200
            and isinstance(event["comment"], str) and 0 < len(event["comment"]) <= COMMENT_MAX
            and not event["self_approved"])
  return event["control_id"] is None and event["comment"] is None and (event["action"] == "approve" or not event["self_approved"])


def validate_review(row, ids):
  history = row.get("history")
  if (not valid_ids(ids) or row.get("tenant_id") != ids[0] or row.get("pack_id") != ids[1]
      or row.get("assessment_id") != ids[2] or row.get("submitted_revision") != int(ids[3])
      or type(row.get("submitted_revision")) is not int
      or not isinstance(row.get("fingerprint"), str) or not c._SHA256_HEX.fullmatch(row["fingerprint"])
      or not isinstance(history, list) or not 1 <= len(history) <= EVENT_MAX
      or type(row.get("review_revision")) is not int or row["review_revision"] != len(history)
      or not all(_event_valid(e, int(ids[3])) for e in history)
      or any(e["self_approved"] != (e["action"] == "approve" and e["actor"] == history[0]["actor"]) for e in history)
      or any(e["action"] == "return" for e in history[:-1])
      or history[0]["action"] != "submit" or any(e["action"] == "submit" for e in history[1:])
      or len({e["request_id"] for e in history}) != len(history)
      or _size(row) > ROW_BYTES_MAX):
    raise ValueError("Invalid framework review record")
  return row


def _ids(row, sub):
  return (row["tenant_id"], row["pack_id"], row.get("assessment_id") or c.DEFAULT_ID, str(sub["revision"]))


def event(sub, action, actor, request_id, *, control_id=None, comment=None, time=None):
  return {"action": action, "actor": actor, "time": time or c._now_iso(), "revision": sub["revision"],
          "request_id": request_id, "control_id": control_id, "comment": comment,
          "self_approved": action == "approve" and actor == sub["actor"]}


def _append(review, entry):
  updated = {**review, "history": [*review["history"], entry], "review_revision": review["review_revision"] + 1}
  if len(updated["history"]) > EVENT_MAX or _size(updated) > ROW_BYTES_MAX - 1024:
    raise c._denied(409, "review_capacity")
  return updated


def reconcile(service, row, sub, repaired=None):
  """Submission itself is the durable receipt; return receipt lives inside that same submission.

  Never infer actor/time from the retry. Persisted events are compared in full, not merely by id.
  A return receipt appended here is added to `repaired` (when given), so the caller can audit it.
  """
  store, ids = c._store(service), _ids(row, sub)
  current = store.get(KIND, *ids)
  submitted = event(sub, "submit", sub["actor"], sub["request_id"], time=sub["submitted_at"])
  if current is None:
    current = store.put(KIND, *ids, record={"tenant_id": ids[0], "pack_id": ids[1], "assessment_id": ids[2],
      "submitted_revision": sub["revision"], "fingerprint": sub["fingerprint"],
      "review_revision": 1, "history": [submitted]})
  if current["fingerprint"] != sub["fingerprint"] or current["history"][0] != submitted:
    raise TenantStoreError("Review submission binding mismatch")
  receipt = sub.get("review_return")
  if receipt is not None:
    if not _event_valid(receipt, sub["revision"]) or receipt["action"] != "return":
      raise TenantStoreError("Invalid review return receipt")
    prior = next((e for e in current["history"] if e["request_id"] == receipt["request_id"]), None)
    if prior is not None and prior != receipt:
      raise TenantStoreError("Review return receipt mismatch")
    if prior is None:
      current = store.put(KIND, *ids, record=_append(current, receipt))
      if repaired is not None:
        repaired.append(copy.deepcopy(receipt))
  return current


def _bound(service, actor, tenant_id, pack_id, revision, snapshot, assessment_id, operation):
  tenant, account = service._authorized_tenant(actor, tenant_id, operation)
  row = c._row(service, tenant_id, pack_id, assessment_id)
  if row is None or type(revision) is not int:
    raise c._denied(404, "assessment_not_found")
  sub = next((s for s in row["submissions"] if s["revision"] == revision), None)
  if sub is None:
    raise c._denied(404, "assessment_not_found")
  if (not isinstance(snapshot, dict) or snapshot.get("tenant_id") != tenant_id
      or snapshot.get("pack_id") != pack_id or (snapshot.get("assessment_id") or c.DEFAULT_ID) != assessment_id
      or not isinstance(snapshot.get("submission"), dict)
      or snapshot["submission"].get("revision") != revision
      or snapshot["submission"].get("fingerprint") != sub["fingerprint"]):
    raise c._denied(409, "document_integrity")
  context = snapshot.get("historical_context")  # the row keeps its digest; the snapshot document keeps the context
  if (c.context_digest(context) if context is not None else None) != sub.get("context_sha256"):
    raise c._denied(409, "document_integrity")
  repaired = []
  return tenant, account, row, sub, reconcile(service, row, sub, repaired), repaired


def _view(service, tenant, account, row, review, snapshot, replayed=False, repaired=()):
  names = c.name_resolver(service)
  decisions = [e for e in review["history"] if e["action"] in ("approve", "return")]
  decision = decisions[-1] if decisions else None
  active = (not row.get("archived") and row["state"] == "submitted"
            and c.latest_revision(row) == review["submitted_revision"])
  return {k: copy.deepcopy(review[k]) for k in ("tenant_id", "pack_id", "assessment_id", "submitted_revision",
      "fingerprint", "review_revision", "history")} | {
    "actor_names": {e["actor"]: names(e["actor"]) for e in review["history"] if names(e["actor"])},
    "status": "internally_approved" if decision and decision["action"] == "approve" else
              "returned_for_changes" if decision else "submitted",
    "self_approved": bool(decision and decision["self_approved"]),
    "can_review": active and authorize_tenant_operation(account, REVIEW, TenantPolicyContext(
      tenant["tenant_id"], tenant["active"], tenant["allow_pentester"]),
      compliance_reviewer=service._compliance_reviewer(account)).allowed,
    "historical_context": copy.deepcopy(snapshot.get("historical_context")),
    "missing_historical_provenance": "historical_context" not in snapshot,
    "replayed": replayed,
    # RM-180 merge review: a return whose review event was written late, here, so the plugin audits it once.
    "repaired_return": repaired[0] if repaired else None}


def read(service, actor, tenant_id, pack_id, revision, snapshot, assessment_id=c.DEFAULT_ID):
  tenant, account, row, sub, review, repaired = _bound(service, actor, tenant_id, pack_id, revision, snapshot,
                                                      assessment_id, c.VIEW)
  return _view(service, tenant, account, row, review, snapshot, repaired=repaired)


def mutate(service, actor, tenant_id, pack_id, revision, snapshot, action, expected_review_revision, request_id,
           control_id=None, comment=None, assessment_id=c.DEFAULT_ID):
  from .administration import _request_id
  tenant, account, row, sub, review, repaired = _bound(service, actor, tenant_id, pack_id, revision, snapshot,
                                                      assessment_id, REVIEW)
  request_id = _request_id(request_id)
  if action not in ("comment", "approve", "return"):
    raise c._denied(400, "invalid_request")
  if action == "comment":
    try:
      comment = c._text(comment, COMMENT_MAX, required=True)
      comment.encode("utf-8")
    except (c.AssessmentInvalid, UnicodeEncodeError):
      raise c._denied(400, "invalid_request") from None
    if not isinstance(control_id, str) or control_id not in sub.get("assessable_ids", []):
      raise c._denied(400, "review_control_invalid")
  elif control_id is not None or comment is not None:
    raise c._denied(400, "invalid_request")
  entry = event(sub, action, account.account_id, request_id, control_id=control_id, comment=comment)
  prior = next((e for e in review["history"] if e["request_id"] == request_id), None)
  if prior is not None:
    if {k: v for k, v in prior.items() if k != "time"} != {k: v for k, v in entry.items() if k != "time"}:
      raise c._denied(409, "conflict")
    return _view(service, tenant, account, row, review, snapshot, replayed=True, repaired=repaired)
  c._not_archived(row)
  if row["state"] != "submitted" or c.latest_revision(row) != revision:
    raise c._denied(409, "review_not_current")
  if type(expected_review_revision) is not int or expected_review_revision != review["review_revision"]:
    raise c._denied(409, "review_stale", current_review_revision=review["review_revision"])
  updated = _append(review, entry)  # capacity checked before return can change assessment
  if action == "return":
    submissions = [*row["submissions"][:-1], {**sub, "review_return": entry, "reopen_request_id": request_id}]
    row = c._put(service, c._stamp({**row, "state": "draft", "reopened_from": revision,
      "management_signoff": None, "completion_date": "", "assessment_revision": row["assessment_revision"] + 1,
      "submissions": submissions}, account.account_id))
  stored = c._store(service).put(KIND, *_ids(row, sub), record=updated)
  return _view(service, tenant, account, row, stored, snapshot, repaired=repaired)
