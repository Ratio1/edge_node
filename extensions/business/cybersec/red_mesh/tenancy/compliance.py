"""RM-120: framework maturity self-assessment per tenant, one row per (tenant, pack).

Contract: `project-red-mesh:docs/resources/redmesh/contracts/framework-assessment.md`.

The row lives in its own CStore key space (`adapters/cstore_compliance.py`), never in the tenancy
hkey, so tenant and engagement listings never read it. Revision snapshots are immutable document
envelopes; the row keeps their references, and no read, history entry or export carries a
reference. The operations run on the administration seam: `TenantAdministrationService` wraps the
functions below as `@_endpoint` methods, so every one of them executes under the administration
lock and never touches the document store. The plugin endpoint does the one document put between
`prepare_submit` and `record_submit`.

Scores are entered by people; nothing here derives a score.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

from ..references.framework_packs import (
  FRAMEWORK_LEVELS,
  FrameworkPackError,
  list_framework_pack_ids,
  load_framework_pack,
)
from ..services.framework_scoring import AXES, CAPS, NA, SCORE_VALUES, score, validate_for_submit, validate_scores
from .ports import TenantStoreError

KIND = "framework_assessment"
SNAPSHOT_SCHEMA = "redmesh.framework_assessment.v1"
SNAPSHOT_ENVELOPE_KIND = "redmesh_framework_assessment"
SNAPSHOT_ENVELOPE_VERSION = "1.0"
STATES = ("draft", "submitted")
VIEW = "compliance_assessments:view"
MANAGE = "compliance_assessments:manage"
PENDING_TTL_SECONDS = 15 * 60
LEVEL_PROVENANCE_KINDS = ("risk_score", "declared")
REMEDIATION_ITEM_MAX = 32
TEXT_MAX = 200
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_EVIDENCE_REF = re.compile(
  r"(?:engagement:[A-Za-z0-9_-]{1,80}/document:ed_[0-9]{1,4}|contract"
  r"|nis2:[A-Za-z0-9_-]{1,80}:[0-9]{1,6}|job:[A-Za-z0-9_-]{1,80}:[0-9]{1,6})\Z")
_REVIEW_STATES = ("linked",)


class AssessmentInvalid(ValueError):
  def __init__(self, code, ids=None, **extra):
    super().__init__(code)
    self.code = code
    self.ids = sorted(ids) if ids else None
    self.extra = extra

  def as_error(self):
    out = {"code": self.code}
    if self.ids:
      out["ids"] = self.ids
    out.update(self.extra)
    return out


def _denied(status_code, error, **details):
  # Imported here: administration imports this module, so the module cannot import it at load time.
  from .administration import AdministrationDenied
  return AdministrationDenied(status_code, error, **details)


def _now_iso():
  return datetime.now(timezone.utc).isoformat()


def _epoch():
  return int(datetime.now(timezone.utc).timestamp())


def _text(value, limit, *, required=False):
  if value is None:
    value = ""
  if not isinstance(value, str):
    raise AssessmentInvalid("invalid_request")
  value = value.strip()
  if len(value) > limit or (required and not value):
    raise AssessmentInvalid("invalid_request")
  return value


def _date(value, *, required=False):
  if value is None or value == "":
    if required:
      raise AssessmentInvalid("invalid_request")
    return ""
  if not isinstance(value, str) or not _DATE.match(value):
    raise AssessmentInvalid("invalid_request")
  try:
    datetime.strptime(value, "%Y-%m-%d")
  except ValueError:
    raise AssessmentInvalid("invalid_request") from None
  return value


def valid_pack_id(value):
  return isinstance(value, str) and value in list_framework_pack_ids()


def pack_for(pack_id):
  if not valid_pack_id(pack_id):
    raise _denied(404, "assessment_not_found")
  try:
    return load_framework_pack(pack_id)
  except FrameworkPackError as exc:
    raise TenantStoreError("Framework pack unavailable") from exc


# -- normalisation of caller input --------------------------------------------------------------


def normalize_level(value):
  if value is None:
    return None
  if value not in FRAMEWORK_LEVELS:
    raise AssessmentInvalid("invalid_level")
  return value


def normalize_level_provenance(value):
  if value is None:
    return None
  if not isinstance(value, dict) or value.get("kind") not in LEVEL_PROVENANCE_KINDS:
    raise AssessmentInvalid("invalid_request")
  out = {"kind": value["kind"]}
  score_value = value.get("score")
  if score_value is not None:
    if type(score_value) is not int or not 0 <= score_value <= 100000:
      raise AssessmentInvalid("invalid_request")
    out["score"] = score_value
  out["declared_by"] = _text(value.get("declared_by"), TEXT_MAX)
  return out


def normalize_signoff(value):
  if value is None:
    return None
  if not isinstance(value, dict):
    raise AssessmentInvalid("invalid_request")
  return {"name": _text(value.get("name"), TEXT_MAX, required=True),
          "role": _text(value.get("role"), TEXT_MAX, required=True),
          "date": _date(value.get("date"), required=True)}


def normalize_remediation(value):
  if value is None:
    return []
  if not isinstance(value, list) or len(value) > CAPS["remediation_items"]:
    raise AssessmentInvalid("invalid_request")
  items = []
  for entry in value:
    if not isinstance(entry, dict):
      raise AssessmentInvalid("invalid_request")
    items.append({"item": _text(entry.get("item"), REMEDIATION_ITEM_MAX, required=True),
                  "action": _text(entry.get("action"), CAPS["remediation_action"], required=True),
                  "deadline": _date(entry.get("deadline"), required=True)})
  return items


def normalize_evidence_refs(value):
  if value is None:
    return []
  if not isinstance(value, list) or len(value) > CAPS["evidence_refs"]:
    raise AssessmentInvalid("evidence_ref_invalid")
  refs = []
  seen = set()
  for entry in value:
    ref = entry.get("ref") if isinstance(entry, dict) else entry
    if not isinstance(ref, str) or not _EVIDENCE_REF.match(ref) or ref in seen:
      raise AssessmentInvalid("evidence_ref_invalid")
    state = entry.get("review_state", "linked") if isinstance(entry, dict) else "linked"
    if state not in _REVIEW_STATES:
      raise AssessmentInvalid("evidence_ref_invalid")
    seen.add(ref)
    refs.append({"ref": ref, "review_state": state})
  return refs


def _axis(value):
  if value is None or value == NA:
    return value
  if type(value) is int and value in SCORE_VALUES:
    return value
  raise AssessmentInvalid("invalid_score_value")


def normalize_score_entry(entry, *, actor, now):
  """One control's entry as the caller sends it, with its justifications and references."""
  if not isinstance(entry, dict):
    raise AssessmentInvalid("invalid_score_value")
  excluded = entry.get("excluded", False)
  if type(excluded) is not bool:
    raise AssessmentInvalid("invalid_score_value")
  justification = entry.get("justification") or {}
  if not isinstance(justification, dict):
    raise AssessmentInvalid("invalid_request")
  return {
    "documentation": _axis(entry.get("documentation")),
    "implementation": _axis(entry.get("implementation")),
    "excluded": excluded,
    "justification": {axis: _text(justification.get(axis), CAPS["justification"]) for axis in AXES},
    "exclusion_justification": (_text(entry.get("exclusion_justification"), CAPS["exclusion_justification"])
                                or None),
    "evidence_refs": normalize_evidence_refs(entry.get("evidence_refs")),
    "updated_by": actor,
    "updated_at": now,
  }


_SHAPE_ERRORS = frozenset({"unknown_level", "unknown_control", "control_not_in_level", "invalid_score_value",
                           "na_without_exclusion", "excluded_not_na"})


def apply_patch(row, patch, pack, *, actor, now):
  """The row after `patch`; raises AssessmentInvalid. `scores` merges per control, `null` removes."""
  if not isinstance(patch, dict):
    raise AssessmentInvalid("invalid_request")
  allowed = {"assurance_level", "level_provenance", "sectoral_requirements", "completion_date",
             "management_signoff", "remediation", "scores"}
  unknown = set(patch) - allowed
  if unknown:
    raise AssessmentInvalid("invalid_request", unknown_fields=sorted(unknown))
  out = dict(row)
  if "assurance_level" in patch:
    out["assurance_level"] = normalize_level(patch["assurance_level"])
  if "level_provenance" in patch:
    out["level_provenance"] = normalize_level_provenance(patch["level_provenance"])
  if "sectoral_requirements" in patch:
    out["sectoral_requirements"] = _text(patch["sectoral_requirements"], CAPS["sectoral_requirements"])
  if "completion_date" in patch:
    out["completion_date"] = _date(patch["completion_date"])
  if "management_signoff" in patch:
    out["management_signoff"] = normalize_signoff(patch["management_signoff"])
  if "remediation" in patch:
    out["remediation"] = normalize_remediation(patch["remediation"])
  if "scores" in patch:
    incoming = patch["scores"]
    if not isinstance(incoming, dict):
      raise AssessmentInvalid("invalid_request")
    scores = dict(row.get("scores") or {})
    known = {c["ref_id"] for c in pack["controls"]}
    unknown_controls = [k for k in incoming if k not in known]
    if unknown_controls:
      raise AssessmentInvalid("unknown_control", unknown_controls)
    for ref_id, entry in incoming.items():
      if entry is None:
        scores.pop(ref_id, None)
        continue
      try:
        scores[ref_id] = normalize_score_entry(entry, actor=actor, now=now)
      except AssessmentInvalid as exc:
        if exc.ids is None:
          raise AssessmentInvalid(exc.code, [ref_id], **exc.extra) from None
        raise
    out["scores"] = scores
  level = out.get("assurance_level")
  if level is not None:
    shape = [e for e in validate_scores(pack, level, out.get("scores") or {}) if e["code"] in _SHAPE_ERRORS]
    if shape:
      first = shape[0]
      raise AssessmentInvalid(first["code"], first.get("ids"))
  return out


# -- the stored row ------------------------------------------------------------------------------


def new_row(tenant_id, pack, *, actor, now):
  return {
    "tenant_id": tenant_id, "pack_id": pack["pack_id"], "pack_acts": list(pack["acts"]),
    "assurance_level": None, "level_provenance": None, "sectoral_requirements": "",
    "completion_date": "", "management_signoff": None, "remediation": [],
    "state": "draft", "assessment_revision": 1, "reopened_from": None, "pending": None,
    "scores": {}, "submissions": [], "created_by": actor, "created_at": now,
    "updated_by": actor, "updated_at": now,
  }


def _valid_ref(value):
  return (isinstance(value, dict) and isinstance(value.get("store"), str) and value["store"]
          and isinstance(value.get("ref"), str) and value["ref"])


def validate_framework_assessment(row, ids):
  """Refuse a stored row the operations could not have written. Unknown fields are kept."""
  if (not isinstance(row, dict) or len(ids) != 2 or row.get("tenant_id") != ids[0]
      or row.get("pack_id") != ids[1] or not valid_pack_id(ids[1])
      or not isinstance(row.get("pack_acts"), list)
      or (row.get("assurance_level") is not None and row["assurance_level"] not in FRAMEWORK_LEVELS)
      or row.get("state") not in STATES
      or type(row.get("assessment_revision")) is not int or row["assessment_revision"] < 1
      or not (row.get("reopened_from") is None or type(row["reopened_from"]) is int)
      or not isinstance(row.get("scores"), dict)
      or not isinstance(row.get("submissions"), list)
      or not isinstance(row.get("remediation"), list)
      or not (row.get("pending") is None or isinstance(row["pending"], dict))
      or not all(isinstance(row.get(key), str) for key in ("created_by", "created_at", "updated_by", "updated_at"))):
    raise ValueError("Invalid framework assessment record")
  for entry in row["scores"].values():
    if not isinstance(entry, dict) or not isinstance(entry.get("justification"), dict):
      raise ValueError("Invalid framework assessment score")
  revisions = []
  for sub in row["submissions"]:
    if (not isinstance(sub, dict) or type(sub.get("revision")) is not int or sub["revision"] < 1
        or not _valid_ref(sub.get("ref")) or not isinstance(sub.get("request_id"), str)
        or not isinstance(sub.get("fingerprint"), str) or not isinstance(sub.get("verdict"), dict)
        or not isinstance(sub.get("actor"), str)):
      raise ValueError("Invalid framework assessment submission")
    revisions.append(sub["revision"])
  if revisions != list(range(1, len(revisions) + 1)):
    raise ValueError("Invalid framework assessment submission order")
  pending = row["pending"]
  if pending is not None and (not isinstance(pending.get("request_id"), str)
                              or not isinstance(pending.get("actor"), str)
                              or not isinstance(pending.get("intent_digest"), str)
                              or type(pending.get("revision")) is not int
                              or type(pending.get("started_at")) is not int):
    raise ValueError("Invalid framework assessment pending marker")
  if row["state"] == "submitted" and pending is not None:
    raise ValueError("Invalid framework assessment state")
  return row


def latest_revision(row):
  return row["submissions"][-1]["revision"] if row["submissions"] else 0


def _draft_fields(row):
  return {key: row.get(key) for key in ("tenant_id", "pack_id", "pack_acts", "assurance_level", "level_provenance",
                                        "sectoral_requirements", "completion_date", "management_signoff",
                                        "remediation", "scores")}


def intent_digest(row):
  """Binds the stored draft, which is frozen while a submit is pending, plus the actor at prepare."""
  blob = json.dumps(_draft_fields(row), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
  return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def claimant_for(tenant):
  legal = tenant.get("legal") if isinstance(tenant, dict) else None
  if not isinstance(legal, dict):
    return None
  return {"legal_name": legal.get("name"), "registration_id": legal.get("registration_id"),
          "signer_name": legal.get("signer_name"), "signer_role": legal.get("signer_role")}


def build_snapshot(row, tenant, computed, pending):
  snapshot = {
    "schema": SNAPSHOT_SCHEMA, "artifact_kind": "self_assessment",
    **_draft_fields(row),
    "claimant": claimant_for(tenant),
    "computed": computed,
    "submission": {"revision": pending["revision"], "submitted_at": pending["submitted_at"],
                   "actor": pending["actor"], "request_id": pending["request_id"],
                   "fingerprint": pending["intent_digest"], "pack_acts": list(row["pack_acts"])},
  }
  return {"kind": SNAPSHOT_ENVELOPE_KIND, "schema_version": SNAPSHOT_ENVELOPE_VERSION,
          "schema": SNAPSHOT_SCHEMA, "tenant_id": row["tenant_id"], "pack_id": row["pack_id"],
          "revision": pending["revision"], "snapshot": snapshot}


def verify_snapshot_envelope(envelope, *, tenant_id, pack_id, revision):
  """The stored snapshot, only while it is the one the row names."""
  if (not isinstance(envelope, dict) or envelope.get("kind") != SNAPSHOT_ENVELOPE_KIND
      or envelope.get("schema") != SNAPSHOT_SCHEMA or envelope.get("tenant_id") != tenant_id
      or envelope.get("pack_id") != pack_id or envelope.get("revision") != revision
      or not isinstance(envelope.get("snapshot"), dict)):
    return None
  return envelope["snapshot"]


def _verdict_summary(computed):
  verdict = computed["verdict"]
  return {"passed": verdict["passed"], "total": verdict["total"],
          "failing_key_measures": list(verdict["failing_key_measures"]),
          "failing_categories": list(verdict["failing_categories"]),
          "total_failed": verdict["total_failed"]}


def _history(row):
  return [{"revision": sub["revision"], "submittedAt": sub["submitted_at"], "actor": sub["actor"],
           "assuranceLevel": sub["assurance_level"], "verdict": sub["verdict"],
           "packActs": sub["pack_acts"]} for sub in reversed(row["submissions"])]


def _pending_view(pending):
  if pending is None:
    return None
  return {"requestId": pending["request_id"], "actor": pending["actor"],
          "ageSeconds": max(0, _epoch() - pending["started_at"]), "revision": pending["revision"]}


def assessment_view(row, pack, *, can_manage):
  """The DTO. Never a document reference."""
  level = row.get("assurance_level")
  computed = score(pack, level, row.get("scores") or {}) if level else None
  submit_errors = validate_for_submit(pack, level, row)[0] if level else [{"code": "level_missing"}]
  return {
    "tenantId": row["tenant_id"], "packId": row["pack_id"], "packActs": list(row["pack_acts"]),
    "currentPackActs": list(pack["acts"]), "stale": {"newerPackActs": list(row["pack_acts"]) != list(pack["acts"])},
    "assuranceLevel": level, "levelProvenance": row.get("level_provenance"),
    "sectoralRequirements": row.get("sectoral_requirements", ""),
    "completionDate": row.get("completion_date", ""), "managementSignoff": row.get("management_signoff"),
    "remediation": list(row.get("remediation") or []),
    "state": row["state"], "assessmentRevision": row["assessment_revision"],
    "reopenedFrom": row.get("reopened_from"), "latestRevision": latest_revision(row),
    "pending": _pending_view(row.get("pending")),
    "scores": row.get("scores") or {},
    "computed": computed, "submitErrors": submit_errors,
    "history": _history(row),
    "canManage": can_manage,
    "updatedBy": row["updated_by"], "updatedAt": row["updated_at"],
  }


# -- operations (wrapped by TenantAdministrationService under its lock) --------------------------


def _store(service):
  store = getattr(service, "compliance", None)
  if store is None:
    raise TenantStoreError("Compliance storage is not configured")
  return store


def _row(service, tenant_id, pack_id):
  return _store(service).get(KIND, tenant_id, pack_id)


def _put(service, row):
  _store(service).put(KIND, row["tenant_id"], row["pack_id"], record=row)
  return _store(service).get(KIND, row["tenant_id"], row["pack_id"])


def _stamp(row, actor):
  return {**row, "updated_by": actor, "updated_at": _now_iso()}


def _expected_revision(row, expected):
  if type(expected) is not int or expected != row["assessment_revision"]:
    raise _denied(409, "assessment_stale", current_assessment_revision=row["assessment_revision"])


def get_assessment(service, actor, tenant_id, pack_id):
  tenant, account = service._authorized_tenant(actor, tenant_id, VIEW)
  pack = pack_for(pack_id)
  row = _row(service, tenant_id, pack_id) or new_row(tenant_id, pack, actor=account.account_id, now=_now_iso())
  return assessment_view(row, pack, can_manage=service._permission(account, tenant, MANAGE))


def save_draft(service, actor, tenant_id, pack_id, patch, expected_assessment_revision):
  tenant, account = service._authorized_tenant(actor, tenant_id, MANAGE)
  pack = pack_for(pack_id)
  now = _now_iso()
  row = _row(service, tenant_id, pack_id)
  if row is None:
    row = new_row(tenant_id, pack, actor=account.account_id, now=now)
  _expected_revision(row, expected_assessment_revision)
  if row["state"] != "draft":
    raise _denied(409, "conflict")
  if row.get("pending") is not None:
    raise _denied(409, "assessment_submit_pending", pending=_pending_view(row["pending"]))
  try:
    updated = apply_patch(row, patch, pack, actor=account.account_id, now=now)
  except AssessmentInvalid as exc:
    raise _denied(400, "assessment_invalid", errors=[exc.as_error()]) from None
  updated = _stamp({**updated, "assessment_revision": row["assessment_revision"] + 1}, account.account_id)
  stored = _put(service, updated)
  return assessment_view(stored, pack, can_manage=True)


def prepare_submit(service, actor, tenant_id, pack_id, expected_assessment_revision, request_id):
  """Step 1 of a submit: replay check first, then compare-and-set, validation and the pending mark.

  Returns `outcome` `replayed` (with the recorded revision), `resume` or `prepared` (both with the
  snapshot envelope the plugin writes outside the lock, and the `assessment_revision` the record
  step compares against).
  """
  from .administration import _request_id
  tenant, account = service._authorized_tenant(actor, tenant_id, MANAGE)
  pack = pack_for(pack_id)
  request_id = _request_id(request_id)
  row = _row(service, tenant_id, pack_id)
  if row is None:
    raise _denied(404, "assessment_not_found")
  digest = intent_digest(row)
  for sub in row["submissions"]:
    if sub["request_id"] == request_id:
      if (sub["revision"] == latest_revision(row) and row["state"] == "submitted"
          and sub["fingerprint"] == digest and sub["actor"] == account.account_id):
        return {"outcome": "replayed", "revision": sub["revision"], "verdict": sub["verdict"]}
      raise _denied(409, "conflict")
  pending = row.get("pending")
  if pending is not None and pending["request_id"] == request_id:
    if pending["actor"] != account.account_id or pending["intent_digest"] != digest:
      raise _denied(409, "conflict")
    level = row["assurance_level"]
    computed = score(pack, level, row["scores"])
    return {"outcome": "resume", "revision": pending["revision"],
            "assessment_revision": row["assessment_revision"],
            "envelope": build_snapshot(row, tenant, computed, pending)}
  if row["state"] != "draft":
    raise _denied(409, "conflict")
  _expected_revision(row, expected_assessment_revision)
  if pending is not None:
    raise _denied(409, "assessment_submit_pending", pending=_pending_view(pending))
  level = row.get("assurance_level")
  if level is None:
    raise _denied(400, "assessment_invalid", errors=[{"code": "level_missing"}])
  errors, computed = validate_for_submit(pack, level, row)
  if errors:
    raise _denied(400, "assessment_invalid", errors=errors)
  if list(row["pack_acts"]) != list(pack["acts"]):
    raise _denied(409, "assessment_pack_stale", current_pack_acts=list(pack["acts"]))
  pending = {"request_id": request_id, "actor": account.account_id, "intent_digest": digest,
             "revision": latest_revision(row) + 1, "submitted_at": _now_iso(), "started_at": _epoch()}
  updated = _stamp({**row, "pending": pending, "assessment_revision": row["assessment_revision"] + 1},
                   account.account_id)
  stored = _put(service, updated)
  return {"outcome": "prepared", "revision": pending["revision"],
          "assessment_revision": stored["assessment_revision"],
          "envelope": build_snapshot(stored, tenant, computed, pending)}


def _tenant_deleting(service, actor, tenant_id):
  """True when the tenant carries the delete marker: `begin_tenant_delete` sets it before the
  documents go and the compliance row is untouched until `finish_tenant_delete`."""
  from .identity import resolve_actor
  from .policy import resolve_tenant_roles
  account, denial = resolve_actor(actor, service.accounts)
  if denial:
    return False
  _, role_denial = resolve_tenant_roles(account, tenant_id)
  if role_denial:
    return False
  tenant = service.store.get("tenant", tenant_id)
  return isinstance(tenant, dict) and isinstance(tenant.get("deleting"), dict)


def record_submit(service, actor, tenant_id, pack_id, request_id, ref, expected_assessment_revision):
  """Step 3 of a submit: bind the written snapshot to revision N, or 409 `assessment_submit_superseded`."""
  from .administration import _request_id
  if _tenant_deleting(service, actor, tenant_id):
    raise _denied(409, "assessment_submit_superseded")
  _, account = service._authorized_tenant(actor, tenant_id, MANAGE)
  pack = pack_for(pack_id)
  request_id = _request_id(request_id)
  if not _valid_ref(ref):
    raise _denied(400, "invalid_request")
  row = _row(service, tenant_id, pack_id)
  if row is None:
    raise _denied(404, "assessment_not_found")
  pending = row.get("pending")
  if (pending is None or pending["request_id"] != request_id or pending["actor"] != account.account_id
      or row["assessment_revision"] != expected_assessment_revision or row["state"] != "draft"):
    raise _denied(409, "assessment_submit_superseded")
  computed = score(pack, row["assurance_level"], row["scores"])
  submission = {
    "revision": pending["revision"], "ref": {"store": ref["store"], "ref": ref["ref"]},
    "submitted_at": pending["submitted_at"], "actor": account.account_id,
    "pack_acts": list(row["pack_acts"]), "assurance_level": row["assurance_level"],
    "fingerprint": pending["intent_digest"], "request_id": request_id, "reopen_request_id": None,
    "verdict": _verdict_summary(computed),
  }
  updated = _stamp({**row, "state": "submitted", "pending": None,
                    "submissions": [*row["submissions"], submission]}, account.account_id)
  stored = _put(service, updated)
  return {"revision": submission["revision"], "verdict": submission["verdict"], "replayed": False,
          "assessmentRevision": stored["assessment_revision"], "actor": account.account_id}


def clear_pending(service, actor, tenant_id, pack_id):
  """Any manager may remove a pending marker older than PENDING_TTL_SECONDS."""
  _, account = service._authorized_tenant(actor, tenant_id, MANAGE)
  pack_for(pack_id)
  row = _row(service, tenant_id, pack_id)
  if row is None:
    raise _denied(404, "assessment_not_found")
  pending = row.get("pending")
  if pending is None:
    return {"cleared": False, "assessmentRevision": row["assessment_revision"]}
  age = _epoch() - pending["started_at"]
  if age < PENDING_TTL_SECONDS:
    raise _denied(409, "assessment_submit_pending", pending=_pending_view(pending))
  stored = _put(service, _stamp({**row, "pending": None}, account.account_id))
  return {"cleared": True, "clearedRequestId": pending["request_id"], "clearedActor": pending["actor"],
          "assessmentRevision": stored["assessment_revision"], "actor": account.account_id}


def reopen(service, actor, tenant_id, pack_id, expected_assessment_revision, request_id):
  """Only the latest submitted revision reopens: a state flip with `reopened_from`, sign-off and
  completion date cleared; `reopen_request_id` on the submission answers a replay."""
  from .administration import _request_id
  tenant, account = service._authorized_tenant(actor, tenant_id, MANAGE)
  pack = pack_for(pack_id)
  request_id = _request_id(request_id)
  row = _row(service, tenant_id, pack_id)
  if row is None or not row["submissions"]:
    raise _denied(404, "assessment_not_found")
  last = row["submissions"][-1]
  if last.get("reopen_request_id") == request_id and row["state"] == "draft" and row["reopened_from"] == last["revision"]:
    return {**assessment_view(row, pack, can_manage=True), "replayed": True}
  if row["state"] != "submitted":
    raise _denied(409, "conflict")
  _expected_revision(row, expected_assessment_revision)
  submissions = [*row["submissions"][:-1], {**last, "reopen_request_id": request_id}]
  updated = _stamp({**row, "state": "draft", "reopened_from": last["revision"],
                    "management_signoff": None, "completion_date": "",
                    "assessment_revision": row["assessment_revision"] + 1, "submissions": submissions},
                   account.account_id)
  stored = _put(service, updated)
  return {**assessment_view(stored, pack, can_manage=True), "replayed": False}


def artifact_ref(service, actor, tenant_id, pack_id, revision):
  """The stored reference of revision N, resolved under the lock after the policy check, for the
  plugin to read outside it. Never returned to a caller."""
  service._authorized_tenant(actor, tenant_id, VIEW)
  pack_for(pack_id)
  row = _row(service, tenant_id, pack_id)
  if row is None or type(revision) is not int:
    raise _denied(404, "assessment_not_found")
  for sub in row["submissions"]:
    if sub["revision"] == revision:
      return {"ref": dict(sub["ref"]), "revision": revision}
  raise _denied(404, "assessment_not_found")


# -- purge hooks ---------------------------------------------------------------------------------


def document_refs(service, tenant_id):
  """Every snapshot reference the tenant's assessment rows name, read raw (a delete must clear rows
  the current validator refuses). Orphans from a crashed submit are not here: they are unlinked."""
  store = getattr(service, "compliance", None)
  if store is None:
    return []
  refs = []
  for ids in store.tenant_record_ids(KIND, tenant_id):
    row = store.raw_record(KIND, *ids) or {}
    for sub in row.get("submissions") if isinstance(row.get("submissions"), list) else []:
      if isinstance(sub, dict) and isinstance(sub.get("ref"), dict):
        refs.append(sub["ref"])
  return refs


def delete_rows(service, tenant_id):
  store = getattr(service, "compliance", None)
  if store is None:
    return 0
  ids = store.tenant_record_ids(KIND, tenant_id)
  for record_ids in ids:
    store.delete(KIND, *record_ids)
  return len(ids)
