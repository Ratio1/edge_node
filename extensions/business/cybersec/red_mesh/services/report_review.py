"""Report review: a per-pass verdict on a job's report (RM-088, contract 2.0.0).

RM-064 made the PDF's Final label require a reviewer. This is that reviewer: a
named account approves or rejects the report for the job's latest scan pass. A
pass without a verdict is `pending`. Approve is gated: where the job has a NIS2
readiness assessment, the NIS2 review for the same pass must be submitted
first, and every reason approve is refused is named (`approve_blocked`).

It mirrors the rulebook review's admission (the endpoints run through
`_read_operation` / `_review_operation`), server-derived actor, revision fence,
lock, audit row and audit event, and deliberately not its submission machinery:
no draft, no R1FS snapshot, no pending registry, no idempotency key. One row per
pass in its own chainstore hash, never on the job record and never in the archive.
Contract: `docs/resources/redmesh/contracts/report-review.md` (project-red-mesh).
"""
from __future__ import annotations

from ..constants import JOB_STATUS_FINALIZED
from ..models.report_review import (
  REPORT_REVIEW_CONTRACT_VERSION,
  ReportReviewAuditEntry,
  ReportReviewState,
)
from ..tenancy.administration import AdministrationDenied
from ..tenancy.effects import EffectState
from ..tenancy.identity import canonical_account_id
from ..tenancy.job_artifacts import checked_job_snapshot, validate_snapshot_mode
from .rulebook_assessment import (
  _job_repo,
  current_rulebook_submission,
  _owner_time,
  _safe_text,
  _submission_lock,
  _utc_timestamp,
)
from .scan_guards import reject_model_test_for_scan_operation


_UNSET = object()
_LOCK_SCOPE = "report_review"

EVENT_APPROVED = "report_review_approved"
EVENT_REJECTED = "report_review_rejected"


def _error(code, job_id, message, *, retryable=False, **extra):
  return {
    "status": "error",
    "error": code,
    "job_id": job_id,
    "review_contract_version": REPORT_REVIEW_CONTRACT_VERSION,
    "message": message,
    "retryable": retryable,
    **extra,
  }


def _latest_pass_nr(job_specs):
  """The newest completed pass on the job record; 1 when nothing says otherwise.

  Read from the record rather than the archive so a read never opens an
  artifact. A finalized record is the pruned `CStoreJobFinalized`, which
  carries `pass_count` and no `pass_reports`; `pass_reports` is read for a
  record that still has them. Today nothing takes a FINALIZED job back to
  RUNNING, so on a real job this value is frozen and a newer pass only appears
  once a re-run path exists (contract §State model).
  """
  numbers = []
  for entry in job_specs.get("pass_reports") or []:
    if isinstance(entry, dict):
      try:
        numbers.append(int(entry.get("pass_nr")))
      except (TypeError, ValueError):
        continue
  if numbers:
    return max(numbers)
  try:
    value = int(job_specs.get("pass_count"))
  except (TypeError, ValueError):
    return 1
  return value if value > 0 else 1


def _validated_expected_revision(value, job_id):
  message = "expected_review_revision must be a non-negative integer."
  if value is None:
    return None, _error("review_revision_conflict", job_id, "expected_review_revision is required.")
  try:
    revision = int(value)
  except (TypeError, ValueError):
    return None, _error("review_revision_conflict", job_id, message)
  if revision < 0:
    return None, _error("review_revision_conflict", job_id, message)
  return revision, None


def approve_blocked_reasons(owner, job_id, job_specs, nis2=_UNSET):
  """Every reason the latest pass cannot be approved; empty means approvable (contract §Approve gate).

  `nis2` is `current_rulebook_submission`'s answer when the caller already has it.
  """
  if job_specs.get("job_status") != JOB_STATUS_FINALIZED:
    return [{"code": "job_not_finalized", "detail": {"job_status": job_specs.get("job_status")}}]
  if nis2 is _UNSET:
    nis2 = current_rulebook_submission(owner, job_id, job_specs)
  if nis2 is None:
    return []
  latest = _latest_pass_nr(job_specs)
  submission = nis2["submission"]
  if submission is None:
    return [{"code": "nis2_review_not_submitted",
             "detail": {"profile_id": nis2["profile_id"], "pass_nr": latest}}]
  if submission["pass_nr"] < latest:
    return [{"code": "nis2_submission_stale",
             "detail": {"profile_id": nis2["profile_id"], "submitted_pass_nr": submission["pass_nr"],
                        "latest_pass_nr": latest}}]
  return []


def _reopened(review, nis2, blocked):
  """Why an approval no longer counts, or None (owner decision, RM-088).

  An approval rests on the NIS2 submission that was current when it was given.
  When NIS2 is in play and the gate now blocks, or the current submission is not
  the one recorded, the approval is reopened: a derived state, never stored.
  Rejections are not NIS2-gated and are never reopened.
  """
  if review is None or review.state != "approved" or nis2 is None:
    return None
  recorded = review.nis2_submission_ref or None
  current = nis2["submission"]
  if (
    not blocked and current and recorded
    and current["revision"] == recorded["revision"] and current["cid"] == recorded["cid"]
  ):
    return None
  return {
    "review": review.to_dict(),
    "code": "nis2_review_changed",
    "detail": {
      "approved_submission_revision": recorded["revision"] if recorded else None,
      "current_submission_revision": current["revision"] if current else None,
    },
  }


def _effective(owner, job_id, job_specs, review):
  """`(review_status, approve_blocked, reopened)` for the latest pass's row."""
  finalized = job_specs.get("job_status") == JOB_STATUS_FINALIZED
  nis2 = current_rulebook_submission(owner, job_id, job_specs) if finalized else None
  blocked = approve_blocked_reasons(owner, job_id, job_specs, nis2)
  reopened = _reopened(review, nis2, blocked)
  if reopened is not None:
    status = "reopened"
  elif review is not None:
    status = review.state
  else:
    status = "pending" if finalized else None
  return status, blocked, reopened


def _view(owner, job_id, job_specs, rows):
  """The one read shape: the latest pass's verdict, the gate, and earlier passes as history."""
  latest_pass_nr = _latest_pass_nr(job_specs)
  review = rows.get(latest_pass_nr)
  review_status, blocked, reopened = _effective(owner, job_id, job_specs, review)
  return {
    "status": "ok",
    "job_id": job_id,
    "review_contract_version": REPORT_REVIEW_CONTRACT_VERSION,
    "review_status": review_status,
    "latest_pass_nr": latest_pass_nr,
    # A reopened approval is shown under `reopened`, not as the verdict; the
    # fence still follows the stored row's revision.
    "review": review.to_dict() if review is not None and reopened is None else None,
    "review_revision": review.review_revision if review is not None else 0,
    "can_approve": not blocked,
    "approve_blocked": blocked,
    "reopened": reopened,
    "history": [rows[nr].to_dict() for nr in sorted(rows, reverse=True) if nr != latest_pass_nr],
  }


def _job_for(owner, job_id, checked_job, snapshot_mode, *, checked_raise):
  """The job record, from the admitted snapshot when the caller was admitted."""
  checked = checked_job is not _UNSET
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked)
  job_specs = (checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
               if checked else owner._get_job_from_cstore(job_id))
  if not isinstance(job_specs, dict):
    return None, _error("job_not_found", job_id, "Job not found.")
  unsupported = reject_model_test_for_scan_operation(job_specs, job_id, _LOCK_SCOPE)
  if unsupported:
    if checked and checked_raise:
      raise AdministrationDenied(400, "unsupported_job_type")
    return None, {**unsupported, "error": "model_test_not_supported"}
  return job_specs, None


def _unsupported(job_id):
  return _error("review_contract_unsupported", job_id,
                "Report review contract version is not supported by this backend.")


def get_report_review(owner, job_id, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  job_specs, err = _job_for(owner, job_id, checked_job, snapshot_mode, checked_raise=True)
  if err:
    return err
  try:
    rows = _job_repo(owner).list_job_report_review_models(job_id, _latest_pass_nr(job_specs))
  except ValueError:
    if checked_job is not _UNSET:
      # `_read_operation` does not project through `_public_review_result`, so
      # a dict with an `error` key would be collapsed by the read guard; the
      # rulebook read raises the same denial here.
      raise AdministrationDenied(503, "review_contract_unsupported")
    return _unsupported(job_id)
  return _view(owner, job_id, job_specs, rows)


def _admit_mutation(owner, job_id, expected_review_revision, actor, checked_job, snapshot_mode):
  expected, err = _validated_expected_revision(expected_review_revision, job_id)
  if err:
    return None, None, None, err
  # The actor is the admitted account id, already canonical; validating it
  # rather than passing it through `_safe_text` keeps an id that happens to
  # look like an IP or a token (`10.0.0.1`, 32 hex chars) from being stored as
  # a pseudonym and printed as such in C.5.
  signer = canonical_account_id(actor)
  if not signer:
    return None, None, None, _error("invalid_review_actor", job_id,
                                    "A server-derived review actor is required.")
  job_specs, err = _job_for(owner, job_id, checked_job, snapshot_mode, checked_raise=False)
  if err:
    return None, None, None, err
  if job_specs.get("job_status") != JOB_STATUS_FINALIZED:
    return None, None, None, _error("job_not_finalized", job_id,
                                    "Only a finalized job's report can be reviewed.",
                                    job_status=job_specs.get("job_status"))
  return expected, signer, job_specs, None


def _write(owner, repo, state, event_type, ledger):
  if ledger is not None:
    # Revalidate right before the write, then record it: the put and the audit
    # append are not atomic, so a failure between them must never read "no trace".
    ledger.checkpoint()
  payload = repo.put_report_review(state)
  if ledger is not None:
    ledger.record(EffectState.PERSISTED)
  repo.append_report_review_audit(ReportReviewAuditEntry(
    job_id=state.job_id,
    event_type=event_type,
    state=state.state,
    reviewer=state.reviewer,
    note=state.note,
    review_revision=state.review_revision,
    pass_nr=state.pass_nr,
    timestamp=_utc_timestamp(_owner_time(owner)),
  ))
  if hasattr(owner, "_log_audit_event"):
    owner._log_audit_event(event_type, {
      "job_id": state.job_id,
      "state": state.state,
      "review_revision": state.review_revision,
      "pass_nr": state.pass_nr,
    })
  return payload


def _decide(owner, job_id, verdict, *, expected_review_revision, note, actor,
            checked_job, snapshot_mode, ledger):
  """Write `verdict` for the latest pass under the fence; shared by approve and reject."""
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-report-review")
  safe_note = _safe_text(note or "", hmac_secret=hmac_secret, max_len=1000).strip()
  if verdict == "rejected" and not safe_note:
    return _error("note_required", job_id, "A rejection needs a note saying why.")
  expected, signer, job_specs, err = _admit_mutation(
    owner, job_id, expected_review_revision, actor, checked_job, snapshot_mode)
  if err:
    return err
  with _submission_lock(owner, job_id, _LOCK_SCOPE):
    repo = _job_repo(owner)
    latest = _latest_pass_nr(job_specs)
    try:
      rows = repo.list_job_report_review_models(job_id, latest)
    except ValueError:
      return _unsupported(job_id)
    review = rows.get(latest)
    current = review.review_revision if review is not None else 0
    if expected != current:
      return _error("review_revision_conflict", job_id,
                    "The report review changed. Reload before deciding.",
                    current_review_revision=current)
    submission_ref = ""
    reopened = None
    if verdict == "approved":
      nis2 = current_rulebook_submission(owner, job_id, job_specs)
      blocked = approve_blocked_reasons(owner, job_id, job_specs, nis2)
      if blocked:
        return _error("approve_blocked", job_id, "The report cannot be approved yet.",
                      approve_blocked=blocked)
      if nis2 is not None:
        submission_ref = {"profile_id": nis2["profile_id"], "revision": nis2["submission"]["revision"],
                          "cid": nis2["submission"]["cid"]}
      reopened = _reopened(review, nis2, blocked)
    # Approving a reopened approval writes a fresh one against the current submission.
    if review is not None and review.state == verdict and reopened is None:
      result = _view(owner, job_id, job_specs, rows)
      result["idempotent_replay"] = True
      return result
    state = ReportReviewState(
      job_id=job_id,
      pass_nr=latest,
      state=verdict,
      review_revision=current + 1,
      reviewer=signer,
      note=safe_note,
      decided_at=_utc_timestamp(_owner_time(owner)),
      nis2_submission_ref=submission_ref,
    )
    _write(owner, repo, state, EVENT_APPROVED if verdict == "approved" else EVENT_REJECTED, ledger)
    rows[latest] = state
    return _view(owner, job_id, job_specs, rows)


def approve_report(owner, job_id, *, expected_review_revision=None, note="", actor="",
                   checked_job=_UNSET, snapshot_mode="tenant_bound", ledger=None):
  """Approve the report for the latest pass. Refused with `approve_blocked` while the gate says no.

  An approve over an existing approval at the current revision is a replay and
  writes nothing.
  """
  return _decide(owner, job_id, "approved", expected_review_revision=expected_review_revision,
                 note=note, actor=actor, checked_job=checked_job, snapshot_mode=snapshot_mode,
                 ledger=ledger)


def reject_report(owner, job_id, *, expected_review_revision=None, note="", actor="",
                  checked_job=_UNSET, snapshot_mode="tenant_bound", ledger=None):
  """Reject the report for the latest pass; the note saying why is required."""
  return _decide(owner, job_id, "rejected", expected_review_revision=expected_review_revision,
                 note=note, actor=actor, checked_job=checked_job, snapshot_mode=snapshot_mode,
                 ledger=ledger)


def review_summaries(owner, jobs):
  """`{job_id: summary | None}` for the jobs list: one keyed read per listed job.

  Keyed reads, not a hash enumeration: a tenant-scoped list must only touch
  the rows of the jobs it was admitted to. An approved row also reads its NIS2
  basis (keyed) so the list shows `reopened` exactly when the job page does.

  A finalized scan job gets `{review_status, pass_nr, reviewer, decided_at}` for
  its latest pass; anything else (not finalized, model test) gets `None`. An
  unreadable row lists as `pending` rather than failing the whole list.
  """
  repo = _job_repo(owner)
  summaries = {}
  for job_id, job_specs in jobs.items():
    if (
      not isinstance(job_specs, dict)
      or job_specs.get("job_status") != JOB_STATUS_FINALIZED
      or reject_model_test_for_scan_operation(job_specs, job_id, _LOCK_SCOPE)
    ):
      summaries[job_id] = None
      continue
    latest = _latest_pass_nr(job_specs)
    summary = {"review_status": "pending", "pass_nr": latest, "reviewer": "", "decided_at": ""}
    try:
      review = repo.get_report_review_model(job_id, latest)
    except ValueError:
      review = None
    if review is not None:
      status = review.state
      if status == "approved":
        # Only an approval can be reopened; its NIS2 basis is two more keyed reads.
        status, _, _ = _effective(owner, job_id, job_specs, review)
      summary.update(review_status=status, reviewer=review.reviewer, decided_at=review.decided_at)
    summaries[job_id] = summary
  return summaries
