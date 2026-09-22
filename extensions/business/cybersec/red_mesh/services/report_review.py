"""Report-level review: approve or reopen a job's report as a whole (RM-086 item 4).

RM-064 made the PDF's Final label require a reviewer, and the only reviewer the
platform recorded was the NIS2 rulebook review's, so a job without a NIS2
assessment could never reach Final. This is the sign-off for the report itself.

It mirrors the rulebook review's admission (the endpoints run through
`_read_operation` / `_review_operation`), server-derived actor, revision fence,
lock, audit row and audit event, and deliberately not its submission machinery:
no draft, no R1FS snapshot, no pending registry, no idempotency key. One row in
its own chainstore hash, never on the job record and never in the archive.
Contract: `docs/resources/redmesh/contracts/report-review.md` (project-red-mesh).
"""
from __future__ import annotations

from dataclasses import replace

from ..constants import JOB_STATUS_FINALIZED
from ..models.report_review import (
  REPORT_REVIEW_CONTRACT_VERSION,
  ReportReviewAuditEntry,
  ReportReviewState,
)
from ..tenancy.administration import AdministrationDenied
from ..tenancy.effects import EffectState
from ..tenancy.job_artifacts import checked_job_snapshot, validate_snapshot_mode
from .rulebook_assessment import (
  _job_repo,
  _owner_time,
  _safe_text,
  _submission_lock,
  _utc_timestamp,
)
from .scan_guards import reject_model_test_for_scan_operation


_UNSET = object()
_LOCK_SCOPE = "report_review"

EVENT_APPROVED = "report_review_approved"
EVENT_REOPENED = "report_review_reopened"


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
  artifact, and so the read fixture's record-only jobs behave like real ones.
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
  for key in ("current_pass", "pass_count"):
    try:
      value = int(job_specs.get(key))
    except (TypeError, ValueError):
      continue
    if value > 0:
      return value
  return 1


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


def _view(job_id, review, latest_pass_nr):
  """The one read shape: the row, the newest pass, and whether the approval still covers it."""
  stale_reasons = []
  if (
    review is not None
    and review.state == "approved"
    and latest_pass_nr is not None
    and review.approved_pass_nr
    and latest_pass_nr > review.approved_pass_nr
  ):
    stale_reasons.append("newer_scan_pass")
  approved = review is not None and review.state == "approved" and not stale_reasons
  return {
    "status": "ok",
    "job_id": job_id,
    "review_contract_version": REPORT_REVIEW_CONTRACT_VERSION,
    "review": review.to_dict() if review is not None else None,
    "review_revision": review.review_revision if review is not None else 0,
    "latest_pass_nr": latest_pass_nr,
    "stale": bool(stale_reasons),
    "stale_reasons": stale_reasons,
    "approved": approved,
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


def get_report_review(owner, job_id, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  job_specs, err = _job_for(owner, job_id, checked_job, snapshot_mode, checked_raise=True)
  if err:
    return err
  repo = _job_repo(owner)
  try:
    review = repo.get_report_review_model(job_id)
  except ValueError:
    return _error("review_contract_unsupported", job_id,
                  "Report review contract version is not supported by this backend.")
  return _view(job_id, review, _latest_pass_nr(job_specs))


def _admit_mutation(owner, job_id, expected_review_revision, actor, checked_job, snapshot_mode):
  expected, err = _validated_expected_revision(expected_review_revision, job_id)
  if err:
    return None, None, None, err
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-report-review")
  signer = _safe_text(actor or "", hmac_secret=hmac_secret, max_len=200)
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
    reviewer=state.reviewer if event_type == EVENT_APPROVED else state.reopened_by,
    note=state.note,
    review_revision=state.review_revision,
    approved_pass_nr=state.approved_pass_nr,
    timestamp=_utc_timestamp(_owner_time(owner)),
  ))
  if hasattr(owner, "_log_audit_event"):
    owner._log_audit_event(event_type, {
      "job_id": state.job_id,
      "state": state.state,
      "review_revision": state.review_revision,
      "approved_pass_nr": state.approved_pass_nr,
    })
  return payload


def approve_report(owner, job_id, *, expected_review_revision=None, note="", actor="",
                   checked_job=_UNSET, snapshot_mode="tenant_bound", ledger=None):
  """Approve the report as a whole, pinned to the newest pass at approval time.

  A second approve at the same revision while the approval still covers the
  newest pass is a replay and returns the current view; after a newer pass it
  is a fresh approval that re-pins the pass.
  """
  expected, signer, job_specs, err = _admit_mutation(
    owner, job_id, expected_review_revision, actor, checked_job, snapshot_mode)
  if err:
    return err
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-report-review")
  safe_note = _safe_text(note or "", hmac_secret=hmac_secret, max_len=1000)
  with _submission_lock(owner, job_id, _LOCK_SCOPE):
    repo = _job_repo(owner)
    try:
      review = repo.get_report_review_model(job_id)
    except ValueError:
      return _error("review_contract_unsupported", job_id,
                    "Report review contract version is not supported by this backend.")
    current = review.review_revision if review is not None else 0
    if expected != current:
      return _error("review_revision_conflict", job_id,
                    "The report review changed. Reload before approving.",
                    current_review_revision=current)
    latest = _latest_pass_nr(job_specs)
    if review is not None and review.state == "approved" and review.approved_pass_nr >= latest:
      result = _view(job_id, review, latest)
      result["idempotent_replay"] = True
      return result
    state = ReportReviewState(
      job_id=job_id,
      state="approved",
      review_revision=current + 1,
      reviewer=signer,
      note=safe_note,
      approved_at=_utc_timestamp(_owner_time(owner)),
      approved_pass_nr=latest,
      reopened_at="",
      reopened_by="",
    )
    _write(owner, repo, state, EVENT_APPROVED, ledger)
    return _view(job_id, state, latest)


def reopen_report_review(owner, job_id, *, expected_review_revision=None, actor="",
                         checked_job=_UNSET, snapshot_mode="tenant_bound", ledger=None):
  """Withdraw an approval. The row keeps who approved and when; the state flips."""
  expected, signer, job_specs, err = _admit_mutation(
    owner, job_id, expected_review_revision, actor, checked_job, snapshot_mode)
  if err:
    return err
  with _submission_lock(owner, job_id, _LOCK_SCOPE):
    repo = _job_repo(owner)
    try:
      review = repo.get_report_review_model(job_id)
    except ValueError:
      return _error("review_contract_unsupported", job_id,
                    "Report review contract version is not supported by this backend.")
    current = review.review_revision if review is not None else 0
    if expected != current:
      return _error("review_revision_conflict", job_id,
                    "The report review changed. Reload before reopening.",
                    current_review_revision=current)
    if review is None or review.state != "approved":
      return _error("not_approved", job_id, "There is no approval to reopen.")
    state = replace(
      review,
      state="reopened",
      review_revision=current + 1,
      reopened_at=_utc_timestamp(_owner_time(owner)),
      reopened_by=signer,
    )
    _write(owner, repo, state, EVENT_REOPENED, ledger)
    return _view(job_id, state, _latest_pass_nr(job_specs))
