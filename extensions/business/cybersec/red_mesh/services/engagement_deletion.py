"""GDPR engagement-data deletion (PR-3.4).

Provides the service-layer operation that backs
``DELETE /jobs/:id/engagement``. Nulls every engagement-context field
on a job's persisted JobConfig and optionally removes uploaded
authorization documents from R1FS, while preserving the technical
scan record (target, ports, findings, timing) so downstream
analytics still work.

What gets deleted
-----------------

  Typed (PR-3.3):
    JobConfig.engagement       — full EngagementContext dict
    JobConfig.roe              — full RulesOfEngagement dict
    JobConfig.authorization    — full AuthorizationRef dict

  Legacy (pre-Phase-3):
    JobConfig.engagement_metadata
    JobConfig.authorization_ref
    JobConfig.scope_id
    JobConfig.target_allowlist

  R1FS objects (when delete_documents=True, default):
    The R1FS object pointed to by authorization.document_cid
    (and document_thumbnail_cid if present)
    Each entry in authorization.third_party_auth_cids

What is preserved
-----------------

  Everything else on the JobConfig (target, ports, mode, features,
  worker count, etc.). Findings, pass reports, scan metrics,
  timeline events. The job remains discoverable and viewable; it
  just no longer carries client identity / objectives / contacts /
  authorization paperwork.

Audit record
------------

A redaction audit entry is appended to the job's timeline so the
operation is traceable. The audit carries who requested deletion
and what was removed (counts only — no PII echoed back).

Scope of this PR
----------------

PR-3.4 ships the service-layer function + tests with mocked R1FS
and CStore. The HTTP route (``DELETE /jobs/:id/engagement``) is
defined in pentester_api_01.py and lands alongside PR-3.5 when the
frontend wires end-to-end.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class DeleteEngagementResult:
  """Summary of what an engagement-deletion call removed.

  All counters are 0 when the corresponding section was already
  empty (idempotent: deleting twice is safe).
  """
  job_id: str
  ok: bool
  fields_cleared: int           # count of typed/legacy engagement fields nulled
  documents_deleted: int        # count of R1FS auth documents removed
  documents_failed: int         # docs we attempted to delete but R1FS errored
  new_job_config_cid: str       # CID of the sanitized JobConfig (new R1FS entry)
  performed_at: str             # ISO 8601 UTC
  message: str = ""


@dataclass(frozen=True)
class DeleteEngagementError(Exception):
  code: str   # job_not_found | config_not_found | storage_failed
  message: str

  def __str__(self) -> str:
    return f"{self.code}: {self.message}"


# ---------------------------------------------------------------------
# Public service
# ---------------------------------------------------------------------


def delete_engagement_data(
  *,
  job_id: str,
  job_specs: dict,
  artifact_repo,
  delete_documents: bool = True,
  requested_by: str = "",
  now_fn=None,
) -> DeleteEngagementResult:
  """Null every engagement-context field on the job's JobConfig and
  optionally delete uploaded authorization documents from R1FS.

  Parameters
  ----------
  job_id : str
      The job id to act on. Used for the result record / audit only;
      the actual mutation targets ``job_specs``.
  job_specs : dict
      The CStore job-specs record. Mutated in place: ``job_config_cid``
      is updated to point at the new sanitized JobConfig.
  artifact_repo : ArtifactRepository
      R1FS access. Used for get_job_config / put_job_config /
      delete (auth doc removal).
  delete_documents : bool, default True
      Whether to also delete the authorization document CIDs from
      R1FS. Set False if the operator wants to preserve the document
      for legal-hold reasons.
  requested_by : str
      Identity of who requested deletion (for the audit entry).
  now_fn : callable | None
      Injectable clock for tests.

  Raises
  ------
  DeleteEngagementError
      job_not_found / config_not_found / storage_failed.
  """
  if not job_id:
    raise DeleteEngagementError(
      code="job_not_found", message="job_id is required",
    )
  if not isinstance(job_specs, dict):
    raise DeleteEngagementError(
      code="job_not_found", message=f"invalid job_specs for {job_id}",
    )
  if now_fn is None:
    now_fn = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

  # 1. Load existing JobConfig from R1FS
  config_cid = job_specs.get("job_config_cid", "")
  if not config_cid:
    raise DeleteEngagementError(
      code="config_not_found",
      message=f"job_specs for {job_id} has no job_config_cid",
    )
  try:
    config = artifact_repo.get_job_config(job_specs)
  except Exception as exc:
    raise DeleteEngagementError(
      code="config_not_found",
      message=f"failed to load JobConfig {config_cid}: {exc}",
    )
  if not isinstance(config, dict):
    raise DeleteEngagementError(
      code="config_not_found",
      message=f"JobConfig {config_cid} is not a dict",
    )

  # 2. Build sanitized copy
  sanitized, fields_cleared = _strip_engagement(config)

  # 3. Optionally delete authorization documents from R1FS
  documents_deleted = 0
  documents_failed = 0
  if delete_documents:
    cids_to_delete = _collect_auth_document_cids(config)
    for cid in cids_to_delete:
      try:
        ok = artifact_repo.delete(cid, show_logs=False, raise_on_error=False)
      except Exception:
        ok = False
      if ok:
        documents_deleted += 1
      else:
        documents_failed += 1

  # 4. Persist sanitized JobConfig — new CID
  try:
    new_cid = artifact_repo.put_job_config(sanitized, show_logs=False)
  except Exception as exc:
    raise DeleteEngagementError(
      code="storage_failed",
      message=f"failed to write sanitized JobConfig: {exc}",
    )
  if not new_cid:
    raise DeleteEngagementError(
      code="storage_failed",
      message="put_job_config returned empty CID",
    )

  # 5. Update job_specs to point at new config
  job_specs["job_config_cid"] = new_cid

  # 6. Append audit entry to timeline (best-effort)
  performed_at = now_fn()
  _append_redaction_audit(
    job_specs, job_id=job_id,
    fields_cleared=fields_cleared,
    documents_deleted=documents_deleted,
    documents_failed=documents_failed,
    requested_by=requested_by,
    performed_at=performed_at,
  )

  return DeleteEngagementResult(
    job_id=job_id, ok=True,
    fields_cleared=fields_cleared,
    documents_deleted=documents_deleted,
    documents_failed=documents_failed,
    new_job_config_cid=new_cid,
    performed_at=performed_at,
    message=(
      f"redacted engagement context for {job_id}: "
      f"{fields_cleared} fields cleared, "
      f"{documents_deleted} document(s) deleted, "
      f"{documents_failed} document(s) failed to delete"
    ),
  )


# ---------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------


# Field names on JobConfig that carry engagement-context data.
# Distinguished into typed (PR-3.3) and legacy (pre-Phase-3) buckets
# for clarity in the audit message.
_TYPED_FIELDS = ("engagement", "roe", "authorization")
_LEGACY_FIELDS = (
  "engagement_metadata",
  "authorization_ref",
  "scope_id",
  "target_allowlist",
)


def _strip_engagement(config: dict) -> tuple[dict, int]:
  """Return (sanitized_copy, fields_cleared_count).

  A field counts as 'cleared' if it carried a non-empty value before
  redaction. Fields already empty are not counted (idempotent).
  """
  sanitized = dict(config)
  cleared = 0
  for fld in _TYPED_FIELDS:
    if sanitized.get(fld):
      cleared += 1
    sanitized[fld] = None
  for fld in _LEGACY_FIELDS:
    val = sanitized.get(fld)
    if val:
      cleared += 1
    if fld == "authorization_ref":
      sanitized[fld] = ""
    elif fld == "scope_id":
      sanitized[fld] = ""
    else:
      sanitized[fld] = None
  return sanitized, cleared


def _collect_auth_document_cids(config: dict) -> list[str]:
  """Walk the AuthorizationRef and legacy authorization_ref fields and
  return every R1FS CID that points to an uploaded auth document."""
  out: list[str] = []
  auth = config.get("authorization") or {}
  if isinstance(auth, dict):
    for key in ("document_cid", "document_thumbnail_cid"):
      cid = auth.get(key)
      if cid and isinstance(cid, str):
        out.append(cid)
    third = auth.get("third_party_auth_cids") or []
    for cid in third:
      if cid and isinstance(cid, str):
        out.append(cid)
  legacy_ref = config.get("authorization_ref")
  if isinstance(legacy_ref, str) and legacy_ref:
    out.append(legacy_ref)
  # Dedup while preserving order
  seen: set = set()
  unique: list[str] = []
  for cid in out:
    if cid not in seen:
      seen.add(cid)
      unique.append(cid)
  return unique


def _append_redaction_audit(
  job_specs: dict, *,
  job_id: str, fields_cleared: int,
  documents_deleted: int, documents_failed: int,
  requested_by: str, performed_at: str,
) -> None:
  """Append a single audit entry to the job's timeline. Best-effort:
  silently no-ops when timeline isn't a list."""
  timeline = job_specs.setdefault("timeline", [])
  if not isinstance(timeline, list):
    return
  timeline.append({
    "type": "engagement_redacted",
    "label": (
      f"Engagement context redacted "
      f"({fields_cleared} field(s), {documents_deleted} document(s))"
    ),
    "actor": requested_by or "system",
    "actor_type": "user" if requested_by else "system",
    "date": performed_at,
    "meta": {
      "job_id": job_id,
      "fields_cleared": fields_cleared,
      "documents_deleted": documents_deleted,
      "documents_failed": documents_failed,
      "reason": "GDPR engagement-context deletion",
    },
  })
