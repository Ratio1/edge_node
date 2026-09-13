from copy import deepcopy
from contextlib import ExitStack

from ..model_testing.artifacts import ModelTestArchive
from ..model_testing.constants import is_model_test_job
from ..models import FindingTriageAuditEntry, FindingTriageState, JobArchive, VALID_TRIAGE_STATUSES
from ..repositories import ArtifactRepository, JobStateRepository
from ..tenancy.administration import AdministrationDenied
from ..tenancy.job_artifacts import MAX_ARTIFACT_REFERENCES, TenantJobArtifacts, checked_job_snapshot
from ..tenancy.ports import TenantStoreError
from .event_hooks import emit_finding_event

_UNSET = object()


def _job_repo(owner):
  getter = getattr(type(owner), "_get_job_state_repository", None)
  if callable(getter):
    return getter(owner)
  return JobStateRepository(owner)


def _artifact_repo(owner):
  getter = getattr(type(owner), "_get_artifact_repository", None)
  if callable(getter):
    return getter(owner)
  return ArtifactRepository(owner)


def _write_job_record(owner, job_id, job_specs, context):
  writer = getattr(type(owner), "_write_job_record", None)
  if callable(writer):
    return writer(owner, job_id, job_specs, context=context)
  launcher = job_specs.get("launcher") if isinstance(job_specs, dict) else None
  if launcher and launcher != getattr(owner, "ee_addr", None):
    return None
  return _job_repo(owner).put_job(job_id, job_specs)


def _archive_contains_finding(archive: dict, finding_id: str) -> bool:
  return _find_archive_finding(archive, finding_id) is not None


def _find_archive_finding(archive: dict, finding_id: str):
  for pass_report in archive.get("passes", []) or []:
    for finding in pass_report.get("findings", []) or []:
      if isinstance(finding, dict) and finding.get("finding_id") == finding_id:
        return finding
  return None


def _merge_triage_into_archive_dict(archive: dict, triage_map: dict) -> dict:
  merged = deepcopy(archive)
  for pass_report in merged.get("passes", []) or []:
    for finding in pass_report.get("findings", []) or []:
      if not isinstance(finding, dict):
        continue
      triage = triage_map.get(finding.get("finding_id"))
      if triage:
        finding["triage"] = triage
  ui = merged.get("ui_aggregate")
  if isinstance(ui, dict):
    for finding in ui.get("top_findings", []) or []:
      if not isinstance(finding, dict):
        continue
      triage = triage_map.get(finding.get("finding_id"))
      if triage:
        finding["triage"] = triage
  return merged


def _checked_triage_map(owner, job_id, archive, finding_id=""):
  """Read state only for archive-owned findings; reports:view does not grant audit:view."""
  try:
    passes = archive.get("passes", [])
    if not isinstance(passes, list) or len(passes) > MAX_ARTIFACT_REFERENCES:
      raise ValueError("Invalid archived passes")
    finding_ids = set()
    count = 0
    for report in passes:
      findings = report.get("findings", [])
      if not isinstance(findings, list):
        raise ValueError("Invalid archived findings")
      count += len(findings)
      if count > MAX_ARTIFACT_REFERENCES:
        raise ValueError("Finding read budget exceeded")
      for finding in findings:
        identifier = finding.get("finding_id")
        if not isinstance(identifier, str) or not identifier.strip():
          raise ValueError("Invalid finding identity")
        finding_ids.add(identifier)
    if finding_id and finding_id not in finding_ids:
      raise AdministrationDenied(404, "not_found")
    result = {}
    for identifier in ([finding_id] if finding_id else sorted(finding_ids)):
      state = deepcopy(_job_repo(owner).get_finding_triage(job_id, identifier))
      if state is None:
        continue
      if not isinstance(state, dict) or state.get("job_id") != job_id or state.get("finding_id") != identifier:
        raise ValueError("Invalid finding state identity")
      result[identifier] = FindingTriageState.from_dict(state).to_dict()
    return result
  except AdministrationDenied:
    raise
  except Exception:
    raise TenantStoreError("Tenant finding state is unavailable") from None


def get_job_triage(owner, job_id: str, finding_id: str = "", *, checked_job=_UNSET):
  if checked_job is not _UNSET:
    job = checked_job_snapshot(checked_job, job_id)
    archive = TenantJobArtifacts(job, _artifact_repo(owner).get_json).archive()
    if archive is None:
      raise AdministrationDenied(404, "not_found")
    if is_model_test_job(job):
      if finding_id:
        raise AdministrationDenied(404, "not_found")
      triage_map = {}
    else:
      triage_map = _checked_triage_map(owner, job_id, archive, finding_id)
    result = {"job_id": job_id, "execution_binding": job["execution_binding"]}
    if finding_id:
      state = triage_map.get(finding_id)
      result.update(finding_id=finding_id, found=state is not None, triage=state)
    else:
      result["triage"] = triage_map
    return result
  triage_map = _job_repo(owner).list_job_triage(job_id)
  if finding_id:
    state = triage_map.get(finding_id)
    audit = _job_repo(owner).get_finding_triage_audit(job_id, finding_id)
    if state is None:
      return {"job_id": job_id, "finding_id": finding_id, "found": False, "triage": None, "audit": audit}
    return {"job_id": job_id, "finding_id": finding_id, "found": True, "triage": state, "audit": audit}
  return {"job_id": job_id, "triage": triage_map}


def update_finding_triage(owner, job_id: str, finding_id: str, status: str, note: str = "", actor: str = "", review_at: float = 0):
  from .rulebook_assessment import _submission_lock, list_rulebook_profiles

  with ExitStack() as stack:
    profiles = sorted(list_rulebook_profiles(), key=lambda item: item["profile_id"])
    for profile in profiles:
      stack.enter_context(_submission_lock(owner, job_id, profile["profile_id"]))
    repo = _job_repo(owner)
    for profile in profiles:
      registry = repo.get_rulebook_submission_registry(job_id, profile["profile_id"])
      if isinstance(registry, dict) and registry.get("pending"):
        return {
          "error": "submission_in_progress",
          "message": "Finding triage cannot change while a formal review submission is pending.",
          "job_id": job_id,
          "finding_id": finding_id,
        }
    return _update_finding_triage_locked(owner, job_id, finding_id, status, note, actor, review_at)


def _update_finding_triage_locked(owner, job_id: str, finding_id: str, status: str, note: str = "", actor: str = "", review_at: float = 0):
  if status not in VALID_TRIAGE_STATUSES:
    return {
      "error": "validation_error",
      "message": f"Unsupported triage status: {status}. Allowed: {sorted(VALID_TRIAGE_STATUSES)}",
    }

  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return {"error": "not_found", "message": f"Job {job_id} not found."}
  if not job_specs.get("job_cid"):
    return {"error": "not_available", "message": f"Job {job_id} is still running (triage requires archived findings)."}
  launcher = job_specs.get("launcher")
  if launcher and launcher != getattr(owner, "ee_addr", None):
    return {
      "error": "job_launcher_mismatch",
      "message": "Finding triage must be handled by the job launcher.",
      "status_code": 409,
      "job_id": job_id,
    }

  archive = _artifact_repo(owner).get_archive(job_specs)
  if not isinstance(archive, dict):
    return {"error": "fetch_failed", "message": f"Failed to fetch archive for job {job_id}."}
  archived_finding = _find_archive_finding(archive, finding_id)
  if archived_finding is None:
    return {"error": "not_found", "message": f"Finding {finding_id} not found in archived job {job_id}."}

  triage_state = FindingTriageState(
    job_id=job_id,
    finding_id=finding_id,
    status=status,
    note=note or "",
    actor=actor or "",
    updated_at=owner.time(),
    review_at=review_at or None,
  )
  repo = _job_repo(owner)
  state_payload = repo.put_finding_triage(triage_state)
  audit_payload = repo.append_finding_triage_audit(FindingTriageAuditEntry(
    job_id=job_id,
    finding_id=finding_id,
    status=status,
    note=note or "",
    actor=actor or "",
    timestamp=owner.time(),
  ))
  if hasattr(owner, "_log_audit_event"):
    owner._log_audit_event("finding_triage_updated", {
      "job_id": job_id,
      "finding_id": finding_id,
      "status": status,
      "actor": actor or "",
    })
  finding_event = dict(archived_finding)
  finding_event["triage_state"] = status
  emit_finding_event(
    owner,
    job_specs,
    finding=finding_event,
    event_action="triaged",
  )
  if isinstance(job_specs.get("soc_event_status"), dict):
    _write_job_record(owner, job_id, job_specs, context="finding_triage_soc_event")
  return {
    "job_id": job_id,
    "finding_id": finding_id,
    "triage": state_payload,
    "audit": audit_payload,
  }


def get_job_archive_with_triage(owner, job_id: str, *, checked_job=_UNSET):
  if checked_job is not _UNSET:
    job = checked_job_snapshot(checked_job, job_id)
    payload = TenantJobArtifacts(job, _artifact_repo(owner).get_json).archive()
    if payload is None:
      return {"job_id": job_id, "execution_binding": job["execution_binding"], "error": "not_available"}
    try:
      model = ModelTestArchive if is_model_test_job(job) else JobArchive
      archive = model.from_dict(payload).to_dict()
      triage_map = {} if is_model_test_job(job) else _checked_triage_map(owner, job_id, payload)
      return {"job_id": job_id, "execution_binding": job["execution_binding"],
              "archive": _merge_triage_into_archive_dict(archive, triage_map), "triage": triage_map}
    except Exception:
      raise TenantStoreError("Tenant archive is unavailable") from None
  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return {"error": "not_found", "message": f"Job {job_id} not found."}

  job_cid = job_specs.get("job_cid")
  if not job_cid:
    return {"error": "not_available", "message": f"Job {job_id} is still running (no archive yet)."}

  if is_model_test_job(job_specs):
    try:
      payload = _artifact_repo(owner).get_archive(job_specs)
      if not isinstance(payload, dict):
        return {"error": "fetch_failed", "message": f"Failed to fetch archive from R1FS (CID: {job_cid})."}
      archive = ModelTestArchive.from_dict(payload).to_dict()
    except (KeyError, TypeError, ValueError) as exc:
      return {
        "error": "unsupported_archive_version",
        "message": str(exc),
        "job_id": job_id,
        "job_cid": job_cid,
      }

    if archive.get("job_id") != job_id:
      owner.P(
        f"[INTEGRITY] Archive CID {job_cid} has job_id={archive.get('job_id')}, expected {job_id}",
        color='r'
      )
      return {"error": "integrity_mismatch", "message": "Archive job_id does not match requested job_id."}

    return {"job_id": job_id, "archive": archive, "triage": {}}

  try:
    archive = _artifact_repo(owner).get_archive_model(job_specs)
    if archive is None:
      return {"error": "fetch_failed", "message": f"Failed to fetch archive from R1FS (CID: {job_cid})."}
    archive = archive.to_dict()
  except ValueError as exc:
    return {
      "error": "unsupported_archive_version",
      "message": str(exc),
      "job_id": job_id,
      "job_cid": job_cid,
    }

  if archive.get("job_id") != job_id:
    owner.P(
      f"[INTEGRITY] Archive CID {job_cid} has job_id={archive.get('job_id')}, expected {job_id}",
      color='r'
    )
    return {"error": "integrity_mismatch", "message": "Archive job_id does not match requested job_id."}

  triage_map = _job_repo(owner).list_job_triage(job_id)
  merged_archive = _merge_triage_into_archive_dict(archive, triage_map)
  return {"job_id": job_id, "archive": merged_archive, "triage": triage_map}
