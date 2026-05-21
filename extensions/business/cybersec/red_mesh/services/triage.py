from copy import deepcopy

from ..models import FindingTriageAuditEntry, FindingTriageState, VALID_TRIAGE_STATUSES
from ..repositories import ArtifactRepository, JobStateRepository
from .event_hooks import emit_finding_event


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


def get_job_triage(owner, job_id: str, finding_id: str = ""):
  triage_map = _job_repo(owner).list_job_triage(job_id)
  if finding_id:
    state = triage_map.get(finding_id)
    audit = _job_repo(owner).get_finding_triage_audit(job_id, finding_id)
    if state is None:
      return {"job_id": job_id, "finding_id": finding_id, "found": False, "triage": None, "audit": audit}
    return {"job_id": job_id, "finding_id": finding_id, "found": True, "triage": state, "audit": audit}
  return {"job_id": job_id, "triage": triage_map}


def update_finding_triage(owner, job_id: str, finding_id: str, status: str, note: str = "", actor: str = "", review_at: float = 0):
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
    repo.put_job(job_id, job_specs)
  return {
    "job_id": job_id,
    "finding_id": finding_id,
    "triage": state_payload,
    "audit": audit_payload,
  }


def get_job_archive_with_triage(owner, job_id: str):
  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return {"error": "not_found", "message": f"Job {job_id} not found."}

  job_cid = job_specs.get("job_cid")
  if not job_cid:
    return {"error": "not_available", "message": f"Job {job_id} is still running (no archive yet)."}

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
