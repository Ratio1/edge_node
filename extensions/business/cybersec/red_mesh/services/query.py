from ..models import JobArchive
from ..repositories import ArtifactRepository, JobStateRepository


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


def get_job_data(owner, job_id: str):
  """
  Retrieve job data from CStore.

  Finalized/stopped jobs return the lightweight stub as-is. Running jobs keep
  only the most recent pass report references to avoid large response payloads.
  """
  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return {
      "job_id": job_id,
      "found": False,
      "message": "Job not found in network store.",
    }

  if job_specs.get("job_cid"):
    return {
      "job_id": job_id,
      "found": True,
      "job": job_specs,
    }

  pass_reports = job_specs.get("pass_reports", [])
  if isinstance(pass_reports, list) and len(pass_reports) > 5:
    job_specs["pass_reports"] = pass_reports[-5:]

  return {
    "job_id": job_id,
    "found": True,
    "job": job_specs,
  }


def get_job_archive(owner, job_id: str):
  """
  Retrieve the full archived job payload from R1FS for finalized jobs.
  """
  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return {"error": "not_found", "message": f"Job {job_id} not found."}

  job_cid = job_specs.get("job_cid")
  if not job_cid:
    return {"error": "not_available", "message": f"Job {job_id} is still running (no archive yet)."}

  archive = _artifact_repo(owner).get_json(job_cid)
  if archive is None:
    return {"error": "fetch_failed", "message": f"Failed to fetch archive from R1FS (CID: {job_cid})."}

  try:
    archive = JobArchive.from_dict(archive).to_dict()
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

  return {"job_id": job_id, "archive": archive}


def get_job_progress(owner, job_id: str):
  """
  Return real-time progress for all workers in the given job.
  """
  live_hkey = f"{owner.cfg_instance_id}:live"
  all_progress = _job_repo(owner).list_live_progress() or {}
  prefix = f"{job_id}:"
  result = {}
  for key, value in all_progress.items():
    if key.startswith(prefix) and value is not None:
      worker_addr = key[len(prefix):]
      result[worker_addr] = value

  job_specs = _job_repo(owner).get_job(job_id)
  status = None
  scan_type = None
  if isinstance(job_specs, dict):
    status = job_specs.get("job_status")
    scan_type = job_specs.get("scan_type")
  return {"job_id": job_id, "status": status, "scan_type": scan_type, "workers": result}


def list_network_jobs(owner):
  """
  Return a normalized network-job listing from CStore.
  """
  raw_network_jobs = _job_repo(owner).list_jobs()
  normalized_jobs = {}
  for job_key, job_spec in raw_network_jobs.items():
    normalized_key, normalized_spec = owner._normalize_job_record(job_key, job_spec)
    if normalized_key and normalized_spec:
      if normalized_spec.get("job_cid"):
        normalized_jobs[normalized_key] = normalized_spec
        continue

      normalized_jobs[normalized_key] = {
        "job_id": normalized_spec.get("job_id"),
        "job_status": normalized_spec.get("job_status"),
        "target": normalized_spec.get("target"),
        "scan_type": normalized_spec.get("scan_type", "network"),
        "target_url": normalized_spec.get("target_url", ""),
        "task_name": normalized_spec.get("task_name"),
        "risk_score": normalized_spec.get("risk_score", 0),
        "run_mode": normalized_spec.get("run_mode"),
        "start_port": normalized_spec.get("start_port"),
        "end_port": normalized_spec.get("end_port"),
        "date_created": normalized_spec.get("date_created"),
        "launcher": normalized_spec.get("launcher"),
        "launcher_alias": normalized_spec.get("launcher_alias"),
        "worker_count": len(normalized_spec.get("workers", {}) or {}),
        "pass_count": len(normalized_spec.get("pass_reports", []) or []),
        "job_pass": normalized_spec.get("job_pass", 1),
      }
  return normalized_jobs


def list_local_jobs(owner):
  """
  Return jobs currently running on the local node.
  """
  return {
    job_id: owner._get_job_status(job_id)
    for job_id, local_workers in owner.scan_jobs.items()
  }
