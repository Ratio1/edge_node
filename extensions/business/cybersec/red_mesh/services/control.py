from ..constants import (
  JOB_STATUS_FINALIZED,
  JOB_STATUS_RUNNING,
  JOB_STATUS_SCHEDULED_FOR_STOP,
  JOB_STATUS_STOPPED,
  RUN_MODE_CONTINUOUS_MONITORING,
)
from ..repositories import ArtifactRepository, JobStateRepository
from .secrets import collect_secret_refs_from_job_config
from .state_machine import set_job_status


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
  write_job_record = getattr(type(owner), "_write_job_record", None)
  if callable(write_job_record):
    return write_job_record(owner, job_id, job_specs, context=context)
  _job_repo(owner).put_job(job_id, job_specs)
  return job_specs


def _delete_job_record(owner, job_id):
  delete_job_record = getattr(type(owner), "_delete_job_record", None)
  if callable(delete_job_record):
    delete_job_record(owner, job_id)
    return
  _job_repo(owner).delete_job(job_id)


def stop_and_delete_job(owner, job_id: str):
  """
  Stop a running job, mark it stopped, then delegate to purge_job
  for full R1FS + CStore cleanup.
  """
  local_workers = owner.scan_jobs.get(job_id)
  if local_workers:
    owner.P(f"Stopping and deleting job {job_id}.")
    for local_worker_id, job in local_workers.items():
      owner.P(f"Stopping job {job_id} on local worker {local_worker_id}.")
      job.stop()
    owner.P(f"Job {job_id} stopped.")
  owner.scan_jobs.pop(job_id, None)

  raw_job_specs = _job_repo(owner).get_job(job_id)
  if isinstance(raw_job_specs, dict):
    _, job_specs = owner._normalize_job_record(job_id, raw_job_specs)
    worker_entry = job_specs.setdefault("workers", {}).setdefault(owner.ee_addr, {})
    worker_entry["finished"] = True
    worker_entry["canceled"] = True
    set_job_status(job_specs, JOB_STATUS_STOPPED)
    owner._emit_timeline_event(job_specs, "stopped", "Job stopped and deleted", actor_type="user")
    _write_job_record(owner, job_id, job_specs, context="stop_and_delete")
  else:
    owner._log_audit_event("scan_stopped", {"job_id": job_id})
    return {"status": "success", "job_id": job_id, "cids_deleted": 0, "cids_total": 0}

  owner._log_audit_event("scan_stopped", {"job_id": job_id})
  return owner.purge_job(job_id)


def purge_job(owner, job_id: str):
  """
  Purge a job: delete all R1FS artifacts, clean up live progress keys,
  then tombstone the CStore entry.
  """
  raw = _job_repo(owner).get_job(job_id)
  if not isinstance(raw, dict):
    return {"status": "error", "message": f"Job {job_id} not found."}

  _, job_specs = owner._normalize_job_record(job_id, raw)

  job_status = job_specs.get("job_status", "")
  workers = job_specs.get("workers", {})
  if workers and any(not w.get("finished") for w in workers.values()):
    return {"status": "error", "message": "Cannot purge a running job. Stop it first."}
  if job_status not in (JOB_STATUS_FINALIZED, JOB_STATUS_STOPPED) and workers:
    return {"status": "error", "message": "Cannot purge a running job. Stop it first."}

  cids = set()

  def _track(cid, source):
    if cid and isinstance(cid, str) and cid not in cids:
      cids.add(cid)
      owner.P(f"[PURGE] Collected CID {cid} from {source}")

  _track(job_specs.get("job_config_cid"), "job_specs.job_config_cid")
  artifacts = _artifact_repo(owner)
  job_config = artifacts.get_job_config(job_specs) if job_specs.get("job_config_cid") else {}
  if isinstance(job_config, dict):
    for secret_ref in collect_secret_refs_from_job_config(job_config):
        _track(secret_ref, "job_config.secret_ref")

  job_cid = job_specs.get("job_cid")
  if job_cid:
    _track(job_cid, "job_specs.job_cid")
    try:
      archive = artifacts.get_json(job_cid)
      if isinstance(archive, dict):
        owner.P(f"[PURGE] Archive fetched OK, {len(archive.get('passes', []))} passes")
        for pi, pass_data in enumerate(archive.get("passes", [])):
          _track(pass_data.get("aggregated_report_cid"), f"archive.passes[{pi}].aggregated_report_cid")
          for addr, wr in (pass_data.get("worker_reports") or {}).items():
            if isinstance(wr, dict):
              _track(wr.get("report_cid"), f"archive.passes[{pi}].worker_reports[{addr}].report_cid")
      else:
        owner.P(f"[PURGE] Archive fetch returned non-dict: {type(archive)}", color='y')
    except Exception as e:
      owner.P(f"[PURGE] Failed to fetch archive {job_cid}: {e}", color='r')

  for addr, w in workers.items():
    _track(w.get("report_cid"), f"workers[{addr}].report_cid")

  for ri, ref in enumerate(job_specs.get("pass_reports", [])):
    report_cid = ref.get("report_cid")
    if report_cid:
      _track(report_cid, f"pass_reports[{ri}].report_cid")
      try:
        pass_data = artifacts.get_pass_report(report_cid)
        if isinstance(pass_data, dict):
          _track(pass_data.get("aggregated_report_cid"), f"pass_reports[{ri}]->aggregated_report_cid")
          for addr, wr in (pass_data.get("worker_reports") or {}).items():
            if isinstance(wr, dict):
              _track(wr.get("report_cid"), f"pass_reports[{ri}]->worker_reports[{addr}].report_cid")
        else:
          owner.P(f"[PURGE] Pass report fetch returned non-dict: {type(pass_data)}", color='y')
      except Exception as e:
        owner.P(f"[PURGE] Failed to fetch pass report {report_cid}: {e}", color='r')

  owner.P(f"[PURGE] Total CIDs collected: {len(cids)}: {sorted(cids)}")

  deleted, failed = 0, 0
  for cid in cids:
    try:
      success = artifacts.delete(cid, show_logs=True, raise_on_error=False)
      if success:
        deleted += 1
        owner.P(f"[PURGE] Deleted CID {cid}")
      else:
        failed += 1
        owner.P(f"[PURGE] delete_file returned False for CID {cid}", color='r')
    except Exception as e:
      owner.P(f"[PURGE] Failed to delete CID {cid}: {e}", color='r')
      failed += 1

  if failed > 0:
    owner.P(f"Purge incomplete: {failed}/{len(cids)} CIDs failed. CStore kept.", color='r')
    return {
      "status": "partial",
      "job_id": job_id,
      "cids_deleted": deleted,
      "cids_failed": failed,
      "cids_total": len(cids),
      "message": "Some R1FS artifacts could not be deleted. Retry purge later.",
    }

  all_live = _job_repo(owner).list_live_progress()
  if isinstance(all_live, dict):
    prefix = f"{job_id}:"
    for key in all_live:
      if key.startswith(prefix):
        _job_repo(owner).delete_live_progress(key)

  _delete_job_record(owner, job_id)

  owner.P(f"Purged job {job_id}: {deleted}/{len(cids)} CIDs deleted.")
  owner._log_audit_event("job_purged", {"job_id": job_id, "cids_deleted": deleted, "cids_total": len(cids)})

  return {"status": "success", "job_id": job_id, "cids_deleted": deleted, "cids_total": len(cids)}


def stop_monitoring(owner, job_id: str, stop_type: str = "SOFT"):
  """
  Stop a job (any run mode with HARD stop, continuous-only for SOFT stop).
  """
  raw_job_specs = _job_repo(owner).get_job(job_id)
  if not raw_job_specs:
    return {"error": "Job not found", "job_id": job_id}

  _, job_specs = owner._normalize_job_record(job_id, raw_job_specs)
  stop_type = str(stop_type).upper()
  is_continuous = job_specs.get("run_mode") == RUN_MODE_CONTINUOUS_MONITORING

  if stop_type != "HARD" and not is_continuous:
    return {"error": "SOFT stop is only supported for CONTINUOUS_MONITORING jobs", "job_id": job_id}

  passes_completed = job_specs.get("job_pass", 1)

  if stop_type == "HARD":
    local_workers = owner.scan_jobs.get(job_id)
    if local_workers:
      for local_worker_id, job in local_workers.items():
        owner.P(f"Stopping job {job_id} on local worker {local_worker_id}.")
        job.stop()
      owner.scan_jobs.pop(job_id, None)

    worker_entry = job_specs.setdefault("workers", {}).setdefault(owner.ee_addr, {})
    worker_entry["finished"] = True
    worker_entry["canceled"] = True

    set_job_status(job_specs, JOB_STATUS_STOPPED)
    owner._emit_timeline_event(job_specs, "stopped", "Job stopped", actor_type="user")
    owner.P(f"Hard stop for job {job_id} after {passes_completed} passes")
  else:
    set_job_status(job_specs, JOB_STATUS_SCHEDULED_FOR_STOP)
    owner._emit_timeline_event(job_specs, "scheduled_for_stop", "Stop scheduled", actor_type="user")
    owner.P(f"[CONTINUOUS] Soft stop scheduled for job {job_id} (will stop after current pass)")

  _write_job_record(owner, job_id, job_specs, context="stop_monitoring")

  return {
    "job_status": job_specs["job_status"],
    "stop_type": stop_type,
    "job_id": job_id,
    "passes_completed": passes_completed,
    "pass_reports": job_specs.get("pass_reports", []),
  }
