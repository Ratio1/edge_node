from ..constants import (
  JOB_STATUS_FINALIZED,
  JOB_STATUS_RUNNING,
  JOB_STATUS_SCHEDULED_FOR_STOP,
  JOB_STATUS_STOPPED,
  RUN_MODE_CONTINUOUS_MONITORING,
)
from ..repositories import ArtifactRepository, JobStateRepository
from .event_hooks import emit_lifecycle_event
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
    emit_lifecycle_event(
      owner,
      job_specs,
      event_type="redmesh.job.stopped",
      event_action="stopped",
      event_outcome="success",
      pass_nr=job_specs.get("job_pass"),
    )
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

  _job_repo(owner).delete_job_triage(job_id)
  _delete_job_record(owner, job_id)

  owner.P(f"Purged job {job_id}: {deleted}/{len(cids)} CIDs deleted.")
  owner._log_audit_event("job_purged", {"job_id": job_id, "cids_deleted": deleted, "cids_total": len(cids)})

  return {"status": "success", "job_id": job_id, "cids_deleted": deleted, "cids_total": len(cids)}


def _collect_cids_from_raw(payload):
  """Walk a raw CStore payload and yield every value stored under a `*_cid` key."""
  if isinstance(payload, dict):
    for key, value in payload.items():
      if isinstance(key, str) and key.endswith("_cid") and isinstance(value, str) and value:
        yield value
      else:
        yield from _collect_cids_from_raw(value)
  elif isinstance(payload, (list, tuple)):
    for item in payload:
      yield from _collect_cids_from_raw(item)


def _force_purge_job(owner, job_id, raw_payload, errors):
  """
  Best-effort wipe of a job whose record could not be parsed/purged by
  ``stop_and_delete_job``. Returns (cids_deleted, cids_failed).

  Scans the raw payload for ``*_cid`` fields, attempts R1FS deletion, then
  tombstones the CStore record and matching live/triage rows regardless.
  """
  cids = sorted({c for c in _collect_cids_from_raw(raw_payload) if isinstance(c, str)})
  cids_deleted = 0
  cids_failed = 0
  artifacts = _artifact_repo(owner)
  for cid in cids:
    try:
      success = artifacts.delete(cid, show_logs=True, raise_on_error=False)
      if success:
        cids_deleted += 1
        owner.P(f"[PURGE_ALL_FORCE] Deleted CID {cid} for {job_id}")
      else:
        cids_failed += 1
        owner.P(f"[PURGE_ALL_FORCE] delete returned False for CID {cid} ({job_id})", color='y')
    except Exception as exc:
      cids_failed += 1
      owner.P(f"[PURGE_ALL_FORCE] Failed to delete CID {cid} ({job_id}): {exc}", color='r')
      errors.append({"job_id": job_id, "scope": "r1fs", "message": f"{type(exc).__name__}: {exc}"})

  cfg_instance_id = owner.cfg_instance_id
  prefix = f"{job_id}:"

  for hkey in (f"{cfg_instance_id}:live", f"{cfg_instance_id}:triage", f"{cfg_instance_id}:triage:audit"):
    try:
      rows = owner.chainstore_hgetall(hkey=hkey)
    except Exception as exc:
      errors.append({"job_id": job_id, "scope": hkey, "message": f"{type(exc).__name__}: {exc}"})
      continue
    if not isinstance(rows, dict):
      continue
    for key in list(rows):
      if isinstance(key, str) and key.startswith(prefix):
        try:
          owner.chainstore_hset(hkey=hkey, key=key, value=None)
        except Exception as exc:
          errors.append({"job_id": job_id, "scope": hkey, "message": f"{type(exc).__name__}: {exc}"})

  try:
    owner.chainstore_hset(hkey=cfg_instance_id, key=job_id, value=None)
  except Exception as exc:
    errors.append({"job_id": job_id, "scope": cfg_instance_id, "message": f"{type(exc).__name__}: {exc}"})

  owner.P(f"[PURGE_ALL_FORCE] Force-purged {job_id}: {cids_deleted}/{len(cids)} CIDs deleted.")
  return cids_deleted, cids_failed


def purge_all_jobs(owner):
  """
  Purge every RedMesh job on this edge node: stop running jobs, delete all
  R1FS artifacts, tombstone CStore records, and sweep orphan rows in the
  live progress / triage / triage audit hashes. When all jobs purge cleanly,
  also clear integration status rows that point at now-deleted job activity.

  Records that cannot be parsed by the current schema (legacy structures)
  are force-tombstoned via :func:`_force_purge_job` with best-effort R1FS
  cleanup.

  Preserves the single-job partial-failure contract for parseable records:
  any job whose purge returned ``partial`` keeps its CStore rows intact so
  the operator can retry artifact deletion later.
  """
  raw_jobs = _job_repo(owner).list_jobs() or {}
  job_entries = [(jid, payload) for jid, payload in raw_jobs.items() if isinstance(jid, str) and isinstance(payload, dict)]

  jobs_total = len(job_entries)
  jobs_succeeded = 0
  jobs_failed = 0
  jobs_force_purged = 0
  cids_deleted = 0
  cids_failed = 0
  failed_job_ids = set()
  errors = []

  terminal_statuses = (JOB_STATUS_FINALIZED, JOB_STATUS_STOPPED)
  for job_id, raw_payload in job_entries:
    raw_status = raw_payload.get("job_status") if isinstance(raw_payload, dict) else None
    use_direct_purge = raw_status in terminal_statuses
    try:
      if use_direct_purge:
        result = owner.purge_job(job_id)
      else:
        result = owner.stop_and_delete_job(job_id)
    except Exception as exc:
      owner.P(f"[PURGE_ALL] stop_and_delete_job({job_id}) raised: {exc}; falling back to force-purge.", color='y')
      errors.append({"job_id": job_id, "message": f"{type(exc).__name__}: {exc}"})
      fc_deleted, fc_failed = _force_purge_job(owner, job_id, raw_payload, errors)
      cids_deleted += fc_deleted
      cids_failed += fc_failed
      jobs_failed += 1
      jobs_force_purged += 1
      continue

    if not isinstance(result, dict):
      errors.append({"job_id": job_id, "message": f"unexpected non-dict response: {type(result).__name__}"})
      fc_deleted, fc_failed = _force_purge_job(owner, job_id, raw_payload, errors)
      cids_deleted += fc_deleted
      cids_failed += fc_failed
      jobs_failed += 1
      jobs_force_purged += 1
      continue

    status = result.get("status")
    cids_deleted += int(result.get("cids_deleted", 0) or 0)
    cids_failed += int(result.get("cids_failed", 0) or 0)

    if status == "success":
      jobs_succeeded += 1
    elif status == "partial":
      jobs_failed += 1
      failed_job_ids.add(job_id)
      errors.append({
        "job_id": job_id,
        "message": result.get("message") or "purge returned status='partial'",
      })
    else:
      errors.append({
        "job_id": job_id,
        "message": result.get("message") or f"purge returned status={status!r}",
      })
      fc_deleted, fc_failed = _force_purge_job(owner, job_id, raw_payload, errors)
      cids_deleted += fc_deleted
      cids_failed += fc_failed
      jobs_failed += 1
      jobs_force_purged += 1

  cfg_instance_id = owner.cfg_instance_id
  live_hkey = f"{cfg_instance_id}:live"
  triage_hkey = f"{cfg_instance_id}:triage"
  triage_audit_hkey = f"{cfg_instance_id}:triage:audit"
  integrations_hkey = f"{cfg_instance_id}:integrations"

  def _job_id_from_compound_key(key):
    if not isinstance(key, str):
      return None
    return key.split(":", 1)[0]

  def _sweep_hash(hkey, expected_value_types):
    rows_deleted = 0
    rows = owner.chainstore_hgetall(hkey=hkey)
    if not isinstance(rows, dict):
      return rows_deleted
    for key, value in list(rows.items()):
      if not isinstance(key, str):
        continue
      if expected_value_types is not None and not isinstance(value, expected_value_types):
        continue
      job_id_prefix = _job_id_from_compound_key(key)
      if job_id_prefix and job_id_prefix in failed_job_ids:
        continue
      try:
        owner.chainstore_hset(hkey=hkey, key=key, value=None)
        rows_deleted += 1
      except Exception as exc:
        owner.P(f"[PURGE_ALL] failed to tombstone {hkey}/{key}: {exc}", color='r')
        errors.append({"job_id": job_id_prefix or "", "scope": hkey, "message": f"{type(exc).__name__}: {exc}"})
    return rows_deleted

  _sweep_hash(live_hkey, dict)
  _sweep_hash(triage_hkey, dict)
  _sweep_hash(triage_audit_hkey, list)
  integration_status_rows_deleted = 0
  if jobs_failed == 0 and cids_failed == 0:
    integration_status_rows_deleted = _sweep_hash(integrations_hkey, dict)

  surviving = owner.chainstore_hgetall(hkey=cfg_instance_id)
  if isinstance(surviving, dict):
    for key, value in list(surviving.items()):
      if not isinstance(key, str) or not isinstance(value, dict):
        continue
      if key in failed_job_ids:
        continue
      try:
        owner.chainstore_hset(hkey=cfg_instance_id, key=key, value=None)
      except Exception as exc:
        owner.P(f"[PURGE_ALL] failed to tombstone job record {key}: {exc}", color='r')
        errors.append({"job_id": key, "scope": cfg_instance_id, "message": f"{type(exc).__name__}: {exc}"})

  status = "success" if jobs_failed == 0 and cids_failed == 0 else "partial"

  owner._log_audit_event("all_data_purged", {
    "jobs_total": jobs_total,
    "jobs_succeeded": jobs_succeeded,
    "jobs_failed": jobs_failed,
    "jobs_force_purged": jobs_force_purged,
    "cids_deleted": cids_deleted,
    "cids_failed": cids_failed,
    "integration_status_rows_deleted": integration_status_rows_deleted,
  })
  owner.P(
    f"[PURGE_ALL] {jobs_succeeded}/{jobs_total} jobs purged "
    f"({jobs_force_purged} force-wiped), {cids_deleted} CIDs deleted, {cids_failed} CIDs failed, "
    f"{integration_status_rows_deleted} integration status rows deleted."
  )

  return {
    "status": status,
    "jobs_total": jobs_total,
    "jobs_succeeded": jobs_succeeded,
    "jobs_failed": jobs_failed,
    "jobs_force_purged": jobs_force_purged,
    "cids_deleted": cids_deleted,
    "cids_failed": cids_failed,
    "integration_status_rows_deleted": integration_status_rows_deleted,
    "errors": errors,
  }


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
    emit_lifecycle_event(
      owner,
      job_specs,
      event_type="redmesh.job.stopped",
      event_action="stopped",
      event_outcome="success",
      pass_nr=job_specs.get("job_pass"),
    )
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
