from contextlib import ExitStack

from ..constants import (
  JOB_STATUS_FINALIZED,
  JOB_STATUS_RUNNING,
  JOB_STATUS_SCHEDULED_FOR_STOP,
  JOB_STATUS_STOPPED,
  RUN_MODE_CONTINUOUS_MONITORING,
)
from ..model_testing.constants import (
  MODEL_TEST_ERROR_CANCELED_BY_USER,
  is_model_test_job,
  selected_model_test_worker_addr,
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
    workers_map = job_specs.setdefault("workers", {})
    if is_model_test_job(job_specs):
      selected_worker = selected_model_test_worker_addr(job_specs, fallback=getattr(owner, "ee_addr", None))
      if selected_worker:
        workers_map.setdefault(selected_worker, {})
      local_model_worker = getattr(owner, "model_test_jobs", {}).get(job_id)
      if local_model_worker:
        local_model_worker.stop()
        getattr(owner, "model_test_jobs", {}).pop(job_id, None)
    else:
      workers_map.setdefault(owner.ee_addr, {})
    for worker_entry in workers_map.values():
      if not worker_entry.get("finished"):
        worker_entry["finished"] = True
        worker_entry["canceled"] = True
        worker_entry["cancel_requested"] = True
        if is_model_test_job(job_specs):
          worker_entry["error_class"] = MODEL_TEST_ERROR_CANCELED_BY_USER
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
  """Serialize purge with every supported rulebook review mutation for the job."""
  from .rulebook_assessment import _submission_lock, list_rulebook_profiles

  with ExitStack() as stack:
    for profile in sorted(list_rulebook_profiles(), key=lambda item: item["profile_id"]):
      stack.enter_context(_submission_lock(owner, job_id, profile["profile_id"]))
    return _purge_job_locked(owner, job_id)


def _purge_job_locked(owner, job_id: str):
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
  if job_status not in (JOB_STATUS_FINALIZED, JOB_STATUS_STOPPED):
    if workers and any(not w.get("finished") for w in workers.values()):
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

  rulebook_assessments = job_specs.get("rulebook_assessments")
  if isinstance(rulebook_assessments, dict):
    for profile_id, meta in rulebook_assessments.items():
      if isinstance(meta, dict):
        _track(meta.get("artifact_cid"), f"rulebook_assessments[{profile_id}].artifact_cid")
        for hi, historical in enumerate(meta.get("history") or []):
          if isinstance(historical, dict):
            _track(historical.get("artifact_cid"), f"rulebook_assessments[{profile_id}].history[{hi}].artifact_cid")

  submission_hkey = f"{owner.cfg_instance_id}:rulebook_review:submissions"
  submission_key_prefix = f"{job_id}:"
  all_submission_rows = owner.chainstore_hgetall(hkey=submission_hkey) or {}
  formal_submission_cids = set()
  if isinstance(all_submission_rows, dict):
    for key, registry in all_submission_rows.items():
      if not isinstance(key, str) or not key.startswith(submission_key_prefix) or not isinstance(registry, dict):
        continue
      for reference in registry.get("submissions") or []:
        if isinstance(reference, dict) and isinstance(reference.get("cid"), str) and reference.get("cid"):
          formal_submission_cids.add(reference["cid"])
          _track(reference["cid"], f"rulebook_review_submissions[{key}].submissions")
      pending = registry.get("pending")
      if isinstance(pending, dict) and isinstance(pending.get("cid"), str) and pending.get("cid"):
        formal_submission_cids.add(pending["cid"])
        _track(pending["cid"], f"rulebook_review_submissions[{key}].pending")

    other_job_cids = set()
    for key, registry in all_submission_rows.items():
      if not isinstance(key, str) or key.startswith(submission_key_prefix) or not isinstance(registry, dict):
        continue
      for reference in registry.get("submissions") or []:
        if isinstance(reference, dict) and isinstance(reference.get("cid"), str) and reference.get("cid"):
          other_job_cids.add(reference["cid"])
      pending = registry.get("pending")
      if isinstance(pending, dict) and isinstance(pending.get("cid"), str) and pending.get("cid"):
        other_job_cids.add(pending["cid"])
    all_jobs = _job_repo(owner).list_jobs() or {}
    if isinstance(all_jobs, dict):
      for other_job_id, other_payload in all_jobs.items():
        if other_job_id != job_id and isinstance(other_payload, dict):
          other_job_cids.update(_collect_cids_from_raw(other_payload))
    shared_cids = formal_submission_cids & other_job_cids
    if shared_cids:
      owner.P(f"[PURGE] Shared submission CIDs retained: {sorted(shared_cids)}", color='r')
      return {
        "status": "partial",
        "job_id": job_id,
        "cids_deleted": 0,
        "cids_failed": len(shared_cids),
        "cids_total": len(cids),
        "message": "Submission artifacts are referenced by another job; CStore was kept for retry.",
      }

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
      success = artifacts.delete(cid, show_logs=True, raise_on_error=False, purge=True)
      if success and cid in formal_submission_cids:
        try:
          remaining = artifacts.get_json(cid)
        except Exception as exc:
          success = False
          owner.P(f"[PURGE] Could not verify deletion of formal CID {cid}: {exc}", color='r')
        else:
          if remaining is not None:
            success = False
            owner.P(f"[PURGE] Formal CID {cid} remains retrievable after deletion.", color='r')
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
  _job_repo(owner).delete_job_rulebook_reviews(job_id)
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


def _collect_rulebook_submission_cids(payload):
  if not isinstance(payload, dict):
    return set()
  cids = {
    reference.get("cid")
    for reference in payload.get("submissions") or []
    if isinstance(reference, dict) and isinstance(reference.get("cid"), str) and reference.get("cid")
  }
  pending = payload.get("pending")
  if isinstance(pending, dict) and isinstance(pending.get("cid"), str) and pending.get("cid"):
    cids.add(pending["cid"])
  return cids


def _force_purge_job(owner, job_id, raw_payload, errors):
  from .rulebook_assessment import _submission_lock, list_rulebook_profiles

  with ExitStack() as stack:
    for profile in sorted(list_rulebook_profiles(), key=lambda item: item["profile_id"]):
      stack.enter_context(_submission_lock(owner, job_id, profile["profile_id"]))
    return _force_purge_job_locked(owner, job_id, raw_payload, errors)


def _force_purge_job_locked(owner, job_id, raw_payload, errors):
  """
  Best-effort wipe of a job whose record could not be parsed/purged by
  ``stop_and_delete_job``. Returns (cids_deleted, cids_failed).

  Scans the raw payload for ``*_cid`` fields and attempts R1FS deletion.
  Formal submission pointers remain retryable unless their CIDs are verified absent;
  other legacy artifacts retain the existing best-effort force-wipe behavior.
  """
  cids = {c for c in _collect_cids_from_raw(raw_payload) if isinstance(c, str)}
  submission_hkey = f"{owner.cfg_instance_id}:rulebook_review:submissions"
  try:
    submission_rows = owner.chainstore_hgetall(hkey=submission_hkey) or {}
  except Exception as exc:
    submission_rows = {}
    errors.append({"job_id": job_id, "scope": submission_hkey, "message": f"{type(exc).__name__}: {exc}"})
  shared_submission_cids = set()
  job_submission_cids = set()
  if isinstance(submission_rows, dict):
    prefix = f"{job_id}:"
    other_submission_cids = set()
    for key, registry in submission_rows.items():
      if isinstance(key, str) and key.startswith(prefix):
        job_submission_cids.update(_collect_rulebook_submission_cids(registry))
      elif isinstance(key, str):
        other_submission_cids.update(_collect_rulebook_submission_cids(registry))
    shared_submission_cids = job_submission_cids & other_submission_cids
    try:
      all_jobs = _job_repo(owner).list_jobs() or {}
      if isinstance(all_jobs, dict):
        for other_job_id, other_payload in all_jobs.items():
          if other_job_id != job_id and isinstance(other_payload, dict):
            other_submission_cids.update(_collect_cids_from_raw(other_payload))
      shared_submission_cids = job_submission_cids & other_submission_cids
    except Exception as exc:
      errors.append({"job_id": job_id, "scope": owner.cfg_instance_id, "message": f"{type(exc).__name__}: {exc}"})
    cids.update(job_submission_cids - shared_submission_cids)
  cids = sorted(cids)
  cids_deleted = 0
  cids_failed = len(shared_submission_cids)
  if shared_submission_cids:
    errors.append({
      "job_id": job_id,
      "scope": submission_hkey,
      "message": f"retained shared submission CIDs: {sorted(shared_submission_cids)}",
    })
  artifacts = _artifact_repo(owner)
  failed_submission_cids = set(shared_submission_cids)
  for cid in cids:
    try:
      success = artifacts.delete(cid, show_logs=True, raise_on_error=False, purge=True)
      if success and cid in job_submission_cids:
        try:
          success = artifacts.get_json(cid) is None
        except Exception as exc:
          success = False
          errors.append({"job_id": job_id, "scope": "r1fs", "message": f"{type(exc).__name__}: {exc}"})
        if not success:
          failed_submission_cids.add(cid)
      if success:
        cids_deleted += 1
        owner.P(f"[PURGE_ALL_FORCE] Deleted CID {cid} for {job_id}")
      else:
        cids_failed += 1
        if cid in job_submission_cids:
          failed_submission_cids.add(cid)
        owner.P(f"[PURGE_ALL_FORCE] delete returned False for CID {cid} ({job_id})", color='y')
    except Exception as exc:
      cids_failed += 1
      if cid in job_submission_cids:
        failed_submission_cids.add(cid)
      owner.P(f"[PURGE_ALL_FORCE] Failed to delete CID {cid} ({job_id}): {exc}", color='r')
      errors.append({"job_id": job_id, "scope": "r1fs", "message": f"{type(exc).__name__}: {exc}"})

  if failed_submission_cids:
    owner.P(
      f"[PURGE_ALL_FORCE] Retaining CStore rows for {job_id}; formal submission CIDs require retry.",
      color='r',
    )
    return cids_deleted, cids_failed

  cfg_instance_id = owner.cfg_instance_id
  prefix = f"{job_id}:"

  for hkey in (
    f"{cfg_instance_id}:live",
    f"{cfg_instance_id}:triage",
    f"{cfg_instance_id}:triage:audit",
    f"{cfg_instance_id}:rulebook_review",
    f"{cfg_instance_id}:rulebook_review:audit",
    f"{cfg_instance_id}:rulebook_review:submissions",
  ):
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
      if fc_failed:
        failed_job_ids.add(job_id)
      continue

    if not isinstance(result, dict):
      errors.append({"job_id": job_id, "message": f"unexpected non-dict response: {type(result).__name__}"})
      fc_deleted, fc_failed = _force_purge_job(owner, job_id, raw_payload, errors)
      cids_deleted += fc_deleted
      cids_failed += fc_failed
      jobs_failed += 1
      jobs_force_purged += 1
      if fc_failed:
        failed_job_ids.add(job_id)
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
      if fc_failed:
        failed_job_ids.add(job_id)

  cfg_instance_id = owner.cfg_instance_id
  live_hkey = f"{cfg_instance_id}:live"
  triage_hkey = f"{cfg_instance_id}:triage"
  triage_audit_hkey = f"{cfg_instance_id}:triage:audit"
  rulebook_review_hkey = f"{cfg_instance_id}:rulebook_review"
  rulebook_review_audit_hkey = f"{cfg_instance_id}:rulebook_review:audit"
  rulebook_review_submissions_hkey = f"{cfg_instance_id}:rulebook_review:submissions"
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

  def _sweep_submission_hash():
    nonlocal cids_deleted, cids_failed

    rows = owner.chainstore_hgetall(hkey=rulebook_review_submissions_hkey)
    if not isinstance(rows, dict):
      return 0
    protected_cids = set()
    for key, value in rows.items():
      if _job_id_from_compound_key(key) in failed_job_ids:
        protected_cids.update(_collect_rulebook_submission_cids(value))

    rows_deleted = 0
    deletion_results = {}
    artifacts = _artifact_repo(owner)
    for key, value in list(rows.items()):
      job_id_prefix = _job_id_from_compound_key(key)
      if not job_id_prefix or job_id_prefix in failed_job_ids or not isinstance(value, dict):
        continue
      row_cids = _collect_rulebook_submission_cids(value)
      shared_cids = row_cids & protected_cids
      if shared_cids:
        failed_job_ids.add(job_id_prefix)
        cids_failed += len(shared_cids)
        errors.append({
          "job_id": job_id_prefix,
          "scope": rulebook_review_submissions_hkey,
          "message": f"retained orphan registry with shared CIDs: {sorted(shared_cids)}",
        })
        continue

      row_failed = False
      for cid in sorted(row_cids):
        success = deletion_results.get(cid)
        if success is None:
          try:
            success = artifacts.delete(cid, show_logs=True, raise_on_error=False, purge=True)
            if success:
              success = artifacts.get_json(cid) is None
          except Exception as exc:
            success = False
            errors.append({
              "job_id": job_id_prefix,
              "scope": "r1fs",
              "message": f"{type(exc).__name__}: {exc}",
            })
          deletion_results[cid] = success
          if success:
            cids_deleted += 1
          else:
            cids_failed += 1
        if not success:
          row_failed = True
      if row_failed:
        failed_job_ids.add(job_id_prefix)
        errors.append({
          "job_id": job_id_prefix,
          "scope": rulebook_review_submissions_hkey,
          "message": "orphan submission CIDs remain retrievable or could not be deleted",
        })
        continue
      try:
        owner.chainstore_hset(hkey=rulebook_review_submissions_hkey, key=key, value=None)
        rows_deleted += 1
      except Exception as exc:
        errors.append({
          "job_id": job_id_prefix,
          "scope": rulebook_review_submissions_hkey,
          "message": f"{type(exc).__name__}: {exc}",
        })
    return rows_deleted

  _sweep_hash(live_hkey, dict)
  _sweep_hash(triage_hkey, dict)
  _sweep_hash(triage_audit_hkey, list)
  _sweep_hash(rulebook_review_hkey, dict)
  _sweep_hash(rulebook_review_audit_hkey, list)
  _sweep_submission_hash()
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
    if is_model_test_job(job_specs):
      selected_worker = selected_model_test_worker_addr(job_specs, fallback=getattr(owner, "ee_addr", None))
      worker_entry = job_specs.setdefault("workers", {}).setdefault(selected_worker, {})
      worker_entry["cancel_requested"] = True
      worker_entry["error_class"] = MODEL_TEST_ERROR_CANCELED_BY_USER
      worker_entry["model_test_worker_status"] = "cancel_requested"
      job_specs["model_test_summary"] = {
        **dict(job_specs.get("model_test_summary") or {}),
        "overall_status": "cancel_requested",
        "error_class": MODEL_TEST_ERROR_CANCELED_BY_USER,
      }
      local_model_worker = getattr(owner, "model_test_jobs", {}).get(job_id)
      if local_model_worker:
        owner.P(f"Stopping model-test job {job_id} on local worker {selected_worker}.")
        local_model_worker.stop()
      set_job_status(job_specs, JOB_STATUS_SCHEDULED_FOR_STOP)
      owner._emit_timeline_event(job_specs, "cancel_requested", "Model test cancellation requested", actor_type="user")
    else:
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
