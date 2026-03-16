from ..models import WorkerProgress


def _safe_int(value, default):
  try:
    return int(value)
  except (TypeError, ValueError):
    return default


def _safe_float(value, default=None):
  try:
    return float(value)
  except (TypeError, ValueError):
    return default


def _distributed_stale_timeout(owner):
  timeout = getattr(owner, "cfg_distributed_stale_timeout", None)
  if timeout is None:
    config = getattr(owner, "CONFIG", None)
    if isinstance(config, dict):
      timeout = config.get("DISTRIBUTED_STALE_TIMEOUT")
  timeout = _safe_float(timeout, 120.0)
  if timeout is None or timeout <= 0:
    return 120.0
  return timeout


def _matched_live_progress(job_id, worker_addr, pass_nr, assignment_revision, live_payloads):
  key = f"{job_id}:{worker_addr}"
  payload = (live_payloads or {}).get(key)
  if not isinstance(payload, dict):
    return None, None
  live = WorkerProgress.from_dict(payload)
  if live.job_id != job_id:
    return None, "job_mismatch"
  if live.pass_nr != pass_nr:
    return None, "pass_mismatch"
  if live.assignment_revision_seen != assignment_revision:
    return None, "revision_mismatch"
  return live, None


def reconcile_job_workers(owner, job_specs, *, live_payloads=None, now=None):
  """
  Merge launcher-owned worker assignments with worker-owned :live state.

  Returned worker entries always include launcher assignment metadata and a
  derived ``worker_state``. Matched ``:live`` payloads are folded into the
  same per-worker dict so API consumers and launcher logic interpret state
  through one canonical path.
  """
  if not isinstance(job_specs, dict):
    return {}

  job_id = job_specs.get("job_id")
  pass_nr = _safe_int(job_specs.get("job_pass", 1), 1)
  workers = job_specs.get("workers") or {}
  live_payloads = live_payloads or {}
  stale_timeout = _distributed_stale_timeout(owner)
  if now is None:
    time_fn = getattr(owner, "time", None)
    if callable(time_fn):
      now = _safe_float(time_fn(), None)

  reconciled = {}
  for worker_addr, raw_worker_entry in workers.items():
    worker_entry = dict(raw_worker_entry or {})
    assignment_revision = _safe_int(worker_entry.get("assignment_revision", 1), 1)
    live, ignored_reason = _matched_live_progress(
      job_id,
      worker_addr,
      pass_nr,
      assignment_revision,
      live_payloads,
    )

    state = "unseen"
    if worker_entry.get("terminal_reason") == "unreachable":
      state = "unreachable"
    elif worker_entry.get("finished"):
      state = "failed" if worker_entry.get("error") else "finished"
    elif live is not None:
      if live.error:
        state = "failed"
      elif live.finished:
        state = "finished"
      else:
        last_seen_at = _safe_float(live.last_seen_at, _safe_float(live.updated_at, None))
        if now is not None and last_seen_at is not None and now - last_seen_at > stale_timeout:
          state = "stale"
        elif live.started_at:
          state = "started" if _safe_float(live.progress, 0.0) <= 0 else "active"

    payload = dict(worker_entry)
    payload["worker_addr"] = worker_addr
    payload["pass_nr"] = pass_nr
    payload["assignment_revision"] = assignment_revision
    payload["worker_state"] = state

    if live is not None:
      payload.update(live.to_dict())
    elif ignored_reason:
      payload["ignored_live_reason"] = ignored_reason

    reconciled[worker_addr] = payload
  return reconciled
