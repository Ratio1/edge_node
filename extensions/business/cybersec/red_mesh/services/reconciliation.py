from ..models import WorkerProgress
from .config import resolve_config_block

DEFAULT_LIVE_HSYNC_INTERVAL_SECONDS = 90.0

DEFAULT_DISTRIBUTED_JOB_RECONCILIATION_CONFIG = {
  "STARTUP_TIMEOUT": 45.0,
  "STALE_TIMEOUT": 120.0,
  "STALE_GRACE": 30.0,
  "MAX_REANNOUNCE_ATTEMPTS": 3,
  "LIVE_HSYNC_ENABLED": False,
  "LIVE_HSYNC_INTERVAL_SECONDS": DEFAULT_LIVE_HSYNC_INTERVAL_SECONDS,
  "LIVE_HSYNC_TIMEOUT": 3.0,
  "LIVE_HSYNC_MAX_PEERS_PER_TICK": 6,
  "LIVE_HSYNC_FALLBACK_DEFAULT_PEERS": True,
}


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


def _safe_bool(value, default=False):
  if isinstance(value, bool):
    return value
  if value is None:
    return default
  if isinstance(value, str):
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
      return True
    if normalized in {"0", "false", "no", "off", ""}:
      return False
    return default
  return bool(value)


def get_distributed_job_reconciliation_config(owner):
  """Return normalized distributed-job reconciliation config."""
  def _normalize(merged, defaults):
    startup_timeout = _safe_float(
      merged.get("STARTUP_TIMEOUT"),
      defaults["STARTUP_TIMEOUT"],
    )
    if startup_timeout is None or startup_timeout <= 0:
      startup_timeout = defaults["STARTUP_TIMEOUT"]

    stale_timeout = _safe_float(
      merged.get("STALE_TIMEOUT"),
      defaults["STALE_TIMEOUT"],
    )
    if stale_timeout is None or stale_timeout <= 0:
      stale_timeout = defaults["STALE_TIMEOUT"]

    stale_grace = _safe_float(
      merged.get("STALE_GRACE"),
      defaults["STALE_GRACE"],
    )
    if stale_grace is None or stale_grace < 0:
      stale_grace = defaults["STALE_GRACE"]

    max_reannounce_attempts = _safe_int(
      merged.get("MAX_REANNOUNCE_ATTEMPTS"),
      defaults["MAX_REANNOUNCE_ATTEMPTS"],
    )
    if max_reannounce_attempts < 0:
      max_reannounce_attempts = defaults["MAX_REANNOUNCE_ATTEMPTS"]

    live_hsync_interval = _safe_float(
      merged.get("LIVE_HSYNC_INTERVAL_SECONDS"),
      defaults["LIVE_HSYNC_INTERVAL_SECONDS"],
    )
    if live_hsync_interval is None or live_hsync_interval <= 0:
      live_hsync_interval = defaults["LIVE_HSYNC_INTERVAL_SECONDS"]

    live_hsync_timeout = _safe_float(
      merged.get("LIVE_HSYNC_TIMEOUT"),
      defaults["LIVE_HSYNC_TIMEOUT"],
    )
    if live_hsync_timeout is None or live_hsync_timeout <= 0:
      live_hsync_timeout = defaults["LIVE_HSYNC_TIMEOUT"]

    live_hsync_max_peers = _safe_int(
      merged.get("LIVE_HSYNC_MAX_PEERS_PER_TICK"),
      defaults["LIVE_HSYNC_MAX_PEERS_PER_TICK"],
    )
    if live_hsync_max_peers <= 0:
      live_hsync_max_peers = defaults["LIVE_HSYNC_MAX_PEERS_PER_TICK"]

    return {
      "STARTUP_TIMEOUT": startup_timeout,
      "STALE_TIMEOUT": stale_timeout,
      "STALE_GRACE": stale_grace,
      "MAX_REANNOUNCE_ATTEMPTS": max_reannounce_attempts,
      "LIVE_HSYNC_ENABLED": _safe_bool(
        merged.get("LIVE_HSYNC_ENABLED"),
        defaults["LIVE_HSYNC_ENABLED"],
      ),
      "LIVE_HSYNC_INTERVAL_SECONDS": live_hsync_interval,
      "LIVE_HSYNC_TIMEOUT": live_hsync_timeout,
      "LIVE_HSYNC_MAX_PEERS_PER_TICK": live_hsync_max_peers,
      "LIVE_HSYNC_FALLBACK_DEFAULT_PEERS": _safe_bool(
        merged.get("LIVE_HSYNC_FALLBACK_DEFAULT_PEERS"),
        defaults["LIVE_HSYNC_FALLBACK_DEFAULT_PEERS"],
      ),
    }

  return resolve_config_block(
    owner,
    "DISTRIBUTED_JOB_RECONCILIATION",
    DEFAULT_DISTRIBUTED_JOB_RECONCILIATION_CONFIG,
    normalizer=_normalize,
  )


def _matched_live_progress(job_id, worker_addr, pass_nr, assignment_revision, live_payloads):
  key = f"{job_id}:{worker_addr}"
  payload = (live_payloads or {}).get(key)
  if not isinstance(payload, dict):
    return None, None
  try:
    live = WorkerProgress.from_dict(payload)
  except (KeyError, TypeError, ValueError):
    return None, "malformed_live"
  if live.job_id != job_id:
    return None, "job_mismatch"
  if live.pass_nr != pass_nr:
    return None, "pass_mismatch"
  if live.assignment_revision_seen != assignment_revision:
    return None, "revision_mismatch"
  return live, None


def _job_repo(owner):
  getter = getattr(owner, "_get_job_state_repository", None)
  if callable(getter):
    return getter()
  return getattr(owner, "_job_state_repository", None)


def _stats_inc(stats, key, amount=1):
  if isinstance(stats, dict):
    stats[key] = int(stats.get(key, 0) or 0) + amount


def _stats_inc_once(stats, key, identity):
  if not isinstance(stats, dict):
    return
  seen_key = f"_seen_{key}"
  seen = stats.setdefault(seen_key, set())
  if identity in seen:
    return
  seen.add(identity)
  _stats_inc(stats, key)


def reconcile_workers_from_live(owner, job_id, *, live_payloads=None, now=None, stats=None):
  """
  Repair launcher-owned durable worker completion state from ``:live`` rows.

  This helper intentionally copies only the terminal fields required for
  finalization. Runtime progress stays in the worker-owned live namespace.
  """
  repo = _job_repo(owner)
  if repo is None:
    return False

  raw = repo.get_job(job_id)
  if not isinstance(raw, dict) or raw.get("job_cid"):
    return False

  normalizer = getattr(owner, "_normalize_job_record", None)
  if callable(normalizer):
    normalized_key, job_specs = normalizer(job_id, raw)
  else:
    normalized_key, job_specs = job_id, raw
  if normalized_key is None or not isinstance(job_specs, dict):
    return False
  if job_specs.get("job_cid"):
    return False
  if job_specs.get("launcher") != getattr(owner, "ee_addr", None):
    return False

  workers = job_specs.get("workers") or {}
  if not isinstance(workers, dict) or not workers:
    return False

  if live_payloads is None:
    live_payloads = repo.list_live_progress() or {}

  pass_nr = _safe_int(job_specs.get("job_pass", 1), 1)
  changed_workers = []

  for worker_addr, worker_entry in workers.items():
    if not isinstance(worker_entry, dict):
      continue
    if worker_entry.get("canceled"):
      continue
    if worker_entry.get("terminal_reason") == "unreachable":
      continue
    if worker_entry.get("finished") and worker_entry.get("report_cid"):
      continue

    assignment_revision = _safe_int(worker_entry.get("assignment_revision", 1), 1)
    live, ignored_reason = _matched_live_progress(
      job_specs.get("job_id"),
      worker_addr,
      pass_nr,
      assignment_revision,
      live_payloads,
    )
    if live is None:
      if ignored_reason == "pass_mismatch":
        _stats_inc_once(stats, "ignored_stale_pass", (job_id, worker_addr))
      elif ignored_reason == "revision_mismatch":
        _stats_inc_once(stats, "ignored_revision", (job_id, worker_addr))
      continue
    if not live.finished:
      continue
    if not live.report_cid:
      _stats_inc_once(stats, "ignored_no_report_cid", (job_id, worker_addr))
      continue

    if not worker_entry.get("report_cid"):
      worker_entry["report_cid"] = live.report_cid
    worker_entry["finished"] = True
    worker_entry["result"] = None
    changed_workers.append(worker_addr)

  if not changed_workers:
    return False

  emit = getattr(owner, "_emit_timeline_event", None)
  if callable(emit):
    emit(
      job_specs,
      "reconciled",
      "Reconciled missing worker completion from live state",
      actor_type="system",
      meta={
        "workers": changed_workers,
        "pass_nr": pass_nr,
        "source": "live",
      },
    )

  writer = getattr(owner, "_write_job_record", None)
  if callable(writer):
    writer(normalized_key, job_specs, context="reconcile_from_live")
  else:
    repo.put_job(normalized_key, job_specs)
  _stats_inc(stats, "changed_workers", len(changed_workers))
  return True


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
  stale_timeout = get_distributed_job_reconciliation_config(owner)["STALE_TIMEOUT"]
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
      if ignored_reason == "malformed_live" and hasattr(owner, "P"):
        owner.P(
          f"[LIVE] Ignoring malformed live payload for job_id={job_id} worker={worker_addr}",
          color='y',
        )

    reconciled[worker_addr] = payload
  return reconciled
