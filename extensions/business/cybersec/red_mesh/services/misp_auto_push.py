"""Automatic MISP push when a pass finishes (RM-139).

A dedicated queue, separate from automatic LLM analysis: its own single-thread executor and its own
per-job state, `owner._misp_push_state = {job_id: {"future", "pass_nr", "queue"}}`. It never makes
the finalization loop yield and a terminal job status never cancels it.

Threading: everything here except `_push_worker` runs on the launcher loop thread. The worker only
delivers and returns an outcome; `poll_misp_auto_push` re-reads the job, merges `misp_export` and
writes the record on the loop thread, so the worker never races a loop write. At most one push per
job is in flight and that job's later passes wait in FIFO order, so pass N+1 starts from the record
that already holds pass N's event and updates it instead of creating a second one.

Accepted risk: the queue is not persisted, so a push in flight when the plugin restarts is lost and
the operator re-runs it with the manual export.
"""

import time as _time
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

from ..tenancy.administration import AdministrationDenied
from ..tenancy.execution import binding_from_record
from ..tenancy.ports import TenantStoreError
from . import misp_export as _misp_export
from .event_hooks import emit_export_status_event


# Recorded on the job's `misp_export` as the actor of an automatic push.
SYSTEM_ACTOR = "system:misp_auto_push"


def _executor(owner):
  executor = owner.__dict__.get("_misp_push_executor")
  if executor is None:
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="redmesh-misp-push")
    owner._misp_push_executor = executor
  return executor


def _state(owner):
  state = owner.__dict__.get("_misp_push_state")
  if not isinstance(state, dict):
    state = {}
    owner._misp_push_state = state
  return state


def misp_auto_push_pending(owner, job_id):
  """True while an automatic push for the job is in flight or queued (the manual export waits)."""
  state = owner.__dict__.get("_misp_push_state")
  return isinstance(state, dict) and job_id in state


def _passes_exported(job_specs):
  export = (job_specs or {}).get("misp_export")
  return set((export or {}).get("passes_exported") or []) if isinstance(export, dict) else set()


def enqueue_misp_auto_push(owner, job_specs, pass_nr):
  """Queue one finalized pass for the automatic push, if the effective config wants it now.

  Called on the loop thread once the pass report exists. Gate: MISP enabled and configured, the
  effective `AUTO_EXPORT` (STA override, else the Deeploy block, else true) on, a bound job, and the
  pass not already exported. Never raises and never touches the job: an unreadable override skips
  this pass with a log line only, so finalization is never failed by the push.
  """
  try:
    job_id = job_specs.get("job_id")
    if not job_id or type(pass_nr) is not int or binding_from_record(job_specs) is None:
      # MISP push carries the job's tenant; an unbound job has none to carry.
      return False
    try:
      cfg, sharing_groups = _misp_export._misp_config_and_sharing_groups(owner)
    except Exception:
      owner.P(f"[MISP] Auto push skipped for job {job_id} pass {pass_nr}: integration config unavailable",
              color='y')
      return False
    if not (cfg["ENABLED"] and cfg["MISP_URL"] and cfg["MISP_API_KEY"] and cfg["AUTO_EXPORT"]):
      return False
    if pass_nr in _passes_exported(job_specs):
      return False
    entry = _state(owner).setdefault(job_id, {"future": None, "pass_nr": None, "queue": []})
    if entry["pass_nr"] == pass_nr or any(item["pass_nr"] == pass_nr for item in entry["queue"]):
      return False
    entry["queue"].append({"pass_nr": pass_nr, "cfg": cfg, "sharing_groups": sharing_groups})
    if entry["future"] is None:
      try:
        _start_next(owner, job_id)
      except Exception:
        # Never leave a job queued with nothing running: the manual export would wait forever.
        _state(owner).pop(job_id, None)
        raise
    return True
  except Exception as exc:
    owner.P(f"[MISP] Auto push enqueue failed: {type(exc).__name__}", color='y')
    return False


def _start_next(owner, job_id):
  """Submit the job's next queued pass, from a fresh read of the job; drop the job when idle."""
  state = _state(owner)
  entry = state.get(job_id)
  while entry is not None and entry["queue"]:
    item = entry["queue"].pop(0)
    current = _misp_export._job_repo(owner).get_job(job_id)
    if not isinstance(current, dict) or item["pass_nr"] in _passes_exported(current):
      continue
    entry["pass_nr"] = item["pass_nr"]
    entry["future"] = _executor(owner).submit(
      _push_worker, owner, job_id, item["pass_nr"], deepcopy(current),
      item["cfg"], item["sharing_groups"],
    )
    return
  state.pop(job_id, None)


def _push_worker(owner, job_id, pass_nr, snapshot, cfg, sharing_groups):
  """Executor thread: deliver one pass as the system actor and return the outcome. No admission (no
  request), but the job's own tenant binding and the effective config captured at enqueue. Never
  writes the job record."""
  try:
    return _misp_export.deliver_misp_event(
      owner, job_id, pass_nr, job_specs=snapshot, export_config=cfg, sharing_groups=sharing_groups,
      checked_job=snapshot, snapshot_mode="tenant_bound",
    )
  except AdministrationDenied as exc:
    return {"status": "error", "error": exc.error}
  except TenantStoreError:
    return {"status": "error", "error": "unavailable"}
  except Exception:
    return {"status": "error", "error": "push_failed"}


def poll_misp_auto_push(owner):
  """Merge finished pushes into their jobs and start each job's next queued pass.

  Runs on the loop thread at the very top of maybe_finalize_pass, before its job list read, so a
  loop write later in the same turn starts from the merged record. Never yields and never cancels.
  """
  state = owner.__dict__.get("_misp_push_state")
  if not isinstance(state, dict) or not state:
    return
  for job_id in list(state):
    entry = state.get(job_id)
    future = entry.get("future") if isinstance(entry, dict) else None
    if future is not None and not future.done():
      continue
    if future is None:
      # Nothing running for this job (a start that raised): start its next pass, or drop it.
      _start_next_or_drop(owner, job_id)
      continue
    if future.cancelled():
      outcome = {"status": "error", "error": "push_failed"}
    else:
      try:
        outcome = future.result()
      except Exception:
        outcome = {"status": "error", "error": "push_failed"}
    pass_nr = entry["pass_nr"]
    entry["future"] = entry["pass_nr"] = None
    try:
      _merge(owner, job_id, pass_nr, outcome)
    except Exception as exc:
      owner.P(f"[MISP] Auto push merge failed for job {job_id}: {type(exc).__name__}", color='y')
    _start_next_or_drop(owner, job_id)


def _start_next_or_drop(owner, job_id):
  try:
    _start_next(owner, job_id)
  except Exception as exc:
    _state(owner).pop(job_id, None)
    owner.P(f"[MISP] Auto push for job {job_id} stopped: {type(exc).__name__}", color='y')


def _merge(owner, job_id, pass_nr, outcome):
  """Record one outcome on the job as it is now. A failure is recorded and never retried, and it
  never touches the job's status."""
  current = _misp_export._job_repo(owner).get_job(job_id)
  if not isinstance(current, dict):
    return
  merged = dict(current.get("misp_export") or {})
  passes = set(merged.get("passes_exported") or [])
  ok = isinstance(outcome, dict) and outcome.get("status") == "ok"
  if ok:
    meta = outcome.get("meta") or {}
    merged.update(meta)
    passes |= set(meta.get("passes_exported") or [])
    error = None
  else:
    error = outcome.get("error") if isinstance(outcome, dict) else None
    error = error if isinstance(error, str) and error else "push_failed"
  merged.update({
    "passes_exported": sorted(passes),
    "status": "completed" if ok else "failed",
    "last_error": error,
    "trigger": "auto",
    "actor": SYSTEM_ACTOR,
    "last_attempt_pass": pass_nr,
    "last_attempt_at": _time.time(),
  })
  current["misp_export"] = merged
  try:
    # Directly, not through the finalization wrappers: those refuse a terminal job, and a push
    # usually lands after the job finished.
    emit_export_status_event(
      owner, current, adapter_type="misp", status="completed" if ok else "failed", pass_nr=pass_nr,
      destination_label="misp",
      artifact_refs=({"misp_event_uuid": merged.get("event_uuid"), "misp_event_id": merged.get("event_id")}
                     if ok else None),
    )
  except Exception as exc:
    owner.P(f"[MISP] Auto push status event failed for job {job_id}: {type(exc).__name__}", color='y')
  _misp_export._write_job_record(owner, job_id, current, context="misp_auto_export")
  if not ok:
    owner.P(f"[MISP] Auto push failed for job {job_id} pass {pass_nr}: {error}", color='y')


def shutdown_misp_auto_push(owner):
  """Plugin close: cancel what is queued and drop the state (pushes in flight are lost)."""
  owner._misp_push_state = None
  executor = owner.__dict__.get("_misp_push_executor")
  if executor is not None:
    try:
      executor.shutdown(wait=False, cancel_futures=True)
    except TypeError:
      executor.shutdown(wait=False)
    owner._misp_push_executor = None
