"""Local disk checkpoints of network workers (RM-201).

A worker saves its partial state as plain pickle under the plugin data folder so a node restart
resumes the pass instead of scanning it again. Every file goes through the framework
`diskapi_*_pickle_*_data` helpers (`save_pickle` writes atomically). `save_pickle` swallows errors,
so `save` confirms the file exists. Plain functions taking `owner`, like the other services.
"""
import os
import re
from math import isfinite

from .config import resolve_config_block
from .reconciliation import _safe_bool, _safe_float

CHECKPOINT_VERSION = 1
CHECKPOINT_SUBFOLDER = "plugin_data/redmesh_ckpt"

# Exact payload schema (version 1). `metrics` is `vars(metrics)`. No `reference_dump` (the owner
# never sets `dynamic_reference_cache`) and never the worker object (owner, thread, Event, SQLite).
PAYLOAD_FIELDS = (
  "version", "job_id", "pass_nr", "ee_addr", "scan_type", "start_port", "end_port",
  "target_ports", "config_cid", "local_id_prefix", "local_worker_id", "initial_ports", "state",
  "metrics", "ics_detected", "saved_at",
)

DEFAULT_WORKER_CHECKPOINT_CONFIG = {
  "ENABLED": True,
  "MIN_INTERVAL": 30,
  "PORT_EVERY": 250,
  "GC_INTERVAL": 600,
  "MAX_AGE": 172800,
}

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")


def get_worker_checkpoint_config(owner):
  """Return normalized WORKER_CHECKPOINT config."""
  def _normalize(merged, defaults):
    out = {"ENABLED": _safe_bool(merged.get("ENABLED"), defaults["ENABLED"])}
    for key in ("MIN_INTERVAL", "PORT_EVERY", "GC_INTERVAL", "MAX_AGE"):
      value = _safe_float(merged.get(key), None)
      # A non-finite or non-positive value falls back to the default.
      if value is None or not isfinite(value) or value <= 0:
        out[key] = defaults[key]
      else:
        out[key] = int(value) if key == "PORT_EVERY" else value
    return out

  return resolve_config_block(
    owner, "WORKER_CHECKPOINT", DEFAULT_WORKER_CHECKPOINT_CONFIG, normalizer=_normalize,
  )


def _valid_name(value):
  return isinstance(value, str) and _SAFE_NAME.fullmatch(value) is not None


def _subfolder(job_id):
  return f"{CHECKPOINT_SUBFOLDER}/{job_id}"


def _root_dir(owner):
  return os.path.join(
    owner.get_data_folder(), owner._get_instance_data_subfolder(), CHECKPOINT_SUBFOLDER,
  )


def _filename(pass_nr, prefix):
  return f"{int(pass_nr)}_{prefix}.pkl"


def _stamp(path):
  try:
    st = os.stat(path)
  except OSError:
    return None
  return (st.st_ino, st.st_mtime_ns, st.st_size)


def save(owner, job_id, pass_nr, prefix, payload):
  """Save one worker payload. Return True only when the file exists afterwards."""
  if not _valid_name(job_id) or not _valid_name(str(prefix)):
    return False
  try:
    filename = _filename(pass_nr, prefix)
    path = os.path.join(_root_dir(owner), job_id, filename)
    # save_pickle swallows errors; keep the last good file and detect a write that did not land.
    before = _stamp(path)
    owner.diskapi_save_pickle_to_data(
      payload, filename, subfolder=_subfolder(job_id), verbose=False,
    )
    after = _stamp(path)
    return after is not None and after != before
  except Exception:
    return False


def load_all(owner, job_id, pass_nr):
  """Return `{prefix: payload}` for one pass. Unreadable or wrong-version files are deleted."""
  if not _valid_name(job_id):
    return {}
  job_dir = os.path.join(_root_dir(owner), job_id)
  try:
    lead = f"{int(pass_nr)}_"
    names = [e.name for e in os.scandir(job_dir)
             if e.is_file() and e.name.startswith(lead) and e.name.endswith(".pkl")]
  except (OSError, TypeError, ValueError):
    return {}
  result = {}
  for name in sorted(names):
    prefix = name[len(lead):-len(".pkl")]
    try:
      payload = owner.diskapi_load_pickle_from_data(
        name, subfolder=_subfolder(job_id), verbose=False,
      )
    except Exception:
      payload = None
    if isinstance(payload, dict) and payload.get("version") == CHECKPOINT_VERSION:
      result[prefix] = payload
    else:
      owner.diskapi_delete_file(os.path.join(job_dir, name))
  return result


def delete_job(owner, job_id):
  """Remove every checkpoint of one job."""
  if _valid_name(job_id):
    owner.diskapi_delete_directory(os.path.join(_root_dir(owner), job_id))


def delete_pass(owner, job_id, pass_nr):
  """Remove the checkpoints of one pass of a job."""
  if not _valid_name(job_id):
    return
  job_dir = os.path.join(_root_dir(owner), job_id)
  try:
    lead = f"{int(pass_nr)}_"
    names = [e.name for e in os.scandir(job_dir) if e.is_file() and e.name.startswith(lead)]
  except (OSError, TypeError, ValueError):
    return
  for name in names:
    owner.diskapi_delete_file(os.path.join(job_dir, name))


def list_jobs(owner):
  """Return the job ids that have a checkpoint folder (no diskapi list helper exists)."""
  try:
    return sorted(e.name for e in os.scandir(_root_dir(owner)) if e.is_dir() and _valid_name(e.name))
  except OSError:
    return []
