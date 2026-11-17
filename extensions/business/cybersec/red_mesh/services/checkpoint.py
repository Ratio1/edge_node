"""Local disk checkpoints of network workers (RM-201).

A worker saves its partial state as plain pickle under the plugin data folder so a node restart
resumes the pass instead of scanning it again. Every file goes through the framework
`diskapi_*_pickle_*_data` helpers (`save_pickle` writes atomically). `save_pickle` swallows errors,
so `save` confirms the file exists. Plain functions taking `owner`, like the other services.
"""
import os
import pickle
import re
import time
from collections import deque
from math import isfinite

from .config import resolve_config_block
from .reconciliation import _safe_bool, _safe_float
from .state_machine import is_terminal_job_status

CHECKPOINT_VERSION = 1
CHECKPOINT_SUBFOLDER = "plugin_data/redmesh_ckpt"
MAX_FILE_BYTES = 32 * 1024 * 1024  # a larger file is treated as corrupt

# Exact payload schema (version 1). `metrics` is `vars(metrics)`. No `reference_dump` (the owner
# never sets `dynamic_reference_cache`) and never the worker object (owner, thread, Event, SQLite).
PAYLOAD_FIELDS = (
  "version", "job_id", "pass_nr", "ee_addr", "scan_type", "start_port", "end_port",
  "target_ports", "config_cid", "local_id_prefix", "local_worker_id", "initial_ports", "state",
  "metrics", "ics_detected", "saved_at",
)

# Final marker (version 1): plain types only, no findings and no credentials. The first group is the
# republish identity, stamped by `save_final_marker`; the second is copied from the terminal :live row.
# `load_final_marker` returns only these keys and rejects a value of another type.
_NUM = (int, float)
FINAL_TYPES = {
  "version": int, "job_id": str, "pass_nr": int, "ee_addr": str, "report_cid": str, "done": bool, "saved_at": _NUM,
  "assignment_revision_seen": int, "ports_scanned": int, "ports_total": int, "open_ports_found": list,
  "completed_tests": list, "started_at": _NUM, "first_seen_live_at": _NUM, "live_metrics": dict, "threads": dict,
  "scan_type": str, "phase_index": int, "total_phases": int,
}
FINAL_FIELDS = tuple(FINAL_TYPES)
# Fields without a default in WorkerProgress that the republish takes from the marker.
FINAL_REQUIRED = ("assignment_revision_seen", "ports_scanned", "ports_total", "open_ports_found", "completed_tests")
MAX_CID_LEN = 256

DEFAULT_WORKER_CHECKPOINT_CONFIG = {
  "ENABLED": True,
  "MIN_INTERVAL": 30,
  "PORT_EVERY": 250,
  "GC_INTERVAL": 600,
  "MAX_AGE": 172800,
}

_SAFE_NAME = re.compile(r"^[A-Za-z0-9_-]+$")
_PASS_FILE = re.compile(r"^(\d+)_[A-Za-z0-9_-]+\.pkl$")
_FINAL_FILE = re.compile(r"^final_(\d+)\.pkl$")
# `save_pickle` makes its temp file as `mkstemp(prefix=<filename> + ".", suffix=".tmp")` beside the target.
_TMP_FILE = re.compile(r"^(?:\d+_[A-Za-z0-9_-]+|final_\d+)\.pkl\..+\.tmp$")
TMP_MIN_AGE = 300  # seconds; a younger temp file may belong to a save in progress

# Globals a worker state may legitimately pickle. A state of dicts, lists, tuples, str, int, float,
# bool, None and bytes needs none: those use native opcodes. Callables such as `str`, `list` or
# `dict` are not allowed: through REDUCE they can chain into memo-shared amplification.
_ALLOWED_GLOBALS = frozenset(
  [("builtins", "set"), ("builtins", "frozenset"), ("collections", "OrderedDict"), ("collections", "deque")]
  + [("datetime", n) for n in ("datetime", "date", "time", "timedelta", "timezone")]
)
MAX_NODES = 1_000_000  # container and leaf nodes of one payload, shared references counted each time


class _RestrictedUnpickler(pickle.Unpickler):
  def find_class(self, module, name):
    if (module, name) in _ALLOWED_GLOBALS:
      return super().find_class(module, name)
    raise pickle.UnpicklingError(f"checkpoint refuses global {module}.{name}")


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
        out[key] = max(1, int(value)) if key == "PORT_EVERY" else value
    return out

  return resolve_config_block(
    owner, "WORKER_CHECKPOINT", DEFAULT_WORKER_CHECKPOINT_CONFIG, normalizer=_normalize,
  )


def _within_node_bound(obj):
  """Walk `obj` without de-duplicating shared references; False past `MAX_NODES`."""
  stack, count = [obj], 0
  while stack:
    item = stack.pop()
    count += 1
    if count > MAX_NODES:
      return False
    if isinstance(item, dict):
      stack.extend(item.keys())
      stack.extend(item.values())
    elif isinstance(item, (list, tuple, set, frozenset, deque)):
      stack.extend(item)
  return True


def _valid_name(value):
  return isinstance(value, str) and _SAFE_NAME.fullmatch(value) is not None


def _subfolder(job_id):
  return f"{CHECKPOINT_SUBFOLDER}/{job_id}"


def _root_dir(owner):
  return os.path.join(
    owner.get_data_folder(), owner._get_instance_data_subfolder(), CHECKPOINT_SUBFOLDER,
  )


def _job_dir(owner, job_id):
  """Folder of one job, or None for a bad name or when the checkpoint root or the folder is a symlink."""
  if not _valid_name(job_id):
    return None
  root = _root_dir(owner)
  path = os.path.join(root, job_id)
  return None if os.path.islink(root) or os.path.islink(path) else path


def _filename(pass_nr, prefix=None):
  """`<pass>_<prefix>.pkl` for a worker payload, `final_<pass>.pkl` for the final marker."""
  return f"{int(pass_nr)}_{prefix}.pkl" if prefix is not None else f"final_{int(pass_nr)}.pkl"


def _stamp(path):
  try:
    st = os.stat(path)
  except OSError:
    return None
  return (st.st_ino, st.st_mtime_ns, st.st_size)


def _write(owner, job_id, payload, pass_nr, prefix=None):
  """Write one file through the diskapi. True only when it exists afterwards and differs from before."""
  try:
    filename = _filename(pass_nr, prefix)
    job_dir = _job_dir(owner, job_id)
    if job_dir is None:
      return False
    path = os.path.join(job_dir, filename)
    # save_pickle swallows errors; keep the last good file and detect a write that did not land.
    before = _stamp(path)
    owner.diskapi_save_pickle_to_data(payload, filename, subfolder=_subfolder(job_id), verbose=False)
    after = _stamp(path)
    return after is not None and after != before
  except Exception:
    return False


def save(owner, job_id, pass_nr, prefix, payload):
  """Save one worker payload. Return True only when the file exists afterwards."""
  if not _valid_name(job_id) or not _valid_name(str(prefix)):
    return False
  return _write(owner, job_id, payload, pass_nr, prefix)


def _read_file(path):
  """Unpickle one checkpoint file through the restricted unpickler. None when it is unreadable, refused,
  oversized or over the node bound. Never follows a symlink."""
  try:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as fh:
      if os.fstat(fh.fileno()).st_size > MAX_FILE_BYTES:
        return None
      payload = _RestrictedUnpickler(fh).load()
      return payload if _within_node_bound(payload) else None
  except Exception:
    return None


def load_all(owner, job_id, pass_nr):
  """Return `{prefix: payload}` for one pass. Unreadable, refused, oversized, over-bound or wrong-version files
  are deleted. A symlinked job folder or file is skipped, never followed."""
  job_dir = _job_dir(owner, job_id)
  if job_dir is None:
    return {}
  try:
    lead = f"{int(pass_nr)}_"
    names = [e.name for e in os.scandir(job_dir)
             if e.is_file(follow_symlinks=False) and e.name.startswith(lead) and e.name.endswith(".pkl")]
  except (OSError, TypeError, ValueError):
    return {}
  result = {}
  for name in sorted(names):
    prefix = name[len(lead):-len(".pkl")]
    payload = _read_file(os.path.join(job_dir, name))
    if isinstance(payload, dict) and payload.get("version") == CHECKPOINT_VERSION:
      result[prefix] = payload
    else:
      owner.diskapi_delete_file(os.path.join(job_dir, name))
  return result


def delete_job(owner, job_id):
  """Remove every checkpoint of one job."""
  job_dir = _job_dir(owner, job_id)
  if job_dir is not None:
    owner.diskapi_delete_directory(job_dir)


def delete_pass(owner, job_id, pass_nr):
  """Remove the checkpoints of one pass of a job."""
  job_dir = _job_dir(owner, job_id)
  if job_dir is None:
    return
  try:
    lead = f"{int(pass_nr)}_"
    names = [e.name for e in os.scandir(job_dir)
             if e.is_file(follow_symlinks=False) and e.name.startswith(lead)]
  except (OSError, TypeError, ValueError):
    return
  for name in names:
    owner.diskapi_delete_file(os.path.join(job_dir, name))


def list_jobs(owner):
  """Return the job ids that have a checkpoint folder (no diskapi list helper exists)."""
  try:
    if os.path.islink(_root_dir(owner)):
      return []
    return sorted(e.name for e in os.scandir(_root_dir(owner)) if e.is_dir(follow_symlinks=False) and _valid_name(e.name))
  except OSError:
    return []


def save_final_marker(owner, job_id, pass_nr, data):
  """Save the final marker of one (job, pass): the terminal :live row summary in `data` plus the identity
  fields. Return True only when the file exists afterwards."""
  if not _valid_name(job_id):
    return False
  try:
    marker = {k: v for k, v in data.items() if k in FINAL_FIELDS}
    marker.update(version=CHECKPOINT_VERSION, job_id=job_id, pass_nr=int(pass_nr), ee_addr=owner.ee_addr,
                  done=True, saved_at=time.time())
    return _write(owner, job_id, marker, pass_nr)
  except Exception:
    return False


def delete_final_marker(owner, job_id, pass_nr):
  """Remove the final marker of one (job, pass), if any."""
  job_dir = _job_dir(owner, job_id)
  if job_dir is None:
    return
  try:
    path = os.path.join(job_dir, _filename(pass_nr))
    if os.path.isfile(path) and not os.path.islink(path):
      owner.diskapi_delete_file(path)
  except (OSError, TypeError, ValueError):
    return


def load_final_marker(owner, job_id, pass_nr):
  """Return the final marker of one (job, pass) for this node, or None. A missing file is None. An unreadable
  marker, one whose job, pass or node does not match, or one with a field of the wrong type is deleted.
  Only `FINAL_FIELDS` keys are returned. Symlinks are never followed."""
  job_dir = _job_dir(owner, job_id)
  if job_dir is None:
    return None
  try:
    path = os.path.join(job_dir, _filename(pass_nr))
    if not os.path.lexists(path):
      return None
    pass_nr = int(pass_nr)
  except (OSError, TypeError, ValueError):
    return None
  raw = _read_file(path)
  marker = {k: v for k, v in raw.items() if k in FINAL_TYPES} if isinstance(raw, dict) else {}
  if (marker.get("version") == CHECKPOINT_VERSION and marker.get("done") is True
      and marker.get("job_id") == job_id and marker.get("pass_nr") == pass_nr
      and marker.get("ee_addr") == owner.ee_addr
      and all(k in marker for k in FINAL_REQUIRED)
      and all(isinstance(v, FINAL_TYPES[k]) and (FINAL_TYPES[k] is bool or not isinstance(v, bool))
              for k, v in marker.items())
      and 0 < len(marker.get("report_cid", "")) <= MAX_CID_LEN
      and all(type(p) is int for p in marker.get("open_ports_found", ()))
      and all(isinstance(t, str) for t in marker.get("completed_tests", ()))):
    return marker
  delete_final_marker(owner, job_id, pass_nr)
  return None


def _job_files(job_dir):
  """Known checkpoint files of one job folder as `(name, kind, pass_nr, stat)`; symlinks and strangers are skipped."""
  out = []
  for e in os.scandir(job_dir):
    if not e.is_file(follow_symlinks=False):
      continue
    for kind, pattern in (("pass", _PASS_FILE), ("final", _FINAL_FILE), ("tmp", _TMP_FILE)):
      m = pattern.match(e.name)
      if m:
        out.append((e.name, kind, int(m.group(1)) if kind != "tmp" else None, e.stat(follow_symlinks=False)))
        break
  return out


def cleanup(owner, get_job, missing_before, max_age, now=None):
  """One GC pass over every job folder. Return `(files, bytes, missing_now)`. Nothing is unpickled.

  `get_job(job_id)` returns the normalized job record, None when CStore has none, and raises for a record
  it cannot read (that folder is then left alone). `missing_before` is the set of job ids that were missing
  on the previous tick; pass back `missing_now` next time. The whole folder goes when the job was missing
  on two consecutive ticks, is terminal, is not a network job (graybox or model test, by its record), or
  this worker is `finished`. Otherwise a file goes when its pass is below the job's `job_pass` (a lagging
  replica never deletes a newer pass) or it is older than `max_age`. A stray temp file older than
  `TMP_MIN_AGE` goes too. Markers follow the same rules as pass files.
  """
  now = time.time() if now is None else now
  files = size = 0
  missing_now = set()

  def remove(path, st):
    nonlocal files, size
    try:
      owner.diskapi_delete_file(path)
    except Exception:
      pass
    if not os.path.lexists(path):
      files += 1
      size += st.st_size

  for job_id in list_jobs(owner):
    job_dir = os.path.join(_root_dir(owner), job_id)
    try:
      entries = _job_files(job_dir)
      job = get_job(job_id)
      job_pass = 0
      if job is None:
        missing_now.add(job_id)
        whole = job_id in missing_before
      else:
        worker = (job.get("workers") or {}).get(owner.ee_addr)
        whole = (is_terminal_job_status(job.get("job_status")) or job.get("job_type") == "model_test"
                 or job.get("scan_type") == "webapp" or (isinstance(worker, dict) and bool(worker.get("finished"))))
        job_pass = job.get("job_pass") if type(job.get("job_pass")) is int else 0
    except Exception:
      continue
    for name, kind, pass_nr, st in entries:
      old = now - st.st_mtime > (TMP_MIN_AGE if kind == "tmp" else max_age)
      if whole or old or (kind != "tmp" and pass_nr < job_pass):
        remove(os.path.join(job_dir, name), st)
    if whole:
      delete_job(owner, job_id)
  return files, size, missing_now
