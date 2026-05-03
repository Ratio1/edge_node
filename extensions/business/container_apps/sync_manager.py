"""Volume-sync manager for the Container App Runner.

Coordinates publishing app-state snapshots to R1FS+ChainStore (provider) and
applying them on remote nodes (consumer). The contract with the app inside
the container is file-based, mediated through the always-on system volume
mounted at ``/r1en_system``:

  app writes  /r1en_system/volume-sync/request.json   (one-shot)
  CAR writes  /r1en_system/volume-sync/response.json  (provider, paired)
  CAR writes  /r1en_system/volume-sync/last_apply.json  (consumer)
  CAR writes  /r1en_system/volume-sync/request.json.invalid  (failed request body + diagnostics)

Persistent per-plugin audit trail lives under
``<plugin_data>/sync_history/{sent,received}/<version>__<short_cid>.json``
so both sides can be inspected with ``ls`` / ``cat`` / ``jq`` after the fact.

See ``docs/_todos/2026-05-03T17:37:43_car_volume_sync_provider_consumer.md``
for the full contract, validation rules, and lifecycle decisions.
"""

from __future__ import annotations

import json
import os
import tarfile
import tempfile
from pathlib import Path
from typing import Any, Optional

# ---------------------------------------------------------------------------
# System volume — non-configurable defaults
# ---------------------------------------------------------------------------

SYSTEM_VOLUME_NAME = "r1en_system"          # logical name (host paths)
SYSTEM_VOLUME_MOUNT = "/r1en_system"        # mount point inside container
SYSTEM_VOLUME_SIZE = "10M"                  # fixed-size ext4 image — control-plane only
SYSTEM_VOLUME_FS = "ext4"

# Per-feature subdirectory under the system volume root, so future CAR ↔ app
# control-plane features (not just sync) can coexist without colliding.
VOLUME_SYNC_SUBDIR = "volume-sync"

# Filenames inside <system_volume_root>/<VOLUME_SYNC_SUBDIR>/
SYNC_REQUEST_FILE = "request.json"
SYNC_PROCESSING_FILE = "request.json.processing"
SYNC_INVALID_FILE = "request.json.invalid"
SYNC_RESPONSE_FILE = "response.json"
SYNC_LAST_APPLY_FILE = "last_apply.json"

# Persistent audit folders under <plugin_data>/sync_history/
SYNC_HISTORY_DIR = "sync_history"
SYNC_HISTORY_SENT = "sent"          # provider — writes to R1FS
SYNC_HISTORY_RECEIVED = "received"  # consumer — reads from R1FS

# ChainStore namespace
CHAINSTORE_SYNC_HKEY = "CHAINSTORE_SYNC"

# Manifest schema versioning so consumers can refuse newer-than-known formats
MANIFEST_SCHEMA_VERSION = 1
ARCHIVE_FORMAT = "tar.gz"

# Stages reported on failure (used in response.json + request.json.invalid)
STAGE_VALIDATION = "validation"
STAGE_ARCHIVE_BUILD = "archive_build"
STAGE_R1FS_UPLOAD = "r1fs_upload"
STAGE_CHAINSTORE_PUBLISH = "chainstore_publish"
STAGE_EXTRACT = "extract"

# History entry deletion sub-record default (filled in when superseded).
_UNDELETED = {"deleted_at": None, "deletion_succeeded": None, "deletion_error": None}


# ---------------------------------------------------------------------------
# Path helpers (host-side)
# ---------------------------------------------------------------------------

def system_volume_host_root(owner) -> Path:
  """Host-side root of the system volume's loopback mount.

  The system volume is provisioned via the same machinery as
  FIXED_SIZE_VOLUMES, so its mount lives at:
    <plugin_data>/fixed_volumes/mounts/<SYSTEM_VOLUME_NAME>/
  """
  return (
    Path(owner.get_data_folder())
    / owner._get_instance_data_subfolder()
    / "fixed_volumes" / "mounts" / SYSTEM_VOLUME_NAME
  )


def volume_sync_dir(owner) -> Path:
  """Host-side path of the volume-sync control-plane subdir."""
  return system_volume_host_root(owner) / VOLUME_SYNC_SUBDIR


def history_root(owner) -> Path:
  """Host-side root of the per-plugin sync history folders."""
  return (
    Path(owner.get_data_folder())
    / owner._get_instance_data_subfolder()
    / SYNC_HISTORY_DIR
  )


def history_sent_dir(owner) -> Path:
  return history_root(owner) / SYNC_HISTORY_SENT


def history_received_dir(owner) -> Path:
  return history_root(owner) / SYNC_HISTORY_RECEIVED


# ---------------------------------------------------------------------------
# SyncManager
# ---------------------------------------------------------------------------

class SyncManager:
  """Pure orchestration layer driven by ``_SyncMixin`` ticks.

  All file I/O is rooted at host-side paths derived from the plugin's per-
  instance data folder. Network/storage operations are delegated to the
  plugin's ``self.r1fs`` and ``self.chainstore_*`` APIs.

  Required attributes on ``owner``:
    - P, time                                    (BasePlugin)
    - get_data_folder, _get_instance_data_subfolder  (BasePlugin)
    - volumes                                    (dict, populated by CAR)
    - r1fs                                       (R1FSEngine)
    - chainstore_hset, chainstore_hget, chainstore_hsync  (BasePlugin API)
    - cfg_sync_key, cfg_sync_type                (CAR config — propagated by mixin)
    - ee_id                                      (BasePlugin — node identity)
  """

  def __init__(self, owner):
    self.owner = owner

  # ----- path resolution -------------------------------------------------
  def resolve_container_path(self, container_path: str) -> tuple[str, str, str]:
    """Map an app-perspective absolute path to a host path via owner.volumes.

    Enforces the six-rule check from the plan:
      1. absolute, 2. covered by a mount, 3. fixed-size mount,
      4. not inside the system volume, 5. no ``..`` after normalization,
      6. resolved host path stays within its host_root.

    Returns ``(host_path, bind_root, host_root)`` on success, raises
    ``ValueError`` on any rule violation.
    """
    if not isinstance(container_path, str) or not container_path:
      raise ValueError(f"archive_paths entry must be a non-empty string: {container_path!r}")

    # Reject explicit '..' segments BEFORE normalization (rule 5). normpath
    # will collapse them silently and we want the error to be clear.
    parts = container_path.split("/")
    if any(p == ".." for p in parts):
      raise ValueError(f"archive_paths entries must not contain '..': {container_path!r}")

    cp = os.path.normpath(container_path)
    if not cp.startswith("/"):  # rule 1
      raise ValueError(f"archive_paths entries must be absolute: {container_path!r}")

    # Rule 4: refuse the system volume mount itself.
    if cp == SYSTEM_VOLUME_MOUNT or cp.startswith(SYSTEM_VOLUME_MOUNT + "/"):
      raise ValueError(
        f"refusing to archive system volume content (anti-recursion): {container_path!r}"
      )

    fixed_root_marker = os.sep + os.path.join("fixed_volumes", "mounts") + os.sep

    volumes = getattr(self.owner, "volumes", {}) or {}
    for host_root, spec in volumes.items():
      if not isinstance(spec, dict):
        continue
      bind = str(spec.get("bind", "")).rstrip("/")
      if not bind:
        continue
      # Rule 2: container path must fall under this mount's bind point.
      if cp != bind and not cp.startswith(bind + "/"):
        continue

      host_root_n = os.path.normpath(str(host_root))
      # Rule 3: only fixed-size volumes are eligible. Their host root sits
      # under <plugin_data>/fixed_volumes/mounts/. This rejects VOLUMES,
      # FILE_VOLUMES, anonymous Docker mounts, and ephemeral container fs.
      if fixed_root_marker not in (host_root_n + os.sep):
        raise ValueError(
          f"refusing non-fixed-size mount for {container_path!r}: "
          f"host_root={host_root_n!r} (only FIXED_SIZE_VOLUMES-backed paths allowed)"
        )

      rel = "" if cp == bind else os.path.relpath(cp, bind)
      host_path = os.path.normpath(os.path.join(host_root_n, rel))
      # Rule 6: resolved path must stay within host_root.
      if not (host_path == host_root_n or host_path.startswith(host_root_n + os.sep)):
        raise ValueError(
          f"resolved host path escapes mount root: {container_path!r} -> {host_path!r}"
        )
      return host_path, bind, host_root_n

    raise ValueError(f"no mounted volume covers {container_path!r}")

  # ----- atomic I/O -------------------------------------------------------
  def _write_json_atomic(self, path: Path, payload: Any) -> None:
    """Write JSON to ``path`` atomically (tmp + ``os.replace``).

    Creates the parent directory if missing. Uses a NamedTemporaryFile in
    the same directory so ``os.replace`` is an atomic rename within one
    filesystem.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
      dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
      with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
      os.replace(tmp_name, str(path))
    except Exception:
      try:
        os.unlink(tmp_name)
      except OSError:
        pass
      raise

  # ----- history ---------------------------------------------------------
  @staticmethod
  def _history_filename(version: int, cid: str) -> str:
    """Build the canonical filename for a history entry.

    ``<10-digit-version>__<12-char-cid>.json`` so lexical sort matches
    chronological order (version is a Unix timestamp).
    """
    short_cid = (cid or "")[:12] or "no_cid"
    # safe_path_component-like sanitisation kept simple — CIDs are base58.
    safe_short = "".join(ch if ch.isalnum() else "_" for ch in short_cid)
    return f"{int(version):010d}__{safe_short}.json"

  def _ensure_history_dirs(self) -> None:
    history_sent_dir(self.owner).mkdir(parents=True, exist_ok=True)
    history_received_dir(self.owner).mkdir(parents=True, exist_ok=True)

  def _append_history(self, history_dir: Path, entry: dict) -> Path:
    self._ensure_history_dirs()
    fname = self._history_filename(entry.get("version", 0), entry.get("cid", ""))
    path = history_dir / fname
    payload = dict(entry)
    payload.setdefault("deletion", dict(_UNDELETED))
    self._write_json_atomic(path, payload)
    return path

  def append_sent(self, entry: dict) -> Path:
    """Write a provider history entry to sync_history/sent/."""
    return self._append_history(history_sent_dir(self.owner), entry)

  def append_received(self, entry: dict) -> Path:
    """Write a consumer history entry to sync_history/received/."""
    return self._append_history(history_received_dir(self.owner), entry)

  def _latest_in(self, history_dir: Path) -> Optional[dict]:
    if not history_dir.is_dir():
      return None
    candidates = sorted(p for p in history_dir.iterdir() if p.suffix == ".json")
    if not candidates:
      return None
    latest = candidates[-1]
    try:
      with latest.open("r", encoding="utf-8") as handle:
        return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
      self.owner.P(f"[sync] failed to read history file {latest}: {exc}", color="r")
      return None

  def latest_sent(self) -> Optional[dict]:
    """Return the most recent provider history entry, or None if empty."""
    return self._latest_in(history_sent_dir(self.owner))

  def latest_received(self) -> Optional[dict]:
    """Return the most recent consumer history entry, or None if empty."""
    return self._latest_in(history_received_dir(self.owner))

  def update_history_deletion(
    self, history_dir: Path, entry: dict, succeeded: bool, error: Optional[str]
  ) -> None:
    """Update the deletion sub-record on an existing history entry.

    Atomic via tmp+rename. Identifies the file by its filename convention
    (``<version>__<short_cid>.json``) derived from the entry's fields.
    Silently logs and returns if the file isn't found.
    """
    fname = self._history_filename(entry.get("version", 0), entry.get("cid", ""))
    path = Path(history_dir) / fname
    if not path.is_file():
      self.owner.P(
        f"[sync] history file missing for deletion update: {path}", color="y"
      )
      return
    try:
      with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
      self.owner.P(
        f"[sync] failed to read history file for deletion update {path}: {exc}",
        color="r",
      )
      return
    data["deletion"] = {
      "deleted_at": self.owner.time(),
      "deletion_succeeded": bool(succeeded),
      "deletion_error": error,
    }
    self._write_json_atomic(path, data)

  # ----- provider --------------------------------------------------------
  def _fail_request(
    self,
    request_body: Optional[dict],
    stage: str,
    error: str,
    processing_path: Optional[Path],
    raw_body: Optional[str] = None,
  ) -> None:
    """Write request.json.invalid + response.json (error), discard .processing.

    Used by both claim_request validation failures and publish_snapshot
    execution failures so the artifact pair is consistent across stages.
    """
    failed_ts = self.owner.time()
    node_id = getattr(self.owner, "ee_id", None) or getattr(self.owner, "node_id", None)
    invalid_payload: dict[str, Any] = {
      "request": request_body,  # may be None for malformed JSON
      "_error": {
        "stage": stage,
        "error": error,
        "failed_timestamp": failed_ts,
        "node_id": node_id,
      },
    }
    if raw_body is not None and request_body is None:
      invalid_payload["_error"]["raw_body"] = raw_body[:1024]

    vsd = volume_sync_dir(self.owner)
    try:
      self._write_json_atomic(vsd / SYNC_INVALID_FILE, invalid_payload)
    except Exception as exc:
      self.owner.P(f"[sync] failed to write request.json.invalid: {exc}", color="r")

    archive_paths: list[Any] = []
    if isinstance(request_body, dict):
      ap = request_body.get("archive_paths")
      if isinstance(ap, list):
        archive_paths = ap
    response_payload = {
      "status": "error",
      "stage": stage,
      "error": error,
      "failed_timestamp": failed_ts,
      "archive_paths": archive_paths,
    }
    try:
      self._write_json_atomic(vsd / SYNC_RESPONSE_FILE, response_payload)
    except Exception as exc:
      self.owner.P(f"[sync] failed to write response.json: {exc}", color="r")

    if processing_path is not None and processing_path.exists():
      try:
        os.unlink(str(processing_path))
      except OSError as exc:
        self.owner.P(
          f"[sync] failed to delete .processing after error: {exc}", color="r"
        )

  def claim_request(self) -> Optional[tuple[list[str], dict]]:
    """Atomically claim the pending request.json, validate, return its payload.

    On success: renames ``request.json`` → ``request.json.processing``,
    returns ``(archive_paths, metadata)``.
    On any failure (no file, malformed JSON, validation): writes
    ``request.json.invalid`` (request body + ``_error`` diagnostics) and
    ``response.json`` (error shape), discards the ``.processing`` file, and
    returns ``None``.
    """
    vsd = volume_sync_dir(self.owner)
    req_path = vsd / SYNC_REQUEST_FILE
    proc_path = vsd / SYNC_PROCESSING_FILE

    if not req_path.is_file():
      return None  # nothing pending

    try:
      os.replace(str(req_path), str(proc_path))
    except OSError as exc:
      self.owner.P(
        f"[sync] could not rename request.json -> .processing: {exc}", color="r"
      )
      return None

    raw_body: Optional[str] = None
    try:
      raw_body = proc_path.read_text(encoding="utf-8")
    except OSError as exc:
      self._fail_request(
        None, STAGE_VALIDATION, f"could not read .processing: {exc}", proc_path
      )
      return None

    try:
      body = json.loads(raw_body)
    except json.JSONDecodeError as exc:
      self._fail_request(
        None, STAGE_VALIDATION, f"malformed JSON: {exc}", proc_path, raw_body=raw_body
      )
      return None

    if not isinstance(body, dict):
      self._fail_request(
        None, STAGE_VALIDATION,
        "request.json must be a JSON object", proc_path, raw_body=raw_body,
      )
      return None

    archive_paths = body.get("archive_paths")
    metadata = body.get("metadata", {}) or {}
    if not isinstance(metadata, dict):
      self._fail_request(
        body, STAGE_VALIDATION, "metadata must be a JSON object", proc_path
      )
      return None

    if not isinstance(archive_paths, list) or not archive_paths:
      self._fail_request(
        body, STAGE_VALIDATION,
        "archive_paths must be a non-empty list of container-absolute paths",
        proc_path,
      )
      return None

    for entry in archive_paths:
      try:
        self.resolve_container_path(entry)
      except ValueError as exc:
        self._fail_request(body, STAGE_VALIDATION, str(exc), proc_path)
        return None

    return list(archive_paths), dict(metadata)

  def make_archive(self, archive_paths: list[str]) -> tuple[str, int]:
    """Build the snapshot tar.gz under the plugin output folder.

    Tar member names are the **container paths** (so consumers can reverse-
    resolve via their own self.volumes). Returns ``(tar_path, size_bytes)``.
    Re-runs ``resolve_container_path`` for each entry as defence in depth.
    """
    output_dir: Path
    get_output = getattr(self.owner, "get_output_folder", None)
    if callable(get_output):
      output_dir = Path(get_output())
    else:
      output_dir = Path(tempfile.gettempdir())
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = int(self.owner.time())
    tar_path = output_dir / f"sync_archive_{ts}_{os.getpid()}.tar.gz"

    with tarfile.open(str(tar_path), "w:gz") as tar:
      for container_path in archive_paths:
        host_path, _bind, _host_root = self.resolve_container_path(container_path)
        if not os.path.exists(host_path):
          raise FileNotFoundError(
            f"archive_paths target does not exist on host: {container_path!r} -> {host_path!r}"
          )
        tar.add(host_path, arcname=container_path, recursive=True)

    return str(tar_path), os.path.getsize(str(tar_path))

  def publish_snapshot(self, archive_paths: list[str], metadata: dict) -> bool:
    """Full provider orchestration. See plan section "Code layout"."""
    raise NotImplementedError

  # ----- consumer --------------------------------------------------------
  def fetch_latest(self) -> Optional[dict]:
    """``chainstore_hsync`` then ``chainstore_hget`` for the configured KEY."""
    raise NotImplementedError

  def validate_manifest(self, record: dict) -> list[str]:
    """Return list of archive_paths in record.manifest that are not covered
    by self.owner.volumes. Empty list means the consumer can apply.
    """
    raise NotImplementedError

  def extract_archive(self, tar_path: str) -> list[str]:
    """Reverse-map tar member container paths to host paths and extract.

    Two-pass: first pass validates every member by feeding its name through
    ``resolve_container_path`` (so the entire extract aborts before any
    write if the consumer's volume layout doesn't cover all members).
    Symlinks/hardlinks are skipped with a warning — never extracted, since
    a malicious tar could otherwise create a link that subsequent regular
    members would write through. Each regular file is written via tmp +
    ``os.replace`` so a mid-flight crash never leaves a half-written file.
    Returns the list of container paths that were applied (regular files +
    directories created).
    """
    extracted: list[str] = []
    with tarfile.open(str(tar_path), "r:gz") as tar:
      members = tar.getmembers()

      # Pass 1: validate every member, build (member, host_path) pairs.
      # Python's tarfile.add() strips leading '/' from arcnames as a POSIX
      # safety default, so member names look like "app/data/foo.bin" even
      # when we put them in as "/app/data/foo.bin". Normalize back to the
      # container-absolute form before running through the resolver.
      planned: list[tuple[tarfile.TarInfo, str]] = []
      for member in members:
        if member.issym() or member.islnk():
          self.owner.P(
            f"[sync] skipping link member in tar (security): {member.name}",
            color="y",
          )
          continue
        if any(part == ".." for part in member.name.split("/")):
          raise ValueError(f"tar member name contains '..': {member.name!r}")
        container_name = member.name
        if not container_name.startswith("/"):
          container_name = "/" + container_name
        host_path, _bind, _host_root = self.resolve_container_path(container_name)
        planned.append((member, host_path, container_name))

      # Pass 2: actually extract.
      for member, host_path, container_name in planned:
        if member.isdir():
          os.makedirs(host_path, exist_ok=True)
          extracted.append(container_name)
          continue
        if not member.isfile():
          continue
        os.makedirs(os.path.dirname(host_path), exist_ok=True)
        fobj = tar.extractfile(member)
        if fobj is None:
          continue
        # Atomic per-file write: tmp in same directory, then os.replace.
        fd, tmp_name = tempfile.mkstemp(
          dir=os.path.dirname(host_path),
          prefix=f".{os.path.basename(host_path)}.",
          suffix=".tmp",
        )
        try:
          with os.fdopen(fd, "wb") as out:
            while True:
              chunk = fobj.read(1024 * 1024)
              if not chunk:
                break
              out.write(chunk)
          os.replace(tmp_name, host_path)
        except Exception:
          try:
            os.unlink(tmp_name)
          except OSError:
            pass
          raise
        try:
          os.chmod(host_path, member.mode & 0o7777)
        except OSError as exc:
          self.owner.P(
            f"[sync] could not chmod extracted file {host_path}: {exc}", color="y"
          )
        extracted.append(container_name)
    return extracted

  def apply_snapshot(self, record: dict) -> bool:
    """Full consumer orchestration. See plan section "Code layout"."""
    raise NotImplementedError

  # ----- retirement ------------------------------------------------------
  def _retire_previous_cid(
    self, history_dir: Path, cleanup_local_files: bool = False
  ) -> None:
    """Delete the prior R1FS CID after a successful new operation.

    Only the immediately-prior un-retired entry is touched per call. Updates
    that entry's ``deletion`` sub-record. Never raises — deletion failures
    must not roll back the new publish/apply.
    """
    raise NotImplementedError
