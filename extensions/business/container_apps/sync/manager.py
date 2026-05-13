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

See ``extensions/business/container_apps/README.md`` for the public
operator/app contract.
"""

from __future__ import annotations

import json
import os
import copy
import stat
import tarfile
import tempfile
import time as _time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from extensions.business.container_apps.container_utils import (
  CONTAINER_VOLUMES_PATH,
)

from .control_files import (
  JsonControlFile,
  JsonControlFileClaimError,
  JsonControlFileDecodeError,
  JsonControlFileObjectError,
  JsonControlFileReadError,
  JsonControlFileUnsafeError,
  write_json_atomic,
)

_HISTORY_WRITTEN_AT_NS = "history_written_at_ns"
PROVIDER_CAPTURE_OFFLINE = "offline"
PROVIDER_CAPTURE_ONLINE = "online"
CONSUMER_APPLY_OFFLINE_RESTART = "offline_restart"
CONSUMER_APPLY_ONLINE_NO_RESTART = "online_no_restart"
CONSUMER_APPLY_ONLINE_RESTART = "online_restart"
_PROVIDER_CAPTURE_MODES = {PROVIDER_CAPTURE_OFFLINE, PROVIDER_CAPTURE_ONLINE}
_CONSUMER_APPLY_MODES = {
  CONSUMER_APPLY_OFFLINE_RESTART,
  CONSUMER_APPLY_ONLINE_NO_RESTART,
  CONSUMER_APPLY_ONLINE_RESTART,
}

from .constants import (
  ARCHIVE_ENCRYPTION,
  ARCHIVE_FORMAT,
  CHAINSTORE_SYNC_HKEY,
  MANIFEST_SCHEMA_VERSION,
  STAGE_ARCHIVE_BUILD,
  STAGE_CHAINSTORE_PUBLISH,
  STAGE_EXTRACT,
  STAGE_R1FS_UPLOAD,
  STAGE_VALIDATION,
  SYNC_HISTORY_DIR,
  SYNC_HISTORY_RECEIVED,
  SYNC_HISTORY_SENT,
  SYNC_INVALID_FILE,
  SYNC_LAST_APPLY_FILE,
  SYNC_PROCESSING_FILE,
  SYNC_REQUEST_FILE,
  SYNC_RESPONSE_FILE,
  SYSTEM_VOLUME_FS,
  SYSTEM_VOLUME_MOUNT,
  SYSTEM_VOLUME_NAME,
  SYSTEM_VOLUME_SIZE,
  VOLUME_SYNC_SUBDIR,
  _UNDELETED,
)


@dataclass(frozen=True)
class SyncRuntimePolicy:
  provider_capture: str = PROVIDER_CAPTURE_OFFLINE
  consumer_apply: str = CONSUMER_APPLY_OFFLINE_RESTART


@dataclass(frozen=True)
class SyncRequest:
  archive_paths: list[str]
  metadata: dict
  runtime: SyncRuntimePolicy


def runtime_policy_to_dict(runtime: SyncRuntimePolicy) -> dict:
  return {
    "provider_capture": runtime.provider_capture,
    "consumer_apply": runtime.consumer_apply,
  }


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

  # Fallback used by fetch_latest when the owner doesn't expose
  # cfg_sync_hsync_poll_interval (e.g. test fixtures or older configs).
  # Mirrors _SyncMixin._HSYNC_POLL_INTERVAL_DEFAULT.
  _DEFAULT_HSYNC_POLL_INTERVAL = 60.0
  _DEFAULT_HSYNC_FAILURE_RETRY_INTERVAL = 30.0

  def __init__(self, owner):
    self.owner = owner
    # Timestamp (owner.time() units) of the last hsync attempt. Initial 0
    # guarantees the first ``fetch_latest`` call still hsyncs.
    self._last_hsync = 0.0

  def _request_control_file(self) -> JsonControlFile:
    return JsonControlFile(
      volume_sync_dir(self.owner), SYNC_REQUEST_FILE, SYNC_PROCESSING_FILE
    )

  @staticmethod
  def _validate_container_path_shape(container_path: str) -> None:
    if not isinstance(container_path, str) or not container_path:
      raise ValueError(f"archive_paths entry must be a non-empty string: {container_path!r}")

    parts = container_path.split("/")
    if any(p == ".." for p in parts):
      raise ValueError(f"archive_paths entries must not contain '..': {container_path!r}")

    cp = os.path.normpath(container_path)
    if not cp.startswith("/"):
      raise ValueError(f"archive_paths entries must be absolute: {container_path!r}")

    if cp == SYSTEM_VOLUME_MOUNT or cp.startswith(SYSTEM_VOLUME_MOUNT + "/"):
      raise ValueError(
        f"refusing to archive system volume content (anti-recursion): {container_path!r}"
      )
    return

  # ----- path resolution -------------------------------------------------
  def resolve_container_path(self, container_path: str) -> tuple[str, str, str]:
    """Map an app-perspective absolute path to a host path via owner.volumes.

    Enforces the six-rule check from the plan:
      1. absolute, 2. covered by a mount, 3. backed by a volume-managed
      mount (fixed-size OR legacy VOLUMES — both are per-instance host
      directories under known roots; anonymous Docker mounts and ephemeral
      container fs are still rejected), 4. not inside the system volume,
      5. no ``..`` after normalization, 6. resolved host path stays within
      its host_root.

    Returns ``(host_path, bind_root, host_root)`` on success, raises
    ``ValueError`` on any rule violation.
    """
    self._validate_container_path_shape(container_path)
    cp = os.path.normpath(container_path)

    # Rule 3 allow-list — both eligible roots are bounded, per-instance, and
    # inside the edge node's data root:
    #   - fixed_volumes/mounts/ : FIXED_SIZE_VOLUMES (ext4 loopbacks)
    #   - CONTAINER_VOLUMES_PATH : legacy VOLUMES (raw bind dirs, deprecated
    #     but still in use by some pipelines). These are functionally
    #     equivalent for sync purposes: a per-instance host directory
    #     identified by a known parent root.
    # Anonymous Docker mounts, FILE_VOLUMES (content-injected single files),
    # and ephemeral container fs all sit outside both roots and are rejected.
    fixed_root_marker = os.sep + os.path.join("fixed_volumes", "mounts") + os.sep
    legacy_root_marker = os.path.normpath(CONTAINER_VOLUMES_PATH) + os.sep

    # Collect every mount whose bind prefix covers cp, then pick the longest.
    # Docker overlays the more specific mount on top of the broader one inside
    # the container (e.g. /app/data is shadowed onto /app), so the longest-
    # prefix match is the one that actually serves reads/writes for cp. The
    # previous first-match-wins iteration used dict insertion order, which has
    # no relationship to overlay specificity and could resolve to the wrong
    # host root for nested mounts.
    volumes = getattr(self.owner, "volumes", {}) or {}
    matches: list[tuple[str, str]] = []
    for host_root, spec in volumes.items():
      if not isinstance(spec, dict):
        continue
      bind = str(spec.get("bind", "")).rstrip("/")
      if not bind:
        continue
      # Rule 2: container path must fall under this mount's bind point.
      if cp != bind and not cp.startswith(bind + "/"):
        continue
      matches.append((str(host_root), bind))

    if not matches:
      raise ValueError(f"no mounted volume covers {container_path!r}")

    host_root, bind = max(matches, key=lambda hb: len(hb[1]))
    host_root_n = os.path.normpath(host_root)
    # Rule 3: the winning mount's host root must fall under a known
    # volume-managed root (fixed-size or legacy VOLUMES). See the allow-list
    # construction above for the rationale and the list of rejected cases.
    host_root_with_sep = host_root_n + os.sep
    if not (
      fixed_root_marker in host_root_with_sep
      or host_root_with_sep.startswith(legacy_root_marker)
    ):
      raise ValueError(
        f"refusing non-volume-backed mount for {container_path!r}: "
        f"host_root={host_root_n!r} (only FIXED_SIZE_VOLUMES or legacy "
        f"VOLUMES paths allowed; expected host root under "
        f"{fixed_root_marker.strip(os.sep)!r} or "
        f"{CONTAINER_VOLUMES_PATH!r})"
      )

    rel = "" if cp == bind else os.path.relpath(cp, bind)
    host_path = os.path.normpath(os.path.join(host_root_n, rel))
    # Rule 6: resolved path must stay within host_root.
    if not (host_path == host_root_n or host_path.startswith(host_root_n + os.sep)):
      raise ValueError(
        f"resolved host path escapes mount root: {container_path!r} -> {host_path!r}"
      )
    return host_path, bind, host_root_n

  @staticmethod
  def _is_within_root(path: str, root: str) -> bool:
    path_n = os.path.normpath(path)
    root_n = os.path.normpath(root)
    return path_n == root_n or path_n.startswith(root_n + os.sep)

  @staticmethod
  def _archive_arcname(container_root: str, rel_path: str) -> str:
    root = os.path.normpath(container_root)
    if rel_path in ("", "."):
      return root
    return os.path.normpath(os.path.join(root, rel_path))

  @staticmethod
  def _safe_extract_mode(member_mode: int, *, is_dir: bool) -> int:
    normal_bits = member_mode & 0o777
    minimum = 0o755 if is_dir else 0o644
    return normal_bits | minimum

  def _validate_archive_source_path(
    self,
    host_path: str,
    host_root: str,
    container_path: str,
  ) -> int:
    """Validate an offline archive source without following symlinks."""
    host_path_n = os.path.normpath(host_path)
    host_root_n = os.path.normpath(host_root)
    if not self._is_within_root(host_path_n, host_root_n):
      raise ValueError(
        f"archive source escapes volume root: {container_path!r} -> {host_path_n!r}"
      )
    rel = os.path.relpath(host_path_n, host_root_n)
    current = host_root_n
    for part in [] if rel == "." else rel.split(os.sep):
      current = os.path.join(current, part)
      try:
        st = os.lstat(current)
      except FileNotFoundError as exc:
        raise FileNotFoundError(
          f"archive_paths target does not exist on host: "
          f"{container_path!r} -> {host_path_n!r}"
        ) from exc
      if stat.S_ISLNK(st.st_mode):
        raise ValueError(
          f"archive source contains symlink: {container_path!r} -> {current!r}"
        )
    root_real = os.path.realpath(host_root_n)
    path_real = os.path.realpath(host_path_n)
    if not self._is_within_root(path_real, root_real):
      raise ValueError(
        f"archive source escapes volume root: {container_path!r} -> {host_path_n!r}"
      )
    return os.lstat(host_path_n).st_mode

  def _add_offline_archive_path(
    self,
    tar: tarfile.TarFile,
    container_path: str,
    host_path: str,
    host_root: str,
  ) -> None:
    mode = self._validate_archive_source_path(
      host_path, host_root, container_path
    )
    if stat.S_ISREG(mode):
      tar.add(host_path, arcname=os.path.normpath(container_path), recursive=False)
      return
    if not stat.S_ISDIR(mode):
      raise ValueError(
        f"archive source is not a regular file or directory: {container_path!r}"
      )

    for current_root, dirnames, filenames in os.walk(
      host_path, topdown=True, followlinks=False
    ):
      rel_root = os.path.relpath(current_root, host_path)
      current_container = self._archive_arcname(container_path, rel_root)
      current_mode = self._validate_archive_source_path(
        current_root, host_root, current_container
      )
      if stat.S_ISLNK(current_mode):
        raise ValueError(
          f"archive source contains symlink: {current_container!r}"
        )
      tar.add(current_root, arcname=current_container, recursive=False)

      kept_dirs: list[str] = []
      for name in dirnames:
        child = os.path.join(current_root, name)
        child_container = self._archive_arcname(
          container_path, os.path.relpath(child, host_path)
        )
        child_mode = self._validate_archive_source_path(
          child, host_root, child_container
        )
        if stat.S_ISLNK(child_mode):
          raise ValueError(
            f"archive source contains symlink: {child_container!r}"
          )
        if not stat.S_ISDIR(child_mode):
          raise ValueError(
            f"archive source is not a directory: {child_container!r}"
          )
        kept_dirs.append(name)
      dirnames[:] = kept_dirs

      for name in filenames:
        child = os.path.join(current_root, name)
        child_container = self._archive_arcname(
          container_path, os.path.relpath(child, host_path)
        )
        child_mode = self._validate_archive_source_path(
          child, host_root, child_container
        )
        if not stat.S_ISREG(child_mode):
          raise ValueError(
            f"archive source is not a regular file: {child_container!r}"
          )
        tar.add(child, arcname=child_container, recursive=False)

  # ----- atomic I/O -------------------------------------------------------
  def _write_json_atomic(self, path: Path, payload: Any) -> None:
    """Write JSON to ``path`` atomically (tmp + ``os.replace``).

    Creates the parent directory if missing. Uses a NamedTemporaryFile in
    the same directory so ``os.replace`` is an atomic rename within one
    filesystem. The final file is chmod'd to 0o666 because CAR runs as
    root inside the edge node but the app inside the container typically
    runs as a non-root user — without world-readable mode the app can't
    read response.json / last_apply.json / request.json.invalid.
    """
    write_json_atomic(path, payload)

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
    payload.setdefault(_HISTORY_WRITTEN_AT_NS, _time.time_ns())
    payload.setdefault("deletion", dict(_UNDELETED))
    self._write_json_atomic(path, payload)
    return path

  def _read_history_entries(self, history_dir: Path) -> list[tuple[Path, dict, int]]:
    """Read history JSON files with stable insertion-order metadata.

    ``history_written_at_ns`` is set when an entry is first appended and is
    preserved by deletion updates. Older history files fall back to mtime.
    """
    entries = []
    if not history_dir.is_dir():
      return entries
    for path in history_dir.iterdir():
      if path.suffix != ".json":
        continue
      try:
        with path.open("r", encoding="utf-8") as handle:
          entry = json.load(handle)
      except (OSError, json.JSONDecodeError) as exc:
        self.owner.P(f"[sync] failed to read history file {path}: {exc}", color="r")
        continue
      written_at = entry.get(_HISTORY_WRITTEN_AT_NS)
      if not isinstance(written_at, int):
        written_at = path.stat().st_mtime_ns
      entries.append((path, entry, written_at))
    return entries

  def append_sent(self, entry: dict) -> Path:
    """Write a provider history entry to sync_history/sent/."""
    return self._append_history(history_sent_dir(self.owner), entry)

  def append_received(self, entry: dict) -> Path:
    """Write a consumer history entry to sync_history/received/."""
    return self._append_history(history_received_dir(self.owner), entry)

  def _latest_in(self, history_dir: Path) -> Optional[dict]:
    """Return the most recently *written* history entry.

    Sorts by the append-time marker, not by filename. Filenames are
    version-prefixed for chronological browsability under normal operation,
    but the consumer's "what did I last apply?" question is about insert
    order, not about whatever ``version`` happens to be in the entry.
    Older files without that marker fall back to mtime.
    """
    entries = self._read_history_entries(history_dir)
    if not entries:
      return None
    _, latest, _ = max(entries, key=lambda item: item[2])
    return latest

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
      "deleted_at": self.owner.time() if succeeded else None,
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

    control_file = self._request_control_file()
    try:
      control_file.write_json(SYNC_INVALID_FILE, invalid_payload)
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
      control_file.write_json(SYNC_RESPONSE_FILE, response_payload)
    except Exception as exc:
      self.owner.P(f"[sync] failed to write response.json: {exc}", color="r")

    if processing_path is not None and processing_path.exists():
      try:
        control_file.discard_processing()
      except OSError as exc:
        self.owner.P(
          f"[sync] failed to delete .processing after error: {exc}", color="r"
        )

  def _parse_runtime_policy(self, body: dict) -> SyncRuntimePolicy:
    runtime = body.get("runtime") or {}
    if not isinstance(runtime, dict):
      raise ValueError("runtime must be a JSON object")

    provider_capture = runtime.get("provider_capture", PROVIDER_CAPTURE_OFFLINE)
    consumer_apply = runtime.get("consumer_apply", CONSUMER_APPLY_OFFLINE_RESTART)

    if provider_capture not in _PROVIDER_CAPTURE_MODES:
      allowed = ", ".join(sorted(_PROVIDER_CAPTURE_MODES))
      raise ValueError(
        f"runtime.provider_capture must be one of [{allowed}], got {provider_capture!r}"
      )
    if consumer_apply not in _CONSUMER_APPLY_MODES:
      allowed = ", ".join(sorted(_CONSUMER_APPLY_MODES))
      raise ValueError(
        f"runtime.consumer_apply must be one of [{allowed}], got {consumer_apply!r}"
      )

    return SyncRuntimePolicy(
      provider_capture=provider_capture,
      consumer_apply=consumer_apply,
    )

  def claim_request(self) -> Optional[SyncRequest]:
    """Atomically claim the pending request.json, validate, return its payload.

    On success: renames ``request.json`` → ``request.json.processing``,
    returns a ``SyncRequest``.
    On any failure (no file, malformed JSON, validation): writes
    ``request.json.invalid`` (request body + ``_error`` diagnostics) and
    ``response.json`` (error shape), discards the ``.processing`` file, and
    returns ``None``.
    """
    control_file = self._request_control_file()
    try:
      claimed = control_file.claim_object()
    except JsonControlFileClaimError as exc:
      self.owner.P(
        f"[sync] could not rename request.json -> .processing: {exc}", color="r"
      )
      return None
    except JsonControlFileReadError as exc:
      self._fail_request(
        None, STAGE_VALIDATION,
        f"could not read .processing: {exc}", control_file.processing_path,
      )
      return None
    except JsonControlFileUnsafeError as exc:
      self._fail_request(
        None, STAGE_VALIDATION,
        str(exc), control_file.processing_path,
      )
      return None
    except JsonControlFileDecodeError as exc:
      self._fail_request(
        None, STAGE_VALIDATION,
        f"malformed JSON: {exc}", control_file.processing_path,
        raw_body=exc.raw_body,
      )
      return None
    except JsonControlFileObjectError as exc:
      self._fail_request(
        None, STAGE_VALIDATION,
        str(exc), control_file.processing_path, raw_body=exc.raw_body,
      )
      return None

    if claimed is None:
      return None  # nothing pending

    body = claimed.body
    proc_path = claimed.processing_path

    archive_paths = body.get("archive_paths")
    metadata = body.get("metadata", {}) or {}
    if not isinstance(metadata, dict):
      self._fail_request(
        body, STAGE_VALIDATION, "metadata must be a JSON object", proc_path
      )
      return None

    try:
      runtime = self._parse_runtime_policy(body)
    except ValueError as exc:
      self._fail_request(body, STAGE_VALIDATION, str(exc), proc_path)
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
        if runtime.provider_capture == PROVIDER_CAPTURE_ONLINE:
          if not bool(
            getattr(self.owner, "cfg_sync_allow_online_provider_capture", False)
          ):
            raise ValueError(
              "runtime.provider_capture='online' requires local "
              "SYNC.ALLOW_ONLINE_PROVIDER_CAPTURE=True"
            )
          self._validate_container_path_shape(entry)
        else:
          self.resolve_container_path(entry)
      except ValueError as exc:
        self._fail_request(body, STAGE_VALIDATION, str(exc), proc_path)
        return None

    return SyncRequest(
      archive_paths=list(archive_paths),
      metadata=dict(metadata),
      runtime=runtime,
    )

  @staticmethod
  def _docker_member_arcname(container_path: str, docker_name: str, member_name: str) -> str:
    target = os.path.normpath(container_path).rstrip("/")
    base = (docker_name or os.path.basename(target)).strip("/")
    raw = member_name.strip("/")

    if base and raw == base:
      return target.lstrip("/")
    if base and raw.startswith(base + "/"):
      suffix = raw[len(base) + 1:]
      return f"{target}/{suffix}".lstrip("/")
    return f"{target}/{raw}".lstrip("/")

  def _append_docker_archive_path(self, tar: tarfile.TarFile, container_path: str) -> None:
    container = getattr(self.owner, "container", None)
    if container is None:
      raise RuntimeError("online provider capture requires a running container")

    self._validate_container_path_shape(container_path)
    bits, stat = container.get_archive(container_path)

    output_dir = Path(tempfile.gettempdir())
    get_output = getattr(self.owner, "get_output_folder", None)
    if callable(get_output):
      output_dir = Path(get_output())
    output_dir.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(
      dir=str(output_dir),
      prefix="sync_docker_archive_",
      suffix=".tar",
    )
    try:
      with os.fdopen(fd, "wb") as handle:
        if isinstance(bits, (bytes, bytearray)):
          handle.write(bits)
        else:
          for chunk in bits:
            handle.write(chunk)

      docker_name = (stat or {}).get("name") or os.path.basename(
        os.path.normpath(container_path)
      )
      with tarfile.open(tmp_name, "r:*") as src:
        for member in src.getmembers():
          if any(part == ".." for part in member.name.split("/")):
            raise ValueError(f"docker archive member name contains '..': {member.name!r}")
          new_member = copy.copy(member)
          new_member.name = self._docker_member_arcname(
            container_path, docker_name, member.name
          )
          fileobj = src.extractfile(member) if member.isfile() else None
          tar.addfile(new_member, fileobj)
    finally:
      try:
        os.unlink(tmp_name)
      except OSError:
        pass
    return

  def make_archive(
    self,
    archive_paths: list[str],
    provider_capture: str = PROVIDER_CAPTURE_OFFLINE,
  ) -> tuple[str, int]:
    """Build the snapshot tar.gz under the plugin output folder.

    Tar member names are the **container paths** (so consumers can reverse-
    resolve via their own self.volumes). Returns ``(tar_path, size_bytes)``.
    Offline capture re-runs ``resolve_container_path`` for each entry as
    defence in depth. Online capture uses Docker's archive API against the
    running container, allowing non-mounted provider paths.
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
        if provider_capture == PROVIDER_CAPTURE_ONLINE:
          if not bool(
            getattr(self.owner, "cfg_sync_allow_online_provider_capture", False)
          ):
            raise ValueError(
              "provider_capture='online' requires local "
              "SYNC.ALLOW_ONLINE_PROVIDER_CAPTURE=True"
            )
          self._append_docker_archive_path(tar, container_path)
        else:
          host_path, _bind, host_root = self.resolve_container_path(container_path)
          self._add_offline_archive_path(tar, container_path, host_path, host_root)

    return str(tar_path), os.path.getsize(str(tar_path))

  def _coerce_sync_request(
    self,
    request: SyncRequest | list[str],
    metadata: Optional[dict] = None,
  ) -> SyncRequest:
    if isinstance(request, SyncRequest):
      return request
    return SyncRequest(
      archive_paths=list(request),
      metadata=dict(metadata or {}),
      runtime=SyncRuntimePolicy(),
    )

  def _delete_uploaded_cid_best_effort(
    self,
    cid: str,
    *,
    cleanup_local_files: bool = False,
  ) -> None:
    try:
      self.owner.r1fs.delete_file(
        cid=cid,
        unpin_remote=True,
        cleanup_local_files=cleanup_local_files,
      )
    except Exception as exc:  # noqa: BLE001 - cleanup must not mask root failure
      self.owner.P(
        f"[sync] failed to clean up uploaded CID {cid}: {exc}", color="y"
      )

  def publish_snapshot(
    self,
    request: SyncRequest | list[str],
    metadata: Optional[dict] = None,
  ) -> bool:
    """Full provider orchestration: archive → R1FS add → ChainStore hset →
    history append → response.json → clear .invalid → delete .processing →
    retire previous CID.

    Returns True on success, False on any failure (and writes
    response.json/error + request.json.invalid for the app).
    Always cleans up the archive tmp file.
    """
    sync_request = self._coerce_sync_request(request, metadata)
    archive_paths = sync_request.archive_paths
    runtime_payload = runtime_policy_to_dict(sync_request.runtime)
    request_body = {
      "archive_paths": list(archive_paths),
      "metadata": dict(sync_request.metadata),
      "runtime": runtime_payload,
    }
    control_file = self._request_control_file()
    vsd = volume_sync_dir(self.owner)
    proc_path = control_file.processing_path
    tar_path: Optional[str] = None
    try:
      # ---- Stage: archive_build
      try:
        tar_path, size_bytes = self.make_archive(
          archive_paths,
          provider_capture=sync_request.runtime.provider_capture,
        )
      except Exception as exc:
        self._fail_request(request_body, STAGE_ARCHIVE_BUILD, str(exc), proc_path)
        return False

      # ---- Stage: r1fs_upload
      try:
        cid = self.owner.r1fs.add_file(tar_path)
      except Exception as exc:
        self._fail_request(request_body, STAGE_R1FS_UPLOAD, str(exc), proc_path)
        return False
      if not cid:
        self._fail_request(
          request_body, STAGE_R1FS_UPLOAD,
          "r1fs.add_file returned no CID", proc_path,
        )
        return False

      # Build the manifest + record
      version = int(self.owner.time())
      ts = self.owner.time()
      node_id = getattr(self.owner, "ee_id", None) or getattr(self.owner, "node_id", None)
      manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "archive_paths": list(archive_paths),
        "archive_format": ARCHIVE_FORMAT,
        "archive_size_bytes": size_bytes,
        "encryption": ARCHIVE_ENCRYPTION,
        "runtime": runtime_payload,
      }
      record = {
        "cid": cid,
        "version": version,
        "timestamp": ts,
        "node_id": node_id,
        "metadata": dict(sync_request.metadata),
        "runtime": runtime_payload,
        "manifest": manifest,
      }

      # ---- Stage: chainstore_publish
      try:
        ack = self.owner.chainstore_hset(
          hkey=CHAINSTORE_SYNC_HKEY,
          key=getattr(self.owner, "cfg_sync_key", None),
          value=record,
        )
      except Exception as exc:
        self._delete_uploaded_cid_best_effort(cid)
        self._fail_request(
          request_body, STAGE_CHAINSTORE_PUBLISH, str(exc), proc_path
        )
        return False

      # Persist history entry (pre-retirement so deletion update finds it).
      entry = {
        "cid": cid,
        "version": version,
        "published_timestamp": ts,
        "request": dict(request_body),
        "manifest": manifest,
        "archive_size_bytes": size_bytes,
        "chainstore_ack": bool(ack),
        "node_id": node_id,
      }
      self.append_sent(entry)

      # Write success response and clean up control-plane artifacts. We
      # include the app-supplied metadata so the in-volume-sync state file
      # is self-contained — UIs that surface response.json (without access
      # to host-side sync_history/) can show the metadata that travelled
      # with this snapshot.
      response_payload = {
        "status": "ok",
        "cid": cid,
        "version": version,
        "published_timestamp": ts,
        "archive_paths": list(archive_paths),
        "archive_size_bytes": size_bytes,
        "chainstore_ack": bool(ack),
        "metadata": dict(sync_request.metadata),
      }
      try:
        control_file.write_json(SYNC_RESPONSE_FILE, response_payload)
      except Exception as exc:
        self.owner.P(
          f"[sync] failed to write response.json: {exc}", color="r"
        )

      invalid_path = vsd / SYNC_INVALID_FILE
      if os.path.lexists(str(invalid_path)):
        try:
          os.unlink(str(invalid_path))
        except OSError:
          pass
      if os.path.lexists(str(proc_path)):
        try:
          control_file.discard_processing()
        except OSError as exc:
          self.owner.P(
            f"[sync] failed to delete .processing after success: {exc}", color="y"
          )

      # Retire prior CID (best-effort, never blocks success).
      self._retire_previous_cid(history_sent_dir(self.owner))
      return True
    finally:
      if tar_path:
        try:
          os.unlink(tar_path)
        except OSError:
          pass

  # ----- consumer --------------------------------------------------------
  def fetch_latest(self) -> Optional[dict]:
    """Refresh the local CHAINSTORE_SYNC replica (gated by HSYNC_POLL_INTERVAL),
    then read the configured KEY.

    The ``hsync`` is the expensive bit — a network round-trip to the chain
    cluster with a timeout. It fires at most every
    ``SYNC.HSYNC_POLL_INTERVAL`` seconds (default 60s, min 10s). The cheap
    local-replica ``hget`` runs on every call regardless, so a consumer that
    already has the record cached keeps reading it without paying the
    network cost.

    On ``hsync`` failure we retry sooner than the full success interval
    (default 30s) to avoid leaving consumers stale for a whole cadence while
    still avoiding a network attempt on every sync tick.
    """
    sync_key = getattr(self.owner, "cfg_sync_key", None)
    if not sync_key:
      return None

    interval = getattr(
      self.owner, "cfg_sync_hsync_poll_interval", self._DEFAULT_HSYNC_POLL_INTERVAL,
    )
    now = self.owner.time()
    if now - self._last_hsync >= interval:
      # Always log the hsync attempt result (success or failure) — this is
      # the only sync mixin log that fires on the happy path, so it doubles
      # as the heartbeat that confirms the consumer is actually ticking and
      # the rate-limit gating is working. Quiet enough at one log per
      # HSYNC_POLL_INTERVAL window (default once per minute) to stay on in
      # prod logs.
      hsync_start = _time.monotonic()
      try:
        self.owner.chainstore_hsync(hkey=CHAINSTORE_SYNC_HKEY)
        self._last_hsync = now
        elapsed = _time.monotonic() - hsync_start
        self.owner.P(f"[sync] chainstore_hsync ok ({elapsed:.2f}s)", color="g")
      except Exception as exc:
        retry_after = min(self._DEFAULT_HSYNC_FAILURE_RETRY_INTERVAL, interval)
        self._last_hsync = now - max(0.0, interval - retry_after)
        elapsed = _time.monotonic() - hsync_start
        self.owner.P(
          f"[sync] chainstore_hsync error after {elapsed:.2f}s "
          f"(retry in {retry_after:.0f}s): {exc}",
          color="y",
        )

    try:
      return self.owner.chainstore_hget(
        hkey=CHAINSTORE_SYNC_HKEY, key=sync_key
      )
    except Exception as exc:
      self.owner.P(f"[sync] chainstore_hget error: {exc}", color="r")
      return None

  def validate_manifest(self, record: dict) -> list[str]:
    """Return list of human-readable rejection reasons for ``record``.

    Empty list means the manifest is acceptable: schema_version and
    archive_format are recognised AND the consumer's ``self.volumes`` covers
    every container path with a (fixed-size) mount. A non-empty list means
    apply must be skipped without touching the filesystem.

    Reasons are surfaced for:
      - missing/wrong ``schema_version`` (must be an int <= MANIFEST_SCHEMA_VERSION)
      - unexpected ``archive_format`` (must equal ARCHIVE_FORMAT)
      - unexpected ``encryption`` (must equal ARCHIVE_ENCRYPTION)
      - ``archive_paths`` entries that don't map to a mount on this consumer

    Format/schema checks come first so they short-circuit before we burn
    cycles resolving paths against a manifest we can't read anyway.
    """
    if not isinstance(record, dict):
      return ["manifest record is not a dict"]
    manifest = record.get("manifest") or {}
    reasons: list[str] = []

    sv = manifest.get("schema_version")
    if not isinstance(sv, int):
      reasons.append(
        f"unsupported schema_version: {sv!r} (expected int, max supported: {MANIFEST_SCHEMA_VERSION})"
      )
    elif sv > MANIFEST_SCHEMA_VERSION:
      reasons.append(
        f"unsupported schema_version: {sv} (max supported by this CAR: {MANIFEST_SCHEMA_VERSION})"
      )

    fmt = manifest.get("archive_format")
    if fmt != ARCHIVE_FORMAT:
      reasons.append(
        f"unsupported archive_format: {fmt!r} (expected: {ARCHIVE_FORMAT!r})"
      )

    enc = manifest.get("encryption")
    if enc != ARCHIVE_ENCRYPTION:
      reasons.append(
        f"unsupported encryption: {enc!r} (expected: {ARCHIVE_ENCRYPTION!r})"
      )

    raw_paths = manifest.get("archive_paths")
    paths: list[str] = []
    if not isinstance(raw_paths, list) or not raw_paths:
      reasons.append(
        "archive_paths must be a non-empty list of container-absolute paths"
      )
    else:
      invalid_paths = [
        entry for entry in raw_paths
        if not isinstance(entry, str) or not entry
      ]
      if invalid_paths:
        reasons.append(f"invalid archive_paths entries: {invalid_paths!r}")
      paths = [entry for entry in raw_paths if isinstance(entry, str) and entry]
    missing: list[str] = []
    for entry in paths:
      try:
        self.resolve_container_path(entry)
      except ValueError:
        missing.append(entry)
    if missing:
      reasons.append(f"unmapped archive_paths on this consumer: {missing}")
    return reasons

  @staticmethod
  def _is_within_real_root(path: str, root: str) -> bool:
    root_real = os.path.realpath(root)
    path_real = os.path.realpath(path)
    return path_real == root_real or path_real.startswith(root_real + os.sep)

  def _validate_extract_target_within_root(
    self,
    host_path: str,
    host_root: str,
    container_name: str,
  ) -> None:
    """Reject extraction targets that would resolve outside their volume.

    ``resolve_container_path`` already proves the normalized string path sits
    under the selected host root. This second check follows symlinks in the
    target and parent path so a pre-existing symlink inside the mounted volume
    cannot redirect extraction outside that volume.
    """
    candidates = [host_path]
    if os.path.normpath(host_path) != os.path.normpath(host_root):
      candidates.append(os.path.dirname(host_path) or host_root)
    for candidate in candidates:
      if not self._is_within_real_root(candidate, host_root):
        raise ValueError(
          f"tar member target escapes volume root: {container_name!r} -> {host_path!r}"
        )

  @staticmethod
  def _container_path_in_declared_archive_paths(
    container_name: str,
    archive_paths: list[str],
  ) -> bool:
    candidate = os.path.normpath(container_name)
    if not candidate.startswith("/"):
      candidate = "/" + candidate
    for entry in archive_paths:
      if not isinstance(entry, str) or not entry:
        continue
      declared = os.path.normpath(entry)
      if not declared.startswith("/"):
        declared = "/" + declared
      if candidate == declared or candidate.startswith(declared.rstrip("/") + "/"):
        return True
    return False

  def extract_archive(
    self,
    tar_path: str,
    allowed_archive_paths: Optional[list[str]] = None,
  ) -> list[str]:
    """Reverse-map tar member container paths to host paths and extract.

    Two-pass: first pass validates every member by feeding its name through
    ``resolve_container_path`` (so the entire extract aborts before any
    write if the consumer's volume layout doesn't cover all members).
    Symlinks/hardlinks are skipped with a warning — never extracted, since
    a malicious tar could otherwise create a link that subsequent regular
    members would write through. Each regular file is written via tmp +
    ``os.replace`` so a mid-flight crash never leaves a half-written file.
    If ``allowed_archive_paths`` is provided, every extracted member must also
    sit under at least one manifest-declared archive path. Returns the list of
    container paths that were applied (regular files + directories created).
    """
    return self._extract_archive(tar_path, allowed_archive_paths)

  def _extract_archive(
    self,
    tar_path: str,
    allowed_archive_paths: Optional[list[str]] = None,
  ) -> list[str]:
    extracted: list[str] = []
    with tarfile.open(str(tar_path), "r:gz") as tar:
      members = tar.getmembers()

      # Pass 1: validate every member, build (member, host_path) pairs.
      # Python's tarfile.add() strips leading '/' from arcnames as a POSIX
      # safety default, so member names look like "app/data/foo.bin" even
      # when we put them in as "/app/data/foo.bin". Normalize back to the
      # container-absolute form before running through the resolver.
      planned: list[tuple[tarfile.TarInfo, str, str, str]] = []
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
        if (
          allowed_archive_paths is not None
          and not self._container_path_in_declared_archive_paths(
            container_name, allowed_archive_paths
          )
        ):
          raise ValueError(
            f"tar member outside manifest archive_paths: {container_name!r}"
          )
        host_path, _bind, host_root = self.resolve_container_path(container_name)
        self._validate_extract_target_within_root(host_path, host_root, container_name)
        planned.append((member, host_path, container_name, host_root))

      # Pass 2: actually extract.
      for member, host_path, container_name, host_root in planned:
        if member.isdir():
          os.makedirs(host_path, exist_ok=True)
          self._validate_extract_target_within_root(host_path, host_root, container_name)
          # Widen dir mode so the in-container app user can traverse, even
          # if CAR (running as root in the edge node) created the directory.
          try:
            os.chmod(host_path, self._safe_extract_mode(member.mode, is_dir=True))
          except OSError:
            pass
          extracted.append(container_name)
          continue
        if not member.isfile():
          continue
        os.makedirs(os.path.dirname(host_path), exist_ok=True)
        self._validate_extract_target_within_root(host_path, host_root, container_name)
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
          # Widen mode before replace: extracted files end up owned by root
          # (CAR runs as root); the app inside the container is typically a
          # non-root user. Preserve the source mode but ensure at least
          # world-readable so the app can ``cat`` what we just landed.
          os.chmod(tmp_name, self._safe_extract_mode(member.mode, is_dir=False))
          os.replace(tmp_name, host_path)
        except Exception:
          try:
            os.unlink(tmp_name)
          except OSError:
            pass
          raise
        extracted.append(container_name)
    return extracted

  def apply_snapshot(self, record: dict) -> bool:
    """Full consumer orchestration: validate_manifest → r1fs.get_file →
    extract → history append → last_apply.json → retire previous CID.

    Returns True on success, False on any failure. On failure no
    last_apply.json is written so the consumer-side app can tell nothing
    landed; history is not advanced.
    """
    if not isinstance(record, dict):
      self.owner.P(f"[sync] apply_snapshot got non-dict record: {record!r}", color="r")
      return False
    cid = record.get("cid")
    version = record.get("version")
    if not cid or not isinstance(version, int):
      self.owner.P(
        f"[sync] apply_snapshot record missing cid/version: {record!r}", color="r"
      )
      return False

    rejection_reasons = self.validate_manifest(record)
    if rejection_reasons:
      self.owner.P(
        f"[sync] cannot apply v{version} (cid={cid}): "
        + "; ".join(rejection_reasons),
        color="r",
      )
      return False

    try:
      local_path = self.owner.r1fs.get_file(cid)
    except Exception as exc:
      self.owner.P(f"[sync] r1fs.get_file({cid}) failed: {exc}", color="r")
      return False
    if not local_path:
      self.owner.P(f"[sync] r1fs.get_file({cid}) returned no path", color="r")
      return False

    try:
      manifest = record.get("manifest") or {}
      extracted = self.extract_archive(
        local_path,
        allowed_archive_paths=manifest.get("archive_paths") or [],
      )
    except Exception as exc:
      self.owner.P(f"[sync] extract_archive failed: {exc}", color="r")
      return False

    applied_ts = self.owner.time()
    entry = {
      "cid": cid,
      "version": version,
      "source_timestamp": record.get("timestamp"),
      "applied_timestamp": applied_ts,
      "node_id": record.get("node_id"),
      "metadata": record.get("metadata") or {},
      "manifest": record.get("manifest") or {},
      "extracted_paths": extracted,
    }
    self.append_received(entry)

    last_apply = {
      "cid": cid,
      "version": version,
      "source_timestamp": record.get("timestamp"),
      "applied_timestamp": applied_ts,
      "node_id": record.get("node_id"),
      "metadata": record.get("metadata") or {},
    }
    try:
      self._write_json_atomic(
        volume_sync_dir(self.owner) / SYNC_LAST_APPLY_FILE, last_apply
      )
    except Exception as exc:
      self.owner.P(f"[sync] failed to write last_apply.json: {exc}", color="r")

    self._retire_previous_cid(history_received_dir(self.owner), cleanup_local_files=True)
    return True

  # ----- retirement ------------------------------------------------------
  def _retire_previous_cid(
    self, history_dir: Path, cleanup_local_files: bool = False
  ) -> None:
    """Delete the prior R1FS CID after a successful new operation.

    Only the immediately-prior un-retired entry is touched per call. Updates
    that entry's ``deletion`` sub-record. Never raises — deletion failures
    must not roll back the new publish/apply.
    """
    # Sort by append-time marker, not filename. Filenames embed the version
    # prefix for chronological browsability under monotonic clocks, but the
    # question "what did we just publish/apply?" is answered by insert order.
    # Sorting by name here would retire the highest-*version* entry instead
    # of the most-recently-appended one.
    entries = sorted(
      self._read_history_entries(history_dir),
      key=lambda item: item[2],
    )
    if len(entries) < 2:
      return  # nothing to retire yet
    latest = entries[-1][1]
    latest_cid = latest.get("cid")
    target_entry: Optional[dict] = None
    for _, entry, _ in reversed(entries[:-1]):
      if entry.get("cid") == latest_cid:
        continue  # same content -- nothing to retire
      if (entry.get("deletion") or {}).get("deleted_at") is not None:
        continue  # already retired
      target_entry = entry
      break

    if target_entry is None:
      return
    target_cid = target_entry.get("cid")
    if not target_cid:
      return

    succeeded = False
    error: Optional[str] = None
    try:
      self.owner.r1fs.delete_file(
        cid=target_cid,
        unpin_remote=True,
        cleanup_local_files=cleanup_local_files,
      )
      succeeded = True
    except Exception as exc:  # noqa: BLE001 — never raise
      error = str(exc)
      self.owner.P(
        f"[sync] failed to retire CID {target_cid}: {exc}", color="y"
      )

    self.update_history_deletion(history_dir, target_entry, succeeded, error)
