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
    raise NotImplementedError

  # ----- atomic I/O -------------------------------------------------------
  def _write_json_atomic(self, path: Path, payload: Any) -> None:
    """Write JSON to ``path`` atomically (tmp + os.replace)."""
    raise NotImplementedError

  # ----- history ---------------------------------------------------------
  def append_sent(self, entry: dict) -> Path:
    """Write a provider history entry to sync_history/sent/."""
    raise NotImplementedError

  def append_received(self, entry: dict) -> Path:
    """Write a consumer history entry to sync_history/received/."""
    raise NotImplementedError

  def latest_sent(self) -> Optional[dict]:
    """Return the most recent provider history entry, or None if empty."""
    raise NotImplementedError

  def latest_received(self) -> Optional[dict]:
    """Return the most recent consumer history entry, or None if empty."""
    raise NotImplementedError

  def update_history_deletion(
    self, history_dir: Path, entry: dict, succeeded: bool, error: Optional[str]
  ) -> None:
    """Update the deletion sub-record on an existing history entry.

    Atomic via tmp+rename. Identifies the file by its filename convention
    (``<version>__<short_cid>.json``) derived from the entry's fields.
    """
    raise NotImplementedError

  # ----- provider --------------------------------------------------------
  def claim_request(self) -> Optional[tuple[list[str], dict]]:
    """Atomically claim the pending request.json, validate, return its payload.

    On success: renames ``request.json`` → ``request.json.processing``,
    returns ``(archive_paths, metadata)``.
    On any failure (no file, malformed JSON, validation): writes
    ``request.json.invalid`` (request body + ``_error`` diagnostics) and
    ``response.json`` (error shape), discards the ``.processing`` file, and
    returns ``None``.
    """
    raise NotImplementedError

  def make_archive(self, archive_paths: list[str]) -> tuple[str, int]:
    """Build the snapshot tar.gz under the plugin output folder.

    Tar member names are the **container paths** (so consumers can reverse-
    resolve via their own self.volumes). Returns ``(tar_path, size_bytes)``.
    """
    raise NotImplementedError

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

    Aborts the entire extract on any unmapped/invalid member (no partial
    state). Returns the list of container paths that were extracted.
    """
    raise NotImplementedError

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
