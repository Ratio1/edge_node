"""Volume-sync subpackage for the Container App Runner.

The whole feature lives here:
  * ``constants.py`` — file names, namespace strings, schema versions,
    failure-stage labels. No code, just data.
  * ``manager.py``   — ``SyncManager`` class plus host-side path helpers.
    Pure I/O orchestration; takes the plugin as ``owner`` and delegates
    network/storage to ``owner.r1fs`` / ``owner.chainstore_*``.
  * ``mixin.py``     — ``_SyncMixin`` class. Plugin-class integration:
    knows when sync work should happen (on_init, _restart_container,
    _perform_additional_checks, _handle_initial_launch) and frames each
    invocation around a ``stop_container → SyncManager.work →
    start_container`` window.

Re-exports below let callers import from the package root rather than
reaching into individual modules.
"""

from .constants import (
  ARCHIVE_ENCRYPTION,
  ARCHIVE_FORMAT,
  CHAINSTORE_SYNC_HKEY,
  MANIFEST_SCHEMA_VERSION,
  STAGE_ARCHIVE_BUILD,
  STAGE_CHAINSTORE_PUBLISH,
  STAGE_EXTRACT,
  STAGE_R1FS_UPLOAD,
  STAGE_RUNTIME_STOP,
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
)
from .manager import (
  SyncManager,
  history_received_dir,
  history_root,
  history_sent_dir,
  sync_state_dir,
  system_volume_host_root,
  volume_sync_dir,
)
from .mixin import _SyncMixin

__all__ = [
  # constants
  "ARCHIVE_ENCRYPTION",
  "ARCHIVE_FORMAT",
  "CHAINSTORE_SYNC_HKEY",
  "MANIFEST_SCHEMA_VERSION",
  "STAGE_ARCHIVE_BUILD",
  "STAGE_CHAINSTORE_PUBLISH",
  "STAGE_EXTRACT",
  "STAGE_R1FS_UPLOAD",
  "STAGE_RUNTIME_STOP",
  "STAGE_VALIDATION",
  "SYNC_HISTORY_DIR",
  "SYNC_HISTORY_RECEIVED",
  "SYNC_HISTORY_SENT",
  "SYNC_INVALID_FILE",
  "SYNC_LAST_APPLY_FILE",
  "SYNC_PROCESSING_FILE",
  "SYNC_REQUEST_FILE",
  "SYNC_RESPONSE_FILE",
  "SYSTEM_VOLUME_FS",
  "SYSTEM_VOLUME_MOUNT",
  "SYSTEM_VOLUME_NAME",
  "SYSTEM_VOLUME_SIZE",
  "VOLUME_SYNC_SUBDIR",
  # path helpers
  "history_received_dir",
  "history_root",
  "history_sent_dir",
  "sync_state_dir",
  "system_volume_host_root",
  "volume_sync_dir",
  # classes
  "SyncManager",
  "_SyncMixin",
]
