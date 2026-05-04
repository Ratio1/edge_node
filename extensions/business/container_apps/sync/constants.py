"""Volume-sync constants and namespace conventions.

Hard-coded values (no config knobs) shared by ``SyncManager``,
``_SyncMixin``, and the unit tests. Lives in its own module so a reader
can `cat sync/constants.py` to see the full data-plane vocabulary in one
place — file names, the ChainStore hkey, the stage labels, the schema
version. Anything tunable belongs in the plugin's ``SYNC`` config block,
not here.
"""

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
