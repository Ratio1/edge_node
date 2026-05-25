"""CAR local environment override constants.

These values define the v1 file protocol and host-private state file for
environment overrides. Runtime config can only enable/disable the feature;
wire names and size limits intentionally stay fixed.
"""

ENV_OVERRIDES_SUBDIR = "env-overrides"

ENV_OVERRIDES_REQUEST_FILE = "request.json"
ENV_OVERRIDES_PROCESSING_FILE = "request.json.processing"
ENV_OVERRIDES_INVALID_FILE = "request.json.invalid"
ENV_OVERRIDES_RESPONSE_FILE = "response.json"

ENV_OVERRIDES_STATE_FILE = "env_overrides.json"
ENV_OVERRIDES_SCHEMA_VERSION = 1
ENV_OVERRIDES_MAX_BYTES = 64 * 1024

APPLY_NEXT_RESTART = "next_restart"
APPLY_RESTART_NOW = "restart_now"
APPLY_VALUES = {APPLY_NEXT_RESTART, APPLY_RESTART_NOW}

ENV_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"

RESERVED_ENV_PREFIXES = (
  "R1EN_",
  "R1_",
  "EE_",
)

RESERVED_ENV_NAMES = {
  "CONTAINER_NAME",
  "HOST",
  "HOST_IP",
  "HOST_PORT",
  "HOST_PROTOCOL",
  "HOST_URL",
  "PORT",
  "URL",
  "CONTAINER_IP",
  "CONTAINER_PORT",
}
