"""
container_app_runner.py
A Ratio1 plugin to run a single Docker/Podman container and (if needed) expose it via tunnel engine.

On-init:
  - CR login
  - Port allocation (optional)
  - Volume configuration (including FILE_VOLUMES)
  - Container run
  - tunnel (optional)
  - extra tunnels (optional)

Loop:
  - check and maybe reload container
  - retrieve logs and maybe show them

On-close:
  - stop container
  - stop tunnel (if needed)
  - stop extra tunnels (if configured)
  - stop logs process
  - save logs to disk

FILE_VOLUMES Feature:
  Allows dynamic creation and mounting of files with specified content into containers.

  Example configuration:
    FILE_VOLUMES = {
      "app_config": {
        "content": "server_port=8080\ndebug=true",
        "mounting_point": "/app/config/settings.conf"
      },
      "secret_key": {
        "content": "my-secret-api-key-12345",
        "mounting_point": "/etc/secrets/api.key"
      }
    }

  The plugin will:
    1. Extract filename from mounting_point (e.g., "settings.conf", "api.key")
    2. Create a directory under /edge_node/_local_cache/_data/container_volumes/
    3. Write the content to the file
    4. Mount the file into the container at the specified mounting_point

EXTRA_TUNNELS Feature:
  Allows exposing multiple container ports via Cloudflare tunnels.

  Example configuration:
    EXTRA_TUNNELS = {
      9000: "eyJhIjoiY2xvdWRmbGFyZV90b2tlbl8xIn0=",
      9090: "eyJhIjoiY2xvdWRmbGFyZV90b2tlbl8yIn0=",
    }

  Notes:
    - Dict keys can be strings or integers (container ports)
    - Values are Cloudflare tunnel tokens
    - Ports can be defined only in EXTRA_TUNNELS (not in CONTAINER_RESOURCES)
    - If TUNNEL_ENGINE_ENABLED=False, all tunnels (main + extra) are disabled
    - Each extra tunnel runs independently and auto-restarts on failure
    - URLs are extracted from logs and included in payloads


"""

import docker
import requests
import threading
import time
import socket
import subprocess
from enum import Enum
from dataclasses import dataclass
from typing import Optional

from docker.types import DeviceRequest

from naeural_core.business.base.web_app.base_tunnel_engine_plugin import BaseTunnelEnginePlugin as BasePlugin
from extensions.business.mixins.chainstore_response_mixin import _ChainstoreResponseMixin

from .container_utils import _ContainerUtilsMixin # provides container management support currently empty it is embedded in the plugin

__VER__ = "0.7.1"

from extensions.utils.memory_formatter import parse_memory_to_mb

# Persistent state filename (stored in instance-specific subfolder)
_PERSISTENT_STATE_FILE = "persistent_state.pkl"

# Subfolder prefix for container app data
_CONTAINER_APPS_SUBFOLDER = "container_apps"


class ContainerState(Enum):
  """Container lifecycle states for proper state machine management."""
  UNINITIALIZED = "uninitialized"  # Container not yet created
  STARTING = "starting"             # Container is being launched
  RUNNING = "running"               # Container is running normally
  STOPPING = "stopping"             # Container is being stopped
  STOPPED = "stopped"               # Container stopped gracefully
  FAILED = "failed"                 # Container crashed or exited with error
  RESTARTING = "restarting"         # Container is being restarted
  PAUSED = "paused"                 # Manual pause requested


class StopReason(Enum):
  """
  Reasons why a container stopped - used for restart policy decisions.

  Two categories of stop reasons:
  1. **Unplanned stops** (subject to RESTART_POLICY):
     - CRASH, NORMAL_EXIT, HEALTH_CHECK_FAILED, UNKNOWN
     - Policy determines if restart happens

  2. **Planned restarts** (bypass RESTART_POLICY):
     - IMAGE_UPDATE, CONFIG_UPDATE, EXTERNAL_UPDATE, MANUAL_STOP
     - These trigger restarts via _perform_periodic_monitoring()
     - Always executed regardless of policy (except MANUAL_STOP which pauses)

  Note: Subclasses can use EXTERNAL_UPDATE for domain-specific triggers
        (e.g., Git updates, database migrations, file changes)
  """
  # Unplanned stops
  UNKNOWN = "unknown"
  CRASH = "crash"                   # Container exited with non-zero code
  NORMAL_EXIT = "normal_exit"       # Container exited with code 0
  HEALTH_CHECK_FAILED = "health_check_failed"  # Health check failures

  # Planned restarts
  MANUAL_STOP = "manual_stop"       # User requested stop via command
  IMAGE_UPDATE = "image_update"     # Restarting for image update
  CONFIG_UPDATE = "config_update"   # Restarting for config change
  EXTERNAL_UPDATE = "external_update"  # Generic external trigger (VCS, DB, file watch, etc.)


class RestartPolicy(Enum):
  """
  Container restart policies (Docker-compatible).

  Policies:
    NO: Never restart the container
    ALWAYS: Always restart unless manually stopped
    ON_FAILURE: Only restart on non-zero exit codes
    UNLESS_STOPPED: Always restart unless explicitly stopped by user
  """
  NO = "no"
  ALWAYS = "always"
  ON_FAILURE = "on-failure"
  UNLESS_STOPPED = "unless-stopped"


class HealthCheckMode(Enum):
  """
  Health check modes for determining app readiness before starting tunnels.

  Modes:
    AUTO: Smart detection - uses ENDPOINT if path set, else TCP if port configured, else DELAY
    TCP: TCP port check - works for any protocol (HTTP, WebSocket, gRPC, raw TCP)
    ENDPOINT: HTTP probe to HEALTH_ENDPOINT_PATH - expects 2xx response
    DELAY: Simple time-based delay using TUNNEL_START_DELAY
  """
  AUTO = "auto"
  TCP = "tcp"
  ENDPOINT = "endpoint"
  DELAY = "delay"


@dataclass
class HealthCheckConfig:
  """
  Configuration for health check probing.

  Provides type-safe attribute access instead of dict key access.

  Attributes
  ----------
  mode : str
      Health check mode: "auto", "tcp", "endpoint", or "delay"
  path : str or None
      HTTP endpoint path for "endpoint" mode (e.g., "/health")
  port : int or None
      Container port for health check (None = use main PORT)
  delay : int
      Seconds before first probe / full delay for "delay" mode
  interval : int
      Seconds between probe attempts (tcp/endpoint modes)
  timeout : int
      Max wait time in seconds (0 = unlimited, probe forever)
  on_failure : str
      Behavior when timeout reached: "start" or "skip"
  """
  mode: str = "auto"
  path: Optional[str] = None
  port: Optional[int] = None
  delay: int = 30
  interval: int = 5
  timeout: int = 300
  on_failure: str = "start"

  @classmethod
  def from_dict(cls, config_dict: dict) -> "HealthCheckConfig":
    """
    Create HealthCheckConfig from a configuration dict.

    Parameters
    ----------
    config_dict : dict
        Configuration dict with keys matching attribute names (case-insensitive)

    Returns
    -------
    HealthCheckConfig
        New instance with values from dict (defaults for missing keys)
    """
    # Normalize keys to lowercase
    normalized = {k.lower(): v for k, v in config_dict.items() if v is not None}

    return cls(
      mode=str(normalized.get("mode", "auto")).lower().strip(),
      path=normalized.get("path"),
      port=normalized.get("port"),
      delay=normalized.get("delay", 30),
      interval=normalized.get("interval", 5),
      timeout=normalized.get("timeout", 300),
      on_failure=str(normalized.get("on_failure", "start")).lower().strip(),
    )


_CONFIG = {
  **BasePlugin.CONFIG,

  "PROCESS_DELAY": 5,  # seconds to wait between process calls
  "ALLOW_EMPTY_INPUTS": True,

  "NGROK_EDGE_LABEL": None,  # Optional ngrok edge label for the tunnel
  "NGROK_AUTH_TOKEN" : None,  # Optional ngrok auth token for the tunnel
  "NGROK_USE_API": True,
  'NGROK_DOMAIN': None,
  'NGROK_URL_PING_INTERVAL': 10, # seconds to ping the ngrok URL and to send it in payload
  'NGROK_URL_PING_COUNT': 10, # nr or times we send payload with ngrok url

  # Generic tunnel engine Section
  "TUNNEL_ENGINE": "cloudflare",

  "TUNNEL_ENGINE_ENABLED": True,
  "TUNNEL_ENGINE_PING_INTERVAL": 30,  # seconds
  "TUNNEL_ENGINE_PARAMETERS": {
  },

  # Cloudflare token for main tunnel (backward compatibility)
  "CLOUDFLARE_TOKEN": None,

  # Extra tunnels for additional ports: {container_port: "cloudflare_token"}
  "EXTRA_TUNNELS": {},
  "EXTRA_TUNNELS_PING_INTERVAL": 30,  # seconds to ping extra tunnel URLs


  # TODO: this flag needs to be renamed both here and in the ngrok mixin
  "DEBUG_WEB_APP": False,  # If True, will run the web app in debug mode
  "CAR_VERBOSE": 1,

  # Container-specific config options
  "IMAGE": None,            # Required container image, e.g. "my_repo/my_app:latest"
  "CONTAINER_START_COMMAND": None,  # Optional command list executed when launching the container
  "BUILD_AND_RUN_COMMANDS": [],     # Optional commands executed inside the running container
  "CR_DATA": {              # dict of container registry data
    "SERVER": 'docker.io',  # Optional container registry URL
    "USERNAME": None,       # Optional registry username
    "PASSWORD": None,       # Optional registry password or token
  },
  "ENV": {},                # dict of env vars for the container
  "DYNAMIC_ENV": {},        # dict of dynamic env vars for the container
  "PORT": None,             # internal container port if it's a web app (int)
  "CONTAINER_RESOURCES" : {
    "cpu": 1,          # e.g. "0.5" for half a CPU, or "1.0" for one CPU core
    "gpu": 0,          # 0 - no GPU, 1 - use GPU
    "memory": "512m",  # e.g. "512m" for 512MB,
    "ports": []        # dict of host_port: container_port mappings (e.g. {8080: 8081}) or list of container ports (e.g. [8080, 9000])
  },
  "RESTART_POLICY": "always",  # "always", "on-failure", "unless-stopped", "no"
  "IMAGE_PULL_POLICY": "always",  # "always" will always pull the image
  "AUTOUPDATE" : True, # If True, will check for image updates and pull them if available
  "AUTOUPDATE_INTERVAL": 100,

  # Restart retry configuration (exponential backoff)
  "RESTART_MAX_RETRIES": 5,     # Max consecutive restart attempts before giving up (0 = unlimited)
  "RESTART_BACKOFF_INITIAL": 2,  # Initial backoff delay in seconds
  "RESTART_BACKOFF_MAX": 300,    # Maximum backoff delay in seconds (5 minutes)
  "RESTART_BACKOFF_MULTIPLIER": 2,  # Backoff multiplier for exponential backoff
  "RESTART_RESET_INTERVAL": 300,  # Reset retry count after this many seconds of successful run

  # Tunnel restart retry configuration (exponential backoff)
  "TUNNEL_RESTART_MAX_RETRIES": 5,     # Max consecutive tunnel restart attempts (0 = unlimited)
  "TUNNEL_RESTART_BACKOFF_INITIAL": 2,  # Initial tunnel backoff delay in seconds
  "TUNNEL_RESTART_BACKOFF_MAX": 60,     # Maximum tunnel backoff delay in seconds (1 minute)
  "TUNNEL_RESTART_BACKOFF_MULTIPLIER": 2,  # Tunnel backoff multiplier
  "TUNNEL_RESTART_RESET_INTERVAL": 300,  # Reset tunnel retry count after successful run

  "VOLUMES": {},                # dict mapping host paths to container paths, e.g. {"/host/path": "/container/path"}
  "FILE_VOLUMES": {},           # dict mapping host paths to file configs: {"host_path": {"content": "...", "mounting_point": "..."}}

  # Health check configuration (consolidated)
  # Controls how app readiness is determined before starting tunnels
  #
  # Usage examples:
  #   "HEALTH_CHECK": {}                           # TCP check with all defaults
  #   "HEALTH_CHECK": {"PATH": "/health"}          # HTTP endpoint check
  #   "HEALTH_CHECK": {"MODE": "delay", "DELAY": 60}  # Simple delay, no probing
  #   "HEALTH_CHECK": {"PATH": "/health", "TIMEOUT": 0}  # Probe forever until success
  #
  "HEALTH_CHECK": {
    "MODE": "auto",        # "auto" | "tcp" | "endpoint" | "delay"
                           #   "auto": Smart detection (default)
                           #     - If PATH set -> HTTP probe to that path
                           #     - Else if PORT configured -> TCP port check
                           #     - Else -> no delay (immediate ready)
                           #   "tcp": TCP port check (works for any protocol)
                           #   "endpoint": HTTP probe to PATH (requires PATH)
                           #   "delay": Simple wait, no probing
    "PATH": None,          # HTTP endpoint path (e.g., "/health", "/api/ready")
    "PORT": None,          # Container port for health check (None = use main PORT)
    "DELAY": 30,           # Seconds before first probe / full delay for "delay" mode
    "INTERVAL": 5,         # Seconds between probe attempts (tcp/endpoint modes)
    "TIMEOUT": 300,        # Max wait time in seconds (0 = unlimited, probe forever)
    "ON_FAILURE": "start", # "start" | "skip" - behavior when timeout reached
  },

  #### Logging
  "SHOW_LOG_EACH" : 60,       # seconds to show logs
  "SHOW_LOG_LAST_LINES" : 5,  # last lines to show
  "MAX_LOG_LINES" : 10_000,   # max lines to keep in memory
  # When container is STOPPED_MANUALLY (PAUSED state), this will define how often we log its existance
  "PAUSED_STATE_LOG_INTERVAL": 60,

  # Semaphore synchronization for paired plugins
  # List of semaphore keys to wait for before starting container
  "SEMAPHORED_KEYS": [],
  # How often to log waiting status (seconds)
  "SEMAPHORE_LOG_INTERVAL": 10,

  # end of container-specific config options

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class ContainerAppRunnerPlugin(
  BasePlugin,
  _ContainerUtilsMixin,
  _ChainstoreResponseMixin,
):
  """
  A Ratio1 plugin to run a single Docker/Podman container.

  This plugin:
    - Logs in to a container registry if CR_USER and CR_PASSWORD are provided.
    - Allocates a host port if PORT is provided and exposes it via cloudflare using an access token.
    - Runs the container with optional CPU and memory constraints.
    - Captures logs in real-time using the LogReader class.
    - Stores logs to disk upon plugin close using diskapi_save_pickle_to_output.
    - Supports a restart policy: "always" or ... not
    - Supports pull policy: "always" or ... not
  """

  CONFIG = _CONFIG

  @property
  def port(self):
      return getattr(self, '_port', None)


  @port.setter
  def port(self, value):
      self._port = value


  def Pd(self, s, *args, score=-1, **kwargs):
    """
    Print debug message if verbosity level allows.

    Parameters
    ----------
    s : str
        Message to print
    score : int, optional
        Verbosity threshold (default: -1). Message prints if cfg_car_verbose > score
    *args
        Additional positional arguments passed to P()
    **kwargs
        Additional keyword arguments passed to P()

    Returns
    -------
    None
    """
    if self.cfg_car_verbose > score:
      s = "[DEBUG] " + s
      self.P(s, *args, **kwargs)
    return


  def __reset_vars(self):
    self.container = None
    self.container_id = None
    self.container_name = self.cfg_instance_id + "_" + self.uuid(4)

    # Initialize Docker client with proper error handling
    try:
      self.docker_client = docker.from_env()
      # Verify Docker daemon is accessible by pinging it
      self.docker_client.ping()
    except docker.errors.DockerException as e:
      raise RuntimeError(
        f"Failed to connect to Docker daemon: {e}\n"
        "Please ensure Docker is installed and running:\n"
        "  - Check: systemctl status docker (Linux) or Docker Desktop (Windows/Mac)\n"
        "  - Start: systemctl start docker (Linux) or start Docker Desktop\n"
        "  - Verify: docker ps"
      ) from e
    except Exception as e:
      raise RuntimeError(
        f"Unexpected error initializing Docker client: {e}\n"
        "Please verify Docker installation and permissions."
      ) from e

    self.container_logs = self.deque(maxlen=self.cfg_max_log_lines)

    # Handle port allocation for main port and additional ports
    self.extra_ports_mapping = {}  # Dictionary to store host_port -> container_port mappings
    self.inverted_ports_mapping = {} # inverted mapping for docker-py container_port -> host_port

    self.volumes = {}
    self.env = {}
    self.dynamic_env = {}

    # Container state machine
    self.container_state = ContainerState.UNINITIALIZED
    self.stop_reason = StopReason.UNKNOWN

    # Restart policy and retry logic
    self._consecutive_failures = 0
    self._last_failure_time = 0
    self._next_restart_time = 0
    self._restart_backoff_seconds = 0
    self._last_successful_start = None

    # Initialize tunnel process
    self.tunnel_process = None

    # Extra tunnels management
    self.extra_tunnel_processes = {}  # Dict: {container_port: process_handle}
    self.extra_tunnel_urls = {}       # Dict: {container_port: public_url}
    self.extra_tunnel_log_readers = {}  # Dict: {container_port: {"stdout": reader, "stderr": reader}}
    self.extra_tunnel_configs = {}    # Dict: {container_port: token}
    self.extra_tunnel_start_times = {}  # Dict: {container_port: timestamp}

    # Tunnel restart backoff tracking (per port)
    self._tunnel_consecutive_failures = {}  # Dict: {container_port: failure_count}
    self._tunnel_last_failure_time = {}     # Dict: {container_port: timestamp}
    self._tunnel_next_restart_time = {}     # Dict: {container_port: timestamp}
    self._tunnel_last_successful_start = {} # Dict: {container_port: timestamp}

    # Log streaming
    self.log_thread = None
    self.exec_threads = []
    self._stop_event = threading.Event()

    # Container start time tracking
    self.container_start_time = None

    # Periodic intervals
    self._last_image_check = 0
    self._last_extra_tunnels_ping = 0
    self._last_paused_log = 0  # Track when we last logged the paused message

    # Image update tracking
    self.current_image_hash = None

    # Command execution state
    self._commands_started = False

    # App readiness tracking (for tunnel startup gating)
    self._app_ready = False
    self._health_probe_start = None
    self._last_health_probe = 0
    self._health_probing_disabled = False  # Set True if health config is invalid

    # Tunnel startup gating
    self._tunnel_start_allowed = False

    self._after_reset()

    return


  def _after_reset(self):
    """
    Hook for subclasses to reset additional state.

    Called after parent reset to allow subclasses to initialize
    their own state variables.

    Returns
    -------
    None
    """
    return

  # ============================================================================
  # Persistent State Management (General Purpose)
  # ============================================================================


  def _get_instance_data_subfolder(self):
    """
    Get instance-specific subfolder for persistent data.

    Uses plugin_id to ensure each plugin instance has its own data folder,
    preventing collisions when multiple containers run on the same node.

    Structure: container_apps/{plugin_id}/
      - persistent_state.pkl
      - (future: logs, etc.)

    Returns
    -------
    str
        Subfolder path: container_apps/{plugin_id}
    """
    return f"{_CONTAINER_APPS_SUBFOLDER}/{self.plugin_id}"


  def _load_persistent_state(self):
    """
    Load persistent state from disk.

    Returns
    -------
    dict
        Persistent state dictionary (empty dict if no state exists)
    """
    state = self.diskapi_load_pickle_from_data(
      _PERSISTENT_STATE_FILE,
      subfolder=self._get_instance_data_subfolder()
    )
    return state if state is not None else {}


  def _save_persistent_state(self, **kwargs):
    """
    Save or update persistent state fields.

    Parameters
    ----------
    **kwargs
        State fields to save/update (e.g., manually_stopped=True)

    Returns
    -------
    None

    Examples
    --------
    >>> self._save_persistent_state(manually_stopped=True, last_config_hash="abc123")
    """
    # Load existing state
    state = self._load_persistent_state()
    # Update with new values
    state.update(kwargs)
    # Save back to disk
    self.diskapi_save_pickle_to_data(
      state,
      _PERSISTENT_STATE_FILE,
      subfolder=self._get_instance_data_subfolder()
    )
    return


  def _load_manual_stop_state(self):
    """
    Load manual stop state from persistent storage.

    Returns
    -------
    bool
        True if container was manually stopped, False otherwise
    """
    state = self._load_persistent_state()
    return state.get("manually_stopped", False)


  def _clear_manual_stop_state(self):
    """
    Clear manual stop state (called on RESTART command).

    Returns
    -------
    None
    """
    self._save_persistent_state(manually_stopped=False)
    return

  # ============================================================================
  # End of Persistent State Management
  # ============================================================================

  # ============================================================================
  # Restart Policy and Retry Logic
  # ============================================================================


  def _normalize_restart_policy(self, policy):
    """
    Normalize restart policy to RestartPolicy enum.

    Parameters
    ----------
    policy : str, RestartPolicy, or None
        Policy string, enum, or None

    Returns
    -------
    RestartPolicy
        Normalized RestartPolicy enum value
    """
    if policy is None:
      return RestartPolicy.NO

    # Already an enum
    if isinstance(policy, RestartPolicy):
      return policy

    # Convert string to enum (case-insensitive)
    if isinstance(policy, str):
      policy_str = policy.lower().strip()
      try:
        return RestartPolicy(policy_str)
      except ValueError:
        self.P(f"Unknown restart policy '{policy}', defaulting to 'no'", color='r')
        return RestartPolicy.NO

    # Unknown type
    self.P(f"Invalid restart policy type {type(policy)}, defaulting to 'no'", color='r')
    return RestartPolicy.NO


  def _should_restart_container(self, stop_reason=None):
    """
    Determine if container should be restarted based on RESTART_POLICY and stop reason.

    Implements Docker-style restart policies:
    - NO: Never restart
    - ALWAYS: Always restart (unless manually stopped)
    - ON_FAILURE: Restart only on non-zero exit code
    - UNLESS_STOPPED: Always restart unless explicitly stopped by user

    Parameters
    ----------
    stop_reason : StopReason, optional
        StopReason enum value indicating why container stopped

    Returns
    -------
    bool
        True if container should be restarted
    """
    policy = self._normalize_restart_policy(self.cfg_restart_policy)
    stop_reason = stop_reason or self.stop_reason

    # Never restart if manually stopped (user sent STOP command)
    if stop_reason == StopReason.MANUAL_STOP:
      self.Pd(f"Container manually stopped, restart policy '{policy.value}' will not trigger restart")
      return False

    # Check if we're in PAUSED state
    if self.container_state == ContainerState.PAUSED:
      self.Pd("Container is paused, restart policy will not trigger restart")
      return False

    # Policy: NO - never restart
    if policy == RestartPolicy.NO:
      return False

    # Policy: ALWAYS - restart unless manually stopped
    if policy == RestartPolicy.ALWAYS:
      return True

    # Policy: UNLESS_STOPPED - same as always in this implementation
    if policy == RestartPolicy.UNLESS_STOPPED:
      return True

    # Policy: ON_FAILURE - only restart on crashes
    if policy == RestartPolicy.ON_FAILURE:
      return stop_reason in [
        StopReason.CRASH,
        StopReason.HEALTH_CHECK_FAILED,
        StopReason.UNKNOWN,
      ]

    # Fallback (should never reach here due to normalization)
    self.P(f"Unhandled restart policy '{policy}', defaulting to no restart", color='r')
    return False


  def _calculate_restart_backoff(self):
    """
    Calculate exponential backoff delay for restart attempts.

    Returns
    -------
    float
        Seconds to wait before next restart attempt
    """
    if self._consecutive_failures == 0:
      return 0

    # Exponential backoff: initial * (multiplier ^ (failures - 1))
    backoff = self.cfg_restart_backoff_initial * (
      self.cfg_restart_backoff_multiplier ** (self._consecutive_failures - 1)
    )

    # Cap at maximum backoff
    backoff = min(backoff, self.cfg_restart_backoff_max)

    return backoff


  def _should_reset_retry_counter(self):
    """
    Check if container has been running long enough to reset retry counter.

    Returns
    -------
    bool
        True if retry counter should be reset
    """
    if not self._last_successful_start:
      return False

    uptime = self.time() - self._last_successful_start
    return uptime >= self.cfg_restart_reset_interval


  def _record_restart_failure(self):
    """
    Record a restart failure and update backoff state.

    Returns
    -------
    None
    """
    self._consecutive_failures += 1
    self._last_failure_time = self.time()
    self._restart_backoff_seconds = self._calculate_restart_backoff()
    self._next_restart_time = self.time() + self._restart_backoff_seconds

    self.P(
      f"Container restart failure #{self._consecutive_failures}. "
      f"Next retry in {self._restart_backoff_seconds:.1f}s",
      color='r'
    )
    return


  def _record_restart_success(self):
    """
    Record a successful restart and reset failure counters if appropriate.

    Returns
    -------
    None
    """
    self._last_successful_start = self.time()

    # Reset failure counter after first successful start
    if self._consecutive_failures > 0:
      self.P(
        f"Container started successfully after {self._consecutive_failures} failure(s). "
        f"Retry counter will reset after {self.cfg_restart_reset_interval}s of uptime.",
      )
      # Don't reset immediately - wait for reset interval
      # self._consecutive_failures = 0  # This happens in _maybe_reset_retry_counter
    # end if
    return


  def _maybe_reset_retry_counter(self):
    """
    Reset retry counter if container has been running successfully.

    Returns
    -------
    None
    """
    if self._consecutive_failures > 0 and self._should_reset_retry_counter():
      old_failures = self._consecutive_failures
      self._consecutive_failures = 0
      self._restart_backoff_seconds = 0
      self.P(
        f"Container running successfully for {self.cfg_restart_reset_interval}s. "
        f"Reset failure counter (was {old_failures})"
      )
    # end if
    return


  def _is_restart_backoff_active(self):
    """
    Check if we're currently in backoff period.

    Returns
    -------
    bool
        True if we should wait before restarting
    """
    if self._next_restart_time == 0:
      return False

    current_time = self.time()
    if current_time < self._next_restart_time:
      remaining = self._next_restart_time - current_time
      self.Pd(f"Restart backoff active: {remaining:.1f}s remaining")
      return True

    return False


  def _has_exceeded_max_retries(self):
    """
    Check if max retry attempts exceeded.

    Returns
    -------
    bool
        True if max retries exceeded (and max_retries > 0)
    """
    if self.cfg_restart_max_retries <= 0:
      return False  # Unlimited retries

    return self._consecutive_failures >= self.cfg_restart_max_retries


  def _set_container_state(self, new_state, stop_reason=None):
    """
    Update container state and optionally stop reason.

    Parameters
    ----------
    new_state : ContainerState
        ContainerState enum value
    stop_reason : StopReason, optional
        Optional StopReason enum value

    Returns
    -------
    None
    """
    old_state = self.container_state
    self.container_state = new_state

    if stop_reason:
      self.stop_reason = stop_reason
    # end if

    self.Pd(f"Container state: {old_state.value} -> {new_state.value}", score=0)
    return

  # ============================================================================
  # End of Restart Policy Logic
  # ============================================================================

  # ============================================================================
  # Health Check Configuration
  # ============================================================================


  def _get_health_config(self) -> HealthCheckConfig:
    """
    Get effective health check configuration with defaults.

    Merges HEALTH_CHECK dict values with defaults.

    Returns
    -------
    HealthCheckConfig
        Complete health check configuration with attributes:
        - mode: "auto" | "tcp" | "endpoint" | "delay"
        - path: HTTP endpoint path or None
        - port: Container port or None (uses main PORT)
        - delay: Seconds before first probe
        - interval: Seconds between probes
        - timeout: Max wait time (0 = unlimited)
        - on_failure: "start" | "skip"
    """
    health_check_dict = getattr(self, 'cfg_health_check', None) or {}
    return HealthCheckConfig.from_dict(health_check_dict)


  def _get_effective_health_mode(self, health_config: HealthCheckConfig = None) -> HealthCheckMode:
    """
    Determine the effective health check mode based on configuration.

    For "auto" mode, determines the best check method:
    - If PATH set -> ENDPOINT
    - Else if PORT configured -> TCP
    - Else -> DELAY (no ports to check)

    Parameters
    ----------
    health_config : HealthCheckConfig, optional
        Health config (from _get_health_config). If None, fetches it.

    Returns
    -------
    HealthCheckMode
        Effective health check mode enum value
    """
    if health_config is None:
      health_config = self._get_health_config()

    # Try to convert string to enum
    try:
      mode_enum = HealthCheckMode(health_config.mode)
    except ValueError:
      self.P(f"Unknown HEALTH_CHECK MODE '{health_config.mode}', using 'auto'", color='y')
      mode_enum = HealthCheckMode.AUTO

    # Validate endpoint mode has required path
    if mode_enum == HealthCheckMode.ENDPOINT:
      if not health_config.path:
        self.P(
          "HEALTH_CHECK MODE='endpoint' requires PATH to be set. "
          "Falling back to 'tcp' mode.",
          color='y'
        )
        return HealthCheckMode.TCP if self.cfg_port else HealthCheckMode.DELAY
      return HealthCheckMode.ENDPOINT

    # Direct modes pass through
    if mode_enum in (HealthCheckMode.TCP, HealthCheckMode.DELAY):
      return mode_enum

    # Auto mode: smart detection
    if health_config.path:
      return HealthCheckMode.ENDPOINT
    elif self.cfg_port:
      return HealthCheckMode.TCP
    return HealthCheckMode.DELAY

  # ============================================================================
  # End of Health Check Configuration
  # ============================================================================

  # ============================================================================
  # Tunnel Restart Backoff Logic
  # ============================================================================


  def _calculate_tunnel_backoff(self, container_port):
    """
    Calculate exponential backoff delay for tunnel restart attempts.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    float
        Seconds to wait before next tunnel restart attempt
    """
    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    if failures == 0:
      return 0

    # Exponential backoff: initial * (multiplier ^ (failures - 1))
    backoff = self.cfg_tunnel_restart_backoff_initial * (
      self.cfg_tunnel_restart_backoff_multiplier ** (failures - 1)
    )

    # Cap at maximum backoff
    backoff = min(backoff, self.cfg_tunnel_restart_backoff_max)

    return backoff


  def _record_tunnel_restart_failure(self, container_port):
    """
    Record a tunnel restart failure and update backoff state.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    None
    """
    self._tunnel_consecutive_failures[container_port] = \
      self._tunnel_consecutive_failures.get(container_port, 0) + 1
    self._tunnel_last_failure_time[container_port] = self.time()

    backoff = self._calculate_tunnel_backoff(container_port)
    self._tunnel_next_restart_time[container_port] = self.time() + backoff

    failures = self._tunnel_consecutive_failures[container_port]
    self.P(
      f"Tunnel restart failure for port {container_port} (#{failures}). "
      f"Next retry in {backoff:.1f}s",
      color='r'
    )
    return


  def _record_tunnel_restart_success(self, container_port):
    """
    Record a successful tunnel restart.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    None
    """
    self._tunnel_last_successful_start[container_port] = self.time()

    # Note success if there were previous failures
    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    if failures > 0:
      self.P(
        f"Tunnel for port {container_port} started successfully after {failures} failure(s)."
      )
    return


  def _is_tunnel_backoff_active(self, container_port):
    """
    Check if tunnel is currently in backoff period.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    bool
        True if we should wait before restarting tunnel
    """
    next_restart = self._tunnel_next_restart_time.get(container_port, 0)
    if next_restart == 0:
      return False

    current_time = self.time()
    if current_time < next_restart:
      remaining = next_restart - current_time
      self.Pd(f"Tunnel {container_port} backoff active: {remaining:.1f}s remaining")
      return True

    return False


  def _has_tunnel_exceeded_max_retries(self, container_port):
    """
    Check if tunnel has exceeded max retry attempts.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    bool
        True if max retries exceeded (and max_retries > 0)
    """
    if self.cfg_tunnel_restart_max_retries <= 0:
      return False  # Unlimited retries

    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    return failures >= self.cfg_tunnel_restart_max_retries


  def _maybe_reset_tunnel_retry_counter(self, container_port):
    """
    Reset tunnel retry counter if it has been running successfully.

    Parameters
    ----------
    container_port : int
        Container port for the tunnel

    Returns
    -------
    None
    """
    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    if failures == 0:
      return

    last_start = self._tunnel_last_successful_start.get(container_port, 0)
    if not last_start:
      return

    uptime = self.time() - last_start
    if uptime >= self.cfg_tunnel_restart_reset_interval:
      self.P(
        f"Tunnel {container_port} running successfully for {self.cfg_tunnel_restart_reset_interval}s. "
        f"Reset failure counter (was {failures})",
      )
      self._tunnel_consecutive_failures[container_port] = 0

    return

  # ============================================================================
  # End of Tunnel Restart Backoff Logic
  # ============================================================================


  def _normalize_container_command(self, value, *, field_name):
    """
    Normalize a container command into a Docker-compatible representation.

    Parameters
    ----------
    value : str, list, tuple, or None
        Command to normalize
    field_name : str
        Name of the configuration field (for error messages)

    Returns
    -------
    str, list, or None
        Normalized command ready for Docker

    Raises
    ------
    ValueError
        If command format is invalid
    """
    if value is None:
      return None

    if isinstance(value, str):
      normalized = value.strip()
      return normalized or None

    if isinstance(value, (list, tuple)):
      command = [str(part).strip() for part in value]
      if not all(command):
        raise ValueError(f"{field_name} entries must be non-empty strings")
      return command

    raise ValueError(f"{field_name} must be None, a string, or a list/tuple of strings")


  def _normalize_command_sequence(self, value, *, field_name):
    """
    Normalize build/run command sequences into a list of shell fragments.

    Parameters
    ----------
    value : str, list, tuple, or None
        Command sequence to normalize
    field_name : str
        Name of the configuration field (for error messages)

    Returns
    -------
    list of str
        Normalized command list

    Raises
    ------
    ValueError
        If command sequence format is invalid
    """
    if value is None:
      return []

    if isinstance(value, str):
      normalized = value.strip()
      return [normalized] if normalized else []

    if isinstance(value, (list, tuple)):
      commands = [str(cmd).strip() for cmd in value if str(cmd).strip()]
      if len(commands) != len(value):
        raise ValueError(f"{field_name} entries must be non-empty strings")
      return commands

    raise ValueError(f"{field_name} must be a string or an iterable of strings")


  def _validate_runner_config(self):
    """
    Validate configuration and prepare normalized command data.

    Returns
    -------
    None

    Raises
    ------
    ValueError
        If configuration is invalid
    """
    self._start_command = self._normalize_container_command(
      getattr(self, 'cfg_container_start_command', None),
      field_name='CONTAINER_START_COMMAND',
    )

    self._build_commands = self._normalize_command_sequence(
      getattr(self, 'cfg_build_and_run_commands', None),
      field_name='BUILD_AND_RUN_COMMANDS',
    )

    # Validate health endpoint port (soft error - disables health probing if invalid)
    self._validate_health_endpoint_port()

    self._validate_subclass_config()
    return


  def _validate_subclass_config(self):
    """
    Hook for subclasses to enforce additional validation.

    Allows subclasses to add their own configuration validation
    beyond the base container configuration checks.

    Returns
    -------
    None

    Raises
    ------
    ValueError
        If subclass-specific validation fails
    """
    return


  def on_init(self):
    """
    Lifecycle hook called once the plugin is initialized.

    Performs initial setup including:
    - Container registry authentication
    - Docker client initialization
    - Dynamic environment variable configuration
    - Resource limits and port allocation
    - Volume and file volume configuration
    - Extra tunnels validation
    - Manual stop state checking

    Returns
    -------
    None

    Raises
    ------
    RuntimeError
        If Docker daemon is not accessible or registry authentication fails
    """
    self._reset_chainstore_response()
    self.__reset_vars()

    super(ContainerAppRunnerPlugin, self).on_init()

    self.container_start_time = self.time()

    # Login to container registry if credentials are provided
    if not self._login_to_registry():
      raise RuntimeError("Failed to login to container registry. Cannot proceed without authentication.")

    self.reset_tunnel_engine()

    self._configure_dynamic_env() # setup dynamic env vars for the container
    self._setup_resource_limits_and_ports() # setup container resource limits (CPU, GPU, memory, ports)
    self._configure_volumes() # setup container volumes
    self._configure_file_volumes() # setup file volumes with dynamic content

    # If we have semaphored keys, defer _setup_env_and_ports() until semaphores are ready
    # This ensures we get the env vars from provider plugins before starting the container
    if not self._semaphore_get_keys():
      self._setup_env_and_ports()
    else:
      self.Pd("Deferring _setup_env_and_ports() until semaphores are ready")

    # Validate extra tunnels configuration
    self._validate_extra_tunnels_config()

    self._validate_runner_config()

    # Check if container was manually stopped in a previous session
    if self._load_manual_stop_state():
      self.P("Container was manually stopped in previous session. Keeping container paused.")
      self._set_container_state(ContainerState.PAUSED, StopReason.MANUAL_STOP)

    self._extra_on_init()
    self.P(f"{self.__class__.__name__} initialized (version {__VER__})")
    return

  
  def _extra_on_init(self):
    """
    Hook for subclasses to perform additional initialization.

    Called at the end of on_init() to allow subclasses to add
    their own initialization logic.

    Returns
    -------
    None
    """
    return


  def on_command(self, data, **kwargs):
    """
    Handle instance commands sent to the plugin.

    Processes commands sent via cmdapi_send_instance_command from
    commanding nodes. Supported commands:
    - RESTART: Restart the container
    - STOP: Stop container and enter paused state

    Parameters
    ----------
    data : str
        Command string to execute
    **kwargs
        Additional command parameters

    Returns
    -------
    None

    Examples
    --------
    Sending a command from another plugin:
        >>> plugin.cmdapi_send_instance_command(
        ...     pipeline="app_pipeline",
        ...     signature="CONTAINER_APP_RUNNER",
        ...     instance_id="CONTAINER_APP_1e8dac",
        ...     instance_command="RESTART",
        ...     node_address="0xai_..."
        ... )
    """
    self.P(f"Received a command: {data}")
    self.P(f"Command kwargs: {kwargs}")

    if data == "RESTART":
      self.P("Restarting container...")
      self._clear_manual_stop_state()  # Clear persistent stop state
      self._set_container_state(ContainerState.RESTARTING, StopReason.CONFIG_UPDATE)
      self._stop_container_and_save_logs_to_disk()
      self._restart_container(StopReason.CONFIG_UPDATE)
      return

    elif data == "STOP":
      self.P("Stopping container (manual stop - restart policy will not trigger)...")
      self._save_persistent_state(manually_stopped=True)  # Save persistent stop state
      self._stop_container_and_save_logs_to_disk()
      self._set_container_state(ContainerState.PAUSED, StopReason.MANUAL_STOP)
      return
    else:
      self.P(f"Unknown plugin command: {data}")
    return


  def _handle_config_restart(self, restart_callable):
    """
    Handle container restart when configuration changes.

    Stops the current container and invokes the provided restart callable
    to reinitialize with new configuration.

    Parameters
    ----------
    restart_callable : callable
        Function to call after stopping container to perform restart

    Returns
    -------
    None

    Notes
    -----
    If the container is in PAUSED state (manual stop), this method will NOT
    restart the container. The user must send a RESTART command to resume.
    """
    self.P(f"Received an updated config for {self.__class__.__name__}")

    # Check if container is paused (manual stop) - do NOT restart
    if self.container_state == ContainerState.PAUSED:
      self.P(
        "Container is in PAUSED state (manual stop). "
        "Ignoring config restart. Send RESTART command to resume.",
        color='y'
      )
      return

    # Check persistent state as fallback (in case container_state not yet set)
    if self._load_manual_stop_state():
      self.P(
        "Container was manually stopped (persistent state). "
        "Ignoring config restart. Send RESTART command to resume.",
        color='y'
      )
      return

    self._stop_container_and_save_logs_to_disk()
    restart_callable()
    return


  def on_config(self, *args, **kwargs):
    """
    Lifecycle hook called when configuration changes.

    Stops current container and restarts with new configuration.

    Parameters
    ----------
    *args
        Positional arguments (unused)
    **kwargs
        Keyword arguments (unused)

    Returns
    -------
    None
    """
    return self._handle_config_restart(lambda: self._restart_container(StopReason.CONFIG_UPDATE))


  def on_post_container_start(self):
    """
    Lifecycle hook called after container starts.

    Runs commands in the container if specified in the config.
    Called both after initial start and after restarts.

    Returns
    -------
    None

    Notes
    -----
    This is a hook method that subclasses can override to add
    custom post-start behavior.
    """
    self.P("Container started, running post-start commands...")
    return


  def start_tunnel_engine(self):
    """
    Start the main tunnel engine (Cloudflare or ngrok).

    Initiates tunnel process using base tunnel engine functionality
    to expose container ports via public URL.

    Returns
    -------
    None

    Notes
    -----
    Only starts if TUNNEL_ENGINE_ENABLED is True. Tunnel type
    is determined by use_cloudflare() method.
    """
    if self.cfg_tunnel_engine_enabled:
      engine_name = "Cloudflare" if self.use_cloudflare() else "ngrok"
      self.P(f"Starting {engine_name} tunnel...")
      self.tunnel_process = self.run_tunnel_engine()
      if self.tunnel_process:
        self.P(f"{engine_name} tunnel started successfully")
      else:
        self.P(f"Failed to start {engine_name} tunnel", color='r')
      # end if
    # end if
    return


  def stop_tunnel_engine(self):
    """
    Stop the main tunnel engine.

    Terminates the running tunnel process and cleans up resources.

    Returns
    -------
    None
    """
    if self.tunnel_process:
      engine_name = "Cloudflare" if self.use_cloudflare() else "ngrok"
      self.P(f"Stopping {engine_name} tunnel...")
      self.stop_tunnel_command(self.tunnel_process)
      self.tunnel_process = None
      self.P(f"{engine_name} tunnel stopped")
    # end if
    return


  def get_tunnel_engine_ping_data(self):
    """
    Get tunnel data including main app_url and extra tunnel URLs.

    Returns
    -------
    dict
        Tunnel data including:
        - app_url: Main tunnel URL (if available)
        - extra_tunnel_urls: Dict mapping container ports to URLs
        - extra_tunnel_status: Status of each extra tunnel
    """
    result = {}

    # Main tunnel URL (backward compatible)
    if self.app_url is not None:
      result['app_url'] = self.app_url

    # Extra tunnel URLs
    if self.extra_tunnel_urls:
      result['extra_tunnel_urls'] = self.deepcopy(self.extra_tunnel_urls)
      # Format: {8080: "https://xxx.trycloudflare.com", 9000: "https://yyy.trycloudflare.com"}

    # Extra tunnel status
    if self.extra_tunnel_processes:
      tunnel_status = {}
      for container_port, process in self.extra_tunnel_processes.items():
        tunnel_status[container_port] = {
          "running": process.poll() is None,
          "url": self.extra_tunnel_urls.get(container_port),
          "start_time": self.time_to_str(self.extra_tunnel_start_times.get(container_port)),
          "uptime_seconds": int(self.time() - self.extra_tunnel_start_times.get(container_port, self.time())),
        }
      result['extra_tunnel_status'] = tunnel_status

    return result


  def maybe_extra_tunnels_ping(self):
    """
    Emit periodic pings with extra tunnel URLs and status.

    Sends heartbeat payloads containing extra tunnel URLs and
    their operational status at configured intervals.

    Returns
    -------
    None
    """
    if not self.extra_tunnel_urls:
      return

    ping_interval = self.cfg_extra_tunnels_ping_interval
    if ping_interval is None or not isinstance(ping_interval, (int, float)):
      return

    ping_interval = max(ping_interval, 0)
    current_time = self.time()

    if current_time - self._last_extra_tunnels_ping >= ping_interval:
      ping_data = {}

      # Add extra tunnel URLs
      if self.extra_tunnel_urls:
        ping_data['extra_tunnel_urls'] = self.deepcopy(self.extra_tunnel_urls)

      # Add status for each tunnel
      if self.extra_tunnel_processes:
        tunnel_status = {}
        for container_port, process in self.extra_tunnel_processes.items():
          tunnel_status[container_port] = {
            "running": process.poll() is None,
            "url": self.extra_tunnel_urls.get(container_port),
            "uptime_seconds": int(current_time - self.extra_tunnel_start_times.get(container_port, current_time)),
          }
        ping_data['extra_tunnel_status'] = tunnel_status

      if ping_data:
        self.add_payload_by_fields(**ping_data)
        self._last_extra_tunnels_ping = current_time
        self.Pd(f"Extra tunnels ping sent: {len(self.extra_tunnel_urls)} tunnel(s)")

    return


  def _get_host_port_for_container_port(self, container_port):
    """
    Get the host port mapped to a container port.

    Parameters
    ----------
    container_port : int
        Container port to look up

    Returns
    -------
    int or None
        Host port if found, None otherwise
    """
    # Check main port first
    if container_port == self.cfg_port:
      return self.port

    # Check extra ports mapping
    for host_port, c_port in self.extra_ports_mapping.items():
      if c_port == container_port:
        return host_port
    return None


  def _get_valid_container_ports(self):
    """
    Get set of valid container ports for health checking.

    Valid ports are:
    1. Main port (cfg_port)
    2. Extra ports from ports_mapping (container ports)

    Returns
    -------
    set of int
        Set of valid container ports
    """
    valid_ports = set()

    # Main port
    if self.cfg_port:
      valid_ports.add(self.cfg_port)

    # Extra ports (container ports from mapping)
    for container_port in self.extra_ports_mapping.values():
      valid_ports.add(container_port)

    return valid_ports


  def _validate_health_endpoint_port(self):
    """
    Validate HEALTH_CHECK.PORT is a configured container port.

    Soft error handling: If port is invalid, logs error and disables
    health probing (falls back to DELAY mode).

    Returns
    -------
    bool
        True if valid or not configured, False if invalid (probing disabled)
    """
    health = self._get_health_config()
    if health.port is None:
      return True  # Will use main port

    valid_ports = self._get_valid_container_ports()

    if health.port not in valid_ports:
      self.P(
        f"HEALTH_CHECK.PORT {health.port} is not a configured container port. "
        f"Valid ports: {sorted(valid_ports)}. "
        f"Health probing DISABLED - using DELAY mode instead.",
        color='r'
      )
      self._health_probing_disabled = True
      return False

    return True


  def _build_tunnel_command(self, container_port, token):
    """
    Build Cloudflare tunnel command for a specific port.

    Parameters
    ----------
    container_port : int
        Container port to tunnel
    token : str
        Cloudflare tunnel token

    Returns
    -------
    list or None
        Command list to execute, or None if error
    """
    host_port = self._get_host_port_for_container_port(container_port)
    if not host_port:
      self.P(f"No host port found for container port {container_port}", color='r')
      return None

    # Return list to avoid shell injection - use list-based subprocess
    return [
      "cloudflared",
      "tunnel",
      "--no-autoupdate",
      "run",
      "--token",
      str(token),
      "--url",
      f"http://127.0.0.1:{host_port}"
    ]


  def _should_start_main_tunnel(self):
    """
    Determine if the main tunnel should be started.

    Main tunnel starts if:
    1. TUNNEL_ENGINE_ENABLED=True (checked by caller)
    2. PORT is defined OR CLOUDFLARE_TOKEN is defined
    3. Main PORT is not handled by EXTRA_TUNNELS

    Returns
    -------
    bool
        True if main tunnel should start
    """
    # Check if we have a token (backward compatibility)
    has_cloudflare_token = bool(getattr(self, 'cfg_cloudflare_token', None))
    has_params_token = bool(
      self.cfg_tunnel_engine_parameters and
      self.cfg_tunnel_engine_parameters.get("CLOUDFLARE_TOKEN")
    )

    has_main_token = has_cloudflare_token or has_params_token

    # If no token at all, no main tunnel
    if not has_main_token:
      # self.Pd("No main tunnel token configured, skipping main tunnel")
      return False

    # If PORT is defined and in EXTRA_TUNNELS, skip main tunnel
    if self.cfg_port and self.cfg_port in self.extra_tunnel_configs:
      self.P(f"Main PORT {self.cfg_port} is defined in EXTRA_TUNNELS, using extra tunnel instead")
      return False

    return True


  def _start_extra_tunnel(self, container_port, token):
    """
    Start a single extra tunnel for a specific container port.

    Parameters
    ----------
    container_port : int
        Container port to expose
    token : str
        Cloudflare tunnel token

    Returns
    -------
    bool
        True if tunnel started successfully, False otherwise
    """
    if not token:
      self.P(f"No token provided for extra tunnel on port {container_port}", color='r')
      return False

    # Build tunnel command
    command = self._build_tunnel_command(container_port, token)
    if not command:
      return False

    # Start tunnel process
    try:
      host_port = self._get_host_port_for_container_port(container_port)
      self.P(f"Starting Cloudflare tunnel for container port {container_port} (host port {host_port})...")
      self.Pd(f"  Command: {' '.join(command)}")

      # Use list-based subprocess to prevent shell injection
      process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=0
      )

      # Create log readers for this tunnel
      logs_reader = self.LogReader(process.stdout, size=100, daemon=None)
      err_logs_reader = self.LogReader(process.stderr, size=100, daemon=None)

      # Store process and log readers
      self.extra_tunnel_processes[container_port] = process
      self.extra_tunnel_log_readers[container_port] = {
        "stdout": logs_reader,
        "stderr": err_logs_reader,
      }
      self.extra_tunnel_start_times[container_port] = self.time()

      # Record successful start for backoff tracking
      self._record_tunnel_restart_success(container_port)

      self.P(f"Extra tunnel for port {container_port} started (PID: {process.pid})")
      return True

    except Exception as e:
      self.P(f"Failed to start extra tunnel for port {container_port}: {e}", color='r')
      # Record failure for backoff tracking
      self._record_tunnel_restart_failure(container_port)
      return False


  def start_extra_tunnels(self):
    """
    Start all configured extra Cloudflare tunnels.

    Iterates through extra_tunnel_configs and starts a tunnel
    process for each configured port.

    Returns
    -------
    None

    Notes
    -----
    Logs the number of successfully started tunnels.
    Failed tunnels are tracked for exponential backoff retry.
    """
    if not self.extra_tunnel_configs:
      self.Pd("No extra tunnels configured")
      return

    self.P(f"Starting {len(self.extra_tunnel_configs)} extra tunnel(s)...")

    started_count = 0
    for container_port, token in self.extra_tunnel_configs.items():
      if self._start_extra_tunnel(container_port, token):
        started_count += 1

    self.P(f"Started {started_count}/{len(self.extra_tunnel_configs)} extra tunnels")
    return


  def _stop_extra_tunnel(self, container_port):
    """
    Stop a single extra tunnel.

    Parameters
    ----------
    container_port : int
        Container port whose tunnel should be stopped

    Returns
    -------
    None
    """
    process = self.extra_tunnel_processes.get(container_port)
    if not process:
      return

    try:
      self.P(f"Stopping extra tunnel for port {container_port}...")

      # Read remaining logs before stopping
      self._read_extra_tunnel_logs(container_port)

      # Stop process
      if process.poll() is None:  # Still running
        process.terminate()
        try:
          process.wait(timeout=5)
        except Exception:
          process.kill()
          process.wait()

      # Clean up log readers (following base class pattern)
      log_readers = self.extra_tunnel_log_readers.get(container_port, {})

      # Stop stdout reader and read remaining logs
      stdout_reader = log_readers.get("stdout")
      if stdout_reader:
        try:
          stdout_reader.stop()
          # Read any remaining logs before cleanup
          remaining_logs = stdout_reader.get_next_characters()
          if remaining_logs:
            self._process_extra_tunnel_log(container_port, remaining_logs, is_error=False)
        except Exception as e:
          self.Pd(f"Error stopping stdout reader: {e}")

      # Stop stderr reader and read remaining logs
      stderr_reader = log_readers.get("stderr")
      if stderr_reader:
        try:
          stderr_reader.stop()
          # Read any remaining error logs before cleanup
          remaining_err_logs = stderr_reader.get_next_characters()
          if remaining_err_logs:
            self._process_extra_tunnel_log(container_port, remaining_err_logs, is_error=True)
        except Exception as e:
          self.Pd(f"Error stopping stderr reader: {e}")

      # Clean up references
      self.extra_tunnel_processes.pop(container_port, None)
      self.extra_tunnel_log_readers.pop(container_port, None)
      self.extra_tunnel_urls.pop(container_port, None)
      self.extra_tunnel_start_times.pop(container_port, None)

      self.P(f"Extra tunnel for port {container_port} stopped")

    except Exception as e:
      self.P(f"Error stopping extra tunnel for port {container_port}: {e}", color='r')


  def stop_extra_tunnels(self):
    """
    Stop all running extra tunnels.

    Iterates through all extra tunnel processes and stops each one,
    reading remaining logs before termination.

    Returns
    -------
    None
    """
    if not self.extra_tunnel_processes:
      return

    self.P(f"Stopping {len(self.extra_tunnel_processes)} extra tunnel(s)...")

    for container_port in list(self.extra_tunnel_processes.keys()):
      self._stop_extra_tunnel(container_port)

    self.P("All extra tunnels stopped")


  def _read_extra_tunnel_logs(self, container_port):
    """
    Read and process logs from an extra tunnel.

    Parameters
    ----------
    container_port : int
        Container port whose tunnel logs to read

    Returns
    -------
    None
    """
    log_readers = self.extra_tunnel_log_readers.get(container_port, {})

    # Read stdout
    stdout_reader = log_readers.get("stdout")
    if stdout_reader:
      try:
        logs = stdout_reader.get_next_characters()
        if logs:
          self._process_extra_tunnel_log(container_port, logs, is_error=False)
      except Exception as e:
        self.Pd(f"Error reading stdout for tunnel {container_port}: {e}")

    # Read stderr
    stderr_reader = log_readers.get("stderr")
    if stderr_reader:
      try:
        err_logs = stderr_reader.get_next_characters()
        if err_logs:
          self._process_extra_tunnel_log(container_port, err_logs, is_error=True)
      except Exception as e:
        self.Pd(f"Error reading stderr for tunnel {container_port}: {e}")


  def _process_extra_tunnel_log(self, container_port, text, is_error=False):
    """
    Process tunnel logs and extract URL.

    For Cloudflare tunnels, extracts URL matching pattern
    https://*.trycloudflare.com from the log output.

    Parameters
    ----------
    container_port : int
        Container port for this tunnel
    text : str
        Log text to process
    is_error : bool, optional
        Whether this is error output (default: False)

    Returns
    -------
    None
    """
    log_prefix = f"[TUNNEL:{container_port}]"

    # Log the output
    for line in text.split('\n'):
      if line.strip():
        self.Pd(f"{log_prefix} {line}", score=0)
      # endif
    # endfor line in text

    # Extract URL if not already found
    if container_port not in self.extra_tunnel_urls:
      # Extract Cloudflare URL: https://xxx.trycloudflare.com
      url_pattern = r'https://[a-z0-9-]+\.trycloudflare\.com'
      match = self.re.search(url_pattern, text)
      if match:
        url = match.group(0)
        self.extra_tunnel_urls[container_port] = url
        self.P(f"Extra tunnel URL for port {container_port}: {url}")
      # endif
    # endif container_port
    return

  def read_all_extra_tunnel_logs(self):
    """
    Read and process logs from all running extra tunnels.

    Iterates through all extra tunnel processes and reads their
    stdout/stderr logs, extracting public URLs when found.

    Returns
    -------
    None
    """
    for container_port in list(self.extra_tunnel_processes.keys()):
      try:
        self._read_extra_tunnel_logs(container_port)
      except Exception as e:
        self.Pd(f"Error reading logs for tunnel {container_port}: {e}")


  def start_container(self):
    """
    Start the Docker container with configured settings.

    Creates and starts a Docker container with the configured image,
    ports, volumes, environment variables, and resource limits.

    Returns
    -------
    docker.models.containers.Container or None
        Container object if started successfully, None otherwise

    Notes
    -----
    Updates container state to RUNNING on success or FAILED on error.
    Records restart success/failure for backoff tracking.
    """
    self._set_container_state(ContainerState.STARTING)

    log_str = f"Launching container with image '{self.cfg_image}'...\n"

    log_str += f"Container data:\n"
    log_str += f"  Image: {self.cfg_image}\n"
    log_str += f"  Ports: {self.json_dumps(self.inverted_ports_mapping) if self.inverted_ports_mapping else 'None'}\n"
    log_str += f"  Env: {self.json_dumps(self.env) if self.env else 'None'}\n"
    log_str += f"  Volumes: {self.json_dumps(self.volumes) if self.volumes else 'None'}\n"
    log_str += f"  Resources: {self.json_dumps(self.cfg_container_resources) if self.cfg_container_resources else 'None'}\n"
    log_str += f"  Restart policy: {self.cfg_restart_policy}\n"
    log_str += f"  Pull policy: {self.cfg_image_pull_policy}\n"
    log_str += f"  Start command: {self._start_command if self._start_command else 'Image default'}\n"

    self.P(log_str)

    nano_cpu_limit = self._cpu_limit * 1_000_000_000
    mem_reservation = f"{parse_memory_to_mb(self._mem_limit, 0.9)}m"

    run_kwargs = dict(
      detach=True,
      ports=self.inverted_ports_mapping,
      environment=self.env,
      volumes=self.volumes,
      name=self.container_name,
      nano_cpus=nano_cpu_limit,
      mem_limit=self._mem_limit,
      mem_reservation=mem_reservation,
      # pids_limit=
    )

    if self._gpu_limit:
      gpus_info = self.log.gpu_info()
      if len(gpus_info) > 0:
        self.P(f"GPU is requested and NVIDIA GPUs found, starting container with 1 GPU.")
        run_kwargs["device_requests"] = [DeviceRequest(
          count=1,  # -1 = "all" devices
          capabilities=[['gpu']],  # what kind of device we want
          # optionally:
          # device_ids=['0', '1'],
          # options={'compute': 'all'}
        )]
      else:
        self.P("Warning! GPU is requested but no NVIDIA GPUs found, starting container without GPU")
      # endif available GPUs
    else:
      self.P(f"Starting container without GPU")
    # endif

    try:
      if self._start_command:
        run_kwargs['command'] = self._start_command

      self.container = self.docker_client.containers.run(
        self.cfg_image,
        **run_kwargs,
      )

      self.container_id = self.container.short_id
      self.P(f"Container started (ID: {self.container.short_id})")

      # Container started successfully
      self._set_container_state(ContainerState.RUNNING)
      self._record_restart_success()

      self._maybe_send_plugin_start_confirmation()

      return self.container

    except Exception as e:
      self.P(f"Could not start container: {e}", color='r')
      self.container = None
      self._set_container_state(ContainerState.FAILED, StopReason.CRASH)
      self._record_restart_failure()
    return None


  def stop_container(self):
    """
    Stop and remove the Docker container.

    Gracefully stops the container with a 5-second timeout,
    then removes it from the Docker daemon.

    Returns
    -------
    None

    Notes
    -----
    If no container exists, logs a warning and returns.
    Clears container and container_id attributes after removal.
    """
    if not self.container:
      self.P("No container to stop", color='r')
      return

    try:
      # Stop the container (gracefully)
      self.P(f"Stopping container {self.container.short_id}...")
      self.container.stop(timeout=5)
      self.P(f"Container {self.container.short_id} stopped successfully")
    except Exception as e:
      self.P(f"Error stopping container: {e}", color='r')
    # end try

    try:
      self.P(f"Removing container {self.container.short_id}...")
      self.container.remove()
      self.P(f"Container {self.container.short_id} removed successfully")
    except Exception as e:
      self.P(f"Error removing container: {e}", color='r')
    finally:
      self.container = None
      self.container_id = None
    # end try
    return


  def _stream_logs(self, log_stream):
    """
    Consume a log iterator from container logs and print its output.

    Parameters
    ----------
    log_stream : iterator
        Log stream iterator from container.logs()

    Returns
    -------
    None
    """
    if not log_stream:
      self.P("No log stream provided", color='r')
      return

    try:
      for log_bytes in log_stream:
        if log_bytes is None:
          break
        try:
          log_str = log_bytes.decode("utf-8", errors="replace")
        except Exception as e:
          self.P(f"Warning: Could not decode log bytes: {e}", color='r')
          log_str = str(log_bytes)

        self.P(f"[CONTAINER] {log_str}", end='')
        self.container_logs.append(log_str)

        if self._stop_event.is_set():
          self.P("Log streaming stopped by stop event")
          break
    except Exception as e:
      self.P(f"Exception while streaming logs: {e}", color='r')
    # end try
    return


  def _start_container_log_stream(self):
    """
    Start following container logs if not already streaming.

    Returns
    -------
    None
    """
    if not self.container:
      return

    if self.log_thread and self.log_thread.is_alive():
      return

    try:
      log_stream = self.container.logs(stream=True, follow=True)
      self.log_thread = threading.Thread(
        target=self._stream_logs,
        args=(log_stream,),
        daemon=True,
      )
      self.log_thread.start()
    except Exception as exc:
      self.P(f"Could not start container log stream: {exc}", color='r')
    return


  def _collect_exec_commands(self):
    """
    Return the list of commands to execute inside the container.

    Returns
    -------
    list of str
        Commands to execute, or empty list if none configured
    """
    return list(self._build_commands) if getattr(self, '_build_commands', None) else []


  def _compose_exec_shell(self, commands):
    """
    Compose a shell command string out of the command fragments.

    Parameters
    ----------
    commands : list of str
        Command fragments to chain together

    Returns
    -------
    str or None
        Shell command string with commands chained by &&, or None if empty
    """
    if not commands:
      return None
    return " && ".join(commands)


  def _run_container_exec(self, shell_cmd):
    """
    Run a shell command inside the container and stream its output.

    Parameters
    ----------
    shell_cmd : str
        Shell command to execute inside container

    Returns
    -------
    None
    """
    if not self.container or not shell_cmd:
      return

    try:
      # Refresh container status and verify it's running before exec
      # This prevents race condition where container exits before exec can run
      self.container.reload()
      if self.container.status != "running":
        self.P(
          f"Cannot execute command: container is not running (status: {self.container.status})",
          color='r'
        )
        self._commands_started = False
        # Update state machine to reflect actual container status
        if self.container_state == ContainerState.RUNNING:
          exit_code = self.container.attrs.get('State', {}).get('ExitCode', -1)
          stop_reason = StopReason.NORMAL_EXIT if exit_code == 0 else StopReason.CRASH
          self._set_container_state(ContainerState.FAILED, stop_reason)
          self._record_restart_failure()
        return

      self.P(f"Running container exec command: {shell_cmd}")
      exec_result = self.container.exec_run(
        ["sh", "-c", shell_cmd],
        stream=True,
        detach=False,
      )
      thread = threading.Thread(
        target=self._stream_logs,
        args=(exec_result.output,),
        daemon=True,
      )
      thread.start()
      self.exec_threads.append(thread)
    except Exception as exc:
      self.P(f"Container exec command failed: {exc}", color='r')
      self._commands_started = False
    return


  def _maybe_execute_build_and_run(self):
    """
    Execute configured build/run commands if necessary.

    Returns
    -------
    None
    """
    if self._commands_started:
      return

    if not self.container:
      return

    commands = self._collect_exec_commands()
    if not commands:
      return

    shell_cmd = self._compose_exec_shell(commands)
    if not shell_cmd:
      return

    self._commands_started = True
    self._run_container_exec(shell_cmd)
    return


  def _get_health_check_url(self):
    """
    Get the full URL for health checking.

    Always constructs: http://{localhost_ip}:{host_port}{path}
    - Path from HEALTH_CHECK.PATH
    - Port from HEALTH_CHECK.PORT or main PORT
    - Port is validated and mapped to host port
    - IP from self.log.get_localhost_ip() for consistency with other host URLs

    Security: No external URLs, no arbitrary ports (SSRF prevention).

    Returns
    -------
    str or None
        Full URL for health check, or None if not configured
    """
    health = self._get_health_config()
    if not health.path:
      self.Pd("Health URL: no HEALTH_CHECK.PATH configured")
      return None

    # Ensure path starts with /
    path = health.path if health.path.startswith('/') else '/' + health.path

    # Get container port (default to main port)
    container_port = health.port or self.cfg_port
    if not container_port:
      self.Pd("Health URL: no container port (HEALTH_CHECK.PORT or PORT not set)")
      return None

    # Look up host port from container port mapping
    host_port = self._get_host_port_for_container_port(container_port)
    if not host_port:
      self.Pd(f"Health URL: no host port mapping for container port {container_port}")
      return None

    # Use localhost IP for consistency with other host URLs in the codebase
    localhost_ip = self.log.get_localhost_ip()
    return f"http://{localhost_ip}:{host_port}{path}"


  def _probe_health_endpoint(self):
    """
    Probe health endpoint for app readiness.

    Returns
    -------
    bool
        True if health check passed (2xx response), False otherwise
    """
    url = self._get_health_check_url()
    if not url:
      self.Pd("Health probe skipped: no URL (check HEALTH_CHECK.PATH and PORT config)")
      return False

    try:
      resp = requests.get(url, timeout=5)
      if 200 <= resp.status_code < 300:
        self.Pd(f"Health probe OK: {url} -> {resp.status_code}")
        return True
      self.Pd(f"Health probe failed: {url} -> HTTP {resp.status_code}")
    except requests.exceptions.ConnectionError as e:
      self.Pd(f"Health probe connection error: {url} -> {e}")
    except requests.exceptions.Timeout as e:
      self.Pd(f"Health probe timeout: {url} -> {e}")
    except requests.RequestException as e:
      self.Pd(f"Health probe error: {url} -> {e}")
    return False


  def _get_health_check_port(self):
    """
    Get the host port for health checking.

    Determines the appropriate port based on configuration:
    - Uses HEALTH_CHECK.PORT if specified
    - Otherwise uses main PORT

    Returns
    -------
    int or None
        Host port for health checking, or None if not configured
    """
    health = self._get_health_config()
    container_port = health.port or self.cfg_port
    if not container_port:
      self.Pd("Health check port: no container port configured (HEALTH_CHECK.PORT or PORT)")
      return None

    host_port = self._get_host_port_for_container_port(container_port)
    if not host_port:
      self.Pd(f"Health check port: no host port mapping for container port {container_port}")
      return None

    return host_port


  def _probe_tcp_port(self):
    """
    Probe TCP port to check if app is accepting connections.

    This is a universal health check that works for any protocol
    (HTTP, WebSocket, gRPC, raw TCP, etc.) - it simply checks if
    the port is accepting TCP connections.

    Returns
    -------
    bool
        True if port is accepting connections, False otherwise
    """
    host_port = self._get_health_check_port()
    if not host_port:
      self.Pd("TCP probe skipped: no port configured")
      return False

    try:
      with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(2)
        result = sock.connect_ex(('127.0.0.1', host_port))
        if result == 0:
          self.Pd(f"TCP probe OK: port {host_port} is accepting connections")
          return True
        self.Pd(f"TCP probe failed: port {host_port} refused connection (error code: {result})")
    except socket.timeout:
      self.Pd(f"TCP probe timeout: port {host_port}")
    except socket.error as e:
      self.Pd(f"TCP probe error: port {host_port} -> {e}")
    except Exception as e:
      self.Pd(f"TCP probe unexpected error: port {host_port} -> {e}")
    return False


  def _is_app_ready(self):
    """
    Check if app is ready for tunnel startup.

    Uses consolidated HEALTH_CHECK configuration:
    - AUTO: Smart detection (endpoint if path set, else tcp if port, else delay)
    - TCP: TCP port check (works for any protocol)
    - ENDPOINT: HTTP probe to HEALTH_CHECK.PATH
    - DELAY: Simple delay using HEALTH_CHECK.DELAY

    Supports TIMEOUT=0 for unlimited probing (probe forever until success).

    Returns
    -------
    bool
        True if app is ready, False otherwise
    """
    if self._app_ready:
      return True

    # Container must be running
    if not self.container or self.container_state != ContainerState.RUNNING:
      return False

    if not self.container_start_time:
      return False

    current_time = self.time()

    # Get consolidated health config
    health = self._get_health_config()
    mode = self._get_effective_health_mode(health)

    # Mode: DELAY - simple time-based waiting
    if mode == HealthCheckMode.DELAY or self._health_probing_disabled:
      elapsed = current_time - self.container_start_time
      if elapsed >= health.delay:
        if health.delay > 0:
          self.P(f"Health check delay ({health.delay}s) elapsed - app assumed ready")
        self._app_ready = True
        self._signal_semaphore_ready()
      return self._app_ready

    # Mode: TCP or ENDPOINT - active probing with delay/interval/timeout
    # Initialize probe timing on first call
    if self._health_probe_start is None:
      self._health_probe_start = current_time
      mode_desc = "TCP port" if mode == HealthCheckMode.TCP else "HTTP endpoint"
      timeout_desc = "unlimited" if health.timeout == 0 else f"{health.timeout}s"
      self.P(
        f"Starting {mode_desc} probing "
        f"(delay={health.delay}s, interval={health.interval}s, timeout={timeout_desc})"
      )

    probe_elapsed = current_time - self._health_probe_start

    # Wait for initial delay before probing
    if probe_elapsed < health.delay:
      self.Pd(
        f"Health probe waiting for delay: elapsed={probe_elapsed:.1f}s < delay={health.delay}s"
      )
      return False

    # Check timeout (0 = unlimited, probe forever)
    if health.timeout > 0 and probe_elapsed > health.timeout:
      self.P(f"Health probe timeout ({health.timeout}s) exceeded", color='r')
      if health.on_failure == "start":
        self.P("Starting tunnel anyway per HEALTH_CHECK.ON_FAILURE='start'", color='y')
        self._app_ready = True
        self._signal_semaphore_ready()
      else:
        self.P("Tunnel startup skipped per HEALTH_CHECK.ON_FAILURE='skip'", color='y')
        self._app_ready = False  # Stay false, but stop probing
        self._health_probe_start = float('inf')  # Prevent further probing
      return self._app_ready

    # Rate-limit probing
    time_since_last_probe = current_time - self._last_health_probe
    if time_since_last_probe < health.interval:
      self.Pd(
        f"Health probe rate-limited: {time_since_last_probe:.1f}s since last probe "
        f"(interval={health.interval}s)"
      )
      return False
    self._last_health_probe = current_time

    # Execute probe based on mode
    timeout_desc = "unlimited" if health.timeout == 0 else f"{health.timeout}s"
    if mode == HealthCheckMode.TCP:
      host_port = self._get_health_check_port()
      self.Pd(
        f"Probing TCP port: {host_port} "
        f"(elapsed={probe_elapsed:.1f}s, timeout={timeout_desc})"
      )
      probe_result = self._probe_tcp_port()
      success_msg = "TCP port check passed - app is ready!"
    else:  # mode == HealthCheckMode.ENDPOINT
      health_url = self._get_health_check_url()
      self.Pd(
        f"Probing health endpoint: {health_url} "
        f"(elapsed={probe_elapsed:.1f}s, timeout={timeout_desc})"
      )
      probe_result = self._probe_health_endpoint()
      success_msg = "Health check passed - app is ready!"

    if probe_result:
      self.P(success_msg, color='g')
      self._app_ready = True
      self._signal_semaphore_ready()
    else:
      self.Pd(f"Health probe returned False, will retry in {health.interval}s")

    return self._app_ready

  def _signal_semaphore_ready(self):
    """
    Signal semaphore readiness when container is ready.

    Called when the container passes health checks and is ready to serve.
    Exposes container port and URL as environment variables to dependent plugins.
    """
    if not self.cfg_semaphore:
      return

    # Only signal once
    if getattr(self, '_semaphore_signaled', False):
      return
    self._semaphore_signaled = True

    # Expose container connection details
    env_vars_set = []
    if self._container_port:
      self.semaphore_set_env('PORT', str(self._container_port))
      env_vars_set.append(f"{self.cfg_semaphore}_PORT = {self._container_port}")

    # If we have a tunnel URL, expose it
    tunnel_url = getattr(self, 'tunnel_url', None)
    if tunnel_url:
      self.semaphore_set_env('URL', tunnel_url)
      env_vars_set.append(f"{self.cfg_semaphore}_URL = {tunnel_url}")

    # Signal that this container is ready
    self.semaphore_set_ready()

    # Log the full semaphore data structure
    semaphore_data = self.plugins_shmem.get(self.cfg_semaphore, {})
    log_lines = [
      "=" * 60,
      "SEMAPHORE SIGNAL - CAR Provider Mode",
      "=" * 60,
      f"  Semaphore key: {self.cfg_semaphore}",
    ]
    for env_var in env_vars_set:
      log_lines.append(f"  Env var set: {env_var}")
    log_lines.extend([
      f"  Semaphore data:",
      f"    env vars: {semaphore_data.get('env', {})}",
      f"    metadata: {semaphore_data.get('metadata', {})}",
      f"  Status: READY",
      "=" * 60,
    ])
    self.Pd("\n".join(log_lines))
    return


  def _check_container_status(self):
    """
    Check container status and update state machine.

    Returns
    -------
    bool
        True if container is running normally, False if stopped/failed

    Notes
    -----
    Side effects:
    - Updates container_state based on container status
    - Sets stop_reason based on exit code
    - Does NOT trigger restart - that's handled by process()
    """
    try:
      if not self.container:
        return False

      # Refresh container status from Docker
      # @see https://docker-py.readthedocs.io/en/stable/containers.html#docker.models.containers.Container.reload
      self.container.reload()

      if self.container.status == "running":
        # Container running normally
        if self.container_state != ContainerState.RUNNING:
          self._set_container_state(ContainerState.RUNNING)
        return True

      # Container is not running - determine why
      exit_code = self.container.attrs.get('State', {}).get('ExitCode', -1)

      # Determine stop reason based on exit code
      if exit_code == 0:
        stop_reason = StopReason.NORMAL_EXIT
      else:
        stop_reason = StopReason.CRASH

      # Only record failure if transitioning from RUNNING to FAILED (not already failed)
      # This ensures we count each crash/exit only once
      was_running = self.container_state == ContainerState.RUNNING

      # Update state
      self._set_container_state(ContainerState.FAILED, stop_reason)

      self.P(
        f"Container stopped (exit code: {exit_code}, reason: {stop_reason.value})",
        color='r' if exit_code != 0 else 'b'
      )

      # Record restart failure for unplanned stops (affects backoff and retry limits)
      # Only record if we were previously running to avoid double-counting
      if was_running:
        self._record_restart_failure()

      self._commands_started = False
      # Reset app readiness state for fresh probing on restart
      self._app_ready = False
      self._health_probe_start = None
      self._last_health_probe = 0
      self._tunnel_start_allowed = False
      return False

    except Exception as e:
      self.P(f"Could not check container status: {e}", color='r')
      self.container = None
      self._commands_started = False
      self._set_container_state(ContainerState.FAILED, StopReason.UNKNOWN)
      return False


  def _check_extra_tunnel_health(self):
    """
    Check health of extra tunnels and restart if needed with exponential backoff.

    Returns
    -------
    None
    """
    for container_port, process in list(self.extra_tunnel_processes.items()):
      # Check if tunnel is still running
      if process.poll() is not None:  # Process exited
        exit_code = process.returncode
        self.P(f"Extra tunnel for port {container_port} exited (code {exit_code})", color='r')

        # Clean up dead tunnel
        self._stop_extra_tunnel(container_port)

        # Record failure for backoff tracking
        self._record_tunnel_restart_failure(container_port)

        # Check if we've exceeded max retries
        if self._has_tunnel_exceeded_max_retries(container_port):
          failures = self._tunnel_consecutive_failures.get(container_port, 0)
          max_retries = self.cfg_tunnel_restart_max_retries
          self.P(
            f"Tunnel for port {container_port} restart abandoned after {failures} "
            f"consecutive failures (max: {max_retries})",
            color='r'
          )
          continue

        # Check if we're in backoff period
        if self._is_tunnel_backoff_active(container_port):
          self.Pd(f"Tunnel {container_port} restart delayed due to active backoff period")
          continue

        # All checks passed - attempt restart
        token = self.extra_tunnel_configs.get(container_port)
        if token:
          failures = self._tunnel_consecutive_failures.get(container_port, 0)
          self.P(
            f"Restarting extra tunnel for port {container_port} (attempt {failures})...",
            color='r'
          )
          self._start_extra_tunnel(container_port, token)
      else:
        # Tunnel is running - maybe reset retry counter
        self._maybe_reset_tunnel_retry_counter(container_port)


  def _stop_container_and_save_logs_to_disk(self):
    """
    Stop the container and all tunnels, then save logs to disk.

    Performs full shutdown sequence:
    - Stops log streaming threads
    - Stops main tunnel engine
    - Stops all extra tunnels
    - Stops and removes container
    - Saves logs to disk

    Returns
    -------
    None
    """
    self.P(f"Stopping container app '{self.container_id}' ...")

    # Stop log streaming
    self._stop_event.set()
    if self.log_thread:
      self.log_thread.join(timeout=5)
      self.log_thread = None

    if getattr(self, 'exec_threads', None):
      for thread in self.exec_threads:
        if thread and thread.is_alive():
          thread.join(timeout=5)
      self.exec_threads = []

    self._stop_event = threading.Event()
    self._commands_started = False

    # Stop tunnel engine if needed
    self.stop_tunnel_engine()

    # Stop extra tunnels
    self.stop_extra_tunnels()

    # Stop the container if it's running
    self.stop_container()

    # Save logs to disk (in instance-specific subfolder alongside persistent state)
    try:
      self.diskapi_save_pickle_to_data(
        obj=list(self.container_logs),
        filename="container_logs.pkl",
        subfolder=self._get_instance_data_subfolder()
      )
      self.P("Container logs saved to disk.")
    except Exception as exc:
      self.P(f"Failed to save logs: {exc}", color='r')
    return


  def on_close(self):
    """
    Lifecycle hook called when plugin is stopping.

    Performs cleanup including:
    - Clearing semaphore (if configured)
    - Stopping container
    - Stopping all tunnels (main and extra)
    - Terminating log processes
    - Saving container logs to disk

    Returns
    -------
    None
    """
    # Clear semaphore to signal dependent plugins
    self.semaphore_clear()

    self._stop_container_and_save_logs_to_disk()

    super(ContainerAppRunnerPlugin, self).on_close()


  def _get_local_image(self):
    """
    Get the local Docker image if it exists.

    Returns
    -------
    Image or None
        Image object or None if image doesn't exist locally
    """
    if not self.cfg_image:
      return None

    try:
      img = self.docker_client.images.get(self.cfg_image)
      return img
    except Exception:
      return None


  def _pull_image_from_registry(self):
    """
    Pull image from registry (assumes authentication already done).

    Returns
    -------
    Image or None
        Image object or None if pull failed

    Raises
    ------
    RuntimeError
        If authentication hasn't been performed
    """
    if not self.cfg_image:
      self.P("No Docker image configured", color='r')
      return None

    try:
      self.P(f"Pulling image '{self.cfg_image}'...")
      img = self.docker_client.images.pull(self.cfg_image)

      # docker-py may return Image or list[Image]
      if isinstance(img, list) and img:
        img = img[-1]

      self.P(f"Successfully pulled image '{self.cfg_image}'")
      return img

    except Exception as e:
      self.P(f"Image pull failed: {e}", color='r')
      return None


  def _pull_image_with_fallback(self):
    """
    Pull image from registry with fallback to local image.

    This is the main image acquisition method that:
    1. Authenticates with registry
    2. Attempts to pull from registry
    3. Falls back to local image if pull fails
    4. Returns None only if both pull and local check fail

    Returns
    -------
    Image or None
        Image object or None if no image is available

    Raises
    ------
    RuntimeError
        If authentication fails and no local image exists
    """
    # Step 1: Authenticate with registry
    if not self._login_to_registry():
      self.P("Registry authentication failed", color='r')
      # Try to use local image if authentication fails
      local_img = self._get_local_image()
      if local_img:
        self.P(f"Using local image (registry login failed): {self.cfg_image}", color='r')
        return local_img
      raise RuntimeError("Failed to authenticate with registry and no local image available.")

    # Step 2: Attempt to pull from registry
    img = self._pull_image_from_registry()
    if img:
      return img

    # Step 3: Fallback to local image
    self.P(f"Pull failed, checking for local image: {self.cfg_image}", color='r')
    local_img = self._get_local_image()
    if local_img:
      self.P(f"Using local image as fallback: {self.cfg_image}", color='r')
      return local_img

    # Step 4: No image available
    self.P(f"No image available (pull failed and no local image): {self.cfg_image}", color='r')
    return None


  def _get_image_digest(self, img):
    """
    Extract digest hash from image object.

    Parameters
    ----------
    img : Image
        Docker image object

    Returns
    -------
    str or None
        Digest hash (sha256:...) or None
    """
    if not img:
      return None

    try:
      img.reload()
    except Exception as e:
      self.Pd(f"Warning: Could not reload image attributes: {e}")

    attrs = getattr(img, "attrs", {}) or {}
    repo_digests = attrs.get("RepoDigests") or []
    if repo_digests:
      # 'repo@sha256:...'
      digest = repo_digests[0].split("@")[-1]
      return digest
    # Fallback to image id (sha256:...)
    return getattr(img, "id", None)


  def _get_latest_image_hash(self):
    """
    Get the latest identifier for the configured Docker image tag.

    This method pulls the image and extracts its digest for version tracking.
    Used by AUTOUPDATE feature to detect image changes.

    Returns
    -------
    str or None
      A digest like ``sha256:<hex>`` (preferred) or the local image ID. Returns
      ``None`` if neither can be obtained.

    Notes
    -----
    - Works for public and private registries as long as the Docker daemon has
      credentials configured.
    - This call contacts the registry; tune ``poll_interval`` appropriately.
    """
    img = self._pull_image_with_fallback()
    return self._get_image_digest(img)


  def _has_image_hash_changed(self, latest_hash):
    """
    Check if image hash has changed from current version.

    Parameters
    ----------
    latest_hash : str
        Latest image hash from registry

    Returns
    -------
    bool
        True if hash changed and update needed, False otherwise
    """
    if not latest_hash:
      # Pull failed, can't determine if update needed
      return False

    if not self.current_image_hash:
      # First time - establish baseline
      self.P(f"Establishing baseline image hash: {latest_hash}")
      self.current_image_hash = latest_hash
      return False

    # Compare hashes
    return latest_hash != self.current_image_hash


  def _handle_image_update(self, new_hash):
    """
    Handle detected image update by updating hash and restarting container.

    Parameters
    ----------
    new_hash : str
        New image hash detected

    Returns
    -------
    None
    """
    self.P(f"New image version detected ({new_hash} != {self.current_image_hash}). Restarting container...")

    # Update current_image_hash BEFORE restart
    # This prevents infinite retry loops if restart fails
    old_hash = self.current_image_hash
    self.current_image_hash = new_hash

    try:
      self._restart_container(StopReason.IMAGE_UPDATE)
    except Exception as e:
      self.P(f"Container restart failed after image update: {e}", color='r')
      # Hash already updated, won't retry this version
      self.P(f"Image hash updated from {old_hash} to {new_hash}, but container restart failed", color='r')


  def _check_image_updates(self, current_time=None):
    """
    Periodic check for image updates when AUTOUPDATE is enabled.

    This method:
    1. Checks if update check is due (based on interval)
    2. Pulls latest image and gets its hash
    3. Compares with current hash
    4. Triggers restart if changed

    Parameters
    ----------
    current_time : float, optional
        Current timestamp (for interval checking)

    Returns
    -------
    None
    """
    if not self.cfg_autoupdate:
      return

    # Check if update check is due
    if current_time - self._last_image_check < self.cfg_autoupdate_interval:
      return

    self._last_image_check = current_time

    # Get latest image hash
    latest_hash = self._get_latest_image_hash()
    if not latest_hash:
      self.P("Failed to check for image updates (pull failed). Container continues running.")
      return

    # Check if update is needed
    if self._has_image_hash_changed(latest_hash):
      self._handle_image_update(latest_hash)
    else:
      self.Pd(f"Image up to date: {self.current_image_hash}")

    return


  def _restart_container(self, stop_reason=None):
    """
    Restart the container from scratch.

    Parameters
    ----------
    stop_reason : StopReason, optional
        Optional StopReason enum indicating why restart was triggered

    Returns
    -------
    None
    """
    self.P("Restarting container from scratch...")

    # Preserve state before reset (prevents redundant operations after restart)
    preserved_failures = self._consecutive_failures
    preserved_last_success = self._last_successful_start
    preserved_last_image_check = self._last_image_check
    preserved_current_hash = self.current_image_hash

    self._stop_container_and_save_logs_to_disk()
    self.__reset_vars()

    # Restore preserved state (reset_vars clears it)
    self._consecutive_failures = preserved_failures
    self._last_successful_start = preserved_last_success
    self._last_image_check = preserved_last_image_check
    self.current_image_hash = preserved_current_hash

    # Set state after reset
    self._set_container_state(ContainerState.RESTARTING, stop_reason or StopReason.UNKNOWN)

    self._configure_dynamic_env()
    self._setup_resource_limits_and_ports()
    self._configure_volumes()
    self._configure_file_volumes()
    self._setup_env_and_ports()

    # Revalidate extra tunnels
    self._validate_extra_tunnels_config()

    self._validate_runner_config()

    # Ensure image is available (respecting AUTOUPDATE and IMAGE_PULL_POLICY)
    if not self._ensure_image_available():
      self.P("Failed to ensure image availability during restart, cannot start container", color='r')
      self._set_container_state(ContainerState.FAILED, StopReason.CRASH)
      self._record_restart_failure()
      return

    self.container = self.start_container()
    if not self.container:
      # start_container already recorded the failure
      return

    self.container_start_time = self.time()
    self._start_container_log_stream()
    self._maybe_execute_build_and_run()
    return


  def _ensure_image_always_pull(self):
    """
    Ensure image is available with 'always' pull policy.

    Pulls image without tracking hash.

    Returns
    -------
    bool
        True if image pulled successfully, False otherwise
    """
    self.Pd("IMAGE_PULL_POLICY is 'always', pulling image")
    img = self._pull_image_with_fallback()
    return img is not None


  def _ensure_image_if_not_present(self):
    """
    Ensure image is available with 'if-not-present' policy.

    Only pulls if image doesn't exist locally.

    Returns
    -------
    bool
        True if image is available (locally or after pull), False otherwise
    """
    # Check if image exists locally
    local_img = self._get_local_image()
    if local_img:
      self.P(f"Image '{self.cfg_image}' found locally")
      return True

    # Image not found locally, pull it
    self.P(f"Image not found locally, pulling '{self.cfg_image}'...")
    img = self._pull_image_with_fallback()
    return img is not None


  def _ensure_image_available(self):
    """
    Ensure the container image is available before starting container.

    This method uses a strategy pattern based on configuration:
    - AUTOUPDATE enabled: Ensure image exists locally (update detection handled separately)
    - IMAGE_PULL_POLICY='always': Always pull (no tracking)
    - IMAGE_PULL_POLICY='if-not-present' or default: Pull only if missing locally

    Returns
    -------
    bool
        True if image is available, False otherwise
    """
    # Strategy 1: AUTOUPDATE (takes precedence)
    # When AUTOUPDATE is enabled, just ensure image exists locally
    # Update checking and pulling happens in _check_image_updates()
    if self.cfg_autoupdate:
      return self._ensure_image_if_not_present()

    # Strategy 2: Always pull policy
    if self.cfg_image_pull_policy == "always":
      return self._ensure_image_always_pull()

    # Strategy 3: If-not-present policy (default)
    return self._ensure_image_if_not_present()


  def _wait_for_semaphores(self):
    """
    Wait for all configured semaphores to be ready.

    This method implements a non-blocking wait that integrates with the
    plugin's process() loop. It starts a wait timer on first call and
    returns False while waiting. Once all semaphores are ready, it returns True.
    Waits indefinitely until all semaphores are ready.

    Returns
    -------
    bool
      True if all semaphores are ready, False if still waiting
    """
    # Log initial wait state on first call
    if not hasattr(self, '_semaphore_wait_logged'):
      self._semaphore_wait_logged = True
      required_keys = self._semaphore_get_keys()
      log_msg = "\n".join([
        "=" * 60,
        "SEMAPHORE WAIT - Consumer Mode",
        "=" * 60,
        f"  Waiting for semaphores: {required_keys}",
        f"  Container will NOT start until all semaphores are ready",
        "=" * 60,
      ])
      self.Pd(log_msg)

    # Start waiting timer on first call
    self.semaphore_start_wait()

    # Check if all semaphores are ready
    if self.semaphore_check_with_logging():
      # All ready - log detailed info and proceed
      log_lines = [
        "=" * 60,
        "ALL SEMAPHORES READY!",
        "=" * 60,
      ]

      # Log semaphore status details
      status = self.semaphore_get_status()
      for key, info in status.items():
        log_lines.extend([
          f"  Semaphore '{key}':",
          f"    Ready: {info['ready']}",
          f"    Provider: {info['provider']}",
          f"    Env vars count: {info['env_count']}",
        ])

      # Log env vars that will be injected
      env_vars = self.semaphore_get_env()
      if env_vars:
        log_lines.append(f"  Environment variables to inject into container:")
        for k, v in env_vars.items():
          log_lines.append(f"    {k} = {v}")
      else:
        log_lines.append(f"  No environment variables from semaphores")

      log_lines.extend([
        "=" * 60,
        "Proceeding with container launch...",
      ])
      self.Pd("\n".join(log_lines))
      return True

    # Still waiting - log periodically
    elapsed = self.semaphore_get_wait_elapsed()
    if int(elapsed) % self.cfg_semaphore_log_interval == 0 and elapsed > 0:
      missing = self.semaphore_get_missing()
      log_lines = [f"Waiting for semaphores ({elapsed:.0f}s elapsed): {missing}"]
      # Log current status of each semaphore
      for key in self._semaphore_get_keys():
        shmem_data = self.plugins_shmem.get(key, {})
        is_ready = shmem_data.get('start', False)
        log_lines.append(f"  - {key}: {'READY' if is_ready else 'NOT READY'}")
      self.Pd("\n".join(log_lines))

    return False


  def _handle_initial_launch(self):
    """
    Handle the initial container launch.

    If SEMAPHORED_KEYS is configured, waits for all semaphores to be ready
    before starting the container. Environment variables from provider plugins
    are automatically merged into the container's environment.

    Returns
    -------
    None
    """
    # Check if we need to wait for semaphores
    if self._semaphore_get_keys():
      if not self._wait_for_semaphores():
        return  # Still
      # end if
      # Semaphores ready - now setup env vars with semaphore values
      self._setup_env_and_ports()
    # end if

    try:
      self.P("Initial container launch...")

      # Ensure image is available before starting container
      if not self._ensure_image_available():
        self.P("Failed to ensure image availability, cannot start container", color='r')
        return

      self.container = self.start_container()
      if not self.container:
        return

      self.container_start_time = self.time()
      self._start_container_log_stream()
      self._maybe_execute_build_and_run()

      self.P("Container launched successfully")
      self.P(self.container)
      if self.current_image_hash:
        self.P(f"Current image hash: {self.current_image_hash}")
    except Exception as e:
      self.P(f"Could not start container: {e}", color='r')
    # end try
    return


  def _perform_periodic_monitoring(self):
    """
    Perform periodic monitoring tasks.

    Executes image update checks, tunnel health checks,
    and any subclass-defined additional checks.

    Returns
    -------
    None
    """
    current_time = self.time()

    if self.cfg_autoupdate:
      self._check_image_updates(current_time)

    # Check extra tunnel health
    if self.extra_tunnel_processes:
      self._check_extra_tunnel_health()

    restart_stop_reason = self._perform_additional_checks(current_time)

    if restart_stop_reason:
      self._restart_container(restart_stop_reason)
    return


  def _perform_additional_checks(self, current_time):
    """
    Hook for subclasses to implement additional monitoring checks.

    This hook is called during periodic monitoring to check for conditions
    that require container restart. Use StopReason.EXTERNAL_UPDATE for
    domain-specific triggers (Git updates, database changes, file watches, etc.)

    Note: Restarts triggered here BYPASS restart policy - they always execute.
    This is intentional for planned updates vs unplanned crashes.

    Returns
    -------
    StopReason or None
      StopReason if container restart is required, None otherwise.

    Examples
    --------
    # Git-based updates (WorkerAppRunner)
    def _perform_additional_checks(self, current_time):
      if self._check_git_updates():
        return StopReason.EXTERNAL_UPDATE
      return None

    # File watch updates
    def _perform_additional_checks(self, current_time):
      if self._config_file_changed():
        return StopReason.EXTERNAL_UPDATE
      return None

    # Database schema updates
    def _perform_additional_checks(self, current_time):
      if self._schema_version_changed():
        return StopReason.EXTERNAL_UPDATE
      return None
    """
    return None


  def process(self):
    """
    Main process loop for the plugin.

    Called every PROCESS_DELAY seconds. Performs:
    1. Check for paused state (manual stop)
    2. Handle initial launch if container not started
    3. Initialize and start tunnel engine if needed
    4. Start main and extra tunnels
    5. Check container status and restart if needed
    6. Perform periodic monitoring (health checks, image updates)
    7. Send tunnel engine pings

    Returns
    -------
    None

    Notes
    -----
    The process loop implements a state machine for container lifecycle
    management with automatic restart based on configured policies.
    """
    # Use state machine instead of deprecated _is_manually_stopped flag
    if self.container_state == ContainerState.PAUSED:
      # Log paused message periodically instead of every process cycle
      current_time = self.time()
      if current_time - self._last_paused_log >= self.cfg_paused_state_log_interval:
        self.P("Container is paused (manual stop). Send RESTART command to resume.")
        self._last_paused_log = current_time
      return

    if not self.container:
      self._handle_initial_launch()
      # If still no container (e.g., waiting for semaphores), return early
      # to avoid triggering restart logic
      if not self.container:
        return

    # Tunnel management (only if TUNNEL_ENGINE_ENABLED=True)
    if self.cfg_tunnel_engine_enabled:
      self.maybe_init_tunnel_engine()
      self.maybe_start_tunnel_engine()

      # Gate tunnel startup on app readiness
      if self._is_app_ready():
        if not self._tunnel_start_allowed:
          self.P("App is ready, enabling tunnel startup", color='g')
          self._tunnel_start_allowed = True

        # Start main tunnel if configured and not already running
        if not self.tunnel_process and self._should_start_main_tunnel():
          self.start_tunnel_engine()

        # Start extra tunnels if configured and not already running
        if self.extra_tunnel_configs and not self.extra_tunnel_processes:
          self.start_extra_tunnels()

      # Read logs from all extra tunnels (always, for monitoring)
      if self.extra_tunnel_processes:
        self.read_all_extra_tunnel_logs()

    # ============================================================================
    # Container Status Check and Restart Logic
    # ============================================================================
    container_is_running = self._check_container_status()

    if not container_is_running:
      # Container has stopped - decide if we should restart based on policy
      policy = self._normalize_restart_policy(self.cfg_restart_policy)

      # Check if restart policy allows restart
      if not self._should_restart_container():
        self.Pd(f"Container stopped. Restart policy '{policy.value}' does not allow restart.")
        return

      # Check if we've exceeded max retry attempts
      if self._has_exceeded_max_retries():
        self.P(
          f"Container restart abandoned after {self._consecutive_failures} consecutive failures "
          f"(max: {self.cfg_restart_max_retries})",
          color='r'
        )
        return

      # Check if we're in backoff period
      if self._is_restart_backoff_active():
        self.Pd("Container restart delayed due to active backoff period")
        return

      # All checks passed - attempt restart
      self.P(
        f"Container stopped. Restarting per policy '{policy.value}' "
        f"(attempt {self._consecutive_failures + 1})",
        color='r'
      )
      self._restart_container(self.stop_reason)
      return

    # Container is running normally - reset retry counter if appropriate
    self._maybe_reset_retry_counter()

    # Signal semaphore readiness when container is running
    # (for tunneled apps, this is also called after health check passes)
    self._signal_semaphore_ready()

    # ============================================================================
    # End of Restart Logic
    # ============================================================================

    self._start_container_log_stream()
    self._maybe_execute_build_and_run()

    self._perform_periodic_monitoring()

    # Only ping if tunneling is enabled
    if self.cfg_tunnel_engine_enabled:
      self.maybe_tunnel_engine_ping()
      self.maybe_extra_tunnels_ping()

    return
