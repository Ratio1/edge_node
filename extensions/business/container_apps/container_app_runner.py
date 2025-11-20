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

from naeural_core.business.base.web_app.base_tunnel_engine_plugin import BaseTunnelEnginePlugin as BasePlugin
from extensions.business.mixins.chainstore_response_mixin import _ChainstoreResponseMixin

from .container_utils import _ContainerUtilsMixin # provides container management support currently empty it is embedded in the plugin

__VER__ = "0.6.0"

# Persistent state filename (general purpose)
_PERSISTENT_STATE_FILE = "container_persistent_state.pkl"


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
    "gpu": 0,
    "memory": "512m",  # e.g. "512m" for 512MB,
    "ports": []        # dict of host_port: container_port mappings (e.g. {8080: 8081}) or list of container ports (e.g. [8080, 9000])
  },
  "USE_CUDA": False,        # If True, will use nvidia runtime for GPU support
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

  # Application endpoint polling
  "ENDPOINT_POLL_INTERVAL": 0,  # seconds between endpoint health checks
  "ENDPOINT_URL": None,  # endpoint to poll for health checks

  #### Logging
  "SHOW_LOG_EACH" : 60,       # seconds to show logs
  "SHOW_LOG_LAST_LINES" : 5,  # last lines to show
  "MAX_LOG_LINES" : 10_000,   # max lines to keep in memory
  "PAUSED_LOG_INTERVAL": 60,  # seconds between paused state log messages

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
    Print a message to the console.
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
    self._last_endpoint_check = 0
    self._last_image_check = 0
    self._last_extra_tunnels_ping = 0
    self._last_paused_log = 0  # Track when we last logged the paused message

    # Image update tracking
    self.current_image_hash = None

    # Command execution state
    self._commands_started = False

    self._after_reset()

    return

  def _after_reset(self):
    """Hook for subclasses to reset additional state."""
    return

  # ============================================================================
  # Persistent State Management (General Purpose)
  # ============================================================================

  def _load_persistent_state(self):
    """
    Load persistent state from disk.

    Returns:
      dict: Persistent state dictionary (empty dict if no state exists)
    """
    state = self.diskapi_load_pickle_from_data(_PERSISTENT_STATE_FILE)
    return state if state is not None else {}

  def _save_persistent_state(self, **kwargs):
    """
    Save or update persistent state fields.

    Args:
      **kwargs: State fields to save/update (e.g., manually_stopped=True)

    Example:
      self._save_persistent_state(manually_stopped=True, last_config_hash="abc123")
    """
    # Load existing state
    state = self._load_persistent_state()
    # Update with new values
    state.update(kwargs)
    # Save back to disk
    self.diskapi_save_pickle_to_data(state, _PERSISTENT_STATE_FILE)
    return

  def _load_manual_stop_state(self):
    """
    Load manual stop state from persistent storage.

    Returns:
      bool: True if container was manually stopped, False otherwise
    """
    state = self._load_persistent_state()
    return state.get("manually_stopped", False)

  def _clear_manual_stop_state(self):
    """Clear manual stop state (called on RESTART command)."""
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

    Args:
      policy: String, RestartPolicy enum, or None

    Returns:
      RestartPolicy enum value
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
        self.P(f"Unknown restart policy '{policy}', defaulting to 'no'", color='y')
        return RestartPolicy.NO

    # Unknown type
    self.P(f"Invalid restart policy type {type(policy)}, defaulting to 'no'", color='y')
    return RestartPolicy.NO

  def _should_restart_container(self, stop_reason=None):
    """
    Determine if container should be restarted based on RESTART_POLICY and stop reason.

    Implements Docker-style restart policies:
    - NO: Never restart
    - ALWAYS: Always restart (unless manually stopped)
    - ON_FAILURE: Restart only on non-zero exit code
    - UNLESS_STOPPED: Always restart unless explicitly stopped by user

    Args:
      stop_reason: StopReason enum value indicating why container stopped

    Returns:
      bool: True if container should be restarted
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
    self.P(f"Unhandled restart policy '{policy}', defaulting to no restart", color='y')
    return False

  def _calculate_restart_backoff(self):
    """
    Calculate exponential backoff delay for restart attempts.

    Returns:
      float: Seconds to wait before next restart attempt
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

    Returns:
      bool: True if retry counter should be reset
    """
    if not self._last_successful_start:
      return False

    uptime = self.time() - self._last_successful_start
    return uptime >= self.cfg_restart_reset_interval

  def _record_restart_failure(self):
    """Record a restart failure and update backoff state."""
    self._consecutive_failures += 1
    self._last_failure_time = self.time()
    self._restart_backoff_seconds = self._calculate_restart_backoff()
    self._next_restart_time = self.time() + self._restart_backoff_seconds

    self.P(
      f"Container restart failure #{self._consecutive_failures}. "
      f"Next retry in {self._restart_backoff_seconds:.1f}s",
      color='y'
    )
    return

  def _record_restart_success(self):
    """Record a successful restart and reset failure counters if appropriate."""
    self._last_successful_start = self.time()

    # Reset failure counter after first successful start
    if self._consecutive_failures > 0:
      self.P(
        f"Container started successfully after {self._consecutive_failures} failure(s). "
        f"Retry counter will reset after {self.cfg_restart_reset_interval}s of uptime.",
        color='g'
      )
      # Don't reset immediately - wait for reset interval
      # self._consecutive_failures = 0  # This happens in _maybe_reset_retry_counter
    # end if
    return

  def _maybe_reset_retry_counter(self):
    """Reset retry counter if container has been running successfully."""
    if self._consecutive_failures > 0 and self._should_reset_retry_counter():
      old_failures = self._consecutive_failures
      self._consecutive_failures = 0
      self._restart_backoff_seconds = 0
      self.P(
        f"Container running successfully for {self.cfg_restart_reset_interval}s. "
        f"Reset failure counter (was {old_failures})",
        color='g'
      )
    # end if
    return

  def _is_restart_backoff_active(self):
    """
    Check if we're currently in backoff period.

    Returns:
      bool: True if we should wait before restarting
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

    Returns:
      bool: True if max retries exceeded (and max_retries > 0)
    """
    if self.cfg_restart_max_retries <= 0:
      return False  # Unlimited retries

    return self._consecutive_failures >= self.cfg_restart_max_retries

  def _set_container_state(self, new_state, stop_reason=None):
    """
    Update container state and optionally stop reason.

    Args:
      new_state: ContainerState enum value
      stop_reason: Optional StopReason enum value
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
  # Tunnel Restart Backoff Logic
  # ============================================================================

  def _calculate_tunnel_backoff(self, container_port):
    """
    Calculate exponential backoff delay for tunnel restart attempts.

    Args:
      container_port: Container port for the tunnel

    Returns:
      float: Seconds to wait before next tunnel restart attempt
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
    """Record a tunnel restart failure and update backoff state."""
    self._tunnel_consecutive_failures[container_port] = \
      self._tunnel_consecutive_failures.get(container_port, 0) + 1
    self._tunnel_last_failure_time[container_port] = self.time()

    backoff = self._calculate_tunnel_backoff(container_port)
    self._tunnel_next_restart_time[container_port] = self.time() + backoff

    failures = self._tunnel_consecutive_failures[container_port]
    self.P(
      f"Tunnel restart failure for port {container_port} (#{failures}). "
      f"Next retry in {backoff:.1f}s",
      color='y'
    )
    return

  def _record_tunnel_restart_success(self, container_port):
    """Record a successful tunnel restart."""
    self._tunnel_last_successful_start[container_port] = self.time()

    # Note success if there were previous failures
    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    if failures > 0:
      self.P(
        f"Tunnel for port {container_port} started successfully after {failures} failure(s).",
        color='g'
      )
    return

  def _is_tunnel_backoff_active(self, container_port):
    """
    Check if tunnel is currently in backoff period.

    Args:
      container_port: Container port for the tunnel

    Returns:
      bool: True if we should wait before restarting tunnel
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

    Args:
      container_port: Container port for the tunnel

    Returns:
      bool: True if max retries exceeded (and max_retries > 0)
    """
    if self.cfg_tunnel_restart_max_retries <= 0:
      return False  # Unlimited retries

    failures = self._tunnel_consecutive_failures.get(container_port, 0)
    return failures >= self.cfg_tunnel_restart_max_retries

  def _maybe_reset_tunnel_retry_counter(self, container_port):
    """Reset tunnel retry counter if it has been running successfully."""
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
        color='g'
      )
      self._tunnel_consecutive_failures[container_port] = 0

    return

  # ============================================================================
  # End of Tunnel Restart Backoff Logic
  # ============================================================================

  def _normalize_container_command(self, value, *, field_name):
    """Normalize a container command into a Docker-compatible representation."""
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
    """Normalize build/run command sequences into a list of shell fragments."""
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
    """Validate configuration and prepare normalized command data."""
    self._start_command = self._normalize_container_command(
      getattr(self, 'cfg_container_start_command', None),
      field_name='CONTAINER_START_COMMAND',
    )

    self._build_commands = self._normalize_command_sequence(
      getattr(self, 'cfg_build_and_run_commands', None),
      field_name='BUILD_AND_RUN_COMMANDS',
    )

    self._validate_subclass_config()
    return

  def _validate_subclass_config(self):
    """Hook for subclasses to enforce additional validation."""
    return

  def on_init(self):
    """
    Lifecycle hook called once the plugin is initialized.
    Authenticates with the container registry (if config is provided).
    Determines whether Docker or Podman is available, sets up port (if needed),
    and prepares for container run.
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

    self._setup_env_and_ports()

    # Validate extra tunnels configuration
    self._validate_extra_tunnels_config()

    self._validate_runner_config()

    # Check if container was manually stopped in a previous session
    if self._load_manual_stop_state():
      self.P("Container was manually stopped in previous session. Keeping container paused.", color='y')
      self._set_container_state(ContainerState.PAUSED, StopReason.MANUAL_STOP)

    self._extra_on_init()
    self.P(f"{self.__class__.__name__} initialized (version {__VER__})", color='g')
    return
  
  def _extra_on_init(self):
    """Hook for subclasses to perform additional initialization."""
    return

  def on_command(self, data, **kwargs):
    """
    Called when a INSTANCE_COMMAND is received by the plugin instance.

    The command is sent via `cmdapi_send_instance_command` from a commanding node (Deeploy plugin)
    as in below simplified example:

    ```python
      pipeline = "some_app_pipeline"
      signature = "CONTAINER_APP_RUNNER"
      instance_id = "CONTAINER_APP_1e8dac"
      node_address = "0xai_1asdfG11sammamssdjjaggxffaffaheASSsa"

      instance_command = "RESTART"

      plugin.cmdapi_send_instance_command(
        pipeline=pipeline,
        signature=signature,
        instance_id=instance_id,
        instance_command=instance_command,
        node_address=node_address,
      )
    ```

    while the `on_command` method should look like this:

    ```python
      def on_command(self, data, **kwargs):
        if data == "RESTART":
          self.P("Restarting container...")
          ...
        elif data == "STOP":
          self.P("Stopping container (restart policy still applies)...")
          ...
        else:
          self.P(f"Unknown command: {data}")
        return
    ```

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

  def on_config(self, *args, **kwargs):
    return self._handle_config_restart(lambda: self._restart_container(StopReason.CONFIG_UPDATE))


  def on_post_container_start(self):
    """
    Lifecycle hook called after the container is started.
    Runs commands in the container if specified in the config.

      - after the container first start
      - after the container is restarted
    """
    self.P("Container started, running post-start commands...")
    return




  def start_tunnel_engine(self):
    """
    Start the tunnel engine using the base tunnel engine functionality.
    """
    if self.cfg_tunnel_engine_enabled:
      engine_name = "Cloudflare" if self.use_cloudflare() else "ngrok"
      self.P(f"Starting {engine_name} tunnel...", color='b')
      self.tunnel_process = self.run_tunnel_engine()
      if self.tunnel_process:
        self.P(f"{engine_name} tunnel started successfully", color='g')
      else:
        self.P(f"Failed to start {engine_name} tunnel", color='r')
      # end if
    # end if
    return

  def stop_tunnel_engine(self):
    """
    Stop the tunnel engine.
    """
    if self.tunnel_process:
      engine_name = "Cloudflare" if self.use_cloudflare() else "ngrok"
      self.P(f"Stopping {engine_name} tunnel...", color='b')
      self.stop_tunnel_command(self.tunnel_process)
      self.tunnel_process = None
      self.P(f"{engine_name} tunnel stopped", color='g')
    # end if
    return

  def get_tunnel_engine_ping_data(self):
    """
    Override to include extra tunnel URLs in payloads.

    Returns:
      dict: Tunnel data including main app_url and extra tunnel URLs
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
    Similar to maybe_tunnel_engine_ping but for extra tunnels.
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

    Args:
      container_port: Container port (int)

    Returns:
      int or None: Host port if found, None otherwise
    """
    for host_port, c_port in self.extra_ports_mapping.items():
      if c_port == container_port:
        return host_port
    return None

  def _build_tunnel_command(self, container_port, token):
    """
    Build Cloudflare tunnel command for a specific port.

    Args:
      container_port: Container port to tunnel
      token: Cloudflare tunnel token

    Returns:
      list or None: Command list to execute, or None if error
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

    Returns:
      bool: True if main tunnel should start
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
      self.P(
        f"Main PORT {self.cfg_port} is defined in EXTRA_TUNNELS, using extra tunnel instead",
        color='y'
      )
      return False

    return True

  def _start_extra_tunnel(self, container_port, token):
    """
    Start a single extra tunnel for a specific container port.

    Args:
      container_port: Container port to expose
      token: Cloudflare tunnel token

    Returns:
      bool: True if tunnel started successfully, False otherwise
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
      self.P(f"Starting Cloudflare tunnel for container port {container_port} (host port {host_port})...", color='b')
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

      self.P(f"Extra tunnel for port {container_port} started (PID: {process.pid})", color='g')
      return True

    except Exception as e:
      self.P(f"Failed to start extra tunnel for port {container_port}: {e}", color='r')
      # Record failure for backoff tracking
      self._record_tunnel_restart_failure(container_port)
      return False

  def start_extra_tunnels(self):
    """Start all configured extra tunnels."""
    if not self.extra_tunnel_configs:
      self.Pd("No extra tunnels configured")
      return

    self.P(f"Starting {len(self.extra_tunnel_configs)} extra tunnel(s)...", color='b')

    started_count = 0
    for container_port, token in self.extra_tunnel_configs.items():
      if self._start_extra_tunnel(container_port, token):
        started_count += 1

    self.P(
      f"Started {started_count}/{len(self.extra_tunnel_configs)} extra tunnels",
      color='g' if started_count == len(self.extra_tunnel_configs) else 'y'
    )
    return

  def _stop_extra_tunnel(self, container_port):
    """
    Stop a single extra tunnel.

    Args:
      container_port: Container port whose tunnel should be stopped
    """
    process = self.extra_tunnel_processes.get(container_port)
    if not process:
      return

    try:
      self.P(f"Stopping extra tunnel for port {container_port}...", color='b')

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

      self.P(f"Extra tunnel for port {container_port} stopped", color='g')

    except Exception as e:
      self.P(f"Error stopping extra tunnel for port {container_port}: {e}", color='r')

  def stop_extra_tunnels(self):
    """Stop all extra tunnels."""
    if not self.extra_tunnel_processes:
      return

    self.P(f"Stopping {len(self.extra_tunnel_processes)} extra tunnel(s)...", color='b')

    for container_port in list(self.extra_tunnel_processes.keys()):
      self._stop_extra_tunnel(container_port)

    self.P("All extra tunnels stopped", color='g')

  def _read_extra_tunnel_logs(self, container_port):
    """
    Read and process logs from an extra tunnel.

    Args:
      container_port: Container port whose tunnel logs to read
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

    For Cloudflare: Extract URL from pattern https://*.trycloudflare.com

    Args:
      container_port: Container port
      text: Log text
      is_error: Whether this is error output
    """
    log_prefix = f"[TUNNEL:{container_port}]"
    color = 'r' if is_error else 'd'

    # Log the output
    for line in text.split('\n'):
      if line.strip():
        self.Pd(f"{log_prefix} {line}", score=0)

    # Extract URL if not already found
    if container_port not in self.extra_tunnel_urls:
      # Extract Cloudflare URL: https://xxx.trycloudflare.com
      url_pattern = r'https://[a-z0-9-]+\.trycloudflare\.com'
      match = self.re.search(url_pattern, text)
      if match:
        url = match.group(0)
        self.extra_tunnel_urls[container_port] = url
        self.P(f"Extra tunnel URL for port {container_port}: {url}", color='g')

  def read_all_extra_tunnel_logs(self):
    """Read logs from all extra tunnels."""
    for container_port in list(self.extra_tunnel_processes.keys()):
      try:
        self._read_extra_tunnel_logs(container_port)
      except Exception as e:
        self.Pd(f"Error reading logs for tunnel {container_port}: {e}")

  def start_container(self):
    """Start the Docker container."""
    self._set_container_state(ContainerState.STARTING)

    log_str = f"Launching container with image '{self.cfg_image}'..."

    log_str += f"Container data:"
    log_str += f"  Image: {self.cfg_image}"
    log_str += f"  Ports: {self.json_dumps(self.inverted_ports_mapping) if self.inverted_ports_mapping else 'None'}"
    log_str += f"  Env: {self.json_dumps(self.env) if self.env else 'None'}"
    log_str += f"  Volumes: {self.json_dumps(self.volumes) if self.volumes else 'None'}"
    log_str += f"  Resources: {self.json_dumps(self.cfg_container_resources) if self.cfg_container_resources else 'None'}"
    log_str += f"  Restart policy: {self.cfg_restart_policy}"
    log_str += f"  Pull policy: {self.cfg_image_pull_policy}"
    log_str += f"  Start command: {self._start_command if self._start_command else 'Image default'}"
    self.P(log_str)

    try:
      run_kwargs = dict(
        detach=True,
        ports=self.inverted_ports_mapping,
        environment=self.env,
        volumes=self.volumes,
        name=self.container_name,
      )
      if self._start_command:
        run_kwargs['command'] = self._start_command

      if self.cfg_use_cuda:
        gpus_info = self.log.gpu_info()
        if len(gpus_info) > 0:
          run_kwargs['runtime'] = 'nvidia'
          self.P(f"USE_CUDA is True and NVIDIA GPUs found, starting container with GPU support")
        else:
          self.P("Warning! USE_CUDA is True but no NVIDIA GPUs found, starting container without GPU support")
        # endif available GPUs
      else:
        self.P(f"Starting container without GPU support")
      # endif cfg_use_cuda

      self.container = self.docker_client.containers.run(
        self.cfg_image,
        **run_kwargs,
      )

      self.container_id = self.container.short_id
      self.P(f"Container started (ID: {self.container.short_id})", color='g')

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
    """Stop and remove the Docker container if it is running."""
    if not self.container:
      self.P("No container to stop", color='y')
      return

    try:
      # Stop the container (gracefully)
      self.P(f"Stopping container {self.container.short_id}...", color='b')
      self.container.stop(timeout=5)
      self.P(f"Container {self.container.short_id} stopped successfully", color='g')
    except Exception as e:
      self.P(f"Error stopping container: {e}", color='r')
    # end try

    try:
      self.P(f"Removing container {self.container.short_id}...", color='b')
      self.container.remove()
      self.P(f"Container {self.container.short_id} removed successfully", color='g')
    except Exception as e:
      self.P(f"Error removing container: {e}", color='r')
    finally:
      self.container = None
      self.container_id = None
    # end try
    return

  def _stream_logs(self, log_stream):
    """Consume a log iterator from container logs and print its output."""
    if not log_stream:
      self.P("No log stream provided", color='y')
      return

    try:
      for log_bytes in log_stream:
        if log_bytes is None:
          break
        try:
          log_str = log_bytes.decode("utf-8", errors="replace")
        except Exception as e:
          self.P(f"Warning: Could not decode log bytes: {e}", color='y')
          log_str = str(log_bytes)

        self.P(f"[CONTAINER] {log_str}", color='d', end='')
        self.container_logs.append(log_str)

        if self._stop_event.is_set():
          self.P("Log streaming stopped by stop event", color='y')
          break
    except Exception as e:
      self.P(f"Exception while streaming logs: {e}", color='r')
    # end try
    return

  def _start_container_log_stream(self):
    """Start following container logs if not already streaming."""
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
    """Return the list of commands to execute inside the container."""
    return list(self._build_commands) if getattr(self, '_build_commands', None) else []

  def _compose_exec_shell(self, commands):
    """Compose a shell command string out of the command fragments."""
    if not commands:
      return None
    return " && ".join(commands)

  def _run_container_exec(self, shell_cmd):
    """Run a shell command inside the container and stream its output."""
    if not self.container or not shell_cmd:
      return

    try:
      self.P(f"Running container exec command: {shell_cmd}", color='b')
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
    """Execute configured build/run commands if necessary."""
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

  def _check_health_endpoint(self, current_time=None):
    if not self.container or not self.cfg_endpoint_url or self.cfg_endpoint_poll_interval <= 0:
      return

    if current_time - self._last_endpoint_check >= self.cfg_endpoint_poll_interval:
      self._last_endpoint_check = current_time
      self._poll_endpoint()
    # end if time elapsed
    return

  def _poll_endpoint(self):
    """Poll the container's health endpoint and log the response."""
    if not self.port:
      self.P("No port allocated, cannot poll endpoint", color='r')
      return

    if not self.cfg_endpoint_url:
      self.P("No endpoint URL configured, skipping health check", color='y')
      return

    url = f"http://localhost:{self.port}{self.cfg_endpoint_url}"

    try:
      resp = requests.get(url, timeout=5)
      status = resp.status_code

      if status == 200:
        self.P(f"Health check: {url} -> {status} OK", color='g')
      else:
        self.P(f"Health check: {url} -> {status} Error", color='r')
    except requests.RequestException as e:
      self.P(f"Health check failed: {url} - {e}", color='r')
    except Exception as e:
      self.P(f"Unexpected error during health check: {e}", color='r')
    # end try
    return

  def _check_container_status(self):
    """
    Check container status and update state machine.

    Returns:
      bool: True if container is running normally, False if stopped/failed

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

      # Update state
      self._set_container_state(ContainerState.FAILED, stop_reason)

      self.P(
        f"Container stopped (exit code: {exit_code}, reason: {stop_reason.value})",
        color='y' if exit_code == 0 else 'r'
      )

      self._commands_started = False
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
            color='y'
          )
          self._start_extra_tunnel(container_port, token)
      else:
        # Tunnel is running - maybe reset retry counter
        self._maybe_reset_tunnel_retry_counter(container_port)




  def _stop_container_and_save_logs_to_disk(self):
    """
    Stops the container and cloudflare tunnel.
    Then logs are saved to disk.
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

    # Save logs to disk
    try:
      # using parent class method to save logs
      self.diskapi_save_pickle_to_output(
        obj=list(self.container_logs), filename="container_logs.pkl"
      )
      self.P("Container logs saved to disk.")
    except Exception as exc:
      self.P(f"Failed to save logs: {exc}", color='r')
    return

  def on_close(self):
    """
    Lifecycle hook called when plugin is stopping.
    Ensures container is shut down and logs are saved.
    Ensures the log process is killed.
    Stops tunnel if started.
    """
    self._stop_container_and_save_logs_to_disk()

    super(ContainerAppRunnerPlugin, self).on_close()


  def _get_local_image(self):
    """
    Get the local Docker image if it exists.

    Returns:
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

    Returns:
      Image object or None if pull failed

    Raises:
      RuntimeError: If authentication hasn't been performed
    """
    if not self.cfg_image:
      self.P("No Docker image configured", color='r')
      return None

    try:
      self.P(f"Pulling image '{self.cfg_image}'...", color='b')
      img = self.docker_client.images.pull(self.cfg_image)

      # docker-py may return Image or list[Image]
      if isinstance(img, list) and img:
        img = img[-1]

      self.P(f"Successfully pulled image '{self.cfg_image}'", color='g')
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

    Returns:
      Image object or None if no image is available

    Raises:
      RuntimeError: If authentication fails and no local image exists
    """
    # Step 1: Authenticate with registry
    if not self._login_to_registry():
      self.P("Registry authentication failed", color='y')
      # Try to use local image if authentication fails
      local_img = self._get_local_image()
      if local_img:
        self.P(f"Using local image (registry login failed): {self.cfg_image}", color='y')
        return local_img
      raise RuntimeError("Failed to authenticate with registry and no local image available.")

    # Step 2: Attempt to pull from registry
    img = self._pull_image_from_registry()
    if img:
      return img

    # Step 3: Fallback to local image
    self.P(f"Pull failed, checking for local image: {self.cfg_image}", color='b')
    local_img = self._get_local_image()
    if local_img:
      self.P(f"Using local image as fallback: {self.cfg_image}", color='y')
      return local_img

    # Step 4: No image available
    self.P(f"No image available (pull failed and no local image): {self.cfg_image}", color='r')
    return None

  def _get_image_digest(self, img):
    """
    Extract digest hash from image object.

    Args:
      img: Docker image object

    Returns:
      str or None: Digest hash (sha256:...) or None
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

    Args:
      latest_hash: Latest image hash from registry

    Returns:
      bool: True if hash changed and update needed, False otherwise
    """
    if not latest_hash:
      # Pull failed, can't determine if update needed
      return False

    if not self.current_image_hash:
      # First time - establish baseline
      self.P(f"Establishing baseline image hash: {latest_hash}", color='b')
      self.current_image_hash = latest_hash
      return False

    # Compare hashes
    return latest_hash != self.current_image_hash

  def _handle_image_update(self, new_hash):
    """
    Handle detected image update by updating hash and restarting container.

    Args:
      new_hash: New image hash detected
    """
    self.P(f"New image version detected ({new_hash} != {self.current_image_hash}). Restarting container...", color='y')

    # Update current_image_hash BEFORE restart
    # This prevents infinite retry loops if restart fails
    old_hash = self.current_image_hash
    self.current_image_hash = new_hash

    try:
      self._restart_container(StopReason.IMAGE_UPDATE)
    except Exception as e:
      self.P(f"Container restart failed after image update: {e}", color='r')
      # Hash already updated, won't retry this version
      self.P(f"Image hash updated from {old_hash} to {new_hash}, but container restart failed", color='y')

  def _check_image_updates(self, current_time=None):
    """
    Periodic check for image updates when AUTOUPDATE is enabled.

    This method:
    1. Checks if update check is due (based on interval)
    2. Pulls latest image and gets its hash
    3. Compares with current hash
    4. Triggers restart if changed

    Args:
      current_time: Current timestamp (for interval checking)
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
      self.P("Failed to check for image updates (pull failed). Container continues running.", color='y')
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

    Args:
      stop_reason: Optional StopReason enum indicating why restart was triggered
    """
    self.P("Restarting container from scratch...", color='b')

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

    Returns:
      bool: True if image pulled successfully, False otherwise
    """
    self.Pd("IMAGE_PULL_POLICY is 'always', pulling image")
    img = self._pull_image_with_fallback()
    return img is not None

  def _ensure_image_if_not_present(self):
    """
    Ensure image is available with 'if-not-present' policy.
    Only pulls if image doesn't exist locally.

    Returns:
      bool: True if image is available (locally or after pull), False otherwise
    """
    # Check if image exists locally
    local_img = self._get_local_image()
    if local_img:
      self.P(f"Image '{self.cfg_image}' found locally", color='g')
      return True

    # Image not found locally, pull it
    self.P(f"Image not found locally, pulling '{self.cfg_image}'...", color='b')
    img = self._pull_image_with_fallback()
    return img is not None

  def _ensure_image_available(self):
    """
    Ensure the container image is available before starting container.

    This method uses a strategy pattern based on configuration:
    - AUTOUPDATE enabled: Ensure image exists locally (update detection handled separately)
    - IMAGE_PULL_POLICY='always': Always pull (no tracking)
    - IMAGE_PULL_POLICY='if-not-present' or default: Pull only if missing locally

    Returns:
      bool: True if image is available, False otherwise
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

  def _handle_initial_launch(self):
    """Handle the initial container launch."""
    try:
      self.P("Initial container launch...", color='b')

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

      self.P("Container launched successfully", color='g')
      self.P(self.container)
      if self.current_image_hash:
        self.P(f"Current image hash: {self.current_image_hash}", color='d')
    except Exception as e:
      self.P(f"Could not start container: {e}", color='r')
    # end try
    return

  def _perform_periodic_monitoring(self):
    """Perform periodic monitoring tasks."""
    current_time = self.time()
    self._check_health_endpoint(current_time)
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
    This is the main process loop for the plugin that gets called each PROCESS_DELAY seconds and
    it performs the following:

      1. Initialize and start tunnel engine if needed
      2. Check if container is running and restart if needed
      3. Perform periodic monitoring (health checks, etc.)
      4. Tunnel engine ping and maintenance

    """
    # Use state machine instead of deprecated _is_manually_stopped flag
    if self.container_state == ContainerState.PAUSED:
      # Log paused message periodically instead of every process cycle
      current_time = self.time()
      if current_time - self._last_paused_log >= self.cfg_paused_log_interval:
        self.P("Container is paused (manual stop). Send RESTART command to resume.", color='y')
        self._last_paused_log = current_time
      return

    if not self.container:
      self._handle_initial_launch()

    # Tunnel management (only if TUNNEL_ENGINE_ENABLED=True)
    if self.cfg_tunnel_engine_enabled:
      self.maybe_init_tunnel_engine()
      self.maybe_start_tunnel_engine()

      # Start main tunnel if configured and not already running
      if not self.tunnel_process and self._should_start_main_tunnel():
        self.start_tunnel_engine()

      # Start extra tunnels if configured and not already running
      if self.extra_tunnel_configs and not self.extra_tunnel_processes:
        self.start_extra_tunnels()

      # Read logs from all extra tunnels
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
        color='y'
      )
      self._restart_container(self.stop_reason)
      return

    # Container is running normally - reset retry counter if appropriate
    self._maybe_reset_retry_counter()

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
