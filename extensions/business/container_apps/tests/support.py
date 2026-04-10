import os
import sys
import threading
import types
from collections import deque
from unittest.mock import MagicMock


class _DummyBasePlugin:
  CONFIG = {'VALIDATION_RULES': {}}

  def __init__(self, *args, **kwargs):
    pass

  def on_init(self):
    return

  def on_close(self):
    return

  def reset_tunnel_engine(self):
    return

  def maybe_init_tunnel_engine(self):
    return

  def maybe_start_tunnel_engine(self):
    return

  def maybe_tunnel_engine_ping(self):
    return

  def maybe_extra_tunnels_ping(self):
    return

  def stop_tunnel_engine(self):
    return

  def stop_extra_tunnels(self):
    return

  def start_tunnel_engine(self):
    return

  def start_extra_tunnels(self):
    return

  def read_all_extra_tunnel_logs(self):
    return

  def diskapi_save_pickle_to_output(self, *args, **kwargs):
    return

  def diskapi_save_pickle_to_data(self, *args, **kwargs):
    return

  def diskapi_load_pickle_from_data(self, *args, **kwargs):
    return None

  def chainstore_set(self, *args, **kwargs):
    return

  def set_plugin_ready(self, ready):
    return

  def reset_chainstore_response(self):
    return

  def use_cloudflare(self):
    return True

  def stop_tunnel_command(self, *args, **kwargs):
    return

  def run_tunnel_engine(self):
    return None

  def get_cloudflare_token(self):
    params = getattr(self, 'cfg_tunnel_engine_parameters', None) or {}
    return getattr(self, 'cfg_cloudflare_token', None) or params.get("CLOUDFLARE_TOKEN")

  def get_data_folder(self):
    return "/tmp/test_data"

  # Semaphore stubs
  def _semaphore_get_keys(self):
    return getattr(self, 'cfg_semaphored_keys', None) or []

  def _semaphore_reset_signal(self):
    return

  def _semaphore_set_ready_flag(self):
    return

  def semaphore_start_wait(self):
    return

  def semaphore_check_with_logging(self):
    return True

  def semaphore_get_status(self):
    return {}

  def semaphore_is_ready(self, key):
    return True

  def semaphore_get_wait_elapsed(self):
    return 0

  def semaphore_get_missing(self):
    return []

  def semaphore_get_env(self):
    return {}

  def semaphore_get_env_value(self, key, env_key):
    return None

  def semaphore_get_env_value_by_path(self, path):
    return None

  def time(self):
    return 0

  def sleep(self, *args, **kwargs):
    return

  def deepcopy(self, obj):
    return obj

  def json_dumps(self, obj):
    return str(obj)

  def sanitize_name(self, name):
    return name.replace('/', '_')


def install_dummy_base_plugin():
  module_hierarchy = [
    ('naeural_core', types.ModuleType('naeural_core')),
    ('naeural_core.business', types.ModuleType('naeural_core.business')),
    ('naeural_core.business.base', types.ModuleType('naeural_core.business.base')),
    ('naeural_core.business.base.web_app', types.ModuleType('naeural_core.business.base.web_app')),
  ]

  for name, module in module_hierarchy:
    sys.modules.setdefault(name, module)

  base_tunnel_mod = types.ModuleType('naeural_core.business.base.web_app.base_tunnel_engine_plugin')
  base_tunnel_mod.BaseTunnelEnginePlugin = _DummyBasePlugin
  sys.modules['naeural_core.business.base.web_app.base_tunnel_engine_plugin'] = base_tunnel_mod


install_dummy_base_plugin()

from extensions.business.container_apps.container_app_runner import ContainerAppRunnerPlugin


def make_container_app_runner():
  plugin = ContainerAppRunnerPlugin.__new__(ContainerAppRunnerPlugin)
  plugin.logged_messages = []

  def _log(*args, **kwargs):
    if args:
      plugin.logged_messages.append(str(args[0]))
    return

  plugin.P = _log
  plugin.Pd = _log
  plugin.deque = deque
  plugin.os_path = os.path
  plugin.os = os
  plugin.cfg_instance_id = "car_instance"
  plugin.uuid = lambda *a, **k: "efgh"
  plugin.time = lambda: 0
  plugin.cfg_max_log_lines = 10
  plugin.cfg_image = "test/image:latest"
  plugin.cfg_env = {}
  plugin.cfg_dynamic_env = {}
  plugin.cfg_exposed_ports = {}
  plugin.cfg_container_resources = {}
  plugin.cfg_volumes = {}
  plugin.cfg_file_volumes = {}
  plugin.cfg_port = None
  plugin.cfg_autoupdate = True
  plugin.cfg_autoupdate_interval = 10
  plugin.cfg_image_poll_interval = 10
  plugin.cfg_chainstore_response_key = None
  plugin.cfg_chainstore_peers = []
  plugin.cfg_car_verbose = 10
  plugin.cfg_cloudflare_token = None
  plugin.cfg_tunnel_engine_enabled = True
  plugin.cfg_tunnel_engine_parameters = {}
  plugin.cfg_extra_tunnels = {}
  plugin.cfg_extra_tunnels_ping_interval = 30
  plugin.cfg_health_check = {}
  plugin.cfg_restart_policy = "always"
  plugin.volumes = {}
  plugin.extra_ports_mapping = {}
  plugin.inverted_ports_mapping = {}
  plugin.extra_tunnel_configs = {}
  plugin.extra_tunnel_processes = {}
  plugin.extra_tunnel_urls = {}
  plugin.extra_tunnel_log_readers = {}
  plugin.extra_tunnel_start_times = {}
  plugin._tunnel_consecutive_failures = {}
  plugin._tunnel_last_failure_time = {}
  plugin._tunnel_next_restart_time = {}
  plugin._tunnel_last_successful_start = {}
  plugin._health_probing_disabled = False
  plugin._normalized_exposed_ports = {}
  plugin._normalized_main_exposed_port = None
  plugin.container = object()
  plugin.container_name = "car_instance"
  plugin.log = types.SimpleNamespace(get_localhost_ip=lambda: "127.0.0.1")
  plugin.bc = types.SimpleNamespace(eth_address="0x0", get_evm_network=lambda: "testnet")
  plugin.re = __import__("re")
  plugin.json_dumps = lambda obj: str(obj)
  plugin.deepcopy = lambda obj: obj
  plugin.semaphore_env = {}
  plugin.semaphore_set_env = lambda key, value: plugin.semaphore_env.__setitem__(key, str(value))
  plugin._get_container_ip = lambda: "172.18.0.5"

  next_dynamic_port = {'value': 20000}

  def allocate_port(required_port=0, allow_dynamic=False, sleep_time=5):
    if required_port:
      return required_port
    next_dynamic_port['value'] += 1
    return next_dynamic_port['value']

  plugin._allocate_port = allocate_port
  return plugin


def make_mock_container(status="running", exit_code=0):
  """Create a mock Docker container with realistic attributes."""
  container = MagicMock()
  container.short_id = "abc1234567"
  container.id = "abc1234567890abcdef"
  container.name = "car_instance"
  container.status = status
  container.attrs = {
    "State": {"ExitCode": exit_code, "Running": status == "running"},
    "NetworkSettings": {"IPAddress": "172.18.0.5", "Networks": {}},
  }
  container.reload = MagicMock()
  container.logs = MagicMock(return_value=iter([]))
  container.stop = MagicMock()
  container.remove = MagicMock()
  container.exec_run = MagicMock(
    return_value=MagicMock(output=iter([b""]), exit_code=0)
  )
  return container


def make_mock_docker_client(container=None):
  """Create a mock Docker client with all required methods."""
  import docker.errors

  client = MagicMock()
  client.ping.return_value = None

  if container is None:
    container = make_mock_container()

  client.containers.run.return_value = container
  client.containers.get.side_effect = docker.errors.NotFound("Not found")

  mock_image = MagicMock()
  mock_image.short_id = "img123"
  mock_image.id = "sha256:abc123"
  mock_image.tags = ["test/image:latest"]
  mock_image.attrs = {"RepoDigests": ["test/image@sha256:abc123"]}
  client.images.get.return_value = mock_image
  client.images.pull.return_value = mock_image
  client.login.return_value = {"Status": "Login Succeeded"}
  return client, container


def make_lifecycle_runner(docker_client=None, mock_container=None, **cfg_overrides):
  """Create a plugin fully wired for lifecycle testing.

  Extends make_container_app_runner() with all attributes needed to call
  on_init(), process(), _handle_initial_launch(), _restart_container(),
  stop_container(), on_close(), and _check_container_status().

  Returns (plugin, docker_client, mock_container).
  """
  from extensions.business.container_apps.container_app_runner import (
    ContainerState, StopReason,
  )

  if docker_client is None:
    docker_client, mock_container = make_mock_docker_client(mock_container)

  plugin = make_container_app_runner()

  # Override container to None (lifecycle starts with no container)
  plugin.container = None
  plugin.container_id = None
  plugin.container_name = plugin.cfg_instance_id
  plugin.docker_client = docker_client
  plugin.container_logs = deque(maxlen=plugin.cfg_max_log_lines)

  # Environment and ports (normally populated by _setup_env_and_ports)
  plugin.env = {}
  plugin.dynamic_env = {}

  # State machine
  plugin.container_state = ContainerState.UNINITIALIZED
  plugin.stop_reason = StopReason.UNKNOWN

  # Restart/backoff
  plugin._consecutive_failures = 0
  plugin._last_failure_time = 0
  plugin._next_restart_time = 0
  plugin._restart_backoff_seconds = 0
  plugin._last_successful_start = None
  plugin.cfg_restart_max_retries = 5
  plugin.cfg_restart_backoff_initial = 2
  plugin.cfg_restart_backoff_max = 300
  plugin.cfg_restart_backoff_multiplier = 2
  plugin.cfg_restart_reset_interval = 300

  # Image pull backoff
  plugin._image_pull_failures = 0
  plugin._next_image_pull_time = 0
  plugin.cfg_image_pull_max_retries = 100
  plugin.cfg_image_pull_backoff_base = 2

  # Tunnel (disabled for lifecycle tests by default)
  plugin.cfg_tunnel_engine_enabled = False
  plugin.cfg_tunnel_engine = "cloudflare"
  plugin.cfg_tunnel_engine_ping_interval = 30
  plugin.tunnel_process = None

  # Tunnel restart backoff
  plugin.cfg_tunnel_restart_max_retries = 5
  plugin.cfg_tunnel_restart_backoff_initial = 2
  plugin.cfg_tunnel_restart_backoff_max = 60
  plugin.cfg_tunnel_restart_backoff_multiplier = 2
  plugin.cfg_tunnel_restart_reset_interval = 300

  # Log streaming
  plugin.log_thread = None
  plugin.exec_threads = []
  plugin._stop_event = threading.Event()

  # Timing
  plugin.container_start_time = None
  plugin._last_image_check = 0
  plugin._last_extra_tunnels_ping = 0
  plugin._last_paused_log = 0
  plugin.cfg_paused_state_log_interval = 60
  plugin.cfg_show_log_each = 60
  plugin.cfg_show_log_last_lines = 5
  plugin.cfg_semaphore_log_interval = 10

  # Image update
  plugin.current_image_hash = None
  plugin.cfg_image_pull_policy = "always"

  # Commands
  plugin._commands_started = False
  plugin.cfg_build_and_run_commands = []
  plugin.cfg_container_entrypoint = None
  plugin.cfg_container_start_command = None
  plugin.cfg_container_user = None

  # Derived command attributes (normally set by _validate_runner_config)
  plugin._entrypoint = None
  plugin._start_command = None
  plugin._build_commands = []

  # Resource limits (normally set by _setup_resource_limits_and_ports)
  plugin._cpu_limit = 1.0
  plugin._gpu_limit = 0
  plugin._mem_limit = "512m"

  # Health check
  plugin._app_ready = False
  plugin._health_probe_start = None
  plugin._last_health_probe = 0
  plugin._tunnel_start_allowed = False

  # Semaphore (disabled)
  plugin.cfg_semaphored_keys = []

  # Fixed-size volumes
  plugin._fixed_volumes = []
  plugin.cfg_fixed_size_volumes = {}

  # Persistent state / identity
  plugin.plugin_id = "test_stream__CAR__car_instance"
  plugin.ee_id = "test_edge_node"
  plugin.ee_addr = "0xTestAddr"

  # CR data (container registry)
  plugin.cfg_cr_data = {"SERVER": "docker.io", "USERNAME": None, "PASSWORD": None}

  # Ngrok / tunnel config
  plugin.cfg_ngrok_edge_label = None
  plugin.cfg_ngrok_auth_token = None
  plugin.cfg_ngrok_use_api = True
  plugin.cfg_ngrok_domain = None
  plugin.cfg_ngrok_url_ping_interval = 10
  plugin.cfg_ngrok_url_ping_count = 10
  plugin.cfg_debug_web_app = False
  plugin.cfg_cloudflare_protocol = "http"

  # Log config
  plugin.cfg_show_log_each = 60
  plugin.cfg_show_log_last_lines = 5

  # Apply overrides
  for key, value in cfg_overrides.items():
    setattr(plugin, key, value)

  return plugin, docker_client, mock_container
