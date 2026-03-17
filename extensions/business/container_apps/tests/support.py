import os
import sys
import types
from collections import deque


class _DummyBasePlugin:
  CONFIG = {'VALIDATION_RULES': {}}

  def __init__(self, *args, **kwargs):
    pass

  def on_init(self):
    return

  def reset_tunnel_engine(self):
    return

  def maybe_init_tunnel_engine(self):
    return

  def maybe_start_tunnel_engine(self):
    return

  def maybe_tunnel_engine_ping(self):
    return

  def diskapi_save_pickle_to_output(self, *args, **kwargs):
    return

  def chainstore_set(self, *args, **kwargs):
    return

  def use_cloudflare(self):
    return True

  def stop_tunnel_command(self, *args, **kwargs):
    return

  def run_tunnel_engine(self):
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
  plugin.P = lambda *args, **kwargs: None
  plugin.Pd = lambda *args, **kwargs: None
  plugin.deque = deque
  plugin.os_path = os.path
  plugin.os = os
  plugin.cfg_instance_id = "car_instance"
  plugin.uuid = lambda *a, **k: "efgh"
  plugin.time = lambda: 0
  plugin.cfg_max_log_lines = 10
  plugin.cfg_env = {}
  plugin.cfg_dynamic_env = {}
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
  plugin.container = object()
  plugin.container_name = "car_instance_efgh"
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
