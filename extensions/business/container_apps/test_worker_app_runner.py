import os
import shutil
import stat
import sys
import tempfile
import types
import unittest
from unittest import mock


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

  def _safe_path_component(self, raw):
    from extensions.business.container_apps.fixed_volume import safe_path_component
    return safe_path_component(raw)

  def _get_instance_data_subfolder(self):
    sid = self._safe_path_component(getattr(self, '_stream_id', 'test_stream'))
    iid = self._safe_path_component(getattr(self, 'cfg_instance_id', 'test_instance'))
    return "pipelines_data/{}/{}".format(sid, iid)

  def get_data_folder(self):
    # Overridden per-test via `plugin.get_data_folder = lambda: <tmpdir>`.
    return "/tmp/test_data"


def _install_dummy_base_plugin():
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


def _install_dummy_docker_module():
  docker_mod = types.ModuleType('docker')
  docker_types_mod = types.ModuleType('docker.types')

  class _DummyDeviceRequest:
    def __init__(self, *args, **kwargs):
      self.args = args
      self.kwargs = kwargs

  docker_types_mod.DeviceRequest = _DummyDeviceRequest
  docker_mod.types = docker_types_mod
  sys.modules.setdefault('docker', docker_mod)
  sys.modules.setdefault('docker.types', docker_types_mod)


_install_dummy_base_plugin()
_install_dummy_docker_module()

from extensions.business.container_apps.worker_app_runner import WorkerAppRunnerPlugin
from extensions.business.container_apps import container_utils
from extensions.business.container_apps.container_app_runner import (
  ContainerAppRunnerPlugin,
  ContainerState,
  StopReason,
)


def _seed_lifecycle_state(plugin):
  plugin.container_state = ContainerState.RUNNING
  plugin.stop_reason = StopReason.UNKNOWN
  plugin._cleanup_failed = False
  plugin._manual_stop_pending = False
  plugin._load_manual_stop_state = lambda: False
  plugin._set_container_state = lambda state, reason=None: (
    setattr(plugin, "container_state", state),
    setattr(plugin, "stop_reason", reason or plugin.stop_reason),
  )
  plugin._record_restart_failure = lambda: None
  return plugin


class WorkerAppRunnerConfigTests(unittest.TestCase):

  def _make_plugin(self):
    """
    Create a mock WorkerAppRunnerPlugin instance for testing.

    Creates a plugin instance with mock attributes and methods
    to facilitate unit testing without requiring actual Docker
    infrastructure or network connections.

    Returns
    -------
    WorkerAppRunnerPlugin
        A mock plugin instance with test configuration
    """
    plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    plugin.P = lambda *args, **kwargs: None
    from collections import deque
    plugin.deque = deque
    plugin.os_path = os.path
    plugin.os = os
    plugin.cfg_instance_id = "test_instance"
    plugin.uuid = lambda *a, **k: "abcd"
    plugin.time = lambda: 0
    plugin.cfg_max_log_lines = 10
    plugin.cfg_env = {}
    plugin.cfg_dynamic_env = {}
    plugin.cfg_container_resources = {}
    plugin.cfg_volumes = {}
    plugin.cfg_port = None
    plugin.cfg_autoupdate = True
    plugin.cfg_autoupdate_interval = 10
    plugin.cfg_image_poll_interval = 10
    plugin.cfg_chainstore_response_key = None
    plugin.cfg_chainstore_peers = []
    plugin.cfg_car_verbose = 10
    plugin.volumes = {}
    plugin.extra_ports_mapping = {}
    plugin.inverted_ports_mapping = {}
    plugin.log = types.SimpleNamespace(get_localhost_ip=lambda: "127.0.0.1")
    plugin.bc = types.SimpleNamespace(eth_address="0x0", get_evm_network=lambda: "testnet")
    plugin.current_commit = None
    plugin.branch = None
    plugin.repo_url = None
    plugin._last_git_check = 0
    plugin._git_backoff_until = 0
    plugin._repo_configured = False
    plugin._repo_owner = None
    plugin._repo_name = None
    _seed_lifecycle_state(plugin)
    return plugin

  def test_configure_repo_url_public(self):
    """Test repository URL configuration for public repositories."""
    plugin = self._make_plugin()
    plugin.cfg_vcs_data = {
      "REPO_OWNER": "ratio1",
      "REPO_NAME": "demo",
    }
    plugin._configure_repo_url()
    self.assertEqual(plugin.repo_url, "https://github.com/ratio1/demo.git")

  def test_configure_repo_url_with_credentials(self):
    """Test repository URL configuration with username and token credentials."""
    plugin = self._make_plugin()
    plugin.cfg_vcs_data = {
      "REPO_OWNER": "ratio1",
      "REPO_NAME": "demo",
      "USERNAME": "user",
      "TOKEN": "token",
    }
    plugin._configure_repo_url()
    self.assertEqual(plugin.repo_url, "https://user:token@github.com/ratio1/demo.git")

  def test_configure_repo_url_token_only(self):
    """Test repository URL configuration with token-only authentication."""
    plugin = self._make_plugin()
    plugin.cfg_vcs_data = {
      "REPO_OWNER": "ratio1",
      "REPO_NAME": "demo",
      "TOKEN": "token",
    }
    plugin._configure_repo_url()
    self.assertEqual(plugin.repo_url, "https://token@github.com/ratio1/demo.git")

  def test_git_clone_command_uses_configured_branch(self):
    """Test repository setup clones the same branch monitored for updates."""
    plugin = self._make_plugin()
    plugin.repo_url = "https://github.com/ratio1/demo.git"
    plugin.branch = "develop"

    command = plugin._build_git_clone_command("/app")

    self.assertEqual(
      command,
      "git clone --branch develop --single-branch https://github.com/ratio1/demo.git /app",
    )

  def test_git_clone_command_allows_branchless_clone(self):
    """Test repository setup keeps the old default-branch behavior if branch is absent."""
    plugin = self._make_plugin()
    plugin.repo_url = "https://github.com/ratio1/demo.git"
    plugin.branch = None

    command = plugin._build_git_clone_command("/app")

    self.assertEqual(command, "git clone https://github.com/ratio1/demo.git /app")

  def test_check_image_updates_respects_autoupdate_flag(self):
    """Test that image update checks respect the AUTOUPDATE flag."""
    plugin = self._make_plugin()
    plugin.cfg_autoupdate = False
    plugin._last_image_check = 0

    def fail_pull():
      raise AssertionError("_get_latest_image_hash should not be called when AUTOUPDATE disabled")

    plugin._get_latest_image_hash = fail_pull
    plugin._check_image_updates(current_time=100)

  def test_check_image_updates_triggers_restart_on_new_digest(self):
    """Test that new image digest triggers container restart."""
    plugin = self._make_plugin()
    plugin.cfg_autoupdate = True
    plugin.cfg_autoupdate_interval = 10
    plugin.current_image_hash = "old"
    plugin._last_image_check = 0
    plugin._get_latest_image_hash = lambda: "new"
    restart_calls = []
    plugin._restart_container = lambda reason: restart_calls.append(reason)

    plugin._check_image_updates(current_time=15)

    self.assertEqual(plugin.current_image_hash, "new")
    self.assertEqual(restart_calls, [StopReason.IMAGE_UPDATE])

  def test_configure_volumes_primary_path(self):
    """Test volume configuration creates directories with correct permissions."""
    plugin = self._make_plugin()
    plugin.cfg_volumes = {"/data": "/app/data"}

    temp_dir = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, temp_dir, ignore_errors=True)
    volumes_base = os.path.join(temp_dir, "volumes")

    with unittest.mock.patch.object(container_utils, "CONTAINER_VOLUMES_PATH", volumes_base):
      plugin._configure_volumes()

    self.assertEqual(len(plugin.volumes), 1)
    host_path = next(iter(plugin.volumes.keys()))
    self.assertTrue(host_path.startswith(volumes_base))
    self.assertTrue(os.path.isdir(host_path))
    self.assertEqual(stat.S_IMODE(os.stat(host_path).st_mode), 0o777)

  def test_on_config_triggers_restart(self):
    """Test that configuration changes trigger container restart."""
    plugin = self._make_plugin()
    with mock.patch.object(plugin, "_stop_container_and_save_logs_to_disk", return_value=True) as stop_mock, \
         mock.patch.object(plugin, "_restart_container") as restart_mock:
      plugin.on_config()

    stop_mock.assert_called_once()
    restart_mock.assert_called_once_with(StopReason.CONFIG_UPDATE, cleanup_first=False)

  def test__on_config_aliases_to_on_config(self):
    """Test that _on_config is an alias for on_config method."""
    plugin = self._make_plugin()
    with mock.patch.object(plugin, "_stop_container_and_save_logs_to_disk", return_value=True) as stop_mock, \
         mock.patch.object(plugin, "_restart_container") as restart_mock:
      plugin._on_config()

    stop_mock.assert_called_once()
    restart_mock.assert_called_once_with(StopReason.CONFIG_UPDATE, cleanup_first=False)


class ContainerAppRunnerConfigTests(unittest.TestCase):

  def _make_plugin(self):
    """
    Create a mock ContainerAppRunnerPlugin instance for testing.

    Creates a plugin instance with mock attributes and methods
    to facilitate unit testing without requiring actual Docker
    infrastructure or network connections.

    Returns
    -------
    ContainerAppRunnerPlugin
        A mock plugin instance with test configuration
    """
    plugin = ContainerAppRunnerPlugin.__new__(ContainerAppRunnerPlugin)
    plugin.P = lambda *args, **kwargs: None
    from collections import deque
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
    plugin.cfg_port = None
    plugin.cfg_autoupdate = True
    plugin.cfg_autoupdate_interval = 10
    plugin.cfg_image_poll_interval = 10
    plugin.cfg_chainstore_response_key = None
    plugin.cfg_chainstore_peers = []
    plugin.cfg_car_verbose = 10
    plugin.volumes = {}
    plugin.extra_ports_mapping = {}
    plugin.inverted_ports_mapping = {}
    plugin.log = types.SimpleNamespace(get_localhost_ip=lambda: "127.0.0.1")
    plugin.bc = types.SimpleNamespace(eth_address="0x0", get_evm_network=lambda: "testnet")
    _seed_lifecycle_state(plugin)
    return plugin

  def test_on_config_triggers_restart(self):
    """Test that configuration changes trigger container restart."""
    plugin = self._make_plugin()
    with mock.patch.object(plugin, "_stop_container_and_save_logs_to_disk", return_value=True) as stop_mock, \
         mock.patch.object(plugin, "_restart_container") as restart_mock:
      plugin.on_config()

    stop_mock.assert_called_once()
    restart_mock.assert_called_once_with(StopReason.CONFIG_UPDATE, cleanup_first=False)

  def test__on_config_aliases_to_on_config(self):
    """Test that _on_config is an alias for on_config method."""
    plugin = self._make_plugin()
    with mock.patch.object(plugin, "_stop_container_and_save_logs_to_disk", return_value=True) as stop_mock, \
         mock.patch.object(plugin, "_restart_container") as restart_mock:
      plugin._on_config()

    stop_mock.assert_called_once()
    restart_mock.assert_called_once_with(StopReason.CONFIG_UPDATE, cleanup_first=False)

  def test_configure_file_volumes(self):
    """Test FILE_VOLUMES feature creates files with correct content and mounts them."""
    plugin = self._make_plugin()
    plugin.cfg_file_volumes = {
      "app_config": {
        "content": "server_port=8080\ndebug=true",
        "mounting_point": "/app/config/settings.conf"
      },
      "secret_key": {
        "content": "my-secret-api-key-12345",
        "mounting_point": "/etc/secrets/api.key"
      }
    }

    temp_dir = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, temp_dir, ignore_errors=True)

    # FILE_VOLUMES now resolves to <data_folder>/pipelines_data/<sid>/<iid>/file_volumes/
    plugin.get_data_folder = lambda: temp_dir
    plugin._configure_file_volumes()

    # Verify two file volumes were created
    self.assertEqual(len(plugin.volumes), 2)
    
    # Check that files were created with correct content
    for host_path, mount_config in plugin.volumes.items():
      self.assertTrue(os.path.isfile(host_path))
      
      if mount_config["bind"] == "/app/config/settings.conf":
        with open(host_path, 'r') as f:
          content = f.read()
        self.assertEqual(content, "server_port=8080\ndebug=true")
        self.assertTrue(host_path.endswith("settings.conf"))
      
      elif mount_config["bind"] == "/etc/secrets/api.key":
        with open(host_path, 'r') as f:
          content = f.read()
        self.assertEqual(content, "my-secret-api-key-12345")
        self.assertTrue(host_path.endswith("api.key"))

  def test_configure_file_volumes_empty_config(self):
    """Test FILE_VOLUMES with empty config does nothing."""
    plugin = self._make_plugin()
    plugin.cfg_file_volumes = {}
    
    plugin._configure_file_volumes()
    
    self.assertEqual(len(plugin.volumes), 0)

  def test_configure_file_volumes_missing_fields(self):
    """Test FILE_VOLUMES handles missing fields gracefully."""
    plugin = self._make_plugin()
    plugin.cfg_file_volumes = {
      "incomplete1": {
        "content": "test"
        # missing mounting_point
      },
      "incomplete2": {
        "mounting_point": "/test/file.txt"
        # missing content
      },
      "valid": {
        "content": "valid content",
        "mounting_point": "/valid/file.txt"
      }
    }

    temp_dir = tempfile.mkdtemp()
    self.addCleanup(shutil.rmtree, temp_dir, ignore_errors=True)

    plugin.get_data_folder = lambda: temp_dir
    plugin._configure_file_volumes()

    # Only the valid entry should be processed
    self.assertEqual(len(plugin.volumes), 1)
    
    # Verify the valid file was created
    host_path = next(iter(plugin.volumes.keys()))
    self.assertTrue(os.path.isfile(host_path))
    with open(host_path, 'r') as f:
      content = f.read()
    self.assertEqual(content, "valid content")


if __name__ == "__main__":
  unittest.main()
