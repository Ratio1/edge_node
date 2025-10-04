import sys
import types
import unittest


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


_install_dummy_base_plugin()

from extensions.business.container_apps.worker_app_runner import WorkerAppRunnerPlugin


class WorkerAppRunnerConfigTests(unittest.TestCase):

  def _make_plugin(self):
    plugin = WorkerAppRunnerPlugin.__new__(WorkerAppRunnerPlugin)
    plugin.P = lambda *args, **kwargs: None
    from collections import deque
    plugin.deque = deque
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
    return plugin

  def test_configure_repo_url_public(self):
    plugin = self._make_plugin()
    plugin.cfg_vcs_data = {
      "REPO_OWNER": "ratio1",
      "REPO_NAME": "demo",
    }
    plugin._configure_repo_url()
    self.assertEqual(plugin.repo_url, "https://github.com/ratio1/demo.git")

  def test_configure_repo_url_with_credentials(self):
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
    plugin = self._make_plugin()
    plugin.cfg_vcs_data = {
      "REPO_OWNER": "ratio1",
      "REPO_NAME": "demo",
      "TOKEN": "token",
    }
    plugin._configure_repo_url()
    self.assertEqual(plugin.repo_url, "https://token@github.com/ratio1/demo.git")

  def test_check_image_updates_respects_autoupdate_flag(self):
    plugin = self._make_plugin()
    plugin.cfg_autoupdate = False
    plugin._last_image_check = 0

    def fail_pull():
      raise AssertionError("_get_latest_image_hash should not be called when AUTOUPDATE disabled")

    plugin._get_latest_image_hash = fail_pull
    plugin._check_image_updates(current_time=100)

  def test_check_image_updates_triggers_restart_on_new_digest(self):
    plugin = self._make_plugin()
    plugin.cfg_autoupdate = True
    plugin.cfg_autoupdate_interval = 10
    plugin.current_image_hash = "old"
    plugin._last_image_check = 0
    plugin._get_latest_image_hash = lambda: "new"
    restart_calls = []
    plugin._restart_from_scratch = lambda: restart_calls.append("called")

    plugin._check_image_updates(current_time=15)

    self.assertEqual(plugin.current_image_hash, "new")
    self.assertEqual(restart_calls, ["called"])


if __name__ == "__main__":
  unittest.main()
