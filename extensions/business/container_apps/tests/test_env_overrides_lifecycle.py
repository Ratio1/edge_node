import json
import tempfile
import unittest
from pathlib import Path

from extensions.business.container_apps.env_overrides import (
  ENV_OVERRIDES_REQUEST_FILE,
  ENV_OVERRIDES_RESPONSE_FILE,
  EnvOverrideManager,
  env_overrides_dir,
)
from extensions.business.container_apps.env_overrides.constants import (
  ENV_OVERRIDES_STATE_FILE,
)
from extensions.business.container_apps.tests.support import make_container_app_runner
from extensions.business.container_apps.container_app_runner import StopReason


class TestEnvOverrideLifecycleIntegration(unittest.TestCase):

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.plugin = make_container_app_runner()
    self.plugin.get_data_folder = lambda: str(self.tmpdir)
    self.plugin.cfg_env_overrides = {"ENABLED": True}
    self.plugin.cfg_sync = {"ENABLED": False}
    self.plugin._sync_unavailable = False
    self.plugin._env_overrides_unavailable = False
    self.plugin._env_overrides_manager = None
    self.plugin.ee_id = "ee_test"
    self.plugin.ee_addr = "0xTestAddr"
    self.plugin.env = {}
    self.plugin.dynamic_env = {}
    env_overrides_dir(self.plugin).mkdir(parents=True, exist_ok=True)

  def tearDown(self):
    self._tmp.cleanup()

  def _state_path(self):
    return (
      self.tmpdir
      / self.plugin._get_instance_data_subfolder()
      / "plugin_data"
      / ENV_OVERRIDES_STATE_FILE
    )

  def test_setup_env_and_ports_applies_local_overrides_after_cfg_env(self):
    EnvOverrideManager(self.plugin).apply_patch({
      "schema_version": 1,
      "set": {
        "LOG_LEVEL": "trace",
        "EXTRA_FLAG": 7,
      },
    })
    self.plugin.cfg_env = {"LOG_LEVEL": "info", "BASE_ONLY": "yes"}

    self.plugin._setup_env_and_ports()

    self.assertEqual(self.plugin.env["LOG_LEVEL"], "trace")
    self.assertEqual(self.plugin.env["EXTRA_FLAG"], "7")
    self.assertEqual(self.plugin.env["BASE_ONLY"], "yes")

  def test_restart_now_request_maps_to_env_override_stop_reason(self):
    request_path = env_overrides_dir(self.plugin) / ENV_OVERRIDES_REQUEST_FILE
    request_path.write_text(
      json.dumps({
        "schema_version": 1,
        "request_id": "env-restart",
        "apply": "restart_now",
        "set": {"LOG_LEVEL": "trace"},
      }),
      encoding="utf-8",
    )

    reason = self.plugin._perform_additional_checks(current_time=123.0)

    self.assertEqual(reason, StopReason.ENV_OVERRIDE)
    response = json.loads(
      (env_overrides_dir(self.plugin) / ENV_OVERRIDES_RESPONSE_FILE).read_text()
    )
    self.assertEqual(response["status"], "ok")
    self.assertEqual(response["request_id"], "env-restart")
    self.assertEqual(response["restart"]["requested"], True)
    self.assertEqual(json.loads(self._state_path().read_text()), {"LOG_LEVEL": "trace"})


if __name__ == "__main__":
  unittest.main()
