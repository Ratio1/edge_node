import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from extensions.business.container_apps.reset import (
  RESET_REQUEST_FILE,
  RESET_RESPONSE_FILE,
  reset_dir,
)
from extensions.business.container_apps.tests.support import make_container_app_runner


class TestResetLifecycleIntegration(unittest.TestCase):

  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.plugin = make_container_app_runner()
    self.plugin.get_data_folder = lambda: str(self.tmpdir)
    self.plugin.cfg_reset = {"ENABLED": True}
    self.plugin.cfg_sync = {"ENABLED": False}
    self.plugin._sync_unavailable = False
    self.plugin._reset_unavailable = False
    self.plugin._reset_manager = None
    self.plugin.ee_id = "ee_test"

    self.data_root = (
      self.tmpdir
      / self.plugin._get_instance_data_subfolder()
      / "fixed_volumes"
      / "mounts"
      / "data"
    )
    self.data_root.mkdir(parents=True)
    self.plugin.cfg_fixed_size_volumes = {
      "data": {"SIZE": "10M", "MOUNTING_POINT": "/app/data"}
    }
    self.plugin._fixed_volumes = [
      SimpleNamespace(name="data", mount_path=self.data_root, owner_uid=None, owner_gid=None)
    ]
    reset_dir(self.plugin).mkdir(parents=True, exist_ok=True)

  def tearDown(self):
    self._tmp.cleanup()

  def test_periodic_checks_process_reset_inline_without_restart_container(self):
    lifecycle = []
    self.plugin._stop_container_runtime_for_restart = lambda: lifecycle.append("stop") or True
    self.plugin.start_container = lambda: lifecycle.append("start") or object()
    self.plugin._reset_runtime_state_post_start = lambda: lifecycle.append("reset-state")
    self.plugin._restart_container = lambda *_args, **_kwargs: lifecycle.append("restart-container")
    (self.data_root / "payload.txt").write_text("data", encoding="utf-8")
    (reset_dir(self.plugin) / RESET_REQUEST_FILE).write_text(
      json.dumps({
        "schema_version": 1,
        "request_id": "reset-inline",
        "mode": "volumes",
        "volumes": ["data"],
      }),
      encoding="utf-8",
    )

    result = self.plugin._perform_additional_checks(current_time=123.0)

    self.assertIsNone(result)
    self.assertEqual(lifecycle, ["stop", "start", "reset-state"])
    self.assertEqual(list(self.data_root.iterdir()), [])
    response = json.loads((reset_dir(self.plugin) / RESET_RESPONSE_FILE).read_text())
    self.assertEqual(response["status"], "ok")
    self.assertEqual(response["request_id"], "reset-inline")


if __name__ == "__main__":
  unittest.main()
