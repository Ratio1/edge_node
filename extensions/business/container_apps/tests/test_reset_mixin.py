import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from extensions.business.container_apps.reset import (
  RESET_INVALID_FILE,
  RESET_PROCESSING_FILE,
  RESET_REQUEST_FILE,
  RESET_RESPONSE_FILE,
  _ResetMixin,
  reset_dir,
)
from extensions.business.container_apps.reset.constants import RESET_SUBDIR
from extensions.business.container_apps.tests.test_reset_manager import _make_owner


class _FakePlugin(_ResetMixin):
  def __init__(self, owner_ns):
    self._delegate = owner_ns
    self.env = {}
    self._sync_unavailable = False
    self._reset_unavailable = False
    self._reset_manager = None
    self.stop_result = True
    self.start_result = True
    self.lifecycle_log = []
    self.messages = []
    self.ee_id = "ee_test"
    self.clock = 100.0

  def __getattr__(self, name):
    return getattr(self._delegate, name)

  def P(self, message, **kwargs):
    self.messages.append(str(message))

  def time(self):
    self.clock += 1.0
    return self.clock

  def _stop_container_runtime_for_restart(self):
    self.lifecycle_log.append("stop")
    return self.stop_result

  def start_container(self):
    self.lifecycle_log.append("start")
    return object() if self.start_result else None

  def _reset_runtime_state_post_start(self):
    self.lifecycle_log.append("reset-state")


def _make_plugin(tmpdir, *, enabled=True):
  owner = _make_owner(tmpdir)
  owner.cfg_reset = {"ENABLED": enabled}
  plugin = _FakePlugin(owner)
  reset_dir(plugin).mkdir(parents=True, exist_ok=True)
  return plugin, owner


class TestResetControlDirAndEnv(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)

  def tearDown(self):
    self._tmp.cleanup()

  def test_configure_control_dir_creates_reset_subdir(self):
    plugin, _ = _make_plugin(self.tmpdir)
    root = reset_dir(plugin)
    root.rmdir()

    with patch("extensions.business.container_apps.reset.mixin.os.chown"):
      plugin._configure_reset_control_dir()

    self.assertTrue(root.is_dir())
    self.assertFalse(plugin._reset_unavailable)

  def test_injects_reset_request_paths(self):
    plugin, _ = _make_plugin(self.tmpdir)

    plugin._inject_reset_env_vars()

    self.assertEqual(plugin.env["R1_RESET_DIR"], f"/r1en_system/{RESET_SUBDIR}")
    self.assertEqual(
      plugin.env["R1_RESET_REQUEST_FILE"],
      f"/r1en_system/{RESET_SUBDIR}/request.json",
    )
    self.assertEqual(
      plugin.env["R1_RESET_RESPONSE_FILE"],
      f"/r1en_system/{RESET_SUBDIR}/response.json",
    )

  def test_recovers_stale_processing(self):
    plugin, _ = _make_plugin(self.tmpdir)
    root = reset_dir(plugin)
    (root / RESET_PROCESSING_FILE).write_text(
      '{"schema_version":1,"mode":"volumes"}',
      encoding="utf-8",
    )

    plugin._recover_reset_processing()

    self.assertTrue((root / RESET_REQUEST_FILE).is_file())
    self.assertFalse((root / RESET_PROCESSING_FILE).exists())


class TestResetTick(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.plugin, self.owner = _make_plugin(self.tmpdir)
    self.root = reset_dir(self.plugin)
    self.data_root = Path(self.owner._fixed_volumes[0].mount_path)
    self.logs_root = Path(self.owner._fixed_volumes[1].mount_path)

  def tearDown(self):
    self._tmp.cleanup()

  def _write_request(self, body):
    (self.root / RESET_REQUEST_FILE).write_text(json.dumps(body), encoding="utf-8")

  def test_valid_request_stops_resets_starts_and_writes_response(self):
    (self.data_root / "payload.txt").write_text("data", encoding="utf-8")
    (self.logs_root / "keep.log").write_text("log", encoding="utf-8")
    self._write_request({
      "schema_version": 1,
      "request_id": "reset-001",
      "volumes": ["data"],
    })

    self.plugin._reset_tick(current_time=123.0)

    self.assertEqual(self.plugin.lifecycle_log, ["stop", "start", "reset-state"])
    self.assertEqual(list(self.data_root.iterdir()), [])
    self.assertTrue((self.logs_root / "keep.log").is_file())
    response = json.loads((self.root / RESET_RESPONSE_FILE).read_text())
    self.assertEqual(response["status"], "ok")
    self.assertEqual(response["request_id"], "reset-001")
    self.assertEqual(response["reset"]["volumes"], ["data"])
    self.assertTrue(response["reset"]["preserved"]["env_overrides"])
    self.assertFalse((self.root / RESET_PROCESSING_FILE).exists())

  def test_runtime_stop_failure_aborts_before_mutation(self):
    self.plugin.stop_result = False
    (self.data_root / "payload.txt").write_text("data", encoding="utf-8")
    self._write_request({
      "schema_version": 1,
      "request_id": "reset-stop-fail",
      "mode": "volumes",
      "volumes": ["data"],
    })

    self.plugin._reset_tick(current_time=123.0)

    self.assertEqual(self.plugin.lifecycle_log, ["stop"])
    self.assertTrue((self.data_root / "payload.txt").is_file())
    response = json.loads((self.root / RESET_RESPONSE_FILE).read_text())
    self.assertEqual(response["status"], "error")
    self.assertEqual(response["stage"], "runtime_stop")
    self.assertEqual(response["reset"]["status"], "skipped")

  def test_volume_reset_failure_does_not_restart_container(self):
    manager = self.plugin._ensure_reset_manager()
    (self.data_root / "payload.txt").write_text("data", encoding="utf-8")
    self._write_request({
      "schema_version": 1,
      "request_id": "reset-volume-fail",
      "mode": "volumes",
      "volumes": ["data"],
    })

    with patch.object(manager, "reset_volumes", side_effect=RuntimeError("clear failed")):
      self.plugin._reset_tick(current_time=123.0)

    self.assertEqual(self.plugin.lifecycle_log, ["stop"])
    self.assertTrue((self.data_root / "payload.txt").is_file())
    response = json.loads((self.root / RESET_RESPONSE_FILE).read_text())
    self.assertEqual(response["status"], "error")
    self.assertEqual(response["stage"], "volume_reset")
    self.assertEqual(response["reset"]["status"], "error")
    self.assertEqual(response["restart"]["started"], False)
    self.assertFalse((self.root / RESET_PROCESSING_FILE).exists())

  def test_invalid_request_writes_invalid_and_does_not_restart_or_mutate(self):
    (self.data_root / "payload.txt").write_text("data", encoding="utf-8")
    self._write_request({
      "schema_version": 1,
      "request_id": "reset-bad",
      "mode": "volumes",
      "volumes": ["/app/data"],
    })

    self.plugin._reset_tick(current_time=123.0)

    self.assertEqual(self.plugin.lifecycle_log, [])
    self.assertTrue((self.data_root / "payload.txt").is_file())
    invalid = json.loads((self.root / RESET_INVALID_FILE).read_text())
    response = json.loads((self.root / RESET_RESPONSE_FILE).read_text())
    self.assertEqual(invalid["_error"]["stage"], "validation")
    self.assertEqual(invalid["_error"]["request_id"], "reset-bad")
    self.assertEqual(response["status"], "error")
    self.assertEqual(response["request_id"], "reset-bad")

  def test_unsupported_request_field_writes_invalid_and_does_not_restart(self):
    (self.data_root / "payload.txt").write_text("data", encoding="utf-8")
    self._write_request({
      "schema_version": 1,
      "request_id": "reset-clear-all",
      "clear_all": True,
    })

    self.plugin._reset_tick(current_time=123.0)

    self.assertEqual(self.plugin.lifecycle_log, [])
    self.assertTrue((self.data_root / "payload.txt").is_file())
    response = json.loads((self.root / RESET_RESPONSE_FILE).read_text())
    self.assertEqual(response["status"], "error")
    self.assertEqual(response["request_id"], "reset-clear-all")
    self.assertIn("unsupported request field", response["error"])

  def test_env_override_state_is_outside_reset_scope(self):
    plugin_data = (
      Path(self.owner.get_data_folder())
      / self.owner._get_instance_data_subfolder()
      / "plugin_data"
    )
    plugin_data.mkdir(parents=True)
    env_state = plugin_data / "env_overrides.json"
    env_state.write_text('{"LOG_LEVEL":"trace"}', encoding="utf-8")
    (self.data_root / "payload.txt").write_text("data", encoding="utf-8")
    self._write_request({
      "schema_version": 1,
      "mode": "volumes",
      "volumes": ["data"],
    })

    self.plugin._reset_tick(current_time=123.0)

    self.assertEqual(env_state.read_text(encoding="utf-8"), '{"LOG_LEVEL":"trace"}')
    self.assertEqual(list(self.data_root.iterdir()), [])


if __name__ == "__main__":
  unittest.main()
