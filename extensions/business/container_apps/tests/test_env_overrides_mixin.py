import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from extensions.business.container_apps.env_overrides import (
  ENV_OVERRIDES_INVALID_FILE,
  ENV_OVERRIDES_PROCESSING_FILE,
  ENV_OVERRIDES_REQUEST_FILE,
  ENV_OVERRIDES_RESPONSE_FILE,
  _EnvOverridesMixin,
  env_overrides_dir,
)
from extensions.business.container_apps.env_overrides.constants import (
  ENV_OVERRIDES_STATE_FILE,
)
from extensions.business.container_apps.tests.test_sync_manager import _make_owner


class _FakePlugin(_EnvOverridesMixin):
  def __init__(self, owner_ns):
    self._delegate = owner_ns
    self.env = {}
    self._sync_unavailable = False
    self._env_overrides_unavailable = False
    self._env_overrides_manager = None

  def __getattr__(self, name):
    return getattr(self._delegate, name)


def _make_plugin(tmpdir, *, enabled=True):
  owner = _make_owner(tmpdir)
  owner.cfg_env_overrides = {"ENABLED": enabled}
  plugin = _FakePlugin(owner)
  env_overrides_dir(plugin).mkdir(parents=True, exist_ok=True)
  return plugin, owner


class TestEnvOverrideConfigAndEnv(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)

  def tearDown(self):
    self._tmp.cleanup()

  def test_enabled_defaults_to_true_when_config_is_absent(self):
    plugin, owner = _make_plugin(self.tmpdir)
    del owner.cfg_env_overrides

    self.assertTrue(plugin._env_overrides_enabled())

  def test_disabled_config_blocks_manager_and_env_vars(self):
    plugin, _ = _make_plugin(self.tmpdir, enabled=False)

    self.assertFalse(plugin._env_overrides_enabled())
    self.assertIsNone(plugin._ensure_env_overrides_manager())
    plugin._inject_env_overrides_env_vars()
    self.assertEqual(plugin.env, {})

  def test_injects_request_and_response_paths_when_available(self):
    plugin, _ = _make_plugin(self.tmpdir)

    plugin._inject_env_overrides_env_vars()

    self.assertEqual(plugin.env["R1_ENV_OVERRIDES_DIR"], "/r1en_system/env-overrides")
    self.assertEqual(
      plugin.env["R1_ENV_OVERRIDES_REQUEST_FILE"],
      "/r1en_system/env-overrides/request.json",
    )
    self.assertEqual(
      plugin.env["R1_ENV_OVERRIDES_RESPONSE_FILE"],
      "/r1en_system/env-overrides/response.json",
    )

  def test_sync_unavailable_blocks_control_paths_but_not_state_overlay(self):
    plugin, _ = _make_plugin(self.tmpdir)
    manager = plugin._ensure_env_overrides_manager()
    manager.apply_patch({"schema_version": 1, "set": {"LOG_LEVEL": "trace"}})
    plugin._sync_unavailable = True

    plugin._inject_env_overrides_env_vars()
    plugin.env = {"LOG_LEVEL": "info"}
    plugin._apply_env_overrides_to_env()

    self.assertNotIn("R1_ENV_OVERRIDES_REQUEST_FILE", plugin.env)
    self.assertEqual(plugin.env["LOG_LEVEL"], "trace")


class TestEnvOverrideControlDir(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)

  def tearDown(self):
    self._tmp.cleanup()

  def test_configure_control_dir_creates_sticky_app_writable_dir(self):
    plugin, _ = _make_plugin(self.tmpdir)
    eod = env_overrides_dir(plugin)
    eod.rmdir()

    with patch(
      "extensions.business.container_apps.env_overrides.mixin.os.chown",
    ):
      plugin._configure_env_overrides_control_dir()

    self.assertFalse(plugin._env_overrides_unavailable)
    self.assertTrue(eod.is_dir())
    self.assertEqual(os.stat(eod).st_mode & 0o777, 0o777)
    self.assertEqual(os.stat(eod).st_mode & 0o1000, 0o1000)

  def test_configure_control_dir_recreates_symlink(self):
    plugin, _ = _make_plugin(self.tmpdir)
    eod = env_overrides_dir(plugin)
    eod.rmdir()
    outside = self.tmpdir / "outside"
    outside.mkdir()
    os.symlink(str(outside), str(eod))

    with patch(
      "extensions.business.container_apps.env_overrides.mixin.os.chown",
    ):
      plugin._configure_env_overrides_control_dir()

    self.assertTrue(eod.is_dir())
    self.assertFalse(eod.is_symlink())
    self.assertFalse(plugin._env_overrides_unavailable)

  def test_recover_stale_processing_renames_back_to_request(self):
    plugin, _ = _make_plugin(self.tmpdir)
    eod = env_overrides_dir(plugin)
    (eod / ENV_OVERRIDES_PROCESSING_FILE).write_text(
      '{"schema_version":1,"set":{"LOG_LEVEL":"trace"}}',
      encoding="utf-8",
    )

    plugin._recover_env_overrides_processing()

    self.assertTrue((eod / ENV_OVERRIDES_REQUEST_FILE).is_file())
    self.assertFalse((eod / ENV_OVERRIDES_PROCESSING_FILE).exists())


class TestEnvOverrideTick(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.plugin, self.owner = _make_plugin(self.tmpdir)
    self.eod = env_overrides_dir(self.plugin)

  def tearDown(self):
    self._tmp.cleanup()

  def _write_request(self, body):
    (self.eod / ENV_OVERRIDES_REQUEST_FILE).write_text(json.dumps(body), encoding="utf-8")

  def _state_path(self):
    return (
      Path(self.owner.get_data_folder())
      / self.owner._get_instance_data_subfolder()
      / "plugin_data"
      / ENV_OVERRIDES_STATE_FILE
    )

  def test_no_request_no_action(self):
    self.assertFalse(self.plugin._env_overrides_tick(current_time=100.0))

  def test_next_restart_request_persists_state_and_writes_response(self):
    self._write_request({
      "schema_version": 1,
      "request_id": "env-001",
      "set": {"LOG_LEVEL": "trace"},
    })

    restart = self.plugin._env_overrides_tick(current_time=100.0)

    self.assertFalse(restart)
    self.assertFalse((self.eod / ENV_OVERRIDES_PROCESSING_FILE).exists())
    response = json.loads((self.eod / ENV_OVERRIDES_RESPONSE_FILE).read_text())
    self.assertEqual(response["status"], "ok")
    self.assertEqual(response["request_id"], "env-001")
    self.assertEqual(response["restart"]["deferred"], True)
    self.assertEqual(json.loads(self._state_path().read_text()), {"LOG_LEVEL": "trace"})

  def test_restart_now_request_returns_restart_after_response_is_written(self):
    self._write_request({
      "schema_version": 1,
      "apply": "restart_now",
      "set": {"LOG_LEVEL": "trace"},
    })

    restart = self.plugin._env_overrides_tick(current_time=100.0)

    self.assertTrue(restart)
    response = json.loads((self.eod / ENV_OVERRIDES_RESPONSE_FILE).read_text())
    self.assertEqual(response["restart"]["requested"], True)
    self.assertEqual(response["restart"]["deferred"], False)

  def test_invalid_request_writes_invalid_and_response_without_persisting(self):
    self._write_request({
      "schema_version": 1,
      "request_id": "env-bad",
      "set": {"R1EN_FORBIDDEN": "x"},
    })

    restart = self.plugin._env_overrides_tick(current_time=100.0)

    self.assertFalse(restart)
    self.assertFalse((self.eod / ENV_OVERRIDES_PROCESSING_FILE).exists())
    self.assertFalse(self._state_path().exists())
    invalid = json.loads((self.eod / ENV_OVERRIDES_INVALID_FILE).read_text())
    response = json.loads((self.eod / ENV_OVERRIDES_RESPONSE_FILE).read_text())
    self.assertEqual(invalid["_error"]["stage"], "validation")
    self.assertEqual(invalid["_error"]["request_id"], "env-bad")
    self.assertEqual(response["status"], "error")
    self.assertEqual(response["request_id"], "env-bad")

  def test_malformed_json_writes_raw_body_diagnostic(self):
    (self.eod / ENV_OVERRIDES_REQUEST_FILE).write_text("{not-json", encoding="utf-8")

    restart = self.plugin._env_overrides_tick(current_time=100.0)

    self.assertFalse(restart)
    invalid = json.loads((self.eod / ENV_OVERRIDES_INVALID_FILE).read_text())
    response = json.loads((self.eod / ENV_OVERRIDES_RESPONSE_FILE).read_text())
    self.assertIsNone(invalid["request"])
    self.assertIn("raw_body", invalid["_error"])
    self.assertEqual(response["status"], "error")


if __name__ == "__main__":
  unittest.main()
