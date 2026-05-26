import json
import tempfile
import unittest
from pathlib import Path

from extensions.business.container_apps.env_overrides.constants import (
  APPLY_NEXT_RESTART,
  APPLY_RESTART_NOW,
  ENV_OVERRIDES_MAX_BYTES,
  ENV_OVERRIDES_STATE_FILE,
)
from extensions.business.container_apps.env_overrides.manager import (
  EnvOverrideManager,
  EnvOverrideValidationError,
)


class _Owner:
  def __init__(self, root):
    self.root = Path(root)
    self.messages = []

  def get_data_folder(self):
    return str(self.root)

  def _get_instance_data_subfolder(self):
    return "pipelines_data/test_stream/car_instance"

  def P(self, message, **kwargs):
    self.messages.append(str(message))


class _DiskApiOwner(_Owner):
  def __init__(self, root):
    super().__init__(root)
    self.load_calls = []
    self.save_calls = []

  def diskapi_load_json_from_data(self, filename, subfolder=None, verbose=True):
    self.load_calls.append({
      "filename": filename,
      "subfolder": subfolder,
      "verbose": verbose,
    })
    if subfolder != "plugin_data":
      flat_path = self.root / filename
      if flat_path.exists():
        with open(flat_path, "r", encoding="utf-8") as handle:
          return json.load(handle)
      return None

    path = (
      self.root
      / self._get_instance_data_subfolder()
      / "plugin_data"
      / filename
    )
    if not path.exists():
      return None
    with open(path, "r", encoding="utf-8") as handle:
      return json.load(handle)

  def diskapi_save_json_to_data(self, dct, filename, subfolder=None, indent=True):
    self.save_calls.append({
      "filename": filename,
      "subfolder": subfolder,
      "indent": indent,
    })
    path = (
      self.root
      / self._get_instance_data_subfolder()
      / (subfolder or "plugin_data")
      / filename
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
      json.dump(dct, handle, indent=2 if indent else None)


class TestEnvOverrideManager(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.owner = _Owner(self.tmp.name)
    self.manager = EnvOverrideManager(self.owner)

  def tearDown(self):
    self.tmp.cleanup()

  def _state_path(self):
    return (
      Path(self.tmp.name)
      / "pipelines_data/test_stream/car_instance/plugin_data"
      / ENV_OVERRIDES_STATE_FILE
    )

  def _read_state(self):
    with open(self._state_path(), "r", encoding="utf-8") as handle:
      return json.load(handle)

  def test_apply_patch_normalizes_supported_value_types(self):
    result = self.manager.apply_patch({
      "schema_version": 1,
      "request_id": "env-001",
      "apply": APPLY_NEXT_RESTART,
      "set": {
        "LOG_LEVEL": "trace",
        "RETRIES": 3,
        "ENABLED": True,
        "RATIO": 1.5,
        "FLAGS": ["fast", 2],
        "CONFIG": {"b": 2, "a": 1},
      },
    })

    self.assertEqual(result.request_id, "env-001")
    self.assertFalse(result.restart_requested)
    self.assertEqual(result.active_count, 6)
    self.assertEqual(result.set_keys, (
      "CONFIG", "ENABLED", "FLAGS", "LOG_LEVEL", "RATIO", "RETRIES",
    ))
    self.assertEqual(self._read_state(), {
      "LOG_LEVEL": "trace",
      "RETRIES": "3",
      "ENABLED": "true",
      "RATIO": "1.5",
      "FLAGS": '["fast",2]',
      "CONFIG": '{"a":1,"b":2}',
    })

    response = result.to_response()
    self.assertEqual(response["status"], "ok")
    self.assertEqual(response["request_id"], "env-001")
    self.assertEqual(response["restart"]["requested"], False)
    self.assertEqual(response["restart"]["deferred"], True)
    self.assertEqual(response["overrides"]["active_count"], 6)

  def test_remove_deletes_only_existing_local_override(self):
    self.manager.apply_patch({
      "schema_version": 1,
      "set": {
        "LOG_LEVEL": "trace",
        "EXTRA_FLAG": "1",
      },
    })

    result = self.manager.apply_patch({
      "schema_version": 1,
      "apply": APPLY_RESTART_NOW,
      "remove": ["LOG_LEVEL", "CONFIG_DEFINED_VAR"],
    })

    self.assertTrue(result.restart_requested)
    self.assertEqual(result.removed_keys, ("LOG_LEVEL",))
    self.assertEqual(result.active_count, 1)
    self.assertEqual(self._read_state(), {"EXTRA_FLAG": "1"})
    self.assertEqual(result.to_response()["restart"]["scheduled"], True)
    self.assertEqual(result.to_response()["restart"]["deferred"], False)

  def test_apply_to_env_uses_local_overrides_as_final_precedence(self):
    self.manager.apply_patch({
      "schema_version": 1,
      "set": {
        "LOG_LEVEL": "trace",
        "EXTRA_FLAG": 7,
      },
    })

    env = {"LOG_LEVEL": "info", "BASE_ONLY": "yes"}
    returned = self.manager.apply_to_env(env)

    self.assertIs(returned, env)
    self.assertEqual(env, {
      "LOG_LEVEL": "trace",
      "BASE_ONLY": "yes",
      "EXTRA_FLAG": "7",
    })

  def test_repeat_request_is_processed_again_without_idempotency_tracking(self):
    request = {
      "schema_version": 1,
      "request_id": "repeat-me",
      "set": {"LOG_LEVEL": "trace"},
    }

    first = self.manager.apply_patch(request)
    second = self.manager.apply_patch(request)

    self.assertEqual(first.request_id, "repeat-me")
    self.assertEqual(second.request_id, "repeat-me")
    self.assertEqual(second.set_keys, ("LOG_LEVEL",))
    self.assertEqual(self._read_state(), {"LOG_LEVEL": "trace"})

  def test_invalid_requests_are_rejected_without_persisting_state(self):
    cases = [
      ({"schema_version": 2}, "schema_version"),
      ({"schema_version": 1, "apply": "later"}, "apply"),
      ({"schema_version": 1, "set": []}, "set"),
      ({"schema_version": 1, "remove": {}}, "remove"),
      ({"schema_version": 1, "set": {"BAD-NAME": "x"}}, "invalid environment"),
      ({"schema_version": 1, "set": {"R1EN_SECRET": "x"}}, "reserved"),
      ({"schema_version": 1, "set": {"HOST": "x"}}, "reserved"),
      ({"schema_version": 1, "set": {"VALUE": None}}, "null"),
      ({"schema_version": 1, "set": {"VALUE": object()}}, "unsupported"),
      ({"schema_version": 1, "set": {"VALUE": "x"}, "remove": ["VALUE"]}, "both"),
      ({"schema_version": 1, "request_id": 123}, "request_id"),
    ]

    for request, message in cases:
      with self.subTest(message=message):
        with self.assertRaisesRegex(EnvOverrideValidationError, message):
          self.manager.apply_patch(request)

    self.assertFalse(self._state_path().exists())

  def test_request_and_resulting_state_are_size_limited(self):
    request = {"schema_version": 1, "set": {"LOG_LEVEL": "trace"}}

    with self.assertRaisesRegex(EnvOverrideValidationError, "request body exceeds"):
      self.manager.apply_patch(request, raw_body="x" * (ENV_OVERRIDES_MAX_BYTES + 1))

    with self.assertRaisesRegex(EnvOverrideValidationError, "persisted env override state"):
      self.manager.apply_patch({
        "schema_version": 1,
        "set": {"LARGE_VALUE": "x" * ENV_OVERRIDES_MAX_BYTES},
      })

    self.assertFalse(self._state_path().exists())

  def test_malformed_state_is_ignored(self):
    self._state_path().parent.mkdir(parents=True, exist_ok=True)
    with open(self._state_path(), "w", encoding="utf-8") as handle:
      json.dump(["not", "an", "object"], handle)

    self.assertEqual(self.manager.load_overrides(), {})

  def test_diskapi_load_uses_plugin_data_without_flat_fallback(self):
    owner = _DiskApiOwner(self.tmp.name)
    manager = EnvOverrideManager(owner)
    flat_state = Path(self.tmp.name) / ENV_OVERRIDES_STATE_FILE
    with open(flat_state, "w", encoding="utf-8") as handle:
      json.dump({"LOG_LEVEL": "flat"}, handle)

    self.assertEqual(manager.load_overrides(), {})
    self.assertEqual(owner.load_calls, [{
      "filename": ENV_OVERRIDES_STATE_FILE,
      "subfolder": "plugin_data",
      "verbose": False,
    }])

  def test_diskapi_save_targets_plugin_data_explicitly(self):
    owner = _DiskApiOwner(self.tmp.name)
    manager = EnvOverrideManager(owner)

    manager.save_overrides({"LOG_LEVEL": "trace"})

    self.assertEqual(owner.save_calls, [{
      "filename": ENV_OVERRIDES_STATE_FILE,
      "subfolder": "plugin_data",
      "indent": True,
    }])
    state_path = (
      Path(self.tmp.name)
      / owner._get_instance_data_subfolder()
      / "plugin_data"
      / ENV_OVERRIDES_STATE_FILE
    )
    with open(state_path, "r", encoding="utf-8") as handle:
      self.assertEqual(json.load(handle), {"LOG_LEVEL": "trace"})


if __name__ == "__main__":
  unittest.main()
