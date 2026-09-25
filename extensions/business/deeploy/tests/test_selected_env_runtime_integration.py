import copy
import unittest

from naeural_core.config.runtime_secret_resolution import (
  RuntimeSecretResolutionError,
  build_capture_pipeline_config,
  build_runtime_pipeline_config,
  get_dauth_pipeline_identity,
  overlay_canonical_secret_references,
)

from extensions.business.container_apps.container_utils import _ContainerUtilsMixin
from extensions.business.deeploy.deeploy_mixin import DEEPLOY_DAUTH_SECRET_PLACEHOLDER
from extensions.business.deeploy.tests.support import make_deeploy_plugin


class _DynamicEnvRunner(_ContainerUtilsMixin):
  def __init__(self, instance):
    self.cfg_dynamic_env = instance["DYNAMIC_ENV"]
    self.dynamic_env = {}
    self.messages = []

  def semaphore_get_env_value(self, semaphore, key):
    return {("database", "CONTAINER_IP"): "10.0.0.9"}[(semaphore, key)]

  def P(self, message, **kwargs):
    self.messages.append(message)


def _pipeline():
  return {
    "NAME": "selected-env",
    "DEEPLOY_SPECS": {"job_id": "7", "date_updated": 1},
    "PLUGINS": [{
      "SIGNATURE": "CONTAINER_APP_RUNNER",
      "INSTANCES": [{
        "INSTANCE_ID": "consumer",
        "SECRET_PATHS": [["ENV", "CUSTOM_VALUE"], ["DYNAMIC_ENV", "CONNECTION"]],
        "ENV": {"CUSTOM_VALUE": "custom-private", "PUBLIC": "visible"},
        "DYNAMIC_ENV": {"CONNECTION": [
          {"type": "static", "value": "private-prefix@"},
          {"type": "shmem", "path": ["database", "CONTAINER_IP"]},
          {"type": "static", "value": ""},
        ]},
      }],
    }],
  }


class SelectedEnvRuntimeIntegrationTests(unittest.TestCase):
  def setUp(self):
    self.plugin = make_deeploy_plugin()
    self.canonical, self.secrets = self.plugin._extract_and_redact_deeploy_dauth_secrets(
      _pipeline(),
    )

  def test_selected_values_restore_before_dynamic_env_assembly(self):
    canonical_before = copy.deepcopy(self.canonical)
    instance = self.canonical["PLUGINS"][0]["INSTANCES"][0]
    self.assertEqual(instance["ENV"]["CUSTOM_VALUE"], DEEPLOY_DAUTH_SECRET_PLACEHOLDER)
    self.assertEqual(
      [part.get("value") for part in instance["DYNAMIC_ENV"]["CONNECTION"]],
      [DEEPLOY_DAUTH_SECRET_PLACEHOLDER, None, DEEPLOY_DAUTH_SECRET_PLACEHOLDER],
    )

    runtime = build_runtime_pipeline_config(
      self.canonical, secret_plugins=self.secrets["PLUGINS"], environment={},
    )
    runtime_instance = runtime["PLUGINS"][0]["INSTANCES"][0]
    self.assertEqual(runtime_instance["ENV"]["CUSTOM_VALUE"], "custom-private")
    self.assertEqual(runtime_instance["ENV"]["PUBLIC"], "visible")
    runner = _DynamicEnvRunner(runtime_instance)
    runner._configure_dynamic_env()
    self.assertEqual(runner.dynamic_env["CONNECTION"], "private-prefix@10.0.0.9")
    self.assertNotIn("private-prefix", str(runner.messages))
    self.assertEqual(self.canonical, canonical_before)

  def test_capture_and_persistence_views_keep_selected_values_redacted(self):
    runtime = build_runtime_pipeline_config(
      self.canonical, secret_plugins=self.secrets["PLUGINS"], environment={},
    )
    capture = build_capture_pipeline_config(self.canonical, environment={})
    self.assertEqual(capture["PLUGINS"], self.canonical["PLUGINS"])
    restored = overlay_canonical_secret_references(runtime, self.canonical)
    self.assertEqual(restored, self.canonical)
    self.assertNotIn("custom-private", str(restored))
    self.assertNotIn("private-prefix", str(restored))

  def test_missing_selected_static_part_fails_closed(self):
    secrets = copy.deepcopy(self.secrets)
    secrets["PLUGINS"][0]["INSTANCES"][0]["DYNAMIC_ENV"]["CONNECTION"][2] = None
    with self.assertRaises(RuntimeSecretResolutionError):
      build_runtime_pipeline_config(
        self.canonical, secret_plugins=secrets["PLUGINS"], environment={},
      )

  def test_per_node_selected_values_restore_at_their_exact_paths(self):
    pipeline = _pipeline()
    instance = pipeline["PLUGINS"][0]["INSTANCES"][0]
    instance["PER_NODE_CONFIG"] = {"byNode": {
      "node-a": {"ENV": {"CUSTOM_VALUE": "node-a-private"}},
      "node-b": {"ENV": {"CUSTOM_VALUE": "node-b-private"}},
    }}
    instance["SECRET_PATHS"].extend([
      ["PER_NODE_CONFIG", "byNode", node, "ENV", "CUSTOM_VALUE"]
      for node in ("node-a", "node-b")
    ])
    canonical, secrets = self.plugin._extract_and_redact_deeploy_dauth_secrets(pipeline)
    runtime = build_runtime_pipeline_config(canonical, secret_plugins=secrets["PLUGINS"], environment={})
    self.assertEqual(runtime, pipeline)
    self.assertNotIn("node-a-private", str(canonical))
    self.assertNotIn("node-b-private", str(canonical))
    self.assertEqual(overlay_canonical_secret_references(runtime, canonical), canonical)

  def test_selection_changes_invalidate_the_runtime_cache_identity(self):
    updated = copy.deepcopy(self.canonical)
    updated["PLUGINS"][0]["INSTANCES"][0]["SECRET_PATHS"].append(["ENV", "PUBLIC"])
    self.assertNotEqual(
      get_dauth_pipeline_identity("selected-env", self.canonical),
      get_dauth_pipeline_identity("selected-env", updated),
    )


if __name__ == "__main__":
  unittest.main()
