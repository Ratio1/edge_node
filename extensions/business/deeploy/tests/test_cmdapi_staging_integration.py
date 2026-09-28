import importlib.util
import unittest
from pathlib import Path

from naeural_core import constants as core_constants

from extensions.business.deeploy.deeploy_cmdapi_integration import (
  build_pipeline_config,
  dispatch_pipeline_config,
)
from extensions.business.deeploy.tests.support import make_deeploy_plugin


class _CmdApiPluginStub:
  def __init__(self):
    self.built = []
    self.dispatched = []

  def cmdapi_build_pipeline_config(self, **kwargs):
    self.built.append(kwargs)
    return {
      "NAME": kwargs["name"],
      "TYPE": kwargs["stream_type"],
      "PLUGINS": kwargs["plugins"],
    }

  def cmdapi_start_pipeline(self, config, node_address=None):
    self.dispatched.append((node_address, config))


class CmdApiStagingIntegrationTests(unittest.TestCase):
  def test_installed_core_exposes_required_pure_builder(self):
    cmdapi_path = Path(core_constants.__file__).resolve().parent / "business" / "mixins_base" / "cmdapi.py"
    spec = importlib.util.spec_from_file_location("edge_test_core_cmdapi", cmdapi_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    self.assertTrue(callable(getattr(module._CmdAPIMixin, "cmdapi_build_pipeline_config", None)))

  def test_pure_builder_does_not_dispatch_before_explicit_send(self):
    plugin = _CmdApiPluginStub()

    pipeline = build_pipeline_config(
      plugin,
      name="app",
      stream_type="void",
      plugins=[{"SIGNATURE": "A", "INSTANCES": []}],
    )

    self.assertEqual(len(plugin.built), 1)
    self.assertEqual(plugin.dispatched, [])
    dispatch_pipeline_config(plugin, "node-a", pipeline)
    self.assertEqual(plugin.dispatched, [("node-a", pipeline)])

  def test_scale_up_base_pipeline_comes_from_r1fs_metadata(self):
    plugin = make_deeploy_plugin()
    plugin.get_job_pipeline_from_cstore = lambda job_id: {
      "NAME": "app",
      "TYPE": "void",
      "URL": "https://example.invalid/input",
      "OWNER": "0xowner",
      "PLUGINS": [{"SIGNATURE": "A", "INSTANCES": []}],
      "DEEPLOY_SPECS": {
        "job_id": job_id,
        "current_target_nodes": ["node-a"],
      },
    }
    plugin._get_pipeline_params_from_deeploy_specs = lambda specs: {"CUSTOM": 1}

    base = plugin.get_job_base_pipeline_from_r1fs(7)

    self.assertEqual(base["app_id"], "app")
    self.assertEqual(base["plugins"][0]["SIGNATURE"], "A")
    self.assertEqual(base["pipeline_params"], {"CUSTOM": 1})

  def test_scale_up_base_rejects_mismatched_job_owner_and_running_app(self):
    plugin = make_deeploy_plugin()
    plugin.get_job_pipeline_from_cstore = lambda job_id: {
      "NAME": "persisted-app",
      "TYPE": "void",
      "OWNER": "0xowner",
      "PLUGINS": [],
      "DEEPLOY_SPECS": {
        "job_id": "7",
        "current_target_nodes": ["node-a"],
      },
    }
    plugin._get_pipeline_params_from_deeploy_specs = lambda specs: {}

    with self.assertRaisesRegex(ValueError, "job ID"):
      plugin.get_job_base_pipeline_from_r1fs(8)
    with self.assertRaisesRegex(ValueError, "owner"):
      plugin.get_job_base_pipeline_from_r1fs(7, owner="0xother")
    with self.assertRaisesRegex(ValueError, "app ID"):
      plugin.get_job_base_pipeline_from_r1fs(
        7,
        owner="0xowner",
        expected_nodes=["node-a"],
        running_apps_for_job={"node-a": {"different-app": {}}},
      )


if __name__ == "__main__":
  unittest.main()
