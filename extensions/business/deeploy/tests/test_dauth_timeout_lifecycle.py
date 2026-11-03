"""Shared staging primitives retained for scale-up dispatch.

Create/update timeout and recovery behavior is covered by durable operation
barrier tests in test_deployment_operations, not the retired HTTP finalizer.
"""
import copy
import unittest
from unittest.mock import patch

from extensions.business.deeploy.tests.test_secret_staging import (
  _SecretStagingPlugin, _pipeline,
)


class _LifecyclePlugin(_SecretStagingPlugin):
  def __init__(self):
    super().__init__()
    self.worker_configs = {}


class DeeployDauthTimeoutLifecycleTests(unittest.TestCase):
  def test_partial_create_dispatch_keeps_staged_metadata(self):
    plugin = _LifecyclePlugin()
    state = plugin.stage_job_pipeline_and_secrets(
      _pipeline(), 116, {"job_id": "116", "job_secrets": {"PLUGINS": []}}
    )
    state["retain_on_failed_dispatch"] = True

    def dispatch(_plugin, node, config):
      if node == "node-b":
        raise RuntimeError("command unavailable")
      plugin.worker_configs[node] = copy.deepcopy(config)

    with patch("extensions.business.deeploy.deeploy_mixin.dispatch_pipeline_config", dispatch):
      with self.assertRaisesRegex(RuntimeError, "command unavailable"):
        plugin._DeeployMixin__create_pipeline_on_nodes(
          nodes=["node-a", "node-b"],
          inputs={},
          app_id="app",
          app_alias="app",
          app_type="void",
          owner="owner",
          prepared_deploy_plan={"enable_chainstore_response": False},
          prepared_pipeline_configs={"node-a": _pipeline(), "node-b": _pipeline()},
          dispatch_state=state,
        )

    self.assertTrue(state["dispatch_attempted"])
    self.assertIn("node-a", plugin.worker_configs)
    self.assertTrue(plugin.settle_failed_staged_job_pipeline_and_secrets(
      state, "dispatch error"
    ))
    self.assertEqual(plugin._get_pipeline_from_cstore(116), state["staged_cid"])

  def test_pre_dispatch_create_failure_removes_staged_metadata(self):
    plugin = _LifecyclePlugin()
    state = plugin.stage_job_pipeline_and_secrets(
      _pipeline(), 116, {"job_id": "116", "job_secrets": {"PLUGINS": []}}
    )
    state["retain_on_failed_dispatch"] = True

    self.assertTrue(plugin.settle_failed_staged_job_pipeline_and_secrets(
      state, "validation error"
    ))
    self.assertIsNone(plugin._get_pipeline_from_cstore(116))
    self.assertIsNone(plugin._load_dauth_job_secret_bundle(116))
    self.assertNotIn("dispatch_uncertain", state)
    self.assertIn("staged-cid", [event[1] for event in plugin.events if event[0] == "r1fs_delete"])


if __name__ == "__main__":
  unittest.main()
