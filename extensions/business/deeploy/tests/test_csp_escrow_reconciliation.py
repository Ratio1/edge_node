import copy
import unittest
from collections import defaultdict

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS
from extensions.business.deeploy.tests.support import InputsStub, make_deeploy_plugin


class DeeployCspEscrowReconciliationTests(unittest.TestCase):
  """
  Unit tests for CSP escrow owner reconciliation helpers.
  """

  def setUp(self):
    self.plugin = make_deeploy_plugin()
    self.plugin.NestedDotDict = InputsStub
    self.plugin.defaultdict = defaultdict
    self.plugin.time = lambda: 1_000.0
    self.persisted = []
    self.deleted = []
    self.deploy_calls = []

    def persist_job_pipeline_metadata(pipeline, job_id, previous_cid=None, delete_previous=False):
      self.persisted.append({
        "pipeline": pipeline,
        "job_id": job_id,
        "previous_cid": previous_cid,
        "delete_previous": delete_previous,
      })
      return True

    def delete_pipeline_from_nodes(**kwargs):
      self.deleted.append(kwargs)
      return kwargs.get("discovered_instances", [])

    def check_and_deploy_pipelines(**kwargs):
      self.deploy_calls.append(kwargs)
      pipeline = copy.deepcopy(kwargs["inputs"]["_source_pipeline"])
      pipeline["OWNER"] = kwargs["owner"]
      return {}, "pending", {}, pipeline

    self.plugin.persist_job_pipeline_metadata = persist_job_pipeline_metadata
    self.plugin.delete_pipeline_from_nodes = delete_pipeline_from_nodes
    self.plugin.check_and_deploy_pipelines = check_and_deploy_pipelines

  def _pipeline(self, owner="0xOld"):
    """
    Build a persisted pipeline payload for reconciliation tests.
    """
    return {
      "NAME": "app1",
      "APP_ALIAS": "App One",
      "TYPE": "void",
      "OWNER": owner,
      "DEEPLOY_SPECS": {
        "job_id": 10,
        "current_target_nodes": ["node1"],
        "date_created": 900,
        "date_updated": 900,
        "job_tags": [],
        "spare_nodes": [],
        "allow_replication_in_the_wild": False,
        "chainstore_response_keys": {"node1": ["resp1"]},
      },
      "PLUGINS": [
        {
          "SIGNATURE": "CONTAINER_APP_RUNNER",
          "INSTANCES": [
            {
              "INSTANCE_ID": "inst1",
              "IMAGE": "repo/app:latest",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "512m"},
              "CHAINSTORE_RESPONSE_KEY": "resp1",
            }
          ],
        }
      ],
    }

  def _install_pipeline(self, pipeline):
    """
    Configure CStore/R1FS stubs for a stored job pipeline.
    """
    self.plugin._get_pipeline_from_cstore = lambda job_id: "cid-10"
    self.plugin.get_pipeline_from_r1fs = lambda *args, **kwargs: pipeline

  def test_reconcile_updates_persisted_pipeline_and_restarts_stale_node_owner(self):
    """
    Reconciliation rewrites metadata and restarts stale live nodes with the new owner.
    """
    self._install_pipeline(self._pipeline(owner="0xOld"))
    online_calls = []

    def get_online_apps(job_id=None, owner=None, target_nodes=None, project_id=None):
      online_calls.append({"job_id": job_id, "owner": owner, "target_nodes": target_nodes})
      return {"node1": {"app1": {"owner": "0xOld", "deeploy_specs": {"job_id": 10}}}}

    def discover_plugin_instances(app_id=None, job_id=None, target_nodes=None, owner=None, **kwargs):
      self.assertIsNone(owner)
      return [{
        "app_id": "app1",
        "instance_id": "inst1",
        "plugin_signature": "CONTAINER_APP_RUNNER",
        "plugin_instance": {"instance_conf": {"IMAGE": "repo/app:latest"}},
        "NODE": "node1",
        "CHAINSTORE_RESPONSE_KEY": "resp1",
      }]

    original_build_inputs = self.plugin._build_csp_reconcile_inputs

    def build_inputs(*args, **kwargs):
      inputs = original_build_inputs(*args, **kwargs)
      inputs["_source_pipeline"] = kwargs["pipeline"]
      return inputs

    self.plugin._get_online_apps = get_online_apps
    self.plugin._discover_plugin_instances = discover_plugin_instances
    self.plugin._build_csp_reconcile_inputs = build_inputs

    result = self.plugin._reconcile_csp_escrow_job_owner(
      job_id=10,
      old_owner="0xOld",
      new_owner="0xNew",
    )

    self.assertEqual(result[DEEPLOY_KEYS.STATUS], "node_update_delivered")
    self.assertEqual(self.deploy_calls[0]["owner"], "0xNew")
    self.assertEqual(self.persisted[0]["pipeline"]["OWNER"], "0xNew")
    self.assertEqual(self.deleted[0]["owner"], None)
    self.assertTrue(any(call["owner"] is None for call in online_calls))

  def test_reconcile_is_idempotent_when_pipeline_and_live_owner_are_current(self):
    """
    Repeated reconciliation returns already_current and does not persist again.
    """
    self._install_pipeline(self._pipeline(owner="0xNew"))
    self.plugin._get_online_apps = lambda **kwargs: {
      "node1": {"app1": {"owner": "0xNew", "deeploy_specs": {"job_id": 10}}}
    }

    result = self.plugin._reconcile_csp_escrow_job_owner(
      job_id=10,
      old_owner="0xOld",
      new_owner="0xNew",
    )

    self.assertEqual(result[DEEPLOY_KEYS.STATUS], "already_current")
    self.assertEqual(self.persisted, [])
    self.assertEqual(self.deploy_calls, [])

  def test_reconcile_returns_pipeline_missing_for_active_job_without_r1fs_payload(self):
    """
    Active escrow jobs without stored Deeploy metadata are reported per job.
    """
    self.plugin._get_pipeline_from_cstore = lambda job_id: None

    result = self.plugin._reconcile_csp_escrow_job_owner(
      job_id=10,
      old_owner="0xOld",
      new_owner="0xNew",
    )

    self.assertEqual(result[DEEPLOY_KEYS.STATUS], "pipeline_missing")

  def test_reconcile_fails_when_stale_live_app_has_no_discoverable_instances(self):
    """
    Stale live apps must not be reported as migrated if node instances cannot be found.
    """
    self._install_pipeline(self._pipeline(owner="0xOld"))
    self.plugin._get_online_apps = lambda **kwargs: {
      "node1": {"app1": {"owner": "0xOld", "deeploy_specs": {"job_id": 10}}}
    }
    self.plugin._discover_plugin_instances = lambda **kwargs: []

    result = self.plugin._reconcile_csp_escrow_job_owner(
      job_id=10,
      old_owner="0xOld",
      new_owner="0xNew",
    )

    self.assertEqual(result[DEEPLOY_KEYS.STATUS], "failed")
    self.assertEqual(self.persisted, [])
    self.assertEqual(self.deploy_calls, [])

  def test_reconcile_validates_restart_payload_before_stopping_pipeline(self):
    """
    Invalid reconstructed configs fail before any stop command is sent.
    """
    pipeline = self._pipeline(owner="0xOld")
    del pipeline["PLUGINS"][0]["INSTANCES"][0]["IMAGE"]
    self._install_pipeline(pipeline)
    self.plugin._get_online_apps = lambda **kwargs: {
      "node1": {"app1": {"owner": "0xOld", "deeploy_specs": {"job_id": 10}}}
    }
    self.plugin._discover_plugin_instances = lambda **kwargs: [{
      "app_id": "app1",
      "instance_id": "inst1",
      "plugin_signature": "CONTAINER_APP_RUNNER",
      "plugin_instance": {"instance_conf": {"CONTAINER_RESOURCES": {"cpu": 1, "memory": "512m"}}},
      "NODE": "node1",
      "CHAINSTORE_RESPONSE_KEY": "resp1",
    }]

    result = self.plugin._reconcile_csp_escrow_job_owner(
      job_id=10,
      old_owner="0xOld",
      new_owner="0xNew",
    )

    self.assertEqual(result[DEEPLOY_KEYS.STATUS], "failed")
    self.assertIn("invalid", result[DEEPLOY_KEYS.ERROR])
    self.assertEqual(self.deleted, [])
    self.assertEqual(self.deploy_calls, [])


if __name__ == "__main__":
  unittest.main()
