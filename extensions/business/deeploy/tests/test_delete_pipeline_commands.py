import threading
import sys
import types
import unittest


_supervisor_module = types.ModuleType("naeural_core.business.default.web_app.supervisor_fast_api_web_app")


class _BasePluginStub:
  CONFIG = {"VALIDATION_RULES": {}}

  @classmethod
  def endpoint(cls, **kwargs):
    def decorator(fn):
      return fn
    return decorator


_supervisor_module.SupervisorFastApiWebApp = _BasePluginStub
sys.modules.setdefault(
  "naeural_core.business.default.web_app.supervisor_fast_api_web_app",
  _supervisor_module,
)

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_PLUGIN_DATA, DEEPLOY_STATUS
from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin
from extensions.business.deeploy.tests.support import InputsStub, make_deeploy_plugin


def _discovered_instance(app_id, node, signature, instance_id):
  return {
    DEEPLOY_PLUGIN_DATA.APP_ID: app_id,
    DEEPLOY_PLUGIN_DATA.NODE: node,
    DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: signature,
    DEEPLOY_PLUGIN_DATA.INSTANCE_ID: instance_id,
    DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
      "instance": instance_id,
      "instance_conf": {},
    },
    DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: None,
  }


def _make_delete_plugin():
  plugin = make_deeploy_plugin()
  plugin.stop_calls = []
  plugin.logs = []
  plugin.cmdapi_stop_pipeline = lambda node_address, name: plugin.stop_calls.append((node_address, name))
  plugin.P = lambda msg, *args, **kwargs: plugin.logs.append(str(msg))
  plugin.Pd = lambda msg, *args, **kwargs: plugin.logs.append(str(msg))
  return plugin


class DeeployDeletePipelineCommandTests(unittest.TestCase):

  def test_multiplugin_single_node_delete_emits_one_pipeline_stop(self):
    plugin = _make_delete_plugin()
    discovered = [
      _discovered_instance("sentinelapi-0_d60b35d", "0xai_node_1", "CONTAINER_APP_RUNNER", "car-1"),
      _discovered_instance("sentinelapi-0_d60b35d", "0xai_node_1", "SENTINEL_API", "sentinel-1"),
      _discovered_instance("sentinelapi-0_d60b35d", "0xai_node_1", "SENTINEL_MONITOR", "monitor-1"),
    ]

    returned = plugin.delete_pipeline_from_nodes(
      app_id="sentinelapi-0_d60b35d",
      owner="0xOwner",
      discovered_instances=discovered,
    )

    self.assertIs(returned, discovered)
    self.assertEqual(plugin.stop_calls, [("0xai_node_1", "sentinelapi-0_d60b35d")])
    self.assertTrue(any("duplicate" in log.lower() or "collapsed" in log.lower() for log in plugin.logs))

  def test_multinode_delete_emits_one_stop_per_node_in_first_discovery_order(self):
    plugin = _make_delete_plugin()
    discovered = [
      _discovered_instance("app-1", "0xai_node_2", "PLUGIN_A", "a-2"),
      _discovered_instance("app-1", "0xai_node_1", "PLUGIN_A", "a-1"),
      _discovered_instance("app-1", "0xai_node_2", "PLUGIN_B", "b-2"),
      _discovered_instance("app-1", "0xai_node_1", "PLUGIN_B", "b-1"),
    ]

    plugin.delete_pipeline_from_nodes(
      app_id="app-1",
      owner="0xOwner",
      discovered_instances=discovered,
    )

    self.assertEqual(plugin.stop_calls, [
      ("0xai_node_2", "app-1"),
      ("0xai_node_1", "app-1"),
    ])

  def test_job_id_discovery_path_deduplicates_pipeline_stops(self):
    plugin = _make_delete_plugin()
    discovered = [
      _discovered_instance("job-app", "0xai_node_1", "PLUGIN_A", "a-1"),
      _discovered_instance("job-app", "0xai_node_1", "PLUGIN_B", "b-1"),
    ]
    discovery_calls = []

    def discover(**kwargs):
      discovery_calls.append(kwargs)
      return discovered

    plugin._discover_plugin_instances = discover

    returned = plugin.delete_pipeline_from_nodes(job_id=77, owner="0xOwner")

    self.assertIs(returned, discovered)
    self.assertEqual(discovery_calls, [{
      "app_id": None,
      "job_id": 77,
      "owner": "0xOwner",
      "target_nodes": None,
    }])
    self.assertEqual(plugin.stop_calls, [("0xai_node_1", "job-app")])

  def test_target_nodes_are_forwarded_to_discovery(self):
    plugin = _make_delete_plugin()
    discovered = [
      _discovered_instance("app-1", "0xai_node_2", "PLUGIN_A", "a-2"),
    ]
    discovery_calls = []

    def discover(**kwargs):
      discovery_calls.append(kwargs)
      return discovered

    plugin._discover_plugin_instances = discover

    plugin.delete_pipeline_from_nodes(
      app_id="app-1",
      owner="0xOwner",
      target_nodes=["0xai_node_2"],
    )

    self.assertEqual(discovery_calls, [{
      "app_id": "app-1",
      "job_id": None,
      "owner": "0xOwner",
      "target_nodes": ["0xai_node_2"],
    }])
    self.assertEqual(plugin.stop_calls, [("0xai_node_2", "app-1")])

  def test_falsy_target_nodes_default_discovers_all_nodes(self):
    plugin = _make_delete_plugin()
    discovered = [
      _discovered_instance("app-1", "0xai_node_2", "PLUGIN_A", "a-2"),
    ]
    discovery_calls = []

    def discover(**kwargs):
      discovery_calls.append(kwargs)
      return discovered

    plugin._discover_plugin_instances = discover

    plugin.delete_pipeline_from_nodes(
      app_id="app-1",
      owner="0xOwner",
      target_nodes=0,
    )

    self.assertEqual(discovery_calls, [{
      "app_id": "app-1",
      "job_id": None,
      "owner": "0xOwner",
      "target_nodes": None,
    }])
    self.assertEqual(plugin.stop_calls, [("0xai_node_2", "app-1")])

  def test_allow_missing_still_returns_empty_without_command(self):
    plugin = _make_delete_plugin()
    plugin._discover_plugin_instances = lambda **kwargs: []

    returned = plugin.delete_pipeline_from_nodes(
      app_id="missing-app",
      owner="0xOwner",
      allow_missing=True,
    )

    self.assertEqual(returned, [])
    self.assertEqual(plugin.stop_calls, [])


class DeeployDeletePipelineEndpointTests(unittest.TestCase):

  def test_delete_endpoint_returns_durable_acceptance_without_direct_stops(self):
    from unittest.mock import Mock
    plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    plugin._deployment_admission_lock = threading.RLock()
    plugin._get_response = lambda result: result
    plugin.deeploy_verify_and_get_inputs = lambda request, **kw: ("sender", InputsStub(request))
    plugin.deeploy_get_auth_result = lambda inputs: {DEEPLOY_KEYS.ESCROW_OWNER: "owner"}
    accepted = {"status_code": 202, "status": "accepted", "operation_id": "delete-op"}
    plugin._admit_delete_operation = Mock(return_value=accepted)
    plugin.cmdapi_stop_pipeline = Mock()
    request = {"job_id": 1, "request_id": "delete", "expected_revision": 3}
    self.assertEqual(plugin.delete_pipeline(request), accepted)
    plugin._admit_delete_operation.assert_called_once_with(request, {DEEPLOY_KEYS.ESCROW_OWNER: "owner"})
    plugin.cmdapi_stop_pipeline.assert_not_called()

  def test_delete_endpoint_reports_uncertain_storage_without_false_success(self):
    from unittest.mock import Mock
    plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    plugin._deployment_admission_lock = threading.RLock()
    plugin._get_response = lambda result: result
    plugin.deeploy_verify_and_get_inputs = lambda request, **kw: ("sender", InputsStub(request))
    plugin.deeploy_get_auth_result = lambda inputs: {DEEPLOY_KEYS.ESCROW_OWNER: "owner"}
    plugin._admit_delete_operation = Mock(side_effect=RuntimeError("private storage failure"))
    response = plugin.delete_pipeline({"job_id": 1, "request_id": "delete", "expected_revision": 3})
    self.assertEqual(response["status_code"], 503)
    self.assertTrue(response["error"]["retryable"])
    self.assertNotIn("private storage failure", str(response))


if __name__ == "__main__":
  unittest.main()
