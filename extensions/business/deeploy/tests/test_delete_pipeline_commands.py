import copy
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
from naeural_core import constants as ct


def _discovered_instance(app_id, node, signature, instance_id, lifecycle_generation=3, date_updated=300.0):
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
    DEEPLOY_PLUGIN_DATA.DEEPLOY_SPECS: {
      DEEPLOY_KEYS.LIFECYCLE_GENERATION: lifecycle_generation,
      DEEPLOY_KEYS.DATE_UPDATED: date_updated,
      DEEPLOY_KEYS.JOB_ID: 77,
    },
  }


def _make_delete_plugin():
  plugin = make_deeploy_plugin()
  plugin.stop_calls = []
  plugin.stop_payloads = []
  plugin.logs = []

  def stop_pipeline(node_address, name, command_content=None):
    plugin.stop_calls.append((node_address, name))
    plugin.stop_payloads.append(command_content)

  plugin.cmdapi_stop_pipeline = stop_pipeline
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

  def test_delete_command_uses_discovered_lifecycle_generation(self):
    plugin = _make_delete_plugin()
    discovered = [
      _discovered_instance(
        "app-1",
        "0xai_node_1",
        "PLUGIN_A",
        "a-1",
        lifecycle_generation=4,
        date_updated=400.0,
      ),
    ]

    plugin.delete_pipeline_from_nodes(
      app_id="app-1",
      owner="0xOwner",
      discovered_instances=discovered,
    )

    self.assertEqual(plugin.stop_calls, [("0xai_node_1", "app-1")])
    self.assertEqual(len(plugin.stop_payloads), 1)
    payload = plugin.stop_payloads[0]
    self.assertEqual(payload[ct.CONFIG_STREAM.NAME], "app-1")
    self.assertEqual(payload[ct.CONFIG_STREAM.K_OWNER], "0xOwner")
    self.assertEqual(
      payload[ct.CONFIG_STREAM.DEEPLOY_SPECS][DEEPLOY_KEYS.LIFECYCLE_GENERATION],
      4,
    )
    self.assertEqual(
      payload[ct.CONFIG_STREAM.DEEPLOY_SPECS][DEEPLOY_KEYS.DATE_UPDATED],
      400.0,
    )

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

  def test_delete_endpoint_passes_target_nodes_to_delete_helper(self):
    plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    captured = {}
    plugin.cfg_deeploy_verbose = 0
    plugin.P = lambda *args, **kwargs: None
    plugin.Pd = lambda *args, **kwargs: None
    plugin._get_response = lambda dct_data: dct_data
    plugin.deeploy_verify_and_get_inputs = lambda request, **kwargs: ("0xSender", InputsStub(request))
    plugin.deeploy_get_auth_result = lambda inputs: {
      DEEPLOY_KEYS.SENDER: "0xSender",
      DEEPLOY_KEYS.SENDER_ESCROW: "0xEscrow",
      DEEPLOY_KEYS.ESCROW_OWNER: "0xOwner",
    }
    plugin._DeeployManagerApiPlugin__ensure_eth_balance = lambda: None

    def delete_pipeline_from_nodes(**kwargs):
      captured.update(kwargs)
      return []

    plugin.delete_pipeline_from_nodes = delete_pipeline_from_nodes

    res = plugin.delete_pipeline({
      DEEPLOY_KEYS.APP_ID: "app-1",
      DEEPLOY_KEYS.TARGET_NODES: ["0xai_node_2"],
      DEEPLOY_KEYS.NONCE: "0x1",
    })

    self.assertEqual(captured, {
      "app_id": "app-1",
      "job_id": None,
      "owner": "0xOwner",
      "target_nodes": ["0xai_node_2"],
    })
    self.assertEqual(res[DEEPLOY_KEYS.REQUEST][DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(res[DEEPLOY_KEYS.REQUEST][DEEPLOY_KEYS.TARGETS], [])

  def test_delete_endpoint_omitted_target_nodes_discovers_all_targets(self):
    plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    plugin.stop_calls = []
    plugin.discovery_calls = []
    plugin.deepcopy = copy.deepcopy
    plugin.cfg_deeploy_verbose = 0
    plugin.P = lambda *args, **kwargs: None
    plugin.Pd = lambda *args, **kwargs: None
    plugin._get_response = lambda dct_data: dct_data
    plugin.deeploy_verify_and_get_inputs = lambda request, **kwargs: (
      "0xSender",
      InputsStub({
        **request,
        DEEPLOY_KEYS.TARGET_NODES: 0,
      }),
    )
    plugin.deeploy_get_auth_result = lambda inputs: {
      DEEPLOY_KEYS.SENDER: "0xSender",
      DEEPLOY_KEYS.SENDER_ESCROW: "0xEscrow",
      DEEPLOY_KEYS.ESCROW_OWNER: "0xOwner",
    }
    plugin._DeeployManagerApiPlugin__ensure_eth_balance = lambda: None

    def stop_pipeline(node_address, name, command_content=None):
      plugin.stop_calls.append((node_address, name))

    plugin.cmdapi_stop_pipeline = stop_pipeline

    def discover(**kwargs):
      plugin.discovery_calls.append(kwargs)
      return [
        _discovered_instance("app-1", "0xai_node_1", "PLUGIN_A", "a-1"),
        _discovered_instance("app-1", "0xai_node_2", "PLUGIN_A", "a-2"),
      ]

    plugin._discover_plugin_instances = discover

    res = plugin.delete_pipeline({
      DEEPLOY_KEYS.APP_ID: "app-1",
      DEEPLOY_KEYS.NONCE: "0x1",
    })

    self.assertEqual(plugin.discovery_calls, [{
      "app_id": "app-1",
      "job_id": None,
      "owner": "0xOwner",
      "target_nodes": None,
    }])
    self.assertEqual(plugin.stop_calls, [
      ("0xai_node_1", "app-1"),
      ("0xai_node_2", "app-1"),
    ])
    self.assertEqual(res[DEEPLOY_KEYS.REQUEST][DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(len(res[DEEPLOY_KEYS.REQUEST][DEEPLOY_KEYS.TARGETS]), 2)


if __name__ == "__main__":
  unittest.main()
