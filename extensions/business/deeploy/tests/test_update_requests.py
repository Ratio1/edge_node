import unittest
import copy
from collections import defaultdict
import sys
import types


for _mod_name in ("torch", "torch.nn", "torch.nn.functional"):
  sys.modules.setdefault(_mod_name, types.ModuleType(_mod_name))

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

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_PLUGIN_DATA
from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs


class DeeployUpdateRequestPreparationTests(unittest.TestCase):

  def test_prepare_single_plugin_instance_update_uses_plugin_config_and_strips_signature_fields(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-1",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "signature": "IGNORED",
        "IMAGE": "repo/app:latest",
        "PORT": 3000,
      },
    )

    self.assertEqual(prepared[plugin.ct.CONFIG_PLUGIN.K_SIGNATURE], "CONTAINER_APP_RUNNER")
    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance[plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID], "instance-1")
    self.assertEqual(instance["IMAGE"], "repo/app:latest")
    self.assertEqual(instance["PORT"], 3000)
    self.assertNotIn(DEEPLOY_KEYS.PLUGIN_SIGNATURE, instance)
    self.assertNotIn("signature", instance)

  def test_prepare_single_plugin_instance_update_falls_back_to_instance_conf(self):
    plugin = make_deeploy_plugin()
    fallback_instance = {
      plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
      "instance_conf": {
        plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "old-instance",
        "IMAGE": "repo/old:1.0",
        "PORT": 3002,
      },
    }

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-2",
      fallback_instance=fallback_instance,
    )

    self.assertEqual(prepared[plugin.ct.CONFIG_PLUGIN.K_SIGNATURE], "CONTAINER_APP_RUNNER")
    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance[plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID], "instance-2")
    self.assertEqual(instance["IMAGE"], "repo/old:1.0")
    self.assertEqual(instance["PORT"], 3002)

  def test_extract_plugin_request_conf_removes_update_metadata_fields(self):
    plugin = make_deeploy_plugin()
    result = plugin._extract_plugin_request_conf(
      plugin_entry={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "instance-1",
        "instance_id": "instance-1",
        plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "instance-1",
        "CHAINSTORE_RESPONSE_KEY": "resp-key",
        "CHAINSTORE_PEERS": ["peer-a"],
        "IMAGE": "repo/app:latest",
        "PORT": 3000,
      },
      instance_id_key=plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID,
      chainstore_response_key="CHAINSTORE_RESPONSE_KEY",
      chainstore_peers_key="CHAINSTORE_PEERS",
    )

    self.assertEqual(result, {
      "IMAGE": "repo/app:latest",
      "PORT": 3000,
    })

  def test_prepare_single_plugin_instance_update_preserves_exposed_ports(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-3",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "IMAGE": "repo/app:latest",
        "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
        "EXPOSED_PORTS": {
          "3005": {"is_main_port": True},
          "3006": {"tunnel": {"enabled": True, "engine": "cloudflare", "token": "upd-token"}},
        },
      },
    )

    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertTrue(instance["EXPOSED_PORTS"]["3005"]["is_main_port"])
    self.assertEqual(instance["EXPOSED_PORTS"]["3006"]["tunnel"]["token"], "upd-token")

  def test_extract_plugin_request_conf_keeps_exposed_ports(self):
    plugin = make_deeploy_plugin()
    result = plugin._extract_plugin_request_conf(
      plugin_entry={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "instance-1",
        "instance_id": "instance-1",
        plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "instance-1",
        "CHAINSTORE_RESPONSE_KEY": "resp-key",
        "CHAINSTORE_PEERS": ["peer-a"],
        "IMAGE": "repo/app:latest",
        "EXPOSED_PORTS": {
          "3000": {"is_main_port": True},
        },
      },
      instance_id_key=plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID,
      chainstore_response_key="CHAINSTORE_RESPONSE_KEY",
      chainstore_peers_key="CHAINSTORE_PEERS",
    )

    self.assertEqual(result, {
      "IMAGE": "repo/app:latest",
      "EXPOSED_PORTS": {
        "3000": {"is_main_port": True},
      },
    })

  def test_prepare_single_plugin_instance_update_preserves_dynamic_env(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-4",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "IMAGE": "repo/app:latest",
        "DYNAMIC_ENV": {
          "API_HOST": [
            {"type": "host_ip"},
            {"type": "static", "value": ":3000"},
          ]
        },
      },
    )

    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["DYNAMIC_ENV"]["API_HOST"], [
      {"type": "host_ip"},
      {"type": "static", "value": ":3000"},
    ])

  def test_prepare_single_plugin_instance_update_preserves_shmem_dynamic_env(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-5",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "IMAGE": "repo/app:latest",
        "DYNAMIC_ENV": {
          "UPSTREAM_PORT": [
            {"type": "shmem", "path": ["native-agent", "PORT"]},
          ]
        },
      },
    )

    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["DYNAMIC_ENV"]["UPSTREAM_PORT"], [
      {"type": "shmem", "path": ["native-agent", "PORT"]},
    ])

  def test_validate_update_request_fails_without_dispatching_changes(self):
    plugin = make_deeploy_plugin()
    plugin.time = lambda: 1_000.0
    plugin.defaultdict = defaultdict
    called = {"cmd": 0, "reset": 0}
    plugin.cmdapi_start_pipeline_by_params = lambda **kwargs: called.__setitem__("cmd", called["cmd"] + 1)
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: called.__setitem__("reset", called["reset"] + 1)

    inputs = make_inputs(
      app_alias="app",
      job_id=11,
      pipeline_input_type="void",
      chainstore_response=True,
      plugins=[
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "missing-instance",
          "IMAGE": "repo/app:1.0",
          "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
        },
      ],
    )
    discovered = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "current-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: "resp-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "worker",
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        },
      },
    ]

    with self.assertRaisesRegex(ValueError, "Unknown plugin instance_id"):
      plugin._validate_update_pipeline_request(
        owner="owner",
        inputs=inputs,
        app_id="app-123",
        app_alias="app",
        app_type="void",
        update_nodes=["node-1"],
        discovered_plugin_instances=discovered,
        dct_deeploy_specs={"job_id": 11},
        job_app_type="generic",
      )

    self.assertEqual(called["cmd"], 0)
    self.assertEqual(called["reset"], 0)

  def test_validate_update_request_rejects_dependency_tree_before_dispatch(self):
    plugin = make_deeploy_plugin()
    plugin.time = lambda: 1_000.0
    plugin.defaultdict = defaultdict
    called = {"cmd": 0, "reset": 0}
    plugin.cmdapi_start_pipeline_by_params = lambda **kwargs: called.__setitem__("cmd", called["cmd"] + 1)
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: called.__setitem__("reset", called["reset"] + 1)

    inputs = make_inputs(
      app_alias="app",
      job_id=11,
      pipeline_input_type="void",
      chainstore_response=True,
      dependency_tree=[
        ["frontend", "backend"],
        ["backend", "frontend"],
      ],
      plugins=[
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "current-instance",
          "IMAGE": "repo/app:1.0",
          "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
        },
      ],
    )
    discovered = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "current-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: "resp-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "worker",
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        },
      },
    ]

    with self.assertRaisesRegex(ValueError, "Circular dependency"):
      plugin._validate_update_pipeline_request(
        owner="owner",
        inputs=inputs,
        app_id="app-123",
        app_alias="app",
        app_type="void",
        update_nodes=["node-1"],
        discovered_plugin_instances=discovered,
        dct_deeploy_specs={"job_id": 11},
        job_app_type="generic",
      )

    self.assertEqual(called["cmd"], 0)
    self.assertEqual(called["reset"], 0)

  def test_process_update_rejects_dependency_tree_before_delete(self):
    plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    plugin.cfg_deeploy_verbose = 0
    plugin.deepcopy = copy.deepcopy
    plugin.P = lambda *args, **kwargs: None
    plugin.Pd = lambda *args, **kwargs: None
    plugin.json_dumps = lambda obj, **kwargs: str(obj)
    plugin._get_response = lambda dct_data: dct_data
    plugin._DeeployManagerApiPlugin__ensure_eth_balance = lambda: None
    plugin._DeeployManagerApiPlugin__handle_error = lambda exc, request: {
      DEEPLOY_KEYS.STATUS: "failed",
      DEEPLOY_KEYS.ERROR: str(exc),
    }
    plugin.deeploy_verify_and_get_inputs = lambda request, **kwargs: ("0xSender", make_inputs(**request))
    plugin._normalize_plugins_input = lambda request: request
    plugin.deeploy_get_auth_result = lambda inputs: {
      DEEPLOY_KEYS.SENDER: "0xSender",
      DEEPLOY_KEYS.SENDER_ESCROW: "0xEscrow",
      DEEPLOY_KEYS.ESCROW_OWNER: "0xOwner",
    }
    plugin.deeploy_check_payment_and_job_owner = lambda *args, **kwargs: True
    plugin._extract_pipeline_params = lambda inputs: {}
    plugin._check_and_maybe_convert_address = lambda node: node
    plugin._gather_running_pipeline_context = lambda **kwargs: {
      "discovered_instances": [
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "current-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: "resp-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "worker",
              "IMAGE": "repo/app:1.0",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            },
          },
        },
      ],
      "nodes": ["node-1"],
      "deeploy_specs": {"job_id": 11},
    }
    plugin._get_pipeline_from_cstore = lambda job_id: None
    plugin._ensure_plugin_instance_ids = lambda *args, **kwargs: None
    plugin._check_nodes_availability = lambda inputs: ["node-1"]

    called = {"delete": 0, "deploy": 0}
    plugin.delete_pipeline_from_nodes = lambda **kwargs: called.__setitem__("delete", called["delete"] + 1)
    plugin.check_and_deploy_pipelines = lambda **kwargs: called.__setitem__("deploy", called["deploy"] + 1)

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "generic",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.DEPENDENCY_TREE: [
          ["frontend", "backend"],
          ["backend", "frontend"],
        ],
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "current-instance",
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("Circular dependency", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)


if __name__ == "__main__":
  unittest.main()
