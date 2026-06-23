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

from naeural_core import constants as ct

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_PLUGIN_DATA
from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs


class DeeployUpdateRequestPreparationTests(unittest.TestCase):

  def _make_process_update_plugin(self, discovered_instances, nodes=None, deeploy_specs=None):
    plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    plugin.ct = ct
    plugin.cfg_deeploy_verbose = 0
    plugin.deepcopy = copy.deepcopy
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1_000.0
    plugin.uuid = lambda size: "x" * size
    plugin.sanitize_name = lambda value: str(value).replace("/", "_").replace(" ", "_")
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
      "discovered_instances": discovered_instances,
      "nodes": nodes or ["node-1"],
      "deeploy_specs": deeploy_specs or {"job_id": 11},
    }
    plugin._get_pipeline_from_cstore = lambda job_id: None
    plugin._ensure_plugin_instance_ids = lambda *args, **kwargs: None
    plugin._check_nodes_availability = lambda inputs: nodes or ["node-1"]

    called = {"delete": 0, "deploy": 0, "deploy_kwargs": None, "queued": 0}
    plugin.delete_pipeline_from_nodes = lambda **kwargs: called.__setitem__("delete", called["delete"] + 1)

    def check_and_deploy_pipelines(**kwargs):
      called["deploy"] += 1
      called["deploy_kwargs"] = kwargs
      return {}, "success", {}, {"NAME": kwargs.get("app_id")}

    plugin.check_and_deploy_pipelines = check_and_deploy_pipelines
    plugin._build_pipeline_persistence_state = lambda **kwargs: {"state": kwargs}
    plugin._queue_pipeline_persistence = lambda state: called.__setitem__("queued", called["queued"] + 1)
    return plugin, called

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

  def test_validate_update_request_rejects_duplicate_plugin_names_before_dispatch(self):
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
      chainstore_response=False,
      plugins=[
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native-instance",
          DEEPLOY_KEYS.PLUGIN_NAME: "duplicate",
          "PROCESS_DELAY": 5,
        },
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "container-instance",
          DEEPLOY_KEYS.PLUGIN_NAME: "duplicate",
          "IMAGE": "repo/app:1.0",
          "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
        },
      ],
    )
    discovered = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "native-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "native",
            "PROCESS_DELAY": 5,
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "container-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        },
      },
    ]

    with self.assertRaisesRegex(ValueError, "Duplicate plugin_name"):
      plugin._validate_update_pipeline_request(
        owner="owner",
        inputs=inputs,
        app_id="app-123",
        app_alias="app",
        app_type="void",
        update_nodes=["node-1"],
        discovered_plugin_instances=discovered,
        dct_deeploy_specs={"job_id": 11},
        job_app_type="native",
      )

    self.assertEqual(called["cmd"], 0)
    self.assertEqual(called["reset"], 0)

  def test_validate_update_request_rejects_duplicate_explicit_semaphore_without_shmem_before_dispatch(self):
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
      chainstore_response=False,
      plugins=[
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native-instance-1",
          "SEMAPHORE": "shared",
          "PROCESS_DELAY": 5,
        },
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native-instance-2",
          "SEMAPHORE": "shared",
          "PROCESS_DELAY": 5,
        },
      ],
    )
    discovered = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "native-instance-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            "PROCESS_DELAY": 5,
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "native-instance-2",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            "PROCESS_DELAY": 5,
          },
        },
      },
    ]

    with self.assertRaisesRegex(ValueError, "Duplicate semaphore key"):
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

  def test_update_pipeline_on_nodes_strips_stale_chainstore_response_key_when_disabled(self):
    plugin = make_deeploy_plugin()
    plugin.time = lambda: 1_000.0
    plugin.defaultdict = defaultdict
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: None
    response_key_field = plugin.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY

    def start_pipeline(**kwargs):
      return {
        "PLUGINS": kwargs["plugins"],
        "DEEPLOY_SPECS": kwargs["deeploy_specs"],
      }

    plugin.cmdapi_start_pipeline_by_params = start_pipeline
    inputs = make_inputs(
      app_alias="app",
      job_id=11,
      pipeline_input_type="void",
      pipeline_input_uri="",
      chainstore_response=False,
      plugins=[
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "current-instance",
          "IMAGE": "repo/app:2.0",
          "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          response_key_field: "stale-from-request",
        },
      ],
    )
    discovered = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "current-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: "stale-from-discovery",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        },
      },
    ]

    response_keys, saved_pipeline = plugin._DeeployMixin__update_pipeline_on_nodes(
      ["node-1"],
      inputs,
      "app-123",
      "app",
      "void",
      "owner",
      discovered,
      dct_deeploy_specs={"job_id": 11, DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS: {"node-1": ["old-key"]}},
      job_app_type="generic",
    )

    instance = saved_pipeline["PLUGINS"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(response_keys, {})
    self.assertNotIn(response_key_field, instance)
    self.assertNotIn(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, saved_pipeline["DEEPLOY_SPECS"])

  def test_update_pipeline_on_nodes_recovers_duplicate_stale_named_semaphores_with_autowire(self):
    plugin = make_deeploy_plugin()
    plugin.time = lambda: 1_000.0
    plugin.defaultdict = defaultdict
    called = {"start": 0, "reset": 0}
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: called.__setitem__("reset", called["reset"] + 1)

    def start_pipeline(**kwargs):
      called["start"] += 1
      return {
        "PLUGINS": kwargs["plugins"],
        "DEEPLOY_SPECS": kwargs["deeploy_specs"],
      }

    plugin.cmdapi_start_pipeline_by_params = start_pipeline
    response_key_field = plugin.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY
    inputs = make_inputs(
      app_alias="app",
      job_id=11,
      pipeline_input_type="void",
      pipeline_input_uri="",
      chainstore_response=True,
      plugins=[
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native-1",
          DEEPLOY_KEYS.PLUGIN_NAME: "alpha",
          "SEMAPHORE": "old-app__shared-api",
          "PROCESS_DELAY": 5,
        },
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native-2",
          DEEPLOY_KEYS.PLUGIN_NAME: "beta",
          "SEMAPHORE": "old-app__shared-api",
          "PROCESS_DELAY": 5,
        },
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "car-1",
          DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
          "IMAGE": "repo/app:2.0",
          "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
        },
      ],
    )
    discovered = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "native-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: "resp-native-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {"instance_conf": {"PROCESS_DELAY": 5}},
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "native-2",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: "resp-native-2",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {"instance_conf": {"PROCESS_DELAY": 5}},
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "car-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY: "resp-car-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        },
      },
    ]

    response_keys, saved_pipeline = plugin._DeeployMixin__update_pipeline_on_nodes(
      ["node-1"],
      inputs,
      "app-123",
      "app",
      "void",
      "owner",
      discovered,
      dct_deeploy_specs={"job_id": 11},
      job_app_type="native",
    )

    native_alpha = saved_pipeline["PLUGINS"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    native_beta = saved_pipeline["PLUGINS"][1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    container_instance = saved_pipeline["PLUGINS"][2][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(native_alpha["SEMAPHORE"], "app-123__alpha")
    self.assertEqual(native_beta["SEMAPHORE"], "app-123__beta")
    self.assertEqual(container_instance["SEMAPHORED_KEYS"], ["app-123__alpha", "app-123__beta"])
    self.assertEqual(native_alpha[response_key_field], "resp-native-1")
    self.assertEqual(native_beta[response_key_field], "resp-native-2")
    self.assertEqual(container_instance[response_key_field], "resp-car-1")
    self.assertEqual(response_keys, {"node-1": ["resp-native-1", "resp-native-2", "resp-car-1"]})
    self.assertEqual(saved_pipeline["DEEPLOY_SPECS"][DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS], response_keys)
    self.assertEqual(called["start"], 1)
    self.assertEqual(called["reset"], 1)

  def test_update_pipeline_on_nodes_rejects_duplicate_final_autowire_semaphores(self):
    plugin = make_deeploy_plugin()
    plugin.time = lambda: 1_000.0
    plugin.defaultdict = defaultdict
    called = {"start": 0, "reset": 0}
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: called.__setitem__("reset", called["reset"] + 1)
    plugin.cmdapi_start_pipeline_by_params = lambda **kwargs: called.__setitem__("start", called["start"] + 1)

    inputs = make_inputs(
      app_alias="app",
      job_id=11,
      pipeline_input_type="void",
      pipeline_input_uri="",
      chainstore_response=False,
      plugins=[
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native/a",
          "PROCESS_DELAY": 5,
        },
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native a",
          "PROCESS_DELAY": 5,
        },
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "car-1",
          "IMAGE": "repo/app:2.0",
          "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
        },
      ],
    )
    discovered = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "native/a",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {"instance_conf": {"PROCESS_DELAY": 5}},
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "native a",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {"instance_conf": {"PROCESS_DELAY": 5}},
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "car-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        },
      },
    ]

    with self.assertRaisesRegex(ValueError, "Duplicate final semaphore key"):
      plugin._DeeployMixin__update_pipeline_on_nodes(
        ["node-1"],
        inputs,
        "app-123",
        "app",
        "void",
        "owner",
        discovered,
        dct_deeploy_specs={"job_id": 11},
        job_app_type="native",
      )

    self.assertEqual(called["start"], 0)
    self.assertEqual(called["reset"], 0)

  def test_process_update_rejects_dependency_tree_before_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
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
    )

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

  def test_process_update_rejects_duplicate_plugin_names_before_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "native-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "native",
              "PROCESS_DELAY": 5,
            },
          },
        },
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "container-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
              "IMAGE": "repo/app:1.0",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            },
          },
        },
      ],
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "native",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "duplicate",
            "PROCESS_DELAY": 5,
          },
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "container-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "duplicate",
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("Duplicate plugin_name", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

  def test_process_update_rejects_duplicate_instance_ids_before_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "native-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "native",
              "PROCESS_DELAY": 5,
            },
          },
        },
      ],
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "native",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "native",
            "PROCESS_DELAY": 5,
          },
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "native-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "native-copy",
            "PROCESS_DELAY": 10,
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("Duplicate plugin_instance_id", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

  def test_process_update_materializes_omitted_live_plugins_before_redeploy(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "api-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "api",
              "PROCESS_DELAY": 5,
            },
          },
        },
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "worker-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "worker",
              "IMAGE": "repo/worker:1.0",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            },
          },
        },
      ],
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "native",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "api-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 10,
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "command_delivered")
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    redeploy_inputs = called["deploy_kwargs"]["inputs"]
    redeploy_plugins = redeploy_inputs[DEEPLOY_KEYS.PLUGINS]
    self.assertEqual(len(redeploy_plugins), 2)
    self.assertEqual(
      {entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] for entry in redeploy_plugins},
      {"api-instance", "worker-instance"},
    )
    worker = next(
      entry for entry in redeploy_plugins
      if entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] == "worker-instance"
    )
    self.assertEqual(worker["IMAGE"], "repo/worker:1.0")
    self.assertEqual(worker[DEEPLOY_KEYS.PLUGIN_NAME], "worker")

  def test_process_update_does_not_append_consumed_no_id_update_as_new_plugin(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "legacy",
              "PROCESS_DELAY": 5,
            },
          },
        },
      ],
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "native",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_NAME: "legacy",
            "PROCESS_DELAY": 10,
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "command_delivered")
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    redeploy_inputs = called["deploy_kwargs"]["inputs"]
    redeploy_plugins = redeploy_inputs[DEEPLOY_KEYS.PLUGINS]
    self.assertEqual(len(redeploy_plugins), 1)
    self.assertEqual(redeploy_plugins[0][DEEPLOY_KEYS.PLUGIN_NAME], "legacy")
    self.assertEqual(redeploy_plugins[0]["PROCESS_DELAY"], 10)

  def test_process_update_dedupes_nameless_no_id_legacy_plugin_across_nodes(self):
    discovered_instances = [
      {
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            "PROCESS_DELAY": 5,
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "api-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 5,
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-2",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            "PROCESS_DELAY": 5,
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "api-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-2",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 5,
          },
        },
      },
    ]
    plugin, called = self._make_process_update_plugin(
      discovered_instances=discovered_instances,
      nodes=["node-1", "node-2"],
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "native",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1", "node-2"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 2,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "api-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 10,
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "command_delivered")
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)

    redeploy_plugins = called["deploy_kwargs"]["inputs"][DEEPLOY_KEYS.PLUGINS]
    self.assertEqual(len(redeploy_plugins), 2)
    api = next(
      entry for entry in redeploy_plugins
      if entry.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID) == "api-instance"
    )
    legacy = next(
      entry for entry in redeploy_plugins
      if entry.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID) != "api-instance"
    )
    self.assertEqual(api["PROCESS_DELAY"], 10)
    self.assertEqual(legacy["PROCESS_DELAY"], 5)
    self.assertNotIn(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID, legacy)
    self.assertNotIn(DEEPLOY_KEYS.PLUGIN_NAME, legacy)

  def test_process_update_preserves_same_node_nameless_no_id_legacy_multiplicity(self):
    discovered_instances = [
      {
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            "PROCESS_DELAY": 5,
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            "PROCESS_DELAY": 5,
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "api-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 5,
          },
        },
      },
    ]
    plugin, called = self._make_process_update_plugin(
      discovered_instances=discovered_instances,
      nodes=["node-1"],
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "native",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "api-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 10,
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "command_delivered")
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)

    redeploy_plugins = called["deploy_kwargs"]["inputs"][DEEPLOY_KEYS.PLUGINS]
    self.assertEqual(len(redeploy_plugins), 3)
    legacy_plugins = [
      entry for entry in redeploy_plugins
      if entry.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID) != "api-instance"
    ]
    self.assertEqual(len(legacy_plugins), 2)
    for legacy in legacy_plugins:
      self.assertEqual(legacy["PROCESS_DELAY"], 5)
      self.assertNotIn(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID, legacy)
      self.assertNotIn(DEEPLOY_KEYS.PLUGIN_NAME, legacy)

  def test_process_update_materializes_one_logical_plugin_set_for_multinode_redeploy(self):
    discovered_instances = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "api-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 5,
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "worker-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.NODE: "node-1",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "worker",
            "IMAGE": "repo/worker:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "api-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: "node-2",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 5,
          },
        },
      },
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "worker-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.NODE: "node-2",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "worker",
            "IMAGE": "repo/worker:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        },
      },
    ]
    plugin, called = self._make_process_update_plugin(
      discovered_instances=discovered_instances,
      nodes=["node-1", "node-2"],
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "native",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1", "node-2"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 2,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "api-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 10,
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "command_delivered")
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    self.assertEqual(called["deploy_kwargs"]["new_nodes"], ["node-1", "node-2"])

    redeploy_inputs = called["deploy_kwargs"]["inputs"]
    redeploy_plugins = redeploy_inputs[DEEPLOY_KEYS.PLUGINS]
    self.assertEqual(len(redeploy_plugins), 2)
    self.assertEqual(
      {entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] for entry in redeploy_plugins},
      {"api-instance", "worker-instance"},
    )

    api = next(
      entry for entry in redeploy_plugins
      if entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] == "api-instance"
    )
    worker = next(
      entry for entry in redeploy_plugins
      if entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] == "worker-instance"
    )
    self.assertEqual(api["PROCESS_DELAY"], 10)
    self.assertEqual(worker["IMAGE"], "repo/worker:1.0")
    self.assertEqual(worker[DEEPLOY_KEYS.PLUGIN_NAME], "worker")

  def test_process_update_rejects_malformed_dynamic_env_before_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "current-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "worker",
              "IMAGE": "repo/app:1.0",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            },
          },
        },
      ],
    )

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
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "current-instance",
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            "DYNAMIC_ENV": {
              "API_URL": {"type": "shmem", "path": ["provider", "PORT"]},
            },
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("DYNAMIC_ENV entries for 'API_URL' must be a list", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)


if __name__ == "__main__":
  unittest.main()
