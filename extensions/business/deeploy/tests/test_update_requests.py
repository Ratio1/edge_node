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

from extensions.business.deeploy.deeploy_const import (
  DEEPLOY_DYNAMIC_ENV_KEYS,
  DEEPLOY_DYNAMIC_ENV_TYPES,
  DEEPLOY_ERRORS,
  DEEPLOY_KEYS,
  DEEPLOY_PLUGIN_DATA,
  DEEPLOY_STATUS,
  JOB_APP_TYPES,
)
from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs, make_plugin_entry


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
    plugin._normalize_plugins_input = lambda request, **kwargs: request
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
    plugin._check_nodes_availability = lambda inputs: nodes or ["node-1"]
    plugin.chainstore_writes = []

    def chainstore_hset(hkey, key, value):
      plugin.chainstore_writes.append({
        "hkey": hkey,
        "key": key,
        "value": copy.deepcopy(value),
      })
      return True

    plugin.chainstore_hset = chainstore_hset

    called = {"delete": 0, "deploy": 0, "deploy_kwargs": None, "queued": 0, "bc_update": 0}
    plugin.bc = types.SimpleNamespace(
      node_addr_to_eth_addr=lambda node: node,
      submit_node_update=lambda **kwargs: called.__setitem__("bc_update", called["bc_update"] + 1),
    )

    def build_pipeline_config(**kwargs):
      config = {
        "NAME": kwargs["name"],
        "TYPE": kwargs["stream_type"],
      }
      if kwargs.get("url") is not None:
        config["URL"] = kwargs["url"]
      if kwargs.get("plugins") is not None:
        config["PLUGINS"] = copy.deepcopy(kwargs["plugins"])
      ignored = {"name", "stream_type", "url", "plugins"}
      config.update({
        key.upper(): copy.deepcopy(value)
        for key, value in kwargs.items()
        if key not in ignored
      })
      return config

    plugin.cmdapi_build_pipeline_config = build_pipeline_config
    plugin._load_dauth_job_secret_bundle = lambda job_id: None
    plugin.stage_job_pipeline_and_secrets = lambda pipeline, job_id, secret_bundle: {
      "job_id": str(job_id),
      "pipeline": copy.deepcopy(pipeline),
      "secret_bundle": copy.deepcopy(secret_bundle),
    }
    plugin.commit_staged_job_pipeline_and_secrets = lambda state: True
    plugin.rollback_staged_job_pipeline_and_secrets = lambda state: True
    plugin.delete_pipeline_from_nodes = lambda **kwargs: called.__setitem__("delete", called["delete"] + 1)

    def check_and_deploy_pipelines(**kwargs):
      called["deploy"] += 1
      called["deploy_kwargs"] = kwargs
      return {}, "success", {}, {"NAME": kwargs.get("app_id")}

    plugin.check_and_deploy_pipelines = check_and_deploy_pipelines
    plugin._build_pipeline_persistence_state = lambda **kwargs: {"state": kwargs}
    plugin._queue_pipeline_persistence = lambda state: called.__setitem__("queued", called["queued"] + 1)
    return plugin, called

  def _make_four_replica_cockroach_update_fixture(self, plugin):
    nodes = ["0xai_node_a", "0xai_node_b", "0xai_node_c", "0xai_node_d"]
    instance_id = "CONTAINER_APP_3ab323"
    runtime_config = {
      plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: instance_id,
      "IMAGE": "ghcr.io/ratio1/deeploy-cockroachdb-service:main",
      "CONTAINER_RESOURCES": {"cpu": 1, "memory": "2g", "storage": "0g"},
      "FIXED_SIZE_VOLUMES": {
        "cockroach_data": {"SIZE": "8G", "MOUNTING_POINT": "/cockroach/cockroach-data"},
      },
      "ENV": {
        "CRDB_DATABASE": "appdb",
        "CRDB_USER": "app_user",
        "CRDB_PASSWORD": "sanitized-password",
        "CRDB_NODE_COUNT": "4",
        "CRDB_HOSTNAMES": "roach1,roach2,roach3,roach4",
      },
      "PER_NODE_TARGET_NODES": nodes,
    }
    discovered_instances = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: instance_id,
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.NODE: node,
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": copy.deepcopy(runtime_config),
        },
      }
      for node in nodes
    ]
    request_plugin = make_plugin_entry(
      "CONTAINER_APP_RUNNER",
      instance_id=instance_id,
      IMAGE=runtime_config["IMAGE"],
      CONTAINER_RESOURCES=copy.deepcopy(runtime_config["CONTAINER_RESOURCES"]),
      FIXED_SIZE_VOLUMES=copy.deepcopy(runtime_config["FIXED_SIZE_VOLUMES"]),
      ENV=copy.deepcopy(runtime_config["ENV"]),
      PER_NODE_CONFIG={
        "byNode": {
          node: {"ENV": {"CF_TUNNEL_TOKEN": f"sanitized-token-{index + 1}"}}
          for index, node in enumerate(nodes)
        },
      },
    )
    return nodes, discovered_instances, request_plugin

  def _make_legacy_service_update_request(
    self,
    nodes,
    request_plugin,
    top_level_instance_id=None,
    nested_instance_id=None,
  ):
    app_params = {
      key: copy.deepcopy(value)
      for key, value in request_plugin.items()
      if key not in (DEEPLOY_KEYS.PLUGIN_SIGNATURE, DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
    }
    if nested_instance_id is not None:
      app_params[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] = nested_instance_id
    request = {
      DEEPLOY_KEYS.APP_ID: "cockroachdb_422ce92",
      DEEPLOY_KEYS.APP_ALIAS: "cockroachdb",
      DEEPLOY_KEYS.JOB_ID: 11,
      DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
      DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
      DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
      DEEPLOY_KEYS.TARGET_NODES: nodes,
      DEEPLOY_KEYS.TARGET_NODES_COUNT: len(nodes),
      DEEPLOY_KEYS.PLUGIN_SIGNATURE: request_plugin[DEEPLOY_KEYS.PLUGIN_SIGNATURE],
      DEEPLOY_KEYS.APP_PARAMS: app_params,
    }
    if top_level_instance_id is not None:
      request[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] = top_level_instance_id
    return request

  def test_normalize_legacy_update_copies_top_level_instance_id(self):
    plugin = make_deeploy_plugin()
    request = {
      DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
      DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "CONTAINER_APP_3ab323",
      DEEPLOY_KEYS.APP_PARAMS: {"IMAGE": "repo/app:2.0"},
    }

    normalized = plugin._normalize_plugins_input(
      plugin.deepcopy(request),
      preserve_legacy_instance_id=True,
    )

    self.assertEqual(
      normalized[DEEPLOY_KEYS.PLUGINS][0][DEEPLOY_KEYS.PLUGIN_INSTANCE_ID],
      "CONTAINER_APP_3ab323",
    )

  def test_normalize_legacy_identity_duplicate_and_create_compatibility(self):
    plugin = make_deeploy_plugin()
    matching_request = {
      DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
      DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "CONTAINER_APP_3ab323",
      DEEPLOY_KEYS.APP_PARAMS: {
        DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "CONTAINER_APP_3ab323",
        "IMAGE": "repo/app:2.0",
      },
    }

    normalized_update = plugin._normalize_plugins_input(
      plugin.deepcopy(matching_request),
      preserve_legacy_instance_id=True,
    )
    normalized_create = plugin._normalize_plugins_input(plugin.deepcopy({
      DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
      DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "CONTAINER_APP_3ab323",
      DEEPLOY_KEYS.APP_PARAMS: {"IMAGE": "repo/app:2.0"},
    }))
    nested_only = plugin._normalize_plugins_input(
      plugin.deepcopy({
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_KEYS.APP_PARAMS: {
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "CONTAINER_APP_3ab323",
          "IMAGE": "repo/app:2.0",
        },
      }),
      preserve_legacy_instance_id=True,
    )
    modern_plugins = plugin._normalize_plugins_input(
      plugin.deepcopy({
        DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "IGNORED_TOP_LEVEL_ID",
        DEEPLOY_KEYS.PLUGINS: [
          make_plugin_entry(
            "CONTAINER_APP_RUNNER",
            instance_id="CONTAINER_APP_3ab323",
            IMAGE="repo/app:2.0",
          ),
        ],
      }),
      preserve_legacy_instance_id=True,
    )

    self.assertEqual(
      normalized_update[DEEPLOY_KEYS.PLUGINS][0][DEEPLOY_KEYS.PLUGIN_INSTANCE_ID],
      "CONTAINER_APP_3ab323",
    )
    self.assertNotIn(
      DEEPLOY_KEYS.PLUGIN_INSTANCE_ID,
      normalized_create[DEEPLOY_KEYS.PLUGINS][0],
    )
    self.assertEqual(
      nested_only[DEEPLOY_KEYS.PLUGINS][0][DEEPLOY_KEYS.PLUGIN_INSTANCE_ID],
      "CONTAINER_APP_3ab323",
    )
    self.assertEqual(
      modern_plugins[DEEPLOY_KEYS.PLUGINS][0][DEEPLOY_KEYS.PLUGIN_INSTANCE_ID],
      "CONTAINER_APP_3ab323",
    )

  def test_normalize_legacy_update_rejects_conflicting_instance_ids(self):
    plugin = make_deeploy_plugin()
    request = {
      DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
      DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "CONTAINER_APP_3ab323",
      DEEPLOY_KEYS.APP_PARAMS: {
        DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "CONTAINER_APP_other",
        "IMAGE": "repo/app:2.0",
      },
    }

    with self.assertRaisesRegex(ValueError, DEEPLOY_ERRORS.REQUEST3):
      plugin._normalize_plugins_input(
        request,
        preserve_legacy_instance_id=True,
      )

  def test_normalize_legacy_update_preserves_blank_and_null_identity_for_validation(self):
    plugin = make_deeploy_plugin()
    for submitted_instance_id in ("", None):
      with self.subTest(submitted_instance_id=submitted_instance_id):
        normalized = plugin._normalize_plugins_input(
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: submitted_instance_id,
            DEEPLOY_KEYS.APP_PARAMS: {"IMAGE": "repo/app:2.0"},
          },
          preserve_legacy_instance_id=True,
        )

        self.assertIn(
          DEEPLOY_KEYS.PLUGIN_INSTANCE_ID,
          normalized[DEEPLOY_KEYS.PLUGINS][0],
        )
        self.assertEqual(
          normalized[DEEPLOY_KEYS.PLUGINS][0][DEEPLOY_KEYS.PLUGIN_INSTANCE_ID],
          submitted_instance_id,
        )

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

  def test_process_service_update_preserves_four_replica_identity_and_storage(self):
    fixture_plugin = make_deeploy_plugin()
    nodes, discovered_instances, request_plugin = self._make_four_replica_cockroach_update_fixture(fixture_plugin)
    plugin, called = self._make_process_update_plugin(
      discovered_instances=discovered_instances,
      nodes=nodes,
      deeploy_specs={
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes,
      },
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "cockroachdb_422ce92",
        DEEPLOY_KEYS.APP_ALIAS: "cockroachdb",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: " SERVICE ",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: nodes,
        DEEPLOY_KEYS.TARGET_NODES_COUNT: len(nodes),
        DEEPLOY_KEYS.PLUGINS: [request_plugin],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.COMMAND_DELIVERED)
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    self.assertEqual(called["deploy_kwargs"]["job_app_type"], JOB_APP_TYPES.SERVICE)
    redeploy_inputs = called["deploy_kwargs"]["inputs"]
    self.assertEqual(len(redeploy_inputs[DEEPLOY_KEYS.PLUGINS]), 1)
    self.assertEqual(
      redeploy_inputs[DEEPLOY_KEYS.PLUGINS][0][DEEPLOY_KEYS.PLUGIN_INSTANCE_ID],
      "CONTAINER_APP_3ab323",
    )
    self.assertEqual(
      plugin._aggregate_container_resources(redeploy_inputs)["storage"],
      "8192m",
    )

    prepared_plan = called["deploy_kwargs"]["prepared_create_deploy_plan"]
    self.assertEqual(set(prepared_plan["node_plugins_by_addr"]), set(nodes))
    for node_plugins in prepared_plan["node_plugins_by_addr"].values():
      self.assertEqual(len(node_plugins), 1)
      instance = node_plugins[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
      self.assertEqual(instance[plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID], "CONTAINER_APP_3ab323")
      self.assertEqual(instance["PER_NODE_TARGET_NODES"], nodes)
      self.assertEqual(instance["CONTAINER_RESOURCES"]["storage"], "0g")
      self.assertEqual(instance["FIXED_SIZE_VOLUMES"]["cockroach_data"]["SIZE"], "8G")

  def test_process_legacy_service_update_preserves_four_replica_identity_and_storage(self):
    fixture_plugin = make_deeploy_plugin()
    nodes, discovered_instances, request_plugin = self._make_four_replica_cockroach_update_fixture(fixture_plugin)
    plugin, called = self._make_process_update_plugin(
      discovered_instances=discovered_instances,
      nodes=nodes,
      deeploy_specs={
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes,
      },
    )
    plugin._normalize_plugins_input = types.MethodType(
      DeeployManagerApiPlugin._normalize_plugins_input,
      plugin,
    )
    request = self._make_legacy_service_update_request(
      nodes,
      request_plugin,
      top_level_instance_id="CONTAINER_APP_3ab323",
    )

    response = plugin._process_pipeline_request(
      request,
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.COMMAND_DELIVERED)
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    redeploy_inputs = called["deploy_kwargs"]["inputs"]
    self.assertEqual(len(redeploy_inputs[DEEPLOY_KEYS.PLUGINS]), 1)
    self.assertEqual(
      redeploy_inputs[DEEPLOY_KEYS.PLUGINS][0][DEEPLOY_KEYS.PLUGIN_INSTANCE_ID],
      "CONTAINER_APP_3ab323",
    )
    self.assertEqual(plugin._aggregate_container_resources(redeploy_inputs)["storage"], "8192m")
    prepared_plan = called["deploy_kwargs"]["prepared_create_deploy_plan"]
    self.assertEqual(set(prepared_plan["node_plugins_by_addr"]), set(nodes))
    prepared_ids = {
      instance[plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID]
      for node_plugins in prepared_plan["node_plugins_by_addr"].values()
      for node_plugin in node_plugins
      for instance in node_plugin[plugin.ct.CONFIG_PLUGIN.K_INSTANCES]
    }
    self.assertEqual(prepared_ids, {"CONTAINER_APP_3ab323"})

  def test_process_legacy_service_update_without_identity_fails_before_side_effects(self):
    fixture_plugin = make_deeploy_plugin()
    nodes, discovered_instances, request_plugin = self._make_four_replica_cockroach_update_fixture(fixture_plugin)
    plugin, called = self._make_process_update_plugin(
      discovered_instances=discovered_instances,
      nodes=nodes,
      deeploy_specs={
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes,
      },
    )
    plugin._normalize_plugins_input = types.MethodType(
      DeeployManagerApiPlugin._normalize_plugins_input,
      plugin,
    )
    phase_calls = defaultdict(int)
    plugin._ensure_plugin_instance_ids = (
      lambda *args, **kwargs: phase_calls.__setitem__("backfill", phase_calls["backfill"] + 1)
    )
    plugin.deeploy_check_payment_and_job_owner = (
      lambda *args, **kwargs: phase_calls.__setitem__("payment", phase_calls["payment"] + 1) or True
    )
    plugin._prepare_create_pipeline_deploy_plan = (
      lambda **kwargs: phase_calls.__setitem__("preparation", phase_calls["preparation"] + 1) or {}
    )
    plugin._reset_chainstore_response_keys = (
      lambda *args, **kwargs: phase_calls.__setitem__("reset", phase_calls["reset"] + 1)
    )
    request = self._make_legacy_service_update_request(nodes, request_plugin)

    response = plugin._process_pipeline_request(
      request,
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "failed")
    self.assertIn(DEEPLOY_ERRORS.PLUGINS3, response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(dict(phase_calls), {})
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)
    self.assertEqual(called["queued"], 0)

  def test_process_legacy_service_update_rejects_conflicting_identity_before_discovery(self):
    fixture_plugin = make_deeploy_plugin()
    nodes, discovered_instances, request_plugin = self._make_four_replica_cockroach_update_fixture(fixture_plugin)
    plugin, called = self._make_process_update_plugin(
      discovered_instances=discovered_instances,
      nodes=nodes,
      deeploy_specs={
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes,
      },
    )
    plugin._normalize_plugins_input = types.MethodType(
      DeeployManagerApiPlugin._normalize_plugins_input,
      plugin,
    )
    phase_calls = defaultdict(int)
    plugin._gather_running_pipeline_context = (
      lambda **kwargs: phase_calls.__setitem__("discovery", phase_calls["discovery"] + 1) or {}
    )
    plugin.deeploy_check_payment_and_job_owner = (
      lambda *args, **kwargs: phase_calls.__setitem__("payment", phase_calls["payment"] + 1) or True
    )
    plugin._prepare_create_pipeline_deploy_plan = (
      lambda **kwargs: phase_calls.__setitem__("preparation", phase_calls["preparation"] + 1) or {}
    )
    plugin._reset_chainstore_response_keys = (
      lambda *args, **kwargs: phase_calls.__setitem__("reset", phase_calls["reset"] + 1)
    )
    request = self._make_legacy_service_update_request(
      nodes,
      request_plugin,
      top_level_instance_id="CONTAINER_APP_3ab323",
      nested_instance_id="CONTAINER_APP_other",
    )

    response = plugin._process_pipeline_request(
      request,
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "failed")
    self.assertIn(DEEPLOY_ERRORS.REQUEST3, response[DEEPLOY_KEYS.ERROR])
    self.assertIn("Conflicting legacy instance_id", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(dict(phase_calls), {})
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)
    self.assertEqual(called["queued"], 0)

  def test_process_update_without_job_app_type_fails_before_discovery_or_side_effects(self):
    for persisted_job_app_type in (None, JOB_APP_TYPES.SERVICE):
      with self.subTest(persisted_job_app_type=persisted_job_app_type):
        fixture_plugin = make_deeploy_plugin()
        nodes, discovered_instances, request_plugin = self._make_four_replica_cockroach_update_fixture(
          fixture_plugin
        )
        request_plugin.pop(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
        request_plugin["IMAGE"] = "ghcr.io/ratio1/deeploy-cockroachdb-service:review-repro"
        deeploy_specs = {
          DEEPLOY_KEYS.JOB_ID: 11,
          DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes,
        }
        if persisted_job_app_type is not None:
          deeploy_specs[DEEPLOY_KEYS.JOB_APP_TYPE] = persisted_job_app_type
        plugin, called = self._make_process_update_plugin(
          discovered_instances=discovered_instances,
          nodes=nodes,
          deeploy_specs=deeploy_specs,
        )
        phase_calls = defaultdict(int)

        def gather_context(**kwargs):
          phase_calls["discovery"] += 1
          return {
            "discovered_instances": discovered_instances,
            "nodes": nodes,
            "deeploy_specs": deeploy_specs,
          }

        plugin._gather_running_pipeline_context = gather_context
        plugin.deeploy_check_payment_and_job_owner = (
          lambda *args, **kwargs: phase_calls.__setitem__("payment", phase_calls["payment"] + 1) or True
        )
        plugin._check_nodes_availability = (
          lambda inputs: phase_calls.__setitem__("nodes", phase_calls["nodes"] + 1) or nodes
        )
        plugin._prepare_create_pipeline_deploy_plan = (
          lambda **kwargs: phase_calls.__setitem__("preparation", phase_calls["preparation"] + 1)
          or {"enable_chainstore_response": False, "response_keys": {}, "node_plugins_by_addr": {}}
        )
        plugin._reset_chainstore_response_keys = (
          lambda *args, **kwargs: phase_calls.__setitem__("reset", phase_calls["reset"] + 1)
        )

        response = plugin._process_pipeline_request(
          {
            DEEPLOY_KEYS.APP_ID: "cockroachdb_422ce92",
            DEEPLOY_KEYS.APP_ALIAS: "cockroachdb",
            DEEPLOY_KEYS.JOB_ID: 11,
            DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
            DEEPLOY_KEYS.CHAINSTORE_RESPONSE: True,
            DEEPLOY_KEYS.TARGET_NODES: nodes,
            DEEPLOY_KEYS.TARGET_NODES_COUNT: len(nodes),
            DEEPLOY_KEYS.PLUGINS: [request_plugin],
          },
          is_create=False,
          async_mode=True,
        )

        self.assertEqual(response[DEEPLOY_KEYS.STATUS], "failed")
        self.assertIn(DEEPLOY_ERRORS.REQUEST3, response[DEEPLOY_KEYS.ERROR])
        self.assertIn("job_app_type is required for update requests", response[DEEPLOY_KEYS.ERROR])
        self.assertEqual(dict(phase_calls), {})
        self.assertEqual(called["delete"], 0)
        self.assertEqual(called["deploy"], 0)
        self.assertEqual(called["queued"], 0)

  def test_process_update_rejects_blank_and_invalid_job_app_type_before_discovery(self):
    for submitted_job_app_type in ("   ", "unsupported"):
      with self.subTest(submitted_job_app_type=submitted_job_app_type):
        plugin, called = self._make_process_update_plugin(discovered_instances=[])
        discovery_calls = []
        plugin._gather_running_pipeline_context = lambda **kwargs: discovery_calls.append(kwargs) or {}

        response = plugin._process_pipeline_request(
          {
            DEEPLOY_KEYS.APP_ID: "app-123",
            DEEPLOY_KEYS.APP_ALIAS: "app",
            DEEPLOY_KEYS.JOB_ID: 11,
            DEEPLOY_KEYS.JOB_APP_TYPE: submitted_job_app_type,
            DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
            DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
            DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
            DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
            DEEPLOY_KEYS.PLUGINS: [
              make_plugin_entry(
                "CONTAINER_APP_RUNNER",
                IMAGE="repo/app:2.0",
                CONTAINER_RESOURCES={"cpu": 1, "memory": "256m", "storage": "1g"},
              ),
            ],
          },
          is_create=False,
          async_mode=True,
        )

        self.assertEqual(response[DEEPLOY_KEYS.STATUS], "failed")
        self.assertIn(DEEPLOY_ERRORS.REQUEST3, response[DEEPLOY_KEYS.ERROR])
        self.assertIn("job_app_type", response[DEEPLOY_KEYS.ERROR])
        self.assertEqual(discovery_calls, [])
        self.assertEqual(called["delete"], 0)
        self.assertEqual(called["deploy"], 0)

  def test_process_create_without_job_app_type_keeps_inference(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[],
      nodes=["node-1"],
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.PLUGINS: [
          make_plugin_entry(
            "CONTAINER_APP_RUNNER",
            IMAGE="repo/app:1.0",
            CONTAINER_RESOURCES={"cpu": 1, "memory": "256m", "storage": "1g"},
          ),
        ],
      },
      is_create=True,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.COMMAND_DELIVERED)
    self.assertEqual(called["deploy"], 1)
    self.assertEqual(called["deploy_kwargs"]["job_app_type"], JOB_APP_TYPES.GENERIC)
    self.assertEqual(
      called["deploy_kwargs"]["inputs"][DEEPLOY_KEYS.JOB_APP_TYPE],
      JOB_APP_TYPES.GENERIC,
    )

  def test_process_legacy_create_ignores_top_level_instance_id(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[],
      nodes=["node-1"],
    )
    plugin._normalize_plugins_input = types.MethodType(
      DeeployManagerApiPlugin._normalize_plugins_input,
      plugin,
    )

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "CALLER_SUPPLIED_CREATE_ID",
        DEEPLOY_KEYS.APP_PARAMS: {
          "IMAGE": "repo/app:1.0",
          "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m", "storage": "1g"},
        },
      },
      is_create=True,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.COMMAND_DELIVERED)
    self.assertEqual(called["deploy"], 1)
    self.assertNotIn(
      DEEPLOY_KEYS.PLUGIN_INSTANCE_ID,
      called["deploy_kwargs"]["inputs"][DEEPLOY_KEYS.PLUGINS][0],
    )

  def test_process_service_update_without_resolved_id_fails_before_side_effects(self):
    fixture_plugin = make_deeploy_plugin()
    nodes, discovered_instances, request_plugin = self._make_four_replica_cockroach_update_fixture(fixture_plugin)
    request_plugin.pop(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
    request_plugin["IMAGE"] = "repo/reconfigured-service:latest"
    plugin, called = self._make_process_update_plugin(
      discovered_instances=discovered_instances,
      nodes=nodes,
      deeploy_specs={
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes,
      },
    )
    payment_calls = []
    reset_calls = []
    backfill_calls = []
    plugin.deeploy_check_payment_and_job_owner = lambda *args, **kwargs: payment_calls.append(args) or True
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: reset_calls.append(args)
    plugin._ensure_plugin_instance_ids = lambda *args, **kwargs: backfill_calls.append(args)

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "cockroachdb_422ce92",
        DEEPLOY_KEYS.APP_ALIAS: "cockroachdb",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: True,
        DEEPLOY_KEYS.TARGET_NODES: nodes,
        DEEPLOY_KEYS.TARGET_NODES_COUNT: len(nodes),
        DEEPLOY_KEYS.PLUGINS: [request_plugin],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn(DEEPLOY_ERRORS.PLUGINS3, response[DEEPLOY_KEYS.ERROR])
    self.assertIn("Service update plugins must include instance_id", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(backfill_calls, [])
    self.assertEqual(payment_calls, [])
    self.assertEqual(reset_calls, [])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

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

  def test_process_update_return_request_preserves_config_values(self):
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
        DEEPLOY_KEYS.RETURN_REQUEST: True,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "current-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "worker",
            "IMAGE": "repo/app:2.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            "ENV": {"API_TOKEN": "raw-token"},
            "PER_NODE_CONFIG": {
              "node-1": {"ENV": {"NODE_PASSWORD": "raw-password"}},
            },
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.COMMAND_DELIVERED)
    self.assertEqual(called["deploy"], 1)
    request_payload = response[DEEPLOY_KEYS.REQUEST]
    self.assertEqual(request_payload[DEEPLOY_KEYS.PLUGINS][0]["ENV"]["API_TOKEN"], "raw-token")
    self.assertEqual(
      request_payload[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["node-1"]["ENV"]["NODE_PASSWORD"],
      "raw-password",
    )

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

  def test_process_update_rejects_unknown_plugin_instance_before_delete(self):
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
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "missing-instance",
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("Unknown plugin instance_id", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

  def test_process_update_rejects_duplicate_explicit_semaphore_before_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
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
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("Duplicate semaphore key", response[DEEPLOY_KEYS.ERROR])
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

  def test_process_update_omits_unrequested_live_plugins_from_redeploy(self):
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
    self.assertEqual(len(redeploy_plugins), 1)
    self.assertEqual(
      {entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] for entry in redeploy_plugins},
      {"api-instance"},
    )
    prepared_plan = called["deploy_kwargs"]["prepared_create_deploy_plan"]
    self.assertIsNotNone(prepared_plan)
    prepared_instances = [
      instance
      for plugin_entry in prepared_plan["node_plugins_by_addr"]["node-1"]
      for instance in plugin_entry[plugin.ct.CONFIG_PLUGIN.K_INSTANCES]
    ]
    self.assertEqual(
      {instance[plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID] for instance in prepared_instances},
      {"api-instance"},
    )
    prepared_api = next(
      instance for instance in prepared_instances
      if instance[plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID] == "api-instance"
    )
    self.assertEqual(prepared_api["PROCESS_DELAY"], 10)

  def test_process_update_validates_requested_replacement_payload_before_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "api-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "api",
              "IMAGE": "repo/api:1.0",
              "CONTAINER_RESOURCES": {"cpu": "0.5", "memory": "256m", "storage": "1g"},
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
              "CONTAINER_RESOURCES": {"cpu": "0.5", "memory": "256m", "storage": "1g"},
            },
          },
        },
      ],
      deeploy_specs={
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "stack",
      },
    )
    validation_calls = []

    def assert_full_replacement_payload(inputs, context):
      plugins = inputs.get(DEEPLOY_KEYS.PLUGINS)
      plugin_ids = [
        entry.get(DEEPLOY_KEYS.PLUGIN_INSTANCE_ID)
        for entry in plugins
      ]
      validation_calls.append((context, plugin_ids, inputs.get(DEEPLOY_KEYS.JOB_APP_TYPE)))
      self.assertEqual(set(plugin_ids), {"api-instance"})
      self.assertEqual(inputs.get(DEEPLOY_KEYS.JOB_APP_TYPE), "stack")

    def check_payment_and_owner(inputs, *args, **kwargs):
      assert_full_replacement_payload(inputs, "payment")
      return True

    def check_nodes_availability(inputs):
      assert_full_replacement_payload(inputs, "nodes")
      return ["node-1"]

    plugin.deeploy_check_payment_and_job_owner = check_payment_and_owner
    plugin._check_nodes_availability = check_nodes_availability

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "stack",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "api-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "IMAGE": "repo/api:2.0",
            "CONTAINER_RESOURCES": {"cpu": "0.5", "memory": "256m", "storage": "1g"},
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "command_delivered")
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    self.assertEqual([context for context, _, _ in validation_calls], ["payment", "nodes"])

  def test_process_update_uses_persisted_pipeline_when_all_old_nodes_are_offline(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[],
      nodes=["old-node-1", "old-node-2"],
      deeploy_specs={
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.PROJECT_ID: "0xProject",
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["old-node-1", "old-node-2"],
        DEEPLOY_KEYS.JOB_APP_TYPE: "generic",
      },
    )
    plugin._gather_running_pipeline_context = lambda **kwargs: (_ for _ in ()).throw(
      ValueError(f"{DEEPLOY_ERRORS.NODES3}: No running workers found")
    )
    plugin._get_pipeline_from_cstore = lambda job_id: "cid-old-pipeline"
    plugin.get_pipeline_from_r1fs = lambda *args, **kwargs: {
      "NAME": "app-123",
      "OWNER": "0xOwner",
      "DEEPLOY_SPECS": {
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.PROJECT_ID: "0xProject",
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["old-node-1", "old-node-2"],
        DEEPLOY_KEYS.JOB_APP_TYPE: "generic",
      },
      "PLUGINS": [
        {
          plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
          plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
            {
              plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "current-instance",
              DEEPLOY_KEYS.PLUGIN_NAME: "worker",
              "IMAGE": "repo/app:1.0",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            },
          ],
        },
        {
          plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
          plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
            {
              plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "omitted-invalid-instance",
              DEEPLOY_KEYS.PLUGIN_NAME: "omitted-invalid",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            },
          ],
        },
      ],
    }
    plugin._check_nodes_availability = lambda inputs: ["new-node-1"]

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.PROJECT_ID: "0xProject",
        DEEPLOY_KEYS.JOB_APP_TYPE: "generic",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["new-node-1"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 1,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "current-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "worker",
            "IMAGE": "repo/app:2.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.COMMAND_DELIVERED)
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 1)
    self.assertEqual(called["queued"], 1)
    self.assertEqual(called["bc_update"], 1)
    self.assertEqual(called["deploy_kwargs"]["new_nodes"], ["new-node-1"])
    redeploy_plugins = called["deploy_kwargs"]["inputs"][DEEPLOY_KEYS.PLUGINS]
    self.assertEqual(len(redeploy_plugins), 1)
    self.assertEqual(
      redeploy_plugins[0][DEEPLOY_KEYS.PLUGIN_INSTANCE_ID],
      "current-instance",
    )
    self.assertEqual(redeploy_plugins[0]["IMAGE"], "repo/app:2.0")

  def test_process_update_rejects_job_app_type_change_before_payment_or_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "api-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "api",
              "IMAGE": "repo/api:1.0",
              "CONTAINER_RESOURCES": {"cpu": "0.5", "memory": "256m", "storage": "1g"},
            },
          },
        },
      ],
      deeploy_specs={
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "stack",
      },
    )
    payment_calls = []
    node_calls = []
    plugin.deeploy_check_payment_and_job_owner = lambda *args, **kwargs: payment_calls.append(args) or True
    plugin._check_nodes_availability = lambda inputs: node_calls.append(inputs) or ["node-1"]

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
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "api-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "IMAGE": "repo/api:2.0",
            "CONTAINER_RESOURCES": {"cpu": "0.5", "memory": "256m", "storage": "1g"},
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "failed")
    self.assertIn("job_app_type cannot be changed", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(payment_calls, [])
    self.assertEqual(node_calls, [])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)
    self.assertEqual(called["queued"], 0)

  def test_process_update_ignores_invalid_omitted_live_plugin_config(self):
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
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "broken-worker",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "worker",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            },
          },
        },
      ],
    )
    payment_calls = []
    node_calls = []
    plugin.deeploy_check_payment_and_job_owner = (
      lambda *args, **kwargs: payment_calls.append(args) or True
    )
    plugin._check_nodes_availability = (
      lambda inputs: node_calls.append(inputs) or ["node-1"]
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
    self.assertEqual(len(payment_calls), 1)
    self.assertEqual(len(node_calls), 1)
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    self.assertEqual(
      [
        entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID]
        for entry in called["deploy_kwargs"]["inputs"][DEEPLOY_KEYS.PLUGINS]
      ],
      ["api-instance"],
    )

  def test_process_update_uses_explicit_type_with_requested_replacement_only(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "api-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "api",
              "IMAGE": "repo/api:1.0",
              "CONTAINER_RESOURCES": {"cpu": "0.5", "memory": "256m", "storage": "1g"},
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
              "CONTAINER_RESOURCES": {"cpu": "0.5", "memory": "256m", "storage": "1g"},
            },
          },
        },
      ],
      deeploy_specs={DEEPLOY_KEYS.JOB_ID: 11},
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
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "api-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "IMAGE": "repo/api:2.0",
            "CONTAINER_RESOURCES": {"cpu": "0.5", "memory": "256m", "storage": "1g"},
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "command_delivered")
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    self.assertEqual(
      called["deploy_kwargs"]["inputs"][DEEPLOY_KEYS.PLUGINS][0]["IMAGE"],
      "repo/api:2.0",
    )

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

  def test_process_update_does_not_restore_nameless_legacy_plugins_across_nodes(self):
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
    self.assertEqual(len(redeploy_plugins), 1)
    api = redeploy_plugins[0]
    self.assertEqual(api["PROCESS_DELAY"], 10)

  def test_process_update_does_not_restore_same_node_nameless_legacy_plugins(self):
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
    self.assertEqual(len(redeploy_plugins), 1)
    self.assertEqual(redeploy_plugins[0][DEEPLOY_KEYS.PLUGIN_INSTANCE_ID], "api-instance")
    self.assertEqual(redeploy_plugins[0]["PROCESS_DELAY"], 10)

  def test_process_update_uses_requested_plugin_set_for_multinode_redeploy(self):
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
    self.assertEqual(len(redeploy_plugins), 1)
    self.assertEqual(
      {entry[DEEPLOY_KEYS.PLUGIN_INSTANCE_ID] for entry in redeploy_plugins},
      {"api-instance"},
    )

    api = redeploy_plugins[0]
    self.assertEqual(api["PROCESS_DELAY"], 10)

  def test_process_update_warns_on_live_replica_drift_and_uses_requested_config(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "shared-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "WORKER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "worker",
              "IMAGE": "node:22",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
              "ENV": {"API_TOKEN": "live-secret-a", "MODE": "replica-a"},
            },
          },
        },
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "shared-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "WORKER_APP_RUNNER",
          DEEPLOY_PLUGIN_DATA.NODE: "node-2",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "worker",
              "IMAGE": "node:22",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
              "ENV": {"API_TOKEN": "live-secret-b", "MODE": "replica-b"},
            },
          },
        },
      ],
      nodes=["node-1", "node-2"],
    )
    log_lines = []
    plugin.P = lambda message, **kwargs: log_lines.append(message)

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "generic",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.TARGET_NODES: ["node-1", "node-2"],
        DEEPLOY_KEYS.TARGET_NODES_COUNT: 2,
        DEEPLOY_KEYS.PLUGINS: [
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "WORKER_APP_RUNNER",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "shared-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "worker",
            "IMAGE": "node:22",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            "ENV": {"API_TOKEN": "requested-secret", "MODE": "requested"},
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "command_delivered")
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    prepared_plan = called["deploy_kwargs"]["prepared_create_deploy_plan"]
    for node_plugins in prepared_plan["node_plugins_by_addr"].values():
      instance = node_plugins[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
      self.assertEqual(instance["ENV"]["API_TOKEN"], "requested-secret")
      self.assertEqual(instance["ENV"]["MODE"], "requested")
      self.assertNotIn(instance["ENV"]["API_TOKEN"], {"live-secret-a", "live-secret-b"})
      self.assertNotIn(instance["ENV"]["MODE"], {"replica-a", "replica-b"})

    drift_logs = [line for line in log_lines if "live replica config drift" in line]
    self.assertEqual(len(drift_logs), 1)
    warning = drift_logs[0]
    self.assertIn("job_id=11", warning)
    self.assertIn("app_id=app-123", warning)
    self.assertIn("plugin_instance_id=shared-instance", warning)
    self.assertIn("node-1", warning)
    self.assertIn("node-2", warning)
    self.assertIn("WORKER_APP_RUNNER", warning)
    self.assertIn("worker", warning)
    self.assertIn("$.ENV.API_TOKEN", warning)
    self.assertIn("$.ENV.MODE", warning)
    for value in (
      "live-secret-a",
      "live-secret-b",
      "requested-secret",
      "replica-a",
      "replica-b",
      "requested",
    ):
      self.assertNotIn(value, warning)

  def test_process_update_emits_no_drift_warning_for_identical_replicas(self):
    discovered_instances = [
      {
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "shared-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
        DEEPLOY_PLUGIN_DATA.NODE: node,
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "instance_conf": {
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 5,
          },
        },
      }
      for node in ("node-1", "node-2")
    ]
    plugin, called = self._make_process_update_plugin(
      discovered_instances=discovered_instances,
      nodes=["node-1", "node-2"],
    )
    log_lines = []
    plugin.P = lambda message, **kwargs: log_lines.append(message)

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
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "shared-instance",
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
    self.assertFalse(any("live replica config drift" in line for line in log_lines))

  def test_process_update_rejects_instance_id_signature_mismatch_before_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "shared-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "api",
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
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "ANOTHER_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "shared-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "api",
            "PROCESS_DELAY": 10,
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("cannot be reused with signature", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

  def test_process_update_generates_id_for_new_plugin_without_id(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "existing-instance",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: "existing",
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
            DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "existing-instance",
            DEEPLOY_KEYS.PLUGIN_NAME: "existing",
            "PROCESS_DELAY": 10,
          },
          {
            DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_KEYS.PLUGIN_NAME: "new-plugin",
            "PROCESS_DELAY": 15,
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "command_delivered")
    prepared_plan = called["deploy_kwargs"]["prepared_create_deploy_plan"]
    instances = prepared_plan["node_plugins_by_addr"]["node-1"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES]
    by_name = {instance[DEEPLOY_KEYS.PLUGIN_NAME]: instance for instance in instances}
    self.assertEqual(
      by_name["existing"][plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID],
      "existing-instance",
    )
    self.assertEqual(
      by_name["new-plugin"][plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID],
      "A_SIMPLE_PLUG_xxxxxx",
    )

  def test_live_replica_drift_warning_is_bounded_and_value_free(self):
    plugin = make_deeploy_plugin()
    log_lines = []
    plugin.P = lambda message, **kwargs: log_lines.append(message)
    long_segment = "X" * 200
    discovered_instances = []
    for idx in range(12):
      for node_idx in range(2):
        discovered_instances.append({
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: f"instance-{idx}",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_PLUGIN_DATA.NODE: f"node-{idx}-{node_idx}\nforged",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              DEEPLOY_KEYS.PLUGIN_NAME: f"plugin-{idx}",
              f"{long_segment}-{idx}": f"secret-value-{idx}-{node_idx}",
            },
          },
        })

    warned = plugin._warn_on_live_plugin_config_drift(
      discovered_instances,
      job_id=11,
      app_id="app-123",
    )

    self.assertEqual(warned, 10)
    self.assertEqual(len(log_lines), 11)
    self.assertTrue(all(len(line) <= 2000 for line in log_lines))
    self.assertTrue(all("\n" not in line for line in log_lines))
    self.assertIn("omitted_groups=2", log_lines[-1])
    joined = "\n".join(log_lines)
    for idx in range(12):
      self.assertNotIn(f"secret-value-{idx}-0", joined)
      self.assertNotIn(f"secret-value-{idx}-1", joined)

  def test_process_update_rejects_ambiguous_nameless_no_id_update_before_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "legacy-instance-a",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
              "PROCESS_DELAY": 5,
            },
          },
        },
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "legacy-instance-b",
          DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          DEEPLOY_PLUGIN_DATA.NODE: "node-1",
          DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
            "instance_conf": {
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
            "PROCESS_DELAY": 5,
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("Ambiguous no-ID/no-name update request", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

  def test_ensure_plugin_instance_ids_rejects_ambiguous_nameless_config_match(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
          "PROCESS_DELAY": 5,
        },
      ],
    )

    with self.assertRaisesRegex(ValueError, "Ambiguous no-ID/no-name update request"):
      plugin._ensure_plugin_instance_ids(
        inputs,
        discovered_plugin_instances=[
          {
            DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "instance-a",
            DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
              "instance_conf": {"PROCESS_DELAY": 5},
            },
          },
          {
            DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "instance-b",
            DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "A_SIMPLE_PLUGIN",
            DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
              "instance_conf": {"PROCESS_DELAY": 5},
            },
          },
        ],
      )

  def test_process_update_resets_chainstore_response_before_delete_and_reuses_plan(self):
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
      ],
    )
    reset_calls = []

    def reset_response_keys(response_keys, **kwargs):
      reset_calls.append({
        "delete_count": called["delete"],
        "response_keys": copy.deepcopy(response_keys),
        "kwargs": kwargs,
      })
      return response_keys

    plugin._reset_chainstore_response_keys = reset_response_keys

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "native",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: True,
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
    self.assertEqual(len(reset_calls), 1)
    self.assertEqual(reset_calls[0]["delete_count"], 0)
    self.assertEqual(called["delete"], 1)
    self.assertEqual(called["deploy"], 1)
    self.assertTrue(called["deploy_kwargs"]["skip_create_response_key_reset"])
    prepared_plan = called["deploy_kwargs"]["prepared_create_deploy_plan"]
    self.assertEqual(prepared_plan["response_keys"], reset_calls[0]["response_keys"])

  def test_process_update_aborts_before_delete_when_chainstore_reset_fails(self):
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
      ],
    )

    def reset_response_keys(*args, **kwargs):
      raise ValueError("reset failed before delete")

    plugin._reset_chainstore_response_keys = reset_response_keys

    response = plugin._process_pipeline_request(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        DEEPLOY_KEYS.APP_ALIAS: "app",
        DEEPLOY_KEYS.JOB_ID: 11,
        DEEPLOY_KEYS.JOB_APP_TYPE: "native",
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: True,
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

    self.assertIn("reset failed before delete", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

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

  def test_process_update_rejects_per_node_malformed_dynamic_env_before_delete(self):
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
            DEEPLOY_KEYS.PLUGIN_NAME: "worker",
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            "perNodeConfig": {
              "node-1": {
                "DYNAMIC_ENV": {
                  "API_URL": {"type": "static", "value": "http://api"},
                },
              },
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

  def test_process_update_rejects_unsupported_dynamic_env_type_before_payment_or_delete(self):
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
    called["payment"] = 0

    def check_payment(*args, **kwargs):
      called["payment"] += 1
      return True

    plugin.deeploy_check_payment_and_job_owner = check_payment

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
              "API_URL": [
                {"type": "container_ip", "provider": "api"}
              ],
            },
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("unsupported type 'container_ip'", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["payment"], 0)
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

  def test_process_update_rejects_per_node_unsupported_dynamic_env_type_before_delete(self):
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
    called["payment"] = 0

    def check_payment(*args, **kwargs):
      called["payment"] += 1
      return True

    plugin.deeploy_check_payment_and_job_owner = check_payment

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
            DEEPLOY_KEYS.PLUGIN_NAME: "worker",
            "IMAGE": "repo/app:1.0",
            "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
            "perNodeConfig": {
              "node-1": {
                "DYNAMIC_ENV": {
                  "API_URL": [
                    {"type": "plugin_value", "provider": "api", "key": "PORT"}
                  ],
                },
              },
            },
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("unsupported type 'plugin_value'", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["payment"], 0)
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

  def test_process_update_rejects_source_shmem_before_delete(self):
    plugin, called = self._make_process_update_plugin(
      discovered_instances=[
        {
          DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "current-instance",
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
              "API_URL": [
                {
                  DEEPLOY_DYNAMIC_ENV_KEYS.SOURCE: DEEPLOY_DYNAMIC_ENV_TYPES.SHMEM,
                  DEEPLOY_DYNAMIC_ENV_KEYS.PATH: ["provider", "PORT"],
                }
              ],
            },
          },
        ],
      },
      is_create=False,
      async_mode=True,
    )

    self.assertIn("source='shmem'", response[DEEPLOY_KEYS.ERROR])
    self.assertEqual(called["delete"], 0)
    self.assertEqual(called["deploy"], 0)

  def test_handle_error_redacts_per_node_config_recursively(self):
    plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    plugin.cfg_deeploy_verbose = 0
    log_lines = []
    plugin.Pd = lambda message, **kwargs: log_lines.append(message)

    request = {
      "perNodeConfig": {"node-1": {"secret": "top-secret"}},
      "plugins": [
        {
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          "PER_NODE_CONFIG": {"node-1": {"secret": "nested-secret"}},
        },
      ],
    }

    response = plugin._DeeployManagerApiPlugin__handle_error(ValueError("boom"), request)

    self.assertEqual(response[DEEPLOY_KEYS.REQUEST]["perNodeConfig"], "***")
    self.assertEqual(response[DEEPLOY_KEYS.REQUEST]["plugins"][0]["PER_NODE_CONFIG"], "***")
    self.assertNotIn("top-secret", str(response))
    self.assertNotIn("nested-secret", str(response))
    self.assertNotIn("top-secret", "\n".join(log_lines))
    self.assertNotIn("nested-secret", "\n".join(log_lines))

  def test_update_pipeline_log_redacts_per_node_config(self):
    plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    log_lines = []
    plugin.P = lambda message, **kwargs: log_lines.append(message)
    plugin.json_dumps = lambda payload, **kwargs: str(payload)
    plugin._process_pipeline_request = lambda request, **kwargs: {"ok": True}

    response = plugin.update_pipeline(
      {
        DEEPLOY_KEYS.APP_ID: "app-123",
        "perNodeConfig": {"node-1": {"secret": "top-secret"}},
        "nested": {"PER_NODE_CONFIG": {"node-1": {"secret": "nested-secret"}}},
      }
    )

    self.assertEqual(response, {"ok": True})
    self.assertIn("***", "\n".join(log_lines))
    self.assertNotIn("top-secret", "\n".join(log_lines))
    self.assertNotIn("nested-secret", "\n".join(log_lines))

  def test_prepare_single_plugin_instance_update_materializes_per_node_config(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-6",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "WORKER_APP_RUNNER",
        "IMAGE": "node:22",
        "VCS_DATA": {
          "REPO_OWNER": "ratio1",
          "REPO_NAME": "demo",
          "BRANCH": "main",
        },
        "perNodeConfig": {
          "0xai_node_b": {
            "VCS_DATA": {"BRANCH": "develop"},
            "ENV": {"WORKER_NODE": "node-b"},
          },
        },
      },
    )

    materialized = plugin._materialize_plugins_for_node([prepared], "0xai_node_b", 1)

    instance = materialized[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["VCS_DATA"]["REPO_OWNER"], "ratio1")
    self.assertEqual(instance["VCS_DATA"]["REPO_NAME"], "demo")
    self.assertEqual(instance["VCS_DATA"]["BRANCH"], "develop")
    self.assertEqual(instance["ENV"], {"WORKER_NODE": "node-b"})
    self.assertNotIn("perNodeConfig", instance)

  def test_per_node_config_update_uses_persisted_target_node_order(self):
    plugin = make_deeploy_plugin()

    ordered = plugin._ordered_nodes_for_per_node_config(
      nodes=["0xai_node_b", "0xai_node_a"],
      dct_deeploy_specs={DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["0xai_node_a", "0xai_node_b"]},
    )

    self.assertEqual(ordered, ["0xai_node_a", "0xai_node_b"])

  def test_update_pipeline_reuses_requested_instance_config_for_duplicate_node_instances(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 123.0
    plugin._ensure_deeploy_specs_job_config = lambda specs, pipeline_params=None: specs
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: None
    captures = []

    def start_pipeline(**kwargs):
      captures.append({
        "node": kwargs["node_address"],
        "plugins": kwargs["plugins"],
      })
      return {"node": kwargs["node_address"], "plugins": kwargs["plugins"]}

    plugin.cmdapi_start_pipeline_by_params = start_pipeline
    nodes = ["0xai_node_a", "0xai_node_b"]
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          instance_id="shared-instance",
          plugin_name="shared-service",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          ENV={"BASE": "1"},
          perNodeConfig={
            "byIndex": {
              "0": {"ENV": {"NODE_INDEX": "0"}},
              "1": {"ENV": {"NODE_INDEX": "1"}},
            },
            "byNode": {
              "0xai_node_b": {"ENV": {"NODE_NAME": "node-b"}},
            },
          },
        ),
      ],
      pipeline_input_uri="",
      chainstore_response=False,
      job_tags=[],
      spare_nodes=[],
      allow_replication_in_the_wild=False,
    )
    discovered_plugin_instances = [
      {
        DEEPLOY_PLUGIN_DATA.NODE: node,
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "shared-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "signature": "CONTAINER_APP_RUNNER",
          "instance_conf": {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "shared-instance",
            "plugin_name": "shared-service",
            "IMAGE": "repo/old:latest",
          },
        },
      }
      for node in nodes
    ]

    plugin._DeeployMixin__update_pipeline_on_nodes(
      nodes=nodes,
      inputs=inputs,
      app_id="app-1",
      app_alias="App 1",
      app_type="Void",
      owner="owner",
      discovered_plugin_instances=discovered_plugin_instances,
      dct_deeploy_specs={DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes},
      job_app_type=JOB_APP_TYPES.SERVICE,
    )

    self.assertEqual(len(captures), 2)
    by_node = {
      capture["node"]: capture["plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
      for capture in captures
    }
    self.assertEqual(by_node["0xai_node_a"]["ENV"], {"BASE": "1"})
    self.assertEqual(by_node["0xai_node_b"]["ENV"], {"BASE": "1"})
    self.assertIn("PER_NODE_CONFIG", by_node["0xai_node_a"])
    self.assertIn("PER_NODE_CONFIG", by_node["0xai_node_b"])
    self.assertEqual(
      by_node["0xai_node_a"]["PER_NODE_CONFIG"],
      by_node["0xai_node_b"]["PER_NODE_CONFIG"],
    )
    self.assertEqual(by_node["0xai_node_a"]["PER_NODE_TARGET_NODES"], nodes)
    self.assertEqual(by_node["0xai_node_b"]["PER_NODE_TARGET_NODES"], nodes)

  def test_update_partial_operation_uses_full_per_node_target_order(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1000
    plugin._ensure_deeploy_specs_job_config = lambda specs, pipeline_params=None: specs
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: True
    captures = []

    def start_pipeline(**kwargs):
      captures.append({
        "node": kwargs["node_address"],
        "plugins": kwargs["plugins"],
      })
      return {"node": kwargs["node_address"], "plugins": kwargs["plugins"]}

    plugin.cmdapi_start_pipeline_by_params = start_pipeline
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          instance_id="shared-instance",
          plugin_name="shared-service",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          ENV={"BASE": "1"},
          perNodeConfig={
            "byIndex": {
              "1": {"ENV": {"NODE_INDEX": "1"}},
            },
          },
        ),
      ],
      pipeline_input_uri="",
      chainstore_response=False,
      job_tags=[],
      spare_nodes=[],
      allow_replication_in_the_wild=False,
    )
    discovered_plugin_instances = [
      {
        DEEPLOY_PLUGIN_DATA.NODE: "0xai_node_b",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "shared-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "signature": "CONTAINER_APP_RUNNER",
          "instance_conf": {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "shared-instance",
            "plugin_name": "shared-service",
            "IMAGE": "repo/old:latest",
          },
        },
      }
    ]

    plugin._DeeployMixin__update_pipeline_on_nodes(
      nodes=["0xai_node_b"],
      inputs=inputs,
      app_id="app-1",
      app_alias="App 1",
      app_type="Void",
      owner="owner",
      discovered_plugin_instances=discovered_plugin_instances,
      dct_deeploy_specs={DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["0xai_node_a", "0xai_node_b"]},
      job_app_type=JOB_APP_TYPES.SERVICE,
    )

    instance = captures[0]["plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["ENV"], {"BASE": "1"})
    self.assertEqual(instance["CHAINSTORE_PEERS"], ["0xai_node_a", "0xai_node_b"])
    self.assertEqual(instance["PER_NODE_TARGET_NODES"], ["0xai_node_a", "0xai_node_b"])
    self.assertEqual(instance["PER_NODE_CONFIG"]["byIndex"], {"1": {"ENV": {"NODE_INDEX": "1"}}})

  def test_scale_up_prepare_refreshes_full_per_node_target_order(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1000
    base_pipeline = {
      "app_id": "app-1",
      "pipeline_type": "Void",
      "url": "",
      "pipeline_params": {},
      "deeploy_specs": {
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["0xai_node_a", "0xai_node_b"],
        DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
      },
      "plugins": [
        {
          "SIGNATURE": "CONTAINER_APP_RUNNER",
          "INSTANCES": [
            {
              "INSTANCE_ID": "stale-instance",
              "plugin_name": "db",
              "IMAGE": "repo/db:latest",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "128m"},
              "PER_NODE_TARGET_NODES": ["stale-node"],
              "PER_NODE_CONFIG": {
                "byIndex": {
                  "2": {"ENV": {"NODE_ID": "3"}},
                },
              },
            }
          ],
        }
      ],
    }
    running_apps_for_job = {
      "0xai_node_a": {
        "app-1": {
          "plugins": {
            "CONTAINER_APP_RUNNER": [
              {
                "instance": "existing-instance-a",
                "instance_conf": {"CHAINSTORE_RESPONSE_KEY": "resp-a"},
              }
            ],
          },
        },
      },
      "0xai_node_b": {
        "app-1": {
          "plugins": {
            "CONTAINER_APP_RUNNER": [
              {
                "instance": "existing-instance-b",
                "instance_conf": {"CHAINSTORE_RESPONSE_KEY": "resp-b"},
              }
            ],
          },
        },
      },
    }

    create_pipelines, update_pipelines, _response_keys = plugin.prepare_create_update_pipelines(
      base_pipeline=base_pipeline,
      new_nodes=["0xai_node_c"],
      update_nodes=["0xai_node_a", "0xai_node_b"],
      running_apps_for_job=running_apps_for_job,
    )

    expected_nodes = ["0xai_node_a", "0xai_node_b", "0xai_node_c"]
    created = create_pipelines["0xai_node_c"]["plugins"][0]["INSTANCES"][0]
    updated = update_pipelines["0xai_node_b"]["plugins"][0]["INSTANCES"][0]
    self.assertEqual(created["CHAINSTORE_PEERS"], expected_nodes)
    self.assertEqual(created["PER_NODE_TARGET_NODES"], expected_nodes)
    self.assertEqual(updated["CHAINSTORE_PEERS"], expected_nodes)
    self.assertEqual(updated["PER_NODE_TARGET_NODES"], expected_nodes)

  def test_scale_up_prepare_preserves_offline_persisted_targets(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1000
    base_pipeline = {
      "app_id": "app-1",
      "pipeline_type": "Void",
      "url": "",
      "pipeline_params": {},
      "deeploy_specs": {
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["online-node", "offline-node"],
        DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
      },
      "plugins": [{
        "SIGNATURE": "CONTAINER_APP_RUNNER",
        "INSTANCES": [{"INSTANCE_ID": "stale", "ENV": {}}],
      }],
    }
    running_apps = {
      "online-node": {
        "app-1": {
          "plugins": {
            "CONTAINER_APP_RUNNER": [{
              "instance": "existing",
              "instance_conf": {"CHAINSTORE_RESPONSE_KEY": "response"},
            }],
          },
        },
      },
    }

    create_pipelines, update_pipelines, _ = plugin.prepare_create_update_pipelines(
      base_pipeline=base_pipeline,
      new_nodes=["new-node"],
      update_nodes=["online-node"],
      running_apps_for_job=running_apps,
    )

    expected = ["online-node", "offline-node", "new-node"]
    self.assertEqual(
      create_pipelines["new-node"]["deeploy_specs"][DEEPLOY_KEYS.CURRENT_TARGET_NODES],
      expected,
    )
    self.assertEqual(
      update_pipelines["online-node"]["deeploy_specs"][DEEPLOY_KEYS.CURRENT_TARGET_NODES],
      expected,
    )


if __name__ == "__main__":
  unittest.main()
