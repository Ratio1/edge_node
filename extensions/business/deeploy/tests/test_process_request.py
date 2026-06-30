import copy
import sys
import types
import unittest

from naeural_core import constants as ct

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_STATUS


class _BasePluginStub:
  CONFIG = {"VALIDATION_RULES": {}}

  @staticmethod
  def endpoint(*_args, **_kwargs):
    def decorator(func):
      return func
    return decorator


_supervisor_module = types.ModuleType(
  "naeural_core.business.default.web_app.supervisor_fast_api_web_app"
)
_supervisor_module.SupervisorFastApiWebApp = _BasePluginStub
sys.modules[
  "naeural_core.business.default.web_app.supervisor_fast_api_web_app"
] = _supervisor_module

from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin


class _InputsStub(dict):
  def __getattr__(self, item):
    try:
      return self[item]
    except KeyError:
      raise KeyError(item)


class _BCStub:
  def __init__(self):
    self.submitted = []

  def node_addr_to_eth_addr(self, node):
    return f"eth_{node}"

  def submit_node_update(self, job_id, nodes):
    self.submitted.append((job_id, list(nodes)))


class _ProcessRequestStub(DeeployManagerApiPlugin):
  def __init__(self):
    pass

  def _DeeployManagerApiPlugin__ensure_eth_balance(self):
    return True

  def _get_response(self, dct_data):
    return dct_data

  def P(self, *args, **kwargs):
    return

  def Pd(self, *args, **kwargs):
    return

  def time(self):
    return 1_000.0

  def trace_info(self):
    return ""

  def json_dumps(self, obj, **kwargs):
    return str(obj)

  def deeploy_verify_and_get_inputs(self, request, request_type=None, **_kwargs):
    return "sender", _InputsStub(copy.deepcopy(request))

  def deeploy_get_auth_result(self, inputs):
    return {
      DEEPLOY_KEYS.ESCROW_OWNER: "owner",
      DEEPLOY_KEYS.SENDER_ESCROW: "escrow",
    }

  def deeploy_check_payment_and_job_owner(self, inputs, owner, is_create=False, debug=False):
    return True

  def _check_nodes_availability(self, inputs, skip_resource_check=False):
    return list(inputs[DEEPLOY_KEYS.TARGET_NODES])

  def _ensure_deeploy_specs_job_config(self, specs, pipeline_params=None):
    return specs

  def _queue_pipeline_persistence(self, persistence_state):
    self.queued_persistence = persistence_state
    return True


class DeeployProcessRequestTests(unittest.TestCase):

  def test_create_pipeline_accepts_ui_cockroach_single_plugin_top_level_per_node_config(self):
    plugin = _ProcessRequestStub.__new__(_ProcessRequestStub)
    plugin.ct = ct
    plugin.bc = _BCStub()
    plugin.deepcopy = copy.deepcopy
    plugin.sanitize_name = lambda value: str(value).replace("/", "_").replace(" ", "_")
    plugin.uuid = lambda size=7: "abc1234"[:size]
    plugin.cfg_deeploy_verbose = 0
    plugin.queued_persistence = None
    captured = {}

    def check_and_deploy_pipelines(**kwargs):
      captured.update(kwargs)
      captured["prepared_plugins"] = plugin.deeploy_prepare_plugins(kwargs["inputs"])
      return {}, DEEPLOY_STATUS.COMMAND_DELIVERED, {}, {
        "CONFIG_STREAMS": [{"NAME": kwargs["app_id"]}],
      }

    plugin.check_and_deploy_pipelines = check_and_deploy_pipelines
    request = {
      DEEPLOY_KEYS.APP_ALIAS: "cockroachdb",
      DEEPLOY_KEYS.TARGET_NODES: ["0xai_node_a", "0xai_node_b"],
      DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
      DEEPLOY_KEYS.PIPELINE_INPUT_URI: None,
      DEEPLOY_KEYS.PIPELINE_PARAMS: {
        "deeploy_cockroachdb": {
          "version": 1,
          "service": "cockroachdb",
        },
      },
      DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
      DEEPLOY_KEYS.JOB_APP_TYPE: "service",
      DEEPLOY_KEYS.JOB_ID: 97,
      DEEPLOY_KEYS.RETURN_REQUEST: True,
      DEEPLOY_KEYS.PLUGINS: [{
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "IMAGE": "ghcr.io/ratio1/deeploy-cockroachdb-service:main",
        "CONTAINER_RESOURCES": {"cpu": 1, "memory": "2g", "storage": "8g"},
        "ENV": {"CRDB_MAX_OFFSET": "500ms"},
      }],
      "PER_NODE_CONFIG": {
        "byNode": {
          "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1", "CF_TUNNEL_TOKEN": "token-a"}},
          "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2", "CF_TUNNEL_TOKEN": "token-b"}},
        },
      },
    }

    res = plugin._process_pipeline_request(request, is_create=True, async_mode=True)

    self.assertEqual(res[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.COMMAND_DELIVERED)
    deployed_inputs = captured["inputs"]
    self.assertNotIn("PER_NODE_CONFIG", deployed_inputs)
    deployed_plugin = deployed_inputs[DEEPLOY_KEYS.PLUGINS][0]
    prepared_plugin = captured["prepared_plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(
      deployed_plugin["PER_NODE_CONFIG"]["byNode"]["0xai_node_b"]["ENV"]["CRDB_NODE_ID"],
      "2",
    )
    self.assertEqual(
      prepared_plugin["PER_NODE_CONFIG"]["byNode"]["0xai_node_b"]["ENV"]["CRDB_NODE_ID"],
      "2",
    )
    self.assertEqual(plugin.bc.submitted, [(97, ["eth_0xai_node_a", "eth_0xai_node_b"])])
    self.assertIn("token-a", str(res[DEEPLOY_KEYS.REQUEST]))
    self.assertIn("token-b", str(res[DEEPLOY_KEYS.REQUEST]))
    self.assertIsInstance(res[DEEPLOY_KEYS.REQUEST]["PER_NODE_CONFIG"], dict)

  def test_error_handler_redacts_secret_request_values(self):
    plugin = _ProcessRequestStub.__new__(_ProcessRequestStub)
    plugin.deepcopy = copy.deepcopy
    plugin.cfg_deeploy_verbose = 0
    request = {
      DEEPLOY_KEYS.PLUGINS: [{
        "EXPOSED_PORTS": {
          "26257": {
            "token": "cf-token",
            "protocol": "tcp",
          },
        },
        "PER_NODE_CONFIG": {
          "byNode": {
            "0xai_node_a": {"ENV": {"CF_TUNNEL_TOKEN": "node-token"}},
          },
        },
      }],
    }

    res = plugin._DeeployManagerApiPlugin__handle_error(ValueError("boom"), request)

    serialized = str(res)
    self.assertNotIn("cf-token", serialized)
    self.assertNotIn("node-token", serialized)
    self.assertIn("'token': '***'", serialized)
    self.assertIn("'PER_NODE_CONFIG': '***'", serialized)


if __name__ == "__main__":
  unittest.main()
