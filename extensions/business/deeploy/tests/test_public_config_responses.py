import sys
import types
import unittest

from naeural_core import constants as ct

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_STATUS


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

from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin


class _InputsStub(dict):
  def __getattr__(self, item):
    try:
      return self[item]
    except KeyError as exc:
      raise AttributeError(item) from exc


def make_api_plugin(request_inputs=None):
  plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
  plugin.ct = ct
  plugin.cfg_deeploy_verbose = 0
  plugin.P = lambda *args, **kwargs: None
  plugin.Pd = lambda *args, **kwargs: None
  plugin.trace_info = lambda: ""
  plugin._get_response = lambda dct_data: dct_data
  plugin.deeploy_verify_and_get_inputs = lambda request, **kwargs: (
    "0xSender",
    _InputsStub(request_inputs if request_inputs is not None else request),
  )
  plugin.deeploy_get_auth_result = lambda inputs: {
    DEEPLOY_KEYS.SENDER: "0xSender",
    DEEPLOY_KEYS.SENDER_ESCROW: "0xEscrow",
    DEEPLOY_KEYS.ESCROW_OWNER: "0xOwner",
  }
  plugin._DeeployManagerApiPlugin__ensure_eth_balance = lambda: None
  return plugin


class DeeployPublicConfigResponseTests(unittest.TestCase):

  def test_get_apps_returns_config_values_without_public_redaction(self):
    plugin = make_api_plugin()
    app_payload = [{
      "APP_ID": "app-1",
      "ENV": {
        "PASSWORD": "db-password",
        "CF_TUNNEL_TOKEN": "cf-token",
      },
      "PER_NODE_CONFIG": {
        "byNode": {
          "0xai_node_a": {"ENV": {"CRDB_NODE_KEY": "node-key"}},
        },
      },
    }]
    plugin._get_apps_by_escrow_active_jobs = lambda **kwargs: app_payload

    response = plugin.get_apps({DEEPLOY_KEYS.PROJECT_ID: "project-1"})

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(response[DEEPLOY_KEYS.APPS], app_payload)
    serialized = str(response)
    self.assertIn("db-password", serialized)
    self.assertIn("cf-token", serialized)
    self.assertIn("node-key", serialized)

  def test_get_r1fs_job_pipeline_returns_config_values_without_public_redaction(self):
    pipeline = {
      "OWNER": "0xOwner",
      "PLUGINS": [{
        "INSTANCES": [{
          "ENV": {
            "CRDB_PASSWORD": "db-password",
            "CF_TUNNEL_TOKEN": "cf-token",
          },
          "PER_NODE_CONFIG": {
            "byNode": {
              "0xai_node_a": {"ENV": {"CRDB_NODE_KEY": "node-key"}},
            },
          },
        }],
      }],
    }
    plugin = make_api_plugin({DEEPLOY_KEYS.JOB_ID: 42})
    plugin.get_job_pipeline_from_cstore = lambda job_id: pipeline

    response = plugin.get_r1fs_job_pipeline({DEEPLOY_KEYS.JOB_ID: 42})

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(response[DEEPLOY_KEYS.PIPELINE], pipeline)
    serialized = str(response)
    self.assertIn("db-password", serialized)
    self.assertIn("cf-token", serialized)
    self.assertIn("node-key", serialized)

  def test_delete_pipeline_returns_discovered_targets_without_public_redaction(self):
    plugin = make_api_plugin({
      DEEPLOY_KEYS.APP_ID: "app-1",
      DEEPLOY_KEYS.TARGET_NODES: ["0xai_node_a"],
    })
    targets = [{
      "node": "0xai_node_a",
      "instance_conf": {
        "ENV": {"API_KEY": "service-key"},
        "PER_NODE_CONFIG": {"byNode": {"0xai_node_a": {"ENV": {"TOKEN": "node-token"}}}},
      },
    }]
    plugin.delete_pipeline_from_nodes = lambda **kwargs: targets

    response = plugin.delete_pipeline({
      DEEPLOY_KEYS.APP_ID: "app-1",
      DEEPLOY_KEYS.TARGET_NODES: ["0xai_node_a"],
    })

    request_payload = response[DEEPLOY_KEYS.REQUEST]
    self.assertEqual(request_payload[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(request_payload[DEEPLOY_KEYS.TARGETS], targets)
    serialized = str(response)
    self.assertIn("service-key", serialized)
    self.assertIn("node-token", serialized)


if __name__ == "__main__":
  unittest.main()
