import unittest
from copy import deepcopy
from pathlib import Path

from extensions.business.dauth.dauth_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY,
  DEEPLOY_JOBS_CSTORE_HKEY,
  _DauthMixin,
)


ROOT = Path(__file__).resolve().parents[3]


class _FakeBasePlugin:
  CONFIG = {"VALIDATION_RULES": {}}

  @staticmethod
  def endpoint(method="get", require_token=False):  # pylint: disable=unused-argument
    def decorator(func):
      return func
    return decorator

  def on_init(self):
    return None

  def _process(self):
    return "base-process"


class _FakeDauthMixin:
  pass


class _FakeNodeTagsMixin:
  pass


class _FakeRequestTrackingMixin:
  pass


def _load_dauth_manager_class():
  source_path = ROOT / "extensions" / "business" / "dauth" / "dauth_manager.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.business.mixins.node_tags_mixin import _NodeTagsMixin\n",
    "",
  )
  source = source.replace(
    "from naeural_core.business.default.web_app.supervisor_fast_api_web_app import SupervisorFastApiWebApp as BasePlugin\n",
    "",
  )
  source = source.replace(
    "from extensions.business.mixins.request_tracking_mixin import _RequestTrackingMixin\n",
    "",
  )
  source = source.replace(
    "from extensions.business.dauth.dauth_mixin import _DauthMixin\n",
    "",
  )
  namespace = {
    "BasePlugin": _FakeBasePlugin,
    "_DauthMixin": _FakeDauthMixin,
    "_NodeTagsMixin": _FakeNodeTagsMixin,
    "_RequestTrackingMixin": _FakeRequestTrackingMixin,
    "__name__": "loaded_dauth_manager",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["DauthManagerPlugin"]


DauthManagerPlugin = _load_dauth_manager_class()


class _FakeDauthConst:
  DAUTH_ENV_KEYS_PREFIX = "EE_"
  DAUTH_WHITELIST = "DAUTH_WHITELIST"


class _FakeBCBaseConst:
  SENDER = "EE_SENDER"
  ETH_SENDER = "EE_ETH_SENDER"


class _FakeBaseConst:
  BCctbase = _FakeBCBaseConst
  dAuth = _FakeDauthConst


class _FakeConst:
  BASE_CT = _FakeBaseConst
  ADMIN_PIPELINE = {
    "DAUTH_MANAGER": {
      "AUTH_ENV_KEYS": [],
      "AUTH_NODE_ENV_KEYS": [],
      "AUTH_PREDEFINED_KEYS": {},
    }
  }


class _FakeBC:

  def __init__(self, *, dauth_oracle=True, protocol_oracles=None, valid_signature=True):
    self.dauth_oracle = dauth_oracle
    self.protocol_oracles = protocol_oracles or ["node-oracle"]
    self.valid_signature = valid_signature
    self.node_eth = {
      "node-oracle": "0xORACLE",
      "node-runner": "0xRUNNER",
      "node-other": "0xOTHER",
    }

  def get_oracles(self, include_eth_addrs=False):
    names = ["Oracle"] * len(self.protocol_oracles)
    eth_addresses = ["0xDAUTH"] * len(self.protocol_oracles)
    if include_eth_addrs:
      return self.protocol_oracles, names, eth_addresses
    return self.protocol_oracles, names

  def get_whitelist_with_names(self):
    return [], []

  def is_dauth_oracle(self, node_address_eth=None):  # pylint: disable=unused-argument
    if isinstance(self.dauth_oracle, Exception):
      raise self.dauth_oracle
    return self.dauth_oracle

  def get_eth_oracles(self):
    return [self.node_eth.get(node, "0xORACLE") for node in self.protocol_oracles]

  def node_address_to_eth_address(self, node_address):
    return self.node_eth[node_address]

  def verify(self, body, return_full_info=False):  # pylint: disable=unused-argument
    class _VerifyData:
      pass

    data = _VerifyData()
    data.valid = self.valid_signature
    data.message = "ok" if self.valid_signature else "bad signature"
    return data

  def maybe_add_prefix(self, node_address):
    if node_address.startswith("0xai_"):
      return node_address
    return "0xai_" + node_address


class _FakeR1FS:

  def __init__(self, data):
    self.data = data

  def get_json(self, cid, show_logs=False):  # pylint: disable=unused-argument
    return self.data[cid]


class _DauthHarness(_DauthMixin):
  pass


def _make_dauth_harness(*, dauth_oracle=True, protocol_oracles=None, valid_signature=True):
  plugin = _DauthHarness()
  plugin.const = _FakeConst
  plugin.bc = _FakeBC(
    dauth_oracle=dauth_oracle,
    protocol_oracles=protocol_oracles,
    valid_signature=valid_signature,
  )
  plugin.deepcopy = deepcopy
  plugin._chainstore = {}
  plugin._r1fs_data = {}
  plugin.r1fs = _FakeR1FS(plugin._r1fs_data)
  plugin.evm_network = "devnet"
  plugin.cfg_auth_env_keys = []
  plugin.cfg_auth_node_env_keys = []
  plugin.cfg_auth_predefined_keys = {}
  plugin.cfg_supervisor_keys = [
    "EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER",
    "EE_NGROK_EDGE_LABEL_DAUTH_MANAGER",
    "EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER",
  ]
  plugin.cfg_dauth_oracle_only_supervisor_keys = [
    "EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER",
  ]
  plugin.cfg_comms_host_key = "EE_MQTT_HOST"
  plugin.cfg_comms_host_seed_key = "EE_MQTT_HOST_SEED"
  plugin.cfg_dauth_log_response = False
  plugin.cfg_dauth_verbose = False
  plugin.os_environ = {
    "EE_MQTT_HOST_SEED": "mqtt-a",
    "EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER": "cloudflare-secret",
    "EE_NGROK_EDGE_LABEL_DAUTH_MANAGER": "ngrok-label",
    "EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER": "deeploy-secret",
  }
  plugin.fetch_node_tags = lambda node_address_eth=None: {}
  plugin.P = lambda *args, **kwargs: None
  plugin.Pd = lambda *args, **kwargs: None
  plugin.chainstore_hset = lambda hkey, key, value: plugin._chainstore.__setitem__(
    (hkey, str(key)),
    deepcopy(value),
  ) or True
  plugin.chainstore_hget = lambda hkey, key: plugin._chainstore.get((hkey, str(key)))
  return plugin


class DauthRegistrySecretGatingTests(unittest.TestCase):

  def test_supervisor_keys_are_sent_to_protocol_oracles_registered_for_dauth(self):
    plugin = _make_dauth_harness(dauth_oracle=True)

    data = plugin.fill_dauth_data(
      dauth_data={},
      requester_node_address="node-oracle",
      is_node=True,
      sender_eth_address="0xDAUTH",
    )

    self.assertTrue(data["EE_SUPERVISOR"])
    self.assertEqual(data["EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER"], "cloudflare-secret")
    self.assertEqual(data["EE_NGROK_EDGE_LABEL_DAUTH_MANAGER"], "ngrok-label")
    self.assertEqual(data["EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER"], "deeploy-secret")

  def test_only_dauth_token_is_omitted_for_protocol_oracles_not_registered_for_dauth(self):
    plugin = _make_dauth_harness(dauth_oracle=False)

    data = plugin.fill_dauth_data(
      dauth_data={},
      requester_node_address="node-oracle",
      is_node=True,
      sender_eth_address="0xOTHER",
    )

    self.assertTrue(data["EE_SUPERVISOR"])
    self.assertNotIn("EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER", data)
    self.assertEqual(data["EE_NGROK_EDGE_LABEL_DAUTH_MANAGER"], "ngrok-label")
    self.assertEqual(data["EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER"], "deeploy-secret")

  def test_supervisor_keys_still_require_protocol_oracle_membership(self):
    plugin = _make_dauth_harness(dauth_oracle=True, protocol_oracles=["node-other"])

    data = plugin.fill_dauth_data(
      dauth_data={},
      requester_node_address="node-oracle",
      is_node=True,
      sender_eth_address="0xDAUTH",
    )

    self.assertFalse(data["EE_SUPERVISOR"])
    self.assertNotIn("EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER", data)
    self.assertNotIn("EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER", data)

  def test_dauth_token_fails_closed_when_dauth_registry_check_fails(self):
    plugin = _make_dauth_harness(dauth_oracle=RuntimeError("registry unavailable"))

    data = plugin.fill_dauth_data(
      dauth_data={},
      requester_node_address="node-oracle",
      is_node=True,
      sender_eth_address="0xDAUTH",
    )

    self.assertTrue(data["EE_SUPERVISOR"])
    self.assertNotIn("EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER", data)
    self.assertEqual(data["EE_NGROK_EDGE_LABEL_DAUTH_MANAGER"], "ngrok-label")
    self.assertEqual(data["EE_CLOUDFLARE_TOKEN_DEEPLOY_MANAGER"], "deeploy-secret")


class DauthJobSecretEndpointTests(unittest.TestCase):

  def test_add_secrets_allows_protocol_oracle_and_overwrites_bundle(self):
    plugin = _make_dauth_harness(protocol_oracles=["node-oracle"])
    plugin._chainstore[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")] = {
      "job_id": "7",
      "old": True,
    }
    body = {
      "EE_SENDER": "node-oracle",
      "EE_ETH_SENDER": "0xORACLE",
      "job_id": 7,
      "plugin_secrets": {
        "plugins": {
          "CONTAINER_APP_RUNNER": [{
            "instance_conf": {
              "ENV": {
                "API_KEY": "secret",
              },
            },
          }],
        },
      },
    }

    response = plugin.process_dauth_add_secrets_request(body)

    self.assertEqual(response["status"], "success")
    self.assertEqual(response["job_id"], "7")
    self.assertEqual(
      plugin._chainstore[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")],
      {
        "job_id": "7",
        "plugin_secrets": body["plugin_secrets"],
      },
    )

  def test_add_secrets_rejects_non_oracle_writer(self):
    plugin = _make_dauth_harness(protocol_oracles=["node-oracle"])
    body = {
      "EE_SENDER": "node-runner",
      "EE_ETH_SENDER": "0xRUNNER",
      "job_id": "7",
      "plugin_secrets": {"plugins": {}},
    }

    with self.assertRaisesRegex(ValueError, "not an oracle"):
      plugin.process_dauth_add_secrets_request(body)

    self.assertNotIn((DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"), plugin._chainstore)

  def test_add_secrets_rejects_invalid_signature(self):
    plugin = _make_dauth_harness(valid_signature=False)
    body = {
      "EE_SENDER": "node-oracle",
      "EE_ETH_SENDER": "0xORACLE",
      "job_id": "7",
      "plugin_secrets": {"plugins": {}},
    }

    with self.assertRaisesRegex(ValueError, "Invalid request signature"):
      plugin.process_dauth_add_secrets_request(body)

    self.assertNotIn((DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"), plugin._chainstore)

  def test_get_secrets_returns_bundle_for_node_running_job_from_r1fs_pipeline(self):
    plugin = _make_dauth_harness()
    bundle = {
      "job_id": "7",
      "plugin_secrets": {
        "plugins": {
          "CONTAINER_APP_RUNNER": [{
            "instance_conf": {
              "ENV": {
                "API_KEY": "secret",
              },
            },
          }],
        },
      },
    }
    plugin._chainstore[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")] = bundle
    plugin._chainstore[(DEEPLOY_JOBS_CSTORE_HKEY, "7")] = "cid-7"
    plugin._r1fs_data["cid-7"] = {
      "deeploy_specs": {
        "current_target_nodes": ["node-runner"],
      },
    }
    body = {
      "EE_SENDER": "node-runner",
      "EE_ETH_SENDER": "0xRUNNER",
      "job_id": "7",
    }

    response = plugin.process_dauth_get_secret_request(body)

    self.assertEqual(response["status"], "success")
    self.assertEqual(response["job_id"], "7")
    self.assertEqual(response["secret_bundle"], bundle)

  def test_get_secrets_rejects_node_not_running_job(self):
    plugin = _make_dauth_harness()
    plugin._chainstore[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")] = {
      "job_id": "7",
      "plugin_secrets": {"plugins": {}},
    }
    plugin._chainstore[(DEEPLOY_JOBS_CSTORE_HKEY, "7")] = "cid-7"
    plugin._r1fs_data["cid-7"] = {
      "DEEPLOY_SPECS": {
        "current_target_nodes": ["node-runner"],
      },
    }
    body = {
      "EE_SENDER": "node-other",
      "EE_ETH_SENDER": "0xOTHER",
      "job_id": "7",
    }

    with self.assertRaisesRegex(ValueError, "not running job"):
      plugin.process_dauth_get_secret_request(body)


class DauthServerRegistryGateTests(unittest.TestCase):

  def _make_manager(self, *, dauth_oracle):
    class _ManagerBC:
      def __init__(self, result):
        self.result = result
        self.calls = 0

      def is_dauth_oracle(self):
        self.calls += 1
        return self.result

    plugin = DauthManagerPlugin.__new__(DauthManagerPlugin)
    plugin.bc = _ManagerBC(dauth_oracle)
    plugin._dauth_server_enabled = None
    plugin._dauth_server_enabled_message = None
    plugin._stopped_tunnels = 0
    plugin._messages = []
    plugin.time = lambda: 1000
    plugin.P = lambda msg, *args, **kwargs: plugin._messages.append(msg)
    plugin.maybe_stop_tunnel_engine = lambda: setattr(
      plugin,
      "_stopped_tunnels",
      plugin._stopped_tunnels + 1,
    )
    return plugin

  def test_process_stops_before_web_app_work_when_current_node_is_not_dauth_oracle(self):
    plugin = self._make_manager(dauth_oracle=False)

    self.assertFalse(plugin._check_dauth_server_enabled_on_start())  # pylint: disable=protected-access
    self.assertIsNone(plugin._process())  # pylint: disable=protected-access
    self.assertEqual(plugin.bc.calls, 1)
    self.assertEqual(plugin._stopped_tunnels, 1)

  def test_process_continues_to_web_app_work_when_current_node_is_dauth_oracle(self):
    plugin = self._make_manager(dauth_oracle=True)

    self.assertTrue(plugin._check_dauth_server_enabled_on_start())  # pylint: disable=protected-access
    self.assertEqual(plugin._process(), "base-process")  # pylint: disable=protected-access
    self.assertEqual(plugin.bc.calls, 1)
    self.assertEqual(plugin._stopped_tunnels, 0)


if __name__ == "__main__":
  unittest.main()
