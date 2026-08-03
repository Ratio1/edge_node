from collections import deque
import json
import queue
import threading
import unittest
from copy import deepcopy
from pathlib import Path

from extensions.business.dauth.dauth_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY,
  DEEPLOY_JOBS_CSTORE_HKEY,
  _DauthMixin,
)
from extensions.business.dauth.dauth_registry import load_dauth_registry_snapshot


ROOT = Path(__file__).resolve().parents[3]
REQUEST_TIME = 1_700_000_000
REQUEST_NONCE = hex(REQUEST_TIME * 1000)


class _FakeProcess:

  def __init__(self):
    self.running = True

  def poll(self):
    return None if self.running else 0


class _FakeThread:

  def __init__(self):
    self.running = True

  def join(self, timeout=None):  # pylint: disable=unused-argument
    self.running = False

  def is_alive(self):
    return self.running


class _FakeBasePlugin:
  CONFIG = {"VALIDATION_RULES": {}}

  @staticmethod
  def endpoint(method="get", require_token=False):  # pylint: disable=unused-argument
    def decorator(func):
      return func
    return decorator

  def on_init(self):
    self._base_init_calls += 1
    self._lifecycle_events.append("base_init")
    self._stop_request_monitor = threading.Event()
    self._request_monitor_thread = _FakeThread()
    self._incoming_lock = threading.Lock()
    self._incoming_requests = deque(["incoming"])
    self.postponed_requests = deque(["postponed"])
    self._server_queue = queue.Queue()
    self._server_queue.put("server")
    self.start_commands_started = [True, True]
    self.start_commands_finished = [True, True]
    self.start_commands_processes = [_FakeProcess(), _FakeProcess()]
    self.start_commands_start_time = [10, 20]
    self.tunnel_engine_started = True
    self.failed = False
    return None

  def get_start_commands(self):
    return ["uvicorn", "cloudflared"]

  def _maybe_close_start_commands(self):
    self._lifecycle_events.append("stop_commands")
    for process in self.start_commands_processes:
      if process is not None:
        process.running = False
    # endfor
    return

  def _maybe_read_and_stop_all_log_readers(self):
    self._lifecycle_events.append("stop_log_readers")
    return

  def maybe_stop_tunnel_engine(self):
    self._lifecycle_events.append("stop_tunnel")
    self.tunnel_engine_started = False
    return

  def reset_tunnel_engine(self):
    self._lifecycle_events.append("reset_tunnel")
    return

  def _start_request_monitor_thread(self):
    self._lifecycle_events.append("start_monitor")
    self._request_monitor_thread = _FakeThread()
    return

  def set_plugin_ready(self, ready=True):
    self._is_plugin_ready = ready
    return

  def on_log_handler(self, text, key=None):  # pylint: disable=unused-argument
    self._lifecycle_events.append("log")
    return


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
    "from extensions.business.dauth.dauth_mixin import (\n"
    "  DAUTH_JOB_SECRETS_CSTORE_HKEY,\n"
    "  _DauthMixin,\n"
    ")\n",
    "",
  )
  source = source.replace(
    "from extensions.business.dauth.dauth_registry import (\n"
    "  dauth_registry_write_kwargs,\n"
    "  load_dauth_registry_snapshot,\n"
    ")\n",
    "",
  )
  namespace = {
    "BasePlugin": _FakeBasePlugin,
    "DAUTH_JOB_SECRETS_CSTORE_HKEY": DAUTH_JOB_SECRETS_CSTORE_HKEY,
    "_DauthMixin": _FakeDauthMixin,
    "_NodeTagsMixin": _FakeNodeTagsMixin,
    "_RequestTrackingMixin": _FakeRequestTrackingMixin,
    "dauth_registry_write_kwargs": (
      lambda plugin: {
        "extra_peers": list(plugin._dauth_registry_internal_peers),
        "include_default_peers": False,
        "include_configured_peers": False,
      }
    ),
    "load_dauth_registry_snapshot": load_dauth_registry_snapshot,
    "__name__": "loaded_dauth_manager",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["DauthManagerPlugin"]


DauthManagerPlugin = _load_dauth_manager_class()


class _FakeDauthConst:
  DAUTH_NONCE = "nonce"
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
    self.encrypt_calls = []
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

  def encrypt_str(self, str_data, str_recipient):
    self.encrypt_calls.append((str_data, str_recipient))
    return "encrypted-secret-bundle"


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
  plugin.json_dumps = json.dumps
  plugin.time = lambda: REQUEST_TIME
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
  plugin._dauth_registry_internal_peers = ["node-oracle"]
  plugin.chainstore_hset = lambda hkey, key, value, **kwargs: plugin._chainstore.__setitem__(
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

  def test_secret_request_nonce_accepts_only_last_120_seconds(self):
    plugin = _make_dauth_harness()

    self.assertEqual(
      plugin._validate_dauth_secret_request_nonce({"nonce": REQUEST_NONCE}),
      REQUEST_NONCE,
    )
    boundary_nonce = hex(int((REQUEST_TIME - 120) * 1000))
    self.assertEqual(
      plugin._validate_dauth_secret_request_nonce({"nonce": boundary_nonce}),
      boundary_nonce,
    )

    invalid_nonces = (
      ({}, "required"),
      ({"nonce": "not-hex"}, "invalid"),
      ({"nonce": hex(int((REQUEST_TIME + 1) * 1000))}, "future"),
      ({"nonce": hex(int((REQUEST_TIME - 121) * 1000))}, "expired"),
    )
    for body, message in invalid_nonces:
      with self.subTest(body=body):
        with self.assertRaisesRegex(ValueError, message):
          plugin._validate_dauth_secret_request_nonce(body)

  def test_add_secrets_allows_protocol_oracle_and_overwrites_bundle(self):
    plugin = _make_dauth_harness(protocol_oracles=["node-oracle"])
    plugin._chainstore[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")] = {
      "job_id": "7",
      "old": True,
    }
    body = {
      "EE_SENDER": "node-oracle",
      "EE_ETH_SENDER": "0xORACLE",
      "nonce": REQUEST_NONCE,
      "job_id": 7,
      "job_secrets": {
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
    self.assertEqual(response["nonce"], REQUEST_NONCE)
    self.assertEqual(
      plugin._chainstore[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")],
      {
        "job_id": "7",
        "job_secrets": body["job_secrets"],
      },
    )

  def test_add_secrets_rejects_non_oracle_writer(self):
    plugin = _make_dauth_harness(protocol_oracles=["node-oracle"])
    body = {
      "EE_SENDER": "node-runner",
      "EE_ETH_SENDER": "0xRUNNER",
      "nonce": REQUEST_NONCE,
      "job_id": "7",
      "job_secrets": {"plugins": {}},
    }

    with self.assertRaisesRegex(ValueError, "not an oracle"):
      plugin.process_dauth_add_secrets_request(body)

    self.assertNotIn((DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"), plugin._chainstore)

  def test_add_secrets_rejects_expired_nonce_before_write(self):
    plugin = _make_dauth_harness()
    body = {
      "EE_SENDER": "node-oracle",
      "EE_ETH_SENDER": "0xORACLE",
      "nonce": hex(int((REQUEST_TIME - 121) * 1000)),
      "job_id": "7",
      "job_secrets": {"plugins": {}},
    }

    with self.assertRaisesRegex(ValueError, "nonce is expired"):
      plugin.process_dauth_add_secrets_request(body)

    self.assertNotIn((DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"), plugin._chainstore)

  def test_add_secrets_rejects_invalid_signature(self):
    plugin = _make_dauth_harness(valid_signature=False)
    body = {
      "EE_SENDER": "node-oracle",
      "EE_ETH_SENDER": "0xORACLE",
      "nonce": REQUEST_NONCE,
      "job_id": "7",
      "job_secrets": {"plugins": {}},
    }

    with self.assertRaisesRegex(ValueError, "Invalid request signature"):
      plugin.process_dauth_add_secrets_request(body)

    self.assertNotIn((DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"), plugin._chainstore)

  def test_add_secrets_rejects_legacy_plugin_secrets_shape(self):
    plugin = _make_dauth_harness()
    body = {
      "EE_SENDER": "node-oracle",
      "EE_ETH_SENDER": "0xORACLE",
      "nonce": REQUEST_NONCE,
      "job_id": "7",
      "plugin_secrets": {"plugins": {}},
    }

    with self.assertRaisesRegex(ValueError, "job_secrets must be a dictionary"):
      plugin.process_dauth_add_secrets_request(body)

    self.assertNotIn((DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"), plugin._chainstore)

  def test_get_secrets_returns_bundle_for_node_running_job_from_r1fs_pipeline(self):
    plugin = _make_dauth_harness()
    bundle = {
      "job_id": "7",
      "job_secrets": {
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
      "nonce": REQUEST_NONCE,
      "job_id": "7",
    }

    response = plugin.process_dauth_get_secret_request(body)

    self.assertEqual(response["status"], "success")
    self.assertEqual(response["job_id"], "7")
    self.assertEqual(response["nonce"], REQUEST_NONCE)
    self.assertEqual(
      response["encrypted_secret_bundle"],
      "encrypted-secret-bundle",
    )
    self.assertNotIn("secret_bundle", response)
    self.assertEqual(
      plugin.bc.encrypt_calls,
      [(json.dumps(bundle), "node-runner")],
    )

  def test_get_secrets_rejects_node_not_running_job(self):
    plugin = _make_dauth_harness()
    plugin._chainstore[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")] = {
      "job_id": "7",
      "job_secrets": {"plugins": {}},
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
      "nonce": REQUEST_NONCE,
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

      def get_eth_dauth_oracles(self):
        self.calls += 1
        if isinstance(self.result, Exception):
          raise self.result
        if isinstance(self.result, list):
          return self.result
        return ["0xNODE", "0xPEER"] if self.result else ["0xPEER"]

      def eth_addr_to_internal_addr(self, eth_address):
        return {
          "0xnode": "node-address",
          "0xpeer": "peer-address",
          "0xnew": "new-peer-address",
        }.get(eth_address.lower())

    plugin = DauthManagerPlugin.__new__(DauthManagerPlugin)
    plugin.bc = _ManagerBC(dauth_oracle)
    plugin._dauth_server_enabled = None
    plugin._dauth_server_enabled_message = None
    plugin._dauth_web_app_initialized = False
    plugin._dauth_pause_teardown_succeeded = True
    plugin._base_init_calls = 0
    plugin._lifecycle_events = []
    plugin._messages = []
    plugin._now = 100.0
    plugin.P = lambda msg, *args, **kwargs: plugin._messages.append(msg)
    plugin.time = lambda: plugin._now
    plugin.sleep = lambda seconds: setattr(plugin, "_now", plugin._now + seconds)
    plugin.cfg_auth_env_keys = []
    plugin.cfg_auth_predefined_keys = {}
    plugin._init_request_tracking = lambda: None
    plugin.bc.address = "node-address"
    plugin.bc.eth_address = "0xNODE"
    plugin._dauth_registry_eth_oracles = None
    plugin._dauth_registry_internal_peers = None
    plugin._last_dauth_registry_refresh = None
    plugin._dauth_registry_refresh_failed = False
    plugin._last_dauth_job_secrets_hsync = None
    plugin.cfg_dauth_job_secrets_hsync_interval = 10 * 60
    plugin.cfg_dauth_registry_refresh_interval = 60 * 60
    plugin.cfg_dauth_registry_refresh_retry_interval = 60
    plugin._is_plugin_ready = None
    plugin._hsync_calls = []
    plugin.chainstore_hsync = lambda **kwargs: plugin._hsync_calls.append(kwargs) or {
      "hkey": kwargs["hkey"],
    }
    plugin._DauthManagerPlugin__get_response = lambda data: data
    return plugin

  def test_secret_endpoint_errors_echo_request_nonce(self):
    plugin = self._make_manager(dauth_oracle=True)
    plugin._dauth_server_enabled = True
    plugin.process_dauth_add_secrets_request = lambda body: (_ for _ in ()).throw(
      ValueError("add failed")
    )
    plugin.process_dauth_get_secret_request = lambda body: (_ for _ in ()).throw(
      ValueError("get failed")
    )
    body = {"nonce": REQUEST_NONCE}

    add_response = plugin.add_secrets(body)
    get_response = plugin.get_secrets(body)

    self.assertEqual(add_response["nonce"], REQUEST_NONCE)
    self.assertEqual(add_response["error"], "add failed")
    self.assertEqual(get_response["nonce"], REQUEST_NONCE)
    self.assertEqual(get_response["error"], "get failed")

  def test_registry_lookup_is_cached_between_hourly_lifecycle_refreshes(self):
    plugin = self._make_manager(dauth_oracle=True)

    plugin.on_init()

    self.assertFalse(plugin.should_pause())
    self.assertFalse(plugin.should_pause())
    self.assertTrue(plugin.should_resume())
    self.assertTrue(plugin.should_resume())
    self.assertTrue(plugin._check_dauth_server_enabled_on_start())  # pylint: disable=protected-access
    self.assertEqual(plugin.bc.calls, 1)
    self.assertEqual(plugin._base_init_calls, 1)
    self.assertEqual(plugin._lifecycle_events, ["base_init"])
    self.assertEqual(
      plugin._dauth_registry_internal_peers,
      ["node-address", "peer-address"],
    )

    plugin._now += (60 * 60) - 1
    self.assertFalse(plugin.should_pause())
    self.assertEqual(plugin.bc.calls, 1)

    plugin._now += 1
    self.assertFalse(plugin.should_pause())
    self.assertEqual(plugin.bc.calls, 2)

  def test_secret_hsync_runs_at_startup_and_every_ten_minutes_on_cached_peers(self):
    plugin = self._make_manager(dauth_oracle=True)

    plugin.on_init()
    plugin.process()
    plugin._now += (10 * 60) - 1
    plugin.process()
    plugin._now += 1
    plugin.process()

    self.assertEqual(plugin.bc.calls, 1)
    self.assertEqual(len(plugin._hsync_calls), 2)
    for call in plugin._hsync_calls:
      self.assertEqual(call["hkey"], DAUTH_JOB_SECRETS_CSTORE_HKEY)
      self.assertEqual(call["extra_peers"], ["node-address", "peer-address"])
      self.assertFalse(call["include_default_peers"])
      self.assertFalse(call["include_configured_peers"])

  def test_secret_hsync_failure_waits_until_next_interval(self):
    plugin = self._make_manager(dauth_oracle=True)
    attempts = []

    def fail_hsync(**kwargs):
      attempts.append(kwargs)
      raise ValueError("sync unavailable")

    plugin.chainstore_hsync = fail_hsync
    plugin.on_init()
    plugin.process()
    plugin._now += 10 * 60
    plugin.process()

    self.assertEqual(len(attempts), 2)
    self.assertTrue(any("sync unavailable" in message for message in plugin._messages))

  def test_false_startup_lookup_fails_closed_and_tears_down_fastapi(self):
    plugin = self._make_manager(dauth_oracle=False)

    plugin.on_init()

    self.assertTrue(plugin.should_pause())
    self.assertFalse(plugin.should_resume())
    self.assertEqual(plugin.bc.calls, 1)
    self.assertEqual(plugin._hsync_calls, [])
    self.assertTrue(plugin._stop_request_monitor.is_set())
    self.assertFalse(plugin._request_monitor_thread.is_alive())
    self.assertEqual(plugin.start_commands_started, [False, False])
    self.assertEqual(plugin.start_commands_finished, [False, False])
    self.assertEqual(plugin.start_commands_processes, [None, None])
    self.assertEqual(plugin.start_commands_start_time, [None, None])
    self.assertEqual(list(plugin._incoming_requests), [])
    self.assertEqual(list(plugin.postponed_requests), [])
    self.assertTrue(plugin._server_queue.empty())
    self.assertEqual(
      plugin._lifecycle_events,
      [
        "base_init",
        "stop_commands",
        "stop_log_readers",
        "stop_tunnel",
        "reset_tunnel",
      ],
    )

  def test_startup_lookup_error_fails_closed_and_retries_after_one_minute(self):
    plugin = self._make_manager(dauth_oracle=RuntimeError("registry unavailable"))

    plugin.on_init()

    self.assertTrue(plugin.should_pause())
    self.assertFalse(plugin.should_resume())
    self.assertTrue(plugin.should_pause())
    self.assertEqual(plugin.bc.calls, 1)
    self.assertEqual(plugin._dauth_server_enabled_message, "registry unavailable")
    self.assertTrue(plugin._dauth_pause_teardown_succeeded)

    plugin._now += 59
    self.assertTrue(plugin.should_pause())
    self.assertEqual(plugin.bc.calls, 1)

    plugin._now += 1
    self.assertTrue(plugin.should_pause())
    self.assertEqual(plugin.bc.calls, 2)

  def test_hourly_refresh_revokes_server_and_secret_replication(self):
    plugin = self._make_manager(dauth_oracle=True)
    plugin.on_init()
    plugin.bc.result = False

    plugin._now += (60 * 60) - 1
    self.assertFalse(plugin.should_pause())
    self.assertEqual(plugin.bc.calls, 1)

    plugin._now += 1
    self.assertTrue(plugin.should_pause())
    plugin.on_pause()
    self.assertEqual(plugin.bc.calls, 2)
    self.assertIsNone(plugin._dauth_registry_eth_oracles)
    self.assertIsNone(plugin._dauth_registry_internal_peers)
    self.assertTrue(plugin._stop_request_monitor.is_set())
    self.assertEqual(plugin.start_commands_processes, [None, None])

    hsync_calls = len(plugin._hsync_calls)
    plugin._now += 10 * 60
    plugin.process()
    self.assertEqual(len(plugin._hsync_calls), hsync_calls)

  def test_hourly_refresh_replaces_removed_replication_peers(self):
    plugin = self._make_manager(dauth_oracle=True)
    plugin.on_init()
    plugin.bc.result = ["0xNODE", "0xNEW"]

    plugin._now += 60 * 60
    self.assertFalse(plugin.should_pause())

    self.assertEqual(plugin.bc.calls, 2)
    self.assertEqual(plugin._dauth_registry_eth_oracles, ["0xNODE", "0xNEW"])
    self.assertEqual(
      plugin._dauth_registry_internal_peers,
      ["node-address", "new-peer-address"],
    )
    plugin.process()
    self.assertEqual(
      plugin._hsync_calls[-1]["extra_peers"],
      ["node-address", "new-peer-address"],
    )

  def test_hourly_refresh_allows_newly_registered_server_to_resume(self):
    plugin = self._make_manager(dauth_oracle=False)
    plugin.on_init()
    plugin.bc.result = True

    plugin._now += 60 * 60
    self.assertTrue(plugin.should_resume())

    self.assertEqual(plugin.bc.calls, 2)
    self.assertEqual(
      plugin._dauth_registry_internal_peers,
      ["node-address", "peer-address"],
    )

  def test_hourly_refresh_error_revokes_server_and_clears_peers(self):
    plugin = self._make_manager(dauth_oracle=True)
    plugin.on_init()
    plugin.bc.result = RuntimeError("registry unavailable")

    plugin._now += 60 * 60
    self.assertTrue(plugin.should_pause())

    self.assertEqual(plugin.bc.calls, 2)
    self.assertEqual(plugin._dauth_server_enabled_message, "registry unavailable")
    self.assertIsNone(plugin._dauth_registry_eth_oracles)
    self.assertIsNone(plugin._dauth_registry_internal_peers)

    plugin.bc.result = True
    plugin._now += 59
    self.assertFalse(plugin.should_resume())
    self.assertEqual(plugin.bc.calls, 2)

    plugin._now += 1
    self.assertTrue(plugin.should_resume())
    self.assertEqual(plugin.bc.calls, 3)

  def test_pause_tears_down_and_resume_restarts_only_request_monitor(self):
    plugin = self._make_manager(dauth_oracle=True)
    plugin.on_init()
    plugin._incoming_requests.append("second-incoming")
    plugin.postponed_requests.append("second-postponed")
    plugin._server_queue.put("second-server")

    plugin.on_pause()

    self.assertTrue(plugin._dauth_pause_teardown_succeeded)
    self.assertFalse(plugin._is_plugin_ready)
    self.assertEqual(plugin.start_commands_processes, [None, None])
    self.assertEqual(list(plugin._incoming_requests), [])
    self.assertEqual(list(plugin.postponed_requests), [])
    self.assertTrue(plugin._server_queue.empty())

    plugin.failed = True
    plugin.on_resume()

    self.assertFalse(plugin.failed)
    self.assertFalse(plugin._stop_request_monitor.is_set())
    self.assertTrue(plugin._request_monitor_thread.is_alive())
    self.assertFalse(plugin._is_plugin_ready)
    self.assertEqual(plugin._lifecycle_events[-1], "start_monitor")
    self.assertEqual(plugin.bc.calls, 1)

    plugin.on_log_handler("Uvicorn running on http://0.0.0.0:1234 (Press CTRL+C to quit)")
    self.assertTrue(plugin._is_plugin_ready)

  def test_ineligible_server_cannot_resume(self):
    plugin = self._make_manager(dauth_oracle=False)
    plugin.on_init()

    with self.assertRaisesRegex(RuntimeError, "ineligible dAuth server"):
      plugin.on_resume()

    self.assertTrue(plugin._stop_request_monitor.is_set())
    self.assertFalse(plugin._request_monitor_thread.is_alive())
    self.assertNotIn("start_monitor", plugin._lifecycle_events)

  def test_failed_teardown_is_verified_and_blocks_resume(self):
    plugin = self._make_manager(dauth_oracle=True)
    plugin.on_init()
    running_processes = list(plugin.start_commands_processes)
    plugin._maybe_close_start_commands = lambda: None

    with self.assertRaisesRegex(RuntimeError, "Failed to stop start commands"):
      plugin.on_pause()

    self.assertFalse(plugin._dauth_pause_teardown_succeeded)
    self.assertEqual(plugin.start_commands_processes, running_processes)
    with self.assertRaisesRegex(RuntimeError, "incomplete web app teardown"):
      plugin.on_resume()

  def test_failed_tunnel_stop_is_verified_before_state_is_reset(self):
    plugin = self._make_manager(dauth_oracle=True)
    plugin.on_init()
    plugin.maybe_stop_tunnel_engine = lambda: plugin._lifecycle_events.append(
      "stop_tunnel"
    )

    with self.assertRaisesRegex(RuntimeError, "Failed to stop tunnel engine"):
      plugin.on_pause()

    self.assertFalse(plugin._dauth_pause_teardown_succeeded)
    self.assertTrue(plugin.tunnel_engine_started)
    self.assertNotIn("reset_tunnel", plugin._lifecycle_events)

  def test_pause_callback_before_on_init_is_safe(self):
    plugin = self._make_manager(dauth_oracle=True)

    plugin.on_pause()

    self.assertEqual(plugin._lifecycle_events, [])
    self.assertEqual(plugin.bc.calls, 0)

  def test_initially_disabled_then_enabled_ineligible_init_stays_torn_down(self):
    plugin = self._make_manager(dauth_oracle=False)

    plugin.on_pause()
    plugin.on_init()
    remains_stopped = not plugin.should_resume()
    if not remains_stopped:
      plugin.on_resume()
    # endif

    self.assertTrue(remains_stopped)
    self.assertTrue(plugin.should_pause())
    self.assertTrue(plugin._stop_request_monitor.is_set())
    self.assertFalse(plugin._request_monitor_thread.is_alive())
    self.assertEqual(plugin.start_commands_processes, [None, None])
    self.assertEqual(plugin.bc.calls, 1)

  def test_endpoint_authorization_uses_cached_startup_result(self):
    plugin = self._make_manager(dauth_oracle=False)
    plugin.on_init()
    plugin._DauthManagerPlugin__get_response = lambda data: data
    plugin.process_dauth_request = lambda body: self.fail(
      f"process_dauth_request unexpectedly called with {body}"
    )

    response = plugin.get_auth_data({"nonce": "value"})

    self.assertEqual(
      response,
      {"error": "dAuth server is not registered as a dAuth oracle"},
    )
    self.assertEqual(plugin.bc.calls, 1)


if __name__ == "__main__":
  unittest.main()
