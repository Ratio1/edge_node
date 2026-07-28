from collections import deque
import queue
import threading
import unittest
from pathlib import Path

from extensions.business.dauth.dauth_mixin import _DauthMixin


ROOT = Path(__file__).resolve().parents[3]


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


class _FakeBaseConst:
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

  def __init__(self, *, dauth_oracle=True, protocol_oracles=None):
    self.dauth_oracle = dauth_oracle
    self.protocol_oracles = protocol_oracles or ["node-oracle"]

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


class _DauthHarness(_DauthMixin):
  pass


def _make_dauth_harness(*, dauth_oracle=True, protocol_oracles=None):
  plugin = _DauthHarness()
  plugin.const = _FakeConst
  plugin.bc = _FakeBC(
    dauth_oracle=dauth_oracle,
    protocol_oracles=protocol_oracles,
  )
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


class DauthServerRegistryGateTests(unittest.TestCase):

  def _make_manager(self, *, dauth_oracle):
    class _ManagerBC:
      def __init__(self, result):
        self.result = result
        self.calls = 0

      def is_dauth_oracle(self):
        self.calls += 1
        if isinstance(self.result, Exception):
          raise self.result
        return self.result

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
    return plugin

  def test_startup_lookup_is_cached_across_repeated_lifecycle_predicates(self):
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

  def test_false_startup_lookup_fails_closed_and_tears_down_fastapi(self):
    plugin = self._make_manager(dauth_oracle=False)

    plugin.on_init()

    self.assertTrue(plugin.should_pause())
    self.assertFalse(plugin.should_resume())
    self.assertEqual(plugin.bc.calls, 1)
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

  def test_startup_lookup_error_fails_closed_and_is_not_retried(self):
    plugin = self._make_manager(dauth_oracle=RuntimeError("registry unavailable"))

    plugin.on_init()

    self.assertTrue(plugin.should_pause())
    self.assertFalse(plugin.should_resume())
    self.assertTrue(plugin.should_pause())
    self.assertEqual(plugin.bc.calls, 1)
    self.assertEqual(plugin._dauth_server_enabled_message, "registry unavailable")
    self.assertTrue(plugin._dauth_pause_teardown_succeeded)

  def test_pause_tears_down_and_resume_restarts_only_request_monitor(self):
    plugin = self._make_manager(dauth_oracle=True)
    plugin.on_init()
    plugin._incoming_requests.append("second-incoming")
    plugin.postponed_requests.append("second-postponed")
    plugin._server_queue.put("second-server")

    plugin.on_pause()

    self.assertTrue(plugin._dauth_pause_teardown_succeeded)
    self.assertEqual(plugin.start_commands_processes, [None, None])
    self.assertEqual(list(plugin._incoming_requests), [])
    self.assertEqual(list(plugin.postponed_requests), [])
    self.assertTrue(plugin._server_queue.empty())

    plugin.failed = True
    plugin.on_resume()

    self.assertFalse(plugin.failed)
    self.assertFalse(plugin._stop_request_monitor.is_set())
    self.assertTrue(plugin._request_monitor_thread.is_alive())
    self.assertEqual(plugin._lifecycle_events[-1], "start_monitor")
    self.assertEqual(plugin.bc.calls, 1)

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
