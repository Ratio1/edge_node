import json
import unittest

from collections import deque
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]


class _FakeRandomModule:
  @staticmethod
  def randint(high):
    return 0


class _FakeNumpyModule:
  random = _FakeRandomModule()


class _FakeBasePlugin:
  CONFIG = {"VALIDATION_RULES": {}}

  def __init__(self, **kwargs):
    self.cfg_ai_engine = kwargs.get("AI_ENGINE", "fake-engine")
    self.cfg_request_timeout = kwargs.get("REQUEST_TIMEOUT", 600)
    self.cfg_request_ttl_seconds = kwargs.get("REQUEST_TTL_SECONDS", 7200)
    self.cfg_log_requests_status_every_seconds = kwargs.get("LOG_REQUESTS_STATUS_EVERY_SECONDS", 5)
    self.cfg_request_balancing_enabled = kwargs.get("REQUEST_BALANCING_ENABLED", True)
    self.cfg_request_balancing_group = kwargs.get("REQUEST_BALANCING_GROUP", "test-group")
    self.cfg_request_balancing_capacity = kwargs.get("REQUEST_BALANCING_CAPACITY", 1)
    self.cfg_request_balancing_pending_limit = kwargs.get("REQUEST_BALANCING_PENDING_LIMIT", 8)
    self.cfg_request_balancing_announce_period = kwargs.get("REQUEST_BALANCING_ANNOUNCE_PERIOD", 60)
    self.cfg_request_balancing_peer_stale_seconds = kwargs.get("REQUEST_BALANCING_PEER_STALE_SECONDS", 180)
    self.cfg_request_balancing_mailbox_poll_period = kwargs.get("REQUEST_BALANCING_MAILBOX_POLL_PERIOD", 1)
    self.cfg_request_balancing_capacity_cstore_timeout = kwargs.get(
      "REQUEST_BALANCING_CAPACITY_CSTORE_TIMEOUT", 2
    )
    self.cfg_request_balancing_capacity_cstore_max_retries = kwargs.get(
      "REQUEST_BALANCING_CAPACITY_CSTORE_MAX_RETRIES", 0
    )
    self.cfg_request_balancing_capacity_warn_period = kwargs.get(
      "REQUEST_BALANCING_CAPACITY_WARN_PERIOD", 60
    )
    self.cfg_request_balancing_max_cstore_bytes = kwargs.get("REQUEST_BALANCING_MAX_CSTORE_BYTES", 512 * 1024)
    self.cfg_request_balancing_request_ttl_seconds = kwargs.get("REQUEST_BALANCING_REQUEST_TTL_SECONDS", None)
    self.cfg_request_balancing_result_ttl_seconds = kwargs.get("REQUEST_BALANCING_RESULT_TTL_SECONDS", None)
    self.cfg_tunnel_engine_enabled = False
    self.cfg_is_loopback_plugin = True
    self.cfg_api_summary = "test"
    self._stream_id = kwargs.get("STREAM_ID", "stream-a")
    self._signature = kwargs.get("SIGNATURE", "BASE_INFERENCE_API")
    self._instance_id = kwargs.get("INSTANCE_ID", "inst-a")
    self._eeid = kwargs.get("EE_ID", "node-alias-a")
    self.ee_addr = kwargs.get("EE_ADDR", "node-a")
    self.bc = SimpleNamespace(
      eth_address=kwargs.get("ETH_ADDRESS", "0xeth-a"),
      get_evm_network=lambda: kwargs.get("EVM_NETWORK", "devnet"),
    )
    self._endpoints = {}
    self._now = kwargs.get("NOW", 1000.0)
    self._uuid_counter = 0
    self.chainstore_hset_calls = []
    self.chainstore_hset_result = kwargs.get("CHAINSTORE_HSET_RESULT", True)
    self.chainstore_hgetall_values = {}
    self.payloads = []
    self.logs = []
    self.log = SimpleNamespace(
      compress_text=self._compress_text,
      decompress_text=self._decompress_text,
    )

  @staticmethod
  def endpoint(method="get", require_token=False, streaming_type=None, chunk_size=1024 * 1024):  # pylint: disable=unused-argument
    def decorator(func):
      return func
    return decorator

  def on_init(self):
    return

  def P(self, *args, **kwargs):
    self.logs.append((args, kwargs))
    return

  def Pd(self, *_args, **_kwargs):
    return

  def uuid(self):
    self._uuid_counter += 1
    return f"req-{self._uuid_counter}"

  def time(self):
    return self._now

  def json_dumps(self, data, indent=None, **kwargs):
    return json.dumps(data, indent=indent, **kwargs)

  def json_loads(self, data):
    return json.loads(data)

  @property
  def np(self):
    return _FakeNumpyModule()

  @property
  def deque(self):
    return deque

  def get_signature(self):
    return self._signature

  def get_stream_id(self):
    return self._stream_id

  def get_instance_id(self):
    return self._instance_id

  @property
  def eeid(self):
    return self._eeid

  def get_status(self):
    return "ok"

  def get_alive_time(self):
    return 1.0

  def load_persistence_data(self):
    return

  def cacheapi_load_pickle(self, *args, **kwargs):  # pylint: disable=unused-argument
    return None

  def cacheapi_save_pickle(self, *args, **kwargs):  # pylint: disable=unused-argument
    return None

  def maybe_refresh_metrics(self):
    return

  def cleanup_expired_requests(self):
    return

  def maybe_save_persistence_data(self):
    return

  def dataapi_struct_datas(self, *args, **kwargs):  # pylint: disable=unused-argument
    return []

  def dataapi_struct_data_inferences(self):
    return []

  def create_postponed_request(self, solver_method=None, method_kwargs=None):
    return {
      "postponed": True,
      "solver_method": solver_method,
      "method_kwargs": method_kwargs or {},
    }

  def authorize_request(self, _authorization):
    return "anonymous"

  def enforce_rate_limit(self, _subject):
    return

  def add_payload_by_fields(self, **kwargs):
    self.payloads.append(kwargs)
    return

  def chainstore_hset(self, **kwargs):
    self.chainstore_hset_calls.append(kwargs)
    hkey = kwargs["hkey"]
    key = kwargs["key"]
    value = kwargs["value"]
    self.chainstore_hgetall_values.setdefault(hkey, {})
    self.chainstore_hgetall_values[hkey][key] = value
    return self.chainstore_hset_result

  def chainstore_hgetall(self, hkey, **kwargs):  # pylint: disable=unused-argument
    return self.chainstore_hgetall_values.get(hkey, {})

  @staticmethod
  def _compress_text(text):
    import base64
    import zlib
    return base64.b64encode(zlib.compress(text.encode("utf-8"), level=9)).decode("utf-8")

  @staticmethod
  def _decompress_text(text):
    import base64
    import zlib
    return zlib.decompress(base64.b64decode(text.encode("utf-8"))).decode("utf-8")


class _FakeBaseAgentMixin:
  def filter_valid_inference(self, inference):  # pylint: disable=unused-argument
    return True


class _FakeNumpyScalar:
  def __init__(self, value):
    self._value = value

  def item(self):
    return self._value


def _load_plugin_class():
  source_path = ROOT / "extensions" / "business" / "edge_inference_api" / "base_inference_api.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin\n",
    "",
  )
  source = source.replace(
    "from extensions.business.mixins.base_agent_mixin import _BaseAgentMixin, BASE_AGENT_MIXIN_CONFIG\n",
    "",
  )
  namespace = {
    "BasePlugin": _FakeBasePlugin,
    "_BaseAgentMixin": _FakeBaseAgentMixin,
    "BASE_AGENT_MIXIN_CONFIG": {},
    "__name__": "loaded_base_inference_api",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["BaseInferenceApiPlugin"]


BaseInferenceApiPlugin = _load_plugin_class()


class BaseInferenceApiBalancingTests(unittest.TestCase):
  def _make_plugin(self, **kwargs):
    plugin = BaseInferenceApiPlugin(**kwargs)
    plugin.on_init()
    plugin._endpoints = {
      "predict": SimpleNamespace(__balanced_endpoint__=True),
      "predict_async": SimpleNamespace(__balanced_endpoint__=True),
    }
    return plugin

  def test_capacity_publish_uses_soft_state_cstore_options(self):
    plugin = self._make_plugin(
      REQUEST_BALANCING_CAPACITY_CSTORE_TIMEOUT=3,
      REQUEST_BALANCING_CAPACITY_CSTORE_MAX_RETRIES=0,
    )

    capacity_call = plugin.chainstore_hset_calls[0]

    self.assertEqual(capacity_call["hkey"], plugin._capacity_hkey())  # pylint: disable=protected-access
    self.assertEqual(capacity_call["timeout"], 3.0)
    self.assertEqual(capacity_call["max_retries"], 0)
    self.assertNotIn("extra_peers", capacity_call)

  def test_capacity_publish_failure_is_non_fatal_and_rate_limited(self):
    plugin = self._make_plugin(
      CHAINSTORE_HSET_RESULT=False,
      REQUEST_BALANCING_ANNOUNCE_PERIOD=0,
      REQUEST_BALANCING_CAPACITY_WARN_PERIOD=60,
      NOW=100.0,
    )

    self.assertTrue(plugin.logs)
    first_log_count = len(plugin.logs)
    self.assertEqual(plugin._last_capacity_announce, 100.0)  # pylint: disable=protected-access

    plugin._now = 101.0  # pylint: disable=protected-access
    plugin._publish_capacity_record(force=True)  # pylint: disable=protected-access

    self.assertEqual(len(plugin.logs), first_log_count)
    self.assertEqual(plugin._last_capacity_announce, 101.0)  # pylint: disable=protected-access

  def test_select_execution_peer_prefers_highest_capacity_free_and_ignores_stale(self):
    plugin = self._make_plugin()
    plugin.chainstore_hgetall_values[plugin._capacity_hkey()] = {
      "stale-peer": {
        "ee_addr": "peer-stale",
        "balancer_group": plugin._normalize_balancing_group(),
        "signature": plugin.get_signature(),
        "capacity_total": 2,
        "capacity_used": 0,
        "capacity_free": 2,
        "updated_at": plugin.time() - 999,
      },
      "peer-one": {
        "ee_addr": "peer-one",
        "instance_id": "one",
        "balancer_group": plugin._normalize_balancing_group(),
        "signature": plugin.get_signature(),
        "capacity_total": 2,
        "capacity_used": 1,
        "capacity_free": 1,
        "updated_at": plugin.time(),
      },
      "peer-two": {
        "ee_addr": "peer-two",
        "instance_id": "two",
        "balancer_group": plugin._normalize_balancing_group(),
        "signature": plugin.get_signature(),
        "capacity_total": 3,
        "capacity_used": 1,
        "capacity_free": 2,
        "updated_at": plugin.time(),
      },
    }

    selected = plugin._select_execution_peer()  # pylint: disable=protected-access

    self.assertEqual(selected["ee_addr"], "peer-two")

  def test_select_execution_peer_allows_same_node_different_instance(self):
    plugin = self._make_plugin(INSTANCE_ID="inst-a")
    plugin.chainstore_hgetall_values[plugin._capacity_hkey()] = {
      "same-instance": {
        "ee_addr": plugin.ee_addr,
        "pipeline": plugin.get_stream_id(),
        "signature": plugin.get_signature(),
        "instance_id": plugin.get_instance_id(),
        "balancer_group": plugin._normalize_balancing_group(),
        "capacity_free": 5,
        "updated_at": plugin.time(),
      },
      "same-node-other-instance": {
        "ee_addr": plugin.ee_addr,
        "pipeline": plugin.get_stream_id(),
        "signature": plugin.get_signature(),
        "instance_id": "inst-b",
        "balancer_group": plugin._normalize_balancing_group(),
        "capacity_free": 1,
        "updated_at": plugin.time(),
      },
    }

    selected = plugin._select_execution_peer()  # pylint: disable=protected-access

    self.assertEqual(selected["instance_id"], "inst-b")

  def test_write_delegated_request_targets_only_executor(self):
    plugin = self._make_plugin()
    request_id, request_data = plugin.register_request(
      subject="anonymous",
      parameters={"timeout": 30},
      metadata={"source": "test"},
    )

    delegation_id, err = plugin._write_delegated_request(  # pylint: disable=protected-access
      request_id=request_id,
      request_data=request_data,
      target_record={
        "ee_addr": "peer-b",
        "instance_id": "inst-b",
      },
      endpoint_name="predict",
    )

    self.assertIsNone(err)
    self.assertEqual(request_data["delegation_id"], delegation_id)
    write_call = plugin.chainstore_hset_calls[-1]
    self.assertEqual(write_call["hkey"], plugin._request_hkey())  # pylint: disable=protected-access
    self.assertEqual(write_call["extra_peers"], ["peer-b"])
    self.assertFalse(write_call["include_default_peers"])
    self.assertFalse(write_call["include_configured_peers"])
    self.assertEqual(write_call["timeout"], 2.0)
    self.assertEqual(write_call["max_retries"], 0)

  def test_write_delegated_request_rejects_unserializable_parameters_cleanly(self):
    plugin = self._make_plugin()
    request_id, request_data = plugin.register_request(
      subject="anonymous",
      parameters={"bad": object()},
      metadata={},
    )

    delegation_id, err = plugin._write_delegated_request(  # pylint: disable=protected-access
      request_id=request_id,
      request_data=request_data,
      target_record={
        "ee_addr": "peer-b",
        "instance_id": "inst-b",
      },
      endpoint_name="predict",
    )

    self.assertIsNone(delegation_id)
    self.assertIn("could not encode delegated request envelope", err)

  def test_predict_entrypoint_queues_when_full_and_no_peer(self):
    plugin = self._make_plugin()
    plugin._active_execution_slots.add("busy")  # pylint: disable=protected-access

    result = plugin._predict_entrypoint(  # pylint: disable=protected-access
      authorization=None,
      async_request=True,
      metadata={"source": "test"},
    )

    self.assertEqual(result["status"], plugin.STATUS_PENDING)
    self.assertEqual(len(plugin._pending_request_ids), 1)  # pylint: disable=protected-access
    request_id = result["request_id"]
    self.assertEqual(plugin._requests[request_id]["queue_state"], "queued")  # pylint: disable=protected-access

  def test_predict_entrypoint_fails_cleanly_when_delegated_request_cannot_encode(self):
    plugin = self._make_plugin()
    plugin._active_execution_slots.add("busy")  # pylint: disable=protected-access
    plugin.chainstore_hgetall_values[plugin._capacity_hkey()] = {
      "peer-b": {
        "ee_addr": "peer-b",
        "pipeline": plugin.get_stream_id(),
        "signature": plugin.get_signature(),
        "instance_id": "inst-b",
        "balancer_group": plugin._normalize_balancing_group(),
        "capacity_free": 1,
        "updated_at": plugin.time(),
      },
    }

    result = plugin._predict_entrypoint(  # pylint: disable=protected-access
      authorization=None,
      async_request=True,
      bad=object(),
    )

    self.assertEqual(result["status"], plugin.STATUS_FAILED)
    self.assertIn("could not encode delegated request envelope", result["error"])
    self.assertEqual(len(plugin._pending_request_ids), 0)  # pylint: disable=protected-access

  def test_delegated_executor_uses_delegation_id_and_returns_tracked_request(self):
    plugin = self._make_plugin(EE_ADDR="peer-b", INSTANCE_ID="inst-b")

    result = plugin._predict_entrypoint(  # pylint: disable=protected-access
      authorization=None,
      async_request=False,
      _force_local_execution=True,
      _delegated_execution=True,
      _delegation_context={
        "delegation_id": "deleg-1",
        "origin_request_id": "origin-1",
        "origin_addr": "peer-a",
        "origin_alias": "alias-a",
        "origin_instance_id": "inst-a",
      },
      metadata={"source": "delegated"},
    )

    self.assertIs(result, plugin._requests["deleg-1"])  # pylint: disable=protected-access
    self.assertNotIn("postponed", result)
    self.assertEqual(result["origin_request_id"], "origin-1")
    self.assertEqual(plugin.payloads[-1]["REQUEST_ID"], "deleg-1")

  def test_poll_delegated_results_updates_origin_request_and_cleans_mailbox(self):
    plugin = self._make_plugin()
    request_id, request_data = plugin.register_request(
      subject="anonymous",
      parameters={},
      metadata={},
    )
    request_data["delegation_id"] = "deleg-1"
    request_data["execution_mode"] = "delegated"
    request_data["delegated_at"] = plugin.time() + 2
    request_data["slot_reserved_at"] = plugin.time() + 5
    result_body = {
      "status": plugin.STATUS_COMPLETED,
      "request_id": request_id,
      "prediction": {"label": "ok"},
      "EXECUTOR_NODE_ADDR": "peer-b",
      "EXECUTOR_NODE_ALIAS": "alias-b",
      "INFERENCE_ELAPSED_TIME": 3.5,
    }
    envelope, _ = plugin._build_transport_envelope(  # pylint: disable=protected-access
      result_body,
      kind="result",
      delegation_id="deleg-1",
      origin_request_id=request_id,
      status=plugin.STATUS_COMPLETED,
      origin_addr=plugin.ee_addr,
      origin_instance_id=plugin.get_instance_id(),
      target_addr="peer-b",
      target_instance_id="inst-b",
      created_at=plugin.time(),
      updated_at=plugin.time(),
      expires_at=plugin.time() + 10,
    )
    plugin.chainstore_hgetall_values[plugin._result_hkey()] = {"deleg-1": envelope}  # pylint: disable=protected-access

    plugin._poll_delegated_results()  # pylint: disable=protected-access

    self.assertEqual(request_data["status"], plugin.STATUS_COMPLETED)
    self.assertEqual(request_data["result"]["prediction"], {"label": "ok"})
    self.assertEqual(request_data["result"]["EXECUTOR_NODE_ADDR"], "peer-b")
    self.assertEqual(request_data["result"]["EXECUTOR_NODE_ALIAS"], "alias-b")
    self.assertEqual(request_data["result"]["DELEGATOR_NODE_ADDR"], "node-a")
    self.assertEqual(request_data["result"]["DELEGATOR_NODE_ALIAS"], "node-alias-a")
    self.assertEqual(request_data["result"]["INFERENCE_ELAPSED_TIME"], 3.5)
    self.assertEqual(request_data["result"]["BALANCING_ELAPSED_TIME"], 5.0)
    self.assertNotIn("EXECUTOR_NODE_NETWORK", request_data["result"])
    cleanup_call = plugin.chainstore_hset_calls[-1]
    self.assertEqual(cleanup_call["hkey"], plugin._result_hkey())  # pylint: disable=protected-access
    self.assertEqual(cleanup_call["key"], "deleg-1")
    self.assertIsNone(cleanup_call["value"])
    self.assertEqual(cleanup_call["extra_peers"], ["peer-b"])

  def test_publish_executor_results_writes_result_and_request_cleanup(self):
    plugin = self._make_plugin(EE_ADDR="peer-b", INSTANCE_ID="inst-b")
    request_id, request_data = plugin.register_request(
      subject="delegated:peer-a",
      parameters={},
      metadata={},
      request_id="origin-1",
    )
    request_data["status"] = plugin.STATUS_COMPLETED
    request_data["result"] = {
      "status": plugin.STATUS_COMPLETED,
      "request_id": "origin-1",
      "prediction": {"value": 1},
    }
    request_data["delegated_execution"] = True
    request_data["delegation_id"] = "deleg-1"
    request_data["origin_request_id"] = "origin-1"
    request_data["origin_addr"] = "peer-a"
    request_data["origin_alias"] = "alias-a"
    request_data["origin_instance_id"] = "inst-a"
    plugin._executor_request_map["peer-a:origin-1"] = request_id  # pylint: disable=protected-access

    plugin._publish_executor_results()  # pylint: disable=protected-access

    self.assertEqual(len(plugin.chainstore_hset_calls), 3)  # capacity + result + cleanup
    result_call = plugin.chainstore_hset_calls[-2]
    cleanup_call = plugin.chainstore_hset_calls[-1]
    self.assertEqual(result_call["hkey"], plugin._result_hkey())  # pylint: disable=protected-access
    self.assertEqual(result_call["extra_peers"], ["peer-a"])
    result_body = plugin._decode_transport_envelope_body(result_call["value"])  # pylint: disable=protected-access
    self.assertEqual(result_body["EXECUTOR_NODE_ADDR"], "peer-b")
    self.assertEqual(result_body["EXECUTOR_NODE_ALIAS"], "node-alias-a")
    self.assertEqual(result_body["DELEGATOR_NODE_ADDR"], "peer-a")
    self.assertEqual(result_body["DELEGATOR_NODE_ALIAS"], "alias-a")
    self.assertEqual(result_body["request_id"], "origin-1")
    self.assertNotIn("EXECUTOR_NODE_NETWORK", result_body)
    self.assertNotIn("peer-a:origin-1", plugin._executor_request_map)  # pylint: disable=protected-access
    self.assertEqual(cleanup_call["hkey"], plugin._request_hkey())  # pylint: disable=protected-access
    self.assertEqual(cleanup_call["extra_peers"], ["peer-a"])

  def test_delegated_executor_replay_does_not_overwrite_existing_request(self):
    plugin = self._make_plugin(EE_ADDR="peer-b", INSTANCE_ID="inst-b")
    first = plugin._predict_entrypoint(  # pylint: disable=protected-access
      authorization=None,
      async_request=False,
      _force_local_execution=True,
      _delegated_execution=True,
      _delegation_context={
        "delegation_id": "deleg-1",
        "origin_request_id": "origin-1",
        "origin_addr": "peer-a",
      },
      metadata={"attempt": 1},
    )
    first["marker"] = "original"

    replay = plugin._predict_entrypoint(  # pylint: disable=protected-access
      authorization=None,
      async_request=False,
      _force_local_execution=True,
      _delegated_execution=True,
      _delegation_context={
        "delegation_id": "deleg-1",
        "origin_request_id": "origin-1",
        "origin_addr": "peer-a",
      },
      metadata={"attempt": 2},
    )

    self.assertIs(replay, first)
    self.assertEqual(plugin._requests["deleg-1"]["marker"], "original")  # pylint: disable=protected-access

  def test_publish_executor_results_marks_oversized_result_failed_locally(self):
    plugin = self._make_plugin(EE_ADDR="peer-b", INSTANCE_ID="inst-b", REQUEST_BALANCING_MAX_CSTORE_BYTES=4096)
    request_id, request_data = plugin.register_request(
      subject="delegated:peer-a",
      parameters={},
      metadata={},
      request_id="deleg-1",
    )
    request_data["status"] = plugin.STATUS_COMPLETED
    request_data["result"] = {
      "status": plugin.STATUS_COMPLETED,
      "request_id": "deleg-1",
      "blob": [f"value-{idx}" for idx in range(3000)],
    }
    request_data["delegated_execution"] = True
    request_data["delegation_id"] = "deleg-1"
    request_data["origin_request_id"] = "origin-1"
    request_data["origin_addr"] = "peer-a"
    plugin._metrics["requests_completed"] = 1  # pylint: disable=protected-access

    plugin._publish_executor_results()  # pylint: disable=protected-access

    self.assertEqual(request_data["status"], plugin.STATUS_FAILED)
    self.assertEqual(plugin._metrics["requests_completed"], 0)  # pylint: disable=protected-access
    self.assertEqual(plugin._metrics["requests_failed"], 1)  # pylint: disable=protected-access
    result_body = plugin._decode_transport_envelope_body(  # pylint: disable=protected-access
      plugin.chainstore_hset_calls[-2]["value"]
    )
    self.assertEqual(result_body["request_id"], "origin-1")
    self.assertIn("transport limit", result_body["error"])

  def test_cleanup_balancing_state_uses_retention_deadline(self):
    plugin = self._make_plugin(NOW=100.0)
    plugin._seen_delegation_ids = {  # pylint: disable=protected-access
      "expired": 99.0,
      "retained": 101.0,
    }

    plugin._cleanup_balancing_state()  # pylint: disable=protected-access

    self.assertNotIn("expired", plugin._seen_delegation_ids)  # pylint: disable=protected-access
    self.assertIn("retained", plugin._seen_delegation_ids)  # pylint: disable=protected-access

  def test_fail_request_adds_executor_and_delegator_identity_inside_result(self):
    plugin = self._make_plugin(EE_ADDR="node-x", EE_ID="alias-x", ETH_ADDRESS="0xeth-x")
    request_id, _request_data = plugin.register_request(
      subject="anonymous",
      parameters={},
      metadata={},
    )

    plugin._fail_request(request_id=request_id, error_message="boom")  # pylint: disable=protected-access

    result = plugin._requests[request_id]["result"]
    self.assertEqual(result["EXECUTOR_NODE_ADDR"], "node-x")
    self.assertEqual(result["EXECUTOR_NODE_ALIAS"], "alias-x")
    self.assertEqual(result["DELEGATOR_NODE_ADDR"], "node-x")
    self.assertEqual(result["DELEGATOR_NODE_ALIAS"], "alias-x")
    self.assertNotIn("EXECUTOR_NODE_NETWORK", result)

  def test_annotate_result_adds_balancing_and_inference_elapsed(self):
    plugin = self._make_plugin(NOW=100.0)
    request_id, request_data = plugin.register_request(
      subject="anonymous",
      parameters={},
      metadata={},
    )
    request_data["slot_reserved_at"] = 104.0
    request_data["finished_at"] = 111.5

    result = plugin._annotate_result_with_node_roles(  # pylint: disable=protected-access
      result_payload={"status": plugin.STATUS_COMPLETED, "request_id": request_id},
      request_data=request_data,
    )

    self.assertEqual(result["BALANCING_ELAPSED_TIME"], 4.0)
    self.assertEqual(result["INFERENCE_ELAPSED_TIME"], 7.5)

  def test_annotate_result_makes_numpy_like_scalars_json_safe(self):
    plugin = self._make_plugin()
    request_id, request_data = plugin.register_request(
      subject="anonymous",
      parameters={},
      metadata={},
    )
    request_data["finished_at"] = plugin.time()

    result = plugin._annotate_result_with_node_roles(  # pylint: disable=protected-access
      result_payload={
        "status": plugin.STATUS_COMPLETED,
        "request_id": request_id,
        "score": _FakeNumpyScalar(0.97),
        "nested": [{"value": _FakeNumpyScalar(1.25)}],
      },
      request_data=request_data,
    )

    self.assertEqual(result["score"], 0.97)
    self.assertEqual(result["nested"][0]["value"], 1.25)

  def test_build_owned_payloads_by_request_id_filters_mixed_payloads(self):
    plugin = self._make_plugin()
    owned_request_id, _request_data = plugin.register_request(
      subject="anonymous",
      parameters={},
      metadata={},
      request_id="owned-1",
    )

    payloads = [
      {"request_id": owned_request_id, "metadata": {"source": "owned"}},
      {"request_id": "foreign-1", "metadata": {"source": "foreign"}},
      {"REQUEST_ID": "owned-2", "metadata": {"source": "missing-local-request"}},
      {"metadata": {"source": "missing-id"}},
    ]

    owned_payloads = plugin._build_owned_payloads_by_request_id(payloads)  # pylint: disable=protected-access

    self.assertEqual(
      owned_payloads,
      {
        owned_request_id: {"request_id": owned_request_id, "metadata": {"source": "owned"}},
      },
    )

  def test_build_owned_payloads_by_request_id_accepts_dict_input(self):
    plugin = self._make_plugin()
    owned_request_id, _request_data = plugin.register_request(
      subject="anonymous",
      parameters={},
      metadata={},
      request_id="owned-1",
    )

    payloads = {
      0: {"request_id": "foreign-1"},
      1: {"request_id": owned_request_id, "metadata": {"source": "owned"}},
    }

    owned_payloads = plugin._build_owned_payloads_by_request_id(payloads)  # pylint: disable=protected-access

    self.assertEqual(
      owned_payloads,
      {
        owned_request_id: {"request_id": owned_request_id, "metadata": {"source": "owned"}},
      },
    )


if __name__ == "__main__":
  unittest.main()
