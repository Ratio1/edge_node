"""RM-141: Demo attestations on Base Sepolia through a token-gated bridge, live attestation unchanged."""
import hashlib
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from .conftest import mock_plugin_modules

DOMAIN = "0x" + ("11" * 32)
TOKEN = "test-backend-token-material-at-least-32-bytes"
DEMO_KEY = "0xdemo-private-key-value"


def _host(attestation=None, demo=None):
  from extensions.business.cybersec.red_mesh.mixins.attestation import _AttestationMixin

  class MockHost(_AttestationMixin):
    REDMESH_ATTESTATION_DOMAIN = DOMAIN
    REDMESH_ATTESTATION_NETWORK = "base-sepolia"

    def __init__(self):
      self.cfg_attestation = attestation if attestation is not None else {
        "ENABLED": True, "PRIVATE_KEY": "0xlive", "RETRIES": 2}
      if demo is not None:
        self.cfg_demo = {"ATTESTATION": demo}
      self.bc = MagicMock()
      self.bc.eth_address = "0xsender"
      self.bc.submit_attestation.return_value = "0xtxhash"
      self.bc.node_addr_to_eth_addr.return_value = "0x" + ("ab" * 20)
      self.bc.eth_hash_message.return_value = "0x" + ("22" * 32)

    def P(self, *_args, **_kwargs):
      return None

  return MockHost()


class TestLiveAttestationUnchanged(unittest.TestCase):
  """The arguments the live callers hand to `bc.submit_attestation`, pinned before the RM-141 refactor."""

  def test_test_attestation_arguments_are_byte_identical(self):
    host = _host()
    host._submit_redmesh_test_attestation(
      job_id="jobid123",
      job_specs={"target": "10.1.2.3", "run_mode": "CONTINUOUS_MONITORING"},
      workers={"0xa": {}, "0xb": {}},
      vulnerability_score=42,
      report_cid="QmAggregatedCid",
    )
    call = host.bc.submit_attestation.call_args
    self.assertEqual(call.args, ())
    self.assertEqual(call.kwargs, {
      "function_name": "submitRedmeshTestAttestation",
      "function_args": [1, 2, 42, "0x6a6f626964313233", "0x0a03", "0x516d4167676564436964"],
      "signature_types": ["bytes32", "uint8", "uint16", "uint8", "bytes8", "bytes2", "bytes10"],
      "signature_values": [DOMAIN, 1, 2, 42, "0x6a6f626964313233", "0x0a03", "0x516d4167676564436964"],
      "tx_private_key": "0xlive",
    })

  def test_job_start_attestation_arguments_are_byte_identical(self):
    host = _host()
    host._submit_redmesh_job_start_attestation(
      job_id="jobid123",
      job_specs={"target": "10.1.2.3", "run_mode": "SINGLEPASS"},
      workers={"0xa": {}},
    )
    call = host.bc.submit_attestation.call_args
    self.assertEqual(call.args, ())
    self.assertEqual(call.kwargs, {
      "function_name": "submitRedmeshJobStartAttestation",
      "function_args": [0, 1, "0x6a6f626964313233", "0x" + ("22" * 32), "0x0a03"],
      "signature_types": ["bytes32", "uint8", "uint16", "bytes8", "bytes32", "bytes2"],
      "signature_values": [DOMAIN, 0, 1, "0x6a6f626964313233", "0x" + ("22" * 32), "0x0a03"],
      "tx_private_key": "0xlive",
    })

  def test_live_preamble_still_skips_when_disabled(self):
    host = _host(attestation={"ENABLED": False, "PRIVATE_KEY": "0xlive", "RETRIES": 2},
                 demo={"ENABLED": True, "PRIVATE_KEY": DEMO_KEY})
    self.assertIsNone(host._submit_redmesh_job_start_attestation("jobid123", {"target": "10.1.2.3"}, {"0xa": {}}))
    host.bc.submit_attestation.assert_not_called()


class _Postponed:
  def __init__(self, solver_method, method_kwargs):
    self.solver_method = solver_method
    self.method_kwargs = method_kwargs


def _bridge_host(demo=None, attestation=None):
  from extensions.business.cybersec.red_mesh.services import demo_attestation

  host = _host(attestation=attestation, demo=demo if demo is not None else {
    "ENABLED": True, "PRIVATE_KEY": DEMO_KEY, "SETTLE_SECONDS": 0})
  host.create_postponed_request = lambda solver_method, method_kwargs: _Postponed(solver_method, method_kwargs)
  host.solve_postponed_demo_attestation = lambda pending_id: demo_attestation.solve_demo_attestation(host, pending_id)
  return host


def _resolve(result, rounds=200):
  """Drive a postponed request to its answer, as the web app loop does."""
  for _ in range(rounds):
    if not isinstance(result, _Postponed):
      return result
    time.sleep(0.01)
    result = result.solver_method(**result.method_kwargs)
  raise AssertionError("postponed request never resolved")


def _submit(host, **overrides):
  from extensions.business.cybersec.red_mesh.services.demo_attestation import submit_demo_attestation
  kwargs = {"job_id": "demo-job-1234", "event": "start", "target": "192.0.2.10",
            "run_mode": "SINGLEPASS", "node_count": 2, "vulnerability_score": 0}
  kwargs.update(overrides)
  return submit_demo_attestation(host, **kwargs)


def _packed_demo_id(job_id):
  return "0x" + hashlib.sha256(job_id.encode()).hexdigest()[:8].encode("ascii").hex()


class TestDemoAttestationConfig(unittest.TestCase):

  def test_defaults_are_off_with_an_empty_key_on_testnet(self):
    from extensions.business.cybersec.red_mesh.services.config import get_demo_attestation_config
    host = _host()
    cfg = get_demo_attestation_config(host)
    self.assertEqual((cfg["ENABLED"], cfg["PRIVATE_KEY"], cfg["NETWORK"]), (False, "", "testnet"))

  def test_a_none_key_is_empty_and_mainnet_falls_back_to_testnet(self):
    from extensions.business.cybersec.red_mesh.services.config import get_demo_attestation_config
    host = _host(demo={"ENABLED": "false", "PRIVATE_KEY": None, "NETWORK": "mainnet"})
    cfg = get_demo_attestation_config(host)
    self.assertEqual((cfg["ENABLED"], cfg["PRIVATE_KEY"], cfg["NETWORK"]), (False, "", "testnet"))
    host = _host(demo={"NETWORK": " DEVNET "})
    self.assertEqual(get_demo_attestation_config(host)["NETWORK"], "devnet")

  def test_the_block_lives_under_demo_and_a_partial_override_keeps_the_defaults(self):
    from extensions.business.cybersec.red_mesh.services.config import get_demo_attestation_config
    host = _host()
    host.cfg_demo = {"ATTESTATION": {"ENABLED": True, "PRIVATE_KEY": DEMO_KEY}, "OTHER": {"X": 1}}
    cfg = get_demo_attestation_config(host)
    self.assertEqual((cfg["ENABLED"], cfg["PRIVATE_KEY"], cfg["NETWORK"], cfg["RETRIES"]), (True, DEMO_KEY, "testnet", 2))
    # A flat block at the root is not read.
    host = _host()
    host.cfg_demo_attestation = {"ENABLED": True, "PRIVATE_KEY": DEMO_KEY}
    self.assertEqual(get_demo_attestation_config(host)["ENABLED"], False)

  def test_status_says_configured_and_never_returns_the_key(self):
    from extensions.business.cybersec.red_mesh.services.demo_attestation import get_demo_attestation_status
    self.assertEqual(get_demo_attestation_status(_host())["configured"], False)
    status = get_demo_attestation_status(_host(demo={"ENABLED": True, "PRIVATE_KEY": DEMO_KEY}))
    self.assertEqual(status, {"configured": True, "network": "base-sepolia", "evm_network": "testnet"})
    self.assertNotIn(DEMO_KEY, str(status))


class TestDemoAttestationBridge(unittest.TestCase):

  def test_start_is_sent_with_the_demo_key_on_the_demo_network_and_derived_fields(self):
    # Live attestation off, Demo on: the Demo path never consults the live block.
    host = _bridge_host(attestation={"ENABLED": False, "PRIVATE_KEY": "", "RETRIES": 2})
    result = _resolve(_submit(host))
    execution_id = _packed_demo_id("demo-job-1234")
    self.assertEqual(result, {"status": "ok", "tx_hash": "0xtxhash", "execution_id": execution_id,
                              "network": "base-sepolia", "signer": "0xsender"})
    self.assertEqual(host.bc.submit_attestation.call_args.kwargs, {
      "function_name": "submitRedmeshJobStartAttestation",
      "function_args": [0, 2, execution_id, "0x" + ("00" * 32), "0xc00a"],
      "signature_types": ["bytes32", "uint8", "uint16", "bytes8", "bytes32", "bytes2"],
      "signature_values": [DOMAIN, 0, 2, execution_id, "0x" + ("00" * 32), "0xc00a"],
      "tx_private_key": DEMO_KEY,
      "network": "testnet",
    })
    self.assertNotIn(DEMO_KEY, str(result))

  def test_an_unprefixed_sdk_hash_is_answered_with_0x(self):
    # `HexBytes.hex()` drops the prefix with hexbytes >= 1.0 (rm3 runs 1.3.1).
    host = _bridge_host()
    host.bc.submit_attestation.return_value = "AB" * 32
    self.assertEqual(_resolve(_submit(host))["tx_hash"], "0x" + "ab" * 32)

  def test_complete_clamps_the_score_to_100_and_sends_the_zero_cid(self):
    host = _bridge_host(demo={"ENABLED": True, "PRIVATE_KEY": DEMO_KEY, "NETWORK": "devnet", "SETTLE_SECONDS": 0})
    _resolve(_submit(host, event="complete", run_mode="CONTINUOUS_MONITORING", vulnerability_score=250))
    kwargs = host.bc.submit_attestation.call_args.kwargs
    self.assertEqual(kwargs["function_name"], "submitRedmeshTestAttestation")
    self.assertEqual(kwargs["function_args"], [1, 2, 100, _packed_demo_id("demo-job-1234"), "0xc00a", "0x" + ("00" * 10)])
    self.assertEqual(kwargs["network"], "devnet")
    _resolve(_submit(host, event="complete", vulnerability_score=-3))
    self.assertEqual(host.bc.submit_attestation.call_args.kwargs["function_args"][2], 0)

  def test_only_documentation_addresses_are_packed(self):
    host = _bridge_host()
    for target in ("10.0.0.5", "https://app.example/", "198.51.100.7:8080", "2001:db8::1"):
      _resolve(_submit(host, target=target))
      expected = "0xc607" if target.startswith("198.51.100.7") else "0x0000"
      self.assertEqual(host.bc.submit_attestation.call_args.kwargs["function_args"][-1], expected, target)

  def test_refusals_happen_before_any_submit(self):
    cases = (
      (_bridge_host(demo={"ENABLED": False, "PRIVATE_KEY": DEMO_KEY}), {}, 409, "demo_attestation_disabled"),
      (_bridge_host(demo={"ENABLED": True, "PRIVATE_KEY": "  "}), {}, 409, "demo_attestation_not_configured"),
      (_bridge_host(attestation={"ENABLED": True, "PRIVATE_KEY": DEMO_KEY, "RETRIES": 2}), {}, 409,
       "demo_wallet_shared"),
      # The same key written without `0x` and in another case is still the same wallet.
      (_bridge_host(attestation={"ENABLED": True, "PRIVATE_KEY": DEMO_KEY[2:].upper(), "RETRIES": 2}), {}, 409,
       "demo_wallet_shared"),
      (_bridge_host(), {"job_id": "abcd1234"}, 400, "demo_job_required"),
      (_bridge_host(), {"job_id": None}, 400, "demo_job_required"),
      (_bridge_host(), {"event": "pass-1"}, 400, "invalid_event"),
      (_bridge_host(), {"event": ["start"]}, 400, "invalid_event"),
    )
    for host, overrides, status, error_class in cases:
      with self.subTest(error_class=error_class, overrides=overrides):
        result = _submit(host, **overrides)
        self.assertEqual((result["status_code"], result["error_class"]), (status, error_class))
        host.bc.submit_attestation.assert_not_called()

  def test_a_failed_submit_reports_only_an_error_class(self):
    host = _bridge_host()
    host.bc.submit_attestation.side_effect = Exception(f"Insufficient ETH balance to cover gas fees. {DEMO_KEY}")
    result = _resolve(_submit(host))
    self.assertEqual((result["status_code"], result["error_class"]), (502, "insufficient_funds"))
    self.assertEqual(host.bc.submit_attestation.call_count, 2)
    self.assertNotIn(DEMO_KEY, str(result))
    host.bc.submit_attestation.side_effect = RuntimeError("rpc said no")
    self.assertEqual(_resolve(_submit(host))["error_class"], "submit_failed")

  def test_two_sends_are_spaced_by_the_settle_delay(self):
    from extensions.business.cybersec.red_mesh.services import demo_attestation
    host = _bridge_host(demo={"ENABLED": True, "PRIVATE_KEY": DEMO_KEY, "SETTLE_SECONDS": 5})
    sleeps = []
    with patch.object(demo_attestation.time, "sleep", side_effect=lambda s: sleeps.append(s)):
      first = _submit(host)
      second = _submit(host, event="complete")
      demo_attestation._pending(host)  # both queued on the one worker
      host._demo_attestation_executor.shutdown(wait=True)
    self.assertEqual(host.bc.submit_attestation.call_count, 2)
    self.assertEqual(len([s for s in sleeps if s > 4]), 1, sleeps)
    del first, second

  def test_a_request_past_its_deadline_answers_a_timeout(self):
    from extensions.business.cybersec.red_mesh.services import demo_attestation
    host = _bridge_host()
    release = threading.Event()
    host.bc.submit_attestation.side_effect = lambda **_kw: release.wait(5) and "0xlate"
    postponed = _submit(host)
    state = demo_attestation._pending(host)[postponed.method_kwargs["pending_id"]]
    state["deadline"] = 0
    result = postponed.solver_method(**postponed.method_kwargs)
    release.set()
    self.assertEqual((result["status_code"], result["error_class"]), (504, "timeout"))
    self.assertEqual(demo_attestation._pending(host), {})

  def test_the_worker_never_sends_after_the_deadline(self):
    from extensions.business.cybersec.red_mesh.services import demo_attestation
    host = _bridge_host()
    work = {"event": "start", "submit_kwargs": {}, "retries": 2, "settle_seconds": 0,
            "deadline": time.monotonic() - 1}
    self.assertEqual(demo_attestation._run_demo_submit(host, work), {"error_class": "deadline"})
    host.bc.submit_attestation.assert_not_called()


if __name__ == "__main__":
  unittest.main()
