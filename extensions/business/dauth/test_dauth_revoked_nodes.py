"""dAuth refuses revoked node addresses."""
import base64
import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from naeural_core.utils.plugins_base.bc_wrapper import BCWrapper
from ratio1.bc.base import BaseBlockEngine
from ratio1.bc.ec import BaseBCEllipticCurveEngine
from ratio1.bc.evm import _EVMMixin
from ratio1.const.base import dAuth

from extensions.business.dauth.dauth_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY,
  DEEPLOY_JOBS_CSTORE_HKEY,
  VersionCheckData,
)
from extensions.business.dauth.dauth_revoked_nodes import (
  DAUTH_REVOKED_LICENSE_CHECK_INTERVAL,
  DAUTH_REVOKED_LICENSE_RETRY_INTERVAL,
  DAUTH_REVOKED_NODES_ENV_KEY,
  DAUTH_REVOKED_TRIES_FILE,
  DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY,
  DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL,
  DAUTH_REVOKED_UNLICENSED_WRITE_TIMEOUT,
)
from extensions.business.dauth import test_dauth_registry_gating as gating
from extensions.business.dauth.test_dauth_registry_gating import (
  REQUEST_NONCE,
  SOURCE_IP,
  _FakeBCBaseConst,
  _FakeConst,
  _make_dauth_harness,
)


REVOKED = "0xai_" + "Arevoked".ljust(44, "0")
REVOKED_UNPREFIXED = "Brevoked".ljust(44, "1")
ALLOWED = "0xai_" + "Callowed".ljust(44, "2")
SERVER = "0xai_" + "Dserver".ljust(44, "3")
# Whitespace, empty items and a trailing comma are tolerated.
DENYLIST = f" {REVOKED} ,, {REVOKED_UNPREFIXED},"
ETH = {REVOKED: "0x" + "a" * 40, "0xai_" + REVOKED_UNPREFIXED: "0x" + "b" * 40, ALLOWED: "0x" + "c" * 40}
VERSIONS = {"sender_app_ver": "2.10.621", "sender_core_ver": "7.7.1", "sender_sdk_ver": "3.4.90"}
RECORD_KEYS = {
  "time_utc", "endpoint", "source_ip", "node_address", "eth_address", "requester_type",
  "sender_app_ver", "sender_core_ver", "sender_sdk_ver", "sender_alias",
}


class _Const(_FakeConst):
  class BASE_CT:
    BCctbase = _FakeBCBaseConst
    dAuth = dAuth


class _PrefixEngine:
  maybe_remove_prefix = BaseBlockEngine.maybe_remove_prefix
  _remove_prefix = BaseBlockEngine._remove_prefix
  maybe_add_prefix = BaseBlockEngine.maybe_add_prefix
  _add_prefix = BaseBlockEngine._add_prefix


class _KeyEngine(_PrefixEngine):
  """The SDK's own address decoding and ETH derivation, without a node identity."""
  _text_to_binary = staticmethod(BaseBlockEngine._text_to_binary)
  _address_to_pk = BaseBCEllipticCurveEngine._address_to_pk
  _get_eth_address = _EVMMixin._get_eth_address
  node_address_to_eth_address = _EVMMixin.node_address_to_eth_address

  def P(self, *args, **kwargs):  # pylint: disable=unused-argument
    return


def _key_spellings():
  """One secp256k1 key written as the canonical address and as other valid spellings."""
  public_key = ec.generate_private_key(ec.SECP256K1()).public_key()
  def encode(point_format):
    raw = public_key.public_bytes(serialization.Encoding.X962, point_format)
    return base64.urlsafe_b64encode(raw).decode()
  canonical = encode(serialization.PublicFormat.CompressedPoint)
  return canonical, {
    "canonical": "0xai_" + canonical,
    "unprefixed": canonical,
    "old prefix": "aixp_" + canonical,
    "uncompressed point": "0xai_" + encode(serialization.PublicFormat.UncompressedPoint),
    "skipped characters": "0xai_" + canonical[:10] + ".!" + canonical[10:],
  }


def _auth_body(sender, **overrides):
  return {
    "EE_SENDER": sender, "EE_ETH_SENDER": ETH[sender], "EE_SIGN": "signature-value",
    "nonce": "a1b2", "sender_alias": "node-1", **VERSIONS, **overrides,
  }


def _harness(messages, evm_network="mainnet", denylist=DENYLIST):
  plugin = _make_dauth_harness()
  plugin.const = _Const
  plugin.P = lambda msg, *args, **kwargs: messages.append(msg)
  plugin.evm_network = evm_network
  plugin.ee_ver, plugin.ee_core_ver, plugin.ee_sdk_ver = VERSIONS.values()
  plugin.bc.node_eth.update(ETH)
  plugin.bc.address = SERVER
  plugin.bc.is_node_licensed = Mock(return_value=True)
  if denylist is not None:
    plugin.os_environ[DAUTH_REVOKED_NODES_ENV_KEY] = denylist
  return plugin


class DauthRevokedNodeTests(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)
    self.messages = []
    plugin = _harness(self.messages)
    plugin.get_data_folder = lambda: self.tmp.name
    plugin._resolve_data_subfolder = lambda subfolder=None: "pipelines_data/admin/dauth/plugin_data"
    plugin._load_dauth_revoked_nodes()
    self.plugin = plugin

  def _bookkeeping(self):
    """Run the recorder pass, then the plugin-loop writes until none is pending."""
    self.plugin._flush_dauth_revoked_tries()
    while self.plugin._dauth_revoked_unlicensed_pending:
      self.plugin._maybe_publish_dauth_revoked_unlicensed_tries()

  def _refuse(self, body):
    """Refuse one request, then run the bookkeeping the recorder and plugin loop would run."""
    self._assert_auth_refused(self.plugin.process_dauth_request(body))
    self._bookkeeping()

  def _records(self):
    self._bookkeeping()
    path = os.path.join(
      self.tmp.name, "pipelines_data/admin/dauth/plugin_data", DAUTH_REVOKED_TRIES_FILE,
    )
    if not os.path.exists(path):
      return [], ""
    with open(path, encoding="utf-8") as fh:
      raw = fh.read()
    return [json.loads(line) for line in raw.splitlines()], raw

  def _assert_auth_refused(self, data):
    dauth_data = data[dAuth.DAUTH_SUBKEY]
    self.assertIn("not allowed on mainnet", dauth_data["error"])
    self.assertNotIn("revoked", dauth_data["error"])
    self.assertNotIn("EE_MQTT_HOST", dauth_data)

  def _refusals(self):
    return [msg for msg in self.messages if msg.startswith("dAuth refused revoked")]

  def _unlicensed_writes_logged(self):
    return [msg for msg in self.messages if "has no license: try written to" in msg]

  def _unlicensed_cstore(self):
    self._bookkeeping()
    return {
      key: value for (hkey, key), value in self.plugin._chainstore.items()
      if hkey == DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY
    }

  def test_listed_node_is_refused_whatever_its_license(self):
    for sender, licensed in ((REVOKED, True), ("0xai_" + REVOKED_UNPREFIXED, False)):
      with self.subTest(licensed=licensed):
        self.plugin.bc.is_node_licensed.return_value = licensed
        self._refuse(_auth_body(sender))
    with self.subTest(licensed="lookup raises"):
      self.plugin._dauth_revoked_license_checks.clear()
      self.plugin.bc.is_node_licensed = Mock(side_effect=RuntimeError("rpc down"))
      self._refuse(_auth_body(REVOKED))
    records, _ = self._records()
    self.assertEqual(
      [record["node_address"] for record in records], [REVOKED, "0xai_" + REVOKED_UNPREFIXED, REVOKED],
    )
    self.assertEqual(records[0]["requester_type"], dAuth.DAUTH_SENDER_TYPE_NODE)
    self.assertEqual(records[0]["endpoint"], "get_auth_data")
    self.assertEqual(records[0]["source_ip"], SOURCE_IP)
    self.assertIn(f"({ETH[REVOKED]}) from {SOURCE_IP} on /get_auth_data", self._refusals()[0])
    failed = [msg for msg in self.messages if msg.startswith("dAuth request ")]
    self.assertIn(f"(ETH: {ETH[REVOKED][:6]}...{ETH[REVOKED][-4:]}) from {SOURCE_IP}: ", failed[0])

  def test_unlicensed_revoked_try_writes_one_timestamp_per_node_for_dauth_peers_only(self):
    writes = []
    store = self.plugin.chainstore_hset
    self.plugin.chainstore_hset = lambda **kwargs: writes.append(kwargs) or store(**kwargs)
    self.plugin.time = lambda: 1000.0
    self.plugin.bc.is_node_licensed.return_value = False
    self._refuse(_auth_body(REVOKED))
    self.plugin.bc.is_node_licensed.assert_called_once_with(node_address_eth=ETH[REVOKED])
    records, _ = self._records()
    self.assertEqual(set(records[0]), RECORD_KEYS)
    self.assertEqual(self._unlicensed_cstore(), {REVOKED.removeprefix("0xai_"): 1000.0})
    self.assertEqual(
      {name: value for name, value in writes[0].items() if name not in ("hkey", "key", "value")},
      {
        "extra_peers": ["node-oracle"], "include_default_peers": False, "include_configured_peers": False,
        "timeout": DAUTH_REVOKED_UNLICENSED_WRITE_TIMEOUT, "max_retries": 0,
      },
    )
    self.assertEqual(len(self._unlicensed_writes_logged()), 1)

  def test_licensed_revoked_try_stays_local(self):
    self._refuse(_auth_body(REVOKED))
    self.plugin.bc.is_node_licensed.assert_called_once_with(node_address_eth=ETH[REVOKED])
    self.assertEqual(self._unlicensed_cstore(), {})
    self.assertEqual(len(self._records()[0]), 1)
    self.assertEqual(self._unlicensed_writes_logged(), [])

  def test_unlicensed_tries_within_the_interval_rewrite_nothing(self):
    writes = []
    store = self.plugin.chainstore_hset
    self.plugin.chainstore_hset = lambda **kwargs: writes.append(kwargs) or store(**kwargs)
    now = [1000.0]
    self.plugin.time = lambda: now[0]
    self.plugin.bc.is_node_licensed.return_value = False
    for _ in range(3):
      self._refuse(_auth_body(REVOKED))
    self._refuse(_auth_body("0xai_" + REVOKED_UNPREFIXED))
    self.assertEqual(self.plugin.bc.is_node_licensed.call_count, 2)
    self.assertEqual(len(writes), 2)
    self.assertEqual(
      self._unlicensed_cstore(), {REVOKED.removeprefix("0xai_"): 1000.0, REVOKED_UNPREFIXED: 1000.0},
    )
    self.assertEqual(len(self._unlicensed_writes_logged()), 2)

    now[0] += DAUTH_REVOKED_UNLICENSED_WRITE_INTERVAL
    self._refuse(_auth_body(REVOKED))
    self.assertEqual(len(writes), 3)
    self.assertEqual(self._unlicensed_cstore()[REVOKED.removeprefix("0xai_")], now[0])
    self.assertEqual(len(self._records()[0]), 5)

  def test_timestamp_written_by_another_server_suppresses_the_write(self):
    self.plugin.time = lambda: 1000.0
    self.plugin._chainstore[(DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY, REVOKED.removeprefix("0xai_"))] = 900.0
    self.plugin.chainstore_hset = Mock(side_effect=AssertionError("must not write"))
    self.plugin.bc.is_node_licensed.return_value = False
    self._refuse(_auth_body(REVOKED))
    self.plugin.chainstore_hset.assert_not_called()
    self.assertEqual(self._unlicensed_writes_logged(), [])
    self.assertEqual(len(self._records()[0]), 1)

  def test_license_result_is_reused_for_an_hour(self):
    now = [1000.0]
    self.plugin.time = lambda: now[0]
    for _ in range(2):
      self._refuse(_auth_body(REVOKED))
      now[0] += DAUTH_REVOKED_LICENSE_RETRY_INTERVAL
    self.assertEqual(self.plugin.bc.is_node_licensed.call_count, 1)
    now[0] = 1000.0 + DAUTH_REVOKED_LICENSE_CHECK_INTERVAL
    self._refuse(_auth_body(REVOKED))
    self.assertEqual(self.plugin.bc.is_node_licensed.call_count, 2)

  def test_failed_license_lookup_is_retried_after_a_minute(self):
    now = [1000.0]
    self.plugin.time = lambda: now[0]
    self.plugin.bc.is_node_licensed = Mock(side_effect=RuntimeError("rpc down"))
    for _ in range(2):
      self._refuse(_auth_body(REVOKED))
    self.assertEqual(self.plugin.bc.is_node_licensed.call_count, 1)
    self.assertEqual(self._unlicensed_cstore(), {})
    now[0] += DAUTH_REVOKED_LICENSE_RETRY_INTERVAL
    self.plugin.bc.is_node_licensed = Mock(return_value=False)
    self._refuse(_auth_body(REVOKED))
    self.assertEqual(self._unlicensed_cstore(), {REVOKED.removeprefix("0xai_"): now[0]})
    self.assertEqual(len(self._records()[0]), 3)

  def test_license_or_cstore_failure_keeps_refusing_without_broadcast(self):
    failures = {
      "license call fails": lambda: setattr(
        self.plugin.bc, "is_node_licensed", Mock(side_effect=RuntimeError("rpc down")),
      ),
      "write fails": lambda: setattr(self.plugin, "chainstore_hset", lambda **kwargs: False),
      "no cached dAuth peers": lambda: setattr(self.plugin, "_dauth_registry_internal_peers", []),
    }
    for name, fail in failures.items():
      with self.subTest(name):
        self.setUp()
        self.plugin.bc.is_node_licensed.return_value = False
        fail()
        self._refuse(_auth_body(REVOKED))
        self.assertEqual(self._unlicensed_cstore(), {})
        self.assertEqual(len(self._records()[0]), 1)
        self.assertTrue(any(msg.startswith("Could not") for msg in self.messages))
        self.assertEqual(self._unlicensed_writes_logged(), [])

  def test_rejection_is_the_same_as_for_an_unlinked_node(self):
    revoked_error = self.plugin.process_dauth_request(_auth_body(REVOKED))[dAuth.DAUTH_SUBKEY]["error"]
    self.plugin.bc.is_node_licensed.return_value = False
    unlinked_error = self.plugin.process_dauth_request(_auth_body(ALLOWED))[dAuth.DAUTH_SUBKEY]["error"]
    self.assertEqual(revoked_error.replace(ETH[REVOKED], ETH[ALLOWED]), unlinked_error)

  def test_listed_sdk_requester_is_refused(self):
    body = _auth_body(REVOKED, sender_app_ver=None, sender_core_ver=None)
    self._refuse(body)
    self.assertEqual(self._records()[0][0]["requester_type"], dAuth.DAUTH_SENDER_TYPE_SDK)

  def test_every_spelling_of_a_revoked_key_is_refused(self):
    revoked, spellings = _key_spellings()
    other, _ = _key_spellings()
    self.plugin.bc = BCWrapper(_KeyEngine(), owner=self.plugin)
    self.plugin.os_environ[DAUTH_REVOKED_NODES_ENV_KEY] = revoked
    self.plugin._load_dauth_revoked_nodes()
    self.plugin._is_dauth_revoked_node_licensed = Mock(return_value=False)
    self.plugin._maybe_publish_dauth_revoked_unlicensed_try = Mock(return_value=False)
    version_data = VersionCheckData(result=True, requester_type=dAuth.DAUTH_SENDER_TYPE_NODE)
    for name, sender in spellings.items():
      with self.subTest(spelling=name):
        allowed, msg = self.plugin.check_if_node_allowed(sender, "0x" + "d" * 40, version_data)
        self.assertFalse(allowed)
        self.assertEqual(msg, f"node 0x{'d' * 40} not allowed on mainnet")
    records, _ = self._records()
    self.assertEqual([record["node_address"] for record in records], list(spellings.values()))
    self.assertEqual(len({record["eth_address"] for record in records}), 1)
    for checked in (
      self.plugin._is_dauth_revoked_node_licensed, self.plugin._maybe_publish_dauth_revoked_unlicensed_try,
    ):
      self.assertEqual({call.args[0] for call in checked.call_args_list}, {revoked})
    self.assertFalse(self.plugin._is_dauth_node_revoked("get_auth_data", "0xai_" + other))

  def test_licensed_unlisted_node_is_still_allowed(self):
    data = self.plugin.process_dauth_request(_auth_body(ALLOWED))
    self.assertIn(
      f"dAuth req 'a1b2' success for <{ALLOWED[:8]}...{ALLOWED[-4:]}> 'node-1' "
      f"(ETH: {ETH[ALLOWED][:6]}...{ETH[ALLOWED][-4:]}) from {SOURCE_IP}",
      self.messages,
    )
    # Successful requests carry the non-critical version note in `error`.
    self.assertNotIn("revoked", data[dAuth.DAUTH_SUBKEY]["error"])
    self.assertEqual(data[dAuth.DAUTH_SUBKEY]["EE_MQTT_HOST"], "mqtt-a")
    self.plugin.bc.is_node_licensed.assert_called_once_with(node_address_eth=ETH[ALLOWED])
    self.assertEqual(self._records(), ([], ""))

  def test_secret_endpoints_refuse_listed_senders(self):
    self.plugin._chainstore[(DEEPLOY_JOBS_CSTORE_HKEY, "7")] = "cid-7"
    self.plugin._r1fs_data["cid-7"] = {
      "OWNER": "0xOWNER", "DEEPLOY_SPECS": {"job_id": "7", "current_target_nodes": [REVOKED]},
    }
    self.plugin.bc.protocol_oracles = [REVOKED]
    endpoints = {
      "add_secrets": self.plugin.process_dauth_add_secrets_request,
      "reconcile_job_secrets": self.plugin.process_dauth_reconcile_secrets_request,
      "get_secrets": self.plugin.process_dauth_get_secret_request,
      "reveal_job_secrets": self.plugin.process_dauth_reveal_secret_request,
    }
    for endpoint, process in endpoints.items():
      with self.subTest(endpoint=endpoint):
        body = {
          "EE_SENDER": REVOKED, "EE_ETH_SENDER": ETH[REVOKED], "EE_SIGN": "signature-value",
          "nonce": REQUEST_NONCE, "job_id": "7", "job_secrets": {"TOKEN": "super-secret"},
          "wallet_request": {"job_id": "7"},
        }
        with self.assertRaisesRegex(ValueError, f"Sender {ETH[REVOKED]} not allowed on mainnet"):
          process(body)
    self.assertNotIn((DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"), self.plugin._chainstore)
    self.assertEqual(self.plugin.bc.encrypt_calls, [])
    self.assertEqual([record["endpoint"] for record in self._records()[0]], list(endpoints))

  def test_registry_records_tries_without_secrets(self):
    for _ in range(2):
      with self.assertRaises(ValueError):
        self.plugin.process_dauth_get_secret_request({
          "EE_SENDER": REVOKED, "EE_ETH_SENDER": ETH[REVOKED], "EE_SIGN": "signature-value",
          "nonce": REQUEST_NONCE, "job_id": "7", "job_secrets": {"TOKEN": "super-secret"},
        })
    records, raw = self._records()
    self.assertEqual(len(records), 2)
    self.assertEqual(set(records[1]), RECORD_KEYS)
    self.assertEqual(records[1]["node_address"], REVOKED)
    self.assertEqual(records[1]["eth_address"], ETH[REVOKED])
    for leaked in ("super-secret", "signature-value", "job_secrets", "EE_SIGN", REQUEST_NONCE):
      self.assertNotIn(leaked, raw)
    self.assertTrue(self.messages[-1].startswith("dAuth refused revoked"))

  def test_unsigned_requests_are_not_recorded(self):
    self.plugin.bc.valid_signature = False
    with self.assertRaisesRegex(ValueError, "Invalid request signature"):
      self.plugin.process_dauth_get_secret_request({
        "EE_SENDER": REVOKED, "EE_ETH_SENDER": ETH[REVOKED], "nonce": REQUEST_NONCE, "job_id": "7",
      })
    self.assertEqual(self._records(), ([], ""))

  def test_registry_stops_growing_at_size_cap_but_keeps_refusing(self):
    with patch("extensions.business.dauth.dauth_revoked_nodes.DAUTH_REVOKED_TRIES_MAX_BYTES", 1):
      for _ in range(2):
        self._refuse(_auth_body(REVOKED))
    self.assertEqual(len(self._records()[0]), 1)
    refusals = [msg for msg in self.messages if msg.startswith("dAuth refused revoked")]
    self.assertEqual(len(refusals), 2)
    self.assertIn("registry is full: 1 tries not recorded", self.messages[-1])

  def test_refusal_does_no_lookup_write_or_file_io_in_the_request(self):
    self.plugin.bc.is_node_licensed.return_value = False
    self.plugin.chainstore_hget = Mock(side_effect=AssertionError("not in the request"))
    self.plugin.chainstore_hset = Mock(side_effect=AssertionError("not in the request"))
    self.plugin.get_data_folder = Mock(side_effect=AssertionError("not in the request"))
    for _ in range(2):
      self._assert_auth_refused(self.plugin.process_dauth_request(_auth_body(REVOKED)))
    self.plugin.bc.is_node_licensed.assert_not_called()
    self.assertEqual(len(self._refusals()), 2)
    self.assertEqual(len(self.plugin._dauth_revoked_pending), 2)

  def test_recorder_pass_checks_each_node_once(self):
    self.plugin.bc.is_node_licensed.return_value = False
    for sender in (REVOKED, REVOKED, "0xai_" + REVOKED_UNPREFIXED, REVOKED):
      self._assert_auth_refused(self.plugin.process_dauth_request(_auth_body(sender)))
    self.assertEqual(len(self._records()[0]), 4)
    self.assertEqual(self.plugin.bc.is_node_licensed.call_count, 2)
    self.assertEqual(len(self._unlicensed_cstore()), 2)

  def test_full_backlog_keeps_refusing_without_recording(self):
    with patch("extensions.business.dauth.dauth_revoked_nodes.DAUTH_REVOKED_PENDING_MAX", 1):
      for _ in range(3):
        self._assert_auth_refused(self.plugin.process_dauth_request(_auth_body(REVOKED)))
    self.assertEqual(len(self._records()[0]), 1)
    self.assertIn("backlog was full: 2 tries not recorded", "".join(self.messages))

  def test_recorder_thread_records_tries_and_flushes_on_stop(self):
    self.plugin._start_dauth_revoked_recorder()
    self.addCleanup(self.plugin._stop_dauth_revoked_recorder)
    self.assertEqual(self.plugin._dauth_revoked_thread.name, "dauth-revoked-recorder")
    self._assert_auth_refused(self.plugin.process_dauth_request(_auth_body(REVOKED)))
    deadline = time.time() + 5
    while self.plugin._dauth_revoked_pending and time.time() < deadline:
      time.sleep(0.01)
    self.plugin._stop_dauth_revoked_recorder()
    self.assertFalse(self.plugin._dauth_revoked_thread.is_alive())
    self.assertEqual(len(self._records()[0]), 1)
    self.plugin.bc.is_node_licensed.assert_called_once_with(node_address_eth=ETH[REVOKED])

  def test_chainstore_is_used_only_from_the_plugin_thread(self):
    callers = []
    get, store = self.plugin.chainstore_hget, self.plugin.chainstore_hset
    def track(func):
      return lambda **kwargs: callers.append(threading.current_thread().name) or func(**kwargs)
    self.plugin.chainstore_hget, self.plugin.chainstore_hset = track(get), track(store)
    self.plugin.bc.is_node_licensed.return_value = False
    self.plugin._start_dauth_revoked_recorder()
    self.addCleanup(self.plugin._stop_dauth_revoked_recorder)
    self._assert_auth_refused(self.plugin.process_dauth_request(_auth_body(REVOKED)))
    deadline = time.time() + 5
    while not self.plugin._dauth_revoked_unlicensed_pending and time.time() < deadline:
      time.sleep(0.01)
    self.plugin._stop_dauth_revoked_recorder()
    self.assertEqual(callers, [])
    self.plugin._maybe_publish_dauth_revoked_unlicensed_tries()
    self.assertEqual(callers, [threading.current_thread().name] * 2)
    self.assertEqual(set(self._unlicensed_cstore()), {REVOKED.removeprefix("0xai_")})

  def test_plugin_loop_makes_at_most_one_write_per_call(self):
    self.plugin.time = lambda: 1000.0
    self.plugin.bc.is_node_licensed.return_value = False
    unprefixed_revoked = REVOKED.removeprefix("0xai_")
    for sender in (REVOKED, "0xai_" + REVOKED_UNPREFIXED):
      self._assert_auth_refused(self.plugin.process_dauth_request(_auth_body(sender)))
    self.plugin._flush_dauth_revoked_tries()
    stored = lambda: {
      key for (hkey, key) in self.plugin._chainstore if hkey == DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY
    }
    self.plugin._maybe_publish_dauth_revoked_unlicensed_tries()
    self.assertEqual(stored(), {unprefixed_revoked})
    self.plugin._maybe_publish_dauth_revoked_unlicensed_tries()
    self.assertEqual(stored(), {unprefixed_revoked, REVOKED_UNPREFIXED})

  def test_recent_timestamps_do_not_use_up_the_write_of_a_call(self):
    self.plugin.time = lambda: 1000.0
    self.plugin._chainstore[(DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY, REVOKED.removeprefix("0xai_"))] = 900.0
    self.plugin.bc.is_node_licensed.return_value = False
    for sender in (REVOKED, "0xai_" + REVOKED_UNPREFIXED):
      self._assert_auth_refused(self.plugin.process_dauth_request(_auth_body(sender)))
    self.plugin._flush_dauth_revoked_tries()
    self.plugin._maybe_publish_dauth_revoked_unlicensed_tries()
    self.assertEqual(self.plugin._dauth_revoked_unlicensed_pending, {})
    self.assertEqual(
      self.plugin._chainstore[(DAUTH_REVOKED_UNLICENSED_CSTORE_HKEY, REVOKED_UNPREFIXED)], 1000.0,
    )

  def test_unloaded_denylist_fails_closed(self):
    del self.plugin._dauth_revoked_nodes
    version_data = VersionCheckData(result=True, requester_type=dAuth.DAUTH_SENDER_TYPE_NODE)
    allowed, msg = self.plugin.check_if_node_allowed(ALLOWED, ETH[ALLOWED], version_data)
    self.assertFalse(allowed)
    self.assertIn("not loaded", msg)
    with self.assertRaisesRegex(RuntimeError, "not loaded"):
      self.plugin.process_dauth_get_secret_request({
        "EE_SENDER": ALLOWED, "EE_ETH_SENDER": ETH[ALLOWED], "nonce": REQUEST_NONCE, "job_id": "7",
      })


class DauthRevokedNodeStartupTests(unittest.TestCase):

  BAD_VALUES = {
    "unset": None,
    "empty": "",
    "only separators": " , ,",
    "malformed item": f"{REVOKED},not-an-address",
    "eth address": f"{REVOKED},0x{'a' * 40}",
    "not a public key": f"{REVOKED},0xai_{'Z' * 44}",
  }

  def test_startup_log_has_count_and_hash_but_no_addresses(self):
    messages = []
    _harness(messages)._load_dauth_revoked_nodes()
    expected_hash = hashlib.sha256(
      ",".join(sorted([REVOKED.removeprefix("0xai_"), REVOKED_UNPREFIXED])).encode()
    ).hexdigest()
    self.assertIn(f"{DAUTH_REVOKED_NODES_ENV_KEY}: 2 node addresses, sha256 {expected_hash}", messages[-1])
    for address in (REVOKED.removeprefix("0xai_"), REVOKED_UNPREFIXED):
      self.assertNotIn(address, "".join(messages))

  def test_mainnet_server_refuses_unset_empty_or_malformed_list(self):
    for case, value in self.BAD_VALUES.items():
      with self.subTest(case=case):
        plugin = _harness([], denylist=value)
        plugin._load_dauth_revoked_nodes()
        with self.assertRaisesRegex(ValueError, DAUTH_REVOKED_NODES_ENV_KEY) as ctx:
          plugin._require_dauth_revoked_nodes()
        self.assertNotIn(REVOKED.removeprefix("0xai_"), str(ctx.exception))
        self.assertNotIn("not-an-address", str(ctx.exception))

  def test_other_networks_warn_and_turn_the_check_off(self):
    version_data = VersionCheckData(result=True, requester_type=dAuth.DAUTH_SENDER_TYPE_NODE)
    for evm_network in (dAuth.EvmNetData.TESTNET, dAuth.EvmNetData.DEVNET):
      for case, value in self.BAD_VALUES.items():
        with self.subTest(evm_network=evm_network, case=case):
          messages = []
          plugin = _harness(messages, evm_network=evm_network, denylist=value)
          plugin._load_dauth_revoked_nodes()
          plugin._require_dauth_revoked_nodes()
          self.assertIn("revoked-node check is OFF", messages[-1])
          allowed, _ = plugin.check_if_node_allowed(REVOKED, ETH[REVOKED], version_data)
          self.assertTrue(allowed)

  def _mainnet_manager(self, dauth_oracle):
    manager = gating.DauthServerRegistryGateTests("test_ineligible_server_cannot_resume")
    plugin = manager._make_manager(dauth_oracle=dauth_oracle)
    plugin.evm_network = dAuth.EvmNetData.MAINNET
    return plugin

  def test_mainnet_dauth_server_does_not_start_without_denylist(self):
    plugin = self._mainnet_manager(dauth_oracle=True)
    with self.assertRaisesRegex(ValueError, f"{DAUTH_REVOKED_NODES_ENV_KEY} is not set"):
      plugin.on_init()
    self.assertEqual(plugin._base_init_calls, 0)

  def test_mainnet_node_that_does_not_serve_dauth_starts_but_cannot_resume_without_denylist(self):
    plugin = self._mainnet_manager(dauth_oracle=False)
    plugin.on_init()
    plugin.bc.result = True
    plugin._now += 60 * 60
    self.assertTrue(plugin.should_resume())
    with self.assertRaisesRegex(ValueError, f"{DAUTH_REVOKED_NODES_ENV_KEY} is not set"):
      plugin.on_resume()


if __name__ == "__main__":
  unittest.main()
