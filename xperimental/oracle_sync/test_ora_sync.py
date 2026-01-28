"""
Oracle Sync test harness and scenario suite.

Run:
  pytest -q xperimental/oracle_sync/test_ora_sync.py
  python3 xperimental/oracle_sync/test_ora_sync.py
"""

from __future__ import annotations

import hashlib
import json
import os
import pickle
import sys
import tempfile
import types
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
  sys.path.insert(0, _REPO_ROOT)

__VER__ = "0.1.0"


def _install_naeural_core_stubs():
  if "naeural_core" in sys.modules:
    return

  naeural_core = types.ModuleType("naeural_core")
  naeural_core_constants = types.ModuleType("naeural_core.constants")
  naeural_core_business = types.ModuleType("naeural_core.business")
  naeural_core_business_base = types.ModuleType("naeural_core.business.base")
  naeural_core_business_base_np = types.ModuleType("naeural_core.business.base.network_processor")

  naeural_core_constants.SUPERVISOR_MIN_AVAIL_PRC = 0.8
  naeural_core_constants.EPOCH_MAX_VALUE = 100
  naeural_core_constants.ORACLE_SYNC_USE_R1FS = False
  naeural_core_constants.ORACLE_SYNC_BLOCKCHAIN_PRESENCE_MIN_THRESHOLD = 0.5
  naeural_core_constants.ORACLE_SYNC_ONLINE_PRESENCE_MIN_THRESHOLD = 0.5

  class _StubPayloadData:
    EE_SENDER = "EE_SENDER"

  class _StubCt:
    PAYLOAD_DATA = _StubPayloadData

  class NetworkProcessorPlugin:
    CONFIG = {
      "VALIDATION_RULES": {},
    }

    def __init__(self):
      self.ct = _StubCt()
      self._state_machines = {}

    @staticmethod
    def payload_handler():
      def _decorator(fn):
        return fn
      return _decorator

    def P(self, msg, **kwargs):
      return msg

    def state_machine_api_init(self, name, state_machine_transitions, initial_state, on_successful_step_callback):
      self._state_machines[name] = {
        "transitions": state_machine_transitions,
        "state": initial_state,
        "on_success": on_successful_step_callback,
      }

    def state_machine_api_get_current_state(self, name):
      return self._state_machines[name]["state"]

    def state_machine_api_set_current_state(self, name, state):
      self._state_machines[name]["state"] = state

    def state_machine_api_callback_do_nothing(self):
      return

    def state_machine_api_step(self, name):
      state = self._state_machines[name]["state"]
      transitions = self._state_machines[name]["transitions"]
      state_info = transitions[state]
      state_callback = state_info["STATE_CALLBACK"]
      state_callback()
      for transition in state_info.get("TRANSITIONS", []):
        if transition["TRANSITION_CONDITION"]():
          transition["ON_TRANSITION_CALLBACK"]()
          self._state_machines[name]["state"] = transition["NEXT_STATE"]
          break
      on_success = self._state_machines[name]["on_success"]
      if on_success:
        on_success()

  naeural_core_business_base_np.NetworkProcessorPlugin = NetworkProcessorPlugin

  sys.modules["naeural_core"] = naeural_core
  sys.modules["naeural_core.constants"] = naeural_core_constants
  sys.modules["naeural_core.business"] = naeural_core_business
  sys.modules["naeural_core.business.base"] = naeural_core_business_base
  sys.modules["naeural_core.business.base.network_processor"] = naeural_core_business_base_np


_install_naeural_core_stubs()

from extensions.business.oracle_sync.oracle_sync_01 import OracleSync01Plugin
from extensions.business.oracle_sync.sync_mixins.ora_sync_constants import (
  FULL_AVAILABILITY_THRESHOLD,
  POTENTIALLY_FULL_AVAILABILITY_THRESHOLD,
  VALUE_STANDARDS,
  EPOCH_MAX_VALUE,
  LOCAL_TABLE_SEND_MULTIPLIER,
  MEDIAN_TABLE_SEND_MULTIPLIER,
  REQUEST_AGREEMENT_TABLE_MULTIPLIER,
  SIGNATURES_EXCHANGE_MULTIPLIER,
  OracleSyncCt,
  SUPERVISOR_MIN_AVAIL_PRC,
)


class FakeClock:
  def __init__(self, start: float = 0.0):
    self._now = start

  def time(self):
    return self._now

  def sleep(self, dt: float):
    self._now += dt

  def now(self, tz=None):
    return datetime.fromtimestamp(self._now, tz=tz)


class FakeDateTime:
  def __init__(self, clock: FakeClock):
    self._clock = clock

  def now(self, tz=None):
    return self._clock.now(tz=tz)


class FakeR1FS:
  def __init__(self, warmed=True):
    self.is_ipfs_warmed = warmed
    self._store = {}
    self._counter = 0
    self.fail_add = False
    self.fail_get = False
    self.raise_add = False

  def add_pickle(self, obj, show_logs=True):
    if self.raise_add:
      raise RuntimeError("fake add error")
    if self.fail_add:
      return None
    self._counter += 1
    cid = f"cid_{self._counter}"
    self._store[cid] = obj
    return cid

  def get_file(self, cid, show_logs=True):
    if self.fail_get or cid not in self._store:
      raise FileNotFoundError(cid)
    fd, path = tempfile.mkstemp(prefix="fake_r1fs_", suffix=".pkl")
    os.close(fd)
    with open(path, "wb") as f:
      pickle.dump(self._store[cid], f)
    return path


class FakeEpochManager:
  def __init__(self, clock: FakeClock, epoch_length: int = 100, current_epoch: int = 2):
    self.clock = clock
    self.epoch_length = epoch_length
    self._current_epoch = current_epoch
    self._last_sync_epoch = current_epoch - 1
    self.epoch_availability = defaultdict(dict)
    self.epoch_signatures = defaultdict(dict)
    self.epoch_valid = defaultdict(lambda: True)
    self.epoch_cids = defaultdict(dict)
    self.faulty_epochs = set()

  def get_current_epoch(self):
    return self._current_epoch

  def set_current_epoch(self, epoch: int):
    self._current_epoch = epoch

  def get_time_epoch(self):
    return self._current_epoch

  def maybe_close_epoch(self):
    return

  def get_current_epoch_end(self, current_epoch):
    epoch_end_ts = (current_epoch + 1) * self.epoch_length
    return datetime.fromtimestamp(epoch_end_ts, tz=timezone.utc)

  def get_current_epoch_availability(self, return_absolute=True, return_max=True):
    total_from_start = min(self.clock.time(), self.epoch_length)
    return total_from_start, total_from_start

  def get_node_previous_epoch(self, node):
    prev_epoch = self._current_epoch - 1
    return self.epoch_availability[prev_epoch].get(node, 0)

  def get_epoch_availability(self, epoch, return_additional=True):
    availability = self.epoch_availability.get(epoch, {})
    signatures = self.epoch_signatures.get(epoch, {})
    cids = self.epoch_cids.get(epoch, {})
    return availability, signatures, cids.get("agreement"), cids.get("signatures")

  def update_epoch_availability(self, epoch, availability_table, agreement_signatures, debug=False,
                                agreement_cid=None, signatures_cid=None):
    self.epoch_availability[epoch] = dict(availability_table)
    self.epoch_signatures[epoch] = dict(agreement_signatures)
    if agreement_cid or signatures_cid:
      self.epoch_cids[epoch] = {
        "agreement": agreement_cid,
        "signatures": signatures_cid,
      }
    self.epoch_valid[epoch] = True
    return True

  def mark_epoch_as_faulty(self, epoch, debug=False):
    self.epoch_valid[epoch] = False
    self.faulty_epochs.add(epoch)
    return True

  def is_epoch_valid(self, epoch):
    return self.epoch_valid[epoch]

  def get_last_sync_epoch(self):
    return self._last_sync_epoch

  def set_last_sync_epoch(self, epoch):
    self._last_sync_epoch = epoch

  def add_cid_for_epoch(self, epoch, agreement_cid, signatures_cid, debug=False):
    self.epoch_cids[epoch] = {
      "agreement": agreement_cid,
      "signatures": signatures_cid,
    }

  def maybe_update_cached_data(self, force=True):
    return

  def save_status(self):
    return


class FakeBlockchain:
  def __init__(self, oracles, current_address):
    self._oracles = list(oracles)
    self.current_address = current_address
    self._verify_override = None
    self.calls = defaultdict(int)

  def get_oracles(self):
    self.calls["get_oracles"] += 1
    return list(self._oracles), None

  def sign(self, dct, add_data=True, use_digest=True):
    sender = self.current_address
    if add_data:
      dct["EE_SENDER"] = sender
    payload = json.dumps({k: dct[k] for k in sorted(dct) if k != "EE_SIGN"}, sort_keys=True)
    sig = hashlib.sha256((payload + sender).encode("utf-8")).hexdigest()
    dct["EE_SIGN"] = sig
    return sig

  def verify(self, dct_data, str_signature=None, sender_address=None):
    if self._verify_override is not None:
      return self._verify_override
    sender = sender_address or dct_data.get("EE_SENDER", "")
    payload = json.dumps({k: dct_data[k] for k in sorted(dct_data) if k != "EE_SIGN"}, sort_keys=True)
    expected = hashlib.sha256((payload + sender).encode("utf-8")).hexdigest()
    signature = dct_data.get("EE_SIGN") if str_signature is None else str_signature
    valid = signature == expected
    message = "valid" if valid else "invalid signature"
    return types.SimpleNamespace(valid=valid, message=message)

  def maybe_add_prefix(self, addr):
    return addr

  def address_is_valid(self, addr):
    return isinstance(addr, str) and len(addr) > 0


class FakeNetmon:
  def __init__(self, epoch_manager: FakeEpochManager, oracles: list[str]):
    self.epoch_manager = epoch_manager
    self._oracles = list(oracles)
    self.all_nodes = list(oracles)

  def network_node_eeid(self, addr):
    return addr[-4:]

  def network_node_is_supervisor(self, addr):
    return addr in self._oracles

  def network_node_is_online(self, addr):
    return addr in self._oracles


class MessageBus:
  def __init__(self, duplicate_rate=0.0, reorder=False, seed=123):
    self._oracles = {}
    self._duplicate_rate = duplicate_rate
    self._reorder = reorder
    self._rng = __import__("random").Random(seed)

  def add_oracle(self, node_addr, oracle):
    self._oracles[node_addr] = oracle

  def broadcast(self, sender, oracle_data):
    deliveries = []
    for addr, oracle in self._oracles.items():
      if addr == sender:
        continue
      payload = {
        oracle.ct.PAYLOAD_DATA.EE_SENDER: sender,
        "ORACLE_DATA": oracle_data,
      }
      deliveries.append((oracle, payload))
      if self._duplicate_rate > 0 and self._rng.random() < self._duplicate_rate:
        deliveries.append((oracle, payload))
    if self._reorder:
      self._rng.shuffle(deliveries)
    for oracle, payload in deliveries:
      oracle.handle_received_payloads(payload)


def _get_numpy_like():
  try:
    import numpy as np  # type: ignore
    return np
  except Exception:
    import statistics

    class _NP:
      @staticmethod
      def median(values):
        return statistics.median(values)

      @staticmethod
      def mean(values):
        return statistics.mean(values)

      class random:
        @staticmethod
        def choice(values):
          return values[0]

    return _NP()


def _json_dumps(data, **kwargs):
  return json.dumps(data, sort_keys=True, **kwargs)


def _get_hash(data, algorithm="sha256"):
  h = hashlib.new(algorithm)
  h.update(data.encode("utf-8"))
  return h.hexdigest()


@dataclass
class OracleHarness:
  node_addr: str
  oracles: list[str]
  epoch_manager: FakeEpochManager
  clock: FakeClock
  bus: MessageBus | None = None
  use_r1fs: bool = False
  use_r1fs_during_consensus: bool = False

  def build(self):
    oracle = OracleSync01Plugin()
    oracle._name__ = "oracle_sync_test"
    oracle.node_addr = self.node_addr
    oracle.time = self.clock.time
    oracle.sleep = self.clock.sleep
    oracle.datetime = FakeDateTime(self.clock)
    oracle.timezone = timezone
    oracle.deque = deque
    oracle.defaultdict = defaultdict
    oracle.json_dumps = _json_dumps
    oracle.deepcopy = lambda d: json.loads(json.dumps(d))
    oracle.os_path = os.path
    oracle.diskapi_load_pickle_from_output = lambda filename: pickle.load(open(filename, "rb"))
    oracle.get_hash = _get_hash
    oracle.np = _get_numpy_like()
    oracle.trace_info = lambda: "trace"
    oracle.get_sender_str = lambda sender: sender[-4:] if isinstance(sender, str) else str(sender)
    oracle.get_elapsed_and_total_time_of_stage = lambda stage=None: (0.0, 0.0)
    oracle.r1fs = FakeR1FS(warmed=True)
    oracle.cfg_debug_sync = False
    oracle.cfg_debug_sync_full = False
    oracle.cfg_send_interval = 1
    oracle.cfg_send_period = 1
    oracle.cfg_oracle_list_refresh_interval = 10
    oracle.cfg_self_assessment_interval = 60
    oracle.cfg_use_r1fs = self.use_r1fs
    oracle.cfg_use_r1fs_during_consensus = self.use_r1fs_during_consensus

    oracle.bc = FakeBlockchain(oracles=self.oracles, current_address=self.node_addr)
    oracle.netmon = FakeNetmon(epoch_manager=self.epoch_manager, oracles=self.oracles)

    def _add_payload_by_fields(oracle_data):
      if self.bus is not None:
        self.bus.broadcast(self.node_addr, oracle_data)

    oracle.add_payload_by_fields = _add_payload_by_fields
    oracle.on_init()
    return oracle


def _set_state(oracle, state):
  if hasattr(oracle, "state_machine_api_set_current_state"):
    oracle.state_machine_api_set_current_state(oracle.state_machine_name, state)
  elif hasattr(oracle, "_state_machines"):
    oracle._state_machines[oracle.state_machine_name]["state"] = state
  else:
    oracle._current_state = state


def _sign_agreement(oracle, compiled_table, epoch):
  signature_dict = {
    OracleSyncCt.COMPILED_AGREED_MEDIAN_TABLE: compiled_table,
    OracleSyncCt.EPOCH: epoch,
  }
  oracle.bc.sign(signature_dict, add_data=True, use_digest=True)
  signature_dict.pop(OracleSyncCt.EPOCH)
  signature_dict.pop(OracleSyncCt.COMPILED_AGREED_MEDIAN_TABLE)
  return signature_dict


@pytest.fixture()
def fake_clock():
  return FakeClock()


@pytest.fixture()
def fake_epoch_manager(fake_clock):
  return FakeEpochManager(clock=fake_clock, epoch_length=EPOCH_MAX_VALUE, current_epoch=2)


def test_constants_sanity():
  assert FULL_AVAILABILITY_THRESHOLD == round(SUPERVISOR_MIN_AVAIL_PRC * EPOCH_MAX_VALUE)
  assert 0 <= POTENTIALLY_FULL_AVAILABILITY_THRESHOLD <= EPOCH_MAX_VALUE
  assert LOCAL_TABLE_SEND_MULTIPLIER > 0
  assert MEDIAN_TABLE_SEND_MULTIPLIER > 0
  assert REQUEST_AGREEMENT_TABLE_MULTIPLIER > 0
  assert SIGNATURES_EXCHANGE_MULTIPLIER > 0
  assert VALUE_STANDARDS[OracleSyncCt.LOCAL_TABLE]["maybe_cid"] is True
  assert VALUE_STANDARDS[OracleSyncCt.MEDIAN_TABLE]["maybe_cid"] is True


def test_r1fs_add_data_to_message(fake_epoch_manager, fake_clock):
  harness = OracleHarness("oracle_a", ["oracle_a"], fake_epoch_manager, fake_clock, use_r1fs=True)
  oracle = harness.build()
  message = {}
  oracle.r1fs.is_ipfs_warmed = False
  oracle.r1fs_add_data_to_message(message_dict=message, data_dict={"a": 1}, data_key="K")
  assert message["K"] == {"a": 1}

  oracle.r1fs.is_ipfs_warmed = True
  message = {}
  oracle.r1fs.fail_add = False
  oracle.r1fs_add_data_to_message(message_dict=message, data_dict={"b": 2}, data_key="K")
  assert isinstance(message["K"], str)

  message = {}
  oracle.r1fs.fail_add = True
  oracle.r1fs_add_data_to_message(message_dict=message, data_dict={"c": 3}, data_key="K")
  assert message["K"] == {"c": 3}

  message = {}
  oracle.r1fs.fail_add = False
  oracle.r1fs.raise_add = True
  oracle.r1fs_add_data_to_message(message_dict=message, data_dict={"d": 4}, data_key="K")
  assert message["K"] == {"d": 4}


def test_r1fs_get_data_from_message(fake_epoch_manager, fake_clock):
  harness = OracleHarness("oracle_a", ["oracle_a"], fake_epoch_manager, fake_clock, use_r1fs=True)
  oracle = harness.build()
  message = {"K": {"a": 1}}
  assert oracle.r1fs_get_data_from_message(message_dict=message, data_key="K") == {"a": 1}

  cid = oracle.r1fs.add_pickle({"b": 2})
  message = {"K": cid}
  assert oracle.r1fs_get_data_from_message(message_dict=message, data_key="K") == {"b": 2}

  oracle.r1fs.fail_get = True
  message = {"K": "missing"}
  assert oracle.r1fs_get_data_from_message(message_dict=message, data_key="K") is None


def test_check_received_oracle_data_for_values(fake_epoch_manager, fake_clock):
  harness = OracleHarness("oracle_a", ["oracle_a"], fake_epoch_manager, fake_clock)
  oracle = harness.build()
  sender = "oracle_b"
  bad = {"STAGE": oracle.STATES.S2_SEND_LOCAL_TABLE}
  assert not oracle._check_received_oracle_data_for_values(
    sender=sender,
    oracle_data=bad,
    expected_variable_names=[OracleSyncCt.STAGE, OracleSyncCt.LOCAL_TABLE],
  )

  good = {
    OracleSyncCt.STAGE: oracle.STATES.S2_SEND_LOCAL_TABLE,
    OracleSyncCt.LOCAL_TABLE: {"n1": 1},
  }
  oracle.bc.sign(good, add_data=True, use_digest=True)
  assert oracle._check_received_oracle_data_for_values(
    sender=sender,
    oracle_data=good,
    expected_variable_names=[OracleSyncCt.STAGE, OracleSyncCt.LOCAL_TABLE],
    expected_stage=oracle.STATES.S2_SEND_LOCAL_TABLE,
  )

  bad_type = {
    OracleSyncCt.STAGE: oracle.STATES.S2_SEND_LOCAL_TABLE,
    OracleSyncCt.LOCAL_TABLE: ["not-a-dict"],
  }
  oracle.bc.sign(bad_type, add_data=True, use_digest=True)
  assert not oracle._check_received_oracle_data_for_values(
    sender=sender,
    oracle_data=bad_type,
    expected_variable_names=[OracleSyncCt.STAGE, OracleSyncCt.LOCAL_TABLE],
    expected_stage=oracle.STATES.S2_SEND_LOCAL_TABLE,
  )

  bad_stage = {
    OracleSyncCt.STAGE: oracle.STATES.S4_SEND_MEDIAN_TABLE,
    OracleSyncCt.LOCAL_TABLE: {"n1": 1},
  }
  oracle.bc.sign(bad_stage, add_data=True, use_digest=True)
  assert not oracle._check_received_oracle_data_for_values(
    sender=sender,
    oracle_data=bad_stage,
    expected_variable_names=[OracleSyncCt.STAGE, OracleSyncCt.LOCAL_TABLE],
    expected_stage=oracle.STATES.S2_SEND_LOCAL_TABLE,
  )

  bad_sig = {
    OracleSyncCt.STAGE: oracle.STATES.S2_SEND_LOCAL_TABLE,
    OracleSyncCt.LOCAL_TABLE: {"n1": 1},
    "EE_SIGN": "bad",
  }
  assert not oracle._check_received_oracle_data_for_values(
    sender=sender,
    oracle_data=bad_sig,
    expected_variable_names=[OracleSyncCt.STAGE, OracleSyncCt.LOCAL_TABLE],
    expected_stage=oracle.STATES.S2_SEND_LOCAL_TABLE,
  )


def test_check_received_epoch_agreed_median_table_ok(fake_epoch_manager, fake_clock):
  harness = OracleHarness("oracle_a", ["oracle_a"], fake_epoch_manager, fake_clock)
  oracle = harness.build()
  _set_state(oracle, oracle.STATES.S0_WAIT_FOR_EPOCH_CHANGE)
  oracle_data = {
    OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE: {"1": {"n1": 1}, "3": {"n1": 2}},
    OracleSyncCt.EPOCH__AGREEMENT_SIGNATURES: {"1": {}, "3": {}},
    OracleSyncCt.EPOCH__IS_VALID: {"1": True, "3": True},
    OracleSyncCt.EPOCH_KEYS: [1, 3],
    OracleSyncCt.STAGE: oracle.STATES.S0_WAIT_FOR_EPOCH_CHANGE,
  }
  assert not oracle._check_received_epoch__agreed_median_table_ok("oracle_b", oracle_data)

  oracle_data = {
    OracleSyncCt.EPOCH__AGREED_MEDIAN_TABLE: {"1": {"n1": 1}, "2": {"n1": 2}},
    OracleSyncCt.EPOCH__AGREEMENT_SIGNATURES: {"1": {}},
    OracleSyncCt.EPOCH__IS_VALID: {"1": True, "2": True},
    OracleSyncCt.EPOCH_KEYS: [1, 2],
    OracleSyncCt.STAGE: oracle.STATES.S0_WAIT_FOR_EPOCH_CHANGE,
  }
  assert not oracle._check_received_epoch__agreed_median_table_ok("oracle_b", oracle_data)


def test_check_too_close_to_epoch_change(fake_epoch_manager, fake_clock):
  harness = OracleHarness("oracle_a", ["oracle_a"], fake_epoch_manager, fake_clock)
  oracle = harness.build()
  oracle._current_epoch = 1
  fake_clock._now = (oracle.netmon.epoch_manager.epoch_length * 2) - 10
  assert oracle._check_too_close_to_epoch_change(show_logs=False)


def test_compute_agreed_median_table_majority(fake_epoch_manager, fake_clock):
  oracles = ["oracle_a", "oracle_b", "oracle_c"]
  harness = OracleHarness("oracle_a", oracles, fake_epoch_manager, fake_clock)
  oracle = harness.build()
  oracle.is_participating = {k: True for k in oracles}
  oracle.dct_median_tables = {
    "oracle_a": {"n1": {"VALUE": 10, "EE_SENDER": "oracle_a"}},
    "oracle_b": {"n1": {"VALUE": 10, "EE_SENDER": "oracle_b"}},
    "oracle_c": {"n1": {"VALUE": 12, "EE_SENDER": "oracle_c"}},
  }
  oracle._compute_agreed_median_table()
  assert oracle.compiled_agreed_median_table["n1"] == 10


def test_compute_agreed_median_table_failure(fake_epoch_manager, fake_clock):
  oracles = ["oracle_a", "oracle_b", "oracle_c"]
  harness = OracleHarness("oracle_a", oracles, fake_epoch_manager, fake_clock)
  oracle = harness.build()
  oracle.is_participating = {k: True for k in oracles}
  oracle.dct_median_tables = {
    "oracle_a": {"n1": {"VALUE": 10, "EE_SENDER": "oracle_a"}},
    "oracle_b": {"n1": {"VALUE": 11, "EE_SENDER": "oracle_b"}},
    "oracle_c": {"n1": {"VALUE": 12, "EE_SENDER": "oracle_c"}},
  }
  oracle._compute_agreed_median_table()
  assert oracle.compiled_agreed_median_table is None


def test_compute_requested_agreed_median_table_majority(fake_epoch_manager, fake_clock, monkeypatch):
  oracles = ["oracle_a", "oracle_b", "oracle_c"]
  harness = OracleHarness("oracle_a", oracles, fake_epoch_manager, fake_clock)
  oracle = harness.build()
  oracle._current_epoch = 4
  oracle._last_epoch_synced = 1
  oracle.dct_agreed_availability_table = {
    "oracle_a": {2: {"n1": 10}, 3: {"n1": 12}},
    "oracle_b": {2: {"n1": 10}, 3: {"n1": 12}},
    "oracle_c": {2: {"n1": 11}, 3: {"n1": 13}},
  }
  oracle.dct_agreed_availability_signatures = {
    "oracle_a": {2: {"oracle_a": {"EE_SIGN": "sig"}}, 3: {"oracle_a": {"EE_SIGN": "sig"}}},
    "oracle_b": {2: {"oracle_b": {"EE_SIGN": "sig"}}, 3: {"oracle_b": {"EE_SIGN": "sig"}}},
    "oracle_c": {2: {"oracle_c": {"EE_SIGN": "sig"}}, 3: {"oracle_c": {"EE_SIGN": "sig"}}},
  }
  oracle.dct_agreed_availability_is_valid = {
    "oracle_a": {2: True, 3: True},
    "oracle_b": {2: True, 3: True},
    "oracle_c": {2: True, 3: True},
  }
  oracle.dct_agreed_availability_cid = {
    "oracle_a": {2: None, 3: None},
    "oracle_b": {2: None, 3: None},
    "oracle_c": {2: None, 3: None},
  }
  oracle.dct_agreement_signatures_cid = {
    "oracle_a": {2: None, 3: None},
    "oracle_b": {2: None, 3: None},
    "oracle_c": {2: None, 3: None},
  }
  monkeypatch.setattr(oracle.np.random, "choice", lambda x: x[0])
  oracle._compute_requested_agreed_median_table()
  assert fake_epoch_manager.epoch_availability[2]["n1"] == 10
  assert fake_epoch_manager.epoch_availability[3]["n1"] == 12


def test_compute_requested_agreed_median_table_failure(fake_epoch_manager, fake_clock):
  oracles = ["oracle_a", "oracle_b"]
  harness = OracleHarness("oracle_a", oracles, fake_epoch_manager, fake_clock)
  oracle = harness.build()
  oracle._current_epoch = 3
  oracle._last_epoch_synced = 0
  oracle.dct_agreed_availability_table = {
    "oracle_a": {1: {"n1": 10}, 2: {"n1": 11}},
    "oracle_b": {1: {"n1": 12}, 2: {"n1": 13}},
  }
  oracle.dct_agreed_availability_signatures = {
    "oracle_a": {1: {}, 2: {}},
    "oracle_b": {1: {}, 2: {}},
  }
  oracle.dct_agreed_availability_is_valid = {
    "oracle_a": {1: True, 2: True},
    "oracle_b": {1: True, 2: True},
  }
  oracle.dct_agreed_availability_cid = {
    "oracle_a": {1: None, 2: None},
    "oracle_b": {1: None, 2: None},
  }
  oracle.dct_agreement_signatures_cid = {
    "oracle_a": {1: None, 2: None},
    "oracle_b": {1: None, 2: None},
  }
  oracle._compute_requested_agreed_median_table()
  assert 1 in fake_epoch_manager.faulty_epochs
  assert 2 in fake_epoch_manager.faulty_epochs


def test_message_queue_bounds(fake_epoch_manager, fake_clock):
  oracles = ["oracle_a", "oracle_b"]
  harness = OracleHarness("oracle_a", oracles, fake_epoch_manager, fake_clock)
  oracle = harness.build()
  sender = "oracle_b"
  for i in range(100):
    oracle.handle_received_payloads({
      oracle.ct.PAYLOAD_DATA.EE_SENDER: sender,
      "ORACLE_DATA": {"idx": i},
    })
  assert len(oracle._oracle_received_messages[sender]) <= 50
  messages = oracle.get_received_messages_from_oracles()
  assert len(messages) == 1


def test_on_init_sets_state(fake_epoch_manager, fake_clock):
  oracles = ["oracle_a"]
  harness = OracleHarness("oracle_a", oracles, fake_epoch_manager, fake_clock)
  oracle = harness.build()
  assert oracle.state_machine_api_get_current_state(oracle.state_machine_name) == oracle.STATES.S8_SEND_REQUEST_AGREED_MEDIAN_TABLE
  assert oracle._oracle_received_messages is not None


def test_process_exception_sets_flag(fake_epoch_manager, fake_clock, monkeypatch):
  harness = OracleHarness("oracle_a", ["oracle_a"], fake_epoch_manager, fake_clock)
  oracle = harness.build()
  monkeypatch.setattr(oracle, "state_machine_api_step", lambda name: (_ for _ in ()).throw(RuntimeError("boom")))
  oracle.process()
  assert oracle.exception_occurred


def test_maybe_refresh_oracle_list_rate_limit(fake_epoch_manager, fake_clock):
  harness = OracleHarness("oracle_a", ["oracle_a"], fake_epoch_manager, fake_clock)
  oracle = harness.build()
  oracle._last_oracle_list_refresh_attempt = oracle.time()
  oracle.bc.calls["get_oracles"] = 0
  oracle.maybe_refresh_oracle_list()
  assert oracle.bc.calls["get_oracles"] == 0


def test_scenario_a_happy_path_consensus(fake_epoch_manager, fake_clock):
  oracles = ["oracle_a", "oracle_b", "oracle_c"]
  bus = MessageBus()
  harnesses = [
    OracleHarness(addr, oracles, fake_epoch_manager, fake_clock, bus=bus)
    for addr in oracles
  ]
  instances = [h.build() for h in harnesses]
  for oracle in instances:
    bus.add_oracle(oracle.node_addr, oracle)

  prev_epoch = fake_epoch_manager.get_current_epoch() - 1
  fake_epoch_manager.set_last_sync_epoch(prev_epoch - 1)
  for oracle in instances:
    oracle._last_epoch_synced = prev_epoch - 1
  for node in oracles:
    fake_epoch_manager.epoch_availability[prev_epoch][node] = FULL_AVAILABILITY_THRESHOLD + 1
  fake_epoch_manager.epoch_availability[prev_epoch]["node_x"] = 40

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S11_ANNOUNCE_PARTICIPANTS)
    oracle._announce_and_observe_participants()
  for oracle in instances:
    oracle._announce_and_observe_participants()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S1_COMPUTE_LOCAL_TABLE)
    oracle._compute_local_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S2_SEND_LOCAL_TABLE)
    oracle._receive_local_table_and_maybe_send_local_table()
  for oracle in instances:
    oracle._receive_local_table_and_maybe_send_local_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S3_COMPUTE_MEDIAN_TABLE)
    oracle._compute_median_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S4_SEND_MEDIAN_TABLE)
    oracle._receive_median_table_and_maybe_send_median_table()
  for oracle in instances:
    oracle._receive_median_table_and_maybe_send_median_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S5_COMPUTE_AGREED_MEDIAN_TABLE)
    oracle._compute_agreed_median_table()
    assert oracle.compiled_agreed_median_table is not None

  compiled = instances[0].compiled_agreed_median_table
  for oracle in instances:
    assert oracle.compiled_agreed_median_table == compiled

  epoch = fake_epoch_manager.get_current_epoch() - 1
  for oracle in instances:
    oracle.compiled_agreed_median_table_signatures[oracle.node_addr] = _sign_agreement(
      oracle, compiled, epoch
    )
  instances[0]._update_epoch_manager_with_agreed_median_table(
    epoch=epoch,
    compiled_agreed_median_table=compiled,
    agreement_signatures=instances[0].compiled_agreed_median_table_signatures,
    epoch_is_valid=True,
  )
  assert fake_epoch_manager.epoch_availability[epoch] == compiled


def test_scenario_b_one_oracle_cannot_participate(fake_epoch_manager, fake_clock, monkeypatch):
  oracles = ["oracle_a", "oracle_b", "oracle_c"]
  bus = MessageBus()
  harnesses = [
    OracleHarness(addr, oracles, fake_epoch_manager, fake_clock, bus=bus)
    for addr in oracles
  ]
  instances = [h.build() for h in harnesses]
  for oracle in instances:
    bus.add_oracle(oracle.node_addr, oracle)

  prev_epoch = fake_epoch_manager.get_current_epoch() - 1
  for node in oracles:
    fake_epoch_manager.epoch_availability[prev_epoch][node] = FULL_AVAILABILITY_THRESHOLD + 1
  fake_epoch_manager.epoch_availability[prev_epoch]["oracle_c"] = FULL_AVAILABILITY_THRESHOLD - 1

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S11_ANNOUNCE_PARTICIPANTS)
    oracle._announce_and_observe_participants()
  for oracle in instances:
    oracle._announce_and_observe_participants()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S1_COMPUTE_LOCAL_TABLE)
    oracle._compute_local_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S2_SEND_LOCAL_TABLE)
    oracle._receive_local_table_and_maybe_send_local_table()
  for oracle in instances:
    oracle._receive_local_table_and_maybe_send_local_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S3_COMPUTE_MEDIAN_TABLE)
    oracle._compute_median_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S4_SEND_MEDIAN_TABLE)
    oracle._receive_median_table_and_maybe_send_median_table()
  for oracle in instances:
    oracle._receive_median_table_and_maybe_send_median_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S5_COMPUTE_AGREED_MEDIAN_TABLE)
    oracle._compute_agreed_median_table()

  compiled = instances[0].compiled_agreed_median_table
  assert compiled is not None

  non_participant = instances[2]
  non_participant._current_epoch = 3
  non_participant._last_epoch_synced = 1
  non_participant.dct_agreed_availability_table = {
    "oracle_a": {2: compiled},
    "oracle_b": {2: compiled},
  }
  non_participant.dct_agreed_availability_signatures = {
    "oracle_a": {2: {"oracle_a": {"EE_SIGN": "sig"}}},
    "oracle_b": {2: {"oracle_b": {"EE_SIGN": "sig"}}},
  }
  non_participant.dct_agreed_availability_is_valid = {
    "oracle_a": {2: True},
    "oracle_b": {2: True},
  }
  non_participant.dct_agreed_availability_cid = {
    "oracle_a": {2: None},
    "oracle_b": {2: None},
  }
  non_participant.dct_agreement_signatures_cid = {
    "oracle_a": {2: None},
    "oracle_b": {2: None},
  }
  monkeypatch.setattr(non_participant.np.random, "choice", lambda x: x[0])
  non_participant._compute_requested_agreed_median_table()
  assert fake_epoch_manager.epoch_availability[2] == compiled


def test_scenario_c_disordered_and_duplicated_messages(fake_epoch_manager, fake_clock):
  oracles = ["oracle_a", "oracle_b", "oracle_c"]
  bus = MessageBus(duplicate_rate=0.5, reorder=True)
  harnesses = [
    OracleHarness(addr, oracles, fake_epoch_manager, fake_clock, bus=bus)
    for addr in oracles
  ]
  instances = [h.build() for h in harnesses]
  for oracle in instances:
    bus.add_oracle(oracle.node_addr, oracle)

  prev_epoch = fake_epoch_manager.get_current_epoch() - 1
  for node in oracles:
    fake_epoch_manager.epoch_availability[prev_epoch][node] = FULL_AVAILABILITY_THRESHOLD + 2

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S11_ANNOUNCE_PARTICIPANTS)
    oracle._announce_and_observe_participants()
  for oracle in instances:
    oracle._announce_and_observe_participants()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S1_COMPUTE_LOCAL_TABLE)
    oracle._compute_local_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S2_SEND_LOCAL_TABLE)
    oracle._receive_local_table_and_maybe_send_local_table()
  for oracle in instances:
    oracle._receive_local_table_and_maybe_send_local_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S3_COMPUTE_MEDIAN_TABLE)
    oracle._compute_median_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S4_SEND_MEDIAN_TABLE)
    oracle._receive_median_table_and_maybe_send_median_table()
  for oracle in instances:
    oracle._receive_median_table_and_maybe_send_median_table()

  for oracle in instances:
    _set_state(oracle, oracle.STATES.S5_COMPUTE_AGREED_MEDIAN_TABLE)
    oracle._compute_agreed_median_table()
    assert oracle.compiled_agreed_median_table is not None


def test_scenario_d_invalid_signature_rejected(fake_epoch_manager, fake_clock):
  harness = OracleHarness("oracle_a", ["oracle_a", "oracle_b"], fake_epoch_manager, fake_clock)
  oracle = harness.build()
  oracle_data = {
    OracleSyncCt.STAGE: oracle.STATES.S2_SEND_LOCAL_TABLE,
    OracleSyncCt.LOCAL_TABLE: {"n1": 1},
  }
  oracle.bc.sign(oracle_data, add_data=True, use_digest=True)
  oracle_data[OracleSyncCt.LOCAL_TABLE]["n1"] = 999
  assert not oracle._check_received_oracle_data_for_values(
    sender="oracle_b",
    oracle_data=oracle_data,
    expected_variable_names=[OracleSyncCt.STAGE, OracleSyncCt.LOCAL_TABLE],
    expected_stage=oracle.STATES.S2_SEND_LOCAL_TABLE,
  )


def test_scenario_e_r1fs_cid_success_and_failure(fake_epoch_manager, fake_clock):
  harness = OracleHarness("oracle_a", ["oracle_a", "oracle_b"], fake_epoch_manager, fake_clock, use_r1fs=True)
  oracle = harness.build()
  oracle.r1fs.is_ipfs_warmed = True
  msg = {}
  oracle.r1fs_add_data_to_message(msg, {"n1": 1}, "DATA")
  cid = msg["DATA"]
  assert isinstance(cid, str)
  assert oracle.r1fs_get_data_from_message(msg, "DATA") == {"n1": 1}

  oracle.r1fs.fail_get = True
  msg = {"DATA": cid}
  assert oracle.r1fs_get_data_from_message(msg, "DATA") is None


def test_scenario_f_historical_sync_multi_epoch(fake_epoch_manager, fake_clock, monkeypatch):
  oracles = ["oracle_a", "oracle_b", "oracle_c"]
  harness = OracleHarness("oracle_a", oracles, fake_epoch_manager, fake_clock)
  oracle = harness.build()
  oracle._current_epoch = 5
  oracle._last_epoch_synced = 1
  oracle.dct_agreed_availability_table = {
    "oracle_a": {2: {"n1": 10}, 3: {"n1": 11}, 4: {"n1": 12}},
    "oracle_b": {2: {"n1": 10}, 3: {"n1": 11}, 4: {"n1": 12}},
    "oracle_c": {2: {"n1": 10}, 3: {"n1": 11}, 4: {"n1": 12}},
  }
  oracle.dct_agreed_availability_signatures = {
    "oracle_a": {2: {}, 3: {}, 4: {}},
    "oracle_b": {2: {}, 3: {}, 4: {}},
    "oracle_c": {2: {}, 3: {}, 4: {}},
  }
  oracle.dct_agreed_availability_is_valid = {
    "oracle_a": {2: True, 3: True, 4: True},
    "oracle_b": {2: True, 3: True, 4: True},
    "oracle_c": {2: True, 3: True, 4: True},
  }
  oracle.dct_agreed_availability_cid = {
    "oracle_a": {2: None, 3: None, 4: None},
    "oracle_b": {2: None, 3: None, 4: None},
    "oracle_c": {2: None, 3: None, 4: None},
  }
  oracle.dct_agreement_signatures_cid = {
    "oracle_a": {2: None, 3: None, 4: None},
    "oracle_b": {2: None, 3: None, 4: None},
    "oracle_c": {2: None, 3: None, 4: None},
  }
  monkeypatch.setattr(oracle.np.random, "choice", lambda x: x[0])
  oracle._compute_requested_agreed_median_table()
  assert fake_epoch_manager.epoch_availability[2]["n1"] == 10
  assert fake_epoch_manager.epoch_availability[3]["n1"] == 11
  assert fake_epoch_manager.epoch_availability[4]["n1"] == 12


if __name__ == "__main__":
  raise SystemExit(pytest.main([__file__]))
