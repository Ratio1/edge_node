"""The oracle API signs full availability for eligible revoked node keys and serves their new keys."""
import unittest
from types import SimpleNamespace
from threading import Event
from unittest.mock import patch

from ratio1.const.base import dAuth

from extensions.business.dauth.dauth_revoked_nodes import NODE_KEY_ROTATIONS_CSTORE_HKEY
from extensions.business.oracle_management import oracle_api
from extensions.business.oracle_management.oracle_api import OracleApiPlugin


REVOKED_ETH = "0x" + "A" * 40
OTHER_ETH = "0x" + "b" * 40
EPOCHS = list(range(526, 560))


def _floor(node_eth, epochs_vals, revoked=(REVOKED_ETH,)):
  plugin = OracleApiPlugin.__new__(OracleApiPlugin)
  plugin._OracleApiPlugin__revoked_nodes = {addr.lower(): "internal" for addr in revoked}
  return dict(zip(EPOCHS, plugin._OracleApiPlugin__apply_revoked_floor(node_eth, EPOCHS, epochs_vals)))


class RevokedFloorTests(unittest.TestCase):

  def setUp(self):
    self.vals = {epoch: 0 for epoch in range(500, 560)}
    self.vals[527] = 40
    self.vals[530] = 100

  def test_eligible_revoked_key_gets_full_availability_only_in_the_window(self):
    result = _floor(REVOKED_ETH.lower(), self.vals)
    self.assertEqual(result[526], 0)
    self.assertEqual(result[527], 40)
    self.assertEqual([result[e] for e in range(528, 558)], [255] * 30)
    self.assertEqual(result[558], 0)

  def test_key_without_availability_before_revocation_is_not_raised(self):
    self.vals[527] = 0
    self.assertEqual(_floor(REVOKED_ETH, self.vals), {e: self.vals[e] for e in EPOCHS})

  def test_key_not_revoked_is_not_raised(self):
    self.vals[521] = 255
    self.assertEqual(_floor(OTHER_ETH, self.vals), {e: self.vals[e] for e in EPOCHS})

  def test_no_list_raises_nothing(self):
    self.assertEqual(_floor(REVOKED_ETH, self.vals, revoked=()), {e: self.vals[e] for e in EPOCHS})


class _LookupPlugin(OracleApiPlugin):
  plugins_shmem = {"__chain_storage_set": True}  # Initialized local ChainStore fixture.
  bc = None  # a plain attribute instead of the plugin's blockchain property


class NodeKeyRotationLookupTests(unittest.TestCase):

  def setUp(self):
    self.plugin = _LookupPlugin.__new__(_LookupPlugin)
    self.plugin._OracleApiPlugin__revoked_nodes = {REVOKED_ETH.lower(): "internal", OTHER_ETH: "internal-2"}
    self.plugin._OracleApiPlugin__rotation_stop = Event()
    self.plugin._OracleApiPlugin__rotation_thread = None
    self.plugin._OracleApiPlugin__last_node_key_rotations_sync = 0
    self.plugin._OracleApiPlugin__get_response = lambda data: data
    self.plugin.bc = SimpleNamespace(address="self", node_address_to_eth_address=lambda node: "eth-" + node)
    self.plugin.P = lambda *args, **kwargs: None
    self.stored = {REVOKED_ETH.lower(): {dAuth.DAUTH_KEY_ROTATION: {"new_node": "new"}}}
    self.plugin.chainstore_hget = lambda hkey, key: self.stored.get(key) if hkey == NODE_KEY_ROTATIONS_CSTORE_HKEY else None

  def test_revoked_keys_are_answered_with_their_new_key_or_none(self):
    result = self.plugin.node_key_rotations([REVOKED_ETH, OTHER_ETH, "0x" + "c" * 40])
    self.assertEqual(result, {"rotations": {
      REVOKED_ETH: {"node": "new", "node_eth_address": "eth-new"},
      OTHER_ETH: None,
    }})

  def test_rotations_are_synced_from_every_other_dauth_server(self):
    entered, proceed = Event(), Event()
    calls = []
    def hsync(**kwargs):
      calls.append(kwargs["extra_peers"])
      if kwargs["extra_peers"] == ["down"]:
        entered.set()  # Keep a real worker in flight while the plugin loop is exercised.
        if not proceed.wait(timeout=3):
          raise AssertionError("test did not release peer")
        raise ValueError("timeout")
      return {"merged_fields": 1}
    self.plugin.chainstore_hsync_from_peer = lambda hkey, peer, timeout: hsync(extra_peers=[peer])
    self.plugin.time = lambda: 1000
    with patch.object(oracle_api, "get_dauth_registry_internal_peers", return_value=["self", "down", "up"]):
      self.plugin._OracleApiPlugin__maybe_sync_node_key_rotations()
      self.assertTrue(entered.wait(timeout=2))
      self.plugin.time = lambda: 2000  # The period expires with an active worker.
      self.plugin._OracleApiPlugin__maybe_sync_node_key_rotations()
      self.assertEqual(calls, [["down"]])
      proceed.set()
      self.plugin._OracleApiPlugin__rotation_thread.join(timeout=2)
      self.assertFalse(self.plugin._OracleApiPlugin__rotation_thread.is_alive())
    self.assertEqual(calls, [["down"], ["up"]])

  def test_shutdown_during_discovery_starts_no_new_peer_wait(self):
    entered, proceed = Event(), Event()
    def discovery(plugin):
      entered.set()  # A blocked registry simulates the in-flight discovery.
      proceed.wait(timeout=3)
      return ["up"]
    self.plugin.time = lambda: 1000
    with patch.object(oracle_api, "get_dauth_registry_internal_peers", discovery):
      with patch.object(self.plugin, "chainstore_hsync_from_peer") as hsync:
        self.plugin._OracleApiPlugin__maybe_sync_node_key_rotations()
        self.assertTrue(entered.wait(timeout=2))
        self.plugin._OracleApiPlugin__rotation_stop.set()
        proceed.set()
        self.plugin._OracleApiPlugin__rotation_thread.join(timeout=2)
        hsync.assert_not_called()


# The internal address of the one node the epoch stand-in knows.
NODE = "0xai_node"
# The last synced epoch of the stand-in unless a test gives another: inside the floor epochs.
SYNCED_EPOCH = 538


class _Epochs:
  """
  Epoch manager stand-in for one node.

  Serves one availability history through both reads the single-epoch endpoints make: the
  whole history (which the API then floors) and the stored value of one epoch (never floored).

  Parameters
  ----------
  history : dict
    {epoch: availability} of the node.
  synced : int
    The last synced epoch.
  stored : int, optional
    When given, the single-epoch read answers this instead of the history's value.
  """

  def __init__(self, history, synced, stored=None):
    """
    Keep the history and the two knobs.

    Parameters
    ----------
    history : dict
      {epoch: availability} of the node.
    synced : int
      The last synced epoch.
    stored : int, optional
      When given, the single-epoch read answers this instead of the history's value.

    Returns
    -------
    None
    """
    # Kept as given; the reads below answer from them.
    self.history, self.synced, self.stored = history, synced, stored

  def get_last_sync_epoch(self):
    """
    Return the last synced epoch.

    Returns
    -------
    int
      The epoch given at construction.
    """
    # The epoch `node_last_epoch` reads.
    return self.synced

  def get_node_epochs(self, node_addr, autocomplete=True, as_list=False):  # pylint: disable=unused-argument
    """
    Return the node's whole history, as the API reads it before applying the floor.

    Parameters
    ----------
    node_addr : str
      Ignored: the stand-in knows one node.
    autocomplete : bool
      Ignored.
    as_list : bool
      Ignored.

    Returns
    -------
    dict
      A copy of {epoch: availability}.
    """
    # A copy, so the caller cannot change the stand-in's history.
    return dict(self.history)

  def get_node_epoch(self, node_addr, epoch_id=None):  # pylint: disable=unused-argument
    """
    Return the stored availability of one epoch, with no floor.

    Parameters
    ----------
    node_addr : str
      Ignored: the stand-in knows one node.
    epoch_id : int
      The epoch to read.

    Returns
    -------
    int
      The history's value, or the `stored` override when one was given.
    """
    # The override stands for a stored value that differs from the history.
    return self.history[epoch_id] if self.stored is None else self.stored

  def get_cached_stats(self, node_addrs=None, online_only=False):
    """
    Return no node statistics.

    Returns
    -------
    dict
      Empty: the endpoints then report no resources and no tags.
    """
    # No statistics for any node.
    return {}

  def get_oracle_state(self, start_epoch, end_epoch):  # pylint: disable=unused-argument
    """
    Report an oracle state that is not valid, so the answer is built without a signature.

    Parameters
    ----------
    start_epoch : int
      Ignored.
    end_epoch : int
      Ignored.

    Returns
    -------
    dict
      The part of the oracle state the endpoints read.
    """
    # Not valid: the endpoints then add no signature to the answer.
    return {"manager": {"valid": False}}

  def eth_to_internal(self, eth_node_address):  # pylint: disable=unused-argument
    """
    Map any ETH address to the one node of the stand-in.

    Parameters
    ----------
    eth_node_address : str
      Ignored.

    Returns
    -------
    str
      The internal address of the node.
    """
    # Every ETH address is the one node.
    return NODE


class _EpochPlugin(OracleApiPlugin):
  """The oracle API plugin with plain attributes instead of its blockchain and network-monitor properties."""
  # A plain attribute, so a test can set the blockchain stand-in.
  bc = None
  # A plain attribute, so a test can set the network-monitor stand-in.
  netmon = None


def _epoch_plugin(node_eth, history, stored=None, synced=SYNCED_EPOCH):
  """
  Build an oracle API plugin that can answer `node_epoch` and `node_last_epoch` for one node.

  Parameters
  ----------
  node_eth : str
    The ETH address the node's internal address maps to.
  history : dict
    {epoch: availability} of the node.
  stored : int, optional
    Makes the single-epoch read differ from the history, as a real inconsistency would.
  synced : int
    The last synced epoch.

  Returns
  -------
  _EpochPlugin
    The plugin, with `REVOKED_ETH` as the only revoked key.
  """
  # Built without the plugin's own start-up: only what the two endpoints read is set below.
  plugin = _EpochPlugin.__new__(_EpochPlugin)
  # One revoked key, stored lowercase as the plugin's own loader stores it.
  plugin._OracleApiPlugin__revoked_nodes = {REVOKED_ETH.lower(): "internal"}
  # The response envelope is not under test: the endpoint's own dictionary comes back.
  plugin._OracleApiPlugin__get_response = lambda data: data
  # Log lines are dropped.
  plugin.P = lambda *args, **kwargs: None
  # The node's internal address maps to `node_eth`; the oracle's own ETH address is listed in the answer.
  plugin.bc = SimpleNamespace(node_address_to_eth_address=lambda node: node_eth, eth_address="0xoracle")
  # The network monitor answers the per-node details the endpoints add to the answer.
  plugin.netmon = SimpleNamespace(
    epoch_manager=_Epochs(history, synced, stored),
    network_node_eeid=lambda addr: "alias", network_node_last_seen=lambda addr: 1.0,
    network_node_is_online=lambda addr: False, network_node_version=lambda addr: "v",
    network_node_is_supervisor=lambda addr: False,
  )
  # The plugin, ready for `node_epoch` and `node_last_epoch`.
  return plugin


class EpochEndpointSelfCheckTests(unittest.TestCase):

  def setUp(self):
    """
    Build the availability history each test starts from.

    A node seen in the last eligibility epoch (527) and absent in every other epoch from 500 to
    559, so an eligible revoked key gets the floor and its stored values in the floor epochs are 0.

    Returns
    -------
    None
    """
    # No availability in any epoch from 500 to 559.
    self.history = {epoch: 0 for epoch in range(500, 560)}
    # Seen in epoch 527, the last one that makes a revoked key eligible for the floor.
    self.history[527] = 40

  def test_batch_uses_one_metadata_generation_and_keeps_claims_on_cold_cache(self):
    plugin = _epoch_plugin(REVOKED_ETH, self.history)
    plugin._OracleApiPlugin__get_response = lambda data, **kw: data
    plugin.time = lambda: 1
    cache_results = [{NODE: {'resources': {'cpu': 2}, 'tags': ['x']}}, {'error': 'cold'}]
    with patch.object(plugin.netmon.epoch_manager, 'get_cached_stats', side_effect=cache_results) as cached:
      query = {REVOKED_ETH: [528, 530], OTHER_ETH: [528, 530]}
      warm = plugin.multi_node_epochs_range(query)
      cold = plugin.multi_node_epochs_range(query)
    self.assertEqual(cached.call_count, 2)  # One read for each two-row request.
    for address in query:
      self.assertEqual(warm[address]['tags'], ['x'])
      self.assertEqual(cold[address]['resources'], {})
      self.assertEqual(cold[address]['tags'], [])
      self.assertEqual(warm[address]['epochs_vals'], cold[address]['epochs_vals'])

  def test_previous_core_uses_its_existing_get_stats_contract(self):
    plugin = _epoch_plugin(REVOKED_ETH, self.history)
    previous = SimpleNamespace(get_stats=lambda online_only: {'online_filter': online_only})
    plugin.netmon.epoch_manager = previous
    self.assertEqual(plugin._OracleApiPlugin__read_stats(online_only=True), {'online_filter': True})

  def test_last_epoch_of_an_eligible_revoked_key_is_answered_with_the_floor(self):
    """`node_last_epoch` answers the floor value for an eligible revoked key instead of failing its self-check."""
    # The last synced epoch (538) is a floor epoch, and the stored value there is 0: before, this raised.
    answer = _epoch_plugin(REVOKED_ETH, self.history).node_last_epoch(node_addr=NODE)
    # The answer is for that epoch and carries the floor value.
    self.assertEqual((answer["last_epoch_id"], answer["last_epoch_val"]), (SYNCED_EPOCH, 255))
    # The same value as a share: 255 of 255.
    self.assertEqual(answer["last_epoch_prc"], 1.0)

  def test_floor_epoch_of_an_eligible_revoked_key_is_answered_with_the_floor(self):
    """`node_epoch` answers the floor value in the first and the last floor epoch, by either address form."""
    # Synced past the floor epochs, so every one of them can be asked for.
    plugin = _epoch_plugin(REVOKED_ETH, self.history, synced=559)
    # The first floor epoch, asked by the internal address.
    self.assertEqual(plugin.node_epoch(epoch=528, node_addr=NODE)["epoch_val"], 255)
    # The last floor epoch, asked by the ETH address.
    self.assertEqual(plugin.node_epoch(epoch=557, eth_node_addr=REVOKED_ETH)["epoch_val"], 255)

  def test_epochs_outside_the_floor_are_answered_with_the_stored_value(self):
    """Before and after the floor epochs the same key is answered with what is stored."""
    # A stored value in the first epoch after the floor.
    self.history[558] = 9
    # Synced past the floor epochs.
    plugin = _epoch_plugin(REVOKED_ETH, self.history, synced=559)
    # The epoch just before the floor: the stored 40, not the floor value.
    self.assertEqual(plugin.node_epoch(epoch=527, node_addr=NODE)["epoch_val"], 40)
    # The epoch just after the floor: the stored 9.
    self.assertEqual(plugin.node_epoch(epoch=558, node_addr=NODE)["epoch_val"], 9)
    # With epoch 558 as the last synced one, `node_last_epoch` is past the floor too.
    self.assertEqual(_epoch_plugin(REVOKED_ETH, self.history, synced=558).node_last_epoch(node_addr=NODE)["last_epoch_val"], 9)

  def test_any_other_difference_still_fails_and_names_both_values(self):
    """A served value that differs from the stored one for another reason still raises, with both values in the text."""
    # A history whose own values are the floor value just before, inside and just after the floor epochs.
    full = {**self.history, 527: 255, 530: 255, 558: 255}
    # Per case: the plugin, the epoch asked for and the two values the error must name. The stored
    # value is 7 in each, which no served value here equals.
    cases = {
      # A key that is not revoked, inside the floor epochs, even when it is served the floor value.
      "not revoked": (_epoch_plugin(OTHER_ETH, self.history, stored=7), 530, "served 0, stored 7"),
      "not revoked, floor value": (_epoch_plugin(OTHER_ETH, full, stored=7), 530, "served 255, stored 7"),
      # A revoked key just outside the floor epochs, even when it is served the floor value.
      "revoked, before the floor": (_epoch_plugin(REVOKED_ETH, full, stored=7, synced=559), 527, "served 255, stored 7"),
      "revoked, after the floor": (_epoch_plugin(REVOKED_ETH, full, stored=7, synced=559), 558, "served 255, stored 7"),
      # A revoked key in a floor epoch whose served value is not the floor value: the node had no
      # availability in the eligibility epochs, so the floor does not apply to it.
      "revoked, not eligible": (
        _epoch_plugin(REVOKED_ETH, {**self.history, 527: 0}, stored=7), 530, "served 0, stored 7",
      ),
      # The same key served a value above the stored one that is not the floor value: only the floor
      # value itself is accepted, not any value higher than what is stored.
      "revoked, not eligible, higher value": (
        _epoch_plugin(REVOKED_ETH, {**self.history, 527: 0, 530: 100}, stored=7), 530, "served 100, stored 7",
      ),
    }
    # Every case in turn.
    for name, (plugin, epoch, text) in cases.items():
      # Each case reports on its own.
      with self.subTest(name):
        # The self-check refuses to answer.
        with self.assertRaises(AssertionError) as raised:
          # The request for the case's epoch.
          plugin.node_epoch(epoch=epoch, node_addr=NODE)
        # The error names the epoch, the served value and the stored value.
        self.assertIn(f"Epoch {epoch}: {text}", str(raised.exception))
    # `node_last_epoch` runs the same check.
    with self.assertRaises(AssertionError) as raised:
      # A key that is not revoked, whose stored value differs from the served one.
      _epoch_plugin(OTHER_ETH, self.history, stored=7).node_last_epoch(node_addr=NODE)
    # The error names the last synced epoch and both values.
    self.assertIn(f"Epoch {SYNCED_EPOCH}: served 0, stored 7", str(raised.exception))

  def test_revoked_key_that_is_not_eligible_is_answered_with_the_stored_value(self):
    """A revoked key with no availability in the eligibility epochs gets no floor and passes the check."""
    # A revoked key never seen in the eligibility epochs, with a stored 3 in a floor epoch.
    plugin = _epoch_plugin(REVOKED_ETH, {**self.history, 527: 0, 530: 3})
    # Served and stored are both 3: answered, with no floor and no error.
    self.assertEqual(plugin.node_epoch(epoch=530, node_addr=NODE)["epoch_val"], 3)


if __name__ == "__main__":
  # Run this file's tests when it is started as a script.
  unittest.main()
