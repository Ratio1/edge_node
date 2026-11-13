"""The oracle API signs full availability for eligible revoked node keys and serves their new keys."""
import unittest
from types import SimpleNamespace
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
  bc = None  # a plain attribute instead of the plugin's blockchain property


class NodeKeyRotationLookupTests(unittest.TestCase):

  def setUp(self):
    self.plugin = _LookupPlugin.__new__(_LookupPlugin)
    self.plugin._OracleApiPlugin__revoked_nodes = {REVOKED_ETH.lower(): "internal", OTHER_ETH: "internal-2"}
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
    calls = []
    def hsync(**kwargs):
      calls.append(kwargs["extra_peers"])
      if kwargs["extra_peers"] == ["down"]:
        raise ValueError("timeout")
    self.plugin.chainstore_hsync = hsync
    self.plugin.time = lambda: 1000
    with patch.object(oracle_api, "get_dauth_registry_internal_peers", return_value=["self", "down", "up"]):
      self.plugin._OracleApiPlugin__maybe_sync_node_key_rotations()
      self.plugin._OracleApiPlugin__maybe_sync_node_key_rotations()
    self.assertEqual(calls, [["down"], ["up"]])


if __name__ == "__main__":
  unittest.main()
