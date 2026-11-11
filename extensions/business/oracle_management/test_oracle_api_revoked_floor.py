"""The oracle API signs full availability for eligible revoked node keys."""
import unittest

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


if __name__ == "__main__":
  unittest.main()
