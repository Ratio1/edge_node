"""dAuth remembers a "not licensed" verdict for a short time instead of asking the chain at every refusal."""
import unittest
from unittest.mock import Mock

from ratio1.const.base import dAuth

from extensions.business.dauth.dauth_revoked_nodes import (
  DAUTH_UNLICENSED_MEMO_MAX,
  DAUTH_UNLICENSED_MEMO_SECONDS,
)
from extensions.business.dauth.test_dauth_revoked_nodes import ALLOWED, ETH, REVOKED, _auth_body, _harness


# A second requester that is neither revoked nor the first one.
OTHER = "0xai_" + "Eother".ljust(44, "4")
OTHER_ETH = "0x" + "e" * 40


class DauthLicenseMemoTests(unittest.TestCase):

  def setUp(self):
    """A dAuth server with a clock the test moves and a license lookup that answers "not licensed"."""
    self.now = [1000.0]
    self.plugin = _harness([])
    # Read the denylist the harness has set, so that `REVOKED` is a revoked key here.
    self.plugin._load_dauth_revoked_nodes()
    # The plugin clock, which dates every remembered verdict.
    self.plugin.time = lambda: self.now[0]
    self.plugin.bc.node_eth[OTHER] = OTHER_ETH
    self.lookup = self.plugin.bc.is_node_licensed = Mock(return_value=False)

  def _error(self, sender=ALLOWED):
    """
    Send one node request and return the error text of the answer.

    Parameters
    ----------
    sender : str
      The internal address that signs the request.

    Returns
    -------
    str or None
      `dauth.error` of the answer.
    """
    # The body of the revoked-node tests, signed by `sender` with the ETH address the server derives for it.
    body = {**_auth_body(ALLOWED), "EE_SENDER": sender, "EE_ETH_SENDER": self.plugin.bc.node_eth[sender]}
    return self.plugin.process_dauth_request(body)[dAuth.DAUTH_SUBKEY]["error"]

  def test_repeated_refusals_within_the_memo_time_make_one_lookup(self):
    """A node without a license that asks again and again costs one chain lookup, and every answer has the same text."""
    errors = []
    # 12 requests 25 s apart: the pace of a refused node, all inside one memo time.
    for _ in range(12):
      errors.append(self._error())
      self.now[0] += 25
    self.assertEqual(self.lookup.call_count, 1)
    self.assertEqual(len(set(errors)), 1)
    self.assertIn(f"{ETH[ALLOWED]} not allowed on mainnet", errors[0])

  def test_verdict_is_looked_up_again_when_the_memo_time_has_passed(self):
    """The remembered verdict lasts the memo time and not longer, so a newly linked license is seen after it."""
    self._error()
    # Just inside the memo time the chain is not asked.
    self.now[0] += DAUTH_UNLICENSED_MEMO_SECONDS - 0.1
    self._error()
    self.assertEqual(self.lookup.call_count, 1)
    # At the memo time it is asked again, and the node is licensed by now.
    self.now[0] += 0.1
    self.lookup.return_value = True
    self.assertNotIn("not allowed", self._error())
    self.assertEqual(self.lookup.call_count, 2)

  def test_licensed_verdict_is_never_remembered(self):
    """A licensed node is looked up at every request, so a license that ends is seen at once."""
    self.lookup.return_value = True
    for _ in range(3):
      self.assertNotIn("not allowed", self._error())
    self.assertEqual(self.lookup.call_count, 3)
    self.assertEqual(self.plugin._dauth_unlicensed_until, {})
    # The license ends: the next request is refused.
    self.lookup.return_value = False
    self.assertIn("not allowed on mainnet", self._error())

  def test_failed_lookup_is_not_remembered(self):
    """A lookup that raises refuses that request with the error text and is tried again at the next request."""
    self.lookup.side_effect = RuntimeError("rpc down")
    self.assertIn("Error checking if node is allowed", self._error())
    self.assertEqual(self.plugin._dauth_unlicensed_until, {})
    # The next request asks the chain again and gets its real verdict.
    self.lookup.side_effect = None
    self.lookup.return_value = True
    self.assertNotIn("not allowed", self._error())
    self.assertEqual(self.lookup.call_count, 2)

  def test_each_address_has_its_own_verdict(self):
    """One node's remembered verdict does not answer for another node."""
    self._error(ALLOWED)
    self._error(OTHER)
    self._error(OTHER)
    self.assertEqual(
      [call.kwargs["node_address_eth"] for call in self.lookup.call_args_list], [ETH[ALLOWED], OTHER_ETH],
    )

  def test_revoked_requester_still_makes_no_lookup_in_the_request(self):
    """A revoked key is refused before the license question, so it neither asks the chain nor fills the memo."""
    self.assertIn("not allowed on mainnet", self._error(REVOKED))
    self.lookup.assert_not_called()
    self.assertEqual(self.plugin._dauth_unlicensed_until, {})

  def test_expired_verdicts_are_dropped_when_the_memo_is_full(self):
    """At the size limit the expired verdicts are dropped and the ones still valid are kept."""
    # A full memo: all entries expired but one, which is valid for another 100 s.
    self.plugin._dauth_unlicensed_until = {f"0x{index}": self.now[0] - 1 for index in range(DAUTH_UNLICENSED_MEMO_MAX - 1)}
    self.plugin._dauth_unlicensed_until["0xvalid"] = self.now[0] + 100
    self._error()
    self.assertEqual(
      self.plugin._dauth_unlicensed_until,
      {"0xvalid": self.now[0] + 100, ETH[ALLOWED]: self.now[0] + DAUTH_UNLICENSED_MEMO_SECONDS},
    )

  def test_memo_below_the_size_limit_is_not_scanned(self):
    """Below the size limit expired verdicts stay until the limit is reached: no scan per refusal."""
    self.plugin._dauth_unlicensed_until = {f"0x{index}": self.now[0] - 1 for index in range(DAUTH_UNLICENSED_MEMO_MAX - 2)}
    self._error()
    self.assertEqual(len(self.plugin._dauth_unlicensed_until), DAUTH_UNLICENSED_MEMO_MAX - 1)

  def test_memo_time_is_300_seconds(self):
    """The memo time is the 300 s the change states: a refused node asks about 12 times in it."""
    self.assertEqual(DAUTH_UNLICENSED_MEMO_SECONDS, 300)


if __name__ == "__main__":
  unittest.main()
