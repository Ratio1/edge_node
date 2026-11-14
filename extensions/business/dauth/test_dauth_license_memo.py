"""dAuth remembers a "not licensed" verdict for a short time instead of asking the chain at every refusal."""
# The test framework.
import unittest
# Stands in for the chain's license lookup and counts its calls.
from unittest.mock import Mock

# The dAuth constants: the key of the answer's settings part.
from ratio1.const.base import dAuth

# The memo's size limit and the time a verdict is remembered.
from extensions.business.dauth.dauth_revoked_nodes import (
  DAUTH_UNLICENSED_MEMO_MAX,
  DAUTH_UNLICENSED_MEMO_SECONDS,
)
# The harness of the revoked-node tests: two requester addresses, their ETH addresses, a request body and the stand-in.
from extensions.business.dauth.test_dauth_revoked_nodes import ALLOWED, ETH, REVOKED, _auth_body, _harness


# A second requester that is neither revoked nor the first one.
OTHER = "0xai_" + "Eother".ljust(44, "4")
# The ETH address the stand-in derives for that second requester.
OTHER_ETH = "0x" + "e" * 40


class DauthLicenseMemoTests(unittest.TestCase):

  def setUp(self):
    """
    Build the dAuth server each test asks.

    A server stand-in with a clock the test moves, a loaded denylist and a license lookup that
    answers "not licensed" until a test says otherwise.

    Returns
    -------
    None
    """
    # The clock, in a list so that the lambda below reads the value a test has set.
    self.now = [1000.0]
    # The stand-in of the revoked-node tests; its log lines are not read here.
    self.plugin = _harness([])
    # Read the denylist the harness has set, so that `REVOKED` is a revoked key here.
    self.plugin._load_dauth_revoked_nodes()
    # The plugin clock, which dates every remembered verdict.
    self.plugin.time = lambda: self.now[0]
    # The stand-in derives this ETH address for the second requester.
    self.plugin.bc.node_eth[OTHER] = OTHER_ETH
    # The chain's license lookup: counted, and "not licensed" for every address.
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
    # The whole request path; only the error text of the answer is of interest.
    return self.plugin.process_dauth_request(body)[dAuth.DAUTH_SUBKEY]["error"]

  def test_repeated_refusals_within_the_memo_time_make_one_lookup(self):
    """A node without a license that asks again and again costs one chain lookup, and every answer has the same text."""
    # The error text of each answer.
    errors = []
    # 12 requests 25 s apart: the pace of a refused node, all inside one memo time.
    for _ in range(12):
      # One request of the unlicensed node.
      errors.append(self._error())
      # The node waits 25 s before it asks again.
      self.now[0] += 25
    # The chain was asked for the first request only.
    self.assertEqual(self.lookup.call_count, 1)
    # A remembered verdict gives the same text as a looked-up one.
    self.assertEqual(len(set(errors)), 1)
    # That text is the refusal of a node without a license.
    self.assertIn(f"{ETH[ALLOWED]} not allowed on mainnet", errors[0])

  def test_verdict_is_looked_up_again_when_the_memo_time_has_passed(self):
    """The remembered verdict lasts the memo time and not longer, so a newly linked license is seen after it."""
    # The first request asks the chain and the verdict is remembered.
    self._error()
    # Just inside the memo time the chain is not asked.
    self.now[0] += DAUTH_UNLICENSED_MEMO_SECONDS - 0.1
    # A second request, 0.1 s before the verdict expires.
    self._error()
    # Still the one lookup of the first request.
    self.assertEqual(self.lookup.call_count, 1)
    # At the memo time it is asked again, and the node is licensed by now.
    self.now[0] += 0.1
    # The chain now says "licensed".
    self.lookup.return_value = True
    # The third request is served: the old verdict no longer answers.
    self.assertNotIn("not allowed", self._error())
    # It cost the second lookup.
    self.assertEqual(self.lookup.call_count, 2)

  def test_licensed_verdict_is_never_remembered(self):
    """A licensed node is looked up at every request, so a license that ends is seen at once."""
    # The chain says "licensed".
    self.lookup.return_value = True
    # Three requests with no time between them.
    for _ in range(3):
      # Each one is served.
      self.assertNotIn("not allowed", self._error())
    # Each one asked the chain.
    self.assertEqual(self.lookup.call_count, 3)
    # Nothing was remembered about the licensed node.
    self.assertEqual(self.plugin._dauth_unlicensed_until, {})
    # The license ends: the next request is refused.
    self.lookup.return_value = False
    # The refusal comes at once, with no remembered "licensed" in the way.
    self.assertIn("not allowed on mainnet", self._error())

  def test_failed_lookup_is_not_remembered(self):
    """A lookup that raises refuses that request with the error text and is tried again at the next request."""
    # The chain cannot be reached.
    self.lookup.side_effect = RuntimeError("rpc down")
    # The request is refused as a failed check, not as an unlicensed node.
    self.assertIn("Error checking if node is allowed", self._error())
    # A failed lookup is no verdict: nothing is remembered.
    self.assertEqual(self.plugin._dauth_unlicensed_until, {})
    # The next request asks the chain again and gets its real verdict.
    self.lookup.side_effect = None
    # The chain answers "licensed" now.
    self.lookup.return_value = True
    # The node is served.
    self.assertNotIn("not allowed", self._error())
    # Two lookups: the failed one and the one that answered.
    self.assertEqual(self.lookup.call_count, 2)

  def test_each_address_has_its_own_verdict(self):
    """One node's remembered verdict does not answer for another node."""
    # The first node asks: one lookup, its verdict is remembered.
    self._error(ALLOWED)
    # The second node asks: its own lookup, although the first node's verdict is remembered.
    self._error(OTHER)
    # The second node asks again: answered from its remembered verdict.
    self._error(OTHER)
    # Two lookups in all, one per ETH address, in the order the nodes first asked.
    self.assertEqual(
      [call.kwargs["node_address_eth"] for call in self.lookup.call_args_list], [ETH[ALLOWED], OTHER_ETH],
    )

  def test_revoked_requester_still_makes_no_lookup_in_the_request(self):
    """A revoked key is refused before the license question, so it neither asks the chain nor fills the memo."""
    # The revoked key is refused with the same text as an unlicensed node.
    self.assertIn("not allowed on mainnet", self._error(REVOKED))
    # The chain was not asked.
    self.lookup.assert_not_called()
    # The memo holds no entry for the revoked key.
    self.assertEqual(self.plugin._dauth_unlicensed_until, {})

  def test_expired_verdicts_are_dropped_when_the_memo_is_full(self):
    """At the size limit the expired verdicts are dropped and the ones still valid are kept."""
    # A full memo: all entries expired but one, which is valid for another 100 s.
    self.plugin._dauth_unlicensed_until = {f"0x{index}": self.now[0] - 1 for index in range(DAUTH_UNLICENSED_MEMO_MAX - 1)}
    # The one entry that has not expired, which brings the memo to its size limit.
    self.plugin._dauth_unlicensed_until["0xvalid"] = self.now[0] + 100
    # One more refusal, of a node the memo does not hold yet.
    self._error()
    # Left in the memo: the valid entry and the new one; every expired entry is gone.
    self.assertEqual(
      self.plugin._dauth_unlicensed_until,
      {"0xvalid": self.now[0] + 100, ETH[ALLOWED]: self.now[0] + DAUTH_UNLICENSED_MEMO_SECONDS},
    )

  def test_memo_below_the_size_limit_is_not_scanned(self):
    """Below the size limit expired verdicts stay until the limit is reached: no scan per refusal."""
    # A memo two entries short of the limit, every entry expired.
    self.plugin._dauth_unlicensed_until = {f"0x{index}": self.now[0] - 1 for index in range(DAUTH_UNLICENSED_MEMO_MAX - 2)}
    # One more refusal, of a node the memo does not hold yet.
    self._error()
    # The expired entries are all still there, plus the new one.
    self.assertEqual(len(self.plugin._dauth_unlicensed_until), DAUTH_UNLICENSED_MEMO_MAX - 1)

  def test_memo_time_is_300_seconds(self):
    """The memo time is the 300 s the change states: a refused node asks about 12 times in it."""
    # The number itself, so that a change of it is a change of this test too.
    self.assertEqual(DAUTH_UNLICENSED_MEMO_SECONDS, 300)


if __name__ == "__main__":
  # Run this file's tests when it is started as a script.
  unittest.main()
