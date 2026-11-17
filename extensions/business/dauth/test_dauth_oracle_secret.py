"""dAuth hands the oracle-only secret from process memory, only to oracles whose client keeps it in memory."""
# The test framework.
import unittest
# Replaces the process-wide holder of the secret for one test.
from unittest.mock import patch

# The SDK engine class that holds the secret.
from ratio1.bc.base import BaseBlockEngine
# The names of the variable and of the dAuth fields.
from ratio1.const.base import dAuth

# The dAuth server stand-in whose answer `fill_dauth_data` fills.
from extensions.business.dauth.test_dauth_registry_gating import _make_dauth_harness
# A requester address, a signed request body and a server stand-in that runs `process_dauth_request`.
from extensions.business.dauth.test_dauth_revoked_nodes import ALLOWED, _auth_body, _harness


# An obvious fake: no real secret is ever used in a test.
FAKE_SECRET = "fake-oracle-secret-for-tests-only"


def _hold(value):
  """
  Hold: make this process hold a given oracle-only secret for one test.

  Patches the private class attribute of the SDK engine that holds the secret; stopping the patch
  gives the attribute its previous value back.

  Parameters
  ----------
  value : str or None
    The secret the SDK engine class holds; None means that this server holds none.

  Returns
  -------
  unittest.mock._patch
    A started patch of the class-wide holder; the caller stops it (``addCleanup``).

  Examples
  --------
  >>> self.addCleanup(_hold(FAKE_SECRET).stop)
  """
  # The holder is a private class attribute; the patch restores its value when stopped.
  holder = patch.object(BaseBlockEngine, "_BaseBlockEngine__oracle_secret", value)
  # Started here, so the test only needs to register the stop.
  holder.start()
  # The caller stops it.
  return holder


class FillDauthDataOracleSecretTests(unittest.TestCase):
  """Who gets the oracle-only secret in a served answer."""

  def setUp(self):
    """
    Make this server hold the fake secret and build a dAuth server stand-in.

    The holder gets its previous value back after each test; the stand-in's protocol oracle is
    `node-oracle`, and `node-runner` is a worker.

    Returns
    -------
    None
    """
    # The server holds the fake secret in process memory for each test.
    self.addCleanup(_hold(FAKE_SECRET).stop)
    # A server stand-in whose protocol oracle is `node-oracle`.
    self.plugin = _make_dauth_harness()

  def _fill(self, requester="node-oracle", memory_secrets=True):
    """
    Fill an answer for one node requester.

    Calls `fill_dauth_data` the way the request path does for a node, with the stand-in's
    protocol oracle as the default requester.

    Parameters
    ----------
    requester : str, optional
      The requester's node address; `node-oracle` is the stand-in's protocol oracle.
    memory_secrets : bool, optional
      Whether the request said that its client keeps memory-only secrets.

    Returns
    -------
    dict
      The filled ``auth`` part of the answer.

    Examples
    --------
    >>> self._fill(requester="node-runner")["EE_SUPERVISOR"]
    False
    """
    # A node request from the given address, through the method the request path calls.
    return self.plugin.fill_dauth_data(
      dauth_data={}, requester_node_address=requester, is_node=True,
      sender_eth_address="0xDAUTH", requester_memory_secrets=memory_secrets,
    )

  def test_an_oracle_whose_client_keeps_it_in_memory_gets_it(self):
    """A protocol oracle that sent the flag gets the held value, under a field without the EE_ prefix."""
    # The answer to an oracle that sent the flag.
    data = self._fill()
    # The requester is served as an oracle.
    self.assertTrue(data["EE_SUPERVISOR"])
    # It gets the value this server holds.
    self.assertEqual(data[dAuth.DAUTH_ORACLE_SECRET], FAKE_SECRET)
    # No client writes a field without the EE_ prefix to its environment.
    self.assertFalse(dAuth.DAUTH_ORACLE_SECRET.startswith(dAuth.DAUTH_ENV_KEYS_PREFIX))

  def test_every_protocol_oracle_gets_it_not_only_dauth_oracles(self):
    """An oracle that is not in the dAuth registry still gets it; only the dAuth token is withheld."""
    # A protocol oracle that the dAuth registry does not list.
    self.plugin.bc.dauth_oracle = False
    # Its answer, with the flag.
    data = self._fill()
    # The dAuth-only token is withheld, as before.
    self.assertNotIn("EE_CLOUDFLARE_TOKEN_DAUTH_MANAGER", data)
    # The oracle-only secret is not: it goes to every protocol oracle.
    self.assertEqual(data[dAuth.DAUTH_ORACLE_SECRET], FAKE_SECRET)

  def test_an_oracle_without_the_flag_does_not_get_it(self):
    """A previous-release oracle sends no flag, so its answer is the same as before."""
    # The answer to an oracle that did not send the flag.
    data = self._fill(memory_secrets=False)
    # Still served as an oracle.
    self.assertTrue(data["EE_SUPERVISOR"])
    # But without the field.
    self.assertNotIn(dAuth.DAUTH_ORACLE_SECRET, data)

  def test_a_worker_never_gets_it(self):
    """A node that is not a protocol oracle gets no secret, even when its client sent the flag."""
    # The answer to a worker that sent the flag.
    data = self._fill(requester="node-runner")
    # Served as a worker.
    self.assertFalse(data["EE_SUPERVISOR"])
    # Without the field.
    self.assertNotIn(dAuth.DAUTH_ORACLE_SECRET, data)

  def test_a_server_that_holds_none_sends_no_field_and_never_reads_the_environment(self):
    """With nothing held, no field is sent, not even None, and a value left in the environment is ignored."""
    # This server holds no secret in memory.
    self.addCleanup(_hold(None).stop)
    # A value under the variable name in the server's environment, which a seed no longer has after its start.
    self.plugin.os_environ[dAuth.DAUTH_ORACLE_SECRET_ENV_KEY] = "environment-value"
    # The answer to an oracle that sent the flag.
    data = self._fill()
    # Served as an oracle.
    self.assertTrue(data["EE_SUPERVISOR"])
    # No field at all: neither None nor the environment's value.
    self.assertNotIn(dAuth.DAUTH_ORACLE_SECRET, data)


class ProcessDauthRequestOracleSecretTests(unittest.TestCase):
  """The request path carries the flag from the signed body, and no log line carries the value."""

  def setUp(self):
    """
    Hold the fake secret and build a server whose log calls and debug lines are all recorded.

    The server is the mainnet stand-in of the revoked-node tests; it serves `ALLOWED` as a licensed
    protocol oracle, with verbose mode and the answer log line on.

    Returns
    -------
    None
    """
    # The server holds the fake secret in process memory for each test.
    self.addCleanup(_hold(FAKE_SECRET).stop)
    # Every line the server logs, its debug lines included.
    self.lines = []
    # A mainnet server stand-in that serves `ALLOWED` as a licensed node.
    self.plugin = _harness(self.lines)
    # `ALLOWED` is a protocol oracle of this server.
    self.plugin.bc.protocol_oracles = [ALLOWED]
    # The debug lines go to the same list.
    self.plugin.Pd = lambda message, *args, **kwargs: self.lines.append(message)
    # Verbose mode on, so every line this path can write is written.
    self.plugin.cfg_dauth_verbose = True
    # The answer log line on too.
    self.plugin.cfg_dauth_log_response = True

  def test_the_flag_in_the_signed_body_decides(self):
    """Only a body with the flag set to true gets the field; without it, or with false, there is none."""
    # Per case: the flag in the body (None: no flag) and whether the field is expected.
    for flag, expected in ((True, True), (False, False), (None, False)):
      # Each case reports on its own.
      with self.subTest(flag=flag):
        # The signed request of the oracle, with the flag or without it.
        extra = {} if flag is None else {dAuth.DAUTH_SENDER_MEMORY_SECRETS: flag}
        # The served answer's `auth` part.
        auth = self.plugin.process_dauth_request(_auth_body(ALLOWED, **extra))[dAuth.DAUTH_SUBKEY]
        # Served as an oracle in every case.
        self.assertTrue(auth["EE_SUPERVISOR"])
        # The field only with the flag set to true.
        self.assertEqual(dAuth.DAUTH_ORACLE_SECRET in auth, expected)

  def test_no_log_line_carries_the_value(self):
    """The served request writes its usual lines, and none of them contains the secret."""
    # A served request that gets the secret.
    auth = self.plugin.process_dauth_request(
      _auth_body(ALLOWED, **{dAuth.DAUTH_SENDER_MEMORY_SECRETS: True})
    )[dAuth.DAUTH_SUBKEY]
    # The answer carries it.
    self.assertEqual(auth[dAuth.DAUTH_ORACLE_SECRET], FAKE_SECRET)
    # The success line was written, so the log path ran.
    self.assertTrue(any("success for" in str(line) for line in self.lines))
    # No line contains the value.
    self.assertFalse(any(FAKE_SECRET in str(line) for line in self.lines))


if __name__ == "__main__":
  # Runs this file's tests when it is started on its own.
  unittest.main()
