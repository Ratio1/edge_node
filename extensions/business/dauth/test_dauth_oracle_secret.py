"""dAuth hands the oracle-only secret from process memory, only to oracles whose client keeps it in memory."""
# Copies of a signed request and of an answer, as a third party or a log would keep them.
import copy
# The environment the oracle's client writes its dAuth keys to, restored after a test.
import os
# A folder of its own for the key files of the real engines.
import tempfile
# The test framework.
import unittest
# Replaces the process-wide holder of the secret, the HTTP call and module values for one test.
from unittest.mock import Mock, patch
# A new engine name per engine: engines are per-name multitons.
from uuid import uuid4

# The node's blockchain wrapper, whose encrypt_str dAuth calls.
from naeural_core.utils.plugins_base.bc_wrapper import BCWrapper
# The logger a real engine needs.
from ratio1 import Logger
# The engine class a node builds, with a real key.
from ratio1.bc import DefaultBlockEngine
# The SDK module whose VPN flag and version values a test sets.
from ratio1.bc import base as bc_base
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
# What the stand-in's encrypt_str returns for any text.
STAND_IN_CIPHERTEXT = "encrypted-secret-bundle"
# A dAuth URL that no request reaches: the HTTP call is replaced.
DAUTH_URL = "https://dauth.invalid/get_auth_data"


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
    """A protocol oracle that sent the flag gets the held value encrypted to its address, under a field without the
    EE_ prefix."""
    # The answer to an oracle that sent the flag.
    data = self._fill()
    # The requester is served as an oracle.
    self.assertTrue(data["EE_SUPERVISOR"])
    # The value this server holds was encrypted to the requester, and the field carries only that encryption.
    self.assertEqual((self.plugin.bc.encrypt_calls, data[dAuth.DAUTH_ORACLE_SECRET]),
                     ([(FAKE_SECRET, "node-oracle")], STAND_IN_CIPHERTEXT))
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
    # The oracle-only secret is not: it goes to every protocol oracle, encrypted to it.
    self.assertEqual((self.plugin.bc.encrypt_calls, data[dAuth.DAUTH_ORACLE_SECRET]),
                     ([(FAKE_SECRET, "node-oracle")], STAND_IN_CIPHERTEXT))

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
    # The answer carries it, encrypted to the requester.
    self.assertEqual((self.plugin.bc.encrypt_calls, auth[dAuth.DAUTH_ORACLE_SECRET]),
                     ([(FAKE_SECRET, ALLOWED)], STAND_IN_CIPHERTEXT))
    # The success line was written, so the log path ran.
    self.assertTrue(any("success for" in str(line) for line in self.lines))
    # No line contains the value.
    self.assertFalse(any(FAKE_SECRET in str(line) for line in self.lines))


def _engine(folder, name):
  """
  Engine: build a real SDK block engine, with a key of its own, whose log lines are kept.

  Parameters
  ----------
  folder : str
    The folder of its logger and key file.
  name : str
    The start of its engine name and the name of its key file.

  Returns
  -------
  tuple
    ``(engine, lines)``: the engine, and the list each of its log lines is added to.

  Examples
  --------
  >>> oracle, lines = _engine(folder, "oracle")
  >>> oracle.address.startswith("0xai_")
  True
  """
  # The lines the engine logs.
  lines = []
  # A silent logger in the given folder.
  log = Logger(lib_name=name, base_folder=folder, app_folder=name, silent=True)
  # Each line kept instead of printed.
  log.P = lambda text, *args, **kwargs: lines.append(str(text))
  # A new engine name, so the multiton builds a new engine and its key.
  return DefaultBlockEngine(name=name + uuid4().hex, log=log, config={"PEM_FILE": name + ".pem"}), lines


class RealKeysTests(unittest.TestCase):
  """With real keys: the oracle's own start-up dAuth gets the value, and a replay of its request gives no one else."""

  def setUp(self):
    """
    Build an oracle, a dAuth server and a third party with real keys, and a server that uses the server's key.

    The server stand-in serves the oracle as a licensed protocol oracle, checks request signatures with
    the server engine, encrypts through the node's blockchain wrapper around that engine, and holds the
    fake secret.

    Returns
    -------
    None
    """
    # The server holds the fake secret in process memory for each test.
    self.addCleanup(_hold(FAKE_SECRET).stop)
    # A folder for the engines' key files.
    folder = tempfile.TemporaryDirectory()
    # Removed after the test.
    self.addCleanup(folder.cleanup)
    # The oracle (whose log lines are kept), the dAuth server and a third party, each with a key of its own.
    (self.oracle, self.oracle_lines), (self.server, _), (self.other, _) = (
      _engine(folder.name, name) for name in ("oracle", "server", "other"))
    # The server stand-in, with its log lines kept.
    self.plugin = _harness([])
    # Request signatures checked by the server engine.
    self.plugin.bc.verify = self.server.verify
    # Encryption as on a node: the blockchain wrapper's encrypt_str around the server engine.
    self.plugin.bc.encrypt_str = BCWrapper(self.server, owner=self.plugin).encrypt_str
    # The oracle's ETH address, as the registry gives it.
    self.plugin.bc.node_eth[self.oracle.address] = self.oracle.eth_address
    # The oracle is a protocol oracle of this server.
    self.plugin.bc.protocol_oracles = [self.oracle.address]
    # The answers the server sent, as copies taken before the client reads them.
    self.answers = []

  def _serve(self, url, json, timeout):
    """
    Serve: answer one HTTP request of the oracle's client as the dAuth endpoint does.

    The server stand-in processes the signed request, and the server engine signs the result, as the
    endpoint's answer is signed. A copy of each answer is kept in ``self.answers``.

    Parameters
    ----------
    url : str
      The dAuth URL; not used.
    json : dict
      The request, ``{"body": <signed request>}``.
    timeout : tuple
      The request's timeouts; not used.

    Returns
    -------
    unittest.mock.Mock
      A status 200 response whose JSON is ``{"result": <signed answer>}``.

    Examples
    --------
    >>> self._serve(DAUTH_URL, {"body": body}, (60, 120)).status_code
    200
    """
    # The answer the request path builds, with the server's alias.
    result = {**self.plugin.process_dauth_request(json["body"]), "server_alias": "server"}
    # Signed by the server engine, as the endpoint's answer is.
    self.server.sign(result)
    # A copy, kept before the client pops fields out of it.
    self.answers.append(copy.deepcopy(result))
    # A status 200 response that carries it.
    response = Mock(status_code=200)
    # Its JSON.
    response.json.return_value = {"result": result}
    # What requests.post returns to the client.
    return response

  def _start_up_dauth(self):
    """
    Start-up dAuth: run the oracle's own client once against the server, on a debug network.

    The client is the SDK's ``dauth_autocomplete`` of the oracle engine; its one HTTP request goes to
    ``_serve``. The versions it declares are above every minimum, no VPN is assumed, and the keys it
    writes to the environment are removed afterwards.

    Returns
    -------
    dict
      The signed request the client sent (its ``body``).

    Examples
    --------
    >>> self._start_up_dauth()["sender_memory_secrets"]
    True
    """
    # The HTTP call, the VPN flag, the declared versions and the environment, for this run only.
    with patch("ratio1.bc.base.requests.post", side_effect=self._serve) as post, \
         patch.object(bc_base, "EE_VPN_IMPL", False), patch.object(bc_base, "app_version", "2.10.730"), \
         patch.object(bc_base, "core_version", "7.7.360"), patch.dict(os.environ):
      # The start-up dAuth on devnet, where debug logging is forced on.
      self.oracle.dauth_autocomplete(dauth_endp=DAUTH_URL, network="devnet", max_tries=1, sender_alias="oracle")
    # The signed request of that one call.
    return post.call_args.kwargs["json"]["body"]

  def test_the_oracle_gets_the_value_through_its_own_start_up_dauth(self):
    """The oracle's own client gets an answer whose field is not the value, decrypts it with its key, holds the
    value, and logs neither the value nor its request's signature."""
    # The oracle's start-up dAuth; the holder is the same class attribute, so the client's write replaces the server's.
    body = self._start_up_dauth()
    # The answer carried the field, and the value is in no part of it.
    self.assertEqual(
      [(dAuth.DAUTH_ORACLE_SECRET in answer["auth"], FAKE_SECRET in str(answer)) for answer in self.answers],
      [(True, False)],
    )
    # The client decrypted the field into the holder: the fake value, not its encrypted form.
    self.assertEqual(BaseBlockEngine.oracle_secret(), FAKE_SECRET)
    # Its one line about it names the server.
    self.assertEqual(
      sum("kept in process memory" in line and self.server.address in line for line in self.oracle_lines), 1,
    )
    # No line of the oracle carries the value or the signature of its request.
    self.assertFalse(any(FAKE_SECRET in line or body["EE_SIGN"] in line for line in self.oracle_lines))

  def test_a_replayed_request_gives_no_one_else_the_value(self):
    """A third party that sends the oracle's signed request again, three times, is served each time, but the field
    is ciphertext that its key does not decrypt; only the oracle's key does."""
    # The oracle's signed request, as anyone on its way to the server could copy it.
    body = self._start_up_dauth()
    # The server holds the fake value again: the oracle's client wrote to the same class-wide holder.
    self.addCleanup(_hold(FAKE_SECRET).stop)
    # The field of each of three replays of a copy of it.
    fields = [self.plugin.process_dauth_request(copy.deepcopy(body))[dAuth.DAUTH_SUBKEY][dAuth.DAUTH_ORACLE_SECRET]
              for _ in range(3)]
    # Per replay: the value is not in the field, the third party cannot decrypt it, the oracle can.
    self.assertEqual(
      [(FAKE_SECRET in field, self.other.decrypt(field, self.server.address),
        self.oracle.decrypt(field, self.server.address)) for field in fields],
      [(False, None, FAKE_SECRET)] * 3,
    )


if __name__ == "__main__":
  # Runs this file's tests when it is started on its own.
  unittest.main()
