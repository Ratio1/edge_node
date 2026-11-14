"""dAuth refusal lines: a verdict on a requester is yellow, a fault red, and the line says who asked for which job."""
# The test framework.
import unittest
# Stands in for the chain's license lookup.
from unittest.mock import Mock

# The dAuth server tests: their harness, the manager plugin class and the fixed request time and source address.
from extensions.business.dauth import test_dauth_registry_gating as gating
# The two chain-store hashes of job secrets, the refusal type and the label under test.
from extensions.business.dauth.dauth_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY,
  DAUTH_JOB_SECRET_REVISIONS_CSTORE_HKEY,
  DauthRefused,
  dauth_request_label,
)
# The harness of the revoked-node tests: two requester addresses, their ETH addresses, a request body and the stand-in.
from extensions.business.dauth.test_dauth_revoked_nodes import ALLOWED, ETH, REVOKED, _auth_body, _harness
# A dAuth server that holds job 7 as an existing pipeline, and the request its runner sends.
from extensions.business.dauth.test_unversioned_secret_resolution import existing_job, request


# The chain-store key of the one secret revision the revision tests use.
REVISION_KEY = (DAUTH_JOB_SECRET_REVISIONS_CSTORE_HKEY, "7|op:deploy")


def _record_lines(plugin):
  """
  Make a plugin stand-in keep every log line with its colour.

  Parameters
  ----------
  plugin : object
    A dAuth harness or manager stand-in.

  Returns
  -------
  list
    Receives `(text, color)` per log call; `color` is None for a plain line. A red line ("r") is
    the kind the logger also copies to the error log.
  """
  # One entry per log call, in the order of the calls.
  lines = []
  # The stand-in's log call keeps the text and the `color` keyword, None when there is none.
  plugin.P = lambda text, *args, **kwargs: lines.append((text, kwargs.get("color")))
  # The list the log call fills.
  return lines


def _revision_job():
  """
  Build a dAuth harness that holds one secret revision of job 7, planned for `node-runner`.

  Returns
  -------
  _DauthHarness
    The harness; `_revision_request()` is the request its planned runner sends.
  """
  # A dAuth server stand-in with an empty chain store.
  plugin = gating._make_dauth_harness()
  # The revision record: its secrets, the pipeline it belongs to and the one node of its plan.
  plugin._chainstore[REVISION_KEY] = {
    "job_id": "7", "revision": "op:deploy", "job_secrets": {"ENV": {"TOKEN": "secret"}},
    "pipeline_cid": "cid-7", "pipelines": {"node-runner": {"NAME": "app"}},
  }
  # The harness with that one revision.
  return plugin


def _revision_request(**overrides):
  """
  Build a `get_secrets` request for the revision of `_revision_job`.

  Parameters
  ----------
  **overrides
    Body fields that replace the defaults.

  Returns
  -------
  dict
    The request body, signed by `node-runner` unless overridden.
  """
  # The planned runner asks for the revision, with a nonce of the harness's own time.
  return {
    "EE_SENDER": "node-runner", "EE_ETH_SENDER": "0xRUNNER", "nonce": gating.REQUEST_NONCE,
    "job_id": "7", "revision": "op:deploy", **overrides,
  }


def _manager(process_name, process):
  """
  Build a registered dAuth manager whose request handling for one endpoint is replaced.

  Parameters
  ----------
  process_name : str
    The name of the handler the endpoint calls, for example ``process_dauth_get_secret_request``.
  process : callable
    Called with the request body in its place.

  Returns
  -------
  tuple
    `(manager, lines)`: the manager stand-in and the `(text, color)` lines it logs.
  """
  # The manager plugin, built without its own start-up.
  manager = gating.DauthManagerPlugin.__new__(gating.DauthManagerPlugin)
  # A registered dAuth server whose answer is returned as the endpoint builds it, unsigned.
  manager._dauth_server_enabled = True
  # The response envelope is not under test: the endpoint's own dictionary comes back.
  manager._DauthManagerPlugin__get_response = lambda data: data
  # The endpoint calls the given handler in place of the manager's own.
  setattr(manager, process_name, process)
  # The manager and the list its log calls fill.
  return manager, _record_lines(manager)


class AuthDataRefusalColorTests(unittest.TestCase):

  def setUp(self):
    """
    Build the dAuth server each test asks.

    A mainnet server stand-in with a loaded denylist, whose log lines are recorded with their
    colour.

    Returns
    -------
    None
    """
    # The stand-in of the revoked-node tests, on mainnet; its own message list is not read.
    self.plugin = _harness([])
    # Read the denylist the harness has set, so that `REVOKED` is a revoked key here.
    self.plugin._load_dauth_revoked_nodes()
    # Every line from here on, with its colour.
    self.lines = _record_lines(self.plugin)

  def test_refusal_of_a_node_without_license_is_one_yellow_line(self):
    """A node the chain says has no license is refused with the same text as before, in yellow."""
    # The chain answers "not licensed".
    self.plugin.bc.is_node_licensed = Mock(return_value=False)
    # The request of a node that is not revoked.
    self.plugin.process_dauth_request(_auth_body(ALLOWED))
    # One line for the refusal.
    self.assertEqual(len(self.lines), 1)
    # Its text and its colour.
    text, color = self.lines[0]
    # Yellow: a verdict on the node, kept out of the error log.
    self.assertEqual(color, "y")
    # The line starts as before, with the nonce of the request.
    self.assertTrue(text.startswith("dAuth request 'a1b2' failed for <"))
    # It ends with the reason as before.
    self.assertTrue(text.endswith(f"Node not allowed to request auth data. node {ETH[ALLOWED]} not allowed on mainnet"))

  def test_refusal_of_a_revoked_key_is_yellow(self):
    """A revoked key gives two lines, the revoked-key line and the refusal line, and neither is red."""
    # The request of a key on the denylist.
    self.plugin.process_dauth_request(_auth_body(REVOKED))
    # Two lines, both yellow.
    self.assertEqual([color for _, color in self.lines], ["y", "y"])
    # The first names the revoked node.
    self.assertTrue(self.lines[0][0].startswith("dAuth refused revoked node"))
    # The second is the refusal line of the request.
    self.assertTrue(self.lines[1][0].startswith("dAuth request 'a1b2' failed for <"))

  def test_version_gate_refusal_stays_red(self):
    """A sender below the minimum release is still refused in red: that refusal can be this server's own doing."""
    # The harness sender is on 2.10.621; a much newer server refuses it as too old.
    self.plugin.ee_ver = "99.0.0"
    # The request of a licensed node that is not revoked.
    self.plugin.process_dauth_request(_auth_body(ALLOWED))
    # One line for the refusal.
    self.assertEqual(len(self.lines), 1)
    # The reason is the version check.
    self.assertIn("Version check failed", self.lines[0][0])
    # The line is red.
    self.assertEqual(self.lines[0][1], "r")

  def test_request_that_could_not_be_judged_stays_red(self):
    """A bad signature, a wrong ETH address and a check that fails on this server are red, in one line each."""
    def bad_signature(plugin):
      """
      Make the signature of every request invalid.

      Parameters
      ----------
      plugin : _DauthHarness
        The server stand-in to change.

      Returns
      -------
      None
      """
      # The signature check of the stand-in answers "not valid".
      plugin.bc.valid_signature = False
    def lookup_fails(plugin):
      """
      Make the license lookup fail.

      Parameters
      ----------
      plugin : _DauthHarness
        The server stand-in to change.

      Returns
      -------
      None
      """
      # The chain call raises, as when the RPC endpoint cannot be reached.
      plugin.bc.is_node_licensed = Mock(side_effect=RuntimeError("rpc down"))
    def denylist_missing(plugin):
      """
      Remove the loaded denylist of revoked keys.

      Parameters
      ----------
      plugin : _DauthHarness
        The server stand-in to change.

      Returns
      -------
      None
      """
      # The server then cannot tell whether a key is revoked.
      del plugin._dauth_revoked_nodes
    # Per expected reason: how the server is prepared and the request it gets.
    cases = {
      "Invalid request signature": (bad_signature, _auth_body(ALLOWED)),
      "Sender eth address and recovered eth address do not match": (lambda plugin: None, _auth_body(ALLOWED, EE_ETH_SENDER="0xdead")),
      "Error checking if node is allowed": (lookup_fails, _auth_body(ALLOWED)),
      "denylist is not loaded": (denylist_missing, _auth_body(ALLOWED)),
    }
    # Every case in turn.
    for text, (prepare, body) in cases.items():
      # Each case reports on its own.
      with self.subTest(text):
        # A fresh server and an empty line list for the case.
        self.setUp()
        # The fault of the case.
        prepare(self.plugin)
        # The request that meets it.
        self.plugin.process_dauth_request(body)
        # One line for the refusal.
        self.assertEqual(len(self.lines), 1)
        # It carries the reason of the case.
        self.assertIn(text, self.lines[0][0])
        # Red: the server could not judge the request, so the line belongs in the error log.
        self.assertEqual(self.lines[0][1], "r")


class SecretRefusalTypeTests(unittest.TestCase):

  def test_verdicts_on_the_requester_raise_the_refusal_type(self):
    """A node outside the job or the revision, a revoked revision and a revoked key are refused with `DauthRefused`."""
    # A server whose revision is revoked by a marker record beside it.
    revoked_marker = _revision_job()
    # The marker of the revoked revision.
    revoked_marker._chainstore[(DAUTH_JOB_SECRET_REVISIONS_CSTORE_HKEY, "7|op:deploy|revoked")] = True
    # A server whose revision record itself says it is revoked.
    revoked_record = _revision_job()
    # The revision record, replaced by its revoked form with no secrets.
    revoked_record._chainstore[REVISION_KEY] = {"job_id": "7", "revision": "op:deploy", "revoked": True}
    # A server with a denylist of revoked keys.
    revoked_key = _harness([])
    # Read the denylist the harness has set, so that `REVOKED` is a revoked key there.
    revoked_key._load_dauth_revoked_nodes()
    # The sender fields of a node that is neither the job's runner nor in the revision's plan.
    other_node = {"EE_SENDER": "node-other", "EE_ETH_SENDER": "0xOTHER"}
    # Per expected text: the server and the request it refuses.
    cases = {
      "not running the existing job": (existing_job(), request(**other_node)),
      "not authorized for the requested job revision": (_revision_job(), _revision_request(**other_node)),
      "revision has been revoked (marker)": (revoked_marker, _revision_request()),
      "revision has been revoked (record)": (revoked_record, _revision_request()),
      "not allowed on mainnet": (
        revoked_key,
        {"EE_SENDER": REVOKED, "EE_ETH_SENDER": ETH[REVOKED], "nonce": gating.REQUEST_NONCE, "job_id": "7"},
      ),
    }
    # Every case in turn.
    for text, (plugin, body) in cases.items():
      # Each case reports on its own.
      with self.subTest(text):
        # The handler raises the refusal type, not a plain error.
        with self.assertRaises(DauthRefused) as raised:
          # The request the server refuses.
          plugin.process_dauth_get_secret_request(body)
        # The answer keeps its text (the part of the case name before any bracket).
        self.assertIn(text.split(" (")[0], str(raised.exception))

  def test_refusal_type_is_a_value_error(self):
    """The type is a ValueError, so the endpoint still answers such a refusal as final (`retryable` False)."""
    # A handler that catches ValueError catches the refusal type too.
    self.assertTrue(issubclass(DauthRefused, ValueError))

  def test_requests_that_could_not_be_judged_do_not_raise_the_refusal_type(self):
    """A bad signature, an expired nonce and missing or inconsistent stored records stay plain errors."""
    # A server that holds the revision and finds every signature invalid.
    bad_signature = _revision_job()
    # The signature check of the stand-in answers "not valid".
    bad_signature.bc.valid_signature = False
    # A server that holds the existing job's pipeline.
    no_bundle = existing_job()
    # Its secret bundle is removed: the pointer of the job is there, the secrets are not.
    no_bundle._chainstore.pop((DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"))
    # Per expected text: the server and the request that fails on it.
    cases = {
      "Invalid request signature": (bad_signature, _revision_request()),
      "nonce is expired": (_revision_job(), _revision_request(nonce=hex((gating.REQUEST_TIME - 121) * 1000))),
      "existing pipeline is unavailable": (gating._make_dauth_harness(), request()),
      "No dAuth secret bundle found for job 7": (no_bundle, request()),
    }
    # Every case in turn.
    for text, (plugin, body) in cases.items():
      # Each case reports on its own.
      with self.subTest(text):
        # The handler raises a ValueError with the text of the case.
        with self.assertRaisesRegex(ValueError, text) as raised:
          # The request that fails.
          plugin.process_dauth_get_secret_request(body)
        # It is not the refusal type, so the endpoint logs it in red.
        self.assertNotIsInstance(raised.exception, DauthRefused)


class SecretRefusalColorTests(unittest.TestCase):

  def _get_secrets(self, plugin, body):
    """
    Send one request through the real `get_secrets` endpoint of a dAuth manager.

    Parameters
    ----------
    plugin : _DauthHarness
      The dAuth harness whose request handling the endpoint calls.
    body : dict
      The request body.

    Returns
    -------
    tuple
      `(response, lines)`: the endpoint's answer and the `(text, color)` lines it logged.
    """
    # A manager whose endpoint hands the request to the harness.
    manager, lines = _manager("process_dauth_get_secret_request", plugin.process_dauth_get_secret_request)
    # The endpoint's answer and what it logged on the way.
    return manager.get_secrets(body), lines

  def test_verdict_is_logged_yellow_and_answered_as_final(self):
    """A node that does not run the job gets the same final answer as before and a yellow line."""
    # The request of a node that is not the runner of the existing job.
    response, lines = self._get_secrets(existing_job(), request(EE_SENDER="node-other", EE_ETH_SENDER="0xOTHER"))
    # The answer text is the one from before.
    self.assertEqual(response["error"], "Sender is not running the existing job.")
    # The answer is final: the requester is told not to try again.
    self.assertIs(response["retryable"], False)
    # One line, yellow.
    self.assertEqual([color for _, color in lines], ["y"])
    # It is the refusal line of the endpoint.
    self.assertIn("Error processing get_secrets request from", lines[0][0])

  def test_faults_are_logged_red(self):
    """A final error that is not a verdict and a retryable one are both still red."""
    # No pointer for the job on this server: a ValueError, final for the requester, but about this server's records.
    response, lines = self._get_secrets(gating._make_dauth_harness(), request())
    # Final for the requester.
    self.assertIs(response["retryable"], False)
    # One line, red.
    self.assertEqual([color for _, color in lines], ["r"])
    # A revision this server does not hold yet: a RuntimeError, which the requester may retry.
    response, lines = self._get_secrets(_revision_job(), _revision_request(revision="op:other"))
    # The requester may try again.
    self.assertIs(response["retryable"], True)
    # One line, red.
    self.assertEqual([color for _, color in lines], ["r"])


class RefusalLineNamesTests(unittest.TestCase):

  def test_get_secrets_refusal_line_names_sender_job_and_reason(self):
    """A refused `get_secrets` request is logged with the sender's address, its ETH address, the job and the reason."""
    # The request of a node that is not the runner of the existing job.
    body = request(EE_SENDER="node-other", EE_ETH_SENDER="0xOTHER")
    # A manager whose endpoint hands the request to a server that holds the job.
    manager, lines = _manager("process_dauth_get_secret_request", existing_job().process_dauth_get_secret_request)
    # The refused request.
    response = manager.get_secrets(body)
    # One yellow line: the source address, then who the request names and for which job, then the reason.
    self.assertEqual(lines, [(
      f"Error processing get_secrets request from {gating.SOURCE_IP} "
      "(sender 'node-other' ETH '0xOTHER' job '7'): Sender is not running the existing job.", "y",
    )])
    # The answer to the requester is the text it got before: only the server's log line changed.
    self.assertEqual(response["error"], "Sender is not running the existing job.")
    # The job's stored secret value is in no line.
    self.assertNotIn("existing-secret", str(lines))

  def test_reconcile_failure_line_names_sender_job_and_the_failing_line_but_no_error_text(self):
    """A failed reconciliation is logged with the sender, the job and the function and line that raised, never the error text."""
    def failing_check(body):
      """
      Fail as a reconciliation check would, with a text that must not be logged.

      Parameters
      ----------
      body : dict
        The request body; not read.

      Returns
      -------
      None
        Never returns.

      Raises
      ------
      ValueError
        Always.
      """
      # The text stands for a secret value that the error of a dependency could carry.
      raise ValueError("credential-in-dependency-error")
    # The line of the `raise`: the last line of the function's code, wherever its docstring ends.
    raised_at = max(line for _, _, line in failing_check.__code__.co_lines())
    # A manager whose reconciliation handler is the failing check.
    manager, lines = _manager("process_dauth_reconcile_secrets_request", failing_check)
    # A request that names its sender and its job.
    response = manager.reconcile_job_secrets({"nonce": "n1", "EE_SENDER": "node-oracle", "EE_ETH_SENDER": "0xORACLE", "job_id": 7})
    # One red line: who asked for which job, the error type, the call path, and the line and function of the raise.
    self.assertEqual(lines, [(
      f"dAuth secret reconciliation failed for request from {gating.SOURCE_IP} "
      "(sender 'node-oracle' ETH '0xORACLE' job 7): ValueError in reconcile_job_secrets > failing_check "
      f"(line {raised_at} of failing_check).", "r",
    )])
    # The caller is still told only that it failed.
    self.assertEqual(response["error"], "dAuth secret reconciliation failed")
    # The error text is neither answered nor logged.
    self.assertNotIn("credential-in-dependency-error", str(response) + str(lines))

  def test_label_escapes_and_cuts_what_the_request_names(self):
    """Text the requester controls cannot add a log line or grow one without bound."""
    # A sender with line breaks in it, and an ETH address and a job id far longer than their limits.
    label = dauth_request_label({"EE_SENDER": "a\nfake line " * 50, "EE_ETH_SENDER": "0x" + "f" * 500, "job_id": "9" * 500})
    # A line break is written as an escape, so the text stays on the line of the refusal.
    self.assertNotIn("\n", label)
    # The escaped form is what the label holds.
    self.assertIn("a\\nfake line", label)
    # 60, 50 and 40 characters of the three values, plus the three field names and separators.
    self.assertEqual(len(label), len("sender  ETH  job ") + 60 + 50 + 40)

  def test_label_of_a_request_without_the_fields(self):
    """A body that names no sender or job, or is not a dictionary, gives a label that says so."""
    # An empty body, one with other fields only, no body and a body that is a text.
    for body in ({}, {"nonce": "n1"}, None, "text"):
      # Each body reports on its own.
      with self.subTest(body=body):
        # The label says None for each of the three values.
        self.assertEqual(dauth_request_label(body), "sender None ETH None job None")


if __name__ == "__main__":
  # Run this file's tests when it is started as a script.
  unittest.main()
