"""dAuth refusal lines: a verdict on a requester is yellow, a fault red, and the line says who asked for which job."""
import unittest
from unittest.mock import Mock

from extensions.business.dauth import test_dauth_registry_gating as gating
from extensions.business.dauth.dauth_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY,
  DAUTH_JOB_SECRET_REVISIONS_CSTORE_HKEY,
  DauthRefused,
  dauth_request_label,
)
from extensions.business.dauth.test_dauth_revoked_nodes import ALLOWED, ETH, REVOKED, _auth_body, _harness
from extensions.business.dauth.test_unversioned_secret_resolution import existing_job, request


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
  lines = []
  plugin.P = lambda text, *args, **kwargs: lines.append((text, kwargs.get("color")))
  return lines


def _revision_job():
  """
  Build a dAuth harness that holds one secret revision of job 7, planned for `node-runner`.

  Returns
  -------
  _DauthHarness
    The harness; `_revision_request()` is the request its planned runner sends.
  """
  plugin = gating._make_dauth_harness()
  plugin._chainstore[REVISION_KEY] = {
    "job_id": "7", "revision": "op:deploy", "job_secrets": {"ENV": {"TOKEN": "secret"}},
    "pipeline_cid": "cid-7", "pipelines": {"node-runner": {"NAME": "app"}},
  }
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
  manager = gating.DauthManagerPlugin.__new__(gating.DauthManagerPlugin)
  # A registered dAuth server whose answer is returned as the endpoint builds it, unsigned.
  manager._dauth_server_enabled = True
  manager._DauthManagerPlugin__get_response = lambda data: data
  setattr(manager, process_name, process)
  return manager, _record_lines(manager)


class AuthDataRefusalColorTests(unittest.TestCase):

  def setUp(self):
    """A mainnet dAuth server with a loaded denylist; its log lines are recorded with their colour."""
    self.plugin = _harness([])
    self.plugin._load_dauth_revoked_nodes()
    self.lines = _record_lines(self.plugin)

  def test_refusal_of_a_node_without_license_is_one_yellow_line(self):
    """A node the chain says has no license is refused with the same text as before, in yellow."""
    self.plugin.bc.is_node_licensed = Mock(return_value=False)
    self.plugin.process_dauth_request(_auth_body(ALLOWED))
    self.assertEqual(len(self.lines), 1)
    text, color = self.lines[0]
    self.assertEqual(color, "y")
    self.assertTrue(text.startswith("dAuth request 'a1b2' failed for <"))
    self.assertTrue(text.endswith(f"Node not allowed to request auth data. node {ETH[ALLOWED]} not allowed on mainnet"))

  def test_refusal_of_a_revoked_key_is_yellow(self):
    """A revoked key gives two lines, the revoked-key line and the refusal line, and neither is red."""
    self.plugin.process_dauth_request(_auth_body(REVOKED))
    self.assertEqual([color for _, color in self.lines], ["y", "y"])
    self.assertTrue(self.lines[0][0].startswith("dAuth refused revoked node"))
    self.assertTrue(self.lines[1][0].startswith("dAuth request 'a1b2' failed for <"))

  def test_version_gate_refusal_stays_red(self):
    """A sender below the minimum release is still refused in red: that refusal can be this server's own doing."""
    # The harness sender is on 2.10.621; a much newer server refuses it as too old.
    self.plugin.ee_ver = "99.0.0"
    self.plugin.process_dauth_request(_auth_body(ALLOWED))
    self.assertEqual(len(self.lines), 1)
    self.assertIn("Version check failed", self.lines[0][0])
    self.assertEqual(self.lines[0][1], "r")

  def test_request_that_could_not_be_judged_stays_red(self):
    """A bad signature, a wrong ETH address and a check that fails on this server are red, in one line each."""
    def bad_signature(plugin):
      plugin.bc.valid_signature = False
    def lookup_fails(plugin):
      plugin.bc.is_node_licensed = Mock(side_effect=RuntimeError("rpc down"))
    def denylist_missing(plugin):
      del plugin._dauth_revoked_nodes
    cases = {
      "Invalid request signature": (bad_signature, _auth_body(ALLOWED)),
      "Sender eth address and recovered eth address do not match": (lambda plugin: None, _auth_body(ALLOWED, EE_ETH_SENDER="0xdead")),
      "Error checking if node is allowed": (lookup_fails, _auth_body(ALLOWED)),
      "denylist is not loaded": (denylist_missing, _auth_body(ALLOWED)),
    }
    for text, (prepare, body) in cases.items():
      with self.subTest(text):
        self.setUp()
        prepare(self.plugin)
        self.plugin.process_dauth_request(body)
        self.assertEqual(len(self.lines), 1)
        self.assertIn(text, self.lines[0][0])
        self.assertEqual(self.lines[0][1], "r")


class SecretRefusalTypeTests(unittest.TestCase):

  def test_verdicts_on_the_requester_raise_the_refusal_type(self):
    """A node outside the job or the revision, a revoked revision and a revoked key are refused with `DauthRefused`."""
    revoked_marker = _revision_job()
    revoked_marker._chainstore[(DAUTH_JOB_SECRET_REVISIONS_CSTORE_HKEY, "7|op:deploy|revoked")] = True
    revoked_record = _revision_job()
    revoked_record._chainstore[REVISION_KEY] = {"job_id": "7", "revision": "op:deploy", "revoked": True}
    revoked_key = _harness([])
    revoked_key._load_dauth_revoked_nodes()
    other_node = {"EE_SENDER": "node-other", "EE_ETH_SENDER": "0xOTHER"}
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
    for text, (plugin, body) in cases.items():
      with self.subTest(text):
        with self.assertRaises(DauthRefused) as raised:
          plugin.process_dauth_get_secret_request(body)
        # The answer keeps its text (the part of the case name before any bracket).
        self.assertIn(text.split(" (")[0], str(raised.exception))

  def test_refusal_type_is_a_value_error(self):
    """The type is a ValueError, so the endpoint still answers such a refusal as final (`retryable` False)."""
    self.assertTrue(issubclass(DauthRefused, ValueError))

  def test_requests_that_could_not_be_judged_do_not_raise_the_refusal_type(self):
    """A bad signature, an expired nonce and missing or inconsistent stored records stay plain errors."""
    bad_signature = _revision_job()
    bad_signature.bc.valid_signature = False
    no_bundle = existing_job()
    no_bundle._chainstore.pop((DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"))
    cases = {
      "Invalid request signature": (bad_signature, _revision_request()),
      "nonce is expired": (_revision_job(), _revision_request(nonce=hex((gating.REQUEST_TIME - 121) * 1000))),
      "existing pipeline is unavailable": (gating._make_dauth_harness(), request()),
      "No dAuth secret bundle found for job 7": (no_bundle, request()),
    }
    for text, (plugin, body) in cases.items():
      with self.subTest(text):
        with self.assertRaisesRegex(ValueError, text) as raised:
          plugin.process_dauth_get_secret_request(body)
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
    manager, lines = _manager("process_dauth_get_secret_request", plugin.process_dauth_get_secret_request)
    return manager.get_secrets(body), lines

  def test_verdict_is_logged_yellow_and_answered_as_final(self):
    """A node that does not run the job gets the same final answer as before and a yellow line."""
    response, lines = self._get_secrets(existing_job(), request(EE_SENDER="node-other", EE_ETH_SENDER="0xOTHER"))
    self.assertEqual(response["error"], "Sender is not running the existing job.")
    self.assertIs(response["retryable"], False)
    self.assertEqual([color for _, color in lines], ["y"])
    self.assertIn("Error processing get_secrets request from", lines[0][0])

  def test_faults_are_logged_red(self):
    """A final error that is not a verdict and a retryable one are both still red."""
    # No pointer for the job on this server: a ValueError, final for the requester, but about this server's records.
    response, lines = self._get_secrets(gating._make_dauth_harness(), request())
    self.assertIs(response["retryable"], False)
    self.assertEqual([color for _, color in lines], ["r"])
    # A revision this server does not hold yet: a RuntimeError, which the requester may retry.
    response, lines = self._get_secrets(_revision_job(), _revision_request(revision="op:other"))
    self.assertIs(response["retryable"], True)
    self.assertEqual([color for _, color in lines], ["r"])


class RefusalLineNamesTests(unittest.TestCase):

  def test_get_secrets_refusal_line_names_sender_job_and_reason(self):
    """A refused `get_secrets` request is logged with the sender's address, its ETH address, the job and the reason."""
    body = request(EE_SENDER="node-other", EE_ETH_SENDER="0xOTHER")
    manager, lines = _manager("process_dauth_get_secret_request", existing_job().process_dauth_get_secret_request)
    response = manager.get_secrets(body)
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
      raise ValueError("credential-in-dependency-error")
    # The `raise` is the line after the `def`.
    raised_at = failing_check.__code__.co_firstlineno + 1
    manager, lines = _manager("process_dauth_reconcile_secrets_request", failing_check)
    response = manager.reconcile_job_secrets({"nonce": "n1", "EE_SENDER": "node-oracle", "EE_ETH_SENDER": "0xORACLE", "job_id": 7})
    self.assertEqual(lines, [(
      f"dAuth secret reconciliation failed for request from {gating.SOURCE_IP} "
      "(sender 'node-oracle' ETH '0xORACLE' job 7): ValueError in reconcile_job_secrets > failing_check "
      f"(line {raised_at} of failing_check).", "r",
    )])
    # The caller is still told only that it failed.
    self.assertEqual(response["error"], "dAuth secret reconciliation failed")
    self.assertNotIn("credential-in-dependency-error", str(response) + str(lines))

  def test_label_escapes_and_cuts_what_the_request_names(self):
    """Text the requester controls cannot add a log line or grow one without bound."""
    label = dauth_request_label({"EE_SENDER": "a\nfake line " * 50, "EE_ETH_SENDER": "0x" + "f" * 500, "job_id": "9" * 500})
    # A line break is written as an escape, so the text stays on the line of the refusal.
    self.assertNotIn("\n", label)
    self.assertIn("a\\nfake line", label)
    # 60, 50 and 40 characters of the three values, plus the three field names and separators.
    self.assertEqual(len(label), len("sender  ETH  job ") + 60 + 50 + 40)

  def test_label_of_a_request_without_the_fields(self):
    """A body that names no sender or job, or is not a dictionary, gives a label that says so."""
    for body in ({}, {"nonce": "n1"}, None, "text"):
      with self.subTest(body=body):
        self.assertEqual(dauth_request_label(body), "sender None ETH None job None")


if __name__ == "__main__":
  unittest.main()
