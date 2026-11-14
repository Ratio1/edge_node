"""The dAuth version gate serves every node release at or above a named minimum release."""
import re
import unittest

from ratio1.const.base import dAuth

from ver import __VER__ as EDGE_VERSION
from extensions.business.dauth.dauth_mixin import DAUTH_MIN_SENDER_APP_VERSION, version_to_int
from extensions.business.dauth.test_dauth_revoked_nodes import ALLOWED, _auth_body, _harness


# The three numbers of the named minimum release; the test versions below are built from them.
MAJOR, MINOR, BUILD = (int(part) for part in DAUTH_MIN_SENDER_APP_VERSION.split("."))
# The oldest release the gate serves and the one just below it.
AT_MINIMUM = DAUTH_MIN_SENDER_APP_VERSION
BELOW_MINIMUM = f"{MAJOR}.{MINOR}.{BUILD - 1}"
# Servers one release step (10 build numbers), two steps and one minor version ahead of that sender.
NEWER_SERVERS = (f"{MAJOR}.{MINOR}.{BUILD + 10}", f"{MAJOR}.{MINOR}.{BUILD + 20}", f"{MAJOR}.{MINOR + 1}.0")


def _gate(server_version, messages=None):
  """
  Build a dAuth harness that answers as a server of one release.

  The harness of the revoked-node tests, with an empty denylist so that only the version gate
  and the mocked license lookup decide.

  Parameters
  ----------
  server_version : str
    The app version the server reports as its own.
  messages : list, optional
    Receives every line the plugin logs.

  Returns
  -------
  _DauthHarness
    The plugin stand-in, licensed for every requester.
  """
  # No denylist: the requester is never refused as revoked.
  plugin = _harness([] if messages is None else messages, denylist=None)
  # The server's own release, the one the old rule measured the distance from.
  plugin.ee_ver = server_version
  return plugin


def _check(server_version, sender_version):
  """
  Run the version check of a node request alone.

  Parameters
  ----------
  server_version : str
    The app version of the answering server.
  sender_version : str
    The app version the requester declares.

  Returns
  -------
  VersionCheckData
    The verdict: `result`, `message` and `requester_type`.
  """
  # Core and SDK versions equal the server's, so only the app version can refuse.
  return _gate(server_version).version_check(
    sender_app_version=sender_version, sender_core_version="7.7.1", sender_sdk_version="3.4.90",
  )


class DauthVersionGateTests(unittest.TestCase):

  def test_minimum_release_is_served_by_every_newer_server(self):
    """A node on the minimum release is served by a server 10, 20 or a minor version ahead."""
    for server in NEWER_SERVERS:
      with self.subTest(server=server):
        verdict = _check(server, AT_MINIMUM)
        # The distance to the server no longer refuses: before, 10 or more build numbers did.
        self.assertTrue(verdict.result)
        # The older sender is still named in the message, as a warning only.
        self.assertIn(f"Sender app version {AT_MINIMUM} is lower than server app version {server}", verdict.message)
        self.assertNotIn("too old", verdict.message)

  def test_sender_below_the_minimum_is_refused_and_told_the_minimum(self):
    """A node below the minimum release is refused by any newer server, with the minimum in the text."""
    for sender in (BELOW_MINIMUM, f"{MAJOR}.{MINOR - 1}.999", "1.0.0"):
      with self.subTest(sender=sender):
        verdict = _check(NEWER_SERVERS[0], sender)
        self.assertFalse(verdict.result)
        # The refusal replaces the whole message and names the release to reach.
        self.assertEqual(
          verdict.message,
          f" FAIL: Sender app version {sender} is too old (minimum: {DAUTH_MIN_SENDER_APP_VERSION}).",
        )

  def test_sender_at_or_above_the_server_is_served(self):
    """A node on the server's release or a newer one is served: a rolled-back server refuses nobody for being newer."""
    for sender in (NEWER_SERVERS[0], NEWER_SERVERS[1], NEWER_SERVERS[2]):
      with self.subTest(sender=sender):
        self.assertTrue(_check(NEWER_SERVERS[0], sender).result)

  def test_sdk_requester_is_not_measured_against_the_minimum(self):
    """A client that declares no app version is typed as an SDK and passes the gate as before."""
    plugin = _gate(NEWER_SERVERS[0])
    verdict = plugin.version_check(sender_app_version=None, sender_core_version=None, sender_sdk_version="3.4.90")
    self.assertTrue(verdict.result)
    self.assertEqual(verdict.requester_type, dAuth.DAUTH_SENDER_TYPE_SDK)

  def test_minimum_is_a_plain_release_number_strictly_below_this_release(self):
    """The minimum is three plain numbers and lower than this tree's own release, so the previous release passes."""
    # `version_to_int` keeps a partial sum for text it cannot read ("2.10" or "v2.10.700"), which
    # would put the minimum below every real node: the text itself must be three numbers.
    self.assertIsNotNone(re.fullmatch(r"\d{1,3}\.\d{1,3}\.\d{1,3}", DAUTH_MIN_SENDER_APP_VERSION))
    # The weighted sum the gate compares is the one the three numbers give.
    self.assertEqual(version_to_int(DAUTH_MIN_SENDER_APP_VERSION), MAJOR * 1000000 + MINOR * 1000 + BUILD)
    # A minimum equal to the release would refuse every node that has not updated yet.
    self.assertLess(version_to_int(DAUTH_MIN_SENDER_APP_VERSION), version_to_int(EDGE_VERSION))

  def test_request_below_the_minimum_is_refused_before_the_license_lookup(self):
    """A request below the minimum gets the version refusal and costs no license lookup."""
    plugin = _gate(NEWER_SERVERS[0])
    data = plugin.process_dauth_request(_auth_body(ALLOWED, sender_app_ver=BELOW_MINIMUM))
    self.assertIn("Version check failed", data[dAuth.DAUTH_SUBKEY]["error"])
    self.assertIn("is too old (minimum: ", data[dAuth.DAUTH_SUBKEY]["error"])
    plugin.bc.is_node_licensed.assert_not_called()

  def test_request_of_an_older_served_release_reaches_the_license_lookup_and_is_served(self):
    """A request of the minimum release against a newer server is licence-checked and gets its settings."""
    plugin = _gate(NEWER_SERVERS[0])
    data = plugin.process_dauth_request(_auth_body(ALLOWED, sender_app_ver=AT_MINIMUM))
    plugin.bc.is_node_licensed.assert_called_once()
    # A served node request carries the broker host; a refused one carries no settings.
    self.assertIn("EE_MQTT_HOST", data[dAuth.DAUTH_SUBKEY])
    # The answer still tells the node, as a non-critical note, that it is behind the server.
    self.assertIn("is lower than server app version", data[dAuth.DAUTH_SUBKEY]["error"])


if __name__ == "__main__":
  unittest.main()
