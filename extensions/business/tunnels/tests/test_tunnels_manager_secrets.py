import sys
import time
import types
import unittest
# A fake sync that raises once and then answers.
from unittest import mock

_supervisor_module = types.ModuleType("naeural_core.business.default.web_app.supervisor_fast_api_web_app")


class _BasePluginStub:
  CONFIG = {"VALIDATION_RULES": {}}

  def on_init(self):
    return

  @classmethod
  def endpoint(cls, **kwargs):
    def decorator(fn):
      return fn
    return decorator


_supervisor_module.SupervisorFastApiWebApp = _BasePluginStub
sys.modules.setdefault(
  "naeural_core.business.default.web_app.supervisor_fast_api_web_app",
  _supervisor_module,
)

# The plugin under test and the bound of its Cloudflare fields.
from extensions.business.tunnels.tunnels_manager import SECRET_FIELD_MAX_LEN, TunnelsManagerPlugin

WALLET = "0x" + "9" * 40
TOKEN = "cloudflare-token-value"


class _Manager(TunnelsManagerPlugin):
  """
  The secret endpoints over a fake chain store and a fake chain.

  The signature check always names WALLET, and the escrow lookup answers from ``escrow_active`` and records the
  address it was asked for.

  Parameters
  ----------
  confirmed : bool, optional
    Whether other oracles confirm a write. Default is True.
  escrow_active : bool, optional
    Whether the signing wallet has an active escrow. Default is True.

  Returns
  -------
  _Manager
    The plugin, with ``store``, ``logged`` and ``escrow_lookups``.

  Examples
  --------
  >>> _Manager(escrow_active=False).add_secrets(_payload())["success"]
  False
  """

  def __init__(self, confirmed=True, escrow_active=True):  # pylint: disable=super-init-not-called
    """
    Set the fake chain store, the fake chain and the recorders.

    Parameters
    ----------
    confirmed : bool, optional
      Whether other oracles confirm a write. Default is True.
    escrow_active : bool, optional
      Whether the signing wallet has an active escrow. Default is True.

    Returns
    -------
    None
    """
    # Whether a write is confirmed; a test may change it between requests.
    self.confirmed = confirmed
    # The fake chain store, the log lines and the addresses the escrow lookup was asked for.
    self.store, self.logged, self.escrow_lookups = {}, [], []
    # The signature check names WALLET; the escrow lookup records its address and answers like the chain's
    # getUserEscrowDetails, reduced to the field add_secrets reads.
    self.bc = types.SimpleNamespace(
      eth_verify_payload_signature=lambda **kwargs: WALLET,
      get_user_escrow_details=lambda address: self.escrow_lookups.append(address) or {"isActive": escrow_active},
    )

  def P(self, msg, **kwargs):
    self.logged.append(msg)

  def time(self):
    return time.time()

  def time_to_str(self, value):
    return str(value)

  def chainstore_hset(self, hkey, key, value):
    self.store[(hkey, key)] = value  # the store keeps the local copy also when peers do not confirm
    return self.confirmed

  def chainstore_hget(self, hkey, key):
    return self.store.get((hkey, key))


def _payload(age_s=1.0):
  return {
    "nonce": hex(int((time.time() - age_s) * 1000)),
    "cloudflare_api_key": TOKEN, "cloudflare_account_id": "acc", "cloudflare_zone_id": "zone", "cloudflare_domain": "example.org",
  }


class TunnelSecretsTests(unittest.TestCase):

  def test_a_confirmed_update_is_stored_with_its_signed_time_as_revision(self):
    manager = _Manager()
    payload = _payload()
    self.assertEqual(manager.add_secrets(payload), {"success": True})
    stored = manager.store[("tunnels_manager_secrets", WALLET)]
    self.assertEqual(stored["cs_rev"], int(payload["nonce"], 16))
    self.assertEqual(manager.get_secrets(_payload()), {
      "cloudflare_api_key": TOKEN, "cloudflare_account_id": "acc", "cloudflare_zone_id": "zone", "cloudflare_domain": "example.org",
    })  # the revision is not part of what the client reads back

  def test_an_update_other_oracles_did_not_confirm_is_reported_as_a_failure(self):
    manager = _Manager(confirmed=False)
    result = manager.add_secrets(_payload())
    self.assertFalse(result["success"])
    self.assertIn("did not confirm", result["error"])

  def test_the_update_leaves_a_log_line_without_the_secret(self):
    for confirmed, word in ((True, "confirmed by other oracles"), (False, "NOT confirmed by other oracles")):
      manager = _Manager(confirmed=confirmed)
      manager.add_secrets(_payload())
      [line] = manager.logged
      self.assertIn(WALLET, line)
      self.assertIn(word, line)
      self.assertNotIn(TOKEN, line)

  def test_an_old_signed_update_cannot_be_replayed(self):
    manager = _Manager()
    result = manager.add_secrets(_payload(age_s=13 * 3600))
    self.assertEqual((result["success"], "expired" in result["error"]), (False, True))
    self.assertEqual(manager.store, {})

  def test_no_failure_raises_because_a_raising_endpoint_gets_its_arguments_logged(self):
    """The web-app base logs the arguments of an endpoint that raises; here that is the credential."""
    unsigned = _Manager()
    unsigned.bc.eth_verify_payload_signature = lambda **kwargs: None
    broken = _Manager()
    broken.bc.eth_verify_payload_signature = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("bad signature"))
    cases = [
      (_Manager(), {k: v for k, v in _payload().items() if k != "nonce"}),      # no nonce
      (_Manager(), dict(_payload(), nonce="not-hex")),                             # malformed nonce
      (_Manager(), dict(_payload(), nonce=hex(int((time.time() + 600) * 1000)))),  # client clock ahead
      (_Manager(), {k: v for k, v in _payload().items() if k != "cloudflare_zone_id"}),  # missing field
      (unsigned, _payload()), (broken, _payload()), (_Manager(confirmed=False), _payload()),
    ]
    for manager, payload in cases:
      result = manager.add_secrets(payload)  # must not raise
      self.assertFalse(result["success"])
      self.assertTrue(result["error"].startswith("Secrets were not saved"))
      self.assertNotIn(TOKEN, " ".join(manager.logged) + result["error"])

  def test_a_field_that_is_not_a_string_or_is_longer_than_the_bound_is_refused(self):
    """Each Cloudflare field must be a string of at most SECRET_FIELD_MAX_LEN characters; the bound itself is
    accepted, and a refusal stores nothing and names no value."""
    # Each of the four Cloudflare fields.
    for field in ("cloudflare_api_key", "cloudflare_account_id", "cloudflare_zone_id", "cloudflare_domain"):
      # One character over the bound, and two values that are not strings: a number and a list.
      for bad in ("x" * (SECRET_FIELD_MAX_LEN + 1), 12345, ["acc"]):
        # Name the case in a failure report.
        with self.subTest(field=field, bad=type(bad).__name__):
          # A fresh manager over an empty store.
          manager = _Manager()
          # The request with the bad field.
          result = manager.add_secrets(dict(_payload(), **{field: bad}))
          # Refused with the endpoint's error answer, naming no value, and nothing stored.
          self.assertEqual(
            (result["success"], result["error"].startswith("Secrets were not saved"), str(bad) in result["error"],
             manager.store),
            (False, True, False, {}),
          )
      # A fresh manager for a value exactly at the bound.
      manager = _Manager()
      # Accepted.
      self.assertEqual(manager.add_secrets(dict(_payload(), **{field: "y" * SECRET_FIELD_MAX_LEN})), {"success": True})
      # Stored as sent.
      self.assertEqual(manager.store[("tunnels_manager_secrets", WALLET)][field], "y" * SECRET_FIELD_MAX_LEN)

  def test_the_same_signed_request_is_written_again_after_an_unconfirmed_write(self):
    """After a write other oracles did not confirm, the same signed request is written again and succeeds once
    they confirm it."""
    # Other oracles do not confirm the first write.
    manager = _Manager(confirmed=False)
    # The writes the endpoint makes, and the fake store's own write.
    writes, store_write = [], manager.chainstore_hset
    # Count each write, keeping the fake store's behavior.
    manager.chainstore_hset = lambda hkey, key, value: writes.append(key) or store_write(hkey, key, value)
    # One signed request.
    payload = _payload()
    # First request: written, but other oracles did not confirm it; the local copy is kept.
    self.assertEqual(("did not confirm" in manager.add_secrets(payload)["error"], len(writes)), (True, 1))
    # Other oracles confirm from now on.
    manager.confirmed = True
    # The same signed request again: written again, and reported as saved.
    self.assertEqual((manager.add_secrets(dict(payload)), len(writes)), ({"success": True}, 2))

  def test_a_wallet_with_an_active_escrow_is_stored_as_before(self):
    """A wallet with an active escrow is stored as before, and the escrow lookup is asked for the address the
    signature check returned."""
    # A manager whose signing wallet has an active escrow.
    manager = _Manager(escrow_active=True)
    # One signed request.
    payload = _payload()
    # Saved.
    self.assertEqual(manager.add_secrets(payload), {"success": True})
    # The record and its revision are stored under the wallet, and the lookup was asked for that wallet once.
    self.assertEqual(
      (manager.store[("tunnels_manager_secrets", WALLET)]["cs_rev"], manager.escrow_lookups),
      (int(payload["nonce"], 16), [WALLET]),
    )

  def test_a_wallet_without_an_active_escrow_or_with_a_failed_lookup_is_refused(self):
    """A wallet without an active escrow, and a lookup that raises (the chain cannot be read), are refused with
    the endpoint's error answer, nothing is written, and the token appears in neither the answer nor the log."""
    # A wallet without an active escrow.
    inactive = _Manager(escrow_active=False)
    # A manager whose escrow lookup raises, as a failed chain read does.
    unreadable = _Manager()
    # The lookup raises instead of answering.
    unreadable.bc.get_user_escrow_details = lambda address: (_ for _ in ()).throw(ConnectionError("no answer"))
    # Each case with the reason its answer gives.
    for manager, reason in ((inactive, "Wallet has no active escrow."), (unreadable, "no answer")):
      # Name the case in a failure report.
      with self.subTest(reason=reason):
        # The signed request.
        result = manager.add_secrets(_payload())
        # Refused with the reason, nothing stored, no log line.
        self.assertEqual(
          (result, manager.store, manager.logged),
          ({"success": False, "error": "Secrets were not saved: " + reason}, {}, []),
        )

  def test_on_init_returns_when_the_secrets_sync_times_out(self):
    """A start-up sync of the tunnel secrets that raises a timeout leaves one log line, and on_init goes on to
    sync the TCP routes and returns."""
    # A manager with the plugin's default hash key for the TCP routes.
    manager = _Manager()
    # The default TCP_ROUTES_HKEY; the test stub does not load the plugin configuration.
    manager.cfg_tcp_routes_hkey = "tunnels_manager_tcp_routes"
    # The secrets sync raises the timeout error the plugin API raises; the TCP routes sync answers.
    manager.chainstore_hsync = mock.Mock(side_effect=[
      ValueError("Error in chainstore_hsync: hsync for 'tunnels_manager_secrets' timed out after 10s."),
      {"hkey": "tunnels_manager_tcp_routes"},
    ])
    # on_init returns instead of raising.
    self.assertIsNone(manager.on_init())
    # Both namespaces were synced, in order.
    self.assertEqual(
      [call.kwargs["hkey"] for call in manager.chainstore_hsync.call_args_list],
      ["tunnels_manager_secrets", "tunnels_manager_tcp_routes"],
    )
    # Exactly one log line.
    [line] = manager.logged
    # It names the failed sync and its reason.
    self.assertEqual((line.startswith("Could not sync tunnel secrets"), "timed out" in line), (True, True))


if __name__ == "__main__":
  unittest.main()
