import sys
import time
import types
import unittest

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

from extensions.business.tunnels.tunnels_manager import TunnelsManagerPlugin

WALLET = "0x" + "9" * 40
TOKEN = "cloudflare-token-value"


class _Manager(TunnelsManagerPlugin):
  """The secret endpoints over a fake chain store; the signature check always names WALLET."""

  def __init__(self, confirmed=True):  # pylint: disable=super-init-not-called
    self.confirmed = confirmed
    self.store = {}
    self.logged = []
    self.bc = types.SimpleNamespace(eth_verify_payload_signature=lambda **kwargs: WALLET)

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
    with self.assertRaisesRegex(Exception, "not saved"):
      manager.add_secrets(_payload())

  def test_the_update_leaves_a_log_line_without_the_secret(self):
    for confirmed, word in ((True, "confirmed by other oracles"), (False, "NOT confirmed by other oracles")):
      manager = _Manager(confirmed=confirmed)
      try:
        manager.add_secrets(_payload())
      except Exception:
        pass
      [line] = manager.logged
      self.assertIn(WALLET, line)
      self.assertIn(word, line)
      self.assertNotIn(TOKEN, line)

  def test_an_old_signed_update_cannot_be_replayed(self):
    manager = _Manager()
    with self.assertRaisesRegex(ValueError, "expired"):
      manager.add_secrets(_payload(age_s=13 * 3600))
    self.assertEqual(manager.store, {})


if __name__ == "__main__":
  unittest.main()
