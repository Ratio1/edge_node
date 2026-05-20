import sys
import types
import unittest


class _BasePluginStub:
  CONFIG = {
    'VALIDATION_RULES': {},
  }

  @staticmethod
  def endpoint(method=None):
    def decorator(func):
      return func
    return decorator


def _install_naeural_core_stubs():
  modules = {
    'naeural_core': types.ModuleType('naeural_core'),
    'naeural_core.business': types.ModuleType('naeural_core.business'),
    'naeural_core.business.default': types.ModuleType('naeural_core.business.default'),
    'naeural_core.business.default.web_app': types.ModuleType('naeural_core.business.default.web_app'),
    'naeural_core.business.default.web_app.supervisor_fast_api_web_app': types.ModuleType(
      'naeural_core.business.default.web_app.supervisor_fast_api_web_app'
    ),
  }
  modules[
    'naeural_core.business.default.web_app.supervisor_fast_api_web_app'
  ].SupervisorFastApiWebApp = _BasePluginStub
  sys.modules.update(modules)


_install_naeural_core_stubs()

from extensions.business.tunnels.tunnels_manager import MESSAGE_PREFIX, MESSAGE_PREFIX_DEEPLOY, TunnelsManagerPlugin


class _BcStub:
  def __init__(self, sender):
    self.sender = sender
    self.calls = []

  def eth_verify_payload_signature(self, **kwargs):
    self.calls.append(kwargs)
    return self.sender


class TestTunnelsManagerSecretsSignature(unittest.TestCase):
  def _make_plugin(self, sender='0x1234567890123456789012345678901234567890'):
    plugin = object.__new__(TunnelsManagerPlugin)
    plugin.bc = _BcStub(sender)
    plugin.time = lambda: 1_000
    plugin.time_to_str = lambda value: str(value)
    return plugin

  def _payload(self, sender='0x1234567890123456789012345678901234567890'):
    return {
      'nonce': hex(1_000_000),
      'EE_ETH_SIGN': '0xsig',
      'EE_ETH_SENDER': sender,
      'cloudflare_api_key': 'api-key',
      'cloudflare_account_id': 'account-id',
      'cloudflare_zone_id': 'zone-id',
      'cloudflare_domain': 'example.com',
    }

  def test_get_secrets_requires_deeploy_prefix_and_safe_verification(self):
    sender = '0x1234567890123456789012345678901234567890'
    plugin = self._make_plugin(sender)
    plugin.chainstore_hget = lambda hkey, key: {'cloudflare_api_key': 'api-key'} if key == sender else None

    result = plugin.get_secrets(self._payload(sender))

    self.assertEqual(result, {'cloudflare_api_key': 'api-key'})
    self.assertEqual(len(plugin.bc.calls), 1)
    call = plugin.bc.calls[0]
    self.assertEqual(call['message_prefix'], MESSAGE_PREFIX_DEEPLOY)
    self.assertTrue(call['verify_safe'])
    self.assertTrue(call['raise_if_error'])
    self.assertTrue(call['no_hash'])
    self.assertEqual(call['indent'], 1)

  def test_add_secrets_requires_tunnel_prefix_and_safe_verification(self):
    sender = '0x1234567890123456789012345678901234567890'
    plugin = self._make_plugin(sender)
    stored = {}
    plugin.chainstore_hset = lambda hkey, key, value: stored.update({'hkey': hkey, 'key': key, 'value': value})

    result = plugin.add_secrets(self._payload(sender))

    self.assertEqual(result, {'success': True})
    self.assertEqual(len(plugin.bc.calls), 1)
    self.assertEqual(plugin.bc.calls[0]['message_prefix'], MESSAGE_PREFIX)
    self.assertTrue(plugin.bc.calls[0]['verify_safe'])
    self.assertEqual(stored['hkey'], 'tunnels_manager_secrets')
    self.assertEqual(stored['key'], sender)

  def test_rejects_sender_mismatch(self):
    plugin = self._make_plugin('0x1234567890123456789012345678901234567890')

    with self.assertRaisesRegex(Exception, 'Invalid signature'):
      plugin.add_secrets(self._payload('0x9999999999999999999999999999999999999999'))


if __name__ == '__main__':
  unittest.main()
