"""Signed endpoint and persistence regressions for optional shared aliases."""

import unittest
from eth_account import Account

from extensions.business.deeploy.tests.delegate_aliases_harness import (
  DELEGATE, OTHER_DELEGATE, OWNER, ESCROW, make_plugin, sign,
)


class DelegateAliasesTests(unittest.TestCase):
  def setUp(self):
    self.plugin = make_plugin()

  def save(self, alias='Automation', address=DELEGATE):
    return self.plugin.set_delegate_alias(sign({'delegate_address': address, 'alias': alias}))

  def load(self, addresses=None):
    return self.plugin.get_delegate_aliases(sign({'delegate_addresses': [DELEGATE] if addresses is None else addresses}))

  def test_existing_delegates_have_no_required_alias(self):
    self.assertEqual(self.load(), {'status': 'success', 'aliases': {}})
    self.assertEqual(self.load([])['aliases'], {})

  def test_save_normalizes_and_survives_new_session(self):
    self.assertEqual(self.save('  Automation  '), {'status': 'success', 'delegate_address': DELEGATE, 'alias': 'Automation'})
    self.plugin = make_plugin(self.plugin.storage)
    self.assertEqual(self.load()['aliases'], {DELEGATE: 'Automation'})

  def test_clear_keeps_other_delegates(self):
    self.save()
    self.save('CI', OTHER_DELEGATE)
    self.assertEqual(self.save('   ')['status'], 'success')
    self.assertEqual(self.load([DELEGATE, OTHER_DELEGATE])['aliases'], {OTHER_DELEGATE: 'CI'})

  def test_only_owner_may_write_but_delegate_may_read(self):
    self.save()
    key = '02' * 32
    delegate = Account.from_key(key).address.lower()
    self.plugin.bc.members.add(delegate)
    result = self.plugin.set_delegate_alias(sign({'delegate_address': DELEGATE, 'alias': 'bad'}, key))
    self.assertIn('Only the escrow owner', result['error'])
    result = self.plugin.get_delegate_aliases(sign({'delegate_addresses': [DELEGATE]}, key))
    self.assertEqual(result['aliases'][DELEGATE], 'Automation')

  def test_rejects_unknown_inactive_owner_and_zero_targets(self):
    for address in ['0x' + 'f' * 40, OWNER, '0x' + '0' * 40, 'bad']:
      with self.subTest(address=address):
        self.assertEqual(self.save(address=address)['status'], 'fail')
    self.plugin.bc.members.remove(DELEGATE)
    self.assertEqual(self.save()['status'], 'fail')
    self.assertEqual(self.plugin.storage, {})

  def test_revoked_label_hidden_and_readded_label_retained(self):
    self.save()
    self.plugin.bc.members.remove(DELEGATE)
    self.assertEqual(self.load()['aliases'], {})
    self.plugin.bc.members.add(DELEGATE)
    self.assertEqual(self.load()['aliases'][DELEGATE], 'Automation')

  def test_csp_and_network_isolation_and_owner_transfer(self):
    self.save()
    self.plugin.bc.network = 'testnet'
    self.assertEqual(self.load()['aliases'], {})
    self.plugin.bc.network = 'devnet'
    original = self.plugin.bc.get_user_escrow_details
    self.plugin.bc.get_user_escrow_details = lambda address: {**original(address), 'escrowAddress': '0x' + 'b' * 40}
    self.assertEqual(self.load()['aliases'], {})
    self.plugin.bc.get_user_escrow_details = original
    auth = {'sender_escrow': ESCROW, 'escrow_owner': '0x' + 'd' * 40}
    self.assertEqual(self.plugin.deeploy_load_delegate_aliases(auth, [DELEGATE])[DELEGATE], 'Automation')

  def test_case_variants_share_one_key_and_cross_csp_target_fails(self):
    self.save(address=Account.from_key('02' * 32).address)
    self.assertEqual(self.load()['aliases'], {DELEGATE: 'Automation'})
    self.assertEqual(len(self.plugin.storage), 1)
    original = self.plugin.bc.get_user_escrow_details
    self.plugin.bc.get_user_escrow_details = lambda address: {
      **original(address),
      'escrowAddress': '0x' + 'b' * 40 if address.lower() == DELEGATE else ESCROW,
    }
    self.assertEqual(self.save()['status'], 'fail')
    self.assertEqual(self.load()['aliases'], {})

  def test_storage_failure_does_not_report_success(self):
    self.plugin.write_ok = False
    self.assertIn('Failed to save', self.save()['error'])
    self.assertEqual(self.plugin.storage, {})

  def test_alias_validation_and_unicode(self):
    for alias in [None, 7, ['bad'], 'a' * 81, 'a\nb', '\x00', '\u202ebad']:
      with self.subTest(alias=repr(alias)):
        self.assertEqual(self.save(alias)['status'], 'fail')
    with self.assertRaisesRegex(ValueError, 'control or format'):
      self.plugin._normalize_delegate_alias('\ud800')  # Surrogates cannot be UTF-8 signed, but storage validation still rejects them.
    self.assertEqual(self.save('🚀' * 80)['status'], 'success')

  def test_read_limits_and_malformed_storage(self):
    self.assertEqual(self.load([DELEGATE] * 101)['status'], 'fail')
    self.assertEqual(self.load(['invalid'])['status'], 'fail')
    self.save()
    self.plugin.storage[next(iter(self.plugin.storage))] = 42
    self.assertEqual(self.load()['status'], 'fail')

  def test_tampered_signature_or_payload_cannot_write(self):
    request = sign({'delegate_address': DELEGATE, 'alias': 'safe'})
    request['alias'] = 'tampered'
    self.assertEqual(self.plugin.set_delegate_alias(request)['status'], 'fail')
    request = sign({'delegate_address': DELEGATE, 'alias': 'safe'})
    request['EE_ETH_SIGN'] = '0x00'
    self.assertEqual(self.plugin.set_delegate_alias(request)['status'], 'fail')
    self.assertEqual(self.plugin.storage, {})

  def test_expired_nonce_and_inactive_signer_fail(self):
    request = sign({'delegate_addresses': [DELEGATE]}, nonce='0x1')
    self.assertEqual(self.plugin.get_delegate_aliases(request)['status'], 'fail')
    self.assertIn('expired', self.plugin.get_delegate_aliases(request)['error'])
    self.plugin.bc.active = False
    self.assertEqual(self.save()['status'], 'fail')


if __name__ == '__main__':
  unittest.main()
