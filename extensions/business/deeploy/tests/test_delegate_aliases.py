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

  def test_read_limits(self):
    self.assertEqual(self.load([DELEGATE] * 11)['status'], 'fail')
    self.assertEqual(self.load(['invalid'])['status'], 'fail')

  def test_corrupt_aliases_are_skipped_without_losing_valid_entries(self):
    for invalid in [42, {'malicious': 'do not log'}, 'untrusted\ntext', 'a' * 10000]:
      with self.subTest(invalid_type=type(invalid).__name__):
        self.plugin = make_plugin()
        self.save('Good label', OTHER_DELEGATE)
        self.save('Replace with corrupt stored value', DELEGATE)
        key = next(key for key in self.plugin.storage if key.endswith(DELEGATE))
        self.plugin.storage[key] = invalid
        warnings = []
        self.plugin.P = lambda message, **kwargs: warnings.append(message)
        response = self.load([DELEGATE, OTHER_DELEGATE])
        self.assertEqual(response, {'status': 'success', 'aliases': {OTHER_DELEGATE: 'Good label'}})
        self.assertEqual(warnings, ['Skipped 1 invalid delegate alias record(s).'])

  def test_multiple_corrupt_aliases_emit_one_bounded_warning(self):
    self.save('First')
    self.save('Second', OTHER_DELEGATE)
    for key in self.plugin.storage:
      self.plugin.storage[key] = {'bad': 'untrusted'}
    warnings = []
    self.plugin.P = lambda message, **kwargs: warnings.append(message)
    self.assertEqual(self.load([DELEGATE, OTHER_DELEGATE])['aliases'], {})
    self.assertEqual(warnings, ['Skipped 2 invalid delegate alias record(s).'])

  def test_read_membership_rpc_is_bounded_and_missing_labels_skip_probes(self):
    addresses = ['0x' + format(index, '040x') for index in range(1, 11)]
    self.plugin.bc.members.update(addresses)
    for address in addresses:
      self.save('Stored label', address)
    calls = []
    original = self.plugin.bc.get_user_escrow_details
    self.plugin.bc.get_user_escrow_details = lambda address: (calls.append(address.lower()), original(address))[1]
    self.assertEqual(len(self.load(addresses)['aliases']), 10)
    self.assertEqual(len(calls), 11)  # One existing signer-auth RPC plus at most ten target probes.
    self.plugin.storage.clear()
    calls.clear()
    self.assertEqual(self.load(addresses)['aliases'], {})
    self.assertEqual(calls, [OWNER])  # A new CSP with no labels pays no per-target RPC cost.

  def test_read_over_limit_or_invalid_input_has_no_target_or_storage_reads(self):
    for addresses in [[DELEGATE] * 11, [DELEGATE, 'invalid']]:
      calls = []
      storage_reads = []
      original = make_plugin().bc.get_user_escrow_details
      self.plugin.bc.get_user_escrow_details = lambda address: (calls.append(address.lower()), original(address))[1]
      self.plugin.chainstore_hget = lambda **kwargs: storage_reads.append(kwargs)
      self.assertEqual(self.load(addresses)['status'], 'fail')
      self.assertEqual(calls, [OWNER])  # Endpoint authentication runs first; target validation precedes external per-target work.
      self.assertEqual(storage_reads, [])

  def test_empty_cleared_and_corrupt_records_skip_target_probes(self):
    self.save('')
    self.save('Will become corrupt', OTHER_DELEGATE)
    key = next(key for key in self.plugin.storage if key.endswith(OTHER_DELEGATE))
    self.plugin.storage[key] = 42
    calls = []
    original = self.plugin.bc.get_user_escrow_details
    self.plugin.bc.get_user_escrow_details = lambda address: (calls.append(address.lower()), original(address))[1]
    self.assertEqual(self.load([DELEGATE, OTHER_DELEGATE])['aliases'], {})
    self.assertEqual(calls, [OWNER])

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
