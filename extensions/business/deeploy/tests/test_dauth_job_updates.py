"""Exercise both sides of dAuth staging with an empty coordinator secret store."""
import copy
import json
import unittest
from types import SimpleNamespace
from unittest import mock

from requests import Timeout
from ratio1.bc.base import BaseBlockEngine
from naeural_core import constants as ct
from extensions.business.dauth.dauth_mixin import _DauthMixin
from extensions.business.dauth.dauth_registry import (
  DAUTH_JOB_SECRET_GENERATIONS_HKEY, DAUTH_JOB_UPDATES_HKEY,
)
from extensions.business.dauth.job_updates import _DauthJobUpdatesMixin
from extensions.business.deeploy.dauth_updates import _DeeployDauthUpdatesMixin
from extensions.business.deeploy.deeploy_job_mixin import _DeeployJobMixin
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin
from extensions.business.deeploy.tests.support import InputsStub
from extensions.business.deeploy.tests.test_secret_staging import _R1FSStub


NOW = 1_700_000_000
HIDDEN = '__R1_DAUTH_SECRET__'


def pipeline(token=HIDDEN):
  return {
    'NAME': 'app', 'OWNER': '0xOwner', 'TYPE': 'void',
    'DEEPLOY_SPECS': {'job_id': 7, 'current_target_nodes': ['worker']},
    'PLUGINS': [{'SIGNATURE': 'CONTAINER_APP_RUNNER', 'INSTANCES': [{
      'INSTANCE_ID': 'car', 'ENV': {'CF_TUNNEL_TOKEN': token},
    }]}],
  }


def wallet_request():
  return {'job_id': 7, 'app_id': 'app', 'nonce': hex(NOW * 1000), 'wallet_signature': 'valid'}


class _BC:
  address = 'coordinator'
  evm_network = 'devnet'

  def __init__(self):
    self.permissions = 1  # Deploy, deliberately without view-secrets permission.
    self.wallet = '0xDelegate'
    self.owner = '0xOwner'
    self.valid = True
    self.protocol_oracle = True
    self.dauth_oracle = True

  def sign(self, body):
    body.update(EE_SENDER=self.address, EE_ETH_SENDER='0xOracle', EE_SIGN='valid')

  def verify(self, body, **kwargs):
    return SimpleNamespace(valid=self.valid and body.get('EE_SIGN') == 'valid', sender=body.get('EE_SENDER'))

  def node_address_to_eth_address(self, address):
    return '0xDauth' if address == 'dauth' else '0xOracle'

  def get_eth_oracles(self):
    return ['0xOracle'] if self.protocol_oracle else []

  def get_dauth_oracles(self):
    return ['dauth'], ['0xDauth']

  def is_dauth_oracle(self, **kwargs):
    return self.dauth_oracle

  def web3_is_dauth_oracle(self, address, network=None):
    return self.dauth_oracle

  def get_user_escrow_details(self, sender):
    return {'isActive': True, 'escrowAddress': '0xEscrow', 'escrowOwner': self.owner, 'permissions': self.permissions}

  def get_job_details(self, job_id):
    return {'escrowOwner': self.owner}

  def get_evm_network(self):
    return 'devnet'

  def get_network_data(self, network):
    return {'EE_DAUTH_URL': 'https://dauth.example/get_auth_data'}


class _Custodian(_DauthMixin, _DauthJobUpdatesMixin):
  def __init__(self):
    self.ct = ct
    self.const = ct
    self.bc = _BC()
    self.deepcopy = copy.deepcopy
    self.time = lambda: NOW
    self.events = []
    self.r1fs = _R1FSStub(self.events)
    self.prior_pipeline = pipeline()
    self.store = {
      ('DEEPLOY_DEPLOYED_JOBS', '7'): 'prior-cid',
      ('DAUTH_JOB_SECRETS', '7'): {
        'job_id': '7', 'pipeline_cid': 'prior-cid',
        'job_secrets': {'PLUGINS': [{'INSTANCES': [{'ENV': {'CF_TUNNEL_TOKEN': 'kept-secret'}}]}]},
      },
    }
    self.logs = []
    self.expected_request_type = 'update pipeline'

  def P(self, message, **kwargs):
    self.logs.append(message)

  def Pd(self, *args, **kwargs):
    return

  def json_dumps(self, value, **kwargs):
    return json.dumps(value)

  def chainstore_hget(self, hkey, key):
    return copy.deepcopy(self.store.get((hkey, str(key))))

  def chainstore_hset(self, hkey, key, value, **kwargs):
    self.events.append(('write', hkey, str(key), copy.deepcopy(value), kwargs))
    self.store[(hkey, str(key))] = copy.deepcopy(value)
    return True

  def get_pipeline_from_r1fs(self, *args, **kwargs):
    return copy.deepcopy(self.prior_pipeline)

  def _load_dauth_job_pipeline_record(self, job_id):
    return self._get_pipeline_from_cstore(job_id), copy.deepcopy(self.prior_pipeline)

  def deeploy_verify_and_get_inputs(self, request, request_type=None):
    assert request_type == self.expected_request_type
    if request.get('wallet_signature') != 'valid':
      raise ValueError('Invalid wallet signature')
    return self.bc.wallet, InputsStub(copy.deepcopy(request))

  def deeploy_get_auth_result(self, inputs):
    return {'escrow_owner': '0xOwner'}


class _Requests:
  def __init__(self, custodian):
    self.custodian = custodian
    self.calls = []
    self.lose_first_response = False
    self.tamper = None

  def post(self, url, json=None, timeout=None):
    self.calls.append(copy.deepcopy(json['body']))
    try:
      result = self.custodian.process_dauth_job_update(copy.deepcopy(json['body']))
    except Exception:
      result = {'nonce': json['body']['nonce'], 'error': 'rejected'}
    result.update(EE_SENDER='dauth', EE_SIGN='valid')
    if self.lose_first_response and len(self.calls) == 1:
      raise Timeout('response lost after custodian staged')
    if self.tamper:
      self.tamper(result)
    return SimpleNamespace(status_code=200, json=lambda: {'result': result})


class _Coordinator(_DeeployMixin, _DeeployDauthUpdatesMixin, _DeeployJobMixin):
  def __init__(self, custodian):
    self.bc = _BC()
    self.time = lambda: NOW
    self.deepcopy = copy.deepcopy
    self.requests = _Requests(custodian)
    self.custodian = custodian
    self.logs = []
    def request_dauth_job_update(payload):
      # Exercise the real SDK transport with only its HTTP and clock replaced.
      with mock.patch('ratio1.bc.base.requests.post', self.requests.post), mock.patch('ratio1.bc.base.time', self.time):
        return BaseBlockEngine.request_dauth_job_update(self.bc, payload)
    self.bc.request_dauth_job_update = request_dauth_job_update

  def _get_pipeline_from_cstore(self, job_id):
    return self.custodian._get_pipeline_from_cstore(job_id)

  def chainstore_hget(self, hkey, key):
    raise AssertionError('Coordinator must never read secret storage')

  def P(self, message, **kwargs):
    self.logs.append(message)


class DauthJobUpdateTests(unittest.TestCase):
  def setUp(self):
    self.server = _Custodian()
    self.client = _Coordinator(self.server)

  def stage(self, configs=None, request=None):
    return self.client._stage_dauth_pipeline_update(request or wallet_request(), configs or {'worker': pipeline()})

  def body(self):
    value = {
      'action': 'stage', 'nonce': hex(NOW * 1000),
      'wallet_request': wallet_request(), 'expected_pipeline_cid': 'prior-cid',
      'pipeline_configs': {'worker': pipeline()},
    }
    self.client.bc.sign(value)
    return value

  def test_non_custodian_preserves_secrets_without_reveal_permission_or_plaintext(self):
    configs, state = self.stage()
    self.assertEqual(configs['worker']['PLUGINS'][0]['INSTANCES'][0]['ENV']['CF_TUNNEL_TOKEN'], HIDDEN)
    self.assertNotIn('kept-secret', str(configs) + str(state) + str(self.client.requests.calls) + str(self.client.logs))
    self.assertNotIn('job_secrets', state)
    self.assertEqual(self.server._get_pipeline_from_cstore(7), 'staged-cid')
    current = self.server._load_dauth_job_secret_bundle('7')
    self.assertEqual(current['job_secrets']['PLUGINS'][0]['INSTANCES'][0]['ENV']['CF_TUNNEL_TOKEN'], 'kept-secret')
    for event in self.server.events:
      if event[0] == 'write' and event[1] in ('DAUTH_JOB_SECRETS', DAUTH_JOB_UPDATES_HKEY, DAUTH_JOB_SECRET_GENERATIONS_HKEY):
        self.assertFalse(event[4]['include_default_peers'])
        self.assertFalse(event[4]['include_configured_peers'])
    self.assertTrue(self.client.commit_staged_job_pipeline_and_secrets(state))
    self.assertTrue(self.client.commit_staged_job_pipeline_and_secrets(state))

  def test_response_loss_retries_same_operation_without_duplicate_staging(self):
    self.client.requests.lose_first_response = True
    self.stage()
    self.assertEqual(sum(event[0] == 'r1fs_add' for event in self.server.events), 1)
    self.assertEqual(len([key for key in self.server.store if key[0] == DAUTH_JOB_UPDATES_HKEY]), 1)

  def test_rollback_restores_previous_generation_and_retains_both_bundles(self):
    _, state = self.stage()
    self.assertTrue(self.client.rollback_staged_job_pipeline_and_secrets(state))
    self.assertEqual(self.server._get_pipeline_from_cstore(7), 'prior-cid')
    self.assertEqual(self.server._load_dauth_job_secret_bundle('7')['pipeline_cid'], 'prior-cid')
    self.assertIn((DAUTH_JOB_SECRET_GENERATIONS_HKEY, '7:prior-cid'), self.server.store)
    self.assertIn((DAUTH_JOB_SECRET_GENERATIONS_HKEY, '7:staged-cid'), self.server.store)
    self.assertTrue(self.client.rollback_staged_job_pipeline_and_secrets(state))
    self.assertFalse(self.client.commit_staged_job_pipeline_and_secrets(state))

  def test_delayed_rollback_never_replaces_newer_pointer(self):
    _, state = self.stage()
    self.server.store[('DEEPLOY_DEPLOYED_JOBS', '7')] = 'newer-cid'
    self.assertFalse(self.client.rollback_staged_job_pipeline_and_secrets(state))
    self.assertEqual(self.server._get_pipeline_from_cstore(7), 'newer-cid')

  def test_rejects_wrong_wallet_permission_and_signature_before_writes(self):
    self.server.bc.permissions = 0
    with self.assertRaisesRegex(ValueError, 'permission'):
      self.server.process_dauth_job_update(self.body())
    self.server.bc.permissions = 1
    body = self.body()
    body['wallet_request']['wallet_signature'] = 'invalid'
    with self.assertRaisesRegex(ValueError, 'signature'):
      self.server.process_dauth_job_update(body)
    self.assertEqual(self.server.events, [])

  def test_rejects_non_oracle_transport_and_expired_nonce(self):
    self.server.bc.protocol_oracle = False
    with self.assertRaises(ValueError):
      self.server.process_dauth_job_update(self.body())
    self.server.bc.protocol_oracle = True
    body = self.body()
    body['nonce'] = hex((NOW - 121) * 1000)
    with self.assertRaisesRegex(ValueError, 'expired'):
      self.server.process_dauth_job_update(body)
    self.assertEqual(self.server.events, [])

  def test_rejects_wrong_generation_and_prepared_app_owner_job_or_targets(self):
    changes = [
      lambda b: b.update(expected_pipeline_cid='stale-cid'),
      lambda b: b['pipeline_configs']['worker'].update(NAME='another-app'),
      lambda b: b['pipeline_configs']['worker'].update(OWNER='another-owner'),
      lambda b: b['pipeline_configs']['worker']['DEEPLOY_SPECS'].update(job_id=8),
      lambda b: b['pipeline_configs']['worker']['DEEPLOY_SPECS'].update(current_target_nodes=['other']),
    ]
    for change in changes:
      body = self.body()
      change(body)
      with self.subTest(change=change), self.assertRaises(ValueError):
        self.server.process_dauth_job_update(body)
    self.assertEqual(self.server.events, [])

  def test_changed_retry_plan_is_not_reauthorized_under_same_wallet_request(self):
    body = self.body()
    self.server.process_dauth_job_update(body)
    body['pipeline_configs']['worker']['PLUGINS'][0]['INSTANCES'][0]['ENV']['CF_TUNNEL_TOKEN'] = 'different-secret'
    with self.assertRaisesRegex(ValueError, 'retry changed'):
      self.server.process_dauth_job_update(body)

  def test_rejects_tampered_receipt_plan_and_non_dauth_response(self):
    self.client.requests.tamper = lambda r: r['receipt'].update(plan_hash='wrong')
    with self.assertRaisesRegex(ValueError, 'digest'):
      self.stage()
    self.setUp()
    self.client.bc.dauth_oracle = False
    with self.assertRaisesRegex(ValueError, 'Unauthorized'):
      self.stage()

  def test_generation_selected_by_pointer_even_when_legacy_bundle_is_stale(self):
    self.stage()
    self.server.store[('DAUTH_JOB_SECRETS', '7')] = {'job_id': '7', 'pipeline_cid': 'stale', 'job_secrets': {}}
    result = self.server._load_current_dauth_secret_bundle('7', 'staged-cid', pipeline())
    self.assertEqual(result['pipeline_cid'], 'staged-cid')

  def test_generation_overwrite_is_rejected(self):
    self.stage()
    bundle = self.server._load_dauth_job_secret_bundle('7')
    bundle['job_secrets'] = {'replaced': True}
    with self.assertRaisesRegex(ValueError, 'different contents'):
      self.server._save_dauth_job_secret_bundle('7', bundle)

  def test_partial_dispatch_retains_generation_without_rollback(self):
    _, state = self.stage()
    state['dispatch_attempted'] = True
    calls = len(self.client.requests.calls)
    self.assertTrue(self.client.settle_failed_staged_job_pipeline_and_secrets(state, 'dispatch failed'))
    self.assertTrue(state['dispatch_uncertain'])
    self.assertEqual(len(self.client.requests.calls), calls)
    self.assertEqual(self.server._get_pipeline_from_cstore(7), 'staged-cid')

  def test_staged_replay_rejects_superseded_generation(self):
    body = self.body()
    self.server.process_dauth_job_update(body)
    self.server.store[('DEEPLOY_DEPLOYED_JOBS', '7')] = 'newer-cid'
    with self.assertRaisesRegex(ValueError, 'superseded'):
      self.server.process_dauth_job_update(body)

  def test_rollback_retries_after_terminal_journal_write_failure(self):
    _, state = self.stage()
    write = self.server.chainstore_hset
    failed = []

    def fail_terminal(hkey, key, value, **kwargs):
      if hkey == DAUTH_JOB_UPDATES_HKEY and value['phase'] == 'rolled_back' and not failed:
        failed.append(True)
        return False
      return write(hkey, key, value, **kwargs)

    self.server.chainstore_hset = fail_terminal
    # The transport reports failure after restoration; its retry finishes the journal.
    self.assertFalse(self.client.rollback_staged_job_pipeline_and_secrets(state))
    self.assertTrue(self.client.rollback_staged_job_pipeline_and_secrets(state))
    self.assertEqual(self.server._get_pipeline_from_cstore(7), 'prior-cid')

  def test_rollback_retries_after_partial_legacy_restoration_failure(self):
    _, state = self.stage()
    write = self.server.chainstore_hset
    failed = []

    def fail_legacy(hkey, key, value, **kwargs):
      if hkey == 'DAUTH_JOB_SECRETS' and value['pipeline_cid'] == 'prior-cid' and not failed:
        failed.append(True)
        return False
      return write(hkey, key, value, **kwargs)

    self.server.chainstore_hset = fail_legacy
    self.assertFalse(self.client.rollback_staged_job_pipeline_and_secrets(state))
    self.assertTrue(self.client.rollback_staged_job_pipeline_and_secrets(state))
    self.assertEqual(self.server._load_dauth_job_secret_bundle('7')['pipeline_cid'], 'prior-cid')

  def test_interrupted_staging_restores_payload_and_resumes_same_operation(self):
    body = self.body()
    write = self.server.chainstore_hset
    failed = []

    def fail_pointer(hkey, key, value, **kwargs):
      if hkey == 'DEEPLOY_DEPLOYED_JOBS' and not failed:
        failed.append(True)
        return False
      return write(hkey, key, value, **kwargs)

    self.server.chainstore_hset = fail_pointer
    with self.assertRaisesRegex(ValueError, 'pipeline CID'):
      self.server.process_dauth_job_update(body)
    self.assertEqual(self.server._get_pipeline_from_cstore(7), 'prior-cid')
    self.assertEqual(self.server.store[('DAUTH_JOB_SECRETS', '7')]['pipeline_cid'], 'prior-cid')
    result = self.server.process_dauth_job_update(body)
    self.assertEqual(result['receipt']['phase'], 'staged')
    self.assertEqual(sum(event[0] == 'r1fs_add' for event in self.server.events), 2)

  def test_legacy_job_without_bundle_accepts_fresh_values_but_not_hidden_values(self):
    del self.server.store[('DAUTH_JOB_SECRETS', '7')]
    with self.assertRaisesRegex(ValueError, 'Unresolved'):
      self.server.process_dauth_job_update(self.body())
    body = self.body()
    body['pipeline_configs'] = {'worker': pipeline('fresh-secret')}
    result = self.server.process_dauth_job_update(body)
    self.assertNotIn('fresh-secret', str(result))
    self.assertEqual(result['receipt']['phase'], 'staged')

  def test_resume_archives_prior_generation_after_interruption_before_secret_writes(self):
    body = self.body()
    save = self.server._save_dauth_update
    failed = []

    def interrupt_after_prepare(operation_id, operation):
      save(operation_id, operation)
      if operation['phase'] == 'prepared' and not failed:
        failed.append(True)
        raise RuntimeError('interrupted before publication')

    self.server._save_dauth_update = interrupt_after_prepare
    with self.assertRaisesRegex(RuntimeError, 'interrupted'):
      self.server.process_dauth_job_update(body)
    self.assertNotIn((DAUTH_JOB_SECRET_GENERATIONS_HKEY, '7:prior-cid'), self.server.store)
    self.server.process_dauth_job_update(body)
    self.assertIn((DAUTH_JOB_SECRET_GENERATIONS_HKEY, '7:prior-cid'), self.server.store)

  def test_bookkeeping_only_save_preserves_secret_binding(self):
    candidate = pipeline()
    candidate.update(INITIATOR_ADDR='node', INITIATOR_ID='id', MODIFIED_BY_ADDR='node',
                     MODIFIED_BY_ID='id', VALIDATED=True, TIME='later')
    self.assertTrue(self.server.save_job_pipeline_in_cstore(candidate, 7))
    self.assertEqual(self.server.events, [])
    self.assertEqual(self.server._get_pipeline_from_cstore(7), 'prior-cid')

  def test_metadata_writer_cannot_bypass_secret_staging(self):
    candidate = pipeline()
    candidate['PLUGINS'][0]['INSTANCES'][0]['IMAGE'] = 'changed-image'
    self.assertFalse(self.server.save_job_pipeline_in_cstore(candidate, 7))
    self.assertEqual(self.server.events, [])

  def test_custodian_uses_shared_wallet_wrapper_verifier_on_unchanged_request(self):
    self.server.deeploy_verify_and_get_inputs = _DeeployMixin.deeploy_verify_and_get_inputs.__get__(self.server)
    self.server.deeploy_get_auth_result = _DeeployMixin.deeploy_get_auth_result.__get__(self.server)
    self.server.NestedDotDict = InputsStub
    self.server.time_to_str = str
    self.server.bc.is_valid_eth_address = lambda address: address == '0xDelegate'
    body = self.body()
    request = body['wallet_request']
    request.update(EE_ETH_SENDER='0xDelegate', EE_ETH_SIGN='wallet-signature')
    request['EE_HASH'] = self.server._deeploy_payload_hash(request)
    expected = self.server._deeploy_wrapper_message('update pipeline', request, request['EE_HASH'])
    verified = []

    def verify_wallet(text, signature, **kwargs):
      verified.append(text)
      return '0xDelegate' if text == expected and signature == 'wallet-signature' else None

    self.server.bc.eth_verify_text_signature = verify_wallet
    original_request = copy.deepcopy(request)
    result = self.server.process_dauth_job_update(body)
    self.assertEqual(result['receipt']['phase'], 'staged')
    self.assertEqual(verified, [expected])
    self.assertEqual(body['wallet_request'], original_request)
    tampered = copy.deepcopy(body)
    tampered['wallet_request']['app_id'] = 'tampered'
    with self.assertRaisesRegex(ValueError, 'payload hash'):
      self.server.process_dauth_job_update(tampered)


if __name__ == '__main__':
  unittest.main()
