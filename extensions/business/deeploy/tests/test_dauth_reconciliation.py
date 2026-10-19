"""Exercise reconciliation on dAuth with a coordinator that cannot read secrets."""
import copy
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from ratio1.bc.base import BaseBlockEngine
from ratio1.const.base import dAuth
from extensions.business.dauth.dauth_mixin import _DauthMixin
from extensions.business.dauth.test_dauth_registry_gating import _FakeBC, _FakeConst
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin, DEEPLOY_DAUTH_SECRET_PLACEHOLDER as HIDDEN
from extensions.business.deeploy.tests.test_secret_staging import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY, DEEPLOY_JOBS_CSTORE_HKEY,
  _SecretStagingPlugin, _pipeline,
)


class _DauthReconciliationPlugin(_DauthMixin, _SecretStagingPlugin):
  pass


class DauthReconciliationTests(unittest.TestCase):
  def setUp(self):
    self.dauth = _DauthReconciliationPlugin()
    self.dauth.const = _FakeConst
    self.dauth.bc = _FakeBC()
    self.dauth.bc.verify = Mock(wraps=self.dauth.bc.verify)
    self.dauth.cfg_dauth_verbose = False
    self.dauth.time = lambda: 1000
    self.dauth._dauth_registry_internal_peers = ['dauth-a']
    self.prior = _pipeline()
    self.prior.update(OWNER='owner', DEEPLOY_SPECS={'job_id': 7})
    self.dauth.r1fs.get_json = lambda cid, **kwargs: copy.deepcopy(self.prior)
    self.dauth.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, '7')]['pipeline_cid'] = 'prior-cid'
    self.coordinator = _SecretStagingPlugin()
    self.coordinator.store = copy.deepcopy(self.dauth.store)
    self.coordinator._load_dauth_job_secret_bundle = Mock(side_effect=AssertionError('Local secret read'))
    self.coordinator._reconcile_dauth_job_secrets = _DeeployMixin._reconcile_dauth_job_secrets.__get__(self.coordinator)
    self.client = Mock()
    self.client.evm_network = 'testnet'
    self.client.get_network_data.return_value = {dAuth.EvmNetData.DAUTH_URL_KEY: 'https://dauth/get_auth_data'}
    self.client.sign.side_effect = lambda body: body.update(EE_SENDER='node-oracle', EE_ETH_SENDER='0xORACLE')
    self.client.verify.return_value = SimpleNamespace(valid=True, sender='dauth-a')
    self.client.node_address_to_eth_address.return_value = '0xDAUTH'
    self.client.web3_is_dauth_oracle.return_value = True
    self.coordinator.bc = SimpleNamespace(
      reconcile_dauth_job_secrets=lambda payload: BaseBlockEngine.reconcile_dauth_job_secrets(self.client, payload),
    )

    def post(url, json, timeout):
      self.assertEqual(url, 'https://dauth/reconcile_job_secrets')
      self.assertEqual(timeout, (10, 60))
      result = self.dauth.process_dauth_reconcile_secrets_request(json['body'])
      return SimpleNamespace(status_code=200, json=lambda: {'result': result})

    http = patch('ratio1.bc.base.requests.post', side_effect=post)
    self.http = http.start()
    self.addCleanup(http.stop)
    clock = patch('ratio1.bc.base.time', return_value=1000)
    clock.start()
    self.addCleanup(clock.stop)

  def test_update_reconciles_hidden_and_fresh_values_only_on_dauth(self):
    current = copy.deepcopy(self.prior)
    current['PLUGINS'][0]['INSTANCES'][0]['ENV']['CRDB_PASSWORD'] = 'fresh-password'
    configs, state = self.coordinator._reconcile_dauth_job_secrets(7, {'worker': current})
    bundle = self.dauth.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, '7')]
    env = bundle['job_secrets']['PLUGINS'][0]['INSTANCES'][0]['ENV']
    self.assertEqual(env, {'CF_TUNNEL_TOKEN': 'prior-token', 'CRDB_PASSWORD': 'fresh-password'})
    self.assertEqual(bundle['pipeline_cid'], 'staged-cid')
    self.assertEqual(self.dauth.store[(DEEPLOY_JOBS_CSTORE_HKEY, '7')], 'staged-cid')
    self.assertNotIn('prior-token', str(configs) + str(state))
    self.assertNotIn('fresh-password', str(configs) + str(state))
    stored_pipeline = next(event[1] for event in self.dauth.events if event[0] == 'r1fs_add')
    self.assertNotIn('fresh-password', str(stored_pipeline))
    self.assertTrue(self.coordinator.commit_staged_job_pipeline_and_secrets(state))
    self.assertFalse(self.coordinator.rollback_staged_job_pipeline_and_secrets(state))
    self.assertFalse(self.coordinator.settle_failed_staged_job_pipeline_and_secrets(state, 'failed dispatch'))
    self.coordinator._load_dauth_job_secret_bundle.assert_not_called()
    self.assertFalse(self.dauth.bc.verify.call_args.kwargs["log_hash_sign_fails"])
    self.assertEqual(self.dauth.store[(DEEPLOY_JOBS_CSTORE_HKEY, '7')], 'staged-cid')
    # Reconciliation succeeds even while this coordinator has the old replica.
    self.assertEqual(self.coordinator.store[(DEEPLOY_JOBS_CSTORE_HKEY, "7")], "prior-cid")
    self.coordinator._get_pipeline_from_cstore = Mock(side_effect=AssertionError("Local metadata read"))
    self.assertTrue(self.coordinator.commit_staged_job_pipeline_and_secrets(state))
    self.assertFalse(self.coordinator.rollback_staged_job_pipeline_and_secrets(state))

  def test_scale_up_transfers_existing_identity_alias_to_dauth(self):
    current = copy.deepcopy(self.prior)
    current['PLUGINS'][0]['INSTANCES'][0]['INSTANCE_ID'] = 'generated-car'
    configs, _ = self.coordinator._reconcile_dauth_job_secrets(
      7, {'new-worker': current},
      current_identity_aliases={('CONTAINER_APP_RUNNER', 'generated-car'): ('CONTAINER_APP_RUNNER', 'car')},
    )
    self.assertEqual(configs['new-worker']['PLUGINS'][0]['INSTANCES'][0]['INSTANCE_ID'], 'generated-car')
    bundle = self.dauth.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, '7')]
    self.assertEqual(bundle['job_secrets']['PLUGINS'][0]['INSTANCES'][0]['ENV']['CF_TUNNEL_TOKEN'], 'prior-token')
    self.coordinator._load_dauth_job_secret_bundle.assert_not_called()

  def test_rejects_stale_binding_untrusted_sender_or_unresolved_values_before_writes(self):
    body = {'job_id': '7', 'expected_pipeline_cid': 'prior-cid', 'pipeline_configs': {'worker': self.prior},
            'nonce': hex(1000000), 'EE_SENDER': 'node-oracle', 'EE_ETH_SENDER': '0xORACLE'}
    original_store = copy.deepcopy(self.dauth.store)
    original_prior = copy.deepcopy(self.prior)
    for mutation in (
      lambda: body.update(expected_pipeline_cid='wrong-cid'),
      lambda: self.dauth.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, '7')].update(pipeline_cid='wrong-cid'),
      lambda: body.update(EE_SENDER='node-other', EE_ETH_SENDER='0xOTHER'),
      lambda: self.dauth.bc.__setattr__('valid_signature', False),
      lambda: self.prior['PLUGINS'][0]['INSTANCES'][0]['ENV'].update(CUSTOM_SECRET=HIDDEN),
    ):
      with self.subTest(mutation=mutation):
        # Restore the fixture for each independent rejection.
        self.dauth.store.clear()
        self.dauth.store.update(copy.deepcopy(original_store))
        self.prior = copy.deepcopy(original_prior)
        self.dauth.bc.valid_signature = True
        body = {'job_id': '7', 'expected_pipeline_cid': 'prior-cid', 'pipeline_configs': {'worker': self.prior},
                'nonce': hex(1000000), 'EE_SENDER': 'node-oracle', 'EE_ETH_SENDER': '0xORACLE'}
        mutation()
        with self.assertRaises(ValueError):
          self.dauth.process_dauth_reconcile_secrets_request(body)
        self.assertEqual(self.dauth.events, [])

  def test_coordinator_rejects_unredacted_reply_before_dispatch(self):
    self.client.verify.return_value = SimpleNamespace(valid=True, sender='dauth-a')
    response = {'status': 'success', 'job_id': '7', 'nonce': hex(1000000), 'pipeline_cid': 'prior-cid',
                'pipeline_configs': {'worker': _pipeline(token='unexpected-plaintext')}}
    self.http.side_effect = None
    self.http.return_value = SimpleNamespace(status_code=200, json=lambda: {'result': response})
    with self.assertRaisesRegex(ValueError, 'containing secret values'):
      self.coordinator._reconcile_dauth_job_secrets(7, {'worker': self.prior})
    self.assertEqual(self.dauth.events, [])
