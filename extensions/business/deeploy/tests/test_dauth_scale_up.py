"""Scale-up admission, dAuth custody and dispatch recovery across both RPC sides."""
import copy
import unittest
from collections import defaultdict

from naeural_core import constants as ct
from extensions.business.dauth.dauth_registry import DAUTH_JOB_UPDATES_HKEY
from extensions.business.deeploy.deeploy_const import DEEPLOY_STATUS
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin
from extensions.business.deeploy.tests.support import InputsStub, make_deeploy_plugin
from extensions.business.deeploy.tests.test_update_requests import DeeployManagerApiPlugin
from extensions.business.deeploy.tests.test_dauth_job_updates import (
  _Coordinator, _Custodian, HIDDEN, NOW, pipeline, wallet_request,
)


class DauthScaleUpTests(unittest.TestCase):
  def setUp(self):
    self.server = _Custodian()
    self.server.expected_request_type = 'scale up workers'
    self.server.bc.permissions = 4  # EXTEND_NODES, without reveal permission.
    prior = pipeline('kept-secret')
    prior['DEEPLOY_SPECS'].update(current_target_nodes=['worker', 'offline'], job_app_type='generic')
    source = prior['PLUGINS'][0]['INSTANCES'][0]
    source.update(
      DYNAMIC_ENV={'URL': [{'type': 'static', 'value': 'url-secret'}, {'type': 'host_ip'}]},
      PER_NODE_CONFIG={
        'byIndex': {'0': {'ENV': {'KEY': 'index-zero'}}, '3': {'ENV': {'KEY': 'index-three'}}},
        'byNode': {'new-b': {'ENV': {'KEY': 'node-secret'}}},
      },
      SECRET_PATHS=[
        ['DYNAMIC_ENV', 'URL'], ['PER_NODE_CONFIG', 'byIndex', '0', 'ENV', 'KEY'],
        ['PER_NODE_CONFIG', 'byIndex', '3', 'ENV', 'KEY'], ['PER_NODE_CONFIG', 'byNode', 'new-b', 'ENV', 'KEY'],
      ],
    )
    prior['PLUGINS'][0]['INSTANCES'].append({'INSTANCE_ID': 'db', 'ENV': {'CF_TUNNEL_TOKEN': 'db-secret'}})
    redacted, secrets = self.server._extract_and_redact_deeploy_dauth_secrets(prior)
    self.server.prior_pipeline = redacted
    self.server.store[('DAUTH_JOB_SECRETS', '7')]['job_secrets'] = secrets
    self.client = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    self.client.__dict__.update(_Coordinator(self.server).__dict__)
    client = self.client
    support = make_deeploy_plugin()
    client.ct = ct
    client.defaultdict = defaultdict
    client.cfg_deeploy_verbose = 0
    client.cfg_request_timeout = 60
    client.cfg_postponed_poll_interval = 0.5
    client.uuid = support.uuid
    client.cmdapi_build_pipeline_config = support.cmdapi_build_pipeline_config
    client.Pd = lambda *args, **kwargs: None
    client.P = lambda message, **kwargs: client.logs.append(message)
    client.json_dumps = lambda payload, **kwargs: str(payload)
    client._get_pipeline_from_cstore = self.server._get_pipeline_from_cstore
    client.get_pipeline_from_r1fs = lambda *args, **kwargs: copy.deepcopy(self.server.prior_pipeline)
    def forbid_secret_reads(*args, **kwargs):
      raise AssertionError('Non-dAuth coordinator read secret storage')
    client.chainstore_hget = forbid_secret_reads
    client._DeeployManagerApiPlugin__ensure_eth_balance = lambda: None
    client._DeeployManagerApiPlugin__handle_error = lambda exc, request: {'status': DEEPLOY_STATUS.FAIL, 'error': str(exc)}
    client._get_response = lambda data: data
    client.deeploy_verify_and_get_inputs = lambda request, **kwargs: ('0xDelegate', InputsStub({'chainstore_response': True, **request}))
    client.deeploy_get_auth_result = lambda inputs: {'escrow_owner': '0xOwner'}
    client.deeploy_check_payment_and_job_owner = lambda *args, **kwargs: True
    client._check_nodes_availability = lambda inputs: ['new-a', 'new-b']
    self.running = {'worker': {'app': {'plugins': {'CONTAINER_APP_RUNNER': [
      {'instance': 'running-car', 'instance_conf': {'CHAINSTORE_RESPONSE_KEY': 'existing-car'}},
      {'instance': 'running-db', 'instance_conf': {'CHAINSTORE_RESPONSE_KEY': 'existing-db'}},
    ]}}}}
    client._get_online_apps = lambda **kwargs: copy.deepcopy(self.running)
    client._reset_chainstore_response_keys = lambda *args, **kwargs: None
    client._DeeployManagerApiPlugin__pending_deploy_requests = {}
    client.create_postponed_request = lambda **kwargs: kwargs
    self.creates = []
    self.updates = []
    client.cmdapi_start_pipeline = lambda **kwargs: self.creates.append(copy.deepcopy(kwargs))
    client.cmdapi_update_instance_config = lambda **kwargs: self.updates.append(copy.deepcopy(kwargs))
    self.confirmations = []
    client.bc.node_addr_to_eth_addr = lambda node: node
    client.bc.submit_node_update = lambda **kwargs: self.confirmations.append(kwargs)
    self.request = wallet_request()
    self.request.pop('app_id')  # Existing scale-up clients may supply job_id alone.

  def start(self):
    result = self.client.scale_up_job_workers(copy.deepcopy(self.request))
    pending = self.client._DeeployManagerApiPlugin__pending_deploy_requests
    return result, next(iter(pending.values())) if pending else None

  def prepared_body(self):
    _, pending = self.start()
    self.assertIsNotNone(pending)
    body = copy.deepcopy(self.client.requests.calls[0])
    self.setUp()
    return body

  def test_scale_up_reconstructs_all_workers_without_local_secrets_or_reveal_permission(self):
    _, pending = self.start()
    self.assertIsNotNone(pending)
    self.assertEqual(len(self.creates), 2)
    self.assertEqual(len(self.updates), 2)
    state = pending['staging']
    self.assertEqual(state['request_type'], 'scale up workers')
    self.assertEqual(state['app_id'], 'app')
    self.assertEqual(state['target_nodes'], ['worker', 'offline', 'new-a', 'new-b'])
    self.assertTrue(state['dispatch_attempted'])
    for call in self.creates:
      self.assertEqual(call['config']['DEEPLOY_SPECS']['current_target_nodes'], state['target_nodes'])
      instance = call['config']['PLUGINS'][0]['INSTANCES'][0]
      self.assertEqual(instance['DYNAMIC_ENV']['URL'][0]['value'], HIDDEN)
      self.assertEqual(instance['PER_NODE_CONFIG']['byIndex']['3']['ENV']['KEY'], HIDDEN)
    self.assertEqual(self.updates[0]['instance_config']['ENV']['CF_TUNNEL_TOKEN'], HIDDEN)
    bundle = self.server._load_dauth_job_secret_bundle('7')['job_secrets']['PLUGINS'][0]['INSTANCES'][0]
    self.assertEqual(bundle['DYNAMIC_ENV']['URL'][0]['value'], 'url-secret')
    self.assertEqual(bundle['PER_NODE_CONFIG']['byNode']['new-b']['ENV']['KEY'], 'node-secret')
    exposed = str(self.creates) + str(self.updates) + str(state) + str(self.client.logs) + str(self.client.requests.calls)
    for secret in ('kept-secret', 'db-secret', 'url-secret', 'index-zero', 'index-three', 'node-secret'):
      self.assertNotIn(secret, exposed)
    self.assertTrue(self.client.commit_staged_job_pipeline_and_secrets(state))

  def test_scale_up_confirmations_preserve_offline_targets_with_multiple_plugins(self):
    _, pending = self.start()
    statuses = {key: {'node': node} for node, keys in pending['response_keys'].items() for key in keys}
    result = self.client.finalize_pending_request_scale_up(pending, statuses, DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(result['status'], DEEPLOY_STATUS.SUCCESS)
    self.assertEqual(self.confirmations[0]['nodes'], ['new-a', 'new-b', 'offline', 'worker'])

  def test_uncertain_new_or_existing_worker_dispatch_retains_generation_and_reports_uncertainty(self):
    for kind in ('create', 'update'):
      with self.subTest(kind=kind):
        self.setUp()
        calls = self.creates if kind == 'create' else self.updates
        def failed_send(**kwargs):
          calls.append(copy.deepcopy(kwargs))
          if len(calls) == 2:
            raise RuntimeError('delivery unconfirmed after one successful send')
        if kind == 'create':
          self.client.cmdapi_start_pipeline = failed_send
        else:
          self.client.cmdapi_update_instance_config = failed_send
        result, pending = self.start()
        self.assertIsNone(pending)
        self.assertTrue(result['dispatch_uncertain'])
        self.assertEqual(self.server._get_pipeline_from_cstore('7'), 'staged-cid')
        operation = next(value for (hkey, _), value in self.server.store.items() if hkey == DAUTH_JOB_UPDATES_HKEY)
        self.assertEqual(operation['phase'], 'staged')
        self.assertEqual(len(self.client.requests.calls), 1)
        self.assertEqual(len(calls), 2)

  def test_failure_before_dispatch_rolls_back(self):
    def fail_reset(*args, **kwargs):
      raise RuntimeError('reset failed')
    self.client._reset_chainstore_response_keys = fail_reset
    result, pending = self.start()
    self.assertIsNone(pending)
    self.assertNotIn('dispatch_uncertain', result)
    self.assertEqual(self.server._get_pipeline_from_cstore('7'), 'prior-cid')
    self.assertEqual(self.creates + self.updates, [])

  def test_pending_failure_and_timeout_retain_dispatched_generation(self):
    for failure in ('timeout', 'worker-error'):
      with self.subTest(failure=failure):
        self.setUp()
        _, pending = self.start()
        if failure == 'timeout':
          result = self.client.maybe_mark_timed_out_request(pending['pending_id'], pending, now=NOW + 61)
        else:
          result = self.client.finalize_pending_request_scale_up(pending, {}, DEEPLOY_STATUS.FAIL)
        self.assertTrue(result['dispatch_uncertain'])
        self.assertEqual(self.server._get_pipeline_from_cstore('7'), 'staged-cid')
        self.assertEqual(len(self.client.requests.calls), 1)
        self.assertEqual(self.confirmations, [])

  def test_scale_up_requires_extend_permission_not_create_or_reveal(self):
    for permission in (0, 1, 16):
      with self.subTest(permission=permission):
        self.setUp()
        self.server.bc.permissions = permission
        result, pending = self.start()
        self.assertIsNone(pending)
        self.assertIn('rejected', result['error'])
        self.assertEqual(self.server.events, [])
        self.assertEqual(self.creates + self.updates, [])

  def test_owner_can_scale_up_without_delegate_permissions(self):
    self.server.bc.permissions = 0
    self.server.bc.wallet = '0xOwner'
    _, pending = self.start()
    self.assertIsNotNone(pending)

  def test_lost_staging_response_reuses_operation_before_single_dispatch(self):
    self.client.requests.lose_first_response = True
    _, pending = self.start()
    self.assertIsNotNone(pending)
    self.assertEqual(len(self.client.requests.calls), 2)
    self.assertEqual(len(self.creates), 2)
    self.assertEqual(len(self.updates), 2)
    self.assertEqual(sum(hkey == DAUTH_JOB_UPDATES_HKEY for hkey, _ in self.server.store), 1)
    self.assertEqual(sum(event[0] == 'r1fs_add' for event in self.server.events), 1)

  def test_immediate_confirmation_without_response_keys_keeps_full_fleet(self):
    prepare = self.client.prepare_create_update_pipelines
    def without_response_keys(*args, **kwargs):
      creates, updates, _ = prepare(*args, **kwargs)
      return creates, updates, {}
    self.client.prepare_create_update_pipelines = without_response_keys
    self.request['chainstore_response'] = False
    result, pending = self.start()
    self.assertIsNone(pending)
    self.assertEqual(result['status'], DEEPLOY_STATUS.COMMAND_DELIVERED)
    self.assertEqual(self.confirmations[0]['nodes'], ['new-a', 'new-b', 'offline', 'worker'])

  def test_rejects_dropped_reordered_duplicate_or_unknown_targets_and_wrong_app(self):
    body = self.prepared_body()
    def targets(payload, nodes):
      for config in payload['pipeline_configs'].values():
        config['DEEPLOY_SPECS']['current_target_nodes'] = nodes
    cases = [
      lambda b: targets(b, ['worker', 'new-a', 'new-b']),
      lambda b: targets(b, ['offline', 'worker', 'new-a', 'new-b']),
      lambda b: b.update(new_nodes=['worker', 'new-b']),
      lambda b: b.update(new_nodes=['new-a', 'new-a']),
      lambda b: b.update(new_nodes=[]),
      lambda b: b['pipeline_configs'].update(unknown=copy.deepcopy(b['pipeline_configs']['worker'])),
      lambda b: b['wallet_request'].update(app_id='wrong-app'),
    ]
    for mutate in cases:
      with self.subTest(mutate=mutate):
        self.setUp()
        candidate = copy.deepcopy(body)
        mutate(candidate)
        with self.assertRaises(ValueError):
          self.server.process_dauth_job_update(candidate)
        self.assertEqual(self.server.events, [])

  def test_rejects_invalid_alias_sources_destinations_duplicates_and_signatures(self):
    body = self.prepared_body()
    cases = [
      lambda b: b['identity_aliases'][0].__setitem__(2, 'missing-source'),
      lambda b: b['identity_aliases'][0].__setitem__(1, 'missing-destination'),
      lambda b: b['identity_aliases'][0].__setitem__(0, 'OTHER_PLUGIN'),
      lambda b: b['identity_aliases'].append(copy.deepcopy(b['identity_aliases'][0])),
      lambda b: b.update(identity_aliases='invalid'),
    ]
    for mutate in cases:
      with self.subTest(mutate=mutate):
        self.setUp()
        candidate = copy.deepcopy(body)
        mutate(candidate)
        with self.assertRaises(ValueError):
          self.server.process_dauth_job_update(candidate)
        self.assertEqual(self.server.events, [])

  def test_aliases_resolve_reordered_sources_instead_of_positional_values(self):
    body = self.prepared_body()
    for config in body['pipeline_configs'].values():
      config['PLUGINS'][0]['INSTANCES'].reverse()
    result = self.server.process_dauth_job_update(body)
    self.assertEqual(result['receipt']['phase'], 'staged')
    stored = self.server._load_dauth_job_secret_bundle('7')['job_secrets']['PLUGINS'][0]['INSTANCES']
    self.assertEqual(stored[0]['ENV']['CF_TUNNEL_TOKEN'], 'db-secret')
    self.assertEqual(stored[1]['ENV']['CF_TUNNEL_TOKEN'], 'kept-secret')
    self.assertEqual(stored[1]['DYNAMIC_ENV']['URL'][0]['value'], 'url-secret')

  def test_duplicate_prior_identity_and_changed_dynamic_structure_fail_closed(self):
    body = self.prepared_body()
    self.server.prior_pipeline['PLUGINS'][0]['INSTANCES'].append(
      copy.deepcopy(self.server.prior_pipeline['PLUGINS'][0]['INSTANCES'][0])
    )
    with self.assertRaisesRegex(ValueError, 'ambiguous'):
      self.server.process_dauth_job_update(body)
    self.assertEqual(self.server.events, [])
    self.setUp()
    for config in body['pipeline_configs'].values():
      config['PLUGINS'][0]['INSTANCES'][0]['DYNAMIC_ENV']['URL'][1]['type'] = 'shmem'
    with self.assertRaisesRegex(ValueError, 'Unresolved'):
      self.server.process_dauth_job_update(body)
    self.assertEqual(self.server.events, [])

  def test_different_secret_layouts_between_workers_are_rejected(self):
    body = self.prepared_body()
    body['pipeline_configs']['worker']['PLUGINS'][0]['INSTANCES'].reverse()
    with self.assertRaisesRegex(ValueError, 'inconsistent'):
      self.server.process_dauth_job_update(body)
    self.assertEqual(self.server.events, [])

  def test_scale_up_uses_shared_v3_wallet_wrapper_and_rejects_operation_type_substitution(self):
    body = self.prepared_body()
    request = body['wallet_request']
    request.update(EE_ETH_SENDER='0xDelegate', EE_ETH_SIGN='wallet-signature')
    request['EE_HASH'] = self.server._deeploy_payload_hash(request)
    expected = self.server._deeploy_wrapper_message('scale up workers', request, request['EE_HASH'])
    self.server.deeploy_verify_and_get_inputs = _DeeployMixin.deeploy_verify_and_get_inputs.__get__(self.server)
    self.server.deeploy_get_auth_result = _DeeployMixin.deeploy_get_auth_result.__get__(self.server)
    self.server.NestedDotDict = InputsStub
    self.server.time_to_str = str
    self.server.bc.is_valid_eth_address = lambda address: address == '0xDelegate'
    self.server.bc.eth_verify_text_signature = lambda text, signature, **kwargs: '0xDelegate' if text == expected else None
    original = copy.deepcopy(request)
    result = self.server.process_dauth_job_update(body)
    self.assertEqual(result['receipt']['request_type'], 'scale up workers')
    self.assertEqual(request, original)
    body['request_type'] = 'update pipeline'
    with self.assertRaisesRegex(ValueError, 'Signature verification failed'):
      self.server.process_dauth_job_update(body)


if __name__ == '__main__':
  unittest.main()
