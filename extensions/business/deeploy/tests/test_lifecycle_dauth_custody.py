"""Lifecycle preparation and finalization through real SDK and Core wrapper APIs."""
import copy
import unittest
from unittest.mock import Mock

from ratio1.const.base import dAuth
from extensions.business.deeploy.tests.lifecycle_custody_support import (
  Coordinator, Custodian, State, pipeline, connect, report,
)


class LifecycleDauthCustodyTests(unittest.TestCase):
  def setUp(self):
    self.state = State()
    self.coordinator = Coordinator(self.state)
    self.dauth = Custodian(self.state)
    self.dauth.chainstore_hsync = Mock(side_effect=AssertionError('Custody requests must not synchronize namespaces.'))
    self.addCleanup(self.dauth.chainstore_hsync.assert_not_called)
    self.http = connect(self, self.state, self.dauth)

  def legacy(self, secret=dAuth.DAUTH_SECRET_PLACEHOLDER, with_bundle=True):
    canonical = pipeline(secret)
    cid = self.state.blobs.add_json(canonical)
    self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'] = cid
    if with_bundle:
      self.state.secrets['DAUTH_JOB_SECRETS', '7'] = dict(
        job_id='7', pipeline_cid=cid,
        job_secrets={'PLUGINS': [{'INSTANCES': [{'ENV': {'CF_TUNNEL_TOKEN': 'old-token'}}]}]},
      )
    self.coordinator.known = {'A': [canonical]}
    return canonical, cid

  def admit(self, previous=None, secret='fresh-token'):
    return self.coordinator._admit_prepared_deployment(
      request={'job_id': 7, 'request_id': 'request', 'expected_revision': 0},
      auth_result={'escrow_owner': 'owner'}, app_id='app', configs={'A': pipeline(secret)},
      prior_pipeline=previous, is_create=previous is None,
    )

  def operation(self):
    return copy.deepcopy(next(iter(self.coordinator._operation_records().values())))

  def token(self, bundle):
    return bundle['job_secrets']['PLUGINS'][0]['INSTANCES'][0]['ENV']['CF_TUNNEL_TOKEN']

  def finalize(self, operation):
    self.coordinator._advance_deployment_operation(operation)
    if operation['kind'] == 'update':
      report(self.state, operation, 'retire', 'stopped')
      self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'ready')
    self.coordinator._advance_deployment_operation(operation)
    self.coordinator._advance_deployment_operation(operation)

  def active(self):
    pointer = self.state.public['DEEPLOY_DEPLOYED_JOBS', '7']
    return self.state.blobs.get_json(pointer['pipeline_cid'])

  def test_create_stages_only_on_dauth_and_publishes_after_readiness(self):
    self.assertEqual(self.admit()['status_code'], 202)
    operation = self.operation()
    self.assertNotIn(('DEEPLOY_DEPLOYED_JOBS', '7'), self.state.public)
    self.assertEqual(operation['phase'], 'accepted')
    self.assertNotIn('fresh-token', str(self.state.blobs.data) + str(self.state.public))
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'ready')
    self.coordinator._advance_deployment_operation(operation)
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(operation['outcome'], 'succeeded')
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'fresh-token')
    self.assertEqual(self.state.secrets['DAUTH_JOB_SECRETS', '7']['EE_SENDER'], 'dauth')
    self.assertEqual(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7']['EE_SENDER'], 'oracle')

  def test_failed_first_update_restores_old_secrets_with_new_generation(self):
    previous, cid = self.legacy()
    self.admit(previous)
    self.assertEqual(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'], cid)
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'old-token')
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'retire', 'stopped')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'failed')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'stopped')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'restore', 'ready')
    self.coordinator._advance_deployment_operation(operation)
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual((operation['outcome'], operation['recovery']), ('failed', 'completed'))
    pointer = self.state.public['DEEPLOY_DEPLOYED_JOBS', '7']
    self.assertEqual(pointer['revision'], 1)
    restored = self.state.blobs.get_json(pointer['pipeline_cid'])
    self.assertEqual(restored['DEEPLOY_SPECS']['revision'], 0)
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'old-token')
    self.assertTrue(self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', '7|' + operation['operation_id'] + ':deploy']['revoked'])
    # Simulate an older peer answering operation repair after restore commit.
    self.state.public = {key: value for key, value in self.state.public.items() if key[0] != 'DEEPLOY_OPERATIONS'}
    stale = dict(operation, phase='finalizing')
    self.coordinator.bc.sign(stale)
    writes = len(self.state.writes)
    with self.assertRaises(RuntimeError):
      self.coordinator._deployment_secret_request('revoke', stale, active_attempt='deploy')
    self.assertEqual(len(self.state.writes), writes)
    restored_ref = '7|' + operation['operation_id'] + ':restore'
    self.assertNotIn('revoked', self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', restored_ref])

  def test_first_update_without_bundle_preserves_plaintext_values(self):
    previous, cid = self.legacy('old-token', with_bundle=False)
    self.admit(previous, secret=dAuth.DAUTH_SECRET_PLACEHOLDER)
    operation = self.operation()
    self.assertNotIn(('DAUTH_JOB_SECRETS', '7'), self.state.secrets)
    self.assertEqual(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'], cid)
    self.assertNotIn('old-token', str(self.state.public))
    self.finalize(operation)
    self.assertEqual(operation['outcome'], 'succeeded')
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'old-token')

  def test_failed_first_update_without_bundle_restores_plaintext_values(self):
    previous, _ = self.legacy('old-token', with_bundle=False)
    self.admit(previous)
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'retire', 'stopped')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'failed')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'stopped')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'restore', 'ready')
    self.coordinator._advance_deployment_operation(operation)
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual((operation['outcome'], operation['recovery']), ('failed', 'completed'))
    self.assertEqual(self.active()['DEEPLOY_SPECS']['revision'], 0)
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'old-token')

  def test_first_update_with_missing_required_bundle_fails_before_staging(self):
    previous, _ = self.legacy(with_bundle=False)
    with self.assertRaises(RuntimeError):
      self.admit(previous)
    self.assertFalse(any(namespace == 'DAUTH_JOB_SECRET_REVISIONS' for namespace, _ in self.state.secrets))

  def test_plaintext_previous_pipeline_does_not_bypass_existing_bundle_guards(self):
    previous, cid = self.legacy('old-token')
    for changed in ({'pipeline_cid': 'other'}, {'revoked': True}, {'deleted': True},
                    {'revision': 'other'}, {'deployment_revision': 1}, {'operation_id': 'other'}):
      with self.subTest(changed=changed):
        self.state.secrets['DAUTH_JOB_SECRETS', '7'] = dict(job_id='7', pipeline_cid=cid)
        self.state.secrets['DAUTH_JOB_SECRETS', '7'].update(changed)
        with self.assertRaises(RuntimeError):
          self.admit(previous)
        self.assertFalse(any(namespace == 'DAUTH_JOB_SECRET_REVISIONS' for namespace, _ in self.state.secrets))

  def test_first_update_without_bundle_rejects_changed_pipeline_generation(self):
    previous, _ = self.legacy('old-token', with_bundle=False)
    original = self.dauth._load_dauth_job_secret_bundle
    def load(job_id):
      self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'] = 'changed-cid'
      return original(job_id)
    self.dauth._load_dauth_job_secret_bundle = load
    with self.assertRaises(RuntimeError):
      self.admit(previous)
    self.assertFalse(any(namespace == 'DAUTH_JOB_SECRET_REVISIONS' for namespace, _ in self.state.secrets))

  def test_lost_fresh_values_leave_partial_preparation_until_deadline_then_cleanup(self):
    previous, cid = self.legacy()
    self.state.fail_write = lambda namespace, key: 'before' if namespace == 'DAUTH_JOB_SECRET_REVISIONS' and key.endswith(':deploy') else None
    with self.assertRaises(RuntimeError):
      self.admit(previous)
    self.state.fail_write = None
    self.coordinator = Coordinator(self.state)
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(operation['phase'], 'preparing')
    self.state.now = operation['preparation_deadline'] + 1
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual((operation['phase'], operation['outcome']), ('completed', 'failed'))
    self.assertEqual(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'], cid)
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'old-token')
    self.assertEqual(self.coordinator.commands, [])

  def test_uncertain_complete_preparation_recovers_without_credentials_in_coordinator(self):
    self.state.fail_write = lambda namespace, key: 'after' if namespace == 'DAUTH_JOB_SECRET_REVISIONS' else None
    with self.assertRaises(RuntimeError):
      self.admit()
    self.state.fail_write = None
    self.coordinator = Coordinator(self.state)
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(operation['phase'], 'accepted')
    self.assertEqual(self.coordinator.commands, [])

  def test_immutable_preparation_cannot_be_replaced_with_different_values(self):
    self.state.fail_write = lambda namespace, key: 'after' if namespace == 'DAUTH_JOB_SECRET_REVISIONS' else None
    with self.assertRaises(RuntimeError):
      self.admit()
    self.state.fail_write = None
    operation = self.operation()
    with self.assertRaises(RuntimeError):
      self.coordinator._deployment_secret_request('prepare', operation, new_secrets={
        'PLUGINS': [{'INSTANCES': [{'ENV': {'CF_TUNNEL_TOKEN': 'different-token'}}]}],
      })
    reference = '7|' + operation['operation_id'] + ':deploy'
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', reference]), 'fresh-token')

  def test_scale_up_reuses_hidden_values_for_generated_identity_on_dauth(self):
    self.admit()
    original = self.operation()
    self.finalize(original)
    accepted = self.coordinator._admit_scale_up_operation(
      {'job_id': 7, 'request_id': 'scale', 'expected_revision': 1},
      {'escrow_owner': 'owner'}, ['B'],
    )
    operation = self.coordinator._operation_records()[accepted['operation_id']]
    self.assertEqual(operation['nodes'], ['A', 'B'])
    plan = self.coordinator._load_operation_plan(operation)
    new_identity = plan['configs']['B']['PLUGINS'][0]['INSTANCES'][0]['INSTANCE_ID']
    self.assertNotEqual(new_identity, 'worker')
    self.assertNotIn('fresh-token', str(self.state.public) + str(self.state.blobs.data))
    self.finalize(operation)
    self.assertEqual(operation['outcome'], 'succeeded')
    bundle = self.state.secrets['DAUTH_JOB_SECRETS', '7']
    self.assertEqual(self.token(bundle), 'fresh-token')
    requested = self.dauth._load_revision_runner_secret_bundle('7', operation['operation_id'] + ':deploy', 'B')
    self.assertEqual(self.token(requested), 'fresh-token')
    aliases = next(call.kwargs['json']['body']['identity_aliases'] for call in self.http.call_args_list
                   if call.kwargs['json']['body'].get('action') == 'prepare'
                   and call.kwargs['json']['body']['operation']['operation_id'] == operation['operation_id'])
    self.assertTrue(any(pair[0][1] == new_identity and pair[1][1] == 'worker' for pair in aliases))
    self.assertTrue(self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', '7|' + original['operation_id'] + ':deploy']['revoked'])

  def test_delete_retains_secrets_until_stop_then_dauth_publishes_tombstone(self):
    self.admit()
    original = self.operation()
    self.finalize(original)
    cid = self.state.public['DEEPLOY_DEPLOYED_JOBS', '7']['pipeline_cid']
    accepted = self.coordinator._admit_delete_operation(
      {'job_id': 7, 'request_id': 'delete', 'expected_revision': 1}, {'escrow_owner': 'owner'},
    )
    operation = self.coordinator._operation_records()[accepted['operation_id']]
    self.coordinator._advance_delete_operation(operation)
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'fresh-token')
    self.assertNotIn(cid, self.state.blobs.deleted)
    report(self.state, operation, 'retire', 'stopped')
    self.coordinator._advance_delete_operation(operation)
    pointer = self.state.public['DEEPLOY_DEPLOYED_JOBS', '7']
    self.assertTrue(pointer['deleted'])
    self.assertIsNone(pointer['pipeline_cid'])
    self.assertEqual(pointer['revision'], 2)
    self.assertEqual(self.state.secrets['DAUTH_JOB_SECRETS', '7']['job_secrets'], {})
    self.assertIn(cid, self.state.blobs.deleted)
    self.assertTrue(self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', '7|' + original['operation_id'] + ':deploy']['revoked'])

  def test_owner_transfer_recovery_keeps_new_owner_and_old_content_secrets(self):
    self.admit()
    self.finalize(self.operation())
    accepted = self.coordinator._admit_owner_transfer_operation(7, 'owner', 'new-owner', 'tx|0')
    operation = self.coordinator._operation_records()[accepted['operation_id']]
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'retire', 'stopped')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'failed')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'stopped')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'restore', 'ready')
    self.coordinator._advance_deployment_operation(operation)
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(operation['recovery'], 'completed')
    self.assertEqual(self.active()['OWNER'], 'new-owner')
    self.assertEqual(self.active()['DEEPLOY_SPECS']['revision'], 1)
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'fresh-token')

  def test_partial_publication_replays_before_old_cid_cleanup(self):
    previous, cid = self.legacy()
    self.admit(previous)
    operation = self.operation()
    self.state.fail_write = lambda namespace, key: 'before' if namespace == 'DEEPLOY_DEPLOYED_JOBS' else None
    with self.assertRaises(RuntimeError):
      self.finalize(operation)
    self.assertEqual(operation['phase'], 'finalizing')
    self.assertEqual(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'], cid)
    self.assertNotIn(cid, self.state.blobs.deleted)
    self.state.fail_write = None
    self.coordinator = Coordinator(self.state)
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(operation['outcome'], 'succeeded')
    self.assertEqual(self.state.blobs.deleted.count(cid), 1)
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'fresh-token')

  def test_retry_after_pointer_publication_reuses_cid_and_finishes_cleanup(self):
    previous, cid = self.legacy()
    self.admit(previous)
    operation = self.operation()
    self.state.fail_write = lambda namespace, key: 'before' if key.endswith('|revoked') else None
    with self.assertRaises(RuntimeError):
      self.finalize(operation)
    pointer = copy.deepcopy(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'])
    uploads = self.state.blobs.uploads
    self.assertNotEqual(pointer['pipeline_cid'], cid)
    self.state.fail_write = None
    self.coordinator = Coordinator(self.state)
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(operation['outcome'], 'succeeded')
    self.assertEqual(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'], pointer)
    self.assertEqual(self.state.blobs.uploads, uploads)
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'fresh-token')

  def test_missing_or_changed_published_content_cannot_publish_or_revoke(self):
    self.admit()
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'ready')
    self.coordinator._advance_deployment_operation(operation)
    plan = self.coordinator._load_operation_plan(operation)
    canonical = copy.deepcopy(plan['configs']['A'])
    canonical.pop('DEEPLOY_OPERATION', None)
    canonical = self.dauth._recursively_sort_pipeline_data(
      self.dauth.extract_invariable_data_from_pipeline(canonical))
    pointer = dict(job_id='7', revision=operation['target_revision'], operation_id=operation['operation_id'],
                   coordinator='oracle', deleted=False, pipeline_cid='published-folder')
    self.coordinator.bc.sign(pointer)
    for content, error in ((None, RuntimeError), (dict(canonical, unexpected=True), ValueError)):
      with self.subTest(content_missing=content is None):
        self.state.blobs.data['published-folder'] = content
        writes = len(self.state.writes)
        self.state.public.pop(('DEEPLOY_DEPLOYED_JOBS', '7'), None)
        with self.assertRaises(error):
          self.dauth._publish_deployment_secrets('7', operation, plan, pointer)
        self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'] = pointer
        with self.assertRaises(error):
          self.dauth._revoke_deployment_secret_revisions('7', operation, plan, 'deploy')
        self.assertEqual(len(self.state.writes), writes)
        self.assertNotIn(('DAUTH_JOB_SECRETS', '7'), self.state.secrets)

  def test_invalid_target_is_rejected_before_staging_restoration(self):
    previous, _ = self.legacy()
    target = pipeline(dAuth.DAUTH_SECRET_PLACEHOLDER)
    target['PLUGINS'][0]['INSTANCES'][0]['ENV']['CRDB_PASSWORD'] = dAuth.DAUTH_SECRET_PLACEHOLDER
    with self.assertRaises(RuntimeError):
      self.coordinator._admit_prepared_deployment(
        request={'job_id': 7, 'request_id': 'invalid', 'expected_revision': 0},
        auth_result={'escrow_owner': 'owner'}, app_id='app', configs={'A': target},
        prior_pipeline=previous, is_create=False,
      )
    self.assertFalse(any(namespace == 'DAUTH_JOB_SECRET_REVISIONS' for namespace, _ in self.state.secrets))

  def test_invalid_scope_and_phase_cannot_stage_or_publish_secrets(self):
    self.admit()
    operation = self.operation()
    for changed in (dict(operation, job_id=8), dict(operation, app_id='other'),
                    dict(operation, owner='other'), dict(operation, network='other'),
                    dict(operation, nodes=['B']), dict(operation, target_revision=0),
                    dict(operation, coordinator='other')):
      with self.subTest(changed=changed):
        changed['phase'] = 'preparing'
        self.coordinator.bc.sign(changed)
        writes = len(self.state.writes)
        with self.assertRaises(RuntimeError):
          self.coordinator._deployment_secret_request('prepare', changed)
        self.assertEqual(len(self.state.writes), writes)
    writes = len(self.state.writes)
    with self.assertRaises(RuntimeError):
      self.coordinator._deployment_secret_request('commit', operation, pointer={'pipeline_cid': 'wrong'})
    self.assertEqual(len(self.state.writes), writes)

  def test_forged_pointer_and_plan_cid_mismatch_cannot_publish(self):
    self.admit()
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'ready')
    self.coordinator._advance_deployment_operation(operation)
    pointer = dict(job_id='7', revision=operation['target_revision'], operation_id=operation['operation_id'],
                   coordinator='oracle', deleted=False, pipeline_cid='wrong-cid')
    self.coordinator.bc.sign(pointer)
    for value in (dict(pointer, EE_SIGN='forged'), pointer):
      writes = len(self.state.writes)
      with self.assertRaises(RuntimeError):
        self.coordinator._deployment_secret_request('commit', operation, pointer=value)
      self.assertEqual(len(self.state.writes), writes)
      self.assertNotIn(('DAUTH_JOB_SECRETS', '7'), self.state.secrets)

  def test_revocation_marker_wins_over_cached_payload_during_recovery(self):
    self.state.fail_write = lambda namespace, key: 'after' if namespace == 'DAUTH_JOB_SECRET_REVISIONS' else None
    with self.assertRaises(RuntimeError):
      self.admit()
    self.state.fail_write = None
    operation = self.operation()
    reference = operation['operation_id'] + ':deploy'
    self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', '7|' + reference + '|revoked'] = dict(job_id='7', revision=reference)
    writes = len(self.state.writes)
    self.assertFalse(self.coordinator._deployment_secret_request('status', operation)['prepared'])
    self.assertEqual(len(self.state.writes), writes)

  def test_secrets_on_additional_nodes_are_validated_and_retained(self):
    configs = {'A': pipeline(), 'B': pipeline()}
    for config in configs.values():
      config['DEEPLOY_SPECS']['current_target_nodes'] = ['A', 'B']
    configs['B']['PLUGINS'][0]['INSTANCES'][0]['ENV']['CRDB_PASSWORD'] = 'node-secret'
    self.coordinator._admit_prepared_deployment(
      request={'job_id': 7, 'request_id': 'nodes'}, auth_result={'escrow_owner': 'owner'},
      app_id='app', configs=configs, prior_pipeline=None, is_create=True,
    )
    operation = self.operation()
    bundle = self.dauth._load_revision_runner_secret_bundle('7', operation['operation_id'] + ':deploy', 'B')
    self.assertEqual(bundle['job_secrets']['PLUGINS'][0]['INSTANCES'][0]['ENV']['CRDB_PASSWORD'], 'node-secret')
    self.assertNotIn('node-secret', str(self.state.public) + str(self.state.blobs.data))

  def test_stale_preparation_cleanup_cannot_revoke_published_secrets(self):
    self.admit()
    operation = self.operation()
    stale = dict(operation, phase='preparing')
    self.coordinator.bc.sign(stale)
    self.finalize(operation)
    self.state.now = stale['preparation_deadline'] + 1
    self.state.public = {key: value for key, value in self.state.public.items() if key[0] != 'DEEPLOY_OPERATIONS'}
    writes = len(self.state.writes)
    with self.assertRaises(RuntimeError):
      self.coordinator._deployment_secret_request('revoke', stale, active_attempt=None)
    self.assertEqual(len(self.state.writes), writes)

  def test_interrupted_preparation_erasure_resumes_after_revocation_marker(self):
    self.state.fail_write = lambda namespace, key: 'before' if namespace == 'DAUTH_JOB_SECRET_REVISIONS' and key.endswith(':deploy') else None
    with self.assertRaises(RuntimeError):
      self.admit()
    operation = self.operation()
    self.state.now = operation['preparation_deadline'] + 1
    with self.assertRaises(RuntimeError):
      self.coordinator._advance_deployment_operation(operation)
    self.assertEqual((operation['phase'], operation['outcome'], operation['recovery']),
                     ('cleaning_up_preparation', 'failed', 'in_progress'))
    marker = '7|' + operation['operation_id'] + ':deploy|revoked'
    self.assertIn(('DAUTH_JOB_SECRET_REVISIONS', marker), self.state.secrets)
    self.state.fail_write = None
    self.coordinator = Coordinator(self.state)
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual((operation['phase'], operation['outcome']), ('completed', 'failed'))
    self.assertEqual(self.coordinator.commands, [])

  def test_preparation_cleanup_rejects_delayed_preparation_and_requires_expiry(self):
    self.state.fail_write = lambda namespace, key: 'before' if namespace == 'DAUTH_JOB_SECRET_REVISIONS' and key.endswith(':deploy') else None
    with self.assertRaises(RuntimeError):
      self.admit()
    stale = self.operation()
    operation = copy.deepcopy(stale)
    self.state.now = operation['preparation_deadline']
    with self.assertRaises(RuntimeError):
      self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(operation['phase'], 'cleaning_up_preparation')
    writes = len(self.state.writes)
    for snapshot in (stale, operation):
      for action in ('prepare', 'status'):
        with self.subTest(phase=snapshot['phase'], action=action):
          with self.assertRaises(RuntimeError):
            self.coordinator._deployment_secret_request(action, snapshot)
    with self.assertRaises(RuntimeError):
      self.coordinator._deployment_secret_request('revoke', operation, active_attempt='deploy')
    self.state.now = operation['preparation_deadline'] - 1
    with self.assertRaises(RuntimeError):
      self.coordinator._deployment_secret_request('revoke', operation, active_attempt=None)
    self.assertEqual(len(self.state.writes), writes)
    self.assertEqual(self.coordinator.commands, [])

  def test_conflicting_values_at_shared_secret_path_fail_before_persistence(self):
    with self.assertRaisesRegex(ValueError, 'conflicting values'):
      self.coordinator._admit_prepared_deployment(
        request={'job_id': 7, 'request_id': 'conflict'}, auth_result={'escrow_owner': 'owner'},
        app_id='app', configs={'A': pipeline('token-A'), 'B': pipeline('token-B')},
        prior_pipeline=None, is_create=True,
      )
    self.assertEqual(self.state.writes, [])
    self.assertEqual(self.state.blobs.data, {})
    self.assertEqual(self.http.call_count, 0)
