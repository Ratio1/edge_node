"""Fault injection at the real admission persistence and protected-copy boundaries."""
import copy
import unittest

from extensions.business.deeploy.deployment_operations import OPERATIONS_HKEY, SECRET_REVISIONS_HKEY
from extensions.business.deeploy.tests.test_deployment_admission import Admission, config


class DeploymentAdmissionRecoveryTests(unittest.TestCase):
  def recover(self, plugin):
    operation = next(iter(plugin._operation_records().values()))
    plugin.r1fs.get_json = lambda cid, **kwargs: copy.deepcopy(plugin.plans[cid])
    plugin._advance_deployment_operation(operation)
    return operation

  def test_plan_or_first_operation_failure_never_writes_secrets(self):
    for failure in ('plan', 'operation'):
      with self.subTest(failure=failure):
        plugin = Admission()
        plugin.fail_blob = failure == 'plan'
        plugin.fail_namespace = OPERATIONS_HKEY if failure == 'operation' else None
        with self.assertRaises(RuntimeError):
          plugin.admit()
        self.assertFalse(any(namespace == SECRET_REVISIONS_HKEY for namespace, _ in plugin.writes))
        self.assertEqual(plugin.commands, [])
        if failure == 'plan':
          self.assertEqual(plugin.writes, [])

  def test_complete_but_uncertain_secret_replication_resumes_without_early_dispatch(self):
    plugin = Admission()
    plugin.fail_namespace = SECRET_REVISIONS_HKEY
    with self.assertRaises(RuntimeError):
      plugin.admit()
    operation = next(iter(plugin._operation_records().values()))
    self.assertEqual(operation['phase'], 'preparing')
    with self.assertRaises(RuntimeError):
      self.recover(plugin)
    self.assertEqual(plugin.commands, [])
    plugin.fail_namespace = None
    before = len(plugin.writes)
    operation = self.recover(plugin)
    self.assertEqual(operation['phase'], 'accepted')
    self.assertTrue(any(namespace == SECRET_REVISIONS_HKEY for namespace, _ in plugin.writes[before:]))
    self.assertEqual(plugin.commands, [])
    self.assertEqual(operation['deadline'], 160)

  def partial_update(self):
    plugin = Admission()
    previous = {node: config(node, revision=4) for node in ['A', 'B']}
    prior_bundle = {'job_id': '7', 'revision': 'previous:deploy',
                    'pipelines': previous, 'job_secrets': {'secret': 'original-secret'}}
    plugin.seed_previous(previous, prior_bundle)
    # Local restore copy is written, replication fails, so the new deploy copy is absent.
    plugin.fail_namespace = SECRET_REVISIONS_HKEY
    with self.assertRaises(RuntimeError):
      plugin.admit({'request_id': 'update', 'job_id': 7, 'expected_revision': 4},
                   prior=previous['A'], prior_bundle=prior_bundle)
    plugin.fail_namespace = None
    return plugin, prior_bundle

  def test_partial_update_waits_then_revokes_only_its_copies(self):
    plugin, prior = self.partial_update()
    operation = self.recover(plugin)
    self.assertEqual(operation['phase'], 'preparing')
    self.assertEqual(plugin.commands, [])
    plugin.time = lambda: 221
    operation = self.recover(plugin)
    self.assertEqual((operation['phase'], operation['outcome'], operation['recovery']),
                     ('completed', 'failed', 'completed'))
    self.assertEqual(operation['error']['code'], 'ADMISSION_PREPARATION_FAILED')
    self.assertEqual(plugin.storage[SECRET_REVISIONS_HKEY, '7|previous:deploy'], prior)
    self.assertNotIn((SECRET_REVISIONS_HKEY, '7|previous:deploy|revoked'), plugin.storage)
    for attempt in ('deploy', 'restore'):
      key = '7|' + operation['operation_id'] + ':' + attempt
      self.assertTrue(plugin.storage[SECRET_REVISIONS_HKEY, key]['revoked'])
      self.assertIn((SECRET_REVISIONS_HKEY, key + '|revoked'), plugin.storage)
    self.assertEqual(plugin.commands, [])

  def test_cleanup_replication_failure_is_retried_before_completion(self):
    plugin, prior = self.partial_update()
    plugin.time = lambda: 221
    plugin.fail_namespace = SECRET_REVISIONS_HKEY
    with self.assertRaisesRegex(RuntimeError, 'revocation is pending'):
      self.recover(plugin)
    self.assertEqual(next(iter(plugin._operation_records().values()))['phase'], 'preparing')
    self.assertEqual(plugin.commands, [])
    plugin.fail_namespace = None
    operation = self.recover(plugin)
    self.assertEqual(operation['phase'], 'completed')
    self.assertEqual(plugin.storage[SECRET_REVISIONS_HKEY, '7|previous:deploy'], prior)

  def test_mismatched_complete_bundle_cannot_become_accepted(self):
    plugin = Admission()
    plugin.fail_namespace = SECRET_REVISIONS_HKEY
    with self.assertRaises(RuntimeError):
      plugin.admit()
    secret_key = next(key for namespace, key in plugin.storage if namespace == SECRET_REVISIONS_HKEY)
    plugin.storage[SECRET_REVISIONS_HKEY, secret_key]['pipelines']['A']['NAME'] = 'different-app'
    plugin.fail_namespace = None
    operation = self.recover(plugin)
    self.assertEqual(operation['phase'], 'preparing')
    plugin.time = lambda: 221
    self.assertEqual(self.recover(plugin)['outcome'], 'failed')
    self.assertEqual(plugin.commands, [])


if __name__ == '__main__':
  unittest.main()
