"""Lifecycle preparation and finalization through real SDK and Core wrapper APIs."""
import copy
# Store encrypted files by their checksum in the offline transport.
import hashlib
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from ratio1.bc.base import BaseBlockEngine
from ratio1.const.base import dAuth
from ratio1.ipfs.r1fs import R1FSEngine
# The error type of a secret record the chain store refused for its size.
from extensions.business.dauth.deployment_secrets import DeploymentSecretRecordTooLarge
from extensions.business.deeploy.tests.lifecycle_custody_support import (
  Coordinator, Custodian, Engine, State, pipeline, connect, report,
)


def ciphertext_transport(folder):
  """Keep the SDK encryption and replace only its IPFS command boundary.

  Parameters
  ----------
  folder : str
    Private SDK download root for this test.

  Returns
  -------
  tuple[R1FSEngine, dict]
    The SDK engine and the immutable bytes captured from uploads.

  Examples
  --------
  >>> sdk, blobs = ciphertext_transport(folder)  # doctest: +SKIP
  """
  # Skip daemon startup and configure only the fields used by these file operations.
  sdk = object.__new__(R1FSEngine)
  # Preserve each synthetic CID even when the application stops pinning it.
  blobs = {}
  # No external relay, storage daemon or network configuration is needed.
  sdk._R1FSEngine__ipfs_started = True
  sdk._R1FSEngine__downloads_dir = folder
  sdk._R1FSEngine__downloaded_files = {}
  sdk._R1FSEngine__uploaded_files = {}
  sdk._R1FSEngine__relay_publication_status = {}
  sdk._R1FSEngine__DEFAULT_SECRET = "ratio1"
  # Record execution without side effects from the logger, relay or in-memory upload bookkeeping.
  sdk.P = sdk.Pd = Mock()
  sdk._R1FSEngine__set_upload_status = Mock()
  sdk._R1FSEngine__publish_cid_to_relay = Mock()
  sdk._R1FSEngine__relay_in_background = Mock()
  sdk.delete_file = Mock(return_value=True)

  def run(command, **kwargs):
    """Save and restore the SDK's real ciphertext at the IPFS command boundary.

    Parameters
    ----------
    command : list
      Command passed by the SDK to IPFS.
    **kwargs : dict
      SDK command options.

    Returns
    -------
    str
      A synthetic CID or the expected command result.

    Examples
    --------
    >>> run(["ipfs", "pin", "add", "FixtureCid"])
    'ok'
    """
    if command[1] == "add":
      # Capture actual SDK AES-GCM output before its temporary file is cleaned up.
      contents = Path(command[-1]).read_bytes()
      # Pick a valid bare CID in the SDK's input contract.
      cid = hashlib.sha256(contents).hexdigest()
      # Retain old ciphertext to test whether it remains decryptable after rewrite.
      blobs[cid] = contents
      return cid
    if command[1] == "get":
      # Replicate the wrapped one-file directory created by Kubo.
      output = Path(command[-1])
      # The SDK has removed any older downloads of this CID.
      output.mkdir()
      # Restore the same bytes that were uploaded.
      (output / "ciphertext").write_bytes(blobs[command[2]])
    return "ok"

  # Record exactly how many network-bound commands a request would have executed.
  sdk._R1FSEngine__run_command = Mock(side_effect=run)
  return sdk, blobs


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
    self.running(operation)

  def running(self, operation, attempt='configs'):
    # NetMon stand-in: each node now reports the config it was sent.
    plan = self.coordinator._load_operation_plan(operation)
    self.coordinator.known = {node: [copy.deepcopy(config)] for node, config in plan[attempt].items()}

  def active(self):
    pointer = self.state.public['DEEPLOY_DEPLOYED_JOBS', '7']
    return self.state.blobs.get_json(pointer['pipeline_cid'])

  def _admit_resource_removal(self):
    # Two same-signature rows, with different protected credentials, occupy the initial placement.
    previous = pipeline()
    previous["DEEPLOY_SPECS"].update(job_app_type="stack", node_res_req={"cpu": 1, "memory": "2g"})
    group = previous["PLUGINS"][0]
    group["SIGNATURE"] = "CONTAINER_APP_RUNNER"
    kept = group["INSTANCES"][0]
    kept.update(CONTAINER_RESOURCES={"cpu": ".4", "memory": "512m", "storage": "0g"})
    removed = copy.deepcopy(kept)
    removed.update(INSTANCE_ID="removed", ENV={"CF_TUNNEL_TOKEN": "removed-token"})
    group["INSTANCES"].insert(0, removed)
    cid = self.state.blobs.add_json(previous)
    self.state.public["DEEPLOY_DEPLOYED_JOBS", "7"] = cid
    self.coordinator.known = {"A": [previous]}
    desired = copy.deepcopy(previous)
    desired["PLUGINS"][0]["INSTANCES"].pop(0)
    survivor = desired["PLUGINS"][0]["INSTANCES"][0]
    survivor.update(CONTAINER_RESOURCES={"cpu": ".8", "memory": "1g", "storage": "0g"},
                    ENV={"CF_TUNNEL_TOKEN": dAuth.DAUTH_SECRET_PLACEHOLDER})
    accepted = self.coordinator._admit_prepared_deployment(
      request={"job_id": 7, "request_id": "split", "expected_revision": 0, "plugins": [{"instance_id": "worker"}]}, auth_result={"escrow_owner": "owner"},
      app_id="app", configs={"A": desired}, prior_pipeline=previous, is_create=False,
      resource_tier={"cpu": 1, "memory": "2g"}, deferred_capacity=True)
    self.assertEqual(accepted["status_code"], 202)
    return self.operation()

  def test_redistribution_stages_by_identity_and_restores_on_capacity_timeout(self):
    from datetime import datetime, timezone
    from naeural_core import constants as ct
    from extensions.business.deeploy.deployment_operations import deployment_operation_phase
    operation = self._admit_resource_removal()
    self.assertEqual(operation["mutation"], "resource_redistribution_v1")
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, "retire", "stopped")
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(deployment_operation_phase(operation), "waiting_for_capacity")
    # The old packet has ample capacity. Its sender timestamp makes it unusable after a stop.
    sampled = datetime.fromtimestamp(self.state.now - 1, timezone.utc).strftime(ct.HB.TIMESTAMP_FORMAT)
    sample = {ct.HB.CURRENT_TIME: sampled, ct.PAYLOAD_DATA.EE_TIMEZONE: "UTC+0",
              ct.HB.CPU_NR_CORES: 4, ct.HB.CPU_USED: 10, ct.HB.AVAILABLE_MEMORY: 16, ct.HB.AVAILABLE_DISK: 3}
    self.coordinator.netmon.network_node_last_heartbeat = lambda node: sample
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(deployment_operation_phase(operation), "waiting_for_capacity")
    self.assertFalse(any(command[1]["DEEPLOY_OPERATION"]["action"] == "start" for command in self.coordinator.commands))
    self.state.now += 2
    sample[ct.HB.CURRENT_TIME] = datetime.fromtimestamp(self.state.now, timezone.utc).strftime(ct.HB.TIMESTAMP_FORMAT)
    self.assertEqual(self.coordinator._post_retirement_capacity("A", operation["capacity_after"]["A"],
                                                              [".8", "1073741824", "0"]), (self.state.now, True))
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(deployment_operation_phase(operation), "waiting_for_capacity")  # First post-stop sample is the fence.
    self.state.now += 1
    sample[ct.HB.CURRENT_TIME] = datetime.fromtimestamp(self.state.now, timezone.utc).strftime(ct.HB.TIMESTAMP_FORMAT)
    sample[ct.HB.AVAILABLE_MEMORY] = 0.01
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(deployment_operation_phase(operation), "waiting_for_capacity")
    self.state.now = operation["deadline"]
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(deployment_operation_phase(operation), "restoring_previous")
    self.assertEqual(operation["error"]["code"], "POST_RETIRE_CAPACITY_UNCONFIRMED")
    report(self.state, operation, "restore", "ready")
    self.coordinator._advance_deployment_operation(operation)
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(operation["recovery"], "completed")
    self.assertEqual(len(self.active()["PLUGINS"][0]["INSTANCES"]), 2)

  def test_legacy_native_update_recovers_worker_ceiling_when_both_requests_omit_it(self):
    previous = pipeline()
    previous["DEEPLOY_SPECS"]["job_app_type"] = "native"  # This older client never sent node_res_req.
    group = previous["PLUGINS"][0]
    group["SIGNATURE"] = "CONTAINER_APP_RUNNER"
    group["INSTANCES"] = [{"INSTANCE_ID": iid, "CONTAINER_RESOURCES": {"cpu": 1, "memory": "7g"}}
                          for iid in ("first", "second")]
    self.state.public["DEEPLOY_DEPLOYED_JOBS", "7"] = self.state.blobs.add_json(previous)
    self.coordinator.known = {"A": [previous]}  # The saved revision and worker report agree.

    def admit_pair(first, second):
      desired = copy.deepcopy(previous)
      rows = desired["PLUGINS"][0]["INSTANCES"]
      for row, memory in zip(rows, (first, second)):
        row["CONTAINER_RESOURCES"]["memory"] = memory
      request_rows = [{"plugin_signature": group["SIGNATURE"], "instance_id": row["INSTANCE_ID"],
                       "CONTAINER_RESOURCES": row["CONTAINER_RESOURCES"]} for row in rows]
      return self.coordinator._admit_prepared_deployment(
        request={"job_id": 7, "request_id": "legacy-" + first, "expected_revision": 0, "plugins": request_rows},
        auth_result={"escrow_owner": "owner"}, app_id="app", configs={"A": desired}, prior_pipeline=previous,
        is_create=False, resource_tier={"cpu": 3, "memory": "14g"})

    with self.assertRaisesRegex(ValueError, "worker tier"):
      admit_pair("11g", "3g")  # Balanced total; one row exceeds the historical N-ENTRY usable limit.
    self.assertFalse(self.coordinator._operation_records())
    self.assertEqual(admit_pair("10g", "4g")["status_code"], 202)
    self.assertEqual(self.operation()["mutation"], "resource_redistribution_v1")

  def test_redistribution_publishes_one_survivor_after_two_fresh_worker_samples(self):
    from datetime import datetime, timezone
    from naeural_core import constants as ct
    from extensions.business.deeploy.deployment_operations import deployment_operation_phase
    operation = self._admit_resource_removal()
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, "retire", "stopped")
    self.coordinator._advance_deployment_operation(operation)
    def fresh(node):
      return {ct.HB.CURRENT_TIME: datetime.fromtimestamp(self.state.now, timezone.utc).strftime(ct.HB.TIMESTAMP_FORMAT),
              ct.PAYLOAD_DATA.EE_TZ: "UTC", ct.HB.CPU_NR_CORES: 2, ct.HB.CPU_USED: 30,
              ct.HB.AVAILABLE_MEMORY: 1, ct.HB.AVAILABLE_DISK: 0}
    self.coordinator.netmon.network_node_last_heartbeat = fresh
    self.state.now += 1
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(deployment_operation_phase(operation), "waiting_for_capacity")
    operation = self.operation()  # A coordinator restart reloads the first heartbeat fence.
    self.state.now += 1
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(deployment_operation_phase(operation), "waiting_for_readiness")
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, "deploy", "ready")
    self.coordinator._advance_deployment_operation(operation)
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual(operation["outcome"], "succeeded")
    self.assertEqual([i["INSTANCE_ID"] for i in self.active()["PLUGINS"][0]["INSTANCES"]], ["worker"])
    self.assertEqual(self.token(self.state.secrets["DAUTH_JOB_SECRETS", "7"]), "fresh-token")

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

  def test_legacy_reordered_workers_reject_before_custody(self):
    # Synthetic job 31 shape: both identities changed; the same two workers report
    # reversed commands, peers and placement. The original NetMon snapshots were not retained.
    stored = pipeline()
    stored['DEEPLOY_SPECS'] = {'job_id': 31, 'current_target_nodes': ['old-A', 'old-B']}
    plugin = stored['PLUGINS'][0]
    plugin['SIGNATURE'] = 'WORKER_APP_RUNNER'
    plugin['INSTANCES'][0].update(BUILD_AND_RUN_COMMANDS=['build', 'install'], CHAINSTORE_PEERS=['P', 'Q'])
    pointer_key = ('DEEPLOY_DEPLOYED_JOBS', '31')
    cid = self.state.public[pointer_key] = self.state.blobs.add_json(stored)
    running = copy.deepcopy(stored)
    running['DEEPLOY_SPECS']['current_target_nodes'].reverse()
    instance = running['PLUGINS'][0]['INSTANCES'][0]
    instance['BUILD_AND_RUN_COMMANDS'].reverse()
    instance['CHAINSTORE_PEERS'].reverse()
    reports = {node: [running] for node in ('new-A', 'new-B')}
    # The submitted configuration names the current identities; it is distinct from rollback content.
    desired = copy.deepcopy(running)
    desired['DEEPLOY_SPECS']['current_target_nodes'] = list(reports)
    for later_reports in (reports, {}):
      with self.subTest(later_observation_empty=not later_reports):
        self.coordinator.netmon.network_known_pipelines = Mock(side_effect=[reports, later_reports])
        with self.assertRaisesRegex(ValueError, 'repair the stored job first'):
          self.coordinator._admit_prepared_deployment(
            request={'job_id': 31, 'expected_revision': 0, 'request_id': 'legacy-update'},
            auth_result={'escrow_owner': 'owner'}, app_id=stored['NAME'],
            configs={node: copy.deepcopy(desired) for node in reports}, prior_pipeline=stored, is_create=False,
          )
        # A rejected update must leave the old job running and its canonical pointer intact.
        self.assertEqual(self.state.public, {pointer_key: cid})
        self.assertEqual(self.state.writes, [])
        self.assertEqual(self.coordinator.commands, [])
        self.http.assert_not_called()

  def test_waiting_create_and_update_publish_secrets_and_allow_job_commands_and_delete(self):
    previous = None
    operations = []
    for revision in (1, 2):
      cfg = pipeline(secret='token-' + str(revision))
      cfg['PLUGINS'][0]['SIGNATURE'] = 'WORKER_APP_RUNNER'
      accepted = self.coordinator._admit_prepared_deployment(
        request={'request_id': 'source-' + str(revision), 'job_id': 7, 'expected_revision': revision - 1},
        auth_result={'escrow_owner': 'owner'}, app_id='app', configs={'A': cfg},
        prior_pipeline=previous, is_create=previous is None)
      operation = self.coordinator._operation_records()[accepted['operation_id']]
      self.coordinator._advance_deployment_operation(operation)
      if previous:
        report(self.state, operation, 'retire', 'stopped')
        self.coordinator._advance_deployment_operation(operation)
      report(self.state, operation, 'deploy', 'failed', mode='following', error='WORKLOAD_START_FAILED')
      self.coordinator._advance_deployment_operation(operation)
      self.coordinator._advance_deployment_operation(operation)
      previous = self.active()
      self.assertEqual((operation['outcome'], operation['recovery']), ('waiting_for_source', None))
      self.assertEqual(previous['DEEPLOY_SPECS']['revision'], revision)
      self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'token-' + str(revision))
      self.coordinator._assert_no_active_deployment(job_id=7, app_id='app')  # Same guard as restart.
      self.running(operation)
      operations.append(operation)
    ref = '7|' + operations[0]['operation_id'] + ':deploy'
    self.assertIn('revoked', self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', ref])
    self.assertNotIn('stop', [cmd['DEEPLOY_OPERATION']['action'] for _, cmd in self.coordinator.commands])
    deleted = self.coordinator._admit_delete_operation(
      {'request_id': 'delete', 'job_id': 7, 'expected_revision': 2}, {'escrow_owner': 'owner'})
    self.assertEqual(deleted['status_code'], 202)

  def test_custody_reads_do_not_pin_so_their_timeout_bounds_them(self):
    previous, _ = self.legacy()
    self.dauth.r1fs = Mock(wraps=self.state.blobs)
    self.admit(previous)
    self.finalize(self.operation())
    reads = self.dauth.r1fs.get_json.call_args_list
    self.assertGreaterEqual(len(reads), 3)
    self.assertTrue(all(read.kwargs.get('pin') is False and read.kwargs.get('timeout') == 10 for read in reads))

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
    logs = []
    self.coordinator.engine.P = lambda message, color=None, **kwargs: logs.append((message, color))
    with self.assertRaises(RuntimeError):
      self.coordinator._deployment_secret_request('revoke', stale, active_attempt='deploy')
    # The SDK names the dAuth server that refused, by the alias its signed answer carries.
    self.assertEqual(logs, [('dAuth server dauth refused secret reconciliation (revoke).', 'r')])
    self.assertEqual(len(self.state.writes), writes)
    restored_ref = '7|' + operation['operation_id'] + ':restore'
    self.assertNotIn('revoked', self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', restored_ref])

  def test_blocked_update_ends_without_restoring_and_revokes_only_the_deploy_revision(self):
    """Verify a failed rollout across the real SDK and dAuth custody boundary.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Examples
    --------
    >>> LifecycleDauthCustodyTests('test_blocked_update_ends_without_restoring_and_revokes_only_the_deploy_revision').run()
    """
    # Prepare two scoped revisions over the signed custody endpoint.
    previous, cid = self.legacy()
    self.admit(previous)
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'retire', 'stopped')
    self.coordinator._advance_deployment_operation(operation)
    report(self.state, operation, 'deploy', 'failed')
    self.coordinator._advance_deployment_operation(operation)
    # No signed stop arrives after failure. The operation is still open one second before grace expires.
    readiness = self.coordinator.cfg_deployment_readiness_timeout
    self.state.now = operation['recovery_started_at'] + 25 * readiness - 1
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual((operation['phase'], operation['recovery']), ('stopping_failed_rollout', 'blocked'))
    # At the deadline execution ends independently of secret-store availability.
    self.state.now += 1
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual((operation['phase'], operation['outcome'], operation['unconfirmed_nodes']), ('completed', 'failed', ['A']))
    key = '7|' + operation['operation_id']
    deploy = key + ':deploy'
    restore = key + ':restore'
    self.state.fail_write = lambda namespace, field: 'before' if field == deploy + '|revoked' else None
    self.coordinator._reconcile_coordinator_operations()
    self.assertTrue(self.operation()['abandoned_deploy_revocation_pending'])
    # The next successful custody call revokes the attempted revision and keeps the previous plan available.
    self.state.fail_write = None
    self.state.now += 10
    self.coordinator._reconcile_coordinator_operations()
    self.assertTrue(self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', deploy]['revoked'])
    self.assertNotIn('revoked', self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', restore])
    self.assertNotIn('abandoned_deploy_revocation_pending', self.operation())
    self.assertEqual(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'], cid)
    self.assertNotIn('restore', [cmd['DEEPLOY_OPERATION']['attempt'] for _, cmd in self.coordinator.commands])

  def test_late_signed_create_stops_unlock_paid_retry_only_after_custody_release(self):
    """Verify that late receipts can complete cleanup without resuming execution.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Examples
    --------
    >>> LifecycleDauthCustodyTests('test_late_signed_create_stops_unlock_paid_retry_only_after_custody_release').run()
    """
    # Admit a paid create whose worker misses both readiness and cleanup deadlines.
    self.admit()
    operation = self.operation()
    self.coordinator._advance_deployment_operation(operation)
    self.state.now = operation['deadline']
    self.coordinator._advance_deployment_operation(operation)
    self.state.now += 25 * self.coordinator.cfg_deployment_readiness_timeout
    self.coordinator._advance_deployment_operation(operation)
    self.assertEqual((operation['phase'], operation['outcome'], operation['recovery']), ('completed', 'failed', 'blocked'))
    commands = len(self.coordinator.commands)
    # A signed stop by itself does not release the retry if custody cannot yet revoke the abandoned revision.
    report(self.state, operation, 'deploy', 'stopped')
    deploy = '7|' + operation['operation_id'] + ':deploy'
    self.state.fail_write = lambda namespace, field: 'before' if field == deploy + '|revoked' else None
    self.coordinator._reconcile_coordinator_operations()
    self.assertEqual(self.operation()['recovery'], 'blocked')
    request = {'job_id': 7, 'request_id': 'retry', 'expected_revision': 0}
    with self.assertRaisesRegex(ValueError, 'unconfirmed cleanup'):
      self.coordinator._find_request_operation(request, 'owner', 'create')
    # A valid signature for the wrong revision cannot prove this attempt stopped.
    receipt = self.state.public['DEEPLOY_NODE_OPERATIONS', 'A|deploy']
    exact = copy.deepcopy(receipt)
    receipt['revision'] += 1
    Engine('A').sign(receipt)
    self.state.fail_write = None
    self.state.now += 10
    self.coordinator._reconcile_coordinator_operations()
    self.assertTrue(self.state.secrets['DAUTH_JOB_SECRET_REVISIONS', deploy]['revoked'])
    self.assertEqual(self.operation()['recovery'], 'blocked')
    # A fresh matching aggregate with an individually running instance also leaves the retry locked.
    partial = copy.deepcopy(exact)
    partial['instances'][0]['status'] = 'stopping'
    Engine('A').sign(partial)
    self.state.public['DEEPLOY_NODE_OPERATIONS', 'A|deploy'] = partial
    self.state.now += 60
    self.coordinator._reconcile_coordinator_operations()
    self.assertEqual(self.operation()['recovery'], 'blocked')
    # Matching signed evidence completes cleanup without changing the terminal outcome, or sending any command.
    self.state.now += 60
    report(self.state, operation, 'deploy', 'stopped')
    self.coordinator._reconcile_coordinator_operations()
    ended = self.operation()
    self.assertEqual((ended['phase'], ended['outcome'], ended['recovery']), ('completed', 'failed', 'completed'))
    self.assertEqual(ended['error']['code'], 'BLOCKED_OPERATION_ENDED')
    self.assertEqual(ended['unconfirmed_nodes'], ['A'])
    self.assertEqual(len(self.coordinator.commands), commands)
    self.assertIsNone(self.coordinator._find_request_operation(request, 'owner', 'create'))

    # Reuse the paid job with a fresh request and prove its new revision completes normally.
    accepted = self.coordinator._admit_prepared_deployment(
      request=request, auth_result={'escrow_owner': 'owner'}, app_id='app', configs={'A': pipeline('retry-token')},
      prior_pipeline=None, is_create=True,
    )
    self.assertEqual(accepted['status_code'], 202)
    retry = self.coordinator._operation_records()[accepted['operation_id']]
    self.assertNotEqual(retry['operation_id'], operation['operation_id'])
    self.finalize(retry)
    self.assertEqual((retry['job_id'], retry['outcome']), (operation['job_id'], 'succeeded'))

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

  def test_first_successful_edit_publishes_protected_bytes_and_owner_notice(self):
    """Keep historical ciphertext readable but publish an oracle-only copy on first edit.

    Returns
    -------
    None

    Examples
    --------
    >>> LifecycleDauthCustodyTests("test_first_successful_edit_publishes_protected_bytes_and_owner_notice").run()
    """
    # Give the coordinator and custodian the same synthetic ciphertext transport.
    with TemporaryDirectory() as folder:
      # Run both writers and readers through the real SDK encryption code.
      sdk, blobs = ciphertext_transport(folder)
      # Replace the plaintext fixture store at both sides of custody.
      self.state.blobs = self.coordinator.r1fs = self.dauth.r1fs = sdk
      # The old copy and its selected credentials were stored before this switch.
      prior, old_cid = self.legacy()
      # A reader with only the default key can still read the old bytes.
      self.assertEqual(sdk.get_json(old_cid, pin=False, show_logs=False), prior)
      # Activate the new default against a synthetic locally provisioned secret.
      secret = "synthetic-shared-oracle-passphrase-only"
      with patch.object(BaseBlockEngine, "oracle_secret", return_value=secret), \
           patch("extensions.business.deeploy.r1fs_documents.ORACLE_R1FS_WRITES", True):
        # Admission publishes the new operation plan without claiming the canonical rewrite happened.
        self.admit(prior)
        # The status snapshot before readiness carries no credential notice.
        operation = self.operation()
        self.assertNotIn("credential_rotation_required", operation)
        # The custodian will read the plan with the local key, while a default reader cannot.
        self.assertIsNone(sdk.get_json(operation["plan_cid"], pin=False, show_logs=False))
        # Process the signed worker confirmations and commit the protected pointer through dAuth.
        self.finalize(operation)
        # The successful completion is bound to the replacement ciphertext, not the old pointer.
        current = self.state.public["DEEPLOY_DEPLOYED_JOBS", "7"]
        # This stable signed marker supports notice recovery after an interrupted finalization.
        self.assertEqual(current["r1fs_encryption"], "oracle_rewrote_legacy")
        # The user is notified only after custody confirmed the rewrite.
        self.assertIs(operation["credential_rotation_required"], True)
        # The replacement and its plan each use a different random 96-bit nonce.
        ids = (old_cid, operation["plan_cid"], current["pipeline_cid"])
        # Use exact captured ciphertext headers to exclude fixed or reused nonces.
        self.assertEqual(len({blobs[cid][:12] for cid in ids}), 3)
        # A default reader cannot decrypt the new canonical copy.
        self.assertIsNone(sdk.get_json(current["pipeline_cid"], pin=False, show_logs=False))
        # A reader with the correct key can decrypt it using the unchanged public file format.
        protected = sdk.get_json(current["pipeline_cid"], secret=secret, pin=False, show_logs=False)
        # The protected copy contains the new deployment revision.
        self.assertEqual(protected["DEEPLOY_SPECS"]["revision"], 1)
        # Edit the protected revision. A new upload is required but no legacy migration remains.
        self.coordinator._admit_prepared_deployment(
          request={"job_id": 7, "request_id": "second-request", "expected_revision": 1},
          auth_result={"escrow_owner": "owner"}, app_id="app", configs={"A": pipeline("new-synthetic-value")},
          prior_pipeline=protected, is_create=False,
        )
        # Identify the new operation by request ID so older completion snapshots can remain visible.
        second = next(record for record in self.coordinator._operation_records().values()
                      if record["request_id"] == "second-request")
        # Drive it through real custody again.
        self.finalize(second)
        # The next signed pointer remains protected without a repeated migration notice.
        self.assertEqual(self.state.public["DEEPLOY_DEPLOYED_JOBS", "7"]["r1fs_encryption"], "oracle")
        self.assertNotIn("credential_rotation_required", second)
        # Whole-job delete uses the third protected writer, for the plan holding the previous configuration.
        deletion = self.coordinator._admit_delete_operation(
          {"job_id": 7, "request_id": "delete", "expected_revision": 2}, {"escrow_owner": "owner"},
        )
        # Read its immutable plan reference from the signed operation.
        delete_cid = self.coordinator._operation_records()[deletion["operation_id"]]["plan_cid"]
        # The default passphrase cannot open the delete plan either.
        self.assertIsNone(sdk.get_json(delete_cid, pin=False, show_logs=False))
        # The oracle can restore the exact previous placement it needs for retirement.
        delete_plan = sdk.get_json(delete_cid, secret=secret, pin=False, show_logs=False)
        # The signed plan keeps the prior revision intact.
        self.assertEqual(delete_plan["previous_configs"]["A"]["DEEPLOY_SPECS"]["revision"], 2)
        # All three writer paths used independent nonces across the captured uploads.
        self.assertEqual(len({contents[:12] for contents in blobs.values()}), len(blobs))
      # The old record remains readable if it was previously retained elsewhere.
      self.assertEqual(sdk.get_json(old_cid, pin=False, show_logs=False), prior)

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

  def test_worker_waits_after_dauth_refuses_a_cleanup_and_the_sdk_names_the_server(self):
    # Worker passes against a signed dAuth refusal: the refused cleanup waits 10 s instead of calling dAuth every 2 s.
    previous, cid = self.legacy()
    self.state.fail_write = lambda namespace, key: 'before' if namespace == 'DAUTH_JOB_SECRET_REVISIONS' and key.endswith(':deploy') else None
    with self.assertRaises(RuntimeError):
      self.admit(previous)
    self.state.fail_write = None
    self.coordinator = Coordinator(self.state)
    # Wraps the test engine's own P, so the SDK's refusal line also goes through its real signature.
    self.coordinator.engine.P = Mock(wraps=self.coordinator.engine.P)
    lines = []
    self.coordinator.P = lambda message, color=None, **kwargs: lines.append((message, color))
    self.state.now = self.operation()['preparation_deadline']
    serve = self.dauth.process_dauth_reconcile_secrets_request
    self.dauth.process_dauth_reconcile_secrets_request = Mock(side_effect=RuntimeError('custody store unavailable'))
    calls = self.http.call_count
    for _ in range(2):
      self.coordinator._reconcile_coordinator_operations()
      self.state.now += 2
    # Expired at its deadline, its cleanup was refused once; the pass 2 s later did not call dAuth again.
    self.assertEqual(self.http.call_count, calls + 1)
    self.coordinator.engine.P.assert_called_once_with('dAuth server dauth refused secret reconciliation (revoke).', color='r')
    red = [message for message, color in lines if color == 'r']
    self.assertEqual(len(red), 1)
    self.assertTrue(red[0].endswith('(custody failure 1, next try in 10 s)'))
    self.dauth.process_dauth_reconcile_secrets_request = serve
    self.state.now += 6
    self.coordinator._reconcile_coordinator_operations()
    # 10 s after the refusal dAuth is called again, cleans up, and the wait ends.
    self.assertEqual(self.http.call_count, calls + 2)
    self.assertEqual((self.operation()['phase'], self.operation()['outcome']), ('completed', 'failed'))
    self.assertEqual(self.coordinator._custody_retry, {})
    self.assertEqual(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7'], cid)

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

  def test_node_relink_moves_job_and_per_node_secret_without_the_old_node(self):
    config = pipeline()
    instance = config['PLUGINS'][0]['INSTANCES'][0]
    instance.update(CHAINSTORE_PEERS=['A'], BUILD_AND_RUN_COMMANDS=['A', 'serve'],
                    SECRET_PATHS=[['PER_NODE_CONFIG', 'byNode', 'A', 'ENV', field] for field in ('A', 'NODE_KEY')],
                    PER_NODE_CONFIG={'byNode': {'A': {'ENV': {'A': 'A', 'NODE_KEY': 'node-secret'}}}})
    instance['APP_SETTINGS'] = {'A': {'CHAINSTORE_PEERS': ['A']}}  # Customer-owned keys can match node addresses.
    self.coordinator._admit_prepared_deployment(
      request={'job_id': 7, 'request_id': 'request', 'expected_revision': 0},
      auth_result={'escrow_owner': 'owner'}, app_id='app', configs={'A': config},
      prior_pipeline=None, is_create=True,
    )
    self.finalize(self.operation())
    self.coordinator.known = {}  # New hardware with no observed workload cannot account for the old one.
    writes = len(self.state.writes)
    with self.assertRaisesRegex(ValueError, 'previous target'):
      self.coordinator._admit_node_relink_operation(7, 'A', 'N')
    self.assertEqual(len(self.state.writes), writes)
    self.coordinator.known = {'N': [self.active()]}  # Continue the existing custody test with an observed worker.
    accepted = self.coordinator._admit_node_relink_operation(7, 'A', 'N')
    operation = self.coordinator._operation_records()[accepted['operation_id']]
    self.assertEqual((operation['nodes'], operation['previous_nodes']), (['N'], ['N']))
    self.assertNotIn('node-secret', str(self.state.public) + str(self.state.blobs.data))
    self.finalize(operation)
    self.assertEqual(operation['outcome'], 'succeeded')
    active = self.active()['PLUGINS'][0]['INSTANCES'][0]
    self.assertEqual(self.active()['DEEPLOY_SPECS']['current_target_nodes'], ['N'])
    self.assertEqual((active['CHAINSTORE_PEERS'], list(active['PER_NODE_CONFIG']['byNode'])), (['N'], ['N']))
    self.assertEqual(active['BUILD_AND_RUN_COMMANDS'], ['A', 'serve'])
    self.assertEqual(active['APP_SETTINGS'], {'A': {'CHAINSTORE_PEERS': ['A']}})
    self.assertIn(['PER_NODE_CONFIG', 'byNode', 'N', 'ENV', 'A'], active['SECRET_PATHS'])
    self.assertEqual(active['PER_NODE_CONFIG']['byNode']['N']['ENV']['A'], dAuth.DAUTH_SECRET_PLACEHOLDER)
    reference = operation['operation_id'] + ':deploy'
    requested = self.dauth._load_revision_runner_secret_bundle('7', reference, 'N')
    self.assertEqual(self.token(requested), 'fresh-token')
    node_env = requested['job_secrets']['PLUGINS'][0]['INSTANCES'][0]['PER_NODE_CONFIG']['byNode']['N']['ENV']
    self.assertEqual(node_env['A'], 'A')  # The recipient changed; the secret name and plaintext stayed intact.
    self.assertEqual(node_env['NODE_KEY'], 'node-secret')
    with self.assertRaises(ValueError):
      self.dauth._load_revision_runner_secret_bundle('7', reference, 'A')

  def test_update_does_not_need_the_record_of_whoever_deployed_the_running_revision(self):
    self.admit()
    self.finalize(self.operation())
    # The deploying oracle was revoked: its operation records are no longer trusted.
    for key in [key for key in self.state.public if key[0] == 'DEEPLOY_OPERATIONS']:
      del self.state.public[key]
    self.coordinator._deployment_plans.clear()
    accepted = self.coordinator._admit_owner_transfer_operation(7, 'owner', 'new-owner', 'tx|0')
    operation = self.coordinator._operation_records()[accepted['operation_id']]
    self.finalize(operation)
    self.assertEqual(operation['outcome'], 'succeeded')
    self.assertEqual(self.active()['OWNER'], 'new-owner')
    self.assertEqual(self.token(self.state.secrets['DAUTH_JOB_SECRETS', '7']), 'fresh-token')

  def two_node_job(self):
    configs = {}
    for node in ('A', 'B'):
      configs[node] = pipeline()
      configs[node]['DEEPLOY_SPECS']['current_target_nodes'] = ['A', 'B']
    self.coordinator._admit_prepared_deployment(
      request={'job_id': 7, 'request_id': 'request', 'expected_revision': 0},
      auth_result={'escrow_owner': 'owner'}, app_id='app', configs=configs,
      prior_pipeline=None, is_create=True,
    )
    self.finalize(self.operation())

  def move(self, nodes, request_id='move'):
    configs = {}
    for node in nodes:
      configs[node] = pipeline()
      configs[node]['DEEPLOY_SPECS']['current_target_nodes'] = list(nodes)
    accepted = self.coordinator._admit_prepared_deployment(
      request={'job_id': 7, 'request_id': request_id, 'expected_revision': self.active()['DEEPLOY_SPECS']['revision']},
      auth_result={'escrow_owner': 'owner'}, app_id='app', configs=configs,
      prior_pipeline=self.active(), is_create=False,
    )
    return self.coordinator._operation_records()[accepted['operation_id']]

  def test_nodes_keep_their_own_instance_ids_across_updates(self):
    configs = {}
    for node in ('A', 'B'):  # as after a scale-up: each node has its own instance
      configs[node] = pipeline()
      configs[node]['DEEPLOY_SPECS']['current_target_nodes'] = ['A', 'B']
      configs[node]['PLUGINS'][0]['INSTANCES'][0]['INSTANCE_ID'] = 'worker-' + node
    self.coordinator._admit_prepared_deployment(
      request={'job_id': 7, 'request_id': 'request', 'expected_revision': 0},
      auth_result={'escrow_owner': 'owner'}, app_id='app', configs=configs,
      prior_pipeline=None, is_create=True,
    )
    self.finalize(self.operation())
    self.assertEqual(self.state.public['DEEPLOY_DEPLOYED_JOBS', '7']['plan_cid'], self.operation()['plan_cid'])
    for owner, transfer in (('new-owner', 'tx|1'), ('third-owner', 'tx|2')):
      accepted = self.coordinator._admit_owner_transfer_operation(7, self.active()['OWNER'], owner, transfer)
      operation = self.coordinator._operation_records()[accepted['operation_id']]
      plan = self.coordinator._load_operation_plan(operation)
      for key in ('configs', 'previous_configs'):
        self.assertEqual({node: config['PLUGINS'][0]['INSTANCES'][0]['INSTANCE_ID'] for node, config in plan[key].items()},
                         {'A': 'worker-A', 'B': 'worker-B'})
      self.finalize(operation)
      self.assertEqual(operation['outcome'], 'succeeded')

  def test_update_waits_for_a_missing_departing_node_before_stopping_any_node(self):
    self.two_node_job()
    report_a = self.coordinator.known.pop('A')
    writes, commands = len(self.state.writes), len(self.coordinator.commands)
    with self.assertRaisesRegex(ValueError, 'previous target'):
      self.move(['B', 'C'])
    self.assertEqual((len(self.state.writes), len(self.coordinator.commands)), (writes, commands))
    # The same update can proceed with complete retirement and rollback once A reports again.
    self.coordinator.known['A'] = report_a
    operation = self.move(['B', 'C'])
    self.assertEqual(operation['previous_nodes'], ['A', 'B'])
    self.finalize(operation)
    self.assertEqual(operation['outcome'], 'succeeded')
    self.assertEqual(sorted(self.active()['DEEPLOY_SPECS']['current_target_nodes']), ['B', 'C'])
    with self.assertRaises(ValueError):
      self.dauth._load_revision_runner_secret_bundle('7', self.active()['DEEPLOY_SPECS']['secret_revision'], 'A')

  def test_update_baseline_is_the_stored_job_not_what_nodes_report(self):
    self.two_node_job()
    forged = copy.deepcopy(self.coordinator.known['A'][0])
    forged['PLUGINS'][0]['INSTANCES'][0]['IMAGE'] = 'forged-image'
    self.coordinator.known['A'] = [forged]
    operation = self.move(['A', 'C'])
    restore = self.coordinator._load_operation_plan(operation)['previous_configs']
    self.assertEqual(set(restore), {'A', 'B'})
    self.assertNotIn('forged-image', str(restore))

  def test_move_off_only_unobserved_nodes_preserves_the_running_revision(self):
    self.admit()
    self.finalize(self.operation())
    before = self.active()
    self.coordinator.known = {}  # the job's only node is offline
    with self.assertRaisesRegex(ValueError, 'previous target'):
      self.move(['C'])
    self.assertEqual(self.active(), before)
    self.dauth._load_revision_runner_secret_bundle('7', before['DEEPLOY_SPECS']['secret_revision'], 'A')

  def test_unversioned_node_relink_keeps_secrets(self):
    previous, _ = self.legacy()
    self.coordinator.known = {'N': [previous]}
    accepted = self.coordinator._admit_node_relink_operation(7, 'A', 'N')
    operation = self.coordinator._operation_records()[accepted['operation_id']]
    self.finalize(operation)
    self.assertEqual(operation['outcome'], 'succeeded')
    self.assertEqual(self.active()['DEEPLOY_SPECS']['current_target_nodes'], ['N'])
    requested = self.dauth._load_revision_runner_secret_bundle('7', operation['operation_id'] + ':deploy', 'N')
    self.assertEqual(self.token(requested), 'old-token')

  def test_partial_relink_waits_for_the_other_previous_worker(self):
    # Job 31's automatic relink planned one successor and retained the other old address.
    previous = pipeline()
    previous['DEEPLOY_SPECS']['current_target_nodes'] = ['A', 'B']
    pointer_key = ('DEEPLOY_DEPLOYED_JOBS', '7')
    cid = self.state.public[pointer_key] = self.state.blobs.add_json(previous)
    self.coordinator.known = {'N': [previous], 'M': [previous]}  # Both successors report; retained B is unaccounted for.
    with self.assertRaisesRegex(ValueError, 'previous target'):
      self.coordinator._admit_node_relink_operation(7, 'A', 'N')
    self.assertEqual(self.state.public, {pointer_key: cid})
    self.assertEqual(self.state.writes, [])
    self.assertEqual(self.coordinator.commands, [])
    self.http.assert_not_called()

  def test_relink_to_empty_replacement_rejects_before_any_stop_or_custody_write(self):
    previous, cid = self.legacy()
    self.coordinator.known = {'A': [previous], 'N': []}  # The new hardware has no previous workload.
    with self.assertRaisesRegex(ValueError, 'current address'):
      self.coordinator._admit_node_relink_operation(7, 'A', 'N')
    self.assertEqual(self.coordinator._get_pipeline_from_cstore('7'), cid)
    self.assertEqual(self.coordinator.commands, [])
    self.http.assert_not_called()

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
                   coordinator='oracle', deleted=False, pipeline_cid='published-folder',
                   plan_cid=operation['plan_cid'])
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
                   coordinator='oracle', deleted=False, pipeline_cid='wrong-cid',
                   plan_cid=operation['plan_cid'])
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

  def prepare_with_failed_write(self, word, attempt='deploy'):
    """
    Admit a deployment one of whose secret records' write fails as ``word``, on a fresh fixture.

    The target copy is tried with a create; the restoration copy, which only an update has, with an update of a
    job stored before versioned secrets (see ``legacy``).

    Parameters
    ----------
    word : str
      How the write of that copy ends: 'before' or 'after' (see ``Node.chainstore_hset``), or one of the
      chain store's outcome words, such as 'refused_too_large'.
    attempt : str, optional
      The copy whose write fails: 'deploy' (the default), the target copy, or 'restore', the restoration copy.

    Returns
    -------
    list of Exception
      What the dAuth node raised while it served the preparation: one error.

    Examples
    --------
    >>> [type(error).__name__ for error in self.prepare_with_failed_write('after')]
    ['RuntimeError']
    >>> [type(error).__name__ for error in self.prepare_with_failed_write('refused_too_large', 'restore')]
    ['DeploymentSecretRecordTooLarge']
    """
    # A fresh coordinator, dAuth node and stores: the sub-tests of one test must not see each other's operation.
    self.setUp()
    # The job's stored revision for an update, which has a restoration copy; none for a create.
    previous = self.legacy()[0] if attempt == 'restore' else None
    # Only that copy of the secret record fails; every other write is stored and confirmed.
    self.state.fail_write = lambda namespace, key: (
      # The word for the write of the copy named by ``attempt``; None, a stored write, for every other.
      word if namespace == 'DAUTH_JOB_SECRET_REVISIONS' and key.endswith(':' + attempt) else None)
    # The dAuth node's own handler of a custody request, wrapped below.
    serve = self.dauth.process_dauth_reconcile_secrets_request
    # What it raised, in order.
    raised = []

    def recording(body):
      """
      Serve a custody request as the dAuth node does and keep the error it raises.

      Parameters
      ----------
      body : dict
        The signed request body.

      Returns
      -------
      dict
        The dAuth node's result, when it does not raise.

      Examples
      --------
      >>> recording(body)["status"]
      'success'
      """
      try:
        # The real handler.
        return serve(body)
      except Exception as error:
        # Kept for the test.
        raised.append(error)
        # Raised on: the fixture's HTTP side answers every refusal with one fixed text and no reason code.
        raise

    # The fixture's HTTP side looks the handler up on the node at each request.
    self.dauth.process_dauth_reconcile_secrets_request = recording
    # So the coordinator gets the SDK's error of a refusal without a reason, whatever the dAuth node raised;
    # the real endpoint, which names the size refusal, is under test in test_secret_record_size_refusal.py.
    with self.assertRaises(RuntimeError):
      # A create (or an update) of job 7 on node A with one fresh secret value, 'fresh-token'.
      self.admit(previous)
    # The dAuth node's errors.
    return raised

  def test_a_secret_record_refused_for_its_size_ends_in_an_error_that_names_the_cause_and_no_value(self):
    """When the chain store refuses a deployment's secret record for its size, the dAuth node's preparation ends in
    an error of a type of its own (a ValueError) that carries no text, so no job id, node, key or secret value;
    before, it ended in the same "pending" error as a write that was not confirmed."""
    # The chain store's outcome word for a record over its size cap.
    raised = self.prepare_with_failed_write('refused_too_large')
    # One error of the type the dAuth endpoint names to the caller, without a text: the client words it.
    self.assertEqual([(type(error), str(error)) for error in raised], [(DeploymentSecretRecordTooLarge, '')])
    # Final for the request, like every ValueError of the custody code.
    self.assertIsInstance(raised[0], ValueError)
    # The operation the coordinator recorded.
    operation = self.operation()
    # The refused record is not held, and the secret value is in no public store.
    self.assertNotIn(('DAUTH_JOB_SECRET_REVISIONS', '7|' + operation['operation_id'] + ':deploy'), self.state.secrets)
    # Nor in the plan or the operation record.
    self.assertNotIn('fresh-token', str(self.state.public) + str(self.state.blobs.data))

  def test_a_restoration_copy_refused_for_its_size_ends_in_the_same_error(self):
    """The copy of the job's current revision that a failed update restores, refused for its size, ends in the same
    error type as the target copy, and nothing of the update is stored (that copy is written first); refused for
    another reason, it keeps the "pending" error."""
    # An update whose restoration copy the chain store refuses for its size.
    raised = self.prepare_with_failed_write('refused_too_large', 'restore')
    # The size refusal's own type, which the dAuth endpoint names to the caller.
    self.assertEqual([type(error) for error in raised], [DeploymentSecretRecordTooLarge])
    # No secret record of the update is held: the target copy was not written either.
    self.assertEqual([key for namespace, key in self.state.secrets if namespace == 'DAUTH_JOB_SECRET_REVISIONS'], [])
    # The same copy refused for its depth: the retryable error of before.
    self.assertEqual([(type(error), str(error)) for error in self.prepare_with_failed_write('refused_too_deep', 'restore')],
                     [(RuntimeError, 'Deployment secret preparation is pending.')])

  def test_every_other_failed_write_of_a_secret_record_keeps_the_pending_error(self):
    """A secret record's write that fails for any reason but its size still ends in the retryable error
    "Deployment secret preparation is pending.": lost before or after the store took it, refused by another rule
    of the chain store, not confirmed, or a call that raised."""
    # 'before' and 'after' are the fixture's two failures; the others are outcome words of the chain store.
    for word in ('before', 'after', 'unconfirmed', 'refused_by_peers', 'refused_not_member', 'refused_secret_rule',
                 'refused_unencodable', 'refused_too_deep', 'refused_no_peers', 'error'):
      # One sub-test each, on its own fixture.
      with self.subTest(failure=word):
        # What the dAuth node raised.
        raised = self.prepare_with_failed_write(word)
        # Today's type and text, unchanged.
        self.assertEqual([(type(error), str(error)) for error in raised],
                         [(RuntimeError, 'Deployment secret preparation is pending.')])
