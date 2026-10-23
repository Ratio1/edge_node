"""Offline fault-path proof for the receiving-oracle deployment coordinator."""
import copy
import hashlib
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock
from ratio1.const.base import BCct

from extensions.business.deeploy.deployment_operations import (
  _DeploymentOperationsMixin, OPERATIONS_HKEY, NODE_OPERATIONS_HKEY,
  SECRET_REVISIONS_HKEY, request_digest, report_is_ready,
)
from extensions.business.deeploy.tests.support import LifecycleCustodyDouble


CONFIG = {"NAME": "app", "TYPE": "Void", "DEEPLOY_SPECS": {"revision": 1, "secret_revision": "op:deploy"},
          "PLUGINS": [{"SIGNATURE": "RUNNER", "INSTANCES": [{"INSTANCE_ID": "worker"}]}]}


class Coordinator(_DeploymentOperationsMixin):
  def __init__(self, address="oracle"):
    self.now = 100
    self.bc = SimpleNamespace(address=address, get_oracles=lambda **kw: (["oracle", "other"], []),
                              get_dauth_oracles=lambda: (["oracle", "other"], []),
                              verify=lambda record, return_full_info=True: SimpleNamespace(valid=record.get("EE_SIGN") == "valid"))
    self.bc.sign = lambda record, **kw: record.update(EE_SIGN="valid", EE_SENDER=address)
    self.evm_network = "test"
    self.storage = {}
    self.custody = LifecycleCustodyDouble(self)
    self.bc.reconcile_dauth_job_secrets = self.custody
    self.replicate = True
    self.commands = []
    self._deployment_operations_stop = threading.Event()
    self._deployment_operations_event = threading.Event()
    self._deployment_plans = {}
    self._deployment_plan_cache_lock = threading.Lock()
    self._deployment_preparations = {}
    self.cfg_deployment_readiness_timeout = 60
    self._get_response = lambda result: result
    self.P = lambda *args, **kw: None
    self.r1fs = SimpleNamespace(get_json=lambda cid, **kw: copy.deepcopy(self.plan))
    self.plan = {"configs": {node: copy.deepcopy(CONFIG) for node in ("A", "B", "C")}, "previous_configs": {}}
    self._commit_operation_revision = Mock()
    self.chainstore_hsync = Mock(side_effect=AssertionError("Deployment reads must use local replicas"))

  def time(self):
    return self.now

  def chainstore_hset(self, namespace, key, value, **kw):
    self.storage[namespace, key] = copy.deepcopy(value)
    return self.replicate

  def chainstore_hget(self, namespace, key):
    if namespace in (SECRET_REVISIONS_HKEY, 'DAUTH_JOB_SECRETS'):
      raise AssertionError('Coordinator must use the dAuth RPC for protected storage.')
    return copy.deepcopy(self.storage.get((namespace, key)))

  def chainstore_hgetall(self, namespace):
    return {key: copy.deepcopy(value) for (ns, key), value in self.storage.items() if ns == namespace}

  def cmdapi_start_pipeline(self, config, node_address):
    self.commands.append((node_address, copy.deepcopy(config)))

  def operation(self, kind="create"):
    oid = hashlib.sha256(b"oracle").hexdigest()[:16] + "-test"
    previous = ["A", "B"] if kind == "update" else []
    if previous:
      self.plan["previous_configs"] = {node: copy.deepcopy(CONFIG) for node in previous}
      for config in self.plan["previous_configs"].values():
        config["DEEPLOY_SPECS"].update(revision=0, secret_revision="op:restore")
    return dict(operation_id=oid, coordinator="oracle", network="test", sequence=0,
                request_id="request", request_hash="hash", owner="owner", job_id=1,
                app_id="app", kind=kind, target_revision=1, previous_revision=0 if previous else None,
                previous_operation_id=None, previous_secret_revision=None,
                nodes=["A", "B", "C"], previous_nodes=previous, plan_cid="plan",
                phase="accepted", outcome=None, recovery=None, deadline=160,
                created_at=100, updated_at=100, sent_at={}, events=[], error=None,
                instances={n: [("RUNNER", "worker")] for n in ["A", "B", "C"]},
                previous_instances={n: [("RUNNER", "worker")] for n in previous})

  def report(self, operation, node, status, attempt="deploy", sequence=1):
    report = dict(operation_id=operation["operation_id"], coordinator="oracle", app_id="app",
                  node_addr=node, attempt=attempt,
                  revision=1 if attempt == "deploy" else 0,
                  status=status, sequence=sequence, updated_at=self.now,
                  instances=[dict(signature="RUNNER", instance_id="worker", status=status)],
                  EE_SIGN="valid", EE_SENDER=node)
    self.storage[NODE_OPERATIONS_HKEY, node + attempt] = report
    return report


class DeploymentStatusTests(unittest.TestCase):
  def prepare(self):
    plugin = Coordinator()
    plugin.deeploy_verify_and_get_inputs = Mock(return_value=("wallet", {}))
    plugin.deeploy_get_auth_result = lambda inputs: {"escrow_owner": "owner"}
    plugin.get_job_pipeline_from_cstore = lambda *args, **kw: {"DEEPLOY_SPECS": {"job_id": 1}}
    plugin.bc.get_job_details = Mock(return_value={"escrowOwner": "owner"})
    return plugin

  def test_revision_zero_lookup_checks_owner_without_submission_resource_validation(self):
    plugin = self.prepare()
    plugin.deeploy_check_payment_and_job_owner = Mock(side_effect=AssertionError("submission validator is inappropriate for read auth"))
    result = plugin._deployment_status({"job_id": 1, "nonce": "nonce", "EE_ETH_SIGN": "sig", "EE_ETH_SENDER": "wallet"})
    self.assertEqual((result["status"], result["revision"]), ("not_found", 0))
    envelope = plugin.deeploy_verify_and_get_inputs.call_args.args[0]
    self.assertEqual(set(envelope), {"nonce", "EE_ETH_SIGN", "EE_ETH_SENDER"})
    plugin.bc.get_job_details.return_value = {"escrowOwner": "different-owner"}
    self.assertEqual(plugin._deployment_status({"job_id": 1})["status"], "synchronizing")

  def test_other_oracle_polling_is_read_only(self):
    plugin = self.prepare()
    operation = plugin.operation()
    plugin._save_operation(operation)
    plugin.bc.address = "other"
    result = plugin._deployment_status({"operation_id": operation["operation_id"]})
    self.assertEqual(result["coordinator"], "oracle")
    self.assertEqual(result["sequence"], 1)
    self.assertEqual(len(result["nodes"]), 3)
    self.assertNotIn("settlement", result)
    self.assertEqual(plugin.commands, [])
    plugin.chainstore_hsync.assert_not_called()
    plugin.deeploy_get_auth_result = lambda inputs: {"escrow_owner": "someone-else"}
    self.assertEqual(plugin._deployment_status({"operation_id": operation["operation_id"]})["status"], "synchronizing")


class DeploymentOperationTests(unittest.TestCase):
  def test_worker_reconciles_local_operations_without_peer_repair(self):
    plugin = Coordinator()
    plugin._reconcile_coordinator_operations = Mock(side_effect=plugin._deployment_operations_stop.set)
    plugin._deployment_operations_event.set()
    plugin._deployment_operation_worker()
    plugin._reconcile_coordinator_operations.assert_called_once_with()
    plugin.chainstore_hsync.assert_not_called()

  def test_plan_cache_allows_overlapping_downloads_and_keeps_results_after_eviction(self):
    plugin = Coordinator()
    plugin._deployment_plans = {str(index): {"configs": {}} for index in range(32)}
    downloads = threading.Barrier(2)
    def get_json(cid, **kwargs):
      downloads.wait(timeout=5)
      return {"configs": {cid: {"NAME": cid}}}
    plugin.r1fs.get_json = get_json
    with ThreadPoolExecutor(max_workers=2) as executor:
      first = executor.submit(plugin._load_operation_plan, {"plan_cid": "first"})
      second = executor.submit(plugin._load_operation_plan, {"plan_cid": "second"})
      results = [first.result(timeout=5), second.result(timeout=5)]
    self.assertEqual(results, [{"configs": {cid: {"NAME": cid}}} for cid in ("first", "second")])
    self.assertEqual(len(plugin._deployment_plans), 32)
    results[0]["configs"].clear()
    self.assertEqual(plugin._load_operation_plan({"plan_cid": "first"}),
                     {"configs": {"first": {"NAME": "first"}}})

  def test_semantic_retry_ignores_nonce_but_not_payload(self):
    request = {"request_id": "same", "job_id": 1, "nonce": "old", "EE_ETH_SIGN": "sig"}
    self.assertEqual(request_digest(request), request_digest({**request, "nonce": "new", "EE_ETH_SIGN": "new"}))
    self.assertEqual(request_digest(request), request_digest({**request, BCct.SIGN_CANON_V: "v2"}))
    self.assertNotEqual(request_digest(request), request_digest({**request, "job_id": 2}))

  def test_readiness_requires_exact_instances_and_fresh_evidence(self):
    report = dict(status="ready", updated_at=100, instances=[dict(signature="RUNNER", instance_id="worker", status="ready")])
    self.assertTrue(report_is_ready(report, CONFIG, 110))
    self.assertFalse(report_is_ready(report, CONFIG, 131))
    self.assertFalse(report_is_ready({**report, "instances": []}, CONFIG, 110))
    self.assertFalse(report_is_ready({**report, "updated_at": 200}, CONFIG, 110))

  def test_no_dispatch_until_uncertain_snapshot_replicates(self):
    plugin = Coordinator()
    operation = plugin.operation()
    plugin.replicate = False
    with self.assertRaises(RuntimeError):
      plugin._save_operation(operation)
    recovered = next(iter(plugin._operation_records().values()))
    with self.assertRaises(RuntimeError):
      plugin._advance_deployment_operation(recovered)
    self.assertEqual(plugin.commands, [])
    plugin.replicate = True
    plugin._advance_deployment_operation(recovered)
    self.assertEqual(len(plugin.commands), 3)

  def test_no_other_oracle_execution_and_any_oracle_reads(self):
    first = Coordinator()
    operation = first.operation()
    first._save_operation(operation)
    other = Coordinator("other")
    other.storage = first.storage
    other._advance_deployment_operation(copy.deepcopy(operation))
    self.assertEqual(other.commands, [])
    self.assertIn(operation["operation_id"], other._operation_records())

  def test_untrusted_oracle_or_forged_coordinator_rejected(self):
    plugin = Coordinator()
    operation = plugin.operation()
    plugin._save_operation(operation)
    forged = {**operation, "coordinator": "other", "EE_SENDER": "other", "sequence": 999}
    plugin.storage[OPERATIONS_HKEY, "forged"] = forged
    self.assertEqual(plugin._operation_records()[operation["operation_id"]]["coordinator"], "oracle")

  def test_one_failed_node_stops_all_targets_and_waits_for_unreachable(self):
    plugin = Coordinator()
    operation = plugin.operation()
    plugin._save_operation(operation)
    plugin._advance_deployment_operation(operation)
    plugin.report(operation, "A", "ready")
    plugin.report(operation, "B", "ready")
    plugin.report(operation, "C", "failed")
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "stopping_failed_rollout")
    plugin._advance_deployment_operation(operation)
    self.assertEqual([config["DEEPLOY_OPERATION"]["action"] for _, config in plugin.commands[-3:]], ["stop"] * 3)
    plugin.report(operation, "A", "stopped", sequence=2)
    plugin.report(operation, "C", "stopped", sequence=2)
    plugin.now += 70
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["recovery"], "blocked")
    self.assertIsNone(operation["outcome"])
    self.assertFalse(any(key.endswith("|revoked") for namespace, key in plugin.storage))
    plugin.report(operation, "B", "stopped", sequence=2)
    plugin._advance_deployment_operation(operation)
    self.assertEqual((operation["outcome"], operation["recovery"]), ("failed", "completed"))
    self.assertIn((SECRET_REVISIONS_HKEY, "1|op:deploy|revoked"), plugin.storage)

  def test_deadline_does_not_claim_workload_absent(self):
    plugin = Coordinator()
    operation = plugin.operation()
    plugin._save_operation(operation)
    plugin.now = 200
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["error"]["code"], "READINESS_DEADLINE_EXCEEDED")
    self.assertIsNone(operation["outcome"])

  def test_update_retirement_and_restoration_are_both_barriers(self):
    plugin = Coordinator()
    operation = plugin.operation("update")
    plugin._save_operation(operation)
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "retiring_previous")
    self.assertTrue(all(config["DEEPLOY_OPERATION"]["action"] == "retire" for _, config in plugin.commands))
    for node in operation["previous_nodes"]:
      plugin.report(operation, node, "stopped", attempt="retire")
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "waiting_for_readiness")
    plugin.report(operation, "C", "failed")
    plugin._advance_deployment_operation(operation)
    for node in operation["nodes"]:
      plugin.report(operation, node, "stopped", sequence=2)
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "restoring_previous")
    plugin._advance_deployment_operation(operation)
    restores = [(node, config) for node, config in plugin.commands if config["DEEPLOY_OPERATION"]["attempt"] == "restore"]
    self.assertEqual([node for node, _ in restores], ["A", "B"])
    for node in operation["previous_nodes"]:
      plugin.report(operation, node, "ready", attempt="restore")
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "finalizing_recovery")
    plugin._advance_deployment_operation(operation)
    self.assertEqual((operation["phase"], operation["outcome"], operation["recovery"]), ("completed", "failed", "completed"))

  def test_snapshot_storage_bounded_per_operation(self):
    plugin = Coordinator()
    operation = plugin.operation()
    for index in range(30):
      plugin._save_operation(operation)
    self.assertEqual(len(plugin.chainstore_hgetall(OPERATIONS_HKEY)), 8)
    self.assertEqual(plugin._operation_records()[operation["operation_id"]]["sequence"], 30)

  def test_app_id_mutation_conflict(self):
    plugin = Coordinator()
    operation = plugin.operation()
    plugin._save_operation(operation)
    with self.assertRaises(ValueError):
      plugin._assert_no_active_deployment(app_id="app")


class RuntimeCompletionTests(unittest.TestCase):
  def test_completion_and_new_admission_need_no_transaction_apis(self):
    plugin = Coordinator()
    operation = plugin.operation()
    operation["phase"] = "finalizing"
    plugin._commit_operation_revision = lambda op, configs: _DeploymentOperationsMixin._commit_operation_revision(plugin, op, configs)
    plugin.commit_deployment_revision = Mock()
    plugin.storage[SECRET_REVISIONS_HKEY, "1|op:deploy"] = {"job_secrets": {}}
    plugin._save_operation(operation)
    plugin._reconcile_coordinator_operations()
    completed = plugin._operation_records()[operation["operation_id"]]
    self.assertEqual((completed["phase"], completed["outcome"]), ("completed", "succeeded"))
    self.assertNotIn("settlement", completed)
    plugin.commit_deployment_revision.assert_called_once()
    plugin._assert_no_active_deployment(job_id=1, app_id="app")
    for kind in ("update", "delete", "create"):
      self.assertIsNone(plugin._find_request_operation(
        {"job_id": 1, "request_id": "next"}, "owner", kind))
    # Repeated background passes do not require a transaction API or modify
    # completed runtime state. The normal ChainDistMonitor runs separately.
    plugin._reconcile_coordinator_operations()
    self.assertEqual(plugin._operation_records()[operation["operation_id"]], completed)
    self.assertEqual(plugin.commands, [])

  def test_failed_recovery_completion_also_releases_mutations(self):
    plugin = Coordinator()
    operation = plugin.operation("update")
    operation.update(phase="completed", outcome="failed", recovery="completed")
    plugin._save_operation(operation)
    plugin._reconcile_coordinator_operations()
    plugin._assert_no_active_deployment(job_id=1, app_id="app")
    self.assertIsNone(plugin._find_request_operation(
      {"job_id": 1, "request_id": "retry-update"}, "owner", "update"))


if __name__ == "__main__":
  unittest.main()
