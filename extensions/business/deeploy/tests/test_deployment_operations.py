"""Offline fault-path proof for the receiving-oracle deployment coordinator."""
import copy
import hashlib
import threading
import unittest
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock
from ratio1.const.base import BCct

from extensions.business.deeploy.deployment_operations import (
  _DeploymentOperationsMixin, OPERATIONS_HKEY, NODE_OPERATIONS_HKEY,
  SECRET_REVISIONS_HKEY, DeploymentCustodyError, request_digest, report_is_ready,
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
    self._operations_confirmed = {}
    self._operations_sent_at = {}
    self._verified_operation_records = OrderedDict()  # as _init_deployment_operations creates it
    self._verified_operation_records_lock = threading.Lock()
    self._custody_retry = {}  # as _init_deployment_operations creates it
    self.cfg_deployment_readiness_timeout = 60
    self._get_response = lambda result: result
    self.P = lambda *args, **kw: None
    self.r1fs = SimpleNamespace(get_json=lambda cid, **kw: copy.deepcopy(self.plan))
    self.plan = {"configs": {node: copy.deepcopy(CONFIG) for node in ("A", "B", "C")}, "previous_configs": {}}
    self._commit_operation_revision = Mock()
    self.chainstore_hsync = Mock(side_effect=AssertionError("Deployment reads must use local replicas"))
    self.offline = set()

  def _netmon_node_is_online_for_control(self, node):
    return node not in self.offline

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

  def test_status_uses_netmon_liveness_instead_of_report_age(self):
    plugin = self.prepare()
    operation = plugin.operation()
    operation["phase"] = "waiting_for_readiness"
    plugin._save_operation(operation)
    for node in operation["nodes"]:
      plugin.report(operation, node, "ready")
    plugin.now += 3600
    plugin.offline = {"B"}
    result = plugin._deployment_status({"operation_id": operation["operation_id"]})
    self.assertEqual(result["ready_nodes"], 2)
    self.assertEqual({node["node_id"]: node["stale"] for node in result["nodes"]}, {"A": False, "B": True, "C": False})
    # An old snapshot is stale only while its coordinator is away.
    self.assertFalse(result["observation_stale"])
    plugin.offline.add("oracle")
    self.assertTrue(plugin._deployment_status({"operation_id": operation["operation_id"]})["observation_stale"])

  def test_preparation_failure_does_not_project_a_restoration(self):
    plugin = self.prepare()
    operation = plugin.operation(kind="update")
    operation.update(phase="cleaning_up_preparation", outcome="failed", recovery="in_progress",
                     error=dict(code="ADMISSION_PREPARATION_FAILED", message="Cleanup pending.", retryable=False))
    plugin._save_operation(operation)
    result = plugin._deployment_status({"operation_id": operation["operation_id"]})
    self.assertEqual((result["phase"], result["outcome"], result["recovery"]),
                     ("cleaning_up_preparation", "failed", "in_progress"))
    self.assertEqual(result["target_nodes"], len(operation["nodes"]))
    self.assertEqual(result["revision"], operation["previous_revision"])
    self.assertEqual(plugin.commands, [])


class DeploymentOperationTests(unittest.TestCase):
  def test_an_operation_that_cannot_advance_is_logged_with_what_failed_and_not_with_the_error_text(self):
    plugin = Coordinator()
    lines = []
    plugin.P = lambda message, color=None, **kw: lines.append((message, color))
    stuck, fine = plugin.operation(), plugin.operation()
    fine["operation_id"], fine["job_id"], fine["app_id"] = stuck["operation_id"].replace("-test", "-fine"), 2, "app2"
    for operation in (stuck, fine):
      plugin._save_operation(operation)
    advanced = []

    def custody_call(operation):
      raise RuntimeError("secret-value-in-error")

    def advance(operation):
      if operation["operation_id"] == stuck["operation_id"]:
        custody_call(operation)
      advanced.append(operation["operation_id"])

    plugin._advance_deployment_operation = advance
    plugin._reconcile_coordinator_operations()
    self.assertEqual(advanced, [fine["operation_id"]])  # the pass goes on with the next operation
    red = [message for message, color in lines if color == "r"]
    self.assertEqual(len(red), 1)
    for part in (stuck["operation_id"], "job {}".format(stuck["job_id"]), "phase {}".format(stuck["phase"]),
                 "RuntimeError in _reconcile_coordinator_operations > advance > custody_call"):
      self.assertIn(part, red[0])
    self.assertNotIn("secret-value-in-error", str(lines))

  def test_a_pass_that_fails_as_a_whole_is_logged_with_what_failed(self):
    plugin = Coordinator()
    lines = []
    plugin.P = lambda message, color=None, **kw: lines.append((message, color))

    def failing_pass():
      plugin._deployment_operations_stop.set()
      raise KeyError("secret-value-in-error")

    plugin._reconcile_coordinator_operations = failing_pass
    plugin._deployment_operations_event.set()
    plugin._deployment_operation_worker()
    self.assertEqual([color for _, color in lines], ["r"])
    self.assertIn("KeyError in _deployment_operation_worker > failing_pass", lines[0][0])
    self.assertNotIn("secret-value-in-error", lines[0][0])

  def test_a_failed_custody_call_is_tried_again_after_10_20_40_s_and_at_most_every_300_s(self):
    # Before, an operation whose dAuth custody call failed called the same dAuth server again on every 2 s pass.
    plugin = Coordinator()
    lines = []
    plugin.P = lambda message, color=None, **kw: lines.append((message, color))
    stuck, other = plugin.operation(), plugin.operation()
    stuck.update(phase="cleaning_up_preparation", outcome="failed", recovery="in_progress")
    other.update(operation_id=stuck["operation_id"].replace("-test", "-other"), job_id=2,
                 phase="waiting_for_readiness", deadline=10_000)
    for operation in (stuck, other):
      plugin._save_operation(operation)
    calls, handled = [], []

    def unavailable(payload):
      calls.append(plugin.now)
      raise RuntimeError("dAuth reconciliation service is unavailable.")

    plugin.bc.reconcile_dauth_job_secrets = unavailable
    advance = plugin._advance_deployment_operation
    plugin._advance_deployment_operation = lambda operation: handled.append(operation["operation_id"]) or advance(operation)
    # One worker pass every 2 s for 17 minutes.
    passes = 0
    while plugin.now < 1120:
      plugin._reconcile_coordinator_operations()
      plugin.now, passes = plugin.now + 2, passes + 1
    self.assertEqual([later - earlier for earlier, later in zip(calls, calls[1:])], [10, 20, 40, 80, 160, 300, 300])
    # The waiting operation is not even advanced; the other one is handled on every pass.
    self.assertEqual(handled.count(stuck["operation_id"]), len(calls))
    self.assertEqual(handled.count(other["operation_id"]), passes)
    red = [message for message, color in lines if color == "r"]
    self.assertEqual(len(red), len(calls))
    self.assertIn("DeploymentCustodyError in _reconcile_coordinator_operations > ", red[0])
    self.assertTrue(red[0].endswith("_advance_deployment_operation > _deployment_secret_request "
                                    "(custody failure 1, next try in 10 s)"))
    self.assertTrue(red[3].endswith("(custody failure 4, next try in 80 s)"))
    self.assertTrue(red[-1].endswith("(custody failure 8, next try in 300 s)"))
    # An operation whose records are gone from the replica leaves no wait behind.
    self.assertIn(stuck["operation_id"], plugin._custody_retry)
    for key in [key for key in plugin.storage if key[0] == OPERATIONS_HKEY and key[1].startswith(stuck["operation_id"] + "|")]:
      del plugin.storage[key]
    plugin._reconcile_coordinator_operations()
    self.assertNotIn(stuck["operation_id"], plugin._custody_retry)

  def test_a_custody_call_that_succeeds_ends_the_wait(self):
    plugin = Coordinator()
    operation = plugin.operation()
    operation.update(phase="cleaning_up_preparation", outcome="failed", recovery="in_progress")
    plugin._save_operation(operation)
    unavailable = RuntimeError("dAuth reconciliation service is unavailable.")
    answers, calls = [unavailable, unavailable, {}, unavailable, {}], []

    def custody(payload):
      calls.append(plugin.now)
      answer = answers.pop(0)
      if isinstance(answer, Exception):
        raise answer
      return answer

    plugin.bc.reconcile_dauth_job_secrets = custody
    # One custody call per pass that leaves the operation unfinished when it is answered, so a later one can fail.
    plugin._advance_deployment_operation = lambda operation: plugin._deployment_secret_request("revoke", operation)
    while plugin.now <= 142:
      plugin._reconcile_coordinator_operations()
      plugin.now += 2
    # Waits of 10 and 20 s; the answer at 130 s ends the wait, so the failure at 132 s waits 10 s again.
    self.assertEqual(calls, [100, 110, 130, 132, 142])
    self.assertEqual(plugin._custody_retry, {})

  def test_a_preparing_operation_asks_dauth_on_every_pass_until_its_preparation_deadline(self):
    # Preparation is polled until its deadline (created + 120 s), then cleaned up as failed. With custody waits the
    # last poll came at 70 s, so a dAuth that recovered later was not seen and the deployment was cleaned up.
    plugin = Coordinator()
    recovering, down = plugin.operation(), plugin.operation()
    down.update(operation_id=recovering["operation_id"].replace("-test", "-down"), job_id=2)
    for operation in (recovering, down):
      operation.update(phase="preparing", preparation_deadline=220)
      plugin._save_operation(operation)
    calls = {recovering["operation_id"]: [], down["operation_id"]: []}

    def custody(payload):
      calls[payload["operation"]["operation_id"]].append((plugin.now, payload["action"]))
      # dAuth answers the first operation again 6 s before its deadline; for the other one it stays down.
      if plugin.now < 214 or payload["operation"]["operation_id"] == down["operation_id"]:
        raise RuntimeError("dAuth reconciliation service is unavailable.")
      return {"prepared": True}

    plugin.bc.reconcile_dauth_job_secrets = custody
    while plugin.now <= 260:
      plugin._reconcile_coordinator_operations()
      plugin.now += 2
    # Asked on every 2 s pass until dAuth answered, and the deployment was accepted, not cleaned up.
    self.assertEqual(calls[recovering["operation_id"]], [(now, "status") for now in range(100, 216, 2)])
    accepted = plugin._operation_records()[recovering["operation_id"]]
    self.assertIsNone(accepted["outcome"])
    self.assertIn("Deployment preparation recovered.", [event["message"] for event in accepted["events"]])
    # Without an answer it is cleaned up at the deadline; the cleanup has no deadline and is paced (10 s, 20 s).
    self.assertEqual(calls[down["operation_id"]],
                     [(now, "status") for now in range(100, 220, 2)] + [(220, "revoke"), (230, "revoke"), (250, "revoke")])

  def test_a_chain_store_write_that_fails_is_still_tried_on_every_pass(self):
    # Only a failed custody call makes an operation wait, also right after such a wait has run out.
    plugin = Coordinator()
    lines = []
    plugin.P = lambda message, color=None, **kw: lines.append((message, color))
    operation = plugin.operation()
    operation.update(phase="cleaning_up_preparation", outcome="failed", recovery="in_progress")
    plugin._save_operation(operation)
    calls, writes = [], []

    def custody(payload):
      calls.append(plugin.now)
      if len(calls) == 1:
        raise RuntimeError("dAuth reconciliation service is unavailable.")
      return {}

    plugin.bc.reconcile_dauth_job_secrets = custody
    store = plugin.chainstore_hset
    plugin.chainstore_hset = lambda namespace, key, value, **kw: writes.append(plugin.now) or store(namespace, key, value, **kw)
    plugin._reconcile_coordinator_operations()  # custody failure 1, next try in 10 s
    # At 110 s the custody call succeeds, but no chain-store write is confirmed from then on.
    plugin.now, plugin.replicate = 110, False
    for _ in range(4):
      plugin._reconcile_coordinator_operations()
      plugin.now += 2
    self.assertEqual(calls, [100, 110])
    self.assertEqual(writes, [110, 112, 114, 116])
    red = [message for message, color in lines if color == "r"]
    self.assertEqual(len(red), 5)
    self.assertTrue(red[0].endswith("(custody failure 1, next try in 10 s)"))
    self.assertFalse(any("custody failure" in message for message in red[1:]))

  def test_admission_answers_as_before_when_the_custody_call_fails(self):
    # The admission endpoints answer 409 for DeploymentConflictError, 400 for any other ValueError and 503 for
    # every other error (deeploy_manager_api.py). A custody call dAuth could not do stays a RuntimeError (503)
    # with its text; an invalid answer stays the same ValueError (400).
    plugin = Coordinator()
    plugin._prepare_deployment_secret_configs = lambda configs, *args: (copy.deepcopy(configs), {})
    plugin.r1fs.add_json = lambda plan, **kw: "plan"
    plugin._get_pipeline_from_cstore = lambda job_id: None
    admit = lambda request_id: plugin._admit_prepared_deployment(
      request={"request_id": request_id, "job_id": 1}, auth_result={"escrow_owner": "owner"}, app_id="app",
      configs={"A": copy.deepcopy(CONFIG)}, prior_pipeline=None, is_create=True)
    plugin.bc.reconcile_dauth_job_secrets = Mock(side_effect=RuntimeError("dAuth reconciliation service is unavailable."))
    with self.assertRaisesRegex(DeploymentCustodyError, "^dAuth reconciliation service is unavailable.$") as raised:
      admit("unavailable")
    self.assertNotIsInstance(raised.exception, ValueError)  # 503, as before
    invalid = ValueError("Invalid dAuth reconciliation response.")
    plugin.bc.reconcile_dauth_job_secrets = Mock(side_effect=invalid)
    with self.assertRaises(ValueError) as raised:
      admit("invalid")
    self.assertIs(raised.exception, invalid)  # 400, as before
    # Admission handed both operations to the worker, as before.
    self.assertTrue(all(finished.is_set() for finished in plugin._deployment_preparations.values()))

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

  def test_readiness_requires_exact_instances_but_not_recent_reports(self):
    report = dict(status="ready", updated_at=100, instances=[dict(signature="RUNNER", instance_id="worker", status="ready")])
    self.assertTrue(report_is_ready(report, CONFIG))
    self.assertTrue(report_is_ready({**report, "updated_at": 0}, CONFIG))
    self.assertFalse(report_is_ready({**report, "instances": []}, CONFIG))
    self.assertFalse(report_is_ready({**report, "status": "starting"}, CONFIG))

  def test_one_time_ready_reports_finalize_only_while_nodes_are_online(self):
    plugin = Coordinator()
    operation = plugin.operation()
    plugin._save_operation(operation)
    plugin._advance_deployment_operation(operation)
    for node in operation["nodes"]:
      plugin.report(operation, node, "ready")
    plugin.now += 50
    plugin.offline = {"B"}
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "waiting_for_readiness")
    plugin.offline = set()
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "finalizing")

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
      # Each save carries new state; an unchanged save writes nothing.
      plugin._save_operation(operation, message="step {}".format(index))
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

  def test_restoration_needs_a_workers_commit_and_a_container_apps_image(self):
    # A worker is rebuilt from its Git commit on a base image the node pulls again, so the id of an image
    # that existed in one Docker store must not decide whether it can be restored.
    def restore(signature, artifacts):
      plugin = Coordinator()
      operation = plugin._save_operation(plugin.operation("update"), "restoring_previous", "Restoring.")
      operation["retired_runtime"] = {"A": {signature + "|worker": artifacts}}
      config = {"NAME": "app", "TYPE": "Void", "PLUGINS": [{"SIGNATURE": signature, "INSTANCES": [{"INSTANCE_ID": "worker"}]}]}
      plugin._send_operation_commands(operation, {"A": config}, "restore", "start", reports={})
      return plugin.commands[-1][1]["PLUGINS"][0]["INSTANCES"][0]["DEEPLOY_RUNTIME_ARTIFACTS"]
    commit, image = "b" * 40, "sha256:" + "a" * 64
    self.assertEqual(restore("WORKER_APP_RUNNER", {"git_commit": commit}), {"git_commit": commit})
    self.assertEqual(restore("CONTAINER_APP_RUNNER", {"image_id": image}), {"image_id": image})
    for signature, artifacts in (("WORKER_APP_RUNNER", {"image_id": image}), ("CONTAINER_APP_RUNNER", {"git_commit": commit}),
                                 ("CONTAINER_APP_RUNNER", {})):
      with self.assertRaisesRegex(RuntimeError, "runtime artifacts are unavailable"):
        restore(signature, artifacts)
    # The registry reference of a container app travels with its image id, unchanged.
    reference = "ghcr.io/acme/shop@sha256:" + "d" * 64
    self.assertEqual(restore("CONTAINER_APP_RUNNER", {"image_id": image, "image_ref": reference}),
                     {"image_id": image, "image_ref": reference})

  def test_a_blocked_restoration_names_what_is_missing(self):
    for signature, expected in (("WORKER_APP_RUNNER", "Git commit"), ("CONTAINER_APP_RUNNER", "image binding")):
      plugin = Coordinator()
      operation = plugin._save_operation(plugin.operation("update"), "restoring_previous", "Restoring.")
      operation["retired_runtime"] = {"A": {}}
      config = {"NAME": "app", "TYPE": "Void", "PLUGINS": [{"SIGNATURE": signature, "INSTANCES": [{"INSTANCE_ID": "worker"}]}]}
      with self.assertRaises(RuntimeError):
        plugin._send_operation_commands(operation, {"A": config}, "restore", "start", reports={})
      saved = plugin._operation_records()[operation["operation_id"]]
      self.assertEqual(saved["recovery"], "blocked")
      self.assertEqual(saved["events"][-1]["message"], "Previous runtime {} is unavailable; restoration is blocked.".format(expected))

  def test_each_signed_record_is_checked_once_and_a_changed_one_again(self):
    # The worker reads every operation record every 2 s on every oracle, and every status poll reads them
    # again. Each read checked every signature: about 1 ms a record, a few hundred records, all the time.
    plugin = Coordinator()
    checked = []
    verify = plugin.bc.verify
    plugin.bc.verify = lambda record, return_full_info=True: checked.append(record["operation_id"]) or verify(record)
    for index in range(3):
      record = plugin.operation()
      record["operation_id"] += str(index)
      plugin.bc.sign(record)
      plugin.chainstore_hset(OPERATIONS_HKEY, record["operation_id"] + "|0", record)
    for _ in range(5):
      self.assertEqual(len(plugin._operation_records()), 3)
    self.assertEqual(len(checked), 3)  # once per record, not once per record and pass
    # A record that differs in any byte is another record: it is checked in full.
    key = next(key for namespace, key in plugin.storage if namespace == OPERATIONS_HKEY)
    plugin.storage[OPERATIONS_HKEY, key]["phase"] = "completed"
    plugin._operation_records()
    plugin._operation_records()
    self.assertEqual(len(checked), 4)
    # A record that fails the check is never answered from memory, and never returned.
    plugin.storage[OPERATIONS_HKEY, key]["EE_SIGN"] = "forged"
    for _ in range(3):
      self.assertEqual(len(plugin._operation_records()), 2)
    self.assertEqual(len(checked), 7)
    # The writer field is part of what is remembered: valid as a coordinator's record says nothing
    # about the same bytes read as a node's report.
    record = plugin.operation()
    record.update(node_addr="other")
    plugin.bc.sign(record)
    self.assertTrue(plugin._verify_operation_record(record, "coordinator"))
    self.assertFalse(plugin._verify_operation_record(record, "node_addr"))

  def test_verified_fingerprints_evict_only_the_oldest_insertion(self):
    plugin = Coordinator()
    record = dict(coordinator="oracle", EE_SENDER="oracle", EE_SIGN="valid")
    plugin.bc.verify = Mock(wraps=plugin.bc.verify)
    plugin.P = Mock()
    for index in range(10000):
      self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
    self.assertEqual(len(plugin._verified_operation_records), 10000)
    plugin.bc.verify.reset_mock()
    # A cache hit does not refresh insertion order.
    self.assertTrue(plugin._verify_operation_record(dict(record, sequence=0), "coordinator"))
    plugin.bc.verify.assert_not_called()
    # Neither invalid signatures nor a mismatched writer may evict a valid entry.
    for invalid in (dict(record, EE_SIGN="forged"), dict(record, EE_SENDER="other")):
      for _ in range(2):
        self.assertFalse(plugin._verify_operation_record(invalid, "coordinator"))
    self.assertEqual(plugin.bc.verify.call_count, 4)
    self.assertTrue(plugin._verify_operation_record(dict(record, sequence=0), "coordinator"))
    self.assertEqual(plugin.bc.verify.call_count, 4)
    self.assertTrue(plugin._verify_operation_record(dict(record, sequence=10000), "coordinator"))
    self.assertEqual(len(plugin._verified_operation_records), 10000)
    plugin.bc.verify.reset_mock()
    for index in (1, 9999, 10000):
      self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
    plugin.bc.verify.assert_not_called()
    # The evicted record is verified again; its reinsertion evicts the next oldest.
    for index in (0, 1):
      self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
    self.assertEqual(plugin.bc.verify.call_count, 2)
    self.assertEqual(len(plugin._verified_operation_records), 10000)
    plugin.P.assert_not_called()

  def test_concurrent_verified_fingerprints_remain_bounded_without_extra_evictions(self):
    # A barrier alone can miss unprotected cache races under the GIL. Assert lock ownership too.
    test = self

    class CacheLock:
      def __init__(self):
        self.lock = threading.Lock()
        self.owner = None

      def __enter__(self):
        self.lock.acquire()
        self.owner = threading.get_ident()

      def __exit__(self, *args):
        self.owner = None
        self.lock.release()

    class LockedCache(OrderedDict):
      def __contains__(self, key):
        test.assertEqual(self.guard.owner, threading.get_ident())
        return super().__contains__(key)

      def __len__(self):
        test.assertEqual(self.guard.owner, threading.get_ident())
        return super().__len__()

      def __setitem__(self, key, value):
        test.assertEqual(self.guard.owner, threading.get_ident())
        super().__setitem__(key, value)
        test.assertLessEqual(OrderedDict.__len__(self), 10000)

      def popitem(self, *args, **kwargs):
        test.assertEqual(self.guard.owner, threading.get_ident())
        return super().popitem(*args, **kwargs)

    for duplicates in (False, True):
      with self.subTest(duplicates=duplicates):
        plugin = Coordinator()
        cache = LockedCache()
        cache.guard = plugin._verified_operation_records_lock = CacheLock()
        plugin._verified_operation_records = cache
        record = dict(coordinator="oracle", EE_SENDER="oracle", EE_SIGN="valid")
        for index in range(10000):
          self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
        verify = plugin.bc.verify
        barrier = threading.Barrier(4, timeout=5)

        def concurrent_verify(value, **kwargs):
          # All misses must reach verification concurrently: the cache lock cannot cover crypto.
          barrier.wait()
          return verify(value, **kwargs)

        plugin.bc.verify = concurrent_verify
        indices = [10000] * 4 if duplicates else list(range(10000, 10004))
        with ThreadPoolExecutor(max_workers=4) as executor:
          futures = [executor.submit(plugin._verify_operation_record, dict(record, sequence=index), "coordinator")
                     for index in indices]
          self.assertEqual([future.result(timeout=10) for future in futures], [True] * 4)
        with cache.guard:
          self.assertEqual(len(cache), 10000)
        plugin.bc.verify = Mock(wraps=verify)
        # Duplicate misses insert once; distinct misses evict exactly their number of old entries.
        for index in [len(set(indices)), 9999] + indices:
          self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
        plugin.bc.verify.assert_not_called()
        self.assertTrue(plugin._verify_operation_record(dict(record, sequence=0), "coordinator"))
        plugin.bc.verify.assert_called_once()
        with cache.guard:
          self.assertEqual(len(cache), 10000)

  def test_completed_snapshot_is_resent_as_repair_for_ten_minutes(self):
    # One confirmation is enough for a write, so an oracle can miss the final snapshot; nothing else sends it again.
    plugin = Coordinator()
    operation = plugin.operation("update")
    operation.update(phase="completed", outcome="failed", recovery="completed")
    plugin._save_operation(operation)
    stored, sent = dict(plugin.storage), []
    store = plugin.chainstore_hset
    plugin.chainstore_hset = lambda namespace, key, value, **kw: sent.append((namespace, key)) or store(namespace, key, value, **kw)
    plugin._reconcile_coordinator_operations()  # just confirmed: nothing to send
    self.assertEqual(sent, [])
    plugin.now += 31
    plugin._reconcile_coordinator_operations()  # 30 s later: the same record once more
    self.assertEqual(sent, [(OPERATIONS_HKEY, "{}|{}".format(operation["operation_id"], operation["sequence"] % 8))])
    plugin.now += 600
    plugin._reconcile_coordinator_operations()  # past the window: left alone
    self.assertEqual(len(sent), 1)
    self.assertEqual(plugin.storage, stored)


if __name__ == "__main__":
  unittest.main()
