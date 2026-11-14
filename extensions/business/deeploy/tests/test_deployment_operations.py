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


# The ages after completion, in seconds, at which a completed operation's final snapshot is sent again: every 30 s up
# to 600 s, then 1,200, 2,400 and 4,800 s, then every hour up to 84,000 s (45 sends).
REPAIR_SCHEDULE = list(range(30, 630, 30)) + [1200, 2400] + list(range(4800, 86400, 3600))
CONFIG = {"NAME": "app", "TYPE": "Void", "DEEPLOY_SPECS": {"revision": 1, "secret_revision": "op:deploy"},
          "PLUGINS": [{"SIGNATURE": "RUNNER", "INSTANCES": [{"INSTANCE_ID": "worker"}]}]}


class Coordinator(_DeploymentOperationsMixin):
  def __init__(self, address="oracle"):
    """
    Build an offline coordinating oracle with the fields the operations mixin reads.

    The signer, the chain store, R1FS and the clock are in-memory doubles: a record signs as valid, the store is
    a dict keyed by (namespace, key), and the time stands still until a test moves it. The operation fields are
    created as `_init_deployment_operations` creates them, without starting the worker thread.

    Parameters
    ----------
    address : str, optional
      The oracle's own address, used as the signer of every record it writes. Default "oracle".

    Returns
    -------
    None
      The fields are set on the new instance.

    Examples
    --------
    >>> plugin = Coordinator()
    >>> plugin.bc.address, plugin._verified_operation_records_dropped
    ('oracle', 0)
    """
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
    # The served ages of each completed operation's repair schedule, as _init_deployment_operations creates them.
    self._operations_repaired = {}
    self._operations_sent_at = {}
    self._verified_operation_records = OrderedDict()  # as _init_deployment_operations creates it
    # The lock of the cache, as _init_deployment_operations creates it.
    self._verified_operation_records_lock = threading.Lock()
    # The drop count of the cache, as _init_deployment_operations creates it; without it a drop refuses a valid record.
    self._verified_operation_records_dropped = 0
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

  def test_a_chain_store_write_that_fails_is_not_held_back_by_the_custody_wait(self):
    """Only a failed custody call makes an operation wait, also right after such a wait has run out: a final
    write that fails after the custody call succeeded is tried again at its repair ages 30 and 60 s, where
    custody waits of 20 and 40 s would have held the second try back, and its red lines name no custody failure."""
    # A coordinator whose log lines are kept with their colors.
    plugin = Coordinator()
    # The log lines with their colors.
    lines = []
    # Every log call lands in the list.
    plugin.P = lambda message, color=None, **kw: lines.append((message, color))
    # An operation cleaning up after a failed preparation.
    operation = plugin.operation()
    # Its cleanup phase, which makes a custody call.
    operation.update(phase="cleaning_up_preparation", outcome="failed", recovery="in_progress")
    # Written and confirmed.
    plugin._save_operation(operation)
    # The times of the custody calls and of the chain-store writes.
    calls, writes = [], []

    def custody(payload):
      """
      Answer a custody call as dAuth does: unavailable the first time, then a success.

      Parameters
      ----------
      payload : dict
        The custody request; not read.

      Returns
      -------
      dict
        An empty answer, from the second call on.

      Raises
      ------
      RuntimeError
        On the first call, as an unavailable dAuth.

      Examples
      --------
      >>> custody({})  # the first call
      Traceback (most recent call last):
      RuntimeError: dAuth reconciliation service is unavailable.
      """
      # Record the call's time.
      calls.append(plugin.now)
      if len(calls) == 1:
        raise RuntimeError("dAuth reconciliation service is unavailable.")
      return {}

    # dAuth's custody calls go to the fake above.
    plugin.bc.reconcile_dauth_job_secrets = custody
    # The fake store's own write.
    store = plugin.chainstore_hset
    # Record each write's time, keeping the fake store's behaviour.
    plugin.chainstore_hset = lambda namespace, key, value, **kw: writes.append(plugin.now) or store(namespace, key, value, **kw)
    # Custody failure 1, next try in 10 s.
    plugin._reconcile_coordinator_operations()
    # At 110 s the custody call succeeds, but no chain-store write is confirmed from then on.
    plugin.now, plugin.replicate = 110, False
    # One pass every 2 s up to 178 s.
    for _ in range(35):
      # One pass.
      plugin._reconcile_coordinator_operations()
      # The worker's 2 s wait.
      plugin.now += 2
    # dAuth was called at 100 s and, after the 10 s wait, at 110 s.
    self.assertEqual(calls, [100, 110])
    # The final write at 110 s, then its repair ages 30 and 60 s.
    self.assertEqual(writes, [110, 140, 170])
    # The red lines.
    red = [message for message, color in lines if color == "r"]
    # The custody failure and the three failed writes.
    self.assertEqual(len(red), 4)
    # Only the first names a custody failure.
    self.assertTrue(red[0].endswith("(custody failure 1, next try in 10 s)"))
    # The failed writes do not.
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
    """A full cache drops only its oldest insertion, a hit does not move an entry, a failed record drops none."""
    # A coordinator with an empty cache.
    plugin = Coordinator()
    # A valid coordinator record; each sequence number below makes a distinct fingerprint.
    record = dict(coordinator="oracle", EE_SENDER="oracle", EE_SIGN="valid")
    # Count the signature checks, while they still answer as the fixture does.
    plugin.bc.verify = Mock(wraps=plugin.bc.verify)
    # Record every log call.
    plugin.P = Mock()
    # Fill the cache to its 10,000 entries with sequences 0 to 9,999, in that order.
    for index in range(10000):
      # Each one is valid, so each one is remembered.
      self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
    # Full, and nothing was dropped yet.
    self.assertEqual(len(plugin._verified_operation_records), 10000)
    # Count only the checks from here on.
    plugin.bc.verify.reset_mock()
    # A cache hit does not refresh insertion order.
    self.assertTrue(plugin._verify_operation_record(dict(record, sequence=0), "coordinator"))
    # The hit was answered from memory, without a signature check.
    plugin.bc.verify.assert_not_called()
    # Neither invalid signatures nor a mismatched writer may evict a valid entry.
    for invalid in (dict(record, EE_SIGN="forged"), dict(record, EE_SENDER="other")):
      # Twice each: a failed record is not remembered, so the second read is checked again.
      for _ in range(2):
        # Each read is refused.
        self.assertFalse(plugin._verify_operation_record(invalid, "coordinator"))
    # Two records read twice: four full checks.
    self.assertEqual(plugin.bc.verify.call_count, 4)
    # Sequence 0 is still remembered: the refused records dropped nothing.
    self.assertTrue(plugin._verify_operation_record(dict(record, sequence=0), "coordinator"))
    # No check was added for it.
    self.assertEqual(plugin.bc.verify.call_count, 4)
    # A new valid record at capacity is remembered by dropping the oldest insertion, sequence 0.
    self.assertTrue(plugin._verify_operation_record(dict(record, sequence=10000), "coordinator"))
    # Still full, never above it.
    self.assertEqual(len(plugin._verified_operation_records), 10000)
    # Count only the checks from here on.
    plugin.bc.verify.reset_mock()
    # The second oldest, the newest of the first fill and the new record are all still remembered.
    for index in (1, 9999, 10000):
      # Each one is accepted.
      self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
    # All three from memory.
    plugin.bc.verify.assert_not_called()
    # The evicted record is verified again; its reinsertion evicts the next oldest.
    for index in (0, 1):
      # Sequence 0 drops sequence 1, which is then checked again and drops sequence 2.
      self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
    # Both were checked in full.
    self.assertEqual(plugin.bc.verify.call_count, 2)
    # Still full, never above it.
    self.assertEqual(len(plugin._verified_operation_records), 10000)
    # Three drops in all are counted, fewer than the 10,000 that make one red line, so nothing was logged.
    self.assertEqual(plugin._verified_operation_records_dropped, 3)
    # No log call at all.
    plugin.P.assert_not_called()

  def test_concurrent_verified_fingerprints_remain_bounded_without_extra_evictions(self):
    """Four threads that miss at once touch the cache only under its lock and drop exactly one entry per new record.

    Run once with four distinct new records and once with the same new record four times, on a full cache.
    """
    # A barrier alone can miss unprotected cache races under the GIL. Assert lock ownership too.
    test = self

    # The cache lock, which also records the thread that holds it.
    class CacheLock:
      """
      A lock for the fingerprint cache that also records which thread holds it.

      It replaces the plugin's `threading.Lock` for this test, so the checking cache below can assert that each
      of its operations runs on the thread that holds the lock.

      Examples
      --------
      >>> guard = CacheLock()
      >>> with guard:
      ...   guard.owner == threading.get_ident()
      True
      """

      def __init__(self):
        """
        Create the lock, held by no thread.

        Returns
        -------
        None
          `lock` is a new `threading.Lock`; `owner` is None.

        Examples
        --------
        >>> CacheLock().owner is None
        True
        """
        # The real lock behind the context manager.
        self.lock = threading.Lock()
        # No thread holds it yet.
        self.owner = None

      def __enter__(self):
        """
        Take the lock, then record the calling thread as its holder.

        Returns
        -------
        None
          Nothing is bound by `with`.

        Examples
        --------
        >>> with guard:
        ...   guard.owner == threading.get_ident()
        True
        """
        # Take the lock, then note who holds it.
        self.lock.acquire()
        # The holder, as the cache below checks it.
        self.owner = threading.get_ident()

      def __exit__(self, *args):
        """
        Forget the holder, then release the lock.

        Parameters
        ----------
        *args : tuple
          The exception type, value and traceback of the `with` block, or three None; not used.

        Returns
        -------
        None
          An exception raised in the block is not suppressed.

        Examples
        --------
        >>> with guard:
        ...   pass
        >>> guard.owner is None
        True
        """
        # Forget the holder before the lock is released.
        self.owner = None
        # Let the next thread in.
        self.lock.release()

    # The cache, failing the test when one of its operations runs on a thread that does not hold the lock.
    class LockedCache(OrderedDict):
      """
      The fingerprint cache, failing the test when one of its operations runs without the cache lock.

      Its `guard` attribute is the `CacheLock` the plugin uses. Lookup, size, insertion and drop each assert that
      the calling thread holds it, then act as on a plain `OrderedDict`; an insertion also asserts the bound.

      Examples
      --------
      >>> cache = LockedCache()
      >>> cache.guard = CacheLock()
      >>> with cache.guard:
      ...   len(cache)
      0
      """

      def __contains__(self, key):
        """
        Look a fingerprint up, only on the thread that holds the cache lock.

        Parameters
        ----------
        key : str
          The fingerprint looked up.

        Returns
        -------
        bool
          Whether the cache holds it.

        Examples
        --------
        >>> with cache.guard:
        ...   "fingerprint" in cache
        False
        """
        # A lookup only by the thread that holds the lock.
        test.assertEqual(self.guard.owner, threading.get_ident())
        # Then the plain lookup.
        return super().__contains__(key)

      def __len__(self):
        """
        Read the size of the cache, only on the thread that holds the cache lock.

        Returns
        -------
        int
          The number of fingerprints held.

        Examples
        --------
        >>> with cache.guard:
        ...   len(cache)
        0
        """
        # The size read only by the thread that holds the lock.
        test.assertEqual(self.guard.owner, threading.get_ident())
        # Then the plain size.
        return super().__len__()

      def __setitem__(self, key, value):
        """
        Insert a fingerprint, only on the thread that holds the cache lock, and never above 10,000 entries.

        Parameters
        ----------
        key : str
          The fingerprint inserted.
        value : bool
          The value kept for it; the plugin keeps True.

        Returns
        -------
        None

        Examples
        --------
        >>> with cache.guard:
        ...   cache["fingerprint"] = True
        """
        # An insertion only by the thread that holds the lock.
        test.assertEqual(self.guard.owner, threading.get_ident())
        # Then the plain insertion.
        super().__setitem__(key, value)
        # Never above 10,000 entries, read without the ownership check above.
        test.assertLessEqual(OrderedDict.__len__(self), 10000)

      def popitem(self, *args, **kwargs):
        """
        Drop an entry, only on the thread that holds the cache lock.

        Parameters
        ----------
        *args : tuple
          Passed to `OrderedDict.popitem`; the plugin passes none.
        **kwargs : dict
          Passed to `OrderedDict.popitem`; the plugin passes `last=False`, the oldest insertion.

        Returns
        -------
        tuple
          The dropped (fingerprint, value) pair.

        Examples
        --------
        >>> with cache.guard:
        ...   cache.popitem(last=False)
        ('fingerprint', True)
        """
        # A drop only by the thread that holds the lock.
        test.assertEqual(self.guard.owner, threading.get_ident())
        # Then the plain drop.
        return super().popitem(*args, **kwargs)

    # Four distinct new records first, then one new record read four times at once.
    for duplicates in (False, True):
      # Each case on a fresh plugin.
      with self.subTest(duplicates=duplicates):
        # A coordinator with an empty cache.
        plugin = Coordinator()
        # The checking cache, in place of the plugin's own.
        cache = LockedCache()
        # The cache and the plugin share the recording lock.
        cache.guard = plugin._verified_operation_records_lock = CacheLock()
        # The plugin uses the checking cache.
        plugin._verified_operation_records = cache
        # A valid coordinator record; each sequence number below makes a distinct fingerprint.
        record = dict(coordinator="oracle", EE_SENDER="oracle", EE_SIGN="valid")
        # Fill the cache to its 10,000 entries with sequences 0 to 9,999, in that order.
        for index in range(10000):
          # Each one is valid, so each one is remembered.
          self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
        # The fixture's signature check, wrapped below.
        verify = plugin.bc.verify
        # The four checks below wait for each other here, so all four run at the same time.
        barrier = threading.Barrier(4, timeout=5)

        def concurrent_verify(value, **kwargs):
          """
          Check a signature only once all four threads have reached a check.

          Parameters
          ----------
          value : dict
            The record whose signature is checked.
          **kwargs : dict
            The other arguments of the plugin's check, passed on.

          Returns
          -------
          object
            What the fixture's signature check returns for the record.

          Raises
          ------
          threading.BrokenBarrierError
            When the four threads do not all reach a check within 5 s.

          Examples
          --------
          >>> concurrent_verify(record, return_full_info=True).valid   # in each of the four threads at once
          True
          """
          # All misses must reach verification concurrently: the cache lock cannot cover crypto.
          barrier.wait()
          # Then the fixture's answer.
          return verify(value, **kwargs)

        # Every signature check now waits for the other three.
        plugin.bc.verify = concurrent_verify
        # Four distinct new sequences, or the same new sequence four times.
        indices = [10000] * 4 if duplicates else list(range(10000, 10004))
        # One thread per read.
        with ThreadPoolExecutor(max_workers=4) as executor:
          # The four reads, started together.
          futures = [executor.submit(plugin._verify_operation_record, dict(record, sequence=index), "coordinator")
                     for index in indices]
          # All four are accepted.
          self.assertEqual([future.result(timeout=10) for future in futures], [True] * 4)
        # Read the size under the lock, as the checking cache requires.
        with cache.guard:
          # Still full, never above it.
          self.assertEqual(len(cache), 10000)
        # Count the checks from here on.
        plugin.bc.verify = Mock(wraps=verify)
        # Duplicate misses insert once; distinct misses evict exactly their number of old entries.
        for index in [len(set(indices)), 9999] + indices:
          # The oldest that must remain, the newest of the first fill and the new records: all accepted.
          self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
        # All from memory, so nothing was dropped beyond one entry per new record.
        plugin.bc.verify.assert_not_called()
        # Sequence 0, the oldest, was dropped by the first new record.
        self.assertTrue(plugin._verify_operation_record(dict(record, sequence=0), "coordinator"))
        # So it is checked in full again.
        plugin.bc.verify.assert_called_once()
        # Read the size under the lock, as the checking cache requires.
        with cache.guard:
          # Still full, never above it.
          self.assertEqual(len(cache), 10000)
        # Every drop was counted under the lock: one per distinct new record, and one for the reread sequence 0.
        self.assertEqual(plugin._verified_operation_records_dropped, len(set(indices)) + 1)

  def test_every_ten_thousand_dropped_fingerprints_log_one_red_line(self):
    """Each 10,000th fingerprint dropped from the full cache logs one red line; the drops between log nothing."""
    # A coordinator with an empty cache and no drops yet.
    plugin = Coordinator()
    # A valid coordinator record; each sequence number below makes a distinct fingerprint.
    record = dict(coordinator="oracle", EE_SENDER="oracle", EE_SIGN="valid")
    # The log lines, as (message, color).
    lines = []
    # Every log call lands there.
    plugin.P = lambda message, color=None, **kw: lines.append((message, color))
    # Fill the cache, then make 9,999 drops with as many new records: one short of a line.
    for index in range(19999):
      # Each one is valid, so each one is remembered.
      self.assertTrue(plugin._verify_operation_record(dict(record, sequence=index), "coordinator"))
    # 9,999 drops, nothing logged.
    self.assertEqual((plugin._verified_operation_records_dropped, lines), (9999, []))
    # The 10,000th drop.
    self.assertTrue(plugin._verify_operation_record(dict(record, sequence=19999), "coordinator"))
    # One red line, which says what was replaced and what a repeat on every pass means.
    self.assertEqual(lines, [(
      "Replaced 10,000 remembered Deeploy record fingerprints. If this line repeats on every pass, more than "
      "10,000 valid records are alive and every record is checked again.", "r")])
    # The next drop starts the count towards the next line and logs nothing.
    self.assertTrue(plugin._verify_operation_record(dict(record, sequence=20000), "coordinator"))
    # Still one line; the cache stays at its bound.
    self.assertEqual((len(lines), len(plugin._verified_operation_records)), (1, 10000))

  def test_completed_snapshot_is_resent_every_30_s_then_on_a_back_off_for_a_day(self):
    """The final snapshot of a completed operation is re-sent every 30 s for 600 s, as before, then at the ages
    600, 1,200, 2,400 and 4,800 s and every hour after that up to 84,000 s, and no more; always the same record."""
    # One confirmation is enough for a write, so an oracle can miss the final snapshot; nothing else sends it again.
    plugin = Coordinator()
    # A completed update operation.
    operation = plugin.operation("update")
    # Completed, with a failed outcome and a completed recovery.
    operation.update(phase="completed", outcome="failed", recovery="completed")
    # The final snapshot, written and confirmed now: its update time is the completion.
    plugin._save_operation(operation)
    # The store after the final write, and the (seconds after completion, namespace, key) of each re-send.
    stored, sent = dict(plugin.storage), []
    # The fake store's own write.
    store = plugin.chainstore_hset
    # Record each write with its time after completion, keeping the fake store's behaviour.
    plugin.chainstore_hset = lambda namespace, key, value, **kw: sent.append(
      (plugin.now - operation["updated_at"], namespace, key)) or store(namespace, key, value, **kw)
    # One worker pass every 2 s, from completion to 25 h: past 87,600 s, where one more hour would put a send.
    for _ in range(90000 // 2 + 1):
      # One pass.
      plugin._reconcile_coordinator_operations()
      # The worker's 2 s wait.
      plugin.now += 2
    # 19 re-sends 30 s apart in the first 600 s, then 600, 1,200, 2,400 and 4,800 s, then every hour up to 84,000 s.
    self.assertEqual([age for age, _, _ in sent], REPAIR_SCHEDULE)
    # 26 of them from 600 s on.
    self.assertEqual(len([age for age, _, _ in sent if age >= 600]), 26)
    # Every re-send wrote the final snapshot's own slot.
    self.assertEqual({(namespace, key) for _, namespace, key in sent},
                     {(OPERATIONS_HKEY, "{}|{}".format(operation["operation_id"], operation["sequence"] % 8))})
    # And always the same record: the store is as the final write left it.
    self.assertEqual(plugin.storage, stored)

  def test_a_late_send_does_not_hold_back_the_send_of_the_next_age(self):
    """The sends of a completed operation fall on fixed ages after completion, not on the time since the last
    send: a send made 1 s after the age 30 s is followed by the send of the age 60 s, 29 s later."""
    # A coordinator with a completed operation.
    plugin = Coordinator()
    # A completed update operation.
    operation = plugin.operation("update")
    # Completed, with a failed outcome and a completed recovery.
    operation.update(phase="completed", outcome="failed", recovery="completed")
    # The final snapshot, written and confirmed now: its update time is the completion.
    plugin._save_operation(operation)
    # The seconds after completion of each write.
    sent = []
    # The fake store's own write.
    store = plugin.chainstore_hset
    # Record each write's time after completion, keeping the fake store's behaviour.
    plugin.chainstore_hset = lambda namespace, key, value, **kw: sent.append(
      plugin.now - operation["updated_at"]) or store(namespace, key, value, **kw)
    # A pass at completion, a pass 1 s after the age 30 s, and a pass at the age 60 s.
    for age in (0, 31, 60):
      # The pass at this age.
      plugin.now = operation["updated_at"] + age
      # One pass.
      plugin._reconcile_coordinator_operations()
    # Sent at 31 s and again at 60 s.
    self.assertEqual(sent, [31, 60])

  def test_restarts_send_nothing_at_once_and_keep_each_operation_on_its_own_ages(self):
    """Restarts every 1,700 s, closer together than the later gaps, neither send at once nor move the sends:
    two operations completed 1,000 s apart are each sent at their own ages after completion and at no other
    time, and a restart more than 24 h after completion keeps no entry for them."""
    # A coordinator.
    plugin = Coordinator()
    # The completion time of each operation, by its id.
    completed = {}
    # Two completed operations, the second 1,000 s after the first.
    for suffix in ("-first", "-second"):
      # A completed update operation, its id under this coordinator's prefix.
      operation = plugin.operation("update")
      # Its own id, completed, with a failed outcome and a completed recovery.
      operation.update(operation_id=operation["operation_id"].replace("-test", suffix), phase="completed",
                       outcome="failed", recovery="completed")
      # The final snapshot, written and confirmed now.
      plugin._save_operation(operation)
      # Its update time is its completion.
      completed[operation["operation_id"]] = plugin.now
      # The next operation completes 1,000 s later.
      plugin.now += 1000
    # The ids of the first and the second operation, in completion order.
    first, second = completed
    # The (operation id, seconds after its completion) of each write.
    sent = []
    # The fake store's own write.
    store = plugin.chainstore_hset
    # Record each write with its operation and its age, keeping the fake store's behaviour.
    plugin.chainstore_hset = lambda namespace, key, value, **kw: sent.append(
      (value["operation_id"], plugin.now - completed[value["operation_id"]])) or store(namespace, key, value, **kw)
    # One pass every 10 s from the second completion (the first pass sees both, as after a restart) to 87,500 s
    # after the first completion; a restart every 1,700 s from 850 s after the second completion, none on an age.
    for now in range(completed[second], completed[first] + 87500, 10):
      # The pass at this time.
      plugin.now = now
      if now >= completed[second] + 850 and (now - completed[second] - 850) % 1700 == 0:
        # A restart: the maps kept in process memory start empty, as _init_deployment_operations leaves them.
        plugin._operations_confirmed, plugin._operations_repaired = {}, {}
      # One pass.
      plugin._reconcile_coordinator_operations()
    # The first operation, 1,000 s old at the first pass, is sent at each later age of its schedule and only then.
    self.assertEqual([age for operation_id, age in sent if operation_id == first],
                     [age for age in REPAIR_SCHEDULE if age > 1000])
    # The second, seen at its completion, at every age of its schedule and only then.
    self.assertEqual([age for operation_id, age in sent if operation_id == second], REPAIR_SCHEDULE)
    # A restart more than 24 h after both completions.
    plugin._operations_confirmed, plugin._operations_repaired = {}, {}
    # One pass after it.
    plugin._reconcile_coordinator_operations()
    # Neither operation is kept in the schedule's map any more.
    self.assertEqual(plugin._operations_repaired, {})

  def test_a_final_snapshot_never_confirmed_is_logged_at_each_age_before_and_after_a_restart(self):
    """A final snapshot that other oracles never confirmed is sent again at each age of the schedule, not on
    every pass, and each such send leaves one red line, the same before a restart and after it."""
    # A coordinator.
    plugin = Coordinator()
    # An update operation.
    operation = plugin.operation("update")
    # An earlier snapshot, written and confirmed.
    plugin._save_operation(operation)
    # Completed, with a failed outcome and a completed recovery.
    operation.update(phase="completed", outcome="failed", recovery="completed")
    # Other oracles do not confirm from now on.
    plugin.replicate = False
    # The final snapshot is stored here but not confirmed: the save raises.
    with self.assertRaises(RuntimeError):
      # The final write.
      plugin._save_operation(operation)
    # The completion time: the stored final snapshot's update time.
    completion = plugin.now
    # The seconds after completion of each write and of each red line.
    sent, red = [], []
    # The fake store's own write.
    store = plugin.chainstore_hset
    # Record each write's time after completion, keeping the fake store's behaviour.
    plugin.chainstore_hset = lambda namespace, key, value, **kw: sent.append(plugin.now - completion) or store(
      namespace, key, value, **kw)
    # Record the time after completion of each red log line.
    plugin.P = lambda message, color=None, **kw: red.append(plugin.now - completion) if color == "r" else None
    # One pass every 2 s for 1,300 s after completion, with a restart 700 s after completion.
    for now in range(completion, completion + 1300, 2):
      # The pass at this time.
      plugin.now = now
      if now == completion + 700:
        # A restart: the maps kept in process memory start empty, as _init_deployment_operations leaves them.
        plugin._operations_confirmed, plugin._operations_repaired = {}, {}
      # One pass.
      plugin._reconcile_coordinator_operations()
    # Sent at each age up to 600 s before the restart and at 1,200 s after it, and each send is one red line.
    self.assertEqual((sent, red), (REPAIR_SCHEDULE[:21], REPAIR_SCHEDULE[:21]))


if __name__ == "__main__":
  unittest.main()
