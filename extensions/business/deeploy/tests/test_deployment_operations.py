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
  SECRET_REVISIONS_HKEY, DeploymentConflictError, DeploymentCustodyError, request_digest,
  report_is_ready, validate_source_pins, pinned_sources,
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

  def source_operation(self, kind="create", pinned=False, previous_pinned=False):
    operation = self.operation(kind)
    for field, flag, identities in (("configs", pinned, "instances"), ("previous_configs", previous_pinned, "previous_instances")):
      for node, config in self.plan[field].items():
        runner = config["PLUGINS"][0]
        runner["SIGNATURE"] = "WORKER_APP_RUNNER"
        if flag:
          runner["INSTANCES"][0].update(PINNED_VERSION=True, VCS_DATA={"COMMIT": "a" * 40})
        operation[identities][node] = [(runner["SIGNATURE"], "worker")]
    return operation

  def report(self, operation, node, status, attempt="deploy", sequence=1, mode=None, code=None):
    report = dict(operation_id=operation["operation_id"], coordinator="oracle", app_id="app",
                  node_addr=node, attempt=attempt,
                  revision=1 if attempt == "deploy" else 0,
                  status=status, sequence=sequence, updated_at=self.now,
                  instances=[dict(signature=signature, instance_id=instance_id, status=status)
                             for signature, instance_id in operation["instances" if attempt == "deploy" else "previous_instances"][node]],
                  EE_SIGN="valid", EE_SENDER=node)
    for instance in report["instances"]:
      if mode:
        instance["source_mode"] = mode
      if code:
        instance["error"] = {"code": code}
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

  def test_retirement_status_distinguishes_previous_workers_from_new_targets(self):
    plugin = self.prepare()
    operation = plugin.operation("update")
    operation.update(phase="retiring_previous", mutation="node_relink", recovery="blocked")
    plugin._save_operation(operation)
    plugin.report(operation, "B", "stopped", attempt="retire")
    # A different attempt on A cannot satisfy its outstanding retirement.
    plugin.report(operation, "A", "stopped", attempt="deploy")
    result = plugin._deployment_status({"job_id": 1})
    self.assertEqual({row["node_id"]: row["action"] for row in result["nodes"]}, {
      "A": "awaiting_stop_report", "B": "stop_reported", "C": "waiting_to_start",
    })
    # Replication of operation snapshots and worker reports can occur independently.
    plugin.bc.address = "other"
    replica = plugin._deployment_status({"job_id": 1})
    self.assertEqual({row["node_id"]: row["action"] for row in replica["nodes"]}, {
      "A": "stop_report_unavailable", "B": "stop_reported", "C": "waiting_to_start",
    })
    self.assertEqual(plugin.commands, [])

  def test_revision_zero_lookup_checks_owner_without_submission_resource_validation(self):
    plugin = self.prepare()
    plugin.deeploy_check_payment_and_job_owner = Mock(side_effect=AssertionError("submission validator is inappropriate for read auth"))
    result = plugin._deployment_status({"job_id": 1, "nonce": "nonce", "EE_ETH_SIGN": "sig", "EE_ETH_SENDER": "wallet"})
    self.assertEqual((result["status"], result["revision"]), ("not_found", 0))
    envelope = plugin.deeploy_verify_and_get_inputs.call_args.args[0]
    self.assertEqual(set(envelope), {"nonce", "EE_ETH_SIGN", "EE_ETH_SENDER"})
    plugin.bc.get_job_details.return_value = {"escrowOwner": "different-owner"}
    self.assertEqual(plugin._deployment_status({"job_id": 1})["status"], "synchronizing")

  def test_legacy_copy_notice_is_projected_only_after_confirmed_completion(self):
    """Expose only a confirmed credential rotation notice in owner status.

    Returns
    -------
    None

    Examples
    --------
    >>> DeploymentStatusTests("test_legacy_copy_notice_is_projected_only_after_confirmed_completion").run()
    """
    # Check a pending finalization and its subsequent terminal projection.
    plugin = self.prepare()
    # Build an update operation with a durable signed snapshot.
    operation = plugin.operation("update")
    # Custody may succeed before completion of the operation is confirmed.
    operation.update(phase="finalizing", credential_rotation_required=True)
    # Replicate the in-progress snapshot to the status reader.
    plugin._save_operation(operation)
    # A polling owner does not yet receive a rotation notice.
    self.assertNotIn("credential_rotation_required", plugin._deployment_status({"job_id": 1}))
    # The terminal snapshot proves publication and makes the notice available.
    operation["outcome"] = "succeeded"
    # Save completion using the ordinary operation path.
    plugin._save_operation(operation, "completed")
    # This additive response field is the only input the dashboard needs.
    self.assertIs(plugin._deployment_status({"job_id": 1})["credential_rotation_required"], True)

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

  def test_completed_waiting_operation_returns_applied_revision_and_latest_instance_report(self):
    plugin = self.prepare()
    operation = plugin.source_operation()
    operation.update(phase="completed", outcome="waiting_for_source")
    plugin._save_operation(operation)
    for node in operation["nodes"]:
      plugin.report(operation, node, "failed", mode="following", code="WORKLOAD_START_FAILED")
    first = plugin._deployment_status({"job_id": 1})
    self.assertEqual((first["revision"], first["ready_nodes"]), (operation["target_revision"], 0))
    recovered = plugin.report(operation, "B", "ready", sequence=2, mode="following")
    recovered["instances"][0]["runtime_artifacts"] = {"git_commit": "b" * 40}
    latest = plugin._deployment_status({"job_id": 1})
    node = next(node for node in latest["nodes"] if node["node_id"] == "B")
    self.assertEqual((node["report_attempt"], node["report_sequence"]), ("deploy", 2))
    instance = node["instances"][0]
    self.assertEqual((latest["ready_nodes"], instance["source_mode"], instance["runtime_artifacts"]["git_commit"]),
                     (1, "following", "b" * 40))

  def test_polling_checks_source_plan_evidence_for_each_active_node(self):
    plugin = self.prepare()
    op = plugin.source_operation(pinned=True)
    # The signed operation contains the pin projection; another oracle can poll without fetching its plan.
    op["pinned_sources"] = {"deploy": {node: pinned_sources(config) for node, config in plugin.plan["configs"].items()}}
    op["previous_nodes"] = ["retired"]
    plugin._save_operation(op)
    for node, mode, commit in (("A", "pinned", "a"), ("B", "pinned", "b"), ("C", None, "a")):
      report = plugin.report(op, node, "ready", mode=mode)
      report["instances"][0]["runtime_artifacts"] = {"git_commit": commit * 40}
    plugin.r1fs.get_json = Mock(side_effect=AssertionError("Polling must read only local replica records"))
    status = plugin._deployment_status({"operation_id": op["operation_id"]})
    self.assertEqual({node["node_id"]: node["ready"] for node in status["nodes"]},
                     {"A": True, "B": False, "C": False, "retired": False})
    self.assertEqual(status["ready_nodes"], 1)

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
  def test_legacy_order_check_ignores_metadata_permutations_without_editing_the_saved_job(self):
    plugin = Coordinator()
    stored = copy.deepcopy(CONFIG)
    stored["DEEPLOY_SPECS"] = {"job_id": 12, "current_target_nodes": ["A", "B"],
                              "spare_nodes": ["S1", "S2"],
                              "chainstore_response_keys": {"A": ["key1", "key2"]}}
    stored["PLUGINS"][0]["INSTANCES"][0]["BUILD_AND_RUN_COMMANDS"] = ["build", "run"]
    live = copy.deepcopy(stored)
    live["DEEPLOY_SPECS"]["spare_nodes"].reverse()
    live["DEEPLOY_SPECS"]["chainstore_response_keys"]["A"].reverse()

    previous = plugin._previous_deployment_configs(stored, {"A": [live]})
    self.assertEqual(previous, {"A": stored, "B": stored})
    self.assertEqual(stored["DEEPLOY_SPECS"]["spare_nodes"], ["S1", "S2"])
    self.assertEqual(stored["DEEPLOY_SPECS"]["chainstore_response_keys"]["A"], ["key1", "key2"])

    # The same comparator still refuses a reordered command list or an ordered placement.
    for path in ("commands", "targets"):
      with self.subTest(path=path):
        different = copy.deepcopy(live)
        if path == "commands":
          different["PLUGINS"][0]["INSTANCES"][0]["BUILD_AND_RUN_COMMANDS"].reverse()
        else:
          different["DEEPLOY_SPECS"]["current_target_nodes"].reverse()
        with self.assertRaisesRegex(ValueError, "runs this job differently"):
          plugin._previous_deployment_configs(stored, {"A": [different]})

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
    """Only a failed custody call makes an operation wait, also right after such a wait has run out: a final
    write that fails after the custody call succeeded is tried again on every 2 s pass, where a custody wait of
    20 s would have held it back, and its red lines name no custody failure."""
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
    # One pass every 2 s up to 116 s.
    for _ in range(4):
      # One pass.
      plugin._reconcile_coordinator_operations()
      # The worker's 2 s wait.
      plugin.now += 2
    # dAuth was called at 100 s and, after the 10 s wait, at 110 s.
    self.assertEqual(calls, [100, 110])
    # The final write at 110 s, then again on every pass.
    self.assertEqual(writes, [110, 112, 114, 116])
    # The red lines.
    red = [message for message, color in lines if color == "r"]
    # The custody failure and the four failed writes.
    self.assertEqual(len(red), 5)
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
    operation = plugin.source_operation(pinned=True)
    plugin._save_operation(operation)
    plugin._advance_deployment_operation(operation)
    plugin.report(operation, "A", "ready")
    plugin.report(operation, "B", "ready")
    plugin.report(operation, "C", "failed", mode="pinned", code="WORKLOAD_START_FAILED")
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

  def test_unconfirmed_create_stop_blocks_a_new_paid_request_after_expiry(self):
    """Prevent a new create from starting while a previous workload may run.

    Parameters
    ----------
    None
    Returns
    -------
    None
    Examples
    --------
    >>> DeploymentOperationTests('test_unconfirmed_create_stop_blocks_a_new_paid_request_after_expiry').run()
    """
    # Persist a failed paid create with two acknowledged stops and a third worker that never replies.
    plugin = Coordinator()
    operation = plugin.operation()
    operation.update(phase="stopping_failed_rollout", recovery_started_at=plugin.now, recovery="in_progress")
    plugin._save_operation(operation)
    for worker in ("A", "B"):
      plugin.report(operation, worker, "stopped")
    # An expired operation is terminal, but the job remains ineligible for another create without shutdown evidence.
    plugin.now += 25 * plugin.cfg_deployment_readiness_timeout
    plugin._reconcile_coordinator_operations()
    ended = plugin._operation_records()[operation["operation_id"]]
    self.assertEqual((ended["outcome"], ended["unconfirmed_nodes"]), ("failed", ["C"]))
    with self.assertRaisesRegex(DeploymentConflictError, "unconfirmed cleanup"):
      plugin._find_request_operation(dict(request_id="new-request", job_id=1), "owner", "create")

  def test_restore_expiry_names_only_workers_without_ready_evidence(self):
    """Keep restore readiness separate from shutdown evidence at expiry.

    Parameters
    ----------
    None
    Returns
    -------
    None
    Examples
    --------
    >>> DeploymentOperationTests('test_restore_expiry_names_only_workers_without_ready_evidence').run()
    """
    # A prior worker has returned; the second reports no readiness.
    plugin = Coordinator()
    operation = plugin.operation("update")
    operation.update(phase="restoring_previous", restore_deadline=160, recovery="in_progress")
    plugin._save_operation(operation)
    plugin.report(operation, "A", "ready", attempt="restore")
    plugin.now = operation["restore_deadline"] + 24 * plugin.cfg_deployment_readiness_timeout
    plugin._reconcile_coordinator_operations()
    ended = plugin._operation_records()[operation["operation_id"]]
    self.assertEqual((ended["blocked_phase"], ended["unconfirmed_nodes"]), ("restoring_previous", ["B"]))
    self.assertFalse(plugin.commands)
    plugin._commit_operation_revision.assert_not_called()

  def test_restart_with_one_previous_stop_keeps_the_relink_blocked(self):
    # A coordinator can restart after one worker confirmed retirement and the other never answered.
    before = Coordinator()
    operation = before.operation("update")
    operation.update(mutation="node_relink", phase="retiring_previous")
    before._save_operation(operation)
    before.report(operation, "B", "stopped", attempt="retire")
    restarted = Coordinator()
    restarted.storage, restarted.plan = before.storage, before.plan  # Only durable state survives.
    restarted.now = operation["deadline"] + 1
    restarted._reconcile_coordinator_operations()
    saved = restarted._operation_records()[operation["operation_id"]]
    self.assertEqual((saved["phase"], saved["recovery"], saved["error"]["code"]),
                     ("retiring_previous", "blocked", "PREVIOUS_STOP_UNCONFIRMED"))
    self.assertEqual([(node, config["DEEPLOY_OPERATION"]["action"]) for node, config in restarted.commands],
                     [("A", "retire")])
    with self.assertRaises(DeploymentConflictError):
      restarted._assert_no_active_deployment(job_id=operation["job_id"])

  def test_relink_requires_a_stop_for_every_exact_previous_instance(self):
    worker = {"signature": "RUNNER", "instance_id": "worker", "status": "stopped"}
    for instances in ([], [dict(worker, status="starting")], [dict(worker, instance_id="other")],
                      [worker, worker], [worker, dict(worker, instance_id="extra")], [None]):
      with self.subTest(instances=instances):
        plugin = Coordinator()
        operation = plugin.operation("update")
        operation.update(mutation="node_relink", phase="retiring_previous")
        plugin._save_operation(operation)
        plugin.report(operation, "B", "stopped", attempt="retire")
        # Preserve the signed stop from B while A's aggregate conflicts with its instance evidence.
        plugin.report(operation, "A", "stopped", attempt="retire")["instances"] = instances
        plugin._advance_deployment_operation(operation)
        self.assertEqual(operation["phase"], "retiring_previous")
        self.assertEqual([node for node, _ in plugin.commands], ["A"])
        # A later complete receipt unblocks this exact barrier without repeating retirement on B.
        plugin.report(operation, "A", "stopped", attempt="retire", sequence=2)
        plugin._advance_deployment_operation(operation)
        self.assertEqual(operation["phase"], "waiting_for_readiness")

  def test_update_retirement_and_restoration_are_both_barriers(self):
    plugin = Coordinator()
    operation = plugin.source_operation("update", pinned=True, previous_pinned=True)
    plugin._save_operation(operation)
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "retiring_previous")
    self.assertTrue(all(config["DEEPLOY_OPERATION"]["action"] == "retire" for _, config in plugin.commands))
    for node in operation["previous_nodes"]:
      retired = plugin.report(operation, node, "stopped", attempt="retire", mode="pinned")
      retired["instances"][0]["runtime_artifacts"] = {"git_commit": "a" * 40}
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "waiting_for_readiness")
    plugin.report(operation, "C", "failed", mode="pinned", code="WORKLOAD_START_FAILED")
    plugin._advance_deployment_operation(operation)
    for node in operation["nodes"]:
      plugin.report(operation, node, "stopped", sequence=2)
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "restoring_previous")
    plugin._advance_deployment_operation(operation)
    restores = [(node, config) for node, config in plugin.commands if config["DEEPLOY_OPERATION"]["attempt"] == "restore"]
    self.assertEqual([node for node, _ in restores], ["A", "B"])
    for node in operation["previous_nodes"]:
      restored = plugin.report(operation, node, "ready", attempt="restore", mode="pinned")
      restored["instances"][0]["runtime_artifacts"] = {"git_commit": "a" * 40}
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "finalizing_recovery")
    plugin._advance_deployment_operation(operation)
    self.assertEqual((operation["phase"], operation["outcome"], operation["recovery"]), ("completed", "failed", "completed"))

  def test_pinned_ready_requires_requested_worker_commit_on_every_target(self):
    for mode, commit in ((None, "b" * 40), (None, "a" * 40), ("following", "a" * 40),
                         ("pinned", "b" * 40), ("pinned", None), ("pinned", "a" * 40)):
      with self.subTest(mode=mode, commit=commit):
        plugin = Coordinator()
        op = plugin.source_operation(pinned=True)
        plugin._save_operation(op)
        for node in op["nodes"]:
          observed = plugin.report(op, node, "ready", mode=mode if node == "B" else "pinned")
          observed["instances"][0]["runtime_artifacts"] = {"git_commit": commit if node == "B" else "a" * 40}
        reports = plugin._node_operation_reports(op, "deploy")
        accepted = mode == "pinned" and commit == "a" * 40
        self.assertEqual(report_is_ready(reports["B"], plugin.plan["configs"]["B"]), accepted)
        # The early-return dispatch guard must not skip an unverified pinned target.
        plugin._send_operation_commands(op, plugin.plan["configs"], "deploy", "start", reports)
        self.assertEqual([node for node, _ in plugin.commands], [] if accepted else ["B"])
        plugin._advance_deployment_operation(op)
        self.assertEqual(op["phase"], "finalizing" if accepted else "stopping_failed_rollout")
        if mode is None:
          self.assertIn("Update the node", op["error"]["message"])
        plugin._commit_operation_revision.assert_not_called()

  def test_pinned_container_requires_registry_digest_in_its_configured_repository(self):
    digest = "sha256:" + "1" * 64
    for image, server, expected in (
      ("shop/app:v1", "registry.test:5000", "registry.test:5000/shop/app"),
      ("registry.test:5000/shop/app:tag", "registry.test:5000", "registry.test:5000/shop/app"),
      ("docker.io/library/redis:latest", "docker.io", "redis"),
      ("library/redis", "index.docker.io", "redis"),
    ):
      config = {"PLUGINS": [{"SIGNATURE": "CONTAINER_APP_RUNNER", "INSTANCES": [
        {"INSTANCE_ID": "c", "PINNED_VERSION": True, "IMAGE": image, "IMAGE_DIGEST": digest, "CR_DATA": {"SERVER": server}}]}]}
      for artifacts, valid in (({"image_ref": expected + "@" + digest}, True),
                               ({"image_id": digest}, False),
                               ({"image_ref": "wrong.example/shop/app@" + digest}, False),
                               ({"image_ref": expected + "@sha256:" + "2" * 64}, False)):
        with self.subTest(image=image, server=server, artifacts=artifacts):
          report = {"status": "ready", "instances": [{"signature": "CONTAINER_APP_RUNNER", "instance_id": "c",
                    "status": "ready", "source_mode": "pinned", "runtime_artifacts": artifacts}]}
          self.assertEqual(report_is_ready(report, config), valid)

  def test_resumed_finalizing_waits_for_missing_pinned_evidence_before_publication(self):
    plugin = Coordinator()
    op = plugin.source_operation(pinned=True)
    plugin._save_operation(op, "finalizing")
    for node in ("A", "B"):
      report = plugin.report(op, node, "ready", mode="pinned")
      report["instances"][0]["runtime_artifacts"] = {"git_commit": "a" * 40}
    # A replica may lack the latest report when the coordinator restarts.
    plugin._advance_deployment_operation(op)
    self.assertEqual(op["phase"], "waiting_for_readiness")
    self.assertEqual([node for node, _ in plugin.commands], ["C"])
    plugin._commit_operation_revision.assert_not_called()
    report = plugin.report(op, "C", "ready", mode="pinned")
    report["instances"][0]["runtime_artifacts"] = {"git_commit": "a" * 40}
    plugin._advance_deployment_operation(op)
    plugin._advance_deployment_operation(op)
    self.assertEqual(op["outcome"], "succeeded")

  def test_restoration_checks_the_previous_pin_before_committing(self):
    plugin = Coordinator()
    operation = plugin.source_operation("update", pinned=False, previous_pinned=True)
    operation["restore_deadline"] = operation["deadline"]
    plugin._save_operation(operation, "finalizing_recovery")
    for node in operation["previous_nodes"]:
      report = plugin.report(operation, node, "ready", attempt="restore", mode="pinned")
      report["instances"][0]["runtime_artifacts"] = {"git_commit": "b" * 40}
    operation["retired_runtime"] = {node: {"WORKER_APP_RUNNER|worker": {"git_commit": "a" * 40}} for node in operation["previous_nodes"]}
    plugin._advance_deployment_operation(operation)
    self.assertEqual((operation["phase"], operation["recovery"]), ("restoring_previous", "blocked"))
    plugin._commit_operation_revision.assert_not_called()

  def test_following_failure_waits_for_all_nodes_and_commits_target(self):
    plugin = Coordinator()
    operation = plugin.source_operation()
    plugin._save_operation(operation)
    plugin.report(operation, "A", "failed", mode="following", code="WORKLOAD_START_FAILED")
    plugin.report(operation, "B", "ready", mode="following")
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "waiting_for_readiness")
    self.assertEqual([node for node, _ in plugin.commands], ["C"])
    plugin.report(operation, "C", "ready", mode="following")
    plugin._advance_deployment_operation(operation)
    plugin._advance_deployment_operation(operation)
    self.assertEqual((operation["phase"], operation["outcome"], operation["recovery"]),
                     ("completed", "waiting_for_source", None))
    plugin._commit_operation_revision.assert_called_once_with(operation, plugin.plan["configs"])
    plugin._assert_no_active_deployment(job_id=1, app_id="app")

  def test_deadline_keeps_only_reported_following_instances(self):
    for mode, status, code, expired, phase in (
      ("following", "pulling_image", None, True, "finalizing"),
      ("following", "starting", None, True, "finalizing"),
      (None, None, None, True, "stopping_failed_rollout"),
      (None, "starting", None, True, "stopping_failed_rollout"),
      (None, "failed", "WORKLOAD_START_FAILED", False, "stopping_failed_rollout"),
      ("following", "failed", "PLUGIN_INIT_FAILED", False, "stopping_failed_rollout"),
    ):
      with self.subTest(mode=mode, status=status, code=code):
        plugin = Coordinator()
        operation = plugin.source_operation()
        plugin._save_operation(operation)
        plugin.report(operation, "A", "failed", mode="following", code="IMAGE_PULL_FAILED")
        plugin.report(operation, "B", "ready", mode="following")
        if status:
          plugin.report(operation, "C", status, mode=mode, code=code)
        if expired:
          plugin.now = operation["deadline"]
        plugin._advance_deployment_operation(operation)
        self.assertEqual(operation["phase"], phase)
        if status and not mode:
          self.assertIn("Update the node", operation["error"]["message"])

  def test_reported_mode_cannot_override_a_stored_pin_in_a_mixed_stack(self):
    plugin = Coordinator()
    operation = plugin.source_operation()
    for config in plugin.plan["configs"].values():
      config["PLUGINS"][0]["INSTANCES"].append(
        {"INSTANCE_ID": "other", "PINNED_VERSION": True, "VCS_DATA": {"COMMIT": "b" * 40}})
    plugin._save_operation(operation)
    report = plugin.report(operation, "A", "failed", mode="following", code="WORKLOAD_START_FAILED")
    report["instances"].append(dict(report["instances"][0], instance_id="other"))
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "stopping_failed_rollout")

  def test_hard_failure_before_commit_overrides_a_kept_source_failure(self):
    plugin = Coordinator()
    operation = plugin.source_operation()
    plugin._save_operation(operation)
    for node in operation["nodes"]:
      plugin.report(operation, node, "ready", mode="following")
    plugin.report(operation, "B", "failed", mode="following", code="WORKLOAD_UNHEALTHY")
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "finalizing")
    plugin.report(operation, "A", "failed", sequence=2, mode="following", code="PLUGIN_EXECUTION_FAILED")
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "stopping_failed_rollout")
    plugin._commit_operation_revision.assert_not_called()

  def test_offline_following_node_cannot_cross_the_readiness_deadline(self):
    # An authenticated report is insufficient when its node is no longer reachable.
    for status, code in (("starting", None), ("ready", None), ("failed", "WORKLOAD_START_FAILED")):
      with self.subTest(status=status):
        plugin = Coordinator()
        operation = plugin.source_operation("update")
        plugin._save_operation(operation, "waiting_for_readiness")
        for node in ("A", "B"):
          plugin.report(operation, node, "ready", mode="following")
        plugin.report(operation, "C", status, mode="following", code=code)
        plugin.offline.add("C")
        plugin._advance_deployment_operation(operation)
        self.assertEqual(operation["phase"], "waiting_for_readiness")
        plugin.now = operation["deadline"]
        plugin._advance_deployment_operation(operation)
        self.assertEqual(operation["phase"], "stopping_failed_rollout")
        self.assertEqual(operation["error"]["code"], "READINESS_DEADLINE_EXCEEDED")
        plugin._commit_operation_revision.assert_not_called()

  def test_following_node_going_offline_after_barrier_blocks_publication(self):
    plugin = Coordinator()
    operation = plugin.source_operation("update")
    plugin._save_operation(operation, "waiting_for_readiness")
    for node in ("A", "B"):
      plugin.report(operation, node, "ready", mode="following")
    plugin.report(operation, "C", "failed", mode="following", code="WORKLOAD_START_FAILED")
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "finalizing")
    plugin.offline.add("C")
    plugin.now = operation["deadline"]
    plugin._advance_deployment_operation(operation)
    self.assertEqual(operation["phase"], "stopping_failed_rollout")
    plugin._commit_operation_revision.assert_not_called()

  def test_following_owner_transfer_omits_retired_artifacts(self):
    plugin = Coordinator()
    operation = plugin.source_operation("update")
    operation["mutation"] = "owner_transfer"
    for config in plugin.plan["configs"].values():
      config["PLUGINS"][0]["INSTANCES"][0]["DEEPLOY_RUNTIME_ARTIFACTS"] = {"git_commit": "a" * 40}
    plugin._save_operation(operation)
    plugin._send_operation_commands(operation, plugin.plan["configs"], "deploy", "start", {})
    self.assertEqual(len(plugin.commands), len(operation["nodes"]))
    for _, cmd in plugin.commands:
      self.assertNotIn("DEEPLOY_RUNTIME_ARTIFACTS", cmd["PLUGINS"][0]["INSTANCES"][0])

  def test_pinned_update_can_restore_a_following_failure_without_a_retired_binding(self):
    plugin = Coordinator()
    operation = plugin.source_operation("update", pinned=True)
    plugin._save_operation(operation)
    for node in operation["previous_nodes"]:
      plugin.report(operation, node, "stopped", attempt="retire")
    plugin._advance_deployment_operation(operation)
    plugin.report(operation, "A", "failed", mode="pinned", code="WORKLOAD_START_FAILED")
    plugin._advance_deployment_operation(operation)
    for node in operation["nodes"]:
      plugin.report(operation, node, "stopped", sequence=2)
    plugin._advance_deployment_operation(operation)
    plugin._advance_deployment_operation(operation)
    self.assertEqual(len(plugin.commands), len(operation["previous_nodes"]))
    for _, command in plugin.commands:
      self.assertNotIn("DEEPLOY_RUNTIME_ARTIFACTS", command["PLUGINS"][0]["INSTANCES"][0])
    for node in operation["previous_nodes"]:
      plugin.report(operation, node, "failed", attempt="restore", mode="following", code="WORKLOAD_START_FAILED")
    plugin._advance_deployment_operation(operation)
    plugin._advance_deployment_operation(operation)
    self.assertEqual((operation["phase"], operation["outcome"], operation["recovery"]), ("completed", "failed", "completed"))
    plugin._assert_no_active_deployment(job_id=1, app_id="app")

  def test_source_pin_validation_uses_the_final_config_of_each_node(self):
    plugin = Coordinator()
    plugin.source_operation(pinned=True)
    validate_source_pins(plugin.plan["configs"])
    for extra in ({"VCS_DATA": {}}, {"VCS_DATA": {"COMMIT": "A" * 40}},
                  {"VCS_DATA": {"COMMIT": "b" * 40}}, {"PINNED_VERSION": False},
                  {"PINNED_VERSION": 1}, {"IMAGE_DIGEST": "sha256:" + "b" * 64},
                  {"PER_NODE_CONFIG": {"default": {"pinned_version": True}}},
                  {"PER_NODE_CONFIG": {"byIndex": {"1": {"VCS_DATA": {"COMMIT": "a" * 40}}}}}):
      configs = copy.deepcopy(plugin.plan["configs"])
      configs["C"]["PLUGINS"][0]["INSTANCES"][0].update(extra)
      with self.subTest(extra=extra), self.assertRaises(ValueError):
        validate_source_pins(configs)
    for config in plugin.plan["configs"].values():
      config["DEEPLOY_SPECS"]["job_app_type"] = "service"
    with self.assertRaisesRegex(ValueError, "Catalogue"):
      validate_source_pins(plugin.plan["configs"])

  def test_admission_and_resumed_restoration_reject_overlay_runtime_bindings(self):
    plugin = Coordinator()
    op = plugin.source_operation("update", previous_pinned=True)
    config = plugin.plan["previous_configs"]["A"]
    instance = config["PLUGINS"][0]["INSTANCES"][0]
    op["retired_runtime"] = {"A": {"WORKER_APP_RUNNER|worker": {"git_commit": "a" * 40}}}
    for field, override in (("perNodeConfig", {"default": {"DEEPLOY_RUNTIME_ARTIFACTS": {}}}),
                            ("PER_NODE_CONFIG", {"byIndex": {"1": {"Deeploy_Runtime_Artifacts": {}}}}),
                            ("PER_NODE_CONFIG", {"byNode": {"B": {"deeploy_runtime_artifacts": {}}}})):
      with self.subTest(field=field, override=override):
        instance[field] = override
        with self.assertRaisesRegex(ValueError, "system-managed"):
          validate_source_pins({"A": config})
        # Restore of a saved plan has no fresh API request to validate.
        with self.assertRaisesRegex(ValueError, "system-managed"):
          plugin._send_operation_commands(op, {"A": config}, "restore", "start", {})
        self.assertFalse(plugin.commands)
        instance.pop(field)
    instance["PER_NODE_CONFIG"] = {"byNode": {"A": {"ENV": {"ROLE": "replica"}}}}
    plugin._send_operation_commands(op, {"A": config}, "restore", "start", {})
    restored = plugin.commands[0][1]["PLUGINS"][0]["INSTANCES"][0]
    self.assertEqual(restored["DEEPLOY_RUNTIME_ARTIFACTS"], {"git_commit": "a" * 40})

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
      config = {"NAME": "app", "TYPE": "Void", "DEEPLOY_SPECS": {"job_app_type": "service"}, "PLUGINS": [{"SIGNATURE": signature, "INSTANCES": [{"INSTANCE_ID": "worker"}]}]}
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
      config = {"NAME": "app", "TYPE": "Void", "DEEPLOY_SPECS": {"job_app_type": "service"}, "PLUGINS": [{"SIGNATURE": signature, "INSTANCES": [{"INSTANCE_ID": "worker"}]}]}
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

  def test_a_late_pass_does_not_hold_back_a_send(self):
    """A late pass holds no send of a completed operation back: a first pass 35 s after completion sends at once,
    as before, and from 600 s on the sends fall on fixed ages after completion, not on the time since the last send:
    a send made late for the age 1,200 s, 20 s before the age 2,400 s, is followed by the send of that age."""
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
    # A pass at completion, the next one 35 s later, one 20 s before the age 2,400 s, and one at that age.
    for age in (0, 35, 2380, 2400):
      # The pass at this age.
      plugin.now = operation["updated_at"] + age
      # One pass.
      plugin._reconcile_coordinator_operations()
    # Sent at 35 s, at 2,380 s for the ages 600 and 1,200 s, and again at 2,400 s.
    self.assertEqual(sent, [35, 2380, 2400])

  def test_restarts_keep_each_operation_on_its_own_ages(self):
    """A restart in an operation's first 600 s sends it at once and every 30 s from then, as before, and keeps its
    age 600 s; restarts every 1,700 s after that, closer together than the later gaps, neither send at once nor
    move the sends: two operations completed 1,000 s apart are each sent at their own ages after completion and
    at no other time, and a restart more than 24 h after completion keeps no entry for them."""
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
    # after the first completion; a restart 310 s after the second completion, and one every 1,700 s from 850 s
    # after it, none on an age.
    for now in range(completed[second], completed[first] + 87500, 10):
      # The pass at this time.
      plugin.now = now
      # Seconds since the second completion.
      since = now - completed[second]
      if since == 310 or (since >= 850 and (since - 850) % 1700 == 0):
        # A restart: the maps kept in process memory start empty, as _init_deployment_operations leaves them.
        plugin._operations_confirmed, plugin._operations_repaired = {}, {}
      # One pass.
      plugin._reconcile_coordinator_operations()
    # The first operation, 1,000 s old at the first pass, is sent at each later age of its schedule and only then.
    self.assertEqual([age for operation_id, age in sent if operation_id == first],
                     [age for age in REPAIR_SCHEDULE if age > 1000])
    # The second, seen at its completion: every 30 s up to 300 s, at the restart 310 s and every 30 s from there,
    # then at every age of its schedule from 600 s, and only then.
    self.assertEqual([age for operation_id, age in sent if operation_id == second],
                     list(range(30, 330, 30)) + list(range(310, 600, 30)) + REPAIR_SCHEDULE[19:])
    # A restart more than 24 h after both completions.
    plugin._operations_confirmed, plugin._operations_repaired = {}, {}
    # One pass after it.
    plugin._reconcile_coordinator_operations()
    # Neither operation is kept in the schedule's map any more.
    self.assertEqual(plugin._operations_repaired, {})

  def test_a_final_snapshot_never_confirmed_is_logged_the_same_before_and_after_a_restart(self):
    """A final snapshot that other oracles never confirmed is sent again on every pass in its first 600 s, as
    before, then at each age of the schedule only, and each such send leaves one red line, the same before a
    restart and after it, in the first 600 s and later."""
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
    # One pass every 2 s for 1,300 s after completion, with restarts 300 and 700 s after completion.
    for now in range(completion, completion + 1300, 2):
      # The pass at this time.
      plugin.now = now
      if now - completion in (300, 700):
        # A restart: the maps kept in process memory start empty, as _init_deployment_operations leaves them.
        plugin._operations_confirmed, plugin._operations_repaired = {}, {}
      # One pass.
      plugin._reconcile_coordinator_operations()
    # Sent on every pass up to 598 s, across the restart at 300 s, then at the age 600 s and, after the restart at
    # 700 s, at the age 1,200 s; each send is one red line.
    self.assertEqual((sent, red), (list(range(0, 600, 2)) + [600, 1200],) * 2)


if __name__ == "__main__":
  unittest.main()
