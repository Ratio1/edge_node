"""Replay interrupted retirement and its linked, CSP-approved successor using disposable identities."""

import copy
import hashlib
import json
import unittest
from unittest.mock import Mock

from extensions.business.deeploy.job_repair import _JobRepairMixin, MUTATION, order_fields, worker
from extensions.business.deeploy.deployment_operations import NODE_OPERATIONS_HKEY, DeploymentConflictError
from extensions.business.deeploy.tests.lifecycle_custody_support import Coordinator, Custodian, Engine, State, connect, report


class RepairCoordinator(_JobRepairMixin, Coordinator):
  pass


class RepairTests(unittest.TestCase):
  def setUp(self):
    self.state = State()
    self.c = RepairCoordinator(self.state)
    self.dauth = Custodian(self.state)
    self.http = connect(self, self.state, self.dauth)
    self.job = dict(escrowOwner="owner", numberOfNodesRequested=2, activeNodes=["0xoldA", "0xoldB"])
    self.stored = dict(NAME="app", OWNER="owner", TYPE="void",
                       DEEPLOY_SPECS=dict(current_target_nodes=["oldA", "oldB"], job_id=31),
                       PLUGINS=[dict(SIGNATURE="WORKER_APP_RUNNER", INSTANCES=[dict(
                         INSTANCE_ID="worker", BUILD_AND_RUN_COMMANDS=["serve", "setup"],
                         CHAINSTORE_PEERS=["oldA", "oldB"], VCS_DATA=dict(REPO_OWNER="owner", REPO_NAME="repo"),
                         ENV={"CF_TUNNEL_TOKEN": "fixture-credential"})])])
    self.cid = self.state.blobs.add_json(self.stored)
    self.state.public["DEEPLOY_DEPLOYED_JOBS", "31"] = self.cid
    self.live = copy.deepcopy(self.stored)
    for values in order_fields(self.live).values():
      values.reverse()  # Both workers originally ran the same order. B's pipeline has already been removed.
    self.configure(self.c)
    self.configure(self.dauth)
    self.c.known = {"newA": [self.live]}
    self.oid = hashlib.sha256(b"oracle").hexdigest()[:16] + "-" + "f"*32
    self.parent = dict(operation_id=self.oid, kind="update", mutation="node_relink", request_id="automatic",
                       request_hash="parent-request", job_id=31, app_id="app", owner="owner", network="test",
                       coordinator="oracle", target_revision=1, previous_revision=0, previous_operation_id=None,
                       previous_secret_revision=None, previous_pipeline_cid=self.cid, plan_cid="parent-plan",
                       nodes=["oldA", "newB"], previous_nodes=["oldA", "newB"], phase="retiring_previous",
                       outcome=None, recovery="blocked", error=dict(code="PREVIOUS_STOP_UNCONFIRMED"),
                       deadline=999, updated_at=999, created_at=900, sequence=3, events=[], sent_at={})
    self.parent["previous_instances"] = self.parent["instances"] = {node: [["WORKER_APP_RUNNER", "worker"]]
                                                                   for node in self.parent["nodes"]}
    self.c._save_operation(self.parent)
    self.receipt(self.parent, "newB", "retire", "stopped", "b"*40)
    self.c.cmdapi_start_pipeline = self.transport
    self.c.requests = Mock()

  def configure(self, plugin):
    plugin.engine.web3_get_job_details = lambda job_id: self.job
    plugin.bc.encrypt_str = lambda fingerprint, node: "disposable-ciphertext-" + node
    plugin.engine.web3_is_node_licensed = lambda address, **kw: address.lower() in ("0xnewa", "0xnewb")
    plugin.bc.get_node_license_info = lambda node_address_eth, **kw: dict(
      nodeAddress=node_address_eth, licenseId=1 if node_address_eth.lower().endswith("a") else 2, owner="license-owner",
      isValid="new" in node_address_eth.lower())
    plugin.bc.eth_addr_to_internal_addr = lambda value: value.removeprefix("0x")
    plugin.plugins_shmem = {"CHAIN_DIST_CONFIRMED_RELINKS": {
      "0xoldA": ("0xnewA", 1, "license-owner"), "0xoldB": ("0xnewB", 2, "license-owner")}}
    plugin._verify_repair_source = Mock()  # This test isolates lifecycle/custody from the external Git host.

  def receipt(self, operation, node, attempt, status, commit, **fields):
    value = dict(operation_id=operation["operation_id"], app_id="app", coordinator="oracle", node_addr=node,
                 job_id=31, revision=0, sequence=1, attempt=attempt, status=status, updated_at=self.state.now,
                 instances=[dict(signature="WORKER_APP_RUNNER", instance_id="worker", status=status,
                                 runtime_artifacts=dict(git_commit=commit))], **fields)
    Engine(node).sign(value)
    self.state.public[NODE_OPERATIONS_HKEY, operation["operation_id"] + "|" + attempt + "|" + node] = value
    return value

  def transport(self, config, node_address):
    self.c.commands.append((node_address, copy.deepcopy(config)))
    meta = config["DEEPLOY_OPERATION"]
    if meta["action"] == "inspect_worker_v1":
      if meta.get("confirm_prior_stop"):
        self.receipt(meta, node_address, "inspect", "observed", "b"*40, challenge=meta["challenge"],
                     confirm_prior_stop=True, expires_at=meta["expires_at"])
        return
      lists = list(order_fields(self.live).values())
      digest = hashlib.sha256(json.dumps(lists, separators=(",", ":")).encode()).hexdigest()
      self.receipt(meta, node_address, "inspect", "observed", "a"*40, challenge=meta["challenge"],
                   order_digest=digest, expires_at=meta["expires_at"],
                   config_seal_hash=hashlib.sha256(meta["config_seal"].encode()).hexdigest())
    elif meta["action"] == "retire_worker_v1":
      self.receipt(meta, node_address, "retire", "stopped", "a"*40, challenge=meta["challenge"],
                   order_digest=meta["order_digest"], parent_operation_id=self.oid,
                   config_seal_hash=hashlib.sha256(meta["config_seal"].encode()).hexdigest())

  def admit(self):
    proposal, corrected, *_ = self.c._assess_job_repair(31, "owner")
    self.assertEqual(proposal["orders"], dict(targets=[1, 0], commands=[1, 0], peers=[1, 0]))
    self.assertEqual(self.c.commands, [])
    targets = [row["current"] for row in proposal["placements"]]
    request = dict(request_id="signed-edit", job_id=31, app_id="app", expected_revision=0, target_nodes=targets,
                   repair=dict(proposal=proposal, same_host=True, rotate_main_tunnel=False))
    repair = self.c._prepare_job_repair(request, "owner")
    desired = copy.deepcopy(corrected)
    desired["DEEPLOY_SPECS"]["current_target_nodes"] = targets
    worker(desired).update(BUILD_AND_RUN_COMMANDS=["setup", "serve-updated"], CHAINSTORE_PEERS=targets)
    accepted = self.c._admit_prepared_deployment(request, {"escrow_owner": "owner"}, "app",
                    {node: desired for node in targets}, self.stored, False, mutation=MUTATION, repair=repair)
    records = self.c._operation_records()
    self.assertEqual(records[self.oid]["phase"], "holding_for_repair")
    self.assertEqual(records[accepted["operation_id"]]["phase"], "repair_v1_accepted")
    return records[accepted["operation_id"]]

  def test_same_host_repair_preserves_stop_and_restores_exact_previous_execution_after_failure(self):
    child = self.admit()
    self.c._advance_serialized_operation(copy.deepcopy(self.parent))  # A stale reconciler cannot revive the old plan.
    self.c._advance_deployment_operation(child)
    self.assertEqual([node for node, config in self.c.commands if config["DEEPLOY_OPERATION"]["action"].startswith("retire")],
                     ["newA"])
    # Lose every in-memory marker between retire and STOP processing.
    previous_commands = self.c.commands
    self.c = RepairCoordinator(self.state)
    self.configure(self.c)
    self.c.cmdapi_start_pipeline = self.transport
    child = self.c._operation_records()[child["operation_id"]]
    self.c._advance_deployment_operation(child)
    self.assertEqual(child["phase"], "repair_v1_waiting_for_readiness")
    self.assertEqual(child["retired_runtime"]["newB"]["WORKER_APP_RUNNER|worker"]["git_commit"], "b"*40)
    self.c._advance_deployment_operation(child)
    starts = [(node, config["DEEPLOY_OPERATION"]) for node, config in self.c.commands]
    self.assertCountEqual([(node, op["action"], op["parent_operation_id"]) for node, op in starts],
                          [(node, "start_repaired_worker_v1", self.oid) for node in ("newA", "newB")])
    report(self.state, child, "deploy", "failed")
    self.c._advance_deployment_operation(child)
    report(self.state, child, "deploy", "stopped")
    self.c._advance_deployment_operation(child)
    self.c._advance_deployment_operation(child)
    restores = [(node, config) for node, config in self.c.commands if config["DEEPLOY_OPERATION"]["attempt"] == "restore"]
    self.assertCountEqual([node for node, _ in restores], ["newA", "newB"])
    for node, cfg in restores:
      self.assertEqual(worker(cfg)["BUILD_AND_RUN_COMMANDS"], ["setup", "serve"])
      self.assertEqual(worker(cfg)["DEEPLOY_RUNTIME_ARTIFACTS"]["git_commit"], ("a" if node == "newA" else "b")*40)
    report(self.state, child, "restore", "ready")
    self.c._advance_deployment_operation(child)
    self.c._advance_deployment_operation(child)
    self.assertEqual((child["phase"], child["outcome"], child["recovery"]), ("completed", "failed", "completed"))
    self.c._advance_serialized_operation(self.c._operation_records()[self.oid])
    self.assertEqual(self.c._operation_records()[self.oid]["outcome"], "superseded")
    self.assertTrue(all(node in ("newA", "newB") for node, _ in previous_commands + self.c.commands))

  def test_expired_repair_without_dispatched_retirement_releases_parent(self):
    child = self.admit()
    self.state.now = max(child["preparation_deadline"], child["deadline"]) + 1
    self.c.commands.clear()
    self.c._advance_deployment_operation(child)
    self.assertEqual((child["phase"], child["error"]["code"]), ("completed", "ADMISSION_PREPARATION_FAILED"))
    self.assertEqual(self.c.commands, [])
    self.c._advance_serialized_operation(self.c._operation_records()[self.oid])
    parent = self.c._operation_records()[self.oid]
    self.assertEqual(parent["phase"], "retiring_previous")
    self.assertNotIn("repair_child", parent)

  def test_success_only_publishes_after_both_current_workers_report_ready(self):
    child = self.admit()
    for _ in range(3):
      self.c._advance_deployment_operation(child)
    report(self.state, child, "deploy", "ready")
    self.c._advance_deployment_operation(child)
    self.c._advance_deployment_operation(child)
    self.assertEqual((child["phase"], child["outcome"]), ("completed", "succeeded"))
    pointer = self.state.public["DEEPLOY_DEPLOYED_JOBS", "31"]
    committed = self.state.blobs.get_json(pointer["pipeline_cid"])
    self.assertEqual(worker(committed)["BUILD_AND_RUN_COMMANDS"], ["setup", "serve-updated"])
    self.assertEqual(committed["DEEPLOY_SPECS"]["current_target_nodes"], ["newB", "newA"])

  def test_changed_authority_blocks_deploy_and_restore_starts_after_retirement(self):
    child = self.admit()
    for _ in range(2):
      self.c._advance_deployment_operation(child)
    self.job["escrowOwner"] = "new-owner"
    count = len(self.c.commands)
    with self.assertRaises(DeploymentConflictError):
      self.c._advance_deployment_operation(child)
    self.assertEqual(len(self.c.commands), count)
    self.job["escrowOwner"] = "owner"
    self.c._advance_deployment_operation(child)
    report(self.state, child, "deploy", "failed")
    self.c._advance_deployment_operation(child)
    report(self.state, child, "deploy", "stopped")
    self.c._advance_deployment_operation(child)
    self.job["activeNodes"] = ["0xoldA", "0xother"]
    count = len(self.c.commands)
    with self.assertRaises(DeploymentConflictError):
      self.c._advance_deployment_operation(child)
    self.assertEqual(len(self.c.commands), count)

  def test_conflicting_fresh_local_stop_blocks_before_custody_or_retirement(self):
    respond = self.c.cmdapi_start_pipeline
    def changed_stop(config, node_address):
      respond(config, node_address)
      meta = config["DEEPLOY_OPERATION"]
      if meta.get("confirm_prior_stop"):
        self.receipt(meta, node_address, "inspect", "observed", "c"*40, challenge=meta["challenge"],
                     confirm_prior_stop=True, expires_at=meta["expires_at"])
    self.c.cmdapi_start_pipeline = changed_stop
    with self.assertRaisesRegex(ValueError, "local Git receipt changed"):
      self.admit()
    self.assertEqual(set(self.c._operation_records()), {self.oid})
    self.assertTrue(all(cfg["DEEPLOY_OPERATION"]["action"] == "inspect_worker_v1" for _, cfg in self.c.commands))
    self.http.assert_not_called()

  def test_progress_uses_original_stop_at_its_actual_signer(self):
    child = self.admit()
    self.c._advance_deployment_operation(child)
    self.state.public.pop((NODE_OPERATIONS_HKEY, child["operation_id"]+"|retire|newA"))
    self.c.deeploy_verify_and_get_inputs = lambda *args, **kwargs: ("owner", {})
    self.c.deeploy_get_auth_result = lambda inputs: {"escrow_owner": "owner"}
    progress = self.c._deployment_status({"operation_id": child["operation_id"]})
    self.assertEqual({row["node_id"]: row["action"] for row in progress["nodes"]},
                     {"newA": "awaiting_stop_report", "newB": "stop_reported"})
    self.assertEqual((progress["target_nodes"], progress["ready_nodes"]), (2, 0))

  def test_one_time_runtime_commands_cannot_be_replayed_on_repair_or_restore(self):
    for location in ("pipeline", "instance"):
      config = copy.deepcopy(self.stored)
      if location == "pipeline":
        config["PIPELINE_COMMAND"] = {"COMMAND": "pause"}
      else:
        worker(config)["INSTANCE_COMMAND"] = {"COMMAND": "pause"}
      with self.assertRaisesRegex(ValueError, "one-time"):
        worker(config)

  def test_finalization_rechecks_paid_placement_and_accepts_own_committed_retry(self):
    child = self.admit()
    for _ in range(3):
      self.c._advance_deployment_operation(child)
    report(self.state, child, "deploy", "ready")
    self.c._advance_deployment_operation(child)
    self.job["numberOfNodesRequested"] = 1
    with self.assertRaises(DeploymentConflictError):
      self.c._advance_deployment_operation(child)
    self.assertEqual(self.c._get_pipeline_from_cstore(31), self.cid)
    self.job["numberOfNodesRequested"] = 2
    # Simulate a confirmed publication followed by a crash before the child's completion is saved.
    self.c._commit_operation_revision(child, self.c._load_operation_plan(child)["configs"])
    self.c._advance_deployment_operation(child)
    self.assertEqual((child["phase"], child["outcome"]), ("completed", "succeeded"))

  def test_changed_command_unknown_worker_and_stale_pointer_cannot_be_reviewed(self):
    worker(self.live)["BUILD_AND_RUN_COMMANDS"][1] = "changed"
    with self.assertRaisesRegex(ValueError, "changed entries"):
      self.c._assess_job_repair(31, "owner")
    self.c.known["unpaid-extra"] = [self.live]
    with self.assertRaisesRegex(ValueError, "additional node"):
      self.c._assess_job_repair(31, "owner")
    self.state.public["DEEPLOY_DEPLOYED_JOBS", "31"] = "newer-cid"
    with self.assertRaises(DeploymentConflictError):
      self.c._assess_job_repair(31, "owner")
    self.assertEqual(self.c.commands, [])
    self.http.assert_not_called()

  def test_between_writes_crash_has_one_recoverable_child_and_never_retires_from_the_parent(self):
    # Simulate child already saved but no held parent persisted before process exit.
    proposal, _, _, _, licenses = self.c._assess_job_repair(31, "owner")
    recovery = dict(proposal=proposal, aliases={row["previous"]: row["current"] for row in proposal["placements"]},
                    licenses=licenses)
    child = dict(self.parent, operation_id=hashlib.sha256(b"oracle").hexdigest()[:16]+"-"+"1"*32,
                 mutation=MUTATION, repair_parent=proposal["parent"], target_revision=2, phase="repair_v1_preparing",
                 request_id="edit", request_hash="same-intent", sequence=0,
                 repair_aliases=list(map(list, recovery["aliases"].items())), repair_licenses=licenses)
    self.c._save_operation(child)
    same = self.c._hold_repair_parent(dict(child, operation_id=child["operation_id"]+"r"), recovery)
    self.assertEqual(same["operation_id"], child["operation_id"])
    with self.assertRaises(DeploymentConflictError):
      self.c._hold_repair_parent(dict(child, request_id="different", request_hash="other-intent"), recovery)
    self.c._advance_serialized_operation(self.parent)
    latest = self.c._operation_records()
    self.assertEqual(len(latest), 2)
    self.assertEqual(latest[self.oid]["repair_child"]["operation_id"], child["operation_id"])
    self.assertEqual(latest[self.oid]["phase"], "holding_for_repair")
    self.assertEqual(self.c.commands, [])

  def test_delayed_original_stop_is_honored_after_a_renewal(self):
    child = self.admit()
    self.c._advance_deployment_operation(child)
    # The first retire was actually delivered; delay just that report in the replica.
    key = (NODE_OPERATIONS_HKEY, child["operation_id"]+"|retire|newA")
    delayed = self.state.public.pop(key)
    self.state.now += 115
    self.c._advance_deployment_operation(child)  # Non-blocking inspection renewal.
    self.state.now += 11
    self.c._advance_deployment_operation(child)
    self.assertEqual(len(child["retire_challenges"]["newA"]), 2)
    self.state.public[key] = delayed
    self.c._advance_deployment_operation(child)
    self.assertEqual(child["phase"], "repair_v1_waiting_for_readiness")
    self.assertEqual(child["retired_runtime"]["newA"]["WORKER_APP_RUNNER|worker"]["git_commit"], "a"*40)

  def test_sensitive_drift_and_file_volumes_are_refused_before_worker_commands(self):
    worker(self.live)["ENV"]["CF_TUNNEL_TOKEN"] = "different-fixture"
    with self.assertRaisesRegex(ValueError, "outside the reviewed order"):
      self.c._assess_job_repair(31, "owner")
    worker(self.live)["ENV"]["CF_TUNNEL_TOKEN"] = "fixture-credential"
    worker(self.live)["FILE_VOLUMES"] = {"state": {"content": "x"}}
    with self.assertRaisesRegex(ValueError, "persistent volumes"):
      self.c._assess_job_repair(31, "owner")
    self.assertEqual(self.c.commands, [])
    self.http.assert_not_called()
