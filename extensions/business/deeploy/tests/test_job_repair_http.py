"""Exercise the CSP's public Deeploy handlers with real update planning and repair custody."""

import copy
import unittest
from types import SimpleNamespace

from eth_account import Account
from eth_account.messages import encode_defunct
from naeural_core.utils.fastapi_utils import PostponedRequest
from naeural_core.utils.plugins_base.plugin_base_utils import NestedDotDict
from web3 import Web3

from extensions.business.deeploy.repair_relay import _RELAY_KEY
from extensions.business.deeploy.tests import test_update_requests as updates
from extensions.business.deeploy.tests import test_job_repair as lifecycle
from extensions.business.deeploy.tests.lifecycle_custody_support import report
from extensions.business.deeploy.tests.support import make_inputs
from extensions.business.deeploy.tests.test_same_host_repair_custody import connector


class JobRepairHttpTests(unittest.TestCase):
  def setUp(self):
    # Use the same isolated chain, repositories, signed reports and dAuth SDK/service as the lifecycle replay.
    self.replay = lifecycle.RepairTests()
    self.addCleanup(self.replay.doCleanups)
    self.replay.setUp()
    coordinator = self.replay.c
    live = self.replay.live
    # The saved legacy config used the original main token field. The current editor writes both main-port aliases.
    for config in (self.replay.stored, live):
      config["DEEPLOY_SPECS"]["project_id"] = "project"  # The dApp signs the persisted project context.
      lifecycle.worker(config).update(PORT=8080, TUNNEL_ENGINE="cloudflare", TUNNEL_ENGINE_ENABLED=True,
                                      CLOUDFLARE_TOKEN=connector("a"))
    self.replay.cid = self.replay.state.blobs.add_json(self.replay.stored)
    self.replay.state.public["DEEPLOY_DEPLOYED_JOBS", "31"] = self.replay.cid
    self.replay.parent["previous_pipeline_cid"] = self.replay.cid
    coordinator._save_operation(self.replay.parent)
    instance = lifecycle.worker(live)
    self.api, _ = updates.DeeployUpdateRequestPreparationTests()._make_process_update_plugin([])
    # Keep ordinary discovery, normalization, fixed target ordering and capacity selection in the tested path.
    for name in ("_gather_running_pipeline_context", "_normalize_plugins_input", "_extract_pipeline_params",
                 "_check_nodes_availability"):
      delattr(self.api, name)
    self.api._get_online_apps = lambda **kwargs: {"newA": {"app": {
      "deeploy_specs": copy.deepcopy(live["DEEPLOY_SPECS"]),
      "plugins": {"WORKER_APP_RUNNER": [{"instance": instance["INSTANCE_ID"], "instance_conf": copy.deepcopy(instance)}]},
    }}}
    self.api.netmon = SimpleNamespace(network_node_is_supervisor=lambda addr: False)
    self.api._netmon_node_is_online_for_control = lambda node: node in ("newA", "newB")
    self.api.check_node_available_resources = lambda node, inputs: {"status": True}
    # Replace the preparation fixture's admission recorder with the coordinator implementing the actual durable protocol.
    for name in ("_operation_records", "_find_request_operation", "_assess_job_repair", "_prepare_job_repair",
                 "_admit_prepared_deployment", "_accepted_operation_response", "get_job_pipeline_from_cstore"):
      setattr(self.api, name, getattr(coordinator, name))
    self.api.bc = coordinator.bc
    self.domains = []
    def verify(request, request_type):
      self.domains.append(request_type)
      return "owner", make_inputs(**copy.deepcopy(request))
    self.api.deeploy_verify_and_get_inputs = verify
    self.api.deeploy_get_auth_result = lambda inputs: {"escrow_owner": "owner", "sender": "owner", "sender_escrow": "escrow"}
    self.read = dict(nonce="0x1", EE_ETH_SENDER="owner", EE_ETH_SIGN="fixture", EE_HASH="signed-preview",
                     job_id=31, coordinator="oracle")

  def reviewed_update(self):
    status = self.api.get_job_repair_preview(self.read)
    self.assertEqual(status["status"], "reviewable", status)
    self.assertEqual(self.replay.c.commands, [], "read-only preview must never contact a worker")
    self.assertNotIn(connector("a"), str(status))
    proposal = status["proposal"]
    self.assertEqual(proposal["orders"], dict(targets=[1, 0], commands=[1, 0], peers=[1, 0]))
    targets = [row["current"] for row in proposal["placements"]]
    self.assertEqual(targets, ["newB", "newA"])
    # Output of dApp formatGenericJobPayload for a public Git worker, plus its signed update envelope.
    resources = dict(cpu=0.25, memory="512m", storage="2g")
    plugin = dict(instance_id="worker", plugin_signature="WORKER_APP_RUNNER", CONTAINER_RESOURCES=resources,
                  PORT=8080, TUNNEL_ENGINE="cloudflare", TUNNEL_ENGINE_ENABLED=True, CLOUDFLARE_TOKEN=connector("b"),
                  EXPOSED_PORTS={"8080": dict(is_main_port=True, token=connector("b"), protocol="http", engine="cloudflare")},
                  ENV={"CF_TUNNEL_TOKEN": "fixture-credential"}, DYNAMIC_ENV={}, VOLUMES={},
                  FILE_VOLUMES={}, FIXED_SIZE_VOLUMES={}, RESTART_POLICY="always", IMAGE_PULL_POLICY="always",
                  IMAGE="node:22", BUILD_AND_RUN_COMMANDS=["setup", "serve-updated"],
                  VCS_DATA=dict(REPO_URL="https://github.com/owner/repo", USERNAME=None, TOKEN=None, BRANCH="main"))
    return dict(app_alias="app", project_id="project", app_id="app", job_id=31, job_app_type="generic", nonce="0x1",
                request_id="wallet-edit", expected_revision=0, target_nodes=targets, spare_nodes=[],
                allow_replication_in_the_wild=False, target_nodes_count=0, job_tags=[], node_res_req=resources,
                plugins=[plugin], pipeline_input_type="void", pipeline_input_uri=None, chainstore_response=True,
                secret_paths=[], EE_HASH="hash", EE_ETH_SENDER="owner", EE_ETH_SIGN="fixture",
                repair=dict(proposal=proposal, same_host=True, rotate_main_tunnel=True))

  def test_public_edit_admits_ordered_worker_and_preserves_old_stop(self):
    request = self.reviewed_update()
    result = self.api.repair_update_pipeline(copy.deepcopy(request))
    self.assertEqual((result["status_code"], result["status"]), (202, "accepted"), result)
    self.assertEqual(self.domains, ["get job repair preview", "repair update pipeline"])
    # A lost response resends the original envelope. Its operation and the worker inspection remain singletons.
    inspections = list(self.replay.c.commands)
    retry = self.api.repair_update_pipeline(copy.deepcopy(request))
    self.assertEqual((retry["status_code"], retry.get("operation_id")), (202, result["operation_id"]), retry)
    self.assertEqual(self.replay.c.commands, inspections)
    child = self.replay.c._operation_records()[result["operation_id"]]
    plan = self.replay.c._load_operation_plan(child)
    self.assertEqual(self.replay.c._operation_records()[self.replay.oid]["phase"], "holding_for_repair")
    self.assertEqual(child["nodes"], request["target_nodes"])
    for node in child["nodes"]:
      config, previous = plan["configs"][node], plan["previous_configs"][node]
      self.assertEqual(config["DEEPLOY_SPECS"]["current_target_nodes"], request["target_nodes"])
      self.assertEqual(lifecycle.worker(config)["CHAINSTORE_PEERS"], request["target_nodes"])
      self.assertEqual(lifecycle.worker(config)["INSTANCE_ID"], "worker")
      self.assertEqual(lifecycle.worker(config)["BUILD_AND_RUN_COMMANDS"], ["setup", "serve-updated"])
      self.assertEqual(lifecycle.worker(previous)["BUILD_AND_RUN_COMMANDS"], ["setup", "serve"])
      # Only the custodian can read the retained rollback credential, including after the previous token was rotated.
      restore_id = child["operation_id"] + ":repair_v1:restore"
      secrets = self.replay.dauth._load_revision_runner_secret_bundle("31", restore_id, node)["job_secrets"]
      self.assertEqual(secrets["PLUGINS"][0]["INSTANCES"][0]["CLOUDFLARE_TOKEN"], connector("b"))
    self.assertTrue(self.replay.http.called, "acceptance must pass through dAuth custody")
    self.replay.c._advance_deployment_operation(child)
    retires = [node for node, cfg in self.replay.c.commands if cfg["DEEPLOY_OPERATION"]["action"] == "retire_worker_v1"]
    self.assertEqual(retires, ["newA"], "newB already supplied a signed stop for its old workload")

  def replacement_request(self, mixed=False):
    request = self.reviewed_update()
    if mixed:
      # Exercise a saved native pipeline with the same identities in the ordinary wallet-edit payload.
      for config in (self.replay.stored, self.replay.live):
        config["DEEPLOY_SPECS"]["job_app_type"] = "native"
        config["PLUGINS"].append(dict(SIGNATURE="NATIVE_FIXTURE", INSTANCES=[dict(INSTANCE_ID="native")]))
      self.replay.cid = self.replay.state.blobs.add_json(self.replay.stored)
      self.replay.state.public["DEEPLOY_DEPLOYED_JOBS", "31"] = self.replay.cid
      parent = self.replay.parent
      parent["previous_pipeline_cid"] = self.replay.cid
      parent["instances"] = parent["previous_instances"] = {
        node: [["WORKER_APP_RUNNER", "worker"], ["NATIVE_FIXTURE", "native"]] for node in parent["nodes"]
      }
      self.replay.c._save_operation(parent)
      request["job_app_type"] = "native"
      request["plugins"].append(dict(instance_id="native", plugin_signature="NATIVE_FIXTURE"))
    self.replay.c.commands.clear()
    self.replay.c.plugins_shmem.clear()  # No historical relink data is needed for stateless replacement.
    self.replay.state.public.pop((lifecycle.NODE_OPERATIONS_HKEY, self.replay.oid + "|retire|newB"))
    for name in ("_stateless_replacement_proposal", "_prepare_stateless_replacement", "_get_pipeline_from_cstore"):
      setattr(self.api, name, getattr(self.replay.c, name))
    self.api._job_reports = self.replay.c._job_reports
    self.api.get_pipeline_from_r1fs = self.replay.state.blobs.get_json
    self.replay.c.get_pipeline_from_r1fs = self.replay.state.blobs.get_json
    preview = dict(self.read, replace_stateless=True)
    preview.pop("coordinator")  # The balanced ingress chooses the existing operation owner.
    status = self.api.get_job_repair_preview(preview)
    self.assertEqual(status["status"], "reviewable", status)
    request["repair"] = dict(replace_stateless=True, accept_unconfirmed_stop=True, proposal=status["proposal"])
    request["plugins"][0]["BUILD_AND_RUN_COMMANDS"] = ["build replacement", "serve replacement"]
    return request

  def test_stateless_replacement_edits_and_deploys_without_relations_or_stop_proof(self):
    request = self.replacement_request()
    result = self.api.repair_update_pipeline(copy.deepcopy(request))
    self.assertEqual(result.get("status_code"), 202, result)
    child = self.replay.c._operation_records()[result["operation_id"]]
    self.assertEqual(child["previous_nodes"], [])
    self.assertEqual(child["unconfirmed_previous_nodes"], ["newA", "newB", "oldA", "oldB"])
    self.assertEqual(self.replay.c._operation_records()[self.replay.oid]["phase"], "holding_for_repair")
    for node in child["nodes"]:
      secrets = self.replay.dauth._load_revision_runner_secret_bundle(
        "31", child["operation_id"] + ":deploy", node,
      )["job_secrets"]
      self.assertEqual(secrets["PLUGINS"][0]["INSTANCES"][0]["CLOUDFLARE_TOKEN"], connector("b"))
    self.replay.c._advance_serialized_operation(copy.deepcopy(self.replay.parent))
    self.replay.c._advance_deployment_operation(child)
    self.assertEqual({node for node, _ in self.replay.c.commands}, {"newA", "newB"})
    for _, payload in self.replay.c.commands:
      self.assertEqual(payload["DEEPLOY_OPERATION"]["action"], "start_stateless_replacement_v1")
      self.assertEqual(lifecycle.worker(payload)["BUILD_AND_RUN_COMMANDS"], ["build replacement", "serve replacement"])
      self.assertNotIn(connector("b"), str(payload))  # Worker custody is scoped to the new tracked revision.
    report(self.replay.state, child, "deploy", "ready")
    self.replay.c._advance_deployment_operation(child)
    self.replay.c._advance_deployment_operation(child)
    self.assertEqual(child["outcome"], "succeeded")
    stored = self.replay.c.get_job_pipeline_from_cstore(31)
    self.assertEqual(stored["DEEPLOY_SPECS"]["current_target_nodes"], request["target_nodes"])
    self.assertEqual(lifecycle.worker(stored)["BUILD_AND_RUN_COMMANDS"], ["build replacement", "serve replacement"])

  def test_stateless_replacement_accepts_a_stable_proposal_after_worker_sightings_change(self):
    request = self.replacement_request()
    proposal = copy.deepcopy(request["repair"]["proposal"])
    self.replay.c.known["late-worker"] = [self.replay.live]
    refreshed = self.api.get_job_repair_preview(dict(self.read, replace_stateless=True))
    self.assertEqual(refreshed["proposal"], proposal)
    self.assertIn("late-worker", refreshed["observed_previous_nodes"])
    result = self.api.repair_update_pipeline(copy.deepcopy(request))
    self.assertEqual(result.get("status_code"), 202, result)
    child = self.replay.c._operation_records()[result["operation_id"]]
    self.assertIn("late-worker", child["unconfirmed_previous_nodes"])

  def test_stateless_replacement_does_not_elect_a_local_fallback(self):
    self.replacement_request()
    c = self.replay.c
    for key in list(self.replay.state.public):
      if key[0] == "DEEPLOY_OPERATIONS":
        del self.replay.state.public[key]
    c.bc.get_oracles = lambda **kwargs: (["oracle"], None)
    c.bc.get_eth_oracles = lambda: ["0xOther"]
    c.bc.eth_addr_to_checksum_address = lambda address: address
    c.bc.eth_addr_to_internal_addr = lambda address: None
    denied = self.api.get_job_repair_preview(dict(self.read, replace_stateless=True))
    self.assertEqual(denied["status"], "blocked")
    self.assertIn("selected replacement coordinator is not reachable", denied["reason"])
    c.bc.eth_addr_to_internal_addr = lambda address: "other"
    reviewed = self.api.get_job_repair_preview(dict(self.read, replace_stateless=True))
    self.assertEqual(reviewed["proposal"]["coordinator"], "other")

  def test_stateless_replacement_preserves_native_components_and_waits_for_readiness(self):
    request = self.replacement_request(mixed=True)
    # A separate parent-less replacement at this oracle must not block linked admission.
    other = dict(self.replay.parent, job_id=99, mutation="stateless_replacement_v1",
                 operation_id=self.replay.oid[:-1] + "e", phase="stateless_v1_waiting_for_readiness")
    self.replay.c._save_operation(other)
    result = self.api.repair_update_pipeline(copy.deepcopy(request))
    self.assertEqual(result.get("status_code"), 202, result)
    child = self.replay.c._operation_records()[result["operation_id"]]
    expected = [("WORKER_APP_RUNNER", "worker"), ("NATIVE_FIXTURE", "native")]
    self.assertEqual(child["instances"], {node: expected for node in child["nodes"]})
    self.replay.c._advance_deployment_operation(child)

    # A ready runner alone cannot publish a mixed pipeline.
    report(self.replay.state, child, "deploy", "ready")
    for node in child["nodes"]:
      row = self.replay.state.public[lifecycle.NODE_OPERATIONS_HKEY, node + "|deploy"]
      row["instances"] = row["instances"][:1]
      lifecycle.Engine(node).sign(row)
    self.replay.c._advance_deployment_operation(child)
    self.assertEqual(child["phase"], "stateless_v1_waiting_for_readiness")
    self.assertEqual(self.replay.c._get_pipeline_from_cstore(31), self.replay.cid)

    # The complete signed observation publishes the same native and runner identities.
    self.replay.state.now += 1
    report(self.replay.state, child, "deploy", "ready")
    self.replay.c._advance_deployment_operation(child)
    self.replay.c._advance_deployment_operation(child)
    self.assertEqual(child["outcome"], "succeeded")
    saved = self.replay.c.get_job_pipeline_from_cstore(31)
    self.assertEqual({plugin["SIGNATURE"] for plugin in saved["PLUGINS"]}, {"WORKER_APP_RUNNER", "NATIVE_FIXTURE"})
    # The superseded parent's prepared grants can no longer serve the old credentials.
    for attempt in ("deploy", "restore"):
      with self.assertRaisesRegex(ValueError, "revoked"):
        self.replay.dauth._deployment_secret_record("31", self.replay.oid + ":" + attempt)


  def test_stateless_replacement_without_a_pending_operation(self):
    request = self.replacement_request()
    for key in list(self.replay.state.public):
      if key[0] == "DEEPLOY_OPERATIONS":
        del self.replay.state.public[key]
    self.replay.c.bc.get_oracles = lambda **kwargs: ([], None)  # Local heartbeat visibility cannot change election.
    status = self.api.get_job_repair_preview(dict(self.read, replace_stateless=True))
    self.assertEqual(status["status"], "reviewable", status)
    self.assertIsNone(status["proposal"]["parent"])
    request["repair"]["proposal"] = status["proposal"]
    result = self.api.repair_update_pipeline(copy.deepcopy(request))
    self.assertEqual(result.get("status_code"), 202, result)
    child = self.replay.c._operation_records()[result["operation_id"]]
    self.assertNotIn("repair_parent", child)
    self.replay.c._advance_deployment_operation(child)
    self.assertEqual(len(self.replay.c.commands), 2)

  def test_stateless_replacement_rejects_missing_attestation_and_stateful_edits(self):
    request = self.replacement_request()
    request["repair"]["accept_unconfirmed_stop"] = False
    self.assertEqual(self.api.repair_update_pipeline(copy.deepcopy(request))["status_code"], 400)
    request["repair"]["accept_unconfirmed_stop"] = True
    request["plugins"][0]["VOLUMES"] = {"/persistent": "/data"}
    refusal = self.api.repair_update_pipeline(copy.deepcopy(request))
    self.assertEqual(refusal["status_code"], 400, refusal)
    self.assertEqual(set(self.replay.c._operation_records()), {self.replay.oid})
    self.assertEqual(self.replay.c.commands, [])

  def test_stateless_replacement_failure_cleans_up_only_its_own_targets(self):
    request = self.replacement_request()
    result = self.api.repair_update_pipeline(copy.deepcopy(request))
    self.assertEqual(result.get("status_code"), 202, result)
    child = self.replay.c._operation_records()[result["operation_id"]]
    self.replay.c._advance_deployment_operation(child)
    report(self.replay.state, child, "deploy", "failed")
    self.replay.c._advance_deployment_operation(child)
    self.replay.c._advance_deployment_operation(child)
    self.assertEqual({cfg["DEEPLOY_OPERATION"]["action"] for _, cfg in self.replay.c.commands},
                     {"start_stateless_replacement_v1", "stop"})
    report(self.replay.state, child, "deploy", "stopped")
    self.replay.c._advance_deployment_operation(child)
    self.assertEqual((child["phase"], child["outcome"]), ("completed", "failed"))
    self.assertEqual(self.replay.c._get_pipeline_from_cstore(31), self.replay.cid)

  def test_ordinary_endpoint_and_wrong_receiver_refuse_before_custody_or_inspection(self):
    request = self.reviewed_update()
    refused = self.api.update_pipeline(copy.deepcopy(request))
    self.assertEqual(refused["status_code"], 400, refused)
    self.assertEqual(refused["error"]["code"], "INVALID_DEPLOYMENT_REQUEST")
    self.api.bc = SimpleNamespace(address="other")
    self.api._operation_records = lambda: {}  # Without a verified parent this receiver cannot forward.
    self.assertEqual(self.api.get_job_repair_preview(self.read)["status"], "blocked")
    wrong = self.api.repair_update_pipeline(copy.deepcopy(request))
    self.assertEqual(wrong["status_code"], 409, wrong)
    self.assertEqual(wrong["error"]["code"], "DEPLOYMENT_CONFLICT")
    self.assertEqual(set(self.replay.c._operation_records()), {self.replay.oid})
    self.replay.http.assert_not_called()
    self.assertEqual(self.replay.c.commands, [])

  def test_repair_preview_signature_binds_job_and_coordinator(self):
    self.api.bc.eth_verify_text_signature = lambda **kwargs: "owner"  # Isolate signature recovery from v3 payload validation.
    verify = self.api._DeeployMixin__verify_signature_v3
    self.api.deeploy_verify_and_get_inputs = lambda request, request_type: (
      verify(request, request_type), make_inputs(**request)
    )
    valid = dict(self.read, EE_HASH=self.api._deeploy_payload_hash(self.read))
    self.assertEqual(self.api.get_job_repair_preview(valid)["status"], "reviewable")
    for changes in (dict(job_id=32), dict(coordinator="other")):
      blocked = self.api.get_job_repair_preview(dict(valid, **changes))
      self.assertEqual(blocked["status"], "blocked")
      self.assertIn("Invalid payload hash", blocked["reason"])
    unsigned = {key: value for key, value in valid.items() if key != "EE_HASH"}
    self.assertEqual(self.api.get_job_repair_preview(unsigned)["status"], "blocked")
    self.assertEqual(self.replay.c.commands, [])

  def test_forwarded_preview_keeps_the_envelope_and_only_accepts_its_coordinators_reply(self):
    self.api.const = self.api.ct
    self.api.bc = SimpleNamespace(address="ingress", get_eth_oracles=lambda: ["0xoracle", "0xother"],
                                  node_address_to_eth_address=lambda address: "0x" + address,
                                  verify=lambda payload, **kw: SimpleNamespace(valid=True))
    self.api._repair_relay_pending = {}
    self.api.create_postponed_request = PostponedRequest
    sent = []
    self.api.send_encrypted_payload = lambda node_addr, **message: sent.append((node_addr, message))
    self.api.receive_and_decrypt_payload = lambda payload: payload  # This test isolates reply correlation.

    response = self.api.get_job_repair_preview(self.read)
    self.assertIsInstance(response, PostponedRequest)
    destination, message = sent.pop()
    relay = message[_RELAY_KEY]
    self.assertEqual((destination, relay["request"]), ("oracle", self.read))
    reply = {"id": relay["id"], "method": "reply", "result": {"status": "reviewable"}}

    self.api._handle_job_repair_peer({"EE_SENDER": "other", _RELAY_KEY: reply})
    self.assertIsInstance(response.get_solver_method()(**response.get_method_kwargs()), PostponedRequest)
    self.api._handle_job_repair_peer({"EE_SENDER": "oracle", _RELAY_KEY: reply})
    self.assertEqual(response.get_solver_method()(**response.get_method_kwargs()), reply["result"])
    self.assertEqual(self.api._repair_relay_pending, {})

  def _use_wallet_verification(self, escrow_details):
    # Keep production v3 verification and nonce/escrow authorization with fixture chain responses.
    check_time = 1795096800
    self.api.time = lambda: check_time
    self.api.time_to_str = str
    self.api.NestedDotDict = NestedDotDict
    del self.api.deeploy_verify_and_get_inputs, self.api.deeploy_get_auth_result
    self.api.bc.is_valid_eth_address = Web3.is_address
    self.api.bc.get_user_escrow_details = escrow_details
    self.api.bc.eth_verify_text_signature = lambda text, signature, **kwargs: Account.recover_message(
      encode_defunct(text=text), signature=signature)
    return check_time

  def _sign_request(self, account, request_type, payload):
    # Sign the same payload and endpoint domain as the dApp with a disposable wallet.
    digest = self.api._deeploy_payload_hash(payload)
    message = self.api._deeploy_wrapper_message(request_type, payload, digest)
    signature = account.sign_message(encode_defunct(text=message)).signature.to_0x_hex()
    return dict(payload, EE_HASH=digest, EE_ETH_SIGN=signature, EE_ETH_SENDER=account.address)

  def test_delegate_can_preview_and_submit_with_escrow_scoped_retry(self):
    delegate = Account.create()
    request = self.reviewed_update()
    # Use the coordinator's existing paid-job owner fixture and an active delegate with no secret-reveal permission.
    membership = dict(isActive=True, escrowOwner="owner", escrowAddress="escrow", permissions=4)
    check_time = self._use_wallet_verification(lambda address: membership)
    nonce = hex(check_time * 1000 - 1)
    preview = self._sign_request(delegate, "get job repair preview", dict(job_id=31, coordinator="oracle", nonce=nonce))
    result = self.api.get_job_repair_preview(preview)
    self.assertEqual((result["status"], result.get("proposal")), ("reviewable", request["repair"]["proposal"]), result)

    payload = {key: value for key, value in request.items() if key not in ("EE_HASH", "EE_ETH_SIGN", "EE_ETH_SENDER")}
    update = self._sign_request(delegate, "repair update pipeline", dict(payload, nonce=nonce))
    # A preview does not authorize submission after the delegate leaves or switches escrow.
    for status, owner in ((False, "owner"), (True, "unrelated-owner")):
      membership.update(isActive=status, escrowOwner=owner)
      blocked = self.api.get_job_repair_preview(preview)
      self.assertEqual(blocked["status"], "blocked")
      self.assertIn("does not belong" if status else "no active escrow", blocked["reason"])
      self.assertNotEqual(self.api.repair_update_pipeline(copy.deepcopy(update))["status_code"], 202)
      self.assertEqual(set(self.replay.c._operation_records()), {self.replay.oid})
      self.replay.http.assert_not_called()
      self.assertEqual(self.replay.c.commands, [])
    membership.update(isActive=True, escrowOwner="owner", permissions=1 << 4)
    blocked = self.api.get_job_repair_preview(preview)
    self.assertIn("lacks permission to edit", blocked["reason"])
    self.assertIn("lacks permission to edit", self.api.repair_update_pipeline(copy.deepcopy(update))["error"]["message"])
    self.replay.http.assert_not_called()
    membership["permissions"] = 1 << 2

    accepted = self.api.repair_update_pipeline(copy.deepcopy(update))
    self.assertEqual((accepted["status_code"], accepted["status"]), (202, "accepted"), accepted)
    child = self.replay.c._operation_records()[accepted["operation_id"]]
    self.assertEqual(child["owner"], "owner")  # Custody and job ownership remain scoped to the escrow.
    inspections = list(self.replay.c.commands)
    retry = self.api.repair_update_pipeline(copy.deepcopy(update))
    self.assertEqual((retry["status_code"], retry.get("operation_id")), (202, accepted["operation_id"]), retry)
    self.assertEqual(self.replay.c.commands, inspections)
    self.assertTrue(self.replay.http.called)
    membership["isActive"] = False
    # A previous successful submission still requires current escrow access on a signed retry.
    revoked = self.api.repair_update_pipeline(copy.deepcopy(update))
    self.assertIn("no active escrow", revoked["error"]["message"])
    self.assertEqual(self.replay.c.commands, inspections)

  def test_dapp_preview_payload_passes_real_wallet_authorization_and_nonce_validation(self):
    account = Account.create()
    check_time = self._use_wallet_verification(
      lambda address: dict(isActive=True, escrowOwner=address, escrowAddress=address),
    )
    self.api._assess_job_repair = lambda job_id, owner, coordinator: (
      {"job_id": job_id, "coordinator": coordinator, "owner": owner},
    )

    def sign(payload):
      return self._sign_request(account, "get job repair preview", payload)

    # EditJobPage signs exactly these three fields.
    payload = dict(job_id=31, coordinator="oracle", nonce=hex(check_time * 1000 - 1))
    request = sign(payload)
    result = self.api.get_job_repair_preview(request)
    self.assertEqual(result, {"status": "reviewable", "proposal": {
      "job_id": 31, "coordinator": "oracle", "owner": account.address,
    }})
    missing = self.api.get_job_repair_preview(sign({"job_id": 31, "coordinator": "oracle"}))
    self.assertIn("nonce is required", missing["reason"])
    stale = sign(dict(payload, nonce=hex((check_time - 12 * 3600 - 1) * 1000)))
    self.assertIn("expired", self.api.get_job_repair_preview(stale)["reason"])
    tampered = dict(request, nonce=hex(check_time * 1000 - 2))
    self.assertIn("Invalid payload hash", self.api.get_job_repair_preview(tampered)["reason"])
    self.assertEqual(self.replay.c.commands, [])
