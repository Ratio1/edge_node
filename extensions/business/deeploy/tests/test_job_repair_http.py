"""Exercise the CSP's public Deeploy handlers with real update planning and repair custody."""

import copy
import unittest
from types import SimpleNamespace

from eth_account import Account
from eth_account.messages import encode_defunct
from naeural_core.utils.plugins_base.plugin_base_utils import NestedDotDict
from web3 import Web3

from extensions.business.deeploy.tests import test_update_requests as updates
from extensions.business.deeploy.tests import test_job_repair as lifecycle
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

  def test_ordinary_endpoint_and_wrong_receiver_refuse_before_custody_or_inspection(self):
    request = self.reviewed_update()
    refused = self.api.update_pipeline(copy.deepcopy(request))
    self.assertEqual(refused["status_code"], 400, refused)
    self.assertEqual(refused["error"]["code"], "INVALID_DEPLOYMENT_REQUEST")
    self.api.bc = SimpleNamespace(address="other")
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
    membership = dict(isActive=True, escrowOwner="owner", escrowAddress="escrow", permissions=1)
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
    membership.update(isActive=True, escrowOwner="owner")

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
