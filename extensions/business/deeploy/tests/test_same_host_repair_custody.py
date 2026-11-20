"""Test dAuth recovery for two relinked workers with a rotated main connector."""

import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import Mock

from ratio1.const.base import dAuth

from extensions.business.deeploy.tests.lifecycle_custody_support import Coordinator, Custodian, State, pipeline


def connector(secret, account="a" * 32, tunnel="b64fa4f8-b332-4fd3-89da-6721413a07d4"):
  """Build a disposable connector token in the same format as the tunnel provider.

  Parameters
  ----------
  secret, account, tunnel : str
    A one-character disposable seed and public connector identity.

  Returns
  -------
  str
    Encoded local test credential.

  Examples
  --------
  >>> isinstance(connector("a"), str)
  True
  """
  encoded = base64.b64encode(secret.encode() * 32).decode()
  return base64.b64encode(json.dumps(dict(a=account, t=tunnel, s=encoded)).encode()).decode()


class SameHostRepairCustodyTests(unittest.TestCase):
  def setUp(self):
    self.state = State()
    self.oracle = Coordinator(self.state)
    self.vault = Custodian(self.state)
    self.vault.engine.web3_is_node_licensed = lambda address: address in ("0xN", "0xM")
    self.job = dict(escrowOwner="owner", numberOfNodesRequested=2, activeNodes=["0xA", "0xB"])
    self.vault.engine.web3_get_job_details = lambda job_id: self.job
    self.vault.bc.get_node_license_info = lambda node_address_eth, **kw: dict(
      isValid=True, nodeAddress=node_address_eth, licenseId=1 if node_address_eth.lower()=="0xn" else 2, owner="license-owner")
    prefix = hashlib.sha256(b"oracle").hexdigest()[:16] + "-"
    self.child_id, self.parent_id = prefix + "1" * 32, prefix + "2" * 32
    self.aliases = [["A", "N"], ["B", "M"]]
    self.legacy = pipeline("prior-other-secret")
    self.legacy["DEEPLOY_SPECS"]["current_target_nodes"] = ["A", "B"]
    plugin = self.legacy["PLUGINS"][0]
    plugin["SIGNATURE"] = "WORKER_APP_RUNNER"
    self.instance(self.legacy).update(PORT=8080, TUNNEL_ENGINE_ENABLED=True, CLOUDFLARE_TOKEN=connector("a"))
    self.cid = self.state.blobs.add_json(self.legacy)
    self.state.public["DEEPLOY_DEPLOYED_JOBS", "7"] = self.cid
    self.ref = dict(operation_id=self.parent_id, sequence=4, plan_cid="parent-plan")
    self.licenses = {"N": [1, "license-owner"], "M": [2, "license-owner"]}
    self.parent = dict(operation_id=self.parent_id, request_hash="original", kind="update", mutation="node_relink",
                       job_id=7, app_id="app", owner="owner", network="test", coordinator="oracle",
                       previous_revision=0, target_revision=1, previous_pipeline_cid=self.cid,
                       previous_secret_revision=None, phase="holding_for_repair", sequence=5, plan_cid="parent-plan",
                       repair_child=dict(operation_id=self.child_id, request_hash="reviewed", base_sequence=4,
                                         node_aliases=self.aliases, licenses=self.licenses))
    self.oracle.bc.sign(self.parent)
    self.state.public["DEEPLOY_OPERATIONS", self.parent_id + "|5"] = self.parent
    self.old, self.new = [copy.deepcopy(self.legacy) for _ in range(2)]
    for config, attempt, rev in ((self.old, "restore", 0), (self.new, "deploy", 2)):
      config["DEEPLOY_SPECS"].update(revision=rev, current_target_nodes=["N", "M"],
                                    secret_revision=self.child_id + ":repair_v1:" + attempt)
    self.instance(self.new).update(CLOUDFLARE_TOKEN=connector("b"),
                                  EXPOSED_PORTS={"8080": {"is_main_port": True, "token": connector("b")}})
    self.instance(self.new)["ENV"]["CF_TUNNEL_TOKEN"] = "edited-other-secret"
    self.child = dict(self.parent, mutation="same_host_repair_v1", operation_id=self.child_id,
                      request_hash="reviewed", repair_parent=self.ref, repair_licenses=self.licenses, sequence=1, rotate_main_tunnel=True,
                      nodes=["N", "M"], previous_nodes=["N", "M"], target_revision=2,
                      instances={node: [["WORKER_APP_RUNNER", "worker"]] for node in ("N", "M")},
                      preparation_deadline=1100)
    self.child["previous_instances"] = copy.deepcopy(self.child["instances"])
    self.plan = {}

  @staticmethod
  def instance(config):
    return config["PLUGINS"][0]["INSTANCES"][0]

  def action(self, action, phase, **kwargs):
    op = dict(self.child, phase="repair_v1_" + phase)
    self.oracle.bc.sign(op)
    return self.vault.process_dauth_deployment_secrets_request(dict(job_id=7, action=action, operation=op, **kwargs),
                                                              "oracle", "n")

  def prepare(self, aliases=None, **kwargs):
    for config, name in ((self.old, "previous_configs"), (self.new, "configs")):
      self.plan[name], fragments = self.oracle._prepare_deployment_secret_configs({n: config for n in ("N", "M")})
    if self.state.blobs.get_json(self.child.get("plan_cid")) != self.plan:
      self.child["plan_cid"] = self.state.blobs.add_json(self.plan)
    return self.action("prepare", "preparing", node_aliases=self.aliases if aliases is None else aliases,
                       new_secrets=fragments, **kwargs)

  def test_failed_rollout_publishes_prior_app_with_only_its_rotated_main_credential(self):
    # Simulate a coordinator accidentally including edited unrelated fragments in the restoration request.
    injected = {"PLUGINS": [{"INSTANCES": [{"ENV": {"CF_TUNNEL_TOKEN": "wrong"}}]}]}
    prepared = self.prepare(previous_new_secrets=injected)
    self.assertEqual((prepared["prepared"], prepared["repair_protocol"]), (True, 1))
    restored = self.child_id + ":repair_v1:restore"
    for node in ("N", "M"):
      private = self.vault._load_revision_runner_secret_bundle("7", restored, node)
      self.assertEqual(self.instance(private["job_secrets"])["CLOUDFLARE_TOKEN"], connector("b"))
      self.assertEqual(self.instance(private["job_secrets"])["ENV"]["CF_TUNNEL_TOKEN"], "prior-other-secret")
    for node in ("A", "B"):
      for attempt in ("deploy", "restore"):
        with self.assertRaisesRegex(ValueError, "not authorized"):
          self.vault._load_revision_runner_secret_bundle("7", self.child_id + ":repair_v1:" + attempt, node)
    self.assertEqual(self.action("status", "preparing")["prepared"], True)
    self.assertEqual(prepared, self.prepare(previous_new_secrets=injected))  # replay cannot stage another token.
    self.assertNotIn(connector("b"), str(self.state.public) + str(self.state.blobs.data))
    # A failed deployment can finalize its previous app only after this coordinator publishes the exact restore plan.
    canonical = self.vault._recursively_sort_pipeline_data(self.vault.extract_invariable_data_from_pipeline(
      self.plan["previous_configs"]["N"]))
    pointer = dict(job_id="7", revision=2, operation_id=self.child_id, coordinator="oracle",
                   deleted=False, pipeline_cid=self.state.blobs.add_json(canonical), plan_cid=self.child["plan_cid"])
    self.oracle.bc.sign(pointer)
    with self.assertRaisesRegex(RuntimeError, "publication is pending"):
      self.action("revoke", "finalizing_recovery", active_attempt="restore")
    self.action("commit", "finalizing_recovery", pointer=pointer)
    for _ in range(2):  # replay after a coordinator restart leaves the active child usable
      self.action("revoke", "finalizing_recovery", active_attempt="restore")
    published = self.state.secrets["DAUTH_JOB_SECRETS", "7"]
    self.assertEqual(self.instance(published["job_secrets"])["CLOUDFLARE_TOKEN"], connector("b"))
    for ref in (self.parent_id + ":deploy", self.parent_id + ":restore", self.child_id + ":repair_v1:deploy"):
      self.assertTrue(self.state.secrets["DAUTH_JOB_SECRET_REVISIONS", "7|" + ref]["revoked"])
    self.vault._load_revision_runner_secret_bundle("7", restored, "M")

  def test_prior_main_port_alias_rotates_with_legacy_field(self):
    for config in (self.legacy, self.old):
      self.instance(config)["EXPOSED_PORTS"] = {"8080": {"is_main_port": True, "token": connector("a")}}
    self.cid = self.state.blobs.add_json(self.legacy)
    self.state.public["DEEPLOY_DEPLOYED_JOBS", "7"] = self.cid
    self.parent["previous_pipeline_cid"] = self.child["previous_pipeline_cid"] = self.cid
    self.oracle.bc.sign(self.parent)
    self.prepare()
    bundle = self.vault._load_revision_runner_secret_bundle("7", self.child_id + ":repair_v1:restore", "M")
    self.assertEqual(self.instance(bundle["job_secrets"])["EXPOSED_PORTS"]["8080"]["token"], connector("b"))

  def test_next_ordinary_csp_update_inherits_the_repaired_workers_custody(self):
    self.prepare()
    active_configs = self.plan["configs"]
    canonical = self.vault._recursively_sort_pipeline_data(self.vault.extract_invariable_data_from_pipeline(active_configs["N"]))
    pointer = dict(job_id="7", revision=2, operation_id=self.child_id, coordinator="oracle", deleted=False,
                   pipeline_cid=self.state.blobs.add_json(canonical), plan_cid=self.child["plan_cid"])
    self.oracle.bc.sign(pointer)
    self.action("commit", "finalizing", pointer=pointer)
    following = self.child_id.rsplit("-", 1)[0] + "-" + "f" * 32
    plan = {}
    for name, suffix, rev in (("previous_configs", "restore", 2), ("configs", "deploy", 3)):
      plan[name] = copy.deepcopy(active_configs)
      for config in plan[name].values():
        config["DEEPLOY_SPECS"].update(revision=rev, secret_revision=following + ":" + suffix)
    op = dict(self.child, operation_id=following, mutation="update", phase="preparing",
              previous_pipeline_cid=pointer["pipeline_cid"], previous_revision=2, target_revision=3,
              previous_secret_revision=self.child_id + ":repair_v1:deploy", plan_cid=self.state.blobs.add_json(plan))
    self.oracle.bc.sign(op)
    result = self.vault.process_dauth_deployment_secrets_request(dict(job_id=7, operation=op, action="prepare",
                                                                     new_secrets={}), "oracle", "n")
    self.assertTrue(result["prepared"])
    regular = self.vault._load_revision_runner_secret_bundle("7", following + ":deploy", "N")
    self.assertEqual(self.instance(regular["job_secrets"])["CLOUDFLARE_TOKEN"], connector("b"))

  def test_legacy_inline_connector_and_hidden_environment_restore_together(self):
    self.instance(self.legacy)["ENV"]["CF_TUNNEL_TOKEN"] = dAuth.DAUTH_SECRET_PLACEHOLDER
    self.cid = self.state.blobs.add_json(self.legacy)
    self.state.public["DEEPLOY_DEPLOYED_JOBS", "7"] = self.cid
    hidden = {"PLUGINS": [{"INSTANCES": [{"ENV": {"CF_TUNNEL_TOKEN": "prior-other-secret"}}]}]}
    self.state.secrets["DAUTH_JOB_SECRETS", "7"] = dict(job_id="7", pipeline_cid=self.cid, job_secrets=hidden)
    self.parent["previous_pipeline_cid"] = self.child["previous_pipeline_cid"] = self.cid
    self.oracle.bc.sign(self.parent)
    self.prepare()
    bundle = self.vault._load_revision_runner_secret_bundle("7", self.child_id + ":repair_v1:restore", "N")
    self.assertEqual(self.instance(bundle["job_secrets"])["CLOUDFLARE_TOKEN"], connector("b"))
    self.assertEqual(self.instance(bundle["job_secrets"])["ENV"]["CF_TUNNEL_TOKEN"], "prior-other-secret")
    self.assertNotIn("CLOUDFLARE_TOKEN", self.instance(hidden))

  def test_rotation_rejects_other_tunnel_or_account_unchanged_and_mismatched_aliases(self):
    for candidate in (connector("b", account="c" * 32), connector("b", tunnel="00000000-0000-0000-0000-000000000001"),
                      connector("a"), "malformed"):
      with self.subTest(token_type="disposable"):
        for path in ("CLOUDFLARE_TOKEN", "port"):
          self.instance(self.new)["CLOUDFLARE_TOKEN"] = candidate
          self.instance(self.new)["EXPOSED_PORTS"]["8080"]["token"] = candidate if path == "port" else connector("b")
          with self.assertRaises(ValueError):
            self.prepare()
          self.assertEqual(self.state.secrets, {})

  def test_unapproved_credential_change_or_removal_stages_nothing(self):
    self.child["rotate_main_tunnel"] = False
    with self.assertRaisesRegex(ValueError, "explicit rotation approval"):
      self.prepare()
    self.instance(self.new).update(CLOUDFLARE_TOKEN=None, EXPOSED_PORTS={}, TUNNEL_ENGINE_ENABLED=False)
    with self.assertRaisesRegex(ValueError, "unambiguous main Cloudflare"):
      self.prepare()
    self.instance(self.old)["CLOUDFLARE_TOKEN"] = None  # Removing the source path from both plans still checks custody.
    with self.assertRaisesRegex(ValueError, "tunnel configuration differs"):
      self.prepare()
    self.instance(self.old)["CLOUDFLARE_TOKEN"] = connector("a")
    self.assertEqual(self.state.secrets, {})
    self.instance(self.new).update(CLOUDFLARE_TOKEN=connector("a"), TUNNEL_ENGINE_ENABLED=True)
    self.assertTrue(self.prepare()["prepared"])  # An unchanged main connector requires no rotation.

  def test_signed_hold_and_current_license_are_both_required(self):
    with self.assertRaisesRegex(ValueError, "recipients changed"):
      self.prepare(aliases=[["A", "X"], ["B", "M"]])
    broken = dict(self.parent, phase="retiring_previous", sequence=6)
    self.oracle.bc.sign(broken)
    self.state.public["DEEPLOY_OPERATIONS", self.parent_id + "|6"] = broken
    with self.assertRaisesRegex(ValueError, "has not authorized"):
      self.prepare()
    del self.state.public["DEEPLOY_OPERATIONS", self.parent_id + "|6"]
    self.vault.engine.web3_is_node_licensed = lambda address: address != "0xB"
    with self.assertRaisesRegex(ValueError, "active license"):
      self.prepare()
    self.assertEqual(self.state.secrets, {})

  def test_recovery_rejects_an_unsigned_hold_wrong_paid_count_and_revoked_recipient(self):
    self.parent["repair_child"]["request_hash"] = "edited"  # The stored signature still covers the original value.
    with self.assertRaisesRegex(RuntimeError, "hold is unavailable"):
      self.prepare()
    self.parent["repair_child"]["request_hash"] = "reviewed"
    self.vault.engine.web3_get_job_details = lambda job_id: {"escrowOwner": "owner", "numberOfNodesRequested": 1}
    with self.assertRaisesRegex(ValueError, "paid placement"):
      self.prepare()
    self.vault.engine.web3_get_job_details = lambda job_id: self.job
    self.vault._dauth_revoked_nodes = {"0xn": "N"}
    with self.assertRaisesRegex(ValueError, "cannot grant"):
      self.prepare()
    self.assertEqual(self.state.secrets, {})

  def test_even_a_prepared_direct_worker_fetch_rechecks_owner_license_id_and_paid_slots(self):
    self.prepare()
    revision = self.child_id + ":repair_v1:deploy"
    raw = self.state.secrets["DAUTH_JOB_SECRET_REVISIONS", "7|" + revision]
    self.assertNotIn("pipelines", raw)  # The previous dAuth reader requires this key and therefore refuses repair records.
    self.job["escrowOwner"] = "transferred"
    with self.assertRaisesRegex(ValueError, "owner or paid placement changed"):
      self.vault._load_revision_runner_secret_bundle("7", revision, "N")
    self.job.update(escrowOwner="owner", activeNodes=["0xQ", "0xB"])
    with self.assertRaisesRegex(ValueError, "owner or paid placement changed"):
      self.vault._load_revision_runner_secret_bundle("7", revision, "N")
    self.job["activeNodes"] = ["0xN", "0xB"]  # The chain may have materialized the current address in either paid slot.
    self.vault._load_revision_runner_secret_bundle("7", revision, "N")
    self.vault.engine.web3_is_node_licensed = lambda address: address in ("0xN", "0xM", "0xA")
    with self.assertRaisesRegex(ValueError, "no longer owns"):
      self.vault._load_revision_runner_secret_bundle("7", revision, "N")
    self.vault.engine.web3_is_node_licensed = lambda address: address in ("0xN", "0xM")
    for owner, license_id in (("different-owner", 1), ("license-owner", 99)):
      self.vault.bc.get_node_license_info = lambda node_address_eth, **kw: dict(
        isValid=True, nodeAddress=node_address_eth, licenseId=license_id, owner=owner)
      with self.assertRaisesRegex(ValueError, "no longer owns"):
        self.vault._load_revision_runner_secret_bundle("7", revision, "N")
    self.vault.bc.get_node_license_info = lambda **kw: {}
    with self.assertRaisesRegex(ValueError, "active license"):
      self.vault._load_revision_runner_secret_bundle("7", revision, "N")

  def test_same_address_different_license_between_signed_review_and_staging_fails_closed(self):
    for owner, license_id in (("license-owner", 91), ("different-owner", 1)):
      self.vault.bc.get_node_license_info = lambda node_address_eth, **kw: dict(
        isValid=True, nodeAddress=node_address_eth, licenseId=license_id if node_address_eth.lower()=="0xn" else 2, owner=owner)
      with self.assertRaisesRegex(ValueError, "reviewed license"):
        self.prepare()
      self.assertEqual(self.state.secrets, {})
    self.child["repair_licenses"] = {"N": [91, "license-owner"], "M": [2, "license-owner"]}
    with self.assertRaisesRegex(ValueError, "Invalid repair secret recipients"):
      self.prepare()
    self.assertEqual(self.state.secrets, {})

  def test_pending_child_preparation_can_be_retried_without_touching_parent(self):
    self.state.fail_write = lambda hkey, key: "before" if key.endswith(":repair_v1:deploy") else None
    with self.assertRaisesRegex(RuntimeError, "preparation is pending"):
      self.prepare()
    self.state.fail_write = None
    self.assertFalse(self.action("status", "preparing")["prepared"])
    self.assertTrue(self.prepare()["prepared"])
    for attempt in ("deploy", "restore"):
      self.assertNotIn(("DAUTH_JOB_SECRET_REVISIONS", "7|" + self.parent_id + ":" + attempt + "|revoked"),
                       self.state.secrets)
    self.assertEqual(self.state.public["DEEPLOY_DEPLOYED_JOBS", "7"], self.cid)

  def test_wrong_parent_precondition_and_unsuffixed_phase_are_refused(self):
    self.prepare()
    self.child["repair_parent"] = dict(self.ref, sequence=3)
    with self.assertRaisesRegex(ValueError, "has not authorized"):
      self.action("status", "preparing")
    op = dict(self.child, phase="preparing", repair_parent=self.ref)
    self.oracle.bc.sign(op)
    with self.assertRaisesRegex(ValueError, "Invalid repair custody phase"):
      self.vault.process_dauth_deployment_secrets_request(dict(action="status", operation=op, job_id=7), "oracle", "n")

  def test_status_and_commit_check_the_binding_of_private_prepared_records(self):
    self.prepare()
    key = ("DAUTH_JOB_SECRET_REVISIONS", "7|" + self.child_id + ":repair_v1:restore")
    self.state.secrets[key].pop("repair_plan_cid")
    self.assertFalse(self.action("status", "preparing")["prepared"])
    canonical = self.vault._recursively_sort_pipeline_data(self.vault.extract_invariable_data_from_pipeline(
      self.plan["previous_configs"]["N"]))
    pointer = dict(job_id="7", revision=2, operation_id=self.child_id, coordinator="oracle",
                   deleted=False, pipeline_cid=self.state.blobs.add_json(canonical), plan_cid=self.child["plan_cid"])
    self.oracle.bc.sign(pointer)
    with self.assertRaisesRegex(RuntimeError, "Active deployment secrets are unavailable"):
      self.action("commit", "finalizing_recovery", pointer=pointer)

  def test_unversioned_in_place_reconcile_cannot_bypass_the_hold_on_a_partitioned_replica(self):
    # No copy of the coordinator hold or staged child has reached this dAuth.
    self.state.public.pop(("DEEPLOY_OPERATIONS", self.parent_id + "|5"))
    body = dict(job_id=7, expected_pipeline_cid=self.cid, pipeline_configs={"A": self.legacy}, nonce="n")
    self.vault._verify_signed_dauth_body = Mock(return_value=("oracle", "0xoracle"))
    self.vault._validate_dauth_secret_request_nonce = Mock(return_value="n")
    self.vault._is_protocol_oracle_eth = Mock(return_value=True)
    with self.assertRaisesRegex(ValueError, "requires a versioned deployment"):
      self.vault.process_dauth_reconcile_secrets_request(body)
    self.assertEqual(self.state.writes, [])

  def test_legacy_secret_writer_cannot_replace_held_or_published_repair_custody(self):
    self.prepare()
    self.vault._verify_signed_dauth_body = Mock(return_value=("oracle", "0xoracle"))
    self.vault._validate_dauth_secret_request_nonce = Mock(return_value="n")
    self.vault._is_protocol_oracle_eth = Mock(return_value=True)
    body = dict(job_id=7, job_secrets={"ENV": {"CF_TUNNEL_TOKEN": "unrelated-fixture"}}, nonce="n")
    self.vault._save_dauth_job_secret_bundle = Mock()
    with self.assertRaisesRegex(ValueError, "requires lifecycle"):
      self.vault.process_dauth_add_secrets_request(body)
    restored = self.plan["previous_configs"]["N"]
    pointer = dict(job_id="7", revision=2, operation_id=self.child_id, coordinator="oracle", deleted=False,
                   pipeline_cid=self.state.blobs.add_json(self.vault._recursively_sort_pipeline_data(
                     self.vault.extract_invariable_data_from_pipeline(restored))), plan_cid=self.child["plan_cid"])
    self.oracle.bc.sign(pointer)
    self.action("commit", "finalizing_recovery", pointer=pointer)
    self.state.secrets.pop(("DAUTH_JOB_SECRET_REVISIONS", "7|repair_hold|" + self.cid))  # Public publication replicated first.
    with self.assertRaisesRegex(ValueError, "requires lifecycle"):
      self.vault.process_dauth_add_secrets_request(body)
    self.vault._save_dauth_job_secret_bundle.assert_not_called()

  def test_legacy_secret_writer_rechecks_an_unrelated_pointer_immediately_before_writing(self):
    self.vault._verify_signed_dauth_body = Mock(return_value=("oracle", "0xoracle"))
    self.vault._validate_dauth_secret_request_nonce = Mock(return_value="n")
    self.vault._is_protocol_oracle_eth = Mock(return_value=True)
    self.vault._save_dauth_job_secret_bundle = Mock()
    self.vault.chainstore_hget = Mock(side_effect=[self.cid, None, "new-generation"])
    with self.assertRaisesRegex(ValueError, "job changed"):
      self.vault.process_dauth_add_secrets_request(dict(job_id=7, job_secrets={}, nonce="n"))
    self.vault._save_dauth_job_secret_bundle.assert_not_called()
