"""Non-HTTP admission facts at real identity/publication/asset/storage seams."""
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView

from . import test_tenant_asset_administration as fixtures


class TestTenantExecution(unittest.TestCase):
  setUp = fixtures.TestTenantAssetAdministration.setUp
  create = fixtures.TestTenantAssetAdministration.create

  def ready(self):
    asset = self.create()["data"]
    self.service.configured_peers_reader = lambda: ["node-a", "node-b", "global-only"]
    for node in ("node-a", "node-b"):
      self.assertTrue(self.service.set_tenant_node_assignment(self.actor, self.tenant, node, True)["success"])
    return asset

  def test_resolves_saved_target_and_builds_actual_worker_binding(self):
    asset = self.create()["data"]
    self.service.configured_peers_reader = lambda: ["node-b", "node-a", "global-only"]
    for node in ("node-a", "node-b"):
      self.assertTrue(self.service.set_tenant_node_assignment(self.actor, self.tenant, node, True)["success"])
    before = len(self.owner.writes)
    context = self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"])
    self.assertEqual(context.to_dict()["selected_candidates"], ["node-a", "node-b"])
    binding = context.build_binding("coordinator-only", ["node-b"])
    self.assertEqual(binding.to_dict(), {
      "schema_version": 1, "namespace": "deployment", "tenant_id": self.tenant,
      "asset_id": asset["assetId"], "asset_target": self.target,
      "asset_target_digest": asset["targetDigest"], "actor_id": "creator",
      "actor_generation": self.owner.data[("auth", "creator")]["generation"], "node_failure_policy": "stop",
      "original_launcher": "coordinator-only", "participant_order": ["node-b"],
    })
    self.assertEqual(len(self.owner.writes), before)

  def test_same_account_and_fresh_policies_without_target_effects(self):
    asset = self.ready()
    with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")), \
         patch("requests.sessions.Session.request", side_effect=AssertionError("No HTTP")), \
         patch.object(self.service.accounts, "get_account", wraps=self.service.accounts.get_account) as reads:
      context = self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"])
      self.assertEqual(reads.call_count, 1)
    original = context.to_dict()
    self.assertTrue(self.service.update_tenant_node_failure_policy(self.actor, self.tenant, "continue")["success"])
    self.assertEqual(context.to_dict(), original)
    self.assertEqual(self.service.resolve_execution_admission(
      self.actor, self.tenant, asset["assetId"]).to_dict()["node_failure_policy"], "continue")
    self.owner.account("pentester", memberships=[{"role": "tenant_pentester", "tenant_id": self.tenant}])
    actor = {"account_id": "pentester"}
    with self.assertRaises(AdministrationDenied) as denied:
      self.service.resolve_execution_admission(actor, self.tenant, asset["assetId"])
    self.assertEqual(denied.exception.error, "pentesting_disabled")
    self.service.update_tenant_allow_pentester(self.actor, self.tenant, True)
    self.assertEqual(self.service.resolve_execution_admission(actor, self.tenant, asset["assetId"]).to_dict()["actor_id"], "pentester")
    self.owner.data[("auth", "pentester")]["memberships"] = []
    with self.assertRaises(AdministrationDenied):
      self.service.resolve_execution_admission(actor, self.tenant, asset["assetId"])

  def test_memberships_are_the_stored_rows_and_a_malformed_list_is_no_account(self):
    # RM-084 P6: "no memberships key" (the legacy seam) is gone; an empty list is the "none" scope.
    self.owner.account("explicit", memberships=[])
    explicit = self.service.accounts.get_account("explicit")
    self.assertEqual(explicit.tenant_memberships, ())
    # RM-084 P6: an account has membership rows, possibly zero; there is no "unknown" third state.
    self.assertEqual(AccountView("fixture", True).tenant_memberships, ())
    for malformed in (None, {}, "", False):
      self.owner.data[("auth", "explicit")]["memberships"] = malformed
      self.assertIsNone(self.service.accounts.get_account("explicit"))

  def test_private_admission_reuses_exact_resolved_account_and_digest_is_precondition(self):
    asset = self.ready()
    account = self.service.accounts.get_account("creator")
    before = len(self.owner.writes)
    with patch.object(self.service.accounts, "get_account", side_effect=AssertionError("Second identity read")), \
         patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")), \
         patch("requests.sessions.Session.request", side_effect=AssertionError("No HTTP")):
      context = self.service._resolve_execution_admission_for_account(
        account, self.tenant, asset["assetId"], ["node-a"], expected_target_digest=asset["targetDigest"])
      self.assertEqual(context.to_dict()["actor_id"], "creator")
      for digest, status in (("0" * 64, 409), ("", 400), (False, 400), ({}, 400)):
        with self.subTest(digest=digest), self.assertRaises(AdministrationDenied) as denied:
          self.service._resolve_execution_admission_for_account(
            account, self.tenant, asset["assetId"], expected_target_digest=digest)
        self.assertEqual(denied.exception.status_code, status)
    self.assertEqual(len(self.owner.writes), before)
    with patch.object(self.service.accounts, "get_account", wraps=self.service.accounts.get_account) as reads:
      self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"],
        expected_target_digest=asset["targetDigest"])
      self.assertEqual(reads.call_count, 1)

  def test_existing_execution_reauthorizes_current_facts_without_rewriting_saved_policy(self):
    asset = self.ready()
    binding = self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"]).build_binding(
      "coordinator", ["node-a"])
    saved = binding.to_dict()
    self.service.update_tenant_node_failure_policy(self.actor, self.tenant, "continue")
    row = self.store.get("tenant", self.tenant)
    self.store.put("tenant", self.tenant, record={**row, "future_policy": {"retain": True}})
    before = len(self.owner.writes)
    with patch.object(self.service.accounts, "get_account", wraps=self.service.accounts.get_account) as reads:
      facts = self.service.reauthorize_execution(binding, worker_node="node-a")
      self.assertEqual(reads.call_count, 1)
    self.assertEqual(facts.to_dict()["eligible_nodes"], ["node-a", "node-b"])
    self.assertNotIn("node_failure_policy", facts.to_dict())
    self.assertFalse(hasattr(facts, "build_binding"))
    self.assertEqual(binding.to_dict(), saved)
    self.assertEqual(self.store.get("tenant", self.tenant)["future_policy"], {"retain": True})
    self.assertEqual(len(self.owner.writes), before)
    detached = facts.to_dict()
    detached["eligible_nodes"].clear()
    self.assertEqual(facts.to_dict()["eligible_nodes"], ["node-a", "node-b"])

  def test_name_edit_keeps_admission_and_reauthorization_digest_stable(self):
    asset = self.ready()
    binding = self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"]).build_binding(
      "coordinator", ["node-a"])
    updated = self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], asset["version"],
      "Renamed", self.target, True)["data"]
    self.assertEqual(updated["targetDigest"], asset["targetDigest"])
    self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"],
      expected_target_digest=asset["targetDigest"])
    self.service.reauthorize_execution(binding, worker_node="node-a")
    self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], updated["version"],
      "Renamed", {"kind": "network", "address": "192.0.2.99"}, True)
    with self.assertRaises(AdministrationDenied) as denied:
      self.service.reauthorize_execution(binding)
    self.assertEqual((denied.exception.status_code, denied.exception.error), (409, "target_changed"))

  def test_existing_execution_rejects_incarnation_revocation_and_ineligible_workers(self):
    asset = self.ready()
    self.owner.account("pentester", memberships=[{"role": "tenant_pentester", "tenant_id": self.tenant}])
    self.service.update_tenant_allow_pentester(self.actor, self.tenant, True)
    binding = self.service.resolve_execution_admission({"account_id": "pentester"}, self.tenant,
      asset["assetId"]).build_binding("coordinator", ["node-a"])
    for worker in ("node-b", "global-only", "coordinator", "", False):
      with self.subTest(worker=worker), self.assertRaises(AdministrationDenied):
        self.service.reauthorize_execution(binding, worker_node=worker)
    self.service.set_tenant_node_assignment(self.actor, self.tenant, "node-a", False)
    with self.assertRaises(AdministrationDenied):
      self.service.reauthorize_execution(binding, worker_node="node-a")
    self.service.reauthorize_execution(binding)
    self.service.update_tenant_allow_pentester(self.actor, self.tenant, False)
    with self.assertRaises(AdministrationDenied) as denied:
      self.service.reauthorize_execution(binding)
    self.assertEqual(denied.exception.error, "pentesting_disabled")
    self.service.update_tenant_allow_pentester(self.actor, self.tenant, True)
    raw = self.owner.data[("auth", "pentester")]
    original = raw["generation"]
    raw["generation"] = str(uuid4())  # the account was recreated, or its password reset
    with self.assertRaises(AdministrationDenied) as denied:
      self.service.reauthorize_execution(binding)
    self.assertEqual(denied.exception.error, "account_changed")
    raw["generation"] = original
    raw["memberships"] = []
    with self.assertRaises(AdministrationDenied):
      self.service.reauthorize_execution(binding)

  def test_existing_execution_checks_namespace_publication_active_asset_and_current_configuration(self):
    asset = self.ready()
    binding = self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"]).build_binding(
      "coordinator", ["node-a"])
    before = len(self.owner.writes)
    with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")), \
         patch("requests.sessions.Session.request", side_effect=AssertionError("No HTTP")):
      for malformed in (None, {}, {**binding.to_dict(), "namespace": "foreign"},
                        {**binding.to_dict(), "unknown_binding_field": True}):
        with self.subTest(malformed=malformed), self.assertRaises(AdministrationDenied):
          self.service.reauthorize_execution(malformed)
      self.service.configured_peers_reader = lambda: ["node-b"]
      with self.assertRaises(AdministrationDenied):
        self.service.reauthorize_execution(binding, worker_node="node-a")
      self.service.configured_peers_reader = lambda: []
      self.assertEqual(self.service.reauthorize_execution(binding).to_dict()["eligible_nodes"], [])
      self.service.configured_peers_reader = lambda: ["node-a"]
      tenant = self.store.get("tenant", self.tenant)
      domain_key = ('["redmesh","tenancy",1,"deployment"]', '["domain","deployment","tenant"]')
      domain = self.owner.data.pop(domain_key)
      with self.assertRaises(TenantStoreError):
        self.service.reauthorize_execution(binding)
      self.owner.data[domain_key] = domain
      tenant_key = ('["redmesh","tenancy",1,"deployment"]',
                    json.dumps(["tenant", "deployment", self.tenant], separators=(",", ":")))
      self.owner.data[tenant_key]["active"] = False
      with self.assertRaises(AdministrationDenied):
        self.service.reauthorize_execution(binding)
      self.owner.data[tenant_key] = tenant
      asset_key = fixtures.asset_location(self.tenant, asset["assetId"])
      self.owner.data[asset_key]["active"] = False
      with self.assertRaises(AdministrationDenied):
        self.service.reauthorize_execution(binding)
    self.assertEqual(len(self.owner.writes), before)

  def test_scope_role_generation_and_asset_denials(self):
    asset = self.ready()
    for memberships in ([{"role": "tenant_admin", "tenant_id": self.tenant}],
                        [{"role": "tenant_user", "tenant_id": self.tenant}],
                        [{"role": "super_tenant_admin", "tenant_id": "foreign"}],
                        [{"role": "tenant_user", "tenant_id": self.tenant},
                         {"role": "super_tenant_admin", "tenant_id": "foreign"}]):
      with self.subTest(memberships=memberships):
        self.owner.account("operator", memberships=memberships)
        with patch.object(self.store, "get", wraps=self.store.get) as reads:
          with self.assertRaises(AdministrationDenied):
            self.service.resolve_execution_admission({"account_id": "operator", "role": "super_tenant_admin"},
                                                     self.tenant, asset["assetId"])
          self.assertFalse(any(call.args[0] == "asset" for call in reads.call_args_list))
    # A record with no generation is not an account (RM-084 P6 removed the legacy creation-time
    # incarnation that used to stand in for one), so it is unknown rather than changed.
    self.owner.account("operator", memberships=[{"role": "super_pentester", "tenant_id": self.tenant}])
    self.owner.data[("auth", "operator")].pop("generation")
    with self.assertRaises(AdministrationDenied) as denied:
      self.service.resolve_execution_admission({"account_id": "operator"}, self.tenant, asset["assetId"])
    self.assertEqual(denied.exception.status_code, 404)
    self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], asset["version"],
                                     asset["displayName"], asset["target"], False)
    with self.assertRaises(AdministrationDenied):
      self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"])

  def test_selection_is_tenant_intersection_and_configuration_failures_are_closed(self):
    asset = self.ready()
    self.service.set_tenant_node_assignment(self.actor, self.tenant, "node-b", False)
    for selection in (None, [], ["node-a"]):
      self.assertEqual(self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"],
                        selection).to_dict()["selected_candidates"], ["node-a"])
    for selection in (["global-only"], ["node-b"], ["node-a", "node-a"], "node-a", {}, [None]):
      with self.subTest(selection=selection), self.assertRaises(AdministrationDenied) as denied:
        self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"], selection)
      self.assertNotIn("global-only", str(denied.exception))
    for configured in (None, "node-a", [None]):
      self.service.configured_peers_reader = lambda: configured
      with self.assertRaises(TenantStoreError):
        self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"])
    def unavailable():
      raise RuntimeError("private reader failure")
    self.service.configured_peers_reader = unavailable
    with self.assertRaises(TenantStoreError):
      self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"])

  def test_actual_participants_and_nested_values_are_not_caller_aliases(self):
    asset = self.ready()
    selection = ["node-b", "node-a"]
    context = self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"], selection)
    selection.clear()
    detached = context.to_dict()
    detached["asset_target"]["address"] = "192.0.2.99"
    detached["selected_candidates"].clear()
    self.assertEqual(context.to_dict()["asset_target"], self.target)
    participants = ["node-b"]
    binding = context.build_binding("coordinator", participants)
    participants.clear()
    detached = binding.to_dict()
    detached["participant_order"].clear()
    self.assertEqual(binding.to_dict()["participant_order"], ["node-b"])
    for invalid in ([], ["node-b", "node-b"], ["global-only"], [None], "node-b"):
      with self.subTest(invalid=invalid), self.assertRaises(ValueError):
        context.build_binding("coordinator", invalid)

  def test_malformed_stored_generation_is_no_account(self):
    # RM-084 P6: the strict v1 parser refuses the whole record, and a refused record is the same answer
    # as an absent one -- an enumeration probe cannot tell them apart. It used to be a storage failure.
    asset = self.ready()
    for generation in (123, False, [], {}, None, "", "   ", "\ud800", "generation-1"):
      with self.subTest(generation=repr(generation)):
        self.owner.data[("auth", "creator")]["generation"] = generation
        self.assertIsNone(self.service.accounts.get_account("creator"))
        self.assertNotIn("creator", [view.account_id for view in self.service.accounts.list_accounts()])
        with self.assertRaises(AdministrationDenied) as denied:
          self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"])
        self.assertEqual(denied.exception.status_code, 404)

  def test_two_published_tenants_never_admit_foreign_assets_or_nodes(self):
    own_asset = self.ready()
    request = str(uuid4())
    self.owner.account("initial-other")
    foreign = self.service.prepare_tenant(self.actor, request, "Other", "other", "initial-other")["data"]["tenantId"]
    self.owner.grant("initial-other", foreign)
    self.assertTrue(self.service.activate_tenant(self.actor, request)["success"])
    foreign_asset = self.service.create_tenant_asset(self.actor, foreign, str(uuid4()), "Other asset", self.target)["data"]
    self.assertTrue(self.service.set_tenant_node_assignment(self.actor, foreign, "global-only", True)["success"])
    self.owner.account("scoped", memberships=[{"role": "super_pentester", "tenant_id": self.tenant}])
    actor = {"account_id": "scoped"}
    before = len(self.owner.writes)
    self.assertEqual(self.service.resolve_execution_admission(actor, self.tenant,
      own_asset["assetId"]).to_dict()["tenant_id"], self.tenant)
    for tenant, asset, peers in ((foreign, foreign_asset["assetId"], None),
                                  (self.tenant, foreign_asset["assetId"], None),
                                  (self.tenant, own_asset["assetId"], ["global-only"])):
      with self.subTest(tenant=tenant, asset=asset, peers=peers), self.assertRaises(AdministrationDenied):
        self.service.resolve_execution_admission(actor, tenant, asset, peers)
    self.assertEqual(len(self.owner.writes), before)
