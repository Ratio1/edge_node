"""Non-HTTP admission facts at real identity/publication/asset/storage seams."""
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from extensions.business.cybersec.red_mesh.tenancy.identity import IdentityStoreError

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
      "actor_generation": "generation-1", "node_failure_policy": "stop",
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
    self.owner.data[("auth", "pentester")]["metadata"]["tenant_memberships"] = []
    with self.assertRaises(AdministrationDenied):
      self.service.resolve_execution_admission(actor, self.tenant, asset["assetId"])

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
    self.owner.account("operator", generation="", memberships=[{"role": "super_pentester", "tenant_id": self.tenant}])
    self.owner.data[("auth", "operator")]["metadata"].pop("navigatorAccountGeneration")
    self.owner.data[("auth", "operator")].pop("createdAt")
    with self.assertRaises(AdministrationDenied) as denied:
      self.service.resolve_execution_admission({"account_id": "operator"}, self.tenant, asset["assetId"])
    self.assertEqual(denied.exception.error, "account_changed")
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

  def test_malformed_stored_generation_is_storage_failure(self):
    asset = self.ready()
    for generation in (123, False, [], {}, None, "", "   ", "\ud800"):
      with self.subTest(generation=repr(generation)):
        self.owner.data[("auth", "creator")]["metadata"]["navigatorAccountGeneration"] = generation
        with self.assertRaises(IdentityStoreError):
          self.service.accounts.get_account("creator")
        with self.assertRaises(IdentityStoreError):
          self.service.accounts.list_accounts()
        with self.assertRaises(AdministrationDenied) as denied:
          self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"])
        self.assertEqual(denied.exception.status_code, 503)

  def test_only_absent_generation_may_use_legacy_creation_time(self):
    asset = self.ready()
    raw = self.owner.data[("auth", "creator")]
    raw["metadata"].pop("navigatorAccountGeneration")
    context = self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"])
    self.assertEqual(context.to_dict()["actor_generation"], "legacy:2026-01-01")
    raw.pop("createdAt")
    with self.assertRaises(AdministrationDenied) as denied:
      self.service.resolve_execution_admission(self.actor, self.tenant, asset["assetId"])
    self.assertEqual(denied.exception.status_code, 409)

  def test_two_published_tenants_never_admit_foreign_assets_or_nodes(self):
    own_asset = self.ready()
    request = str(uuid4())
    foreign = self.service.prepare_tenant(self.actor, request, "Other", "other", "initial")["data"]["tenantId"]
    self.owner.grant("initial", foreign)
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
