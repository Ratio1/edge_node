"""RM-084 P7: who may archive (deactivate) or restore an account, per `redmesh-auth.md` §9.

The approval writes nothing -- the Navigator writes the state with the generation returned here --
so every test also asserts the store was not touched.
"""
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader

from .test_tenant_administration import FakeAdministrationStore


class TestAccountStateAdministration(unittest.TestCase):
  def setUp(self):
    self.env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    self.env.start()
    self.addCleanup(self.env.stop)
    self.store = FakeAdministrationStore()
    self.repo = CstoreTenantAdministrationStore(self.store, "test-deployment")
    self.service = TenantAdministrationService(CstoreAuthAccountReader(self.store), self.repo)
    self.creator = {"account_id": "creator"}
    self.tenant = self.create()
    # A second admin so the founder rules, not the last-admin rule, are what these tests exercise.
    self.store.account("peer", memberships=[{"role": "tenant_admin", "tenant_id": self.tenant}])
    self.store.account("member", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    self.admin = {"account_id": "peer"}

  def create(self):
    request = str(uuid4())
    prepared = self.service.prepare_tenant(self.creator, request_id=request, display_name="Example",
                                           domain_id="example", initial_admin_id="initial")
    self.assertTrue(prepared["success"], prepared)
    tenant_id = prepared["data"]["tenantId"]
    self.store.grant("initial", tenant_id)
    self.assertTrue(self.service.activate_tenant(self.creator, request)["success"])
    return tenant_id

  def change(self, actor, account_id, state, **kwargs):
    before = list(self.store.writes)
    result = self.service.authorize_account_state_change(actor, account_id, state, **kwargs)
    self.assertEqual(self.store.writes, before, "authorization must not write")
    return result

  def denied(self, actor, account_id, state, **kwargs):
    result = self.change(actor, account_id, state, **kwargs)
    self.assertFalse(result["success"], result)
    return result["status_code"], result["error"]

  def approved(self, actor, account_id, state, **kwargs):
    result = self.change(actor, account_id, state, **kwargs)
    self.assertTrue(result["success"], result)
    return result["data"]

  def test_the_approval_names_the_account_its_generation_and_the_requested_state(self):
    data = self.approved(self.creator, "member", "deactivated")
    self.assertEqual(data, {"accountId": "member", "state": "deactivated",
                            "accountGeneration": self.store.data[("auth", "member")]["generation"]})
    self.store.account("member", state="deactivated", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    self.assertEqual(self.approved(self.creator, "member", "active")["state"], "active")

  def test_asking_for_the_state_an_account_already_holds_is_approved_unchanged(self):
    self.store.account("member", state="deactivated", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    data = self.approved(self.admin, "member", "deactivated")
    self.assertEqual(data["accountGeneration"], self.store.data[("auth", "member")]["generation"])

  def test_an_unknown_state_or_account_id_is_refused_before_anything_is_read(self):
    for state in ("deleting", "", None, "ACTIVE"):
      with self.subTest(state=state):
        self.assertEqual(self.denied(self.creator, "member", state), (400, "invalid_request"))
    self.assertEqual(self.denied(self.creator, "   ", "deactivated"), (400, "invalid_request"))

  def test_an_unknown_tombstoned_or_deleting_account_is_not_found(self):
    self.assertEqual(self.denied(self.creator, "nobody", "deactivated"), (404, "not_found"))
    self.store.data[("auth", "gone")] = "null"
    self.assertEqual(self.denied(self.creator, "gone", "deactivated"), (404, "not_found"))
    self.store.account("leaving", active=False, memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    self.assertEqual(self.store.data[("auth", "leaving")]["state"], "deleting")
    self.assertEqual(self.denied(self.creator, "leaving", "deactivated"), (404, "not_found"))

  def test_nobody_archives_their_own_account_whatever_else_the_rules_would_say(self):
    self.assertEqual(self.denied(self.creator, "creator", "deactivated"), (403, "self"))
    # A tenant admin targeting itself gets `self`, not the founder or last-admin refusal.
    self.assertEqual(self.denied({"account_id": "initial"}, "initial", "deactivated"), (403, "self"))

  def test_a_tenant_route_refuses_a_target_outside_the_tenant_it_names(self):
    other = self.create_second_tenant()
    self.assertEqual(self.denied(self.creator, "member", "deactivated", tenant_id=other), (404, "not_found"))
    self.assertEqual(self.approved(self.creator, "member", "deactivated", tenant_id=self.tenant)["state"],
                     "deactivated")

  def create_second_tenant(self):
    """A second workspace with its own admin and an ordinary member, to test cross-tenant reach."""
    request = str(uuid4())
    self.store.account("second_admin")
    prepared = self.service.prepare_tenant(self.creator, request_id=request, display_name="Second",
                                           domain_id="second", initial_admin_id="second_admin")
    tenant_id = prepared["data"]["tenantId"]
    self.store.grant("second_admin", tenant_id)
    self.assertTrue(self.service.activate_tenant(self.creator, request)["success"])
    self.store.account("second_member", memberships=[{"role": "tenant_user", "tenant_id": tenant_id}])
    return tenant_id

  def test_a_platform_admin_reaches_every_scope_a_tenant_admin_only_its_own_members(self):
    self.store.account("stray")  # none scope
    self.store.account("pentester", memberships=[{"role": "tenant_pentester", "tenant_id": self.tenant}])
    other = self.create_second_tenant()
    self.assertEqual(self.approved(self.creator, "stray", "deactivated")["accountId"], "stray")
    self.assertEqual(self.approved(self.creator, "pentester", "deactivated")["accountId"], "pentester")
    self.assertEqual(self.approved(self.creator, "second_member", "deactivated",
                                   tenant_id=other)["accountId"], "second_member")
    # The same targets, asked by a tenant admin.
    self.assertEqual(self.denied(self.admin, "stray", "deactivated"), (404, "not_found"))
    self.assertEqual(self.denied(self.admin, "pentester", "deactivated"), (403, "pentester_role_reserved"))
    self.assertEqual(self.denied(self.admin, "second_member", "deactivated"), (403, "not_a_member"))

  def test_a_caller_who_may_not_manage_this_tenants_users_is_told_nothing(self):
    self.store.account("plain", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    self.assertEqual(self.denied({"account_id": "plain"}, "member", "deactivated"), (404, "not_found"))
    self.assertEqual(self.denied({"account_id": "nobody"}, "member", "deactivated"), (404, "not_found"))

  def test_the_founder_is_not_a_peers_to_archive_and_an_unknown_founder_protects_every_admin(self):
    self.assertEqual(self.denied(self.admin, "initial", "deactivated"), (403, "root_tenant_admin"))
    self.assertEqual(self.approved(self.creator, "initial", "deactivated")["accountId"], "initial")
    stored = self.repo.get("tenant", self.tenant)
    self.repo.put("tenant", self.tenant, record={k: v for k, v in stored.items() if k != "root_admin_id"})
    # Founder unknown reads as "anyone could be", never as "anyone may be archived".
    self.assertEqual(self.denied(self.admin, "initial", "deactivated"), (403, "root_tenant_admin"))
    self.assertEqual(self.approved(self.admin, "member", "deactivated")["accountId"], "member")

  def test_no_caller_leaves_a_tenant_without_an_active_administrator(self):
    self.store.account("paused", state="deactivated",
                       memberships=[{"role": "tenant_admin", "tenant_id": self.tenant}])
    # `initial` and `peer` are both active admins, so archiving one is fine for either caller.
    self.assertEqual(self.approved(self.creator, "peer", "deactivated")["accountId"], "peer")
    self.store.account("peer", state="deactivated",
                       memberships=[{"role": "tenant_admin", "tenant_id": self.tenant}])
    # `initial` is now the only active admin; an archived peer is not cover. Owner, 2026-09-20:
    # the platform is refused here too, so no tenant is ever left admin-less.
    self.assertEqual(self.denied(self.creator, "initial", "deactivated"), (409, "last_tenant_admin"))
    self.assertEqual(self.approved(self.creator, "peer", "active")["state"], "active")

  def test_restoring_an_administrator_is_never_the_last_admin_refusal(self):
    self.store.account("peer", state="deactivated",
                       memberships=[{"role": "tenant_admin", "tenant_id": self.tenant}])
    self.assertEqual(self.approved(self.creator, "peer", "active")["accountId"], "peer")

  def test_one_platform_administrator_may_archive_another_while_others_stay_active(self):
    self.store.account("sta2", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.store.account("sta3", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.assertEqual(self.approved(self.creator, "sta2", "deactivated")["accountId"], "sta2")
    # An archived platform admin is not cover either: `creator` and `sta3` are what keep this allowed.
    self.store.account("sta2", state="deactivated",
                       memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.assertEqual(self.approved(self.creator, "sta3", "deactivated")["accountId"], "sta3")

  def test_the_only_remaining_platform_administrator_is_refused_to_a_peer(self):
    self.store.account("sta2", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    # Only `sta2` and `creator` are active platform admins; a stale enumeration that omits the
    # caller is what the count defends against, so patch the reader to that view.
    real = self.service.accounts.list_accounts
    with patch.object(self.service.accounts, "list_accounts",
                      side_effect=lambda: [a for a in real() if a.account_id != "sta2"]):
      self.assertEqual(self.denied({"account_id": "sta2"}, "creator", "deactivated"),
                       (409, "last_super_tenant_admin"))
      # Restoring is never refused by the rule; it is a deactivation guard.
      self.assertEqual(self.approved({"account_id": "sta2"}, "creator", "active")["state"], "active")

  def test_a_store_outage_is_unavailable_and_writes_nothing(self):
    with patch.object(self.store, "chainstore_hget", side_effect=RuntimeError("storage down")):
      result = self.service.authorize_account_state_change(self.creator, "member", "deactivated")
    self.assertEqual((result["status_code"], result["error"]), (503, "unavailable"))


if __name__ == "__main__":
  unittest.main()
