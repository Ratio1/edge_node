"""RM-193 step 4a S7: `findings:triage`, held by the `reports:review` roles, with Allow Pentester and no designation."""
import unittest

from extensions.business.cybersec.red_mesh.tenancy import policy, read_access
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.policy import PolicyDecision, TenantPolicyContext, authorize_tenant_operation
from .test_account_profile import _ProfileCase
from .test_tenant_effect_authority_rm078 import account, in_tenant

TRIAGE = "findings:triage"
ROLES = ("super_tenant_admin", "super_pentester", "tenant_admin", "tenant_pentester", "tenant_user")


class TestFindingTriagePolicy(unittest.TestCase):
  def test_exactly_the_roles_that_hold_review_hold_triage(self):
    for role, operations in policy._ROLE_OPERATIONS.items():
      self.assertEqual(TRIAGE in operations, "reports:review" in operations, role)
    self.assertEqual({role for role, ops in policy._ROLE_OPERATIONS.items() if TRIAGE in ops},
                     {"super_tenant_admin", "super_pentester", "tenant_admin", "tenant_pentester"})
    for role in ("tenant_user",):
      self.assertNotIn(TRIAGE, policy._ROLE_OPERATIONS[role])
    self.assertIn(TRIAGE, policy._LAUNCH_BOUND_OPERATIONS)

  def test_role_by_allow_pentester_with_no_designation_needed(self):
    for role, holds, bound in (("super_tenant_admin", True, False), ("super_pentester", True, False),
                               ("tenant_admin", True, True), ("tenant_pentester", True, True),
                               ("tenant_user", False, False)):
      for allow in (True, False):
        with self.subTest(role=role, allow_pentester=allow):
          decision = authorize_tenant_operation(account(in_tenant(role, "a")), TRIAGE, TenantPolicyContext("a", True, allow))
          if not holds:
            expected = PolicyDecision(False, 403, "forbidden")
          elif bound and not allow:
            expected = PolicyDecision(False, 403, "pentesting_disabled")
          else:
            expected = PolicyDecision(True, 200, None)  # `report_reviewer` was never passed
          self.assertEqual(decision, expected)

  def test_scope_stays_the_memberships(self):
    self.assertEqual(authorize_tenant_operation(account(in_tenant("tenant_admin", "a")), TRIAGE,
                                                TenantPolicyContext("b", True, True)),
                     PolicyDecision(False, 404, "not_found"))
    self.assertEqual(authorize_tenant_operation(None, TRIAGE, TenantPolicyContext("a", True, True)).allowed, False)

  def test_the_read_seam_lists_the_operation_and_still_reads_triage_with_reports_view(self):
    self.assertIn(TRIAGE, read_access._TENANT_OPERATIONS)
    for role in ROLES:
      self.assertIn("reports:view", policy._ROLE_OPERATIONS[role], role)


class TestFindingTriageThroughTenantAdmission(_ProfileCase):
  """`authorize_tenant_for_account`: the same decision with the stored tenant, role and designation rows."""

  def set_allow(self, enabled):
    tenant = self.service.store.get("tenant", self.tenant_id)
    self.service.store.put("tenant", self.tenant_id, record={**tenant, "allow_pentester": enabled})

  def decide(self, name, operation=TRIAGE):
    account_view = self.service.accounts.get_account(name)
    try:
      self.service.authorize_tenant_for_account(account_view, self.tenant_id, operation)
      return None
    except AdministrationDenied as exc:
      return exc.status_code, exc.error

  def test_triage_follows_role_and_allow_pentester_and_ignores_the_reviewer_designation(self):
    for name, bound in (("creator", False), ("spent", False), ("tadmin", True), ("tpent", True), ("tuser", None)):
      for allow in (False, True):
        with self.subTest(account=name, allow_pentester=allow):
          self.set_allow(allow)
          if bound is None:
            expected = (403, "forbidden")
          elif bound and not allow:
            expected = (403, "pentesting_disabled")
          else:
            expected = None
          # nobody is designated a reviewer here: review is denied for that, triage is not
          self.assertEqual(self.decide(name), expected)
          if expected is None:
            self.assertEqual(self.decide(name, "reports:review"), (403, "reviewer_not_designated"))

  def test_another_tenants_member_is_denied_and_the_designation_row_is_not_read(self):
    self.set_allow(True)
    self.assertEqual(self.decide("other-admin2"), (404, "not_found"))
    self.assertEqual(self.decide("other-user"), (404, "not_found"))
    self.store.writes.clear()
    self.decide("tpent")
    self.assertEqual(self.store.writes, [])


if __name__ == "__main__":
  unittest.main()
