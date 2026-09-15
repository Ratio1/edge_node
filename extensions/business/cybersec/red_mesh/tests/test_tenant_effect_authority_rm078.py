"""RM-078: tenant-scoped effect authority.

Unblocks RM-026 I1b B9. The tenant authority model already exists and is already populated --
`tenancy/policy.py` carries a full role-to-operation matrix. What blocked every tenant-scoped effect
was one line in `TenantReadAccess._authorize`, which refused any operation outside
`reports:view`/`audit:view`, and one blanket refusal in `_effect_operation`, which returned 403 for
any non-null `tenant_id`.

This task makes the authority expressible and enforced. It wires no endpoint: B6, B8 and B9 spend it.
Requirement 5 of the plan is the one that matters most here -- narrowing a blanket refusal is exactly
the kind of change that widens more than intended, so the last test asserts that no endpoint became
tenant-reachable by accident.

Boundary tests before the implementation, per the standing rule.
"""
import unittest

from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView, TenantMembership
from extensions.business.cybersec.red_mesh.tenancy.policy import (
  PolicyDecision,
  TenantPolicyContext,
  authorize_tenant_operation,
)

EFFECT_OPERATIONS = ("analysis:run", "engagement:delete", "jobs:purge")
ROLES = ("super_tenant_admin", "super_pentester", "tenant_admin", "tenant_pentester", "tenant_user")


def account(*memberships):
  return AccountView("operator", "admin", "admin", True, tuple(
    TenantMembership(role, tenant_id) for role, tenant_id in memberships))


class TestTenantEffectAuthority(unittest.TestCase):
  def test_the_three_operations_the_owner_specified(self):
    """Transcribed from the owner's three decisions, not from what the code happens to allow.

    `tenant_admin` receives none of them: it manages integrations, users and attestation keys, it is
    not an operator role, and none of the three decisions named it.
    """
    rows = (
      # operation            STA    SP     T-admin T-pentester T-user
      ("analysis:run",      (True,  True,  False,  True,       False)),
      ("engagement:delete", (True,  False, False,  False,      False)),
      ("jobs:purge",        (True,  False, False,  False,      False)),
    )
    for operation, expected in rows:
      for role, allowed in zip(ROLES, expected):
        with self.subTest(operation=operation, role=role):
          self.assertEqual(
            authorize_tenant_operation(account((role, "a")), operation,
                                       TenantPolicyContext("a", True, True)),
            PolicyDecision(True, 200, None) if allowed else PolicyDecision(False, 403, "forbidden"))

  def test_manual_analysis_honours_allow_pentester_for_every_scoped_role(self):
    """The owner's words were "scoped STA/SP and Tenant Pentesters subject to Allow Pentester", so
    the switch binds all three, including Super-Tenant Admin.

    This is stricter than `tasks:launch`, which exempts the platform roles. The divergence is
    deliberate: deny-by-default on a literal reading, and a tenant that has switched pentesting off
    has said something about analysis of pentest findings too. Flagged for the owner rather than
    silently harmonised with `tasks:launch`.
    """
    for role in ("super_tenant_admin", "super_pentester", "tenant_pentester"):
      with self.subTest(role=role):
        actor = account((role, "a"))
        self.assertTrue(authorize_tenant_operation(
          actor, "analysis:run", TenantPolicyContext("a", True, True)).allowed)
        self.assertEqual(
          authorize_tenant_operation(actor, "analysis:run", TenantPolicyContext("a", True, False)),
          PolicyDecision(False, 403, "pentesting_disabled"))

  def test_deletion_and_purge_do_not_depend_on_the_pentesting_switch(self):
    """They are administrative, not operator, actions. A tenant that disabled pentesting has not
    thereby forfeited its ability to delete its own data -- and must not gain it either."""
    actor = account(("super_tenant_admin", "a"))
    for operation in ("engagement:delete", "jobs:purge"):
      for allow_pentester in (True, False):
        with self.subTest(operation=operation, allow_pentester=allow_pentester):
          self.assertTrue(authorize_tenant_operation(
            actor, operation, TenantPolicyContext("a", True, allow_pentester)).allowed)

  def test_authority_stays_inside_the_membership_tenant(self):
    """A Super-Tenant Admin scoped to tenant a cannot purge tenant b."""
    actor = account(("super_tenant_admin", "a"))
    for operation in EFFECT_OPERATIONS:
      with self.subTest(operation=operation):
        self.assertEqual(
          authorize_tenant_operation(actor, operation, TenantPolicyContext("b", True, True)),
          PolicyDecision(False, 404, "not_found"))

  def test_an_inactive_tenant_grants_nothing(self):
    actor = account(("super_tenant_admin", "a"))
    for operation in EFFECT_OPERATIONS:
      with self.subTest(operation=operation):
        self.assertEqual(
          authorize_tenant_operation(actor, operation, TenantPolicyContext("a", False, True)),
          PolicyDecision(False, 404, "not_found"))


class TestTenantReadAccessAdmitsTheEffectOperations(unittest.TestCase):
  """Step 2: `TenantReadAccess._authorize` refused every operation outside reports:view and
  audit:view, so the matrix behind it never got a chance to answer. Widening it must admit exactly
  the three new operations and nothing else."""

  def setUp(self):
    from uuid import uuid4
    from unittest.mock import patch
    from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
    from extensions.business.cybersec.red_mesh.tenancy.administration import (
      AdministrationDenied, TenantAdministrationService)
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import (
      CstoreTenantAdministrationStore)
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import (
      CstoreAuthAccountReader)
    from extensions.business.cybersec.red_mesh.tenancy.read_access import TenantReadAccess
    from .test_execution_binding_models import binding_payload
    from .test_tenant_read_access import ReadStore

    self.AdministrationDenied = AdministrationDenied
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.store = ReadStore()
    administration = TenantAdministrationService(
      CstoreAuthAccountReader(self.store), CstoreTenantAdministrationStore(self.store, "deployment"))
    request_id = str(uuid4())
    prepared = administration.prepare_tenant(
      {"account_id": "creator"}, request_id, "Example", "example", "initial")
    self.tenant_id = prepared["data"]["tenantId"]
    self.store.grant("initial", self.tenant_id)
    administration.activate_tenant({"account_id": "creator"}, request_id)
    self.store.jobs["job-1"] = {
      "job_id": "job-1", "job_status": "FINALIZED", "job_cid": "archive-ref",
      "execution_binding": {**binding_payload(), "tenant_id": self.tenant_id}}
    self.access = TenantReadAccess(administration, JobStateRepository(self.store))
    self.actor = {"account_id": "reader"}

  def _as(self, role):
    self.store.account("reader", memberships=[{"role": role, "tenant_id": self.tenant_id}])

  def _allow_pentester(self, enabled):
    """Flip the stored switch through the same store the admission path reads."""
    for (hkey, key), record in self.store.data.items():
      if (isinstance(record, dict) and record.get("tenant_id") == self.tenant_id
          and "allow_pentester" in record):
        record["allow_pentester"] = enabled
        return
    raise AssertionError("tenant record not found; this helper would silently do nothing")

  def test_a_super_tenant_admin_is_admitted_to_all_three(self):
    self._as("super_tenant_admin")
    # The fixture tenant ships with pentesting off, which is itself the analysis:run gate working;
    # the administrative two must not depend on it.
    self._allow_pentester(True)
    for operation in EFFECT_OPERATIONS:
      with self.subTest(operation=operation):
        snapshot = self.access.get_job(self.actor, self.tenant_id, "job-1", operation=operation)
        self.assertEqual(snapshot["job_id"], "job-1")

  def test_the_pentesting_switch_reaches_the_read_seam(self):
    """Not just the pure policy function: the switch has to survive the whole admission path, or it
    is enforced in a unit test and nowhere a caller can reach."""
    self._as("super_tenant_admin")
    self._allow_pentester(False)
    with self.assertRaises(self.AdministrationDenied) as caught:
      self.access.get_job(self.actor, self.tenant_id, "job-1", operation="analysis:run")
    self.assertEqual((caught.exception.status_code, caught.exception.error),
                     (403, "pentesting_disabled"))
    for operation in ("engagement:delete", "jobs:purge"):
      with self.subTest(operation=operation):
        self.assertEqual(
          self.access.get_job(self.actor, self.tenant_id, "job-1", operation=operation)["job_id"],
          "job-1")

  def test_a_tenant_user_is_refused_all_three(self):
    self._as("tenant_user")
    for operation in EFFECT_OPERATIONS:
      with self.subTest(operation=operation):
        with self.assertRaises(self.AdministrationDenied) as caught:
          self.access.get_job(self.actor, self.tenant_id, "job-1", operation=operation)
        self.assertEqual(caught.exception.status_code, 403)

  def test_an_unlisted_operation_is_still_refused_outright(self):
    """Deny-by-default survives the widening: the gate admits a fixed set, not anything the matrix
    happens to contain, so a future matrix entry cannot reach reads without its own decision."""
    self._as("super_tenant_admin")
    for operation in ("tasks:launch", "tenants:manage", "evidence:read", "", None):
      with self.subTest(operation=operation):
        with self.assertRaises(self.AdministrationDenied) as caught:
          self.access.get_job(self.actor, self.tenant_id, "job-1", operation=operation)
        self.assertEqual(caught.exception.status_code, 403)

  def test_the_existing_read_operations_are_unchanged(self):
    self._as("tenant_user")
    self.assertEqual(
      self.access.get_job(self.actor, self.tenant_id, "job-1")["job_id"], "job-1")
    self._as("tenant_admin")
    self.assertEqual(
      self.access.get_job(self.actor, self.tenant_id, "job-1", operation="audit:view")["job_id"],
      "job-1")


class TestNoEndpointBecameTenantReachable(unittest.TestCase):
  """Requirement 5: the blanket refusal is narrowed, so prove nothing widened past it."""

  def test_every_effect_endpoint_still_passes_a_null_tenant(self):
    import ast
    import pathlib
    source = pathlib.Path(__file__).resolve().parents[1] / "pentester_api_01.py"
    tree = ast.parse(source.read_text())
    calls = [node for node in ast.walk(tree)
             if isinstance(node, ast.Call)
             and getattr(node.func, "attr", None) in ("_effect_operation", "_review_operation")]
    assert calls, "the effect wrappers were renamed; this guard would bind nothing"
    for call in calls:
      if getattr(call.func, "attr", None) != "_effect_operation":
        continue
      # _effect_operation(self, request_actor, tenant_id, apply_effect, ...)
      tenant_arg = call.args[2]
      self.assertIsInstance(tenant_arg, ast.Constant, ast.dump(call))
      self.assertIsNone(tenant_arg.value,
                        "an endpoint opted into tenant scope outside its own slice: "
                        + ast.dump(call))


if __name__ == "__main__":
  unittest.main()
