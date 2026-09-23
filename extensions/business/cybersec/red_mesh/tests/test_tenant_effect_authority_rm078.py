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
  return AccountView("operator", True, tenant_memberships=tuple(
    TenantMembership(role, tenant_id) for role, tenant_id in memberships))


def in_tenant(role, tenant_id):
  """RM-083: a Super-Tenant Admin is always full-portfolio; every other role can be scoped."""
  return (role, None if role == "super_tenant_admin" else tenant_id)


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
            authorize_tenant_operation(account(in_tenant(role, "a")), operation,
                                       TenantPolicyContext("a", True, True)),
            PolicyDecision(True, 200, None) if allowed else PolicyDecision(False, 403, "forbidden"))

  def test_the_authorization_upload_carries_the_launch_roles_and_the_same_switch(self):
    """RM-084 P3. Filing a permission-to-test document is a pre-engagement step of launching, so it
    holds the launch role set -- and binds Allow Pentester the way `analysis:run` does, because a
    tenant with pentesting off has nothing to authorize."""
    for role, holds in (("super_tenant_admin", True), ("super_pentester", True),
                        ("tenant_pentester", True), ("tenant_admin", False),
                        ("tenant_user", False)):
      with self.subTest(role=role):
        actor = account(in_tenant(role, "a"))
        self.assertEqual(
          authorize_tenant_operation(actor, "authorization:upload",
                                     TenantPolicyContext("a", True, True)).allowed, holds)
        self.assertEqual(
          authorize_tenant_operation(actor, "authorization:upload",
                                     TenantPolicyContext("a", True, False)),
          PolicyDecision(False, 403, "pentesting_disabled" if holds else "forbidden"))

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
        actor = account(in_tenant(role, "a"))
        self.assertTrue(authorize_tenant_operation(
          actor, "analysis:run", TenantPolicyContext("a", True, True)).allowed)
        self.assertEqual(
          authorize_tenant_operation(actor, "analysis:run", TenantPolicyContext("a", True, False)),
          PolicyDecision(False, 403, "pentesting_disabled"))

  def test_deletion_and_purge_do_not_depend_on_the_pentesting_switch(self):
    """They are administrative, not operator, actions. A tenant that disabled pentesting has not
    thereby forfeited its ability to delete its own data -- and must not gain it either."""
    actor = account(("super_tenant_admin", None))
    for operation in ("engagement:delete", "jobs:purge"):
      for allow_pentester in (True, False):
        with self.subTest(operation=operation, allow_pentester=allow_pentester):
          self.assertTrue(authorize_tenant_operation(
            actor, operation, TenantPolicyContext("a", True, allow_pentester)).allowed)

  def test_authority_stays_inside_the_membership_tenant(self):
    """A tenant-scoped Super-Tenant Admin is not a valid account (RM-083); a Super-Pentester
    allowlisted for tenant a cannot run analysis in tenant b."""
    self.assertEqual(authorize_tenant_operation(account(("super_tenant_admin", "a")), "jobs:purge",
                                                TenantPolicyContext("a", True, True)),
                     PolicyDecision(False, 404, "not_found"))
    actor = account(("super_pentester", "a"))
    for operation in EFFECT_OPERATIONS:
      with self.subTest(operation=operation):
        self.assertEqual(
          authorize_tenant_operation(actor, operation, TenantPolicyContext("b", True, True)),
          PolicyDecision(False, 404, "not_found"))

  def test_an_inactive_tenant_grants_nothing(self):
    actor = account(("super_tenant_admin", None))
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
    scope = None if role == "super_tenant_admin" else self.tenant_id
    self.store.account("reader", memberships=[{"role": role, "tenant_id": scope}])

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
    for operation in ("tasks:launch", "tenants:manage", "assets:create", "", None):
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


class TestEffectOperationNarrowsRatherThanOpens(unittest.TestCase):
  """Step 3. `_effect_operation` returned 403 for any non-null tenant_id, with the comment that a
  tenant-bound snapshot would otherwise reach services raw. Two hazards were bundled there:
  authority (no tenant role could be granted an effect) and plumbing (the snapshot mode must reach
  the service that consumes it). Step 1 and 2 settled the first. The second is already threaded --
  `_admitted_snapshot` returns the mode and every effect lambda forwards it -- so the refusal
  narrows to the operation, not to the tenant id.

  Deleting the refusal outright would open every effect endpoint to tenant callers at once,
  including ones whose operations the matrix does not grant. That is what these tests forbid.
  """

  def setUp(self):
    from .test_api import TestPhase1ConfigCID
    TestPhase1ConfigCID._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    self.Plugin = PentesterApi01Plugin

  def _call(self, operation, tenant_id="tn_7bd2f70d-0000-4000-8000-000000000002"):
    from types import SimpleNamespace
    reached = []
    owner = SimpleNamespace()
    return self.Plugin._effect_operation(
      owner, {"account_id": "reader"}, tenant_id,
      lambda snapshot, mode, ledger: reached.append(mode) or {"ok": True},
      job_id="job-1", operation=operation), reached

  def test_an_ungranted_operation_is_still_refused_for_a_tenant_caller(self):
    """Operations outside _TENANT_EFFECT_OPERATIONS stay refused even though the matrix grants them
    broadly. reports:export left this list on 2026-09-15: the owner's MVP rescope opted
    stop_monitoring (which runs as reports:export) into the tenant seam."""
    for operation in ("reports:view", "tasks:launch", "evidence:read", "tenants:manage"):
      with self.subTest(operation=operation):
        result, reached = self._call(operation)
        self.assertEqual(result, {"success": False, "error": "forbidden", "status_code": 403})
        self.assertEqual(reached, [], "the effect ran for an ungranted tenant operation")

  def test_a_granted_operation_is_no_longer_refused_on_the_tenant_id_alone(self):
    """It proceeds to admission, which is where the account, the tenant and the matrix decide. The
    point is that the blanket refusal no longer answers before any of that is consulted."""
    for operation in EFFECT_OPERATIONS:
      with self.subTest(operation=operation):
        result, _reached = self._call(operation)
        # No real store behind this owner, so admission fails -- but with the effect-path failure,
        # not the blanket 403 that used to short-circuit it.
        self.assertNotEqual(result, {"success": False, "error": "forbidden", "status_code": 403})

  def test_a_null_tenant_is_unaffected(self):
    """B1-B10 all pass tenant_id=None and must behave exactly as before."""
    result, _reached = self._call("reports:export", tenant_id=None)
    self.assertNotEqual(result, {"success": False, "error": "forbidden", "status_code": 403})

  def test_a_malformed_tenant_id_is_refused_before_anything_else(self):
    """Narrowing on the operation must not let a malformed selector through on a granted one.
    `_admitted_snapshot` validates the shape and answers 400 invalid_request, effect-free -- which
    is the right answer, since a blank or non-string tenant id is a bad request rather than a
    refused one."""
    for tenant_id in ("", "   ", 7, [], {}):
      with self.subTest(tenant_id=tenant_id):
        result, reached = self._call("jobs:purge", tenant_id=tenant_id)
        self.assertEqual(result, {"success": False, "error": "invalid_request",
                                  "status_code": 400}, result)
        self.assertEqual(reached, [], "the effect ran for a malformed tenant selector")


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
    # `_purge_operation` is the one intended forwarder (B9): it validates the tenant itself and
    # passes it through. Exempt it by name rather than deleting the assertion -- this guard is what
    # catches the *next* endpoint opting into tenant scope, and it is inert if left red.
    # `stop_monitoring` opted in under the RM-026 MVP (2026-09-15): it forwards the caller's
    # explicit selector and "reports:export" is admitted at both tenant seams. Still by name.
    # RM-084 P1 opted the E1 export effects in, P2 the E2 ingest and review mutations, and P3
    # `delete_job_engagement` -- the last one. Each refuses a missing tenant before admission, so
    # the unscoped count below is now zero and this guard turns into the stronger statement: no
    # endpoint may reintroduce an unscoped effect.
    forwarders = {"_purge_operation", "stop_monitoring", "export_misp", "export_stix_bundle",
                  "dry_run_opencti_export", "push_to_opencti", "dry_run_taxii_export",
                  "publish_to_taxii", "correlate_suricata_eve", "generate_rulebook_assessment",
                  "save_rulebook_review_draft", "submit_rulebook_review", "reopen_rulebook_review",
                  "update_rulebook_review", "delete_job_engagement",
                  "approve_report", "reject_report"}
    enclosing = {}
    for node in ast.walk(tree):
      if isinstance(node, ast.FunctionDef):
        for inner in ast.walk(node):
          enclosing[id(inner)] = node.name
    unscoped = 0
    for call in calls:
      wrapper = getattr(call.func, "attr", None)
      # _effect_operation(self, request_actor, tenant_id, apply_effect, ...) and
      # _review_operation(self, request_actor, tenant_id, job_id, apply_review, ...)
      tenant_arg = call.args[2]
      name = enclosing.get(id(call))
      if name in forwarders or name in ("_effect_operation", "_purge_operation"):
        # An opted-in endpoint may only forward the caller's own selector, never a fabricated one.
        self.assertIsInstance(tenant_arg, ast.Name, ast.dump(call))
        self.assertEqual(tenant_arg.id, "tenant_id", ast.dump(call))
        continue
      self.assertIsInstance(tenant_arg, ast.Constant, ast.dump(call))
      self.assertIsNone(tenant_arg.value,
                        "an endpoint opted into tenant scope outside its own slice: "
                        + ast.dump(call))
      unscoped += 1
    self.assertEqual(unscoped, 0,
                     "an endpoint reintroduced an unscoped effect: the half is gone (RM-084 P3)")



if __name__ == "__main__":
  unittest.main()
