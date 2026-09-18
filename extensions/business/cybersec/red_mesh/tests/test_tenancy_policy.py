"""Behavioral specification for the RM-026 pure existing-tenant policy seam."""
import json
import unittest
from dataclasses import FrozenInstanceError, replace
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import (
  AUTH_HKEY_ENV,
  CstoreAuthAccountReader,
)
from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView, TenantMembership, resolve_actor
from extensions.business.cybersec.red_mesh.tenancy.policy import (
  PolicyDecision,
  TenantPolicyContext,
  authorize_tenant_operation,
)


def account(*memberships):
  return AccountView("operator", True, tenant_memberships=tuple(
    TenantMembership(role, tenant_id) for role, tenant_id in memberships
  ))


def in_tenant(role, tenant_id):
  """The membership giving ``role`` in ``tenant_id``: a Super-Tenant Admin is always full-portfolio."""
  return (role, None if role == "super_tenant_admin" else tenant_id)


class TestTenantPolicy(unittest.TestCase):
  def test_report_authority_stays_inside_membership_tenant(self):
    actor = account(("tenant_user", "a"))
    self.assertEqual(
      authorize_tenant_operation(actor, "reports:view", TenantPolicyContext("a", True, False)),
      PolicyDecision(True, 200, None),
    )
    self.assertEqual(
      authorize_tenant_operation(actor, "reports:view", TenantPolicyContext("b", True, False)),
      PolicyDecision(False, 404, "not_found"),
    )

  def test_named_role_matrix_without_capability_exceptions(self):
    # Literal rows transcribed from the accepted workspace contract, not production tables.
    roles = ("super_tenant_admin", "super_pentester", "tenant_admin", "tenant_pentester", "tenant_user")
    rows = (
      ("tenants:manage",          (True, False, False, False, False)),
      ("tenant_users:manage",     (True, False, True, False, False)),
      ("assets:create",           (True, True, False, False, False)),
      ("assets:update",           (True, True, False, False, False)),
      ("integrations:manage",     (True, False, True, False, False)),
      ("attestation_keys:manage", (True, False, True, False, False)),
      ("allow_pentester:update",  (True, True, False, False, False)),
      ("tasks:launch",            (True, True, False, True, False)),
      ("tasks:update",            (True, True, False, True, False)),
      ("reports:view",            (True, True, True, True, True)),
      ("reports:export",          (True, True, True, True, False)),
      ("evidence:read",           (True, True, False, False, False)),
      ("audit:view",              (True, False, True, False, False)),
    )
    for operation, expected in rows:
      for role, allowed in zip(roles, expected):
        with self.subTest(operation=operation, role=role):
          self.assertEqual(
            authorize_tenant_operation(account(in_tenant(role, "a")), operation,
                                       TenantPolicyContext("a", True, True), asset_tenant_ids=("a",)),
            PolicyDecision(True, 200, None) if allowed else PolicyDecision(False, 403, "forbidden"),
          )

  def test_platform_scope_is_explicit_and_roles_compose_only_in_scope(self):
    tenant = TenantPolicyContext("b", True, True)
    self.assertEqual(authorize_tenant_operation(account(("super_pentester", "a")), "reports:view", tenant),
                     PolicyDecision(False, 404, "not_found"))
    allowlisted = account(("super_pentester", "a"), ("super_pentester", "b"))
    self.assertTrue(authorize_tenant_operation(allowlisted, "assets:create", tenant).allowed)
    self.assertTrue(authorize_tenant_operation(account(("super_tenant_admin", None), ("super_pentester", None)),
                                             "tenants:manage", tenant).allowed)
    for role in ("super_tenant_admin", "super_pentester"):
      with self.subTest(role=role):
        self.assertTrue(authorize_tenant_operation(account((role, None)), "assets:create", tenant).allowed)
    combined = account(("tenant_admin", "b"), ("tenant_pentester", "b"))
    self.assertTrue(authorize_tenant_operation(combined, "integrations:manage", tenant).allowed)
    self.assertTrue(authorize_tenant_operation(combined, "tasks:launch", tenant,
                                             asset_tenant_ids=("b",)).allowed)
    self.assertFalse(authorize_tenant_operation(combined, "assets:update", tenant).allowed)

  def test_an_account_with_more_than_one_scope_is_denied_as_a_whole(self):
    # RM-083 (owner): an account is platform-scoped or scoped to one tenant, never both or two.
    tenant = TenantPolicyContext("b", True, True)
    for memberships in (
      (("super_tenant_admin", "b"),),
      (("super_tenant_admin", None), ("tenant_user", "b")),
      (("super_pentester", "b"), ("tenant_admin", "b")),
      (("tenant_admin", "a"), ("tenant_user", "b")),
      (("super_pentester", None), ("super_pentester", "b")),
    ):
      with self.subTest(memberships=memberships):
        self.assertEqual(authorize_tenant_operation(account(*memberships), "reports:view", tenant),
                         PolicyDecision(False, 404, "not_found"))

  def test_every_task_role_requires_nonempty_same_tenant_assets(self):
    tenant = TenantPolicyContext("a", True, True)
    for role in ("super_tenant_admin", "super_pentester", "tenant_pentester"):
      for operation in ("tasks:launch", "tasks:update"):
        for owners in ((), (None,), ("b",), ("a", "b"), ("a", None), "a", ["a"]):
          with self.subTest(role=role, operation=operation, owners=owners):
            self.assertEqual(authorize_tenant_operation(account(in_tenant(role, "a")), operation, tenant,
                                                       asset_tenant_ids=owners),
                             PolicyDecision(False, 404, "not_found"))
        self.assertTrue(authorize_tenant_operation(account(in_tenant(role, "a")), operation, tenant,
                                                 asset_tenant_ids=("a", "a")).allowed)

  def test_allow_pentester_gates_only_tenant_task_authority_in_selected_scope(self):
    tenant = TenantPolicyContext("a", True, False)
    pentester = account(("tenant_pentester", "a"))
    for operation in ("tasks:launch", "tasks:update"):
      self.assertEqual(authorize_tenant_operation(pentester, operation, tenant, asset_tenant_ids=("a",)),
                       PolicyDecision(False, 403, "pentesting_disabled"))
      for role in ("super_tenant_admin", "super_pentester"):
        with self.subTest(operation=operation, role=role):
          for platform in {(role, None), in_tenant(role, "a")}:
            self.assertTrue(authorize_tenant_operation(account(platform), operation, tenant,
                                                     asset_tenant_ids=("a",)).allowed)
    self.assertTrue(authorize_tenant_operation(pentester, "reports:view", tenant).allowed)

  def test_denial_precedence_does_not_disclose_pentesting_policy_or_asset_ownership(self):
    disabled = TenantPolicyContext("a", True, False)
    self.assertEqual(authorize_tenant_operation(account(("tenant_pentester", "b")), "tasks:launch",
                                               disabled, asset_tenant_ids=("a",)),
                     PolicyDecision(False, 404, "not_found"))
    for enabled in (False, True):
      tenant = TenantPolicyContext("a", True, enabled)
      self.assertEqual(authorize_tenant_operation(account(("tenant_pentester", "a")), "tasks:launch",
                                                 tenant, asset_tenant_ids=("b",)),
                       PolicyDecision(False, 404, "not_found"))
      for owners in (("a",), ("b",), ()):
        self.assertEqual(authorize_tenant_operation(account(("tenant_user", "a")), "tasks:launch",
                                                   tenant, asset_tenant_ids=owners),
                         PolicyDecision(False, 403, "forbidden"))

  def test_missing_inactive_or_malformed_context_has_one_not_found_decision(self):
    actor = account(("super_tenant_admin", None))
    tenant = TenantPolicyContext("a", True, True)
    invalid_actors = (
      None, {}, "operator", replace(actor, active=False), replace(actor, active=1),
      replace(actor, active="true"), replace(actor, account_id=""), replace(actor, account_id="Bad ID"),
      replace(actor, tenant_memberships=()), replace(actor, tenant_memberships=None),
      replace(actor, tenant_memberships=[TenantMembership("super_tenant_admin", None)]),
      replace(actor, tenant_memberships=(None,)),
      replace(actor, tenant_memberships=(TenantMembership("tenant_admin", None),)),
      replace(actor, tenant_memberships=(TenantMembership("super_tenant_admin", ""),)),
      replace(actor, tenant_memberships=(TenantMembership("super_tenant_admin", 1),)),
      replace(actor, tenant_memberships=(TenantMembership({}, "a"),)),
      replace(actor, tenant_memberships=actor.tenant_memberships + (TenantMembership("unknown", "b"),)),
      replace(actor, tenant_memberships=actor.tenant_memberships + (TenantMembership("ratio1_deployer", None),)),
    )
    invalid_tenants = (
      None, {}, "a", replace(tenant, tenant_id=None), replace(tenant, tenant_id=""),
      replace(tenant, tenant_id=" "), replace(tenant, tenant_id=1), replace(tenant, active=False),
      replace(tenant, active=1), replace(tenant, active="true"), replace(tenant, allow_pentester=None),
      replace(tenant, allow_pentester=1), replace(tenant, allow_pentester="false"),
    )
    for invalid in invalid_actors:
      with self.subTest(actor=invalid):
        self.assertEqual(authorize_tenant_operation(invalid, "reports:view", tenant),
                         PolicyDecision(False, 404, "not_found"))
    for invalid in invalid_tenants:
      with self.subTest(tenant=invalid):
        self.assertEqual(authorize_tenant_operation(actor, "reports:view", invalid),
                         PolicyDecision(False, 404, "not_found"))

  def test_unsupported_and_malformed_operations_never_inherit_admin_authority(self):
    actor = account(("super_tenant_admin", None))
    tenant = TenantPolicyContext("a", True, True)
    for operation in ("bootstrap", "tenants:create", "platform_accounts:manage", "allowlists:manage",
                      "resources:update", "tenants:offboard", "evidence:purge", "unknown", "*",
                      " reports:view ", "REPORTS:VIEW", None, {}, [], 1):
      with self.subTest(operation=operation):
        self.assertEqual(authorize_tenant_operation(actor, operation, tenant),
                         PolicyDecision(False, 403, "forbidden"))

  def test_context_and_decisions_are_immutable(self):
    tenant = TenantPolicyContext("a", True, True)
    decision = authorize_tenant_operation(account(("tenant_user", "a")), "reports:view", tenant)
    with self.assertRaises(FrozenInstanceError):
      tenant.tenant_id = "b"
    with self.assertRaises(FrozenInstanceError):
      decision.allowed = False

  def test_bootstrap_actor_has_no_ordinary_tenant_authority(self):
    deployer = account(("ratio1_deployer", None))
    for operation in ("tenants:manage", "assets:create", "tasks:launch", "reports:view", "bootstrap"):
      with self.subTest(operation=operation):
        self.assertEqual(authorize_tenant_operation(deployer, operation, TenantPolicyContext("a", True, True),
                                                   asset_tenant_ids=("a",)),
                         PolicyDecision(False, 404, "not_found"))


class TestIdentityPolicyBoundary(unittest.TestCase):
  def test_real_reader_ignores_forged_role_scope_and_owner_fields(self):
    from .test_account_record_v1 import T1, T2, record
    raw = json.dumps(record("operator", memberships=[{"role": "tenant_pentester", "tenant_id": T1}]))
    store = {"operator": raw}
    reader = CstoreAuthAccountReader(SimpleNamespace(chainstore_hget=lambda **kw: store.get(kw["key"])))
    forged = {"account_id": " OPERATOR ", "role": "super_tenant_admin", "tenant_id": T2,
              "scope": "*", "owner": "operator", "tenant_memberships": [
                {"role": "super_tenant_admin", "tenant_id": None},
              ]}
    with patch.dict("os.environ", {AUTH_HKEY_ENV: "test-policy-auth"}):
      actor, error = resolve_actor(forged, reader)
    self.assertIsNone(error)
    self.assertTrue(authorize_tenant_operation(actor, "reports:export", TenantPolicyContext(T1, True, True)).allowed)
    self.assertEqual(authorize_tenant_operation(actor, "reports:export", TenantPolicyContext(T2, True, True)),
                     PolicyDecision(False, 404, "not_found"))

  def test_fresh_reader_result_revokes_authority_without_policy_cache_fallback(self):
    from .test_account_record_v1 import T2, record
    platform = [{"role": "super_tenant_admin", "tenant_id": None}]
    store = {"operator": json.dumps(record("operator", memberships=platform))}
    reader = CstoreAuthAccountReader(SimpleNamespace(chainstore_hget=lambda **kw: store.get(kw["key"])))
    tenant = TenantPolicyContext("tn_12345678-1234-4234-8234-123456789abc", True, True)
    stamp = {"stateChangedAt": "2026-01-02T00:00:00.000Z", "stateChangedBy": "admin.user"}
    with patch.dict("os.environ", {AUTH_HKEY_ENV: "test-policy-auth"}):
      actor, error = resolve_actor({"account_id": "operator"}, reader)
      self.assertIsNone(error)
      self.assertTrue(authorize_tenant_operation(actor, "assets:create", tenant).allowed)
      for revoked in (record("operator", memberships=[]),
                      {**record("operator"), "memberships": None},
                      record("operator", memberships=platform, state="deleting", **stamp),
                      record("operator", memberships=platform, state="deactivated", **stamp),
                      record("operator", memberships=[{"role": "tenant_user", "tenant_id": T2}])):
        with self.subTest(revoked=revoked):
          store["operator"] = json.dumps(revoked)
          actor, _ = resolve_actor({"account_id": "operator"}, reader)
          self.assertEqual(authorize_tenant_operation(actor, "assets:create", tenant),
                           PolicyDecision(False, 404, "not_found"))


class TestNoAccountRole(unittest.TestCase):
  """RM-082 pinned that the account role and `app_role` never grant authority. RM-084 P6 removed them:
  the resolved identity has no field that could carry one, so the rule no longer needs a sweep."""

  def test_the_resolved_identity_carries_no_account_role(self):
    from dataclasses import fields
    self.assertEqual({field.name for field in fields(AccountView)},
                     {"account_id", "active", "state", "tenant_memberships", "account_generation"})

  def test_record_role_vocabulary_is_the_matrix(self):
    from extensions.business.cybersec.red_mesh.tenancy.account_record import MEMBERSHIP_ROLES
    from extensions.business.cybersec.red_mesh.tenancy.policy import PLATFORM_ROLES, TENANT_LOCAL_ROLES, _ROLE_OPERATIONS
    self.assertEqual(MEMBERSHIP_ROLES, PLATFORM_ROLES | TENANT_LOCAL_ROLES)
    self.assertLessEqual(MEMBERSHIP_ROLES, frozenset(_ROLE_OPERATIONS))
    self.assertEqual(TENANT_LOCAL_ROLES, frozenset({"tenant_admin", "tenant_pentester", "tenant_user"}))
    self.assertEqual(PLATFORM_ROLES, frozenset({"super_tenant_admin", "super_pentester"}))

