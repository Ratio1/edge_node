"""Pure named-role policy for existing tenants; not an endpoint or storage boundary.

All inputs must be resolved server-side. This module neither authenticates requests nor proves
tenant/asset existence or freshness. Endpoint wiring must resolve those facts and enforce the
returned decision before reads or side effects. Legacy account role/app_role never grant authority.
"""
from dataclasses import dataclass

from .identity import AccountView, TenantMembership, canonical_account_id


# The accepted named-role matrix only. No wildcard authority or capability exceptions.
_ROLE_OPERATIONS = {
  "super_tenant_admin": frozenset({
    "node_assignments:manage", "node_failure_policy:update",
    "tenants:manage", "tenant_users:manage", "assets:create", "assets:update",
    "integrations:manage", "attestation_keys:manage", "allow_pentester:update",
    "tasks:launch", "tasks:update", "reports:view", "reports:export", "evidence:read", "audit:view",
  }),
  "super_pentester": frozenset({
    "assets:create", "assets:update", "allow_pentester:update", "tasks:launch", "tasks:update",
    "reports:view", "reports:export", "evidence:read",
  }),
  "tenant_admin": frozenset({
    "node_failure_policy:update",
    "tenant_users:manage", "integrations:manage", "attestation_keys:manage",
    "reports:view", "reports:export", "audit:view",
  }),
  "tenant_pentester": frozenset({"tasks:launch", "tasks:update", "reports:view", "reports:export"}),
  "tenant_user": frozenset({"reports:view"}),
}
_PLATFORM_ROLES = frozenset({"super_tenant_admin", "super_pentester"})


@dataclass(frozen=True)
class TenantPolicyContext:
  """An existing tenant's server-resolved policy, not a request DTO or persistence schema."""

  tenant_id: str
  active: bool
  allow_pentester: bool


@dataclass(frozen=True)
class PolicyDecision:
  allowed: bool
  status_code: int
  error: str | None


def _valid_id(value):
  return isinstance(value, str) and bool(value.strip())


def _valid_actor(actor):
  if (not isinstance(actor, AccountView) or actor.active is not True
      or not actor.account_id or canonical_account_id(actor.account_id) != actor.account_id):
    return False
  if not isinstance(actor.tenant_memberships, tuple):
    return False
  for membership in actor.tenant_memberships:
    if (not isinstance(membership, TenantMembership) or not isinstance(membership.role, str)
        or membership.role not in _ROLE_OPERATIONS):
      return False
    if membership.tenant_id is None:
      if membership.role not in _PLATFORM_ROLES:
        return False
    elif not _valid_id(membership.tenant_id):
      return False
  return True


def resolve_tenant_roles(actor, tenant_id):
  """Scope precheck only: return roles or denial without asserting tenant existence/permission."""
  if not _valid_actor(actor) or not _valid_id(tenant_id):
    return frozenset(), PolicyDecision(False, 404, "not_found")
  roles = frozenset(m.role for m in actor.tenant_memberships
                    if m.tenant_id == tenant_id or (m.tenant_id is None and m.role in _PLATFORM_ROLES))
  if not roles:
    return roles, PolicyDecision(False, 404, "not_found")
  return roles, None


def resolve_operation_roles(actor, operation, tenant):
  """Role precheck on a real active tenant, not final asset/pentesting authorization."""
  if (not isinstance(tenant, TenantPolicyContext) or tenant.active is not True
      or type(tenant.allow_pentester) is not bool):
    return frozenset(), PolicyDecision(False, 404, "not_found")
  roles, denial = resolve_tenant_roles(actor, tenant.tenant_id)
  if denial is not None:
    return roles, denial
  eligible = frozenset(role for role in roles if isinstance(operation, str)
                       and operation in _ROLE_OPERATIONS[role])
  if not eligible:
    return eligible, PolicyDecision(False, 403, "forbidden")
  return eligible, None


def authorize_tenant_operation(
  actor: AccountView | None,
  operation: str,
  tenant: TenantPolicyContext | None,
  *,
  asset_tenant_ids: tuple[str | None, ...] = (),
) -> PolicyDecision:
  """Evaluate supplied facts; use ``decision.allowed``, not the decision object's truthiness.

  For task launch/update, ``asset_tenant_ids`` must contain the owner of every server-resolved
  existing/preset asset. Empty/unknown owners deny; never build this tuple from request claims.
  No lifecycle, capability-grant or arbitrary object/CID authorization is provided here.
  """
  roles, denial = resolve_operation_roles(actor, operation, tenant)
  if denial is not None:
    return denial
  if operation in ("tasks:launch", "tasks:update"):
    if (not isinstance(asset_tenant_ids, tuple) or not asset_tenant_ids
        or any(not _valid_id(owner) or owner != tenant.tenant_id for owner in asset_tenant_ids)):
      return PolicyDecision(False, 404, "not_found")
    if not roles & _PLATFORM_ROLES and tenant.allow_pentester is not True:
      return PolicyDecision(False, 403, "pentesting_disabled")
  return PolicyDecision(True, 200, None)
