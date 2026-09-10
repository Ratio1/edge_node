"""Resolve stored facts before policy evaluation; not wired to live endpoints yet."""
from dataclasses import dataclass

from .identity import AccountView, resolve_actor
from .policy import (
  PolicyDecision, TenantPolicyContext, authorize_tenant_operation,
  resolve_operation_roles, resolve_tenant_roles,
)
from .ports import TenantReader, TenantStoreError


@dataclass(frozen=True)
class AuthorizedTenantContext:
  account: AccountView
  tenant: TenantPolicyContext
  asset_ids: tuple[str, ...]


class TenantAuthorizationService:
  """Read fresh facts per call, without an atomic snapshot or reusable authorization lease.

  The caller must select the operation in trusted route code and authenticate the forwarded
  account selector at the existing BFF boundary. This does not authorize arbitrary jobs/CIDs.
  """
  def __init__(self, account_reader, tenant_reader: TenantReader):
    self._account_reader = account_reader
    self._tenant_reader = tenant_reader

  def authorize(self, actor, operation, tenant_id, *, asset_ids=()):
    try:
      return self._resolve(actor, operation, tenant_id, asset_ids)
    except TenantStoreError:
      return None, PolicyDecision(False, 503, "unavailable")

  def _resolve(self, actor, operation, tenant_id, asset_ids):
    account, error = resolve_actor(actor, self._account_reader)
    if error:
      return None, PolicyDecision(False, error["status_code"], error["error"])
    _, denial = resolve_tenant_roles(account, tenant_id)
    if denial is not None:
      return None, denial
    tenant = self._tenant_reader.get_tenant_policy(tenant_id)
    if not isinstance(tenant, TenantPolicyContext) or tenant.tenant_id != tenant_id:
      return None, PolicyDecision(False, 404, "not_found")
    _, denial = resolve_operation_roles(account, operation, tenant)
    if denial is not None:
      return None, denial
    validated_ids = ()
    if operation in ("tasks:launch", "tasks:update"):
      if not isinstance(asset_ids, (list, tuple)):
        return None, PolicyDecision(False, 404, "not_found")
      validated_ids = tuple(asset_ids)
      if not validated_ids or any(not isinstance(value, str) or not value.strip() for value in validated_ids):
        return None, PolicyDecision(False, 404, "not_found")
    owners = tuple(self._tenant_reader.get_asset_owner(tenant_id, asset_id) for asset_id in validated_ids)
    decision = authorize_tenant_operation(account, operation, tenant, asset_tenant_ids=owners)
    if not decision.allowed:
      return None, decision
    return AuthorizedTenantContext(account, tenant, validated_ids), decision
