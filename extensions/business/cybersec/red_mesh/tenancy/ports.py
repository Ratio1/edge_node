"""Read-side tenant storage contract; no persistence/activation or transaction guarantee."""
from typing import Protocol

from .policy import TenantPolicyContext


class TenantStoreError(RuntimeError):
  """A surfaced storage/configuration failure. Core reads can also fail silently as None."""


class TenantReader(Protocol):
  def get_tenant_policy(self, tenant_id: str) -> TenantPolicyContext | None:
    """Read a bound active policy, None for absent/invalid data, or raise TenantStoreError."""
    ...

  def get_asset_owner(self, tenant_id: str, asset_id: str) -> str | None:
    """Read the owner of a bound existing active asset; never infer it from the selector."""
    ...
