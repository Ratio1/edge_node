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


class DocumentStoreError(TenantStoreError):
  """A document backend failure. A TenantStoreError, so administration endpoints answer 503."""


class DocumentStore(Protocol):
  """RM-095. Where tenant documents (contracts, later engagement documents) live.

  Storage only: ownership is decided by the tenant record that holds the reference, never by the
  stored document. `name` is written into every doc ref as `store`, so a reference keeps pointing
  at its backend when a second one (RM-097) is added.
  """
  name: str

  def put(self, envelope: dict) -> str:
    """Store one document envelope; return its reference, or raise DocumentStoreError."""
    ...

  def get(self, ref: str) -> dict | None:
    """Read an envelope; None when absent or not an envelope; DocumentStoreError on failure."""
    ...

  def delete(self, ref: str) -> None:
    """RM-107. Remove one envelope for good; DocumentStoreError when the backend did not confirm it."""
    ...
