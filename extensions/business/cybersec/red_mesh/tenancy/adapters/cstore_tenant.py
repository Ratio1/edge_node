"""CStore read projections for tenancy; not a workspace writer or publication protocol."""
import json

from ..policy import TenantPolicyContext
from ..ports import TenantStoreError


def _valid_id(value):
  return isinstance(value, str) and bool(value.strip())


class CstoreTenantReader:
  """Read strict v1 projections in a trusted, explicitly supplied deployment namespace.

  Full namespace/IDs belong in each field key as well as the record: core truncates hkey hashes.
  There is no legacy fallback, writer or activation contract here. Surfaced failures raise;
  core failures swallowed as None are indistinguishable from absence and deny as not found.
  """
  def __init__(self, owner, namespace):
    self._owner = owner
    self._namespace = namespace

  def _read(self, kind, tenant_id, *ids):
    if not _valid_id(tenant_id) or any(not _valid_id(value) for value in ids):
      return None
    if not _valid_id(self._namespace):
      raise TenantStoreError("Tenant storage namespace is not configured")
    hkey = json.dumps(["redmesh", "tenancy", 1, self._namespace], separators=(",", ":"))
    key = json.dumps([kind, self._namespace, tenant_id, *ids], separators=(",", ":"))
    try:
      raw = self._owner.chainstore_hget(hkey=hkey, key=key)
    except Exception as exc:
      raise TenantStoreError("Tenant storage cannot be read") from exc
    if isinstance(raw, (bytes, bytearray)):
      try:
        raw = raw.decode("utf-8")
      except UnicodeError:
        return None
    if isinstance(raw, str):
      try:
        raw = json.loads(raw)
      except (ValueError, RecursionError):
        return None
    if (not isinstance(raw, dict) or type(raw.get("schemaVersion")) is not int
        or raw["schemaVersion"] != 1 or raw.get("namespace") != self._namespace
        or raw.get("tenant_id") != tenant_id or raw.get("active") is not True):
      return None
    return raw

  def get_tenant_policy(self, tenant_id):
    row = self._read("tenant", tenant_id)
    if row is None or type(row.get("allow_pentester")) is not bool:
      return None
    return TenantPolicyContext(row["tenant_id"], row["active"], row["allow_pentester"])

  def get_asset_owner(self, tenant_id, asset_id):
    row = self._read("asset", tenant_id, asset_id)
    return row["tenant_id"] if row is not None and row.get("asset_id") == asset_id else None
