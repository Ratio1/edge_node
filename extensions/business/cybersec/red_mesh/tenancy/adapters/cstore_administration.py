"""Namespace-bound administration records with observable write verification.

Verification is a local read-back, not a distributed transaction or freshness guarantee.
"""
import json

from ..ports import TenantStoreError
from ..integrations import validate_integration
from ..nodes import validate_node_assignment
from ..engagements import validate_engagement

MAX_ENUMERATED_RECORDS = 10000
# RM-107 retired the tenant `asset` kind (the engagement owns its targets): a kind outside this list
# is never read or written, so a leftover row cannot come back through a new code path.
_KINDS = frozenset({"tenant", "receipt", "domain", "tenant_node", "integration", "engagement"})


class CstoreTenantAdministrationStore:
  def __init__(self, owner, namespace):
    self._owner = owner
    self._namespace = namespace

  @property
  def namespace(self):
    return self._namespace

  def _location(self, kind, ids):
    if (not isinstance(self._namespace, str) or not self._namespace.strip()
        or kind not in _KINDS or not ids
        or any(not isinstance(value, str) or not value.strip() for value in ids)):
      raise TenantStoreError("Invalid tenant storage binding")
    hkey = json.dumps(["redmesh", "tenancy", 1, self._namespace], separators=(",", ":"))
    key = json.dumps([kind, self._namespace, *ids], separators=(",", ":"))
    return hkey, key

  def get(self, kind, *ids):
    hkey, key = self._location(kind, ids)
    try:
      raw = self._owner.chainstore_hget(hkey=hkey, key=key)
    except Exception as exc:
      raise TenantStoreError("Tenant storage cannot be read") from exc
    if raw is None:
      return None
    return self._validate(raw, kind, ids)

  def _validate(self, raw, kind, ids):
    self._location(kind, ids)
    try:
      if isinstance(raw, (str, bytes, bytearray)):
        raw = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
      raise TenantStoreError("Invalid tenant storage record") from exc
    if (not isinstance(raw, dict) or type(raw.get("schemaVersion")) is not int
        or raw["schemaVersion"] != 1 or raw.get("namespace") != self._namespace
        or raw.get("kind") != kind or raw.get("ids") != list(ids)
        or (kind == "tenant" and (len(ids) != 1 or raw.get("tenant_id") != ids[0]))):
      raise TenantStoreError("Invalid tenant storage record")
    if kind == "tenant_node":
      validate_node_assignment(raw, ids)
    if kind == "integration":
      validate_integration(raw, ids)
    if kind == "engagement":
      try:
        validate_engagement(raw, ids)
      except (ValueError, TypeError, KeyError, RecursionError) as exc:
        raise TenantStoreError("Invalid engagement storage record") from exc
    return raw

  def put(self, kind, *ids, record):
    hkey, key = self._location(kind, ids)
    if not isinstance(record, dict):
      raise TenantStoreError("Invalid tenant storage record")
    envelope = {"schemaVersion": 1, "namespace": self._namespace,
                "kind": kind, "ids": list(ids)}
    for name, value in envelope.items():
      if name in record and (record[name] != value
                             or (name == "schemaVersion" and type(record[name]) is not int)):
        raise TenantStoreError("Conflicting tenant storage binding")
    row = self._validate({**record, **envelope}, kind, ids)
    try:
      expected = json.dumps(row, sort_keys=True, allow_nan=False)
      row = json.loads(expected)
      written = self._owner.chainstore_hset(hkey=hkey, key=key, value=row)
    except Exception as exc:
      raise TenantStoreError("Tenant storage write could not be verified") from exc
    if written is not True:
      raise TenantStoreError("Tenant storage write could not be verified")
    try:
      observed = json.dumps(self.get(kind, *ids), sort_keys=True, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
      raise TenantStoreError("Tenant storage write could not be verified") from exc
    if observed != expected:
      raise TenantStoreError("Tenant storage write could not be verified")

  def delete(self, kind, *ids):
    """RM-107. Remove one record (a CStore tombstone) and verify it reads back as absent."""
    hkey, key = self._location(kind, ids)
    try:
      self._owner.chainstore_hset(hkey=hkey, key=key, value=None)
      remaining = self._owner.chainstore_hget(hkey=hkey, key=key)
    except Exception as exc:
      raise TenantStoreError("Tenant storage delete could not be verified") from exc
    if remaining is not None:
      raise TenantStoreError("Tenant storage delete could not be verified")

  def tenant_record_ids(self, kind, tenant_id):
    """RM-107. The ids of a tenant's rows of one kind, without validating them: a delete must clear
    rows the current validator refuses (an engagement written by an older release)."""
    self._location(kind, (tenant_id,))
    return [ids for ids, _ in self._fields(kind, tenant_id)]

  def raw_record(self, kind, *ids):
    """RM-107. One row decoded but not validated, for the same reason; None when absent or unreadable."""
    hkey, key = self._location(kind, ids)
    try:
      raw = self._owner.chainstore_hget(hkey=hkey, key=key)
      raw = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else raw
    except Exception as exc:
      raise TenantStoreError("Tenant storage cannot be read") from exc
    return raw if isinstance(raw, dict) else None

  def _records(self):
    hkey, _ = self._location("tenant", ("enumeration",))
    try:
      records = self._owner.chainstore_hgetall(hkey=hkey)
    except Exception as exc:
      raise TenantStoreError("Tenant storage cannot be enumerated") from exc
    if not isinstance(records, dict) or len(records) > MAX_ENUMERATED_RECORDS:
      raise TenantStoreError("Tenant storage enumeration is unavailable")
    return records

  def _fields(self, kind, tenant_id=None, node_address=None):
    for key, raw in self._records().items():
      # A deleted record (RM-107 `delete`) is a tombstone, not a row.
      if raw is None:
        continue
      try:
        field = json.loads(key) if isinstance(key, str) else None
      except (ValueError, RecursionError):
        continue
      # A short core hash collision must not expose or corrupt another namespace's rows.
      if (isinstance(field, list) and len(field) >= 3
          and field[:2] == [kind, self._namespace]):
        if tenant_id is not None and field[2] != tenant_id:
          continue
        # RM-102: the cross-tenant read for one node skips rows naming another node, so their
        # corruption cannot block an unrelated assignment.
        if node_address is not None and (len(field) < 4 or field[3] != node_address):
          continue
        if key != self._location(kind, field[2:])[1]:
          raise TenantStoreError("Invalid tenant storage field")
        yield field[2:], raw

  def list_node_assignments(self, tenant_id):
    self._location("tenant_node", (tenant_id,))
    return [self._validate(raw, "tenant_node", ids)
            for ids, raw in self._fields("tenant_node", tenant_id)]

  def list_node_assignments_for_node(self, node_address):
    """RM-102: every tenant's row for one node, for the write validator's cross-tenant conflict
    check. Rows are selected by the node in their field key; a malformed row naming this node
    fails the read closed, one naming another node is never decoded."""
    self._location("tenant_node", (node_address,))
    return [self._validate(raw, "tenant_node", ids)
            for ids, raw in self._fields("tenant_node", node_address=node_address)]

  def list_engagements(self, tenant_id):
    self._location("engagement", (tenant_id,))
    return [self._validate(raw, "engagement", ids) for ids, raw in self._fields("engagement", tenant_id)]

  def list_integrations(self, tenant_id):
    self._location("integration", (tenant_id,))
    return [self._validate(raw, "integration", ids)
            for ids, raw in self._fields("integration", tenant_id)]

  def list_tenants(self):
    rows = []
    for ids, raw in self._fields("tenant"):
      try:
        decoded = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else raw
      except (ValueError, UnicodeError, RecursionError) as exc:
        raise TenantStoreError("Invalid tenant storage record") from exc
      # Foundation projections have no administration DTO fields and were never published here.
      if isinstance(decoded, dict) and "kind" not in decoded and "ids" not in decoded:
        if (len(ids) == 1 and type(decoded.get("schemaVersion")) is int
            and decoded["schemaVersion"] == 1 and decoded.get("namespace") == self._namespace
            and decoded.get("tenant_id") == ids[0] and type(decoded.get("active")) is bool
            and type(decoded.get("allow_pentester")) is bool):
          continue
        raise TenantStoreError("Invalid tenant storage record")
      row = self._validate(decoded, "tenant", ids)
      if type(row.get("active")) is not bool or type(row.get("allow_pentester")) is not bool:
        raise TenantStoreError("Invalid tenant storage record")
      if row["active"]:
        rows.append(row)
    return rows

