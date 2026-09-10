"""Namespace-bound administration records with observable write verification.

Verification is a local read-back, not a distributed transaction or freshness guarantee.
"""
import json

from ..ports import TenantStoreError
from ..nodes import validate_node_assignment

MAX_ENUMERATED_RECORDS = 10000


class CstoreTenantAdministrationStore:
  def __init__(self, owner, namespace):
    self._owner = owner
    self._namespace = namespace

  def _location(self, kind, ids):
    if (not isinstance(self._namespace, str) or not self._namespace.strip()
        or not isinstance(kind, str) or not kind.strip() or not ids
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

  def _records(self):
    hkey, _ = self._location("tenant", ("enumeration",))
    try:
      records = self._owner.chainstore_hgetall(hkey=hkey)
    except Exception as exc:
      raise TenantStoreError("Tenant storage cannot be enumerated") from exc
    if not isinstance(records, dict) or len(records) > MAX_ENUMERATED_RECORDS:
      raise TenantStoreError("Tenant storage enumeration is unavailable")
    return records

  def _fields(self, kind, tenant_id=None):
    for key, raw in self._records().items():
      try:
        field = json.loads(key) if isinstance(key, str) else None
      except (ValueError, RecursionError):
        continue
      # A short core hash collision must not expose or corrupt another namespace's rows.
      if (isinstance(field, list) and len(field) >= 3
          and field[:2] == [kind, self._namespace]):
        if tenant_id is not None and field[2] != tenant_id:
          continue
        if key != self._location(kind, field[2:])[1]:
          raise TenantStoreError("Invalid tenant storage field")
        yield field[2:], raw

  def list_node_assignments(self, tenant_id):
    self._location("tenant_node", (tenant_id,))
    return [self._validate(raw, "tenant_node", ids)
            for ids, raw in self._fields("tenant_node", tenant_id)]

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

  def count_assets(self, tenant_id):
    self._location("asset", (tenant_id,))
    count = 0
    for ids, raw in self._fields("asset"):
      if ids[0] != tenant_id:
        continue
      try:
        row = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else raw
      except (ValueError, UnicodeError, RecursionError) as exc:
        raise TenantStoreError("Invalid asset storage record") from exc
      if (len(ids) != 2 or not isinstance(ids[1], str) or not ids[1].strip()
          or not isinstance(row, dict) or type(row.get("schemaVersion")) is not int
          or row["schemaVersion"] != 1 or row.get("namespace") != self._namespace
          or row.get("tenant_id") != tenant_id or row.get("asset_id") != ids[1]
          or type(row.get("active")) is not bool):
        raise TenantStoreError("Invalid asset storage record")
      count += int(row["active"])
    return count
