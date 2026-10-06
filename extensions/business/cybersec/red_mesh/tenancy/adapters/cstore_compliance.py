"""RM-120: the compliance key space, apart from the tenancy hkey.

`["redmesh","tenancy-compliance",1,<namespace>]` holds the framework maturity self-assessment
rows (`framework_assessment`, keyed `[kind, namespace, tenant_id, pack_id]`). They are large
(hundreds of kilobytes at the caps) and must never be pulled by the tenancy enumeration that backs
tenant, engagement and node listings. Same envelope and read-back verification as
`cstore_administration.py`; same enumeration cap.
"""
import json

from ..compliance import KIND as ASSESSMENT_KIND, validate_framework_assessment
from ..ports import TenantStoreError
from .cstore_administration import MAX_ENUMERATED_RECORDS

_KINDS = frozenset({ASSESSMENT_KIND})


class CstoreComplianceStore:
  def __init__(self, owner, namespace):
    self._owner = owner
    self._namespace = namespace

  @property
  def namespace(self):
    return self._namespace

  @property
  def hkey(self):
    return json.dumps(["redmesh", "tenancy-compliance", 1, self._namespace], separators=(",", ":"))

  def _location(self, kind, ids):
    if (not isinstance(self._namespace, str) or not self._namespace.strip()
        or kind not in _KINDS or len(ids) != 2
        or any(not isinstance(value, str) or not value.strip() for value in ids)):
      raise TenantStoreError("Invalid compliance storage binding")
    return self.hkey, json.dumps([kind, self._namespace, *ids], separators=(",", ":"))

  def _validate(self, raw, kind, ids):
    self._location(kind, ids)
    try:
      if isinstance(raw, (str, bytes, bytearray)):
        raw = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
      raise TenantStoreError("Invalid compliance storage record") from exc
    if (not isinstance(raw, dict) or type(raw.get("schemaVersion")) is not int
        or raw["schemaVersion"] != 1 or raw.get("namespace") != self._namespace
        or raw.get("kind") != kind or raw.get("ids") != list(ids)):
      raise TenantStoreError("Invalid compliance storage record")
    try:
      validate_framework_assessment(raw, ids)
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as exc:
      raise TenantStoreError("Invalid framework assessment storage record") from exc
    return raw

  def get(self, kind, *ids):
    hkey, key = self._location(kind, ids)
    try:
      raw = self._owner.chainstore_hget(hkey=hkey, key=key)
    except Exception as exc:
      raise TenantStoreError("Compliance storage cannot be read") from exc
    if raw is None:
      return None
    return self._validate(raw, kind, ids)

  def put(self, kind, *ids, record):
    hkey, key = self._location(kind, ids)
    if not isinstance(record, dict):
      raise TenantStoreError("Invalid compliance storage record")
    envelope = {"schemaVersion": 1, "namespace": self._namespace, "kind": kind, "ids": list(ids)}
    for name, value in envelope.items():
      if name in record and record[name] != value:
        raise TenantStoreError("Conflicting compliance storage binding")
    row = self._validate({**record, **envelope}, kind, ids)
    try:
      expected = json.dumps(row, sort_keys=True, allow_nan=False)
      row = json.loads(expected)
      written = self._owner.chainstore_hset(hkey=hkey, key=key, value=row)
    except Exception as exc:
      raise TenantStoreError("Compliance storage write could not be verified") from exc
    if written is not True:
      raise TenantStoreError("Compliance storage write could not be verified")
    try:
      stored = self.get(kind, *ids)
      observed = json.dumps(stored, sort_keys=True, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as exc:
      raise TenantStoreError("Compliance storage write could not be verified") from exc
    if observed != expected:
      raise TenantStoreError("Compliance storage write could not be verified")
    return stored

  def delete(self, kind, *ids):
    hkey, key = self._location(kind, ids)
    try:
      self._owner.chainstore_hset(hkey=hkey, key=key, value=None)
      remaining = self._owner.chainstore_hget(hkey=hkey, key=key)
    except Exception as exc:
      raise TenantStoreError("Compliance storage delete could not be verified") from exc
    if remaining is not None:
      raise TenantStoreError("Compliance storage delete could not be verified")

  def raw_record(self, kind, *ids):
    hkey, key = self._location(kind, ids)
    try:
      raw = self._owner.chainstore_hget(hkey=hkey, key=key)
      raw = json.loads(raw) if isinstance(raw, (str, bytes, bytearray)) else raw
    except Exception as exc:
      raise TenantStoreError("Compliance storage cannot be read") from exc
    return raw if isinstance(raw, dict) else None

  def _records(self):
    try:
      records = self._owner.chainstore_hgetall(hkey=self.hkey)
    except Exception as exc:
      raise TenantStoreError("Compliance storage cannot be enumerated") from exc
    if records is None:
      return {}
    if not isinstance(records, dict) or len(records) > MAX_ENUMERATED_RECORDS:
      raise TenantStoreError("Compliance storage enumeration is unavailable")
    return records

  def tenant_record_ids(self, kind, tenant_id):
    """The ids of a tenant's rows of one kind, without validating them (a delete must clear rows
    the current validator refuses)."""
    if kind not in _KINDS or not isinstance(tenant_id, str) or not tenant_id.strip():
      raise TenantStoreError("Invalid compliance storage binding")
    found = []
    for key, raw in self._records().items():
      if raw is None:
        continue
      try:
        field = json.loads(key) if isinstance(key, str) else None
      except (ValueError, RecursionError):
        continue
      if (isinstance(field, list) and len(field) == 4 and field[:3] == [kind, self._namespace, tenant_id]
          and key == self._location(kind, field[2:])[1]):
        found.append(field[2:])
    return found
