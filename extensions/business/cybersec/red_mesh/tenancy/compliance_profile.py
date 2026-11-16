"""Tenant declarations and local edit history, committed in one verified CStore row.

The administration lock serializes this node only; CStore is not distributed CAS.
History follows tenant purge. Stable event IDs support future RM115 mirroring.
"""
import json
from datetime import datetime, timezone
from uuid import NAMESPACE_URL, uuid5

from ..references.framework_packs import COUNTRY_CODES, load_manifest
from .assets import canonical_digest, canonical_uuid
from . import compliance

KIND = "compliance_profile"
MAX_EVENTS = 500
MAX_WRITE_BYTES = 512 * 1024 - 1024
MAX_READ_BYTES = 2 * 1024 * 1024
_FIELDS = {"country", "sectors", "entity_class", "size_band", "sector_taxonomy"}
_ENVELOPE = {"schemaVersion", "namespace", "kind", "ids"}
_EVENT = {"event_id", "request_id", "request_digest", "actor", "at", "revision", "before", "after"}


def taxonomy():
  data = load_manifest()["sector_taxonomy"]
  return {"id": data["id"], "version": data["version"]}


def normalize_profile(value):
  if not isinstance(value, dict) or set(value) - _FIELDS:
    raise ValueError("Invalid profile fields")
  ref = value.get("sector_taxonomy", taxonomy())
  if (not isinstance(ref, dict) or ref != taxonomy() or type(ref.get("version")) is not int):
    raise ValueError("Invalid sector taxonomy")
  country, sectors = value.get("country"), value.get("sectors")
  codes = {s["code"] for s in load_manifest()["sector_taxonomy"]["sectors"]}
  if (country is not None and (not isinstance(country, str) or country not in COUNTRY_CODES)
      or sectors is not None and (not isinstance(sectors, list)
        or any(not isinstance(s, str) or s not in codes for s in sectors)
        or len(set(sectors)) != len(sectors))
      or value.get("entity_class") not in (None, "essential", "important", "none")
      or value.get("size_band") not in (None, "micro", "small", "medium", "large")):
    raise ValueError("Invalid profile declaration")
  return {"country": country, "sectors": sorted(sectors) if sectors is not None else None,
          "entity_class": value.get("entity_class"), "size_band": value.get("size_band"),
          "sector_taxonomy": dict(ref)}


def row_bytes(row):
  # Match the existing adapter's serialized envelope exactly, including ASCII escaping.
  return len(json.dumps(row, sort_keys=True, allow_nan=False).encode("utf-8"))


def event_id(tenant_id, request_id):
  return str(uuid5(NAMESPACE_URL, json.dumps([KIND, tenant_id, request_id], separators=(",", ":"))))


def request_digest(actor, profile, expected):
  return canonical_digest({"actor": actor, "profile": profile, "expected_revision": expected})


def validate_profile(row, ids):
  if (len(ids) != 1 or set(row) != _ENVELOPE | {"tenant_id", "profile", "revision", "history"}
      or row["tenant_id"] != ids[0] or type(row["revision"]) is not int
      or not isinstance(row["history"], list) or not 1 <= len(row["history"]) <= MAX_EVENTS
      or row["revision"] != len(row["history"]) or row_bytes(row) > MAX_READ_BYTES):
    raise ValueError("Invalid profile row")
  previous, requests = normalize_profile({}), set()
  for revision, event in enumerate(row["history"], 1):
    if not isinstance(event, dict) or set(event) != _EVENT:
      raise ValueError("Invalid profile event")
    request = canonical_uuid(event["request_id"])
    after = normalize_profile(event["after"])
    normalize_profile(event["before"])
    actor = event["actor"]
    if (not isinstance(actor, str) or not 1 <= len(actor) <= 255
        or type(event["revision"]) is not int or event["revision"] != revision
        or event["before"] != previous or event["after"] != after or request in requests
        or event["event_id"] != event_id(ids[0], request)
        or event["request_digest"] != request_digest(actor, after, revision - 1)
        or not isinstance(event["at"], str)
        or datetime.fromisoformat(event["at"]).utcoffset() != timezone.utc.utcoffset(None)):
      raise ValueError("Invalid profile event binding")
    requests.add(request)
    previous = after
  normalize_profile(row["profile"])
  if row["profile"] != previous:
    raise ValueError("Profile does not match history")


def _view(service, tenant, account, row):
  return {"profile": row["profile"] if row else normalize_profile({}),
          "revision": row["revision"] if row else 0,
          "canManage": service._permission(account, tenant, compliance.MANAGE)}


def read(service, actor, tenant_id):
  tenant, account = service._authorized_tenant(actor, tenant_id, compliance.VIEW)
  row = compliance._store(service).get(KIND, tenant_id)
  return _view(service, tenant, account, row)


def save(service, actor, tenant_id, profile, expected_revision, request_id):
  tenant, account = service._authorized_tenant(actor, tenant_id, compliance.MANAGE)
  try:
    profile = normalize_profile(profile)
    request_id = canonical_uuid(request_id)
    if type(expected_revision) is not int or expected_revision < 0:
      raise ValueError("Invalid revision")
  except (ValueError, TypeError, AttributeError):
    raise compliance._denied(400, "profile_invalid") from None
  store = compliance._store(service)
  row = store.get(KIND, tenant_id)
  digest = request_digest(account.account_id, profile, expected_revision)
  for event in row["history"] if row else []:
    if event["request_id"] == request_id:
      if event["request_digest"] != digest:
        raise compliance._denied(409, "profile_request_conflict")
      return _view(service, tenant, account, row)
  revision = row["revision"] if row else 0
  if expected_revision != revision:
    raise compliance._denied(409, "profile_stale", current_revision=revision)
  history = row["history"] if row else []
  event = {"event_id": event_id(tenant_id, request_id), "request_id": request_id,
           "request_digest": digest, "actor": account.account_id,
           "at": datetime.now(timezone.utc).isoformat(), "revision": revision + 1,
           "before": row["profile"] if row else normalize_profile({}), "after": profile}
  updated = {"schemaVersion": 1, "namespace": store.namespace, "kind": KIND, "ids": [tenant_id],
             "tenant_id": tenant_id, "profile": profile, "revision": revision + 1, "history": history + [event]}
  if len(updated["history"]) > MAX_EVENTS or row_bytes(updated) > MAX_WRITE_BYTES:
    raise compliance._denied(409, "profile_capacity")
  return _view(service, tenant, account, store.put(KIND, tenant_id, record=updated))
