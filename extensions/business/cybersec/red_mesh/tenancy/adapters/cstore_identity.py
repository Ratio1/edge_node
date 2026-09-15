"""CStore account reader with RM-075 attribution and RM-026 tenant membership integrity.

Reads the account record Navigator's ``@ratio1/cstore-auth-ts`` writes, server-side, through the
plugin's ``chainstore_hget``. Needs only ``R1EN_CSTORE_AUTH_HKEY`` - the auth *secret* is the
password pepper and is never read here. Never reads passwords.

Record facts this binds to (Navigator ``lib/auth/cstore.ts``):

* the hash field key is the canonical account id (lower-cased username);
* an absent field is "no such account"; the literal string ``'null'`` is a tombstone;
* the value is a JSON object ``{type, password, role, metadata, createdAt, updatedAt}``;
* ``metadata.navigatorAccountState`` is ``'active'`` or absent for a live account, anything else
  (``'deleting'``) is not active;
* ``metadata.appRole == 'pentester'`` is Navigator's third role, layered on cstore's ``user``;
* tenant memberships remain role/scope pairs; explicit malformed metadata fails closed and explicit
  empty memberships never restore legacy admin authority;
* Navigator writes no ``schemaVersion``. An absent value is version 0 (today's shape); a present,
  unrecognised value fails closed. This is not a downgrade vector - stripping the field needs
  cstore write access, which could set ``role: admin`` directly.
"""
import json
import os

from ..identity import AccountView, IdentityStoreError, TenantMembership, canonical_account_id

AUTH_HKEY_ENV = "R1EN_CSTORE_AUTH_HKEY"
SUPPORTED_SCHEMA_VERSIONS = frozenset({0, 1})
TOMBSTONE = "null"
ACCOUNT_STATE_KEY = "navigatorAccountState"
ACTIVE_STATE = "active"
APP_ROLE_KEY = "appRole"
MEMBERSHIPS_KEY = "tenant_memberships"
PLATFORM_ROLES = frozenset({"super_tenant_admin", "super_pentester"})
TENANT_ROLES = frozenset({"tenant_admin", "tenant_pentester", "tenant_user"})
MAX_ENUMERATED_ACCOUNTS = 10000


class CstoreAuthAccountReader:
  def __init__(self, owner):
    self._owner = owner

  def _hkey(self):
    # The plugin instance ENV first: deeploy injects the hkey there (a pipeline-level value), and
    # this plugin runs in-process, so that ENV never becomes os.environ the way it does for a
    # containerized app. os.environ remains the fallback for node-level configuration.
    instance_env = getattr(self._owner, "cfg_env", None)
    hkey = ""
    if isinstance(instance_env, dict):
      hkey = str(instance_env.get(AUTH_HKEY_ENV) or "").strip()
    if not hkey:
      hkey = os.environ.get(AUTH_HKEY_ENV, "").strip()
    if not hkey:
      raise IdentityStoreError(f"{AUTH_HKEY_ENV} is not configured")
    return hkey

  def get_account(self, account_id):
    """``AccountView`` for a present record, ``None`` for absent or tombstoned."""
    hkey = self._hkey()
    try:
      raw = self._owner.chainstore_hget(hkey=hkey, key=account_id)
    except Exception as exc:  # the store is the boundary; any failure fails closed
      raise IdentityStoreError(str(exc)) from exc
    return self._view(account_id, raw)

  def list_accounts(self):
    """Bounded validated projections only; never return credentials or arbitrary metadata.

    This enumerates the local CStore view, not an atomic or globally fresh account snapshot.
    """
    hkey = self._hkey()
    try:
      records = self._owner.chainstore_hgetall(hkey=hkey)
    except Exception as exc:
      raise IdentityStoreError("Account storage cannot be enumerated") from exc
    if not isinstance(records, dict) or len(records) > MAX_ENUMERATED_ACCOUNTS:
      raise IdentityStoreError("Account storage enumeration is unavailable")
    views = []
    for account_id, raw in records.items():
      if not isinstance(account_id, str) or canonical_account_id(account_id) != account_id:
        continue
      view = self._view(account_id, raw)
      if view is not None:
        views.append(view)
    return views

  @staticmethod
  def _view(account_id, raw):
    if raw is None or raw == TOMBSTONE:
      return None
    record = _parse_record(raw)
    if record is None:
      return None
    metadata = record.get("metadata", {})
    if not isinstance(metadata, dict):
      return None
    state = metadata.get(ACCOUNT_STATE_KEY)
    app_role = metadata.get(APP_ROLE_KEY)
    memberships = _parse_memberships(metadata, record.get("role"))
    if memberships is None:
      return None
    if "navigatorAccountGeneration" in metadata:
      generation = metadata["navigatorAccountGeneration"]
      if not isinstance(generation, str) or not generation.strip():
        raise IdentityStoreError("Invalid account generation")
      try:
        generation.encode("utf-8", errors="strict")
      except UnicodeError as exc:
        raise IdentityStoreError("Invalid account generation") from exc
    else:
      created_at = record.get("createdAt")
      generation = f"legacy:{created_at}" if isinstance(created_at, str) and created_at else None
    return AccountView(
      account_id=account_id,
      role=str(record.get("role") or "user"),
      app_role=app_role if isinstance(app_role, str) else None,
      active=(ACCOUNT_STATE_KEY not in metadata or state == ACTIVE_STATE),
      tenant_memberships=memberships,
      account_generation=generation,
      tenant_memberships_present=MEMBERSHIPS_KEY in metadata,
    )


def _parse_memberships(metadata, legacy_role):
  """Preserve role/scope pairs; malformed explicit scope must never activate legacy fallback."""
  if MEMBERSHIPS_KEY not in metadata:
    return (TenantMembership("super_tenant_admin", None),) if legacy_role == "admin" else ()
  rows = metadata[MEMBERSHIPS_KEY]
  if not isinstance(rows, list):
    return None
  memberships = []
  for row in rows:
    if not isinstance(row, dict) or "role" not in row or "tenant_id" not in row:
      return None
    role, tenant_id = row["role"], row["tenant_id"]
    if not isinstance(role, str) or role not in PLATFORM_ROLES | TENANT_ROLES:
      return None
    if tenant_id is None:
      if role not in PLATFORM_ROLES:
        return None
    elif not isinstance(tenant_id, str) or not tenant_id.strip():
      return None
    memberships.append(TenantMembership(role, tenant_id))
  return tuple(memberships)


def _parse_record(raw):
  """Dict or JSON-encoded dict -> dict, or ``None`` when unparseable / unsupported version."""
  if isinstance(raw, (bytes, bytearray)):
    raw = raw.decode("utf-8", errors="replace")
  if isinstance(raw, str):
    try:
      raw = json.loads(raw)
    except ValueError:
      return None
  if not isinstance(raw, dict):
    return None
  version = raw.get("schemaVersion", 0)
  if type(version) is not int or version not in SUPPORTED_SCHEMA_VERSIONS:
    return None
  return raw
