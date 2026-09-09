"""Minimal cstore-auth account reader (RM-075 Phase 2; July Phase 3 Task 4, reduced).

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
* Navigator writes no ``schemaVersion``. An absent value is version 0 (today's shape); a present,
  unrecognised value fails closed. This is not a downgrade vector - stripping the field needs
  cstore write access, which could set ``role: admin`` directly.
"""
import json
import os

from ..identity import AccountView, IdentityStoreError

AUTH_HKEY_ENV = "R1EN_CSTORE_AUTH_HKEY"
SUPPORTED_SCHEMA_VERSIONS = frozenset({0, 1})
TOMBSTONE = "null"
ACCOUNT_STATE_KEY = "navigatorAccountState"
ACTIVE_STATE = "active"
APP_ROLE_KEY = "appRole"


class CstoreAuthAccountReader:
  def __init__(self, owner):
    self._owner = owner

  def _hkey(self):
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
    if raw is None or raw == TOMBSTONE:
      return None
    record = _parse_record(raw)
    if record is None:
      return None
    metadata = record.get("metadata")
    if not isinstance(metadata, dict):
      metadata = {}
    state = metadata.get(ACCOUNT_STATE_KEY)
    app_role = metadata.get(APP_ROLE_KEY)
    return AccountView(
      account_id=account_id,
      role=str(record.get("role") or "user"),
      app_role=app_role if isinstance(app_role, str) else None,
      active=(ACCOUNT_STATE_KEY not in metadata or state == ACTIVE_STATE),
    )


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
