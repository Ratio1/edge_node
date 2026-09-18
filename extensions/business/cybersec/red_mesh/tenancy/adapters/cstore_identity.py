"""CStore account reader for the RedMesh v1 account record (RM-084 P6).

Reads the record the Navigator writes, server-side, through the plugin's ``chainstore_hget``. Needs
only ``R1EN_CSTORE_AUTH_HKEY`` -- the auth *secret* is the password pepper and is never read here,
and neither is a password.

Parsing lives in ``tenancy/account_record.py`` so that this file is about *reaching* the store and
that one is about what a record means. What this layer binds to is only the addressing:

* the hash field key is the canonical account id (lower-cased username);
* an absent field is "no such account"; the literal ``'null'`` is a tombstone;
* absent, tombstoned and malformed are indistinguishable to every caller.

The pre-cutover reader interpreted a deployment-wide ``role``, an ``appRole`` flag and a
``navigatorAccountState``, and derived a full-portfolio membership for an ``admin`` account that had
no memberships key -- the legacy bridge. All of it is gone: an account's authority is the membership
rows it actually holds.
"""
import json
import os

from ..account_record import parse_account_record
from ..identity import AccountView, IdentityStoreError, TenantMembership, canonical_account_id

AUTH_HKEY_ENV = "R1EN_CSTORE_AUTH_HKEY"
ACTIVE_STATE = "active"
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
    """``AccountView`` for a valid record, ``None`` for absent, tombstoned or malformed.

    The three are one answer on purpose. A caller that could tell them apart could enumerate which
    account names exist, and all three mean the same thing to authorization anyway: this account
    grants nothing.
    """
    parsed = parse_account_record(raw, account_id)
    if parsed is None:
      return None
    state, generation, memberships = parsed
    return AccountView(
      account_id=account_id,
      active=(state == ACTIVE_STATE),
      state=state,
      tenant_memberships=tuple(TenantMembership(role, tenant_id) for role, tenant_id in memberships),
      account_generation=generation,
    )
