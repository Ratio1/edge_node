"""Server-side actor resolution (RM-075 Phase 2; contract §Caller-identity channel item 3).

The Navigator BFF forwards only ``actor = {"account_id": ...}``. Everything else about the caller
- role, ``appRole``, whether the account still exists and is active - is read from the account
store through an ``AccountReader``; nothing in the request is an authorization input.

Denials use the contract's unified not-found shape so an actor cannot distinguish "unknown
account" from "tombstoned" from "not active".
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class TenantMembership:
  """A stored role scoped to one tenant, or an explicit full-portfolio platform role."""

  role: str
  tenant_id: str | None


@dataclass(frozen=True)
class AccountView:
  """Resolved caller identity with tenant-bound memberships, not flattened global roles.

  ``role`` and ``app_role`` retain the RM-075 attribution contract. Tenant enforcement must use
  the membership pairs, not interpret these legacy fields as cross-tenant authorization.
  """

  account_id: str
  role: str
  app_role: str | None
  active: bool
  tenant_memberships: tuple[TenantMembership, ...] = ()
  account_generation: str | None = None
  # Only the backend account reader can prove absence. Unknown fixtures are not legacy.
  tenant_memberships_present: bool | None = None

  @property
  def created_by(self):
    """``(created_by_name, created_by_id)`` derived from the store, never from the request.

    cstore-auth stores no display name, so both are the account id - lossless today, because
    Navigator already sends the session username for both.
    """
    return self.account_id, self.account_id


def _denial(*, status_code, error, error_class, message):
  return {
    "status": "error",
    "status_code": status_code,
    "error": error,
    "error_class": error_class,
    "message": message,
  }


def actor_not_found():
  return _denial(
    status_code=404,
    error="not_found",
    error_class="actor_not_found",
    message="The requested actor is not available.",
  )


def identity_store_unavailable():
  return _denial(
    status_code=503,
    error="unavailable",
    error_class="identity_store_unavailable",
    message="Caller identity cannot be resolved.",
  )


def canonical_account_id(value):
  """Mirror Navigator's ``canonicalAccountId``: trimmed, lower-cased, ``[a-z0-9._-]+`` only."""
  if not isinstance(value, str):
    return None
  account_id = value.strip().lower()
  if not account_id:
    return None
  allowed = set("abcdefghijklmnopqrstuvwxyz0123456789._-")
  if any(ch not in allowed for ch in account_id):
    return None
  return account_id


def resolve_actor(actor, reader):
  """Return ``(AccountView, None)`` or ``(None, denial)``.

  ``actor`` is the forwarded request field; ``reader`` exposes ``get_account(account_id)`` returning
  an ``AccountView`` or ``None`` and raising ``IdentityStoreError`` when the store cannot be read.
  """
  if not isinstance(actor, dict):
    return None, actor_not_found()
  account_id = canonical_account_id(actor.get("account_id"))
  if not account_id:
    return None, actor_not_found()
  try:
    view = reader.get_account(account_id)
  except IdentityStoreError:
    return None, identity_store_unavailable()
  if view is None or not view.active:
    return None, actor_not_found()
  return view, None


class IdentityStoreError(RuntimeError):
  """The account store is misconfigured or unreachable; callers fail closed."""
