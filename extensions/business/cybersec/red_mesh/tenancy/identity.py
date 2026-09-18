"""Server-side actor resolution (RM-075 Phase 2; contract §Caller-identity channel item 3).

The Navigator BFF forwards only ``actor = {"account_id": ...}``. Everything else about the caller --
their memberships, whether the account still exists and is active -- is read from the account store
through an ``AccountReader``; nothing in the request is an authorization input.

Denials use the contract's unified not-found shape so an actor cannot distinguish "unknown
account" from "tombstoned" from "not active".
"""
from dataclasses import dataclass


@dataclass(frozen=True)
class TenantMembership:
  """A stored role scoped to one tenant, or an explicit full-portfolio platform role."""

  role: str
  tenant_id: str | None


# The full-portfolio Super-Tenant Admin membership: the platform administrator, stated as a stored
# row rather than derived from anything.
FULL_PORTFOLIO_SUPER_TENANT_ADMIN = TenantMembership("super_tenant_admin", None)


def holds_platform_role(account, role="super_tenant_admin"):
  """Whether ``account`` holds ``role`` deployment-wide (``tenant_id`` None, no tenant allowlist).

  A Super-Tenant Admin is always full-portfolio (RM-083, ``policy.valid_account_scope``). An allowlisted
  Super-Pentester membership (``tenant_id`` set) is deliberately not counted: every caller of this
  helper gates a deployment-wide action, which an allowlist does not reach.
  """
  return TenantMembership(role, None) in account.tenant_memberships


@dataclass(frozen=True)
class AccountView:
  """Resolved caller identity: who, what they hold, and whether they may act at all.

  RM-084 P6 removed ``role``, ``app_role`` and ``tenant_memberships_present``. The first two were the
  deployment-wide account role and Navigator's ``appRole`` flag, which the matrix never consulted;
  the third distinguished "this account has no memberships key" -- the legacy seam -- from "it has an
  empty one, and holds nothing". There is no such distinction now: every account has membership rows,
  possibly zero of them.
  """

  account_id: str
  active: bool
  state: str = "active"
  tenant_memberships: tuple[TenantMembership, ...] = ()
  account_generation: str | None = None

  @property
  def created_by(self):
    """``(created_by_name, created_by_id)`` derived from the store, never from the request.

    The store keeps no display name, so both are the account id -- lossless, because the Navigator
    sends the account id for both.
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


# Mirrors the Navigator's `^[a-z0-9][a-z0-9._-]{2,63}$` (lib/auth/store/username.ts). The length and
# first-character rules were added at RM-084 P6: without them the two sides disagreed about which
# names were valid, and a name this side accepted could address a field the Navigator could not write.
_ALLOWED_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789._-")
_ALLOWED_FIRST_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789")
_MIN_ID_LENGTH = 3
_MAX_ID_LENGTH = 64


def canonical_account_id(value):
  """Mirror Navigator's ``canonicalAccountId``, or ``None`` when the value is not a valid id."""
  if not isinstance(value, str):
    return None
  account_id = value.strip().lower()
  if not _MIN_ID_LENGTH <= len(account_id) <= _MAX_ID_LENGTH:
    return None
  if account_id[0] not in _ALLOWED_FIRST_CHARS:
    return None
  if any(ch not in _ALLOWED_ID_CHARS for ch in account_id):
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
