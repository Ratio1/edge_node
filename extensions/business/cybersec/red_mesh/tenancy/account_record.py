"""Strict v1 account-record parsing (RM-084 P6).

The Navigator owns the account store; this is the *reader*, and it is deliberately the same shape
as ``lib/auth/store/record.ts`` on the other side, from the canonical fixture
``account-record.v1.json`` both repos copy. A record that one side accepts and the other rejects is
the failure mode this exists to prevent, so the rules are written out rather than inferred:

* unknown key, wrong type, ``schemaVersion != 1``, or an ``accountId`` that disagrees with the field
  it was stored under -> not a record;
* memberships are role/scope pairs, and the set must satisfy ``valid_account_scope``;
* ``[]`` is valid: the "none" scope, which only a Super-Tenant Admin may act on.

Everything the previous record carried and this one does not is gone on purpose: the deployment-wide
``role``, the free-form ``metadata`` bag, ``appRole``, ``navigatorAccountState`` and
``navigatorAccountGeneration``. Authority is the memberships, and nothing else.

There is no lenient mode and no version negotiation. A new ``schemaVersion`` ships migrators in both
repos in the same release; reading an unknown version leniently is how a record whose meaning changed
keeps being read with the old meaning.
"""
import base64
import binascii
import json
import re
from datetime import datetime

from .identity import canonical_account_id
from .policy import PLATFORM_ROLES, TENANT_LOCAL_ROLES, valid_account_scope

SCHEMA_VERSION = 1
TOMBSTONE = "null"

ACCOUNT_STATES = frozenset({"active", "deactivated", "deleting"})
MEMBERSHIP_ROLES = PLATFORM_ROLES | TENANT_LOCAL_ROLES

_REQUIRED_KEYS = frozenset({
  "schemaVersion", "accountId", "state", "generation", "password", "memberships",
  "createdAt", "createdBy", "updatedAt", "updatedBy", "passwordChangedAt",
})
_OPTIONAL_KEYS = frozenset({"stateChangedAt", "stateChangedBy"})
_PASSWORD_KEYS = frozenset({"algo", "v", "m", "t", "p", "len", "salt", "hash"})

# Bounds on the *stored* parameters. This side never verifies a password, but a record whose
# parameters are absurd is not one the Navigator could have written, and accepting it here would let
# the two sides disagree about which records exist.
_PARAM_BOUNDS = {"m": (8192, 262144), "t": (1, 10), "p": (1, 4)}
_HASH_LEN = 32
_SALT_LEN = 16

# The shared value shapes (redmesh-auth.md 3.1). Written out rather than approximated, because the
# Navigator's parser applies exactly these: a record one side accepts and the other refuses is an
# account that exists for authentication and not for authorization.
_UUID_V4 = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TENANT_ID = re.compile(r"^tn_[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

# The bootstrap wrote the first account; it never changes one's state afterwards.
BOOTSTRAP_ACTOR = "@bootstrap"


def _is_uuid_v4(value):
  return isinstance(value, str) and bool(_UUID_V4.match(value))


def _is_tenant_id(value):
  return isinstance(value, str) and bool(_TENANT_ID.match(value))


def _is_timestamp(value):
  """The ``Date.toISOString`` form, and a real UTC calendar instant.

  Both halves matter: the pattern alone admits ``2026-13-45T99:99:99.999Z``, and a permissive parse
  alone admits a dozen other spellings of the same moment, so a record could carry two spellings of
  one instant and compare unequal to itself.
  """
  if not isinstance(value, str) or not _TIMESTAMP.match(value):
    return False
  try:
    datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
  except ValueError:
    return False
  return True


def _is_actor(value, *, allow_bootstrap):
  """An acting account id, or the bootstrap marker, which no account id can equal."""
  if value == BOOTSTRAP_ACTOR:
    return allow_bootstrap
  return isinstance(value, str) and canonical_account_id(value) == value


def _is_base64_of_length(value, length):
  """Standard alphabet, padded, and canonical: decode then re-encode gives the input back.

  That last clause rejects URL-safe spellings, missing padding and non-zero trailing bits -- three
  different encodings that would otherwise decode to the same secret-sized value.
  """
  if not isinstance(value, str):
    return False
  try:
    decoded = base64.b64decode(value, validate=True)
  except (binascii.Error, ValueError):
    return False
  return len(decoded) == length and base64.b64encode(decoded).decode("ascii") == value


def _is_str(value):
  return isinstance(value, str) and bool(value.strip())


def _is_int(value):
  # `bool` is an `int` in Python; a `true` where a cost parameter belongs is malformed, not 1.
  return type(value) is int


def _parse_password(value):
  if not isinstance(value, dict) or set(value) != _PASSWORD_KEYS:
    return None
  if value["algo"] != "argon2id" or value["v"] != 19:
    return None
  for name, (low, high) in _PARAM_BOUNDS.items():
    if not _is_int(value[name]) or not low <= value[name] <= high:
      return None
  if value["len"] != _HASH_LEN:
    return None
  if not _is_base64_of_length(value["salt"], _SALT_LEN):
    return None
  if not _is_base64_of_length(value["hash"], _HASH_LEN):
    return None
  return dict(value)


def _parse_memberships(value):
  if not isinstance(value, list):
    return None
  rows = []
  for row in value:
    if not isinstance(row, dict) or set(row) != {"role", "tenant_id"}:
      return None
    role, tenant_id = row["role"], row["tenant_id"]
    if not isinstance(role, str) or role not in MEMBERSHIP_ROLES:
      return None
    if tenant_id is None:
      # A tenant-local role with no tenant is meaningless.
      if role not in PLATFORM_ROLES:
        return None
    elif not _is_tenant_id(tenant_id):
      return None
    # A Super-Tenant Admin is always full-portfolio (RM-083), so `null` is the only tenant it takes.
    if role == "super_tenant_admin" and tenant_id is not None:
      return None
    # A duplicate row says the same thing twice, which no writer of ours produces.
    if (role, tenant_id) in rows:
      return None
    rows.append((role, tenant_id))
  if not valid_account_scope(rows):
    return None
  return tuple(rows)


def is_tombstone(raw):
  """Whether the stored value is the removal marker rather than a record."""
  if isinstance(raw, (bytes, bytearray)):
    raw = raw.decode("utf-8", errors="replace")
  return raw == TOMBSTONE or raw is None


def parse_account_record(raw, account_id):
  """``(state, generation, memberships)`` for a valid v1 record, else ``None``.

  ``None`` covers absent, tombstoned and malformed alike. The caller must not distinguish them: to a
  prober, "no such account", "removed" and "unreadable" have to look the same, and to the
  authorization path all three mean the same thing -- this account authorizes nothing.
  """
  if raw is None:
    return None
  if isinstance(raw, (bytes, bytearray)):
    raw = raw.decode("utf-8", errors="replace")
  # Only the exact string is the tombstone. `" null"` is a value something else wrote, and a record
  # we cannot account for is not a removal.
  if raw == TOMBSTONE:
    return None
  if isinstance(raw, str):
    try:
      raw = json.loads(raw)
    except ValueError:
      return None
  if raw is None:
    return None
  if not isinstance(raw, dict):
    return None
  keys = set(raw)
  if not _REQUIRED_KEYS <= keys or not keys <= (_REQUIRED_KEYS | _OPTIONAL_KEYS):
    return None
  if raw["schemaVersion"] != SCHEMA_VERSION or type(raw["schemaVersion"]) is not int:
    return None
  if raw["accountId"] != account_id or canonical_account_id(account_id) != account_id:
    return None
  # Type first: a list or dict here is unhashable, and the membership test would raise instead of
  # refusing the record.
  if not isinstance(raw["state"], str) or raw["state"] not in ACCOUNT_STATES:
    return None
  if not _is_uuid_v4(raw["generation"]):
    return None
  if _parse_password(raw["password"]) is None:
    return None
  memberships = _parse_memberships(raw["memberships"])
  if memberships is None:
    return None
  for name in ("createdAt", "updatedAt", "passwordChangedAt"):
    if not _is_timestamp(raw[name]):
      return None
  for name in ("createdBy", "updatedBy"):
    if not _is_actor(raw[name], allow_bootstrap=True):
      return None
  # The two state keys travel together: a stamp with no author, or an author with no stamp, is a
  # half-written state change rather than a record to act on.
  if ("stateChangedAt" in raw) != ("stateChangedBy" in raw):
    return None
  if "stateChangedAt" in raw and not (
      _is_timestamp(raw["stateChangedAt"])
      # Never `@bootstrap`: the bootstrap creates an account, it never changes one's state.
      and _is_actor(raw["stateChangedBy"], allow_bootstrap=False)):
    return None
  # A record that is not active got there by a state change, so it carries who made it and when.
  if raw["state"] != "active" and "stateChangedAt" not in raw:
    return None
  return raw["state"], raw["generation"], memberships
