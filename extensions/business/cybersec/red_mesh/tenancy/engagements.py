"""RM-095 phase 2: the signed engagement a tenant job runs inside; strict values and stored records.

An engagement is immutable: the only change after creation is a revoke. Its hash covers every
field a launch will rely on, with documents by SHA-256 (never by reference, so a re-upload of the
same bytes is the same engagement). The stored field is `engagement_kind`: `kind` is taken by the
administration store's envelope. The on-chain anchor is not part of the row: until a registry
function exists every engagement's anchor is `pending`, and the follow-up keeps it in its own
record so an anchor write can never race a revoke.
"""
from datetime import datetime, timezone
import re

from .assets import (canonical_digest, canonical_uuid, normalize_name, normalize_port_scope,
                     valid_digest)
from .identity import canonical_account_id
from ..constants import FEATURE_CATALOG
from ..models.engagement import Contact, EngagementContext

ENGAGEMENT_KINDS = ("continuous", "point-in-time")
SCAN_MODES = ("connect", "syn")
DEFAULT_SCAN_MODES = ("connect",)
ROE_DEFAULTS = {"authenticated_action": False, "stateful_probes_allowed": False,
                "ics_safe_mode_required": True}
# The asset kinds an engagement may lock. `model` waits until model launches are engagement-gated.
# Categories mirror `services.scan_strategy.SCAN_STRATEGIES` (not imported: it loads the workers).
_KIND_CATEGORIES = {"network": ("service", "web", "correlation"), "webapp": ("graybox",)}
ENGAGEMENT_ASSET_KINDS = tuple(_KIND_CATEGORIES)
MAX_ENGAGEMENT_ASSETS = 64
HASH_SCHEMA = "redmesh.engagement/1"

_CONTEXT_TEXT = ("client_name", "engagement_code", "primary_objective", "secondary_objective",
                 "scope_rationale", "data_classification", "asset_exposure", "methodology")
_CONTACT_FIELDS = ("name", "email", "phone", "role")
_CONTEXT_TEXT_MAX = 500
_DOC_TEXT = ("store", "ref", "filename", "mime", "uploaded_at", "uploaded_by")
_SIGNER_FIELDS = ("authorized_signer_name", "authorized_signer_role", "third_party_auth_refs")
_INSTANT = "%Y-%m-%dT%H:%M:%SZ"


class EngagementInvalid(ValueError):
  """A refused engagement value; `code` is the 400 error the caller sees."""

  def __init__(self, code):
    super().__init__(code)
    self.code = code


def feature_ids_for_kind(kind):
  categories = _KIND_CATEGORIES.get(kind, ())
  return tuple(item["id"] for item in FEATURE_CATALOG if item["category"] in categories)


def engagement_id_for(request_id):
  return "en_" + canonical_uuid(request_id)


def valid_engagement_id(value):
  if not isinstance(value, str) or not value.startswith("en_"):
    return False
  try:
    return engagement_id_for(value[3:]) == value
  except ValueError:
    return False


def normalize_roe(value):
  if value is None:
    value = {}
  if not isinstance(value, dict) or not set(value) <= set(ROE_DEFAULTS):
    raise EngagementInvalid("roe_invalid")
  roe = {**ROE_DEFAULTS, **value}
  if any(type(flag) is not bool for flag in roe.values()):
    raise EngagementInvalid("roe_invalid")
  return roe


def _context_text(value):
  if not isinstance(value, str):
    raise EngagementInvalid("context_invalid")
  value = value.strip()
  if len(value) > _CONTEXT_TEXT_MAX or any(ord(ch) < 32 and ch not in "\n\t" for ch in value):
    raise EngagementInvalid("context_invalid")
  return value


def _contact(value):
  if value is None:
    return None
  if not isinstance(value, dict) or not set(value) <= set(_CONTACT_FIELDS):
    raise EngagementInvalid("context_invalid")
  contact = Contact(**{key: _context_text(value.get(key, "")) for key in _CONTACT_FIELDS})
  return None if contact.is_empty() else contact


def normalize_context(value):
  """Today's `EngagementContext`, strictly: known keys, strings only (never `str(None)`), bounded."""
  if value is None:
    value = {}
  if (not isinstance(value, dict)
      or not set(value) <= {*_CONTEXT_TEXT, "point_of_contact", "emergency_contact"}):
    raise EngagementInvalid("context_invalid")
  text = {key: _context_text(value[key]) for key in _CONTEXT_TEXT if key in value}
  context = EngagementContext(**text)
  context.point_of_contact = _contact(value.get("point_of_contact"))
  context.emergency_contact = _contact(value.get("emergency_contact"))
  if context.validate():
    raise EngagementInvalid("context_invalid")
  return context.to_dict()


def normalize_instant(value):
  """A UTC instant in one canonical form, seconds precision, so equal windows hash equally."""
  if not isinstance(value, str) or not re.fullmatch(
      r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|\+00:00)", value):
    raise EngagementInvalid("window_invalid")
  try:
    instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
  except ValueError:
    raise EngagementInvalid("window_invalid") from None
  return instant.astimezone(timezone.utc).strftime(_INSTANT)


def normalize_window(valid_from, valid_until):
  start, end = normalize_instant(valid_from), normalize_instant(valid_until)
  if not start < end:
    raise EngagementInvalid("window_invalid")
  return start, end


def normalize_signer(name, role, third_party_auth_refs=None):
  try:
    name, role = normalize_name(name, 200), normalize_name(role, 200)
  except ValueError:
    raise EngagementInvalid("signer_required") from None
  refs = [] if third_party_auth_refs is None else third_party_auth_refs
  if not isinstance(refs, list) or len(refs) > 20:
    raise EngagementInvalid("signer_required")
  try:
    refs = [normalize_name(ref, 200) for ref in refs]
  except ValueError:
    raise EngagementInvalid("signer_required") from None
  return {"authorized_signer_name": name, "authorized_signer_role": role,
          "third_party_auth_refs": refs}


def normalize_scan_modes(value):
  if value is None:
    return list(DEFAULT_SCAN_MODES)
  if (not isinstance(value, list) or not value or len(set(value)) != len(value)
      or any(mode not in SCAN_MODES for mode in value)):
    raise EngagementInvalid("engagement_asset_invalid")
  return sorted(value)


def normalize_tests(kind, value):
  if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
    raise EngagementInvalid("tests_invalid")
  allowed = feature_ids_for_kind(kind)
  if len(set(value)) != len(value) or any(item not in allowed for item in value):
    raise EngagementInvalid("tests_invalid")
  return sorted(value)


def valid_doc_ref(value, *, signer=False):
  keys = {*_DOC_TEXT, "sha256", "size_bytes", *(_SIGNER_FIELDS if signer else ())}
  if not (isinstance(value, dict) and set(value) == keys
          and all(isinstance(value[key], str) and value[key] for key in _DOC_TEXT)
          and valid_digest(value["sha256"])
          and type(value["size_bytes"]) is int and value["size_bytes"] > 0):
    return False
  if not signer:
    return True
  try:
    return normalize_signer(*(value[key] for key in _SIGNER_FIELDS)) == {
      key: value[key] for key in _SIGNER_FIELDS}
  except EngagementInvalid:
    return False


def _asset_entry_valid(entry):
  if not isinstance(entry, dict) or not isinstance(entry.get("kind"), str):
    return False
  kind = entry["kind"]
  network = {"asset_id", "kind", "target_digest", "authorized_ports", "authorized_scan_modes",
             "authorized_tests"}
  expected = network if kind == "network" else {"asset_id", "kind", "target_digest", "authorized_tests"}
  if kind not in ENGAGEMENT_ASSET_KINDS or set(entry) != expected:
    return False
  try:
    if (not isinstance(entry["asset_id"], str) or not entry["asset_id"].startswith("as_")
        or "as_" + canonical_uuid(entry["asset_id"][3:]) != entry["asset_id"]
        or not valid_digest(entry["target_digest"])
        or normalize_tests(kind, entry["authorized_tests"]) != entry["authorized_tests"]):
      return False
    if kind == "network":
      return (entry["authorized_ports"] is not None
              and normalize_port_scope(entry["authorized_ports"]) == entry["authorized_ports"]
              and normalize_scan_modes(entry["authorized_scan_modes"]) == entry["authorized_scan_modes"])
  except (ValueError, TypeError):
    return False
  return True


def hashed_fields(record):
  """The exact content the engagement hash commits to (and RM-068 will later sign)."""
  authorization = record["authorization_document"]
  return {
    "schema": HASH_SCHEMA, "tenant_id": record["tenant_id"], "engagement_id": record["engagement_id"],
    "display_name": record["display_name"], "kind": record["engagement_kind"],
    "valid_from": record["valid_from"], "valid_until": record["valid_until"],
    "contract_sha256": record["contract_sha256"],
    "roe_document_sha256": record["roe_document"]["sha256"],
    "authorization": {"sha256": authorization["sha256"],
                      "signer_name": authorization["authorized_signer_name"],
                      "signer_role": authorization["authorized_signer_role"],
                      "third_party_auth_refs": authorization["third_party_auth_refs"]},
    "supersedes": record.get("supersedes"),
    "roe": record["roe"], "context": record["context"], "assets": record["assets"],
  }


def engagement_hash(record):
  return canonical_digest(hashed_fields(record))


def _utc(value):
  return isinstance(value, str) and datetime.fromisoformat(value).tzinfo == timezone.utc


def validate_engagement(row, ids):
  """Refuse any stored engagement that is not exactly what creation and revoke write.

  Unknown fields are kept (as assets keep them) so a later field does not make older nodes refuse
  the whole tenant's engagements during a mixed deploy.
  """
  assets = row.get("assets")
  if (len(ids) != 2 or row.get("tenant_id") != ids[0] or row.get("engagement_id") != ids[1]
      or ids[1] != engagement_id_for(row.get("request_id"))
      or type(row.get("active")) is not bool
      or normalize_name(row.get("display_name")) != row["display_name"]
      or row.get("engagement_kind") not in ENGAGEMENT_KINDS
      or normalize_window(row.get("valid_from"), row.get("valid_until"))
         != (row["valid_from"], row["valid_until"])
      or not (row.get("contract_sha256") is None or valid_digest(row["contract_sha256"]))
      or not valid_doc_ref(row.get("roe_document"))
      or not valid_doc_ref(row.get("authorization_document"), signer=True)
      or not ("supersedes" not in row
              or (valid_engagement_id(row["supersedes"]) and row["supersedes"] != ids[1]))
      or normalize_roe(row.get("roe")) != row["roe"]
      or normalize_context(row.get("context")) != row["context"]
      or not isinstance(assets, list) or not 1 <= len(assets) <= MAX_ENGAGEMENT_ASSETS
      or not all(_asset_entry_valid(entry) for entry in assets)
      or [entry["asset_id"] for entry in assets] != sorted({entry["asset_id"] for entry in assets})
      or not valid_digest(row.get("create_intent_digest"))
      or row.get("engagement_hash") != engagement_hash(row)):
    raise ValueError("Invalid engagement")
  if not row.get("created_by") or canonical_account_id(row["created_by"]) != row["created_by"]:
    raise ValueError("Invalid engagement attribution")
  if not _utc(row.get("created_at")):
    raise ValueError("Invalid engagement timestamp")
  revoke = ("revoked_by", "revoked_at", "revoke_reason")
  if row["active"]:
    if any(key in row for key in revoke):
      raise ValueError("Invalid engagement revoke")
  elif (not row.get("revoked_by") or canonical_account_id(row["revoked_by"]) != row["revoked_by"]
        or not _utc(row.get("revoked_at"))
        or normalize_name(row.get("revoke_reason"), 500) != row["revoke_reason"]):
    raise ValueError("Invalid engagement revoke")
  canonical_digest(row)
