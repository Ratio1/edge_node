"""RM-095 phase 2, RM-107: the engagement a tenant job runs inside; strict values and stored records.

An engagement is immutable: the only change after creation is a revoke. Its hash covers every
field a launch will rely on, with documents by SHA-256 (never by reference, so a re-upload of the
same bytes is the same engagement). RM-107 (`redmesh.engagement/2`): the tenant contract is the
permission, so there is no separate authorization document or typed signer; the engagement carries
a set of titled documents and the run modes a launch may use. The on-chain anchor is not part of the
row: until a registry function exists every engagement's anchor is `pending`, and the follow-up
keeps it in its own record so an anchor write can never race a revoke.
"""
from datetime import datetime, timezone
import re

from .assets import (canonical_digest, canonical_uuid, normalize_name, normalize_port_scope,
                     normalize_target, valid_digest)
from .identity import canonical_account_id
from ..constants import FEATURE_CATALOG, RUN_MODE_CONTINUOUS_MONITORING, RUN_MODE_SINGLEPASS
from ..models.engagement import Contact, EngagementContext

# RM-107. The engagement's vocabulary, and the launch `run_mode` value each one allows.
RUN_MODES = ("continuous", "single_pass")
RUN_MODE_LAUNCH_VALUES = {"single_pass": RUN_MODE_SINGLEPASS, "continuous": RUN_MODE_CONTINUOUS_MONITORING}
# `agreement`: signed between the client and the Super-Tenant (RoE, SOW, contract annex, permission
# letter; the title says which). `third_party_consent`: a hosting, cloud or MSSP consent.
DOCUMENT_KINDS = ("agreement", "other", "third_party_consent")
MAX_ENGAGEMENT_DOCUMENTS = 20
_DOCUMENT_TITLE_MAX = 200
_DOCUMENT_COMMENT_MAX = 2000
SCAN_MODES = ("connect", "syn")
DEFAULT_SCAN_MODES = ("connect",)
ROE_DEFAULTS = {"authenticated_action": False, "stateful_probes_allowed": False,
                "ics_safe_mode_required": True}
# The asset kinds an engagement owns (RM-107). Scan categories mirror
# `services.scan_strategy.SCAN_STRATEGIES` (not imported: it loads the workers); a model asset's
# tests are the Model Testing question sets.
_KIND_CATEGORIES = {"network": ("service", "web", "correlation"), "webapp": ("graybox",)}
ENGAGEMENT_ASSET_KINDS = ("model", "network", "webapp")
MAX_ENGAGEMENT_ASSETS = 64
_ASSET_NAME_MAX = 200
HASH_SCHEMA = "redmesh.engagement/2"
# v1 fields a v2 row can never carry: their presence means a v1 record (refused, never migrated).
_V1_FIELDS = ("engagement_kind", "roe_document", "authorization_document")

_CONTEXT_TEXT = ("client_name", "engagement_code", "primary_objective", "secondary_objective",
                 "scope_rationale", "data_classification", "asset_exposure", "methodology")
_CONTACT_FIELDS = ("name", "email", "phone", "role")
_CONTEXT_TEXT_MAX = 500
_DOC_TEXT = ("store", "ref", "filename", "mime", "uploaded_at", "uploaded_by")
_DOCUMENT_LABELS = ("document_id", "kind", "title", "comment")
_INSTANT = "%Y-%m-%dT%H:%M:%SZ"


class EngagementInvalid(ValueError):
  """A refused engagement value; `code` is the 400 error the caller sees."""

  def __init__(self, code):
    super().__init__(code)
    self.code = code


def feature_ids_for_kind(kind):
  if kind == "model":
    # Imported here: the catalog loads the probe cases, which the record validator never needs.
    from ..model_testing.catalog import MODEL_TEST_CATALOG
    return tuple(test_set["id"] for test_set in MODEL_TEST_CATALOG)
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


def normalize_run_modes(value):
  if (not isinstance(value, list) or not value or not all(isinstance(mode, str) for mode in value)
      or len(set(value)) != len(value) or any(mode not in RUN_MODES for mode in value)):
    raise EngagementInvalid("run_modes_invalid")
  return sorted(value)


def normalize_document_labels(kind, title, comment):
  """A document's kind, title and comment as stored and hashed; every refusal is `document_invalid`."""
  if kind not in DOCUMENT_KINDS:
    raise EngagementInvalid("document_invalid")
  try:
    title = normalize_name(title, _DOCUMENT_TITLE_MAX)
  except (ValueError, TypeError):
    raise EngagementInvalid("document_invalid") from None
  if not isinstance(comment, str):
    raise EngagementInvalid("document_invalid")
  # Line breaks and tabs are allowed in a comment; every other control is refused, as in a title
  # (checked before the strip, which would silently drop a leading or trailing one).
  if any((ord(ch) < 32 and ch not in "\n\t\r") or 127 <= ord(ch) <= 159 or ch == "\ufeff" for ch in comment):
    raise EngagementInvalid("document_invalid")
  comment = comment.strip()
  if len(comment) > _DOCUMENT_COMMENT_MAX:
    raise EngagementInvalid("document_invalid")
  return {"kind": kind, "title": title, "comment": comment}


def normalize_scan_modes(value):
  if value is None:
    return list(DEFAULT_SCAN_MODES)
  if (not isinstance(value, list) or not value or not all(isinstance(mode, str) for mode in value)
      or len(set(value)) != len(value) or any(mode not in SCAN_MODES for mode in value)):
    raise EngagementInvalid("engagement_asset_invalid")
  return sorted(value)


def normalize_tests(kind, value):
  if not isinstance(value, list) or not value or any(not isinstance(item, str) for item in value):
    raise EngagementInvalid("tests_invalid")
  allowed = feature_ids_for_kind(kind)
  if len(set(value)) != len(value) or any(item not in allowed for item in value):
    raise EngagementInvalid("tests_invalid")
  return sorted(value)


def valid_doc_ref(value, *, labels=False, stored=False):
  """`labels`: the RM-107 kind, title and comment ride on the reference (an uploaded document, not
  yet numbered). `stored` accepts extra keys: a later release (RM-068) may add some to a document it
  wrote."""
  keys = {*_DOC_TEXT, "sha256", "size_bytes", *(_DOCUMENT_LABELS[1:] if labels else ())}
  if not (isinstance(value, dict) and (set(value) >= keys if stored else set(value) == keys)
          and all(isinstance(value[key], str) and value[key] for key in _DOC_TEXT)
          and valid_digest(value["sha256"])
          and type(value["size_bytes"]) is int and value["size_bytes"] > 0):
    return False
  if not labels:
    return True
  try:
    return normalize_document_labels(value["kind"], value["title"], value["comment"]) == {
      key: value[key] for key in _DOCUMENT_LABELS[1:]}
  except EngagementInvalid:
    return False


def engagement_asset_id_for(index):
  """`ea_<n>`, numbered from 1 in the order the assets were given at creation (as documents are)."""
  return "ea_%d" % (index + 1)


def normalize_engagement_asset(index, entry):
  """One requested asset as stored and hashed: the target is defined here, never read from a row.

  The kind is the target's. A network asset always ends with an explicit port scope, so a signed
  engagement never means "any port"; scan modes and ports apply to network assets only.
  """
  if (not isinstance(entry, dict)
      or not set(entry) <= {"display_name", "target", "authorized_ports", "authorized_scan_modes",
                            "authorized_tests"}):
    raise EngagementInvalid("engagement_asset_invalid")
  try:
    display_name = normalize_name(entry.get("display_name"), _ASSET_NAME_MAX)
  except (ValueError, TypeError):
    raise EngagementInvalid("engagement_asset_invalid") from None
  try:
    target = normalize_target(entry.get("target"))
  except (ValueError, TypeError):
    raise EngagementInvalid("asset_target_invalid") from None
  kind = target["kind"]
  stored = {"engagement_asset_id": engagement_asset_id_for(index), "display_name": display_name,
            "kind": kind, "target": target, "target_digest": canonical_digest(target),
            "authorized_tests": normalize_tests(kind, entry.get("authorized_tests"))}
  if kind != "network":
    if "authorized_ports" in entry or "authorized_scan_modes" in entry:
      raise EngagementInvalid("engagement_asset_invalid")
    return stored
  try:
    ports = normalize_port_scope(entry.get("authorized_ports"))
  except (ValueError, TypeError):
    raise EngagementInvalid("engagement_asset_invalid") from None
  if ports is None:  # absent, None or blank
    raise EngagementInvalid("ports_required")
  return {**stored, "authorized_ports": ports,
          "authorized_scan_modes": normalize_scan_modes(entry.get("authorized_scan_modes"))}


def normalize_engagement_assets(value):
  """The requested assets in the order given; the same target twice is refused."""
  if not isinstance(value, list) or not 1 <= len(value) <= MAX_ENGAGEMENT_ASSETS:
    raise EngagementInvalid("engagement_asset_invalid")
  assets = [normalize_engagement_asset(index, entry) for index, entry in enumerate(value)]
  if len({entry["target_digest"] for entry in assets}) != len(assets):
    raise EngagementInvalid("engagement_asset_invalid")
  return assets


def document_id_for(index):
  """`ed_<n>`, numbered from 1 in the order the documents were given at creation."""
  return "ed_%d" % (index + 1)


def _documents_valid(documents):
  if not isinstance(documents, list) or len(documents) > MAX_ENGAGEMENT_DOCUMENTS:
    return False
  for index, document in enumerate(documents):
    if (not isinstance(document, dict) or document.get("document_id") != document_id_for(index)
        or not valid_doc_ref({key: value for key, value in document.items() if key != "document_id"},
                             labels=True, stored=True)):
      return False
  return len({document["sha256"] for document in documents}) == len(documents)


def _stored_tests_valid(tests):
  # Shape only: catalog membership was checked at creation, and a later catalog change must not
  # make an immutable, hashed record unreadable. Launch re-checks membership (phase 3).
  return (isinstance(tests, list) and bool(tests) and all(isinstance(item, str) and item for item in tests)
          and tests == sorted(set(tests)))


def _asset_entry_valid(index, entry):
  if not isinstance(entry, dict) or not isinstance(entry.get("kind"), str):
    return False
  kind = entry["kind"]
  common = {"engagement_asset_id", "display_name", "kind", "target", "target_digest", "authorized_tests"}
  expected = common | ({"authorized_ports", "authorized_scan_modes"} if kind == "network" else set())
  if kind not in ENGAGEMENT_ASSET_KINDS or set(entry) != expected:
    return False
  try:
    if (entry["engagement_asset_id"] != engagement_asset_id_for(index)
        or normalize_name(entry["display_name"], _ASSET_NAME_MAX) != entry["display_name"]
        or normalize_target(entry["target"]) != entry["target"] or entry["target"]["kind"] != kind
        or canonical_digest(entry["target"]) != entry["target_digest"]
        or not _stored_tests_valid(entry["authorized_tests"])):
      return False
    if kind == "network":
      return (entry["authorized_ports"] is not None
              and normalize_port_scope(entry["authorized_ports"]) == entry["authorized_ports"]
              and normalize_scan_modes(entry["authorized_scan_modes"]) == entry["authorized_scan_modes"])
  except (ValueError, TypeError, EngagementInvalid):
    return False
  return True


def hashed_fields(record):
  """The exact content the engagement hash commits to (and RM-068 will later sign)."""
  return {
    "schema": HASH_SCHEMA, "tenant_id": record["tenant_id"], "engagement_id": record["engagement_id"],
    "display_name": record["display_name"], "allowed_run_modes": record["allowed_run_modes"],
    "valid_from": record["valid_from"], "valid_until": record["valid_until"],
    "contract_sha256": record["contract_sha256"],
    # Content, never position: the same files with the same labels are the same engagement.
    "documents": sorted([document["kind"], document["sha256"], document["title"], document["comment"]]
                        for document in record["documents"]),
    "supersedes": record.get("supersedes"),
    # In stored order: `ea_<n>` is positional, and launches and reports name assets by it.
    "roe": record["roe"], "context": record["context"], "assets": record["assets"],
  }


def engagement_hash(record):
  return canonical_digest(hashed_fields(record))


def _utc(value):
  return isinstance(value, str) and datetime.fromisoformat(value).tzinfo == timezone.utc


def validate_engagement(row, ids):
  """Refuse any stored engagement that creation and revoke could not have written.

  Values that live code may later change (the test catalog, `EngagementContext`, the document-ref
  keys) are checked for shape only: the record is immutable and its hash covers the content, so a
  catalog change must not make a tenant's engagements unreadable. Unknown fields are kept (as
  assets keep them) for the same reason during a mixed deploy.
  """
  assets = row.get("assets")
  if any(key in row for key in _V1_FIELDS):
    raise ValueError("Engagement record is v1")
  if (len(ids) != 2 or row.get("tenant_id") != ids[0] or row.get("engagement_id") != ids[1]
      or ids[1] != engagement_id_for(row.get("request_id"))
      or type(row.get("active")) is not bool
      or normalize_name(row.get("display_name")) != row["display_name"]
      or not isinstance(row.get("allowed_run_modes"), list)
      or normalize_run_modes(row["allowed_run_modes"]) != row["allowed_run_modes"]
      or normalize_window(row.get("valid_from"), row.get("valid_until"))
         != (row["valid_from"], row["valid_until"])
      or not valid_digest(row.get("contract_sha256"))
      or not _documents_valid(row.get("documents"))
      or not ("supersedes" not in row
              or (valid_engagement_id(row["supersedes"]) and row["supersedes"] != ids[1]))
      or normalize_roe(row.get("roe")) != row["roe"]
      # Shape only for the context: `EngagementContext` may gain fields; the hash covers the content.
      or not isinstance(row.get("context"), dict)
      or not isinstance(assets, list) or not 1 <= len(assets) <= MAX_ENGAGEMENT_ASSETS
      or not all(_asset_entry_valid(index, entry) for index, entry in enumerate(assets))
      or len({entry["target_digest"] for entry in assets}) != len(assets)
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
