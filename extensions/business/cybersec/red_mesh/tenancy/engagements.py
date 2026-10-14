"""RM-095 phase 2, RM-107: the engagement a tenant job runs inside; strict values and stored records.

An engagement is immutable: the only change after creation is a revoke. Its hash covers every
field a launch will rely on, with documents by SHA-256 (never by reference, so a re-upload of the
same bytes is the same engagement). RM-107 (`redmesh.engagement/2`): the tenant contract is the
permission, so there is no separate authorization document or typed signer; the engagement carries
a set of titled documents (RM-125: every test and both run modes are allowed, so it picks neither). The on-chain anchor is not part of the
row: until a registry function exists every engagement's anchor is `pending`, and the follow-up
keeps it in its own record so an anchor write can never race a revoke.
"""
from datetime import datetime, timezone
import re

from .assets import canonical_digest, canonical_uuid, normalize_name, normalize_target, valid_digest
from .contacts import valid_email, valid_phone
from .identity import canonical_account_id
from ..constants import FEATURE_CATALOG
from ..models.engagement import Contact, EngagementContext

# `agreement`: signed between the client and the Super-Tenant (RoE, SOW, contract annex, permission
# letter; the title says which). `third_party_consent`: a hosting, cloud or MSSP consent.
DOCUMENT_KINDS = ("agreement", "other", "third_party_consent")
MAX_ENGAGEMENT_DOCUMENTS = 20
_DOCUMENT_TITLE_MAX = 200
_DOCUMENT_COMMENT_MAX = 2000
SCAN_MODES = ("connect", "syn")  # launch vocabulary; an engagement no longer picks (RM-125)
# The asset kinds an engagement owns (RM-107). Scan categories mirror
# `services.scan_strategy.SCAN_STRATEGIES` (not imported: it loads the workers); a model asset's
# tests are the Model Testing question sets.
_KIND_CATEGORIES = {"network": ("service", "web", "correlation"), "webapp": ("graybox",)}
ENGAGEMENT_ASSET_KINDS = ("model", "network", "webapp")
MAX_ENGAGEMENT_ASSETS = 64
_ASSET_NAME_MAX = 200
# RM-125: /3 drops the per-engagement test, scan-mode and run-mode picks (every test, both run modes).
# RM-128: /4 drops the rules of engagement and the network assets' authorized ports.
HASH_SCHEMA = "redmesh.engagement/4"
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
  # RM-132: a contact's e-mail and phone have a format; the code stays `context_invalid`.
  if (contact.email and not valid_email(contact.email)) or (contact.phone and not valid_phone(contact.phone)):
    raise EngagementInvalid("context_invalid")
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


def valid_asset_id(value):
  """`ta_<uuid>`, as `tenant_assets.valid_asset_id` (not imported: that module imports this one)."""
  try:
    return isinstance(value, str) and value.startswith("ta_") and canonical_uuid(value[3:]) == value[3:]
  except ValueError:
    return False


def normalize_asset_requests(value):
  """RM-125 phase 2b: the public request form, each entry exactly `{asset_id}` (RM-128: no ports).

  Pure (no store read): this is what the replay intent covers. The target, name and kind are never
  sent; `build_engagement_assets` copies them from the registered asset at write time.
  """
  if not isinstance(value, list) or not 1 <= len(value) <= MAX_ENGAGEMENT_ASSETS:
    raise EngagementInvalid("engagement_asset_invalid")
  requests = []
  for entry in value:
    if not isinstance(entry, dict) or set(entry) != {"asset_id"} or not valid_asset_id(entry["asset_id"]):
      raise EngagementInvalid("engagement_asset_invalid")
    requests.append({"asset_id": entry["asset_id"]})
  if len({request["asset_id"] for request in requests}) != len(requests):
    raise EngagementInvalid("engagement_asset_invalid")
  return requests


def build_engagement_assets(requests, lookup):
  """The stored entries for normalized `requests`, in order. `lookup(asset_id)` answers the
  registered asset row or raises (the administration's `asset_not_found` / `asset_archived`).

  The kind is the target's.
  """
  assets = []
  for index, request in enumerate(requests):
    row = lookup(request["asset_id"])
    target = row["target"]
    assets.append({"engagement_asset_id": engagement_asset_id_for(index), "asset_id": row["asset_id"],
                   "display_name": row["display_name"], "kind": target["kind"], "target": target,
                   "target_digest": row["target_digest"]})
  if len({entry["target_digest"] for entry in assets}) != len(assets):
    raise EngagementInvalid("engagement_asset_invalid")
  return assets


def normalize_engagement_assets(value):
  """Stored (snapshot) entries as the draft keeps them; the engagement keeps exactly these."""
  if (not isinstance(value, list) or not 1 <= len(value) <= MAX_ENGAGEMENT_ASSETS
      or not all(_asset_entry_valid(index, entry) for index, entry in enumerate(value))
      or len({entry["target_digest"] for entry in value}) != len(value)
      or len({entry["asset_id"] for entry in value}) != len(value)):
    raise EngagementInvalid("engagement_asset_invalid")
  return [dict(entry) for entry in value]


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
  # RM-128: unique per kind, so the generated pack (`other`) may also be the signed copy (`agreement`).
  return len({(document["kind"], document["sha256"]) for document in documents}) == len(documents)


def _asset_entry_valid(index, entry):
  if not isinstance(entry, dict) or not isinstance(entry.get("kind"), str):
    return False
  kind = entry["kind"]
  if kind not in ENGAGEMENT_ASSET_KINDS or set(entry) != {
      "engagement_asset_id", "asset_id", "display_name", "kind", "target", "target_digest"}:
    return False
  try:
    if (entry["engagement_asset_id"] != engagement_asset_id_for(index) or not valid_asset_id(entry["asset_id"])
        or normalize_name(entry["display_name"], _ASSET_NAME_MAX) != entry["display_name"]
        or normalize_target(entry["target"]) != entry["target"] or entry["target"]["kind"] != kind
        or canonical_digest(entry["target"]) != entry["target_digest"]):
      return False
  except (ValueError, TypeError, EngagementInvalid):
    return False
  return True


def hashed_fields(record):
  """The exact content the engagement hash commits to (and RM-068 will later sign)."""
  return {
    "schema": HASH_SCHEMA, "tenant_id": record["tenant_id"], "engagement_id": record["engagement_id"],
    "display_name": record["display_name"],
    "valid_from": record["valid_from"], "valid_until": record["valid_until"],
    "contract_sha256": record["contract_sha256"],
    # Content, never position: the same files with the same labels are the same engagement.
    "documents": sorted([document["kind"], document["sha256"], document["title"], document["comment"]]
                        for document in record["documents"]),
    "supersedes": record.get("supersedes"),
    # In stored order: `ea_<n>` is positional, and launches and reports name assets by it.
    "context": record["context"], "assets": record["assets"],
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
      or normalize_window(row.get("valid_from"), row.get("valid_until"))
         != (row["valid_from"], row["valid_until"])
      or not valid_digest(row.get("contract_sha256"))
      or not _documents_valid(row.get("documents"))
      or not ("supersedes" not in row
              or (valid_engagement_id(row["supersedes"]) and row["supersedes"] != ids[1]))
      # Shape only for the context: `EngagementContext` may gain fields; the hash covers the content.
      or not isinstance(row.get("context"), dict)
      or not isinstance(assets, list) or not 1 <= len(assets) <= MAX_ENGAGEMENT_ASSETS
      or not all(_asset_entry_valid(index, entry) for index, entry in enumerate(assets))
      or len({entry["target_digest"] for entry in assets}) != len(assets)
      or len({entry["asset_id"] for entry in assets}) != len(assets)
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
