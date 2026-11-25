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
from ..constants import FEATURE_CATALOG, GRAYBOX_PROBE_REGISTRY
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
# RM-251: /5 brought the authorized ports and tests back, one pair on the engagement. RM-277: /6 puts them on
# each asset entry. The schema follows the keys a row holds (D-10): none anywhere is `/4`, read as scope
# "all"; both on the engagement is `/5` (legacy, read-only: each asset's scope is derived from it); the keys
# on every asset is `/6`, and every new row. Engagement-level plus asset keys, or a mix of assets, is refused.
HASH_SCHEMA = "redmesh.engagement/6"
HASH_SCHEMA_V5 = "redmesh.engagement/5"
HASH_SCHEMA_V4 = "redmesh.engagement/4"
MAX_SCOPE_ENTRIES = 64
_TEST_ID = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
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
  if kind == "webapp":
    # RM-277: the graybox probe families (the probe methods, without the leading underscore).
    return tuple(entry["key"].lstrip("_") for entry in GRAYBOX_PROBE_REGISTRY) + ("graybox_weak_auth",)
  categories = _KIND_CATEGORIES.get(kind, ())
  return tuple(item["id"] for item in FEATURE_CATALOG if item["category"] in categories)


def normalize_authorized_ports(value):
  """RM-251: `"all"` or the ranges as stored: `[start, end]` within 1-65535, sorted and merged."""
  if value == "all":
    return value
  if not isinstance(value, list) or not 1 <= len(value) <= MAX_SCOPE_ENTRIES:
    raise EngagementInvalid("authorized_ports_invalid")
  merged = []
  for entry in value:
    if (not isinstance(entry, (list, tuple)) or len(entry) != 2 or any(type(port) is not int for port in entry)
        or not 1 <= entry[0] <= entry[1] <= 65535):
      raise EngagementInvalid("authorized_ports_invalid")
  for start, end in sorted(tuple(entry) for entry in value):
    if merged and start <= merged[-1][1] + 1:
      merged[-1][1] = max(merged[-1][1], end)
    else:
      merged.append([start, end])
  return merged


def normalize_authorized_tests(value, kinds=None):
  """RM-251: `"all"` or the catalogue ids, sorted. With `kinds` (the asset kind) each id must be valid
  for one of them; without, the shape only (a catalogue change never makes a record unreadable)."""
  if value == "all":
    return value
  if (not isinstance(value, list) or not 1 <= len(value) <= MAX_SCOPE_ENTRIES
      or any(not isinstance(test, str) or not _TEST_ID.fullmatch(test) for test in value)):
    raise EngagementInvalid("authorized_tests_invalid")
  if kinds is not None and not set(value) <= {test for kind in kinds for test in feature_ids_for_kind(kind)}:
    raise EngagementInvalid("authorized_tests_unknown")
  return sorted(set(value))


_SCOPE_KEYS = ("authorized_ports", "authorized_tests")


def scope_keys(kind):
  """RM-277: the scope keys an asset entry of `kind` carries; only a network asset has ports."""
  return _SCOPE_KEYS if kind == "network" else _SCOPE_KEYS[1:]


def scope_of(entry):
  """RM-277: `(authorized_ports, authorized_tests)` of an asset entry; a `/4` entry (no scope keys) is `all`."""
  return entry.get("authorized_ports", "all"), entry.get("authorized_tests", "all")


def derive_scope(ports, tests, kind):
  """RM-251 legacy: one asset's `(authorized_ports, authorized_tests)` from the engagement-level pair.
  Ports bind network assets only. The tests are the listed ids valid for the kind (the old `graybox`
  id is every webapp family); a restricted list holding none for the kind is `[]`: nothing authorized."""
  if tests != "all":
    ids = set(feature_ids_for_kind(kind))
    tests = sorted(({test for test in tests if test in ids} | (ids if kind == "webapp" and "graybox" in tests else set())))
  return (ports if kind == "network" else "all"), tests


def asset_scope(row, entry):
  """The scope of `entry` in the engagement `row`: its own keys, or (a `/5` row) derived from the row's."""
  if "authorized_tests" in row:
    return derive_scope(row["authorized_ports"], row["authorized_tests"], entry["kind"])
  return scope_of(entry)


def with_scope(entry, scope=None):
  """RM-277: the entry with the scope keys its kind carries: `scope` (`(ports, tests)`) if given, else its own, `all` where it had none."""
  scope = scope_of(entry) if scope is None else scope
  return {**entry, **dict(zip(_SCOPE_KEYS, scope))} if entry["kind"] == "network" else {
    **{key: value for key, value in entry.items() if key != "authorized_ports"}, "authorized_tests": scope[1]}


def _legacy_scope_valid(row):
  """RM-251: the engagement-level pair, both keys or neither, in the stored form."""
  if ("authorized_ports" in row) != ("authorized_tests" in row):
    return False
  try:
    ports, tests = row.get("authorized_ports", "all"), row.get("authorized_tests", "all")
    return normalize_authorized_ports(ports) == ports and normalize_authorized_tests(tests) == tests
  except EngagementInvalid:
    return False


def _row_scope_valid(row):
  """The schema rule: the pair on the engagement (`/5`) or the keys on every asset (`/6`), never both."""
  assets = row["assets"]
  return _legacy_scope_valid(row) and _scope_uniform(assets) and not (
    "authorized_tests" in row and any("authorized_tests" in entry for entry in assets))


def _scope_uniform(assets):
  """Every asset carries its scope keys or none does (the schema follows them)."""
  return len({"authorized_tests" in entry for entry in assets}) <= 1


def ports_outside(ports, authorized):
  """RM-251: the `[start, end]` ranges of `ports` (a set) that `authorized` (ranges) does not cover."""
  stray = sorted(port for port in ports if not any(start <= port <= end for start, end in authorized))
  ranges = []
  for port in stray:
    if ranges and port == ranges[-1][1] + 1:
      ranges[-1][1] = port
    else:
      ranges.append([port, port])
  return ranges


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


def normalize_asset_requests(value, keep_all=False):
  """RM-125 phase 2b: the public request form, each entry `{asset_id}` and, RM-277, the asset's
  `authorized_ports` and `authorized_tests` (shape only, kept when restricted, so an "all" request
  replays as before the scope; `keep_all`: an explicit "all" stays, a draft's reset of a held asset).

  Pure (no store read): this is what the replay intent covers. The target, name and kind are never
  sent; `build_engagement_assets` copies them from the registered asset at write time.
  """
  if not isinstance(value, list) or not 1 <= len(value) <= MAX_ENGAGEMENT_ASSETS:
    raise EngagementInvalid("engagement_asset_invalid")
  requests = []
  for entry in value:
    if (not isinstance(entry, dict) or "asset_id" not in entry or not set(entry) <= {"asset_id", *_SCOPE_KEYS}
        or not valid_asset_id(entry["asset_id"])):
      raise EngagementInvalid("engagement_asset_invalid")
    request = {"asset_id": entry["asset_id"]}
    for key, normalize in zip(_SCOPE_KEYS, (normalize_authorized_ports, normalize_authorized_tests)):
      if key in entry and (keep_all or normalize(entry[key]) != "all"):
        request[key] = normalize(entry[key])
    requests.append(request)
  if len({request["asset_id"] for request in requests}) != len(requests):
    raise EngagementInvalid("engagement_asset_invalid")
  return requests


def build_engagement_assets(requests, lookup):
  """The stored entries for normalized `requests`, in order. `lookup(asset_id)` answers the
  registered asset row or raises (the administration's `asset_not_found` / `asset_archived`).

  The kind is the target's. RM-277: each entry carries the scope keys of its kind (`all` unless the
  request restricts them); ports on a non-network asset and tests outside the kind are refused.
  """
  assets = []
  for index, request in enumerate(requests):
    row = lookup(request["asset_id"])
    target = row["target"]
    if "authorized_ports" in request and target["kind"] != "network":
      raise EngagementInvalid("authorized_ports_invalid")
    assets.append({
      "engagement_asset_id": engagement_asset_id_for(index), "asset_id": row["asset_id"],
      "display_name": row["display_name"], "kind": target["kind"], "target": target,
      "target_digest": row["target_digest"],
      # A held draft entry keeps its stored scope unless the request names it; a registered asset starts "all".
      **{key: request.get(key, row.get(key, "all")) for key in scope_keys(target["kind"])}})
    normalize_authorized_tests(assets[-1]["authorized_tests"], {target["kind"]})
  if len({entry["target_digest"] for entry in assets}) != len(assets):
    raise EngagementInvalid("engagement_asset_invalid")
  return assets


def normalize_engagement_assets(value):
  """Stored (snapshot) entries as the draft keeps them; the engagement keeps exactly these."""
  if (not isinstance(value, list) or not 1 <= len(value) <= MAX_ENGAGEMENT_ASSETS
      or not all(_asset_entry_valid(index, entry, empty_tests=True) for index, entry in enumerate(value))
      or len({entry["target_digest"] for entry in value}) != len(value)
      or len({entry["asset_id"] for entry in value}) != len(value) or not _scope_uniform(value)):
    raise EngagementInvalid("engagement_asset_invalid")
  # RM-277: the ids are checked against the asset's kind here (the record check is shape only); `[]` is
  # what an RM-251 draft derives when its list held no id for the kind, never a valid write.
  for entry in value:
    normalize_authorized_tests(scope_of(entry)[1], {entry["kind"]})
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


def _asset_entry_valid(index, entry, empty_tests=False):
  if not isinstance(entry, dict) or not isinstance(entry.get("kind"), str):
    return False
  kind = entry["kind"]
  base = {"engagement_asset_id", "asset_id", "display_name", "kind", "target", "target_digest"}
  # RM-277: the scope keys of its kind, or none (a `/4` entry).
  if kind not in ENGAGEMENT_ASSET_KINDS or set(entry) not in (base, base | set(scope_keys(kind))):
    return False
  try:
    ports, tests = scope_of(entry)
    # `empty_tests`: a draft derived from an RM-251 scope may hold `[]` (nothing authorized); completeness flags it.
    if normalize_authorized_ports(ports) != ports or (
        not (empty_tests and tests == []) and normalize_authorized_tests(tests) != tests):
      return False
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
  legacy = "authorized_tests" in record
  scoped = any("authorized_tests" in entry for entry in record["assets"])
  return {
    "schema": HASH_SCHEMA_V5 if legacy else HASH_SCHEMA if scoped else HASH_SCHEMA_V4, "tenant_id": record["tenant_id"], "engagement_id": record["engagement_id"],
    "display_name": record["display_name"],
    "valid_from": record["valid_from"], "valid_until": record["valid_until"],
    "contract_sha256": record["contract_sha256"],
    # Content, never position: the same files with the same labels are the same engagement.
    "documents": sorted([document["kind"], document["sha256"], document["title"], document["comment"]]
                        for document in record["documents"]),
    "supersedes": record.get("supersedes"),
    # In stored order: `ea_<n>` is positional, and launches and reports name assets by it.
    "context": record["context"], "assets": record["assets"],
    **({"authorized_ports": record["authorized_ports"], "authorized_tests": record["authorized_tests"]} if legacy else {}),
  }


def engagement_hash(record):
  return canonical_digest(hashed_fields(record))


def _utc(value):
  return isinstance(value, str) and datetime.fromisoformat(value).tzinfo == timezone.utc


# RM-248: suspend is a state like revoke, outside the hash. `suspended` is absent on a legacy row.
SUSPEND_FIELDS = ("suspended_by", "suspended_at", "suspend_reason")
RESUME_FIELDS = ("resumed_by", "resumed_at")
SUSPEND_STATE_KEYS = ("suspended", *SUSPEND_FIELDS, *RESUME_FIELDS)


def _valid_attribution(row, by, at):
  return (bool(row.get(by)) and canonical_account_id(row[by]) == row[by] and _utc(row.get(at)))


def _suspend_state_valid(row):
  """RM-248: the shape of the suspend and resume fields; a revoked row carries none of them."""
  if not row["active"]:
    return not any(key in row for key in SUSPEND_STATE_KEYS)
  if "suspended" in row and type(row["suspended"]) is not bool:
    return False
  if row.get("suspended") is True:
    return (_valid_attribution(row, "suspended_by", "suspended_at")
            and normalize_name(row.get("suspend_reason"), 500) == row["suspend_reason"]
            and not any(key in row for key in RESUME_FIELDS))
  if any(key in row for key in SUSPEND_FIELDS):
    return False
  return not any(key in row for key in RESUME_FIELDS) or _valid_attribution(row, "resumed_by", "resumed_at")


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
      # RM-248: the replacement link, outside the hash like revoke; `revoke_superseded` rides on a replacement.
      or not ("superseded_by" not in row
              or (valid_engagement_id(row["superseded_by"]) and row["superseded_by"] != ids[1]))
      or not ("revoke_superseded" not in row
              or (type(row["revoke_superseded"]) is bool and "supersedes" in row))
      # Shape only for the context: `EngagementContext` may gain fields; the hash covers the content.
      or not isinstance(row.get("context"), dict)
      or not isinstance(assets, list) or not 1 <= len(assets) <= MAX_ENGAGEMENT_ASSETS
      or not all(_asset_entry_valid(index, entry) for index, entry in enumerate(assets))
      or len({entry["target_digest"] for entry in assets}) != len(assets)
      or len({entry["asset_id"] for entry in assets}) != len(assets)
      or not valid_digest(row.get("create_intent_digest"))
      or not _row_scope_valid(row)
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
  if not _suspend_state_valid(row):
    raise ValueError("Invalid engagement suspend state")
  canonical_digest(row)
