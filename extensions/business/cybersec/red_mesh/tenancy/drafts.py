"""RM-109 phase 2: the tenant draft, a tenant prepared before its documents are signed.

Vocabulary, formats, the stored-record validator, the completeness rule and the DTO; no storage
I/O. Contract: `docs/resources/redmesh/contracts/onboarding-drafts.md` (project hub). A draft is
mutable, never hashed and never anchored, and it is not a tenant: its id (`td_<uuid>`) is never a
tenant id. Activation (`prepare_tenant` with `draft_id`, the marker, release, close) is phase 3;
until then `activation` and `last_release` stay null on every row this release writes.
"""
from datetime import date
import re

from .assets import normalize_name
from .engagements import valid_doc_ref
from .identity import canonical_account_id

DOCUMENT_KINDS = ("contract", "framework_agreement", "data_handling")
TENANT_RECORDS = ("framework_agreement", "data_handling")
ENGAGEMENT_RECORDS = ("scope_of_work", "authorization_to_test", "rules_of_engagement", "third_party",
                      "elevated_risk")
# Governance records (Compliance Workspace v5.0 §7): the values of `covers`, in this order.
RECORDS = TENANT_RECORDS + ENGAGEMENT_RECORDS
COMPLIANCE_TYPES = ("ai_act", "cra", "nis2")
ITEM_STATES = ("missing", "awaiting_signature", "signed")
DECISIONS = ("required", "not_required", "unknown")
LEGAL_FIELDS = ("name", "registration_id", "signer_name", "signer_role")
# The checklist is fixed and the same for every compliance type (owner, 2026-09-29). No item is a
# duty of NIS2, the CRA or the AI Act.
BASIS = {kind: "Contractual obligation" for kind in DOCUMENT_KINDS}
_OWN_RECORD = {"contract": None, "framework_agreement": "framework_agreement", "data_handling": "data_handling"}
# What an item's document may cover besides its own record: a combined contract, the schedule as the
# framework agreement's annex, and engagement-level records from any item.
_COVERABLE = {
  "contract": frozenset({"framework_agreement", "data_handling", *ENGAGEMENT_RECORDS}),
  "framework_agreement": frozenset({"framework_agreement", "data_handling", *ENGAGEMENT_RECORDS}),
  "data_handling": frozenset({"data_handling", *ENGAGEMENT_RECORDS}),
}
_ITEM_FIELDS = ("state", "document", "covers", "effective_from", "effective_until")
_ITEM_CHANGES = ("state", "covers", "effective_from", "effective_until")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_DOMAIN = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_DISPLAY_NAME_MAX = 120
_LEGAL_MAX = 200
_REASON_MAX = 500
DTO_FIELDS = ("draft_id", "display_name", "domain_id", "initial_admin_id", "legal", "compliance_types",
              "items", "applicability", "activation", "last_release", "created_by", "created_at",
              "updated_by", "updated_at")


class DraftInvalid(Exception):
  def __init__(self, code="invalid_request"):
    super().__init__(code)
    self.code = code


def draft_id_for(request_id):
  return "td_" + request_id


def valid_draft_id(value):
  return isinstance(value, str) and value.startswith("td_") and _UUID.match(value[3:]) is not None


def _text(value, maximum):
  """Free text, empty allowed in a draft; the formats of `normalize_name` otherwise."""
  if not isinstance(value, str):
    raise DraftInvalid()
  if not value.strip():
    return ""
  try:
    return normalize_name(value, maximum)
  except (ValueError, TypeError, UnicodeError):
    raise DraftInvalid() from None


def normalize_display_name(value):
  return _text(value, _DISPLAY_NAME_MAX)


def normalize_domain(value):
  if value == "":
    return ""
  if not isinstance(value, str) or not _DOMAIN.match(value):
    raise DraftInvalid("invalid_domain")
  return value


def normalize_initial_admin(value):
  if isinstance(value, str) and not value.strip():
    return ""
  account_id = canonical_account_id(value)
  if not account_id:
    raise DraftInvalid()
  return account_id


def normalize_compliance_types(value):
  if (not isinstance(value, list) or any(not isinstance(item, str) or item not in COMPLIANCE_TYPES for item in value)
      or len(set(value)) != len(value)):
    raise DraftInvalid()
  return sorted(value)


def normalize_legal(value, current):
  """A partial change: only the keys sent are replaced."""
  if not isinstance(value, dict) or any(key not in LEGAL_FIELDS for key in value):
    raise DraftInvalid()
  return {**current, **{key: _text(text, _LEGAL_MAX) for key, text in value.items()}}


def _effective_date(value):
  if value is None:
    return None
  if not isinstance(value, str) or not _DATE.match(value):
    raise DraftInvalid()
  try:
    date.fromisoformat(value)
  except ValueError:
    raise DraftInvalid() from None
  return value


def normalize_covers(kind, value):
  if (not isinstance(value, list) or any(not isinstance(item, str) or item not in _COVERABLE[kind] for item in value)
      or len(set(value)) != len(value)
      or (_OWN_RECORD[kind] is not None and _OWN_RECORD[kind] not in value)):
    raise DraftInvalid()
  return [record for record in RECORDS if record in value]


def normalize_applicability(value):
  if not isinstance(value, dict) or set(value) != {"decision", "reason"} or value["decision"] not in DECISIONS:
    raise DraftInvalid()
  reason = value["reason"]
  if reason is not None:
    reason = _text(reason, _REASON_MAX) or None
  if value["decision"] == "not_required" and reason is None:
    raise DraftInvalid()
  return {"decision": value["decision"], "reason": reason}


def new_draft(draft_id, display_name, compliance_types, actor_id, now):
  return {
    "draft_id": draft_id, "display_name": normalize_display_name(display_name), "domain_id": "",
    "initial_admin_id": "", "legal": {key: "" for key in LEGAL_FIELDS},
    "compliance_types": normalize_compliance_types(compliance_types),
    "items": {kind: {"state": "missing", "document": None,
                     "covers": [] if _OWN_RECORD[kind] is None else [_OWN_RECORD[kind]],
                     "effective_from": None, "effective_until": None} for kind in DOCUMENT_KINDS},
    "applicability": {record: {"decision": "unknown", "reason": None} for record in TENANT_RECORDS},
    "activation": None, "last_release": None,
    "created_by": actor_id, "created_at": now, "updated_by": actor_id, "updated_at": now,
  }


def apply_changes(row, changes):
  """The row with `changes` applied (`update_tenant_draft`), and the refs whose files it drops.

  Formats are checked, emptiness is allowed. An update may set an item `missing` (its file goes) or
  `awaiting_signature` (only without a file); `signed` is set by an upload alone.
  """
  if not isinstance(changes, dict):
    raise DraftInvalid()
  allowed = {"display_name", "domain_id", "initial_admin_id", "legal", "compliance_types", "items",
             "applicability"}
  if any(key not in allowed for key in changes):
    raise DraftInvalid()
  row = {**row, "legal": dict(row["legal"]), "items": {kind: dict(item) for kind, item in row["items"].items()},
         "applicability": dict(row["applicability"])}
  dropped = []
  if "display_name" in changes:
    row["display_name"] = normalize_display_name(changes["display_name"])
  if "domain_id" in changes:
    row["domain_id"] = normalize_domain(changes["domain_id"])
  if "initial_admin_id" in changes:
    row["initial_admin_id"] = normalize_initial_admin(changes["initial_admin_id"])
  if "legal" in changes:
    row["legal"] = normalize_legal(changes["legal"], row["legal"])
  if "compliance_types" in changes:
    row["compliance_types"] = normalize_compliance_types(changes["compliance_types"])
  if "items" in changes:
    items = changes["items"]
    if not isinstance(items, dict) or any(kind not in DOCUMENT_KINDS for kind in items):
      raise DraftInvalid()
    for kind, change in items.items():
      if not isinstance(change, dict) or any(key not in _ITEM_CHANGES for key in change):
        raise DraftInvalid()
      item = row["items"][kind]
      if "covers" in change:
        item["covers"] = normalize_covers(kind, change["covers"])
      for key in ("effective_from", "effective_until"):
        if key in change:
          item[key] = _effective_date(change[key])
      if "state" in change:
        state = change["state"]
        if state == "missing":
          if item["document"] is not None:
            dropped.append(item["document"]["ref"])
          item.update(state="missing", document=None)
        elif state == "awaiting_signature" and item["document"] is None:
          item["state"] = "awaiting_signature"
        else:
          raise DraftInvalid()
  if "applicability" in changes:
    decisions = changes["applicability"]
    if not isinstance(decisions, dict) or any(record not in TENANT_RECORDS for record in decisions):
      raise DraftInvalid()
    for record, decision in decisions.items():
      row["applicability"][record] = normalize_applicability(decision)
  return row, dropped


def without_documents(row, refs):
  """The row with every item whose file is in `refs` (gone from the store) read as `missing`."""
  refs = set(refs)
  if not any(item["document"] is not None and item["document"]["ref"] in refs for item in row["items"].values()):
    return row
  items = {}
  for kind, item in row["items"].items():
    if item["document"] is not None and item["document"]["ref"] in refs:
      item = {**item, "state": "missing", "document": None}
    items[kind] = item
  return {**row, "items": items}


def document_refs(row):
  return [item["document"]["ref"] for item in row["items"].values() if item["document"] is not None]


def _covered_by(row, kind):
  """The other signed item whose document covers this item's record, or None."""
  record = _OWN_RECORD[kind]
  if record is None:
    return None
  return next((other for other in DOCUMENT_KINDS if other != kind and row["items"][other]["state"] == "signed"
               and record in row["items"][other]["covers"]), None)


def _covered(row, record):
  return any(item["state"] == "signed" and record in item["covers"] for item in row["items"].values())


def completeness(row):
  """The activation rule, one `missing` entry per gap. Engagement-level records never block."""
  missing = []
  if not row["display_name"]:
    missing.append("field:display_name")
  if not row["domain_id"]:
    missing.append("field:domain_id")
  if not row["initial_admin_id"]:
    missing.append("field:initial_admin_id")
  missing.extend(f"field:legal.{key}" for key in LEGAL_FIELDS if not row["legal"][key])
  if not row["compliance_types"]:
    missing.append("field:compliance_types")
  if row["items"]["contract"]["state"] != "signed":
    missing.append("item:contract")
  for record in TENANT_RECORDS:
    # A covered record is never a gap; `unknown` is never read as `not_required`.
    if not _covered(row, record) and row["applicability"][record]["decision"] != "not_required":
      missing.append(f"record:{record}")
  return {"complete": not missing, "missing": missing}


def draft_dto(row):
  dto = {key: row[key] for key in DTO_FIELDS}
  dto["items"] = {kind: {**{key: row["items"][kind][key] for key in _ITEM_FIELDS}, "basis": BASIS[kind],
                         "covered_by": _covered_by(row, kind)} for kind in DOCUMENT_KINDS}
  dto["completeness"] = completeness(row)
  return dto


def draft_list_row(row):
  done = sum(1 for kind in DOCUMENT_KINDS
             if row["items"][kind]["state"] == "signed" or _covered_by(row, kind) is not None)
  return {"draft_id": row["draft_id"], "display_name": row["display_name"],
          "compliance_types": row["compliance_types"], "created_at": row["created_at"],
          "updated_at": row["updated_at"], "items_done": done, "items_total": len(DOCUMENT_KINDS),
          "activation": row["activation"]}


def _nonempty_text(value):
  return isinstance(value, str) and bool(value)


def _valid_stamp(value, keys, optional=()):
  return (isinstance(value, dict) and set(value) == set(keys)
          and all(_nonempty_text(value[key]) or (key in optional and value[key] is None) for key in keys))


def _same(normalize, value):
  try:
    return normalize(value) == value
  except DraftInvalid:
    return False


def validate_tenant_draft(row, ids):
  """Refuse a stored draft the operations could not have written. Unknown fields are kept."""
  items, applicability, legal = row.get("items"), row.get("applicability"), row.get("legal")
  if (len(ids) != 1 or row.get("draft_id") != ids[0] or not valid_draft_id(ids[0])
      or not _same(normalize_display_name, row.get("display_name"))
      or not _same(normalize_domain, row.get("domain_id"))
      or not _same(normalize_initial_admin, row.get("initial_admin_id"))
      or not isinstance(legal, dict) or set(legal) != set(LEGAL_FIELDS)
      or not all(_same(lambda text: _text(text, _LEGAL_MAX), legal[key]) for key in LEGAL_FIELDS)
      or not _same(normalize_compliance_types, row.get("compliance_types"))
      or not isinstance(items, dict) or set(items) != set(DOCUMENT_KINDS)
      or not isinstance(applicability, dict) or set(applicability) != set(TENANT_RECORDS)
      or not all(_same(normalize_applicability, applicability[record]) for record in TENANT_RECORDS)
      or not (row.get("activation") is None
              or _valid_stamp(row["activation"], ("actor_id", "request_id", "started_at")))
      or not (row.get("last_release") is None
              or _valid_stamp(row["last_release"], ("actor_id", "released_at", "request_id", "tenant_id",
                                                     "initial_admin_id"), optional=("tenant_id", "initial_admin_id")))
      or not all(_nonempty_text(row.get(key)) for key in ("created_by", "created_at", "updated_by", "updated_at"))):
    raise ValueError("Invalid tenant draft record")
  for kind in DOCUMENT_KINDS:
    item = items[kind]
    if (not isinstance(item, dict) or set(item) != set(_ITEM_FIELDS) or item["state"] not in ITEM_STATES
        or (item["state"] == "signed") != (item["document"] is not None)
        or (item["document"] is not None and not valid_doc_ref(item["document"]))
        or not _same(lambda covers: normalize_covers(kind, covers), item["covers"])
        or not _same(_effective_date, item["effective_from"])
        or not _same(_effective_date, item["effective_until"])):
      raise ValueError("Invalid tenant draft item")
  return row
