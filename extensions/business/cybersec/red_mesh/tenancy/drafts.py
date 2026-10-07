"""RM-109: the tenant draft, a tenant prepared before its documents are signed.

Vocabulary, formats, the stored-record validator, the completeness rule, the governance terms an
activation copies onto the receipt and the tenant, and the DTO; no storage I/O. Contract:
`docs/resources/redmesh/contracts/onboarding-drafts.md` (project hub). A draft is mutable, never
hashed and never anchored, and it is not a tenant: its id (`td_<uuid>`) is never a tenant id.
`activation` is the marker `prepare_tenant` writes before the receipt (it locks the draft);
`last_release` records the last release of a stuck activation. Both are written by
`tenancy.administration`. RM-112: `nodes` is the node plan, assigned when the tenant is activated;
a private entry holds its node (checked by `tenancy.administration`, which reads every draft).
"""
from datetime import date, datetime
import json
import re

from .assets import normalize_name, valid_digest
from .engagements import valid_doc_ref
from .identity import canonical_account_id
from .nodes import NODE_ASSIGNMENT_MODES, valid_node_address

DOCUMENT_KINDS = ("contract", "framework_agreement", "data_handling")
# The collapsed checklist (owner, 2026-10-07): one tenant agreement pack in the `contract` slot, which
# covers both tenant records; the other two slots stay in the record, null and not shown.
SHOWN_KINDS = ("contract",)
TENANT_RECORDS = ("framework_agreement", "data_handling")
ENGAGEMENT_RECORDS = ("scope_of_work", "authorization_to_test", "rules_of_engagement", "third_party",
                      "elevated_risk")
# Governance records (Compliance Workspace v5.0 §7): the values of `covers`, in this order.
RECORDS = TENANT_RECORDS + ENGAGEMENT_RECORDS
COMPLIANCE_TYPES = ("ai_act", "cra", "nis2")
# `generated` (RM-110): a pack was generated and its baseline recorded, no signed file yet.
ITEM_STATES = ("missing", "generated", "awaiting_signature", "signed")
DECISIONS = ("required", "not_required", "unknown")
# The four fields activation requires, and the RM-110 party-block fields (optional: `address` and
# `contact_email` are needed by generation, never by activation). A row written before RM-110 has
# the first four only; the validator completes it on a copy, so the stored row is never rewritten.
LEGAL_FIELDS = ("name", "registration_id", "signer_name", "signer_role")
LEGAL_OPTIONAL_FIELDS = ("address", "vat_id", "contact_name", "contact_email", "contact_phone")
LEGAL_ALL_FIELDS = LEGAL_FIELDS + LEGAL_OPTIONAL_FIELDS
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
_ITEM_FIELDS = ("state", "document", "covers", "effective_from", "effective_until", "generated")
# `covers` and applicability are fixed by the pack, never edited (owner, 2026-10-07).
_ITEM_CHANGES = ("state", "effective_from", "effective_until")
# The `generated` block (RM-110 `store_generated_document`): the stored ref of the unsigned pack,
# whose envelope also holds the snapshot, plus the baseline stamps. Hashes only on the row.
DOC_REF_KEYS = ("store", "ref", "filename", "mime", "uploaded_at", "uploaded_by", "sha256", "size_bytes")
_GENERATED_FIELDS = ("snapshot_sha256", "generated_at", "generated_by")
SNAPSHOT_MAX_BYTES = 64 * 1024
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
_DOMAIN = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_DATE = re.compile(r"\d{4}-\d{2}-\d{2}\Z")
_INSTANT = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|\+00:00)\Z")
_DISPLAY_NAME_MAX = 120
LEGAL_MAX = 200
_LEGAL_MAX = LEGAL_MAX
_REASON_MAX = 500
DTO_FIELDS = ("draft_id", "display_name", "domain_id", "initial_admin_id", "legal", "compliance_types",
              "items", "applicability", "nodes", "activation", "last_release", "created_by", "created_at",
              "updated_by", "updated_at")


class DraftInvalid(Exception):
  def __init__(self, code="invalid_request"):
    super().__init__(code)
    self.code = code


def draft_id_for(request_id):
  return "td_" + request_id


def valid_draft_id(value):
  return isinstance(value, str) and value.startswith("td_") and _UUID.match(value[3:]) is not None


def text(value, maximum):
  """Free text, empty allowed in a draft; the formats of `normalize_name` otherwise. Shared with the
  super-tenant profile (RM-110)."""
  if not isinstance(value, str):
    raise DraftInvalid()
  if not value.strip():
    return ""
  try:
    return normalize_name(value, maximum)
  except (ValueError, TypeError, UnicodeError):
    raise DraftInvalid() from None


_text = text


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


def normalize_nodes(value):
  """RM-112 node plan: `{node_address, mode}` entries, one per node, sorted by address."""
  if (not isinstance(value, list)
      or any(not isinstance(entry, dict) or set(entry) != {"node_address", "mode"}
             or not valid_node_address(entry["node_address"]) or entry["mode"] not in NODE_ASSIGNMENT_MODES
             for entry in value)
      or len({entry["node_address"] for entry in value}) != len(value)):
    raise DraftInvalid()
  return sorted(({"node_address": entry["node_address"], "mode": entry["mode"]} for entry in value),
                key=lambda entry: entry["node_address"])


def normalize_legal(value, current):
  """A partial change: only the keys sent are replaced."""
  if not isinstance(value, dict) or any(key not in LEGAL_ALL_FIELDS for key in value):
    raise DraftInvalid()
  return {**current, **{key: _text(text, _LEGAL_MAX) for key, text in value.items()}}


def normalize_snapshot(value):
  """The baseline a pack was generated from: one JSON object, at most 64 KB, hashed as sent."""
  if (not isinstance(value, str) or not value or len(value) > SNAPSHOT_MAX_BYTES
      or len(value.encode("utf-8")) > SNAPSHOT_MAX_BYTES):
    raise DraftInvalid()
  try:
    parsed = json.loads(value)
  except (ValueError, RecursionError):
    raise DraftInvalid() from None
  if not isinstance(parsed, dict):
    raise DraftInvalid()
  return value


def normalize_generated_at(value):
  """An ISO-8601 UTC instant (`Z` or `+00:00`), stored as sent."""
  if not isinstance(value, str) or not _INSTANT.match(value):
    raise DraftInvalid()
  try:
    datetime.fromisoformat(value.replace("Z", "+00:00"))
  except ValueError:
    raise DraftInvalid() from None
  return value


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


def valid_generated(value):
  """The `generated` block: the stored ref of the unsigned pack plus its baseline stamps, or null."""
  return (value is None
          or (isinstance(value, dict) and set(value) == {*DOC_REF_KEYS, *_GENERATED_FIELDS}
              and valid_doc_ref({key: value[key] for key in DOC_REF_KEYS})
              and value["mime"] == "application/pdf" and valid_digest(value["snapshot_sha256"])
              and all(_nonempty_text(value[key]) for key in ("generated_at", "generated_by"))))


def new_draft(draft_id, display_name, compliance_types, actor_id, now):
  return {
    "draft_id": draft_id, "display_name": normalize_display_name(display_name), "domain_id": "",
    "initial_admin_id": "", "legal": {key: "" for key in LEGAL_ALL_FIELDS},
    "compliance_types": normalize_compliance_types(compliance_types),
    "items": {kind: {"state": "missing", "document": None,
                     "covers": list(TENANT_RECORDS) if _OWN_RECORD[kind] is None else [_OWN_RECORD[kind]],
                     "effective_from": None, "effective_until": None, "generated": None} for kind in DOCUMENT_KINDS},
    "applicability": {record: {"decision": "required", "reason": None} for record in TENANT_RECORDS},
    "nodes": [], "activation": None, "last_release": None,
    "created_by": actor_id, "created_at": now, "updated_by": actor_id, "updated_at": now,
  }


def apply_changes(row, changes):
  """The row with `changes` applied (`update_tenant_draft`), and the `(slot, ref)` files it drops.

  Formats are checked, emptiness is allowed. An update may set an item `missing` (its file goes) or
  `awaiting_signature` (only without a file); `signed` is set by an upload alone and `generated` by
  `store_generated_document` alone. Neither transition touches `generated`: the unsigned pack and
  its baseline outlive a dropped signed copy. `covers` and `applicability` are not change keys: the
  pack fixes them.
  """
  if not isinstance(changes, dict):
    raise DraftInvalid()
  allowed = {"display_name", "domain_id", "initial_admin_id", "legal", "compliance_types", "items", "nodes"}
  if any(key not in allowed for key in changes):
    raise DraftInvalid()
  row = {**row, "legal": dict(row["legal"]), "items": {kind: dict(item) for kind, item in row["items"].items()}}
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
  if "nodes" in changes:
    row["nodes"] = normalize_nodes(changes["nodes"])
  if "items" in changes:
    items = changes["items"]
    if not isinstance(items, dict) or any(kind not in DOCUMENT_KINDS for kind in items):
      raise DraftInvalid()
    for kind, change in items.items():
      if not isinstance(change, dict) or any(key not in _ITEM_CHANGES for key in change):
        raise DraftInvalid()
      item = row["items"][kind]
      for key in ("effective_from", "effective_until"):
        if key in change:
          item[key] = _effective_date(change[key])
      if "state" in change:
        state = change["state"]
        if state == "missing":
          if item["document"] is not None:
            dropped.append((kind, item["document"]["ref"]))
          item.update(state="missing", document=None)
        elif state == "awaiting_signature" and item["document"] is None:
          item["state"] = "awaiting_signature"
        else:
          raise DraftInvalid()
  return row, dropped


def document_refs(row):
  """Every file the draft names: the signed copies and the generated packs."""
  return [block["ref"] for item in row["items"].values() for block in (item["document"], item["generated"])
          if block is not None]


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
  """The activation rule, one `missing` entry per gap. Engagement-level records never block. RM-112:
  the initial admin is optional (a tenant may be activated without one)."""
  missing = []
  if not row["display_name"]:
    missing.append("field:display_name")
  if not row["domain_id"]:
    missing.append("field:domain_id")
  missing.extend(f"field:legal.{key}" for key in LEGAL_FIELDS if not row["legal"][key])
  if not row["compliance_types"]:
    missing.append("field:compliance_types")
  if row["items"]["contract"]["state"] != "signed":
    missing.append("item:contract")
  for record in TENANT_RECORDS:
    # Rule 3 (owner, 2026-10-07): a record in the contract's fixed covers is decided by rule 2, and no
    # applicability is asked. A record dropped from those covers must be covered by a signed item.
    if record not in row["items"]["contract"]["covers"] and not _covered(row, record):
      missing.append(f"record:{record}")
  return {"complete": not missing, "missing": missing}


def governance(row):
  """What activation copies onto the receipt and the tenant: per record the signed item that covers
  it (its own item first), the applicability decisions, and the signed items' effective dates."""
  signed = [kind for kind in DOCUMENT_KINDS if row["items"][kind]["state"] == "signed"]
  coverage = {}
  for record in RECORDS:
    covering = [kind for kind in signed if record in row["items"][kind]["covers"]]
    if covering:
      coverage[record] = record if record in covering else covering[0]
  return {"coverage": coverage,
          "applicability": {record: dict(row["applicability"][record]) for record in TENANT_RECORDS},
          "effective": {kind: {key: row["items"][kind][key] for key in ("effective_from", "effective_until")}
                        for kind in signed}}


def valid_governance(value):
  """The stored shape `governance` writes; values from the vocabulary."""
  return (isinstance(value, dict) and set(value) == {"coverage", "applicability", "effective"}
          and isinstance(value["coverage"], dict)
          and all(record in RECORDS and kind in DOCUMENT_KINDS for record, kind in value["coverage"].items())
          and isinstance(value["applicability"], dict) and set(value["applicability"]) == set(TENANT_RECORDS)
          and all(_same(normalize_applicability, value["applicability"][record]) for record in TENANT_RECORDS)
          and isinstance(value["effective"], dict)
          and all(kind in DOCUMENT_KINDS and isinstance(dates, dict)
                  and set(dates) == {"effective_from", "effective_until"}
                  and all(_same(_effective_date, dates[key]) for key in dates)
                  for kind, dates in value["effective"].items()))


def draft_dto(row):
  dto = {key: row[key] for key in DTO_FIELDS}
  dto["items"] = {kind: {**{key: row["items"][kind][key] for key in _ITEM_FIELDS}, "basis": BASIS[kind],
                         "covered_by": _covered_by(row, kind)} for kind in DOCUMENT_KINDS}
  dto["completeness"] = completeness(row)
  return dto


def draft_list_row(row):
  """`items_total` counts the shown items, `items_done` those of them that are signed."""
  done = sum(1 for kind in SHOWN_KINDS if row["items"][kind]["state"] == "signed")
  return {"draft_id": row["draft_id"], "display_name": row["display_name"],
          "compliance_types": row["compliance_types"], "created_at": row["created_at"],
          "updated_at": row["updated_at"], "items_done": done, "items_total": len(SHOWN_KINDS),
          "nodes": row["nodes"], "activation": row["activation"]}


def nonempty_text(value):
  return isinstance(value, str) and bool(value)


_nonempty_text = nonempty_text


def _valid_stamp(value, keys, optional=()):
  return (isinstance(value, dict) and set(value) == set(keys)
          and all(_nonempty_text(value[key]) or (key in optional and value[key] is None) for key in keys))


def _same(normalize, value):
  try:
    return normalize(value) == value
  except DraftInvalid:
    return False


def validate_tenant_draft(row, ids):
  """Refuse a stored draft the operations could not have written. Unknown fields are kept. Answers the
  row as the operations read it: an item written before the `generated` slot existed (RM-109 phases
  2-3) gains `generated: None`, and a `legal` block written before the RM-110 party fields gains them
  empty, on a copy, so the stored value itself is never changed by a read. RM-112: a row written
  before the node plan existed gains `nodes: []` the same way."""
  if "nodes" not in row:
    row = {**row, "nodes": []}
  if isinstance(row.get("items"), dict):
    row = {**row, "items": {kind: {"generated": None, **item} if isinstance(item, dict) else item
                            for kind, item in row["items"].items()}}
  if isinstance(row.get("legal"), dict) and set(row["legal"]) >= set(LEGAL_FIELDS):
    row = {**row, "legal": {**{key: "" for key in LEGAL_OPTIONAL_FIELDS}, **row["legal"]}}
  items, applicability, legal = row.get("items"), row.get("applicability"), row.get("legal")
  if (len(ids) != 1 or row.get("draft_id") != ids[0] or not valid_draft_id(ids[0])
      or not _same(normalize_display_name, row.get("display_name"))
      or not _same(normalize_domain, row.get("domain_id"))
      or not _same(normalize_initial_admin, row.get("initial_admin_id"))
      or not isinstance(legal, dict) or set(legal) != set(LEGAL_ALL_FIELDS)
      or not all(_same(lambda text: _text(text, _LEGAL_MAX), legal[key]) for key in LEGAL_ALL_FIELDS)
      or not _same(normalize_compliance_types, row.get("compliance_types"))
      or not isinstance(items, dict) or set(items) != set(DOCUMENT_KINDS)
      or not isinstance(applicability, dict) or set(applicability) != set(TENANT_RECORDS)
      or not all(_same(normalize_applicability, applicability[record]) for record in TENANT_RECORDS)
      or not _same(normalize_nodes, row["nodes"])
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
        or (item["state"] == "generated" and item["generated"] is None)
        or (item["document"] is not None and (not valid_doc_ref(item["document"])
                                              or item["document"]["mime"] != "application/pdf"))
        or not _same(lambda covers: normalize_covers(kind, covers), item["covers"])
        or not _same(_effective_date, item["effective_from"])
        or not _same(_effective_date, item["effective_until"])
        or not valid_generated(item["generated"])):
      raise ValueError("Invalid tenant draft item")
  return row
