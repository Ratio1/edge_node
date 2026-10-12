"""RM-109 phase 4: the engagement draft, an engagement prepared before its pack is signed.

It lives inside a tenant draft (`parent: {draft_id}`) so the whole pack is prepared before the client
signs anything, and is re-homed to the tenant (`parent: {tenant_id}`) when that draft is activated;
it may also be created inside an active tenant. Vocabulary, formats, the stored-record validator, the
completeness rule and the DTO; no storage I/O (contract: `onboarding-drafts.md` §Engagement draft).
Its id (`ted_<uuid>`) is never a tenant or an engagement id; activation creates engagement
`en_<uuid>` with the same uuid, which is what makes a replay recognizable.
"""
from .assets import normalize_name
from .drafts import ITEM_STATES, _UUID, _nonempty_text, valid_draft_id, valid_generated
from .engagements import (EngagementInvalid, MAX_ENGAGEMENT_ASSETS, _asset_entry_valid, normalize_context,
                          normalize_engagement_assets, normalize_instant, normalize_window,
                          valid_doc_ref)
from .tenant_contracts import valid_contract_id

# The `create_engagement` argument set, in the order `missing[]` reports them.
FIELDS = ("display_name", "valid_from", "valid_until", "context", "assets")
# The pack slot's `document_kind` in the upload envelope; the engagement pack is one PDF.
DOCUMENT_KIND = "engagement_pack"
DTO_FIELDS = ("engagement_draft_id", "parent", *FIELDS, "document", "created_by", "created_at",
              "updated_by", "updated_at")
# RM-133: the contract the engagement binds to at activation (`c_<n>`), or None for `c_1`; a row
# written before the key existed reads as None.
CONTRACT_PICK = "contract_id"



class EngagementDraftInvalid(Exception):
  def __init__(self, code="invalid_request"):
    super().__init__(code)
    self.code = code


def engagement_draft_id_for(request_id):
  return "ted_" + request_id


def valid_engagement_draft_id(value):
  return isinstance(value, str) and value.startswith("ted_") and _UUID.match(value[4:]) is not None


def valid_tenant_id(value):
  return isinstance(value, str) and value.startswith("tn_") and _UUID.match(value[3:]) is not None


def valid_parent(value):
  return (isinstance(value, dict) and len(value) == 1
          and (("draft_id" in value and valid_draft_id(value["draft_id"]))
               or ("tenant_id" in value and valid_tenant_id(value["tenant_id"]))))


def _refused(normalize, value, code):
  """`normalize(value)`, every refusal as `EngagementDraftInvalid(code)` (a normalizer's own code wins)."""
  try:
    return normalize(value)
  except EngagementInvalid as exc:
    raise EngagementDraftInvalid(exc.code) from None
  except (ValueError, TypeError):
    raise EngagementDraftInvalid(code) from None


def _display_name(value):
  if value == "":
    return ""
  return _refused(normalize_name, value, "invalid_request")


def _instant(value):
  if value == "":
    return ""
  return _refused(normalize_instant, value, "window_invalid")


def _assets(value):
  # RM-125: the administration resolved the public `{asset_id}` entries into
  # stored entries (asset copy included) before this runs.
  if value == []:
    return []
  return _refused(normalize_engagement_assets, value, "engagement_asset_invalid")


# Per field: the write-time normalizer (emptiness allowed) and the empty value a new draft starts with.
_NORMALIZE = {"display_name": _display_name, "valid_from": _instant, "valid_until": _instant,
              "context": lambda value: _refused(normalize_context, value, "context_invalid"), "assets": _assets}
_EMPTY = {"display_name": "", "valid_from": "", "valid_until": "", "context": None, "assets": []}


def _check_window(row):
  """Both instants set: the window must be ordered, as `create_engagement` requires."""
  if row["valid_from"] and row["valid_until"]:
    _refused(lambda _: normalize_window(row["valid_from"], row["valid_until"]), None, "window_invalid")


def new_draft(engagement_draft_id, parent, display_name, actor_id, now):
  return {
    "engagement_draft_id": engagement_draft_id, "parent": dict(parent),
    **{field: _NORMALIZE[field](_EMPTY[field]) for field in FIELDS},
    "display_name": _display_name(display_name),
    "document": {"state": "missing", "document": None, "generated": None}, CONTRACT_PICK: None,
    "created_by": actor_id, "created_at": now, "updated_by": actor_id, "updated_at": now,
  }


def contract_pick(row):
  return row.get(CONTRACT_PICK)


def _contract_pick(value):
  """RM-133: `c_<n>` or empty (None, `""`) for `c_1`; the format only, the administration checks
  that the tenant holds it (`contract_unknown`)."""
  if value is None or value == "":
    return None
  if not valid_contract_id(value):
    raise EngagementDraftInvalid("contract_unknown")
  return value


def apply_changes(row, changes):
  """The row with `changes` applied (`update_engagement_draft`), and the refs of the files it drops.

  Every field is checked with the engagement normalizers, emptiness allowed; the refusal is the
  normalizer's code. `document.state` moves as a tenant item: `missing` drops the signed file (and
  keeps `generated`), `awaiting_signature` only without a file; `signed` is set by an upload alone
  and `generated` by `store_generated_document` alone.
  """
  if not isinstance(changes, dict) or any(key not in (*FIELDS, "document", CONTRACT_PICK) for key in changes):
    raise EngagementDraftInvalid()
  row = {**row, "document": dict(row["document"])}
  dropped = []
  for field in FIELDS:
    if field in changes:
      row[field] = _NORMALIZE[field](changes[field])
  if CONTRACT_PICK in changes:
    row[CONTRACT_PICK] = _contract_pick(changes[CONTRACT_PICK])
  _check_window(row)
  if "document" in changes:
    change = changes["document"]
    if not isinstance(change, dict) or set(change) != {"state"}:
      raise EngagementDraftInvalid()
    slot, state = row["document"], change["state"]
    if state == "missing":
      if slot["document"] is not None:
        dropped.append(slot["document"]["ref"])
      slot.update(state="missing", document=None)
    elif state == "awaiting_signature" and slot["document"] is None:
      slot["state"] = "awaiting_signature"
    else:
      raise EngagementDraftInvalid()
  return row, dropped


def document_refs(row):
  """The signed and the generated file, whichever exist."""
  return [block["ref"] for block in (row["document"]["document"], row["document"]["generated"]) if block is not None]


def asset_requests(assets):
  """The stored entries as the public `create_engagement` request form (RM-125 phase 2b)."""
  return [{"asset_id": entry["asset_id"]} for entry in assets]


def completeness(row):
  """The activation rule: every creation field passes the full `create_engagement` validation (the
  normalizer's code as the reason), and the pack is signed. One `missing` entry per gap."""
  missing, reasons = [], {}

  def gap(field, code):
    missing.append(f"field:{field}")
    reasons[field] = code

  try:
    normalize_name(row["display_name"])
  except (ValueError, TypeError):
    gap("display_name", "invalid_request")
  for field in ("valid_from", "valid_until"):
    if not row[field]:
      gap(field, "window_invalid")
  if row["valid_from"] and row["valid_until"]:
    try:
      normalize_window(row["valid_from"], row["valid_until"])
    except EngagementInvalid as exc:
      gap("valid_until", exc.code)
  try:
    normalize_context(row["context"])
  except EngagementInvalid as exc:
    gap("context", exc.code)
  try:
    normalize_engagement_assets(row["assets"])
  except EngagementInvalid as exc:
    gap("assets", exc.code)
  if row["document"]["state"] != "signed":
    missing.append(f"item:{DOCUMENT_KIND}")
  return {"complete": not missing, "missing": missing, "reasons": reasons}


def draft_dto(row):
  return {**{key: row[key] for key in DTO_FIELDS}, CONTRACT_PICK: contract_pick(row), "completeness": completeness(row)}


def draft_list_row(row):
  return {"engagement_draft_id": row["engagement_draft_id"], "parent": row["parent"],
          "display_name": row["display_name"], "assets_count": len(row["assets"]),
          "document_state": row["document"]["state"], "created_at": row["created_at"],
          "updated_at": row["updated_at"]}


def _same(normalize, value):
  try:
    return normalize(value) == value
  except EngagementDraftInvalid:
    return False


def _stored_assets_valid(assets):
  # Shape only for the entries, as `validate_engagement` does: a catalog change must not make a
  # draft unreadable; activation re-normalizes them in full.
  return (isinstance(assets, list) and len(assets) <= MAX_ENGAGEMENT_ASSETS
          and all(_asset_entry_valid(index, entry) for index, entry in enumerate(assets))
          and len({entry["target_digest"] for entry in assets}) == len(assets)
          and len({entry["asset_id"] for entry in assets}) == len(assets))


def validate_engagement_draft(row, ids):
  """Refuse a stored engagement draft the operations could not have written. Unknown fields are kept."""
  slot = row.get("document")
  if (len(ids) != 1 or row.get("engagement_draft_id") != ids[0] or not valid_engagement_draft_id(ids[0])
      or not valid_parent(row.get("parent"))
      or not _same(_display_name, row.get("display_name"))
      or not _same(_instant, row.get("valid_from")) or not _same(_instant, row.get("valid_until"))
      # Shape only for the context: `EngagementContext` may gain fields.
      or not isinstance(row.get("context"), dict)
      or not _stored_assets_valid(row.get("assets"))
      or not isinstance(slot, dict) or set(slot) != {"state", "document", "generated"}
      or slot["state"] not in ITEM_STATES
      or (slot["state"] == "signed") != (slot["document"] is not None)
      or (slot["state"] == "generated" and slot["generated"] is None)
      or (slot["document"] is not None and (not valid_doc_ref(slot["document"])
                                            or slot["document"]["mime"] != "application/pdf"))
      or not valid_generated(slot["generated"])
      or not (contract_pick(row) is None or valid_contract_id(contract_pick(row)))
      or not all(_nonempty_text(row.get(key)) for key in ("created_by", "created_at", "updated_by", "updated_at"))):
    raise ValueError("Invalid engagement draft record")
  try:
    _check_window(row)
  except EngagementDraftInvalid:
    raise ValueError("Invalid engagement draft window") from None
  return row
