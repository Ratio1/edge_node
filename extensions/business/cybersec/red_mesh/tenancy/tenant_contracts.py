"""RM-133 step 2: several contracts per tenant.

The first contract stays in the tenant row's `contract` and `contract_generated` fields and is
addressed as `c_1`; every further contract is prepared as a `tenant_contract_draft` row on the
active tenant (`ids = [tenant_id, contract_id]`), goes through the states the tenant draft's
`contract` item knows, and lands in the tenant row's `contracts` map on activation. Vocabulary,
formats, the stored-record validators, the completeness rule and the DTOs; no storage I/O
(contract: `onboarding-drafts.md` §Several contracts per tenant). The two lineage keys
(`supersedes`, `superseded_by`) are defined here and written `null` until step 3.
"""
import re

from .drafts import (DOC_REF_KEYS, ITEM_STATES, _UUID, _effective_date, _nonempty_text, _same, normalize_nodes,
                     valid_generated)
from .engagements import valid_doc_ref

FIRST_CONTRACT_ID = "c_1"
FIRST_CONTRACT_NO = 2
_CONTRACT_ID = re.compile(r"c_[1-9][0-9]*\Z")
# The state, the signed copy and the generated block: the tenant draft's `contract` item, on the row itself.
FIELDS = ("tenant_id", "contract_id", "request_id", "state", "document", "generated", "effective_from",
          "effective_until", "nodes", "supersedes", "created_by", "created_at", "updated_by", "updated_at")
_CHANGES = ("state", "effective_from", "effective_until", "nodes")
# The `contracts[c_<n>]` block an activation writes on the tenant row.
BLOCK_FIELDS = ("contract", "contract_generated", "effective_from", "effective_until", "nodes", "activated_by",
                "activated_at", "supersedes", "superseded_by")


class TenantContractInvalid(Exception):
  def __init__(self, code="invalid_request"):
    super().__init__(code)
    self.code = code


def valid_contract_id(value):
  return isinstance(value, str) and _CONTRACT_ID.match(value) is not None


def contract_id_for(number):
  return "c_%d" % number


def contract_no(contract_id):
  return int(contract_id[2:])


def valid_request_id(value):
  return isinstance(value, str) and _UUID.match(value) is not None


def new_draft(tenant_id, contract_id, request_id, actor_id, now):
  return {
    "tenant_id": tenant_id, "contract_id": contract_id, "request_id": request_id,
    "state": "missing", "document": None, "generated": None,
    "effective_from": None, "effective_until": None, "nodes": [], "supersedes": None,
    "created_by": actor_id, "created_at": now, "updated_by": actor_id, "updated_at": now,
  }


def apply_changes(row, changes):
  """The row with `changes` applied (`update_tenant_contract_draft`) and the refs of the files it
  drops. The transitions are the tenant draft item's: `missing` drops the signed file (and keeps
  `generated`), `awaiting_signature` only without a file; `signed` is set by an upload alone and
  `generated` by `store_generated_document` alone."""
  if not isinstance(changes, dict) or any(key not in _CHANGES for key in changes):
    raise TenantContractInvalid()
  row = dict(row)
  dropped = []
  for key in ("effective_from", "effective_until"):
    if key in changes:
      row[key] = _effective_date(changes[key])
  if "nodes" in changes:
    row["nodes"] = normalize_nodes(changes["nodes"])
  if "state" in changes:
    state = changes["state"]
    if state == "missing":
      if row["document"] is not None:
        dropped.append(row["document"]["ref"])
      row.update(state="missing", document=None)
    elif state == "awaiting_signature" and row["document"] is None:
      row["state"] = "awaiting_signature"
    else:
      raise TenantContractInvalid()
  return row, dropped


def document_refs(row):
  """The signed copy and the generated pack, whichever exist."""
  return [block["ref"] for block in (row["document"], row["generated"]) if block is not None]


def contract_stale(row):
  """As `drafts.contract_stale`: the generated pack printed other nodes, or a signed copy has no
  generated pack behind it."""
  if row["generated"] is None:
    return row["state"] == "signed"
  return row["generated"].get("nodes") != row["nodes"]


def completeness(row):
  """The activation rule, one `missing` entry per gap: the term's start date, the node plan, the
  signed copy, and a generated pack that printed the plan."""
  missing = []
  if not row["effective_from"]:
    missing.append("field:effective_from")
  if not row["nodes"]:
    missing.append("field:nodes")
  if row["state"] != "signed":
    missing.append("item:contract")
  if contract_stale(row):
    missing.append("item:contract_stale")
  return {"complete": not missing, "missing": missing}


def draft_dto(row):
  return {**{key: row[key] for key in FIELDS}, "completeness": completeness(row)}


def draft_list_row(row):
  return {"contract_id": row["contract_id"], "state": row["state"], "effective_from": row["effective_from"],
          "effective_until": row["effective_until"], "nodes_count": len(row["nodes"]),
          "supersedes": row["supersedes"], "created_at": row["created_at"], "updated_at": row["updated_at"]}


def validate_tenant_contract_draft(row, ids):
  """Refuse a stored contract draft the operations could not have written. Strict key set: the
  lineage keys are part of it from the first row, so step 3 adds no compatibility branch."""
  if (len(ids) != 2 or not isinstance(row, dict) or set(row) - {"schemaVersion", "namespace", "kind", "ids"} != set(FIELDS)
      or row["tenant_id"] != ids[0] or row["contract_id"] != ids[1]
      or not valid_contract_id(ids[1]) or ids[1] == FIRST_CONTRACT_ID
      or not valid_request_id(row["request_id"])
      or row["state"] not in ITEM_STATES
      or (row["state"] == "signed") != (row["document"] is not None)
      or (row["state"] == "generated" and row["generated"] is None)
      or (row["document"] is not None and (not valid_doc_ref(row["document"])
                                           or row["document"]["mime"] != "application/pdf"))
      or not valid_generated(row["generated"], with_nodes=True)
      or not _same(_effective_date, row["effective_from"]) or not _same(_effective_date, row["effective_until"])
      or not _same(normalize_nodes, row["nodes"])
      or not (row["supersedes"] is None or (valid_contract_id(row["supersedes"]) and row["supersedes"] != ids[1]))
      or not all(_nonempty_text(row[key]) for key in ("created_by", "created_at", "updated_by", "updated_at"))):
    raise ValueError("Invalid tenant contract draft record")
  return row


def valid_block(contract_id, value, valid_contract):
  """A `contracts[c_<n>]` block on the tenant row, as `activate_tenant_contract` writes it.
  `valid_contract` is the administration's stored-ref check."""
  return (valid_contract_id(contract_id) and contract_id != FIRST_CONTRACT_ID
          and isinstance(value, dict) and set(value) == set(BLOCK_FIELDS)
          and valid_contract(value["contract"])
          and (value["contract_generated"] is None or valid_generated(value["contract_generated"], with_nodes=True))
          and _same(_effective_date, value["effective_from"]) and _same(_effective_date, value["effective_until"])
          and _same(normalize_nodes, value["nodes"]) and bool(value["nodes"])
          and all(_nonempty_text(value[key]) for key in ("activated_by", "activated_at"))
          and all(value[key] is None or (valid_contract_id(value[key]) and value[key] != contract_id)
                  for key in ("supersedes", "superseded_by")))


def block_for(row, signed, generated, actor_id, now):
  """The tenant-row block of an activated contract draft."""
  return {"contract": dict(signed), "contract_generated": None if generated is None else dict(generated),
          "effective_from": row["effective_from"], "effective_until": row["effective_until"],
          "nodes": list(row["nodes"]), "activated_by": actor_id, "activated_at": now,
          "supersedes": row["supersedes"], "superseded_by": None}


def contract_entry(contract_id, contract, generated, effective, nodes, supersedes, superseded_by):
  """One entry of the member-visible `contracts` list: hashes and dates, never a file name or ref."""
  return {"contractId": contract_id, "state": "active", "sha256": contract["sha256"],
          "effectiveFrom": effective.get("effective_from"), "effectiveUntil": effective.get("effective_until"),
          "nodes": [{"nodeAddress": entry["node_address"], "mode": entry["mode"]} for entry in nodes],
          "generatedSha256": None if generated is None else generated["sha256"],
          "supersedes": supersedes, "supersededBy": superseded_by}


def sorted_ids(contract_ids):
  return sorted(contract_ids, key=contract_no)
