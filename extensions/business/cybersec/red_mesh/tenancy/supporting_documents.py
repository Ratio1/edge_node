"""RM-261: supporting documents, files attached to an engagement, a contract or a contract draft after
its record was signed. One store row each, kind `supporting_document`, keyed
`(tenant_id, owner_id, sd_<uuid>)`; outside every hash, so no signed record changes. No storage I/O
(contract: `engagement-documents.md` §Supporting documents).

The row's own document kind is `document_kind`: `kind` is the store envelope's. A withdrawn row stays
listed and downloadable; nothing deletes one but the deletion of its tenant or of its contract draft.
"""
from .assets import normalize_name
from .drafts import _UUID, _nonempty_text
from .engagement_drafts import CARRIED_KINDS, valid_tenant_id
from .engagements import valid_doc_ref, valid_engagement_id
from .tenant_contracts import valid_contract_id

KIND = "supporting_document"
MAX_PER_OWNER = 20
_REF_KEYS = ("store", "ref", "filename", "mime", "size_bytes", "sha256", "uploaded_at", "uploaded_by")
_LABELS = ("title", "comment")


def document_id_for(request_id):
  return "sd_" + request_id


def valid_document_id(value):
  return isinstance(value, str) and value.startswith("sd_") and _UUID.match(value[3:]) is not None


def valid_owner_id(value):
  return valid_engagement_id(value) or valid_contract_id(value)


def new_row(tenant_id, owner_id, document_id, document):
  """`document` is a stored reference with its labels (`store_engagement_document` plus the store name)."""
  if document.get("kind") not in CARRIED_KINDS:
    raise ValueError("Invalid supporting document kind")
  return {"tenant_id": tenant_id, "owner_id": owner_id, "document_id": document_id,
          "document_kind": document["kind"], **{key: document[key] for key in (*_LABELS, *_REF_KEYS)},
          "withdrawn": None}


def withdraw(row, reason, actor_id, now):
  """The row withdrawn: the reason (a bounded text), who and when."""
  return {**row, "withdrawn": {"reason": normalize_name(reason, 500), "by": actor_id, "at": now}}


def doc_ref(row):
  """The stored reference as `read_engagement_document` and the engagement documents take it."""
  return {**{key: row[key] for key in (*_LABELS, *_REF_KEYS)}, "kind": row["document_kind"]}


def validate_supporting_document(row, ids):
  """Refuse a stored row the operations could not have written. Unknown fields are kept."""
  if (len(ids) != 3 or not valid_tenant_id(ids[0]) or not valid_owner_id(ids[1]) or not valid_document_id(ids[2])
      or (row.get("tenant_id"), row.get("owner_id"), row.get("document_id")) != tuple(ids)
      or row.get("document_kind") not in CARRIED_KINDS
      or not valid_doc_ref(doc_ref(row), labels=True, stored=True)):
    raise ValueError("Invalid supporting document record")
  withdrawn = row.get("withdrawn")
  if withdrawn is not None and (not isinstance(withdrawn, dict) or set(withdrawn) != {"reason", "by", "at"}
                                or not all(_nonempty_text(value) for value in withdrawn.values())):
    raise ValueError("Invalid supporting document withdrawal")
  return row


def dto(row, detail=False, uploader=False):
  """The row as answered, never with its store reference. A tenant member sees the id, kind, title,
  SHA-256 and time; `detail` (an engagement-documents reader) adds the file facts and the comment;
  `uploader` (the Super-Tenant Admin) adds who uploaded and who withdrew."""
  withdrawn = row["withdrawn"]
  return {
    "documentId": row["document_id"], "ownerId": row["owner_id"], "kind": row["document_kind"], "title": row["title"],
    "sha256": row["sha256"], "uploadedAt": row["uploaded_at"], "addedAfterSigning": True,
    "withdrawn": None if withdrawn is None else {
      "reason": withdrawn["reason"], "at": withdrawn["at"], **({"by": withdrawn["by"]} if uploader else {})},
    **({"comment": row["comment"], "filename": row["filename"], "mime": row["mime"], "sizeBytes": row["size_bytes"]}
       if detail else {}),
    **({"uploadedBy": row["uploaded_by"]} if uploader else {}),
  }
