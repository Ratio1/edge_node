"""RM-095 phase 1: the signed commercial contract a tenant is created around.

Storage I/O happens here, outside the administration lock: a contract can be tens of megabytes,
and `prepare_tenant` holds a process-wide lock. The administration service only ever sees the
resulting document reference.
"""
from datetime import datetime, timezone

from ..tenancy.ports import DocumentStoreError
from .authorization_upload import AuthorizationUploadError, validate_document

CONTRACT_KIND = "redmesh_tenant_contract"
CONTRACT_FORMATS = ("application/pdf",)
_REF_FIELDS = ("sha256", "filename", "mime", "size_bytes", "uploaded_at", "uploaded_by")


class ContractRefused(Exception):
  def __init__(self, status_code, error):
    self.status_code = status_code
    self.error = error


def contract_result(operation):
  """The administration response shape (`tenancy.administration._endpoint`) for contract calls."""
  try:
    return {"success": True, "status_code": 200, "data": operation()}
  except ContractRefused as exc:
    return {"success": False, "status": "error", "status_code": exc.status_code, "error": exc.error}
  except DocumentStoreError:
    return {"success": False, "status": "error", "status_code": 503, "error": "unavailable"}


def store_contract(documents, *, filename, content_b64, uploaded_by, now_fn=None):
  """Validate one contract (PDF only) and store it; return its document reference."""
  return _store(documents, filename, content_b64, uploaded_by, now_fn, refusal=None,
                envelope_fields={"schema_version": "1.0"})


def store_draft_document(documents, *, draft_id, document_kind, filename, content_b64, uploaded_by,
                         now_fn=None):
  """RM-109. One signed tenant-draft document, checked as a contract; return its document reference.

  The envelope is the contract's at `schema_version` 1.1, naming the draft and the slot; the
  reference keeps the contract's key set (the slot it sits in names its kind). Any failed check is
  `contract_invalid` for the contract slot and `document_invalid` for the other two.
  """
  return _store(documents, filename, content_b64, uploaded_by, now_fn,
                refusal="contract_invalid" if document_kind == "contract" else "document_invalid",
                envelope_fields={"schema_version": "1.1", "document_kind": document_kind, "draft_id": draft_id})


def store_engagement_pack(documents, *, engagement_draft_id, filename, content_b64, uploaded_by, now_fn=None):
  """RM-109 phase 4. The signed engagement pack of an engagement draft, checked as a contract. The
  envelope is the 1.1 draft envelope naming the engagement draft and the `engagement_pack` slot; no
  tenant draft or tenant is named, since none may exist yet. Any failed check is `document_invalid`."""
  return _store(documents, filename, content_b64, uploaded_by, now_fn, refusal="document_invalid",
                envelope_fields={"schema_version": "1.1", "document_kind": "engagement_pack",
                                 "engagement_draft_id": engagement_draft_id})


def _store(documents, filename, content_b64, uploaded_by, now_fn, *, refusal, envelope_fields):
  try:
    document = validate_document(filename, content_b64, accepted=CONTRACT_FORMATS)
  except AuthorizationUploadError as exc:
    raise ContractRefused(400, refusal or exc.code) from None
  uploaded_at = (now_fn or (lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")))()
  envelope = {
    "kind": CONTRACT_KIND, **envelope_fields, "filename": document.filename,
    "mime": document.mime, "size_bytes": document.size_bytes, "sha256": document.sha256_hex,
    "uploaded_at": uploaded_at, "uploaded_by": uploaded_by,
    "content_b64": content_b64 if isinstance(content_b64, str) else "",
  }
  ref = documents.put(envelope)
  return {"store": documents.name, "ref": ref, **{key: envelope[key] for key in _REF_FIELDS}}


def resolve_contract(documents, ref):
  """The document reference for a stored contract, re-verified from its bytes (one-step path).

  Unreadable, foreign-kind, non-PDF and tampered envelopes are all `contract_invalid`: the caller
  learns nothing about which one it was. RM-109: so is a tenant-draft upload (an envelope naming a
  draft, or a slot other than the contract); a draft's documents are bound through its draft.
  """
  if not isinstance(ref, str) or not ref.strip():
    raise ContractRefused(400, "contract_required")
  document, binding = _resolve(documents, ref, "contract_invalid")
  if binding != {"draft_id": None, "engagement_draft_id": None, "document_kind": "contract"}:
    raise ContractRefused(400, "contract_invalid")
  return document


def resolve_draft_document(documents, ref, *, draft_id, document_kind):
  """RM-109. One tenant-draft document re-verified from its bytes, as `resolve_contract`; its
  envelope must name this draft and this slot. Refused `contract_invalid` for the contract slot,
  `document_invalid` for the other two."""
  refusal = "contract_invalid" if document_kind == "contract" else "document_invalid"
  if not isinstance(ref, str) or not ref.strip():
    raise ContractRefused(400, refusal)
  document, binding = _resolve(documents, ref, refusal)
  if binding != {"draft_id": draft_id, "engagement_draft_id": None, "document_kind": document_kind}:
    raise ContractRefused(400, refusal)
  return document


def resolve_engagement_pack(documents, ref, *, engagement_draft_id):
  """RM-109 phase 4. An engagement draft's pack (the signed copy or the generated one) re-verified
  from its bytes; its envelope must name this engagement draft and the `engagement_pack` slot.
  Every refusal is `document_invalid`."""
  if not isinstance(ref, str) or not ref.strip():
    raise ContractRefused(400, "document_invalid")
  document, binding = _resolve(documents, ref, "document_invalid")
  if binding != {"draft_id": None, "engagement_draft_id": engagement_draft_id, "document_kind": "engagement_pack"}:
    raise ContractRefused(400, "document_invalid")
  return document


def _resolve(documents, ref, refusal):
  """The verified reference and the envelope's draft binding; an absent `document_kind` (a
  schema 1.0 envelope) reads as `contract`."""
  envelope = documents.get(ref)
  if not isinstance(envelope, dict) or envelope.get("kind") != CONTRACT_KIND:
    raise ContractRefused(400, refusal)
  try:
    document = validate_document(envelope.get("filename"), envelope.get("content_b64"), accepted=CONTRACT_FORMATS)
  except AuthorizationUploadError:
    raise ContractRefused(400, refusal) from None
  if (document.sha256_hex != envelope.get("sha256") or document.size_bytes != envelope.get("size_bytes")
      or document.filename != envelope.get("filename") or document.mime != envelope.get("mime")
      or any(not isinstance(envelope.get(key), str) or not envelope[key] for key in ("uploaded_at", "uploaded_by"))):
    raise ContractRefused(400, refusal)
  binding = {"draft_id": envelope.get("draft_id"), "engagement_draft_id": envelope.get("engagement_draft_id"),
             "document_kind": envelope.get("document_kind", "contract")}
  return {"store": documents.name, "ref": ref, **{key: envelope[key] for key in _REF_FIELDS}}, binding


def read_contract(documents, contract, absent=None):
  """The stored contract file, served only if it still matches the tenant record.

  The tenant record is the authority: the file's bytes are hashed and sized here and compared with
  the record, never with the envelope's own claims. Anything else is 409 `contract_integrity`.
  `absent` (status, error) answers a file the store does not return (RM-109 draft downloads: 404).
  """
  if contract.get("store") != documents.name:
    raise ContractRefused(503, "unavailable")
  envelope = documents.get(contract["ref"])
  if envelope is None and absent is not None:
    raise ContractRefused(*absent)
  if not isinstance(envelope, dict) or envelope.get("kind") != CONTRACT_KIND:
    raise ContractRefused(409, "contract_integrity")
  try:
    document = validate_document(contract["filename"], envelope.get("content_b64"), accepted=CONTRACT_FORMATS)
  except AuthorizationUploadError:
    raise ContractRefused(409, "contract_integrity") from None
  if document.sha256_hex != contract["sha256"] or document.size_bytes != contract["size_bytes"]:
    raise ContractRefused(409, "contract_integrity")
  return {"filename": contract["filename"], "mime": document.mime, "size_bytes": document.size_bytes,
          "sha256": document.sha256_hex, "content_b64": envelope["content_b64"]}
