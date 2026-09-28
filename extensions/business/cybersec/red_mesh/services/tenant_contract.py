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
  try:
    document = validate_document(filename, content_b64, accepted=CONTRACT_FORMATS)
  except AuthorizationUploadError as exc:
    raise ContractRefused(400, exc.code) from None
  uploaded_at = (now_fn or (lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")))()
  envelope = {
    "kind": CONTRACT_KIND, "schema_version": "1.0", "filename": document.filename,
    "mime": document.mime, "size_bytes": document.size_bytes, "sha256": document.sha256_hex,
    "uploaded_at": uploaded_at, "uploaded_by": uploaded_by,
    "content_b64": content_b64 if isinstance(content_b64, str) else "",
  }
  ref = documents.put(envelope)
  return {"store": documents.name, "ref": ref, **{key: envelope[key] for key in _REF_FIELDS}}


def resolve_contract(documents, ref):
  """The document reference for a stored contract, re-verified from its bytes.

  Unreadable, foreign-kind, non-PDF and tampered envelopes are all `contract_invalid`: the caller
  learns nothing about which one it was.
  """
  if not isinstance(ref, str) or not ref.strip():
    raise ContractRefused(400, "contract_required")
  envelope = documents.get(ref)
  if not isinstance(envelope, dict) or envelope.get("kind") != CONTRACT_KIND:
    raise ContractRefused(400, "contract_invalid")
  try:
    document = validate_document(envelope.get("filename"), envelope.get("content_b64"), accepted=CONTRACT_FORMATS)
  except AuthorizationUploadError:
    raise ContractRefused(400, "contract_invalid") from None
  if (document.sha256_hex != envelope.get("sha256") or document.size_bytes != envelope.get("size_bytes")
      or document.filename != envelope.get("filename") or document.mime != envelope.get("mime")
      or any(not isinstance(envelope.get(key), str) or not envelope[key] for key in ("uploaded_at", "uploaded_by"))):
    raise ContractRefused(400, "contract_invalid")
  return {"store": documents.name, "ref": ref, **{key: envelope[key] for key in _REF_FIELDS}}


def read_contract(documents, contract):
  """The stored contract file, served only if it still matches the tenant record.

  The tenant record is the authority: the file's bytes are hashed and sized here and compared with
  the record, never with the envelope's own claims. Anything else is 409 `contract_integrity`.
  """
  if contract.get("store") != documents.name:
    raise ContractRefused(503, "unavailable")
  envelope = documents.get(contract["ref"])
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
