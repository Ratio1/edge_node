"""RM-095 phase 2: the RoE document and the signed authorization an engagement is created around.

Both are uploaded first through `upload_authorization` (tenant-stamped envelopes) and bound here
by reference. Storage I/O happens outside the administration lock, as for the tenant contract
(`tenant_contract.py`, whose `contract_result` shapes these responses too); the administration
service only sees the verified document references.
"""
from .authorization_upload import AuthorizationUploadError, validate_document
from .tenant_contract import ContractRefused

AUTHORIZATION_KIND = "redmesh_authorization_document"
# The authorization is a signed PDF (not verified in v1, owner Q1); the RoE document may be a scan.
AUTHORIZATION_FORMATS = ("application/pdf",)
ROE_FORMATS = None  # every upload format (PDF, PNG, JPEG)
_REF_FIELDS = ("sha256", "filename", "mime", "size_bytes", "uploaded_at", "uploaded_by")


def resolve_engagement_document(documents, ref, *, tenant_id, uploaded_by, accepted):
  """The document reference for an uploaded envelope, re-verified from its bytes.

  The envelope must carry this tenant and this creator: a document uploaded in another tenant, or
  by another account, cannot be bound. Every failure is `document_invalid`, indistinguishably.
  """
  if not isinstance(ref, str) or not ref.strip():
    raise ContractRefused(400, "document_invalid")
  envelope = documents.get(ref)
  if (not isinstance(envelope, dict) or envelope.get("kind") != AUTHORIZATION_KIND
      or envelope.get("tenant_id") != tenant_id or envelope.get("uploaded_by") != uploaded_by):
    raise ContractRefused(400, "document_invalid")
  try:
    document = validate_document(envelope.get("filename"), envelope.get("content_b64"), accepted=accepted)
  except AuthorizationUploadError:
    raise ContractRefused(400, "document_invalid") from None
  if (document.sha256_hex != envelope.get("sha256") or document.size_bytes != envelope.get("size_bytes")
      or document.filename != envelope.get("filename") or document.mime != envelope.get("mime")
      or not isinstance(envelope.get("uploaded_at"), str) or not envelope["uploaded_at"]):
    raise ContractRefused(400, "document_invalid")
  return {"store": documents.name, "ref": ref, **{key: envelope[key] for key in _REF_FIELDS}}


def read_engagement_document(documents, ref):
  """The stored file, served only while its bytes still match the engagement record."""
  if ref.get("store") != documents.name:
    raise ContractRefused(503, "unavailable")
  envelope = documents.get(ref["ref"])
  if not isinstance(envelope, dict) or envelope.get("kind") != AUTHORIZATION_KIND:
    raise ContractRefused(409, "document_integrity")
  try:
    document = validate_document(ref["filename"], envelope.get("content_b64"), accepted=ROE_FORMATS)
  except AuthorizationUploadError:
    raise ContractRefused(409, "document_integrity") from None
  if document.sha256_hex != ref["sha256"] or document.size_bytes != ref["size_bytes"]:
    raise ContractRefused(409, "document_integrity")
  return {"filename": ref["filename"], "mime": document.mime, "size_bytes": document.size_bytes,
          "sha256": document.sha256_hex, "content_b64": envelope["content_b64"]}
