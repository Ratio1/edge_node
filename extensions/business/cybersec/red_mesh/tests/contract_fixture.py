"""RM-095 phase 1 test support: a tenant contract and an in-memory document store."""
import base64
import copy
import hashlib
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.ports import DocumentStoreError

CONTRACT_PDF = b"%PDF-1.7\n%fixture signed contract\n%%EOF\n"
CONTRACT_SHA256 = hashlib.sha256(CONTRACT_PDF).hexdigest()


class FakeDocumentStore:
  name = "fake"

  def __init__(self):
    self.envelopes = {}
    self.puts = []
    self.fail = False
    self.fail_delete = set()
    self.deleted = []

  def put(self, envelope):
    if self.fail:
      raise DocumentStoreError("fake store down")
    ref = "doc-%d" % (len(self.puts) + 1)
    self.puts.append(copy.deepcopy(envelope))
    self.envelopes[ref] = copy.deepcopy(envelope)
    return ref

  def get(self, ref):
    if self.fail:
      raise DocumentStoreError("fake store down")
    envelope = self.envelopes.get(ref)
    return copy.deepcopy(envelope) if isinstance(envelope, dict) else None

  def delete(self, ref):
    # RM-107. `fail_delete` names the refs whose delete the backend does not confirm.
    if self.fail or ref in self.fail_delete:
      raise DocumentStoreError("fake store down")
    self.deleted.append(ref)
    self.envelopes.pop(ref, None)


def contract_b64(raw=CONTRACT_PDF):
  return base64.b64encode(raw).decode("ascii")


LEGAL = {"name": "Example Holdings SRL", "registration_id": "RO12345678",
         "signer_name": "Ana Pop", "signer_role": "Director"}
# RM-110: the optional party-block fields; a block without them reads back with them empty.
PARTY_FIELDS = ("address", "vat_id", "contact_name", "contact_email", "contact_phone")


def legal_dto(legal=LEGAL):
  """A `legal` block as the DTOs answer it: every party field, the absent optional ones empty."""
  return {**{key: "" for key in PARTY_FIELDS}, **legal}


def contract_ref(uploaded_by="creator", ref="doc-fixture", store="fake"):
  """A document reference as `resolve_contract` returns it for a stored fixture contract."""
  return {"store": store, "ref": ref, "sha256": CONTRACT_SHA256, "filename": "contract.pdf",
          "mime": "application/pdf", "size_bytes": len(CONTRACT_PDF),
          "uploaded_at": "2026-09-27T12:00:00Z", "uploaded_by": uploaded_by}


def contract_terms(uploaded_by="creator", ref=None):
  """Keyword arguments that make a direct `TenantAdministrationService.prepare_tenant` call valid.

  Each call is a fresh upload of the fixture bytes, so a fresh reference (as R1FS gives a new CID to
  every upload, the envelope carrying its upload time): RM-109 refuses a reference another tenant
  or receipt already holds (`contract_in_use`). Same bytes, so a replay is still the same creation.
  """
  return {"legal": dict(LEGAL), "contract": contract_ref(uploaded_by, ref=ref or "doc-" + str(uuid4()))}


def envelope(uploaded_by="creator", raw=CONTRACT_PDF, **changes):
  record = {"kind": "redmesh_tenant_contract", "schema_version": "1.0", "filename": "contract.pdf",
            "mime": "application/pdf", "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "uploaded_at": "2026-09-27T12:00:00Z", "uploaded_by": uploaded_by,
            "content_b64": base64.b64encode(raw).decode("ascii")}
  record.update(changes)
  return record


def install_contract(plugin, uploaded_by="creator", ref="doc-fixture"):
  """Give a real plugin a document store holding one contract; return the prepare_tenant fields.
  A second tenant on the same plugin needs its own `ref` (RM-109 `contract_in_use`)."""
  documents = FakeDocumentStore()
  documents.envelopes[ref] = envelope(uploaded_by)
  plugin._document_store = lambda: documents
  return {"legal_name": LEGAL["name"], "registration_id": LEGAL["registration_id"],
          "signer_name": LEGAL["signer_name"], "signer_role": LEGAL["signer_role"],
          "contract_ref": ref}
