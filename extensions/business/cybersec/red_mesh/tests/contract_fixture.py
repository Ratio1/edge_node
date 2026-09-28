"""RM-095 phase 1 test support: a tenant contract and an in-memory document store."""
import base64
import copy
import hashlib

from extensions.business.cybersec.red_mesh.tenancy.ports import DocumentStoreError

CONTRACT_PDF = b"%PDF-1.7\n%fixture signed contract\n%%EOF\n"
CONTRACT_SHA256 = hashlib.sha256(CONTRACT_PDF).hexdigest()


class FakeDocumentStore:
  name = "fake"

  def __init__(self):
    self.envelopes = {}
    self.puts = []
    self.fail = False

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


def contract_b64(raw=CONTRACT_PDF):
  return base64.b64encode(raw).decode("ascii")


LEGAL = {"name": "Example Holdings SRL", "registration_id": "RO12345678",
         "signer_name": "Ana Pop", "signer_role": "Director"}


def contract_ref(uploaded_by="creator", ref="doc-fixture", store="fake"):
  """A document reference as `resolve_contract` returns it for a stored fixture contract."""
  return {"store": store, "ref": ref, "sha256": CONTRACT_SHA256, "filename": "contract.pdf",
          "mime": "application/pdf", "size_bytes": len(CONTRACT_PDF),
          "uploaded_at": "2026-09-27T12:00:00Z", "uploaded_by": uploaded_by}


def contract_terms(uploaded_by="creator"):
  """Keyword arguments that make a direct `TenantAdministrationService.prepare_tenant` call valid."""
  return {"legal": dict(LEGAL), "contract": contract_ref(uploaded_by)}


def envelope(uploaded_by="creator", raw=CONTRACT_PDF, **changes):
  record = {"kind": "redmesh_tenant_contract", "schema_version": "1.0", "filename": "contract.pdf",
            "mime": "application/pdf", "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "uploaded_at": "2026-09-27T12:00:00Z", "uploaded_by": uploaded_by,
            "content_b64": base64.b64encode(raw).decode("ascii")}
  record.update(changes)
  return record


def install_contract(plugin, uploaded_by="creator"):
  """Give a real plugin a document store holding one contract; return the prepare_tenant fields."""
  documents = FakeDocumentStore()
  documents.envelopes["doc-fixture"] = envelope(uploaded_by)
  plugin._document_store = lambda: documents
  return {"legal_name": LEGAL["name"], "registration_id": LEGAL["registration_id"],
          "signer_name": LEGAL["signer_name"], "signer_role": LEGAL["signer_role"],
          "contract_ref": "doc-fixture"}
