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
