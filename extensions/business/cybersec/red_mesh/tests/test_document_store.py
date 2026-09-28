"""RM-095 phase 1: document store seam and shared document validation."""
import base64
import unittest

from extensions.business.cybersec.red_mesh.services.authorization_upload import (
  AuthorizationUploadError,
  validate_document,
)
from extensions.business.cybersec.red_mesh.tenancy.adapters.r1fs_documents import R1fsDocumentStore
from extensions.business.cybersec.red_mesh.tenancy.ports import DocumentStoreError, TenantStoreError


PDF_BYTES = b"%PDF-1.7\n%contract body\n%%EOF\n"
PNG_BYTES = b"\x89PNG\r\n\x1a\nfake png body"


def _b64(raw):
  return base64.b64encode(raw).decode("ascii")


class _Repo:
  def __init__(self, cid="QmContract", stored=None, fail=False):
    self.cid, self.stored, self.fail, self.puts = cid, stored or {}, fail, []

  def put_json(self, payload, *, show_logs=False, secret=None):
    if self.fail:
      raise RuntimeError("r1fs down")
    self.puts.append(payload)
    return self.cid

  def get_json(self, cid, *, secret=None):
    if self.fail:
      raise RuntimeError("r1fs down")
    return self.stored.get(cid)


class TestValidateDocument(unittest.TestCase):
  def test_returns_the_decoded_facts(self):
    doc = validate_document("../signed contract.pdf", _b64(PDF_BYTES))
    self.assertEqual(doc.raw, PDF_BYTES)
    self.assertEqual(doc.filename, "signed_contract.pdf")
    self.assertEqual(doc.mime, "application/pdf")
    self.assertEqual(doc.size_bytes, len(PDF_BYTES))
    self.assertEqual(doc.sha256_hex, "61f8f93b5b68f47b3e3c66c1a48b68db8c49dbb1cf86f9e1221b44c9f94a8cfd")

  def test_default_formats_still_accept_images(self):
    self.assertEqual(validate_document("a.png", _b64(PNG_BYTES)).mime, "image/png")

  def test_a_narrowed_format_list_refuses_other_formats(self):
    with self.assertRaises(AuthorizationUploadError) as ctx:
      validate_document("a.png", _b64(PNG_BYTES), accepted=("application/pdf",))
    self.assertEqual(ctx.exception.code, "bad_mime")

  def test_errors_keep_their_codes(self):
    for content, code in (("not base64!", "invalid_base64"), ("", "empty")):
      with self.subTest(code=code), self.assertRaises(AuthorizationUploadError) as ctx:
        validate_document("a.pdf", content)
      self.assertEqual(ctx.exception.code, code)


class TestR1fsDocumentStore(unittest.TestCase):
  def test_names_its_store_and_returns_the_reference(self):
    repo = _Repo(cid="QmX")
    store = R1fsDocumentStore(repo)
    self.assertEqual(store.name, "r1fs")
    self.assertEqual(store.put({"kind": "k"}), "QmX")
    self.assertEqual(repo.puts, [{"kind": "k"}])

  def test_reads_back_a_dict_and_nothing_else(self):
    store = R1fsDocumentStore(_Repo(stored={"QmA": {"kind": "k"}, "QmB": ["list"]}))
    self.assertEqual(store.get("QmA"), {"kind": "k"})
    self.assertIsNone(store.get("QmB"))
    self.assertIsNone(store.get("QmMissing"))
    self.assertIsNone(store.get(""))

  def test_backend_failures_surface_as_store_errors(self):
    store = R1fsDocumentStore(_Repo(fail=True))
    with self.assertRaises(DocumentStoreError):
      store.put({"kind": "k"})
    with self.assertRaises(DocumentStoreError):
      store.get("QmA")
    with self.assertRaises(DocumentStoreError):
      R1fsDocumentStore(_Repo(cid="")).put({"kind": "k"})

  def test_store_errors_are_tenant_store_errors(self):
    # The administration endpoint maps TenantStoreError to 503 unavailable.
    self.assertTrue(issubclass(DocumentStoreError, TenantStoreError))


if __name__ == "__main__":
  unittest.main()
