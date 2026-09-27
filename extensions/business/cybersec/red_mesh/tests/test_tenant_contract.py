"""RM-095 phase 1: contract-bound tenant creation (upload, binding, read)."""
import unittest
from unittest.mock import patch

from .contract_fixture import CONTRACT_PDF, CONTRACT_SHA256, FakeDocumentStore, contract_b64
from .test_tenant_administration import FakeAdministrationStore

PNG = b"\x89PNG\r\n\x1a\nnot a contract"


class _PluginCase(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.store = FakeAdministrationStore()
    self.documents = FakeDocumentStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.store, name))
    self.plugin._document_store = lambda: self.documents
    self.actor = {"account_id": "creator"}


class TestUploadTenantContract(_PluginCase):
  def upload(self, actor=None, raw=CONTRACT_PDF, filename="Signed Contract.pdf"):
    return self.plugin.upload_tenant_contract(actor or self.actor, filename, contract_b64(raw))

  def test_a_super_tenant_admin_uploads_a_pdf_and_gets_a_document_reference(self):
    result = self.upload()
    self.assertEqual(result["status_code"], 200, result)
    ref = result["data"]
    self.assertEqual(ref["store"], "fake")
    self.assertEqual(ref["ref"], "doc-1")
    self.assertEqual(ref["sha256"], CONTRACT_SHA256)
    self.assertEqual((ref["filename"], ref["mime"], ref["size_bytes"]),
                     ("Signed_Contract.pdf", "application/pdf", len(CONTRACT_PDF)))
    self.assertEqual(ref["uploaded_by"], "creator")
    self.assertTrue(ref["uploaded_at"].endswith("Z"))
    envelope = self.documents.puts[0]
    self.assertEqual(envelope["kind"], "redmesh_tenant_contract")
    self.assertEqual(envelope["uploaded_by"], "creator")
    self.assertEqual(envelope["content_b64"], contract_b64())
    self.assertNotIn("content_b64", ref)

  def test_only_a_platform_account_may_upload(self):
    result = self.upload(actor={"account_id": "initial"})
    self.assertEqual((result["status_code"], result["error"]), (403, "forbidden"))
    self.assertEqual(self.documents.puts, [])

  def test_a_contract_must_be_a_pdf(self):
    result = self.upload(raw=PNG)
    self.assertEqual((result["status_code"], result["error"]), (400, "bad_mime"))
    self.assertEqual(self.documents.puts, [])

  def test_malformed_content_is_refused_with_the_upload_code(self):
    result = self.plugin.upload_tenant_contract(self.actor, "c.pdf", "not base64!")
    self.assertEqual((result["status_code"], result["error"]), (400, "invalid_base64"))

  def test_a_store_failure_is_unavailable(self):
    self.documents.fail = True
    result = self.upload()
    self.assertEqual((result["status_code"], result["error"]), (503, "unavailable"))

  def test_no_namespace_means_no_upload(self):
    self.plugin.cfg_tenancy_namespace = None
    self.assertEqual(self.upload()["status_code"], 503)
    self.assertEqual(self.documents.puts, [])


if __name__ == "__main__":
  unittest.main()
