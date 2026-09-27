"""RM-095 phase 1: contract-bound tenant creation (upload, binding, read)."""
import unittest
from unittest.mock import patch

from uuid import uuid4

from .contract_fixture import (CONTRACT_PDF, CONTRACT_SHA256, LEGAL, FakeDocumentStore, contract_b64,
                               contract_ref, contract_terms, envelope, install_contract)
from . import test_tenant_administration as administration_tests
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


class TestPrepareBindsTheContract(_PluginCase):
  def prepare(self, **changes):
    fields = install_contract(self.plugin)
    self.documents = self.plugin._document_store()
    fields.update(changes)
    return self.plugin.prepare_tenant(self.actor, str(uuid4()), "Tenant", "tenant", "initial", **fields)

  def test_the_tenant_record_carries_the_legal_details_and_the_contract(self):
    prepared = self.prepare()
    self.assertEqual(prepared["status_code"], 200, prepared)
    tenant_id = prepared["data"]["tenantId"]
    tenant = next(v for (h, k), v in self.store.data.items() if k.startswith('["tenant"') and tenant_id in k)
    self.assertEqual(tenant["legal"], LEGAL)
    self.assertEqual(tenant["contract"], contract_ref(store="fake"))

  def test_creation_without_a_contract_is_refused_before_anything_is_written(self):
    before = len(self.store.writes)
    result = self.prepare(contract_ref="")
    self.assertEqual((result["status_code"], result["error"]), (400, "contract_required"))
    self.assertEqual(len(self.store.writes), before)

  def test_creation_without_legal_details_is_refused(self):
    for field in ("legal_name", "registration_id", "signer_name", "signer_role"):
      with self.subTest(field=field):
        result = self.prepare(**{field: "  "})
        self.assertEqual((result["status_code"], result["error"]), (400, "legal_details_required"))

  def test_an_unreadable_foreign_or_tampered_contract_looks_the_same(self):
    cases = {"missing": None, "wrong kind": envelope(kind="redmesh_authorization_document"),
             "tampered": envelope(sha256="0" * 64), "not a pdf": envelope(raw=b"\x89PNG\r\n\x1a\nimg")}
    for label, stored in cases.items():
      with self.subTest(label):
        install_contract(self.plugin)
        documents = self.plugin._document_store()
        documents.envelopes.pop("doc-fixture")
        if stored is not None:
          documents.envelopes["doc-fixture"] = stored
        result = self.plugin.prepare_tenant(self.actor, str(uuid4()), "Tenant", label.replace(" ", "-"),
                                            "initial", legal_name="A", registration_id="B",
                                            signer_name="C", signer_role="D", contract_ref="doc-fixture")
        self.assertEqual((result["status_code"], result["error"]), (400, "contract_invalid"))

  def test_a_contract_uploaded_by_someone_else_is_refused(self):
    self.store.account("other-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    fields = install_contract(self.plugin, uploaded_by="other-sta")
    result = self.plugin.prepare_tenant(self.actor, str(uuid4()), "Tenant", "tenant", "initial", **fields)
    self.assertEqual((result["status_code"], result["error"]), (400, "contract_invalid"))

  def test_the_contract_is_not_read_for_an_unauthorized_caller(self):
    install_contract(self.plugin)
    documents = self.plugin._document_store()
    documents.fail = True  # any read would surface as 503
    result = self.plugin.prepare_tenant({"account_id": "initial"}, str(uuid4()), "Tenant", "tenant", "initial",
                                        contract_ref="doc-fixture")
    self.assertEqual((result["status_code"], result["error"]), (403, "forbidden"))

  def test_a_store_failure_is_unavailable(self):
    install_contract(self.plugin)
    self.plugin._document_store().fail = True
    result = self.plugin.prepare_tenant(self.actor, str(uuid4()), "Tenant", "tenant", "initial",
                                        contract_ref="doc-fixture")
    self.assertEqual((result["status_code"], result["error"]), (503, "unavailable"))


class TestContractReplay(unittest.TestCase):
  setUp = administration_tests.TestTenantAdministration.setUp
  prepare = administration_tests.TestTenantAdministration.prepare

  def test_a_replay_with_the_same_contract_is_the_same_creation(self):
    first = self.prepare(**contract_terms())
    again = self.prepare(**contract_terms())
    self.assertEqual(again["data"]["tenantId"], first["data"]["tenantId"])

  def test_a_replay_with_a_different_contract_or_legal_details_conflicts(self):
    self.prepare(**contract_terms())
    other = contract_terms()
    other["contract"] = contract_ref(ref="doc-other")
    self.assertEqual(self.prepare(**other)["error"], "request_conflict")
    renamed = contract_terms()
    renamed["legal"]["name"] = "Someone Else SRL"
    self.assertEqual(self.prepare(**renamed)["error"], "request_conflict")

  def test_the_service_refuses_missing_terms_even_without_the_plugin(self):
    self.assertEqual(self.prepare(contract=None)["error"], "contract_required")
    self.assertEqual(self.prepare(legal=None)["error"], "legal_details_required")
    self.assertEqual(self.prepare(**contract_terms(uploaded_by="initial"))["error"], "contract_invalid")

  def _strip(self, tenant_id, keys):
    for (hkey, key), value in self.store.data.items():
      if isinstance(value, dict) and value.get("tenant_id") == tenant_id and value.get("kind") in ("tenant", "receipt"):
        for name in keys:
          value.pop(name, None)

  def test_a_tenant_created_before_contracts_still_reads_and_lists(self):
    tenant_id = self.prepare(**contract_terms())["data"]["tenantId"]
    self.store.grant("initial", tenant_id)
    self._strip(tenant_id, ("legal", "contract"))
    self.assertTrue(self.service.activate_tenant(self.actor, self.request)["success"])
    self.assertEqual(self.service.get_tenant(self.actor, tenant_id)["status_code"], 200)
    self.assertEqual(self.service.list_tenants(self.actor)["data"][0]["tenantId"], tenant_id)

  def test_a_malformed_stored_contract_fails_closed(self):
    tenant_id = self.prepare(**contract_terms())["data"]["tenantId"]
    for (hkey, key), value in self.store.data.items():
      if isinstance(value, dict) and value.get("kind") == "receipt":
        value["contract"] = {"store": "fake"}
    self.store.grant("initial", tenant_id)
    self.assertEqual(self.service.activate_tenant(self.actor, self.request)["status_code"], 503)


if __name__ == "__main__":
  unittest.main()
