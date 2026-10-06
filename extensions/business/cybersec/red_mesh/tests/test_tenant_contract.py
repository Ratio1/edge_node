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

  def test_non_text_content_is_a_typed_refusal(self):
    for content in (7, ["JVBERi0="], {"b64": "x"}):
      with self.subTest(content=content):
        result = self.plugin.upload_tenant_contract(self.actor, "c.pdf", content)
        self.assertEqual((result["status_code"], result["error"]), (400, "invalid_base64"))

  def test_an_uploaded_contract_binds_and_downloads_unchanged(self):
    # The whole path on one store: upload, bind the returned reference, read it back.
    ref = self.upload()["data"]
    request = str(uuid4())
    prepared = self.plugin.prepare_tenant(self.actor, request, "Tenant", "tenant", "initial",
                                          legal_name="A SRL", registration_id="RO1", signer_name="Ana",
                                          signer_role="Director", contract_ref=ref["ref"])
    self.assertEqual(prepared["status_code"], 200, prepared)
    tenant_id = prepared["data"]["tenantId"]
    self.store.grant("initial", tenant_id)
    self.assertTrue(self.plugin.activate_tenant(self.actor, request)["success"])
    self.assertEqual(self.plugin.get_tenant_contract(self.actor, tenant_id)["data"]["contract"], ref)
    downloaded = self.plugin.download_tenant_contract(self.actor, tenant_id)["data"]
    self.assertEqual((downloaded["sha256"], downloaded["content_b64"]), (CONTRACT_SHA256, contract_b64()))

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
             "mime claim": envelope(mime="text/html"),
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

  def test_a_contract_uploaded_by_another_super_tenant_admin_is_accepted(self):
    # RM-109 (owner, 2026-10-07): the uploader must hold the platform role, not be the creator.
    self.store.account("other-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    fields = install_contract(self.plugin, uploaded_by="other-sta")
    result = self.plugin.prepare_tenant(self.actor, str(uuid4()), "Tenant", "tenant", "initial", **fields)
    self.assertEqual(result["status_code"], 200, result)

  def test_a_contract_whose_uploader_lacks_the_platform_role_is_refused(self):
    for uploader, memberships in (("pentester", [{"role": "super_pentester", "tenant_id": None}]),
                                  ("former-sta", []), ("gone", None)):
      with self.subTest(uploader=uploader):
        if memberships is not None:
          self.store.account(uploader, memberships=memberships)
        fields = install_contract(self.plugin, uploaded_by=uploader)
        before = len(self.store.writes)
        result = self.plugin.prepare_tenant(self.actor, str(uuid4()), "Tenant", "tenant", "initial", **fields)
        self.assertEqual((result["status_code"], result["error"]), (400, "contract_invalid"))
        self.assertEqual(len(self.store.writes), before)

  def test_the_one_step_path_refuses_a_draft_envelope(self):
    for changes in ({"schema_version": "1.1", "document_kind": "contract", "draft_id": "td_" + str(uuid4())},
                    {"document_kind": "data_handling"}):
      with self.subTest(changes=changes):
        fields = install_contract(self.plugin)
        self.plugin._document_store().envelopes["doc-fixture"] = envelope(**changes)
        result = self.plugin.prepare_tenant(self.actor, str(uuid4()), "Tenant", "tenant", "initial", **fields)
        self.assertEqual((result["status_code"], result["error"]), (400, "contract_invalid"))

  def test_a_file_bound_to_one_tenant_is_refused_for_a_second(self):
    fields = install_contract(self.plugin)
    first = self.plugin.prepare_tenant(self.actor, str(uuid4()), "Tenant", "tenant", "initial", **fields)
    self.assertEqual(first["status_code"], 200, first)
    self.store.account("initial-2")
    before = len(self.store.writes)
    second = self.plugin.prepare_tenant(self.actor, str(uuid4()), "Other", "other", "initial-2", **fields)
    self.assertEqual((second["status_code"], second["error"]), (409, "contract_in_use"))
    self.assertEqual(len(self.store.writes), before)

  def test_the_contract_in_use_scan_fails_closed_past_the_namespace_cap(self):
    from extensions.business.cybersec.red_mesh.tenancy.adapters import cstore_administration
    fields = install_contract(self.plugin)
    # One row in the namespace, over a cap of zero.
    self.store.data[('["redmesh","tenancy",1,"deployment"]', '["domain","deployment","elsewhere"]')] = {"x": 1}
    with patch.object(cstore_administration, "MAX_ENUMERATED_RECORDS", 0):
      result = self.plugin.prepare_tenant(self.actor, str(uuid4()), "Tenant", "tenant", "initial", **fields)
    self.assertEqual((result["status_code"], result["error"]), (503, "unavailable"))

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

  def test_the_same_file_uploaded_again_replays_the_same_creation(self):
    # A second upload of the same bytes gets a new reference (the envelope carries its upload time);
    # a retry after a page reload, or a seeded rerun, must still be the same creation.
    terms = contract_terms()
    first = self.prepare(**terms)
    again = contract_terms()
    again["contract"] = {**contract_ref(ref="doc-reuploaded"), "uploaded_at": "2026-09-28T08:00:00Z"}
    replay = self.prepare(**again)
    self.assertEqual(replay["data"]["tenantId"], first["data"]["tenantId"])
    receipt = next(v for v in self.store.data.values() if isinstance(v, dict) and v.get("kind") == "receipt")
    self.assertEqual(receipt["contract"]["ref"], terms["contract"]["ref"])

  def test_a_replay_with_a_different_contract_or_legal_details_conflicts(self):
    self.prepare(**contract_terms())
    other = contract_terms()
    other["contract"] = {**contract_ref(ref="doc-other"), "sha256": "b" * 64}
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


class TestReadTenantContract(_PluginCase):
  def setUp(self):
    super().setUp()
    fields = install_contract(self.plugin)
    self.documents = self.plugin._document_store()
    self.request = str(uuid4())
    prepared = self.plugin.prepare_tenant(self.actor, self.request, "Tenant", "tenant", "initial", **fields)
    self.tenant_id = prepared["data"]["tenantId"]
    self.store.grant("initial", self.tenant_id)
    self.assertTrue(self.plugin.activate_tenant(self.actor, self.request)["success"])

  def test_a_super_tenant_admin_reads_the_legal_details_and_contract_record(self):
    result = self.plugin.get_tenant_contract(self.actor, self.tenant_id)
    self.assertEqual(result["status_code"], 200, result)
    self.assertEqual(result["data"], {"legal": LEGAL, "contract": contract_ref(store="fake"),
                                      "compliance_types": None, "framework_agreement": None,
                                      "data_handling": None, "governance": None})

  def test_the_tenant_admin_cannot_read_or_download_the_contract(self):
    initial = {"account_id": "initial"}
    for call in (self.plugin.get_tenant_contract, self.plugin.download_tenant_contract):
      with self.subTest(call.__name__):
        result = call(initial, self.tenant_id)
        self.assertEqual((result["status_code"], result["error"]), (403, "forbidden"))

  def test_download_returns_the_verified_file(self):
    result = self.plugin.download_tenant_contract(self.actor, self.tenant_id)
    self.assertEqual(result["status_code"], 200, result)
    self.assertEqual(result["data"], {"filename": "contract.pdf", "mime": "application/pdf",
                                      "size_bytes": len(CONTRACT_PDF), "sha256": CONTRACT_SHA256,
                                      "content_b64": contract_b64()})

  def test_a_file_that_no_longer_matches_the_tenant_record_is_not_served(self):
    # The stored envelope is rewritten consistently with itself; only the tenant record knows better.
    self.documents.envelopes["doc-fixture"] = envelope(raw=b"%PDF-1.7\n%a different contract\n%%EOF\n")
    result = self.plugin.download_tenant_contract(self.actor, self.tenant_id)
    self.assertEqual((result["status_code"], result["error"]), (409, "contract_integrity"))
    self.documents.envelopes.pop("doc-fixture")
    result = self.plugin.download_tenant_contract(self.actor, self.tenant_id)
    self.assertEqual((result["status_code"], result["error"]), (409, "contract_integrity"))

  def test_a_tenant_created_before_contracts_reads_as_not_recorded(self):
    for (hkey, key), value in self.store.data.items():
      if isinstance(value, dict) and value.get("tenant_id") == self.tenant_id:
        value.pop("legal", None)
        value.pop("contract", None)
    self.assertEqual(self.plugin.get_tenant_contract(self.actor, self.tenant_id)["data"],
                     {"legal": None, "contract": None, "compliance_types": None, "framework_agreement": None,
                      "data_handling": None, "governance": None})
    result = self.plugin.download_tenant_contract(self.actor, self.tenant_id)
    self.assertEqual((result["status_code"], result["error"]), (404, "not_found"))

  def test_a_contract_the_receipt_never_bound_fails_closed(self):
    # A tenant record that gained a contract its creation receipt does not carry (only a CStore
    # writer can do that) is not served as the tenant's contract.
    for (hkey, key), value in self.store.data.items():
      if isinstance(value, dict) and value.get("tenant_id") == self.tenant_id:
        if value.get("kind") == "receipt":
          value.pop("contract"); value.pop("legal")
        elif value.get("kind") == "tenant":
          value["contract"] = {"store": "fake"}
          value.pop("legal")
    for call in (self.plugin.get_tenant_contract, self.plugin.download_tenant_contract):
      with self.subTest(call.__name__):
        self.assertEqual(call(self.actor, self.tenant_id)["status_code"], 503)

  def test_an_unknown_tenant_is_not_found(self):
    result = self.plugin.get_tenant_contract(self.actor, "tn_" + str(uuid4()))
    self.assertEqual(result["status_code"], 404)

  def test_a_store_failure_is_unavailable(self):
    self.documents.fail = True
    result = self.plugin.download_tenant_contract(self.actor, self.tenant_id)
    self.assertEqual((result["status_code"], result["error"]), (503, "unavailable"))


if __name__ == "__main__":
  unittest.main()
