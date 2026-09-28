"""RM-095 phase 2, RM-107: engagement endpoints through real plugin signatures, documents and CStore adapters."""
import base64
import inspect
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from pydantic import create_model

from .test_tenant_administration import FakeAdministrationStore
from .contract_fixture import install_contract

PDF = b"%PDF-1.7\n%fixture signed authorization\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


class TestTenantEngagementPlugin(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    from extensions.business.cybersec.red_mesh.services.engagement_documents import store_engagement_document
    cls.Plugin = PentesterApi01Plugin
    cls.store_engagement_document = staticmethod(store_engagement_document)

  def setUp(self):
    environment = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    environment.start()
    self.addCleanup(environment.stop)
    self.storage = FakeAdministrationStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.storage, name))
    self.events = []
    self.plugin._log_audit_event = lambda event, details: self.events.append((event, details))
    self.actor = {"account_id": "creator"}
    request = str(uuid4())
    prepared = self.plugin.prepare_tenant(self.actor, request, "Example", "example", "initial",
                                          **install_contract(self.plugin))
    self.assertTrue(prepared["success"], prepared)
    self.tenant = prepared["data"]["tenantId"]
    self.storage.grant("initial", self.tenant)
    self.assertTrue(self.plugin.activate_tenant(self.actor, request)["success"])
    self.documents = self.plugin._document_store()
    self.storage.account("platform-pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.storage.account("viewer", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])

  def call_json(self, method, **body):
    endpoint = getattr(self.plugin, method)
    fields = {parameter.name: (parameter.annotation, parameter.default)
              for parameter in inspect.signature(endpoint).parameters.values()}
    model = create_model("EngagementRequest", **fields)
    return endpoint(**model.model_validate_json(json.dumps(body)).model_dump())

  def upload(self, raw=PDF, filename="permission.pdf", actor=None, kind="agreement", title="Permission letter",
             comment=""):
    uploaded = self.call_json("upload_engagement_document", actor=actor or self.actor, tenant_id=self.tenant,
                              filename=filename, content_b64=base64.b64encode(raw).decode("ascii"),
                              kind=kind, title=title, comment=comment)
    self.assertTrue(uploaded["success"], uploaded)
    return uploaded["data"]["ref"]

  def stored(self, uploaded_by="creator", tenant_id=None):
    """An envelope written directly, for owners the endpoint would never stamp."""
    return self.store_engagement_document(
      self.documents, filename="permission.pdf", content_b64=base64.b64encode(PDF).decode("ascii"),
      tenant_id=tenant_id or self.tenant, uploaded_by=uploaded_by, kind="agreement", title="Letter")["ref"]

  def create(self, actor=None, **changes):
    body = {"actor": actor or self.actor, "tenant_id": self.tenant, "request_id": str(uuid4()),
            "display_name": "Q4", "allowed_run_modes": ["continuous", "single_pass"], "valid_from": "2026-10-01T00:00:00Z",
            "valid_until": "2027-10-01T00:00:00Z", "roe": {}, "context": {"client_name": "Example"},
            "assets": [{"display_name": "Edge", "target": {"kind": "network", "address": "192.0.2.10"},
                        "authorized_ports": "443", "authorized_tests": ["service_info_common"]}]}
    body.update(changes)
    if "document_refs" not in body:
      body["document_refs"] = [self.upload(PNG, "roe.png", title="Rules of engagement (scan)"),
                               self.upload(kind="third_party_consent", title="Hosting consent",
                                           comment="provider ticket 42")]
    return self.call_json("create_engagement", **body)

  def refused(self, result, status, error):
    self.assertFalse(result["success"], result)
    self.assertEqual((result["status_code"], result["error"]), (status, error))

  def test_capability_reports_tenant_execution_without_stored_reads(self):
    # RM-084 P6: tenant execution is no longer a rollout a deployment opts into, so the capability
    # reports the only state there is -- whatever a stale `TENANT_EXECUTION_ENABLED` still says.
    # (Moved here from the retired tenant asset suite, RM-107.)
    self.plugin.cfg_tenancy_namespace = ""
    with patch.object(self.plugin, "chainstore_hget", side_effect=AssertionError("No stored capability reads")), \
         patch.object(self.plugin, "chainstore_hgetall", side_effect=AssertionError("No capability enumeration")), \
         patch.object(self.plugin, "chainstore_hset", side_effect=AssertionError("No capability writes")):
      for value in (None, False, "false", True):
        with self.subTest(value=value):
          self.plugin.cfg_tenant_execution_enabled = value
          self.assertIs(self.plugin.get_capability_status()["tenant_execution_enabled"], True)

  def test_upload_create_download_chain(self):
    created = self.create()
    self.assertTrue(created["success"], created)
    engagement = created["data"]
    roe, consent = engagement["documents"]
    self.assertEqual((roe["documentId"], roe["kind"], roe["title"], roe["mime"]),
                     ("ed_1", "agreement", "Rules of engagement (scan)", "image/png"))
    self.assertEqual((consent["documentId"], consent["kind"], consent["title"], consent["comment"]),
                     ("ed_2", "third_party_consent", "Hosting consent", "provider ticket 42"))
    for actor in (self.actor, {"account_id": "platform-pentester"}):
      downloaded = self.call_json("download_engagement_document", actor=actor, tenant_id=self.tenant,
                                  engagement_id=engagement["engagementId"], document_id="ed_2")
      self.assertTrue(downloaded["success"], downloaded)
      self.assertEqual(base64.b64decode(downloaded["data"]["content_b64"]), PDF)
      self.assertEqual(downloaded["data"]["sha256"], consent["sha256"])
    self.refused(self.call_json("download_engagement_document", actor={"account_id": "viewer"},
                                tenant_id=self.tenant, engagement_id=engagement["engagementId"], document_id="ed_1"),
                 403, "forbidden")
    listed = self.call_json("list_engagements", actor={"account_id": "viewer"}, tenant_id=self.tenant, active=True)
    self.assertEqual([row["engagementId"] for row in listed["data"]["engagements"]], [engagement["engagementId"]])

  def test_only_a_super_tenant_admin_uploads_creates_and_revokes(self):
    engagement = self.create()["data"]
    pentester = {"account_id": "platform-pentester"}
    content = base64.b64encode(PDF).decode("ascii")
    for actor in (pentester, {"account_id": "viewer"}):
      self.refused(self.call_json("upload_engagement_document", actor=actor, tenant_id=self.tenant,
                                  filename="a.pdf", content_b64=content, kind="agreement", title="RoE"),
                   403, "forbidden")
      self.refused(self.create(actor=actor, document_refs=["x", "y"]), 403, "forbidden")
      self.refused(self.call_json("revoke_engagement", actor=actor, tenant_id=self.tenant,
                                  engagement_id=engagement["engagementId"], reason="x"), 403, "forbidden")
    self.assertEqual(len([ref for ref in self.documents.envelopes if ref != "doc-fixture"]), 2)

  def test_upload_works_with_pentesting_off_and_refuses_bad_files_and_labels(self):
    self.assertTrue(self.plugin.update_tenant_allow_pentester(self.actor, self.tenant, False)["success"])
    self.assertTrue(self.create()["success"])
    content = base64.b64encode(PDF).decode("ascii")
    self.refused(self.call_json("upload_engagement_document", actor=self.actor, tenant_id=self.tenant,
                                filename="a.txt", content_b64=base64.b64encode(b"plain").decode("ascii"),
                                kind="agreement", title="RoE"),
                 400, "bad_mime")
    before = len(self.documents.puts)
    for labels in ({"kind": "roe", "title": "RoE"}, {"kind": "agreement", "title": ""},
                   {"kind": "agreement"}, {"kind": "other", "title": "Note", "comment": "x" * 2001}):
      with self.subTest(labels=labels):
        self.refused(self.call_json("upload_engagement_document", actor=self.actor, tenant_id=self.tenant,
                                    filename="a.pdf", content_b64=content, **labels), 400, "document_invalid")
    self.assertEqual(len(self.documents.puts), before)

  def test_documents_must_be_this_tenants_this_creators_and_intact(self):
    tampered = self.upload()
    self.documents.envelopes[tampered]["sha256"] = "0" * 64
    wrong_kind = self.upload()
    self.documents.envelopes[wrong_kind]["kind"] = "redmesh_tenant_contract"
    job_level = self.upload()
    self.documents.envelopes[job_level]["kind"] = "redmesh_authorization_document"
    unlabelled = self.upload()
    self.documents.envelopes[unlabelled]["schema_version"] = "1.0"
    relabelled = self.upload()
    self.documents.envelopes[relabelled]["document_kind"] = "roe"
    same = self.upload()
    cases = {
      "other tenant": {"document_refs": [self.stored(tenant_id="tn_other")]},
      "other uploader": {"document_refs": [self.stored(uploaded_by="second-admin")]},
      "job-level authorization upload": {"document_refs": [job_level]},
      "tampered": {"document_refs": [tampered]},
      "wrong kind": {"document_refs": [wrong_kind]},
      "an envelope written before RM-107": {"document_refs": [unlabelled]},
      "a label edited in the store": {"document_refs": [relabelled]},
      "missing": {"document_refs": ["no-such-ref"]},
      "empty": {"document_refs": [""]},
      "the same reference twice": {"document_refs": [same, same]},
      "the same bytes twice": {"document_refs": [same, self.upload()]},
      "not a list": {"document_refs": same},
      "21 references": {"document_refs": ["ref-%d" % index for index in range(21)]},
    }
    for name, changes in cases.items():
      with self.subTest(name):
        self.refused(self.create(**changes), 400, "document_invalid")
    self.assertEqual(self.events, [])

  def test_no_document_is_read_before_authorization(self):
    reads = []
    original = self.documents.get
    self.documents.get = lambda ref: reads.append(ref) or original(ref)
    self.refused(self.create(actor={"account_id": "viewer"}), 403, "forbidden")
    self.refused(self.create(actor={"account_id": "stranger"}), 404, "not_found")
    self.assertEqual(reads, [])

  def test_an_engagement_needs_no_document(self):
    created = self.create(document_refs=[])
    self.assertTrue(created["success"], created)
    self.assertEqual(created["data"]["documents"], [])

  def test_a_tenant_without_a_contract_uploads_and_creates_nothing(self):
    for key, row in self.storage.data.items():
      if isinstance(row, dict) and row.get("tenant_id") == self.tenant and row.get("kind") in ("tenant", "receipt"):
        row.pop("legal", None), row.pop("contract", None)
    before = len(self.documents.puts)
    self.refused(self.call_json("upload_engagement_document", actor=self.actor, tenant_id=self.tenant,
                                filename="a.pdf", content_b64=base64.b64encode(PDF).decode("ascii"),
                                kind="agreement", title="RoE"), 400, "contract_required")
    self.refused(self.create(document_refs=[]), 400, "contract_required")
    self.assertEqual(len(self.documents.puts), before)

  def test_store_outage_is_unavailable(self):
    refs = [self.upload(), self.upload(PNG, "roe.png")]
    self.documents.fail = True
    self.refused(self.create(document_refs=refs), 503, "unavailable")

  def test_download_refuses_a_file_that_no_longer_matches_the_record(self):
    engagement = self.create()["data"]
    ref = json.loads(json.dumps(self.plugin._call_tenant_administration(
      "engagement_document_ref", self.actor, tenant_id=self.tenant,
      engagement_id=engagement["engagementId"], document_id="ed_1")["data"]))
    self.documents.envelopes[ref["ref"]]["content_b64"] = base64.b64encode(PNG + b"x").decode("ascii")
    self.refused(self.call_json("download_engagement_document", actor=self.actor, tenant_id=self.tenant,
                                engagement_id=engagement["engagementId"], document_id="ed_1"),
                 409, "document_integrity")

  def test_create_and_revoke_are_audited_once(self):
    request = str(uuid4())
    refs = [self.upload(), self.upload(PNG, "roe.png")]
    engagement = self.create(request_id=request, document_refs=refs)["data"]
    self.assertTrue(self.create(request_id=request, document_refs=refs)["success"])
    for _ in range(2):
      revoked = self.call_json("revoke_engagement", actor=self.actor,
                               tenant_id=self.tenant, engagement_id=engagement["engagementId"], reason="Done")
      self.assertTrue(revoked["success"], revoked)
    self.assertEqual(self.events, [
      ("engagement_created", {"tenant_id": self.tenant, "engagement_id": engagement["engagementId"],
                              "engagement_hash": engagement["engagementHash"], "actor": "creator"}),
      ("engagement_revoked", {"tenant_id": self.tenant, "engagement_id": engagement["engagementId"],
                              "engagement_hash": engagement["engagementHash"], "actor": "creator"}),
    ])

  def test_capability_status_advertises_engagements(self):
    self.assertEqual(self.plugin.get_capability_status()["engagements"], {"enabled": True, "schema": 2})

if __name__ == "__main__":
  unittest.main()
