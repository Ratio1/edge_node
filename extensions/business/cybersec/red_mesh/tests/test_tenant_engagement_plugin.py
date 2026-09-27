"""RM-095 phase 2: engagement endpoints through real plugin signatures, documents and CStore adapters."""
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


class _SharedRepository:
  """What `upload_authorization` writes through, backed by the plugin's document store."""

  def __init__(self, documents):
    self.documents = documents

  def put_json(self, envelope, **kwargs):
    return self.documents.put(envelope)


class TestTenantEngagementPlugin(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    from extensions.business.cybersec.red_mesh.services.authorization_upload import store_authorization_document
    cls.Plugin = PentesterApi01Plugin
    cls.store_authorization_document = staticmethod(store_authorization_document)

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
    asset = self.call_json("create_tenant_asset", actor=self.actor, tenant_id=self.tenant, request_id=str(uuid4()),
                           display_name="Edge", target={"kind": "network", "address": "192.0.2.10"},
                           authorized_ports="443")
    self.asset = asset["data"]["assetId"]

  def call_json(self, method, **body):
    endpoint = getattr(self.plugin, method)
    fields = {parameter.name: (parameter.annotation, parameter.default)
              for parameter in inspect.signature(endpoint).parameters.values()}
    model = create_model("EngagementRequest", **fields)
    return endpoint(**model.model_validate_json(json.dumps(body)).model_dump())

  def upload(self, raw=PDF, filename="authorization.pdf", uploaded_by="creator", tenant_id=None):
    """Store an envelope exactly as the `upload_authorization` endpoint does."""
    return self.store_authorization_document(
      filename=filename, content_b64=base64.b64encode(raw).decode("ascii"),
      artifact_repo=_SharedRepository(self.documents), uploaded_by=uploaded_by,
      tenant_id=tenant_id or self.tenant).cid

  def create(self, actor=None, **changes):
    body = {"actor": actor or self.actor, "tenant_id": self.tenant, "request_id": str(uuid4()),
            "display_name": "Q4", "kind": "continuous", "valid_from": "2026-10-01T00:00:00Z",
            "valid_until": "2027-10-01T00:00:00Z", "roe": {}, "context": {"client_name": "Example"},
            "assets": [{"asset_id": self.asset, "authorized_tests": ["service_info_common"]}],
            "authorized_signer_name": "Ana Pop", "authorized_signer_role": "CISO"}
    body.update(changes)
    if "roe_document_ref" not in body:
      body["roe_document_ref"] = self.upload(PNG, "roe.png")
    if "authorization_document_ref" not in body:
      body["authorization_document_ref"] = self.upload()
    return self.call_json("create_engagement", **body)

  def refused(self, result, status, error):
    self.assertFalse(result["success"], result)
    self.assertEqual((result["status_code"], result["error"]), (status, error))

  def test_upload_create_download_chain(self):
    created = self.create()
    self.assertTrue(created["success"], created)
    engagement = created["data"]
    self.assertEqual(engagement["roeDocument"]["mime"], "image/png")
    self.assertEqual(engagement["authorizationDocument"]["signerRole"], "CISO")
    for actor in (self.actor, {"account_id": "platform-pentester"}):
      downloaded = self.call_json("download_engagement_document", actor=actor, tenant_id=self.tenant,
                                  engagement_id=engagement["engagementId"], document="authorization")
      self.assertTrue(downloaded["success"], downloaded)
      self.assertEqual(base64.b64decode(downloaded["data"]["content_b64"]), PDF)
      self.assertEqual(downloaded["data"]["sha256"], engagement["authorizationDocument"]["sha256"])
    self.refused(self.call_json("download_engagement_document", actor={"account_id": "viewer"},
                                tenant_id=self.tenant, engagement_id=engagement["engagementId"], document="roe"),
                 403, "forbidden")
    listed = self.call_json("list_engagements", actor={"account_id": "viewer"}, tenant_id=self.tenant, active=True)
    self.assertEqual([row["engagementId"] for row in listed["data"]["engagements"]], [engagement["engagementId"]])

  def test_documents_must_be_this_tenants_this_creators_and_intact(self):
    tampered = self.upload()
    self.documents.envelopes[tampered]["sha256"] = "0" * 64
    wrong_kind = self.upload()
    self.documents.envelopes[wrong_kind]["kind"] = "redmesh_tenant_contract"
    cases = {
      "other tenant": {"authorization_document_ref": self.upload(tenant_id="tn_other")},
      "other uploader": {"authorization_document_ref": self.upload(uploaded_by="platform-pentester")},
      "authorization not a PDF": {"authorization_document_ref": self.upload(PNG, "auth.png")},
      "tampered": {"authorization_document_ref": tampered},
      "wrong kind": {"roe_document_ref": wrong_kind},
      "missing": {"roe_document_ref": "no-such-ref"},
      "empty": {"roe_document_ref": ""},
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

  def test_store_outage_is_unavailable(self):
    refs = {"roe_document_ref": self.upload(), "authorization_document_ref": self.upload()}
    self.documents.fail = True
    self.refused(self.create(**refs), 503, "unavailable")

  def test_download_refuses_a_file_that_no_longer_matches_the_record(self):
    engagement = self.create()["data"]
    ref = json.loads(json.dumps(self.plugin._call_tenant_administration(
      "engagement_document_ref", self.actor, tenant_id=self.tenant,
      engagement_id=engagement["engagementId"], document="roe")["data"]))
    self.documents.envelopes[ref["ref"]]["content_b64"] = base64.b64encode(PNG + b"x").decode("ascii")
    self.refused(self.call_json("download_engagement_document", actor=self.actor, tenant_id=self.tenant,
                                engagement_id=engagement["engagementId"], document="roe"),
                 409, "document_integrity")

  def test_create_and_revoke_are_audited_once(self):
    request = str(uuid4())
    refs = {"roe_document_ref": self.upload(), "authorization_document_ref": self.upload()}
    engagement = self.create(request_id=request, **refs)["data"]
    self.assertTrue(self.create(request_id=request, **refs)["success"])
    for _ in range(2):
      revoked = self.call_json("revoke_engagement", actor={"account_id": "platform-pentester"},
                               tenant_id=self.tenant, engagement_id=engagement["engagementId"], reason="Done")
      self.assertTrue(revoked["success"], revoked)
    self.assertEqual(self.events, [
      ("engagement_created", {"tenant_id": self.tenant, "engagement_id": engagement["engagementId"],
                              "engagement_hash": engagement["engagementHash"], "actor": "creator"}),
      ("engagement_revoked", {"tenant_id": self.tenant, "engagement_id": engagement["engagementId"],
                              "engagement_hash": engagement["engagementHash"], "actor": "platform-pentester"}),
    ])

  def test_capability_status_advertises_engagements(self):
    self.assertEqual(self.plugin.get_capability_status()["engagements"], {"enabled": True})

if __name__ == "__main__":
  unittest.main()
