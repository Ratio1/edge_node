"""RM-095 phase 2: engagements through the real administration service, identity and CStore store."""
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from .test_tenant_administration import FakeAdministrationStore
from .contract_fixture import CONTRACT_SHA256, contract_terms
from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader

SHA_ROE, SHA_AUTH = "1" * 64, "2" * 64


def doc(sha256, ref, uploaded_by="creator", mime="application/pdf"):
  return {"store": "r1fs", "ref": ref, "sha256": sha256, "filename": ref + ".pdf", "mime": mime,
          "size_bytes": 2048, "uploaded_at": "2026-09-28T09:00:00Z", "uploaded_by": uploaded_by}


class TestTenantEngagements(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.owner = FakeAdministrationStore()
    self.store = CstoreTenantAdministrationStore(self.owner, "deployment")
    self.service = TenantAdministrationService(CstoreAuthAccountReader(self.owner), self.store)
    self.actor = {"account_id": "creator"}
    self.tenant = self.new_tenant("tenant", contract=True)
    self.network = self.asset({"kind": "network", "address": "192.0.2.10"}, authorized_ports="22,443")
    self.webapp = self.asset({"kind": "webapp", "url": "https://app.example.com/",
                              "allowedPathPrefix": "/"})
    self.request = str(uuid4())

  def new_tenant(self, domain, contract):
    request, admin = str(uuid4()), "initial" if domain == "tenant" else "initial-" + domain
    self.owner.account(admin)
    prepared = self.service.prepare_tenant(self.actor, request, domain.title(), domain, admin, **contract_terms())
    self.assertTrue(prepared["success"], prepared)
    tenant = prepared["data"]["tenantId"]
    self.owner.grant(admin, tenant)
    self.assertTrue(self.service.activate_tenant(self.actor, request)["success"])
    if not contract:
      # A tenant created before contracts were required: its record and receipt carry no terms.
      for row in self.owner.data.values():
        if isinstance(row, dict) and row.get("tenant_id") == tenant:
          row.pop("legal", None), row.pop("contract", None)
    return tenant

  def asset(self, target, tenant=None, **extra):
    result = self.service.create_tenant_asset(self.actor, tenant or self.tenant, str(uuid4()), "Asset",
                                              target, **extra)
    self.assertTrue(result["success"], result)
    return result["data"]["assetId"]

  def fields(self, **changes):
    fields = {
      "actor": self.actor, "tenant_id": self.tenant, "request_id": self.request,
      "display_name": " Q4 external ", "kind": "point-in-time",
      "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-10-31T00:00:00+00:00",
      "roe": {"authenticated_action": True}, "context": {"client_name": "Example", "asset_exposure": "external"},
      "assets": [{"asset_id": self.network, "authorized_tests": ["service_info_common", "active_auth"]},
                 {"asset_id": self.webapp, "authorized_tests": ["graybox"]}],
      "roe_document": doc(SHA_ROE, "roe"), "authorization_document": doc(SHA_AUTH, "auth"),
      "signer_name": "Ana Pop", "signer_role": "CISO",
    }
    fields.update(changes)
    return fields

  def create(self, **changes):
    return self.service.create_engagement(**self.fields(**changes))

  @staticmethod
  def view(result):
    """The engagement DTO without the per-call `replayed` flag."""
    return {key: value for key, value in result["data"].items() if key != "replayed"}

  def refused(self, result, status, error):
    self.assertFalse(result["success"], result)
    self.assertEqual((result["status_code"], result["error"]), (status, error))

  def test_created_engagement_locks_assets_scope_and_hash(self):
    result = self.create()
    self.assertTrue(result["success"], result)
    engagement = result["data"]
    self.assertEqual(engagement["engagementId"], "en_" + self.request)
    self.assertEqual(engagement["displayName"], "Q4 external")
    self.assertEqual(engagement["validUntil"], "2026-10-31T00:00:00Z")
    self.assertEqual(engagement["contractSha256"], CONTRACT_SHA256)
    self.assertEqual(engagement["roe"], {"authenticated_action": True, "stateful_probes_allowed": False,
                                         "ics_safe_mode_required": True})
    self.assertEqual(engagement["anchor"], {"status": "pending"})
    self.assertRegex(engagement["engagementHash"], r"^[a-f0-9]{64}$")
    network, webapp = sorted(engagement["assets"], key=lambda item: item["kind"])
    self.assertEqual(network["authorizedPorts"], "22,443")  # seeded from the asset row
    self.assertEqual(network["authorizedScanModes"], ["connect"])
    self.assertEqual(network["authorizedTests"], ["active_auth", "service_info_common"])
    self.assertNotIn("authorizedPorts", webapp)
    self.assertEqual(engagement["authorizationDocument"]["signerName"], "Ana Pop")
    self.assertEqual([item["assetId"] for item in engagement["assets"]],
                     sorted(item["assetId"] for item in engagement["assets"]))

  def test_the_dto_never_carries_a_document_or_contract_reference(self):
    engagement = self.create()["data"]
    listed = self.service.list_engagements({"account_id": "initial"}, self.tenant)["data"]["engagements"]
    for view in (engagement, listed[0]):
      text = json.dumps(view)
      self.assertNotIn('"ref"', text)
      self.assertNotIn('"store"', text)
      self.assertNotIn("r1fs", text)

  def test_explicit_ports_and_scan_modes_override_the_seed(self):
    assets = [{"asset_id": self.network, "authorized_ports": "80, 443", "authorized_scan_modes": ["syn", "connect"],
               "authorized_tests": ["service_info_common"]}]
    engagement = self.create(assets=assets)["data"]
    self.assertEqual(engagement["assets"][0]["authorizedPorts"], "80,443")
    self.assertEqual(engagement["assets"][0]["authorizedScanModes"], ["connect", "syn"])

  def test_scan_mode_order_does_not_change_the_request(self):
    assets = lambda modes: [{"asset_id": self.network, "authorized_scan_modes": modes,
                             "authorized_tests": ["active_auth"]}]
    first = self.view(self.create(assets=assets(["syn", "connect"])))
    self.assertEqual(self.view(self.create(assets=assets(["connect", "syn"]))), first)
    self.refused(self.create(request_id=str(uuid4()), assets=assets([["connect"]])), 400, "engagement_asset_invalid")

  def test_a_network_asset_needs_a_port_scope(self):
    bare = self.asset({"kind": "network", "address": "192.0.2.11"})
    self.refused(self.create(assets=[{"asset_id": bare, "authorized_tests": ["service_info_common"]}]),
                 400, "ports_required")
    self.assertTrue(self.create(assets=[{"asset_id": bare, "authorized_ports": "443",
                                         "authorized_tests": ["service_info_common"]}])["success"])

  def test_asset_refusals(self):
    other_tenant = self.new_tenant("other", contract=True)
    foreign = self.asset({"kind": "network", "address": "192.0.2.12"}, tenant=other_tenant, authorized_ports="22")
    model = self.asset({"kind": "model", "adapter": "openai_compatible",
                        "endpointUrl": "https://llm.example.com/v1/chat/completions", "model": "m"})
    cases = [
      ([{"asset_id": foreign, "authorized_tests": ["service_info_common"]}], "engagement_asset_invalid"),
      ([{"asset_id": "as_" + str(uuid4()), "authorized_tests": ["service_info_common"]}], "engagement_asset_invalid"),
      ([{"asset_id": model, "authorized_tests": []}], "tests_invalid"),
      ([{"asset_id": model, "authorized_tests": ["graybox"]}], "engagement_asset_invalid"),
      ([{"asset_id": self.webapp, "authorized_tests": ["service_info_common"]}], "tests_invalid"),
      ([{"asset_id": self.network, "authorized_tests": ["graybox"]}], "tests_invalid"),
      ([{"asset_id": self.network, "authorized_tests": ["nope"]}], "tests_invalid"),
      ([{"asset_id": self.webapp, "authorized_ports": "80", "authorized_tests": ["graybox"]}], "engagement_asset_invalid"),
      ([{"asset_id": self.webapp, "authorized_scan_modes": ["connect"], "authorized_tests": ["graybox"]}],
       "engagement_asset_invalid"),
      ([{"asset_id": self.network, "authorized_scan_modes": ["udp"], "authorized_tests": ["active_auth"]}],
       "engagement_asset_invalid"),
      ([{"asset_id": self.network, "authorized_scan_modes": [], "authorized_tests": ["active_auth"]}],
       "engagement_asset_invalid"),
      ([{"asset_id": self.network, "authorized_tests": ["active_auth"]}] * 2, "engagement_asset_invalid"),
      ([{"asset_id": self.network, "authorized_tests": ["active_auth"], "target": {}}], "engagement_asset_invalid"),
      ([], "engagement_asset_invalid"),
    ]
    for assets, error in cases:
      with self.subTest(error=error, assets=assets):
        self.refused(self.create(request_id=str(uuid4()), assets=assets), 400, error)
    self.service.update_tenant_asset(self.actor, self.tenant, self.network,
      self.service.get_tenant_asset(self.actor, self.tenant, self.network)["data"]["asset"]["version"],
      "Asset", {"kind": "network", "address": "192.0.2.10"}, False)
    self.refused(self.create(request_id=str(uuid4()),
                             assets=[{"asset_id": self.network, "authorized_tests": ["active_auth"]}]),
                 400, "engagement_asset_invalid")

  def test_request_value_refusals(self):
    cases = [
      ({"kind": "forever"}, "invalid_request"), ({"display_name": ""}, "invalid_request"),
      ({"valid_until": "2026-09-01T00:00:00Z"}, "window_invalid"), ({"valid_from": "tomorrow"}, "window_invalid"),
      ({"roe": {"dos_allowed": True}}, "roe_invalid"), ({"roe": {"authenticated_action": "yes"}}, "roe_invalid"),
      ({"context": {"client_name": None}}, "context_invalid"), ({"signer_name": ""}, "signer_required"),
      ({"roe_document": doc(SHA_ROE, "roe", uploaded_by="someone")}, "document_invalid"),
      ({"authorization_document": {"ref": "auth"}}, "document_invalid"),
      ({"supersedes": "en_nope"}, "supersedes_invalid"),
      ({"supersedes": "en_" + str(uuid4())}, "supersedes_invalid"),
      ({"request_id": "not-a-uuid"}, "invalid_request"),
    ]
    for changes, error in cases:
      with self.subTest(error=error, changes=changes):
        self.refused(self.create(**{"request_id": str(uuid4()), **changes}), 400, error)

  def test_replay_returns_the_record_without_a_write_even_after_an_asset_edit(self):
    first = self.create()
    self.assertIs(first["data"]["replayed"], False)
    first = self.view(first)
    version = self.service.get_tenant_asset(self.actor, self.tenant, self.network)["data"]["asset"]["version"]
    self.assertTrue(self.service.update_tenant_asset(self.actor, self.tenant, self.network, version, "Asset",
                                                     {"kind": "network", "address": "192.0.2.99"}, True)["success"])
    writes = len(self.owner.writes)
    replayed = self.create()
    self.assertIs(replayed["data"]["replayed"], True)
    self.assertEqual(self.view(replayed), first)
    # A re-upload of the same bytes has a new reference but is the same creation.
    self.assertEqual(self.view(self.create(roe_document=doc(SHA_ROE, "roe-again"))), first)
    self.assertEqual(len(self.owner.writes), writes)
    self.refused(self.create(display_name="Other"), 409, "conflict")
    self.refused(self.create(roe_document=doc("3" * 64, "roe")), 409, "conflict")

  def test_roles(self):
    self.owner.account("platform-pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.owner.account("scoped-pentester", memberships=[{"role": "super_pentester", "tenant_id": self.tenant}])
    self.owner.account("pentester", memberships=[{"role": "tenant_pentester", "tenant_id": self.tenant}])
    self.owner.account("viewer", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    other = self.new_tenant("other", contract=True)
    self.owner.account("elsewhere", memberships=[{"role": "super_pentester", "tenant_id": other}])
    for account in ("platform-pentester", "scoped-pentester"):
      docs = {"roe_document": doc(SHA_ROE, "roe", account), "authorization_document": doc(SHA_AUTH, "auth", account)}
      result = self.create(actor={"account_id": account}, request_id=str(uuid4()), **docs)
      self.assertTrue(result["success"], (account, result))
    for account in ("pentester", "viewer", "initial"):
      self.refused(self.create(actor={"account_id": account}, request_id=str(uuid4())), 403, "forbidden")
    self.refused(self.create(actor={"account_id": "elsewhere"}, request_id=str(uuid4())), 404, "not_found")
    engagement = self.create()["data"]["engagementId"]
    for account in ("pentester", "viewer"):
      self.refused(self.service.revoke_engagement({"account_id": account}, self.tenant, engagement, "x"),
                   403, "forbidden")
      self.refused(self.service.engagement_document_ref({"account_id": account}, self.tenant, engagement, "roe"),
                   403, "forbidden")
      self.assertTrue(self.service.get_engagement({"account_id": account}, self.tenant, engagement)["success"])
    self.refused(self.service.get_engagement({"account_id": "elsewhere"}, self.tenant, engagement), 404, "not_found")
    self.assertTrue(self.service.engagement_document_ref({"account_id": "platform-pentester"}, self.tenant, engagement, "roe")["success"])
    viewer = self.service.get_engagement({"account_id": "viewer"}, self.tenant, engagement)["data"]
    self.assertEqual((viewer["canRevokeEngagements"], viewer["canDownloadDocuments"]), (False, False))
    listed = self.service.list_engagements({"account_id": "platform-pentester"}, self.tenant)["data"]
    self.assertEqual((listed["canCreateEngagements"], listed["canRevokeEngagements"]), (True, True))

  def test_document_ref_is_authorized_before_the_lookup(self):
    self.owner.account("viewer", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    missing = "en_" + str(uuid4())
    self.refused(self.service.engagement_document_ref({"account_id": "viewer"}, self.tenant, missing, "roe"),
                 403, "forbidden")
    self.refused(self.service.engagement_document_ref(self.actor, self.tenant, missing, "roe"), 404, "not_found")
    engagement = self.create()["data"]["engagementId"]
    self.refused(self.service.engagement_document_ref(self.actor, self.tenant, engagement, "contract"),
                 400, "invalid_request")
    ref = self.service.engagement_document_ref(self.actor, self.tenant, engagement, "authorization")["data"]
    self.assertEqual((ref["store"], ref["ref"], ref["sha256"]), ("r1fs", "auth", SHA_AUTH))

  def test_a_tenant_created_before_contracts_still_creates_engagements(self):
    legacy = self.new_tenant("legacy", contract=False)
    asset = self.asset({"kind": "network", "address": "192.0.2.20"}, tenant=legacy, authorized_ports="22")
    result = self.create(tenant_id=legacy, assets=[{"asset_id": asset, "authorized_tests": ["active_auth"]}])
    self.assertTrue(result["success"], result)
    self.assertIsNone(result["data"]["contractSha256"])

  def test_supersedes_links_without_revoking(self):
    first = self.create()["data"]["engagementId"]
    second = self.create(request_id=str(uuid4()), supersedes=first)["data"]
    self.assertEqual(second["supersedes"], first)
    self.assertTrue(self.service.get_engagement(self.actor, self.tenant, first)["data"]["engagement"]["active"])
    self.refused(self.create(request_id=first[3:], supersedes=first), 409, "conflict")

  def test_revoke_is_final_and_idempotent(self):
    engagement = self.create()["data"]
    self.refused(self.service.revoke_engagement(self.actor, self.tenant, engagement["engagementId"], " "),
                 400, "invalid_request")
    revoked = self.service.revoke_engagement(self.actor, self.tenant, engagement["engagementId"], " Scope withdrawn ")
    self.assertTrue(revoked["success"], revoked)
    self.assertFalse(revoked["data"]["active"])
    self.assertEqual((revoked["data"]["revokedBy"], revoked["data"]["revokeReason"]), ("creator", "Scope withdrawn"))
    self.assertEqual(revoked["data"]["engagementHash"], engagement["engagementHash"])
    self.assertIs(revoked["data"]["replayed"], False)
    writes = len(self.owner.writes)
    again = self.service.revoke_engagement(self.actor, self.tenant, engagement["engagementId"], "again")
    self.assertIs(again["data"]["replayed"], True)
    self.assertEqual(self.view(again), self.view(revoked))
    self.assertEqual(len(self.owner.writes), writes)
    self.refused(self.service.revoke_engagement(self.actor, self.tenant, "en_" + str(uuid4()), "x"), 404, "not_found")

  def test_list_is_newest_first_and_filters_on_active(self):
    with patch("extensions.business.cybersec.red_mesh.tenancy.administration.datetime") as clock:
      ids = []
      for day in (1, 3, 2):
        clock.now.return_value = datetime(2026, 9, day, tzinfo=timezone.utc)
        ids.append(self.create(request_id=str(uuid4()))["data"]["engagementId"])
      self.service.revoke_engagement(self.actor, self.tenant, ids[0], "done")
    listed = self.service.list_engagements(self.actor, self.tenant)["data"]["engagements"]
    self.assertEqual([row["engagementId"] for row in listed], [ids[1], ids[2], ids[0]])
    active = self.service.list_engagements(self.actor, self.tenant, active=True)["data"]["engagements"]
    self.assertEqual([row["engagementId"] for row in active], [ids[1], ids[2]])
    self.refused(self.service.list_engagements(self.actor, self.tenant, active="yes"), 400, "invalid_request")


if __name__ == "__main__":
  unittest.main()
