"""RM-095 phase 3, RM-107: launch admission reads the engagement through the real service and CStore store."""
from datetime import datetime, timezone
import unittest
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied, TenantStoreError

from .contract_fixture import CONTRACT_PDF, CONTRACT_SHA256, LEGAL

from . import test_tenant_engagements as engagements

INSIDE = datetime(2026, 10, 15, tzinfo=timezone.utc)


class TestTenantEngagementLaunch(unittest.TestCase):
  # Borrowed, not inherited, so the phase 2 tests are not collected twice.
  setUp_engagements = engagements.TestTenantEngagements.setUp
  new_tenant = engagements.TestTenantEngagements.new_tenant
  fields = engagements.TestTenantEngagements.fields
  create = engagements.TestTenantEngagements.create

  def setUp(self):
    self.setUp_engagements()
    self.service.clock = lambda: INSIDE
    self.service.configured_peers_reader = lambda: ["node-a"]
    self.assertTrue(self.service.set_tenant_node_assignment(self.actor, self.tenant, "node-a", True)["success"])
    created = self.create()
    self.assertTrue(created["success"], created)
    self.engagement = created["data"]

  def admit(self, asset="ea_1", engagement_id=None, **kwargs):
    return self.service.resolve_execution_admission(
      self.actor, self.tenant, engagement_id or self.engagement["engagementId"], asset, **kwargs)

  def denied(self, status, error, **kwargs):
    with self.assertRaises(AdministrationDenied) as caught:
      self.admit(**kwargs)
    self.assertEqual((caught.exception.status_code, caught.exception.error), (status, error))

  def test_network_admission_carries_the_engagement_facts_and_its_port_scope(self):
    context = self.admit().to_dict()
    self.assertEqual(context["asset_authorized_ports"], "22,443")
    # RM-107: the target is the engagement entry's.
    self.assertEqual((context["engagement_id"], context["engagement_asset_id"], context["engagement_hash"]),
                     (self.engagement["engagementId"], "ea_1", self.engagement["engagementHash"]))
    self.assertEqual(context["asset_target"], engagements.NETWORK)
    self.assertEqual(context["asset_target_digest"], self.engagement["assets"][0]["targetDigest"])
    self.assertEqual(context["engagement"], {
      "engagement_id": self.engagement["engagementId"], "engagement_hash": self.engagement["engagementHash"],
      "contract_sha256": CONTRACT_SHA256,
      "authorized_tests": ["active_auth", "service_info_common"], "authorized_scan_modes": ["connect"],
      "roe": {"authenticated_action": True, "stateful_probes_allowed": False, "ics_safe_mode_required": True},
      "context": self.engagement["context"],
      # RM-107: the signed basis is the tenant contract and its legal signer; the consents are
      # named by the titles of the engagement's third-party consent documents.
      "authorization": {
        "document_cid": "", "document_thumbnail_cid": "", "authorized_signer_name": LEGAL["signer_name"],
        "authorized_signer_role": LEGAL["signer_role"], "third_party_auth_cids": ["Hosting consent"],
        "document_filename": "contract.pdf", "document_mime": "application/pdf",
        "document_size_bytes": len(CONTRACT_PDF), "document_sha256": CONTRACT_SHA256,
        "document_uploaded_at": "2026-09-27T12:00:00Z"},
    })

  def test_an_engagement_without_consents_names_none(self):
    self.request = str(uuid4())
    bare = self.create(documents=[])["data"]
    authorization = self.admit(engagement_id=bare["engagementId"]).to_dict()["engagement"]["authorization"]
    self.assertEqual(authorization["third_party_auth_cids"], [])
    self.assertEqual(authorization["document_sha256"], CONTRACT_SHA256)

  def test_a_tenant_contract_that_no_longer_matches_fails_closed(self):
    # Tenant and receipt edited together, so the receipt binding holds and the engagement check is
    # the one that refuses.
    for key, row in self.owner.data.items():
      if isinstance(row, dict) and row.get("kind") in ("tenant", "receipt") and row.get("tenant_id") == self.tenant:
        self.owner.data[key] = {**row, "contract": {**row["contract"], "sha256": "9" * 64}}
    with self.assertRaises(TenantStoreError):
      self.admit()

  def test_webapp_admission_has_no_port_scope_or_scan_modes(self):
    context = self.admit(asset="ea_2").to_dict()
    self.assertNotIn("asset_authorized_ports", context)
    self.assertNotIn("authorized_scan_modes", context["engagement"])
    self.assertEqual(context["engagement"]["authorized_tests"], ["graybox"])

  def test_the_binding_names_the_engagement_asset_and_keeps_policy_out(self):
    binding = self.admit().build_binding("launcher", ["node-a"]).to_dict()
    self.assertEqual(binding["schema_version"], 2)
    self.assertEqual((binding["engagement_id"], binding["engagement_asset_id"], binding["engagement_hash"]),
                     (self.engagement["engagementId"], "ea_1", self.engagement["engagementHash"]))
    self.assertNotIn("asset_id", binding)
    self.assertFalse(set(binding) & {"engagement", "asset_authorized_ports"})

  def test_a_model_asset_is_admitted_with_its_question_sets(self):
    context = self.admit(asset="ea_3").to_dict()
    self.assertEqual(context["asset_target"]["kind"], "model")
    self.assertEqual(context["engagement"]["authorized_tests"], ["prompt_injection_v1"])
    self.assertNotIn("asset_authorized_ports", context)

  def test_refusals(self):
    self.denied(400, "invalid_request", engagement_id="en_not-a-uuid")
    self.denied(404, "engagement_not_found", engagement_id="en_" + str(uuid4()))
    for bad in ("ea_0", "ea_01", "as_" + str(uuid4()), "", 1):
      with self.subTest(asset=bad):
        self.denied(400, "invalid_request", asset=bad)
    self.denied(400, "engagement_asset_not_locked", asset="ea_4")

  def test_window_bounds(self):
    for instant, allowed in ((datetime(2026, 10, 1, tzinfo=timezone.utc), True),
                             (datetime(2026, 9, 30, 23, 59, 59, tzinfo=timezone.utc), False),
                             (datetime(2026, 10, 30, 23, 59, 59, tzinfo=timezone.utc), True),
                             (datetime(2026, 10, 31, tzinfo=timezone.utc), False)):
      with self.subTest(instant=instant):
        self.service.clock = lambda instant=instant: instant
        if allowed:
          self.assertIn("engagement", self.admit().to_dict())
        else:
          self.denied(400, "engagement_expired")

  def test_a_revoked_engagement_is_refused(self):
    self.assertTrue(self.service.revoke_engagement(self.actor, self.tenant, self.engagement["engagementId"],
                                                   "Contract ended")["success"])
    self.denied(400, "engagement_revoked")

  def test_an_engagement_of_another_tenant_is_not_found(self):
    other = self.new_tenant("other", contract=True)
    self.request = str(uuid4())
    foreign = self.service.create_engagement(**self.fields(tenant_id=other))
    self.assertTrue(foreign["success"], foreign)
    self.denied(404, "engagement_not_found", engagement_id=foreign["data"]["engagementId"])


if __name__ == "__main__":
  unittest.main()
