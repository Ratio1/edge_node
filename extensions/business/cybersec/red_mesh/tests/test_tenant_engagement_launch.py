"""RM-095 phase 3, RM-107: launch admission reads the engagement through the real service and CStore store."""
from datetime import datetime, timezone
import unittest
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied, TenantStoreError

from .asset_fixture import pick, register_asset
from .contract_fixture import CONTRACT_PDF, CONTRACT_SHA256, LEGAL

from . import test_tenant_engagements as engagements

INSIDE = datetime(2026, 10, 15, tzinfo=timezone.utc)


class TestTenantEngagementLaunch(unittest.TestCase):
  # Borrowed, not inherited, so the phase 2 tests are not collected twice.
  setUp_engagements = engagements.TestTenantEngagements.setUp
  new_tenant = engagements.TestTenantEngagements.new_tenant
  fields = engagements.TestTenantEngagements.fields
  default_assets = engagements.TestTenantEngagements.default_assets
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

  def test_network_admission_carries_the_engagement_facts(self):
    context = self.admit().to_dict()
    self.assertNotIn("asset_authorized_ports", context)
    # RM-107: the target is the engagement entry's.
    self.assertEqual((context["engagement_id"], context["engagement_asset_id"], context["engagement_hash"]),
                     (self.engagement["engagementId"], "ea_1", self.engagement["engagementHash"]))
    self.assertEqual(context["asset_target"], engagements.NETWORK)
    self.assertEqual(context["asset_target_digest"], self.engagement["assets"][0]["targetDigest"])
    self.assertEqual(context["engagement"], {
      "engagement_id": self.engagement["engagementId"], "engagement_hash": self.engagement["engagementHash"],
      "contract_sha256": CONTRACT_SHA256, "authorized_ports": "all", "authorized_tests": "all",
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
    self.assertFalse(set(context["engagement"]) & {"roe", "authorized_scan_modes", "allowed_run_modes"})

  def test_the_binding_names_the_engagement_asset_and_keeps_policy_out(self):
    binding = self.admit().build_binding("launcher", ["node-a"]).to_dict()
    self.assertEqual(binding["schema_version"], 2)
    self.assertEqual((binding["engagement_id"], binding["engagement_asset_id"], binding["engagement_hash"]),
                     (self.engagement["engagementId"], "ea_1", self.engagement["engagementHash"]))
    self.assertNotIn("asset_id", binding)
    self.assertFalse(set(binding) & {"engagement", "asset_authorized_ports"})

  def test_admission_carries_the_asset_environment_as_policy(self):
    # RM-131: the registered asset's environment; the binding never carries it.
    context = self.admit()
    self.assertEqual(context.to_dict()["asset_environment"], "dev")
    self.assertNotIn("asset_environment", context.build_binding("launcher", ["node-a"]).to_dict())
    # A row written before RM-131 (no environment) or a missing row is None, held to prod at launch.
    for key, row in list(self.owner.data.items()):
      if isinstance(row, dict) and row.get("asset_id") == self.net and "environment" in row:
        self.owner.data[key] = {name: value for name, value in row.items() if name != "environment"}
    self.assertIsNone(self.admit().to_dict()["asset_environment"])

  def test_the_context_refuses_an_unknown_environment(self):
    from extensions.business.cybersec.red_mesh.tenancy.execution import ResolvedExecutionContext
    value = self.admit().to_dict()
    for bad in ("production", "", 3):
      with self.subTest(bad=bad), self.assertRaises(ValueError):
        ResolvedExecutionContext({**value, "asset_environment": bad})
    # A context without the key (a caller that predates RM-131) still builds; the launch reads it as prod.
    value.pop("asset_environment")
    ResolvedExecutionContext(value)

  def test_admission_carries_the_scope_of_the_asset_it_targets_and_the_gate_holds_each_launch_to_it(self):
    # RM-277: two network assets of one engagement, each launch held to its own ports and tests.
    from unittest.mock import MagicMock
    from extensions.business.cybersec.red_mesh.services.launch_api import _launch_scope_error
    second = register_asset(self.service, self.actor, self.tenant, {"kind": "network", "address": "192.0.2.11"}, "Second host")
    created = self.create(request_id=str(uuid4()), assets=[
      dict(pick(self.net), authorized_ports=[[443, 443]]),
      dict(pick(second), authorized_ports=[[1, 1024]], authorized_tests=["web_discovery"]),
      dict(pick(self.web), authorized_tests=["graybox_injection"])])["data"]
    facts = {asset: self.admit(asset=asset, engagement_id=created["engagementId"]).to_dict()["engagement"]
             for asset in ("ea_1", "ea_2", "ea_3")}
    self.assertEqual([(facts[asset]["authorized_ports"], facts[asset]["authorized_tests"]) for asset in facts],
                     [([[443, 443]], "all"), ([[1, 1024]], ["web_discovery"]), ("all", ["graybox_injection"])])
    def gate(asset, port):
      context = self.admit(asset=asset, engagement_id=created["engagementId"])
      return _launch_scope_error(MagicMock(), context, facts[asset], scan_type="network", target="x",
                                 start_port=port, end_port=port, exceptions=[], comparison_ports=None,
                                 enabled_features=[])
    # Port 80 is inside the second host's range and outside the first host's; port 443 the other way round.
    self.assertEqual((gate("ea_1", 80)["ports"], gate("ea_2", 80)), ([[80, 80]], None))
    self.assertEqual((gate("ea_1", 443), gate("ea_2", 443)), (None, None))
    self.assertEqual(gate("ea_2", 2000)["ports"], [[2000, 2000]])

  def test_a_model_asset_is_admitted_with_its_question_sets(self):
    context = self.admit(asset="ea_3").to_dict()
    self.assertEqual(context["asset_target"]["kind"], "model")
    self.assertNotIn("asset_authorized_ports", context)

  def test_refusals(self):
    self.denied(400, "invalid_request", engagement_id="en_not-a-uuid")
    self.denied(404, "engagement_not_found", engagement_id="en_" + str(uuid4()))
    for bad in ("ea_0", "ea_01", "as_" + str(uuid4()), "", 1):
      with self.subTest(asset=bad):
        self.denied(400, "invalid_request", asset=bad)
    self.denied(400, "engagement_asset_not_locked", asset="ea_4")

  def test_window_bounds(self):
    # RM-248: before `valid_from` the refusal is `engagement_not_yet_valid`, not `engagement_expired`.
    for instant, allowed, error in ((datetime(2026, 10, 1, tzinfo=timezone.utc), True, None),
                                    (datetime(2026, 9, 30, 23, 59, 59, tzinfo=timezone.utc), False,
                                     "engagement_not_yet_valid"),
                                    (datetime(2026, 10, 30, 23, 59, 59, tzinfo=timezone.utc), True, None),
                                    (datetime(2026, 10, 31, tzinfo=timezone.utc), False, "engagement_expired")):
      with self.subTest(instant=instant):
        self.service.clock = lambda instant=instant: instant
        if allowed:
          self.assertIn("engagement", self.admit().to_dict())
        else:
          self.denied(400, error)

  def test_a_revoked_engagement_is_refused(self):
    self.assertTrue(self.service.revoke_engagement(self.actor, self.tenant, self.engagement["engagementId"],
                                                   "Contract ended")["success"])
    self.denied(400, "engagement_revoked")

  def test_a_suspended_engagement_is_refused_until_it_is_resumed(self):
    # RM-248
    engagement_id = self.engagement["engagementId"]
    self.assertTrue(self.service.suspend_engagement(self.actor, self.tenant, engagement_id, "Amended")["success"])
    self.denied(400, "engagement_suspended")
    self.assertTrue(self.service.resume_engagement(self.actor, self.tenant, engagement_id, "Signed")["success"])
    self.assertIn("engagement", self.admit().to_dict())

  def test_a_launch_before_valid_from_is_not_yet_valid_and_the_refusal_order_holds(self):
    # RM-248: revoked, not yet valid, expired, suspended.
    engagement_id = self.engagement["engagementId"]
    self.service.clock = lambda: datetime(2026, 9, 30, 23, 59, 59, tzinfo=timezone.utc)
    self.denied(400, "engagement_not_yet_valid")
    self.assertTrue(self.service.suspend_engagement(self.actor, self.tenant, engagement_id, "Hold")["success"])
    self.denied(400, "engagement_not_yet_valid")
    self.service.clock = lambda: datetime(2026, 10, 31, tzinfo=timezone.utc)
    self.denied(400, "engagement_expired")
    self.service.clock = lambda: INSIDE
    self.denied(400, "engagement_suspended")
    self.assertTrue(self.service.revoke_engagement(self.actor, self.tenant, engagement_id, "Done")["success"])
    self.denied(400, "engagement_revoked")

  def test_reauthorization_holds_only_a_new_pass_while_suspended(self):
    # RM-248: the current pass keeps its authority; the next one is held.
    engagement_id = self.engagement["engagementId"]
    binding = self.admit().build_binding("coordinator", ["node-a"])
    self.assertTrue(self.service.suspend_engagement(self.actor, self.tenant, engagement_id, "Hold")["success"])
    self.service.reauthorize_execution(binding, worker_node="node-a")
    with self.assertRaises(AdministrationDenied) as caught:
      self.service.reauthorize_execution(binding, worker_node="node-a", new_pass=True)
    self.assertEqual(caught.exception.error, "engagement_suspended")
    self.assertTrue(self.service.resume_engagement(self.actor, self.tenant, engagement_id, "Signed")["success"])
    self.service.reauthorize_execution(binding, worker_node="node-a", new_pass=True)
    self.assertIsNone(self.service.engagement_end_reason(self.tenant, engagement_id))

  def test_an_engagement_of_another_tenant_is_not_found(self):
    other = self.new_tenant("other", contract=True)
    self.request = str(uuid4())
    foreign = self.service.create_engagement(**self.fields(tenant_id=other))
    self.assertTrue(foreign["success"], foreign)
    self.denied(404, "engagement_not_found", engagement_id=foreign["data"]["engagementId"])


if __name__ == "__main__":
  unittest.main()
