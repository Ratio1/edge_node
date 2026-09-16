"""Per-tenant SOC/CTI destination config records through the real storage boundary (RM-081 Phase 1)."""
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from .test_tenant_administration import FakeAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.tenancy import integrations
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from extensions.business.cybersec.red_mesh.services.config import (
  DEFAULT_OPENCTI_EXPORT_CONFIG, DEFAULT_TAXII_EXPORT_CONFIG, DEFAULT_WAZUH_EXPORT_CONFIG)
from extensions.business.cybersec.red_mesh.services.misp_config import DEFAULT_MISP_EXPORT_CONFIG


def integration_location(tenant_id, integration_id):
  return ('["redmesh","tenancy",1,"deployment"]',
          json.dumps(["integration", "deployment", tenant_id, integration_id], separators=(",", ":")))


class IntegrationRecordCase(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.owner = FakeAdministrationStore()
    self.store = CstoreTenantAdministrationStore(self.owner, "deployment")
    self.service = TenantAdministrationService(CstoreAuthAccountReader(self.owner), self.store)
    self.actor = {"account_id": "creator"}
    request = str(uuid4())
    self.tenant = self.service.prepare_tenant(
      self.actor, request, "Tenant", "tenant", "initial")["data"]["tenantId"]
    self.owner.grant("initial", self.tenant)
    self.assertTrue(self.service.activate_tenant(self.actor, request)["success"])

  def put(self, **changes):
    fields = {"actor": self.actor, "tenant_id": self.tenant, "integration_id": "misp",
              "enabled": True, "config": {"MISP_URL": "https://misp.example", "MISP_API_KEY": "k"}}
    return self.service.put_tenant_integration(**{**fields, **changes})


class TestConfigTableMatchesDeployment(unittest.TestCase):
  """The record's keys are the deployment block's own keys. A rename there must fail here."""

  def test_every_tenant_key_exists_in_the_deployment_default(self):
    defaults = {"misp": DEFAULT_MISP_EXPORT_CONFIG, "opencti": DEFAULT_OPENCTI_EXPORT_CONFIG,
                "taxii": DEFAULT_TAXII_EXPORT_CONFIG, "wazuh": DEFAULT_WAZUH_EXPORT_CONFIG}
    self.assertEqual(set(defaults), set(integrations.TENANT_INTEGRATION_IDS))
    for integration_id, block in defaults.items():
      allowed = integrations._CONFIG_KEYS[integration_id]
      self.assertEqual(set(allowed) - set(block), set(),
                       f"{integration_id} declares keys the deployment block does not have")
      for key, types in allowed.items():
        self.assertIsInstance(block[key], types,
                              f"{integration_id}.{key} type disagrees with the deployment default")

  def test_every_credential_key_is_a_declared_config_key(self):
    for integration_id, keys in integrations.CREDENTIAL_KEYS.items():
      self.assertIn(integration_id, integrations.TENANT_INTEGRATION_IDS)
      for key in keys:
        self.assertIn(key, integrations._CONFIG_KEYS[integration_id])

  def test_the_node_level_three_are_disjoint_and_explained(self):
    self.assertEqual(set(integrations.NODE_LEVEL_INTEGRATION_IDS)
                     & set(integrations.TENANT_INTEGRATION_IDS), set())
    for reason in integrations.NODE_LEVEL_INTEGRATION_IDS.values():
      self.assertTrue(reason.strip())


class TestTenantIntegrationRecords(IntegrationRecordCase):
  def test_first_write_roundtrips_as_a_persisted_authorized_record(self):
    result = self.put()
    self.assertTrue(result["success"], result)
    row = result["data"]
    self.assertEqual((row["tenantId"], row["integrationId"], row["enabled"]),
                     (self.tenant, "misp", True))
    self.assertEqual(row["updatedBy"], "creator")
    stored = self.owner.data[integration_location(self.tenant, "misp")]
    self.assertEqual(stored["config"]["MISP_API_KEY"], "k")
    self.assertEqual(self.service.get_tenant_integration(
      self.actor, self.tenant, "misp")["data"]["integration"], row)

  def test_no_projection_returns_a_credential_value(self):
    for integration_id, config in (
        ("misp", {"MISP_API_KEY": "misp-secret"}),
        ("opencti", {"TOKEN": "opencti-secret"}),
        ("taxii", {"TOKEN": "taxii-secret", "PASSWORD": "taxii-password"}),
        ("wazuh", {"TOKEN": "wazuh-secret", "PASSWORD": "wazuh-password"})):
      self.assertTrue(self.put(integration_id=integration_id, config=config)["success"])
    rendered = json.dumps([self.service.list_tenant_integrations(self.actor, self.tenant),
                           *(self.service.get_tenant_integration(self.actor, self.tenant, name)
                             for name in integrations.TENANT_INTEGRATION_IDS)])
    for secret in ("misp-secret", "opencti-secret", "taxii-secret", "taxii-password",
                   "wazuh-secret", "wazuh-password"):
      self.assertNotIn(secret, rendered)
    projected = self.service.get_tenant_integration(
      self.actor, self.tenant, "taxii")["data"]["integration"]["config"]
    self.assertTrue(projected["credentialsConfigured"])
    self.assertNotIn("TOKEN", projected)
    self.assertNotIn("PASSWORD", projected)

  def test_blank_credential_reads_as_not_configured(self):
    self.assertTrue(self.put(integration_id="opencti",
                             config={"URL": "https://octi.example", "TOKEN": "  "})["success"])
    projected = self.service.get_tenant_integration(
      self.actor, self.tenant, "opencti")["data"]["integration"]["config"]
    self.assertFalse(projected["credentialsConfigured"])

  def test_listing_shows_every_tenant_id_including_unconfigured_ones(self):
    self.assertTrue(self.put()["success"])
    listed = self.service.list_tenant_integrations(self.actor, self.tenant)["data"]["integrations"]
    self.assertEqual([row["integrationId"] for row in listed],
                     list(integrations.TENANT_INTEGRATION_IDS))
    unset = [row for row in listed if row["integrationId"] == "opencti"][0]
    self.assertEqual((unset["enabled"], unset["config"], unset["version"]), (False, None, None))

  def test_node_level_ids_are_refused_with_their_own_reason(self):
    for integration_id in ("stix", "event_export", "suricata"):
      for call in (lambda name=integration_id: self.put(integration_id=name, config={}),
                   lambda name=integration_id: self.service.get_tenant_integration(
                     self.actor, self.tenant, name)):
        result = call()
        self.assertEqual((result["status_code"], result["error"]),
                         (400, "integration_not_tenant_scoped"), integration_id)
      self.assertNotIn(integration_location(self.tenant, integration_id), self.owner.data)

  def test_unknown_id_is_not_found_rather_than_a_node_level_refusal(self):
    result = self.service.get_tenant_integration(self.actor, self.tenant, "splunk")
    self.assertEqual((result["status_code"], result["error"]), (404, "not_found"))

  def test_unknown_keys_and_wrong_types_never_write(self):
    for config in ({"NOT_A_KEY": "x"}, {"MISP_URL": 7}, {"MISP_VERIFY_TLS": "yes"},
                   {"MISP_DISTRIBUTION": True}, {"MISP_URL": "https://e" + chr(0) + "x"},
                   "not-a-dict"):
      before = len(self.owner.writes)
      result = self.put(config=config)
      self.assertEqual(result["status_code"], 400, config)
      self.assertEqual(len(self.owner.writes), before, config)

  def test_a_second_write_needs_the_current_version_and_a_first_one_needs_none(self):
    first = self.put()["data"]
    self.assertEqual(self.put()["status_code"], 409)
    self.assertEqual(self.put(expected_version=first["version"],
                              config={"MISP_URL": "https://other.example"})["data"]["config"]["MISP_URL"],
                     "https://other.example")
    stale = self.put(expected_version=first["version"], config={"MISP_URL": "https://third.example"})
    self.assertEqual(stale["status_code"], 409)

  def test_a_version_for_a_record_that_does_not_exist_never_creates_one(self):
    before = len(self.owner.writes)
    absent = self.put(expected_version="a" * 64)
    self.assertEqual(absent["status_code"], 409)
    self.assertEqual(len(self.owner.writes), before)
    self.assertNotIn(integration_location(self.tenant, "misp"), self.owner.data)

  def test_an_unchanged_rewrite_is_a_noop_that_still_returns_the_row(self):
    first = self.put()["data"]
    before = len(self.owner.writes)
    again = self.put(expected_version=first["version"])
    self.assertEqual(again["data"], first)
    self.assertEqual(len(self.owner.writes), before)

  def test_a_tenant_admin_manages_and_a_tenant_user_never_reads(self):
    self.owner.account("member", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    self.assertEqual(self.service.list_tenant_integrations(
      {"account_id": "member"}, self.tenant)["status_code"], 403)
    self.assertTrue(self.service.list_tenant_integrations(
      {"account_id": "initial"}, self.tenant)["success"])

  def test_a_foreign_tenant_admin_reads_nothing(self):
    other = str(uuid4())
    foreign = self.service.prepare_tenant(self.actor, other, "Other", "other", "initial")["data"]["tenantId"]
    self.owner.account("outsider", memberships=[{"role": "tenant_admin", "tenant_id": foreign}])
    self.assertIn(self.service.list_tenant_integrations(
      {"account_id": "outsider"}, self.tenant)["status_code"], (403, 404))

  def test_a_corrupted_stored_record_is_refused_rather_than_projected(self):
    self.assertTrue(self.put()["success"])
    location = integration_location(self.tenant, "misp")
    for corruption in ({"enabled": "yes"}, {"integration_id": "suricata"}, {"updated_by": ""},
                       {"updated_at": "not-a-time"}, {"config": {"NOT_A_KEY": 1}}):
      saved = dict(self.owner.data[location])
      self.owner.data[location] = {**saved, **corruption}
      with self.assertRaises(TenantStoreError, msg=corruption):
        self.store.get("integration", self.tenant, "misp")
      self.owner.data[location] = saved


if __name__ == "__main__":
  unittest.main()
