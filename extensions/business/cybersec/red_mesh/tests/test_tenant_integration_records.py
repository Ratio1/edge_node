"""The integration config table, and the retirement of per-tenant integration records (RM-139).

RM-081 stored one destination config per tenant; RM-139 moved integrations to the deployment (Deeploy
config plus an STA override), so the tenant rows are deleted once at plugin start and the kind can no
longer be read or written.
"""
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
from .contract_fixture import contract_terms


TENANCY_HKEY = '["redmesh","tenancy",1,"deployment"]'
SECRET = "legacy-tenant-misp-secret"


def integration_location(tenant_id, integration_id, namespace="deployment"):
  return (json.dumps(["redmesh", "tenancy", 1, namespace], separators=(",", ":")),
          json.dumps(["integration", namespace, tenant_id, integration_id], separators=(",", ":")))


def plant(owner, tenant_id, integration_id="misp", namespace="deployment"):
  """A row as RM-081 `put_tenant_integration` wrote it, credential included."""
  owner.data[integration_location(tenant_id, integration_id, namespace)] = {
    "schemaVersion": 1, "namespace": namespace, "kind": "integration",
    "ids": [tenant_id, integration_id], "tenant_id": tenant_id, "integration_id": integration_id,
    "enabled": True, "config": {"MISP_URL": "https://misp.example", "MISP_API_KEY": SECRET},
    "updated_by": "creator", "updated_at": "2026-09-20T00:00:00+00:00"}


class TestConfigTableMatchesDeployment(unittest.TestCase):
  """The override's keys are the deployment block's own keys. A rename there must fail here."""

  def test_every_override_key_exists_in_the_deployment_default(self):
    defaults = {"misp": DEFAULT_MISP_EXPORT_CONFIG, "opencti": DEFAULT_OPENCTI_EXPORT_CONFIG,
                "taxii": DEFAULT_TAXII_EXPORT_CONFIG, "wazuh": DEFAULT_WAZUH_EXPORT_CONFIG}
    self.assertEqual(set(defaults), set(integrations.INTEGRATION_IDS))
    for integration_id, block in defaults.items():
      allowed = integrations._CONFIG_KEYS[integration_id]
      self.assertEqual(set(allowed) - set(block), set(),
                       f"{integration_id} declares keys the deployment block does not have")
      for key, types in allowed.items():
        self.assertIsInstance(block[key], types,
                              f"{integration_id}.{key} type disagrees with the deployment default")

  def test_every_credential_key_is_a_declared_config_key(self):
    for integration_id, keys in integrations.CREDENTIAL_KEYS.items():
      self.assertIn(integration_id, integrations.INTEGRATION_IDS)
      for key in keys:
        self.assertIn(key, integrations._CONFIG_KEYS[integration_id])

  def test_the_node_level_three_are_not_configurable_integrations(self):
    for integration_id in ("stix", "event_export", "suricata"):
      self.assertFalse(integrations.valid_integration_id(integration_id))
      with self.assertRaises(ValueError):
        integrations.normalize_integration_config(integration_id, {})

  def test_unknown_keys_and_wrong_types_are_refused(self):
    for config in ({"NOT_A_KEY": "x"}, {"MISP_URL": 7}, {"MISP_VERIFY_TLS": "yes"},
                   {"MISP_DISTRIBUTION": True}, {"MISP_URL": "https://e" + chr(0) + "x"},
                   "not-a-dict"):
      with self.assertRaises(ValueError, msg=config):
        integrations.normalize_integration_config("misp", config)


class RetirementCase(unittest.TestCase):
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
      self.actor, request, "Tenant", "tenant", "initial", **contract_terms())["data"]["tenantId"]
    self.owner.grant("initial", self.tenant)
    self.assertTrue(self.service.activate_tenant(self.actor, request)["success"])
    # A tenant deleted before RM-139 left its rows behind: the cleanup must not need the tenant.
    self.orphan = "tn_" + str(uuid4())
    plant(self.owner, self.tenant, "misp")
    plant(self.owner, self.tenant, "opencti")
    plant(self.owner, self.orphan, "taxii")
    # Another namespace's row on the same hkey family is never this deployment's to delete.
    plant(self.owner, self.tenant, "misp", namespace="other")

  def live_rows(self, namespace="deployment"):
    hkey = integration_location("x", "misp", namespace)[0]
    return sorted(json.loads(key)[2:] for (bucket, key), value in self.owner.data.items()
                  if bucket == hkey and value is not None and json.loads(key)[0] == "integration")


class TestRetiredTenantIntegrationKind(RetirementCase):
  def test_the_tenant_integration_endpoints_are_gone(self):
    for name in ("list_tenant_integrations", "get_tenant_integration", "put_tenant_integration"):
      self.assertFalse(hasattr(TenantAdministrationService, name), name)

  def test_a_stored_row_is_neither_read_nor_written(self):
    with self.assertRaises(TenantStoreError):
      self.store.get("integration", self.tenant, "misp")
    before = len(self.owner.writes)
    with self.assertRaises(TenantStoreError):
      self.store.put("integration", self.tenant, "wazuh", record={
        "tenant_id": self.tenant, "integration_id": "wazuh", "enabled": True, "config": {},
        "updated_by": "creator", "updated_at": "2026-10-14T00:00:00+00:00"})
    self.assertEqual(len(self.owner.writes), before)

  def test_record_ids_lists_every_row_of_the_namespace_orphans_included(self):
    self.assertEqual(sorted(self.store.record_ids("integration")),
                     sorted([[self.tenant, "misp"], [self.tenant, "opencti"], [self.orphan, "taxii"]]))

  def test_the_cleanup_deletes_every_row_once_and_leaves_the_rest(self):
    tenant_row = self.store.get("tenant", self.tenant)
    self.assertEqual(integrations.retire_tenant_integration_records(self.store), 3)
    self.assertEqual(self.live_rows(), [])
    self.assertEqual(self.live_rows("other"), [[self.tenant, "misp"]])
    self.assertEqual(self.store.get("tenant", self.tenant), tenant_row)
    writes = len(self.owner.writes)
    self.assertEqual(integrations.retire_tenant_integration_records(self.store), 0)
    self.assertEqual(len(self.owner.writes), writes)


class TestPluginStartCleanup(RetirementCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    super().setUp()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.logs = []
    self.plugin.P = lambda *args, **kwargs: self.logs.append(" ".join(str(arg) for arg in args))
    self.enumerations = 0
    self.unavailable = False

    def hgetall(*, hkey):
      self.enumerations += 1
      if self.unavailable:
        raise RuntimeError("cstore down " + SECRET)
      return self.owner.chainstore_hgetall(hkey=hkey)
    self.plugin.chainstore_hgetall = hgetall
    self.plugin.chainstore_hget = self.owner.chainstore_hget
    self.plugin.chainstore_hset = self.owner.chainstore_hset

  def run_cleanup(self):
    self.Plugin._maybe_retire_tenant_integration_records(self.plugin)

  def test_it_runs_once_and_logs_only_the_count(self):
    self.run_cleanup()
    self.assertEqual(self.live_rows(), [])
    self.assertEqual(self.live_rows("other"), [[self.tenant, "misp"]])
    rendered = "\n".join(self.logs)
    self.assertRegex(rendered, r"\b3\b")
    for content in (SECRET, "misp.example", self.tenant, self.orphan):
      self.assertNotIn(content, rendered)
    enumerations = self.enumerations
    plant(self.owner, self.tenant, "wazuh")
    self.run_cleanup()
    self.assertEqual(self.enumerations, enumerations)
    self.assertEqual(self.live_rows(), [[self.tenant, "wazuh"]])

  def test_an_unavailable_store_is_retried_on_a_later_tick(self):
    self.unavailable = True
    self.run_cleanup()
    self.run_cleanup()
    self.assertEqual(len(self.live_rows()), 3)
    self.assertNotIn(SECRET, "\n".join(self.logs))
    self.unavailable = False
    self.run_cleanup()
    self.assertEqual(self.live_rows(), [])
    enumerations = self.enumerations
    self.run_cleanup()
    self.assertEqual(self.enumerations, enumerations)

  def test_a_node_without_a_tenancy_namespace_has_nothing_to_clean(self):
    self.plugin.cfg_tenancy_namespace = None
    self.run_cleanup()
    self.assertEqual(self.enumerations, 0)
    self.assertEqual(len(self.live_rows()), 3)


if __name__ == "__main__":
  unittest.main()
