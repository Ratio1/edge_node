"""A tenant's stored override wins over the node's destination (RM-081 Phase 3a)."""
import unittest

from extensions.business.cybersec.red_mesh.services.config import (
  DEFAULT_OPENCTI_EXPORT_CONFIG, get_opencti_export_config, get_taxii_export_config,
  get_wazuh_export_config, resolve_config_block, tenant_integration_override)
from extensions.business.cybersec.red_mesh.services.misp_config import get_misp_export_config


class Owner:
  """Duck-types the plugin: a node-level config block plus the stored-record accessor."""

  def __init__(self, blocks=None, records=None, raises=False, accessor=True):
    self.config_data = dict(blocks or {})
    self._records = dict(records or {})
    self._raises = raises
    self.reads = []
    if not accessor:
      # Drop the accessor entirely, as a deployment with no tenancy configured would.
      self.__class__ = type("OwnerWithoutAccessor", (object,), {
        "config_data": self.config_data})

  def _get_tenant_integration_config(self, tenant_id, integration_id):
    self.reads.append((tenant_id, integration_id))
    if self._raises:
      raise RuntimeError("storage unavailable")
    return self._records.get((tenant_id, integration_id))


def record(config):
  return {"config": dict(config)}


class TestTenantIntegrationOverride(unittest.TestCase):
  def test_absent_tenant_never_reads_the_store(self):
    owner = Owner()
    self.assertEqual(tenant_integration_override(owner, None, "misp"), {})
    self.assertEqual(owner.reads, [])

  def test_unavailable_storage_is_an_empty_override_not_an_exception(self):
    owner = Owner(raises=True)
    self.assertEqual(tenant_integration_override(owner, "tn_a", "misp"), {})

  def test_a_deployment_without_the_accessor_resolves_as_it_always_did(self):
    owner = Owner(accessor=False)
    self.assertEqual(tenant_integration_override(owner, "tn_a", "misp"), {})

  def test_a_malformed_record_yields_an_empty_override(self):
    for stored in (None, {}, {"config": None}, {"config": "text"}, "not-a-record"):
      owner = Owner(records={("tn_a", "misp"): stored})
      self.assertEqual(tenant_integration_override(owner, "tn_a", "misp"), {})

  def test_the_override_is_detached_from_the_stored_record(self):
    stored = record({"MISP_URL": "https://a.example"})
    owner = Owner(records={("tn_a", "misp"): stored})
    resolved = tenant_integration_override(owner, "tn_a", "misp")
    resolved["MISP_URL"] = "https://mutated.example"
    self.assertEqual(stored["config"]["MISP_URL"], "https://a.example")


class TestMergeOrder(unittest.TestCase):
  def test_the_tenant_wins_over_the_node_which_wins_over_the_default(self):
    defaults = {"URL": "", "AUTH_MODE": "static", "ENABLED": False}
    self.assertEqual(
      resolve_config_block(Owner({"B": {"URL": "https://node.example", "ENABLED": True}}),
                           "B", defaults, tenant_override={"URL": "https://tenant.example"}),
      {"URL": "https://tenant.example", "AUTH_MODE": "static", "ENABLED": True})

  def test_a_partial_tenant_override_keeps_the_node_values_it_does_not_name(self):
    defaults = {"URL": "", "TIMEOUT": 1}
    self.assertEqual(
      resolve_config_block(Owner({"B": {"URL": "https://node.example", "TIMEOUT": 9}}),
                           "B", defaults, tenant_override={"URL": "https://tenant.example"}),
      {"URL": "https://tenant.example", "TIMEOUT": 9})


class TestResolvedDestinations(unittest.TestCase):
  def setUp(self):
    self.node = {
      "MISP_EXPORT": {"ENABLED": True, "MISP_URL": "https://node-misp.example", "MISP_API_KEY": "node"},
      "WAZUH_EXPORT": {"ENABLED": True, "MODE": "http", "HTTP_URL": "https://node-wazuh.example"},
      "OPENCTI_EXPORT": {"ENABLED": True, "URL": "https://node-octi.example", "TOKEN": "node"},
      "TAXII_EXPORT": {"ENABLED": True, "SERVER_URL": "https://node-taxii.example", "TOKEN": "node"},
    }

  def owner(self, records=None):
    return Owner(self.node, records)

  def test_each_id_resolves_its_own_tenant_destination(self):
    owner = self.owner({
      ("tn_a", "misp"): record({"MISP_URL": "https://a-misp.example", "MISP_API_KEY": "a"}),
      ("tn_a", "wazuh"): record({"HTTP_URL": "https://a-wazuh.example"}),
      ("tn_a", "opencti"): record({"URL": "https://a-octi.example", "TOKEN": "a"}),
      ("tn_a", "taxii"): record({"SERVER_URL": "https://a-taxii.example", "TOKEN": "a"}),
    })
    self.assertEqual(get_misp_export_config(owner, "tn_a")["MISP_URL"], "https://a-misp.example")
    self.assertEqual(get_wazuh_export_config(owner, "tn_a")["HTTP_URL"], "https://a-wazuh.example")
    self.assertEqual(get_opencti_export_config(owner, "tn_a")["URL"], "https://a-octi.example")
    self.assertEqual(get_taxii_export_config(owner, "tn_a")["SERVER_URL"], "https://a-taxii.example")

  def test_two_tenants_resolve_to_different_destinations_and_credentials(self):
    owner = self.owner({
      ("tn_a", "misp"): record({"MISP_URL": "https://a.example", "MISP_API_KEY": "key-a"}),
      ("tn_b", "misp"): record({"MISP_URL": "https://b.example", "MISP_API_KEY": "key-b"}),
    })
    first, second = get_misp_export_config(owner, "tn_a"), get_misp_export_config(owner, "tn_b")
    self.assertEqual((first["MISP_URL"], first["MISP_API_KEY"]), ("https://a.example", "key-a"))
    self.assertEqual((second["MISP_URL"], second["MISP_API_KEY"]), ("https://b.example", "key-b"))

  def test_an_unscoped_call_still_resolves_the_node_and_reads_no_record(self):
    owner = self.owner({("tn_a", "misp"): record({"MISP_URL": "https://a.example"})})
    self.assertEqual(get_misp_export_config(owner)["MISP_URL"], "https://node-misp.example")
    self.assertEqual(owner.reads, [])

  def test_a_tenant_with_no_record_resolves_the_node_block_which_callers_must_not_trust(self):
    # Named for what actually happens, not for what we want to be true elsewhere. An absent record
    # and an unreachable store are the same empty override here, so resolution falls back to the
    # node block. "A bound job whose tenant has no config exports nowhere" is therefore enforced by
    # the export caller checking the record exists -- never by trusting this resolved destination.
    owner = self.owner()
    self.assertEqual(get_misp_export_config(owner, "tn_a")["MISP_URL"], "https://node-misp.example")
    self.assertEqual(owner.reads, [("tn_a", "misp")])

  def test_the_normalizer_still_runs_over_a_tenant_value(self):
    owner = self.owner({("tn_a", "opencti"): record({"MIN_SEVERITY": "not-a-severity"})})
    self.assertEqual(get_opencti_export_config(owner, "tn_a")["MIN_SEVERITY"],
                     DEFAULT_OPENCTI_EXPORT_CONFIG["MIN_SEVERITY"])


if __name__ == "__main__":
  unittest.main()
