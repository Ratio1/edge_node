"""Job-less integration reads admit a tenant without changing the legacy path (RM-081 Phase 3c)."""
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.services.integration_status import (
  _STATUS_BUILDERS, get_public_integration_config)
from extensions.business.cybersec.red_mesh.tenancy.http_runtime import _EFFECT_FIELDS, _READ_FIELDS
from extensions.business.cybersec.red_mesh.tenancy.integrations import (
  NODE_LEVEL_INTEGRATION_IDS, TENANT_INTEGRATION_IDS)


class Owner:
  cfg_instance_id = "pdev5"

  def __init__(self, blocks=None, records=None):
    self.config_data = dict(blocks or {})
    self._records = dict(records or {})

  def _get_tenant_integration_config(self, tenant_id, integration_id):
    return self._records.get((tenant_id, integration_id))

  def chainstore_hget(self, *, hkey, key):
    return None

  def chainstore_hset(self, *, hkey, key, value, **kwargs):
    return True


class TestRegisteredFields(unittest.TestCase):
  """The strict transport enforces exact field names, so the selector must be declared."""

  def test_the_scoped_reads_declare_tenant_id_last(self):
    for name in ("get_integration_status", "get_misp_export_config_status"):
      self.assertEqual([field[0] for field in _READ_FIELDS[name]], ["request_actor", "tenant_id"])
      self.assertEqual(_READ_FIELDS[name][-1], ("tenant_id", str, None))

  def test_the_synthetic_delivery_declares_it_too(self):
    self.assertEqual(_EFFECT_FIELDS["test_event_export"][-1], ("tenant_id", str, None))


class TestScopedReadinessPayload(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"REDMESH_EVENT_HMAC_SECRET": "secret"})
    env.start()
    self.addCleanup(env.stop)
    self.tenant = "tn_" + str(uuid4())
    self.node = {
      "EVENT_EXPORT": {"ENABLED": True},
      "WAZUH_EXPORT": {"ENABLED": True, "MODE": "http", "HTTP_URL": "https://node.example",
                       "TOKEN": "node"},
      "OPENCTI_EXPORT": {"ENABLED": True, "URL": "https://node-octi.example", "TOKEN": "node"},
      "TAXII_EXPORT": {"ENABLED": True, "SERVER_URL": "https://node-taxii.example",
                       "TOKEN": "node", "COLLECTION_ID": "node-collection"},
      "STIX_EXPORT": {"ENABLED": True},
      "SURICATA_CORRELATION": {"ENABLED": True},
    }

  def test_the_payload_keeps_every_key_even_when_scoped(self):
    # get_public_integration_config raises unless the key set equals _STATUS_BUILDERS exactly,
    # so a scoped call may not drop the node-level ids.
    owner = Owner(self.node)
    scoped = get_public_integration_config(owner, self.tenant)
    self.assertEqual(set(scoped["integrations"]), set(_STATUS_BUILDERS))

  def test_a_scoped_read_reports_the_tenants_readiness_not_the_nodes(self):
    # The public projection deliberately omits the host, so two different URLs look identical here.
    # Readiness is the observable difference, and it is the one that matters: a tenant that has not
    # finished configuring must not read as ready because the deployment is.
    owner = Owner(self.node, {
      (self.tenant, "opencti"): {"config": {"ENABLED": True, "URL": "", "TOKEN": ""}}})
    scoped = get_public_integration_config(owner, self.tenant)["integrations"]
    unscoped = get_public_integration_config(owner)["integrations"]
    self.assertTrue(unscoped["opencti"]["configured"])
    self.assertFalse(scoped["opencti"]["configured"])

  def test_a_tenant_can_be_ready_where_the_node_is_not(self):
    owner = Owner({**self.node, "TAXII_EXPORT": {"ENABLED": True, "SERVER_URL": "", "TOKEN": ""}}, {
      (self.tenant, "taxii"): {"config": {"ENABLED": True, "SERVER_URL": "https://a.example",
                                          "TOKEN": "a", "COLLECTION_ID": "a-collection"}}})
    self.assertFalse(get_public_integration_config(owner)["integrations"]["taxii"]["configured"])
    self.assertTrue(
      get_public_integration_config(owner, self.tenant)["integrations"]["taxii"]["configured"])

  def test_the_node_level_three_read_identically_scoped_or_not(self):
    owner = Owner(self.node, {
      (self.tenant, "wazuh"): {"config": {"ENABLED": True, "MODE": "http",
                                          "HTTP_URL": "https://a.example", "TOKEN": "a"}}})
    scoped = get_public_integration_config(owner, self.tenant)["integrations"]
    unscoped = get_public_integration_config(owner)["integrations"]
    for integration_id in NODE_LEVEL_INTEGRATION_IDS:
      self.assertEqual(scoped[integration_id], unscoped[integration_id], integration_id)

  def test_node_level_builders_ignore_the_tenant(self):
    # The property that makes the node-level three tenant-invariant. get_public_integration_config
    # also routes them through status_tenant(), which is a guard against this ceasing to be true.
    owner = Owner(self.node)
    for integration_id in NODE_LEVEL_INTEGRATION_IDS:
      builder = _STATUS_BUILDERS[integration_id]
      self.assertEqual(builder(owner, self.tenant), builder(owner), integration_id)

  def test_no_credential_reaches_a_scoped_payload(self):
    owner = Owner(self.node, {
      (self.tenant, integration_id): {"config": {"TOKEN": f"{integration_id}-secret"}}
      for integration_id in TENANT_INTEGRATION_IDS if integration_id != "misp"})
    import json
    rendered = json.dumps(get_public_integration_config(owner, self.tenant))
    for integration_id in TENANT_INTEGRATION_IDS:
      self.assertNotIn(f"{integration_id}-secret", rendered)


if __name__ == "__main__":
  unittest.main()
