"""Job-less integration reads admit a tenant; RM-139: they report the deployment's effective config."""
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.services.config import IntegrationOverrideUnavailable
from extensions.business.cybersec.red_mesh.services.integration_status import (
  _STATUS_BUILDERS, get_public_integration_config)
from extensions.business.cybersec.red_mesh.tenancy.http_runtime import _EFFECT_FIELDS, _READ_FIELDS
from extensions.business.cybersec.red_mesh.tenancy.integrations import INTEGRATION_IDS


class Owner:
  cfg_instance_id = "pdev5"

  def __init__(self, blocks=None, overrides=None, raises=False):
    self.config_data = dict(blocks or {})
    self._overrides = dict(overrides or {})
    self._raises = raises

  def _get_super_tenant_integration_override(self, integration_id):
    if self._raises:
      raise RuntimeError("storage unavailable")
    config = self._overrides.get(integration_id)
    return None if config is None else {"integration_id": integration_id, "config": config}

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


class TestDeploymentReadinessPayload(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"REDMESH_EVENT_HMAC_SECRET": "secret"})
    env.start()
    self.addCleanup(env.stop)
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

  def test_the_payload_keeps_every_key(self):
    self.assertEqual(set(get_public_integration_config(Owner(self.node))["integrations"]), set(_STATUS_BUILDERS))

  def test_the_deeploy_config_alone_is_ready(self):
    integrations = get_public_integration_config(Owner(self.node))["integrations"]
    for integration_id in ("opencti", "taxii", "wazuh"):
      self.assertTrue(integrations[integration_id]["configured"], integration_id)

  def test_an_override_decides_the_readiness(self):
    # The public projection omits the host, so readiness is the observable difference.
    owner = Owner({**self.node, "TAXII_EXPORT": {"ENABLED": True, "SERVER_URL": "", "TOKEN": ""}}, {
      "opencti": {"ENABLED": False},
      "taxii": {"SERVER_URL": "https://a.example", "TOKEN": "a", "COLLECTION_ID": "a-collection"}})
    integrations = get_public_integration_config(owner)["integrations"]
    self.assertEqual((integrations["opencti"]["configured"], integrations["opencti"]["status"]), (False, "disabled"))
    self.assertTrue(integrations["taxii"]["configured"])

  def test_an_unreadable_override_is_unavailable_not_the_deeploy_readiness(self):
    with self.assertRaises(IntegrationOverrideUnavailable):
      get_public_integration_config(Owner(self.node, raises=True))

  def test_no_credential_reaches_the_payload(self):
    owner = Owner(self.node, {integration_id: {"TOKEN": f"{integration_id}-secret"}
                              for integration_id in INTEGRATION_IDS if integration_id != "misp"})
    import json
    rendered = json.dumps(get_public_integration_config(owner))
    for integration_id in INTEGRATION_IDS:
      self.assertNotIn(f"{integration_id}-secret", rendered)


if __name__ == "__main__":
  unittest.main()
