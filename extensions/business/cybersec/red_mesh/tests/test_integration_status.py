import os
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.services.integration_status import (
  get_integration_status,
  record_integration_status,
  test_event_export as build_integration_test_event,
)


class TestIntegrationStatus(unittest.TestCase):

  def setUp(self):
    self.owner = MagicMock()
    self.owner.cfg_instance_id = "test-instance"
    self.owner.cfg_ee_node_network = "devnet"
    self.records = {}

    def hget(hkey, key):
      return self.records.get((hkey, key))

    def hset(hkey, key, value):
      self.records[(hkey, key)] = value

    self.owner.chainstore_hget.side_effect = hget
    self.owner.chainstore_hset.side_effect = hset

  def tearDown(self):
    os.environ.pop("REDMESH_EVENT_HMAC_SECRET", None)
    os.environ.pop("REDMESH_OPENCTI_TOKEN", None)
    os.environ.pop("REDMESH_TAXII_TOKEN", None)

  def test_status_returns_all_integrations_without_secrets(self):
    self.owner.cfg_event_export = {
      "ENABLED": True,
      "SIGN_PAYLOADS": True,
      "HMAC_SECRET_ENV": "REDMESH_EVENT_HMAC_SECRET",
    }
    self.owner.cfg_wazuh_export = {
      "ENABLED": True,
      "MODE": "http",
      "HTTP_URL": "https://siem.example/ingest",
    }
    self.owner.cfg_opencti_export = {
      "ENABLED": True,
      "URL": "https://opencti.example",
      "TOKEN_ENV": "REDMESH_OPENCTI_TOKEN",
    }
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "event-secret"

    status = get_integration_status(self.owner)

    self.assertEqual(status["schema_version"], "1.0.0")
    self.assertEqual(set(status["integrations"]), {
      "event_export",
      "wazuh",
      "suricata",
      "stix",
      "opencti",
      "taxii",
    })
    self.assertTrue(status["integrations"]["event_export"]["configured"])
    self.assertTrue(status["integrations"]["wazuh"]["configured"])
    self.assertEqual(status["integrations"]["wazuh"]["redacted_host"], "siem.example")
    self.assertFalse(status["integrations"]["opencti"]["configured"])
    self.assertEqual(status["integrations"]["opencti"]["last_error_class"], "missing_token")
    self.assertNotIn("event-secret", str(status))

  def test_status_records_last_success_failure_and_event_id(self):
    ok = record_integration_status(
      self.owner,
      "event_export",
      outcome="success",
      event_id="event-1",
      dry_run=True,
    )

    self.assertTrue(ok)
    status = get_integration_status(self.owner)["integrations"]["event_export"]
    self.assertEqual(status["last_event_id"], "event-1")
    self.assertIsNotNone(status["last_dry_run_at"])
    self.assertIsNotNone(status["last_success_at"])
    self.assertIsNone(status["last_failure_at"])

    record_integration_status(
      self.owner,
      "event_export",
      outcome="failure",
      error_class="timeout",
    )
    status = get_integration_status(self.owner)["integrations"]["event_export"]
    self.assertEqual(status["last_error_class"], "timeout")
    self.assertIsNotNone(status["last_failure_at"])

  def test_wazuh_status_reflects_missing_shared_signing_secret(self):
    self.owner.cfg_wazuh_export = {
      "ENABLED": True,
      "MODE": "syslog",
      "SYSLOG_HOST": "127.0.0.1",
    }
    self.owner.cfg_event_export = {
      "SIGN_PAYLOADS": True,
      "HMAC_SECRET_ENV": "REDMESH_EVENT_HMAC_SECRET",
    }

    status = get_integration_status(self.owner)["integrations"]["wazuh"]

    self.assertTrue(status["enabled"])
    self.assertFalse(status["configured"])
    self.assertEqual(status["last_error_class"], "missing_hmac_secret")

  def test_test_event_export_builds_safe_event_and_persists_dry_run(self):
    result = build_integration_test_event(self.owner, integration_id="event_export")

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["dry_run"])
    self.assertTrue(result["persisted"])
    event = result["event"]
    self.assertEqual(event["schema"], "redmesh.event.v1")
    self.assertEqual(event["event_type"], "redmesh.integration.test")
    self.assertEqual(event["target"]["display"], None)
    self.assertIn("pseudonym", event["target"])
    self.assertNotIn("198.51.100.10", str(event))

    status = get_integration_status(self.owner)["integrations"]["event_export"]
    self.assertEqual(status["last_event_id"], event["event_id"])
    self.assertIsNotNone(status["last_dry_run_at"])
    self.assertIsNotNone(status["last_success_at"])

  def test_test_event_export_rejects_unknown_integration(self):
    result = build_integration_test_event(self.owner, integration_id="unknown")

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "unknown_integration")

  def test_cti_status_does_not_return_token_values(self):
    self.owner.cfg_opencti_export = {
      "ENABLED": True,
      "URL": "https://opencti.example",
      "TOKEN_ENV": "REDMESH_OPENCTI_TOKEN",
    }
    os.environ["REDMESH_OPENCTI_TOKEN"] = "super-secret-token"

    status = get_integration_status(self.owner)["integrations"]["opencti"]

    self.assertTrue(status["configured"])
    self.assertEqual(status["config"]["token_env"], "REDMESH_OPENCTI_TOKEN")
    self.assertNotIn("super-secret-token", str(status))

  def test_configuration_error_survives_dry_run_success_when_unconfigured(self):
    self.owner.cfg_opencti_export = {
      "ENABLED": True,
      "URL": "https://opencti.example",
      "TOKEN_ENV": "REDMESH_OPENCTI_TOKEN",
    }

    result = build_integration_test_event(self.owner, integration_id="opencti")
    status = get_integration_status(self.owner)["integrations"]["opencti"]

    self.assertEqual(result["status"], "ok")
    self.assertFalse(status["configured"])
    self.assertEqual(status["last_error_class"], "missing_token")
    self.assertEqual(status["last_event_id"], result["event"]["event_id"])


if __name__ == "__main__":
  unittest.main()
