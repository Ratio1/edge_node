import json
import os
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.event_builder import build_test_event
from extensions.business.cybersec.red_mesh.services.integration_status import (
  get_integration_status,
  test_event_export as build_integration_test_event,
)
from extensions.business.cybersec.red_mesh.services.log_export import (
  WAZUH_EVENT_GROUPS,
  build_wazuh_decoder_rules_example,
  deliver_wazuh_event,
  format_syslog_json_line,
)


def _owner(wazuh_config=None, event_config=None):
  owner = MagicMock()
  owner.cfg_instance_id = "tenant-a"
  owner.cfg_ee_node_network = "devnet"
  owner.cfg_wazuh_export = {
    "ENABLED": True,
    "MODE": "syslog",
    "SYSLOG_HOST": "127.0.0.1",
    "SYSLOG_PORT": 5514,
    "TIMEOUT_SECONDS": 0.25,
    "RETRY_ATTEMPTS": 0,
    **(wazuh_config or {}),
  }
  owner.cfg_event_export = {
    "SIGN_PAYLOADS": True,
    "HMAC_SECRET_ENV": "REDMESH_EVENT_HMAC_SECRET",
    **(event_config or {}),
  }
  records = {}

  def hget(hkey, key):
    return records.get((hkey, key))

  def hset(hkey, key, value):
    records[(hkey, key)] = value

  owner.chainstore_hget.side_effect = hget
  owner.chainstore_hset.side_effect = hset
  owner._records = records
  return owner


def _event():
  return build_test_event(
    hmac_secret="tenant-secret",
    tenant_id="tenant-a",
    environment="devnet",
  )


class TestWazuhExport(unittest.TestCase):

  def tearDown(self):
    os.environ.pop("REDMESH_EVENT_HMAC_SECRET", None)

  @patch("extensions.business.cybersec.red_mesh.services.log_export.socket.socket")
  def test_syslog_export_emits_one_signed_single_line_json_event(self, socket_factory):
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "signing-secret"
    sock = MagicMock()
    socket_factory.return_value.__enter__.return_value = sock
    owner = _owner()
    event = _event()

    result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "sent")
    sock.settimeout.assert_called_once_with(0.25)
    sent_payload, destination = sock.sendto.call_args.args
    self.assertEqual(destination, ("127.0.0.1", 5514))
    wire = sent_payload.decode("utf-8")
    self.assertEqual(wire.count("\n"), 1)
    payload = json.loads(wire.strip())
    self.assertEqual(payload["schema"], "redmesh.event.v1")
    self.assertEqual(payload["event_id"], event["event_id"])
    self.assertEqual(payload["redmesh_idempotency_key"], event["dedupe_key"])
    self.assertTrue(payload["redmesh_signature"].startswith("sha256="))

  def test_format_syslog_json_line_has_no_embedded_newline(self):
    line = format_syslog_json_line(_event(), signature="abc123")

    self.assertNotIn("\n", line)
    payload = json.loads(line)
    self.assertEqual(payload["redmesh_signature"], "sha256=abc123")
    self.assertEqual(payload["redmesh_idempotency_key"], payload["dedupe_key"])

  @patch("extensions.business.cybersec.red_mesh.services.log_export.socket.socket")
  def test_disabled_export_records_failure_without_sending(self, socket_factory):
    owner = _owner({"ENABLED": False})
    event = _event()

    result = deliver_wazuh_event(owner, event)

    self.assertEqual(result["status"], "disabled")
    self.assertEqual(result["error"], "disabled")
    socket_factory.assert_not_called()
    status = get_integration_status(owner)["integrations"]["wazuh"]
    self.assertFalse(status["enabled"])
    self.assertEqual(status["last_error_class"], "disabled")

  @patch("extensions.business.cybersec.red_mesh.services.log_export.socket.socket")
  def test_wazuh_test_event_endpoint_performs_dry_run_delivery(self, socket_factory):
    os.environ["REDMESH_EVENT_HMAC_SECRET"] = "signing-secret"
    sock = MagicMock()
    socket_factory.return_value.__enter__.return_value = sock
    owner = _owner()

    result = build_integration_test_event(owner, integration_id="wazuh")

    self.assertEqual(result["status"], "sent")
    self.assertEqual(result["integration_id"], "wazuh")
    status = get_integration_status(owner)["integrations"]["wazuh"]
    self.assertIsNotNone(status["last_dry_run_at"])
    self.assertIsNotNone(status["last_success_at"])
    self.assertEqual(status["last_event_id"], result["event_id"])

  def test_wazuh_decoder_rules_cover_required_event_groups(self):
    example = build_wazuh_decoder_rules_example()
    rule_groups = {rule["group"] for rule in example["rules"]}

    self.assertEqual(set(WAZUH_EVENT_GROUPS), rule_groups)
    self.assertIn("redmesh.lifecycle", rule_groups)
    self.assertIn("redmesh.service_observation", rule_groups)
    self.assertIn("redmesh.finding", rule_groups)
    self.assertIn("redmesh.export", rule_groups)
    self.assertIn("redmesh.attestation", rule_groups)
    self.assertIn("redmesh.correlation", rule_groups)


if __name__ == "__main__":
  unittest.main()
