import json
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.event_builder import (
  build_assessment_window,
  build_lifecycle_event,
)
from extensions.business.cybersec.red_mesh.services.event_redaction import (
  contains_sensitive_value,
  redact_event_payload,
)
from extensions.business.cybersec.red_mesh.services.event_hooks import emit_lifecycle_event


def _job_specs():
  return {
    "job_id": "job-1",
    "job_pass": 2,
    "date_created": 1770000000,
    "start_port": 1,
    "end_port": 1024,
    "exceptions": [25],
    "scan_type": "network",
    "run_mode": "SINGLEPASS",
    "target": "10.0.0.5",
    "authorized": True,
    "authorization_id": "scope-1",
    "authorization_ref": "QmAuth",
    "workers": {
      "0xai_worker_a": {"start_port": 1, "end_port": 512},
      "0xai_worker_b": {"start_port": 513, "end_port": 1024},
    },
    "pass_reports": [
      {"pass_nr": 2, "report_cid": "QmPass"},
    ],
  }


def _owner():
  owner = MagicMock()
  owner.cfg_instance_id = "tenant-a"
  owner.cfg_ee_node_network = "devnet"
  owner.cfg_event_export = {"ENABLED": True, "SIGN_PAYLOADS": False}
  owner.cfg_wazuh_export = {"ENABLED": True, "MODE": "syslog", "SYSLOG_HOST": "127.0.0.1"}
  owner.cfg_suricata_correlation = {
    "ENABLED": True,
    "MATCH_WINDOW_SECONDS": 420,
    "CLOCK_SKEW_SECONDS": 30,
    "AUTO_SUPPRESS": True,
  }
  owner.time.return_value = 1770000300
  return owner


class TestAssessmentNotice(unittest.TestCase):

  def test_assessment_window_uses_pseudonyms_and_complete_filter_fields(self):
    window = build_assessment_window(
      _job_specs(),
      hmac_secret="tenant-secret",
      pass_nr=2,
      actual_end_at=1770000120,
      expected_egress_ips=["198.51.100.20", "198.51.100.21"],
      report_refs={"pass_report_cid": "QmPass", "aggregated_report_cid": "QmAgg"},
      grace_seconds=300,
      clock_skew_seconds=60,
    )

    self.assertEqual(window["started_at"], "2026-02-02T02:40:00Z")
    self.assertEqual(window["actual_end_at"], "2026-02-02T02:42:00Z")
    self.assertEqual(window["grace_seconds"], 300)
    self.assertEqual(window["clock_skew_seconds"], 60)
    self.assertEqual(window["source_node_ids"], ["0xai_worker_a", "0xai_worker_b"])
    self.assertEqual(window["ports"], {"start": 1, "end": 1024, "count": 1023, "exceptions": [25]})
    self.assertEqual(window["protocols"], ["tcp"])
    self.assertEqual(window["authorization_context"]["authorization_ref"], "QmAuth")
    self.assertEqual(window["report_refs"]["aggregated_report_cid"], "QmAgg")
    self.assertEqual(window["expected_egress_ip_count"], 2)
    self.assertTrue(all(value.startswith("ip:") for value in window["expected_egress_ip_pseudonyms"]))
    self.assertTrue(window["target_pseudonym"].startswith("target:"))
    self.assertIsNone(window["target_display"])
    self.assertFalse(contains_sensitive_value(window, ["10.0.0.5", "198.51.100.20", "198.51.100.21"]))

  def test_lifecycle_event_includes_assessment_window_notice(self):
    event = build_lifecycle_event(
      _job_specs(),
      event_type="redmesh.job.started",
      event_action="started",
      hmac_secret="tenant-secret",
      pass_nr=2,
    )

    self.assertEqual(event["event_type"], "redmesh.job.started")
    self.assertEqual(event["window"]["pass_nr"], 2)
    self.assertEqual(event["window"]["source_node_count"], 2)
    self.assertEqual(event["window"]["authorization_context"]["authorization_id"], "scope-1")
    self.assertNotIn("10.0.0.5", json.dumps(event, sort_keys=True))

  def test_redaction_removes_raw_window_targets_and_egress_ips(self):
    redacted = redact_event_payload(
      {
        "window": {
          "expected_egress_ips": ["198.51.100.20"],
          "target_ip": "10.0.0.5",
          "target_display": "10.0.0.5",
        },
      },
      hmac_secret="tenant-secret",
    )

    self.assertIsNone(redacted["window"]["target_display"])
    self.assertTrue(redacted["window"]["target_pseudonym"].startswith("target:"))
    self.assertEqual(redacted["window"]["expected_egress_ip_count"], 1)
    self.assertTrue(redacted["window"]["expected_egress_ip_pseudonyms"][0].startswith("ip:"))
    self.assertFalse(contains_sensitive_value(redacted, ["10.0.0.5", "198.51.100.20"]))

  @patch("extensions.business.cybersec.red_mesh.services.event_hooks.deliver_redmesh_event")
  def test_hook_applies_suricata_window_config_without_suppression_control(self, deliver):
    seen_events = []

    def _sent(_owner, event, integration_id="wazuh"):
      seen_events.append(event)
      return {
        "status": "sent",
        "integration_id": integration_id,
        "event_id": event["event_id"],
        "dedupe_key": event["dedupe_key"],
      }

    deliver.side_effect = _sent
    result = emit_lifecycle_event(
      _owner(),
      _job_specs(),
      event_type="redmesh.job.pass_completed",
      event_action="pass_completed",
      pass_nr=2,
      actual_end_at=1770000120,
      expected_egress_ips=["198.51.100.20"],
      report_refs={"pass_report_cid": "QmPass"},
    )

    self.assertEqual(result["status"], "sent")
    window = seen_events[0]["window"]
    self.assertEqual(window["grace_seconds"], 420)
    self.assertEqual(window["clock_skew_seconds"], 30)
    self.assertNotIn("auto_suppress", json.dumps(seen_events[0], sort_keys=True).lower())
    self.assertFalse(contains_sensitive_value(seen_events[0], ["198.51.100.20", "10.0.0.5"]))

  def test_security_onion_examples_do_not_add_suppression_guidance(self):
    with open("docs/suricata-security-onion-examples.md", "r", encoding="utf-8") as handle:
      content = handle.read().lower()

    self.assertIn("event.dataset:suricata.eve", content)
    self.assertIn("window.started_at", content)
    self.assertIn("authorization_ref", content)
    self.assertNotIn("disable rule", content)
    self.assertNotIn("suppress rule", content)


if __name__ == "__main__":
  unittest.main()
