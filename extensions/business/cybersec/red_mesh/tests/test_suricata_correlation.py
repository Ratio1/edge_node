import json
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.services.integration_status import get_integration_status
from extensions.business.cybersec.red_mesh.services.suricata_correlation import (
  correlate_suricata_eve,
  get_detection_correlation,
)


def _owner(job_specs):
  owner = MagicMock()
  owner.cfg_instance_id = "tenant-a"
  owner.cfg_suricata_correlation = {
    "ENABLED": True,
    "MATCH_WINDOW_SECONDS": 300,
    "CLOCK_SKEW_SECONDS": 60,
    "INCLUDE_TARGET_DISPLAY": False,
    "AUTO_SUPPRESS": True,
  }
  owner._get_job_from_cstore.return_value = job_specs
  owner.r1fs.add_json.return_value = "QmCorrelation"
  records = {}

  def hget(hkey, key):
    return records.get((hkey, key))

  def hset(hkey, key, value):
    records[(hkey, key)] = value
    return True

  owner.chainstore_hget.side_effect = hget
  owner.chainstore_hset.side_effect = hset
  owner._records = records
  return owner


def _job_specs():
  return {
    "job_id": "job-1",
    "job_status": "RUNNING",
    "target": "10.0.0.5",
    "start_port": 1,
    "end_port": 1024,
    "date_created": 1770000000,
    "job_pass": 1,
    "workers": {},
  }


def _eve_jsonl():
  return "\n".join([
    json.dumps({
      "timestamp": "2026-02-02T02:40:30Z",
      "event_type": "alert",
      "src_ip": "198.51.100.20",
      "dest_ip": "10.0.0.5",
      "dest_port": 443,
      "proto": "TCP",
      "flow_id": 12345,
      "sensor_name": "sensor-a",
      "alert": {
        "signature": "ET SCAN Possible Nmap User-Agent",
        "category": "Attempted Information Leak",
        "severity": 2,
      },
    }),
    json.dumps({
      "timestamp": "2026-02-02T02:41:00Z",
      "event_type": "flow",
      "src_ip": "198.51.100.20",
      "dest_ip": "10.0.0.5",
      "dest_port": 80,
      "proto": "TCP",
      "flow_id": 67890,
      "sensor_name": "sensor-a",
    }),
    json.dumps({
      "timestamp": "2026-02-02T02:41:00Z",
      "event_type": "alert",
      "src_ip": "203.0.113.50",
      "dest_ip": "10.0.0.55",
      "dest_port": 8080,
      "sensor_name": "sensor-b",
    }),
  ])


class TestSuricataCorrelation(unittest.TestCase):

  def test_correlates_eve_jsonl_and_persists_redacted_summary(self):
    job_specs = _job_specs()
    owner = _owner(job_specs)

    result = correlate_suricata_eve(
      owner,
      "job-1",
      eve_jsonl=_eve_jsonl(),
      source_ips=["198.51.100.20"],
      pass_nr=1,
    )

    self.assertEqual(result["status"], "ok")
    summary = result["correlation"]
    self.assertEqual(summary["status"], "completed")
    self.assertEqual(summary["counts"]["events_received"], 3)
    self.assertEqual(summary["counts"]["matched_events"], 2)
    self.assertEqual(summary["counts"]["matched_alerts"], 1)
    self.assertEqual(summary["counts"]["matched_flows"], 1)
    self.assertEqual(summary["counts"]["unmatched_high_signal"], 1)
    self.assertEqual(summary["sensors_observed"], ["sensor-a"])
    self.assertEqual(summary["confidence"], "high")
    self.assertEqual(summary["artifact_cid"], "QmCorrelation")
    self.assertEqual(job_specs["detection_correlation"]["artifact_cid"], "QmCorrelation")

    evidence = owner.r1fs.add_json.call_args.args[0]
    serialized = json.dumps(evidence, sort_keys=True)
    self.assertIn("src_ip_pseudonym", serialized)
    self.assertIn("dest_ip_pseudonym", serialized)
    self.assertNotIn("198.51.100.20", serialized)
    self.assertNotIn("10.0.0.5", serialized)
    self.assertNotIn("auto_suppress", serialized.lower())

    status = get_integration_status(owner)["integrations"]["suricata"]
    self.assertEqual(status["last_artifact_cid"], "QmCorrelation")
    self.assertIsNotNone(status["last_success_at"])

  def test_empty_correlation_records_non_detection_caveat_without_artifact(self):
    owner = _owner(_job_specs())

    result = correlate_suricata_eve(
      owner,
      "job-1",
      eve_jsonl=json.dumps({
        "timestamp": "2026-02-02T02:40:30Z",
        "event_type": "alert",
        "dest_ip": "10.0.0.55",
        "dest_port": 9999,
      }),
    )

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["correlation"]["status"], "empty")
    self.assertIsNone(result["correlation"]["artifact_cid"])
    self.assertIn("not proof of non-detection", result["correlation"]["message"])
    owner.r1fs.add_json.assert_not_called()

  def test_invalid_jsonl_fails_closed_and_updates_status(self):
    owner = _owner(_job_specs())

    result = correlate_suricata_eve(owner, "job-1", eve_jsonl="{not-json}")

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "invalid_jsonl_line_1")
    status = get_integration_status(owner)["integrations"]["suricata"]
    self.assertEqual(status["last_error_class"], "invalid_jsonl_line_1")

  def test_get_detection_correlation_reads_compact_job_summary(self):
    job_specs = _job_specs()
    job_specs["detection_correlation"] = {"status": "completed", "artifact_cid": "QmCorrelation"}
    owner = _owner(job_specs)

    result = get_detection_correlation(owner, "job-1")

    self.assertTrue(result["found"])
    self.assertEqual(result["correlation"]["artifact_cid"], "QmCorrelation")


if __name__ == "__main__":
  unittest.main()
