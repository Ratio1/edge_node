import json
import time
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.integration_status import get_integration_status
from extensions.business.cybersec.red_mesh.services.stix_export import (
  build_stix_bundle,
  export_stix_bundle,
  get_stix_export_status,
)


def _sample_findings():
  return [
    {
      "finding_id": "finding-1",
      "severity": "CRITICAL",
      "title": "SQL injection on 10.0.0.1 login",
      "description": "The login endpoint on 10.0.0.1 is vulnerable.",
      "evidence": "password=secret&payload=' OR 1=1--",
      "remediation": "Use parameterized queries.",
      "cwe_id": "CWE-89",
      "cve_id": "CVE-2026-0001",
      "cvss_score": 9.8,
      "port": 443,
      "protocol": "https",
      "probe": "_web_test_sql_injection",
      "category": "web",
      "confidence": "certain",
    },
    {
      "finding_id": "finding-2",
      "severity": "LOW",
      "title": "Missing security header",
      "description": "Strict-Transport-Security is missing.",
      "cwe_id": "CWE-693",
      "port": 443,
      "protocol": "https",
      "probe": "_web_test_security_headers",
      "category": "web",
      "confidence": "firm",
    },
  ]


def _sample_pass_report():
  return {
    "pass_nr": 2,
    "date_started": 1770000000.0,
    "date_completed": 1770000300.0,
    "aggregated_report_cid": "agg-cid",
    "risk_score": 88,
    "quick_summary": "Critical issue was observed on 10.0.0.1.",
    "findings": _sample_findings(),
  }


def _sample_archive():
  return {
    "job_id": "job-1",
    "job_config": {
      "target": "10.0.0.1",
      "scan_type": "network",
      "task_name": "Weekly scan",
      "start_port": 1,
      "end_port": 1024,
    },
    "passes": [_sample_pass_report()],
    "timeline": [],
    "ui_aggregate": {},
    "duration": 300.0,
    "date_created": 1770000000.0,
    "date_completed": 1770000300.0,
  }


def _sample_aggregated():
  return {
    "open_ports": [80, 443],
    "port_banners": {"80": "nginx on 10.0.0.1", "443": "Apache/2.4"},
    "port_protocols": {"80": "http", "443": "https"},
  }


class _FakeArtifactRepo:
  def __init__(self, archive, aggregated, owner):
    self.archive = archive
    self.aggregated = aggregated
    self.owner = owner

  def get_archive(self, job_specs):
    return self.archive

  def get_json(self, cid):
    if cid == "agg-cid":
      return self.aggregated
    return None

  def get_job_config(self, job_specs):
    return self.archive.get("job_config", {})

  def put_json(self, payload, *, show_logs=False):
    return self.owner.r1fs.add_json(payload, show_logs=show_logs)


def _owner(stix_config=None, job_specs=None, archive=None, aggregated=None):
  records = {}
  archive = archive or _sample_archive()
  aggregated = aggregated or _sample_aggregated()
  job_specs = job_specs or {
    "job_id": "job-1",
    "job_status": "FINALIZED",
    "target": "10.0.0.1",
    "job_cid": "archive-cid",
    "job_config_cid": "config-cid",
    "date_created": 1770000000.0,
    "date_completed": 1770000300.0,
  }

  class Owner:
    cfg_instance_id = "tenant-a"
    cfg_ee_node_network = "devnet"
    cfg_stix_export = {
      "ENABLED": True,
      "DEFAULT_TLP": "amber",
      "INCLUDE_OBSERVED_DATA": True,
      "INCLUDE_INDICATORS": "all",
      **(stix_config or {}),
    }
    config_data = {}
    CONFIG = {}

    def __init__(self):
      self.r1fs = MagicMock()
      self.r1fs.add_json.return_value = "QmStixBundle"
      self.messages = []
      self.job_specs = job_specs
      self._records = records

    def P(self, msg, **kwargs):
      self.messages.append(msg)

    def time(self):
      return time.time()

    def _get_job_from_cstore(self, job_id):
      return self.job_specs if job_id == "job-1" else None

    def _get_artifact_repository(self):
      return _FakeArtifactRepo(archive, aggregated, self)

    def _write_job_record(self, job_id, updated, context=""):
      self.job_specs = updated
      return updated

    def chainstore_hget(self, hkey, key):
      return records.get((hkey, key))

    def chainstore_hset(self, hkey, key, value):
      records[(hkey, key)] = value
      return True

  return Owner()


class TestStixExport(unittest.TestCase):

  def test_builds_stix_bundle_with_redacted_target_and_findings(self):
    owner = _owner()

    result = build_stix_bundle(owner, "job-1")

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["pass_nr"], 2)
    self.assertEqual(result["finding_count"], 2)
    bundle = result["bundle"]
    self.assertEqual(bundle["type"], "bundle")
    object_types = {obj["type"] for obj in bundle["objects"]}
    self.assertIn("report", object_types)
    self.assertIn("vulnerability", object_types)
    self.assertIn("observed-data", object_types)
    self.assertIn("indicator", object_types)

    serialized = json.dumps(bundle, sort_keys=True)
    self.assertNotIn("10.0.0.1", serialized)
    self.assertNotIn("password=secret", serialized)
    self.assertNotIn("' OR 1=1", serialized)
    self.assertIn("target:", serialized)
    self.assertIn("x_redmesh_banner_hash", serialized)

  @patch("extensions.business.cybersec.red_mesh.services.stix_export.emit_export_status_event")
  def test_export_persists_bundle_and_updates_isolated_status(self, emit_status):
    owner = _owner()

    result = export_stix_bundle(owner, "job-1")

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["artifact_cid"], "QmStixBundle")
    self.assertEqual(owner.job_specs["stix_export"]["artifact_cid"], "QmStixBundle")
    owner.r1fs.add_json.assert_called_once()
    bundle = owner.r1fs.add_json.call_args.args[0]
    self.assertEqual(bundle["type"], "bundle")
    emit_status.assert_called_once()
    self.assertEqual(emit_status.call_args.kwargs["adapter_type"], "stix")
    self.assertEqual(emit_status.call_args.kwargs["destination_label"], "stix-2.1")

    status = get_integration_status(owner)["integrations"]["stix"]
    self.assertEqual(status["last_artifact_cid"], "QmStixBundle")
    self.assertIsNotNone(status["last_success_at"])
    self.assertIsNone(status["last_error_class"])

  def test_disabled_export_does_not_build_or_persist(self):
    owner = _owner({"ENABLED": False})

    result = export_stix_bundle(owner, "job-1")

    self.assertEqual(result["status"], "disabled")
    owner.r1fs.add_json.assert_not_called()
    self.assertNotIn("stix_export", owner.job_specs)

  @patch("extensions.business.cybersec.red_mesh.services.stix_export.emit_export_status_event")
  def test_get_export_status_reads_job_metadata(self, _emit_status):
    owner = _owner()
    export_stix_bundle(owner, "job-1")

    result = get_stix_export_status(owner, "job-1")

    self.assertTrue(result["found"])
    self.assertTrue(result["exported"])
    self.assertEqual(result["artifact_cid"], "QmStixBundle")
    self.assertEqual(result["pass_nr"], 2)

  def test_missing_job_updates_stix_status_only(self):
    owner = _owner()

    result = export_stix_bundle(owner, "missing")

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "job_not_found")
    status = get_integration_status(owner)["integrations"]["stix"]
    self.assertEqual(status["last_error_class"], "job_not_found")
    self.assertIsNone(get_integration_status(owner)["integrations"]["suricata"]["last_failure_at"])


if __name__ == "__main__":
  unittest.main()
