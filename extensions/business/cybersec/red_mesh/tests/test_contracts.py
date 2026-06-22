import json
import unittest

from extensions.business.cybersec.red_mesh.findings import Finding, Severity, probe_result
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin
from extensions.business.cybersec.red_mesh.models.archive import JobArchive


class _ReportHost(_ReportMixin):
  def P(self, *_args, **_kwargs):
    return None

  def json_dumps(self, payload, **kwargs):
    return json.dumps(payload, **kwargs)


class TestArchiveContracts(unittest.TestCase):

  def test_archive_roundtrip_preserves_version(self):
    archive = JobArchive(
      archive_version=1,
      job_id="job-1",
      job_config={"target": "example.com"},
      timeline=[],
      passes=[{"pass_nr": 1, "risk_score": 10}],
      ui_aggregate={"total_open_ports": [], "total_services": 0, "total_findings": 0},
      duration=1.0,
      date_created=1.0,
      date_completed=2.0,
    )

    payload = archive.to_dict()
    restored = JobArchive.from_dict(payload)

    self.assertEqual(restored.archive_version, 1)
    self.assertEqual(restored.to_dict(), payload)


class TestFindingContracts(unittest.TestCase):

  def test_network_probe_result_exposes_required_finding_shape(self):
    finding = Finding(
      severity=Severity.HIGH,
      title="Weak TLS",
      description="TLS config is weak",
      evidence="TLS 1.0 enabled",
      confidence="firm",
    )

    result = probe_result(findings=[finding])
    persisted = result["findings"][0]

    for key in ("severity", "title", "description", "evidence", "confidence"):
      self.assertIn(key, persisted)

  def test_graybox_flat_finding_exposes_required_contract_fields(self):
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="IDOR",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
      cwe=["CWE-639"],
      evidence=["endpoint=/api/records/2", "status=200"],
    )

    flat = finding.to_flat_finding(port=443, protocol="https", probe_name="access_control")

    for key in (
      "finding_id",
      "severity",
      "title",
      "description",
      "evidence",
      "confidence",
      "port",
      "protocol",
      "probe",
      "category",
      "probe_type",
    ):
      self.assertIn(key, flat)


class TestAggregationContracts(unittest.TestCase):

  def test_aggregation_is_deterministic_under_worker_order_variation(self):
    host = _ReportHost()
    worker_a = {
      "open_ports": [80],
      "ports_scanned": [80],
      "completed_tests": ["probe-a"],
      "service_info": {"80": {"_service_info_http": {"findings": [{"title": "A"}]}}},
    }
    worker_b = {
      "open_ports": [443],
      "ports_scanned": [443],
      "completed_tests": ["probe-b"],
      "service_info": {"443": {"_service_info_https": {"findings": [{"title": "B"}]}}},
    }

    first = host._get_aggregated_report({"worker-a": worker_a, "worker-b": worker_b})
    second = host._get_aggregated_report({"worker-b": worker_b, "worker-a": worker_a})

    self.assertEqual(sorted(first["open_ports"]), sorted(second["open_ports"]))
    self.assertEqual(first["service_info"], second["service_info"])
    self.assertEqual(set(first["completed_tests"]), set(second["completed_tests"]))
