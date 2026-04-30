"""
Tests for the MISP export module.

Covers:
  - Config normalization
  - MISP event building (findings → vulnerability, ports → ip-port, TLS → x509)
  - Severity filtering (MIN_SEVERITY)
  - Export status tracking
  - Push to MISP (mocked PyMISP client)
  - Error handling (disabled, not configured, auth error, connection error)
"""

import time
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.services.misp_config import (
  get_misp_export_config,
  DEFAULT_MISP_EXPORT_CONFIG,
  SEVERITY_LEVELS,
)
from extensions.business.cybersec.red_mesh.services.misp_export import (
  _passes_severity_filter,
  _build_misp_event,
  _extract_tls_data,
  build_misp_event,
  export_misp_json,
  get_misp_export_status,
  push_to_misp,
)


# ── Test fixtures ──

def _make_owner(misp_config=None):
  """Build a minimal owner with MISP config that resolve_config_block can read."""
  config = dict(DEFAULT_MISP_EXPORT_CONFIG)
  if misp_config:
    config.update(misp_config)

  class Owner:
    CONFIG = {"MISP_EXPORT": config}
    config_data = {}
    messages = []
    def P(self, msg, **kwargs):
      self.messages.append(msg)
    def time(self):
      return time.time()

  return Owner()


def _sample_findings():
  return [
    {
      "finding_id": "abc123",
      "severity": "CRITICAL",
      "title": "SQL Injection in login form",
      "description": "The login endpoint is vulnerable to SQL injection.",
      "evidence": "param=username, payload=' OR 1=1--",
      "remediation": "Use parameterized queries.",
      "owasp_id": "A03:2021",
      "cwe_id": "CWE-89",
      "confidence": "certain",
      "cvss_score": 9.8,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
      "port": 443,
      "protocol": "https",
      "probe": "_web_test_sql_injection",
      "category": "web",
    },
    {
      "finding_id": "def456",
      "severity": "MEDIUM",
      "title": "Missing HSTS header",
      "description": "The server does not set Strict-Transport-Security.",
      "evidence": "",
      "remediation": "Add HSTS header with max-age >= 31536000.",
      "owasp_id": "A05:2021",
      "cwe_id": "CWE-693",
      "confidence": "firm",
      "cvss_score": 4.3,
      "port": 443,
      "protocol": "https",
      "probe": "_web_test_security_headers",
      "category": "web",
    },
    {
      "finding_id": "ghi789",
      "severity": "INFO",
      "title": "Server responds on port 80",
      "description": "HTTP service detected.",
      "port": 80,
      "protocol": "http",
      "probe": "_service_info_http",
      "category": "service",
      "confidence": "certain",
    },
    {
      "finding_id": "jkl012",
      "severity": "HIGH",
      "title": "Privilege escalation via IDOR",
      "description": "Authenticated user can access other users' data.",
      "owasp_id": "A01:2021",
      "cwe_id": "CWE-639",
      "confidence": "certain",
      "cvss_score": 8.1,
      "port": 443,
      "protocol": "https",
      "probe": "_graybox_access_control",
      "category": "graybox",
      "attack_ids": ["T1078"],
      "scenario_id": "PT-A01-01",
    },
  ]


def _sample_aggregated():
  return {
    "open_ports": [22, 80, 443],
    "port_banners": {"22": "SSH-2.0-OpenSSH_8.9", "80": ""},
    "port_protocols": {"22": "ssh", "80": "http", "443": "https"},
    "service_info": {
      "443/tcp": {
        "_service_info_tls": {
          "certificate": {
            "issuer": "CN=Let's Encrypt Authority X3, O=Let's Encrypt",
            "subject": "CN=example.com",
            "serial": "1234567890",
            "not_before": "2026-01-01",
            "not_after": "2026-04-01",
          }
        }
      }
    },
  }


def _sample_pass_report(findings=None, aggregated_report_cid="agg_cid_123"):
  return {
    "pass_nr": 1,
    "date_started": 1712500000.0,
    "date_completed": 1712500600.0,
    "duration": 600.0,
    "aggregated_report_cid": aggregated_report_cid,
    "risk_score": 72,
    "quick_summary": "Critical SQL injection found on port 443.",
    "findings": findings or _sample_findings(),
  }


def _sample_archive(findings=None):
  return {
    "job_id": "test_job_1",
    "job_config": {
      "target": "10.0.0.1",
      "scan_type": "network",
      "task_name": "Weekly scan",
      "start_port": 1,
      "end_port": 1024,
    },
    "passes": [_sample_pass_report(findings)],
    "timeline": [],
    "ui_aggregate": {},
    "duration": 600.0,
    "date_created": 1712500000.0,
    "date_completed": 1712500600.0,
  }


# ── Config tests ──

class TestMispConfig(unittest.TestCase):

  def test_defaults_returned_when_no_override(self):
    owner = _make_owner()
    owner.CONFIG = {}
    cfg = get_misp_export_config(owner)
    self.assertFalse(cfg["ENABLED"])
    self.assertEqual(cfg["MIN_SEVERITY"], "LOW")
    self.assertEqual(cfg["TIMEOUT"], 30.0)

  def test_enabled_override(self):
    owner = _make_owner({"ENABLED": True, "MISP_URL": "https://misp.test", "MISP_API_KEY": "key123"})
    cfg = get_misp_export_config(owner)
    self.assertTrue(cfg["ENABLED"])
    self.assertEqual(cfg["MISP_URL"], "https://misp.test")
    self.assertEqual(cfg["MISP_API_KEY"], "key123")

  def test_url_trailing_slash_stripped(self):
    owner = _make_owner({"MISP_URL": "https://misp.test/"})
    cfg = get_misp_export_config(owner)
    self.assertEqual(cfg["MISP_URL"], "https://misp.test")

  def test_invalid_distribution_falls_back(self):
    owner = _make_owner({"MISP_DISTRIBUTION": 99})
    cfg = get_misp_export_config(owner)
    self.assertEqual(cfg["MISP_DISTRIBUTION"], 0)

  def test_invalid_timeout_falls_back(self):
    owner = _make_owner({"TIMEOUT": -5})
    cfg = get_misp_export_config(owner)
    self.assertEqual(cfg["TIMEOUT"], 30.0)

  def test_invalid_severity_falls_back(self):
    owner = _make_owner({"MIN_SEVERITY": "ULTRA"})
    cfg = get_misp_export_config(owner)
    self.assertEqual(cfg["MIN_SEVERITY"], "LOW")

  def test_valid_severity_accepted(self):
    for sev in SEVERITY_LEVELS:
      owner = _make_owner({"MIN_SEVERITY": sev})
      cfg = get_misp_export_config(owner)
      self.assertEqual(cfg["MIN_SEVERITY"], sev)


# ── Severity filter tests ──

class TestSeverityFilter(unittest.TestCase):

  def test_critical_passes_all_thresholds(self):
    f = {"severity": "CRITICAL"}
    for sev in SEVERITY_LEVELS:
      self.assertTrue(_passes_severity_filter(f, sev))

  def test_info_only_passes_info(self):
    f = {"severity": "INFO"}
    self.assertTrue(_passes_severity_filter(f, "INFO"))
    self.assertFalse(_passes_severity_filter(f, "LOW"))
    self.assertFalse(_passes_severity_filter(f, "MEDIUM"))

  def test_medium_passes_medium_low_info(self):
    f = {"severity": "MEDIUM"}
    self.assertTrue(_passes_severity_filter(f, "MEDIUM"))
    self.assertTrue(_passes_severity_filter(f, "LOW"))
    self.assertTrue(_passes_severity_filter(f, "INFO"))
    self.assertFalse(_passes_severity_filter(f, "HIGH"))

  def test_default_low_filters_info(self):
    findings = _sample_findings()
    filtered = [f for f in findings if _passes_severity_filter(f, "LOW")]
    severities = {f["severity"] for f in filtered}
    self.assertNotIn("INFO", severities)
    self.assertIn("CRITICAL", severities)
    self.assertIn("HIGH", severities)
    self.assertIn("MEDIUM", severities)


# ── MISP event building tests ──

class TestBuildMispEvent(unittest.TestCase):

  def test_event_metadata(self):
    findings = [f for f in _sample_findings() if f["severity"] != "INFO"]
    event = _build_misp_event(
      target="10.0.0.1", scan_type="network", task_name="Test",
      job_id="job1", risk_score=72, report_cid="cid123",
      distribution=0, findings=findings, open_ports=[22, 80, 443],
      port_banners={"22": "SSH-2.0-OpenSSH_8.9"},
      port_protocols={"22": "ssh", "80": "http", "443": "https"},
      quick_summary="Test summary",
    )
    self.assertIn("RedMesh Scan: 10.0.0.1 (network)", event.info)
    self.assertIn("Test", event.info)
    self.assertEqual(event.distribution, 0)
    self.assertEqual(event.analysis, 2)
    # Threat level should be 1 (High) because CRITICAL finding exists
    self.assertEqual(event.threat_level_id, 1)

  def test_tags_present(self):
    event = _build_misp_event(
      target="10.0.0.1", scan_type="network", task_name="",
      job_id="job1", risk_score=50, report_cid="cid123",
      distribution=0, findings=[], open_ports=[], port_banners={},
      port_protocols={}, quick_summary=None,
    )
    tag_names = [t.name for t in event.tags]
    self.assertIn("redmesh:job_id=job1", tag_names)
    self.assertIn("redmesh:report_cid=cid123", tag_names)
    self.assertIn("tlp:amber", tag_names)

  def test_ip_port_objects(self):
    event = _build_misp_event(
      target="10.0.0.1", scan_type="network", task_name="",
      job_id="job1", risk_score=0, report_cid="",
      distribution=0, findings=[], open_ports=[22, 443],
      port_banners={"22": "SSH-2.0-OpenSSH_8.9"},
      port_protocols={"22": "ssh", "443": "https"},
      quick_summary=None,
    )
    ip_port_objects = [o for o in event.objects if o.name == "ip-port"]
    self.assertEqual(len(ip_port_objects), 2)
    # Check port 22 has banner
    port22 = next(o for o in ip_port_objects
                  if any(a.value == 22 for a in o.attributes if a.object_relation == "dst-port"))
    banner_attrs = [a for a in port22.attributes if a.object_relation == "text"]
    self.assertEqual(len(banner_attrs), 1)
    self.assertIn("OpenSSH", banner_attrs[0].value)

  def test_vulnerability_objects(self):
    findings = _sample_findings()[:2]  # CRITICAL + MEDIUM
    event = _build_misp_event(
      target="10.0.0.1", scan_type="network", task_name="",
      job_id="job1", risk_score=72, report_cid="",
      distribution=0, findings=findings, open_ports=[],
      port_banners={}, port_protocols={}, quick_summary=None,
    )
    vuln_objects = [o for o in event.objects if o.name == "vulnerability"]
    self.assertEqual(len(vuln_objects), 2)

    # Check first vuln has CWE + OWASP reference links
    sqli_vuln = vuln_objects[0]
    refs = [a for a in sqli_vuln.attributes if a.object_relation == "references"]
    self.assertEqual(len(refs), 2)
    ref_values = [r.value for r in refs]
    self.assertTrue(any("cwe.mitre.org" in v for v in ref_values))
    self.assertTrue(any("owasp.org" in v for v in ref_values))

    # Check CVSS score
    cvss = [a for a in sqli_vuln.attributes if a.object_relation == "cvss-score"]
    self.assertEqual(len(cvss), 1)
    self.assertEqual(cvss[0].value, "9.8")

  def test_graybox_attack_ids_tagged(self):
    finding = dict(_sample_findings()[3])  # The IDOR finding with attack_ids
    # Remove owasp_id to avoid second references attribute
    finding.pop("owasp_id", None)
    event = _build_misp_event(
      target="10.0.0.1", scan_type="webapp", task_name="",
      job_id="job1", risk_score=50, report_cid="",
      distribution=0, findings=[finding], open_ports=[],
      port_banners={}, port_protocols={}, quick_summary=None,
    )
    vuln = event.objects[0]
    id_attr = [a for a in vuln.attributes if a.object_relation == "id"][0]
    tag_names = [t.name for t in id_attr.tags]
    self.assertIn("mitre-attack:T1078", tag_names)

  def test_x509_objects(self):
    tls_data = [{
      "issuer": "CN=Let's Encrypt",
      "subject": "CN=example.com",
      "serial": "123456",
      "not_before": "2026-01-01",
      "not_after": "2026-04-01",
      "port": 443,
    }]
    event = _build_misp_event(
      target="10.0.0.1", scan_type="network", task_name="",
      job_id="job1", risk_score=0, report_cid="",
      distribution=0, findings=[], open_ports=[443],
      port_banners={}, port_protocols={"443": "https"},
      quick_summary=None, tls_data=tls_data,
    )
    x509_objects = [o for o in event.objects if o.name == "x509"]
    self.assertEqual(len(x509_objects), 1)
    x509 = x509_objects[0]
    issuer = [a for a in x509.attributes if a.object_relation == "issuer"]
    self.assertEqual(issuer[0].value, "CN=Let's Encrypt")

  def test_quick_summary_attribute(self):
    event = _build_misp_event(
      target="10.0.0.1", scan_type="network", task_name="",
      job_id="job1", risk_score=72, report_cid="",
      distribution=0, findings=[], open_ports=[],
      port_banners={}, port_protocols={},
      quick_summary="Critical SQLi found.",
    )
    text_attrs = [a for a in event.attributes if a.type == "text"]
    self.assertTrue(any("Critical SQLi" in a.value for a in text_attrs))

  def test_no_findings_produces_valid_event(self):
    event = _build_misp_event(
      target="10.0.0.1", scan_type="network", task_name="",
      job_id="job1", risk_score=0, report_cid="",
      distribution=0, findings=[], open_ports=[],
      port_banners={}, port_protocols={}, quick_summary=None,
    )
    self.assertIn("RedMesh Scan", event.info)
    self.assertEqual(event.threat_level_id, 4)  # Undefined when no findings


# ── TLS extraction tests ──

class TestExtractTlsData(unittest.TestCase):

  def test_extracts_cert_from_service_info(self):
    aggregated = _sample_aggregated()
    certs = _extract_tls_data(aggregated)
    self.assertEqual(len(certs), 1)
    self.assertEqual(certs[0]["subject"], "CN=example.com")
    self.assertEqual(certs[0]["port"], 443)

  def test_no_tls_returns_empty(self):
    certs = _extract_tls_data({"service_info": {"80/tcp": {"_service_info_http": {}}}})
    self.assertEqual(len(certs), 0)

  def test_no_structured_cert_returns_empty(self):
    aggregated = {"service_info": {"443/tcp": {"_service_info_tls": {"version": "TLSv1.3"}}}}
    certs = _extract_tls_data(aggregated)
    self.assertEqual(len(certs), 0)


# ── Integration-level tests (mocked owner + artifacts) ──

def _make_integration_owner(misp_config=None, archive=None, aggregated=None, job_specs=None):
  """Build an owner with artifact repo for integration tests."""
  config = dict(DEFAULT_MISP_EXPORT_CONFIG)
  config.update(misp_config or {"ENABLED": True})
  archive_data = archive or _sample_archive()
  aggregated_data = aggregated or _sample_aggregated()
  default_job_specs = job_specs or {
    "job_id": "test_job_1",
    "job_cid": "archive_cid_123",
  }

  class FakeArtifactRepo:
    def get_archive(self, js):
      return archive_data
    def get_json(self, cid):
      return aggregated_data
    def get_job_config(self, js):
      return archive_data.get("job_config", {})

  class IntegrationOwner:
    CONFIG = {"MISP_EXPORT": config}
    config_data = {}
    messages = []
    def P(self, msg, **kwargs):
      self.messages.append(msg)
    def time(self):
      return time.time()
    def _get_job_from_cstore(self, job_id):
      return dict(default_job_specs)
    def _get_artifact_repository(self):
      return FakeArtifactRepo()
    def _write_job_record(self, job_key, job_specs, context=""):
      return job_specs

  return IntegrationOwner()


class TestBuildMispEventIntegration(unittest.TestCase):
  """Test build_misp_event with a mocked owner that returns archive data."""

  def _setup_owner(self, misp_config=None, archive=None, aggregated=None):
    return _make_integration_owner(misp_config, archive, aggregated)

  def test_builds_event_from_archive(self):
    owner = self._setup_owner()
    result = build_misp_event(owner, "test_job_1")
    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["pass_nr"], 1)
    self.assertEqual(result["target"], "10.0.0.1")
    # Default MIN_SEVERITY=LOW filters out INFO
    self.assertEqual(result["findings_exported"], 3)
    self.assertEqual(result["findings_total"], 4)
    self.assertEqual(result["ports_exported"], 3)

  def test_severity_filter_medium(self):
    owner = self._setup_owner({"ENABLED": True, "MIN_SEVERITY": "MEDIUM"})
    result = build_misp_event(owner, "test_job_1")
    self.assertEqual(result["findings_exported"], 3)  # CRITICAL + HIGH + MEDIUM

  def test_severity_filter_high(self):
    owner = self._setup_owner({"ENABLED": True, "MIN_SEVERITY": "HIGH"})
    result = build_misp_event(owner, "test_job_1")
    # CRITICAL + HIGH
    self.assertEqual(result["findings_exported"], 2)

  def test_severity_filter_critical(self):
    owner = self._setup_owner({"ENABLED": True, "MIN_SEVERITY": "CRITICAL"})
    result = build_misp_event(owner, "test_job_1")
    self.assertEqual(result["findings_exported"], 1)

  def test_job_not_found(self):
    owner = self._setup_owner()
    owner._get_job_from_cstore = MagicMock(return_value=None)
    result = build_misp_event(owner, "nonexistent")
    self.assertEqual(result["status"], "error")


class TestExportMispJson(unittest.TestCase):

  def test_returns_misp_dict(self):
    owner = _make_integration_owner({"ENABLED": True})
    result = export_misp_json(owner, "test_job_1")
    self.assertEqual(result["status"], "ok")
    self.assertIn("misp_event", result)
    self.assertIsInstance(result["misp_event"], dict)

  def test_disabled_returns_status(self):
    owner = _make_integration_owner({"ENABLED": False})
    result = export_misp_json(owner, "test_job_1")
    self.assertEqual(result["status"], "disabled")


class TestGetMispExportStatus(unittest.TestCase):

  def test_not_exported(self):
    owner = _make_integration_owner(job_specs={"job_id": "j1", "job_cid": "cid"})
    result = get_misp_export_status(owner, "j1")
    self.assertFalse(result["exported"])

  def test_exported(self):
    owner = _make_integration_owner(job_specs={
      "job_id": "j1",
      "job_cid": "cid",
      "misp_export": {
        "event_uuid": "uuid-123",
        "event_id": 42,
        "misp_url": "https://misp.test",
        "last_exported_at": 1712600000.0,
        "passes_exported": [1],
      },
    })
    result = get_misp_export_status(owner, "j1")
    self.assertTrue(result["exported"])
    self.assertEqual(result["event_uuid"], "uuid-123")
    self.assertEqual(result["passes_exported"], [1])

  def test_job_not_found(self):
    class NoJobOwner:
      CONFIG = {"MISP_EXPORT": DEFAULT_MISP_EXPORT_CONFIG}
      config_data = {}
      def P(self, msg, **kwargs): pass
      def _get_job_from_cstore(self, job_id): return None
    result = get_misp_export_status(NoJobOwner(), "nonexistent")
    self.assertFalse(result["exported"])


class TestPushToMisp(unittest.TestCase):

  def _setup_owner(self, misp_config=None, job_specs=None):
    config = {
      "ENABLED": True,
      "MISP_URL": "https://misp.test",
      "MISP_API_KEY": "testkey123",
      **(misp_config or {}),
    }
    return _make_integration_owner(config, job_specs=job_specs)

  def test_disabled(self):
    owner = self._setup_owner({"ENABLED": False})
    result = push_to_misp(owner, "test_job_1")
    self.assertEqual(result["status"], "disabled")

  def test_not_configured(self):
    owner = self._setup_owner({"MISP_URL": "", "MISP_API_KEY": ""})
    result = push_to_misp(owner, "test_job_1")
    self.assertEqual(result["status"], "not_configured")

  @patch("extensions.business.cybersec.red_mesh.services.misp_export.PyMISP")
  def test_successful_push(self, MockPyMISP):
    from pymisp import MISPEvent
    mock_misp = MockPyMISP.return_value

    response_event = MISPEvent()
    response_event.uuid = "new-uuid-456"
    response_event.id = 99
    mock_misp.add_event.return_value = response_event

    owner = self._setup_owner()
    result = push_to_misp(owner, "test_job_1")

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["event_uuid"], "new-uuid-456")
    self.assertEqual(result["event_id"], 99)
    mock_misp.add_event.assert_called_once()

  @patch("extensions.business.cybersec.red_mesh.services.misp_export.PyMISP")
  def test_connection_error(self, MockPyMISP):
    MockPyMISP.side_effect = Exception("Connection refused")

    owner = self._setup_owner()
    result = push_to_misp(owner, "test_job_1")

    self.assertEqual(result["status"], "error")
    self.assertTrue(result["retryable"])

  @patch("extensions.business.cybersec.red_mesh.services.misp_export.PyMISP")
  def test_reexport_updates_existing(self, MockPyMISP):
    from pymisp import MISPEvent
    mock_misp = MockPyMISP.return_value

    existing_event = MISPEvent()
    existing_event.uuid = "existing-uuid"
    existing_event.id = 50
    mock_misp.get_event.return_value = existing_event
    mock_misp.update_event.return_value = existing_event
    mock_misp.add_object.return_value = MagicMock()

    owner = self._setup_owner(job_specs={
      "job_id": "test_job_1",
      "job_cid": "archive_cid_123",
      "misp_export": {
        "event_uuid": "existing-uuid",
        "event_id": 50,
        "passes_exported": [1],
      },
    })

    result = push_to_misp(owner, "test_job_1")

    self.assertEqual(result["status"], "ok")
    mock_misp.get_event.assert_called_once_with("existing-uuid", pythonify=True)
    mock_misp.update_event.assert_called_once()
    mock_misp.add_event.assert_not_called()


if __name__ == "__main__":
  unittest.main()
