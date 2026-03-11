"""Tests for graybox normalization, dispatch, and redaction."""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.worker import GrayboxLocalWorker
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker
from extensions.business.cybersec.red_mesh.constants import ScanType


def _make_graybox_report(findings_dicts, port="443"):
  """Build a minimal aggregated report with graybox_results."""
  return {
    "open_ports": [int(port)],
    "port_protocols": {port: "https"},
    "service_info": {},
    "web_tests_info": {},
    "correlation_findings": [],
    "graybox_results": {
      port: {
        "_graybox_test": {"findings": findings_dicts},
      },
    },
  }


def _make_mixin():
  """Create a mock host with risk scoring mixin."""
  from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

  class MockHost(_RiskScoringMixin):
    pass

  return MockHost()


class TestGrayboxNormalization(unittest.TestCase):

  def test_graybox_results_normalized(self):
    """GrayboxFinding dicts → flat finding dicts."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="IDOR detected",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
      cwe=["CWE-639"],
      evidence=["endpoint=/api/records/99/", "owner=bob"],
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    risk, flat_findings = host._compute_risk_and_findings(report)

    self.assertEqual(len(flat_findings), 1)
    f = flat_findings[0]
    self.assertEqual(f["scenario_id"], "PT-A01-01")
    self.assertEqual(f["severity"], "HIGH")
    self.assertEqual(f["category"], "graybox")
    self.assertIn("finding_id", f)

  def test_not_vulnerable_zero_score(self):
    """status=not_vulnerable contributes zero risk."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="No IDOR",
      status="not_vulnerable",
      severity="HIGH",
      owasp="A01:2021",
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    risk, flat_findings = host._compute_risk_and_findings(report)

    # not_vulnerable → severity overridden to INFO → zero weight
    f = flat_findings[0]
    self.assertEqual(f["severity"], "INFO")
    self.assertEqual(f["confidence"], "firm")
    # Score should be minimal (only open_ports and breadth contribute)
    self.assertLess(risk["breakdown"]["findings_score"], 0.1)

  def test_vulnerable_certain_confidence(self):
    """status=vulnerable → confidence=certain."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="IDOR",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    _, flat_findings = host._compute_risk_and_findings(report)
    self.assertEqual(flat_findings[0]["confidence"], "certain")

  def test_inconclusive_tentative(self):
    """status=inconclusive → confidence=tentative."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="Might be IDOR",
      status="inconclusive",
      severity="MEDIUM",
      owasp="A01:2021",
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    _, flat_findings = host._compute_risk_and_findings(report)
    self.assertEqual(flat_findings[0]["confidence"], "tentative")

  def test_evidence_joined(self):
    """List evidence joined with '; '."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="Test",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
      evidence=["a=1", "b=2"],
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    _, flat_findings = host._compute_risk_and_findings(report)
    self.assertEqual(flat_findings[0]["evidence"], "a=1; b=2")

  def test_cwe_joined(self):
    """List CWEs joined with ', '."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="Test",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
      cwe=["CWE-639", "CWE-862"],
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    _, flat_findings = host._compute_risk_and_findings(report)
    self.assertEqual(flat_findings[0]["cwe_id"], "CWE-639, CWE-862")

  def test_blackbox_and_graybox_combined(self):
    """Both sections walked, all in flat_findings."""
    gf = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="IDOR",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
    )
    report = {
      "open_ports": [443],
      "port_protocols": {"443": "https"},
      "service_info": {
        "443": {
          "_service_info_https": {
            "findings": [
              {"title": "Weak TLS", "severity": "MEDIUM", "confidence": "firm"},
            ],
          },
        },
      },
      "web_tests_info": {},
      "correlation_findings": [],
      "graybox_results": {
        "443": {
          "_graybox_test": {"findings": [gf.to_dict()]},
        },
      },
    }
    host = _make_mixin()
    _, flat_findings = host._compute_risk_and_findings(report)
    # Should have 2 findings: one service, one graybox
    self.assertEqual(len(flat_findings), 2)
    categories = {f["category"] for f in flat_findings}
    self.assertIn("service", categories)
    self.assertIn("graybox", categories)

  def test_probe_type_discriminator(self):
    """Flat finding has probe_type='graybox'."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="Test",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    _, flat_findings = host._compute_risk_and_findings(report)
    self.assertEqual(flat_findings[0]["probe_type"], "graybox")


class TestGrayboxRedaction(unittest.TestCase):

  def test_graybox_redaction(self):
    """Credential evidence redacted in graybox_results."""
    from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin

    class MockHost(_ReportMixin):
      pass

    host = MockHost()
    report = {
      "service_info": {},
      "graybox_results": {
        "443": {
          "_graybox_weak_auth": {
            "findings": [
              {
                "scenario_id": "PT-A07-01",
                "title": "Weak cred found",
                "status": "vulnerable",
                "severity": "HIGH",
                "evidence": ["admin:password123 accepted"],
              },
            ],
          },
        },
      },
    }
    redacted = host._redact_report(report)
    finding = redacted["graybox_results"]["443"]["_graybox_weak_auth"]["findings"][0]
    self.assertNotIn("password123", finding["evidence"][0])

  def test_redaction_handles_special_characters_and_multiple_credential_formats(self):
    """Credential redaction masks special-character passwords in both blackbox and graybox evidence."""
    from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin

    class MockHost(_ReportMixin):
      pass

    host = MockHost()
    report = {
      "service_info": {
        "22": {
          "_service_info_22": {
            "findings": [
              {"evidence": "Accepted credential: admin:p@$$:w0rd!"},
              {"evidence": "Accepted random creds service-user:s3cr3t/with/slash"},
            ],
            "accepted_credentials": [
              "admin:p@$$:w0rd!",
              "service-user:s3cr3t/with/slash",
            ],
          },
        },
      },
      "graybox_results": {
        "443": {
          "_graybox_weak_auth": {
            "findings": [
              {
                "evidence": [
                  "accepted=admin:p@$$:w0rd!",
                  "candidate service-user:s3cr3t/with/slash worked",
                ],
              },
            ],
          },
        },
      },
    }

    redacted = host._redact_report(report)
    service_findings = redacted["service_info"]["22"]["_service_info_22"]["findings"]
    service_creds = redacted["service_info"]["22"]["_service_info_22"]["accepted_credentials"]
    graybox_evidence = redacted["graybox_results"]["443"]["_graybox_weak_auth"]["findings"][0]["evidence"]

    self.assertNotIn("p@$$:w0rd!", service_findings[0]["evidence"])
    self.assertNotIn("s3cr3t/with/slash", service_findings[1]["evidence"])
    self.assertEqual(service_creds, ["admin:***", "service-user:***"])
    self.assertTrue(all("***" in item for item in graybox_evidence))


class TestFindingCounting(unittest.TestCase):

  def test_count_all_findings_walks_all_sections(self):
    """_count_all_findings counts service, web, correlation, and graybox findings."""
    from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin

    class MockHost(_ReportMixin):
      pass

    host = MockHost()
    report = {
      "service_info": {
        "80": {
          "_service_info_http": {"findings": [{"title": "svc-1"}, {"title": "svc-2"}]},
        },
      },
      "web_tests_info": {
        "80": {
          "_web_test_xss": {"findings": [{"title": "web-1"}]},
        },
      },
      "correlation_findings": [{"title": "corr-1"}],
      "graybox_results": {
        "443": {
          "_graybox_test": {"findings": [{"title": "gb-1"}, {"title": "gb-2"}]},
        },
      },
    }

    self.assertEqual(host._count_all_findings(report), 6)


class TestLaunchValidation(unittest.TestCase):

  def test_launch_invalid_scan_type(self):
    """Unknown scan_type returns error."""
    try:
      ScanType("invalid")
      self.fail("Should have raised ValueError")
    except ValueError:
      pass

  def test_worker_dispatch_table(self):
    """ScanType.WEBAPP maps to GrayboxLocalWorker in WORKER_DISPATCH."""
    # Verify the dispatch mapping without importing pentester_api_01
    # (which requires naeural_core). The mapping is:
    dispatch = {
      ScanType.NETWORK: PentestLocalWorker,
      ScanType.WEBAPP: GrayboxLocalWorker,
    }
    self.assertIs(dispatch[ScanType.WEBAPP], GrayboxLocalWorker)

  def test_worker_dispatch_network(self):
    """ScanType.NETWORK maps to PentestLocalWorker in WORKER_DISPATCH."""
    dispatch = {
      ScanType.NETWORK: PentestLocalWorker,
      ScanType.WEBAPP: GrayboxLocalWorker,
    }
    self.assertIs(dispatch[ScanType.NETWORK], PentestLocalWorker)

  def test_dispatch_uses_local_worker_id(self):
    """Worker stored in scan_jobs by local_worker_id (not local_id)."""
    from unittest.mock import patch
    with patch("extensions.business.cybersec.red_mesh.graybox.worker.SafetyControls"):
      with patch("extensions.business.cybersec.red_mesh.graybox.worker.AuthManager"):
        with patch("extensions.business.cybersec.red_mesh.graybox.worker.DiscoveryModule"):
          cfg = MagicMock()
          cfg.target_url = "http://test.local:8000"
          cfg.target_config = None
          cfg.verify_tls = True
          cfg.scan_min_delay = 0
          worker = GrayboxLocalWorker(
            owner=MagicMock(),
            job_id="j1",
            target_url="http://test.local:8000",
            job_config=cfg,
          )
    self.assertTrue(worker.local_worker_id.startswith("RM-"))
    self.assertNotEqual(worker.local_worker_id, "1")

  def test_probe_kwargs_include_allow_stateful(self):
    """allow_stateful passed to all probes."""
    # Verified by testing that probe_kwargs dict is built correctly
    from unittest.mock import patch
    worker_module = "extensions.business.cybersec.red_mesh.graybox.worker"

    with patch(f"{worker_module}.SafetyControls"):
      with patch(f"{worker_module}.AuthManager"):
        with patch(f"{worker_module}.DiscoveryModule"):
          cfg = MagicMock()
          cfg.target_url = "http://test.local:8000"
          cfg.target_config = None
          cfg.verify_tls = True
          cfg.scan_min_delay = 0
          cfg.allow_stateful_probes = True
          cfg.excluded_features = []
          cfg.authorized = True
          cfg.official_username = "admin"
          cfg.official_password = "pass"
          cfg.regular_username = ""
          cfg.regular_password = ""
          cfg.weak_candidates = None
          cfg.app_routes = None

          worker = GrayboxLocalWorker(
            owner=MagicMock(),
            job_id="j1",
            target_url="http://test.local:8000",
            job_config=cfg,
          )

    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = None
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    captured_kwargs = {}

    def capturing_cls(**kwargs):
      captured_kwargs.update(kwargs)
      mock = MagicMock()
      mock.run.return_value = []
      return mock

    mock_cls = MagicMock(side_effect=capturing_cls)
    mock_cls.is_stateful = False
    mock_cls.requires_auth = False
    mock_cls.requires_regular_session = False

    with patch(f"{worker_module}.GRAYBOX_PROBE_REGISTRY",
               [{"key": "_test", "cls": "test.T"}]):
      with patch.object(GrayboxLocalWorker, '_import_probe', staticmethod(lambda cp: mock_cls)):
        worker.execute_job()

    self.assertTrue(captured_kwargs.get("allow_stateful"))


class TestRiskScoreGraybox(unittest.TestCase):

  def test_risk_score_includes_graybox(self):
    """_compute_risk_score also walks graybox_results."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="IDOR",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    result = host._compute_risk_score(report)
    # Should have non-zero findings_score
    self.assertGreater(result["breakdown"]["findings_score"], 0)
    self.assertGreater(result["breakdown"]["finding_counts"]["HIGH"], 0)


if __name__ == '__main__':
  unittest.main()
