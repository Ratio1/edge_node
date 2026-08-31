"""Tests for graybox normalization, dispatch, and redaction."""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.worker import GrayboxLocalWorker
from extensions.business.cybersec.red_mesh.graybox.scenario_runtime import (
  build_graybox_worker_assignments,
)
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

  def test_typed_evidence_artifacts_survive_normalization(self):
    """Graybox typed evidence artifacts survive into the flat finding contract."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="Typed evidence",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
      evidence=[],
      evidence_artifacts=[{"summary": "GET /admin -> 403", "raw_evidence_cid": "QmEvidence"}],
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    _, flat_findings = host._compute_risk_and_findings(report)
    self.assertEqual(flat_findings[0]["evidence"], "GET /admin -> 403")
    self.assertEqual(flat_findings[0]["evidence_artifacts"][0]["raw_evidence_cid"], "QmEvidence")

  def test_graybox_cvss_metadata_survives_normalization(self):
    """Graybox CVSS metadata survives flat finding normalization."""
    finding = GrayboxFinding(
      scenario_id="PT-A01-01",
      title="Typed CVSS",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
      cvss_score=9.1,
      cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
    )
    report = _make_graybox_report([finding.to_dict()])
    host = _make_mixin()
    _, flat_findings = host._compute_risk_and_findings(report)
    self.assertEqual(flat_findings[0]["cvss_score"], 9.1)
    self.assertEqual(flat_findings[0]["cvss_vector"], "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L")

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

  def test_redaction_masks_graybox_evidence_artifacts(self):
    """Typed graybox evidence artifacts are redacted alongside legacy evidence strings."""
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
                "evidence": ["accepted=admin:password123"],
                "evidence_artifacts": [
                  {
                    "summary": "accepted=admin:password123",
                    "request_snapshot": "POST /login username=admin password=password123",
                    "response_snapshot": "accepted admin:password123",
                  },
                ],
              },
            ],
            "artifacts": [
              {
                "summary": "candidate=admin:password123",
                "request_snapshot": "POST /login password=password123",
                "response_snapshot": "200 admin:password123",
              },
            ],
          },
        },
      },
    }

    redacted = host._redact_report(report)
    finding = redacted["graybox_results"]["443"]["_graybox_weak_auth"]["findings"][0]
    artifact = finding["evidence_artifacts"][0]
    probe_artifact = redacted["graybox_results"]["443"]["_graybox_weak_auth"]["artifacts"][0]

    self.assertNotIn("password123", artifact["summary"])
    self.assertNotIn("password123", artifact["request_snapshot"])
    self.assertNotIn("password123", artifact["response_snapshot"])
    self.assertNotIn("password123", probe_artifact["summary"])

  def test_redaction_masks_configured_graybox_api_secret_names(self):
    from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin

    class MockHost(_ReportMixin):
      pass

    host = MockHost()
    report = {
      "target_config": {
        "api_security": {
          "auth": {
            "api_key_query_param": "customer_key",
            "api_key_header_name": "X-Customer-Api-Key",
          },
        },
      },
      "service_info": {},
      "graybox_results": {
        "443": {
          "_graybox_api_access": {
            "findings": [
              {
                "title": "X-Customer-Api-Key: SECRET-HEADER",
                "evidence": [
                  "GET /v1/users?customer_key=SECRET99&page=1",
                ],
                "replay_steps": [
                  "curl /v1/users?customer_key=SECRET99",
                ],
                "evidence_artifacts": [
                  {
                    "request_snapshot": (
                      "GET /v1/users?customer_key=SECRET99 "
                      "X-Customer-Api-Key: SECRET-HEADER"
                    ),
                  },
                ],
              },
            ],
          },
        },
      },
    }

    redacted = host._redact_report(report)

    haystack = str(redacted)
    self.assertNotIn("SECRET99", haystack)
    self.assertNotIn("SECRET-HEADER", haystack)
    self.assertIn("customer_key=<redacted>", haystack)
    self.assertIn("X-Customer-Api-Key: <redacted>", haystack)


class TestBlackboxCredentialRedaction(unittest.TestCase):
  """
  Default-credential probes interpolate the plaintext pair into `title`, and
  `_redact_report` only ever touched `evidence` and `accepted_credentials`.

  Measured on the client job `6cc55610`, which carried `redactCredentials: true`:
  25 finding titles and 19 `vulnerabilities` entries still held a credential
  pair. The title also reaches the customer's SIEM verbatim, so this is a
  credential-egress event rather than only a rendering defect.
  """

  # Exactly the strings the probes emit — worker/service/common.py:480, 751,
  # 932, 1620 and worker/service/database.py:239, 928, 954.
  PROBE_OUTPUT = (
    ("HTTP Basic Auth default credential: admin:hunter2",
     "GET http://t/adm with admin:hunter2 -> HTTP 200", "hunter2"),
    ("FTP default credential accepted: ftpuser:s3cr3t",
     "Accepted credential: ftpuser:s3cr3t", "s3cr3t"),
    ("SSH default credential accepted: root:toor",
     "Accepted credential: root:toor", "toor"),
    ("Telnet default credential accepted: admin:admin1234",
     "Accepted credential: admin:admin1234", "admin1234"),
    ("MySQL default credential accepted: root:mysqlpw",
     "Auth response OK for root:mysqlpw", "mysqlpw"),
    ("PostgreSQL default credential accepted: postgres:pgpw99",
     "Auth OK for postgres:pgpw99", "pgpw99"),
  )

  @staticmethod
  def _host():
    from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin

    class MockHost(_ReportMixin):
      pass

    return MockHost()

  @staticmethod
  def _report(title, evidence, description):
    return {
      "service_info": {
        "22": {
          "default_creds": {
            "findings": [{
              "title": title,
              "description": description,
              "remediation": "Rotate the credential.",
              "evidence": evidence,
            }],
            "accepted": ["root:toor"],
            "accepted_credentials": ["root:toor"],
          },
        },
      },
      "graybox_results": {},
      "vulnerabilities": [title],
    }

  def test_no_probe_leaves_a_password_anywhere_in_the_report(self):
    for title, evidence, secret in self.PROBE_OUTPUT:
      with self.subTest(title=title):
        host = self._host()
        pair = title.split(": ")[-1]
        description = f"MySQL on 10.0.0.5:3306 accepts {pair}."
        redacted = host._redact_report(self._report(title, evidence, description))
        self.assertNotIn(secret, str(redacted), f"{secret} survived redaction")

  def test_the_host_and_port_are_not_mistaken_for_a_credential(self):
    # `MySQL on {target}:{port} accepts {cred}` puts a host:port pair in the same
    # sentence as the credential. Redacting that too would destroy the field
    # saying which service was affected.
    host = self._host()
    redacted = host._redact_report(self._report(
      "MySQL default credential accepted: root:mysqlpw",
      "Auth response OK for root:mysqlpw",
      "MySQL on 10.0.0.5:3306 accepts root:mysqlpw.",
    ))
    description = redacted["service_info"]["22"]["default_creds"]["findings"][0]["description"]
    self.assertIn("10.0.0.5:3306", description)
    self.assertNotIn("mysqlpw", description)

  def test_the_parallel_vulnerabilities_title_list_is_redacted(self):
    # `result["vulnerabilities"]` is built from finding titles (findings.py:269)
    # and redaction never saw it. 19 entries leaked on the client job.
    host = self._host()
    redacted = host._redact_report(self._report(
      "SSH default credential accepted: root:toor",
      "Accepted credential: root:toor",
      "The SSH server accepted a well-known default credential.",
    ))
    self.assertNotIn("toor", str(redacted.get("vulnerabilities", [])))

  def test_the_http_basic_accepted_key_is_redacted(self):
    # The probe writes `accepted` (common.py:438,477); redaction read only
    # `accepted_credentials` — a key-name mismatch, so that list was archived raw.
    host = self._host()
    redacted = host._redact_report(self._report(
      "HTTP Basic Auth default credential: admin:hunter2",
      "GET http://t/adm with admin:hunter2 -> HTTP 200",
      "The web server accepted a default credential.",
    ))
    accepted = redacted["service_info"]["22"]["default_creds"]["accepted"]
    self.assertNotIn("toor", str(accepted))


class TestFindingCounting(unittest.TestCase):

  def test_count_all_findings_walks_all_published_paths(self):
    """Counting covers nested/flat service, web, graybox, correlation, and top-level paths."""
    from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin

    class MockHost(_ReportMixin):
      pass

    host = MockHost()
    report = {
      "service_info": {
        "80": {
          "findings": [{"title": "legacy-flat-service"}],
          "_service_info_http": {"findings": [{"title": "svc-1"}, {"title": "svc-2"}]},
        },
      },
      "web_tests_info": {
        "80": {
          "findings": [{"title": "legacy-flat-web"}],
          "_web_test_xss": {"findings": [{"title": "web-1"}]},
        },
      },
      "correlation_findings": [{"title": "corr-1"}],
      "findings": [{"title": "top-1"}],
      "graybox_results": {
        "443": {
          "_graybox_test": {"findings": [{"title": "gb-1"}, {"title": "gb-2"}]},
        },
      },
    }

    self.assertEqual(host._count_all_findings(report), 9)


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
          assignments, _error = build_graybox_worker_assignments(["node-1"])
          for key, value in assignments["node-1"].items():
            setattr(cfg, key, value)
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
          assignments, _error = build_graybox_worker_assignments(["node-1"])
          for key, value in assignments["node-1"].items():
            setattr(cfg, key, value)

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


class TestRiskScoreDynamicRange(unittest.TestCase):
  """
  The logistic curve pinned at 100 once raw_total passed ~300 — about eight
  CRITICAL findings — while raw_total grows linearly with finding count. Three
  real archived runs spanning 46 to 600 findings all scored exactly 100, so a
  remediation cycle could remove hundreds of findings without moving the number.
  """

  # (label, raw_total) from the archived runs named in the task.
  ARCHIVED = (
    ("R1 blackbox, 46 findings", 609.1),
    ("client job 6cc55610", 1123.5),
    ("phase-a-v3, 600 findings", 9006.9),
  )

  def test_real_runs_that_all_scored_100_are_now_distinguishable(self):
    from extensions.business.cybersec.red_mesh.mixins.risk import normalize_risk_score
    scores = [normalize_risk_score(raw) for _label, raw in self.ARCHIVED]
    self.assertEqual(
      len(set(scores)), len(scores),
      f"archived runs still collide: {list(zip([l for l, _ in self.ARCHIVED], scores))}",
    )
    for score in scores:
      self.assertLess(score, 100, "a real run still pins at the ceiling")

  def test_the_score_keeps_rising_past_eight_critical_findings(self):
    from extensions.business.cybersec.red_mesh.mixins.risk import normalize_risk_score
    # One CRITICAL/certain finding contributes 40 to raw_total.
    eight = normalize_risk_score(8 * 40)
    twenty = normalize_risk_score(20 * 40)
    hundred = normalize_risk_score(100 * 40)
    self.assertLess(eight, twenty)
    self.assertLess(twenty, hundred)

  def test_the_score_is_monotonic_and_bounded(self):
    from extensions.business.cybersec.red_mesh.mixins.risk import normalize_risk_score
    previous = -1
    for raw in (0, 1, 10, 40, 100, 320, 1000, 5000, 20000, 100000):
      score = normalize_risk_score(raw)
      self.assertGreaterEqual(score, previous)
      self.assertGreaterEqual(score, 0)
      self.assertLessEqual(score, 100)
      previous = score

  def test_a_single_critical_finding_stays_where_it_was(self):
    # The low end is anchored so small scans stay comparable with historical
    # reports: one CRITICAL finding scored 38 under the logistic curve.
    from extensions.business.cybersec.red_mesh.mixins.risk import normalize_risk_score
    self.assertAlmostEqual(normalize_risk_score(40), 38, delta=3)

  def test_a_malformed_raw_total_scores_zero_rather_than_raising(self):
    from extensions.business.cybersec.red_mesh.mixins.risk import normalize_risk_score
    for bad in (None, "", "abc", float("nan")):
      with self.subTest(raw=bad):
        self.assertIsInstance(normalize_risk_score(bad), int)
