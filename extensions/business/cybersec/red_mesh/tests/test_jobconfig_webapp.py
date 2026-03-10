"""Tests for JobConfig graybox fields and blackbox Finding unchanged."""

import unittest

from extensions.business.cybersec.red_mesh.models.archive import JobConfig, UiAggregate
from extensions.business.cybersec.red_mesh.models.shared import ScanMetrics
from extensions.business.cybersec.red_mesh.findings import Finding, Severity


class TestJobConfigWebapp(unittest.TestCase):

  def test_scan_type_default(self):
    """scan_type defaults to 'network'."""
    cfg = JobConfig(
      target="10.0.0.1", start_port=1, end_port=1024,
      exceptions=[], distribution_strategy="SLICE",
      port_order="SEQUENTIAL", nr_local_workers=2,
      enabled_features=[], excluded_features=[],
      run_mode="SINGLEPASS",
    )
    self.assertEqual(cfg.scan_type, "network")

  def test_from_dict_with_graybox_fields(self):
    """Round-trip with all graybox fields."""
    d = {
      "target": "example.com",
      "start_port": 1,
      "end_port": 65535,
      "exceptions": [],
      "distribution_strategy": "SLICE",
      "port_order": "SEQUENTIAL",
      "nr_local_workers": 1,
      "enabled_features": [],
      "excluded_features": [],
      "run_mode": "SINGLEPASS",
      "scan_type": "webapp",
      "target_url": "https://example.com/",
      "official_username": "admin",
      "official_password": "secret123",
      "regular_username": "user",
      "regular_password": "pass456",
      "weak_candidates": ["admin:admin", "test:test"],
      "max_weak_attempts": 10,
      "app_routes": ["/api/users/", "/api/records/"],
      "verify_tls": False,
      "target_config": {"login_path": "/login/"},
      "allow_stateful_probes": True,
    }
    cfg = JobConfig.from_dict(d)
    self.assertEqual(cfg.scan_type, "webapp")
    self.assertEqual(cfg.target_url, "https://example.com/")
    self.assertEqual(cfg.official_username, "admin")
    self.assertEqual(cfg.official_password, "secret123")
    self.assertEqual(cfg.regular_username, "user")
    self.assertEqual(cfg.regular_password, "pass456")
    self.assertEqual(cfg.weak_candidates, ["admin:admin", "test:test"])
    self.assertEqual(cfg.max_weak_attempts, 10)
    self.assertEqual(cfg.app_routes, ["/api/users/", "/api/records/"])
    self.assertFalse(cfg.verify_tls)
    self.assertEqual(cfg.target_config, {"login_path": "/login/"})
    self.assertTrue(cfg.allow_stateful_probes)

    # Round-trip
    restored = JobConfig.from_dict(cfg.to_dict())
    self.assertEqual(restored.scan_type, cfg.scan_type)
    self.assertEqual(restored.target_url, cfg.target_url)
    self.assertEqual(restored.official_username, cfg.official_username)
    self.assertEqual(restored.weak_candidates, cfg.weak_candidates)
    self.assertEqual(restored.allow_stateful_probes, cfg.allow_stateful_probes)

  def test_graybox_defaults(self):
    """All graybox fields have sensible defaults."""
    cfg = JobConfig(
      target="x", start_port=1, end_port=1,
      exceptions=[], distribution_strategy="SLICE",
      port_order="SEQUENTIAL", nr_local_workers=1,
      enabled_features=[], excluded_features=[],
      run_mode="SINGLEPASS",
    )
    self.assertEqual(cfg.scan_type, "network")
    self.assertEqual(cfg.target_url, "")
    self.assertEqual(cfg.official_username, "")
    self.assertEqual(cfg.official_password, "")
    self.assertEqual(cfg.regular_username, "")
    self.assertEqual(cfg.regular_password, "")
    self.assertIsNone(cfg.weak_candidates)
    self.assertEqual(cfg.max_weak_attempts, 5)
    self.assertIsNone(cfg.app_routes)
    self.assertTrue(cfg.verify_tls)
    self.assertIsNone(cfg.target_config)
    self.assertFalse(cfg.allow_stateful_probes)

  def test_redaction_masks_passwords(self):
    """to_dict() includes passwords; redaction must happen at API level."""
    cfg = JobConfig(
      target="x", start_port=1, end_port=1,
      exceptions=[], distribution_strategy="SLICE",
      port_order="SEQUENTIAL", nr_local_workers=1,
      enabled_features=[], excluded_features=[],
      run_mode="SINGLEPASS",
      official_password="secret",
      regular_password="pass",
      weak_candidates=["admin:admin"],
    )
    d = cfg.to_dict()
    # Passwords are present in to_dict() (redaction is at the API level)
    self.assertEqual(d["official_password"], "secret")
    self.assertEqual(d["regular_password"], "pass")
    self.assertEqual(d["weak_candidates"], ["admin:admin"])

  def test_redact_job_config_masks_credentials(self):
    """_redact_job_config masks passwords and weak_candidates."""
    from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin
    d = {
      "target": "x",
      "official_username": "admin",
      "official_password": "secret",
      "regular_username": "user",
      "regular_password": "pass",
      "weak_candidates": ["admin:admin", "test:test"],
    }
    redacted = _ReportMixin._redact_job_config(d)
    self.assertEqual(redacted["official_password"], "***")
    self.assertEqual(redacted["regular_password"], "***")
    self.assertEqual(redacted["weak_candidates"], ["***", "***"])
    # Usernames are NOT masked
    self.assertEqual(redacted["official_username"], "admin")
    self.assertEqual(redacted["regular_username"], "user")

  def test_redact_job_config_noop_when_empty(self):
    """_redact_job_config is a no-op when credential fields are empty/absent."""
    from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin
    d = {"target": "x", "official_password": "", "regular_password": ""}
    redacted = _ReportMixin._redact_job_config(d)
    self.assertEqual(redacted["official_password"], "")
    self.assertEqual(redacted["regular_password"], "")


class TestUiAggregateGraybox(unittest.TestCase):

  def test_graybox_fields_default(self):
    """UiAggregate graybox fields default to 0 / 'network'."""
    ui = UiAggregate(total_open_ports=[], total_services=0, total_findings=0)
    self.assertEqual(ui.scan_type, "network")
    self.assertEqual(ui.total_routes_discovered, 0)
    self.assertEqual(ui.total_forms_discovered, 0)
    self.assertEqual(ui.total_scenarios, 0)
    self.assertEqual(ui.total_scenarios_vulnerable, 0)

  def test_graybox_fields_roundtrip(self):
    """UiAggregate graybox fields round-trip."""
    ui = UiAggregate(
      total_open_ports=[443], total_services=1, total_findings=5,
      scan_type="webapp", total_routes_discovered=12,
      total_forms_discovered=3, total_scenarios=8,
      total_scenarios_vulnerable=2,
    )
    d = ui.to_dict()
    restored = UiAggregate.from_dict(d)
    self.assertEqual(restored.scan_type, "webapp")
    self.assertEqual(restored.total_routes_discovered, 12)
    self.assertEqual(restored.total_forms_discovered, 3)
    self.assertEqual(restored.total_scenarios, 8)
    self.assertEqual(restored.total_scenarios_vulnerable, 2)


class TestScanMetricsGraybox(unittest.TestCase):

  def test_scenario_fields_default(self):
    """ScanMetrics scenario counters default to 0."""
    m = ScanMetrics()
    self.assertEqual(m.scenarios_total, 0)
    self.assertEqual(m.scenarios_vulnerable, 0)
    self.assertEqual(m.scenarios_clean, 0)
    self.assertEqual(m.scenarios_inconclusive, 0)
    self.assertEqual(m.scenarios_error, 0)

  def test_scenario_fields_roundtrip(self):
    """ScanMetrics scenario counters round-trip."""
    m = ScanMetrics(
      scenarios_total=10, scenarios_vulnerable=3,
      scenarios_clean=5, scenarios_inconclusive=1,
      scenarios_error=1,
    )
    d = m.to_dict()
    restored = ScanMetrics.from_dict(d)
    self.assertEqual(restored.scenarios_total, 10)
    self.assertEqual(restored.scenarios_vulnerable, 3)
    self.assertEqual(restored.scenarios_clean, 5)
    self.assertEqual(restored.scenarios_inconclusive, 1)
    self.assertEqual(restored.scenarios_error, 1)


class TestFindingUnchanged(unittest.TestCase):
  """Verify blackbox Finding dataclass is not modified."""

  def test_finding_has_8_fields(self):
    """Finding has exactly 8 fields — no new fields added."""
    import dataclasses
    fields = dataclasses.fields(Finding)
    self.assertEqual(len(fields), 8, f"Expected 8 fields, got {len(fields)}: {[f.name for f in fields]}")

  def test_finding_no_probe_type(self):
    """Finding does not have a probe_type attribute."""
    self.assertFalse(hasattr(Finding, 'probe_type'))
    f = Finding(severity=Severity.HIGH, title="Test", description="Desc")
    self.assertFalse(hasattr(f, 'probe_type'))

  def test_existing_construction_unchanged(self):
    """Existing Finding construction still works."""
    f = Finding(
      severity=Severity.CRITICAL,
      title="SQL Injection",
      description="Found SQL injection in /api/search",
      evidence="error-based: syntax error near 'OR'",
      remediation="Use parameterized queries",
      owasp_id="A03:2021",
      cwe_id="CWE-89",
      confidence="certain",
    )
    self.assertEqual(f.severity, Severity.CRITICAL)
    self.assertEqual(f.title, "SQL Injection")
    self.assertEqual(f.confidence, "certain")


if __name__ == '__main__':
  unittest.main()
