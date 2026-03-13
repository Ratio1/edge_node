"""Tests for GrayboxLocalWorker."""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from extensions.business.cybersec.red_mesh.graybox.worker import GrayboxLocalWorker
from extensions.business.cybersec.red_mesh.worker.base import BaseLocalWorker
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.models import (
  DiscoveryResult,
  GrayboxCredentialSet,
  GrayboxProbeContext,
  GrayboxProbeDefinition,
  GrayboxProbeRunResult,
)
from extensions.business.cybersec.red_mesh.constants import (
  ScanType, GRAYBOX_PROBE_REGISTRY,
)


def _make_job_config(**overrides):
  cfg = MagicMock()
  cfg.scan_type = "webapp"
  cfg.target_url = "http://testapp.local:8000"
  cfg.official_username = "admin"
  cfg.official_password = "secret"
  cfg.regular_username = "alice"
  cfg.regular_password = "pass"
  cfg.weak_candidates = None
  cfg.max_weak_attempts = 5
  cfg.app_routes = None
  cfg.verify_tls = True
  cfg.target_config = None
  cfg.allow_stateful_probes = False
  cfg.excluded_features = []
  cfg.scan_min_delay = 0.0
  cfg.authorized = True
  for k, v in overrides.items():
    setattr(cfg, k, v)
  return cfg


def _make_worker(**overrides):
  owner = MagicMock()
  owner.P = MagicMock()
  cfg = _make_job_config(**overrides)
  with patch("extensions.business.cybersec.red_mesh.graybox.worker.SafetyControls"):
    with patch("extensions.business.cybersec.red_mesh.graybox.worker.AuthManager"):
      with patch("extensions.business.cybersec.red_mesh.graybox.worker.DiscoveryModule"):
        worker = GrayboxLocalWorker(
          owner=owner,
          job_id="test-job-1",
          target_url=cfg.target_url,
          job_config=cfg,
          local_id="1",
          initiator="test-node",
        )
  return worker


class TestBaseLocalWorkerIntegration(unittest.TestCase):

  def test_inherits_base(self):
    """GrayboxLocalWorker inherits from BaseLocalWorker."""
    self.assertTrue(issubclass(GrayboxLocalWorker, BaseLocalWorker))

  def test_start_inherited(self):
    """start() is not redefined."""
    self.assertNotIn("start", GrayboxLocalWorker.__dict__)

  def test_stop_inherited(self):
    """stop() is not redefined."""
    self.assertNotIn("stop", GrayboxLocalWorker.__dict__)

  def test_check_stopped_inherited(self):
    """_check_stopped() is not redefined."""
    self.assertNotIn("_check_stopped", GrayboxLocalWorker.__dict__)

  def test_local_worker_id_format(self):
    """local_worker_id starts with RM-."""
    worker = _make_worker()
    self.assertTrue(worker.local_worker_id.startswith("RM-"))

  def test_initial_ports_is_list(self):
    """initial_ports is a list."""
    worker = _make_worker()
    self.assertIsInstance(worker.initial_ports, list)
    self.assertEqual(worker.initial_ports, [8000])

  def test_ports_scanned_is_list(self):
    """state['ports_scanned'] is a list."""
    worker = _make_worker()
    self.assertIsInstance(worker.state["ports_scanned"], list)


class TestStateShape(unittest.TestCase):

  def test_state_shape(self):
    """State dict has all required keys."""
    worker = _make_worker()
    required = [
      "job_id", "initiator", "target", "scan_type", "target_url",
      "open_ports", "ports_scanned", "port_protocols", "service_info",
      "web_tests_info", "correlation_findings", "graybox_results",
      "completed_tests", "done", "canceled",
    ]
    for key in required:
      self.assertIn(key, worker.state, f"Missing state key: {key}")

  def test_state_has_scan_type(self):
    """state['scan_type'] == 'webapp'."""
    worker = _make_worker()
    self.assertEqual(worker.state["scan_type"], "webapp")

  def test_graybox_results_populated(self):
    """Findings stored in graybox_results, not web_tests_info."""
    worker = _make_worker()
    finding = GrayboxFinding(
      scenario_id="TEST-01",
      title="Test",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
    )
    worker._store_findings("_test_probe", [finding])
    self.assertIn("8000", worker.state["graybox_results"])
    self.assertIn("_test_probe", worker.state["graybox_results"]["8000"])
    self.assertEqual(worker.state["web_tests_info"], {})


class TestStatus(unittest.TestCase):

  def test_get_status_scan_metrics_key(self):
    """Status includes scan_metrics key."""
    worker = _make_worker()
    status = worker.get_status()
    self.assertIn("scan_metrics", status)

  def test_get_status_includes_scenario_stats(self):
    """Status includes scenario_stats."""
    worker = _make_worker()
    status = worker.get_status()
    self.assertIn("scenario_stats", status)

  def test_get_status_merges_scenario_stats_into_scan_metrics(self):
    """scan_metrics includes graybox scenario counters."""
    worker = _make_worker()
    worker._store_findings("_test_probe", [GrayboxFinding(
      scenario_id="TEST-01",
      title="Test",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
    )])
    status = worker.get_status()
    self.assertEqual(status["scan_metrics"]["scenarios_total"], 1)
    self.assertEqual(status["scan_metrics"]["scenarios_vulnerable"], 1)

  def test_get_status_for_aggregations(self):
    """for_aggregations=True omits local_worker_id."""
    worker = _make_worker()
    status = worker.get_status(for_aggregations=True)
    self.assertNotIn("local_worker_id", status)
    status_full = worker.get_status(for_aggregations=False)
    self.assertIn("local_worker_id", status_full)


class TestLifecycle(unittest.TestCase):

  def test_start_creates_thread(self):
    """start() creates thread and stop_event."""
    worker = _make_worker()
    # Patch execute_job to avoid actual execution
    worker.execute_job = MagicMock()
    worker.start()
    self.assertIsNotNone(worker.thread)
    self.assertIsNotNone(worker.stop_event)
    worker.thread.join(timeout=1)

  def test_stop_sets_events(self):
    """stop() sets stop_event and state['canceled']."""
    worker = _make_worker()
    worker.execute_job = MagicMock()
    worker.start()
    worker.stop()
    self.assertTrue(worker.stop_event.is_set())
    self.assertTrue(worker.state["canceled"])
    worker.thread.join(timeout=1)

  def test_check_stopped_after_stop(self):
    """_check_stopped() returns True after stop()."""
    worker = _make_worker()
    worker.execute_job = MagicMock()
    worker.start()
    worker.stop()
    self.assertTrue(worker._check_stopped())
    worker.thread.join(timeout=1)


class TestExecution(unittest.TestCase):

  def test_metrics_phase_timing(self):
    """Phase durations populated after execute_job."""
    worker = _make_worker()
    # Mock auth to succeed
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.safety.validate_target.return_value = None

    # Mock discovery
    worker.discovery.discover.return_value = ([], [])

    # Mock probe registry to be empty for fast execution
    with patch("extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY", []):
      worker.execute_job()

    self.assertTrue(worker.state["done"])
    metrics = worker.metrics.build()
    self.assertTrue(len(metrics.phase_durations) > 0)

  def test_worker_builds_typed_credentials(self):
    worker = _make_worker(regular_username="alice", regular_password="pass", weak_candidates=["admin:admin"])
    self.assertIsInstance(worker._credentials, GrayboxCredentialSet)
    self.assertEqual(worker._credentials.official.username, "admin")
    self.assertEqual(worker._credentials.regular.username, "alice")
    self.assertEqual(worker._credentials.weak_candidates, ["admin:admin"])

  def test_discovery_phase_returns_typed_result(self):
    worker = _make_worker()
    worker.auth.ensure_sessions = MagicMock()
    worker.discovery.discover_result = MagicMock(return_value=DiscoveryResult(routes=["/a"], forms=["/f"]))

    result = worker._run_discovery_phase()

    self.assertIsInstance(result, DiscoveryResult)
    self.assertEqual(result.routes, ["/a"])

  def test_discovery_phase_fails_closed_when_refresh_fails(self):
    worker = _make_worker()
    worker.auth.ensure_sessions = MagicMock(return_value=False)

    result = worker._run_discovery_phase()

    self.assertEqual(result, DiscoveryResult())
    self.assertIn("_graybox_fatal", worker.state["graybox_results"]["8000"])

  def test_build_probe_context_returns_typed_context(self):
    worker = _make_worker(regular_username="alice")
    context = worker._build_probe_kwargs(DiscoveryResult(routes=["/r"], forms=["/f"]))
    self.assertIsInstance(context, GrayboxProbeContext)
    self.assertEqual(context.discovered_routes, ["/r"])
    self.assertEqual(context.discovered_forms, ["/f"])
    self.assertEqual(context.regular_username, "alice")

  def test_supported_features_come_from_typed_probe_definitions(self):
    with patch(
      "extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY",
      [{"key": "_graybox_alpha", "cls": "fake.Alpha"}],
    ):
      self.assertEqual(
        GrayboxLocalWorker.get_supported_features(),
        ["_graybox_alpha", "_graybox_weak_auth"],
      )

  def test_scenario_stats(self):
    """Scenario stats count findings by status."""
    worker = _make_worker()
    worker._store_findings("_test", [
      GrayboxFinding(
        scenario_id="T1", title="Vuln", status="vulnerable",
        severity="HIGH", owasp="A01:2021",
      ),
      GrayboxFinding(
        scenario_id="T2", title="Clean", status="not_vulnerable",
        severity="INFO", owasp="A01:2021",
      ),
    ])
    stats = worker._compute_scenario_stats()
    self.assertEqual(stats["total"], 2)
    self.assertEqual(stats["vulnerable"], 1)
    self.assertEqual(stats["not_vulnerable"], 1)

  def test_registered_probe_records_auth_refresh_failure(self):
    worker = _make_worker()
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth.ensure_sessions = MagicMock(return_value=False)
    worker.auth._auth_errors = []
    probe_context = worker._build_probe_kwargs(DiscoveryResult())
    mock_cls = MagicMock()
    mock_cls.requires_regular_session = False
    mock_cls.requires_auth = True
    mock_cls.is_stateful = False

    with patch.object(worker, "_import_probe", return_value=mock_cls):
      worker._run_registered_probe({"key": "_graybox_test", "cls": "fake.Probe"}, probe_context)

    self.assertEqual(worker.metrics.build().probes_failed, 1)
    self.assertIn("_graybox_fatal", worker.state["graybox_results"]["8000"])
    self.assertEqual(worker.metrics.build().probe_breakdown["_graybox_test"], "failed:auth_refresh")

  def test_store_findings_accepts_typed_probe_run_result(self):
    worker = _make_worker()
    finding = GrayboxFinding(
      scenario_id="TEST-01",
      title="Typed result",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
    )
    run_result = GrayboxProbeRunResult(findings=[finding], outcome="completed")

    worker._store_findings("_typed_probe", run_result)

    stored = worker.state["graybox_results"]["8000"]["_typed_probe"]
    self.assertEqual(stored["outcome"], "completed")
    self.assertEqual(len(stored["findings"]), 1)

  def test_registered_probe_accepts_typed_probe_definition(self):
    worker = _make_worker()
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth.ensure_sessions = MagicMock(return_value=True)
    worker.auth._auth_errors = []
    probe_context = worker._build_probe_kwargs(DiscoveryResult())
    finding = GrayboxFinding(
      scenario_id="TEST-02",
      title="Registry typed",
      status="not_vulnerable",
      severity="INFO",
      owasp="A01:2021",
    )
    mock_probe = MagicMock()
    mock_probe.run.return_value = GrayboxProbeRunResult(findings=[finding], outcome="completed")
    mock_cls = MagicMock(return_value=mock_probe)
    mock_cls.requires_regular_session = False
    mock_cls.requires_auth = True
    mock_cls.is_stateful = False

    with patch.object(worker, "_import_probe", return_value=mock_cls):
      worker._run_registered_probe(
        GrayboxProbeDefinition(key="_typed", cls_path="fake.Probe"),
        probe_context,
      )

    stored = worker.state["graybox_results"]["8000"]["_typed"]
    self.assertEqual(stored["outcome"], "completed")
    self.assertEqual(worker.metrics.build().probe_breakdown["_typed"], "completed")

  def test_auth_failure_aborts(self):
    """Official login fails → fatal finding, done=True."""
    worker = _make_worker()
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = False
    worker.auth.official_session = None
    worker.auth._auth_errors = ["Login failed"]
    worker.auth.cleanup = MagicMock()

    worker.execute_job()

    self.assertTrue(worker.state["done"])
    results = worker.state["graybox_results"]
    fatal = results.get("8000", {}).get("_graybox_fatal", {}).get("findings", [])
    self.assertEqual(len(fatal), 1)
    self.assertEqual(fatal[0]["status"], "inconclusive")
    self.assertIn("authentication failed", fatal[0]["evidence"][0].lower())

  def test_preflight_failure_aborts(self):
    """Bad URL → fatal finding, done=True."""
    worker = _make_worker()
    worker.safety.validate_target.return_value = "Target not authorized"
    worker.auth.cleanup = MagicMock()

    worker.execute_job()

    self.assertTrue(worker.state["done"])
    fatal = worker.state["graybox_results"].get("8000", {}).get("_graybox_fatal", {}).get("findings", [])
    self.assertEqual(len(fatal), 1)

  def test_cancel_before_discovery(self):
    """Routes/forms default to [] when canceled before discovery."""
    worker = _make_worker()
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.cleanup = MagicMock()

    # Cancel after auth
    worker.state["canceled"] = True

    worker.execute_job()
    self.assertTrue(worker.state["done"])

  def test_cancel_stops_probes(self):
    """stop() skips remaining probes."""
    worker = _make_worker()
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    call_count = [0]
    original_import = GrayboxLocalWorker._import_probe

    def counting_import(cls_path):
      call_count[0] += 1
      if call_count[0] >= 2:
        worker.state["canceled"] = True
      return original_import(cls_path)

    with patch.object(GrayboxLocalWorker, '_import_probe', staticmethod(counting_import)):
      worker.execute_job()

    self.assertTrue(worker.state["done"])

  def test_cleanup_always_runs(self):
    """Sessions closed even on error."""
    worker = _make_worker()
    worker.safety.validate_target.side_effect = RuntimeError("boom")
    worker.safety.sanitize_error.return_value = "boom"
    worker.auth.cleanup = MagicMock()

    worker.execute_job()

    worker.auth.cleanup.assert_called_once()
    self.assertTrue(worker.state["done"])


class TestProbeDispatch(unittest.TestCase):

  def test_probe_kwargs_include_forms(self):
    """discovered_forms passed to probes."""
    worker = _make_worker()
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = (["/route1/"], ["/form1/"])

    probe_instances = []

    def mock_registry_probe(**kwargs):
      mock_probe = MagicMock()
      mock_probe.run.return_value = []
      probe_instances.append(kwargs)
      return mock_probe

    mock_cls = MagicMock(side_effect=mock_registry_probe)
    mock_cls.is_stateful = False
    mock_cls.requires_auth = False
    mock_cls.requires_regular_session = False

    with patch("extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY",
               [{"key": "_test", "cls": "test.TestProbe"}]):
      with patch.object(GrayboxLocalWorker, '_import_probe', staticmethod(lambda cls_path: mock_cls)):
        worker.execute_job()

    self.assertTrue(len(probe_instances) > 0)
    self.assertEqual(probe_instances[0]["discovered_forms"], ["/form1/"])

  def test_excluded_features_skips_probes(self):
    """'graybox' in excluded → no probes run."""
    worker = _make_worker(excluded_features=["graybox"])
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    with patch.object(GrayboxLocalWorker, '_import_probe') as mock_import:
      worker.execute_job()
      mock_import.assert_not_called()

  def test_excluded_probe_key_skips_only_that_probe(self):
    """Per-probe exclusions suppress only the disabled graybox probe."""
    worker = _make_worker(excluded_features=["_graybox_injection"])
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    imported = []
    mock_probe = MagicMock()
    mock_probe.run.return_value = []
    mock_cls = MagicMock(return_value=mock_probe)
    mock_cls.is_stateful = False
    mock_cls.requires_auth = False
    mock_cls.requires_regular_session = False

    def track_import(cls_path):
      imported.append(cls_path)
      return mock_cls

    with patch("extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY", [
      {"key": "_graybox_injection", "cls": "inj.Probe"},
      {"key": "_graybox_access_control", "cls": "acc.Probe"},
    ]):
      with patch.object(GrayboxLocalWorker, "_import_probe", staticmethod(track_import)):
        worker.execute_job()

    self.assertEqual(imported, ["acc.Probe"])
    metrics = worker.get_status()["scan_metrics"]
    self.assertEqual(metrics["probe_breakdown"]["_graybox_injection"], "skipped:disabled")
    self.assertEqual(metrics["probe_breakdown"]["_graybox_access_control"], "completed")

  def test_excluded_weak_auth_probe_records_skip(self):
    """Weak-auth probe is skipped cleanly when disabled by feature control."""
    worker = _make_worker(
      weak_candidates=["admin:admin"],
      excluded_features=["_graybox_weak_auth"],
    )
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    with patch("extensions.business.cybersec.red_mesh.graybox.worker.BusinessLogicProbes") as mock_probe:
      worker.execute_job()
      mock_probe.assert_not_called()

    metrics = worker.get_status()["scan_metrics"]
    self.assertEqual(metrics["probe_breakdown"]["_graybox_weak_auth"], "skipped:disabled")

  def test_get_worker_specific_result_fields(self):
    """Includes graybox_results."""
    fields = GrayboxLocalWorker.get_worker_specific_result_fields()
    self.assertIn("graybox_results", fields)
    self.assertEqual(fields["graybox_results"], dict)

  def test_ports_scanned_aggregation_type(self):
    """ports_scanned uses list aggregation type."""
    fields = GrayboxLocalWorker.get_worker_specific_result_fields()
    self.assertEqual(fields["ports_scanned"], list)

  def test_probe_error_isolation(self):
    """One probe crash doesn't kill the scan."""
    worker = _make_worker()
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])
    worker.safety.sanitize_error.return_value = "test error"

    crash_cls = MagicMock(side_effect=RuntimeError("probe crashed"))
    crash_cls.is_stateful = False
    crash_cls.requires_auth = False
    crash_cls.requires_regular_session = False

    ok_cls = MagicMock()
    ok_probe = MagicMock()
    ok_probe.run.return_value = [GrayboxFinding(
      scenario_id="OK-1", title="OK", status="not_vulnerable",
      severity="INFO", owasp="",
    )]
    ok_cls.return_value = ok_probe
    ok_cls.is_stateful = False
    ok_cls.requires_auth = False
    ok_cls.requires_regular_session = False

    imports = iter([crash_cls, ok_cls])

    with patch("extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY",
               [{"key": "_crash", "cls": "crash.CrashProbe"}, {"key": "_ok", "cls": "ok.OkProbe"}]):
      with patch.object(GrayboxLocalWorker, '_import_probe', staticmethod(lambda cls_path: next(imports))):
        worker.execute_job()

    self.assertTrue(worker.state["done"])
    # Crash probe recorded error finding
    crash_findings = worker.state["graybox_results"]["8000"]["_crash"]["findings"]
    self.assertEqual(len(crash_findings), 1)
    self.assertEqual(crash_findings[0]["status"], "inconclusive")
    # OK probe still ran
    ok_findings = worker.state["graybox_results"]["8000"]["_ok"]["findings"]
    self.assertEqual(len(ok_findings), 1)
    metrics = worker.get_status()["scan_metrics"]
    self.assertEqual(metrics["probe_breakdown"]["_crash"], "failed")
    self.assertEqual(metrics["probe_breakdown"]["_ok"], "completed")
    self.assertEqual(metrics["probes_failed"], 1)
    self.assertEqual(metrics["probes_completed"], 1)

  def test_probe_error_records_finding(self):
    """Crashed probe emits inconclusive finding."""
    worker = _make_worker()
    worker.safety.sanitize_error.return_value = "sanitized error"
    worker._record_probe_error("_test_probe", RuntimeError("fail"))
    findings = worker.state["graybox_results"]["8000"]["_test_probe"]["findings"]
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["status"], "inconclusive")
    self.assertIn("sanitized error", findings[0]["evidence"][0])

  def test_verify_tls_false_emits_warning(self):
    """TLS disabled → preflight finding."""
    worker = _make_worker(verify_tls=False)
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    with patch("extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY", []):
      worker.execute_job()

    preflight = worker.state["graybox_results"]["8000"].get("_graybox_preflight", {}).get("findings", [])
    self.assertEqual(len(preflight), 1)
    self.assertEqual(preflight[0]["scenario_id"], "PREFLIGHT-TLS")
    self.assertEqual(preflight[0]["severity"], "LOW")

  def test_probe_registry_iteration(self):
    """Probes loaded from GRAYBOX_PROBE_REGISTRY."""
    worker = _make_worker()
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    imported_paths = []

    def tracking_import(cls_path):
      imported_paths.append(cls_path)
      mock_cls = MagicMock()
      mock_cls.is_stateful = False
      mock_cls.requires_auth = False
      mock_cls.requires_regular_session = False
      mock_probe = MagicMock()
      mock_probe.run.return_value = []
      mock_cls.return_value = mock_probe
      return mock_cls

    with patch.object(GrayboxLocalWorker, '_import_probe', staticmethod(tracking_import)):
      worker.execute_job()

    # Should have imported all registry entries
    expected = [entry["cls"] for entry in GRAYBOX_PROBE_REGISTRY]
    self.assertEqual(imported_paths, expected)

  def test_capability_introspection(self):
    """Worker reads probe_cls.is_stateful, not registry dict."""
    worker = _make_worker()
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    mock_cls = MagicMock()
    mock_cls.is_stateful = True  # Stateful
    mock_cls.requires_auth = False
    mock_cls.requires_regular_session = False
    mock_probe = MagicMock()
    mock_probe.run.return_value = []
    mock_cls.return_value = mock_probe

    with patch("extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY",
               [{"key": "_stateful", "cls": "test.StatefulProbe"}]):
      with patch.object(GrayboxLocalWorker, '_import_probe', staticmethod(lambda cls_path: mock_cls)):
        worker.execute_job()

    # Probe was skipped (stateful disabled by default)
    skip = worker.state["graybox_results"]["8000"].get("_stateful", {}).get("findings", [])
    self.assertEqual(len(skip), 1)
    self.assertEqual(skip[0]["status"], "inconclusive")
    self.assertIn("stateful_probes_disabled", skip[0]["evidence"][0])

  def test_capability_skip_no_regular(self):
    """Probe requiring regular_session skipped when no regular session."""
    worker = _make_worker()
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = None  # No regular session
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    mock_cls = MagicMock()
    mock_cls.is_stateful = False
    mock_cls.requires_auth = False
    mock_cls.requires_regular_session = True
    mock_probe = MagicMock()
    mock_probe.run.return_value = []
    mock_cls.return_value = mock_probe

    with patch("extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY",
               [{"key": "_needs_regular", "cls": "test.NeedsRegular"}]):
      with patch.object(GrayboxLocalWorker, '_import_probe', staticmethod(lambda cls_path: mock_cls)):
        worker.execute_job()

    # Probe was silently skipped (no finding, no error)
    self.assertNotIn("_needs_regular", worker.state["graybox_results"].get("8000", {}))

  def test_capability_skip_stateful(self):
    """Stateful probe emits skip finding when disabled."""
    worker = _make_worker(allow_stateful_probes=False)
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    mock_cls = MagicMock()
    mock_cls.is_stateful = True
    mock_cls.requires_auth = False
    mock_cls.requires_regular_session = False

    with patch("extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY",
               [{"key": "_stateful_probe", "cls": "test.Stateful"}]):
      with patch.object(GrayboxLocalWorker, '_import_probe', staticmethod(lambda cls_path: mock_cls)):
        worker.execute_job()

    skip = worker.state["graybox_results"]["8000"].get("_stateful_probe", {}).get("findings", [])
    self.assertEqual(len(skip), 1)
    self.assertIn("stateful_probes_disabled=True", skip[0]["evidence"])

  def test_import_probe(self):
    """_import_probe resolves cls_path to class."""
    cls = GrayboxLocalWorker._import_probe("access_control.AccessControlProbes")
    from extensions.business.cybersec.red_mesh.graybox.probes.access_control import AccessControlProbes
    self.assertIs(cls, AccessControlProbes)

  def test_weak_auth_direct_import(self):
    """BusinessLogicProbes used directly for weak auth, not via registry."""
    worker = _make_worker(weak_candidates=["admin:admin"])
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None
    worker.auth.authenticate.return_value = True
    worker.auth.official_session = MagicMock()
    worker.auth.regular_session = MagicMock()
    worker.auth._auth_errors = []
    worker.auth.ensure_sessions = MagicMock()
    worker.auth.cleanup = MagicMock()
    worker.discovery.discover.return_value = ([], [])

    with patch("extensions.business.cybersec.red_mesh.graybox.worker.GRAYBOX_PROBE_REGISTRY", []):
      with patch("extensions.business.cybersec.red_mesh.graybox.worker.BusinessLogicProbes") as mock_bl:
        mock_instance = MagicMock()
        mock_instance.run_weak_auth.return_value = []
        mock_bl.return_value = mock_instance
        worker.execute_job()

        mock_bl.assert_called_once()
        mock_instance.run_weak_auth.assert_called_once()


if __name__ == '__main__':
  unittest.main()
