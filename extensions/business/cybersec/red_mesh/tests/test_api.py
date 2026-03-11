import json
import sys
import struct
import unittest
from unittest.mock import MagicMock, patch

from .conftest import DummyOwner, MANUAL_RUN, PentestLocalWorker, color_print, mock_plugin_modules


class TestPhase1ConfigCID(unittest.TestCase):
  """Phase 1: Job Config CID — extract static config from CStore to R1FS."""

  def test_config_cid_roundtrip(self):
    """JobConfig.from_dict(config.to_dict()) preserves all fields."""
    from extensions.business.cybersec.red_mesh.models import JobConfig

    original = JobConfig(
      target="example.com",
      start_port=1,
      end_port=1024,
      exceptions=[22, 80],
      distribution_strategy="SLICE",
      port_order="SHUFFLE",
      nr_local_workers=4,
      enabled_features=["http_headers", "sql_injection"],
      excluded_features=["brute_force"],
      run_mode="SINGLEPASS",
      scan_min_delay=0.1,
      scan_max_delay=0.5,
      ics_safe_mode=True,
      redact_credentials=False,
      scanner_identity="test-scanner",
      scanner_user_agent="RedMesh/1.0",
      task_name="Test Scan",
      task_description="A test scan",
      monitor_interval=300,
      selected_peers=["peer1", "peer2"],
      created_by_name="tester",
      created_by_id="user-123",
      authorized=True,
    )
    d = original.to_dict()
    restored = JobConfig.from_dict(d)
    self.assertEqual(original, restored)

  def test_config_to_dict_has_required_fields(self):
    """to_dict() includes target, start_port, end_port, run_mode."""
    from extensions.business.cybersec.red_mesh.models import JobConfig

    config = JobConfig(
      target="10.0.0.1",
      start_port=1,
      end_port=65535,
      exceptions=[],
      distribution_strategy="SLICE",
      port_order="SEQUENTIAL",
      nr_local_workers=2,
      enabled_features=[],
      excluded_features=[],
      run_mode="CONTINUOUS_MONITORING",
    )
    d = config.to_dict()
    self.assertEqual(d["target"], "10.0.0.1")
    self.assertEqual(d["start_port"], 1)
    self.assertEqual(d["end_port"], 65535)
    self.assertEqual(d["run_mode"], "CONTINUOUS_MONITORING")

  def test_config_strip_none(self):
    """_strip_none removes None values from serialized config."""
    from extensions.business.cybersec.red_mesh.models import JobConfig

    config = JobConfig(
      target="example.com",
      start_port=1,
      end_port=100,
      exceptions=[],
      distribution_strategy="SLICE",
      port_order="SEQUENTIAL",
      nr_local_workers=2,
      enabled_features=[],
      excluded_features=[],
      run_mode="SINGLEPASS",
      selected_peers=None,
    )
    d = config.to_dict()
    self.assertNotIn("selected_peers", d)

  @classmethod
  def _mock_plugin_modules(cls):
    mock_plugin_modules()

  @classmethod
  def _build_mock_plugin(cls, job_id="test-job", time_val=1000000.0, r1fs_cid="QmFakeConfigCID"):
    """Build a mock plugin instance for launch_test testing."""
    plugin = MagicMock()
    plugin.ee_addr = "node-1"
    plugin.ee_id = "node-alias-1"
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_port_order = "SEQUENTIAL"
    plugin.cfg_excluded_features = []
    plugin.cfg_distribution_strategy = "SLICE"
    plugin.cfg_run_mode = "SINGLEPASS"
    plugin.cfg_monitor_interval = 60
    plugin.cfg_scanner_identity = ""
    plugin.cfg_scanner_user_agent = ""
    plugin.cfg_nr_local_workers = 2
    plugin.cfg_llm_agent_api_enabled = False
    plugin.cfg_ics_safe_mode = False
    plugin.cfg_scan_min_rnd_delay = 0
    plugin.cfg_scan_max_rnd_delay = 0
    plugin.uuid.return_value = job_id
    plugin.time.return_value = time_val
    plugin.json_dumps.return_value = "{}"
    plugin.r1fs = MagicMock()
    plugin.r1fs.add_json.return_value = r1fs_cid
    plugin.chainstore_hset = MagicMock()
    plugin.chainstore_hgetall.return_value = {}
    plugin.chainstore_peers = ["node-1"]
    plugin.cfg_chainstore_peers = ["node-1"]
    plugin._redact_job_config = staticmethod(lambda d: d)
    return plugin

  @classmethod
  def _extract_job_specs(cls, plugin, job_id):
    """Extract the job_specs dict from chainstore_hset calls."""
    for call in plugin.chainstore_hset.call_args_list:
      kwargs = call[1] if call[1] else {}
      if kwargs.get("key") == job_id:
        return kwargs["value"]
    return None

  def _launch(self, plugin, **kwargs):
    """Call launch_test with mocked base modules."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    defaults = dict(target="example.com", start_port=1, end_port=1024, exceptions="", authorized=True)
    defaults.update(kwargs)
    return PentesterApi01Plugin.launch_test(plugin, **defaults)

  def test_launch_builds_job_config_and_stores_cid(self):
    """launch_test() builds JobConfig, saves to R1FS, stores job_config_cid in CStore."""
    plugin = self._build_mock_plugin(job_id="test-job-1", r1fs_cid="QmFakeConfigCID123")
    self._launch(plugin)

    # Verify r1fs.add_json was called with a JobConfig dict
    self.assertTrue(plugin.r1fs.add_json.called)
    config_dict = plugin.r1fs.add_json.call_args_list[0][0][0]
    self.assertEqual(config_dict["target"], "example.com")
    self.assertEqual(config_dict["start_port"], 1)
    self.assertEqual(config_dict["end_port"], 1024)
    self.assertIn("run_mode", config_dict)

    # Verify CStore has job_config_cid
    job_specs = self._extract_job_specs(plugin, "test-job-1")
    self.assertIsNotNone(job_specs, "Expected chainstore_hset call for job_specs")
    self.assertEqual(job_specs["job_config_cid"], "QmFakeConfigCID123")

  def test_cstore_has_no_static_config(self):
    """After launch, CStore object has no exceptions, distribution_strategy, etc."""
    plugin = self._build_mock_plugin(job_id="test-job-2")
    self._launch(plugin)

    job_specs = self._extract_job_specs(plugin, "test-job-2")
    self.assertIsNotNone(job_specs)

    # These static config fields must NOT be in CStore
    removed_fields = [
      "exceptions", "distribution_strategy", "enabled_features",
      "excluded_features", "scan_min_delay", "scan_max_delay",
      "ics_safe_mode", "redact_credentials", "scanner_identity",
      "scanner_user_agent", "nr_local_workers", "task_description",
      "monitor_interval", "selected_peers", "created_by_name",
      "created_by_id", "authorized", "port_order",
    ]
    for field in removed_fields:
      self.assertNotIn(field, job_specs, f"CStore should not contain '{field}'")

  def test_cstore_has_listing_fields(self):
    """CStore has target, task_name, start_port, end_port, date_created."""
    plugin = self._build_mock_plugin(job_id="test-job-3", time_val=1700000000.0)
    self._launch(plugin, start_port=80, end_port=443, task_name="Web Scan")

    job_specs = self._extract_job_specs(plugin, "test-job-3")
    self.assertIsNotNone(job_specs)

    self.assertEqual(job_specs["target"], "example.com")
    self.assertEqual(job_specs["task_name"], "Web Scan")
    self.assertEqual(job_specs["start_port"], 80)
    self.assertEqual(job_specs["end_port"], 443)
    self.assertEqual(job_specs["date_created"], 1700000000.0)
    self.assertEqual(job_specs["risk_score"], 0)

  def test_pass_reports_initialized_empty(self):
    """CStore has pass_reports: [] (no pass_history)."""
    plugin = self._build_mock_plugin(job_id="test-job-4")
    self._launch(plugin, start_port=1, end_port=100)

    job_specs = self._extract_job_specs(plugin, "test-job-4")
    self.assertIsNotNone(job_specs)

    self.assertIn("pass_reports", job_specs)
    self.assertEqual(job_specs["pass_reports"], [])
    self.assertNotIn("pass_history", job_specs)

  def test_launch_fails_if_r1fs_unavailable(self):
    """If R1FS fails to store config, launch aborts with error."""
    plugin = self._build_mock_plugin(job_id="test-job-5", r1fs_cid=None)
    result = self._launch(plugin, start_port=1, end_port=100)

    self.assertIn("error", result)
    # CStore should NOT have been written with the job
    job_specs = self._extract_job_specs(plugin, "test-job-5")
    self.assertIsNone(job_specs)



class TestPhase2PassFinalization(unittest.TestCase):
  """Phase 2: Single Aggregation + Consolidated Pass Reports."""

  @classmethod
  def _mock_plugin_modules(cls):
    """Install mock modules so pentester_api_01 can be imported without naeural_core."""
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _build_finalize_plugin(self, job_id="test-job", job_pass=1, run_mode="SINGLEPASS",
                              llm_enabled=False, r1fs_returns=None):
    """Build a mock plugin pre-configured for _maybe_finalize_pass testing."""
    plugin = MagicMock()
    plugin.ee_addr = "launcher-node"
    plugin.ee_id = "launcher-alias"
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_llm_agent_api_enabled = llm_enabled
    plugin.cfg_llm_agent_api_host = "localhost"
    plugin.cfg_llm_agent_api_port = 8080
    plugin.cfg_llm_agent_api_timeout = 30
    plugin.cfg_llm_auto_analysis_type = "security_assessment"
    plugin.cfg_monitor_interval = 60
    plugin.cfg_monitor_jitter = 0
    plugin.cfg_attestation_min_seconds_between_submits = 300
    plugin.time.return_value = 1000100.0
    plugin.json_dumps.return_value = "{}"

    # R1FS mock
    plugin.r1fs = MagicMock()
    cid_counter = {"n": 0}
    def fake_add_json(data, show_logs=True):
      cid_counter["n"] += 1
      if r1fs_returns is not None:
        return r1fs_returns.get(cid_counter["n"], f"QmCID{cid_counter['n']}")
      return f"QmCID{cid_counter['n']}"
    plugin.r1fs.add_json.side_effect = fake_add_json

    # Job config in R1FS
    plugin.r1fs.get_json.return_value = {
      "target": "example.com", "start_port": 1, "end_port": 1024,
      "run_mode": run_mode, "enabled_features": [], "monitor_interval": 60,
    }

    # Build job_specs with two finished workers
    job_specs = {
      "job_id": job_id,
      "job_status": "RUNNING",
      "job_pass": job_pass,
      "run_mode": run_mode,
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "task_name": "Test",
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "risk_score": 0,
      "job_config_cid": "QmConfigCID",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 512, "finished": True, "report_cid": "QmReportA"},
        "worker-B": {"start_port": 513, "end_port": 1024, "finished": True, "report_cid": "QmReportB"},
      },
      "timeline": [{"type": "created", "label": "Created", "date": 1000000.0, "actor": "launcher-alias", "actor_type": "system", "meta": {}}],
      "pass_reports": [],
    }

    plugin.chainstore_hgetall.return_value = {job_id: job_specs}
    plugin.chainstore_hset = MagicMock()

    return plugin, job_specs

  def _sample_node_report(self, start_port=1, end_port=512, open_ports=None, findings=None):
    """Build a sample node report dict."""
    report = {
      "start_port": start_port,
      "end_port": end_port,
      "open_ports": open_ports or [80, 443],
      "ports_scanned": end_port - start_port + 1,
      "nr_open_ports": len(open_ports or [80, 443]),
      "service_info": {},
      "web_tests_info": {},
      "completed_tests": ["port_scan"],
      "port_protocols": {"80": "http", "443": "https"},
      "port_banners": {},
      "correlation_findings": [],
    }
    if findings:
      # Add findings under service_info for port 80
      report["service_info"] = {
        "80": {
          "_service_info_http": {
            "findings": findings,
          }
        }
      }
    return report

  def test_single_aggregation(self):
    """_collect_node_reports called exactly once per pass finalization."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    # Mock _collect_node_reports and _get_aggregated_report
    report_a = self._sample_node_report(1, 512, [80])
    report_b = self._sample_node_report(513, 1024, [443])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a, "worker-B": report_b})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80, 443], "service_info": {}, "web_tests_info": {},
      "completed_tests": ["port_scan"], "ports_scanned": 1024,
      "nr_open_ports": 2, "port_protocols": {"80": "http", "443": "https"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com", "monitor_interval": 60})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 25, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # _collect_node_reports called exactly once
    plugin._collect_node_reports.assert_called_once()

  def test_pass_report_cid_in_r1fs(self):
    """PassReport stored in R1FS with correct fields."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {"findings_score": 5}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # r1fs.add_json called twice: once for aggregated data, once for PassReport
    self.assertEqual(plugin.r1fs.add_json.call_count, 2)

    # Second call is the PassReport
    pass_report_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(pass_report_dict["pass_nr"], 1)
    self.assertIn("aggregated_report_cid", pass_report_dict)
    self.assertIn("worker_reports", pass_report_dict)
    self.assertEqual(pass_report_dict["risk_score"], 10)
    self.assertIn("risk_breakdown", pass_report_dict)
    self.assertIn("date_started", pass_report_dict)
    self.assertIn("date_completed", pass_report_dict)

  def test_aggregated_report_separate_cid(self):
    """aggregated_report_cid is a separate R1FS write from the PassReport."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(r1fs_returns={1: "QmAggCID", 2: "QmPassCID"})

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # First R1FS write = aggregated data, second = PassReport
    agg_dict = plugin.r1fs.add_json.call_args_list[0][0][0]
    pass_dict = plugin.r1fs.add_json.call_args_list[1][0][0]

    # The PassReport references the aggregated CID
    self.assertEqual(pass_dict["aggregated_report_cid"], "QmAggCID")

    # Aggregated data should have open_ports (from AggregatedScanData)
    self.assertIn("open_ports", agg_dict)

  def test_finding_id_deterministic(self):
    """Same input produces same finding_id; different title produces different id."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [80], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
      "service_info": {
        "80": {
          "_service_info_http": {
            "findings": [
              {"title": "SQL Injection", "severity": "HIGH", "cwe_id": "CWE-89", "confidence": "firm"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    risk1, findings1 = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    risk2, findings2 = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)

    self.assertEqual(findings1[0]["finding_id"], findings2[0]["finding_id"])

    # Different title → different finding_id
    aggregated2 = {
      "open_ports": [80], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
      "service_info": {
        "80": {
          "_service_info_http": {
            "findings": [
              {"title": "XSS Vulnerability", "severity": "HIGH", "cwe_id": "CWE-79", "confidence": "firm"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }
    _, findings3 = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated2)
    self.assertNotEqual(findings1[0]["finding_id"], findings3[0]["finding_id"])

  def test_finding_id_cwe_collision(self):
    """Same CWE, different title, same port+probe → different finding_ids."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [80], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
      "service_info": {
        "80": {
          "_web_test_xss": {
            "findings": [
              {"title": "Reflected XSS in search", "severity": "HIGH", "cwe_id": "CWE-79", "confidence": "certain"},
              {"title": "Stored XSS in comment", "severity": "HIGH", "cwe_id": "CWE-79", "confidence": "certain"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    _, findings = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    self.assertEqual(len(findings), 2)
    self.assertNotEqual(findings[0]["finding_id"], findings[1]["finding_id"])

  def test_finding_enrichment_fields(self):
    """Each finding has finding_id, port, protocol, probe, category."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [443], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"443": "https"},
      "service_info": {
        "443": {
          "_service_info_ssl": {
            "findings": [
              {"title": "Weak TLS", "severity": "MEDIUM", "cwe_id": "CWE-326", "confidence": "certain"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    _, findings = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    self.assertEqual(len(findings), 1)
    f = findings[0]
    self.assertIn("finding_id", f)
    self.assertEqual(len(f["finding_id"]), 16)  # 16-char hex
    self.assertEqual(f["port"], 443)
    self.assertEqual(f["protocol"], "https")
    self.assertEqual(f["probe"], "_service_info_ssl")
    self.assertEqual(f["category"], "service")

  def test_port_protocols_none(self):
    """port_protocols is None → protocol defaults to 'unknown' (no crash)."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [22], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": None,
      "service_info": {
        "22": {
          "_service_info_ssh": {
            "findings": [
              {"title": "Weak SSH key", "severity": "LOW", "cwe_id": "CWE-320", "confidence": "firm"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    _, findings = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["protocol"], "unknown")

  def test_llm_success_no_llm_failed(self):
    """LLM succeeds → llm_failed absent from serialized PassReport."""
    from extensions.business.cybersec.red_mesh.models import PassReport

    pr = PassReport(
      pass_nr=1, date_started=1000.0, date_completed=1100.0, duration=100.0,
      aggregated_report_cid="QmAgg",
      worker_reports={},
      risk_score=50,
      llm_analysis="# Analysis\nAll good.",
      quick_summary="No critical issues found.",
      llm_failed=None,  # success
    )
    d = pr.to_dict()
    self.assertNotIn("llm_failed", d)
    self.assertEqual(d["llm_analysis"], "# Analysis\nAll good.")

  def test_llm_failure_flag_and_timeline(self):
    """LLM fails → llm_failed: True, timeline event added."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(llm_enabled=True)

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    # LLM returns None (failure)
    plugin._run_aggregated_llm_analysis = MagicMock(return_value=None)
    plugin._run_quick_summary_analysis = MagicMock(return_value=None)

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # Check PassReport has llm_failed=True
    pass_report_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertTrue(pass_report_dict.get("llm_failed"))

    # Check timeline event was emitted for llm_failed
    llm_failed_calls = [
      c for c in plugin._emit_timeline_event.call_args_list
      if c[0][1] == "llm_failed"
    ]
    self.assertEqual(len(llm_failed_calls), 1)
    # _emit_timeline_event(job_specs, "llm_failed", label, meta={"pass_nr": ...})
    call_kwargs = llm_failed_calls[0][1]  # keyword args
    meta = call_kwargs.get("meta", {})
    self.assertIn("pass_nr", meta)

  def test_aggregated_report_write_failure(self):
    """R1FS fails for aggregated → pass finalization skipped, no partial state."""
    PentesterApi01Plugin = self._get_plugin_class()
    # First R1FS write (aggregated) returns None = failure
    plugin, job_specs = self._build_finalize_plugin(r1fs_returns={1: None, 2: "QmPassCID"})

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # CStore should NOT have pass_reports appended
    self.assertEqual(len(job_specs["pass_reports"]), 0)
    # CStore hset was called for intermediate status updates (COLLECTING, ANALYZING, FINALIZING)
    # but NOT for finalization — verify job_status is NOT FINALIZED in the last write
    for call_args in plugin.chainstore_hset.call_args_list:
      value = call_args.kwargs.get("value") or call_args[1].get("value") if len(call_args) > 1 else None
      if isinstance(value, dict):
        self.assertNotEqual(value.get("job_status"), "FINALIZED")

  def test_pass_report_write_failure(self):
    """R1FS fails for pass report → CStore pass_reports not appended."""
    PentesterApi01Plugin = self._get_plugin_class()
    # First R1FS write (aggregated) succeeds, second (pass report) fails
    plugin, job_specs = self._build_finalize_plugin(r1fs_returns={1: "QmAggCID", 2: None})

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # CStore should NOT have pass_reports appended
    self.assertEqual(len(job_specs["pass_reports"]), 0)
    # CStore hset was called for status updates but NOT for finalization
    for call_args in plugin.chainstore_hset.call_args_list:
      value = call_args.kwargs.get("value") or call_args[1].get("value") if len(call_args) > 1 else None
      if isinstance(value, dict):
        self.assertNotEqual(value.get("job_status"), "FINALIZED")

  def test_cstore_risk_score_updated(self):
    """After pass, risk_score on CStore matches pass result."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 42, "breakdown": {"findings_score": 30}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # CStore risk_score updated
    self.assertEqual(job_specs["risk_score"], 42)

    # PassReportRef in pass_reports has same risk_score
    self.assertEqual(len(job_specs["pass_reports"]), 1)
    ref = job_specs["pass_reports"][0]
    self.assertEqual(ref["risk_score"], 42)
    self.assertIn("report_cid", ref)
    self.assertEqual(ref["pass_nr"], 1)



class TestPhase4UiAggregate(unittest.TestCase):
  """Phase 4: UI Aggregate Computation."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _make_plugin(self):
    plugin = MagicMock()
    Plugin = self._get_plugin_class()
    plugin._count_services = lambda si: Plugin._count_services(plugin, si)
    plugin._compute_ui_aggregate = lambda passes, agg: Plugin._compute_ui_aggregate(plugin, passes, agg)
    plugin.SEVERITY_ORDER = Plugin.SEVERITY_ORDER
    plugin.CONFIDENCE_ORDER = Plugin.CONFIDENCE_ORDER
    return plugin, Plugin

  def _make_finding(self, severity="HIGH", confidence="firm", finding_id="abc123", title="Test"):
    return {"finding_id": finding_id, "severity": severity, "confidence": confidence, "title": title}

  def _make_pass(self, pass_nr=1, findings=None, risk_score=0, worker_reports=None):
    return {
      "pass_nr": pass_nr,
      "risk_score": risk_score,
      "risk_breakdown": {"findings_score": 10},
      "quick_summary": "Summary text",
      "findings": findings,
      "worker_reports": worker_reports or {
        "w1": {"start_port": 1, "end_port": 512, "open_ports": [80]},
      },
    }

  def _make_aggregated(self, open_ports=None, service_info=None):
    return {
      "open_ports": open_ports or [80, 443],
      "service_info": service_info or {
        "80": {"_service_info_http": {"findings": []}},
        "443": {"_service_info_https": {"findings": []}},
      },
    }

  def test_findings_count_uppercase_keys(self):
    """findings_count keys are UPPERCASE."""
    plugin, _ = self._make_plugin()
    findings = [
      self._make_finding(severity="CRITICAL", finding_id="f1"),
      self._make_finding(severity="HIGH", finding_id="f2"),
      self._make_finding(severity="HIGH", finding_id="f3"),
      self._make_finding(severity="MEDIUM", finding_id="f4"),
    ]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    fc = result.to_dict()["findings_count"]
    self.assertEqual(fc["CRITICAL"], 1)
    self.assertEqual(fc["HIGH"], 2)
    self.assertEqual(fc["MEDIUM"], 1)
    for key in fc:
      self.assertEqual(key, key.upper())

  def test_top_findings_max_10(self):
    """More than 10 CRITICAL+HIGH -> capped at 10."""
    plugin, _ = self._make_plugin()
    findings = [self._make_finding(severity="CRITICAL", finding_id=f"f{i}") for i in range(15)]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    self.assertEqual(len(result.to_dict()["top_findings"]), 10)

  def test_top_findings_sorted(self):
    """CRITICAL before HIGH, within same severity sorted by confidence."""
    plugin, _ = self._make_plugin()
    findings = [
      self._make_finding(severity="HIGH", confidence="certain", finding_id="f1", title="H-certain"),
      self._make_finding(severity="CRITICAL", confidence="tentative", finding_id="f2", title="C-tentative"),
      self._make_finding(severity="HIGH", confidence="tentative", finding_id="f3", title="H-tentative"),
      self._make_finding(severity="CRITICAL", confidence="certain", finding_id="f4", title="C-certain"),
    ]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    top = result.to_dict()["top_findings"]
    self.assertEqual(top[0]["title"], "C-certain")
    self.assertEqual(top[1]["title"], "C-tentative")
    self.assertEqual(top[2]["title"], "H-certain")
    self.assertEqual(top[3]["title"], "H-tentative")

  def test_top_findings_excludes_medium(self):
    """MEDIUM/LOW/INFO findings never in top_findings."""
    plugin, _ = self._make_plugin()
    findings = [
      self._make_finding(severity="MEDIUM", finding_id="f1"),
      self._make_finding(severity="LOW", finding_id="f2"),
      self._make_finding(severity="INFO", finding_id="f3"),
    ]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    d = result.to_dict()
    self.assertNotIn("top_findings", d)  # stripped by _strip_none (None)

  def test_finding_timeline_single_pass(self):
    """1 pass -> finding_timeline is None (stripped)."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(findings=[])
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    d = result.to_dict()
    self.assertNotIn("finding_timeline", d)  # None → stripped

  def test_finding_timeline_multi_pass(self):
    """3 passes with overlapping findings -> correct first_seen, last_seen, pass_count."""
    plugin, _ = self._make_plugin()
    f_persistent = self._make_finding(finding_id="persist1")
    f_transient = self._make_finding(finding_id="transient1")
    f_new = self._make_finding(finding_id="new1")
    passes = [
      self._make_pass(pass_nr=1, findings=[f_persistent, f_transient]),
      self._make_pass(pass_nr=2, findings=[f_persistent]),
      self._make_pass(pass_nr=3, findings=[f_persistent, f_new]),
    ]
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate(passes, agg)
    ft = result.to_dict()["finding_timeline"]
    self.assertEqual(ft["persist1"]["first_seen"], 1)
    self.assertEqual(ft["persist1"]["last_seen"], 3)
    self.assertEqual(ft["persist1"]["pass_count"], 3)
    self.assertEqual(ft["transient1"]["first_seen"], 1)
    self.assertEqual(ft["transient1"]["last_seen"], 1)
    self.assertEqual(ft["transient1"]["pass_count"], 1)
    self.assertEqual(ft["new1"]["first_seen"], 3)
    self.assertEqual(ft["new1"]["last_seen"], 3)
    self.assertEqual(ft["new1"]["pass_count"], 1)

  def test_zero_findings(self):
    """findings_count is {}, top_findings is [], total_findings is 0."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(findings=[])
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    d = result.to_dict()
    self.assertEqual(d["total_findings"], 0)
    # findings_count and top_findings are None (stripped) when empty
    self.assertNotIn("findings_count", d)
    self.assertNotIn("top_findings", d)

  def test_open_ports_sorted_unique(self):
    """total_open_ports is deduped and sorted."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(findings=[])
    agg = self._make_aggregated(open_ports=[443, 80, 443, 22, 80])
    result = plugin._compute_ui_aggregate([p], agg)
    self.assertEqual(result.to_dict()["total_open_ports"], [22, 80, 443])

  def test_count_services(self):
    """_count_services counts ports with at least one detected service."""
    plugin, _ = self._make_plugin()
    service_info = {
      "80": {"_service_info_http": {}, "_web_test_xss": {}},
      "443": {"_service_info_https": {}, "_service_info_http": {}},
    }
    self.assertEqual(plugin._count_services(service_info), 2)
    self.assertEqual(plugin._count_services({}), 0)
    self.assertEqual(plugin._count_services(None), 0)



class TestPhase3Archive(unittest.TestCase):
  """Phase 3: Job Close & Archive."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _build_archive_plugin(self, job_id="test-job", pass_count=1, run_mode="SINGLEPASS",
                              job_status="FINALIZED", r1fs_write_fail=False, r1fs_verify_fail=False):
    """Build a mock plugin pre-configured for _build_job_archive testing."""
    plugin = MagicMock()
    plugin.ee_addr = "launcher-node"
    plugin.ee_id = "launcher-alias"
    plugin.cfg_instance_id = "test-instance"
    plugin.time.return_value = 1000200.0
    plugin.json_dumps.return_value = "{}"

    # R1FS mock
    plugin.r1fs = MagicMock()

    # Build pass report dicts and refs
    pass_reports_data = []
    pass_report_refs = []
    for i in range(1, pass_count + 1):
      pr = {
        "pass_nr": i,
        "date_started": 1000000.0 + (i - 1) * 100,
        "date_completed": 1000000.0 + i * 100,
        "duration": 100.0,
        "aggregated_report_cid": f"QmAgg{i}",
        "worker_reports": {
          "worker-A": {"report_cid": f"QmWorker{i}A", "start_port": 1, "end_port": 512, "ports_scanned": 512, "open_ports": [80], "nr_findings": 2},
        },
        "risk_score": 25 + i,
        "risk_breakdown": {"findings_score": 10},
        "findings": [
          {"finding_id": f"f{i}a", "severity": "HIGH", "confidence": "firm", "title": f"Finding {i}A"},
          {"finding_id": f"f{i}b", "severity": "MEDIUM", "confidence": "firm", "title": f"Finding {i}B"},
        ],
        "quick_summary": f"Summary for pass {i}",
      }
      pass_reports_data.append(pr)
      pass_report_refs.append({"pass_nr": i, "report_cid": f"QmPassReport{i}", "risk_score": 25 + i})

    # Job config
    job_config = {
      "target": "example.com", "start_port": 1, "end_port": 1024,
      "run_mode": run_mode, "enabled_features": [], "scan_type": "webapp",
      "target_url": "https://example.com/app",
    }

    # Latest aggregated data
    latest_aggregated = {
      "open_ports": [80, 443], "service_info": {"80": {"_service_info_http": {}}},
      "web_tests_info": {}, "completed_tests": ["port_scan"], "ports_scanned": 1024,
    }

    # R1FS get_json: return the right data for each CID
    cid_map = {"QmConfigCID": job_config}
    for i, pr in enumerate(pass_reports_data):
      cid_map[f"QmPassReport{i+1}"] = pr
      cid_map[f"QmAgg{i+1}"] = latest_aggregated

    if r1fs_write_fail:
      plugin.r1fs.add_json.return_value = None
    else:
      archive_cid = "QmArchiveCID"
      plugin.r1fs.add_json.return_value = archive_cid
      if r1fs_verify_fail:
        # add_json succeeds but get_json for the archive CID returns None
        orig_map = dict(cid_map)
        def verify_fail_get(cid):
          if cid == archive_cid:
            return None
          return orig_map.get(cid)
        plugin.r1fs.get_json.side_effect = verify_fail_get
      else:
        # Verification succeeds — archive CID also returns data
        cid_map[archive_cid] = {"job_id": job_id}  # minimal archive for verification
        plugin.r1fs.get_json.side_effect = lambda cid: cid_map.get(cid)

    if not r1fs_write_fail and not r1fs_verify_fail:
      plugin.r1fs.get_json.side_effect = lambda cid: cid_map.get(cid)

    # Job specs (running state)
    job_specs = {
      "job_id": job_id,
      "job_status": job_status,
      "job_pass": pass_count,
      "run_mode": run_mode,
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "task_name": "Test",
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "risk_score": 25 + pass_count,
      "job_config_cid": "QmConfigCID",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 512, "finished": True, "report_cid": "QmReportA"},
      },
      "timeline": [
        {"type": "created", "label": "Created", "date": 1000000.0, "actor": "launcher-alias", "actor_type": "system", "meta": {}},
      ],
      "pass_reports": pass_report_refs,
    }

    plugin.chainstore_hset = MagicMock()

    # Bind real methods for archive building
    Plugin = self._get_plugin_class()
    plugin._compute_ui_aggregate = lambda passes, agg: Plugin._compute_ui_aggregate(plugin, passes, agg)
    plugin._count_services = lambda si: Plugin._count_services(plugin, si)
    plugin.SEVERITY_ORDER = Plugin.SEVERITY_ORDER
    plugin.CONFIDENCE_ORDER = Plugin.CONFIDENCE_ORDER

    return plugin, job_specs, pass_reports_data, job_config

  def test_archive_written_to_r1fs(self):
    """Archive stored in R1FS with job_id, job_config, passes, ui_aggregate."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, job_config = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # r1fs.add_json called with archive dict
    self.assertTrue(plugin.r1fs.add_json.called)
    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    self.assertEqual(archive_dict["job_id"], "test-job")
    self.assertEqual(archive_dict["job_config"]["target"], "example.com")
    self.assertEqual(len(archive_dict["passes"]), 1)
    self.assertIn("ui_aggregate", archive_dict)
    self.assertIn("total_open_ports", archive_dict["ui_aggregate"])

  def test_archive_duration_computed(self):
    """duration == date_completed - date_created, not 0."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    # date_created=1000000, time()=1000200 → duration=200
    self.assertEqual(archive_dict["duration"], 200.0)
    self.assertGreater(archive_dict["duration"], 0)

  def test_stub_has_job_cid_and_config_cid(self):
    """After prune, CStore stub has job_cid and job_config_cid."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # Extract the stub written to CStore
    hset_call = plugin.chainstore_hset.call_args
    stub = hset_call[1]["value"]
    self.assertEqual(stub["job_cid"], "QmArchiveCID")
    self.assertEqual(stub["job_config_cid"], "QmConfigCID")
    self.assertEqual(stub["scan_type"], "webapp")
    self.assertEqual(stub["target_url"], "https://example.com/app")

  def test_stub_fields_match_model(self):
    """Stub has exactly CStoreJobFinalized fields."""
    from extensions.business.cybersec.red_mesh.models import CStoreJobFinalized
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    stub = plugin.chainstore_hset.call_args[1]["value"]
    # Verify it can be loaded into CStoreJobFinalized
    finalized = CStoreJobFinalized.from_dict(stub)
    self.assertEqual(finalized.job_id, "test-job")
    self.assertEqual(finalized.job_status, "FINALIZED")
    self.assertEqual(finalized.target, "example.com")
    self.assertEqual(finalized.scan_type, "webapp")
    self.assertEqual(finalized.target_url, "https://example.com/app")
    self.assertEqual(finalized.pass_count, 1)
    self.assertEqual(finalized.worker_count, 1)
    self.assertEqual(finalized.start_port, 1)
    self.assertEqual(finalized.end_port, 1024)
    self.assertGreater(finalized.duration, 0)

  def test_pass_report_cids_cleaned_up(self):
    """After archive, individual pass CIDs deleted from R1FS."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # Check delete_file was called for pass report CID
    delete_calls = [c[0][0] for c in plugin.r1fs.delete_file.call_args_list]
    self.assertIn("QmPassReport1", delete_calls)

  def test_node_report_cids_preserved(self):
    """Worker report CIDs NOT deleted."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    delete_calls = [c[0][0] for c in plugin.r1fs.delete_file.call_args_list]
    self.assertNotIn("QmWorker1A", delete_calls)

  def test_aggregated_report_cids_preserved(self):
    """aggregated_report_cid per pass NOT deleted."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    delete_calls = [c[0][0] for c in plugin.r1fs.delete_file.call_args_list]
    self.assertNotIn("QmAgg1", delete_calls)

  def test_archive_write_failure_no_prune(self):
    """R1FS write fails -> CStore untouched, full running state retained."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(r1fs_write_fail=True)

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # CStore should NOT have been pruned
    plugin.chainstore_hset.assert_not_called()
    # pass_reports still present in job_specs
    self.assertEqual(len(job_specs["pass_reports"]), 1)

  def test_archive_verify_failure_no_prune(self):
    """CID not retrievable -> CStore untouched."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(r1fs_verify_fail=True)

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    plugin.chainstore_hset.assert_not_called()

  def test_stuck_recovery(self):
    """FINALIZED without job_cid -> _build_job_archive retried via _maybe_finalize_pass."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(job_status="FINALIZED")
    # Simulate stuck state: FINALIZED but no job_cid
    job_specs["job_status"] = "FINALIZED"
    # No job_cid in specs

    plugin.chainstore_hgetall.return_value = {"test-job": job_specs}
    plugin._normalize_job_record = MagicMock(return_value=("test-job", job_specs))
    plugin._build_job_archive = MagicMock()

    Plugin._maybe_finalize_pass(plugin)

    plugin._build_job_archive.assert_called_once_with("test-job", job_specs)

  def test_idempotent_rebuild(self):
    """Calling _build_job_archive twice doesn't corrupt state."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)
    first_stub = plugin.chainstore_hset.call_args[1]["value"]

    # Reset and call again (simulating a retry where data is still available)
    plugin.chainstore_hset.reset_mock()
    plugin.r1fs.add_json.reset_mock()
    new_archive_cid = "QmArchiveCID2"
    plugin.r1fs.add_json.return_value = new_archive_cid

    # Update get_json to also return data for the new archive CID
    orig_side_effect = plugin.r1fs.get_json.side_effect
    def extended_get(cid):
      if cid == new_archive_cid:
        return {"job_id": "test-job"}
      return orig_side_effect(cid)
    plugin.r1fs.get_json.side_effect = extended_get

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    second_stub = plugin.chainstore_hset.call_args[1]["value"]
    # Both produce valid stubs
    self.assertEqual(first_stub["job_id"], second_stub["job_id"])
    self.assertEqual(first_stub["pass_count"], second_stub["pass_count"])

  def test_multipass_archive(self):
    """Archive with 3 passes contains all pass data."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(pass_count=3, run_mode="CONTINUOUS_MONITORING", job_status="STOPPED")

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    self.assertEqual(len(archive_dict["passes"]), 3)
    self.assertEqual(archive_dict["passes"][0]["pass_nr"], 1)
    self.assertEqual(archive_dict["passes"][2]["pass_nr"], 3)
    stub = plugin.chainstore_hset.call_args[1]["value"]
    self.assertEqual(stub["pass_count"], 3)
    self.assertEqual(stub["job_status"], "STOPPED")



class TestPhase5Endpoints(unittest.TestCase):
  """Phase 5: API Endpoints."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _build_finalized_stub(self, job_id="test-job"):
    """Build a CStoreJobFinalized-shaped dict."""
    return {
      "job_id": job_id,
      "job_status": "FINALIZED",
      "target": "example.com",
      "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "task_name": "Test",
      "risk_score": 42,
      "run_mode": "SINGLEPASS",
      "duration": 200.0,
      "pass_count": 1,
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "worker_count": 2,
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "date_completed": 1000200.0,
      "job_cid": "QmArchiveCID",
      "job_config_cid": "QmConfigCID",
    }

  def _build_running_job(self, job_id="run-job", pass_count=8):
    """Build a running job dict with N pass_reports."""
    pass_reports = [
      {"pass_nr": i, "report_cid": f"QmPass{i}", "risk_score": 10 + i}
      for i in range(1, pass_count + 1)
    ]
    return {
      "job_id": job_id,
      "job_status": "RUNNING",
      "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "job_pass": pass_count,
      "run_mode": "CONTINUOUS_MONITORING",
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "task_name": "Continuous Test",
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "risk_score": 18,
      "job_config_cid": "QmConfigCID",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 512, "finished": False},
        "worker-B": {"start_port": 513, "end_port": 1024, "finished": False},
      },
      "timeline": [
        {"type": "created", "label": "Created", "date": 1000000.0, "actor": "launcher", "actor_type": "system", "meta": {}},
        {"type": "started", "label": "Started", "date": 1000001.0, "actor": "launcher", "actor_type": "system", "meta": {}},
      ],
      "pass_reports": pass_reports,
    }

  def _build_plugin(self, jobs_dict):
    """Build a mock plugin with given jobs in CStore."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.ee_addr = "launcher-node"
    plugin.ee_id = "launcher-alias"
    plugin.cfg_instance_id = "test-instance"
    plugin.r1fs = MagicMock()

    plugin.chainstore_hgetall.return_value = dict(jobs_dict)
    plugin.chainstore_hget.side_effect = lambda hkey, key: jobs_dict.get(key)
    plugin._normalize_job_record = MagicMock(
      side_effect=lambda k, v: (k, v) if isinstance(v, dict) and v.get("job_id") else (None, None)
    )

    # Bind real methods so endpoint logic executes properly
    plugin._get_all_network_jobs = lambda: Plugin._get_all_network_jobs(plugin)
    plugin._get_job_from_cstore = lambda job_id: Plugin._get_job_from_cstore(plugin, job_id)
    return plugin

  def test_get_job_archive_finalized(self):
    """get_job_archive for finalized job returns archive with matching job_id."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    archive_data = {"job_id": "fin-job", "passes": [], "ui_aggregate": {}}
    plugin.r1fs.get_json.return_value = archive_data

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["job_id"], "fin-job")
    self.assertEqual(result["archive"]["job_id"], "fin-job")

  def test_get_job_archive_running(self):
    """get_job_archive for running job returns not_available error."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=2)
    plugin = self._build_plugin({"run-job": running})

    result = Plugin.get_job_archive(plugin, job_id="run-job")
    self.assertEqual(result["error"], "not_available")

  def test_get_job_archive_integrity_mismatch(self):
    """Corrupted job_cid pointing to wrong archive is rejected."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    # Archive has a different job_id
    plugin.r1fs.get_json.return_value = {"job_id": "other-job", "passes": []}

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["error"], "integrity_mismatch")

  def test_get_job_data_running_last_5(self):
    """Running job with 8 passes returns last 5 refs only."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=8)
    plugin = self._build_plugin({"run-job": running})

    result = Plugin.get_job_data(plugin, job_id="run-job")
    self.assertTrue(result["found"])
    refs = result["job"]["pass_reports"]
    self.assertEqual(len(refs), 5)
    # Should be the last 5 (pass_nr 4-8)
    self.assertEqual(refs[0]["pass_nr"], 4)
    self.assertEqual(refs[-1]["pass_nr"], 8)

  def test_get_job_data_finalized_returns_stub(self):
    """Finalized job returns stub as-is with job_cid."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    result = Plugin.get_job_data(plugin, job_id="fin-job")
    self.assertTrue(result["found"])
    self.assertEqual(result["job"]["job_cid"], "QmArchiveCID")
    self.assertEqual(result["job"]["pass_count"], 1)

  def test_list_jobs_finalized_as_is(self):
    """Finalized stubs returned unmodified with all CStoreJobFinalized fields."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("fin-job", result)
    job = result["fin-job"]
    self.assertEqual(job["job_cid"], "QmArchiveCID")
    self.assertEqual(job["pass_count"], 1)
    self.assertEqual(job["worker_count"], 2)
    self.assertEqual(job["risk_score"], 42)
    self.assertEqual(job["duration"], 200.0)
    self.assertEqual(job["scan_type"], "webapp")
    self.assertEqual(job["target_url"], "https://example.com/app")

  def test_list_jobs_running_stripped(self):
    """Running jobs have counts but no timeline, workers, or pass_reports."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=3)
    plugin = self._build_plugin({"run-job": running})

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("run-job", result)
    job = result["run-job"]
    # Should have counts
    self.assertEqual(job["pass_count"], 3)
    self.assertEqual(job["worker_count"], 2)
    self.assertEqual(job["scan_type"], "webapp")
    self.assertEqual(job["target_url"], "https://example.com/app")
    # Should NOT have heavy fields
    self.assertNotIn("timeline", job)
    self.assertNotIn("workers", job)
    self.assertNotIn("pass_reports", job)

  def test_get_job_progress_returns_job_status(self):
    """get_job_progress surfaces job_status from CStore job specs."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=2)
    plugin = self._build_plugin({"run-job": running})
    plugin.chainstore_hgetall.return_value = {"run-job:worker-A": {"job_id": "run-job", "progress": 50}}

    result = Plugin.get_job_progress(plugin, job_id="run-job")
    self.assertEqual(result["status"], "RUNNING")
    self.assertIn("worker-A", result["workers"])

  def test_get_job_archive_not_found(self):
    """get_job_archive for non-existent job returns not_found."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})

    result = Plugin.get_job_archive(plugin, job_id="missing-job")
    self.assertEqual(result["error"], "not_found")

  def test_get_job_archive_r1fs_failure(self):
    """get_job_archive when R1FS fails returns fetch_failed."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = None

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["error"], "fetch_failed")

