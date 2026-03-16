import json
import unittest
from collections import deque
from unittest.mock import MagicMock
import requests

from .conftest import mock_plugin_modules


class TestAttestationHelpers(unittest.TestCase):

  def test_resolve_attestation_report_cid_prefers_explicit_cid(self):
    from extensions.business.cybersec.red_mesh.mixins.attestation import _AttestationMixin

    result = _AttestationMixin._resolve_attestation_report_cid(
      {"0xpeer1": {"report_cid": "QmWorkerCid"}},
      preferred_cid=" QmAggregatedCid ",
    )
    self.assertEqual(result, "QmAggregatedCid")

  def test_resolve_attestation_report_cid_uses_single_worker_cid_as_fallback(self):
    from extensions.business.cybersec.red_mesh.mixins.attestation import _AttestationMixin

    result = _AttestationMixin._resolve_attestation_report_cid(
      {"0xpeer1": {"report_cid": "QmWorkerCid"}},
    )
    self.assertEqual(result, "QmWorkerCid")

  def test_submit_test_attestation_uses_explicit_report_cid(self):
    from extensions.business.cybersec.red_mesh.mixins.attestation import _AttestationMixin

    class MockHost(_AttestationMixin):
      REDMESH_ATTESTATION_DOMAIN = "0x" + ("11" * 32)

      def __init__(self):
        self.cfg_attestation = {"ENABLED": True, "PRIVATE_KEY": "0xprivate", "RETRIES": 2}
        self.ee_addr = "0xlauncher"
        self.bc = MagicMock()
        self.bc.eth_address = "0xsender"
        self.bc.submit_attestation.return_value = "0xtxhash"

      def P(self, *_args, **_kwargs):
        return None

    host = MockHost()
    result = host._submit_redmesh_test_attestation(
      job_id="jobid123",
      job_specs={"target": "https://app.example.com", "run_mode": "SINGLEPASS"},
      workers={"0xlauncher": {"report_cid": "QmWorkerCid"}},
      vulnerability_score=7,
      node_ips=["10.0.0.10"],
      report_cid="QmAggregatedCid",
    )

    self.assertEqual(result["report_cid"], "QmAggregatedCid")
    submit_kwargs = host.bc.submit_attestation.call_args.kwargs
    self.assertEqual(
      submit_kwargs["function_args"][-1],
      host._attestation_pack_cid_obfuscated("QmAggregatedCid"),
    )

  def test_submit_test_attestation_retries_transient_failure(self):
    from extensions.business.cybersec.red_mesh.mixins.attestation import _AttestationMixin

    class MockHost(_AttestationMixin):
      REDMESH_ATTESTATION_DOMAIN = "0x" + ("11" * 32)

      def __init__(self):
        self.cfg_attestation = {"ENABLED": True, "PRIVATE_KEY": "0xprivate", "RETRIES": 2}
        self.ee_addr = "0xlauncher"
        self.bc = MagicMock()
        self.bc.eth_address = "0xsender"
        self.bc.submit_attestation.side_effect = [RuntimeError("temporary"), "0xtxhash"]

      def P(self, *_args, **_kwargs):
        return None

    host = MockHost()
    result = host._submit_redmesh_test_attestation(
      job_id="jobid123",
      job_specs={"target": "https://app.example.com", "run_mode": "SINGLEPASS"},
      workers={"0xlauncher": {"report_cid": "QmWorkerCid"}},
      vulnerability_score=7,
      node_ips=["10.0.0.10"],
      report_cid="QmAggregatedCid",
    )

    self.assertEqual(result["tx_hash"], "0xtxhash")
    self.assertEqual(host.bc.submit_attestation.call_count, 2)


class TestLlmRetryHardening(unittest.TestCase):

  def test_build_llm_analysis_payload_network_is_compact_and_structured(self):
    from extensions.business.cybersec.red_mesh.mixins.llm_agent import _RedMeshLlmAgentMixin

    class MockHost(_RedMeshLlmAgentMixin):
      def __init__(self):
        self.cfg_llm_agent = {"ENABLED": True, "TIMEOUT": 5, "AUTO_ANALYSIS_TYPE": "security_assessment"}
        self.cfg_llm_agent_api_host = "127.0.0.1"
        self.cfg_llm_agent_api_port = 8080

    host = MockHost()
    aggregated_report = {
      "nr_open_ports": 2,
      "ports_scanned": 100,
      "open_ports": [22, 443],
      "scan_metrics": {"total_duration": 45.0},
      "service_info": {
        "22": {
          "port": 22,
          "protocol": "ssh",
          "service": "ssh",
          "product": "OpenSSH",
          "version": "9.6",
          "banner": "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.15",
          "findings": [{
            "severity": "HIGH",
            "title": "SSH weak key exchange",
            "evidence": "Weak KEX offered: diffie-hellman-group14-sha1",
            "port": 22,
            "protocol": "ssh",
          }],
        },
      },
      "correlation_findings": [{
        "severity": "CRITICAL",
        "title": "Redis unauthenticated access",
        "evidence": "Response: +PONG",
        "port": 6379,
        "protocol": "redis",
      }],
      "port_banners": {"22": "x" * 5000},
      "worker_activity": [{"id": "node-a", "start_port": 1, "end_port": 5000, "open_ports": [22, 443]}],
    }
    job_config = {"target": "10.0.0.1", "scan_type": "network", "run_mode": "SINGLEPASS", "start_port": 1, "end_port": 8000}

    payload = host._build_llm_analysis_payload("job-1", aggregated_report, job_config, "security_assessment")

    self.assertIn("metadata", payload)
    self.assertIn("services", payload)
    self.assertIn("top_findings", payload)
    self.assertIn("findings_summary", payload)
    self.assertNotIn("port_banners", payload)
    self.assertEqual(payload["metadata"]["job_id"], "job-1")
    self.assertEqual(payload["findings_summary"]["total_findings"], 2)

  def test_run_aggregated_llm_analysis_uses_shaped_payload(self):
    from extensions.business.cybersec.red_mesh.mixins.llm_agent import _RedMeshLlmAgentMixin

    class MockHost(_RedMeshLlmAgentMixin):
      def __init__(self):
        self.cfg_llm_agent = {"ENABLED": True, "TIMEOUT": 5, "AUTO_ANALYSIS_TYPE": "security_assessment"}
        self.cfg_llm_agent_api_host = "127.0.0.1"
        self.cfg_llm_agent_api_port = 8080
        self.captured = None

      def P(self, *_args, **_kwargs):
        return None

      def Pd(self, *_args, **_kwargs):
        return None

      def _auto_analyze_report(self, job_id, report, target, scan_type="network", analysis_type=None):
        self.captured = report
        return {"content": "ok"}

    host = MockHost()
    aggregated_report = {
      "nr_open_ports": 1,
      "ports_scanned": 10,
      "open_ports": [22],
      "service_info": {"22": {"port": 22, "protocol": "ssh", "service": "ssh", "findings": []}},
      "port_banners": {"22": "y" * 2000},
    }
    job_config = {"target": "10.0.0.1", "scan_type": "network", "run_mode": "SINGLEPASS", "start_port": 1, "end_port": 100}

    result = host._run_aggregated_llm_analysis("job-1", aggregated_report, job_config)

    self.assertEqual(result, "ok")
    self.assertIsNotNone(host.captured)
    self.assertIn("metadata", host.captured)
    self.assertNotIn("port_banners", host.captured)

  def test_call_llm_agent_api_retries_transient_connection_error(self):
    from extensions.business.cybersec.red_mesh.mixins.llm_agent import _RedMeshLlmAgentMixin

    class MockHost(_RedMeshLlmAgentMixin):
      def __init__(self):
        self.cfg_llm_agent = {"ENABLED": True, "TIMEOUT": 5, "AUTO_ANALYSIS_TYPE": "security_assessment"}
        self.cfg_llm_agent_api_host = "127.0.0.1"
        self.cfg_llm_agent_api_port = 8080
        self.cfg_llm_api_retries = 2

      def P(self, *_args, **_kwargs):
        return None

      def Pd(self, *_args, **_kwargs):
        return None

    class Response:
      status_code = 200

      @staticmethod
      def json():
        return {"analysis": "ok"}

    host = MockHost()
    original_post = requests.post
    calls = {"count": 0}

    def flaky_post(*_args, **_kwargs):
      calls["count"] += 1
      if calls["count"] == 1:
        raise requests.exceptions.ConnectionError("temporary")
      return Response()

    requests.post = flaky_post
    try:
      result = host._call_llm_agent_api("/analyze_scan", payload={"scan_results": {}})
    finally:
      requests.post = original_post

    self.assertEqual(result["analysis"], "ok")
    self.assertEqual(calls["count"], 2)

  def test_call_llm_agent_api_does_not_retry_non_retryable_provider_rejection(self):
    from extensions.business.cybersec.red_mesh.mixins.llm_agent import _RedMeshLlmAgentMixin

    class MockHost(_RedMeshLlmAgentMixin):
      def __init__(self):
        self.cfg_llm_agent = {"ENABLED": True, "TIMEOUT": 5, "AUTO_ANALYSIS_TYPE": "security_assessment"}
        self.cfg_llm_agent_api_host = "127.0.0.1"
        self.cfg_llm_agent_api_port = 8080
        self.cfg_llm_api_retries = 2

      def P(self, *_args, **_kwargs):
        return None

      def Pd(self, *_args, **_kwargs):
        return None

    class Response:
      status_code = 500
      text = '{"detail":"DeepSeek API returned status 400"}'

      @staticmethod
      def json():
        return {"detail": "DeepSeek API returned status 400"}

    host = MockHost()
    original_post = requests.post
    calls = {"count": 0}

    def rejected_post(*_args, **_kwargs):
      calls["count"] += 1
      return Response()

    requests.post = rejected_post
    try:
      result = host._call_llm_agent_api("/analyze_scan", payload={"scan_results": {}})
    finally:
      requests.post = original_post

    self.assertEqual(calls["count"], 1)
    self.assertEqual(result["status"], "provider_request_error")
    self.assertEqual(result["provider_status"], 400)
    self.assertFalse(result["retryable"])


class TestAuditLogHardening(unittest.TestCase):

  def test_audit_log_uses_bounded_deque(self):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = PentesterApi01Plugin.__new__(PentesterApi01Plugin)
    plugin._audit_log = deque(maxlen=3)
    plugin.time = lambda: 123.0
    plugin.ee_addr = "0xnode"
    plugin.ee_id = "node-1"
    plugin.json_dumps = json.dumps
    plugin.P = lambda *_args, **_kwargs: None

    for idx in range(5):
      plugin._log_audit_event(f"event-{idx}", {"ordinal": idx})

    self.assertIsInstance(plugin._audit_log, deque)
    self.assertEqual(plugin._audit_log.maxlen, 3)
    self.assertEqual(len(plugin._audit_log), 3)
    self.assertEqual([entry["event"] for entry in plugin._audit_log], ["event-2", "event-3", "event-4"])
