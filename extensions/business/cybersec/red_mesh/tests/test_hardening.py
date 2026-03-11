import json
import unittest
from collections import deque
from unittest.mock import MagicMock

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
        self.cfg_attestation_enabled = True
        self.cfg_attestation_private_key = "0xprivate"
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
