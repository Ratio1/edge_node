import json
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.services.resilience import run_bounded_retry
from extensions.business.cybersec.red_mesh.services.triage import _merge_triage_into_archive_dict

from .conftest import mock_plugin_modules


class TestRegressionScenarios(unittest.TestCase):

  def _get_plugin_class(self):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def test_archive_retry_after_partial_failure(self):
    """Bounded retry recovers a transient archive verification failure."""
    host = MagicMock()
    host.P = MagicMock()
    host._log_audit_event = MagicMock()
    attempts = {"count": 0}

    def _operation():
      attempts["count"] += 1
      if attempts["count"] < 2:
        return None
      return {"job_id": "job-1"}

    result = run_bounded_retry(
      host,
      "archive_verify",
      3,
      _operation,
      is_success=lambda payload: isinstance(payload, dict) and payload.get("job_id") == "job-1",
    )

    self.assertEqual(result["job_id"], "job-1")
    self.assertEqual(attempts["count"], 2)
    host._log_audit_event.assert_any_call("retry_attempt", {"action": "archive_verify", "attempt": 1, "attempts": 3})

  def test_stale_write_conflict_detection_regression(self):
    """Revision mismatch still produces a stale-write audit event."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.chainstore_hget.return_value = {"job_id": "job-1", "job_revision": 5}
    plugin.chainstore_hset = MagicMock()
    plugin._log_audit_event = MagicMock()
    plugin.P = MagicMock()

    updated = Plugin._write_job_record(plugin, "job-1", {"job_id": "job-1", "job_revision": 3}, context="regression")

    self.assertEqual(updated["job_revision"], 6)
    plugin._log_audit_event.assert_called_once()

  def test_triage_merge_does_not_mutate_archive_source(self):
    """Triage view merging must not rewrite the immutable archive payload."""
    archive = {
      "job_id": "job-1",
      "passes": [{"findings": [{"finding_id": "f-1", "title": "Issue"}]}],
      "ui_aggregate": {"top_findings": [{"finding_id": "f-1", "title": "Issue"}]},
    }
    triage_map = {"f-1": {"status": "accepted_risk"}}

    merged = _merge_triage_into_archive_dict(archive, triage_map)

    self.assertEqual(merged["passes"][0]["findings"][0]["triage"]["status"], "accepted_risk")
    self.assertNotIn("triage", archive["passes"][0]["findings"][0])

  def test_multi_node_completion_order_variance_keeps_archive_query_stable(self):
    """Equivalent job listings should remain stable across completion-order variance."""
    Plugin = self._get_plugin_class()
    jobs = {
      "job-1": {
        "job_id": "job-1",
        "job_status": "RUNNING",
        "job_pass": 2,
        "run_mode": "SINGLEPASS",
        "launcher": "node-a",
        "launcher_alias": "node-a",
        "target": "example.com",
        "scan_type": "network",
        "target_url": "",
        "task_name": "Test",
        "start_port": 1,
        "end_port": 10,
        "date_created": 1.0,
        "job_config_cid": "QmConfig",
        "workers": {
          "node-a": {"finished": True},
          "node-b": {"finished": True},
        },
        "timeline": [],
        "pass_reports": [{"pass_nr": 1, "report_cid": "Qm1"}, {"pass_nr": 2, "report_cid": "Qm2"}],
      },
    }
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.chainstore_hgetall.return_value = jobs
    plugin._normalize_job_record = MagicMock(side_effect=lambda key, value: (key, value))
    plugin._get_all_network_jobs = lambda: Plugin._get_all_network_jobs(plugin)

    first = Plugin.list_network_jobs(plugin)
    second = Plugin.list_network_jobs(plugin)

    self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))
