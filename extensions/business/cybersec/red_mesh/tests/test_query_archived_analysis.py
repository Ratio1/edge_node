"""Phase 5 of PR 388 remediation — archived analysis response CID.

Audit #8: the archived branch of get_job_analysis returned
target_pass.get("report_cid"). Archived pass objects written by
finalization.py only carry aggregated_report_cid. The response
therefore surfaced None even when a real aggregated report existed.

Phase 5 fix returns aggregated_report_cid (keeping the response key
name "report_cid" for API continuity — current consumers don't
dereference it, see plan for rationale) and emits a grep-able
[ARCHIVE-INTEGRITY] log line when the field is missing.
"""

import unittest
from unittest.mock import patch


class _Owner:
  """Minimal owner covering the query.get_job_analysis surface used
  in the archived code path.
  """

  def __init__(self, job_specs):
    self._job_specs = job_specs
    self.messages = []

  def P(self, msg, **kwargs):
    self.messages.append(msg)

  def _get_job_from_cstore(self, job_id):
    return self._job_specs


class TestArchivedAnalysisReportCid(unittest.TestCase):

  def _call(self, job_specs, archive_payload, **kwargs):
    from extensions.business.cybersec.red_mesh.services import query
    owner = _Owner(job_specs)
    with patch.object(query, "get_job_archive_with_triage",
                      return_value=archive_payload):
      result = query.get_job_analysis(owner, job_id="j1", **kwargs)
    return result, owner

  def test_archived_pass_returns_aggregated_cid(self):
    job_specs = {"target": "10.0.0.1", "job_status": "FINALIZED",
                 "job_cid": "QmJobCid"}
    archive_payload = {
      "archive": {
        "passes": [
          {
            "pass_nr": 1,
            "aggregated_report_cid": "QmAggregated123",
            "llm_analysis": "analysis text",
            "quick_summary": "one-liner",
            "date_completed": 12345,
            "worker_reports": {"node-a": {}, "node-b": {}},
          },
        ],
        "job_config": {"target": "10.0.0.1"},
      },
    }
    result, owner = self._call(job_specs, archive_payload)
    self.assertEqual(result["report_cid"], "QmAggregated123")
    self.assertEqual(result["pass_nr"], 1)
    self.assertEqual(result["num_workers"], 2)
    # Clean archive → no integrity warning.
    integrity_msgs = [m for m in owner.messages if "[ARCHIVE-INTEGRITY]" in m]
    self.assertEqual(integrity_msgs, [])

  def test_missing_aggregated_cid_is_logged(self):
    """Archive pass with aggregated_report_cid=None — response
    returns None and a [ARCHIVE-INTEGRITY] warning is emitted.
    """
    job_specs = {"target": "10.0.0.1", "job_status": "FINALIZED",
                 "job_cid": "QmJobCid"}
    archive_payload = {
      "archive": {
        "passes": [
          {
            "pass_nr": 2,
            "aggregated_report_cid": None,
            "llm_analysis": "text",
            "worker_reports": {},
          },
        ],
        "job_config": {"target": "10.0.0.1"},
      },
    }
    result, owner = self._call(job_specs, archive_payload)
    self.assertIsNone(result["report_cid"])
    integrity_msgs = [m for m in owner.messages if "[ARCHIVE-INTEGRITY]" in m]
    self.assertEqual(len(integrity_msgs), 1)
    self.assertIn("job=j1", integrity_msgs[0])
    self.assertIn("pass=2", integrity_msgs[0])

  def test_missing_llm_analysis_short_circuits(self):
    """If the pass has no llm_analysis, the function returns the
    "no LLM analysis available" error BEFORE the CID fallback logic
    runs — so no ARCHIVE-INTEGRITY warning is emitted.
    """
    job_specs = {"target": "10.0.0.1", "job_status": "FINALIZED",
                 "job_cid": "QmJobCid"}
    archive_payload = {
      "archive": {
        "passes": [{"pass_nr": 1, "aggregated_report_cid": None,
                    "llm_analysis": None}],
        "job_config": {},
      },
    }
    result, owner = self._call(job_specs, archive_payload)
    self.assertIn("error", result)
    self.assertIn("No LLM analysis", result["error"])
    # No integrity warning — we never reached the CID branch.
    integrity_msgs = [m for m in owner.messages if "[ARCHIVE-INTEGRITY]" in m]
    self.assertEqual(integrity_msgs, [])


if __name__ == '__main__':
  unittest.main()
