import json
import os
import time
import unittest
from unittest.mock import MagicMock, patch

from .conftest import mock_plugin_modules


mock_plugin_modules()

from extensions.business.cybersec.red_mesh.llm_input_builder import build_llm_input
from extensions.business.cybersec.red_mesh.pentester_api_01 import (
  PentesterApi01Plugin,
  _ManualAnalysisOutcome,
  _ManualAnalysisWork,
  _ManualAnalysisWorker,
)


TOKEN = "0123456789abcdef0123456789abcdef"


def _valid_remote_sections():
  return {
    "executive_headline": "Material exposure requires executive attention.",
    "background_draft": "Authorized external assessment.",
    "overall_posture": "The engagement identified high-severity issues requiring remediation.",
    "recommendation_summary": ["Prioritize the verified high-severity findings."],
    "strategic_roadmap": {
      "near_term": ["Address verified exposure."],
      "mid_term": ["Add regression coverage."],
      "long_term": ["Adopt continuous assurance."],
    },
    "attack_chain_narratives": ["Initial exposure could enable privilege escalation."],
    "coverage_gaps": ["Social engineering was outside scope."],
    "conclusion": "Retest after remediation.",
  }


class TestPostponedAnalyze(unittest.TestCase):

  def test_authentication_fails_closed_and_compares_valid_token(self):
    with patch.dict(os.environ, {}, clear=True):
      missing = PentesterApi01Plugin._validate_manual_analysis_token(TOKEN)
    self.assertEqual(missing["error"], "analysis_auth_unavailable")
    self.assertEqual(missing["status_code"], 503)

    with patch.dict(os.environ, {"REDMESH_ANALYZE_TOKEN": "too-short"}, clear=True):
      weak = PentesterApi01Plugin._validate_manual_analysis_token(TOKEN)
    self.assertEqual(weak["error"], "analysis_auth_unavailable")

    with patch.dict(os.environ, {"REDMESH_ANALYZE_TOKEN": TOKEN}, clear=True):
      denied = PentesterApi01Plugin._validate_manual_analysis_token("wrong")
      allowed = PentesterApi01Plugin._validate_manual_analysis_token(TOKEN)
    self.assertEqual(denied["error"], "analysis_auth_denied")
    self.assertEqual(denied["status_code"], 401)
    self.assertIsNone(allowed)
    self.assertNotIn(TOKEN, str(missing) + str(weak) + str(denied))

  def test_busy_request_does_not_prepare_or_queue_work(self):
    plugin = MagicMock()
    plugin._manual_analysis_state = {
      "future": MagicMock(),
      "discard_result": False,
    }
    with patch.dict(os.environ, {"REDMESH_ANALYZE_TOKEN": TOKEN}, clear=True):
      result = PentesterApi01Plugin.analyze_job(
        plugin,
        token=TOKEN,
        job_id="job-1",
      )
    self.assertEqual(result["error"], "analysis_busy")
    self.assertEqual(result["status_code"], 409)
    self.assertTrue(result["retryable"])
    plugin._get_job_from_cstore.assert_not_called()

  def test_pending_solver_uses_only_opaque_key(self):
    plugin = MagicMock()
    future = MagicMock()
    future.done.return_value = False
    plugin._manual_analysis_state = {
      "pending_id": "opaque-key",
      "future": future,
      "job_id": "job-1",
      "deadline_at": 200.0,
      "next_check_at": 0.0,
      "discard_result": False,
    }
    plugin.time.return_value = 100.0
    plugin.create_postponed_request.return_value = "postponed"

    result = PentesterApi01Plugin.solve_postponed_analyze_job(plugin, "opaque-key")

    self.assertEqual(result, "postponed")
    kwargs = plugin.create_postponed_request.call_args.kwargs
    self.assertEqual(kwargs["method_kwargs"], {"pending_id": "opaque-key"})
    self.assertNotIn("job-1", str(kwargs["method_kwargs"]))

  def test_solver_does_not_poll_future_before_next_check(self):
    plugin = MagicMock()
    future = MagicMock()
    plugin._manual_analysis_state = {
      "pending_id": "opaque-key",
      "future": future,
      "job_id": "job-1",
      "deadline_at": 200.0,
      "next_check_at": 100.1,
      "discard_result": False,
    }
    plugin.time.return_value = 100.0
    plugin.create_postponed_request.return_value = "postponed"

    result = PentesterApi01Plugin.solve_postponed_analyze_job(plugin, "opaque-key")

    self.assertEqual(result, "postponed")
    future.done.assert_not_called()

  def test_deadline_returns_timeout_and_holds_slot_until_worker_drains(self):
    plugin = MagicMock()
    future = MagicMock()
    future.done.return_value = False
    plugin._manual_analysis_state = {
      "pending_id": "opaque-key",
      "future": future,
      "job_id": "job-1",
      "deadline_at": 99.0,
      "next_check_at": 0.0,
      "discard_result": False,
    }
    plugin.time.return_value = 100.0

    result = PentesterApi01Plugin.solve_postponed_analyze_job(plugin, "opaque-key")

    self.assertEqual(result["error"], "analysis_timeout")
    self.assertEqual(result["status_code"], 504)
    self.assertTrue(plugin._manual_analysis_state["discard_result"])
    self.assertIsNotNone(plugin._manual_analysis_state)

    future.done.return_value = True
    future.result.return_value = _ManualAnalysisOutcome(sections={}, failed=False)
    PentesterApi01Plugin._discard_drained_manual_analysis(plugin)
    self.assertIsNone(plugin._manual_analysis_state)

  def test_request_shape_bounds_are_explicit(self):
    invalid_type = PentesterApi01Plugin._validate_manual_analysis_request(
      "job-1",
      "x" * 65,
      [],
    )
    invalid_focus_count = PentesterApi01Plugin._validate_manual_analysis_request(
      "job-1",
      "",
      ["web"] * 9,
    )
    invalid_focus_value = PentesterApi01Plugin._validate_manual_analysis_request(
      "job-1",
      "",
      ["x" * 65],
    )

    self.assertEqual(invalid_type["error"], "invalid_analysis_type")
    self.assertEqual(invalid_focus_count["error"], "invalid_focus_areas")
    self.assertEqual(invalid_focus_value["error"], "invalid_focus_areas")

  def test_executor_start_failure_releases_unused_slot(self):
    plugin = PentesterApi01Plugin.__new__(PentesterApi01Plugin)
    plugin._manual_analysis_state = None
    plugin._manual_analysis_executor = MagicMock()
    plugin._manual_analysis_executor.submit.side_effect = RuntimeError(
      "credential-sentinel start failure"
    )
    state = {
      "pending_id": "opaque-key",
      "job_id": "job-1",
      "work": object(),
      "discard_result": False,
    }

    with patch.dict(os.environ, {"REDMESH_ANALYZE_TOKEN": TOKEN}, clear=True), patch.object(
      PentesterApi01Plugin,
      "_prepare_manual_analysis",
      return_value=(state, None),
    ):
      result = PentesterApi01Plugin.analyze_job(
        plugin,
        token=TOKEN,
        job_id="job-1",
      )

    self.assertEqual(result["error"], "analysis_executor_failed")
    self.assertIsNone(plugin._manual_analysis_state)
    self.assertNotIn("credential-sentinel", str(result))

  def test_completion_releases_slot_for_retry(self):
    plugin = MagicMock()
    future = MagicMock()
    future.done.return_value = True
    future.result.return_value = _ManualAnalysisOutcome(
      sections=_valid_remote_sections(),
      failed=False,
    )
    plugin._manual_analysis_state = {
      "pending_id": "opaque-key",
      "future": future,
      "job_id": "job-1",
      "deadline_at": 200.0,
      "next_check_at": 0.0,
      "discard_result": False,
    }
    plugin.time.return_value = 100.0

    with patch.object(
      PentesterApi01Plugin,
      "_finalize_manual_analysis",
      return_value={"job_id": "job-1"},
    ):
      result = PentesterApi01Plugin.solve_postponed_analyze_job(
        plugin,
        "opaque-key",
      )

    self.assertEqual(result, {"job_id": "job-1"})
    self.assertIsNone(plugin._manual_analysis_state)

  def test_stale_completion_does_not_write_artifacts(self):
    plugin = MagicMock()
    plugin._get_job_from_cstore.return_value = {
      "job_id": "job-1",
      "job_revision": 8,
      "pass_reports": [{"pass_nr": 1, "report_cid": "QmCurrent"}],
    }
    state = {
      "job_id": "job-1",
      "job_revision": 7,
      "pass_nr": 1,
      "report_cid": "QmExpected",
      "target": "example.test",
      "num_workers": 1,
    }

    result = PentesterApi01Plugin._finalize_manual_analysis(
      plugin,
      state,
      _ManualAnalysisOutcome(sections=_valid_remote_sections(), failed=False),
    )

    self.assertEqual(result["error"], "analysis_state_changed")
    self.assertEqual(result["status_code"], 409)
    plugin.r1fs.get_json.assert_not_called()
    plugin.r1fs.add_json.assert_not_called()

  def test_persistence_failure_is_typed_and_does_not_expose_artifact(self):
    current_job = {
      "job_id": "job-1",
      "job_revision": 7,
      "pass_reports": [{"pass_nr": 1, "report_cid": "QmExpected"}],
    }
    plugin = MagicMock()
    plugin._get_job_from_cstore.return_value = current_job
    plugin.r1fs.get_json.return_value = {"pass_nr": 1}
    plugin.r1fs.add_json.return_value = None
    state = {
      "job_id": "job-1",
      "job_revision": 7,
      "pass_nr": 1,
      "report_cid": "QmExpected",
      "target": "example.test",
      "num_workers": 1,
    }

    result = PentesterApi01Plugin._finalize_manual_analysis(
      plugin,
      state,
      _ManualAnalysisOutcome(sections=_valid_remote_sections(), failed=False),
    )

    self.assertEqual(result["error"], "analysis_persistence_failed")
    self.assertEqual(result["status_code"], 503)
    self.assertNotIn("QmExpected", str(result))
    self.assertNotIn("QmExpected", str(plugin.P.call_args_list))

  def test_shutdown_cancels_pending_work_before_base_close(self):
    plugin = PentesterApi01Plugin.__new__(PentesterApi01Plugin)
    future = MagicMock()
    executor = MagicMock()
    plugin._manual_analysis_state = {"future": future}
    plugin._manual_analysis_executor = executor

    PentesterApi01Plugin.on_close(plugin)

    future.cancel.assert_called_once_with()
    executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)
    self.assertIsNone(plugin._manual_analysis_state)
    self.assertTrue(plugin._base_closed)

  def test_worker_uses_prepared_input_without_plugin_or_secret_state(self):
    prepared = build_llm_input(
      findings=[{
        "severity": "HIGH",
        "title": "Authorization bypass",
        "description": "Structured description",
        "raw_response": "credential-sentinel-private-body",
      }],
      aggregated_report={"open_ports": [443], "service_info": {"443": {}}},
      engagement={"client_name": "Example"},
    )
    work = _ManualAnalysisWork(
      llm_input=prepared,
      llm_config={
        "MODEL": "deepseek-chat",
        "PROVIDER": "remote",
        "PROMPT_PROFILE": "remote_rich_v1",
        "LOCAL_PROMPT_PROFILE": "local_cybersecqwen_quota_v1",
        "REMOTE_PROMPT_PROFILE": "remote_rich_v1",
        "STRUCTURED_MAX_FINDINGS": 6,
        "STRUCTURED_MAX_TOKENS": 1024,
        "STRUCTURED_TEMPERATURE": 0,
      },
      api_host="127.0.0.1",
      api_port=8080,
      deadline_monotonic=time.monotonic() + 5,
    )
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
      "result": {
        "choices": [{
          "message": {"content": json.dumps(_valid_remote_sections())},
        }],
      },
    }

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01.requests.post",
      return_value=response,
    ) as post:
      outcome = _ManualAnalysisWorker(work).run()

    self.assertFalse(outcome.failed)
    self.assertIsNotNone(outcome.sections)
    serialized_payload = json.dumps(post.call_args.kwargs["json"])
    self.assertNotIn("credential-sentinel-private-body", serialized_payload)
    self.assertNotIn(TOKEN, serialized_payload)
    self.assertFalse(any("plugin" in name for name in work.__dataclass_fields__))
    provider_timeout = post.call_args.kwargs["timeout"]
    self.assertGreater(provider_timeout, 0)
    self.assertLessEqual(provider_timeout, 30)

  def test_provider_body_and_exception_details_are_not_returned(self):
    prepared = build_llm_input(findings=[], aggregated_report={}, engagement={})
    work = _ManualAnalysisWork(
      llm_input=prepared,
      llm_config={
        "MODEL": "deepseek-chat",
        "PROVIDER": "remote",
        "PROMPT_PROFILE": "remote_rich_v1",
        "LOCAL_PROMPT_PROFILE": "local_cybersecqwen_quota_v1",
        "REMOTE_PROMPT_PROFILE": "remote_rich_v1",
        "STRUCTURED_MAX_FINDINGS": 6,
        "STRUCTURED_MAX_TOKENS": 1024,
        "STRUCTURED_TEMPERATURE": 0,
      },
      api_host="private.provider.internal",
      api_port=8080,
      deadline_monotonic=time.monotonic() + 5,
    )
    response = MagicMock()
    response.status_code = 503
    response.text = "credential-sentinel provider body https://private.provider.internal"
    response.json.return_value = {"error": response.text}

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01.requests.post",
      return_value=response,
    ):
      outcome = _ManualAnalysisWorker(work).run()

    public = str(outcome)
    self.assertTrue(outcome.failed)
    self.assertNotIn("credential-sentinel", public)
    self.assertNotIn("private.provider.internal", public)
    self.assertNotIn("provider body", public)

  def test_prepared_input_rejects_wrong_type(self):
    from extensions.business.cybersec.red_mesh.services.llm_structured import generate_exec_summary

    with self.assertRaises(TypeError):
      generate_exec_summary(
        llm_call=lambda *_args: "",
        prepared_input={"not": "trusted"},
      )


if __name__ == "__main__":
  unittest.main()
