import importlib.util
import json
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

from .conftest import mock_plugin_modules


mock_plugin_modules()

from extensions.business.cybersec.red_mesh.llm_input_builder import build_llm_input
from extensions.business.cybersec.red_mesh.pentester_api_01 import (
  PentesterApi01Plugin,
  _ManualAnalysisOutcome,
  _ManualAnalysisWork,
  _ManualAnalysisWorker,
  _bounded_provider_post,
)


SECRET_SENTINEL = "credential-sentinel-private-value"


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

  def test_busy_request_does_not_prepare_or_queue_work(self):
    plugin = MagicMock()
    plugin._manual_analysis_state = {
      "future": MagicMock(),
      "discard_result": False,
    }
    result = PentesterApi01Plugin.analyze_job(plugin, job_id="job-1")
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
      "deadline_monotonic": 200.0,
      "next_check_monotonic": 0.0,
      "discard_result": False,
    }
    plugin.create_postponed_request.return_value = "postponed"

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01.time.monotonic",
      return_value=100.0,
    ):
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
      "deadline_monotonic": 200.0,
      "next_check_monotonic": 100.1,
      "discard_result": False,
    }
    plugin.create_postponed_request.return_value = "postponed"

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01.time.monotonic",
      return_value=100.0,
    ):
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
      "deadline_monotonic": 99.0,
      "next_check_monotonic": 0.0,
      "discard_result": False,
    }

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01.time.monotonic",
      return_value=100.0,
    ):
      result = PentesterApi01Plugin.solve_postponed_analyze_job(plugin, "opaque-key")

    self.assertEqual(result["error"], "analysis_timeout")
    self.assertEqual(result["status_code"], 504)
    self.assertTrue(plugin._manual_analysis_state["discard_result"])
    self.assertIsNotNone(plugin._manual_analysis_state)

    future.done.return_value = True
    future.result.return_value = _ManualAnalysisOutcome(sections={}, failed=False)
    PentesterApi01Plugin._discard_drained_manual_analysis(plugin)
    self.assertIsNone(plugin._manual_analysis_state)

  def test_late_completed_outcome_is_not_finalized(self):
    plugin = MagicMock()
    future = MagicMock()
    future.done.return_value = True
    future.result.return_value = _ManualAnalysisOutcome(
      sections=_valid_remote_sections(),
      failed=False,
      deadline_exceeded=True,
    )
    plugin._manual_analysis_state = {
      "pending_id": "opaque-key",
      "future": future,
      "job_id": "job-1",
      "deadline_monotonic": 99.0,
      "next_check_monotonic": 0.0,
      "discard_result": False,
    }

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01.time.monotonic",
      return_value=100.0,
    ), patch.object(
      PentesterApi01Plugin,
      "_finalize_manual_analysis",
    ) as finalize:
      result = PentesterApi01Plugin.solve_postponed_analyze_job(
        plugin,
        "opaque-key",
      )

    self.assertEqual(result["error"], "analysis_timeout")
    self.assertEqual(result["status_code"], 504)
    finalize.assert_not_called()
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

    with patch.object(
      PentesterApi01Plugin,
      "_prepare_manual_analysis",
      return_value=(state, None),
    ):
      result = PentesterApi01Plugin.analyze_job(
        plugin,
        job_id="job-1",
      )

    self.assertEqual(result["error"], "analysis_executor_failed")
    self.assertIsNone(plugin._manual_analysis_state)
    self.assertNotIn("credential-sentinel", str(result))

  def test_manual_and_automatic_analysis_share_one_bounded_executor(self):
    plugin = PentesterApi01Plugin.__new__(PentesterApi01Plugin)
    executor = ThreadPoolExecutor(max_workers=1)
    plugin._manual_analysis_executor = executor
    plugin._manual_analysis_state = None
    plugin.create_postponed_request = MagicMock(return_value="postponed")
    automatic_started = threading.Event()
    release_automatic = threading.Event()

    def _automatic_work():
      automatic_started.set()
      release_automatic.wait(timeout=2)
      return {"executive_headline": "automatic"}

    automatic_future = executor.submit(_automatic_work)
    plugin._automatic_analysis_state = {"future": automatic_future}
    self.assertTrue(automatic_started.wait(timeout=1))
    state = {
      "pending_id": "opaque-key",
      "job_id": "job-1",
      "work": object(),
      "discard_result": False,
    }

    try:
      with patch.object(
        PentesterApi01Plugin,
        "_prepare_manual_analysis",
        return_value=(state, None),
      ), patch(
        "extensions.business.cybersec.red_mesh.pentester_api_01._run_manual_analysis_worker",
        return_value=_ManualAnalysisOutcome(sections={}, failed=False),
      ):
        result = PentesterApi01Plugin.analyze_job(plugin, job_id="job-1")
        manual_future = plugin._manual_analysis_state["future"]
        self.assertEqual(result, "postponed")
        self.assertFalse(manual_future.done())
        release_automatic.set()
        automatic_future.result(timeout=1)
        self.assertIsInstance(manual_future.result(timeout=1), _ManualAnalysisOutcome)
    finally:
      release_automatic.set()
      executor.shutdown(wait=True, cancel_futures=True)

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
      "deadline_monotonic": 200.0,
      "next_check_monotonic": 0.0,
      "discard_result": False,
    }

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01.time.monotonic",
      return_value=100.0,
    ), patch.object(
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

  def test_manual_finalization_rejects_detected_prewrite_race(self):
    current_job = {
      "job_id": "job-1",
      "job_revision": 7,
      "pass_reports": [{"pass_nr": 1, "report_cid": "QmExpected"}],
    }
    plugin = MagicMock()
    plugin._get_job_from_cstore.return_value = current_job
    plugin.r1fs.get_json.return_value = {"pass_nr": 1}
    plugin.r1fs.add_json.return_value = "QmUnreferenced"
    state = {
      "job_id": "job-1",
      "job_revision": 7,
      "pass_nr": 1,
      "report_cid": "QmExpected",
      "target": "example.test",
      "num_workers": 1,
    }

    with patch.object(
      PentesterApi01Plugin,
      "_write_job_record",
      return_value=None,
    ) as write:
      result = PentesterApi01Plugin._finalize_manual_analysis(
        plugin,
        state,
        _ManualAnalysisOutcome(sections=_valid_remote_sections(), failed=False),
      )

    self.assertEqual(result["error"], "analysis_state_changed")
    self.assertEqual(result["status_code"], 409)
    self.assertNotIn("QmUnreferenced", str(result))
    self.assertTrue(write.call_args.kwargs["reject_stale"])

  def test_guarded_job_write_refuses_detected_stale_revision(self):
    plugin = MagicMock()
    repository = MagicMock()
    repository.get_job.return_value = {
      "job_id": "job-1",
      "job_revision": 8,
    }
    with patch.object(
      PentesterApi01Plugin,
      "_get_job_state_repository",
      return_value=repository,
    ):
      result = PentesterApi01Plugin._write_job_record(
        plugin,
        "job-1",
        {"job_id": "job-1", "job_revision": 7},
        expected_revision=7,
        context="manual_llm_update",
        reject_stale=True,
      )

    self.assertIsNone(result)
    repository.put_job.assert_not_called()

  def test_guarded_job_write_does_not_resurrect_deleted_job(self):
    plugin = MagicMock()
    repository = MagicMock()
    repository.get_job.return_value = None
    with patch.object(
      PentesterApi01Plugin,
      "_get_job_state_repository",
      return_value=repository,
    ):
      result = PentesterApi01Plugin._write_job_record(
        plugin,
        "job-1",
        {"job_id": "job-1", "job_revision": 7},
        expected_revision=7,
        context="manual_llm_update",
        reject_stale=True,
      )

    self.assertIsNone(result)
    repository.put_job.assert_not_called()
    plugin._log_audit_event.assert_called_once()

  def test_admission_exception_is_sanitized(self):
    plugin = PentesterApi01Plugin.__new__(PentesterApi01Plugin)
    plugin._manual_analysis_state = None
    with patch.object(
      PentesterApi01Plugin,
      "_prepare_manual_analysis",
      side_effect=RuntimeError(f"provider exploded with {SECRET_SENTINEL}"),
    ):
      result = PentesterApi01Plugin.analyze_job(
        plugin,
        job_id="job-1",
      )

    self.assertEqual(result["error"], "analysis_executor_failed")
    self.assertNotIn(SECRET_SENTINEL, str(result))

  def test_shutdown_cancels_pending_work_before_base_close(self):
    plugin = PentesterApi01Plugin.__new__(PentesterApi01Plugin)
    future = MagicMock()
    automatic_future = MagicMock()
    executor = MagicMock()
    plugin._manual_analysis_state = {"future": future}
    plugin._automatic_analysis_state = {"future": automatic_future}
    plugin._manual_analysis_executor = executor

    PentesterApi01Plugin.on_close(plugin)

    future.cancel.assert_called_once_with()
    automatic_future.cancel.assert_called_once_with()
    executor.shutdown.assert_called_once_with(wait=False, cancel_futures=True)
    self.assertIsNone(plugin._manual_analysis_state)
    self.assertIsNone(plugin._automatic_analysis_state)
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
    response_payload = {
      "result": {
        "choices": [{
          "message": {"content": json.dumps(_valid_remote_sections())},
        }],
      },
    }

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01._bounded_provider_post",
      return_value=json.dumps(response_payload).encode("utf-8"),
    ) as post:
      outcome = _ManualAnalysisWorker(work).run()

    self.assertFalse(outcome.failed)
    self.assertIsNotNone(outcome.sections)
    serialized_payload = json.dumps(post.call_args.args[1])
    self.assertNotIn("credential-sentinel-private-body", serialized_payload)
    self.assertNotIn(SECRET_SENTINEL, serialized_payload)
    self.assertFalse(any("plugin" in name for name in work.__dataclass_fields__))
    provider_timeout = post.call_args.args[2]
    self.assertGreater(provider_timeout, 0)
    self.assertLessEqual(provider_timeout, 30)
    self.assertEqual(post.call_args.args[3], 2 * 1024 * 1024)

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
    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01._bounded_provider_post",
      side_effect=RuntimeError(
        "credential-sentinel provider body https://private.provider.internal"
      ),
    ):
      outcome = _ManualAnalysisWorker(work).run()

    public = str(outcome)
    self.assertTrue(outcome.failed)
    self.assertNotIn("credential-sentinel", public)
    self.assertNotIn("private.provider.internal", public)
    self.assertNotIn("provider body", public)

  def test_invalid_structured_result_returns_sanitized_failed_sections(self):
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
    response_payload = {
      "result": {
        "choices": [{
          "message": {"content": "not-json credential-sentinel provider body"},
        }],
      },
    }

    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01._bounded_provider_post",
      return_value=json.dumps(response_payload).encode("utf-8"),
    ):
      outcome = _ManualAnalysisWorker(work).run()

    self.assertTrue(outcome.failed)
    self.assertTrue(outcome.sections["error"])
    self.assertNotIn("credential-sentinel", str(outcome))
    self.assertNotIn("private.provider.internal", str(outcome))

  def test_oversized_provider_response_failure_is_sanitized(self):
    prepared = build_llm_input(findings=[], aggregated_report={}, engagement={})
    work = _ManualAnalysisWork(
      llm_input=prepared,
      llm_config={
        "MODEL": "deepseek-chat",
        "PROVIDER": "remote",
        "PROMPT_PROFILE": "remote_rich_v1",
        "REMOTE_PROMPT_PROFILE": "remote_rich_v1",
        "STRUCTURED_MAX_FINDINGS": 6,
        "STRUCTURED_MAX_TOKENS": 1024,
      },
      api_host="private.provider.internal",
      api_port=8080,
      deadline_monotonic=time.monotonic() + 5,
    )
    with patch(
      "extensions.business.cybersec.red_mesh.pentester_api_01._bounded_provider_post",
      side_effect=RuntimeError(
        "private.provider.internal returned an oversized credential-sentinel body"
      ),
    ):
      outcome = _ManualAnalysisWorker(work).run()

    self.assertTrue(outcome.failed)
    self.assertNotIn("private.provider.internal", str(outcome))
    self.assertNotIn("credential-sentinel", str(outcome))

  @unittest.skipUnless(
    importlib.util.find_spec("aiohttp") is not None,
    "aiohttp is unavailable in the host test environment",
  )
  def test_provider_transport_enforces_total_wall_timeout_while_body_trickles(self):
    class _TrickleHandler(BaseHTTPRequestHandler):
      def log_message(self, *_args):
        return

      def do_POST(self):
        body_length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(body_length)
        self.send_response(200)
        self.send_header("Content-Length", "100")
        self.end_headers()
        try:
          for _ in range(100):
            self.wfile.write(b"x")
            self.wfile.flush()
            time.sleep(0.05)
        except (BrokenPipeError, ConnectionResetError):
          pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _TrickleHandler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    self.addCleanup(server.server_close)
    self.addCleanup(server.shutdown)

    started = time.monotonic()
    with self.assertRaises(TimeoutError):
      _bounded_provider_post(
        f"http://127.0.0.1:{server.server_port}/chat",
        {"messages": []},
        0.2,
        1024,
      )
    elapsed = time.monotonic() - started

    # Keep a wide scheduler margin while still proving the 0.2-second client
    # deadline ends well before the server's five-second trickle completes.
    self.assertLess(elapsed, 2.0)

  @unittest.skipUnless(
    importlib.util.find_spec("aiohttp") is not None,
    "aiohttp is unavailable in the host test environment",
  )
  def test_provider_transport_rejects_declared_and_streamed_oversize_bodies(self):
    class _OversizeHandler(BaseHTTPRequestHandler):
      def log_message(self, *_args):
        return

      def do_POST(self):
        body_length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(body_length)
        self.send_response(200)
        if self.path == "/declared":
          self.send_header("Content-Length", "2048")
        else:
          self.send_header("Connection", "close")
          self.close_connection = True
        self.end_headers()
        if self.path != "/declared":
          self.wfile.write(b"x" * 2048)
          self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _OversizeHandler)
    server.daemon_threads = True
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    self.addCleanup(server.server_close)
    self.addCleanup(server.shutdown)

    for path in ("declared", "streamed"):
      with self.subTest(path=path), self.assertRaisesRegex(
        RuntimeError,
        "response is too large",
      ):
        _bounded_provider_post(
          f"http://127.0.0.1:{server.server_port}/{path}",
          {"messages": []},
          2.0,
          1024,
        )

  def test_prepared_input_rejects_wrong_type(self):
    from extensions.business.cybersec.red_mesh.services.llm_structured import generate_exec_summary

    with self.assertRaises(TypeError):
      generate_exec_summary(
        llm_call=lambda *_args: "",
        prepared_input={"not": "trusted"},
      )


if __name__ == "__main__":
  unittest.main()
