"""Phase 4 PR-4.1 plumbing — `_run_structured_report_sections` adapter
test (post-merge followup #4 / option B).

Verifies the LLM Agent mixin's adapter that bridges:
  - the existing `/chat` HTTP endpoint (returns OpenAI-shape JSON), to
  - the chat-callable signature `generate_exec_summary` expects:
      (messages, max_tokens, temperature) -> str

The adapter must:
  - return None when the LLM agent is disabled
  - return None when the chat endpoint returns an error
  - extract `choices[0].message.content` correctly on success
  - persist the dict form of LlmReportSections on success
  - tolerate errors from generate_exec_summary itself (return None)

We mock `_call_llm_agent_api` and `get_llm_agent_config` so the test
exercises only the adapter, not the HTTP layer.
"""
from __future__ import annotations

import json
import os
import unittest
from typing import Any

from extensions.business.cybersec.red_mesh.mixins.llm_agent import _RedMeshLlmAgentMixin as LlmAgentMixin


def _valid_llm_response_content() -> str:
  """A complete LlmReportSections JSON the validator accepts."""
  return json.dumps({
    "background_draft": "Engagement targeted the perimeter of the example.com infrastructure to assess external exposure.",
    "overall_posture": "The external surface shows a high-severity finding requiring prompt remediation; otherwise hardening is acceptable.",
    "recommendation_summary": [
      "Patch the Apache HTTP server to 2.4.51 to remediate CVE-2021-41773.",
      "Disable mod_cgi until the Apache upgrade has been verified end-to-end.",
      "Rotate any credentials disclosed via configuration files exposed by the path-traversal flaw.",
    ],
    "strategic_roadmap": {
      "near_term": ["Upgrade Apache to 2.4.51 within 48 hours."],
      "mid_term": ["Establish a monthly external-perimeter scan cadence."],
      "long_term": ["Adopt continuous attack-surface management tooling."],
    },
    "attack_chain_narratives": [
      "Apache path traversal exposes /etc/passwd and httpd.conf, providing the credentials to access internal services from the public-facing host.",
    ],
    "coverage_gaps": [
      "Internal-segment scanning was out of scope; lateral-movement risk from the breached perimeter remains unassessed.",
    ],
    "conclusion": "Posture is acceptable once the Apache CVE is closed; perimeter hardening is otherwise in line with industry baselines.",
  })


class _FakeOwner(LlmAgentMixin):
  """Minimal stand-in for the plugin instance LlmAgentMixin runs on.

  Inherits from the mixin so helper methods (e.g. diagnostic logging)
  are resolvable on the owner just as they would be on a real plugin.
  """

  def __init__(
    self, *,
    enabled: bool = True,
    chat_response: dict | None = None,
    chat_raises: Exception | None = None,
  ):
    self._enabled = enabled
    self._chat_response = chat_response
    self._chat_raises = chat_raises
    self._calls: list[dict] = []
    self._logs: list[str] = []

  # Mixin uses self.P for logging.
  def P(self, msg, *_args, **_kwargs):
    self._logs.append(str(msg))

  # Mixin uses self.Pd for debug logging.
  def Pd(self, msg, *_args, **_kwargs):
    pass

  # `get_llm_agent_config` reads ENABLED off the owner; we shim by
  # monkeypatching the import path inside the mixin in setUp.

  def _call_llm_agent_api(self, *, endpoint: str, method: str, payload: dict, timeout=None):
    self._calls.append({"endpoint": endpoint, "method": method, "payload": payload})
    if self._chat_raises is not None:
      raise self._chat_raises
    return self._chat_response or {}


# Bind the mixin method to the fake owner.
def _run(owner: _FakeOwner, **kwargs):
  return LlmAgentMixin._run_structured_report_sections.__get__(owner)(**kwargs)


class StructuredReportAdapterTests(unittest.TestCase):
  def setUp(self):
    # Patch the get_llm_agent_config import the mixin uses so we can
    # toggle ENABLED per-test without touching the global config.
    from extensions.business.cybersec.red_mesh.mixins import llm_agent as mod
    self._orig_cfg = mod.get_llm_agent_config
    self._cfg_value = {"ENABLED": True, "MODEL": "deepseek-chat"}
    mod.get_llm_agent_config = lambda _self: self._cfg_value
    self._orig_live_llm = os.environ.get("LIVE_LLM")

  def tearDown(self):
    from extensions.business.cybersec.red_mesh.mixins import llm_agent as mod
    mod.get_llm_agent_config = self._orig_cfg
    if self._orig_live_llm is None:
      os.environ.pop("LIVE_LLM", None)
    else:
      os.environ["LIVE_LLM"] = self._orig_live_llm

  # -----------------------------------------------------------------
  def test_returns_none_when_llm_disabled(self):
    self._cfg_value = {"ENABLED": False}
    owner = _FakeOwner(chat_response={"choices": [{"message": {"content": "x"}}]})
    out = _run(owner, job_id="j1", findings=[], aggregated_report={})
    self.assertIsNone(out)
    self.assertEqual(owner._calls, [])  # never called the chat endpoint

  def test_extracts_assistant_content_on_success(self):
    owner = _FakeOwner(chat_response={
      "choices": [{"message": {"content": _valid_llm_response_content()}}],
    })
    out = _run(
      owner, job_id="j1",
      findings=[{
        "severity": "CRITICAL",
        "title": "Apache RCE",
        "cve": ["CVE-2021-41773"],
        "port": 80,
        "protocol": "http",
        "probe": "service_http",
        "category": "service",
      }],
      aggregated_report={"total_findings": 1, "total_open_ports": 1, "total_services": 1},
    )
    self.assertIsNotNone(out)
    self.assertIsInstance(out, dict)
    self.assertIn("background_draft", out)
    self.assertIn("recommendation_summary", out)
    # Endpoint hit at least once. generate_exec_summary may retry
    # corrective-style if the validator flags missing content; we
    # don't assert exact attempt count because that's the service's
    # business, not the adapter's.
    self.assertGreaterEqual(len(owner._calls), 1)
    self.assertEqual(owner._calls[0]["endpoint"], "/chat")
    self.assertEqual(owner._calls[0]["method"], "POST")
    # The /chat payload carries the OpenAI message shape.
    self.assertIn("messages", owner._calls[0]["payload"])
    self.assertGreater(len(owner._calls[0]["payload"]["messages"]), 0)

  def test_persists_fallback_skeleton_on_validation_failure(self):
    # LLM returns parseable but content-empty JSON twice — corrective
    # retry won't fix it, so generate_exec_summary returns the
    # fallback skeleton with error=True. We still want to persist the
    # dict so Appendix C can show what happened.
    bad_json = json.dumps({"background_draft": ""})
    owner = _FakeOwner(chat_response={
      "choices": [{"message": {"content": bad_json}}],
    })
    out = _run(owner, job_id="j1", findings=[], aggregated_report={})
    self.assertIsNotNone(out)
    self.assertIsInstance(out, dict)
    # The skeleton has every field, just with empty values.
    self.assertIn("background_draft", out)

  def test_persists_fallback_when_chat_returns_error(self):
    # Chat endpoint returns an error envelope. The adapter's
    # closure returns "" → generate_exec_summary treats that as a
    # failure → returns the marker-populated fallback skeleton.
    # The dict is still persisted so Appendix C can show what
    # happened.
    owner = _FakeOwner(chat_response={"error": "API key missing", "status": "error"})
    out = _run(owner, job_id="j1", findings=[], aggregated_report={})
    self.assertIsNotNone(out)
    self.assertIsInstance(out, dict)
    # background_draft is populated with the validation-failed marker.
    self.assertIn("AI generation failed validation", out["background_draft"])

  def test_persists_fallback_when_chat_endpoint_raises(self):
    # _call_llm_agent_api raises. generate_exec_summary catches the
    # exception inside its own try/except (services/llm_structured.py
    # treats an llm_call exception as failure) and returns the
    # fallback skeleton. Adapter's outer try/except is for
    # generate_exec_summary itself raising, which is rare.
    owner = _FakeOwner(chat_raises=RuntimeError("HTTP 500"))
    out = _run(owner, job_id="j1", findings=[], aggregated_report={})
    self.assertIsNotNone(out)
    self.assertIsInstance(out, dict)
    self.assertIn("AI generation failed validation", out["background_draft"])

  def test_persists_fallback_when_choices_empty(self):
    owner = _FakeOwner(chat_response={"choices": []})
    out = _run(owner, job_id="j1", findings=[], aggregated_report={})
    self.assertIsNotNone(out)
    self.assertIn("AI generation failed validation", out["background_draft"])

  def test_failure_emits_per_attempt_diagnostic_log(self):
    # Both attempts return prose instead of JSON. The launcher must
    # log per-attempt diagnostics (length, parser hints, code, head/tail)
    # so a future operator can triage similar issues from the journal
    # without needing a re-run.
    prose = "I'm sorry, I cannot produce that output. Please rephrase."
    owner = _FakeOwner(chat_response={
      "choices": [{"message": {"content": prose}}],
    })
    _run(owner, job_id="job-prose", findings=[], aggregated_report={})

    diag_lines = [line for line in owner._logs if "[LLM-DIAG]" in line]
    self.assertGreaterEqual(len(diag_lines), 2,
                            f"expected per-attempt diagnostics, got: {owner._logs}")
    # Each diagnostic carries the job id, attempt number, response length,
    # validation code, the parser-hint flags, and bounded head/tail snippets.
    first = diag_lines[0]
    self.assertIn("job=job-prose", first)
    self.assertIn("attempt=1", first)
    self.assertIn("raw_len=", first)
    self.assertIn("codes=json_parse_failed", first)
    self.assertIn("appears_prose", first)
    self.assertIn("no_open_brace", first)
    self.assertIn("head=", first)
    self.assertIn(diag_lines[1].split("attempt=")[1][0], "2")

  def test_fixture_cache_env_does_not_gate_runtime_chat_endpoint(self):
    for live_llm_value in (None, "0"):
      with self.subTest(LIVE_LLM=live_llm_value):
        if live_llm_value is None:
          os.environ.pop("LIVE_LLM", None)
        else:
          os.environ["LIVE_LLM"] = live_llm_value

        owner = _FakeOwner(chat_response={
          "choices": [{"message": {"content": _valid_llm_response_content()}}],
        })
        out = _run(
          owner,
          job_id="j1",
          findings=[{
            "severity": "CRITICAL",
            "title": "Apache RCE",
            "cve": ["CVE-2021-41773"],
            "port": 80,
            "protocol": "http",
            "probe": "service_http",
            "category": "service",
          }],
          aggregated_report={
            "total_findings": 1,
            "total_open_ports": 1,
            "total_services": 1,
          },
        )

        self.assertIsNotNone(out)
        self.assertFalse(out.get("error", False))
        self.assertGreaterEqual(len(owner._calls), 1)
        self.assertEqual(owner._calls[0]["endpoint"], "/chat")


if __name__ == "__main__":
  unittest.main()
