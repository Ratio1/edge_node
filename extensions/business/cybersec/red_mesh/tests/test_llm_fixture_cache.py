"""Phase 4 PR-4.4 — fixture-cache + AI-never-writes-remediation invariant tests.

Two concerns:

  1. Fixture cache wrapper:
     - LIVE_LLM=1 → real LLM called, response persisted to disk.
     - LIVE_LLM unset → response loaded from disk; missing cache
       raises LlmFixtureCacheMiss with actionable message.
     - Cache key is stable across identical inputs.
     - Different inputs produce different cache keys.

  2. AI-never-writes-remediation invariant:
     - LlmReportSections has NO per-finding fields (no remediation,
       no evidence, no cvss_score, no cwe). The schema only
       carries engagement-level narrative.
     - The structured-LLM service signature does NOT accept a
       `findings_remediation_override` or similar bypass param.
"""
from __future__ import annotations

import dataclasses
import inspect
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from extensions.business.cybersec.red_mesh.models.llm_output import (
  LlmReportSections,
)
from extensions.business.cybersec.red_mesh.services.llm_fixture_cache import (
  LlmFixtureCacheMiss,
  cached_llm_call,
)
from extensions.business.cybersec.red_mesh.services.llm_structured import (
  generate_exec_summary,
)


# ---------------------------------------------------------------------
# Fixture cache: live mode (LIVE_LLM=1)
# ---------------------------------------------------------------------


class TestFixtureCacheLiveMode(unittest.TestCase):

  def setUp(self):
    self._tmp = TemporaryDirectory()
    self.cache_dir = Path(self._tmp.name)

  def tearDown(self):
    self._tmp.cleanup()

  def _live_env(self):
    return mock.patch.dict(os.environ, {"LIVE_LLM": "1"})

  def test_live_mode_calls_real_llm_and_persists(self):
    inner_calls: list = []
    def real_llm(messages, max_tokens, temperature):
      inner_calls.append((messages, max_tokens, temperature))
      return "real-llm-response"

    with self._live_env():
      cached = cached_llm_call(real_llm, cache_dir=self.cache_dir)
      result = cached([{"role": "user", "content": "hi"}], 100, 0.2)

    self.assertEqual(result, "real-llm-response")
    self.assertEqual(len(inner_calls), 1)
    # File should be on disk now
    fixture_files = list(self.cache_dir.glob("*.json"))
    self.assertEqual(len(fixture_files), 1)

  def test_live_mode_overwrites_existing_fixture(self):
    """Re-running with LIVE_LLM=1 refreshes the fixture."""
    def real_llm_v1(messages, max_tokens, temperature):
      return "v1"
    def real_llm_v2(messages, max_tokens, temperature):
      return "v2"

    msgs = [{"role": "user", "content": "x"}]
    with self._live_env():
      cached_llm_call(real_llm_v1, cache_dir=self.cache_dir)(msgs, 100, 0.2)
      result = cached_llm_call(real_llm_v2, cache_dir=self.cache_dir)(msgs, 100, 0.2)
    self.assertEqual(result, "v2")


# ---------------------------------------------------------------------
# Fixture cache: replay mode (LIVE_LLM unset)
# ---------------------------------------------------------------------


class TestFixtureCacheReplayMode(unittest.TestCase):

  def setUp(self):
    self._tmp = TemporaryDirectory()
    self.cache_dir = Path(self._tmp.name)

  def tearDown(self):
    self._tmp.cleanup()

  def _no_live_env(self):
    return mock.patch.dict(os.environ, {"LIVE_LLM": ""}, clear=False)

  def test_cache_miss_raises_with_actionable_message(self):
    def boom(messages, max_tokens, temperature):
      raise RuntimeError("MUST NOT REACH NETWORK")

    with self._no_live_env():
      cached = cached_llm_call(boom, cache_dir=self.cache_dir)
      with self.assertRaises(LlmFixtureCacheMiss) as ctx:
        cached([{"role": "user", "content": "x"}], 100, 0.2)
    self.assertIn("LIVE_LLM=1", str(ctx.exception))

  def test_replay_returns_cached_response_without_calling_inner(self):
    """Populate cache via live mode, then replay without network."""
    inner_calls = []
    def real_llm(messages, max_tokens, temperature):
      inner_calls.append("called")
      return "cached-response-content"

    msgs = [{"role": "user", "content": "x"}]

    with mock.patch.dict(os.environ, {"LIVE_LLM": "1"}):
      cached_llm_call(real_llm, cache_dir=self.cache_dir)(msgs, 100, 0.2)
    inner_calls.clear()

    def boom(messages, max_tokens, temperature):
      raise RuntimeError("MUST NOT REACH NETWORK")

    with mock.patch.dict(os.environ, {"LIVE_LLM": ""}, clear=False):
      result = cached_llm_call(boom, cache_dir=self.cache_dir)(msgs, 100, 0.2)
    self.assertEqual(result, "cached-response-content")
    self.assertEqual(inner_calls, [])

  def test_different_inputs_different_keys(self):
    """The cache key includes the inputs — different prompts get
    different fixture files."""
    inner_responses = ["resp1", "resp2"]
    def real_llm(messages, max_tokens, temperature):
      return inner_responses.pop(0)

    with mock.patch.dict(os.environ, {"LIVE_LLM": "1"}):
      cached = cached_llm_call(real_llm, cache_dir=self.cache_dir)
      r1 = cached([{"role": "user", "content": "a"}], 100, 0.2)
      r2 = cached([{"role": "user", "content": "b"}], 100, 0.2)

    self.assertEqual(r1, "resp1")
    self.assertEqual(r2, "resp2")
    self.assertEqual(len(list(self.cache_dir.glob("*.json"))), 2)

  def test_same_inputs_same_key(self):
    inner_responses = ["only-once", "should-not-call-again"]
    def real_llm(messages, max_tokens, temperature):
      return inner_responses.pop(0)

    msgs = [{"role": "user", "content": "x"}]

    with mock.patch.dict(os.environ, {"LIVE_LLM": "1"}):
      cached_llm_call(real_llm, cache_dir=self.cache_dir)(msgs, 100, 0.2)

    # Now non-live: same inputs, same key, no inner call.
    def boom(*a, **kw):
      raise RuntimeError("MUST NOT REACH NETWORK")
    with mock.patch.dict(os.environ, {"LIVE_LLM": ""}, clear=False):
      r = cached_llm_call(boom, cache_dir=self.cache_dir)(msgs, 100, 0.2)
    self.assertEqual(r, "only-once")

  def test_cache_files_are_json_with_inputs_for_inspection(self):
    """Saved fixtures include the prompt that produced them so
    a human can audit them."""
    def real_llm(messages, max_tokens, temperature):
      return "the response"

    with mock.patch.dict(os.environ, {"LIVE_LLM": "1"}):
      cached = cached_llm_call(real_llm, cache_dir=self.cache_dir)
      cached([{"role": "user", "content": "audit me"}], 100, 0.2)

    files = list(self.cache_dir.glob("*.json"))
    self.assertEqual(len(files), 1)
    import json
    data = json.loads(files[0].read_text())
    self.assertEqual(data["response"], "the response")
    self.assertEqual(data["max_tokens"], 100)
    self.assertEqual(data["temperature"], 0.2)
    self.assertEqual(len(data["messages"]), 1)


# ---------------------------------------------------------------------
# AI-never-writes-remediation invariant (P12)
# ---------------------------------------------------------------------


class TestAiNeverWritesRemediation(unittest.TestCase):
  """P12: AI never writes finding data, never writes per-finding
  remediation steps. The LLM may write engagement-level narrative
  (overall_posture, recommendation_summary, attack_chain_narratives,
  conclusion) but NOT per-finding fields.

  Enforced architecturally:
    - LlmReportSections has NO per-finding fields.
    - The structured-LLM service signature does NOT accept any
      override that would let the LLM populate per-finding fields.
  """

  # Field names that, if present on LlmReportSections, would
  # constitute a P12 violation (the LLM would have a place to
  # write per-finding data).
  FORBIDDEN_FIELDS = frozenset({
    "remediation",
    "remediations",
    "finding_remediations",
    "evidence",
    "evidence_items",
    "cvss_score",
    "cvss_vector",
    "cwe",
    "cve",
    "owasp_id",
    "affected_assets",
    "steps_to_reproduce",
    "impact",                # impact is per-finding; engagement-
                             # level summary uses overall_posture.
    "severity",
  })

  def test_llm_report_sections_has_no_per_finding_fields(self):
    fields = {f.name for f in dataclasses.fields(LlmReportSections)}
    forbidden_present = fields & self.FORBIDDEN_FIELDS
    self.assertFalse(
      forbidden_present,
      f"LlmReportSections has forbidden per-finding fields: {forbidden_present}. "
      f"P12 says AI may not write finding data — those come from "
      f"probe metadata and the CVE DB, not the LLM. If a new "
      f"engagement-level use case needs one of these names, choose "
      f"a different name (e.g., recommendation_summary) and update "
      f"FORBIDDEN_FIELDS with rationale.",
    )

  def test_engagement_level_fields_are_present(self):
    """Sanity check: the engagement-level fields the LLM IS
    allowed to write are still on the schema."""
    fields = {f.name for f in dataclasses.fields(LlmReportSections)}
    expected = {
      "background_draft", "overall_posture", "recommendation_summary",
      "strategic_roadmap", "attack_chain_narratives", "coverage_gaps",
      "conclusion",
    }
    missing = expected - fields
    self.assertFalse(
      missing, f"engagement-level sections missing from schema: {missing}",
    )

  def test_generate_exec_summary_signature_has_no_remediation_override(self):
    """generate_exec_summary must not accept a parameter that would
    let the caller route LLM output into per-finding remediation."""
    sig = inspect.signature(generate_exec_summary)
    forbidden_params = {
      "remediation", "finding_remediations",
      "remediation_override", "set_remediation",
      "evidence_override", "cvss_override",
    }
    actual_params = set(sig.parameters.keys())
    self.assertFalse(
      actual_params & forbidden_params,
      f"generate_exec_summary signature has parameters that could "
      f"bypass P12: {actual_params & forbidden_params}",
    )


if __name__ == "__main__":
  unittest.main()
