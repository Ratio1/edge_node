"""Phase 4 PR-4.1 — LlmReportSections schema + validator tests.

Coverage:
  - Default construction yields empty sections; round-trip clean.
  - from_dict tolerates partial / malformed input shapes.
  - Required-section emptiness produces error-severity issues.
  - Length caps produce warning-severity issues (truncation
    happens at render time; LLM not retried for warnings).
  - Roadmap shape validation.
  - Narrative/data contradiction:
      "clean posture" claim with HIGH/CRITICAL findings → error
      LLM output naming a CVE not in findings → error
  - ValidationResult.ok / .errors / .warnings bookkeeping.
"""
from __future__ import annotations

import unittest

from extensions.business.cybersec.red_mesh.models.llm_output import (
  MAX_BACKGROUND_DRAFT_CHARS,
  MAX_OVERALL_POSTURE_CHARS,
  MAX_RECOMMENDATION_BULLETS,
  ROADMAP_BUCKETS,
  ROADMAP_LONG_TERM,
  ROADMAP_MID_TERM,
  ROADMAP_NEAR_TERM,
  SEVERITY_ERROR,
  SEVERITY_WARNING,
  LlmReportSections,
  ValidationIssue,
  ValidationResult,
  validate_llm_output,
)


def _full_output(**overrides) -> LlmReportSections:
  base = LlmReportSections(
    background_draft="Engagement context summary.",
    overall_posture="Several critical issues require attention.",
    recommendation_summary=("Patch Apache.", "Rotate PostgreSQL credentials."),
    strategic_roadmap={
      ROADMAP_NEAR_TERM: ("Patch CVE-2021-41773 by Friday.",),
      ROADMAP_MID_TERM: ("Implement WAF rules.",),
      ROADMAP_LONG_TERM: ("Adopt continuous patch management.",),
    },
    attack_chain_narratives=(
      "Open redirect + SSRF chain on the public web service.",
    ),
    coverage_gaps=("Phishing not in scope.",),
    conclusion="Continue with quarterly retesting.",
    model="deepseek-chat",
    generated_at="2026-05-05T10:00:00Z",
    prompt_version="exec-summary-v1",
  )
  for k, v in overrides.items():
    base = LlmReportSections(**{**base.to_dict(), k: v})
  return LlmReportSections.from_dict(_round_trip_dict(base, **overrides))


def _round_trip_dict(base: LlmReportSections, **overrides) -> dict:
  d = base.to_dict()
  for k, v in overrides.items():
    d[k] = v
  return d


# ---------------------------------------------------------------------
# Schema construction + round-trip
# ---------------------------------------------------------------------


class TestSchemaConstruction(unittest.TestCase):

  def test_default_construction_yields_empty_sections(self):
    o = LlmReportSections()
    self.assertEqual(o.background_draft, "")
    self.assertEqual(o.overall_posture, "")
    self.assertEqual(o.recommendation_summary, ())
    self.assertEqual(o.attack_chain_narratives, ())
    self.assertEqual(o.coverage_gaps, ())
    self.assertEqual(o.conclusion, "")
    self.assertEqual(o.model, "")
    self.assertEqual(set(o.strategic_roadmap.keys()), set(ROADMAP_BUCKETS))
    for bucket in ROADMAP_BUCKETS:
      self.assertEqual(o.strategic_roadmap[bucket], ())

  def test_round_trip_through_to_dict_from_dict(self):
    src = LlmReportSections(
      background_draft="bg", overall_posture="op",
      recommendation_summary=("a", "b"),
      strategic_roadmap={
        ROADMAP_NEAR_TERM: ("near1", "near2"),
        ROADMAP_MID_TERM: (), ROADMAP_LONG_TERM: ("lt1",),
      },
      attack_chain_narratives=("chain1",),
      coverage_gaps=(),
      conclusion="conclude",
      model="deepseek-chat",
      generated_at="2026-05-05T10:00:00Z",
      prompt_version="v1",
    )
    d = src.to_dict()
    restored = LlmReportSections.from_dict(d)
    self.assertEqual(restored.background_draft, src.background_draft)
    self.assertEqual(restored.recommendation_summary, src.recommendation_summary)
    self.assertEqual(
      restored.strategic_roadmap[ROADMAP_NEAR_TERM],
      src.strategic_roadmap[ROADMAP_NEAR_TERM],
    )
    self.assertEqual(restored.model, "deepseek-chat")

  def test_from_dict_tolerates_none(self):
    o = LlmReportSections.from_dict(None)
    self.assertIsInstance(o, LlmReportSections)
    self.assertEqual(o.background_draft, "")

  def test_from_dict_tolerates_garbage_lists(self):
    """Non-string entries in list-style fields are silently dropped."""
    o = LlmReportSections.from_dict({
      "recommendation_summary": ["valid", 12345, None, "also-valid"],
    })
    self.assertEqual(o.recommendation_summary, ("valid", "also-valid"))

  def test_from_dict_tolerates_missing_roadmap_buckets(self):
    o = LlmReportSections.from_dict({
      "strategic_roadmap": {ROADMAP_NEAR_TERM: ["a", "b"]},
    })
    self.assertEqual(o.strategic_roadmap[ROADMAP_NEAR_TERM], ("a", "b"))
    self.assertEqual(o.strategic_roadmap[ROADMAP_MID_TERM], ())
    self.assertEqual(o.strategic_roadmap[ROADMAP_LONG_TERM], ())

  def test_from_dict_tolerates_malformed_roadmap(self):
    o = LlmReportSections.from_dict({"strategic_roadmap": "not-a-dict"})
    for bucket in ROADMAP_BUCKETS:
      self.assertEqual(o.strategic_roadmap[bucket], ())


# ---------------------------------------------------------------------
# Required-section emptiness
# ---------------------------------------------------------------------


class TestRequiredSections(unittest.TestCase):

  def test_empty_overall_posture_is_error(self):
    o = LlmReportSections(
      overall_posture="",
      recommendation_summary=("x",),
      conclusion="x",
    )
    result = validate_llm_output(o)
    self.assertFalse(result.ok)
    codes = {i.code for i in result.errors}
    self.assertIn("empty_required_section", codes)

  def test_empty_recommendation_summary_is_error(self):
    o = LlmReportSections(
      overall_posture="x", recommendation_summary=(), conclusion="x",
    )
    result = validate_llm_output(o)
    self.assertFalse(result.ok)
    fields = {i.field for i in result.errors}
    self.assertIn("recommendation_summary", fields)

  def test_empty_conclusion_is_error(self):
    o = LlmReportSections(
      overall_posture="x", recommendation_summary=("x",), conclusion="",
    )
    self.assertFalse(validate_llm_output(o).ok)

  def test_whitespace_only_required_is_error(self):
    o = LlmReportSections(
      overall_posture="   \n\n  ",
      recommendation_summary=("x",), conclusion="x",
    )
    self.assertFalse(validate_llm_output(o).ok)

  def test_full_output_passes(self):
    o = LlmReportSections(
      background_draft="bg",
      overall_posture="2-paragraph posture here",
      recommendation_summary=("Patch X", "Rotate Y"),
      conclusion="Stay vigilant",
    )
    result = validate_llm_output(o)
    self.assertTrue(result.ok)
    self.assertEqual(result.errors, ())

  def test_custom_required_set(self):
    """Pass in an empty required-set to skip required-emptiness checks."""
    o = LlmReportSections()
    result = validate_llm_output(o, required_sections=())
    self.assertTrue(result.ok)


# ---------------------------------------------------------------------
# Length caps
# ---------------------------------------------------------------------


class TestLengthCaps(unittest.TestCase):

  def test_overlong_overall_posture_is_warning_not_error(self):
    o = LlmReportSections(
      overall_posture="x" * (MAX_OVERALL_POSTURE_CHARS + 1),
      recommendation_summary=("x",), conclusion="x",
    )
    result = validate_llm_output(o)
    self.assertTrue(result.ok)  # warnings don't block
    codes = {i.code for i in result.warnings}
    self.assertIn("over_length", codes)

  def test_overlong_background_draft_warning(self):
    o = LlmReportSections(
      background_draft="x" * (MAX_BACKGROUND_DRAFT_CHARS + 1),
      overall_posture="x", recommendation_summary=("x",), conclusion="x",
    )
    result = validate_llm_output(o)
    self.assertTrue(result.ok)
    self.assertGreater(len(result.warnings), 0)

  def test_too_many_recommendation_bullets_warning(self):
    o = LlmReportSections(
      overall_posture="x", conclusion="x",
      recommendation_summary=tuple(f"bullet-{i}" for i in range(MAX_RECOMMENDATION_BULLETS + 1)),
    )
    result = validate_llm_output(o)
    self.assertTrue(result.ok)
    fields = {i.field for i in result.warnings}
    self.assertIn("recommendation_summary", fields)

  def test_overlong_individual_bullet_warning(self):
    o = LlmReportSections(
      overall_posture="x", conclusion="x",
      recommendation_summary=("normal", "x" * 500),  # 500 > 400 cap
    )
    result = validate_llm_output(o)
    self.assertTrue(result.ok)
    fields = {i.field for i in result.warnings}
    self.assertIn("recommendation_summary[1]", fields)


# ---------------------------------------------------------------------
# Narrative/data contradiction
# ---------------------------------------------------------------------


class TestPostureDataMismatch(unittest.TestCase):

  def test_clean_posture_with_critical_findings_is_error(self):
    o = LlmReportSections(
      overall_posture="The system is secure with no significant vulnerabilities.",
      recommendation_summary=("Continue monitoring.",),
      conclusion="Healthy posture.",
    )
    findings = [
      {"severity": "CRITICAL", "title": "RCE in something", "cve": ["CVE-2021-41773"]},
    ]
    result = validate_llm_output(o, findings=findings)
    self.assertFalse(result.ok)
    codes = {i.code for i in result.errors}
    self.assertIn("posture_data_mismatch", codes)

  def test_clean_posture_with_only_low_findings_is_ok(self):
    o = LlmReportSections(
      overall_posture="Overall posture is secure with minor hardening recommendations.",
      recommendation_summary=("Tighten cookie flags.",),
      conclusion="Continue monitoring.",
    )
    findings = [
      {"severity": "LOW", "title": "Missing Secure flag"},
    ]
    result = validate_llm_output(o, findings=findings)
    self.assertTrue(result.ok)

  def test_normal_posture_with_critical_findings_is_ok(self):
    o = LlmReportSections(
      overall_posture="Multiple critical issues identified, including pre-auth RCE.",
      recommendation_summary=("Patch Apache.",),
      conclusion="Re-test once patched.",
    )
    findings = [{"severity": "CRITICAL", "title": "RCE"}]
    result = validate_llm_output(o, findings=findings)
    self.assertTrue(result.ok)

  def test_no_significant_pattern_caught(self):
    o = LlmReportSections(
      overall_posture="No significant findings observed during this engagement.",
      recommendation_summary=("Continue.",), conclusion="ok",
    )
    findings = [{"severity": "HIGH", "title": "x"}]
    self.assertFalse(validate_llm_output(o, findings=findings).ok)


class TestHallucinatedCves(unittest.TestCase):

  def test_cve_not_in_findings_is_error(self):
    o = LlmReportSections(
      overall_posture="The scan identified CVE-2099-99999 as the most severe issue.",
      recommendation_summary=("Patch CVE-2099-99999.",),
      conclusion="ok",
    )
    findings = [
      {"severity": "HIGH", "title": "Apache outdated", "cve": ["CVE-2021-41773"]},
    ]
    result = validate_llm_output(o, findings=findings)
    codes = {i.code for i in result.errors}
    self.assertIn("hallucinated_cve", codes)

  def test_cve_in_findings_is_ok(self):
    o = LlmReportSections(
      overall_posture="CVE-2021-41773 is the most severe issue identified.",
      recommendation_summary=("Patch CVE-2021-41773.",),
      conclusion="ok",
    )
    findings = [
      {"severity": "HIGH", "title": "Apache outdated", "cve": ["CVE-2021-41773"]},
    ]
    result = validate_llm_output(o, findings=findings)
    self.assertTrue(result.ok)

  def test_cve_in_finding_title_is_ok(self):
    """Legacy findings carry the CVE in the title string only."""
    o = LlmReportSections(
      overall_posture="CVE-2021-41773 needs immediate patching.",
      recommendation_summary=("Patch immediately.",),
      conclusion="ok",
    )
    findings = [
      {"severity": "HIGH", "title": "CVE-2021-41773: Apache path traversal"},
    ]
    self.assertTrue(validate_llm_output(o, findings=findings).ok)

  def test_multiple_hallucinated_cves_all_flagged(self):
    o = LlmReportSections(
      overall_posture="See CVE-2099-11111 and CVE-2099-22222.",
      recommendation_summary=("x",), conclusion="x",
    )
    findings = [{"severity": "HIGH", "title": "x", "cve": ["CVE-2021-41773"]}]
    result = validate_llm_output(o, findings=findings)
    hallucinated = [i for i in result.errors if i.code == "hallucinated_cve"]
    self.assertEqual(len(hallucinated), 2)

  def test_no_findings_skips_narrative_checks(self):
    """When findings=None, narrative checks are skipped (e.g., for
    quick-summary outputs that don't need full validation)."""
    o = LlmReportSections(
      overall_posture="The system is secure.",
      recommendation_summary=("x",), conclusion="x",
    )
    # No findings argument
    result = validate_llm_output(o)
    self.assertTrue(result.ok)


# ---------------------------------------------------------------------
# Roadmap shape
# ---------------------------------------------------------------------


class TestRoadmapShape(unittest.TestCase):

  def test_unknown_roadmap_bucket_is_warning(self):
    o = LlmReportSections(
      overall_posture="x", recommendation_summary=("x",), conclusion="x",
      strategic_roadmap={
        ROADMAP_NEAR_TERM: ("x",),
        "yesterday": ("x",),  # unknown bucket
      },
    )
    result = validate_llm_output(o)
    self.assertTrue(result.ok)  # warning, not error
    codes = {i.code for i in result.warnings}
    self.assertIn("unknown_roadmap_bucket", codes)


# ---------------------------------------------------------------------
# ValidationResult bookkeeping
# ---------------------------------------------------------------------


class TestValidationResult(unittest.TestCase):

  def test_ok_true_when_only_warnings(self):
    issues = (
      ValidationIssue(SEVERITY_WARNING, "over_length", "x", field="x"),
    )
    self.assertTrue(ValidationResult(issues=issues).ok)

  def test_ok_false_when_any_error(self):
    issues = (
      ValidationIssue(SEVERITY_WARNING, "over_length", "x"),
      ValidationIssue(SEVERITY_ERROR, "empty_required_section", "x"),
    )
    self.assertFalse(ValidationResult(issues=issues).ok)

  def test_to_dict_separates_errors_and_warnings(self):
    issues = (
      ValidationIssue(SEVERITY_WARNING, "over_length", "warn-msg", field="x"),
      ValidationIssue(SEVERITY_ERROR, "empty_required_section", "err-msg", field="y"),
    )
    d = ValidationResult(issues=issues).to_dict()
    self.assertFalse(d["ok"])
    self.assertEqual(len(d["errors"]), 1)
    self.assertEqual(len(d["warnings"]), 1)
    self.assertEqual(d["errors"][0]["code"], "empty_required_section")


if __name__ == "__main__":
  unittest.main()
