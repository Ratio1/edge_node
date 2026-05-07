"""Structured LLM output schema for the PTES-aligned reporting pipeline.

Phase 4 PR-4.1 of the PTES rebuild. Implements P3 + P11 + P12 of the
architectural principles:

  P3  — AI as a transformer, not an oracle. The LLM produces
        STRUCTURED JSON with named sections; the PDF generator
        decides how to render each section. AI never decides which
        sections exist.

  P11 — LLM never sees raw scan output. Builder constructs prompt
        context from structured Finding records + engagement
        context only. Implemented in PR-4.2.

  P12 — AI never writes finding data or remediation steps. LLM
        may write engagement-level narrative
        (overall_posture, recommendation_summary,
        attack_chain_narratives, conclusion) but NOT
        per-finding remediation, evidence, or CVSS scores.
        Enforced by the PDF generator's data-source rules
        (Phase 6) plus assertion tests in PR-4.4.

What this module ships
----------------------

  LlmReportSections      — frozen dataclass of the seven sections
                            the report consumes from the LLM.
  ValidationIssue        — single validation error (severity, code,
                            message, field path).
  ValidationResult       — bundle of issues with .ok property.
  validate_llm_output()  — pure function: takes LlmReportSections
                            + the structured findings list and
                            returns a ValidationResult flagging
                            schema violations and narrative/data
                            mismatch.

What's NOT here
---------------

  build_llm_input()     — PR-4.2 (LLM input contract; structured
                          findings + engagement context only).
  Prompt templates     — PR-4.3 (system prompts that demand JSON
                          conforming to this schema).
  Fixture cache        — PR-4.4 (offline LLM dev workflow).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------

# Per-section length caps. The LLM is instructed in the prompt to stay
# within these; the validator flags over-cap output as a warning rather
# than a hard rejection (overage is truncated at render time).
MAX_EXECUTIVE_HEADLINE_CHARS = 280
MAX_BACKGROUND_DRAFT_CHARS = 1500
MAX_OVERALL_POSTURE_CHARS = 4000
MAX_RECOMMENDATION_BULLETS = 12
MAX_RECOMMENDATION_BULLET_CHARS = 400
MAX_ROADMAP_BULLETS_PER_BUCKET = 8
MAX_ROADMAP_BULLET_CHARS = 300
MAX_ATTACK_CHAINS = 6
MAX_ATTACK_CHAIN_CHARS = 800
MAX_COVERAGE_GAPS = 12
MAX_COVERAGE_GAP_CHARS = 300
MAX_CONCLUSION_CHARS = 1500

# "Posture sounds clean despite findings" detection — phrases that, if
# present in overall_posture while >= 1 finding has severity HIGH or
# CRITICAL, get flagged as a narrative/data contradiction.
_CLEAN_POSTURE_PATTERNS = (
  re.compile(r"\bno (significant|notable|major|critical) (vulnerabilit|issue|finding|risk)", re.I),
  re.compile(r"\boverall\s+(posture\s+is\s+)?(secure|clean|excellent|strong)", re.I),
  re.compile(r"\bsystem\s+(is\s+)?(secure|clean|hardened)", re.I),
  re.compile(r"\bnothing of concern", re.I),
)

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{3,7}\b", re.I)


# ---------------------------------------------------------------------
# Roadmap buckets
# ---------------------------------------------------------------------

ROADMAP_NEAR_TERM = "near_term"
ROADMAP_MID_TERM = "mid_term"
ROADMAP_LONG_TERM = "long_term"
ROADMAP_BUCKETS = (ROADMAP_NEAR_TERM, ROADMAP_MID_TERM, ROADMAP_LONG_TERM)


# ---------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class LlmReportSections:
  """Structured LLM output consumed by the Phase 6 / Phase 7 PDF.

  Every field is required-with-empty-default so a partially-populated
  output (e.g., when an early prompt iteration emitted only some
  sections) still validates structurally and renders with placeholders
  for the missing parts. The validator separately flags an empty
  *required* section as a warning so the upstream LLM call can be
  retried.
  """

  # Executive summary (PTES §3.1, §3.2)
  executive_headline: str = ""   # 1-3 sentences for dashboard tile
  background_draft: str = ""
  overall_posture: str = ""

  # Recommendations + roadmap (PTES §3.5, §3.6)
  recommendation_summary: tuple[str, ...] = ()
  strategic_roadmap: dict[str, tuple[str, ...]] = field(
    default_factory=lambda: {b: () for b in ROADMAP_BUCKETS}
  )

  # Technical narrative (PTES §4.4, §4.7)
  attack_chain_narratives: tuple[str, ...] = ()
  coverage_gaps: tuple[str, ...] = ()
  conclusion: str = ""

  # Provenance — must round-trip through dump_for_scan_record so the
  # report's AI-disclosure appendix can show which model + prompt
  # version produced this section.
  model: str = ""
  generated_at: str = ""        # ISO 8601 UTC
  prompt_version: str = ""

  def to_dict(self) -> dict:
    return {
      "executive_headline": self.executive_headline,
      "background_draft": self.background_draft,
      "overall_posture": self.overall_posture,
      "recommendation_summary": list(self.recommendation_summary),
      "strategic_roadmap": {
        bucket: list(self.strategic_roadmap.get(bucket, ()))
        for bucket in ROADMAP_BUCKETS
      },
      "attack_chain_narratives": list(self.attack_chain_narratives),
      "coverage_gaps": list(self.coverage_gaps),
      "conclusion": self.conclusion,
      "model": self.model,
      "generated_at": self.generated_at,
      "prompt_version": self.prompt_version,
    }

  @classmethod
  def from_dict(cls, d: dict | None) -> "LlmReportSections":
    if not isinstance(d, dict):
      return cls()
    raw_roadmap = d.get("strategic_roadmap") or {}
    if not isinstance(raw_roadmap, dict):
      raw_roadmap = {}
    roadmap = {
      bucket: tuple(_str_list(raw_roadmap.get(bucket)))
      for bucket in ROADMAP_BUCKETS
    }
    return cls(
      executive_headline=str(d.get("executive_headline", "")),
      background_draft=str(d.get("background_draft", "")),
      overall_posture=str(d.get("overall_posture", "")),
      recommendation_summary=tuple(_str_list(d.get("recommendation_summary"))),
      strategic_roadmap=roadmap,
      attack_chain_narratives=tuple(_str_list(d.get("attack_chain_narratives"))),
      coverage_gaps=tuple(_str_list(d.get("coverage_gaps"))),
      conclusion=str(d.get("conclusion", "")),
      model=str(d.get("model", "")),
      generated_at=str(d.get("generated_at", "")),
      prompt_version=str(d.get("prompt_version", "")),
    )


def _str_list(value: Any) -> list[str]:
  if not isinstance(value, (list, tuple)):
    return []
  return [str(x) for x in value if isinstance(x, str)]


# ---------------------------------------------------------------------
# Validation result types
# ---------------------------------------------------------------------


SEVERITY_ERROR = "error"
SEVERITY_WARNING = "warning"


@dataclass(frozen=True)
class ValidationIssue:
  """A single validation finding on an LlmReportSections instance.

  severity:
    "error"   — schema violation / narrative-data contradiction.
                Caller MUST retry the LLM call (retry once) and on
                second failure emit the section with an explicit
                "[AI generation failed validation]" placeholder.
    "warning" — soft over-limit (length cap exceeded). Renderer
                truncates at display time; LLM is not retried.
  """
  severity: str          # "error" | "warning"
  code: str              # short machine-readable
  message: str           # human-readable
  field: str = ""        # dotted path, e.g. "overall_posture" or "strategic_roadmap.near_term"


@dataclass(frozen=True)
class ValidationResult:
  issues: tuple[ValidationIssue, ...] = ()

  @property
  def errors(self) -> tuple[ValidationIssue, ...]:
    return tuple(i for i in self.issues if i.severity == SEVERITY_ERROR)

  @property
  def warnings(self) -> tuple[ValidationIssue, ...]:
    return tuple(i for i in self.issues if i.severity == SEVERITY_WARNING)

  @property
  def ok(self) -> bool:
    """True when there are no error-severity issues. Warnings allowed."""
    return not self.errors

  def to_dict(self) -> dict:
    return {
      "ok": self.ok,
      "errors": [
        {"code": i.code, "message": i.message, "field": i.field}
        for i in self.errors
      ],
      "warnings": [
        {"code": i.code, "message": i.message, "field": i.field}
        for i in self.warnings
      ],
    }


# ---------------------------------------------------------------------
# Public validator
# ---------------------------------------------------------------------


def validate_llm_output(
  output: LlmReportSections,
  *,
  findings: list[dict] | None = None,
  required_sections: tuple[str, ...] = (
    "overall_posture", "recommendation_summary", "conclusion",
  ),
) -> ValidationResult:
  """Validate an LlmReportSections instance against schema + content rules.

  Parameters
  ----------
  output : LlmReportSections
      The deserialized LLM response.
  findings : list[dict] | None
      The structured findings list the LLM was given as input.
      When provided, enables narrative/data contradiction checks
      (clean-posture-with-findings, hallucinated-CVE, etc.).
  required_sections : tuple[str, ...]
      Section names that, if empty, produce an error-severity
      issue (forcing an LLM retry). Defaults to the three sections
      that the PDF cannot render placeholders for cleanly.

  Returns
  -------
  ValidationResult
  """
  issues: list[ValidationIssue] = []

  # 1. Required-but-empty checks (errors)
  for section in required_sections:
    if section == "recommendation_summary":
      if not output.recommendation_summary:
        issues.append(ValidationIssue(
          SEVERITY_ERROR, "empty_required_section",
          f"required section {section!r} is empty",
          field=section,
        ))
    else:
      val = getattr(output, section, "")
      if not isinstance(val, str) or not val.strip():
        issues.append(ValidationIssue(
          SEVERITY_ERROR, "empty_required_section",
          f"required section {section!r} is empty",
          field=section,
        ))

  # 2. Length cap warnings
  if len(output.executive_headline) > MAX_EXECUTIVE_HEADLINE_CHARS:
    issues.append(ValidationIssue(
      SEVERITY_WARNING, "over_length",
      f"executive_headline exceeds {MAX_EXECUTIVE_HEADLINE_CHARS} chars "
      f"(got {len(output.executive_headline)})",
      field="executive_headline",
    ))
  if len(output.background_draft) > MAX_BACKGROUND_DRAFT_CHARS:
    issues.append(ValidationIssue(
      SEVERITY_WARNING, "over_length",
      f"background_draft exceeds {MAX_BACKGROUND_DRAFT_CHARS} chars "
      f"(got {len(output.background_draft)})",
      field="background_draft",
    ))
  if len(output.overall_posture) > MAX_OVERALL_POSTURE_CHARS:
    issues.append(ValidationIssue(
      SEVERITY_WARNING, "over_length",
      f"overall_posture exceeds {MAX_OVERALL_POSTURE_CHARS} chars "
      f"(got {len(output.overall_posture)})",
      field="overall_posture",
    ))
  if len(output.conclusion) > MAX_CONCLUSION_CHARS:
    issues.append(ValidationIssue(
      SEVERITY_WARNING, "over_length",
      f"conclusion exceeds {MAX_CONCLUSION_CHARS} chars "
      f"(got {len(output.conclusion)})",
      field="conclusion",
    ))
  if len(output.recommendation_summary) > MAX_RECOMMENDATION_BULLETS:
    issues.append(ValidationIssue(
      SEVERITY_WARNING, "over_length",
      f"recommendation_summary has {len(output.recommendation_summary)} "
      f"bullets (cap is {MAX_RECOMMENDATION_BULLETS})",
      field="recommendation_summary",
    ))
  for idx, bullet in enumerate(output.recommendation_summary):
    if len(bullet) > MAX_RECOMMENDATION_BULLET_CHARS:
      issues.append(ValidationIssue(
        SEVERITY_WARNING, "over_length",
        f"recommendation_summary[{idx}] exceeds "
        f"{MAX_RECOMMENDATION_BULLET_CHARS} chars (got {len(bullet)})",
        field=f"recommendation_summary[{idx}]",
      ))
  if len(output.attack_chain_narratives) > MAX_ATTACK_CHAINS:
    issues.append(ValidationIssue(
      SEVERITY_WARNING, "over_length",
      f"attack_chain_narratives has {len(output.attack_chain_narratives)} "
      f"entries (cap is {MAX_ATTACK_CHAINS})",
      field="attack_chain_narratives",
    ))
  for bucket in ROADMAP_BUCKETS:
    bullets = output.strategic_roadmap.get(bucket, ())
    if len(bullets) > MAX_ROADMAP_BULLETS_PER_BUCKET:
      issues.append(ValidationIssue(
        SEVERITY_WARNING, "over_length",
        f"strategic_roadmap.{bucket} has {len(bullets)} entries "
        f"(cap is {MAX_ROADMAP_BULLETS_PER_BUCKET})",
        field=f"strategic_roadmap.{bucket}",
      ))

  # 3. Roadmap shape errors
  if not isinstance(output.strategic_roadmap, dict):
    issues.append(ValidationIssue(
      SEVERITY_ERROR, "bad_shape",
      "strategic_roadmap must be a dict with near_term / mid_term / long_term keys",
      field="strategic_roadmap",
    ))
  else:
    extra_keys = set(output.strategic_roadmap.keys()) - set(ROADMAP_BUCKETS)
    if extra_keys:
      issues.append(ValidationIssue(
        SEVERITY_WARNING, "unknown_roadmap_bucket",
        f"strategic_roadmap has unexpected keys: {sorted(extra_keys)}",
        field="strategic_roadmap",
      ))

  # 4. Narrative / data contradiction checks (only when findings provided)
  if findings is not None:
    issues.extend(_validate_narrative_against_findings(output, findings))

  return ValidationResult(issues=tuple(issues))


# ---------------------------------------------------------------------
# Narrative/data contradiction checks
# ---------------------------------------------------------------------


def _validate_narrative_against_findings(
  output: LlmReportSections,
  findings: list[dict],
) -> list[ValidationIssue]:
  """Detect cases where the narrative output contradicts the structured
  findings the LLM was given as input."""
  out: list[ValidationIssue] = []

  # Count findings per severity. A "clean posture" claim is invalid
  # when CRITICAL or HIGH findings exist.
  severities = []
  for f in findings or []:
    if isinstance(f, dict):
      sev = str(f.get("severity", "")).upper()
      if sev:
        severities.append(sev)
  has_critical_or_high = any(s in {"CRITICAL", "HIGH"} for s in severities)

  if has_critical_or_high and output.overall_posture:
    for pat in _CLEAN_POSTURE_PATTERNS:
      m = pat.search(output.overall_posture)
      if m:
        out.append(ValidationIssue(
          SEVERITY_ERROR, "posture_data_mismatch",
          f"overall_posture claims {m.group(0)!r} but the findings "
          f"include {sum(1 for s in severities if s in {'CRITICAL','HIGH'})} "
          f"critical/high-severity issue(s)",
          field="overall_posture",
        ))
        break  # one finding is enough

  # Hallucinated-CVE check: every CVE id mentioned in the LLM
  # output (excluding background) must exist in the findings list.
  finding_cves: set[str] = set()
  for f in findings or []:
    if not isinstance(f, dict):
      continue
    # Findings may carry the CVE either as a list (Phase 1 schema)
    # or in the title (legacy).
    for cve in f.get("cve", []) or []:
      if isinstance(cve, str):
        finding_cves.add(cve.upper())
    title = f.get("title", "")
    if isinstance(title, str):
      for m in _CVE_RE.finditer(title):
        finding_cves.add(m.group(0).upper())

  llm_text_blocks = (
    output.overall_posture,
    " ".join(output.recommendation_summary),
    " ".join(output.attack_chain_narratives),
    " ".join(output.coverage_gaps),
    output.conclusion,
  )
  llm_cves: set[str] = set()
  for block in llm_text_blocks:
    if not isinstance(block, str):
      continue
    for m in _CVE_RE.finditer(block):
      llm_cves.add(m.group(0).upper())

  hallucinated = llm_cves - finding_cves
  for cve in sorted(hallucinated):
    out.append(ValidationIssue(
      SEVERITY_ERROR, "hallucinated_cve",
      f"LLM output references {cve} but no such CVE is in the findings input",
      field="overall_posture/recommendation_summary/attack_chain_narratives/conclusion",
    ))

  return out
