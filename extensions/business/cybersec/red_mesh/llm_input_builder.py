"""LLM input builder — the trust boundary (Phase 4 PR-4.2).

Implements P11 of the architectural principles:

  *The LLM never sees raw scan output.*

A target server can put arbitrary bytes in HTTP responses, banners,
headers, error pages, JS, SOAP envelopes, etc. If those bytes enter
the LLM prompt verbatim, a malicious target can attempt prompt
injection — instructing the model to ignore prior context, to
declare the scan clean, or to exfiltrate engagement details.

This module is the *only* allowed path from scan data to LLM
context. It accepts:

  - the structured Finding records that probes emit (already
    PII-redacted at the redaction-layer boundary);
  - the engagement context dataclass (client name, objectives,
    classification — operator-supplied, trusted);
  - aggregate counts (open ports, services, etc.).

It refuses to forward:

  - raw banners (HTTP Server header, SSH banner, SMTP HELO,
    SMB negotiate response, etc.);
  - raw HTTP response bodies;
  - X-Powered-By / Server / Title strings;
  - any other field whose bytes originated from the target.

Plus a small set of guard transforms applied to every string that
DOES leave through the boundary:

  - control characters stripped;
  - length-capped per field;
  - zero-width characters stripped (defeat hidden-prompt overlays);
  - prompt-injection sentinel patterns escaped (``<|...|>``,
    ``IGNORE PRIOR INSTRUCTIONS``, etc.).

Test scaffolding includes an architectural-invariant assertion
(test_llm_input_isolation) that scans the redmesh_llm_agent_api
module for any reference to raw scan_results outside this builder.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------
# Limits — keep aggressive caps; if the LLM needs more it can ask
# for follow-up via the structured-only context.
# ---------------------------------------------------------------------

MAX_FINDING_TITLE_CHARS = 200
MAX_FINDING_DESCRIPTION_CHARS = 600
MAX_FINDING_IMPACT_CHARS = 400
MAX_EVIDENCE_CAPTION_CHARS = 240
MAX_EVIDENCE_SNIPPET_CHARS = 200
MAX_FINDINGS_INCLUDED = 80          # cap on findings forwarded to LLM
MAX_REFERENCES_PER_FINDING = 5
MAX_AFFECTED_ASSETS_PER_FINDING = 5
MAX_TAGS_PER_FINDING = 8

# ---------------------------------------------------------------------
# Guard patterns
# ---------------------------------------------------------------------

# Control + zero-width characters — strip outright.
_BAD_CHARS = re.compile(
  r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​‌‍⁠﻿]"
)

# Prompt-injection sentinels. We escape the boundaries so the model
# treats them as text rather than control. These patterns are case-
# insensitive substrings, escaped with marker brackets.
_INJECTION_PATTERNS = (
  re.compile(r"<\|", re.I),
  re.compile(r"\|>", re.I),
  re.compile(r"\[\s*INST\s*\]", re.I),
  re.compile(r"\[\s*/\s*INST\s*\]", re.I),
  re.compile(r"<\s*system\s*>", re.I),
  re.compile(r"<\s*/\s*system\s*>", re.I),
  re.compile(r"\bignore (?:all )?(?:prior|previous|preceding|above) "
             r"(?:instructions|prompts|directions)", re.I),
  re.compile(r"\bdisregard (?:all )?(?:prior|previous|preceding|above)", re.I),
  re.compile(r"\boverride (?:the )?(?:system|prior) (?:prompt|message)", re.I),
)


def _sanitize(value: Any, max_chars: int = 0) -> str:
  """Apply the guard transforms to a single string.

  Steps:
    1. Coerce to str.
    2. Strip control + zero-width chars.
    3. Replace prompt-injection sentinels with neutralized markers.
    4. Length-cap (when max_chars > 0).
  """
  if value is None:
    return ""
  s = str(value)
  s = _BAD_CHARS.sub("", s)
  for pat in _INJECTION_PATTERNS:
    # Replace the matched pattern with a textual escape so the model
    # sees it but doesn't treat it as a directive.
    s = pat.sub(lambda m: f"[neutralized:{m.group(0)}]", s)
  if max_chars and len(s) > max_chars:
    s = s[: max_chars - 3].rstrip() + "..."
  return s


def _sanitize_list(values: Any, max_items: int, max_each_chars: int) -> list[str]:
  if not isinstance(values, (list, tuple)):
    return []
  out: list[str] = []
  for v in values:
    if not isinstance(v, str):
      continue
    cleaned = _sanitize(v, max_each_chars)
    if cleaned:
      out.append(cleaned)
    if len(out) >= max_items:
      break
  return out


# ---------------------------------------------------------------------
# Output shape
# ---------------------------------------------------------------------


@dataclass(frozen=True)
class LlmInput:
  """The structured-only payload that the LLM agent is allowed to see.

  Notice what's NOT here:
    - service_info, web_tests_info, graybox_results raw blobs.
    - HTTP response bodies, banners, X-Powered-By strings.
    - target_url, target IP — those are operator-supplied
      identifiers, not target output, but we still pass them
      sanitized.
  """
  # Engagement context (operator-supplied; trusted but sanitized)
  engagement_summary: dict       # client_name / objectives / data_classification
  scan_summary: dict             # aggregate counts: ports, services, findings

  # Findings — structured-only, post-redaction
  findings: list[dict]

  # Provenance hint
  schema_version: str = "1.0"

  def to_dict(self) -> dict:
    return {
      "schema_version": self.schema_version,
      "engagement_summary": dict(self.engagement_summary),
      "scan_summary": dict(self.scan_summary),
      "findings": list(self.findings),
    }


# ---------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------


def build_llm_input(
  *,
  findings: list[dict] | None,
  aggregated_report: dict | None = None,
  engagement: dict | None = None,
  max_findings: int = MAX_FINDINGS_INCLUDED,
) -> LlmInput:
  """Construct the LLM context payload.

  Parameters
  ----------
  findings : list of finding dicts
      The structured findings (output of probe_result()['findings']
      from the Phase 1 schema, optionally further enriched by the
      Phase 2 dynamic reference cache). May be None / empty.
  aggregated_report : dict | None
      The full aggregated scan report. We extract ONLY count-style
      summary fields (open_ports count, scan_metrics.routes_discovered,
      etc.). The raw service_info / web_tests_info / graybox_results
      blobs are intentionally dropped.
  engagement : dict | None
      EngagementContext.to_dict() output (or None). Operator-supplied
      fields are trusted but still sanitized to defeat any clever
      operator who pastes target HTML into client_name.
  max_findings : int
      Cap on findings included; defaults to MAX_FINDINGS_INCLUDED.
      Findings are sorted by severity descending, then by confidence,
      so the most important make it past the cap.
  """
  finding_dicts = list(findings or [])

  # Sort: severity high → low, then certain → tentative confidence.
  severity_rank = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
  }
  conf_rank = {"certain": 0, "firm": 1, "tentative": 2}

  def _key(f: dict) -> tuple:
    sev = str(f.get("severity", "")).upper()
    conf = str(f.get("confidence", "")).lower()
    return (severity_rank.get(sev, 99), conf_rank.get(conf, 9))

  finding_dicts.sort(key=_key)
  truncated = finding_dicts[:max_findings]

  out_findings = [_sanitize_finding(f) for f in truncated]

  return LlmInput(
    engagement_summary=_summarize_engagement(engagement),
    scan_summary=_summarize_scan(
      aggregated_report,
      total_findings=len(finding_dicts),
      included_findings=len(out_findings),
      truncated_findings=len(finding_dicts) - len(out_findings),
    ),
    findings=out_findings,
  )


# ---------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------


def _summarize_engagement(engagement: dict | None) -> dict:
  """Extract the operator-supplied engagement context, sanitized.

  We DROP the contact email/phone/role fields — the LLM doesn't
  need PII to write the executive summary, and stripping them at
  the boundary is defense-in-depth against prompt-injection
  attacks that try to exfiltrate them via sneaky completions.
  """
  if not isinstance(engagement, dict):
    return {}
  return {
    "client_name": _sanitize(engagement.get("client_name", ""), 120),
    "engagement_code": _sanitize(engagement.get("engagement_code", ""), 60),
    "primary_objective": _sanitize(engagement.get("primary_objective", ""), 240),
    "secondary_objective": _sanitize(engagement.get("secondary_objective", ""), 240),
    "scope_rationale": _sanitize(engagement.get("scope_rationale", ""), 600),
    "data_classification": _sanitize(engagement.get("data_classification", ""), 32),
    "asset_exposure": _sanitize(engagement.get("asset_exposure", ""), 32),
    "methodology": _sanitize(engagement.get("methodology", ""), 240),
    # PoC / emergency contacts intentionally dropped — see docstring.
  }


def _summarize_scan(
  aggregated: dict | None,
  *,
  total_findings: int,
  included_findings: int,
  truncated_findings: int,
) -> dict:
  """Extract count-style summary from aggregated_report. Raw blobs
  (service_info, web_tests_info, graybox_results) are dropped."""
  out = {
    "total_findings": int(total_findings),
    "included_findings": int(included_findings),
    "truncated_findings": int(truncated_findings),
    "open_ports_count": 0,
    "services_count": 0,
    "routes_discovered": 0,
    "scenarios_tested": 0,
    "scan_type": "",
  }
  if not isinstance(aggregated, dict):
    return out

  open_ports = aggregated.get("open_ports") or []
  if isinstance(open_ports, (list, tuple)):
    out["open_ports_count"] = len(open_ports)

  service_info = aggregated.get("service_info") or {}
  if isinstance(service_info, dict):
    out["services_count"] = len(service_info)

  out["scan_type"] = _sanitize(aggregated.get("scan_type", ""), 32)

  # Graybox-specific count fields
  graybox = aggregated.get("graybox_results") or {}
  if isinstance(graybox, dict):
    routes = aggregated.get("scenario_stats") or {}
    if isinstance(routes, dict):
      out["routes_discovered"] = int(routes.get("routes_discovered", 0) or 0)
      out["scenarios_tested"] = int(routes.get("scenarios_tested", 0) or 0)

  return out


def _sanitize_finding(f: dict) -> dict:
  """Sanitize and strip a finding dict to the LLM-safe subset.

  KEEP (operator/probe-controlled fields, sanitized):
    finding_signature, severity, title, description, impact,
    remediation (sanitized), cvss_score, cvss_vector, cve, cwe,
    owasp_top10, kev, epss_score, references (capped),
    affected_assets (host/port/url only — no full request bodies).
    evidence_items: caption + length-capped snippet only — full
    bodies live in R1FS via cid; LLM doesn't need them.

  DROP (raw target output, never forwarded):
    Anything not in the explicit allowlist above.
  """
  if not isinstance(f, dict):
    return {}
  out: dict[str, Any] = {
    "finding_signature": _sanitize(f.get("finding_signature", ""), 96),
    "severity": _sanitize(f.get("severity", ""), 32).upper(),
    "title": _sanitize(f.get("title", ""), MAX_FINDING_TITLE_CHARS),
    "description": _sanitize(f.get("description", ""), MAX_FINDING_DESCRIPTION_CHARS),
    "impact": _sanitize(f.get("impact", ""), MAX_FINDING_IMPACT_CHARS),
    "confidence": _sanitize(f.get("confidence", ""), 32),
    "owasp_id": _sanitize(f.get("owasp_id", ""), 32),
    "cwe_id": _sanitize(f.get("cwe_id", ""), 32),
    "cvss_vector": _sanitize(f.get("cvss_vector", ""), 120),
    "cvss_score": _safe_float(f.get("cvss_score")),
    "kev": bool(f.get("kev", False)),
    "epss_score": _safe_float(f.get("epss_score")),
    "cve": _sanitize_list(f.get("cve"), MAX_REFERENCES_PER_FINDING, 32),
    "cwe": [int(x) for x in (f.get("cwe") or []) if isinstance(x, int) and x > 0][:8],
    "owasp_top10": _sanitize_list(f.get("owasp_top10"), 10, 16),
    "references": _sanitize_list(f.get("references"), MAX_REFERENCES_PER_FINDING, 240),
    "tags": _sanitize_list(f.get("tags"), MAX_TAGS_PER_FINDING, 32),
    "affected_assets": _sanitize_assets(f.get("affected_assets")),
    "evidence_items": _sanitize_evidence(f.get("evidence_items")),
    # NOTE: legacy `evidence: str` field is *not* forwarded — it's
    # raw probe output. Use evidence_items instead (Phase 1 schema).
  }
  return out


def _safe_float(v: Any) -> float | None:
  if isinstance(v, (int, float)):
    return float(v)
  return None


def _sanitize_assets(assets: Any) -> list[dict]:
  if not isinstance(assets, (list, tuple)):
    return []
  out = []
  for a in assets[:MAX_AFFECTED_ASSETS_PER_FINDING]:
    if not isinstance(a, dict):
      continue
    out.append({
      "host": _sanitize(a.get("host", ""), 240),
      "port": int(a["port"]) if isinstance(a.get("port"), int) else None,
      "url": _sanitize(a.get("url", "") or "", 240),
      "parameter": _sanitize(a.get("parameter", "") or "", 120),
      "method": _sanitize(a.get("method", "") or "", 16).upper(),
    })
  return out


def _sanitize_evidence(items: Any) -> list[dict]:
  if not isinstance(items, (list, tuple)):
    return []
  out = []
  for e in items[:5]:
    if not isinstance(e, dict):
      continue
    out.append({
      "kind": _sanitize(e.get("kind", ""), 32),
      "caption": _sanitize(e.get("caption", ""), MAX_EVIDENCE_CAPTION_CHARS),
      # snippet is the only field that may carry target output, so
      # we cap it AND apply the full sanitizer (which neutralizes
      # injection sentinels). Full content stays in R1FS via cid.
      "snippet": _sanitize(e.get("snippet", "") or "", MAX_EVIDENCE_SNIPPET_CHARS),
      "cid": _sanitize(e.get("cid", "") or "", 96),
    })
  return out
