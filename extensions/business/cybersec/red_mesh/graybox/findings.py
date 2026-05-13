"""
Structured findings for authenticated webapp (graybox) probes.

GrayboxFinding is the probe-level finding type. It is converted to a
unified flat finding dict (matching blackbox findings) at the report
level via to_flat_finding(). The blackbox Finding in findings.py is
NOT modified.

Subphase 1.6 (centralised evidence scrubber): every finding traversing
to_flat_finding() passes through `scrub_graybox_secrets`, which strips
Authorization/Cookie/JWT/`password=…`/api_key/etc. patterns from the
evidence list, evidence_artifacts request/response snapshots, finding
description, title, and replay_steps. Probes still SHOULD redact at
emission time (via ProbeBase.emit_*), but the storage-boundary
scrubber is defense-in-depth — one forgetful probe author cannot leak
secrets into the archive, LLM input, or PDF.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, asdict, field
from typing import Any


# ── Centralised secret scrubber (Subphase 1.6 commit #2) ────────────────

# Generic patterns applied to every flat finding regardless of which
# AuthDescriptor was active. Configured names (X-Custom-Key, custom query
# params) are added to the per-call scrub via ``secret_field_names``
# when ProbeBase.emit_* invokes the scrubber with the live AuthDescriptor.
_SCRUB_PATTERNS = (
  # Whole-header redaction: redact the full value, which spans until the
  # next field separator (comma/semicolon/newline) or end of string.
  (re.compile(r"(?i)\b(authorization)\s*:\s*[^,\r\n;]+"), r"\1: <redacted>"),
  (re.compile(r"(?i)\b(cookie)\s*:\s*[^,\r\n;]+"), r"\1: <redacted>"),
  (re.compile(r"(?i)\b(set-cookie)\s*:\s*[^,\r\n;]+"), r"\1: <redacted>"),
  # JWT (3 base64url chunks separated by dots, leading eyJ).
  (re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}"),
   "<jwt-redacted>"),
  # Bearer schema in body / URL: keep prefix only.
  (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{8,}"), "Bearer <redacted>"),
  # Common name=value forms (cookie / form / URL query).
  (re.compile(r"(?i)\b(password|secret|token|api_key|apikey)=([^&\s\";,]+)"),
   r"\1=<redacted>"),
  # JSON-style key:value.
  (re.compile(r'(?i)"(password|secret|token|api_key|bearer_token|api[\w_-]*key)"\s*:\s*"[^"]+"'),
   r'"\1": "<redacted>"'),
)


def scrub_graybox_secrets(value: Any, *, secret_field_names: tuple[str, ...] = ()) -> Any:
  """Recursively redact known secret patterns from ``value``.

  Accepts strings, lists, tuples, dicts. Non-string leaves pass through.
  ``secret_field_names`` is a tuple of additional case-insensitive names
  (e.g. configured API-key header / query param names) to scrub on top of
  the generic pattern set.
  """
  if isinstance(value, str):
    out = value
    for pat, repl in _SCRUB_PATTERNS:
      out = pat.sub(repl, out)
    for name in secret_field_names:
      if not name:
        continue
      esc = re.escape(name)
      # name=val → name=<redacted>
      out = re.sub(rf"(?i)\b({esc})=([^&\s\";]+)", r"\1=<redacted>", out)
      # name: val (header form) → name: <redacted>
      out = re.sub(rf"(?i)\b({esc})\s*:\s*\S+", r"\1: <redacted>", out)
      # JSON "name":"val"
      out = re.sub(rf'(?i)"({esc})"\s*:\s*"[^"]+"', r'"\1": "<redacted>"', out)
    return out
  if isinstance(value, list):
    return [scrub_graybox_secrets(v, secret_field_names=secret_field_names) for v in value]
  if isinstance(value, tuple):
    return tuple(scrub_graybox_secrets(v, secret_field_names=secret_field_names) for v in value)
  if isinstance(value, dict):
    return {k: scrub_graybox_secrets(v, secret_field_names=secret_field_names) for k, v in value.items()}
  return value


def _scrub_flat_finding(flat: dict) -> dict:
  """Final storage-boundary pass on a flat finding dict.

  Targets the fields most likely to carry secret values:
    - title, description, evidence, replay_steps
    - evidence_artifacts (request/response snapshots, evidence_items)
  Other fields (severity, owasp_id, scenario_id, etc.) are policy-bound
  and pass through unchanged.
  """
  for key in ("title", "description", "evidence", "replay_steps", "remediation"):
    if key in flat:
      flat[key] = scrub_graybox_secrets(flat[key])
  if "evidence_artifacts" in flat and isinstance(flat["evidence_artifacts"], list):
    flat["evidence_artifacts"] = scrub_graybox_secrets(flat["evidence_artifacts"])
  return flat


@dataclass(frozen=True)
class GrayboxEvidenceArtifact:
  """Typed graybox evidence payload kept alongside legacy string summaries."""
  summary: str = ""
  request_snapshot: str = ""
  response_snapshot: str = ""
  captured_at: str = ""
  raw_evidence_cid: str = ""
  sensitive: bool = False

  @classmethod
  def from_value(cls, value: Any) -> "GrayboxEvidenceArtifact":
    if isinstance(value, GrayboxEvidenceArtifact):
      return value
    if isinstance(value, dict):
      return cls(
        summary=value.get("summary", "") or "",
        request_snapshot=value.get("request_snapshot", "") or "",
        response_snapshot=value.get("response_snapshot", "") or "",
        captured_at=value.get("captured_at", "") or "",
        raw_evidence_cid=value.get("raw_evidence_cid", "") or "",
        sensitive=bool(value.get("sensitive", False)),
      )
    if isinstance(value, str):
      return cls(summary=value)
    return cls()

  def to_dict(self) -> dict[str, Any]:
    return asdict(self)


@dataclass(frozen=True)
class GrayboxFinding:
  """
  Structured finding from an authenticated web-application probe.

  Uses structured evidence (list of key=value strings), multiple CWEs,
  MITRE ATT&CK IDs, and explicit status outcomes. Separate type from
  blackbox Finding — the two are normalized into a unified flat finding
  dict at the report level by _compute_risk_and_findings().
  """
  scenario_id: str                                  # e.g. "PT-A01-01"
  title: str
  status: str                                       # "vulnerable" | "not_vulnerable" | "inconclusive"
  severity: str                                     # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
  owasp: str                                        # e.g. "A01:2021"
  cwe: list[str] = field(default_factory=list)      # e.g. ["CWE-639", "CWE-862"]
  attack: list[str] = field(default_factory=list)   # MITRE ATT&CK IDs e.g. ["T1078"]
  evidence: list[str] = field(default_factory=list) # ["endpoint=http://...", "status=200"]
  evidence_artifacts: list[GrayboxEvidenceArtifact | dict] = field(default_factory=list)
  replay_steps: list[str] = field(default_factory=list)  # reproducibility steps
  remediation: str = ""
  error: str | None = None                          # non-None if probe had an error
  cvss_score: float | None = None
  cvss_vector: str = ""
  # OWASP API Top 10 — Subphase 1.8. Stateful-probe rollback outcome.
  # Populated by ProbeBase.run_stateful; remains "" for non-stateful
  # findings. Renders as a badge in the Navigator UI (Phase 8.3) and in
  # the PDF report when revert_failed (Phase 8.4 red-bordered note).
  rollback_status: str = ""                         # "" | "reverted" | "revert_failed" | "no_revert_needed"

  @classmethod
  def from_dict(cls, payload: dict[str, Any]) -> "GrayboxFinding":
    """Compatibility-safe constructor for persisted finding dicts."""
    if not isinstance(payload, dict):
      raise TypeError("GrayboxFinding payload must be a dict")
    data = {k: v for k, v in payload.items() if k in cls.__dataclass_fields__}
    data["evidence_artifacts"] = [
      GrayboxEvidenceArtifact.from_value(item)
      for item in data.get("evidence_artifacts", []) or []
    ]
    return cls(**data)

  def to_dict(self) -> dict[str, Any]:
    """JSON-safe serialization."""
    payload = asdict(self)
    payload["evidence_artifacts"] = [
      GrayboxEvidenceArtifact.from_value(item).to_dict()
      for item in self.evidence_artifacts
    ]
    return payload

  def _normalized_evidence_artifacts(self) -> list[GrayboxEvidenceArtifact]:
    return [GrayboxEvidenceArtifact.from_value(item) for item in self.evidence_artifacts]

  def _flat_evidence_summary(self) -> str:
    evidence_lines = [line for line in self.evidence if isinstance(line, str) and line]
    if evidence_lines:
      return "; ".join(evidence_lines)
    artifact_summaries = [
      artifact.summary for artifact in self._normalized_evidence_artifacts()
      if artifact.summary
    ]
    return "; ".join(artifact_summaries)

  def to_flat_finding(self, port: int, protocol: str, probe_name: str) -> dict:
    """
    Normalize to the unified flat finding dict schema used in PassReport.findings.

    Converts structured graybox fields to the common schema that
    _compute_risk_and_findings() produces for all finding types.
    """
    import hashlib
    canon_title = self.title.lower().strip()
    cwe_joined = ", ".join(self.cwe)
    cwe_canonical = ", ".join(sorted({item.strip() for item in self.cwe if isinstance(item, str) and item.strip()}))
    evidence_identity = []
    for item in self.evidence:
      if not isinstance(item, str):
        continue
      if item.startswith(("endpoint=", "path=", "protected_path=", "token_path=", "flow=", "test_id=")):
        evidence_identity.append(item)
    id_input = (
      f"{port}:{probe_name}:{self.scenario_id}:{cwe_canonical}:"
      f"{canon_title}:{'|'.join(sorted(evidence_identity))}"
    )
    finding_id = hashlib.sha256(id_input.encode()).hexdigest()[:16]

    # Map status -> confidence and effective severity
    confidence_map = {
      "vulnerable": "certain",
      "not_vulnerable": "firm",
      "inconclusive": "tentative",
    }
    # not_vulnerable findings contribute zero to risk score —
    # override severity to INFO so they don't inflate finding_counts
    effective_severity = "INFO" if self.status == "not_vulnerable" else self.severity.upper()

    flat = {
      "finding_id": finding_id,
      "probe_type": "graybox",
      "severity": effective_severity,
      "title": self.title,
      "description": f"Scenario {self.scenario_id}: {self.title}",
      "owasp_id": self.owasp,
      "cwe_id": cwe_joined,
      "evidence": self._flat_evidence_summary(),
      "evidence_artifacts": [
        artifact.to_dict() for artifact in self._normalized_evidence_artifacts()
      ],
      "remediation": self.remediation,
      "confidence": confidence_map.get(self.status, "tentative"),
      "port": port,
      "protocol": protocol,
      "probe": probe_name,
      "category": "graybox",
      # graybox-only fields
      "scenario_id": self.scenario_id,
      "status": self.status,
      "replay_steps": list(self.replay_steps),
      "attack_ids": list(self.attack),
      "cvss_score": self.cvss_score,
      "cvss_vector": self.cvss_vector,
      "rollback_status": self.rollback_status,
    }
    return _scrub_flat_finding(flat)

  @classmethod
  def flat_from_dict(cls, payload: dict[str, Any], port: int, protocol: str, probe_name: str) -> dict[str, Any]:
    """Normalize a persisted graybox finding dict into the flat report contract."""
    return cls.from_dict(payload).to_flat_finding(port, protocol, probe_name)
