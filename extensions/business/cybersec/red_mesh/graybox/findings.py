"""
Structured findings for authenticated webapp (graybox) probes.

GrayboxFinding is the probe-level finding type. It is converted to a
unified flat finding dict (matching blackbox findings) at the report
level via to_flat_finding(). The blackbox Finding in findings.py is
NOT modified.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any


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
    id_input = f"{port}:{probe_name}:{cwe_canonical}:{canon_title}"
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

    return {
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
    }

  @classmethod
  def flat_from_dict(cls, payload: dict[str, Any], port: int, protocol: str, probe_name: str) -> dict[str, Any]:
    """Normalize a persisted graybox finding dict into the flat report contract."""
    return cls.from_dict(payload).to_flat_finding(port, protocol, probe_name)
