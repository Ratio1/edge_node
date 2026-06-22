from __future__ import annotations

from dataclasses import dataclass, asdict

from extensions.business.cybersec.red_mesh.models.shared import _strip_none


VALID_TRIAGE_STATUSES = frozenset({
  "open",
  "accepted_risk",
  "false_positive",
  "remediated",
  "reopened",
})


@dataclass(frozen=True)
class FindingTriageState:
  job_id: str
  finding_id: str
  status: str = "open"
  note: str = ""
  actor: str = ""
  updated_at: float = 0.0
  review_at: float = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> "FindingTriageState":
    status = d.get("status", "open")
    if status not in VALID_TRIAGE_STATUSES:
      raise ValueError(f"Unsupported triage status: {status}")
    return cls(
      job_id=d["job_id"],
      finding_id=d["finding_id"],
      status=status,
      note=d.get("note", ""),
      actor=d.get("actor", ""),
      updated_at=float(d.get("updated_at", 0.0) or 0.0),
      review_at=d.get("review_at"),
    )


@dataclass(frozen=True)
class FindingTriageAuditEntry:
  job_id: str
  finding_id: str
  status: str
  note: str = ""
  actor: str = ""
  timestamp: float = 0.0

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> "FindingTriageAuditEntry":
    status = d.get("status", "open")
    if status not in VALID_TRIAGE_STATUSES:
      raise ValueError(f"Unsupported triage status: {status}")
    return cls(
      job_id=d["job_id"],
      finding_id=d["finding_id"],
      status=status,
      note=d.get("note", ""),
      actor=d.get("actor", ""),
      timestamp=float(d.get("timestamp", 0.0) or 0.0),
    )
