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

# The vocabulary `findings.py` used for `Finding.triage_state`, which
# `services/triage.py` never read. The two overlapped on exactly one value,
# `false_positive` — so `rulebook_assessment` comparing a `triage_state` against
# the live closed-status set matched that one and nothing else, and a finding
# remediated and marked `fixed` kept appearing in the compliance gap list.
#
# `confirmed` maps to `open`, not to a closed state: confirming a finding is
# real is the opposite of closing it.
_LEGACY_TRIAGE_ALIASES = {
  "new": "open",
  "confirmed": "open",
  "wont_fix": "accepted_risk",
  "fixed": "remediated",
}


def normalize_triage_status(value) -> str:
  """Return the live triage status for `value`, or `""` if it is not one.

  Unknown values normalise to empty rather than to a guess. Guessing a closed
  status would silently drop a finding out of the report; leaving it unmapped
  keeps it visible, which is the safe direction for a security tool.
  """
  text = str(value or "").strip().lower()
  if text in VALID_TRIAGE_STATUSES:
    return text
  return _LEGACY_TRIAGE_ALIASES.get(text, "")


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
