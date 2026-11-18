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
  # Host-scoped records (report-findings.md §Triage): the tenant and host of the writer's execution
  # binding, `job_id` being the job that wrote it. None for a legacy job-keyed record.
  tenant_id: str = None
  host: str = None
  confirmed: bool = None
  confirmed_by: str = None
  # The id of the audit entry this change writes, so a retry can finish a lost entry exactly once.
  audit_entry_id: str = None

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
      tenant_id=d.get("tenant_id"),
      host=d.get("host"),
      confirmed=True if d.get("confirmed") is True else None,
      confirmed_by=d.get("confirmed_by"),
      audit_entry_id=d.get("audit_entry_id"),
    )


@dataclass(frozen=True)
class FindingTriageAuditEntry:
  job_id: str
  finding_id: str
  status: str
  note: str = ""
  actor: str = ""
  timestamp: float = 0.0
  tenant_id: str = None
  host: str = None

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
      tenant_id=d.get("tenant_id"),
      host=d.get("host"),
    )
