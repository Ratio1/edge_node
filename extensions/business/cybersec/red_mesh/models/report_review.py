"""Report review record (RM-088, contract 2.0.0).

One row per job and scan pass: a named account approved or rejected the report
for that pass. An absent row is `pending`. No draft, no submission snapshot, no
idempotency key; the revision fence is the whole concurrency story. Contract:
`docs/resources/redmesh/contracts/report-review.md` in project-red-mesh.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from extensions.business.cybersec.red_mesh.models.shared import _strip_none


REPORT_REVIEW_CONTRACT_VERSION = "2.0.0"

VALID_REPORT_REVIEW_STATES = frozenset({"approved", "rejected"})


def _int_at_least_zero(value) -> int:
  try:
    return max(0, int(value or 0))
  except (TypeError, ValueError):
    return 0


def _submission_ref(value):
  """`{profile_id, revision, cid}` of the NIS2 submission an approval rested on, or ""."""
  if not isinstance(value, dict) or not value.get("cid"):
    return ""
  return {
    "profile_id": str(value.get("profile_id") or "")[:120],
    "revision": _int_at_least_zero(value.get("revision")),
    "cid": str(value.get("cid"))[:200],
  }


@dataclass(frozen=True)
class ReportReviewState:
  job_id: str
  pass_nr: int
  state: str = "approved"
  review_revision: int = 0
  reviewer: str = ""
  note: str = ""
  decided_at: str = ""
  nis2_submission_ref: object = ""
  contract_version: str = REPORT_REVIEW_CONTRACT_VERSION

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, payload: dict) -> "ReportReviewState":
    state = str(payload.get("state") or "").strip().lower()
    if state not in VALID_REPORT_REVIEW_STATES:
      raise ValueError(f"Unsupported report review state: {state}")
    version = str(payload.get("contract_version") or REPORT_REVIEW_CONTRACT_VERSION)
    if version != REPORT_REVIEW_CONTRACT_VERSION:
      raise ValueError(f"Unsupported report review contract version: {version}")
    pass_nr = _int_at_least_zero(payload.get("pass_nr"))
    if pass_nr < 1:
      raise ValueError("Report review requires a pass number")
    return cls(
      job_id=str(payload["job_id"]),
      pass_nr=pass_nr,
      state=state,
      review_revision=_int_at_least_zero(payload.get("review_revision")),
      reviewer=str(payload.get("reviewer") or "")[:200],
      note=str(payload.get("note") or "")[:1000],
      decided_at=str(payload.get("decided_at") or "")[:40],
      nis2_submission_ref=_submission_ref(payload.get("nis2_submission_ref")),
      contract_version=version,
    )


@dataclass(frozen=True)
class ReportReviewAuditEntry:
  job_id: str
  event_type: str
  state: str
  reviewer: str = ""
  note: str = ""
  review_revision: int = 0
  pass_nr: int = 0
  timestamp: str = ""

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, payload: dict) -> "ReportReviewAuditEntry":
    return cls(
      job_id=str(payload["job_id"]),
      event_type=str(payload.get("event_type") or "")[:80],
      state=str(payload.get("state") or "")[:20],
      reviewer=str(payload.get("reviewer") or "")[:200],
      note=str(payload.get("note") or "")[:1000],
      review_revision=_int_at_least_zero(payload.get("review_revision")),
      pass_nr=_int_at_least_zero(payload.get("pass_nr")),
      timestamp=str(payload.get("timestamp") or "")[:40],
    )
