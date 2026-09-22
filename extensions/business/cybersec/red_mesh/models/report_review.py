"""Report-level review record (RM-086 item 4).

One row per job: a named account approved the report as a whole, or withdrew
that approval. No draft, no submission snapshot, no idempotency key; the
revision fence is the whole concurrency story. Contract:
`docs/resources/redmesh/contracts/report-review.md` in project-red-mesh.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from extensions.business.cybersec.red_mesh.models.shared import _strip_none


REPORT_REVIEW_CONTRACT_VERSION = "1.0.0"

VALID_REPORT_REVIEW_STATES = frozenset({"approved", "reopened"})


def _int_at_least_zero(value) -> int:
  try:
    return max(0, int(value or 0))
  except (TypeError, ValueError):
    return 0


@dataclass(frozen=True)
class ReportReviewState:
  job_id: str
  state: str = "approved"
  review_revision: int = 0
  reviewer: str = ""
  note: str = ""
  approved_at: str = ""
  approved_pass_nr: int = 0
  reopened_at: str = ""
  reopened_by: str = ""
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
    return cls(
      job_id=str(payload["job_id"]),
      state=state,
      review_revision=_int_at_least_zero(payload.get("review_revision")),
      reviewer=str(payload.get("reviewer") or "")[:200],
      note=str(payload.get("note") or "")[:1000],
      approved_at=str(payload.get("approved_at") or "")[:40],
      approved_pass_nr=_int_at_least_zero(payload.get("approved_pass_nr")),
      reopened_at=str(payload.get("reopened_at") or "")[:40],
      reopened_by=str(payload.get("reopened_by") or "")[:200],
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
  approved_pass_nr: int = 0
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
      approved_pass_nr=_int_at_least_zero(payload.get("approved_pass_nr")),
      timestamp=str(payload.get("timestamp") or "")[:40],
    )
