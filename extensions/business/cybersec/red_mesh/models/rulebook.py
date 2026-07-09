from __future__ import annotations

from dataclasses import asdict, dataclass

from extensions.business.cybersec.red_mesh.models.shared import _strip_none


RULEBOOK_ASSESSMENT_SCHEMA = "redmesh.rulebook_assessment.v1"
RULEBOOK_ASSESSMENT_SCHEMA_VERSION = "1.0.0"

VALID_RULEBOOK_CHECK_STATUSES = frozenset({
  "supported",
  "gap",
  "needs_review",
  "not_observable",
  "not_applicable",
})

VALID_RULEBOOK_REVIEW_STATES = frozenset({
  "draft",
  "reviewed",
})

VALID_RULEBOOK_ANSWER_VALUES = frozenset({
  "yes",
  "no",
  "unknown",
  "not_applicable",
})


def _coerce_answers(value):
  if not isinstance(value, dict):
    return {}
  answers = {}
  for question_id, raw_answer in value.items():
    if not isinstance(question_id, str) or not question_id.strip():
      continue
    payload = raw_answer if isinstance(raw_answer, dict) else {"value": raw_answer}
    answer_value = str(payload.get("value") or "unknown").strip().lower()
    if answer_value not in VALID_RULEBOOK_ANSWER_VALUES:
      answer_value = "unknown"
    answers[question_id.strip()] = _strip_none({
      "value": answer_value,
      "note": str(payload.get("note") or "")[:1000],
      "reviewer": str(payload.get("reviewer") or "")[:200],
      "updated_at": float(payload.get("updated_at", 0.0) or 0.0),
    })
  return answers


@dataclass(frozen=True)
class RulebookReviewState:
  job_id: str
  profile_id: str
  profile_version: str = ""
  review_state: str = "draft"
  reviewer: str = ""
  note: str = ""
  answers: dict = None
  updated_at: float = 0.0

  def to_dict(self) -> dict:
    return _strip_none({
      **asdict(self),
      "answers": _coerce_answers(self.answers),
    })

  @classmethod
  def from_dict(cls, payload: dict) -> "RulebookReviewState":
    review_state = str(payload.get("review_state") or "draft").strip().lower()
    if review_state not in VALID_RULEBOOK_REVIEW_STATES:
      raise ValueError(f"Unsupported rulebook review state: {review_state}")
    return cls(
      job_id=str(payload["job_id"]),
      profile_id=str(payload["profile_id"]),
      profile_version=str(payload.get("profile_version") or ""),
      review_state=review_state,
      reviewer=str(payload.get("reviewer") or "")[:200],
      note=str(payload.get("note") or "")[:1000],
      answers=_coerce_answers(payload.get("answers")),
      updated_at=float(payload.get("updated_at", 0.0) or 0.0),
    )


@dataclass(frozen=True)
class RulebookReviewAuditEntry:
  job_id: str
  profile_id: str
  profile_version: str
  review_state: str
  reviewer: str = ""
  note: str = ""
  changed_question_ids: list = None
  previous_answers: dict = None
  current_answers: dict = None
  timestamp: float = 0.0

  def to_dict(self) -> dict:
    return _strip_none({
      **asdict(self),
      "changed_question_ids": list(self.changed_question_ids or []),
      "previous_answers": _coerce_answers(self.previous_answers),
      "current_answers": _coerce_answers(self.current_answers),
    })

  @classmethod
  def from_dict(cls, payload: dict) -> "RulebookReviewAuditEntry":
    review_state = str(payload.get("review_state") or "draft").strip().lower()
    if review_state not in VALID_RULEBOOK_REVIEW_STATES:
      raise ValueError(f"Unsupported rulebook review state: {review_state}")
    return cls(
      job_id=str(payload["job_id"]),
      profile_id=str(payload["profile_id"]),
      profile_version=str(payload.get("profile_version") or ""),
      review_state=review_state,
      reviewer=str(payload.get("reviewer") or "")[:200],
      note=str(payload.get("note") or "")[:1000],
      changed_question_ids=[
        str(item)
        for item in (payload.get("changed_question_ids") or [])
        if isinstance(item, str) and item
      ],
      previous_answers=_coerce_answers(payload.get("previous_answers")),
      current_answers=_coerce_answers(payload.get("current_answers")),
      timestamp=float(payload.get("timestamp", 0.0) or 0.0),
    )
