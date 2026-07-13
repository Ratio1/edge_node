from __future__ import annotations

from dataclasses import asdict, dataclass

from extensions.business.cybersec.red_mesh.models.shared import _strip_none


RULEBOOK_ASSESSMENT_SCHEMA = "redmesh.rulebook_assessment.v1"
RULEBOOK_ASSESSMENT_SCHEMA_VERSION = "1.1.0"
RULEBOOK_SUBMISSION_CONTRACT_VERSION = "1.0.0"

VALID_RULEBOOK_CHECK_STATUSES = frozenset({
  "supported",
  "gap",
  "needs_review",
  "not_observable",
  "not_applicable",
})

VALID_RULEBOOK_REVIEW_STATES = frozenset({
  "draft",
  "submitted",
  "reviewed",
})

VALID_RULEBOOK_SUBMISSION_STATES = frozenset({
  "prepared",
  "artifact_written",
  "reference_recorded",
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
  review_revision: int = 0
  last_reopen_idempotency_key: str = ""
  last_reopen_from_revision: int = 0
  last_reopen_actor: str = ""

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
      review_revision=max(0, int(payload.get("review_revision", 0) or 0)),
      last_reopen_idempotency_key=str(payload.get("last_reopen_idempotency_key") or "")[:200],
      last_reopen_from_revision=max(0, int(payload.get("last_reopen_from_revision", 0) or 0)),
      last_reopen_actor=str(payload.get("last_reopen_actor") or "")[:200],
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
  review_revision: int = 0

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
      review_revision=max(0, int(payload.get("review_revision", 0) or 0)),
    )


@dataclass(frozen=True)
class RulebookSubmissionReference:
  revision: int
  cid: str
  submitted_at: float
  actor: str
  pass_nr: int
  profile_id: str
  profile_version: str
  schema_version: str
  review_revision: int
  idempotency_key: str = ""
  fingerprint: str = ""
  legacy: bool = False

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, payload: dict) -> "RulebookSubmissionReference":
    revision = int(payload.get("revision", 0) or 0)
    if revision < 0:
      raise ValueError("Submission revision cannot be negative")
    cid = str(payload.get("cid") or payload.get("artifact_cid") or "").strip()
    if not cid:
      raise ValueError("Submission reference requires a CID")
    return cls(
      revision=revision,
      cid=cid,
      submitted_at=float(payload.get("submitted_at", 0.0) or 0.0),
      actor=str(payload.get("actor") or "")[:200],
      pass_nr=max(0, int(payload.get("pass_nr", 0) or 0)),
      profile_id=str(payload.get("profile_id") or ""),
      profile_version=str(payload.get("profile_version") or ""),
      schema_version=str(payload.get("schema_version") or ""),
      review_revision=max(0, int(payload.get("review_revision", 0) or 0)),
      idempotency_key=str(payload.get("idempotency_key") or "")[:200],
      fingerprint=str(payload.get("fingerprint") or "")[:128],
      legacy=bool(payload.get("legacy", False)),
    )


@dataclass(frozen=True)
class RulebookPendingSubmission:
  target_revision: int
  expected_review_revision: int
  expected_pass_nr: int
  expected_profile_version: str
  actor: str
  idempotency_key: str
  fingerprint: str
  state: str = "prepared"
  created_at: float = 0.0
  updated_at: float = 0.0
  attempt_count: int = 1
  cid: str = ""
  last_error: dict = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, payload: dict) -> "RulebookPendingSubmission":
    state = str(payload.get("state") or "prepared")
    if state not in VALID_RULEBOOK_SUBMISSION_STATES:
      raise ValueError(f"Unsupported pending submission state: {state}")
    target_revision = int(payload.get("target_revision", 0) or 0)
    if target_revision < 1:
      raise ValueError("Pending submission requires a positive target revision")
    idempotency_key = str(payload.get("idempotency_key") or "").strip()
    fingerprint = str(payload.get("fingerprint") or "").strip()
    if not idempotency_key or not fingerprint:
      raise ValueError("Pending submission requires idempotency key and fingerprint")
    last_error = payload.get("last_error")
    return cls(
      target_revision=target_revision,
      expected_review_revision=max(0, int(payload.get("expected_review_revision", 0) or 0)),
      expected_pass_nr=max(0, int(payload.get("expected_pass_nr", 0) or 0)),
      expected_profile_version=str(payload.get("expected_profile_version") or ""),
      actor=str(payload.get("actor") or "")[:200],
      idempotency_key=idempotency_key[:200],
      fingerprint=fingerprint[:128],
      state=state,
      created_at=float(payload.get("created_at", 0.0) or 0.0),
      updated_at=float(payload.get("updated_at", 0.0) or 0.0),
      attempt_count=max(1, int(payload.get("attempt_count", 1) or 1)),
      cid=str(payload.get("cid") or ""),
      last_error=dict(last_error) if isinstance(last_error, dict) else None,
    )


@dataclass(frozen=True)
class RulebookSubmissionRegistry:
  contract_version: str = RULEBOOK_SUBMISSION_CONTRACT_VERSION
  latest_revision: int = 0
  submissions: list = None
  pending: dict = None

  def to_dict(self) -> dict:
    submissions = [
      item.to_dict() if isinstance(item, RulebookSubmissionReference) else RulebookSubmissionReference.from_dict(item).to_dict()
      for item in (self.submissions or [])
    ]
    pending = self.pending
    if isinstance(pending, RulebookPendingSubmission):
      pending = pending.to_dict()
    elif isinstance(pending, dict):
      pending = RulebookPendingSubmission.from_dict(pending).to_dict()
    return _strip_none({
      "contract_version": self.contract_version,
      "latest_revision": max([self.latest_revision] + [item["revision"] for item in submissions]),
      "submissions": submissions,
      "pending": pending,
    })

  @classmethod
  def from_dict(cls, payload: dict) -> "RulebookSubmissionRegistry":
    contract_version = str(payload.get("contract_version") or RULEBOOK_SUBMISSION_CONTRACT_VERSION)
    if contract_version != RULEBOOK_SUBMISSION_CONTRACT_VERSION:
      raise ValueError(f"Unsupported submission contract version: {contract_version}")
    submissions = [
      RulebookSubmissionReference.from_dict(item).to_dict()
      for item in (payload.get("submissions") or [])
      if isinstance(item, dict)
    ]
    pending_payload = payload.get("pending")
    pending = RulebookPendingSubmission.from_dict(pending_payload).to_dict() if isinstance(pending_payload, dict) else None
    latest_revision = max(
      [max(0, int(payload.get("latest_revision", 0) or 0))] + [item["revision"] for item in submissions]
    )
    return cls(
      contract_version=contract_version,
      latest_revision=latest_revision,
      submissions=submissions,
      pending=pending,
    )
