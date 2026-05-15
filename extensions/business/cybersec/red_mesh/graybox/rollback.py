"""Rollback journal primitives for graybox stateful probes."""

from __future__ import annotations

from dataclasses import dataclass, asdict


MUTATION_NOT_ATTEMPTED = "not_attempted"
MUTATION_ATTEMPTED_UNKNOWN = "attempted_unknown"
MUTATION_CONFIRMED = "confirmed"


@dataclass(frozen=True)
class StatefulMutationPlan:
  scenario_id: str
  method: str = ""
  path: str = ""
  body: dict | None = None
  revert_method: str = ""
  revert_path: str = ""
  revert_body: dict | None = None
  principal: str = ""
  operation_key: str = ""

  def to_dict(self) -> dict:
    return asdict(self)


class RollbackJournalRepository:
  """Worker-owned rollback journal.

  The repository writes into the worker state list by reference, so live
  status/report serialization can surface pending cleanup records without
  probes writing into the shared job document directly.
  """

  def __init__(
    self,
    *,
    job_id: str = "",
    worker_id: str = "",
    assignment_revision: int = 0,
    records: list | None = None,
  ):
    self.job_id = job_id
    self.worker_id = worker_id
    self.assignment_revision = assignment_revision
    self.records = records if records is not None else []

  def record_pending(self, scenario_id: str, plan=None) -> str:
    record_id = f"rollback-{len(self.records) + 1}"
    if isinstance(plan, StatefulMutationPlan):
      plan_dict = plan.to_dict()
    elif isinstance(plan, dict):
      plan_dict = dict(plan)
    else:
      plan_dict = {"scenario_id": scenario_id}
    plan_dict.setdefault("scenario_id", scenario_id)
    record = {
      "record_id": record_id,
      "job_id": self.job_id,
      "worker_id": self.worker_id,
      "assignment_revision": self.assignment_revision,
      "scenario_id": scenario_id,
      "status": "pending",
      "plan": plan_dict,
      "lease_owner": "",
      "lease_expires_at": 0,
    }
    self.records.append(record)
    return record_id

  def update_status(self, record_id: str, status: str, **extra) -> None:
    for record in self.records:
      if record.get("record_id") == record_id:
        record["status"] = status
        record.update(extra)
        return

  def pending_records(self) -> list[dict]:
    return [
      dict(record) for record in self.records
      if record.get("status") in ("pending", "manual_cleanup_required")
    ]

  def claim_pending(self, lease_owner: str, lease_expires_at: float = 0) -> list[dict]:
    claimed = []
    for record in self.records:
      if record.get("status") != "pending":
        continue
      record["lease_owner"] = lease_owner
      record["lease_expires_at"] = lease_expires_at
      record["status"] = "claimed"
      claimed.append(dict(record))
    return claimed

  def replay_claimed(self, revert_fn_by_record_id) -> None:
    """Replay claimed records with caller-provided idempotent revert fns."""
    for record in self.records:
      if record.get("status") != "claimed":
        continue
      fn = revert_fn_by_record_id.get(record.get("record_id"))
      if not callable(fn):
        record["status"] = "manual_cleanup_required"
        continue
      try:
        record["status"] = "reverted" if fn(record) else "manual_cleanup_required"
      except Exception:
        record["status"] = "manual_cleanup_required"
