"""Runtime scenario manifest for graybox API scheduling."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


GRAYBOX_ASSIGNMENT_MIRROR = "MIRROR"
GRAYBOX_ASSIGNMENT_SLICE = "SLICE"
GRAYBOX_BUDGET_PER_WORKER = "per_worker"
GRAYBOX_BUDGET_PER_SCAN = "per_scan"
GRAYBOX_DEFAULT_REQUEST_BUDGET = 1000


@dataclass(frozen=True)
class RuntimeScenario:
  scenario_id: str
  probe_key: str
  runner: str
  stateful: bool = False
  mutating: bool = False
  requires_regular: bool = False
  estimated_budget: int = 1
  single_writer_group: str = ""

  def to_dict(self) -> dict:
    return {
      "scenario_id": self.scenario_id,
      "probe_key": self.probe_key,
      "runner": self.runner,
      "stateful": self.stateful,
      "mutating": self.mutating,
      "requires_regular": self.requires_regular,
      "estimated_budget": self.estimated_budget,
      "single_writer_group": self.single_writer_group,
    }


API_RUNTIME_SCENARIOS = (
  RuntimeScenario(
    "PT-OAPI1-01", "_graybox_api_access", "_test_api_bola",
    requires_regular=True, estimated_budget=4,
  ),
  RuntimeScenario(
    "PT-OAPI2-01", "_graybox_api_auth", "_test_jwt_alg_none",
    estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI2-02", "_graybox_api_auth", "_test_jwt_weak_hmac",
    estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI2-03", "_graybox_api_auth",
    "_test_token_logout_invalidation",
    stateful=True, mutating=True, estimated_budget=3,
    single_writer_group="api_auth_token",
  ),
  RuntimeScenario(
    "PT-OAPI3-01", "_graybox_api_data",
    "_test_api_property_exposure",
    estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI3-02", "_graybox_api_data",
    "_test_api_property_tampering",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=3, single_writer_group="api_data_property",
  ),
  RuntimeScenario(
    "PT-OAPI4-01", "_graybox_api_abuse",
    "_test_no_pagination_cap", estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI4-02", "_graybox_api_abuse",
    "_test_oversized_payload", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI4-03", "_graybox_api_abuse",
    "_test_no_rate_limit", estimated_budget=5,
  ),
  RuntimeScenario(
    "PT-OAPI5-01", "_graybox_api_access",
    "_test_bfla_regular_as_admin",
    requires_regular=True, estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI5-02", "_graybox_api_access",
    "_test_bfla_anon_as_user", estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI5-03", "_graybox_api_access",
    "_test_bfla_method_override",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=3, single_writer_group="api_access_function",
  ),
  RuntimeScenario(
    "PT-OAPI5-04", "_graybox_api_access",
    "_test_bfla_regular_as_admin_mutating",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=3, single_writer_group="api_access_function",
  ),
  RuntimeScenario(
    "PT-OAPI6-01", "_graybox_api_abuse",
    "_test_flow_no_rate_limit",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=5, single_writer_group="api_abuse_flow",
  ),
  RuntimeScenario(
    "PT-OAPI6-02", "_graybox_api_abuse",
    "_test_flow_no_uniqueness",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=2, single_writer_group="api_abuse_flow",
  ),
  RuntimeScenario(
    "PT-OAPI8-01", "_graybox_api_config",
    "_test_cors_misconfig", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI8-02", "_graybox_api_config",
    "_test_security_headers", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI8-03", "_graybox_api_config",
    "_test_debug_endpoint_exposed", estimated_budget=3,
  ),
  RuntimeScenario(
    "PT-OAPI8-04", "_graybox_api_config",
    "_test_verbose_error", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI8-05", "_graybox_api_config",
    "_test_unexpected_methods", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI9-01", "_graybox_api_config",
    "_test_openapi_exposed", estimated_budget=3,
  ),
  RuntimeScenario(
    "PT-OAPI9-02", "_graybox_api_config",
    "_test_version_sprawl", estimated_budget=3,
  ),
  RuntimeScenario(
    "PT-OAPI9-03", "_graybox_api_config",
    "_test_deprecated_live", estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-API7-01", "_graybox_injection", "_test_ssrf",
    estimated_budget=2,
  ),
)


def runtime_scenarios() -> tuple[RuntimeScenario, ...]:
  return API_RUNTIME_SCENARIOS


def runtime_scenario_ids() -> tuple[str, ...]:
  return tuple(item.scenario_id for item in API_RUNTIME_SCENARIOS)


def runtime_scenarios_for_probe(probe_key: str) -> tuple[RuntimeScenario, ...]:
  return tuple(item for item in API_RUNTIME_SCENARIOS if item.probe_key == probe_key)


def runtime_scenario_by_id(scenario_id: str) -> RuntimeScenario | None:
  for item in API_RUNTIME_SCENARIOS:
    if item.scenario_id == scenario_id:
      return item
  return None


def _normalized_strategy(strategy: str) -> str:
  value = (strategy or GRAYBOX_ASSIGNMENT_MIRROR).upper()
  if value not in (GRAYBOX_ASSIGNMENT_MIRROR, GRAYBOX_ASSIGNMENT_SLICE):
    return ""
  return value


def _assignment_hash_payload(
  *,
  strategy: str,
  assigned_scenario_ids: tuple[str, ...],
  assigned_request_budget: int,
  budget_scope: str,
  assignment_revision: int,
  stateful_policy: str,
) -> dict:
  return {
    "graybox_assignment_strategy": strategy,
    "assigned_scenario_ids": list(assigned_scenario_ids),
    "assigned_request_budget": int(assigned_request_budget or 0),
    "budget_scope": budget_scope,
    "assignment_revision": int(assignment_revision or 1),
    "stateful_policy": stateful_policy,
  }


def compute_assignment_hash(
  *,
  strategy: str,
  assigned_scenario_ids,
  assigned_request_budget: int,
  budget_scope: str,
  assignment_revision: int,
  stateful_policy: str,
) -> str:
  payload = _assignment_hash_payload(
    strategy=strategy,
    assigned_scenario_ids=tuple(assigned_scenario_ids or ()),
    assigned_request_budget=assigned_request_budget,
    budget_scope=budget_scope,
    assignment_revision=assignment_revision,
    stateful_policy=stateful_policy,
  )
  raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
  return hashlib.sha256(raw).hexdigest()[:24]


@dataclass(frozen=True)
class GrayboxWorkerAssignment:
  strategy: str
  assigned_scenario_ids: tuple[str, ...]
  assigned_request_budget: int
  budget_scope: str
  assignment_revision: int
  assignment_hash: str
  stateful_policy: str = "disabled"
  validation_error: str = ""

  @property
  def is_valid(self) -> bool:
    return not self.validation_error

  def to_dict(self) -> dict:
    return {
      "graybox_assignment_strategy": self.strategy,
      "assigned_scenario_ids": list(self.assigned_scenario_ids),
      "assigned_request_budget": self.assigned_request_budget,
      "budget_scope": self.budget_scope,
      "assignment_revision": self.assignment_revision,
      "assignment_hash": self.assignment_hash,
      "stateful_policy": self.stateful_policy,
    }

  @classmethod
  def invalid(cls, reason: str) -> "GrayboxWorkerAssignment":
    return cls(
      strategy="",
      assigned_scenario_ids=(),
      assigned_request_budget=0,
      budget_scope="",
      assignment_revision=0,
      assignment_hash="",
      stateful_policy="",
      validation_error=reason,
    )

  @classmethod
  def from_job_config(cls, job_config) -> "GrayboxWorkerAssignment":
    raw_ids = getattr(job_config, "assigned_scenario_ids", None)
    if raw_ids is None:
      return cls.invalid("missing_assigned_scenario_ids")
    if not isinstance(raw_ids, (list, tuple)):
      return cls.invalid("assigned_scenario_ids_must_be_list")

    assigned_scenario_ids = tuple(str(item) for item in raw_ids)
    known_ids = set(runtime_scenario_ids())
    unknown = [item for item in assigned_scenario_ids if item not in known_ids]
    if unknown:
      return cls.invalid("unknown_assigned_scenario_ids:" + ",".join(unknown))

    strategy = _normalized_strategy(
      getattr(job_config, "graybox_assignment_strategy", "")
    )
    if not strategy:
      return cls.invalid("unknown_graybox_assignment_strategy")

    budget_scope = getattr(job_config, "budget_scope", "") or ""
    if budget_scope not in (GRAYBOX_BUDGET_PER_WORKER, GRAYBOX_BUDGET_PER_SCAN):
      return cls.invalid("unknown_budget_scope")

    try:
      assigned_request_budget = int(
        getattr(job_config, "assigned_request_budget", 0) or 0
      )
    except (TypeError, ValueError):
      return cls.invalid("invalid_assigned_request_budget")
    if assigned_request_budget <= 0:
      return cls.invalid("invalid_assigned_request_budget")

    try:
      assignment_revision = int(
        getattr(job_config, "assignment_revision", 0) or 0
      )
    except (TypeError, ValueError):
      return cls.invalid("invalid_assignment_revision")
    if assignment_revision <= 0:
      return cls.invalid("invalid_assignment_revision")

    stateful_policy = getattr(job_config, "stateful_policy", "") or "disabled"
    assignment_hash = getattr(job_config, "assignment_hash", "") or ""
    expected_hash = compute_assignment_hash(
      strategy=strategy,
      assigned_scenario_ids=assigned_scenario_ids,
      assigned_request_budget=assigned_request_budget,
      budget_scope=budget_scope,
      assignment_revision=assignment_revision,
      stateful_policy=stateful_policy,
    )
    if assignment_hash != expected_hash:
      return cls.invalid("assignment_hash_mismatch")

    return cls(
      strategy=strategy,
      assigned_scenario_ids=assigned_scenario_ids,
      assigned_request_budget=assigned_request_budget,
      budget_scope=budget_scope,
      assignment_revision=assignment_revision,
      assignment_hash=assignment_hash,
      stateful_policy=stateful_policy,
    )


def build_graybox_worker_assignments(
  worker_addresses,
  *,
  strategy: str = GRAYBOX_ASSIGNMENT_SLICE,
  total_request_budget: int = GRAYBOX_DEFAULT_REQUEST_BUDGET,
  allow_stateful: bool = False,
  allow_mirror_stateful: bool = False,
  allow_mirror_per_worker_budget: bool = False,
  assignment_revision: int = 1,
):
  """Return launcher-owned per-worker API scenario assignments.

  Defaults to SLICE so the per-scan request budget is split across
  workers (PR406 B5). MIRROR remains explicit and, when more than one
  worker is selected, requires ``allow_mirror_per_worker_budget=True``
  to acknowledge that total traffic is workers × budget; otherwise the
  budget is divided across workers (budget_scope=per_scan).
  """
  addresses = [addr for addr in (worker_addresses or []) if addr]
  if not addresses:
    return None, "No workers available for graybox assignment."

  strategy = _normalized_strategy(strategy)
  if not strategy:
    return None, "graybox_assignment_strategy must be MIRROR or SLICE."

  if (
    strategy == GRAYBOX_ASSIGNMENT_MIRROR
    and allow_stateful
    and len(addresses) > 1
    and not allow_mirror_stateful
  ):
    return (
      None,
      "MIRROR with stateful graybox probes requires an explicit "
      "allow_mirror_stateful override or a single selected worker.",
    )

  raw_budget = (
    GRAYBOX_DEFAULT_REQUEST_BUDGET
    if total_request_budget is None else total_request_budget
  )
  try:
    total_budget = int(raw_budget)
  except (TypeError, ValueError):
    return None, "total_request_budget must be a positive integer."
  if total_budget <= 0:
    return None, "total_request_budget must be a positive integer."

  scenario_ids = runtime_scenario_ids()
  stateful_policy = "enabled" if allow_stateful else "disabled"
  assignments = {}
  if strategy == GRAYBOX_ASSIGNMENT_MIRROR:
    if len(addresses) > 1 and allow_mirror_per_worker_budget:
      mirror_budget = total_budget
      mirror_budget_scope = GRAYBOX_BUDGET_PER_WORKER
    elif len(addresses) > 1:
      # Multi-worker MIRROR without explicit per-worker budget opt-in:
      # divide the per-scan budget across workers so total traffic stays
      # bounded by max_total_requests instead of workers × budget.
      base_budget, budget_remainder = divmod(total_budget, len(addresses))
      mirror_budget = None  # computed per worker below
      mirror_budget_scope = GRAYBOX_BUDGET_PER_SCAN
    else:
      mirror_budget = total_budget
      mirror_budget_scope = GRAYBOX_BUDGET_PER_WORKER

    for index, address in enumerate(addresses):
      if mirror_budget is None:
        assigned_budget = max(1, base_budget + (1 if index < budget_remainder else 0))
      else:
        assigned_budget = mirror_budget
      assignment = GrayboxWorkerAssignment(
        strategy=strategy,
        assigned_scenario_ids=scenario_ids,
        assigned_request_budget=assigned_budget,
        budget_scope=mirror_budget_scope,
        assignment_revision=assignment_revision,
        assignment_hash="",
        stateful_policy=stateful_policy,
      )
      assignments[address] = _with_assignment_hash(assignment).to_dict()
    return assignments, None

  base_budget, budget_remainder = divmod(total_budget, len(addresses))
  for index, address in enumerate(addresses):
    ids = tuple(scenario_ids[index::len(addresses)])
    assigned_budget = max(1, base_budget + (1 if index < budget_remainder else 0))
    assignment = GrayboxWorkerAssignment(
      strategy=strategy,
      assigned_scenario_ids=ids,
      assigned_request_budget=assigned_budget,
      budget_scope=GRAYBOX_BUDGET_PER_SCAN,
      assignment_revision=assignment_revision,
      assignment_hash="",
      stateful_policy=stateful_policy,
    )
    assignments[address] = _with_assignment_hash(assignment).to_dict()
  return assignments, None


_LEGACY_ASSIGNMENT_FIELDS = (
  "graybox_assignment_strategy",
  "assigned_scenario_ids",
  "assigned_request_budget",
  "budget_scope",
  "assignment_hash",
)


def synthesize_legacy_mirror_assignment(
  job_config: dict | None,
  worker_entry: dict | None,
) -> dict | None:
  """Build a compat MIRROR assignment for assignmentless webapp jobs (PR406 B7).

  Returns a dict matching ``GrayboxWorkerAssignment.to_dict()`` plus an
  ``assignment_compat_mode`` audit marker. Returns None when:

    * the worker entry already carries at least one new assignment
      field (partial/corrupt — must fail closed);
    * the entry is not a dict;
    * the entry already includes an explicit compat marker.

  The synthesized assignment runs all runtime scenarios with the
  per-scan budget derived from
  ``target_config.api_security.max_total_requests`` (or the default).
  """
  if not isinstance(worker_entry, dict):
    return None
  if worker_entry.get("assignment_compat_mode"):
    return None
  present = [
    field for field in _LEGACY_ASSIGNMENT_FIELDS
    if worker_entry.get(field) not in (None, "", 0, [], ())
  ]
  if present:
    # Any single new field present means this is a launcher-owned
    # assignment that just happens to be incomplete — refuse to
    # synthesize and let the normal validation reject it.
    return None

  budget = 0
  if isinstance(job_config, dict):
    api_security = job_config.get("target_config", {})
    if isinstance(api_security, dict):
      api_security = api_security.get("api_security") or {}
    if isinstance(api_security, dict):
      try:
        budget = int(api_security.get("max_total_requests") or 0)
      except (TypeError, ValueError):
        budget = 0
  if budget <= 0:
    budget = GRAYBOX_DEFAULT_REQUEST_BUDGET
  scenarios = runtime_scenario_ids()
  assignment = GrayboxWorkerAssignment(
    strategy=GRAYBOX_ASSIGNMENT_MIRROR,
    assigned_scenario_ids=scenarios,
    assigned_request_budget=budget,
    budget_scope=GRAYBOX_BUDGET_PER_WORKER,
    assignment_revision=1,
    assignment_hash="",
    stateful_policy="disabled",
  )
  result = _with_assignment_hash(assignment).to_dict()
  result["assignment_compat_mode"] = "legacy_mirror"
  return result


def rehash_worker_assignment_dict(worker_entry: dict) -> dict:
  """Recompute ``assignment_hash`` in place for a worker entry.

  Used after assignment-bearing fields change (notably
  ``assignment_revision`` during reannounce — PR406 B6) so the hash the
  worker validates against `JobConfig` stays in sync. Returns the same
  dict for chaining; if the entry is missing assignment fields, the
  hash field is left untouched.
  """
  if not isinstance(worker_entry, dict):
    return worker_entry
  strategy = (worker_entry.get("graybox_assignment_strategy") or "").upper()
  scenario_ids = worker_entry.get("assigned_scenario_ids")
  if not strategy or scenario_ids is None:
    return worker_entry
  worker_entry["assignment_hash"] = compute_assignment_hash(
    strategy=strategy,
    assigned_scenario_ids=tuple(scenario_ids or ()),
    assigned_request_budget=int(worker_entry.get("assigned_request_budget") or 0),
    budget_scope=worker_entry.get("budget_scope") or "",
    assignment_revision=int(worker_entry.get("assignment_revision") or 1),
    stateful_policy=worker_entry.get("stateful_policy") or "disabled",
  )
  return worker_entry


def summarize_graybox_worker_assignments(assignments: dict) -> dict:
  """Distil per-worker assignments into a job-level summary.

  When all workers agree on strategy/budget_scope, the summary surfaces
  them directly. When workers disagree (shouldn't happen with the
  launcher-owned model, but defends against legacy/manual edits), the
  summary records 'mixed' so the dashboard can flag it.
  """
  if not isinstance(assignments, dict) or not assignments:
    return {}
  strategies = set()
  budget_scopes = set()
  total_budget = 0
  scenarios: set[str] = set()
  worker_summary = []
  for addr, entry in assignments.items():
    if not isinstance(entry, dict):
      continue
    strategy = entry.get("graybox_assignment_strategy") or ""
    budget_scope = entry.get("budget_scope") or ""
    assigned_budget = int(entry.get("assigned_request_budget") or 0)
    assigned_scenarios = list(entry.get("assigned_scenario_ids") or [])
    if strategy:
      strategies.add(strategy)
    if budget_scope:
      budget_scopes.add(budget_scope)
    total_budget += assigned_budget
    scenarios.update(assigned_scenarios)
    worker_summary.append({
      "worker_address": addr,
      "graybox_assignment_strategy": strategy,
      "assigned_request_budget": assigned_budget,
      "budget_scope": budget_scope,
      "assigned_scenario_count": len(assigned_scenarios),
    })

  if len(strategies) == 1:
    strategy_value = next(iter(strategies))
  else:
    strategy_value = "mixed"
  if len(budget_scopes) == 1:
    budget_scope_value = next(iter(budget_scopes))
  else:
    budget_scope_value = "mixed"
  return {
    "graybox_assignment_strategy": strategy_value,
    "budget_scope": budget_scope_value,
    "assigned_request_budget": total_budget,
    "total_assigned_scenarios": len(scenarios),
    "worker_assignment_summary": worker_summary,
  }


def _with_assignment_hash(
  assignment: GrayboxWorkerAssignment,
) -> GrayboxWorkerAssignment:
  assignment_hash = compute_assignment_hash(
    strategy=assignment.strategy,
    assigned_scenario_ids=assignment.assigned_scenario_ids,
    assigned_request_budget=assignment.assigned_request_budget,
    budget_scope=assignment.budget_scope,
    assignment_revision=assignment.assignment_revision,
    stateful_policy=assignment.stateful_policy,
  )
  return GrayboxWorkerAssignment(
    strategy=assignment.strategy,
    assigned_scenario_ids=assignment.assigned_scenario_ids,
    assigned_request_budget=assignment.assigned_request_budget,
    budget_scope=assignment.budget_scope,
    assignment_revision=assignment.assignment_revision,
    assignment_hash=assignment_hash,
    stateful_policy=assignment.stateful_policy,
  )
