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
  strategy: str = GRAYBOX_ASSIGNMENT_MIRROR,
  total_request_budget: int = GRAYBOX_DEFAULT_REQUEST_BUDGET,
  allow_stateful: bool = False,
  allow_mirror_stateful: bool = False,
  assignment_revision: int = 1,
):
  """Return launcher-owned per-worker API scenario assignments."""
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

  try:
    total_budget = int(total_request_budget or GRAYBOX_DEFAULT_REQUEST_BUDGET)
  except (TypeError, ValueError):
    total_budget = GRAYBOX_DEFAULT_REQUEST_BUDGET
  total_budget = max(1, total_budget)

  scenario_ids = runtime_scenario_ids()
  stateful_policy = "enabled" if allow_stateful else "disabled"
  assignments = {}
  if strategy == GRAYBOX_ASSIGNMENT_MIRROR:
    for address in addresses:
      assignment = GrayboxWorkerAssignment(
        strategy=strategy,
        assigned_scenario_ids=scenario_ids,
        assigned_request_budget=total_budget,
        budget_scope=GRAYBOX_BUDGET_PER_WORKER,
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
