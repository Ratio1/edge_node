"""Immutable tenant execution values, not authentication or a reusable authorization lease."""
from dataclasses import dataclass
from copy import deepcopy
import json

from .assets import canonical_digest, canonical_uuid, normalize_target
from .identity import canonical_account_id
from .nodes import valid_node_address


_FACT_FIELDS = frozenset({"namespace", "tenant_id", "asset_id", "asset_target",
  "asset_target_digest", "actor_id", "actor_generation", "node_failure_policy"})
_BINDING_FIELDS = _FACT_FIELDS | {"schema_version", "original_launcher", "participant_order"}
_ROLLOUT_STAGES = ("compatibility", "draining", "tenant")


@dataclass(frozen=True)
class ExecutionRollout:
  """Known controls for one operation; config and persisted state cannot relax each other."""
  configured_stage: str
  configured_enabled: bool
  stored_stage: str
  stored_enabled: bool

  def __post_init__(self):
    if (self.configured_stage not in _ROLLOUT_STAGES or self.stored_stage not in _ROLLOUT_STAGES
        or type(self.configured_enabled) is not bool or type(self.stored_enabled) is not bool):
      raise ValueError("Invalid execution rollout controls")

  @property
  def stage(self):
    return _ROLLOUT_STAGES[max(_ROLLOUT_STAGES.index(self.configured_stage),
                               _ROLLOUT_STAGES.index(self.stored_stage))]

  def _matches(self, stage, enabled):
    return (self.configured_stage == self.stored_stage == stage
            and self.configured_enabled is enabled and self.stored_enabled is enabled)

  def allows_new(self, *, bound, membership_key_present=None, selectors_omitted=False):
    if type(bound) is not bool:
      return False
    if bound:
      return self._matches("tenant", True)
    return (self._matches("compatibility", False) and membership_key_present is False
            and selectors_omitted is True)

  def allows_existing(self, *, bound, operation="current", membership_key_present=None):
    if type(bound) is not bool or operation not in ("current", "new_pass"):
      return False
    if operation == "new_pass":
      return self.allows_new(bound=bound, membership_key_present=membership_key_present,
        selectors_omitted=True)
    if self.stage == "draining":
      return True
    return self._matches("tenant", True) if bound else self._matches("compatibility", False)


def _validate_facts(value, *, failure_policy=True):
  for name in ("namespace", "actor_generation"):
    text = value.get(name)
    if not isinstance(text, str) or not text.strip():
      raise ValueError("Invalid execution identity")
    text.encode("utf-8", errors="strict")
  for name, prefix in (("tenant_id", "tn_"), ("asset_id", "as_")):
    text = value.get(name)
    if not isinstance(text, str) or not text.startswith(prefix):
      raise ValueError("Invalid execution object identity")
    canonical_uuid(text[len(prefix):])
  actor = value.get("actor_id")
  if not actor or canonical_account_id(actor) != actor:
    raise ValueError("Invalid execution actor")
  target = normalize_target(value.get("asset_target"))
  if target != value["asset_target"] or canonical_digest(target) != value.get("asset_target_digest"):
    raise ValueError("Invalid execution target binding")
  if failure_policy and (not isinstance(value.get("node_failure_policy"), str)
                         or value["node_failure_policy"] not in ("stop", "continue")):
    raise ValueError("Invalid execution failure policy")


def _node_order(value):
  if (not isinstance(value, list) or not value or any(not valid_node_address(node) for node in value)
      or len(set(value)) != len(value)):
    raise ValueError("Invalid execution participant order")
  return value


def _snapshot(value):
  return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True, init=False)
class ExecutionBinding:
  """Strict wire value held as immutable JSON; each projection is a detached copy."""
  _snapshot: str

  def __init__(self, value):
    if not isinstance(value, dict) or set(value) != _BINDING_FIELDS:
      raise ValueError("Invalid execution binding fields")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
      raise ValueError("Unsupported execution binding version")
    _validate_facts(value)
    if not valid_node_address(value["original_launcher"]):
      raise ValueError("Invalid original launcher")
    _node_order(value["participant_order"])
    object.__setattr__(self, "_snapshot", _snapshot(value))

  def to_dict(self):
    return json.loads(self._snapshot)


@dataclass(frozen=True, init=False)
class ResolvedExecutionContext:
  """Current-operation facts; actual workers are supplied later by trusted assignment code."""
  _snapshot: str

  def __init__(self, value):
    if not isinstance(value, dict) or set(value) != _FACT_FIELDS | {"selected_candidates"}:
      raise ValueError("Invalid resolved execution fields")
    _validate_facts(value)
    _node_order(value["selected_candidates"])
    object.__setattr__(self, "_snapshot", _snapshot(value))

  def to_dict(self):
    return json.loads(self._snapshot)

  def build_binding(self, original_launcher, participant_order):
    participants = _node_order(participant_order)
    facts = self.to_dict()
    if not set(participants).issubset(facts.pop("selected_candidates")):
      raise ValueError("Unselected execution participant")
    return ExecutionBinding({**facts, "schema_version": 1, "original_launcher": original_launcher,
                             "participant_order": participants})


@dataclass(frozen=True, init=False)
class CurrentExecutionFacts:
  """Fresh authorization facts, deliberately unable to replace the job's original binding."""
  _snapshot: str

  def __init__(self, value):
    fields = (_FACT_FIELDS - {"node_failure_policy"}) | {"eligible_nodes"}
    if not isinstance(value, dict) or set(value) != fields:
      raise ValueError("Invalid current execution facts")
    _validate_facts(value, failure_policy=False)
    nodes = value["eligible_nodes"]
    if nodes != []:
      _node_order(nodes)
    object.__setattr__(self, "_snapshot", _snapshot(value))

  def to_dict(self):
    return json.loads(self._snapshot)


def binding_from_record(record):
  """Absence is legacy; an explicit null or malformed field is never absence."""
  return ExecutionBinding(record["execution_binding"]) if "execution_binding" in record else None


def binding_value(value):
  """Normalize model constructor input without keeping a caller-owned nested dictionary."""
  if value is None or isinstance(value, ExecutionBinding):
    return value
  return ExecutionBinding(value)


def copy_bound_config(config):
  """Validate only the additive field; partial legacy archive configs remain compatible."""
  result = deepcopy(config)
  if isinstance(result, dict) and "execution_binding" in result:
    result["execution_binding"] = binding_from_record(result).to_dict()
  return result


def checked_archive_config(config, original_binding):
  """Public archive config is mutable; its original binding (including absence) is not."""
  result = copy_bound_config(config)
  observed = binding_from_record(result) if isinstance(result, dict) else None
  if observed != original_binding:
    raise ValueError("Archive execution binding changed")
  return result
