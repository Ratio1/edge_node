"""Immutable tenant execution values, not authentication or a reusable authorization lease."""
from dataclasses import dataclass
from copy import deepcopy
import json
import re

from .assets import canonical_digest, canonical_uuid, normalize_target, valid_digest
from .identity import canonical_account_id
from .nodes import valid_node_address


# RM-107: a job runs on one asset of one engagement; the target is the engagement entry's.
_FACT_FIELDS = frozenset({"namespace", "tenant_id", "engagement_id", "engagement_asset_id",
  "engagement_hash", "asset_target", "asset_target_digest", "actor_id", "actor_generation",
  "node_failure_policy"})
_BINDING_EXTRA = frozenset({"schema_version", "original_launcher", "participant_order"})
_BINDING_FIELDS = _FACT_FIELDS | _BINDING_EXTRA
BINDING_SCHEMA_VERSION = 2
_ENGAGEMENT_ASSET_ID = re.compile(r"ea_[1-9][0-9]*")
# Launch-time policy, read by the launch gate and never part of the binding. RM-131:
# `asset_environment` is the registered asset's environment (None when unset or unknown).
_POLICY_FIELDS = frozenset({"engagement", "asset_environment"})
_ENGAGEMENT_FIELDS = frozenset({"engagement_id", "engagement_hash", "context", "authorization",
                                "contract_sha256"})


def _validate_facts(value, *, failure_policy=True):
  for name in ("namespace", "actor_generation"):
    text = value.get(name)
    if not isinstance(text, str) or not text.strip():
      raise ValueError("Invalid execution identity")
    text.encode("utf-8", errors="strict")
  text = value.get("tenant_id")
  if not isinstance(text, str) or not text.startswith("tn_"):
    raise ValueError("Invalid execution object identity")
  canonical_uuid(text[len("tn_"):])
  # Imported here: `engagements` loads the models package, which imports this module.
  from .engagements import valid_engagement_id
  asset_id = value.get("engagement_asset_id")
  if (not valid_engagement_id(value.get("engagement_id")) or not valid_digest(value.get("engagement_hash"))
      or not isinstance(asset_id, str) or not _ENGAGEMENT_ASSET_ID.fullmatch(asset_id)):
    raise ValueError("Invalid execution object identity")
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


def _validate_engagement(value):
  """The engagement facts a launch is gated on and snapshots (RM-095); shape only."""
  # Imported here: `engagements` loads the models package, which imports this module.
  from .engagements import valid_engagement_id
  if (not isinstance(value, dict) or set(value) != _ENGAGEMENT_FIELDS
      or not valid_engagement_id(value["engagement_id"]) or not valid_digest(value["engagement_hash"])
      or not valid_digest(value["contract_sha256"])
      or not isinstance(value["context"], dict) or not isinstance(value["authorization"], dict)):
    raise ValueError("Invalid execution engagement")


def _snapshot(value):
  return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True, init=False)
class ExecutionBinding:
  """Strict wire value held as immutable JSON; each projection is a detached copy."""
  _snapshot: str

  def __init__(self, value):
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int
        or value["schema_version"] != BINDING_SCHEMA_VERSION):
      raise ValueError("Unsupported execution binding version")
    if set(value) != _BINDING_FIELDS:
      raise ValueError("Invalid execution binding fields")
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
    # `engagement` (the facts the launch gate reads and snapshots, RM-095) is launch-time policy,
    # never part of the binding. RM-107: every launch runs inside an engagement.
    if (not isinstance(value, dict) or "engagement" not in value
        or set(value) - _POLICY_FIELDS != _FACT_FIELDS | {"selected_candidates"}):
      raise ValueError("Invalid resolved execution fields")
    _validate_facts(value)
    _node_order(value["selected_candidates"])
    _validate_engagement(value["engagement"])
    # Imported here, as `engagements` above: `tenant_assets` loads modules that import this one.
    from .tenant_assets import ENVIRONMENTS
    if value.get("asset_environment") not in (None, *ENVIRONMENTS):
      raise ValueError("Invalid execution asset environment")
    if (value["engagement"]["engagement_id"] != value["engagement_id"]
        or value["engagement"]["engagement_hash"] != value["engagement_hash"]):
      raise ValueError("Invalid execution engagement")
    object.__setattr__(self, "_snapshot", _snapshot(value))

  def to_dict(self):
    return json.loads(self._snapshot)

  def build_binding(self, original_launcher, participant_order):
    participants = _node_order(participant_order)
    facts = self.to_dict()
    for name in _POLICY_FIELDS:
      facts.pop(name, None)
    if not set(participants).issubset(facts.pop("selected_candidates")):
      raise ValueError("Unselected execution participant")
    return ExecutionBinding({**facts, "schema_version": BINDING_SCHEMA_VERSION,
                             "original_launcher": original_launcher,
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
  """The record's binding, or None when the field is absent. An explicit null or malformed field
  is never absence -- it is a broken record, and `ExecutionBinding(...)` raises for it."""
  return ExecutionBinding(record["execution_binding"]) if "execution_binding" in record else None


def binding_value(value):
  """Normalize model constructor input without keeping a caller-owned nested dictionary."""
  if value is None or isinstance(value, ExecutionBinding):
    return value
  return ExecutionBinding(value)


def copy_bound_config(config):
  """Deep-copy a job/archive config; validate only the additive field. The binding cannot change
  through this copy, absence included: a present field is re-validated and never left malformed,
  and an absent one stays absent rather than being synthesized."""
  result = deepcopy(config)
  if isinstance(result, dict) and "execution_binding" in result:
    result["execution_binding"] = binding_from_record(result).to_dict()
  return result


def checked_archive_config(config, original_binding):
  """Public archive config is mutable; its original binding, including absence, is not."""
  result = copy_bound_config(config)
  observed = binding_from_record(result) if isinstance(result, dict) else None
  if observed != original_binding:
    raise ValueError("Archive execution binding changed")
  return result
