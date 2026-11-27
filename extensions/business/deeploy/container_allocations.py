"""Exact, per-instance CPU, RAM and Volume Storage accounting for Deeploy."""
from extensions.utils.memory_formatter import size_bytes
from decimal import Decimal, InvalidOperation
from typing import NamedTuple

from .deeploy_const import CONTAINERIZED_APPS_SIGNATURES


class Allocation(NamedTuple):
  cpu: Decimal
  memory: Decimal  # Bytes, preserving fractional GiB without rounding each row.
  storage: Decimal  # Explicit budget or, for legacy Native rows, their fixed volumes.


def allocated_resources(instance, native):
  """Read one container's effective limits and fixed-volume floor.

  Parameters
  ----------
  instance : dict
    A materialized CAR or WAR instance.
  native : bool
    Native supports omitted storage with a baseline of its volume reservations.

  Returns
  -------
  Allocation
    CPU cores, memory bytes and volume budget bytes.

  Examples
  --------
  >>> allocated_resources({"CONTAINER_RESOURCES": {"cpu": 1, "memory": "512m"}}, True).storage
  Decimal('0')
  """
  resources = instance.get("CONTAINER_RESOURCES")
  if not isinstance(resources, dict):
    raise ValueError("Missing container resource limits.")
  try:
    cpu = Decimal(str(resources.get("cpu")))
  except InvalidOperation as exc:
    raise ValueError("Container CPU must be a positive finite number.") from exc
  if not cpu.is_finite() or cpu < Decimal("0.000000001") or cpu >= Decimal(2 ** 63) / 10 ** 9:
    raise ValueError("Container CPU must be a positive finite runtime limit.")
  memory = size_bytes(resources.get("memory"))
  if memory < 1:
    raise ValueError("Container memory must be positive.")
  volumes = instance.get("FIXED_SIZE_VOLUMES", {})
  if not isinstance(volumes, dict) or any(not isinstance(vol, dict) for vol in volumes.values()):
    raise ValueError("Invalid FIXED_SIZE_VOLUMES.")
  reserved = sum((size_bytes(vol.get("SIZE"), "m") for vol in volumes.values()), Decimal(0))
  if native and "storage" not in resources:
    storage = reserved  # Legacy Native tiers do not have a finite storage amount.
  else:
    storage = size_bytes(resources.get("storage"), "m")
  if reserved > storage:
    raise ValueError("FIXED_SIZE_VOLUMES exceed selected Volume Storage.")
  return Allocation(cpu, memory, storage)


def validate_native_limits(inputs, paid, is_create):
  """Check the individual caps and fixed-volume floor at Native job admission.

  Parameters
  ----------
  inputs : dict
    Signed normalized request rows and optional worker requirements.
  paid : dict
    Resources of the job type read from chain.
  is_create : bool
    On creation every row must fit the worker; on edits unchanged legacy caps
    can be grandfathered using the canonical previous revision.

  Returns
  -------
  None
    Raises ValueError when validation fails.

  Examples
  --------
  >>> validate_native_limits({"plugins": []}, {"cpu": 3, "memory": "14g"}, True)
  """
  node_request = inputs.get("node_res_req") or {}
  for row in inputs.get("plugins", []):
    if str(row.get("plugin_signature", "")).upper() not in CONTAINERIZED_APPS_SIGNATURES:
      continue  # In-process plugins share the worker and have no Docker controls.
    allocation = allocated_resources(row, native=True)
    if is_create:
      check_worker_limit(allocation, node_request, paid)


def check_worker_limit(allocation, requested_worker, paid):
  """Validate an individual cap against both signed worker and purchased tier.

  Parameters
  ----------
  allocation : Allocation
    One container's desired limits.
  requested_worker, paid : dict
    Node request and chain resource ceilings.

  Returns
  -------
  None
    Raises ValueError for a cap above either ceiling.

  Examples
  --------
  >>> check_worker_limit(Allocation(1, 1024, 0), {}, {"cpu": 3, "memory": "10g"})
  """
  for tier in (paid, requested_worker):
    if "cpu" in tier:
      try:
        cpu = Decimal(str(tier["cpu"]))
      except InvalidOperation as exc:
        raise ValueError("Invalid worker CPU tier.") from exc
      if not cpu.is_finite() or allocation.cpu > cpu:
        raise ValueError("Container CPU exceeds the worker tier.")
    if "memory" in tier and allocation.memory > size_bytes(tier["memory"]):
      raise ValueError("Container memory exceeds the worker tier.")


def instance_allocations(config, native, saved=False):
  """Index the effective per-worker Docker allocations by stable identity.

  Parameters
  ----------
  config : dict
    Materialized pipeline.
  native : bool
    Whether omitted Volume Storage has Native reservation semantics.
  saved : bool
    Read known historical CAR/WAR runtime defaults for absent persisted fields.

  Returns
  -------
  dict
    One allocation per signature and instance ID.

  Examples
  --------
  >>> instance_allocations({"PLUGINS": []}, True)
  {}
  """
  allocations = {}
  ids = set()
  for group in config["PLUGINS"]:
    signature = group["SIGNATURE"].upper()
    for instance in group["INSTANCES"]:
      iid = instance.get("INSTANCE_ID")
      if not isinstance(iid, str) or not iid or iid in ids:
        raise ValueError("Ambiguous instance identity in the saved or desired configuration.")
      ids.add(iid)
      if signature in CONTAINERIZED_APPS_SIGNATURES:
        if saved and native:
          raw = instance.get("CONTAINER_RESOURCES", {})
          if not isinstance(raw, dict):
            raise ValueError("Ambiguous saved Native container resources.")
          # Older missing fields select the actual CAR/WAR runtime defaults.
          # Old dapp full-tier rows already have explicit CPU and memory.
          instance = dict(instance, CONTAINER_RESOURCES={"cpu": 1, "memory": "512m", **raw})
        allocations[(signature, iid)] = allocated_resources(instance, native)
  return allocations


def _normalized_worker_tier(tier):
  """Normalize an existing worker request without losing other tier dimensions.

  Parameters
  ----------
  tier : dict
    Signed worker requirements or the immutable purchased tier.

  Returns
  -------
  dict
    Numeric dimensions in common units, plus unchanged nonnumeric fields.

  Examples
  --------
  >>> _normalized_worker_tier({"memory": "1g"}) == _normalized_worker_tier({"memory": "1024m"})
  True
  """
  normalized = dict(tier)
  if "cpu" in tier:
    try:
      normalized["cpu"] = Decimal(str(tier["cpu"]))
    except InvalidOperation as exc:
      raise ValueError("Invalid worker CPU tier.") from exc
  if "memory" in tier:
    normalized["memory"] = size_bytes(tier["memory"])
  if "storage" in tier:
    normalized["storage"] = size_bytes(tier["storage"], "m")
  return normalized


# Historical Native dashboard requests contain the worker's usable CPU and RAM.
# GPU variants of the same worker share this table. The chain table lists its capacity before headroom.
_NATIVE_WORKER_HEADROOM = {
  (3, "14g"): (3, "10g"), (8, "22g"): (7, "20g"), (12, "30g"): (11, "30g"),
  (16, "60g"): (15, "60g"), (22, "124g"): (22, "120g"),
}


def redistribution_requirements(previous, desired, paid):
  """Bind an ordinary container edit to its saved per-worker allocation.

  Parameters
  ----------
  previous, desired : dict
    Node-specific prior and requested pipelines for the signed revision.
  paid : dict
    The chain-confirmed worker ceiling for new or changed Native caps.

  Returns
  -------
  dict
    Exact decimal dimensions as JSON strings per node, or empty for an
    unrelated edit. All changed nodes share one stop and recovery barrier.

  Examples
  --------
  >>> redistribution_requirements({}, {}, {})
  {}
  """
  if not previous or not desired:
    return {}
  example = next(iter(previous.values()))
  job_type = next(iter(desired.values()))["DEEPLOY_SPECS"].get("job_app_type")
  if job_type not in ("stack", "native"):
    return {}
  native = job_type == "native"
  changed = False
  allocations = {}
  for node, config in desired.items():
    # A new worker has no capacity credit. Compare its desired shape against
    # the old canonical worker only to classify a combined membership/placement edit.
    before = previous.get(node, example)
    old = instance_allocations(before, native, saved=True)
    if native:
      # Only a historical omission on this exact worker/identity may survive a new signed edit.
      prior_rows = {(g["SIGNATURE"], i["INSTANCE_ID"]): i.get("CONTAINER_RESOURCES", {})
                    for g in before["PLUGINS"] for i in g["INSTANCES"]}
      for group in config["PLUGINS"]:
        if group["SIGNATURE"] not in CONTAINERIZED_APPS_SIGNATURES:
          continue
        for item in group["INSTANCES"]:
          resources = item.get("CONTAINER_RESOURCES", {})
          prior = prior_rows.get((group["SIGNATURE"], item["INSTANCE_ID"]))
          if any(field not in resources and (prior is None or field in prior) for field in ("cpu", "memory")):
            raise ValueError("Resource limits may only remain absent on the same saved legacy container.")
    new = instance_allocations(config, native, saved=native)
    if set(previous) == set(desired):
      # Keep a same-placement metadata-only save from rewriting the baseline for a later redistribution.
      saved_tier = before["DEEPLOY_SPECS"].get("node_res_req")
      tier = config["DEEPLOY_SPECS"].get("node_res_req") or {}
      if saved_tier is None and tier:
        # Legacy plans omitted the worker request. Reconstruct only the known purchased worker tier.
        saved_tier = paid
        if native and "storage" not in paid:
          known = _NATIVE_WORKER_HEADROOM.get((paid.get("cpu"), paid.get("memory")))
          if known:
            saved_tier = {"cpu": known[0], "memory": known[1]}
        if not saved_tier:
          raise ValueError("The saved worker tier cannot be recovered for this resource edit.")
      if saved_tier is not None and _normalized_worker_tier(tier) != _normalized_worker_tier(saved_tier):
        raise ValueError("The saved worker tier must stay fixed during redistribution.")
    allocations[node] = (old, new)
    changed |= old != new
  if not changed:
    return {}
  if set(previous) != set(desired):
    raise ValueError("A container resource or membership edit must preserve the saved worker placement.")
  result = {}
  for node, (old, new) in allocations.items():
    if not native and not new:
      raise ValueError("A running Stack needs at least one container.")
    old_totals = tuple(map(sum, zip(*old.values()))) if old else (0, 0, 0)
    new_totals = tuple(map(sum, zip(*new.values()))) if new else (0, 0, 0)
    if old_totals != new_totals:
      raise ValueError("Total CPU, RAM and Volume Storage must match the saved revision on each worker.")
    # Numeric overlay selectors and existing credential paths use the saved worker order.
    if previous[node]["DEEPLOY_SPECS"].get("current_target_nodes") != desired[node]["DEEPLOY_SPECS"].get("current_target_nodes"):
      raise ValueError("A container edit must retain the saved placement order.")
    if native:
      tier = desired[node]["DEEPLOY_SPECS"].get("node_res_req") or {}
      for identity, allocation in new.items():
        prior = old.get(identity)
        # Preserve unchanged legacy caps independently in each dimension.
        cap = Allocation(allocation.cpu if not prior or allocation.cpu != prior.cpu else 0,
                         allocation.memory if not prior or allocation.memory != prior.memory else 0, 0)
        check_worker_limit(cap, tier, paid)
    result[node] = list(map(str, new_totals))  # Decimal never enters a signed JSON document directly.
  return result


def prepare_native_omissions(rows):
  """Supply runtime defaults to request validation for identified legacy rows.

  Parameters
  ----------
  rows : list
    Working copy of the signed request's container and in-process rows.

  Returns
  -------
  dict
    Missing fields by stable identity. Durable admission verifies those fields
    were also absent from that identity's saved configuration on every worker.

  Examples
  --------
  >>> prepare_native_omissions([])
  {}
  """
  omissions = {}
  for row in rows:
    if not isinstance(row, dict) or str(row.get("plugin_signature", "")).upper() not in CONTAINERIZED_APPS_SIGNATURES:
      continue
    identity = (row["plugin_signature"].upper(), row.get("instance_id"))
    if not identity[1]:
      continue  # New and unidentified containers must provide both fields.
    raw = row.get("CONTAINER_RESOURCES", {})
    if not isinstance(raw, dict):
      continue  # Explicit malformed values remain subject to regular request validation.
    absent = tuple(key for key in ("cpu", "memory") if key not in raw)
    if absent:
      omissions[identity] = (absent, "CONTAINER_RESOURCES" not in row)
      row["CONTAINER_RESOURCES"] = {"cpu": 1, "memory": "512m", **raw}
  return omissions


def restore_native_omissions(configs, omissions):
  """Preserve the signed raw resource layout in the materialized execution plan.

  Parameters
  ----------
  configs : dict
    Materialized desired pipelines keyed by worker.
  omissions : dict
    Stable identities with known omitted runtime field names.

  Returns
  -------
  None
    Updates only the resource dictionaries of matching instances.

  Examples
  --------
  >>> restore_native_omissions({}, {})
  """
  for config in configs.values():
    for group in config["PLUGINS"]:
      for instance in group["INSTANCES"]:
        missing = omissions.get((group["SIGNATURE"], instance["INSTANCE_ID"]))
        if missing:
          fields, absent_dict = missing
          if absent_dict:
            instance.pop("CONTAINER_RESOURCES")
          else:
            for field in fields:
              instance["CONTAINER_RESOURCES"].pop(field)
