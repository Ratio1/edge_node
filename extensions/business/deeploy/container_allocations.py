"""Exact, per-instance CPU, RAM and Volume Storage accounting for Deeploy."""
import re
from decimal import Decimal, InvalidOperation
from typing import NamedTuple

from .deeploy_const import CONTAINERIZED_APPS_SIGNATURES


class Allocation(NamedTuple):
  cpu: Decimal
  memory: Decimal  # Bytes, preserving fractional GiB without rounding each row.
  storage: Decimal  # Explicit budget or, for legacy Native rows, their fixed volumes.


def size_bytes(value, default_unit="b"):
  """Read a finite capacity in binary units.

  Bare Docker memory values are bytes. Bare Deeploy volume allocations are MiB.

  Parameters
  ----------
  value : str or number
    Stored or signed capacity.
  default_unit : str
    Historical interpretation of a unitless value.

  Returns
  -------
  Decimal
    Exact byte-equivalent amount.

  Examples
  --------
  >>> size_bytes("512m") == size_bytes("0.5g")
  True
  """
  match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kmgt]b?|b)?", str(value).strip(), re.I)
  if not match:
    raise ValueError("Invalid container resource size.")
  unit = (match[2] or default_unit)[0].lower()
  amount = Decimal(match[1]) * (1024 ** "bkmgt".index(unit))
  if amount > 2 ** 63 - 1:  # Docker's resource fields are signed 64-bit values.
    raise ValueError("Container resource size exceeds runtime range.")
  return amount


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
    if row.get("plugin_signature", "").upper() not in CONTAINERIZED_APPS_SIGNATURES:
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
