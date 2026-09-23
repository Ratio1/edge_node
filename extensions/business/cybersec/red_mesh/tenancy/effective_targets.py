"""Pure checks of executable destinations against the admitted saved target."""
from copy import deepcopy

from .assets import _normalize_url, normalize_target
from .execution import binding_from_record

_UNSET = object()

def resolve_launch_target(context, kind, supplied):
  """Derive the saved destination; a caller may repeat it, never override it."""
  if context is None:
    return supplied
  protected = context.to_dict()["asset_target"]
  if protected["kind"] != kind or kind not in ("network", "webapp"):
    raise ValueError("Execution target mismatch")
  expected = protected["address" if kind == "network" else "url"]
  if supplied not in (None, ""):
    observed = supplied
    if kind == "webapp":
      observed, _ = _normalize_url(supplied)
    if observed != expected:
      raise ValueError("Execution target mismatch")
  return expected


def validate_effective_config(config, *, target=_UNSET):
  """Check final worker inputs, including a separately passed network destination."""
  binding = binding_from_record(config)
  if binding is None:
    return
  kind = binding.to_dict()["asset_target"]["kind"]
  if config.get("scan_type", "network") != ("model_test" if kind == "model" else kind):
    raise ValueError("Execution target mismatch")
  if kind == "network":
    if not config.get("target"):
      raise ValueError("Execution target mismatch")
    resolve_launch_target(binding, kind, config.get("target"))
    if target is not _UNSET and target != config["target"]:
      raise ValueError("Execution target mismatch")
  elif kind == "webapp":
    if not config.get("target_url"):
      raise ValueError("Execution target mismatch")
    resolve_launch_target(binding, kind, config.get("target_url"))
  else:
    validate_model_provider(binding, config.get("tested_model"))


def validate_model_provider(context, provider):
  if context is None:
    return
  from ..model_testing.runner import _chat_completions_url

  if not isinstance(provider, dict):
    raise ValueError("Execution target mismatch")
  protected = context.to_dict()["asset_target"]
  try:
    observed = normalize_target({"kind": "model", "adapter": provider.get("adapter"),
      "endpointUrl": _chat_completions_url(provider.get("base_url")), "model": provider.get("model")})
  except (TypeError, ValueError):
    raise ValueError("Execution target mismatch") from None
  if (observed != protected or observed["model"] != provider.get("model")
      or provider.get("method", "chat") != "chat"):
    raise ValueError("Execution target mismatch")


def resolve_model_launch_provider(context, provider):
  if context is None:
    return provider
  protected = context.to_dict()["asset_target"]
  if protected["kind"] != "model" or (provider is not None and not isinstance(provider, dict)):
    raise ValueError("Execution target mismatch")
  resolved = deepcopy(provider or {})
  for field, value in (("adapter", protected["adapter"]), ("base_url", protected["endpointUrl"]),
                       ("model", protected["model"])):
    if field not in resolved:
      resolved[field] = value
  validate_model_provider(context, resolved)
  return resolved
