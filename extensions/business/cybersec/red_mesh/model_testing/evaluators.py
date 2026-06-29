"""Model Testing evaluator option helpers."""

from __future__ import annotations

import os

from .security import validate_provider_url


HEURISTIC_EVALUATOR_ID = "heuristic_v1"
HEURISTIC_EVALUATOR_METHOD = "local_heuristic_v1"
LLM_EVALUATOR_METHOD = "openai_compatible_json_judge"


def _validation_error(message: str, *, error_class=None):
  result = {"error": "validation_error", "message": message}
  if error_class:
    result["error_class"] = error_class
  return result


def _heuristic_option():
  return {
    "id": HEURISTIC_EVALUATOR_ID,
    "label": "RedMesh heuristic evaluator",
    "kind": "heuristic",
    "provider_label": "RedMesh",
    "model": HEURISTIC_EVALUATOR_ID,
    "method": HEURISTIC_EVALUATOR_METHOD,
  }


def _enabled_llm_presets(cfg):
  return [
    dict(preset)
    for preset in (cfg.get("EVALUATOR_MODELS") or [])
    if isinstance(preset, dict) and bool(preset.get("enabled", True))
  ]


def _safe_llm_option(preset):
  return {
    "id": str(preset.get("id") or "").strip(),
    "label": str(preset.get("label") or "").strip(),
    "kind": "llm",
    "provider_label": str(preset.get("provider_label") or "").strip(),
    "model": str(preset.get("model") or "").strip(),
    "method": LLM_EVALUATOR_METHOD,
  }


def evaluator_options_for_status(cfg):
  """Return UI-safe evaluator options; never include env names or URLs."""
  options = []
  for preset in _enabled_llm_presets(cfg):
    option = _safe_llm_option(preset)
    if option["id"] and option["label"] and option["provider_label"] and option["model"]:
      options.append(option)
  options.append(_heuristic_option())
  return options


def default_evaluator_id(cfg):
  """Resolve the configured default evaluator id with documented fallback."""
  options = evaluator_options_for_status(cfg)
  option_ids = [option["id"] for option in options]
  configured = str(cfg.get("DEFAULT_EVALUATOR_ID") or "").strip()
  if configured in option_ids:
    return configured
  for option in options:
    if option.get("kind") == "llm":
      return option["id"]
  return HEURISTIC_EVALUATOR_ID


def _api_key_from_env(env_name):
  if not env_name:
    return ""
  value = str(os.environ.get(env_name) or "").strip()
  if "\r" in value or "\n" in value:
    return ""
  return value


def resolve_evaluator_option(cfg, evaluator_id=None):
  """Resolve an evaluator id into safe metadata and optional runtime provider."""
  selected_id = str(evaluator_id or "").strip() or default_evaluator_id(cfg)
  if selected_id == HEURISTIC_EVALUATOR_ID:
    return _heuristic_option(), None, None

  for preset in _enabled_llm_presets(cfg):
    if str(preset.get("id") or "").strip() != selected_id:
      continue
    url_info, err = validate_provider_url(preset.get("base_url"))
    if err:
      return None, None, _validation_error(
        "selected evaluator provider URL is unavailable",
        error_class="provider_unreachable",
      )
    api_key = _api_key_from_env(str(preset.get("api_key_env") or "").strip())
    if not api_key:
      return None, None, _validation_error(
        "selected evaluator credentials are unavailable",
        error_class="credential_unavailable",
      )
    safe_option = _safe_llm_option(preset)
    runtime_provider = {
      "adapter": "openai_compatible",
      "provider_label": safe_option["provider_label"],
      "base_url": url_info["base_url"],
      "model": safe_option["model"],
      "api_key": api_key,
    }
    return safe_option, runtime_provider, None

  return None, None, _validation_error("unknown evaluator_id")
