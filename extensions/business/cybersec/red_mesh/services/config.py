def _config_attr_name(block_name):
  return f"cfg_{block_name.lower()}"


def resolve_config_block(owner, block_name, defaults, normalizer=None):
  """Resolve one shallow nested config block with partial override merge."""
  merged = dict(defaults or {})
  override = getattr(owner, _config_attr_name(block_name), None)
  if override is None:
    config_data = getattr(owner, "config_data", None)
    if isinstance(config_data, dict):
      override = config_data.get(block_name)
  if override is None:
    config = getattr(owner, "CONFIG", None)
    if isinstance(config, dict):
      override = config.get(block_name)
  if isinstance(override, dict):
    merged.update(override)

  if callable(normalizer):
    normalized = normalizer(dict(merged), dict(defaults or {}))
    if isinstance(normalized, dict):
      return normalized
  return merged


DEFAULT_LLM_AGENT_CONFIG = {
  "ENABLED": False,
  "TIMEOUT": 120.0,
  "AUTO_ANALYSIS_TYPE": "security_assessment",
}


def get_llm_agent_config(owner):
  """Return normalized LLM agent integration config."""
  def _normalize(merged, defaults):
    enabled = bool(merged.get("ENABLED", defaults["ENABLED"]))

    try:
      timeout = float(merged.get("TIMEOUT", defaults["TIMEOUT"]))
    except (TypeError, ValueError):
      timeout = defaults["TIMEOUT"]
    if timeout <= 0:
      timeout = defaults["TIMEOUT"]

    analysis_type = str(
      merged.get("AUTO_ANALYSIS_TYPE") or defaults["AUTO_ANALYSIS_TYPE"]
    ).strip() or defaults["AUTO_ANALYSIS_TYPE"]

    return {
      "ENABLED": enabled,
      "TIMEOUT": timeout,
      "AUTO_ANALYSIS_TYPE": analysis_type,
    }

  return resolve_config_block(
    owner,
    "LLM_AGENT",
    DEFAULT_LLM_AGENT_CONFIG,
    normalizer=_normalize,
  )
