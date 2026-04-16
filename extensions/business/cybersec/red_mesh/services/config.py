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

DEFAULT_ATTESTATION_CONFIG = {
  "ENABLED": True,
  "PRIVATE_KEY": "",
  "MIN_SECONDS_BETWEEN_SUBMITS": 86400.0,
  "RETRIES": 2,
}

DEFAULT_GRAYBOX_BUDGETS_CONFIG = {
  "AUTH_ATTEMPTS": 10,
  "ROUTE_DISCOVERY": 100,
  "STATEFUL_ACTIONS": 1,
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


def get_attestation_config(owner):
  """Return normalized attestation config."""
  def _normalize(merged, defaults):
    enabled = bool(merged.get("ENABLED", defaults["ENABLED"]))
    private_key = str(merged.get("PRIVATE_KEY") or defaults["PRIVATE_KEY"])

    try:
      min_seconds = float(
        merged.get("MIN_SECONDS_BETWEEN_SUBMITS", defaults["MIN_SECONDS_BETWEEN_SUBMITS"])
      )
    except (TypeError, ValueError):
      min_seconds = defaults["MIN_SECONDS_BETWEEN_SUBMITS"]
    if min_seconds < 0:
      min_seconds = defaults["MIN_SECONDS_BETWEEN_SUBMITS"]

    try:
      retries = int(merged.get("RETRIES", defaults["RETRIES"]))
    except (TypeError, ValueError):
      retries = defaults["RETRIES"]
    if retries < 0:
      retries = defaults["RETRIES"]

    return {
      "ENABLED": enabled,
      "PRIVATE_KEY": private_key,
      "MIN_SECONDS_BETWEEN_SUBMITS": min_seconds,
      "RETRIES": retries,
    }

  return resolve_config_block(
    owner,
    "ATTESTATION",
    DEFAULT_ATTESTATION_CONFIG,
    normalizer=_normalize,
  )


def get_graybox_budgets_config(owner):
  """Return normalized graybox execution budgets."""
  def _normalize(merged, defaults):
    def _bounded_int(key, minimum, default):
      try:
        value = int(merged.get(key, default))
      except (TypeError, ValueError):
        value = default
      if value < minimum:
        return default
      return value

    return {
      "AUTH_ATTEMPTS": _bounded_int("AUTH_ATTEMPTS", 1, defaults["AUTH_ATTEMPTS"]),
      "ROUTE_DISCOVERY": _bounded_int("ROUTE_DISCOVERY", 1, defaults["ROUTE_DISCOVERY"]),
      "STATEFUL_ACTIONS": _bounded_int("STATEFUL_ACTIONS", 0, defaults["STATEFUL_ACTIONS"]),
    }

  return resolve_config_block(
    owner,
    "GRAYBOX_BUDGETS",
    DEFAULT_GRAYBOX_BUDGETS_CONFIG,
    normalizer=_normalize,
  )
