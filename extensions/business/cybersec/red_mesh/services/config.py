from urllib.parse import urlsplit


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

DEFAULT_EVENT_EXPORT_CONFIG = {
  "ENABLED": False,
  "REDACTION_MODE": "hash_only",
  "DESTINATION_TRUST_PROFILE": "restricted_redacted",
  "DEFAULT_TLP": "amber",
  "INCLUDE_TARGET_DISPLAY": False,
  "INCLUDE_WORKER_SOURCE_IP": False,
  "INCLUDE_EGRESS_IP": False,
  "INCLUDE_SERVICE_BANNERS": False,
  "INCLUDE_RAW_RESPONSES": False,
  "INCLUDE_CREDENTIALS": False,
  "SIGN_PAYLOADS": True,
  "HMAC_SECRET_ENV": "REDMESH_EVENT_HMAC_SECRET",
}

DEFAULT_WAZUH_EXPORT_CONFIG = {
  "ENABLED": False,
  "MODE": "syslog",
  "SYSLOG_HOST": "",
  "SYSLOG_PORT": 514,
  "HTTP_URL": "",
  "HTTP_TOKEN_ENV": "REDMESH_WAZUH_HTTP_TOKEN",
  "MIN_SEVERITY": "INFO",
  "INCLUDE_SERVICE_OBSERVATIONS": True,
  "TIMEOUT_SECONDS": 5.0,
  "RETRY_ATTEMPTS": 2,
  "PERSIST_FAILED_PAYLOADS": False,
  "FAILED_PAYLOAD_SAMPLE_BYTES": 2048,
}

DEFAULT_SURICATA_CORRELATION_CONFIG = {
  "ENABLED": False,
  "MODE": "uploaded_eve_json_or_external_query",
  "MATCH_WINDOW_SECONDS": 300,
  "CLOCK_SKEW_SECONDS": 60,
  "INCLUDE_TARGET_DISPLAY": False,
  "AUTO_SUPPRESS": False,
}

DEFAULT_STIX_EXPORT_CONFIG = {
  "ENABLED": False,
  "DEFAULT_TLP": "amber",
  "INCLUDE_OBSERVED_DATA": True,
  "INCLUDE_INDICATORS": "ioc_only",
}

DEFAULT_OPENCTI_EXPORT_CONFIG = {
  "ENABLED": False,
  "URL": "",
  "TOKEN_ENV": "REDMESH_OPENCTI_TOKEN",
  "PUSH_MODE": "manual",
  "MIN_SEVERITY": "MEDIUM",
}

DEFAULT_TAXII_EXPORT_CONFIG = {
  "ENABLED": False,
  "SERVER_URL": "",
  "TOKEN_ENV": "REDMESH_TAXII_TOKEN",
  "COLLECTION_ID": "",
  "MODE": "publish_manual",
}

_REDACTION_MODES = {"hash_only", "summary", "internal_soc", "custom"}
_TRUST_PROFILES = {"restricted_redacted", "internal_soc", "custom"}
_TLP_VALUES = {"clear", "green", "amber", "amber_strict", "red"}
_STIX_INDICATOR_MODES = {"ioc_only", "never", "all"}
_SEVERITY_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


def _normalized_choice(value, allowed, default):
  normalized = str(value or default).strip().lower()
  return normalized if normalized in allowed else default


def _normalized_upper_choice(value, allowed, default):
  normalized = str(value or default).strip().upper()
  return normalized if normalized in allowed else default


def _bounded_int(value, default, *, minimum=None, maximum=None):
  try:
    result = int(value)
  except (TypeError, ValueError):
    return default
  if minimum is not None and result < minimum:
    return default
  if maximum is not None and result > maximum:
    return default
  return result


def _bounded_float(value, default, *, minimum=None):
  try:
    result = float(value)
  except (TypeError, ValueError):
    return default
  if minimum is not None and result < minimum:
    return default
  return result


def _safe_secret_env(value, default):
  normalized = str(value or default).strip()
  return normalized or default


def _safe_http_url(value):
  raw = str(value or "").strip().rstrip("/")
  if not raw:
    return ""
  try:
    parsed = urlsplit(raw)
  except ValueError:
    return ""
  if parsed.username or parsed.password:
    return ""
  if parsed.scheme and parsed.scheme not in {"http", "https"}:
    return ""
  return raw


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


def get_event_export_config(owner):
  """Return normalized canonical RedMesh event export config."""
  def _normalize(merged, defaults):
    return {
      "ENABLED": bool(merged.get("ENABLED", defaults["ENABLED"])),
      "REDACTION_MODE": _normalized_choice(
        merged.get("REDACTION_MODE"),
        _REDACTION_MODES,
        defaults["REDACTION_MODE"],
      ),
      "DESTINATION_TRUST_PROFILE": _normalized_choice(
        merged.get("DESTINATION_TRUST_PROFILE"),
        _TRUST_PROFILES,
        defaults["DESTINATION_TRUST_PROFILE"],
      ),
      "DEFAULT_TLP": _normalized_choice(
        merged.get("DEFAULT_TLP"),
        _TLP_VALUES,
        defaults["DEFAULT_TLP"],
      ),
      "INCLUDE_TARGET_DISPLAY": bool(merged.get("INCLUDE_TARGET_DISPLAY", defaults["INCLUDE_TARGET_DISPLAY"])),
      "INCLUDE_WORKER_SOURCE_IP": bool(merged.get("INCLUDE_WORKER_SOURCE_IP", defaults["INCLUDE_WORKER_SOURCE_IP"])),
      "INCLUDE_EGRESS_IP": bool(merged.get("INCLUDE_EGRESS_IP", defaults["INCLUDE_EGRESS_IP"])),
      "INCLUDE_SERVICE_BANNERS": bool(merged.get("INCLUDE_SERVICE_BANNERS", defaults["INCLUDE_SERVICE_BANNERS"])),
      "INCLUDE_RAW_RESPONSES": bool(merged.get("INCLUDE_RAW_RESPONSES", defaults["INCLUDE_RAW_RESPONSES"])),
      "INCLUDE_CREDENTIALS": False,
      "SIGN_PAYLOADS": bool(merged.get("SIGN_PAYLOADS", defaults["SIGN_PAYLOADS"])),
      "HMAC_SECRET_ENV": _safe_secret_env(
        merged.get("HMAC_SECRET_ENV"),
        defaults["HMAC_SECRET_ENV"],
      ),
    }

  return resolve_config_block(
    owner,
    "EVENT_EXPORT",
    DEFAULT_EVENT_EXPORT_CONFIG,
    normalizer=_normalize,
  )


def get_wazuh_export_config(owner):
  """Return normalized Wazuh/generic SIEM export config."""
  def _normalize(merged, defaults):
    mode = _normalized_choice(merged.get("MODE"), {"syslog", "http"}, defaults["MODE"])
    return {
      "ENABLED": bool(merged.get("ENABLED", defaults["ENABLED"])),
      "MODE": mode,
      "SYSLOG_HOST": str(merged.get("SYSLOG_HOST") or defaults["SYSLOG_HOST"]).strip(),
      "SYSLOG_PORT": _bounded_int(
        merged.get("SYSLOG_PORT", defaults["SYSLOG_PORT"]),
        defaults["SYSLOG_PORT"],
        minimum=1,
        maximum=65535,
      ),
      "HTTP_URL": _safe_http_url(merged.get("HTTP_URL") or defaults["HTTP_URL"]),
      "HTTP_TOKEN_ENV": _safe_secret_env(
        merged.get("HTTP_TOKEN_ENV"),
        defaults["HTTP_TOKEN_ENV"],
      ),
      "MIN_SEVERITY": _normalized_upper_choice(
        merged.get("MIN_SEVERITY"),
        _SEVERITY_LEVELS,
        defaults["MIN_SEVERITY"],
      ),
      "INCLUDE_SERVICE_OBSERVATIONS": bool(merged.get("INCLUDE_SERVICE_OBSERVATIONS", defaults["INCLUDE_SERVICE_OBSERVATIONS"])),
      "TIMEOUT_SECONDS": _bounded_float(
        merged.get("TIMEOUT_SECONDS", defaults["TIMEOUT_SECONDS"]),
        defaults["TIMEOUT_SECONDS"],
        minimum=0.001,
      ),
      "RETRY_ATTEMPTS": _bounded_int(
        merged.get("RETRY_ATTEMPTS", defaults["RETRY_ATTEMPTS"]),
        defaults["RETRY_ATTEMPTS"],
        minimum=0,
      ),
      "PERSIST_FAILED_PAYLOADS": bool(merged.get("PERSIST_FAILED_PAYLOADS", defaults["PERSIST_FAILED_PAYLOADS"])),
      "FAILED_PAYLOAD_SAMPLE_BYTES": _bounded_int(
        merged.get("FAILED_PAYLOAD_SAMPLE_BYTES", defaults["FAILED_PAYLOAD_SAMPLE_BYTES"]),
        defaults["FAILED_PAYLOAD_SAMPLE_BYTES"],
        minimum=256,
        maximum=16384,
      ),
    }

  return resolve_config_block(
    owner,
    "WAZUH_EXPORT",
    DEFAULT_WAZUH_EXPORT_CONFIG,
    normalizer=_normalize,
  )


def get_suricata_correlation_config(owner):
  """Return normalized Suricata/Security Onion correlation config."""
  def _normalize(merged, defaults):
    return {
      "ENABLED": bool(merged.get("ENABLED", defaults["ENABLED"])),
      "MODE": _normalized_choice(
        merged.get("MODE"),
        {"uploaded_eve_json_or_external_query", "uploaded_eve_json", "external_query"},
        defaults["MODE"],
      ),
      "MATCH_WINDOW_SECONDS": _bounded_int(
        merged.get("MATCH_WINDOW_SECONDS", defaults["MATCH_WINDOW_SECONDS"]),
        defaults["MATCH_WINDOW_SECONDS"],
        minimum=1,
      ),
      "CLOCK_SKEW_SECONDS": _bounded_int(
        merged.get("CLOCK_SKEW_SECONDS", defaults["CLOCK_SKEW_SECONDS"]),
        defaults["CLOCK_SKEW_SECONDS"],
        minimum=0,
      ),
      "INCLUDE_TARGET_DISPLAY": bool(merged.get("INCLUDE_TARGET_DISPLAY", defaults["INCLUDE_TARGET_DISPLAY"])),
      "AUTO_SUPPRESS": False,
    }

  return resolve_config_block(
    owner,
    "SURICATA_CORRELATION",
    DEFAULT_SURICATA_CORRELATION_CONFIG,
    normalizer=_normalize,
  )


def get_stix_export_config(owner):
  """Return normalized STIX export config."""
  def _normalize(merged, defaults):
    return {
      "ENABLED": bool(merged.get("ENABLED", defaults["ENABLED"])),
      "DEFAULT_TLP": _normalized_choice(
        merged.get("DEFAULT_TLP"),
        _TLP_VALUES,
        defaults["DEFAULT_TLP"],
      ),
      "INCLUDE_OBSERVED_DATA": bool(merged.get("INCLUDE_OBSERVED_DATA", defaults["INCLUDE_OBSERVED_DATA"])),
      "INCLUDE_INDICATORS": _normalized_choice(
        merged.get("INCLUDE_INDICATORS"),
        _STIX_INDICATOR_MODES,
        defaults["INCLUDE_INDICATORS"],
      ),
    }

  return resolve_config_block(
    owner,
    "STIX_EXPORT",
    DEFAULT_STIX_EXPORT_CONFIG,
    normalizer=_normalize,
  )


def get_opencti_export_config(owner):
  """Return normalized OpenCTI export config."""
  def _normalize(merged, defaults):
    return {
      "ENABLED": bool(merged.get("ENABLED", defaults["ENABLED"])),
      "URL": _safe_http_url(merged.get("URL") or defaults["URL"]),
      "TOKEN_ENV": _safe_secret_env(merged.get("TOKEN_ENV"), defaults["TOKEN_ENV"]),
      "PUSH_MODE": _normalized_choice(
        merged.get("PUSH_MODE"),
        {"manual", "dry_run"},
        defaults["PUSH_MODE"],
      ),
      "MIN_SEVERITY": _normalized_upper_choice(
        merged.get("MIN_SEVERITY"),
        _SEVERITY_LEVELS,
        defaults["MIN_SEVERITY"],
      ),
    }

  return resolve_config_block(
    owner,
    "OPENCTI_EXPORT",
    DEFAULT_OPENCTI_EXPORT_CONFIG,
    normalizer=_normalize,
  )


def get_taxii_export_config(owner):
  """Return normalized TAXII export config."""
  def _normalize(merged, defaults):
    return {
      "ENABLED": bool(merged.get("ENABLED", defaults["ENABLED"])),
      "SERVER_URL": _safe_http_url(merged.get("SERVER_URL") or defaults["SERVER_URL"]),
      "TOKEN_ENV": _safe_secret_env(merged.get("TOKEN_ENV"), defaults["TOKEN_ENV"]),
      "COLLECTION_ID": str(merged.get("COLLECTION_ID") or defaults["COLLECTION_ID"]).strip(),
      "MODE": _normalized_choice(
        merged.get("MODE"),
        {"publish_manual", "consume_manual"},
        defaults["MODE"],
      ),
    }

  return resolve_config_block(
    owner,
    "TAXII_EXPORT",
    DEFAULT_TAXII_EXPORT_CONFIG,
    normalizer=_normalize,
  )
