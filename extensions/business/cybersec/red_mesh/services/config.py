from math import isfinite
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
  "PROVIDER": "local",
  "MODEL": "CyberSecQwen-4B.Q4_K_M.gguf",
  "PROMPT_PROFILE": "auto",
  "LOCAL_PROMPT_PROFILE": "local_cybersecqwen_quota_v1",
  "REMOTE_PROMPT_PROFILE": "remote_rich_v1",
  "STRUCTURED_MAX_FINDINGS": 6,
  "STRUCTURED_MAX_TOKENS": 2048,
  "STRUCTURED_TEMPERATURE": None,
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
  "IS_REQUIRED": False,
  "MODE": "syslog",
  "SYSLOG_HOST": "",
  "SYSLOG_PORT": 514,
  "HTTP_URL": "",
  "AUTH_MODE": "static",
  # Inline credential — mirrors MISP_API_KEY's "secret in CONFIG" pattern.
  # Takes priority over the env-var indirection below when set.
  "TOKEN": "",
  "TOKEN_ENV": "REDMESH_WAZUH_TOKEN",
  "USERNAME": "",
  "PASSWORD": "",
  "PASSWORD_ENV": "REDMESH_WAZUH_PASSWORD",
  "LOGIN_URL": "",
  "LOGIN_PATH": "/security/user/authenticate?raw=true",
  "JWT_TTL_OVERRIDE_SECONDS": 0,
  "MIN_SEVERITY": "INFO",
  "INCLUDE_SERVICE_OBSERVATIONS": True,
  "TIMEOUT_SECONDS": 5.0,
  "RETRY_ATTEMPTS": 2,
  "FAILURE_COOLDOWN_SECONDS": 300,
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
  "AUTH_MODE": "static",
  "TOKEN": "",
  "TOKEN_ENV": "REDMESH_OPENCTI_TOKEN",
  "PUSH_MODE": "manual",
  "MIN_SEVERITY": "MEDIUM",
}

DEFAULT_TAXII_EXPORT_CONFIG = {
  "ENABLED": False,
  "SERVER_URL": "",
  "AUTH_MODE": "static",
  "TOKEN": "",
  "TOKEN_ENV": "REDMESH_TAXII_TOKEN",
  "USERNAME": "",
  "PASSWORD": "",
  "PASSWORD_ENV": "REDMESH_TAXII_PASSWORD",
  "COLLECTION_ID": "",
  "MODE": "publish_manual",
  "TIMEOUT_SECONDS": 30.0,
}

DEFAULT_MODEL_TESTING_CONFIG = {
  "ENABLED": False,
  "RAW_EVIDENCE_ENABLED": False,
  "RAW_EVALUATOR_EVIDENCE_ENABLED": False,
  "RAW_EVIDENCE_DEFAULT_RETENTION_DAYS": 7,
  "RAW_EVIDENCE_MAX_RETENTION_DAYS": 30,
  "RAW_EVIDENCE_SECRET_REF": "",
  "REMOTE_PROVIDER_URLS_ENABLED": True,
  "REMOTE_PROVIDER_PREFLIGHT_ENABLED": True,
  "DEFAULT_EVALUATOR_MODEL": None,
  "LIMITS": {
    "MAX_CASES": 12,
    "TESTED_MAX_TOKENS": 256,
    "EVALUATOR_MAX_TOKENS": 384,
    "PER_CALL_TIMEOUT_SECONDS": 45,
    "TOTAL_TIMEOUT_SECONDS": 600,
    "TEMPERATURE": 0,
    "MAX_RETRIES": 1,
  },
}

DEFAULT_API_OPERATIONS_CONFIG = {
  "ENABLED": False,
  "TOKEN_HASHES": [],
  "TOKEN_ENV": "REDMESH_API_OPERATION_TOKEN",
  "HMAC_SECRET": "",
  "HMAC_SECRET_ENV": "REDMESH_API_OPERATION_HMAC_SECRET",
  "MAX_IDEMPOTENCY_KEY_LENGTH": 128,
  "MAX_FOCUS_AREAS": 8,
  "MAX_FOCUS_AREA_LENGTH": 80,
  "MAX_QUEUE_GLOBAL": 32,
  "MAX_QUEUE_PER_ACTOR": 8,
  "MAX_QUEUE_PER_JOB": 1,
  "OPERATION_TTL_SECONDS": 86400,
  "LEASE_SECONDS": 300,
  "POLL_AFTER_MS": 1000,
}

_WAZUH_AUTH_MODES = {"static", "wazuh_jwt"}
_TAXII_AUTH_MODES = {"static", "basic"}
_OPENCTI_AUTH_MODES = {"static"}

_REDACTION_MODES = {"hash_only", "summary", "internal_soc", "custom"}
_TRUST_PROFILES = {"restricted_redacted", "internal_soc", "custom"}
_TLP_VALUES = {"clear", "green", "amber", "amber_strict", "red"}
_STIX_INDICATOR_MODES = {"ioc_only", "never", "all"}
_SEVERITY_LEVELS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
_LLM_PROVIDER_PATHS = {"local", "remote", "openai", "anthropic", "auto"}


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


def _bounded_float(value, default, *, minimum=None, maximum=None):
  try:
    result = float(value)
  except (TypeError, ValueError):
    return default
  if not isfinite(result):
    return default
  if minimum is not None and result < minimum:
    return default
  if maximum is not None and result > maximum:
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

    provider = _normalized_choice(
      merged.get("PROVIDER") or merged.get("LLM_PROVIDER"),
      _LLM_PROVIDER_PATHS,
      defaults["PROVIDER"],
    )
    model_value = merged.get("MODEL")
    if (
      (not model_value or model_value == defaults["MODEL"])
      and merged.get("LOCAL_LLM_MODEL")
    ):
      model_value = merged.get("LOCAL_LLM_MODEL")
    model = str(model_value or defaults["MODEL"]).strip() or defaults["MODEL"]

    try:
      structured_max_findings = int(
        merged.get("STRUCTURED_MAX_FINDINGS", defaults["STRUCTURED_MAX_FINDINGS"])
      )
    except (TypeError, ValueError):
      structured_max_findings = defaults["STRUCTURED_MAX_FINDINGS"]
    structured_max_findings = max(1, min(structured_max_findings, 24))

    try:
      structured_max_tokens = int(
        merged.get("STRUCTURED_MAX_TOKENS", defaults["STRUCTURED_MAX_TOKENS"])
      )
    except (TypeError, ValueError):
      structured_max_tokens = defaults["STRUCTURED_MAX_TOKENS"]
    structured_max_tokens = max(64, min(structured_max_tokens, 4096))

    prompt_profile = str(
      merged.get("PROMPT_PROFILE") or defaults["PROMPT_PROFILE"]
    ).strip().lower() or defaults["PROMPT_PROFILE"]
    local_prompt_profile = str(
      merged.get("LOCAL_PROMPT_PROFILE") or defaults["LOCAL_PROMPT_PROFILE"]
    ).strip().lower() or defaults["LOCAL_PROMPT_PROFILE"]
    remote_prompt_profile = str(
      merged.get("REMOTE_PROMPT_PROFILE") or defaults["REMOTE_PROMPT_PROFILE"]
    ).strip().lower() or defaults["REMOTE_PROMPT_PROFILE"]

    structured_temperature = merged.get("STRUCTURED_TEMPERATURE", defaults["STRUCTURED_TEMPERATURE"])
    if structured_temperature in (None, ""):
      structured_temperature = defaults["STRUCTURED_TEMPERATURE"]
    else:
      try:
        structured_temperature = float(structured_temperature)
      except (TypeError, ValueError):
        structured_temperature = defaults["STRUCTURED_TEMPERATURE"]
      if structured_temperature is not None:
        structured_temperature = max(0.0, min(structured_temperature, 2.0))

    return {
      "ENABLED": enabled,
      "TIMEOUT": timeout,
      "AUTO_ANALYSIS_TYPE": analysis_type,
      "PROVIDER": provider,
      "MODEL": model,
      "PROMPT_PROFILE": prompt_profile,
      "LOCAL_PROMPT_PROFILE": local_prompt_profile,
      "REMOTE_PROMPT_PROFILE": remote_prompt_profile,
      "STRUCTURED_MAX_FINDINGS": structured_max_findings,
      "STRUCTURED_MAX_TOKENS": structured_max_tokens,
      "STRUCTURED_TEMPERATURE": structured_temperature,
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


def get_model_testing_config(owner):
  """Return normalized Model Testing capability config."""
  def _normalize_limits(value, defaults):
    raw_limits = value if isinstance(value, dict) else {}
    default_limits = defaults["LIMITS"]
    return {
      "MAX_CASES": _bounded_int(
        raw_limits.get("MAX_CASES", default_limits["MAX_CASES"]),
        default_limits["MAX_CASES"],
        minimum=1,
        maximum=12,
      ),
      "TESTED_MAX_TOKENS": _bounded_int(
        raw_limits.get("TESTED_MAX_TOKENS", default_limits["TESTED_MAX_TOKENS"]),
        default_limits["TESTED_MAX_TOKENS"],
        minimum=1,
        maximum=256,
      ),
      "EVALUATOR_MAX_TOKENS": _bounded_int(
        raw_limits.get("EVALUATOR_MAX_TOKENS", default_limits["EVALUATOR_MAX_TOKENS"]),
        default_limits["EVALUATOR_MAX_TOKENS"],
        minimum=1,
        maximum=384,
      ),
      "PER_CALL_TIMEOUT_SECONDS": _bounded_int(
        raw_limits.get("PER_CALL_TIMEOUT_SECONDS", default_limits["PER_CALL_TIMEOUT_SECONDS"]),
        default_limits["PER_CALL_TIMEOUT_SECONDS"],
        minimum=1,
        maximum=45,
      ),
      "TOTAL_TIMEOUT_SECONDS": _bounded_int(
        raw_limits.get("TOTAL_TIMEOUT_SECONDS", default_limits["TOTAL_TIMEOUT_SECONDS"]),
        default_limits["TOTAL_TIMEOUT_SECONDS"],
        minimum=1,
        maximum=600,
      ),
      "TEMPERATURE": _bounded_float(
        raw_limits.get("TEMPERATURE", default_limits["TEMPERATURE"]),
        default_limits["TEMPERATURE"],
        minimum=0,
        maximum=0,
      ),
      "MAX_RETRIES": _bounded_int(
        raw_limits.get("MAX_RETRIES", default_limits["MAX_RETRIES"]),
        default_limits["MAX_RETRIES"],
        minimum=0,
        maximum=1,
      ),
    }

  def _normalize(merged, defaults):
    default_retention = _bounded_int(
      merged.get("RAW_EVIDENCE_DEFAULT_RETENTION_DAYS"),
      defaults["RAW_EVIDENCE_DEFAULT_RETENTION_DAYS"],
      minimum=1,
      maximum=30,
    )
    max_retention = _bounded_int(
      merged.get("RAW_EVIDENCE_MAX_RETENTION_DAYS"),
      defaults["RAW_EVIDENCE_MAX_RETENTION_DAYS"],
      minimum=1,
      maximum=30,
    )
    if default_retention > max_retention:
      default_retention = max_retention
    default_evaluator = merged.get("DEFAULT_EVALUATOR_MODEL")
    if not isinstance(default_evaluator, dict):
      default_evaluator = None
    return {
      "ENABLED": bool(merged.get("ENABLED", defaults["ENABLED"])),
      "RAW_EVIDENCE_ENABLED": bool(
        merged.get("RAW_EVIDENCE_ENABLED", defaults["RAW_EVIDENCE_ENABLED"])
      ),
      "RAW_EVALUATOR_EVIDENCE_ENABLED": bool(
        merged.get("RAW_EVALUATOR_EVIDENCE_ENABLED", defaults["RAW_EVALUATOR_EVIDENCE_ENABLED"])
      ),
      "RAW_EVIDENCE_DEFAULT_RETENTION_DAYS": default_retention,
      "RAW_EVIDENCE_MAX_RETENTION_DAYS": max_retention,
      "RAW_EVIDENCE_SECRET_REF": str(
        merged.get("RAW_EVIDENCE_SECRET_REF") or defaults["RAW_EVIDENCE_SECRET_REF"]
      ).strip(),
      "REMOTE_PROVIDER_URLS_ENABLED": bool(
        merged.get("REMOTE_PROVIDER_URLS_ENABLED", defaults["REMOTE_PROVIDER_URLS_ENABLED"])
      ),
      "REMOTE_PROVIDER_PREFLIGHT_ENABLED": bool(
        merged.get("REMOTE_PROVIDER_PREFLIGHT_ENABLED", defaults["REMOTE_PROVIDER_PREFLIGHT_ENABLED"])
      ),
      "DEFAULT_EVALUATOR_MODEL": default_evaluator,
      "LIMITS": _normalize_limits(merged.get("LIMITS"), defaults),
    }

  return resolve_config_block(
    owner,
    "MODEL_TESTING",
    DEFAULT_MODEL_TESTING_CONFIG,
    normalizer=_normalize,
  )


def get_api_operations_config(owner):
  """Return normalized RedMesh async API operation config."""
  def _normalize_hashes(value):
    if isinstance(value, str):
      values = [item.strip() for item in value.split(",")]
    elif isinstance(value, (list, tuple, set)):
      values = [str(item or "").strip() for item in value]
    else:
      values = []
    return [item.lower() for item in values if item]

  def _normalize(merged, defaults):
    return {
      "ENABLED": bool(merged.get("ENABLED", defaults["ENABLED"])),
      "TOKEN_HASHES": _normalize_hashes(merged.get("TOKEN_HASHES", defaults["TOKEN_HASHES"])),
      "TOKEN_ENV": _safe_secret_env(merged.get("TOKEN_ENV"), defaults["TOKEN_ENV"]),
      "HMAC_SECRET": str(merged.get("HMAC_SECRET") or defaults["HMAC_SECRET"]),
      "HMAC_SECRET_ENV": _safe_secret_env(
        merged.get("HMAC_SECRET_ENV"),
        defaults["HMAC_SECRET_ENV"],
      ),
      "MAX_IDEMPOTENCY_KEY_LENGTH": _bounded_int(
        merged.get("MAX_IDEMPOTENCY_KEY_LENGTH"),
        defaults["MAX_IDEMPOTENCY_KEY_LENGTH"],
        minimum=16,
        maximum=512,
      ),
      "MAX_FOCUS_AREAS": _bounded_int(
        merged.get("MAX_FOCUS_AREAS"),
        defaults["MAX_FOCUS_AREAS"],
        minimum=0,
        maximum=32,
      ),
      "MAX_FOCUS_AREA_LENGTH": _bounded_int(
        merged.get("MAX_FOCUS_AREA_LENGTH"),
        defaults["MAX_FOCUS_AREA_LENGTH"],
        minimum=8,
        maximum=256,
      ),
      "MAX_QUEUE_GLOBAL": _bounded_int(
        merged.get("MAX_QUEUE_GLOBAL"),
        defaults["MAX_QUEUE_GLOBAL"],
        minimum=1,
        maximum=1024,
      ),
      "MAX_QUEUE_PER_ACTOR": _bounded_int(
        merged.get("MAX_QUEUE_PER_ACTOR"),
        defaults["MAX_QUEUE_PER_ACTOR"],
        minimum=1,
        maximum=256,
      ),
      "MAX_QUEUE_PER_JOB": _bounded_int(
        merged.get("MAX_QUEUE_PER_JOB"),
        defaults["MAX_QUEUE_PER_JOB"],
        minimum=1,
        maximum=16,
      ),
      "OPERATION_TTL_SECONDS": _bounded_int(
        merged.get("OPERATION_TTL_SECONDS"),
        defaults["OPERATION_TTL_SECONDS"],
        minimum=60,
        maximum=30 * 86400,
      ),
      "LEASE_SECONDS": _bounded_int(
        merged.get("LEASE_SECONDS"),
        defaults["LEASE_SECONDS"],
        minimum=10,
        maximum=3600,
      ),
      "POLL_AFTER_MS": _bounded_int(
        merged.get("POLL_AFTER_MS"),
        defaults["POLL_AFTER_MS"],
        minimum=250,
        maximum=60000,
      ),
    }

  return resolve_config_block(
    owner,
    "API_OPERATIONS",
    DEFAULT_API_OPERATIONS_CONFIG,
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
    mode = _normalized_choice(
      merged.get("MODE"),
      {"syslog", "http", "wazuh_api"},
      defaults["MODE"],
    )
    return {
      "ENABLED": bool(merged.get("ENABLED", defaults["ENABLED"])),
      "IS_REQUIRED": bool(merged.get("IS_REQUIRED", defaults["IS_REQUIRED"])),
      "MODE": mode,
      "SYSLOG_HOST": str(merged.get("SYSLOG_HOST") or defaults["SYSLOG_HOST"]).strip(),
      "SYSLOG_PORT": _bounded_int(
        merged.get("SYSLOG_PORT", defaults["SYSLOG_PORT"]),
        defaults["SYSLOG_PORT"],
        minimum=1,
        maximum=65535,
      ),
      "HTTP_URL": _safe_http_url(merged.get("HTTP_URL") or defaults["HTTP_URL"]),
      "AUTH_MODE": _normalized_choice(
        merged.get("AUTH_MODE"),
        _WAZUH_AUTH_MODES,
        defaults["AUTH_MODE"],
      ),
      "TOKEN": str(merged.get("TOKEN") or defaults["TOKEN"]),
      "TOKEN_ENV": _safe_secret_env(
        merged.get("TOKEN_ENV"),
        defaults["TOKEN_ENV"],
      ),
      "USERNAME": str(merged.get("USERNAME") or defaults["USERNAME"]).strip(),
      "PASSWORD": str(merged.get("PASSWORD") or defaults["PASSWORD"]),
      "PASSWORD_ENV": _safe_secret_env(
        merged.get("PASSWORD_ENV"),
        defaults["PASSWORD_ENV"],
      ),
      "LOGIN_URL": _safe_http_url(merged.get("LOGIN_URL") or defaults["LOGIN_URL"]),
      "LOGIN_PATH": str(merged.get("LOGIN_PATH") or defaults["LOGIN_PATH"]).strip()
        or defaults["LOGIN_PATH"],
      "JWT_TTL_OVERRIDE_SECONDS": _bounded_int(
        merged.get("JWT_TTL_OVERRIDE_SECONDS", defaults["JWT_TTL_OVERRIDE_SECONDS"]),
        defaults["JWT_TTL_OVERRIDE_SECONDS"],
        minimum=0,
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
      "FAILURE_COOLDOWN_SECONDS": _bounded_int(
        merged.get("FAILURE_COOLDOWN_SECONDS", defaults["FAILURE_COOLDOWN_SECONDS"]),
        defaults["FAILURE_COOLDOWN_SECONDS"],
        minimum=1,
        maximum=3600,
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
      "AUTH_MODE": _normalized_choice(
        merged.get("AUTH_MODE"),
        _OPENCTI_AUTH_MODES,
        defaults["AUTH_MODE"],
      ),
      "TOKEN": str(merged.get("TOKEN") or defaults["TOKEN"]),
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
      "AUTH_MODE": _normalized_choice(
        merged.get("AUTH_MODE"),
        _TAXII_AUTH_MODES,
        defaults["AUTH_MODE"],
      ),
      "TOKEN": str(merged.get("TOKEN") or defaults["TOKEN"]),
      "TOKEN_ENV": _safe_secret_env(merged.get("TOKEN_ENV"), defaults["TOKEN_ENV"]),
      "USERNAME": str(merged.get("USERNAME") or defaults["USERNAME"]).strip(),
      "PASSWORD": str(merged.get("PASSWORD") or defaults["PASSWORD"]),
      "PASSWORD_ENV": _safe_secret_env(
        merged.get("PASSWORD_ENV"),
        defaults["PASSWORD_ENV"],
      ),
      "COLLECTION_ID": str(merged.get("COLLECTION_ID") or defaults["COLLECTION_ID"]).strip(),
      "MODE": _normalized_choice(
        merged.get("MODE"),
        {"publish_manual", "consume_manual"},
        defaults["MODE"],
      ),
      "TIMEOUT_SECONDS": _bounded_float(
        merged.get("TIMEOUT_SECONDS", defaults["TIMEOUT_SECONDS"]),
        defaults["TIMEOUT_SECONDS"],
        minimum=0.001,
      ),
    }

  return resolve_config_block(
    owner,
    "TAXII_EXPORT",
    DEFAULT_TAXII_EXPORT_CONFIG,
    normalizer=_normalize,
  )
