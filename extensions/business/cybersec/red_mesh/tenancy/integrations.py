"""Per-tenant SOC/CTI destination config records (RM-081 Phase 1).

Validation only. This module neither authorizes a caller nor resolves a destination; the
administration service owns admission and the export services own resolution.

Two facts shape it:

1. Only four integration ids have a destination and credentials, which is what "configure per
   tenant" means. `stix` is `destination_type: manual_download`, `event_export` is redaction and
   signing transport policy, and `suricata` is an IDS reading node traffic (postponed by the owner).
   A record for any of those three is refused outright rather than silently ignored, so the
   node-level three can never acquire tenant state by accident.
2. Config keys are the deployment block's own uppercase keys, not a translated shape. A tenant
   record is a partial override of the same block the node already resolves, so the export path can
   merge it without a mapping layer that could drift.

Credential values live in the record for now by owner decision (2026-09-16), which the deployment
config already supports inline (`services/config.py:81-84` TOKEN, and MISP_API_KEY). They are
write-only across the API: CREDENTIAL_KEYS names them so no projection can return one.
"""
from datetime import datetime, timezone

from .identity import canonical_account_id
from .ports import TenantStoreError


TENANT_INTEGRATION_IDS = ("misp", "opencti", "taxii", "wazuh")

# Refused outright, with their reason, rather than merely absent from the table above: a future
# edit that adds one of these to TENANT_INTEGRATION_IDS has to delete its entry here and say why.
NODE_LEVEL_INTEGRATION_IDS = {
  "stix": "manual download format, no destination and no credential",
  "event_export": "redaction and signing transport policy, no destination",
  "suricata": "node sensor telemetry; per-tenant ownership postponed by the owner 2026-09-16",
}

_BOOL = (bool,)
_STR = (str,)
_INT = (int,)
_NUMBER = (int, float)

# Keys mirror the deployment defaults in services/config.py and services/misp_config.py exactly.
# test_tenant_integration_records.py pins that correspondence, so a default renamed there fails here.
_CONFIG_KEYS = {
  "misp": {
    "ENABLED": _BOOL, "AUTO_EXPORT": _BOOL, "MISP_URL": _STR, "MISP_API_KEY": _STR,
    "MISP_VERIFY_TLS": _BOOL, "MISP_DISTRIBUTION": _INT, "MISP_PUBLISH": _BOOL,
    "TIMEOUT": _NUMBER, "MIN_SEVERITY": _STR,
  },
  "opencti": {
    "ENABLED": _BOOL, "URL": _STR, "AUTH_MODE": _STR, "TOKEN": _STR, "TOKEN_ENV": _STR,
    "PUSH_MODE": _STR, "MIN_SEVERITY": _STR,
  },
  "taxii": {
    "ENABLED": _BOOL, "SERVER_URL": _STR, "AUTH_MODE": _STR, "TOKEN": _STR, "TOKEN_ENV": _STR,
    "USERNAME": _STR, "PASSWORD": _STR, "PASSWORD_ENV": _STR, "COLLECTION_ID": _STR,
    "MODE": _STR, "TIMEOUT_SECONDS": _NUMBER,
  },
  "wazuh": {
    "ENABLED": _BOOL, "IS_REQUIRED": _BOOL, "MODE": _STR, "SYSLOG_HOST": _STR,
    "SYSLOG_PORT": _INT, "HTTP_URL": _STR, "AUTH_MODE": _STR, "TOKEN": _STR, "TOKEN_ENV": _STR,
    "USERNAME": _STR, "PASSWORD": _STR, "PASSWORD_ENV": _STR, "LOGIN_URL": _STR,
    "LOGIN_PATH": _STR, "JWT_TTL_OVERRIDE_SECONDS": _INT, "MIN_SEVERITY": _STR,
    "INCLUDE_SERVICE_OBSERVATIONS": _BOOL, "TIMEOUT_SECONDS": _NUMBER, "RETRY_ATTEMPTS": _INT,
    "FAILURE_COOLDOWN_SECONDS": _INT, "PERSIST_FAILED_PAYLOADS": _BOOL,
    "FAILED_PAYLOAD_SAMPLE_BYTES": _INT,
  },
}

# Every value a read projection must never carry. Not a display hint: the redaction test asserts
# that no projection returns any of these for any id.
CREDENTIAL_KEYS = {
  "misp": ("MISP_API_KEY",),
  "opencti": ("TOKEN",),
  "taxii": ("TOKEN", "PASSWORD"),
  "wazuh": ("TOKEN", "PASSWORD"),
}

_MAX_VALUE_LENGTH = 2048


def integration_ids():
  """The tenant-scopable ids, sorted, for callers that enumerate rather than hard-code."""
  return TENANT_INTEGRATION_IDS


def valid_integration_id(value):
  return isinstance(value, str) and value in TENANT_INTEGRATION_IDS


def status_tenant(integration_id, tenant_id):
  """The one place the tenant/node split for status and history is decided.

  The three node-level ids keep the node's key even under a tenant-scoped call, so what they report
  never changes and existing deployment history is never re-attributed to whichever tenant reads it
  first. Both services modules call this rather than testing membership themselves, so no call site
  can drift from another.
  """
  return tenant_id if tenant_id is not None and integration_id in TENANT_INTEGRATION_IDS else None


def normalize_integration_config(integration_id, config):
  """Return a detached, validated partial override. Raises ValueError for the 400 boundary."""
  if not valid_integration_id(integration_id):
    raise ValueError("Unknown integration")
  if not isinstance(config, dict):
    raise ValueError("Invalid integration config")
  allowed = _CONFIG_KEYS[integration_id]
  normalized = {}
  for key, value in config.items():
    if not isinstance(key, str) or key not in allowed:
      raise ValueError("Unknown integration config key")
    types = allowed[key]
    # bool is an int subclass: an int field must not silently accept True.
    if types is not _BOOL and isinstance(value, bool):
      raise ValueError("Invalid integration config value")
    if not isinstance(value, types):
      raise ValueError("Invalid integration config value")
    if isinstance(value, str):
      value.encode("utf-8", errors="strict")
      if len(value) > _MAX_VALUE_LENGTH or any(
          ord(ch) < 32 or 127 <= ord(ch) <= 159 or ch == "﻿" for ch in value):
        raise ValueError("Invalid integration config value")
    if isinstance(value, float) and value != value:
      raise ValueError("Invalid integration config value")
    normalized[key] = value
  return normalized


def public_integration_config(integration_id, config):
  """Project a stored config with every credential replaced by a configured/not-configured flag."""
  if not valid_integration_id(integration_id):
    raise ValueError("Unknown integration")
  if not isinstance(config, dict):
    raise ValueError("Invalid integration config")
  credentials = CREDENTIAL_KEYS[integration_id]
  projected = {key: value for key, value in config.items() if key not in credentials}
  projected["credentialsConfigured"] = bool(
    any(str(config.get(key) or "").strip() for key in credentials))
  return projected


def validate_integration(row, ids):
  """Validate the domain payload at every persisted integration boundary, enabled or not."""
  if len(ids) != 2 or not valid_integration_id(ids[1]):
    raise TenantStoreError("Invalid tenant integration record")
  if (row.get("tenant_id") != ids[0] or row.get("integration_id") != ids[1]
      or type(row.get("enabled")) is not bool or not row.get("updated_by")
      or canonical_account_id(row["updated_by"]) != row["updated_by"]):
    raise TenantStoreError("Invalid tenant integration record")
  # normalize_integration_config copies validated values verbatim and never coerces, so its
  # returning at all is the whole check; comparing its result to the input would be dead code.
  try:
    normalize_integration_config(ids[1], row.get("config"))
  except (ValueError, TypeError, RecursionError) as exc:
    raise TenantStoreError("Invalid tenant integration record") from exc
  try:
    updated_at = datetime.fromisoformat(row.get("updated_at"))
  except (TypeError, ValueError) as exc:
    raise TenantStoreError("Invalid tenant integration record") from exc
  if updated_at.tzinfo != timezone.utc:
    raise TenantStoreError("Invalid tenant integration record")
