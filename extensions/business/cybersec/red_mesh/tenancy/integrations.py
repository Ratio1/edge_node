"""Deployment SOC/CTI destination config: the configurable ids, their keys and credentials.

Validation only. This module neither authorizes a caller nor resolves a destination; the
administration service owns admission and the export services own resolution.

Two facts shape it:

1. Only four integration ids have a destination and credentials, which is what an STA override can
   set (RM-139). `stix` is `destination_type: manual_download`, `event_export` is redaction and
   signing transport policy, and `suricata` is an IDS reading node traffic; none of them is a valid
   id here, so they can never acquire override state by accident.
2. Config keys are the deployment block's own uppercase keys, not a translated shape. An override is
   a partial override of the same block the node already resolves, so the export path can merge it
   without a mapping layer that could drift.

Credential values live in the record for now by owner decision (2026-09-16), which the deployment
config already supports inline (`services/config.py:81-84` TOKEN, and MISP_API_KEY). They are
write-only across the API: CREDENTIAL_KEYS names them so no projection can return one.

RM-081 stored one such config per tenant (record kind `integration`). RM-139 retired those records:
`retire_tenant_integration_records` deletes them once at plugin start.
"""
INTEGRATION_IDS = ("misp", "opencti", "taxii", "wazuh")
# The retired RM-081 per-tenant record kind, keyed `(tenant_id, integration_id)`.
RETIRED_TENANT_KIND = "integration"

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
  """The configurable ids, sorted, for callers that enumerate rather than hard-code."""
  return INTEGRATION_IDS


def valid_integration_id(value):
  return isinstance(value, str) and value in INTEGRATION_IDS


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


def retire_tenant_integration_records(store):
  """Delete every stored per-tenant integration row of the store's namespace, orphans of deleted
  tenants included, and answer how many went. Idempotent: a second run finds none. The rows are
  found by their field keys and never decoded, so their credentials are never read."""
  ids = store.record_ids(RETIRED_TENANT_KIND)
  for record_ids in ids:
    store.delete(RETIRED_TENANT_KIND, *record_ids)
  return len(ids)
