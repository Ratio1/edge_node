from __future__ import annotations

import os
from datetime import datetime, timezone

from ..tenancy.effects import EffectState
from ..tenancy.integrations import status_tenant
from .auth import credentials_missing
from .config import (
  get_event_export_config,
  get_opencti_export_config,
  get_stix_export_config,
  get_suricata_correlation_config,
  get_taxii_export_config,
  get_wazuh_export_config,
)
from .event_builder import build_test_event
from .soc_export_policy import (
  apply_integration_outcome_policy,
  redacted_url_host as _redacted_url_host,
  retry_after_seconds,
  wazuh_readiness,
)


INTEGRATION_STATUS_SCHEMA_VERSION = "1.0.0"

INTEGRATION_LABELS = {
  "event_export": "RedMesh Event Export",
  "wazuh": "Wazuh / Generic SIEM",
  "suricata": "Suricata / Security Onion",
  "stix": "STIX 2.1 Export",
  "opencti": "OpenCTI",
  "taxii": "TAXII",
}


def _utc_timestamp():
  return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _status_hkey(owner, tenant_id=None):
  """Node history keeps its original key; a tenant's history lives beside it, never merged.

  Callers pass an integration id through status_tenant() first, so the three node-level ids keep
  the node key even under a tenant-scoped call. Existing deployment history is therefore never
  stranded or re-attributed to whichever tenant happens to read first.
  """
  base = f"{getattr(owner, 'cfg_instance_id', 'redmesh')}:integrations"
  if tenant_id is None:
    return base
  if not isinstance(tenant_id, str) or not tenant_id.strip() or ":" in tenant_id:
    raise ValueError("Invalid tenant for integration status")
  return f"{base}:{tenant_id}"


def _load_status_record(owner, integration_id, tenant_id=None):
  try:
    payload = owner.chainstore_hget(
      hkey=_status_hkey(owner, status_tenant(integration_id, tenant_id)), key=integration_id)
  except Exception:
    return {}
  return payload if isinstance(payload, dict) else {}


def _save_status_record(owner, integration_id, record, tenant_id=None):
  try:
    owner.chainstore_hset(
      hkey=_status_hkey(owner, status_tenant(integration_id, tenant_id)),
      key=integration_id, value=record)
  except Exception:
    return False
  return True


def _has_env_secret(env_name):
  return bool(str(os.environ.get(str(env_name or ""), "")).strip())


# Integrations whose Test button does a real probe (Wazuh delivery,
# OpenCTI GraphQL me{}, TAXII api root GET). The frontend should only
# render the Test button for these. Suricata is intentionally absent
# because its integration is upload-based — there is no remote endpoint
# to ping. event_export is also absent because the "test" was just
# stamping a dry-run timestamp; the wazuh button covers the real flow.
_INTEGRATIONS_WITH_TEST = {"wazuh", "opencti", "taxii"}


def _base_status(integration_id, *, enabled, configured, destination_type, destination_label,
                 redacted_host="", redaction_mode="hash_only", error_class=None, config=None,
                 required=False, status=None):
  return {
    "id": integration_id,
    "label": INTEGRATION_LABELS[integration_id],
    "enabled": bool(enabled),
    "configured": bool(configured),
    "required": bool(required),
    "status": status or ("ready" if configured else ("disabled" if not enabled else "not_configured")),
    "destination_type": destination_type,
    "destination_label": destination_label,
    "redacted_host": redacted_host,
    "redaction_mode": redaction_mode,
    "supports_test": integration_id in _INTEGRATIONS_WITH_TEST,
    "last_dry_run_at": None,
    "last_success_at": None,
    "last_failure_at": None,
    "last_error_class": error_class,
    "last_event_id": None,
    "last_artifact_cid": None,
    "first_failure_at": None,
    "current_failure_first_at": None,
    "failure_count": 0,
    "consecutive_failure_count": 0,
    "cooldown_until": None,
    "retry_after_seconds": None,
    "integration_status": status or ("ready" if configured else ("disabled" if not enabled else "not_configured")),
    "config": config or {},
  }


def _merge_record(base, record):
  merged = dict(base)
  for key in (
    "last_dry_run_at",
    "last_success_at",
    "last_failure_at",
    "last_error_class",
    "last_event_id",
    "last_artifact_cid",
    "first_failure_at",
    "current_failure_first_at",
    "failure_count",
    "consecutive_failure_count",
    "cooldown_until",
    "integration_status",
  ):
    if key in record:
      merged[key] = record.get(key)
  retry_after = retry_after_seconds(merged.get("cooldown_until"))
  if retry_after is not None and retry_after > 0:
    merged["retry_after_seconds"] = retry_after
    merged["status"] = "cooling_down"
    merged["integration_status"] = "cooling_down"
  elif merged.get("integration_status") == "cooling_down":
    merged["integration_status"] = "degraded" if merged.get("last_error_class") else merged["status"]
  if base.get("last_error_class") and not base.get("configured") and not merged.get("last_error_class"):
    merged["last_error_class"] = base["last_error_class"]
  return merged


def _event_export_status(owner):
  cfg = get_event_export_config(owner)
  missing_secret = cfg["SIGN_PAYLOADS"] and not _has_env_secret(cfg["HMAC_SECRET_ENV"])
  configured = bool(cfg["ENABLED"]) and not missing_secret
  return _base_status(
    "event_export",
    enabled=cfg["ENABLED"],
    configured=configured,
    destination_type="canonical",
    destination_label="redmesh.event.v1",
    redaction_mode=cfg["REDACTION_MODE"],
    error_class="missing_hmac_secret" if missing_secret and cfg["ENABLED"] else None,
    config={
      "sign_payloads": cfg["SIGN_PAYLOADS"],
      "hmac_secret_env": cfg["HMAC_SECRET_ENV"],
      "default_tlp": cfg["DEFAULT_TLP"],
      "trust_profile": cfg["DESTINATION_TRUST_PROFILE"],
    },
  )


def _wazuh_status(owner):
  cfg = get_wazuh_export_config(owner)
  readiness = wazuh_readiness(owner)
  mode = readiness["mode"]
  host = readiness["host"]
  return _base_status(
    "wazuh",
    enabled=cfg["ENABLED"],
    configured=readiness["configured"],
    required=cfg["IS_REQUIRED"],
    status=readiness["status"],
    destination_type=mode,
    destination_label="wazuh",
    redacted_host=host,
    error_class=readiness["error_class"],
    config={
      "mode": mode,
      "auth_mode": cfg["AUTH_MODE"],
      "is_required": cfg["IS_REQUIRED"],
      "min_severity": cfg["MIN_SEVERITY"],
      "include_service_observations": cfg["INCLUDE_SERVICE_OBSERVATIONS"],
      "timeout_seconds": cfg["TIMEOUT_SECONDS"],
      "retry_attempts": cfg["RETRY_ATTEMPTS"],
      "failure_cooldown_seconds": cfg["FAILURE_COOLDOWN_SECONDS"],
      "persist_failed_payloads": cfg["PERSIST_FAILED_PAYLOADS"],
    },
  )


def _suricata_status(owner):
  cfg = get_suricata_correlation_config(owner)
  return _base_status(
    "suricata",
    enabled=cfg["ENABLED"],
    configured=bool(cfg["ENABLED"]),
    destination_type=cfg["MODE"],
    destination_label="suricata-security-onion",
    config={
      "match_window_seconds": cfg["MATCH_WINDOW_SECONDS"],
      "clock_skew_seconds": cfg["CLOCK_SKEW_SECONDS"],
      "auto_suppress": False,
    },
  )


def _stix_status(owner):
  cfg = get_stix_export_config(owner)
  return _base_status(
    "stix",
    enabled=cfg["ENABLED"],
    configured=bool(cfg["ENABLED"]),
    destination_type="manual_download",
    destination_label="stix-2.1",
    config={
      "default_tlp": cfg["DEFAULT_TLP"],
      "include_observed_data": cfg["INCLUDE_OBSERVED_DATA"],
      "include_indicators": cfg["INCLUDE_INDICATORS"],
    },
  )


def _opencti_status(owner):
  cfg = get_opencti_export_config(owner)
  host = _redacted_url_host(cfg["URL"])
  credentials_error = credentials_missing(cfg)
  configured = bool(cfg["ENABLED"]) and bool(host) and credentials_error is None
  return _base_status(
    "opencti",
    enabled=cfg["ENABLED"],
    configured=configured,
    destination_type="http",
    destination_label="opencti",
    redacted_host=host,
    error_class=credentials_error if cfg["ENABLED"] and host else None,
    config={
      "push_mode": cfg["PUSH_MODE"],
      "min_severity": cfg["MIN_SEVERITY"],
      "auth_mode": cfg["AUTH_MODE"],
      "token_env": cfg["TOKEN_ENV"],
    },
  )


def _taxii_status(owner):
  cfg = get_taxii_export_config(owner)
  host = _redacted_url_host(cfg["SERVER_URL"])
  credentials_error = credentials_missing(cfg)
  configured = (
    bool(cfg["ENABLED"])
    and bool(host)
    and bool(cfg["COLLECTION_ID"])
    and credentials_error is None
  )
  return _base_status(
    "taxii",
    enabled=cfg["ENABLED"],
    configured=configured,
    destination_type="taxii_2.1",
    destination_label="taxii",
    redacted_host=host,
    error_class=credentials_error if cfg["ENABLED"] and host else None,
    config={
      "mode": cfg["MODE"],
      "auth_mode": cfg["AUTH_MODE"],
      "collection_id": cfg["COLLECTION_ID"],
      "token_env": cfg["TOKEN_ENV"],
      "timeout_seconds": cfg["TIMEOUT_SECONDS"],
    },
  )


_STATUS_BUILDERS = {
  "event_export": _event_export_status,
  "wazuh": _wazuh_status,
  "suricata": _suricata_status,
  "stix": _stix_status,
  "opencti": _opencti_status,
  "taxii": _taxii_status,
}


# Public configuration-only projection (RM-026 I1a.3c.8).
#
# The owner chose to omit unowned historical event IDs and artifact CIDs from the
# global integration view while retaining safe configuration/readiness status. This
# path therefore rebuilds from the same six base builders and never touches
# _load_status_record/_merge_record, so no persisted history can reach it. The
# historical producer, record writes and cooldown policy above are unchanged and
# still serve the internal export policy.

PUBLIC_CONFIG_FIELDS = (
  "id",
  "label",
  "enabled",
  "configured",
  "required",
  "supports_test",
  "status",
  "destination_type",
  "destination_label",
  "redaction_mode",
  "configuration_error",
)

_PUBLIC_CONFIG_STATUSES = frozenset({"disabled", "not_configured", "ready"})

_PUBLIC_REDACTION_MODES = frozenset({"hash_only", "summary", "internal_soc", "custom"})

# Configuration codes the six builders can produce. A delivery-outcome error class
# can never appear here because records are not read; an unknown code therefore
# means the builder contract moved, and we fail closed rather than publish it.
_PUBLIC_CONFIGURATION_ERRORS = frozenset({
  "missing_hmac_secret",
  "missing_syslog_host",
  "missing_http_url",
  "missing_token",
  "missing_credentials",
  "invalid_auth_config",
})

_PUBLIC_DESTINATION_TYPES = {
  "event_export": frozenset({"canonical"}),
  "wazuh": frozenset({"syslog", "http", "wazuh_api"}),
  "suricata": frozenset({
    "uploaded_eve_json_or_external_query",
    "uploaded_eve_json",
    "external_query",
  }),
  "stix": frozenset({"manual_download"}),
  "opencti": frozenset({"http"}),
  "taxii": frozenset({"taxii_2.1"}),
}

_PUBLIC_DESTINATION_LABELS = {
  "event_export": "redmesh.event.v1",
  "wazuh": "wazuh",
  "suricata": "suricata-security-onion",
  "stix": "stix-2.1",
  "opencti": "opencti",
  "taxii": "taxii",
}


class IntegrationConfigUnavailable(Exception):
  """The builder contract did not match the pinned public configuration shape."""


def _public_config_item(integration_id, base):
  if not isinstance(base, dict):
    raise IntegrationConfigUnavailable(integration_id)

  enabled = base.get("enabled")
  configured = base.get("configured")
  required = base.get("required")
  supports_test = base.get("supports_test")
  if any(type(value) is not bool for value in (enabled, configured, required, supports_test)):
    raise IntegrationConfigUnavailable(integration_id)
  if supports_test is not (integration_id in _INTEGRATIONS_WITH_TEST):
    raise IntegrationConfigUnavailable(integration_id)
  if required and integration_id != "wazuh":
    raise IntegrationConfigUnavailable(integration_id)

  # Derived from the booleans rather than passed through, so the public status can
  # only ever be one of the three configuration states.
  if not enabled:
    status = "disabled"
  elif configured:
    status = "ready"
  else:
    status = "not_configured"
  if status not in _PUBLIC_CONFIG_STATUSES:
    raise IntegrationConfigUnavailable(integration_id)

  destination_type = base.get("destination_type")
  if destination_type not in _PUBLIC_DESTINATION_TYPES[integration_id]:
    raise IntegrationConfigUnavailable(integration_id)
  if base.get("destination_label") != _PUBLIC_DESTINATION_LABELS[integration_id]:
    raise IntegrationConfigUnavailable(integration_id)

  redaction_mode = base.get("redaction_mode")
  if redaction_mode not in _PUBLIC_REDACTION_MODES:
    raise IntegrationConfigUnavailable(integration_id)

  configuration_error = base.get("last_error_class")
  if configuration_error is not None:
    if (not isinstance(configuration_error, str)
        or configuration_error not in _PUBLIC_CONFIGURATION_ERRORS):
      raise IntegrationConfigUnavailable(integration_id)

  label = INTEGRATION_LABELS[integration_id]
  if base.get("id") != integration_id or base.get("label") != label:
    raise IntegrationConfigUnavailable(integration_id)

  return {
    "id": integration_id,
    "label": label,
    "enabled": enabled,
    "configured": configured,
    "required": required,
    "supports_test": supports_test,
    "status": status,
    "destination_type": destination_type,
    "destination_label": _PUBLIC_DESTINATION_LABELS[integration_id],
    "redaction_mode": redaction_mode,
    "configuration_error": configuration_error,
  }


def get_public_integration_config(owner):
  """Configuration/readiness only: no history, counts, cooldown or stored errors."""
  integrations = {}
  for integration_id, builder in _STATUS_BUILDERS.items():
    # Detached per integration; never _merge_record and never _load_status_record.
    integrations[integration_id] = _public_config_item(integration_id, builder(owner))
  if set(integrations) != set(_STATUS_BUILDERS):
    raise IntegrationConfigUnavailable("integrations")
  generated_at = _utc_timestamp()
  if not isinstance(generated_at, str) or not generated_at.endswith("Z"):
    raise IntegrationConfigUnavailable("generated_at")
  return {
    "schema_version": INTEGRATION_STATUS_SCHEMA_VERSION,
    "generated_at": generated_at,
    "integrations": integrations,
  }


def get_integration_status(owner, tenant_id=None):
  """Historical producer: configuration merged with persisted delivery outcomes.

  Deliberately retained with no production caller as of RM-026 I1a.3c.8. The public
  endpoint now serves get_public_integration_config instead, and the export policy
  uses record_integration_status/_load_status_record directly rather than this
  aggregate. It is kept as F2 groundwork for a tenant-scoped history view, and its
  merge semantics stay under test; remove it if F2 lands on a different shape.
  """
  integrations = {}
  for integration_id, builder in _STATUS_BUILDERS.items():
    base = builder(owner)
    integrations[integration_id] = _merge_record(
      base, _load_status_record(owner, integration_id, tenant_id))
  return {
    "schema_version": INTEGRATION_STATUS_SCHEMA_VERSION,
    "generated_at": _utc_timestamp(),
    "integrations": integrations,
  }


def record_integration_status(owner, integration_id, *, outcome, event_id=None,
                              artifact_cid=None, error_class=None, dry_run=False, tenant_id=None):
  if integration_id not in _STATUS_BUILDERS:
    return False
  now = _utc_timestamp()
  record = _load_status_record(owner, integration_id, tenant_id)
  previous_error_class = record.get("last_error_class")
  if dry_run:
    record["last_dry_run_at"] = now
  if outcome == "success":
    record["last_success_at"] = now
    record["last_error_class"] = None
  elif outcome == "failure":
    record["last_failure_at"] = now
    record["last_error_class"] = error_class or "unknown_error"
  elif error_class:
    record["last_error_class"] = error_class
  record = apply_integration_outcome_policy(
    owner,
    integration_id,
    record,
    outcome=outcome,
    error_class=record.get("last_error_class") or error_class,
    previous_error_class=previous_error_class,
    now=now,
  )
  if event_id:
    record["last_event_id"] = event_id
  if artifact_cid:
    record["last_artifact_cid"] = artifact_cid
  return _save_status_record(owner, integration_id, record, tenant_id)


def test_event_export(owner, integration_id="event_export", *, ledger=None):
  """Probe or deliver a synthetic event. `ledger` records what actually left the node."""
  integration_id = str(integration_id or "event_export").strip().lower()
  if integration_id not in _STATUS_BUILDERS:
    return {
      "status": "error",
      "error": "unknown_integration",
      "integration_id": integration_id,
    }

  if integration_id == "wazuh":
    cfg = get_event_export_config(owner)
    secret = os.environ.get(cfg["HMAC_SECRET_ENV"]) or "redmesh-test-event-secret"
    event = build_test_event(
      hmac_secret=secret,
      tenant_id=str(getattr(owner, "cfg_instance_id", "") or ""),
      environment=str(getattr(owner, "cfg_ee_node_network", "") or ""),
    )
    from .log_export import deliver_redmesh_event
    if ledger is not None:
      # A real send follows: dry_run only affects the status stamp, not the transmission.
      ledger.checkpoint()
    delivered = deliver_redmesh_event(owner, event, integration_id=integration_id, dry_run=True)
    # deliver_redmesh_event returns "sent" | "disabled" | "error" -- never "skipped". Gating on
    # "not skipped" recorded a delivery when the integration was disabled and nothing left the node.
    if ledger is not None and isinstance(delivered, dict) and delivered.get("status") == "sent":
      ledger.record(EffectState.DELIVERED)
    return delivered

  if integration_id == "opencti":
    from .opencti_export import probe_opencti
    return probe_opencti(owner)

  if integration_id == "taxii":
    from .taxii_export import probe_taxii
    return probe_taxii(owner)

  if integration_id == "suricata":
    # Suricata correlation is pull-based — the operator uploads EVE JSONL
    # after a job and RedMesh correlates against the job's time window.
    # There's no remote endpoint to ping. UI hides the button via
    # supports_test=False; this branch exists only for clients that ignore
    # that hint and call the endpoint anyway.
    return {
      "status": "not_applicable",
      "integration_id": "suricata",
      "message": "Suricata is upload-based; upload EVE JSONL after a job to test correlation.",
    }

  # Fallback (event_export, stix): synthesize a sample event and stamp
  # last_dry_run_at — these have no remote endpoint either, but the
  # dry-run stamp is a useful "the schema builds and signs cleanly" smoke.
  cfg = get_event_export_config(owner)
  secret = os.environ.get(cfg["HMAC_SECRET_ENV"]) or "redmesh-test-event-secret"
  event = build_test_event(
    hmac_secret=secret,
    tenant_id=str(getattr(owner, "cfg_instance_id", "") or ""),
    environment=str(getattr(owner, "cfg_ee_node_network", "") or ""),
  )
  persisted = record_integration_status(
    owner,
    integration_id,
    outcome="success",
    event_id=event["event_id"],
    dry_run=True,
  )
  return {
    "status": "ok",
    "dry_run": True,
    "integration_id": integration_id,
    "event": event,
    "persisted": persisted,
  }
