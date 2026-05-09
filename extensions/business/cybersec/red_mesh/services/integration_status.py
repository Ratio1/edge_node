from __future__ import annotations

import os
from datetime import datetime, timezone
from urllib.parse import urlsplit

from .config import (
  get_event_export_config,
  get_opencti_export_config,
  get_stix_export_config,
  get_suricata_correlation_config,
  get_taxii_export_config,
  get_wazuh_export_config,
)
from .event_builder import build_test_event


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


def _status_hkey(owner):
  return f"{getattr(owner, 'cfg_instance_id', 'redmesh')}:integrations"


def _load_status_record(owner, integration_id):
  try:
    payload = owner.chainstore_hget(hkey=_status_hkey(owner), key=integration_id)
  except Exception:
    return {}
  return payload if isinstance(payload, dict) else {}


def _save_status_record(owner, integration_id, record):
  try:
    owner.chainstore_hset(hkey=_status_hkey(owner), key=integration_id, value=record)
  except Exception:
    return False
  return True


def _redacted_url_host(url):
  raw = str(url or "").strip()
  if not raw:
    return ""
  try:
    parsed = urlsplit(raw)
  except ValueError:
    return ""
  return parsed.hostname or ""


def _has_env_secret(env_name):
  return bool(str(os.environ.get(str(env_name or ""), "")).strip())


def _base_status(integration_id, *, enabled, configured, destination_type, destination_label,
                 redacted_host="", redaction_mode="hash_only", error_class=None, config=None):
  return {
    "id": integration_id,
    "label": INTEGRATION_LABELS[integration_id],
    "enabled": bool(enabled),
    "configured": bool(configured),
    "destination_type": destination_type,
    "destination_label": destination_label,
    "redacted_host": redacted_host,
    "redaction_mode": redaction_mode,
    "last_dry_run_at": None,
    "last_success_at": None,
    "last_failure_at": None,
    "last_error_class": error_class,
    "last_event_id": None,
    "last_artifact_cid": None,
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
  ):
    if key in record:
      merged[key] = record.get(key)
  if base.get("last_error_class") and not base.get("configured"):
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
  event_cfg = get_event_export_config(owner)
  mode = cfg["MODE"]
  host = cfg["SYSLOG_HOST"] if mode == "syslog" else _redacted_url_host(cfg["HTTP_URL"])
  missing_secret = event_cfg["SIGN_PAYLOADS"] and not _has_env_secret(event_cfg["HMAC_SECRET_ENV"])
  configured = bool(cfg["ENABLED"]) and bool(host) and not missing_secret
  return _base_status(
    "wazuh",
    enabled=cfg["ENABLED"],
    configured=configured,
    destination_type=mode,
    destination_label="wazuh",
    redacted_host=host,
    error_class="missing_hmac_secret" if cfg["ENABLED"] and host and missing_secret else None,
    config={
      "mode": mode,
      "min_severity": cfg["MIN_SEVERITY"],
      "include_service_observations": cfg["INCLUDE_SERVICE_OBSERVATIONS"],
      "timeout_seconds": cfg["TIMEOUT_SECONDS"],
      "retry_attempts": cfg["RETRY_ATTEMPTS"],
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
  token_ready = _has_env_secret(cfg["TOKEN_ENV"])
  configured = bool(cfg["ENABLED"]) and bool(host) and token_ready
  return _base_status(
    "opencti",
    enabled=cfg["ENABLED"],
    configured=configured,
    destination_type="http",
    destination_label="opencti",
    redacted_host=host,
    error_class="missing_token" if cfg["ENABLED"] and host and not token_ready else None,
    config={
      "push_mode": cfg["PUSH_MODE"],
      "min_severity": cfg["MIN_SEVERITY"],
      "token_env": cfg["TOKEN_ENV"],
    },
  )


def _taxii_status(owner):
  cfg = get_taxii_export_config(owner)
  host = _redacted_url_host(cfg["SERVER_URL"])
  token_ready = _has_env_secret(cfg["TOKEN_ENV"])
  configured = bool(cfg["ENABLED"]) and bool(host) and bool(cfg["COLLECTION_ID"]) and token_ready
  return _base_status(
    "taxii",
    enabled=cfg["ENABLED"],
    configured=configured,
    destination_type="taxii_2.1",
    destination_label="taxii",
    redacted_host=host,
    error_class="missing_token" if cfg["ENABLED"] and host and not token_ready else None,
    config={
      "mode": cfg["MODE"],
      "collection_id": cfg["COLLECTION_ID"],
      "token_env": cfg["TOKEN_ENV"],
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


def get_integration_status(owner):
  integrations = {}
  for integration_id, builder in _STATUS_BUILDERS.items():
    base = builder(owner)
    integrations[integration_id] = _merge_record(base, _load_status_record(owner, integration_id))
  return {
    "schema_version": INTEGRATION_STATUS_SCHEMA_VERSION,
    "generated_at": _utc_timestamp(),
    "integrations": integrations,
  }


def record_integration_status(owner, integration_id, *, outcome, event_id=None,
                              artifact_cid=None, error_class=None, dry_run=False):
  if integration_id not in _STATUS_BUILDERS:
    return False
  now = _utc_timestamp()
  record = _load_status_record(owner, integration_id)
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
  if event_id:
    record["last_event_id"] = event_id
  if artifact_cid:
    record["last_artifact_cid"] = artifact_cid
  return _save_status_record(owner, integration_id, record)


def test_event_export(owner, integration_id="event_export"):
  integration_id = str(integration_id or "event_export").strip().lower()
  if integration_id not in _STATUS_BUILDERS:
    return {
      "status": "error",
      "error": "unknown_integration",
      "integration_id": integration_id,
    }

  cfg = get_event_export_config(owner)
  secret = os.environ.get(cfg["HMAC_SECRET_ENV"]) or "redmesh-test-event-secret"
  event = build_test_event(
    hmac_secret=secret,
    tenant_id=str(getattr(owner, "cfg_instance_id", "") or ""),
    environment=str(getattr(owner, "cfg_ee_node_network", "") or ""),
  )
  if integration_id == "wazuh":
    from .log_export import deliver_redmesh_event
    return deliver_redmesh_event(owner, event, integration_id=integration_id, dry_run=True)

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
