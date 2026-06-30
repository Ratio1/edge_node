from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from .auth import credentials_missing
from .config import get_event_export_config, get_wazuh_export_config


SOC_COOLDOWN_ERROR_CLASSES = {
  "invalid_auth_config",
  "missing_credentials",
  "missing_hmac_secret",
  "missing_http_url",
  "missing_token",
  "http_unreachable",
  "timeout",
}

SOC_DELIVERY_COOLDOWN_ERROR = "soc_delivery_cooldown"


def is_soc_cooldown_error(error_class):
  normalized = str(error_class or "").strip().lower()
  return normalized in SOC_COOLDOWN_ERROR_CLASSES or normalized.startswith("http_5")


def utc_timestamp():
  return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_utc_timestamp(value):
  if not value:
    return None
  raw = str(value).strip()
  if not raw:
    return None
  if raw.endswith("Z"):
    raw = raw[:-1] + "+00:00"
  try:
    parsed = datetime.fromisoformat(raw)
  except ValueError:
    return None
  if parsed.tzinfo is None:
    return parsed.replace(tzinfo=timezone.utc)
  return parsed.astimezone(timezone.utc)


def retry_after_seconds(cooldown_until, *, now=None):
  until = _parse_utc_timestamp(cooldown_until)
  if until is None:
    return None
  if now is None:
    now = datetime.now(timezone.utc)
  remaining = int((until - now).total_seconds())
  return max(0, remaining)


def _status_hkey(owner):
  return f"{getattr(owner, 'cfg_instance_id', 'redmesh')}:integrations"


def load_integration_status_record(owner, integration_id):
  try:
    payload = owner.chainstore_hget(hkey=_status_hkey(owner), key=integration_id)
  except Exception:
    return {}
  return payload if isinstance(payload, dict) else {}


def _has_env_secret(env_name):
  return bool(str(os.environ.get(str(env_name or ""), "")).strip())


def redacted_url_host(url):
  raw = str(url or "").strip()
  if not raw:
    return ""
  try:
    parsed = urlsplit(raw)
  except ValueError:
    return ""
  return parsed.hostname or ""


def wazuh_readiness(owner):
  cfg = get_wazuh_export_config(owner)
  event_cfg = get_event_export_config(owner)
  mode = cfg["MODE"]
  host = cfg["SYSLOG_HOST"] if mode == "syslog" else redacted_url_host(cfg["HTTP_URL"])
  missing_secret = event_cfg["SIGN_PAYLOADS"] and not _has_env_secret(event_cfg["HMAC_SECRET_ENV"])
  credentials_error = credentials_missing(cfg) if mode in {"http", "wazuh_api"} else None
  configured = (
    bool(cfg["ENABLED"])
    and bool(host)
    and not missing_secret
    and credentials_error is None
  )
  if not cfg["ENABLED"]:
    error_class = None
    status = "disabled"
  elif not host:
    error_class = "missing_syslog_host" if mode == "syslog" else "missing_http_url"
    status = "not_configured"
  elif missing_secret:
    error_class = "missing_hmac_secret"
    status = "not_configured"
  elif credentials_error:
    error_class = credentials_error
    status = "not_configured"
  else:
    error_class = None
    status = "ready"
  return {
    "configured": configured,
    "error_class": error_class,
    "status": status,
    "host": host,
    "mode": mode,
    "required": bool(cfg.get("IS_REQUIRED")),
  }


def apply_integration_outcome_policy(owner, integration_id, record, *, outcome, error_class=None,
                                     previous_error_class=None, now=None):
  if now is None:
    now = utc_timestamp()
  if not isinstance(record, dict):
    record = {}
  if outcome == "success":
    record["integration_status"] = "ok"
    record["consecutive_failure_count"] = 0
    record.pop("cooldown_until", None)
    record.pop("retry_after_seconds", None)
    return record
  if outcome != "failure":
    return record

  normalized_error = str(error_class or "unknown_error")
  record["integration_status"] = "degraded"
  record["failure_count"] = int(record.get("failure_count") or 0) + 1
  if not record.get("first_failure_at"):
    record["first_failure_at"] = now

  previous_error = previous_error_class
  if previous_error == normalized_error:
    consecutive = int(record.get("consecutive_failure_count") or 0) + 1
  else:
    consecutive = 1
    record["current_failure_first_at"] = now
  record["consecutive_failure_count"] = consecutive

  if integration_id == "wazuh" and is_soc_cooldown_error(normalized_error) and consecutive >= 2:
    cfg = get_wazuh_export_config(owner)
    cooldown_seconds = int(cfg.get("FAILURE_COOLDOWN_SECONDS") or 300)
    until = datetime.now(timezone.utc) + timedelta(seconds=max(1, cooldown_seconds))
    record["cooldown_until"] = until.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    record["integration_status"] = "cooling_down"
  return record


def current_integration_cooldown(owner, integration_id="wazuh"):
  record = load_integration_status_record(owner, integration_id)
  retry_after = retry_after_seconds(record.get("cooldown_until"))
  if retry_after is None or retry_after <= 0:
    return None
  return {
    "integration_id": integration_id,
    "status": "cooling_down",
    "error_class": record.get("last_error_class") or SOC_DELIVERY_COOLDOWN_ERROR,
    "cooldown_until": record.get("cooldown_until"),
    "retry_after_seconds": retry_after,
  }


def required_soc_launch_error(owner):
  event_cfg = get_event_export_config(owner)
  wazuh_cfg = get_wazuh_export_config(owner)
  if not wazuh_cfg.get("IS_REQUIRED"):
    return None
  if not event_cfg["ENABLED"] or not wazuh_cfg["ENABLED"]:
    return None

  readiness = wazuh_readiness(owner)
  if not readiness["configured"]:
    error_class = readiness.get("error_class") or "not_configured"
    return {
      "error": "soc_export_required_unavailable",
      "message": "Required SOC export is enabled but Wazuh/SOC delivery is not configured.",
      "integration_id": "wazuh",
      "status": readiness.get("status") or "not_configured",
      "error_class": error_class,
      "required": True,
    }

  cooldown = current_integration_cooldown(owner, "wazuh")
  if cooldown:
    return {
      "error": "soc_export_required_unavailable",
      "message": "Required SOC export is cooling down after repeated delivery failures.",
      "integration_id": "wazuh",
      "status": "cooling_down",
      "error_class": cooldown["error_class"],
      "cooldown_until": cooldown["cooldown_until"],
      "retry_after_seconds": cooldown["retry_after_seconds"],
      "required": True,
    }
  return None
