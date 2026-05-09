from __future__ import annotations

import copy
import hashlib
import hmac
import json


SENSITIVE_FIELD_NAMES = {
  "api_key",
  "apikey",
  "auth",
  "authorization",
  "authorization_header",
  "bearer",
  "cookie",
  "cookies",
  "credential",
  "credentials",
  "csrf",
  "csrf_token",
  "exploit_payload",
  "html",
  "password",
  "payload",
  "raw",
  "raw_body",
  "raw_request",
  "raw_response",
  "request_body",
  "response_body",
  "secret",
  "session",
  "session_id",
  "set_cookie",
  "token",
}


def stable_hmac_pseudonym(value, secret, *, prefix="hmac"):
  """Return a deterministic HMAC pseudonym for low-entropy identifiers."""
  if value is None:
    return None
  normalized = str(value).strip()
  if not normalized:
    return ""
  secret_value = str(secret or "").encode("utf-8")
  if not secret_value:
    secret_value = b"redmesh-event-redaction-missing-secret"
  digest = hmac.new(secret_value, normalized.encode("utf-8"), hashlib.sha256).hexdigest()
  return f"{prefix}:{digest[:24]}"


def stable_sha256(value):
  if value is None:
    return None
  normalized = str(value).encode("utf-8")
  return hashlib.sha256(normalized).hexdigest()


def _is_sensitive_key(key):
  return str(key or "").strip().lower() in SENSITIVE_FIELD_NAMES


def strip_sensitive_fields(value):
  """Recursively remove sensitive fields from a JSON-like payload."""
  if isinstance(value, dict):
    cleaned = {}
    for key, item in value.items():
      if _is_sensitive_key(key):
        continue
      cleaned[key] = strip_sensitive_fields(item)
    return cleaned
  if isinstance(value, list):
    return [strip_sensitive_fields(item) for item in value]
  return value


def contains_sensitive_value(value, needles):
  serialized = json.dumps(value, sort_keys=True, default=str)
  return any(str(needle) in serialized for needle in needles)


def redact_event_payload(
  payload,
  *,
  hmac_secret,
  include_target_display=False,
  include_worker_source_ip=False,
  include_egress_ip=False,
  include_service_banners=False,
):
  """Apply destination redaction policy to a canonical event dict."""
  event = strip_sensitive_fields(copy.deepcopy(payload or {}))

  target = event.get("target")
  if isinstance(target, dict):
    raw_identifier = (
      target.get("display")
      or target.get("address")
      or target.get("ip")
      or target.get("hostname")
      or target.get("url")
      or target.get("cidr")
    )
    if raw_identifier and not target.get("pseudonym"):
      target["pseudonym"] = stable_hmac_pseudonym(raw_identifier, hmac_secret, prefix="target")
    for key in ("address", "ip", "hostname", "url", "cidr"):
      target.pop(key, None)
    if not include_target_display:
      target["display"] = None

  worker = event.get("worker")
  if isinstance(worker, dict):
    source_ip = worker.get("source_ip")
    if source_ip and not include_worker_source_ip:
      worker["source_ip_pseudonym"] = stable_hmac_pseudonym(source_ip, hmac_secret, prefix="ip")
      worker["source_ip"] = None
    egress_ip = worker.get("expected_egress_ip")
    if egress_ip and not include_egress_ip:
      worker["expected_egress_ip_pseudonym"] = stable_hmac_pseudonym(egress_ip, hmac_secret, prefix="ip")
      worker["expected_egress_ip"] = None

  window = event.get("window")
  if isinstance(window, dict):
    raw_egress_ips = window.pop("expected_egress_ips", None)
    if isinstance(raw_egress_ips, list) and raw_egress_ips:
      if include_egress_ip:
        window["expected_egress_ips"] = raw_egress_ips
      else:
        existing = window.get("expected_egress_ip_pseudonyms")
        pseudonyms = list(existing) if isinstance(existing, list) else []
        for ip in raw_egress_ips:
          pseudonym = stable_hmac_pseudonym(ip, hmac_secret, prefix="ip")
          if pseudonym not in pseudonyms:
            pseudonyms.append(pseudonym)
        window["expected_egress_ip_pseudonyms"] = pseudonyms
        window["expected_egress_ip_count"] = max(
          int(window.get("expected_egress_ip_count") or 0),
          len(raw_egress_ips),
        )
    for key in ("target_value", "target_ip", "target_url", "target_hostname"):
      raw_target = window.pop(key, None)
      if raw_target and not window.get("target_pseudonym"):
        window["target_pseudonym"] = stable_hmac_pseudonym(raw_target, hmac_secret, prefix="target")
    if not include_target_display:
      window["target_display"] = None

  observation = event.get("observation")
  if isinstance(observation, dict):
    banner = observation.get("banner")
    if banner and not include_service_banners:
      observation["banner_hash"] = stable_sha256(banner)
      observation.pop("banner", None)
    for key in ("raw_response", "raw_request", "response_body", "request_body", "html"):
      observation.pop(key, None)

  event["redaction"] = {
    **(event.get("redaction") if isinstance(event.get("redaction"), dict) else {}),
    "credentials_excluded": True,
    "cookies_excluded": True,
    "tokens_excluded": True,
    "raw_responses_excluded": True,
    "exploit_payloads_excluded": True,
  }
  return event
