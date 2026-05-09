from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import urllib.error
import urllib.request

from ..models.event_schema import validate_event_dict
from ..repositories import ArtifactRepository
from .config import get_event_export_config, get_wazuh_export_config
from .integration_status import record_integration_status


WAZUH_EVENT_GROUPS = (
  "redmesh.lifecycle",
  "redmesh.service_observation",
  "redmesh.finding",
  "redmesh.export",
  "redmesh.attestation",
  "redmesh.correlation",
)


def _artifact_repo(owner):
  getter = getattr(type(owner), "_get_artifact_repository", None)
  if callable(getter):
    return getter(owner)
  return ArtifactRepository(owner)


def _json_bytes(payload):
  return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _payload_sha256(payload_bytes):
  return hashlib.sha256(payload_bytes).hexdigest()


def compute_payload_hmac(payload_bytes, secret):
  if isinstance(payload_bytes, str):
    payload_bytes = payload_bytes.encode("utf-8")
  return hmac.new(str(secret or "").encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()


def _event_id(event):
  return str((event or {}).get("event_id") or "")


def _dedupe_key(event):
  return str((event or {}).get("dedupe_key") or _event_id(event))


def _error_class_from_exception(exc):
  if isinstance(exc, urllib.error.HTTPError):
    return f"http_{exc.code}"
  if isinstance(exc, urllib.error.URLError):
    return "http_unreachable"
  if isinstance(exc, TimeoutError):
    return "timeout"
  return type(exc).__name__


def _sign_payload_if_required(event_cfg, payload_bytes):
  if not event_cfg["SIGN_PAYLOADS"]:
    return None, None

  secret = os.environ.get(event_cfg["HMAC_SECRET_ENV"])
  if not secret:
    return None, "missing_hmac_secret"
  return compute_payload_hmac(payload_bytes, secret), None


def _http_headers(event, signature, token):
  headers = {
    "Content-Type": "application/json",
    "X-RedMesh-Event-Id": _event_id(event),
    "X-RedMesh-Dedupe-Key": _dedupe_key(event),
  }
  if signature:
    headers["X-RedMesh-Signature"] = f"sha256={signature}"
  if token:
    headers["Authorization"] = f"Bearer {token}"
  return headers


def _send_http_json(url, payload_bytes, headers, timeout_seconds):
  request = urllib.request.Request(
    url,
    data=payload_bytes,
    headers=headers,
    method="POST",
  )
  with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
    status = getattr(response, "status", None) or response.getcode()
    if status < 200 or status >= 300:
      raise urllib.error.HTTPError(url, status, "non_success_status", hdrs=None, fp=None)
    return status


def format_syslog_json_line(event, signature=None):
  payload = dict(event or {})
  payload["redmesh_idempotency_key"] = _dedupe_key(payload)
  if signature:
    payload["redmesh_signature"] = f"sha256={signature}"
  return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _send_syslog_json(host, port, line, timeout_seconds):
  payload = f"{line}\n".encode("utf-8")
  with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(timeout_seconds)
    sock.sendto(payload, (host, int(port)))
  return len(payload)


def _persist_failed_payload_sample(owner, integration_id, event, error_class, payload_bytes, cfg):
  if not cfg.get("PERSIST_FAILED_PAYLOADS"):
    return None
  try:
    limit = int(cfg.get("FAILED_PAYLOAD_SAMPLE_BYTES") or 2048)
  except (TypeError, ValueError):
    limit = 2048
  sample = payload_bytes[:limit].decode("utf-8", errors="replace")
  try:
    return _artifact_repo(owner).put_json({
      "schema": "redmesh.integration.failed_payload.v1",
      "integration_id": integration_id,
      "event_id": _event_id(event),
      "dedupe_key": _dedupe_key(event),
      "error_class": error_class,
      "payload_sha256": _payload_sha256(payload_bytes),
      "payload_sample": sample,
    }, show_logs=False)
  except Exception:
    return None


def _record_failure(owner, integration_id, event, error_class, payload_bytes=None, cfg=None, dry_run=False):
  artifact_cid = None
  if payload_bytes is not None and cfg is not None:
    artifact_cid = _persist_failed_payload_sample(owner, integration_id, event, error_class, payload_bytes, cfg)
  record_integration_status(
    owner,
    integration_id,
    outcome="failure",
    event_id=_event_id(event),
    artifact_cid=artifact_cid,
    error_class=error_class,
    dry_run=dry_run,
  )
  return artifact_cid


def deliver_wazuh_event(owner, event, *, dry_run=False):
  """Deliver one canonical RedMesh event to the Wazuh/generic SIEM adapter."""
  integration_id = "wazuh"
  cfg = get_wazuh_export_config(owner)
  event_cfg = get_event_export_config(owner)
  payload_bytes = _json_bytes(event or {})

  if not cfg["ENABLED"]:
    _record_failure(owner, integration_id, event, "disabled", payload_bytes, cfg, dry_run=dry_run)
    return {
      "status": "disabled",
      "integration_id": integration_id,
      "event_id": _event_id(event),
      "error": "disabled",
    }

  errors = validate_event_dict(event)
  if errors:
    _record_failure(owner, integration_id, event, "invalid_event", payload_bytes, cfg, dry_run=dry_run)
    return {
      "status": "error",
      "integration_id": integration_id,
      "event_id": _event_id(event),
      "error": "invalid_event",
      "validation_errors": errors,
    }

  signature, sign_error = _sign_payload_if_required(event_cfg, payload_bytes)
  if sign_error:
    _record_failure(owner, integration_id, event, sign_error, payload_bytes, cfg, dry_run=dry_run)
    return {
      "status": "error",
      "integration_id": integration_id,
      "event_id": _event_id(event),
      "error": sign_error,
    }

  mode = cfg["MODE"]
  attempts_total = int(cfg["RETRY_ATTEMPTS"]) + 1
  timeout_seconds = float(cfg["TIMEOUT_SECONDS"])

  if mode == "http":
    if not cfg["HTTP_URL"]:
      _record_failure(owner, integration_id, event, "missing_http_url", payload_bytes, cfg, dry_run=dry_run)
      return {
        "status": "error",
        "integration_id": integration_id,
        "event_id": _event_id(event),
        "mode": mode,
        "error": "missing_http_url",
      }
    token = os.environ.get(cfg["HTTP_TOKEN_ENV"], "")
    headers = _http_headers(event, signature, token)
    send = lambda: _send_http_json(cfg["HTTP_URL"], payload_bytes, headers, timeout_seconds)
  else:
    if not cfg["SYSLOG_HOST"]:
      _record_failure(owner, integration_id, event, "missing_syslog_host", payload_bytes, cfg, dry_run=dry_run)
      return {
        "status": "error",
        "integration_id": integration_id,
        "event_id": _event_id(event),
        "mode": mode,
        "error": "missing_syslog_host",
      }
    syslog_line = format_syslog_json_line(event, signature=signature)
    send = lambda: _send_syslog_json(cfg["SYSLOG_HOST"], cfg["SYSLOG_PORT"], syslog_line, timeout_seconds)

  last_error = None
  for attempt in range(1, attempts_total + 1):
    try:
      response = send()
      record_integration_status(
        owner,
        integration_id,
        outcome="success",
        event_id=_event_id(event),
        dry_run=dry_run,
      )
      return {
        "status": "sent",
        "integration_id": integration_id,
        "event_id": _event_id(event),
        "dedupe_key": _dedupe_key(event),
        "mode": mode,
        "attempts": attempt,
        "response": response,
      }
    except Exception as exc:
      last_error = _error_class_from_exception(exc)

  artifact_cid = _record_failure(owner, integration_id, event, last_error or "delivery_failed", payload_bytes, cfg, dry_run=dry_run)
  return {
    "status": "error",
    "integration_id": integration_id,
    "event_id": _event_id(event),
    "dedupe_key": _dedupe_key(event),
    "mode": mode,
    "attempts": attempts_total,
    "error": last_error or "delivery_failed",
    "artifact_cid": artifact_cid,
  }


def deliver_redmesh_event(owner, event, *, integration_id="wazuh", dry_run=False):
  integration_id = str(integration_id or "wazuh").strip().lower()
  if integration_id == "wazuh":
    return deliver_wazuh_event(owner, event, dry_run=dry_run)
  return {
    "status": "error",
    "integration_id": integration_id,
    "event_id": _event_id(event),
    "error": "unsupported_integration",
  }


def build_wazuh_decoder_rules_example():
  return {
    "decoder": {
      "name": "redmesh-json",
      "program_name": "redmesh",
      "json_fields": ["schema", "event_type", "event_outcome", "severity", "job_id", "dedupe_key"],
    },
    "rules": [
      {"id": 110100, "group": group, "match": group.replace("redmesh.", "redmesh.")}
      for group in WAZUH_EVENT_GROUPS
    ],
  }
