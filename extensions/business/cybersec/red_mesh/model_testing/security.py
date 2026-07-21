"""Security validation for remote Model Testing providers."""

from __future__ import annotations

import hmac
import ipaddress
import os
import socket
from urllib.parse import urlsplit


MODEL_PROVIDER_CREDENTIAL_UNAVAILABLE = "credential_unavailable"
BACKEND_TOKEN_ENV = "REDMESH_BACKEND_TOKEN"
MIN_BACKEND_TOKEN_BYTES = 32
_PROVIDER_ALLOWED_KEYS = {
  "adapter",
  "provider_label",
  "base_url",
  "model",
  "credential_ref",
}
_SECRET_KEY_MARKERS = (
  "api_key",
  "apikey",
  "authorization",
  "bearer",
  "token",
  "secret",
  "password",
  "headers",
  "auth",
)
_FORBIDDEN_METADATA_IPS = {
  ipaddress.ip_address("169.254.169.254"),
}


def _validation_error(message: str, *, error="validation_error", error_class=None):
  result = {"error": error, "message": message}
  if error_class:
    result["error_class"] = error_class
  return result


def _ip_forbidden(ip):
  if ip in _FORBIDDEN_METADATA_IPS:
    return True
  return (
    ip.is_loopback
    or ip.is_link_local
    or ip.is_private
    or ip.is_multicast
    or ip.is_unspecified
    or ip.is_reserved
  )


def _resolve_host_ips(hostname, *, resolver=None):
  try:
    parsed_ip = ipaddress.ip_address(hostname)
    return [parsed_ip], None
  except ValueError:
    pass
  resolver = resolver or socket.getaddrinfo
  try:
    infos = resolver(hostname, None, type=socket.SOCK_STREAM)
  except Exception:
    return [], _validation_error(
      "provider.base_url DNS resolution failed",
      error_class="dns_failed",
    )
  ips = []
  for info in infos or []:
    sockaddr = info[4] if len(info) > 4 else None
    if not sockaddr:
      continue
    try:
      ips.append(ipaddress.ip_address(sockaddr[0]))
    except ValueError:
      continue
  if not ips:
    return [], _validation_error(
      "provider.base_url DNS resolution failed",
      error_class="dns_failed",
    )
  return ips, None


def validate_provider_url(base_url, *, resolver=None):
  """Validate an operator supplied OpenAI-compatible provider URL."""
  raw = str(base_url or "").strip()
  if not raw:
    return None, _validation_error(
      "provider.base_url is required",
      error_class="invalid_url",
    )
  if len(raw) > 2048:
    return None, _validation_error(
      "provider.base_url is too long",
      error_class="invalid_url",
    )
  try:
    parsed = urlsplit(raw)
  except ValueError:
    return None, _validation_error(
      "provider.base_url is invalid",
      error_class="invalid_url",
    )
  if parsed.scheme.lower() != "https":
    return None, _validation_error(
      "provider.base_url must use https",
      error_class="invalid_url",
    )
  if parsed.username or parsed.password:
    return None, _validation_error(
      "provider.base_url must not contain credentials",
      error_class="invalid_url",
    )
  if parsed.query or parsed.fragment:
    return None, _validation_error(
      "provider.base_url must not contain query strings or fragments",
      error_class="invalid_url",
    )
  if not parsed.hostname:
    return None, _validation_error(
      "provider.base_url hostname is required",
      error_class="invalid_url",
    )

  ips, err = _resolve_host_ips(parsed.hostname, resolver=resolver)
  if err:
    return None, err
  forbidden = [str(ip) for ip in ips if _ip_forbidden(ip)]
  if forbidden:
    return None, _validation_error(
      "provider.base_url resolves to a forbidden destination",
      error_class="forbidden_destination",
    )
  safe_url = parsed._replace(query="", fragment="").geturl().rstrip("/")
  return {
    "base_url": safe_url,
    "safe_hostname": parsed.hostname.lower(),
    "resolved_ip_count": len(ips),
  }, None


def _credential_error():
  return _validation_error(
    "Provider requires an API key payload.",
    error_class=MODEL_PROVIDER_CREDENTIAL_UNAVAILABLE,
  )


def _backend_auth_error(*, status_code, error, error_class, message):
  return {
    "status": "error",
    "status_code": status_code,
    "error": error,
    "error_class": error_class,
    "message": message,
  }


def validate_backend_token(token):
  """Validate the Navigator-to-edge bearer token without exposing token material."""
  expected = os.environ.get(BACKEND_TOKEN_ENV, "")
  expected_bytes = expected.encode("utf-8")
  if len(expected_bytes) < MIN_BACKEND_TOKEN_BYTES:
    return _backend_auth_error(
      status_code=401,
      error="unauthorized",
      error_class="backend_auth_unavailable",
      message="Backend authentication is not configured.",
    )

  presented = token if isinstance(token, str) else ""
  if not presented:
    return _backend_auth_error(
      status_code=401,
      error="unauthorized",
      error_class="backend_auth_required",
      message="Backend authentication is required.",
    )
  if not hmac.compare_digest(presented.encode("utf-8"), expected_bytes):
    return _backend_auth_error(
      status_code=403,
      error="forbidden",
      error_class="backend_auth_invalid",
      message="Backend authentication failed.",
    )
  return None


def validate_provider_config_shape(provider, *, role):
  """Reject inline credential-bearing or unknown provider config fields."""
  if not isinstance(provider, dict):
    return _validation_error(f"{role} must be a JSON object")
  for key in provider:
    normalized = str(key or "").strip().lower()
    if normalized not in _PROVIDER_ALLOWED_KEYS:
      return _validation_error(
        f"{role} contains unsupported provider field",
        error_class="invalid_provider_config",
      )
    if any(marker in normalized for marker in _SECRET_KEY_MARKERS):
      return _validation_error(
        f"{role} contains credential-bearing provider field",
        error_class="invalid_provider_config",
      )
  return None


def validate_model_provider_credentials(
  provider,
  secret_payload,
  *,
  role,
  created_by_id,
  use_default_evaluator_model=False,
):
  """Validate credential source shape without exposing credential details."""
  provider = provider or {}
  credential_ref = str(provider.get("credential_ref") or "").strip()
  api_key = ""
  if isinstance(secret_payload, dict):
    api_key = str(secret_payload.get("api_key") or "")
  has_secret = bool(api_key)
  # Credential references are an accepted historical shape but there is no
  # worker-local resolver yet. Reject them before launch/preflight persistence
  # with one sanitized error that never includes the supplied identifier.
  if credential_ref:
    return None, _credential_error()
  if has_secret:
    return {"source": "secret_payload", "credential_ref_present": False}, None
  return None, _credential_error()
