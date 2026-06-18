"""Security validation for remote Model Testing providers."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit


MODEL_PROVIDER_CREDENTIAL_UNAVAILABLE = "credential_unavailable"
_MODEL_PROVIDER_REF_PREFIX = "model_provider/"
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
    MODEL_PROVIDER_CREDENTIAL_UNAVAILABLE,
    error_class=MODEL_PROVIDER_CREDENTIAL_UNAVAILABLE,
  )


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
  if credential_ref and has_secret:
    return None, _validation_error(
      f"{role} may not supply both credential_ref and secret payload",
      error_class="duplicate_credential_source",
    )
  if has_secret:
    return {"source": "secret_payload", "credential_ref_present": False}, None
  if not credential_ref:
    return None, _validation_error(
      f"{role} requires credential_ref or secret payload",
      error_class=MODEL_PROVIDER_CREDENTIAL_UNAVAILABLE,
    )
  if not credential_ref.startswith(_MODEL_PROVIDER_REF_PREFIX):
    return None, _credential_error()
  ref_body = credential_ref[len(_MODEL_PROVIDER_REF_PREFIX):]
  operator_prefix = f"operator/{created_by_id}/"
  if ref_body.startswith(operator_prefix):
    credential_id = ref_body[len(operator_prefix):]
    if not credential_id or "/" in credential_id:
      return None, _credential_error()
    return {"source": "credential_ref", "credential_ref_present": True}, None
  if ref_body.startswith("deploy/default_evaluator/"):
    if role != "evaluator_model" or not use_default_evaluator_model:
      return None, _credential_error()
    credential_id = ref_body[len("deploy/default_evaluator/"):]
    if not credential_id or "/" in credential_id:
      return None, _credential_error()
    return {"source": "credential_ref", "credential_ref_present": True}, None
  return None, _credential_error()
