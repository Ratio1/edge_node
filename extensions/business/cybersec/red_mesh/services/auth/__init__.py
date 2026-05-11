from __future__ import annotations

import os

from .base import AuthConfigError, AuthError, AuthExpiredError, AuthProvider
from .providers import BasicAuthProvider, StaticBearerProvider
from .wazuh_jwt import WazuhJwtProvider, _origin_from_url


__all__ = [
  "AuthProvider",
  "AuthError",
  "AuthConfigError",
  "AuthExpiredError",
  "StaticBearerProvider",
  "BasicAuthProvider",
  "WazuhJwtProvider",
  "build_auth_provider",
  "credentials_missing",
]


def credentials_missing(integration_cfg: dict) -> str | None:
  """Return None when the cfg has the credentials its AUTH_MODE needs,
  otherwise a stable error_class string suitable for integration_status
  and config-error pre-flight in delivery functions.

  Credentials may be provided two ways:
    - **Inline** in the config block — `TOKEN` for static mode, `PASSWORD`
      for basic / wazuh_jwt. Mirrors MISP's `MISP_API_KEY` pattern; secrets
      live in the persisted pipeline config alongside non-secret fields.
    - **Indirected** via env-var name — `TOKEN_ENV` / `PASSWORD_ENV`. Useful
      when secrets must come from the container env (e.g. orchestrator
      injection).

  Inline values take priority. If both are absent / empty, the integration
  is reported as missing credentials.
  """
  if not isinstance(integration_cfg, dict):
    return "invalid_auth_config"
  mode = (integration_cfg.get("AUTH_MODE") or "static").lower()

  if mode == "static":
    if (integration_cfg.get("TOKEN") or "").strip():
      return None
    env_name = (integration_cfg.get("TOKEN_ENV") or "").strip()
    if env_name and os.environ.get(env_name, "").strip():
      return None
    return "missing_token"

  if mode in {"basic", "wazuh_jwt"}:
    if not (integration_cfg.get("USERNAME") or "").strip():
      return "missing_credentials"
    if (integration_cfg.get("PASSWORD") or "").strip():
      return None
    pw_env = (integration_cfg.get("PASSWORD_ENV") or "").strip()
    if pw_env and os.environ.get(pw_env, "").strip():
      return None
    return "missing_credentials"

  return "invalid_auth_config"


def build_auth_provider(integration_cfg: dict) -> AuthProvider:
  """Construct the right AuthProvider for an integration config block.

  Reads `AUTH_MODE` and a small number of mode-specific fields. Raises
  AuthConfigError if the mode is unsupported or required fields are absent.
  Missing env-var *values* are NOT raised here — they surface lazily inside
  AuthProvider.headers() at delivery time, matching the existing pattern
  where `os.environ.get(TOKEN_ENV)` returning empty is handled by the
  delivery code as `missing_token`.
  """
  if not isinstance(integration_cfg, dict):
    raise AuthConfigError("integration_cfg must be a dict")

  mode = str(integration_cfg.get("AUTH_MODE") or "static").strip().lower()

  if mode == "static":
    return StaticBearerProvider(
      token_env=integration_cfg.get("TOKEN_ENV") or "",
      token=integration_cfg.get("TOKEN") or "",
    )

  if mode == "basic":
    return BasicAuthProvider(
      username=integration_cfg.get("USERNAME") or "",
      password_env=integration_cfg.get("PASSWORD_ENV") or "",
      password=integration_cfg.get("PASSWORD") or "",
    )

  if mode == "wazuh_jwt":
    # LOGIN_URL is optional — when empty, fall back to the origin of HTTP_URL
    # so operators don't have to specify it twice for typical Wazuh setups.
    login_url = (integration_cfg.get("LOGIN_URL") or "").strip()
    if not login_url:
      login_url = _origin_from_url(integration_cfg.get("HTTP_URL") or "")
    if not login_url:
      raise AuthConfigError("wazuh_jwt requires LOGIN_URL or HTTP_URL")
    return WazuhJwtProvider(
      login_url=login_url,
      username=integration_cfg.get("USERNAME") or "",
      password_env=integration_cfg.get("PASSWORD_ENV") or "",
      password=integration_cfg.get("PASSWORD") or "",
      login_path=integration_cfg.get("LOGIN_PATH")
        or "/security/user/authenticate?raw=true",
      ttl_override_s=integration_cfg.get("JWT_TTL_OVERRIDE_SECONDS") or 0.0,
      timeout_seconds=integration_cfg.get("TIMEOUT_SECONDS") or 10.0,
    )

  raise AuthConfigError(f"unsupported AUTH_MODE: {mode!r}")
