from __future__ import annotations

import base64
import os

from .base import AuthError, AuthProvider


class StaticBearerProvider(AuthProvider):
  """Static bearer token. Reads an inline `token` value if provided, otherwise
  falls back to `os.environ.get(token_env)`.

  Used for OpenCTI (UUID tokens that never expire) and for any integration
  where the operator is managing token lifetime externally.
  """

  kind = "static"

  def __init__(self, token_env: str = "", token: str = ""):
    self.token_env = str(token_env or "").strip()
    # Inline token value. Mirrors MISP's pattern (MISP_API_KEY lives directly
    # in the MISP_EXPORT config block). Takes priority over token_env when set.
    self._inline_token = str(token or "")

  def _resolve_token(self) -> str:
    if self._inline_token:
      return self._inline_token
    if self.token_env:
      return os.environ.get(self.token_env, "")
    return ""

  def headers(self) -> dict:
    token = self._resolve_token()
    if not token:
      return {}
    return {"Authorization": f"Bearer {token}"}

  def __repr__(self) -> str:
    # Never include the inline token value in repr — that's the whole reason
    # we have a dedicated repr instead of letting dataclasses generate one.
    return (
      f"StaticBearerProvider(token_env={self.token_env!r}, "
      f"inline_token_set={bool(self._inline_token)})"
    )


class BasicAuthProvider(AuthProvider):
  """Emits RFC 7617 HTTP Basic Authentication on every call. Reads an inline
  `password` value if provided, otherwise falls back to
  `os.environ.get(password_env)`.

  Used for TAXII (medallion has no token concept, only Basic) and any
  integration whose only auth mode is username+password.
  """

  kind = "basic"

  def __init__(self, username: str, password_env: str = "", password: str = ""):
    self.username = str(username or "")
    self.password_env = str(password_env or "").strip()
    self._inline_password = str(password or "")

  def _resolve_password(self) -> str:
    if self._inline_password:
      return self._inline_password
    if self.password_env:
      return os.environ.get(self.password_env, "")
    return ""

  def headers(self) -> dict:
    if not self.username:
      raise AuthError("basic auth username is empty")
    password = self._resolve_password()
    if not password:
      raise AuthError(
        "basic auth password is not configured "
        f"(neither inline PASSWORD nor env {self.password_env!r} set)"
      )
    # RFC 7617: UTF-8 encode the user-id:password tuple before base64.
    raw = f"{self.username}:{password}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}

  def __repr__(self) -> str:
    return (
      f"BasicAuthProvider(username={self.username!r}, "
      f"password_env={self.password_env!r}, "
      f"inline_password_set={bool(self._inline_password)})"
    )
