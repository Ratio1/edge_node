from __future__ import annotations

import base64
import os

from .base import AuthError, AuthProvider


class StaticBearerProvider(AuthProvider):
  """Reads a pre-issued bearer token from an environment variable each call.

  Used for OpenCTI (UUID tokens that never expire) and for any integration
  where the operator is managing token lifetime externally.
  """

  kind = "static"

  def __init__(self, token_env: str):
    self.token_env = str(token_env or "").strip()

  def headers(self) -> dict:
    if not self.token_env:
      return {}
    token = os.environ.get(self.token_env, "")
    if not token:
      return {}
    return {"Authorization": f"Bearer {token}"}

  def __repr__(self) -> str:
    return f"StaticBearerProvider(token_env={self.token_env!r})"


class BasicAuthProvider(AuthProvider):
  """Emits RFC 7617 HTTP Basic Authentication on every call.

  Used for TAXII (medallion has no token concept, only Basic) and any
  integration whose only auth mode is username+password.
  """

  kind = "basic"

  def __init__(self, username: str, password_env: str):
    self.username = str(username or "")
    self.password_env = str(password_env or "").strip()

  def headers(self) -> dict:
    if not self.username:
      raise AuthError("basic auth username is empty")
    if not self.password_env:
      raise AuthError("basic auth PASSWORD_ENV is not configured")
    password = os.environ.get(self.password_env, "")
    if not password:
      raise AuthError(f"basic auth password env {self.password_env!r} is not set")
    # RFC 7617: UTF-8 encode the user-id:password tuple before base64.
    raw = f"{self.username}:{password}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}

  def __repr__(self) -> str:
    return f"BasicAuthProvider(username={self.username!r}, password_env={self.password_env!r})"
