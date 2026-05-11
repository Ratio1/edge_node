from __future__ import annotations

import base64
import json
import os
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .base import AuthError, AuthProvider


@dataclass(frozen=True)
class _Entry:
  jwt: str
  expires_at: float


# Module-level cache keyed by (login_url, username). Per-process, in-memory
# only — JWTs are short-lived and re-login is cheap.
_cache: dict[tuple[str, str], _Entry] = {}
_cache_locks: dict[tuple[str, str], threading.Lock] = {}
_cache_index_lock = threading.Lock()

# Safety margin against clock skew between us and the Wazuh manager. If the
# token expires within this window we treat it as already expired and refresh.
_EXPIRY_SAFETY_SECONDS = 60.0

# Fallback TTL when the JWT carries no usable exp claim and no override was
# configured. Kept short so the next call re-mints if needed.
_DEFAULT_FALLBACK_TTL = 60.0


def _b64url_decode_padded(segment: str) -> bytes:
  """Decode a base64url-encoded JWT segment, restoring missing padding."""
  pad = "=" * (-len(segment) % 4)
  return base64.urlsafe_b64decode(segment + pad)


def _extract_exp(jwt: str) -> float | None:
  """Pull the `exp` claim out of a JWT's middle segment, or None on failure."""
  parts = jwt.split(".")
  if len(parts) != 3:
    return None
  try:
    payload = json.loads(_b64url_decode_padded(parts[1]))
  except (ValueError, json.JSONDecodeError):
    return None
  exp = payload.get("exp")
  if isinstance(exp, (int, float)):
    return float(exp)
  return None


def _normalize_login_url(login_url: str, login_path: str) -> str:
  """Combine login_url + login_path. If login_url already has a path
  matching login_path, use it as-is."""
  base = (login_url or "").rstrip("/")
  path = login_path or ""
  if not path.startswith("/"):
    path = "/" + path
  return base + path


def _origin_from_url(url: str) -> str:
  """Strip path/query/fragment, leaving scheme://host[:port]."""
  raw = (url or "").strip()
  if not raw:
    return ""
  try:
    parts = urlsplit(raw)
  except ValueError:
    return ""
  if not parts.scheme or not parts.netloc:
    return ""
  return urlunsplit((parts.scheme, parts.netloc, "", "", ""))


def _purge_cache_for_tests() -> None:
  """Drop all cache entries. Test-only — not part of the public API."""
  with _cache_index_lock:
    _cache.clear()
    _cache_locks.clear()


class WazuhJwtProvider(AuthProvider):
  """Manages the Wazuh manager API auth dance: Basic credentials → short-lived
  JWT → Bearer header. Caches the JWT in-memory until it (or the configured
  override TTL) expires, with double-checked locking to prevent stampedes.

  Generalizable to any backend that returns a raw JWT from a Basic-auth POST
  (the `login_path` is parameterizable); but `kind` stays "wazuh_jwt" because
  that's the only documented use case today.
  """

  kind = "wazuh_jwt"

  def __init__(
    self,
    login_url: str,
    username: str,
    password_env: str,
    login_path: str = "/security/user/authenticate?raw=true",
    ttl_override_s: float = 0.0,
    timeout_seconds: float = 10.0,
    http_post=None,
  ):
    self.login_url = (login_url or "").strip()
    self.username = str(username or "")
    self.password_env = str(password_env or "").strip()
    self.login_path = login_path or "/security/user/authenticate?raw=true"
    self.ttl_override_s = float(ttl_override_s or 0.0)
    self.timeout_seconds = float(timeout_seconds or 10.0)
    # Injectable for tests; defaults to the real urlopen.
    self._http_post = http_post or urllib.request.urlopen

  def headers(self) -> dict:
    jwt = self._get_or_login()
    return {"Authorization": f"Bearer {jwt}"}

  def invalidate(self) -> None:
    key = self._cache_key()
    lock = self._lock_for(key)
    with lock:
      _cache.pop(key, None)

  def _cache_key(self) -> tuple[str, str]:
    return (self.login_url, self.username)

  def _lock_for(self, key: tuple[str, str]) -> threading.Lock:
    with _cache_index_lock:
      lock = _cache_locks.get(key)
      if lock is None:
        lock = threading.Lock()
        _cache_locks[key] = lock
      return lock

  def _get_or_login(self) -> str:
    key = self._cache_key()
    now = time.time()

    # Fast path: lockless cache read. _Entry is frozen and entries are
    # replaced wholesale, so a torn read can't expose a half-updated token.
    entry = _cache.get(key)
    if entry is not None and entry.expires_at > now + _EXPIRY_SAFETY_SECONDS:
      return entry.jwt

    lock = self._lock_for(key)
    with lock:
      # Re-check under lock: another thread may have just minted a token.
      entry = _cache.get(key)
      if entry is not None and entry.expires_at > now + _EXPIRY_SAFETY_SECONDS:
        return entry.jwt
      entry = self._login()
      _cache[key] = entry
      return entry.jwt

  def _login(self) -> _Entry:
    if not self.login_url:
      raise AuthError("wazuh_jwt LOGIN_URL is not configured")
    if not self.username:
      raise AuthError("wazuh_jwt USERNAME is not configured")
    if not self.password_env:
      raise AuthError("wazuh_jwt PASSWORD_ENV is not configured")
    password = os.environ.get(self.password_env, "")
    if not password:
      raise AuthError(f"wazuh_jwt password env {self.password_env!r} is not set")

    url = _normalize_login_url(self.login_url, self.login_path)
    raw = f"{self.username}:{password}".encode("utf-8")
    basic = base64.b64encode(raw).decode("ascii")
    request = urllib.request.Request(
      url,
      data=b"",
      headers={"Authorization": f"Basic {basic}"},
      method="POST",
    )

    try:
      with self._http_post(request, timeout=self.timeout_seconds) as response:
        status = getattr(response, "status", None) or response.getcode()
        body = response.read()
    except urllib.error.HTTPError as exc:
      raise AuthError(f"wazuh_jwt login HTTP {exc.code}") from exc

    if status < 200 or status >= 300:
      raise AuthError(f"wazuh_jwt login returned status {status}")

    jwt = body.decode("utf-8", errors="replace").strip()
    # `?raw=true` returns the token as plain text. If the operator dropped
    # `?raw=true`, the response is `{"data": {"token": "..."}}`. Handle both.
    if jwt.startswith("{"):
      try:
        parsed = json.loads(jwt)
      except (ValueError, json.JSONDecodeError):
        raise AuthError("wazuh_jwt login response is malformed JSON")
      token = (parsed.get("data") or {}).get("token") if isinstance(parsed, dict) else None
      if not isinstance(token, str) or not token:
        raise AuthError("wazuh_jwt login response missing data.token")
      jwt = token.strip()

    if not jwt or jwt.count(".") != 2:
      raise AuthError("wazuh_jwt login response is not a JWT")

    expires_at = self._resolve_expiry(jwt)
    return _Entry(jwt=jwt, expires_at=expires_at)

  def _resolve_expiry(self, jwt: str) -> float:
    if self.ttl_override_s > 0:
      return time.time() + self.ttl_override_s
    exp = _extract_exp(jwt)
    if exp is not None and exp > time.time():
      return exp
    return time.time() + _DEFAULT_FALLBACK_TTL

  def __repr__(self) -> str:
    return (
      f"WazuhJwtProvider(login_url={self.login_url!r}, "
      f"username={self.username!r}, password_env={self.password_env!r})"
    )
