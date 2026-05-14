"""Scoped graybox HTTP client.

Centralizes host/path scope checks for runtime graybox traffic while
keeping the existing probe-facing ``requests.Session`` shape.
"""

from __future__ import annotations

import posixpath
from urllib.parse import unquote, urlsplit, urlunsplit

import requests


class GrayboxScopeError(requests.RequestException):
  """Raised before any outbound request when scope validation fails."""


def _decode_repeated(value: str, rounds: int = 3) -> str:
  current = value
  for _ in range(rounds):
    decoded = unquote(current)
    if decoded == current:
      break
    current = decoded
  return current


def _normalize_path(path: str) -> str:
  raw = str(path or "").strip()
  if not raw:
    return ""
  decoded = _decode_repeated(raw)
  parsed = urlsplit(decoded)
  path = parsed.path if parsed.scheme or parsed.netloc else decoded.split("?", 1)[0]
  if not path.startswith("/"):
    path = "/" + path
  parts = [part for part in path.split("/") if part]
  if any(part == ".." for part in parts):
    raise GrayboxScopeError(f"path traversal is outside graybox scope: {raw}")
  normalized = posixpath.normpath(path)
  if normalized == ".":
    normalized = "/"
  if path.endswith("/") and not normalized.endswith("/"):
    normalized += "/"
  return normalized if normalized.startswith("/") else "/" + normalized


def _split_target(target_url: str):
  parsed = urlsplit(target_url)
  scheme = parsed.scheme or "http"
  hostname = (parsed.hostname or "").lower()
  port = parsed.port or (443 if scheme == "https" else 80)
  return parsed, scheme, hostname, port


def normalize_request_url(target_url: str, url_or_path: str) -> str:
  target, scheme, hostname, port = _split_target(target_url)
  raw = str(url_or_path or "").strip()
  parsed = urlsplit(raw)
  if parsed.scheme or parsed.netloc:
    req_scheme = parsed.scheme or scheme
    req_host = (parsed.hostname or "").lower()
    req_port = parsed.port or (443 if req_scheme == "https" else 80)
    if req_host != hostname or req_port != port or req_scheme != scheme:
      raise GrayboxScopeError(f"cross-origin graybox request blocked: {raw}")
    path = _normalize_path(parsed.path or "/")
    return urlunsplit((scheme, target.netloc, path, parsed.query, ""))
  path = _normalize_path(raw or "/")
  return urlunsplit((scheme, target.netloc, path, parsed.query, ""))


def path_in_scope(path: str, scope: str) -> bool:
  path = _normalize_path(path)
  scope = _normalize_path(scope)
  if not scope or scope == "/":
    return True
  if path == scope.rstrip("/"):
    return True
  prefix = scope if scope.endswith("/") else scope + "/"
  return path.startswith(prefix)


def path_scopes_from_allowlist(target_url: str, entries) -> list[str]:
  scopes = []
  _target, scheme, hostname, port = _split_target(target_url)
  for entry in entries or []:
    raw = str(entry or "").strip()
    if not raw:
      continue
    parsed = urlsplit(raw)
    if parsed.scheme or parsed.netloc:
      req_scheme = parsed.scheme or scheme
      req_host = (parsed.hostname or "").lower()
      req_port = parsed.port or (443 if req_scheme == "https" else 80)
      if req_scheme == scheme and req_host == hostname and req_port == port and parsed.path:
        scopes.append(_normalize_path(parsed.path))
      continue
    if raw.startswith("/"):
      scopes.append(_normalize_path(raw))
  deduped = []
  for scope in scopes:
    if scope not in deduped:
      deduped.append(scope)
  return deduped


def _append_path(paths, value):
  value = str(value or "").strip()
  if value:
    paths.append(value)


def collect_target_config_paths(config: dict) -> list[str]:
  """Collect known request paths from canonical GrayboxTargetConfig dict."""
  if not isinstance(config, dict):
    return []
  paths = []
  for key in (
    "login_path", "logout_path", "password_reset_path",
    "password_reset_confirm_path",
  ):
    _append_path(paths, config.get(key))

  access = config.get("access_control") or {}
  for item in access.get("idor_endpoints") or []:
    _append_path(paths, item.get("path") if isinstance(item, dict) else "")
  for item in access.get("admin_endpoints") or []:
    _append_path(paths, item.get("path") if isinstance(item, dict) else "")

  misconfig = config.get("misconfig") or {}
  for path in misconfig.get("debug_paths") or []:
    _append_path(paths, path)
  jwt_cfg = misconfig.get("jwt_endpoints") or {}
  _append_path(paths, jwt_cfg.get("token_path"))
  _append_path(paths, jwt_cfg.get("protected_path"))

  injection = config.get("injection") or {}
  for section in (
    "ssrf_endpoints", "xss_endpoints", "ssti_endpoints",
    "cmd_endpoints", "header_endpoints", "json_type_endpoints",
  ):
    for item in injection.get(section) or []:
      _append_path(paths, item.get("path") if isinstance(item, dict) else "")

  business = config.get("business_logic") or {}
  for section in ("workflow_endpoints", "record_endpoints"):
    for item in business.get(section) or []:
      _append_path(paths, item.get("path") if isinstance(item, dict) else "")

  api = config.get("api_security") or {}
  for section in (
    "object_endpoints", "property_endpoints", "function_endpoints",
    "resource_endpoints",
  ):
    for item in api.get(section) or []:
      if not isinstance(item, dict):
        continue
      _append_path(paths, item.get("path"))
      _append_path(paths, item.get("revert_path"))
  for flow in api.get("business_flows") or []:
    if not isinstance(flow, dict):
      continue
    _append_path(paths, flow.get("path"))
    _append_path(paths, flow.get("verify_path"))
    _append_path(paths, flow.get("revert_path"))
  token = api.get("token_endpoints") or {}
  _append_path(paths, token.get("token_path"))
  _append_path(paths, token.get("protected_path"))
  _append_path(paths, token.get("logout_path"))
  auth = api.get("auth") or {}
  _append_path(paths, auth.get("authenticated_probe_path"))
  _append_path(paths, auth.get("api_logout_path"))
  inventory = api.get("inventory_paths") or {}
  for path in inventory.get("openapi_candidates") or []:
    _append_path(paths, path)
  for path in inventory.get("version_sibling_candidates") or []:
    _append_path(paths, path)
  for path in inventory.get("deprecated_paths") or []:
    _append_path(paths, path)
  _append_path(paths, inventory.get("canonical_probe_path"))
  for path in api.get("debug_path_candidates") or []:
    _append_path(paths, path)

  return paths


def validate_target_config_paths(target_url: str, target_config: dict, allowlist) -> list[str]:
  scopes = path_scopes_from_allowlist(target_url, allowlist)
  if not scopes:
    return []
  errors = []
  for raw_path in collect_target_config_paths(target_config):
    try:
      url = normalize_request_url(target_url, raw_path)
      path = urlsplit(url).path
    except GrayboxScopeError as exc:
      errors.append(str(exc))
      continue
    if not any(path_in_scope(path, scope) for scope in scopes):
      errors.append(f"configured path {raw_path!r} is outside authorized scope {scopes}")
  return errors


class ScopedSession:
  """Small proxy that preserves the ``requests.Session`` API used by probes."""

  def __init__(self, session, client: "GrayboxHttpClient"):
    object.__setattr__(self, "_session", session)
    object.__setattr__(self, "_client", client)

  def __getattr__(self, name):
    return getattr(self._session, name)

  def __setattr__(self, name, value):
    if name in {"_session", "_client"}:
      object.__setattr__(self, name, value)
    else:
      setattr(self._session, name, value)

  def request(self, method, url, **kwargs):
    return self._client.request(self._session, method, url, **kwargs)

  def get(self, url, **kwargs):
    return self.request("GET", url, **kwargs)

  def post(self, url, **kwargs):
    return self.request("POST", url, **kwargs)

  def put(self, url, **kwargs):
    return self.request("PUT", url, **kwargs)

  def patch(self, url, **kwargs):
    return self.request("PATCH", url, **kwargs)

  def delete(self, url, **kwargs):
    return self.request("DELETE", url, **kwargs)

  def head(self, url, **kwargs):
    return self.request("HEAD", url, **kwargs)

  def options(self, url, **kwargs):
    return self.request("OPTIONS", url, **kwargs)

  def close(self):
    return self._session.close()


class GrayboxHttpClient:
  """Runtime host/path scope guard for graybox HTTP traffic."""

  def __init__(self, target_url: str, *, allowlist=None, target_config=None):
    self.target_url = target_url.rstrip("/")
    self.scopes = path_scopes_from_allowlist(target_url, allowlist)
    discovery = getattr(target_config, "discovery", None)
    scope_prefix = getattr(discovery, "scope_prefix", "") if discovery else ""
    if scope_prefix and not self.scopes:
      self.scopes = [_normalize_path(scope_prefix)]

  def wrap_session(self, session):
    if isinstance(session, ScopedSession):
      return session
    return ScopedSession(session, self)

  def validate_url(self, url_or_path: str) -> str:
    url = normalize_request_url(self.target_url, url_or_path)
    path = urlsplit(url).path
    if self.scopes and not any(path_in_scope(path, scope) for scope in self.scopes):
      raise GrayboxScopeError(f"out-of-scope graybox request blocked: {path}")
    return url

  def request(self, session, method, url, **kwargs):
    allow_redirects = bool(kwargs.pop("allow_redirects", False))
    safe_url = self.validate_url(url)
    if not allow_redirects:
      return session.request(method, safe_url, allow_redirects=False, **kwargs)
    current_url = safe_url
    response = None
    for _ in range(5):
      response = session.request(method, current_url, allow_redirects=False, **kwargs)
      if response.status_code not in (301, 302, 303, 307, 308):
        return response
      location = response.headers.get("Location", "")
      if not location:
        return response
      current_url = self.validate_url(location)
      if response.status_code in (301, 302, 303) and method != "HEAD":
        method = "GET"
        kwargs.pop("data", None)
        kwargs.pop("json", None)
    return response
