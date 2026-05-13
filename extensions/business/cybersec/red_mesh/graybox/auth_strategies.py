"""Auth strategy pattern for graybox session establishment.

Defines the `AuthStrategy` ABC and concrete strategies used by the
`AuthManager` orchestrator. Each strategy returns a fully-authenticated
`requests.Session` ready for probe families to use.

Strategy implementations are introduced incrementally across Subphase 1.5:
  1.5 commit #1 — AuthStrategy ABC + FormAuth.
  1.5 commit #6 — BearerAuth.
  1.5 commit #7 — ApiKeyAuth.
  1.5 commit #3 — `AuthManager` is wired to dispatch to a strategy
                  selected from `target_config.api_security.auth.auth_type`.

`Credentials` (Subphase 1.5 commit #2) is the value object the
orchestrator hands to each strategy at `authenticate()` time. Strategies
must NOT capture credentials beyond the active session lifetime — call
``creds.clear()`` on ``cleanup()`` when they own the secret material.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Optional

import requests


class AuthStrategy(ABC):
  """Abstract base class for graybox auth strategies.

  Concrete strategies live alongside this module (`auth_strategies.py`).
  They are stateless apart from the active ``requests.Session`` and any
  short-lived collaborator references (target URL, verify_tls flag).

  Lifecycle:
    1. ``preflight()`` validates the target is reachable / configured in
       the strategy-appropriate way. Returns an error string on failure,
       None on success.
    2. ``authenticate(creds)`` returns an authenticated ``Session`` or
       None on failure. The orchestrator (`AuthManager`) is responsible
       for retries and recording errors.
    3. ``refresh(creds)`` re-establishes the authenticated state when a
       session ages out. Returns True on success.
    4. ``cleanup()`` closes the session and zeroises any captured
       credential material owned by the strategy.

  Strategies should be cheap to instantiate; the orchestrator may create
  multiple instances (for example to hold ``official`` and ``regular``
  sessions concurrently).
  """

  def __init__(self, target_url: str, target_config, verify_tls: bool = True):
    self.target_url = target_url.rstrip("/")
    self.target_config = target_config
    self.verify_tls = verify_tls
    self._session: Optional[requests.Session] = None
    # Strategies may expose protocol-specific diagnostic state here; the
    # orchestrator copies it back into AuthManager so probe callers keep
    # using the legacy public API.
    self.last_detected_csrf_field: Optional[str] = None

  def make_session(self) -> requests.Session:
    """Create a fresh, unauthenticated ``requests.Session`` honouring TLS verify."""
    s = requests.Session()
    s.verify = self.verify_tls
    return s

  @property
  def session(self) -> Optional[requests.Session]:
    return self._session

  @abstractmethod
  def preflight(self) -> Optional[str]:
    """Return an error string if preflight fails, None if OK."""
    ...

  @abstractmethod
  def authenticate(self, creds) -> Optional[requests.Session]:
    """Return an authenticated session or None on failure."""
    ...

  def refresh(self, creds) -> bool:
    """Default refresh = re-authenticate. Strategies may override."""
    self.cleanup()
    sess = self.authenticate(creds)
    return sess is not None

  def cleanup(self) -> None:
    """Close the session if owned. Strategies that hold secret material
    in addition to the session should override and zeroise it via
    ``creds.clear()``.
    """
    if self._session is not None:
      try:
        self._session.close()
      except Exception:
        pass
      self._session = None


# Common CSRF field names across frameworks (mirrors COMMON_CSRF_FIELDS in
# target_config.py — kept independent here so the strategy module has no
# upstream dependency on the typed-config package layout).
_FORM_AUTH_CSRF_FIELDS = (
  "csrfmiddlewaretoken",  # Django
  "csrf_token",           # Flask / WTForms
  "authenticity_token",   # Rails
  "_csrf",                # Spring Security
  "_token",               # Laravel
)

_FORM_AUTH_FAILURE_MARKERS = (
  "invalid credentials", "invalid username", "invalid password",
  "incorrect password", "login failed", "authentication failed",
  "try again", "wrong password", "unable to log in",
  "account locked", "account disabled",
)


class FormAuth(AuthStrategy):
  """Cookie-session login via HTML form (existing legacy behaviour).

  Wraps the form-login logic that previously lived inline in
  `AuthManager._try_login_attempt`. The behaviour and heuristics are
  identical — see Subphase 1.5 commit #3 for the wiring into the
  orchestrator.

  Public methods:
    - ``preflight()`` — verifies target reachability AND that the login
      page exists at ``target_config.login_path`` (not 404).
    - ``authenticate(creds)`` — GETs the login page, auto-detects the
      CSRF field, POSTs ``username``/``password`` from ``creds``, and
      heuristically confirms success.
  """

  def preflight(self) -> Optional[str]:
    # 1. Target reachable?
    try:
      requests.head(
        self.target_url,
        timeout=10,
        verify=self.verify_tls,
        allow_redirects=True,
      )
    except requests.RequestException as exc:
      return f"Target unreachable: {exc}"

    # 2. Login page exists?
    login_url = self.target_url + self.target_config.login_path
    try:
      resp = requests.get(login_url, timeout=10, verify=self.verify_tls)
      if resp.status_code == 404:
        return f"Login page not found: {login_url} returned 404"
    except requests.RequestException as exc:
      return f"Login page unreachable: {exc}"

    return None

  def authenticate(self, creds) -> Optional[requests.Session]:
    """Return an authenticated session or None on auth-level failure.

    Transport errors (``requests.RequestException``) bubble up so the
    orchestrator can distinguish retryable transport failures from
    definitive credential failures.
    """
    session = self.make_session()
    login_url = self.target_url + self.target_config.login_path

    # GET login page — transport errors bubble up (retryable).
    try:
      resp = session.get(login_url, timeout=10, allow_redirects=True)
    except requests.RequestException:
      session.close()
      raise

    # Auto-detect or use configured CSRF field
    csrf_field, csrf_token = self._extract_csrf(resp.text)
    if csrf_field:
      self.last_detected_csrf_field = csrf_field

    payload = {
      self.target_config.username_field: creds.username,
      self.target_config.password_field: creds.password,
    }
    headers = {"Referer": login_url}
    if csrf_token and csrf_field:
      payload[csrf_field] = csrf_token
      headers["X-CSRFToken"] = csrf_token

    # POST credentials — transport errors bubble up (retryable).
    try:
      resp = session.post(
        login_url, data=payload, headers=headers,
        timeout=10, allow_redirects=True,
      )
    except requests.RequestException:
      session.close()
      raise

    if self._is_login_success(resp, session, login_url):
      self._session = session
      return session

    session.close()
    return None

  # ── Internal helpers (mirrored from legacy AuthManager) ────────────────

  @staticmethod
  def _is_login_success(response, session, login_url):
    if response.status_code >= 400:
      return False
    body_lower = response.text.lower()
    if any(marker in body_lower for marker in _FORM_AUTH_FAILURE_MARKERS):
      return False
    ct = response.headers.get("content-type", "")
    if "application/json" in ct:
      try:
        data = response.json()
        if isinstance(data, dict):
          if (data.get("error") or data.get("success") is False
              or data.get("authenticated") is False):
            return False
      except ValueError:
        pass
    has_cookies = bool(session.cookies.get_dict())
    if response.url and "login" not in response.url.lower():
      if has_cookies:
        return True
    if response.history and login_url not in response.url:
      if has_cookies:
        return True
    return has_cookies

  def _extract_csrf(self, html):
    """Return ``(field_name, token_value)`` or ``(None, None)``.

    Honours ``target_config.csrf_field`` when set, otherwise tries the
    common framework field names. Falls back to a generic
    hidden-input-with-csrf-or-token heuristic.
    """
    configured = getattr(self.target_config, "csrf_field", "") or ""
    if configured:
      return (configured, self._find_csrf_value(html, configured))
    for field_name in _FORM_AUTH_CSRF_FIELDS:
      token = self._find_csrf_value(html, field_name)
      if token:
        return (field_name, token)
    m = re.search(
      r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']*(?:csrf|token)[^"\']*)["\'][^>]+value=["\']([^"\']+)',
      html or "", re.IGNORECASE,
    )
    if m:
      return (m.group(1), m.group(2))
    return (None, None)

  @staticmethod
  def _find_csrf_value(html, field_name):
    m = re.search(
      rf'name=["\']?{re.escape(field_name)}["\']?\s[^>]*value=["\']([^"\']+)',
      html or "", re.IGNORECASE,
    )
    if m:
      return m.group(1)
    m = re.search(
      rf'value=["\']([^"\']+)["\'][^>]*name=["\']?{re.escape(field_name)}["\']?',
      html or "", re.IGNORECASE,
    )
    return m.group(1) if m else None


class BearerAuth(AuthStrategy):
  """Bearer-token auth for API-only targets.

  Reads `creds.bearer_token` and injects it into every request via the
  configured header/scheme (default ``Authorization: Bearer <token>``).
  No HTTP traffic is needed during ``authenticate`` itself — the strategy
  simply stamps the session with the token.

  ``preflight`` validates that the configured authenticated probe path is
  reachable without sending secret material. A 401/403 is acceptable here
  because it usually means auth is enforced; the AuthManager validates the
  stamped session after ``authenticate``.
  """

  def __init__(self, target_url, target_config, verify_tls=True):
    super().__init__(target_url, target_config, verify_tls)
    self._auth_desc = self._resolve_auth_descriptor()
    self._creds = None  # populated by authenticate(); needed for refresh()

  def _resolve_auth_descriptor(self):
    """Pluck `api_security.auth` off the config or fall back to defaults."""
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is not None:
      auth = getattr(api_security, "auth", None)
      if auth is not None:
        return auth
    # Tests/callers without an ApiSecurityConfig get sensible defaults.
    from .models.target_config import AuthDescriptor
    return AuthDescriptor()

  def preflight(self) -> Optional[str]:
    probe_path = (self._auth_desc.authenticated_probe_path or "").strip()
    if not probe_path:
      # Caller opted out of pre-auth verification — strategy will fail
      # loudly at the first probe call if the token is invalid.
      return None
    url = self.target_url + probe_path
    try:
      resp = requests.head(url, timeout=10, verify=self.verify_tls,
                           allow_redirects=True)
    except requests.RequestException as exc:
      return f"Authenticated probe path unreachable: {exc}"
    return None

  def authenticate(self, creds) -> Optional[requests.Session]:
    if not creds.has_bearer_token():
      return None
    session = self.make_session()
    scheme = self._auth_desc.bearer_scheme or "Bearer"
    header_name = self._auth_desc.bearer_token_header_name or "Authorization"
    value = f"{scheme} {creds.bearer_token}".strip() if scheme else creds.bearer_token
    session.headers[header_name] = value
    self._session = session
    self._creds = creds
    return session

  def refresh(self, creds) -> bool:
    """Default behaviour: re-stamp the same token. Phase 9 OAuth2 follow-up
    can replace this with a real refresh-grant call against
    `bearer_refresh_url` using `creds.bearer_refresh_token`.
    """
    self.cleanup()
    return self.authenticate(creds) is not None

  def cleanup(self) -> None:
    super().cleanup()
    if self._creds is not None:
      # Don't clear caller-owned creds — AuthManager.cleanup() drives that.
      self._creds = None


class ApiKeyAuth(AuthStrategy):
  """API-key auth for legacy / partner APIs.

  Places ``creds.api_key`` in either:
    - a header (default; configured via
      ``auth.api_key_header_name`` — e.g. ``X-Api-Key``)
    - a query parameter (``auth.api_key_location='query'``;
      configured via ``auth.api_key_query_param``).

  Query-parameter placement is supported for legacy interoperability but
  is a known anti-pattern (keys leak to access logs, proxies, referrers).
  The Subphase 1.6 evidence scrubber redacts the configured query
  parameter from finding evidence; the Navigator launch form shows a
  warning banner (Subphase 8.5).
  """

  def __init__(self, target_url, target_config, verify_tls=True):
    super().__init__(target_url, target_config, verify_tls)
    self._auth_desc = self._resolve_auth_descriptor()
    self._creds = None

  def _resolve_auth_descriptor(self):
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is not None:
      auth = getattr(api_security, "auth", None)
      if auth is not None:
        return auth
    from .models.target_config import AuthDescriptor
    return AuthDescriptor()

  def preflight(self) -> Optional[str]:
    probe_path = (self._auth_desc.authenticated_probe_path or "").strip()
    if not probe_path:
      return None
    url = self.target_url + probe_path
    headers = {}
    params = {}
    if self._auth_desc.api_key_location == "query":
      # We have no key here (preflight runs before authenticate's session
      # is created); just check the probe path is reachable.
      pass
    try:
      resp = requests.head(
        url, headers=headers, params=params, timeout=10,
        verify=self.verify_tls, allow_redirects=True,
      )
    except requests.RequestException as exc:
      return f"Authenticated probe path unreachable: {exc}"
    # 401/403 here is informational — we haven't sent the key yet so it
    # may simply mean auth is enforced. Real validation happens after
    # authenticate(), when probes start hitting endpoints.
    return None

  def authenticate(self, creds) -> Optional[requests.Session]:
    if not creds.has_api_key():
      return None
    session = self.make_session()
    location = self._auth_desc.api_key_location or "header"
    if location == "header":
      header_name = self._auth_desc.api_key_header_name or "X-Api-Key"
      session.headers[header_name] = creds.api_key
    elif location == "query":
      # Stash the param name + value on the session for per-request mixing
      # by probes. Cleanest cross-call carrier without a real session
      # extension is the session.params attribute used by requests.
      param_name = self._auth_desc.api_key_query_param or "api_key"
      session.params = {**(session.params or {}), param_name: creds.api_key}
    else:
      session.close()
      return None
    self._session = session
    self._creds = creds
    return session

  def refresh(self, creds) -> bool:
    self.cleanup()
    return self.authenticate(creds) is not None

  def cleanup(self) -> None:
    super().cleanup()
    if self._creds is not None:
      self._creds = None
