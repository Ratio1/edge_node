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
    session = self.make_session()
    login_url = self.target_url + self.target_config.login_path

    # GET login page
    try:
      resp = session.get(login_url, timeout=10, allow_redirects=True)
    except requests.RequestException:
      session.close()
      return None

    # Auto-detect or use configured CSRF field
    csrf_field, csrf_token = self._extract_csrf(resp.text)

    payload = {
      self.target_config.username_field: creds.username,
      self.target_config.password_field: creds.password,
    }
    headers = {"Referer": login_url}
    if csrf_token and csrf_field:
      payload[csrf_field] = csrf_token
      headers["X-CSRFToken"] = csrf_token

    try:
      resp = session.post(
        login_url, data=payload, headers=headers,
        timeout=10, allow_redirects=True,
      )
    except requests.RequestException:
      session.close()
      return None

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
