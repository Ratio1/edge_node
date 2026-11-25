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

import base64
import re
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests

from .http_client import GrayboxScopeError, normalize_request_url
from .login_form import find_login_form, login_links
from .models.target_config import GrayboxTargetConfig, LOGIN_DISCOVERY_PATHS

# Login-page search budget, the configured login_path GET included.
MAX_LOGIN_SEARCH_FETCHES = 8
_DEFAULTS = GrayboxTargetConfig()
_REDIRECT_TO_GET = (301, 302, 303)
# Cache marker: the search ran once and found no login form.
LOGIN_NOT_FOUND = "login_not_found"


@dataclass(frozen=True)
class LoginTarget:
  """A login form found by the search; AuthManager caches it. Each login
  re-parses the cached page, so tokens and the action are always fresh."""
  page_url: str
  username_field: str
  password_field: str


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

  def __init__(self, target_url: str, target_config, verify_tls: bool = True,
               http_client=None):
    self.target_url = target_url.rstrip("/")
    self.target_config = target_config
    self.verify_tls = verify_tls
    self.http_client = http_client
    self._session: Optional[requests.Session] = None
    # Strategies may expose protocol-specific diagnostic state here; the
    # orchestrator copies it back into AuthManager so probe callers keep
    # using the legacy public API.
    self.last_detected_csrf_field: Optional[str] = None
    # Last login response seen, kept so a rejected login can be diagnosed.
    self.last_response = None

  def make_session(self) -> requests.Session:
    """Create a fresh, unauthenticated ``requests.Session`` honouring TLS verify."""
    s = requests.Session()
    s.verify = self.verify_tls
    if self.http_client is not None:
      return self.http_client.wrap_session(s)
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

# A password input in the *post-login* response means the form was re-rendered,
# i.e. the credentials were rejected. Matches `type=password` in any attribute
# order and with either quoting style, or none. The leading `\s` is load-bearing:
# `\btype` also matched `data-type="password"`, because a word boundary sits
# between the hyphen and the `t` — a component-library attribute would then read
# as a rejected login.
_LOGIN_FORM_RE = re.compile(
  r"""<input[^>]*?\stype\s*=\s*["']?password["']?""", re.IGNORECASE
)


def _path_query(url):
  parts = urlparse(url)
  return (parts.path.rstrip("/"), parts.query)


class FormAuth(AuthStrategy):
  """Cookie-session login via HTML form.

  The login form is found structurally (`login_form.find_login_form`); a
  `login_path` / `username_field` / `password_field` that differs from the
  `GrayboxTargetConfig` default is an operator override and wins.

  - ``preflight()`` — verifies target reachability, and for an override
    ``login_path`` that the page exists (not 404).
  - ``authenticate(creds)`` — GETs the login page (searching for it when
    the configured default path answers >= 400), POSTs the form's own
    hidden fields plus credentials, and heuristically confirms success.
  """

  def __init__(self, target_url, target_config, verify_tls=True,
               http_client=None, login_target=None):
    super().__init__(target_url, target_config, verify_tls, http_client)
    self._cached = login_target  # LoginTarget, LOGIN_NOT_FOUND or None
    self.found_login_target = None
    self.search_found_nothing = False
    # Diagnostic stage when authenticate() fails before a credential check.
    self.failure_stage = ""

  def _path_overridden(self) -> bool:
    return self.target_config.login_path != _DEFAULTS.login_path

  def preflight(self) -> Optional[str]:
    if self.http_client is not None:
      session = self.make_session()
      try:
        session.head(self.target_url, timeout=10, allow_redirects=True)
        if not self._path_overridden():
          return None
        login_url = self.target_url + self.target_config.login_path
        resp = session.get(login_url, timeout=10)
        if resp.status_code == 404:
          return f"Login page not found: {login_url} returned 404"
      except requests.RequestException as exc:
        return f"Login page unreachable: {exc}"
      finally:
        session.close()
      return None

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
    if not self._path_overridden():
      return None

    # 2. Override login page exists?
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
    self.last_response = None
    self.found_login_target = None
    self.failure_stage = ""
    if self._cached == LOGIN_NOT_FOUND:
      self.failure_stage = "login_form_not_found"
      return None
    session = self.make_session()
    try:
      resp, form, login_url = self._load_login_page(session)
      if form is None and (self._cached or resp.status_code >= 400):
        self.failure_stage = self.failure_stage or "login_form_not_found"
        self.last_response = resp
        session.close()
        return None
      return self._submit(session, creds, resp, form, login_url)
    except requests.RequestException:
      session.close()
      raise

  def _cfg_overrides(self):
    """(username, password) operator overrides, None when left at the default."""
    cfg = self.target_config
    return (
      cfg.username_field if cfg.username_field != _DEFAULTS.username_field else None,
      cfg.password_field if cfg.password_field != _DEFAULTS.password_field else None,
    )

  def _form_on(self, resp, url):
    """The login form of a < 400 response whose action stays on the target."""
    if resp.status_code >= 400:
      return None
    page_url = resp.url if isinstance(resp.url, str) and resp.url else url
    user, password = self._cfg_overrides()
    if isinstance(self._cached, LoginTarget):
      user, password = self._cached.username_field, self._cached.password_field
    form = find_login_form(
      resp.text, page_url, user, password, self.target_config.username_field)
    if form is None:
      return None
    try:
      form.action = normalize_request_url(self.target_url, form.action)
    except GrayboxScopeError:
      return None  # credentials never go off-origin
    base = urlparse(self.target_url).path.rstrip("/")
    path = urlparse(form.action).path
    if base and path != base and not path.startswith(base + "/"):
      return None  # nor to a path outside the target base
    return form

  def _load_login_page(self, session):
    """GET the login page; returns ``(response, form, page_url)``.

    The search (root, root's login links, LOGIN_DISCOVERY_PATHS) runs only
    when the configured default path answers >= 400.
    """
    cfg_url = (self._cached.page_url if isinstance(self._cached, LoginTarget)
               else self.target_url + self.target_config.login_path)
    resp = session.get(cfg_url, timeout=10, allow_redirects=True)
    form = self._form_on(resp, cfg_url)
    if (form is not None or resp.status_code < 400 or self._cached
        or self._path_overridden()):
      return resp, form, cfg_url
    tried, fetches, transport_failed = {cfg_url}, 1, False
    pending, expanded = deque([self.target_url + "/"]), False
    data_paths = [self.target_url + p for p in LOGIN_DISCOVERY_PATHS]
    while pending and fetches < MAX_LOGIN_SEARCH_FETCHES:
      url = pending.popleft()
      if url in tried:
        continue
      tried.add(url)
      fetches += 1
      try:
        cand = session.get(url, timeout=10, allow_redirects=True)
      except GrayboxScopeError:
        cand = None  # refused by scope: skip this candidate only
      except requests.RequestException:
        cand, transport_failed = None, True  # skip it (budget refusal is not one)
      if cand is not None:
        form = self._form_on(cand, url)
        if form is not None:
          return cand, form, url
        if cand.status_code == 401 and "basic" in str(
            cand.headers.get("WWW-Authenticate", "")).lower():
          self.failure_stage = "basic_challenge"
      if not expanded:
        expanded = True
        if cand is not None:
          page_url = cand.url if isinstance(cand.url, str) and cand.url else url
          pending.extend(login_links(cand.text, page_url))
        pending.extend(data_paths)
    if transport_failed:
      # A candidate that failed in transport may hold the form: retryable, no
      # miss is cached.
      raise requests.ConnectionError("login search: a candidate failed in transport")
    self.search_found_nothing = True
    return resp, None, cfg_url

  def _submit(self, session, creds, resp, form, login_url):
    # Auto-detect or use configured CSRF field
    csrf_field, csrf_token = self._extract_csrf(resp.text)
    if csrf_field:
      self.last_detected_csrf_field = csrf_field

    if form is not None:
      self.failure_stage = ""
      page_url = resp.url if isinstance(resp.url, str) and resp.url else login_url
      self.found_login_target = LoginTarget(
        page_url, form.username_field, form.password_field)
      post_url, payload = form.action, dict(form.fields)
      user_field, pass_field = form.username_field, form.password_field
    else:  # legacy: the configured path answered without a form
      page_url, post_url, payload = "", login_url, {}
      user_field = self.target_config.username_field
      pass_field = self.target_config.password_field
    payload[user_field] = creds.username
    payload[pass_field] = creds.password
    headers = {"Referer": login_url}
    if form is not None and csrf_field in form.fields:
      csrf_token = form.fields[csrf_field]  # the form's own token, not another form's
    if csrf_token and csrf_field:
      payload[csrf_field] = csrf_token
      headers["X-CSRFToken"] = csrf_token

    # POST credentials — transport errors bubble up (retryable). The POST is
    # never auto-followed: a 307/308 would replay the credentials.
    resp = session.post(
      post_url, data=payload, headers=headers,
      timeout=10, allow_redirects=False,
    )
    self.last_response = resp
    if resp.status_code in (307, 308):
      session.close()
      return None
    if resp.status_code in _REDIRECT_TO_GET and resp.headers.get("Location"):
      posted = resp
      resp = session.get(
        urljoin(resp.url or post_url, posted.headers["Location"]),
        timeout=10, allow_redirects=True)
      resp.history = [posted] + list(resp.history or [])
      self.last_response = resp
    # page_url: where the form was served, after redirects.
    if self._is_login_success(resp, session, post_url, page_url):
      self._session = session
      return session

    session.close()
    return None

  # ── Internal helpers (mirrored from legacy AuthManager) ────────────────

  @staticmethod
  def _is_login_success(response, session, login_url, page_url=""):
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
    # A password field still on the page is a real post-login assertion, and it
    # is the one signal cookie presence could never give. Every mainstream
    # framework sets a session cookie on the login page *before* authenticating
    # — Django `sessionid`, Rails `_session_id`, PHP `PHPSESSID` — so a rejected
    # login arrives with a cookie already set. Trusting that made a failed login
    # read as success, and the scan then ran anonymously while believing itself
    # authenticated: every finding behind the login silently absent and reported
    # as "not vulnerable". The failure-marker list does not cover it either,
    # because plenty of apps re-render the form with no message, or a localised
    # one.
    # Scoped to a response that stayed on the login endpoint. A password input
    # on a page we were *redirected to* is far more often a change-password
    # widget or a persistent nav login box on the real dashboard, and reading
    # that as a rejection aborts the entire authenticated scan — the mirror of
    # the bug above, with the same end result of findings never being looked for.
    # Back on the login page (the form's page, or its action) is not navigation.
    # Detected form: exact path+query (a root action must not match every URL);
    # legacy configured path: the historical substring rule.
    final = response.url or ""
    if page_url:
      on_login = _path_query(final) in (_path_query(login_url), _path_query(page_url))
    else:
      on_login = login_url in final
    navigated_away = bool(response.history) and not on_login
    if not navigated_away and _LOGIN_FORM_RE.search(response.text or ""):
      return False
    # Cookie presence is a necessary condition for a cookie session, not
    # evidence of authentication: the login page itself sets one. The evidence
    # is the failure-marker / JSON / password-form checks above; the proof is
    # the authenticated probe path check in
    # `AuthManager._validate_authenticated_session` when one is configured.
    return bool(session.cookies.get_dict())

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

  def __init__(self, target_url, target_config, verify_tls=True, http_client=None):
    super().__init__(target_url, target_config, verify_tls, http_client)
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
      if self.http_client is not None:
        session = self.make_session()
        try:
          resp = session.head(url, timeout=10, allow_redirects=True)
        finally:
          session.close()
      else:
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


class BasicAuth(BearerAuth):
  """HTTP Basic auth: stamps ``Authorization: Basic b64(user:pass)``.

  Sends nothing at login, like BearerAuth; the proof is AuthManager's
  authenticated-probe-path check. The client refuses cross-origin hops, so
  the header never leaves the target.
  """

  def authenticate(self, creds) -> Optional[requests.Session]:
    if not creds.has_form_credentials():
      return None
    session = self.make_session()
    raw = f"{creds.username}:{creds.password}".encode("utf-8")
    session.headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    self._session = session
    self._creds = creds
    return session


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

  def __init__(self, target_url, target_config, verify_tls=True, http_client=None):
    super().__init__(target_url, target_config, verify_tls, http_client)
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
      if self.http_client is not None:
        session = self.make_session()
        try:
          resp = session.head(
            url, headers=headers, params=params, timeout=10,
            allow_redirects=True,
          )
        finally:
          session.close()
      else:
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
