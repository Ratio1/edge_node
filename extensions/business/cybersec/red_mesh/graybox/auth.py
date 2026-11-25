"""
Authentication manager for graybox scanning.

Orchestrates `AuthStrategy` instances to establish authenticated sessions
for one or more principals (`official`, `regular`). The strategy itself
owns the protocol-level details (form login, Bearer header injection,
API-key placement); the manager owns the lifecycle (expiry, retry,
multi-principal coordination, cleanup).

For backward compatibility this module continues to expose `AuthManager`
with the same public API used by `graybox/worker.py` and by tests that
patch `extensions...graybox.auth.requests`. Internally it delegates to
`auth_strategies.FormAuth` for the legacy form-login flow; later
subphases route to `BearerAuth` / `ApiKeyAuth` based on
`target_config.api_security.auth.auth_type`.
"""

import dataclasses
import re
import time
from urllib.parse import urljoin, urlparse

import requests

from ..constants import GRAYBOX_SESSION_MAX_AGE
from .auth_credentials import Credentials
from .auth_strategies import (
  ApiKeyAuth, BasicAuth, BearerAuth, FormAuth, LOGIN_NOT_FOUND, LoginTarget,
)
from .http_client import GrayboxScopeError, normalize_request_url
from .models.target_config import COMMON_CSRF_FIELDS
from .models import GrayboxAuthState


class AuthManager:
  MAX_AUTH_ATTEMPTS = 2
  AUTH_RETRY_DELAY_SECONDS = 0.25
  LIVENESS_CHECK_SECONDS = 60

  """
  Manages authenticated HTTP sessions for graybox probes.

  Handles CSRF auto-detection, login with robust success detection,
  session expiry, re-auth, and cleanup.
  """

  def __init__(self, target_url, target_config, verify_tls=True, http_client=None):
    self.target_url = target_url.rstrip("/")
    self.target_config = target_config
    self.verify_tls = verify_tls
    self.http_client = http_client

    self.anon_session = None
    self.official_session = None
    self.regular_session = None
    self._official_configured = False
    self._session_cookie_names = {}
    self._created_at = 0.0
    self._liveness_checked_at = 0.0
    self._refresh_count = 0
    self._auth_errors = []
    self._auth_diagnostics = []
    self._detected_csrf_field = None
    # Form login found by FormAuth's search: LoginTarget, LOGIN_NOT_FOUND or
    # None (not searched yet). The search runs at most once per manager.
    self._login_target = None

  @property
  def detected_csrf_field(self) -> str | None:
    """Public read access to the auto-detected CSRF field name."""
    return self._detected_csrf_field

  @property
  def primary_session(self):
    """Session probes run under: official when configured, else regular.

    ``official_session`` is never set to the regular session, so reports
    that read it never claim admin access a regular-only scan did not have.
    """
    return self.official_session or self.regular_session

  @property
  def primary_principal(self) -> str:
    if self.official_session is not None:
      return "official"
    if self.regular_session is not None:
      return "regular"
    return ""

  @property
  def admin_context(self) -> str:
    """``provided`` when official (admin) credentials were configured, else ``absent``."""
    return "provided" if self._official_configured else "absent"

  @property
  def is_expired(self) -> bool:
    return time.time() - self._created_at > GRAYBOX_SESSION_MAX_AGE

  @property
  def auth_state(self) -> GrayboxAuthState:
    return GrayboxAuthState(
      created_at=self._created_at,
      refresh_count=self._refresh_count,
      official_authenticated=self.official_session is not None,
      regular_authenticated=self.regular_session is not None,
      auth_errors=tuple(self._auth_errors),
    )

  def needs_refresh(self, require_regular=False) -> bool:
    if self.is_expired:
      return True
    if self.primary_session is None:
      return True
    if self._official_configured and self.official_session is None:
      return True
    if require_regular and self.regular_session is None:
      return True
    # A server-side logout (for example a GET of the logout URL) drops the
    # session cookie while the session object lives on; probes would then
    # run anonymously and report false clean results.
    for session in (self.official_session, self.regular_session):
      if session is not None and not self._session_cookies_alive(session):
        return True
    # A server-side logout that keeps the cookie, and bearer / api_key
    # sessions, show up only on the authenticated probe path. Re-check it at
    # most once per LIVENESS_CHECK_SECONDS. A transport error is not a logout.
    if (self._authenticated_probe_path()
        and time.time() - self._liveness_checked_at >= self.LIVENESS_CHECK_SECONDS):
      self._liveness_checked_at = time.time()
      valid, retryable = self._validate_authenticated_session(self.primary_session)
      # Only a redirect, a 401/403, or a 2xx without the configured marker or
      # identity (a 200 login page at the probe path) means the session ended;
      # a 429 or 5xx on the probe path is the target struggling, not a logout.
      last_stage = (self._auth_diagnostics[-1].get("stage", "")
                    if self._auth_diagnostics else "")
      if not valid and not retryable and last_stage in (
          "authenticated_probe_redirect", "authenticated_probe_rejected",
          "authenticated_probe_marker_missing",
          "authenticated_probe_identity_missing",
          # Proven at login, public now: a logout that kept the cookie and
          # redirects the check path to a public page (form one-hop rule).
          "authenticated_probe_public_control"):
        return True
    return False

  def _remember_session_cookies(self, session):
    """Record the login cookies of a form session (CSRF cookies excluded)."""
    if session is None or self._resolve_auth_type() != "form":
      return
    try:
      names = set(session.cookies.get_dict().keys())
    except Exception:
      return
    names = {n for n in names if "csrf" not in n.lower() and n not in COMMON_CSRF_FIELDS}
    if names:
      self._session_cookie_names[id(session)] = names

  def _session_cookies_alive(self, session) -> bool:
    expected = self._session_cookie_names.get(id(session))
    if not expected:
      return True
    try:
      present = set(session.cookies.get_dict().keys())
    except Exception:
      return True
    # Dead only when every recorded login cookie is gone: a one-shot flash
    # cookie that disappears after one request is not a logout.
    return not expected.isdisjoint(present)

  def ensure_sessions(self, official_creds, regular_creds=None):
    """Re-authenticate if sessions are stale or not yet created."""
    regular_creds = self._coerce_creds(regular_creds, principal="regular")
    require_regular = self._credentials_configured(regular_creds)
    if not self.needs_refresh(require_regular=require_regular):
      return True
    self.cleanup()
    self._refresh_count += 1
    auth_ok = self.authenticate(official_creds, regular_creds)
    if not auth_ok:
      self.cleanup()
    return auth_ok

  def authenticate(self, official_creds, regular_creds=None):
    """Create fresh sessions for all configured users."""
    self.anon_session = self._make_session()
    official_creds = self._coerce_creds(official_creds, principal="official")
    regular_creds = self._coerce_creds(regular_creds, principal="regular")
    self._auth_errors = []
    self._auth_diagnostics = []
    self._session_cookie_names = {}
    self._official_configured = self._credentials_configured(official_creds)
    regular_configured = self._credentials_configured(regular_creds)

    # Never call the auth strategy for an unconfigured principal: a login
    # with empty credentials counts toward lockout and WAF limits.
    if not self._official_configured and not regular_configured:
      self._record_auth_error("no_credentials_configured")
      return False

    if self._official_configured:
      self.official_session = self._try_login_with_retry(
        "official",
        official_creds,
      )
      if not self.official_session:
        return False
      self._remember_session_cookies(self.official_session)

    if regular_configured:
      self.regular_session = self._try_login_with_retry(
        "regular",
        regular_creds,
      )
      if not self.regular_session:
        # Regular is the primary principal when official is absent.
        if not self._official_configured:
          return False
      self._remember_session_cookies(self.regular_session)

    self._created_at = time.time()
    self._liveness_checked_at = self._created_at
    return True

  @staticmethod
  def _coerce_creds(creds, principal="official"):
    if creds is None:
      return None
    if isinstance(creds, Credentials):
      creds.principal = creds.principal or principal
      return creds
    if hasattr(creds, "to_credentials") and callable(creds.to_credentials):
      return creds.to_credentials()
    if isinstance(creds, dict):
      return Credentials(
        username=creds.get("username", "") or "",
        password=creds.get("password", "") or "",
        bearer_token=creds.get("bearer_token", "") or "",
        bearer_refresh_token=creds.get("bearer_refresh_token", "") or "",
        api_key=creds.get("api_key", "") or "",
        principal=creds.get("principal", principal) or principal,
      )
    return Credentials(
      username=getattr(creds, "username", "") or "",
      password=getattr(creds, "password", "") or "",
      bearer_token=getattr(creds, "bearer_token", "") or "",
      bearer_refresh_token=getattr(creds, "bearer_refresh_token", "") or "",
      api_key=getattr(creds, "api_key", "") or "",
      principal=getattr(creds, "principal", principal) or principal,
    )

  @staticmethod
  def _credentials_configured(creds) -> bool:
    if creds is None:
      return False
    return bool(
      creds.has_form_credentials()
      or creds.has_bearer_token()
      or creds.has_api_key()
    )

  def cleanup(self):
    """
    Explicitly close sessions and attempt logout.

    Prevents session accumulation on targets with session limits.
    """
    logout_url = self._logout_url_for_current_auth()
    closed = set()
    for session in [self.official_session, self.regular_session]:
      if session is None or id(session) in closed:
        continue
      closed.add(id(session))
      try:
        if logout_url:
          # Cleanup is exempt from the request budget (it still counts); a bare
          # requests session, with no client, does not take the kwarg.
          extra = {"budget_exempt": True} if self.http_client is not None else {}
          session.get(logout_url, timeout=5, **extra)
      except requests.RequestException:
        pass
      finally:
        session.close()
    if self.anon_session:
      self.anon_session.close()
    self.official_session = None
    self.regular_session = None
    self.anon_session = None
    self._session_cookie_names = {}
    self._created_at = 0.0

  def preflight_check(self) -> str | None:
    """Delegate preflight to the configured auth strategy.

    Strategy chooses its own preflight semantics — FormAuth requires the
    login_path to exist; BearerAuth / ApiKeyAuth (Subphase 1.5 #5-#7)
    instead hit a configured authenticated endpoint.
    """
    return self._build_strategy().preflight()

  def _make_session(self):
    s = requests.Session()
    s.verify = self.verify_tls
    if self.http_client is not None:
      return self.http_client.wrap_session(s)
    return s

  def make_anonymous_session(self):
    """
    Public API for creating anonymous sessions.

    Used by probes that need a fresh session for lockout detection
    or anonymous endpoint testing.
    """
    return self._make_session()

  def try_credentials(self, username, password):
    """
    Public API for credential testing (used by weak-auth probe).

    Returns a Session on success (caller must close it), None on failure.
    """
    return self._try_login(username, password)

  def failure_reason(self) -> str:
    """Name the principal whose login failed and why, for the abort reason."""
    if "no_credentials_configured" in self._auth_errors:
      return "no official or regular credentials are configured"
    principal = "official" if self._official_configured else "regular"
    if f"{principal}_login_transport_error" in self._auth_errors:
      cause = "failed: target unreachable during login"
    elif f"{principal}_login_failed" in self._auth_errors:
      cause = "rejected"
    else:
      return ""
    label = "Official (admin)" if principal == "official" else "Regular"
    reason = f"{label} login {cause}"
    if principal == "regular":
      reason += " (no official credentials configured)"
    if self._auth_diagnostics:
      last = self._auth_diagnostics[-1]
      detail = last.get("stage", "")
      if last.get("status") is not None:
        detail += f", HTTP {last['status']}"
      reason += f"; last check: {detail}"
    return reason

  def _record_auth_error(self, code):
    self._auth_errors.append(code)

  def _has_gateway_auth(self) -> bool:
    api_security = getattr(self.target_config, "api_security", None)
    gateway_auth = (
      getattr(api_security, "gateway_auth", None)
      if api_security is not None else None
    )
    return gateway_auth is not None

  @staticmethod
  def _response_header(resp, name: str) -> str:
    headers = getattr(resp, "headers", None) or {}
    getter = getattr(headers, "get", None)
    if callable(getter):
      value = getter(name)
      if value is not None:
        return str(value)
    lower_name = name.lower()
    for key, value in getattr(headers, "items", lambda: [])():
      if str(key).lower() == lower_name:
        return str(value)
    return ""

  def _classify_auth_failure(self, resp) -> str:
    if not self._has_gateway_auth():
      return "app_auth_likely"
    fixture_layer = self._response_header(resp, "X-RedMesh-Fixture-Layer").lower()
    proxy_status = self._response_header(resp, "Proxy-Status").lower()
    aws_gateway_signal = any(
      self._response_header(resp, name)
      for name in ("x-amzn-ErrorType", "x-amzn-RequestId", "x-amz-apigw-id")
    )
    if fixture_layer == "gateway" or "error=" in proxy_status or aws_gateway_signal:
      return "gateway_block_likely"
    if fixture_layer == "app":
      return "app_auth_likely"
    return "ambiguous_auth_failure"

  def _record_auth_diagnostic(self, stage: str, resp=None, error: str = ""):
    status = getattr(resp, "status_code", None) if resp is not None else None
    classification = self._classify_auth_failure(resp)
    diagnostic = {
      "classification": classification,
      "stage": stage,
      "status": status,
      "fixture_layer": self._response_header(resp, "X-RedMesh-Fixture-Layer"),
      "proxy_status": self._response_header(resp, "Proxy-Status"),
      "www_authenticate": bool(self._response_header(resp, "WWW-Authenticate")),
      "provider_gateway_signal": any(
        self._response_header(resp, name)
        for name in ("x-amzn-ErrorType", "x-amzn-RequestId", "x-amz-apigw-id")
      ),
      "error": error,
    }
    self._auth_diagnostics.append({
      key: value
      for key, value in diagnostic.items()
      if value not in (None, "", False)
    })

  def _try_login_with_retry(self, principal, creds):
    retryable_failure = False
    for attempt in range(1, self.MAX_AUTH_ATTEMPTS + 1):
      session, retryable_failure = self._try_login_attempt(creds)
      if session is not None:
        return session
      if not retryable_failure:
        break
      if attempt < self.MAX_AUTH_ATTEMPTS:
        time.sleep(self.AUTH_RETRY_DELAY_SECONDS)

    if retryable_failure:
      self._record_auth_error(f"{principal}_login_transport_error")
    else:
      self._record_auth_error(f"{principal}_login_failed")
    return None

  def _try_login(self, username, password):
    """
    Attempt login with CSRF auto-detection and robust success detection.
    """
    session, _ = self._try_login_attempt(Credentials(username=username, password=password))
    return session

  def _try_login_attempt(self, creds):
    """Attempt one login via the configured strategy.

    Returns ``(session, retryable_failure)``. Transport errors raised by
    the strategy are translated into ``retryable_failure=True``; auth-level
    failures into ``retryable_failure=False``.
    """
    strategy = self._build_strategy()
    try:
      session = strategy.authenticate(creds)
    except requests.RequestException:
      # Even on transport errors, the strategy may have already seen the
      # login page and detected the CSRF field — preserve it.
      if strategy.last_detected_csrf_field:
        self._detected_csrf_field = strategy.last_detected_csrf_field
      self._remember_login_target(strategy)  # a retry must not search again
      return None, True
    # Always propagate whatever CSRF field the strategy saw, regardless
    # of whether the credential check ultimately succeeded.
    if strategy.last_detected_csrf_field:
      self._detected_csrf_field = strategy.last_detected_csrf_field
    self._remember_login_target(strategy)
    if session is None:
      self._record_auth_diagnostic(
        getattr(strategy, "failure_stage", "") or "login_rejected",
        strategy.last_response)
    if session is not None:
      valid, retryable_failure = self._validate_authenticated_session(session)
      if not valid:
        try:
          session.close()
        except Exception:
          pass
        return None, retryable_failure
      return session, False
    return None, False

  def _remember_login_target(self, strategy):
    """Cache what the form search found and write the detected names back
    to ``target_config``, before the session is validated, so the probe-path
    redirect check and every probe use the detected login page and fields."""
    if getattr(strategy, "search_found_nothing", False):
      self._login_target = LOGIN_NOT_FOUND
    found = getattr(strategy, "found_login_target", None)
    if found is None:
      return
    self._login_target = found
    base = urlparse(self.target_url).path.rstrip("/")
    page = urlparse(found.page_url)
    path = page.path + (f"?{page.query}" if page.query else "")
    if base and not page.path.startswith(base + "/"):
      path = self.target_config.login_path  # outside the base: cache still drives login
    elif base:
      path = path[len(base):]
    self.target_config = dataclasses.replace(
      self.target_config, login_path=path,
      username_field=found.username_field, password_field=found.password_field)

  def _authenticated_probe_path(self) -> str:
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return ""
    auth_desc = getattr(api_security, "auth", None)
    if auth_desc is None:
      return ""
    return (getattr(auth_desc, "authenticated_probe_path", "") or "").strip()

  def _authenticated_probe_method(self) -> str:
    api_security = getattr(self.target_config, "api_security", None)
    auth_desc = getattr(api_security, "auth", None) if api_security is not None else None
    method = (getattr(auth_desc, "authenticated_probe_method", "GET") or "GET").upper()
    allow_non_readonly = bool(
      getattr(auth_desc, "allow_non_readonly_auth_validation_method", False)
    )
    if method in ("GET", "HEAD"):
      return method
    if allow_non_readonly and method in ("POST", "OPTIONS"):
      return method
    return "GET"

  def _logout_url_for_current_auth(self) -> str:
    if self._resolve_auth_type() == "form":
      path = getattr(self.target_config, "logout_path", "") or ""
    else:
      api_security = getattr(self.target_config, "api_security", None)
      auth_desc = getattr(api_security, "auth", None) if api_security is not None else None
      path = getattr(auth_desc, "api_logout_path", "") or ""
    return self.target_url + path if path else ""

  def _auth_descriptor(self):
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return None
    return getattr(api_security, "auth", None)

  def _configured_success_statuses(self) -> tuple[int, ...]:
    auth_desc = self._auth_descriptor()
    if auth_desc is None:
      return ()
    return tuple(getattr(auth_desc, "authenticated_probe_success_statuses", ()) or ())

  def _configured_success_marker(self) -> str:
    auth_desc = self._auth_descriptor()
    if auth_desc is None:
      return ""
    return str(getattr(auth_desc, "authenticated_probe_success_marker", "") or "")

  def _configured_identity_json_path(self) -> str:
    auth_desc = self._auth_descriptor()
    if auth_desc is None:
      return ""
    return str(getattr(auth_desc, "authenticated_probe_identity_json_path", "") or "")

  @staticmethod
  def _traverse_identity_path(payload, path: str):
    """Safely walk a dotted JSON path.

    Only supports nested dict key lookups (no array indexing, no
    expressions). Returns None if any segment is missing. The whole
    traversal is bounded by the depth of the configured path so it
    cannot be turned into an arbitrary-expression evaluator.
    """
    if not path or not isinstance(payload, dict):
      return None
    cursor = payload
    for segment in path.split("."):
      segment = segment.strip()
      if not segment or not isinstance(cursor, dict):
        return None
      if segment not in cursor:
        return None
      cursor = cursor[segment]
    return cursor

  def _anonymous_control_response(self, method: str, url: str):
    """Send the same probe request without credentials, no redirects."""
    try:
      session = self._make_session()
      try:
        return session.request(
          method, url, timeout=10, allow_redirects=False, verify=self.verify_tls,
        )
      finally:
        try:
          session.close()
        except Exception:
          pass
    except requests.RequestException:
      return None

  def _validate_authenticated_session(self, session) -> tuple[bool, bool]:
    """Validate an authenticated session after credentials have been attached.

    Tightened in B2 (PR406 remediation): we no longer follow redirects
    or accept any <400 status, since an invalid bearer token frequently
    triggers a 302 to a public 200 login page. The flow is:

      1. Send the probe with allow_redirects=False; reject 3xx/401/403.
      2. Send an anonymous control request to the same path. If the
         control is also 2xx, require an explicit success assertion
         (status allow-list, marker, or identity JSON path) before
         accepting — otherwise the path is effectively public and the
         configured token tells us nothing.
      3. If a marker / identity path is configured, both the
         authenticated AND anonymous responses must agree with the
         assertion (marker present in authenticated body but missing
         from anonymous; identity path non-empty when authenticated and
         empty/missing when anonymous).

    Redirects: bearer / api_key sessions reject every 3xx (a 302 means the
    token is bad). A form (cookie) session may legitimately be redirected,
    e.g. Django ``APPEND_SLASH`` 301s ``/dashboard`` to ``/dashboard/``. For
    form auth a 3xx whose ``Location`` is in scope and is not the login path
    is followed for exactly one hop, and the destination is evaluated with the
    rules above (the anonymous control then targets the destination). A
    missing, off-origin or login-path ``Location`` is rejected as before.
    """
    # Form auth used to short-circuit here and return success unverified, so
    # the anonymous-control-delta check below — the only thing that actually
    # proves the session is authenticated — never ran for it. Combined with
    # form-login success being inferred from cookie presence, that left form
    # auth with no verification at all. It now takes the same path as every
    # other auth type; when no probe path is configured the function still
    # returns early below, so this only adds verification where it is possible.
    probe_path = self._authenticated_probe_path()
    if not probe_path:
      return True, False
    method = self._authenticated_probe_method().lower()
    probe_url = self.target_url + probe_path
    try:
      req = getattr(session, method, session.get)
      resp = req(probe_url, timeout=10, allow_redirects=False)
    except requests.RequestException:
      self._record_auth_diagnostic(
        "authenticated_probe_transport", error="transport_error",
      )
      return False, True
    status = getattr(resp, "status_code", None)
    if (status is not None and 300 <= status < 400
        and self._resolve_auth_type() == "form"):
      hop_url = self._form_redirect_hop_url(resp, probe_url)
      if hop_url:
        # 301/302/303 become GET (HEAD stays HEAD), as the client's own
        # redirect loop and browsers do; only 307/308 keep the method. The
        # anonymous control below then uses the hop's method too.
        if status in (301, 302, 303) and method != "head":
          method = "get"
          req = session.get
        try:
          resp = req(hop_url, timeout=10, allow_redirects=False)
        except GrayboxScopeError:
          self._record_auth_diagnostic("authenticated_probe_redirect", resp)
          return False, False
        except requests.RequestException:
          self._record_auth_diagnostic(
            "authenticated_probe_transport", error="transport_error",
          )
          return False, True
        probe_url = hop_url
        status = getattr(resp, "status_code", None)
    if status is None:
      self._record_auth_diagnostic("authenticated_probe_missing_status", resp)
      return False, False
    # Reject redirects (commonly mask invalid tokens) and explicit
    # authentication failures.
    if 300 <= status < 400:
      self._record_auth_diagnostic("authenticated_probe_redirect", resp)
      return False, False
    if status in (401, 403):
      self._record_auth_diagnostic("authenticated_probe_rejected", resp)
      return False, False
    if status >= 400:
      self._record_auth_diagnostic("authenticated_probe_error", resp)
      return False, False

    success_statuses = self._configured_success_statuses()
    if success_statuses and status not in success_statuses:
      self._record_auth_diagnostic("authenticated_probe_unexpected_status", resp)
      return False, False

    marker = self._configured_success_marker()
    identity_path = self._configured_identity_json_path()
    requires_assertion = bool(marker or identity_path)

    auth_body = self._read_response_body(resp)
    auth_json = self._read_response_json(resp, auth_body)

    if requires_assertion:
      if marker and marker not in auth_body:
        self._record_auth_diagnostic("authenticated_probe_marker_missing", resp)
        return False, False
      if identity_path:
        value = self._traverse_identity_path(auth_json, identity_path)
        if not value:
          self._record_auth_diagnostic("authenticated_probe_identity_missing", resp)
          return False, False

    control = self._anonymous_control_response(method.upper(), probe_url)
    control_status = getattr(control, "status_code", None) if control is not None else None
    control_is_success = (
      control_status is not None and 200 <= control_status < 300
    )

    if not control_is_success:
      # Anonymous request was rejected (or transport failed) — the
      # authenticated 2xx is a meaningful delta. Accept without
      # requiring a marker.
      return True, False

    # Anonymous request also got 2xx. The endpoint may be public; we
    # need an assertion that distinguishes the two responses.
    if not requires_assertion:
      self._record_auth_diagnostic("authenticated_probe_public_control", resp)
      return False, False
    control_body = self._read_response_body(control)
    control_json = self._read_response_json(control, control_body)
    if marker and marker in control_body:
      return False, False
    if identity_path:
      anon_value = self._traverse_identity_path(control_json, identity_path)
      if anon_value:
        return False, False
    return True, False

  def _form_redirect_hop_url(self, resp, probe_url: str) -> str:
    """Absolute URL of the one hop to follow for a form-auth 3xx, or "".

    Empty means reject: no ``Location``, an unparsable one, a different
    origin than the target (the client's own origin rule), or a destination
    on the configured login or logout path (query ignored; following a
    logout hop would end the session it is checking).
    """
    headers = getattr(resp, "headers", None) or {}
    location = headers.get("Location") or headers.get("location") or ""
    if not isinstance(location, str) or not location.strip():
      return ""
    try:
      dest = normalize_request_url(
        self.target_url, urljoin(probe_url, location.strip()))
    except (GrayboxScopeError, ValueError):
      return ""
    dest_path = urlparse(dest).path.rstrip("/")
    for attr in ("login_path", "logout_path"):
      path = getattr(self.target_config, attr, "") or ""
      if path and dest_path == urlparse(self.target_url + path).path.rstrip("/"):
        return ""
    return dest

  @staticmethod
  def _read_response_body(resp) -> str:
    if resp is None:
      return ""
    text = getattr(resp, "text", None)
    if isinstance(text, str):
      return text
    content = getattr(resp, "content", b"") or b""
    if isinstance(content, (bytes, bytearray)):
      try:
        return content.decode("utf-8", errors="replace")
      except Exception:
        return ""
    return str(content)

  @staticmethod
  def _read_response_json(resp, body_text: str):
    if resp is None:
      return None
    json_fn = getattr(resp, "json", None)
    if callable(json_fn):
      try:
        return json_fn()
      except Exception:
        pass
    if not body_text:
      return None
    try:
      import json as _json
      return _json.loads(body_text)
    except Exception:
      return None

  def _resolve_auth_type(self) -> str:
    """Return the configured auth_type, defaulting to ``form``.

    Targets that don't populate ``target_config.api_security.auth``
    (everything pre-API-Top-10) keep ``form`` and behave identically
    to before the refactor.
    """
    api_security = getattr(self.target_config, "api_security", None)
    if api_security is None:
      return "form"
    auth_desc = getattr(api_security, "auth", None)
    if auth_desc is None:
      return "form"
    return getattr(auth_desc, "auth_type", "form") or "form"

  def _build_strategy(self):
    """Construct the auth strategy for this manager based on auth_type.

    ``form``   → FormAuth (existing form-login)
    ``bearer`` → BearerAuth (Subphase 1.5 commit #6)
    ``api_key``→ ApiKeyAuth (Subphase 1.5 commit #7)
    ``basic``  → BasicAuth
    """
    auth_type = self._resolve_auth_type()
    if auth_type == "form":
      return FormAuth(self.target_url, self.target_config, self.verify_tls,
                      self.http_client, self._login_target)
    if auth_type == "basic":
      return BasicAuth(self.target_url, self.target_config, self.verify_tls, self.http_client)
    if auth_type == "bearer":
      return BearerAuth(self.target_url, self.target_config, self.verify_tls, self.http_client)
    if auth_type == "api_key":
      return ApiKeyAuth(self.target_url, self.target_config, self.verify_tls, self.http_client)
    raise ValueError(f"Unknown auth_type: {auth_type!r}")

  # Form-login internals (``_is_login_success``, ``_extract_csrf``,
  # ``_find_csrf_value``) moved into ``auth_strategies.FormAuth`` in
  # Subphase 1.5 commit #3. ``extract_csrf_value`` remains a public
  # static helper so existing probe-side callers keep working.

  @staticmethod
  def extract_csrf_value(html, field_name):
    """
    Public API for CSRF value extraction from HTML.

    Used by probes that need to include CSRF tokens in form submissions.
    """
    return FormAuth._find_csrf_value(html, field_name)
