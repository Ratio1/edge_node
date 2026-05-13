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

import re
import time

import requests

from ..constants import GRAYBOX_SESSION_MAX_AGE
from .auth_credentials import Credentials
from .auth_strategies import ApiKeyAuth, BearerAuth, FormAuth
from .models.target_config import COMMON_CSRF_FIELDS
from .models import GrayboxAuthState


class AuthManager:
  MAX_AUTH_ATTEMPTS = 2
  AUTH_RETRY_DELAY_SECONDS = 0.25

  """
  Manages authenticated HTTP sessions for graybox probes.

  Handles CSRF auto-detection, login with robust success detection,
  session expiry, re-auth, and cleanup.
  """

  def __init__(self, target_url, target_config, verify_tls=True):
    self.target_url = target_url.rstrip("/")
    self.target_config = target_config
    self.verify_tls = verify_tls

    self.anon_session = None
    self.official_session = None
    self.regular_session = None
    self._created_at = 0.0
    self._refresh_count = 0
    self._auth_errors = []
    self._detected_csrf_field = None

  @property
  def detected_csrf_field(self) -> str | None:
    """Public read access to the auto-detected CSRF field name."""
    return self._detected_csrf_field

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
    if self.official_session is None:
      return True
    if require_regular and self.regular_session is None:
      return True
    return False

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

    self.official_session = self._try_login_with_retry(
      "official",
      official_creds,
    )
    if not self.official_session:
      return False

    if self._credentials_configured(regular_creds):
      self.regular_session = self._try_login_with_retry(
        "regular",
        regular_creds,
      )
      if not self.regular_session:
        self._record_auth_error("regular_login_failed")

    self._created_at = time.time()
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
    for session in [self.official_session, self.regular_session]:
      if session is None:
        continue
      try:
        if logout_url:
          session.get(logout_url, timeout=5)
      except requests.RequestException:
        pass
      finally:
        session.close()
    if self.anon_session:
      self.anon_session.close()
    self.official_session = None
    self.regular_session = None
    self.anon_session = None
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

  def _record_auth_error(self, code):
    self._auth_errors.append(code)

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
      return None, True
    # Always propagate whatever CSRF field the strategy saw, regardless
    # of whether the credential check ultimately succeeded.
    if strategy.last_detected_csrf_field:
      self._detected_csrf_field = strategy.last_detected_csrf_field
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
    return method if method in ("GET", "POST", "HEAD", "OPTIONS") else "GET"

  def _logout_url_for_current_auth(self) -> str:
    if self._resolve_auth_type() == "form":
      path = getattr(self.target_config, "logout_path", "") or ""
    else:
      api_security = getattr(self.target_config, "api_security", None)
      auth_desc = getattr(api_security, "auth", None) if api_security is not None else None
      path = getattr(auth_desc, "api_logout_path", "") or ""
    return self.target_url + path if path else ""

  def _validate_authenticated_session(self, session) -> tuple[bool, bool]:
    """Validate token/key sessions after credentials have been attached.

    Bearer/API-key preflight intentionally runs without secret material, so
    401/403 at that stage only proves the endpoint is protected. This check
    runs after strategy.authenticate() stamps the session, and treats 401/403
    as an authentication failure.
    """
    if self._resolve_auth_type() == "form":
      return True, False
    probe_path = self._authenticated_probe_path()
    if not probe_path:
      return True, False
    try:
      method = self._authenticated_probe_method().lower()
      req = getattr(session, method, session.get)
      resp = req(self.target_url + probe_path, timeout=10, allow_redirects=True)
    except requests.RequestException:
      return False, True
    status = getattr(resp, "status_code", None)
    if status is None or status >= 400:
      return False, False
    return True, False

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
    """
    auth_type = self._resolve_auth_type()
    if auth_type == "form":
      return FormAuth(self.target_url, self.target_config, self.verify_tls)
    if auth_type == "bearer":
      return BearerAuth(self.target_url, self.target_config, self.verify_tls)
    if auth_type == "api_key":
      return ApiKeyAuth(self.target_url, self.target_config, self.verify_tls)
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
