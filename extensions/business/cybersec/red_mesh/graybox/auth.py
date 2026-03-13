"""
Authentication manager for graybox scanning.

Handles CSRF auto-detection, login with robust success detection,
session expiry, re-auth, and cleanup.
"""

import re
import time

import requests

from ..constants import GRAYBOX_SESSION_MAX_AGE
from .models.target_config import COMMON_CSRF_FIELDS


class AuthManager:
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
    self._auth_errors = []
    self._detected_csrf_field = None

  @property
  def detected_csrf_field(self) -> str | None:
    """Public read access to the auto-detected CSRF field name."""
    return self._detected_csrf_field

  @property
  def is_expired(self) -> bool:
    return time.time() - self._created_at > GRAYBOX_SESSION_MAX_AGE

  def ensure_sessions(self, official_creds, regular_creds=None):
    """Re-authenticate if sessions are stale or not yet created."""
    if self.official_session and not self.is_expired:
      return True
    return self.authenticate(official_creds, regular_creds)

  def authenticate(self, official_creds, regular_creds=None):
    """Create fresh sessions for all configured users."""
    self.anon_session = self._make_session()
    official_creds = self._coerce_creds(official_creds)
    regular_creds = self._coerce_creds(regular_creds)

    self.official_session = self._try_login(
      official_creds["username"],
      official_creds["password"],
    )
    if not self.official_session:
      self._auth_errors.append("official_login_failed")
      return False

    if regular_creds and regular_creds.get("username"):
      self.regular_session = self._try_login(
        regular_creds["username"],
        regular_creds["password"],
      )
      if not self.regular_session:
        self._auth_errors.append("regular_login_failed")

    self._created_at = time.time()
    return True

  @staticmethod
  def _coerce_creds(creds):
    if creds is None:
      return None
    if isinstance(creds, dict):
      return {
        "username": creds.get("username", ""),
        "password": creds.get("password", ""),
      }
    return {
      "username": getattr(creds, "username", "") or "",
      "password": getattr(creds, "password", "") or "",
    }

  def cleanup(self):
    """
    Explicitly close sessions and attempt logout.

    Prevents session accumulation on targets with session limits.
    """
    logout_url = self.target_url + self.target_config.logout_path
    for session in [self.official_session, self.regular_session]:
      if session is None:
        continue
      try:
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

  def preflight_check(self) -> str | None:
    """
    Verify target reachability and login page existence.

    Returns error message if preflight fails, None if OK.
    """
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

  def _try_login(self, username, password):
    """
    Attempt login with CSRF auto-detection and robust success detection.
    """
    session = self._make_session()
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
      self.target_config.username_field: username,
      self.target_config.password_field: password,
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

    # Robust success detection
    if self._is_login_success(resp, session, login_url):
      return session

    session.close()
    return None

  def _is_login_success(self, response, session, login_url):
    """
    Determine if login succeeded.

    Checks (in order):
    1. HTTP error -> fail
    2. Response body contains failure markers -> fail
    3. JSON error responses -> fail
    4. Redirected away from login page AND cookies present -> success
    5. Non-empty session cookies -> success
    """
    if response.status_code >= 400:
      return False

    # Check for failure markers in response body.
    # Use multi-word phrases to avoid false matches — single words like
    # "failed" can appear in legitimate post-login content.
    failure_markers = [
      "invalid credentials", "invalid username", "invalid password",
      "incorrect password", "login failed", "authentication failed",
      "try again", "wrong password", "unable to log in",
      "account locked", "account disabled",
    ]
    body_lower = response.text.lower()
    if any(marker in body_lower for marker in failure_markers):
      return False

    # SPA support: check JSON error responses
    ct = response.headers.get("content-type", "")
    if "application/json" in ct:
      try:
        data = response.json()
        if isinstance(data, dict):
          if data.get("error") or data.get("success") is False or data.get("authenticated") is False:
            return False
      except ValueError:
        pass

    has_cookies = bool(session.cookies.get_dict())

    # Redirect away from login URL — require cookies to confirm
    # session was actually established.
    if response.url and "login" not in response.url.lower():
      if has_cookies:
        return True

    # Redirect chain present and final URL differs AND cookies set
    if response.history and login_url not in response.url:
      if has_cookies:
        return True

    # Has auth-relevant cookies (even without redirect — SPA logins)
    return has_cookies

  def _extract_csrf(self, html):
    """
    Extract CSRF token from HTML.

    If csrf_field is configured, use it directly.
    Otherwise, try common framework field names.
    Returns (field_name, token_value) tuple.
    """
    if self.target_config.csrf_field:
      token = self._find_csrf_value(html, self.target_config.csrf_field)
      return (self.target_config.csrf_field, token)

    # Auto-detect: try common CSRF field names
    if self._detected_csrf_field:
      token = self._find_csrf_value(html, self._detected_csrf_field)
      if token:
        return (self._detected_csrf_field, token)

    for field_name in COMMON_CSRF_FIELDS:
      token = self._find_csrf_value(html, field_name)
      if token:
        self._detected_csrf_field = field_name
        return (field_name, token)

    # Fallback: any hidden input with "csrf" or "token" in name
    m = re.search(
      r'<input[^>]+type=["\']hidden["\'][^>]+name=["\']([^"\']*(?:csrf|token)[^"\']*)["\'][^>]+value=["\']([^"\']+)',
      html or "", re.IGNORECASE,
    )
    if m:
      self._detected_csrf_field = m.group(1)
      return (m.group(1), m.group(2))

    return (None, None)

  @staticmethod
  def extract_csrf_value(html, field_name):
    """
    Public API for CSRF value extraction from HTML.

    Used by probes that need to include CSRF tokens in form submissions.
    """
    return AuthManager._find_csrf_value(html, field_name)

  @staticmethod
  def _find_csrf_value(html, field_name):
    """Find value of a named hidden input field."""
    # Try name->value order
    m = re.search(
      rf'name=["\']?{re.escape(field_name)}["\']?\s[^>]*value=["\']([^"\']+)',
      html or "", re.IGNORECASE,
    )
    if m:
      return m.group(1)
    # Try value->name order (some frameworks emit attrs differently)
    m = re.search(
      rf'value=["\']([^"\']+)["\'][^>]*name=["\']?{re.escape(field_name)}["\']?',
      html or "", re.IGNORECASE,
    )
    return m.group(1) if m else None
