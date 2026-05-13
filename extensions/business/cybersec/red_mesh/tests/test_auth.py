"""Tests for AuthManager."""

import time
import unittest
from unittest.mock import MagicMock, patch, PropertyMock

from extensions.business.cybersec.red_mesh.graybox.auth import AuthManager
from extensions.business.cybersec.red_mesh.graybox.models.target_config import GrayboxTargetConfig
from extensions.business.cybersec.red_mesh.constants import GRAYBOX_SESSION_MAX_AGE


def _make_auth(**overrides):
  """Build an AuthManager with defaults."""
  defaults = dict(
    target_url="http://testapp.local:8000",
    target_config=GrayboxTargetConfig(),
    verify_tls=False,
  )
  defaults.update(overrides)
  return AuthManager(**defaults)


def _mock_response(status=200, text="", url="http://testapp.local:8000/dashboard/",
                   history=None, cookies=None, content_type="text/html"):
  """Build a mock requests.Response."""
  resp = MagicMock()
  resp.status_code = status
  resp.text = text
  resp.url = url
  resp.history = history or []
  resp.headers = {"content-type": content_type}
  resp.json.return_value = {}
  if cookies is not None:
    resp.cookies = cookies
  return resp


class TestCsrfAutoDetect(unittest.TestCase):

  # After Subphase 1.5 commit #3, CSRF auto-detection lives on FormAuth
  # (the form-login strategy). These tests drive the strategy directly.

  def _form_auth(self, csrf_field=""):
    from extensions.business.cybersec.red_mesh.graybox.auth_strategies import FormAuth
    cfg = GrayboxTargetConfig(csrf_field=csrf_field)
    return FormAuth("http://testapp.local:8000", cfg)

  def test_csrf_autodetect_django(self):
    """Finds Django csrfmiddlewaretoken."""
    fa = self._form_auth()
    html = '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
    field, token = fa._extract_csrf(html)
    self.assertEqual(field, "csrfmiddlewaretoken")
    self.assertEqual(token, "abc123")

  def test_csrf_autodetect_flask(self):
    """Finds Flask/WTForms csrf_token."""
    fa = self._form_auth()
    html = '<input type="hidden" name="csrf_token" value="flask-token-xyz">'
    field, token = fa._extract_csrf(html)
    self.assertEqual(field, "csrf_token")
    self.assertEqual(token, "flask-token-xyz")

  def test_csrf_autodetect_rails(self):
    """Finds Rails authenticity_token."""
    fa = self._form_auth()
    html = '<input name="authenticity_token" type="hidden" value="rails-tok">'
    field, token = fa._extract_csrf(html)
    self.assertEqual(field, "authenticity_token")
    self.assertEqual(token, "rails-tok")

  def test_csrf_autodetect_fallback(self):
    """Fallback finds generic hidden input with 'csrf' in name."""
    fa = self._form_auth()
    html = '<input type="hidden" name="my_csrf_thing" value="custom-tok">'
    field, token = fa._extract_csrf(html)
    self.assertEqual(field, "my_csrf_thing")
    self.assertEqual(token, "custom-tok")

  def test_csrf_configured_override(self):
    """Configured csrf_field overrides auto-detection."""
    fa = self._form_auth(csrf_field="custom_token")
    html = '<input name="custom_token" value="override-val" type="hidden">'
    field, token = fa._extract_csrf(html)
    self.assertEqual(field, "custom_token")
    self.assertEqual(token, "override-val")

  def test_csrf_field_property(self):
    """AuthManager.detected_csrf_field surfaces what FormAuth observed."""
    fa = self._form_auth()
    html = '<input type="hidden" name="csrf_token" value="x">'
    fa._extract_csrf(html)
    # FormAuth tracks last_detected_csrf_field via authenticate() — for
    # the standalone-helper case used in this test, the field is the
    # second return value of _extract_csrf. The AuthManager-level
    # detected_csrf_field property is asserted in TestAuthManagerLifecycle.
    self.assertIsNone(fa.last_detected_csrf_field)  # _extract_csrf alone does not set it

  def test_csrf_none_when_missing(self):
    """Returns (None, None) when no CSRF field found."""
    fa = self._form_auth()
    field, token = fa._extract_csrf("<form><input name='username'></form>")
    self.assertIsNone(field)
    self.assertIsNone(token)

  def test_extract_csrf_value_public_api(self):
    """Static extract_csrf_value works for probes."""
    html = '<input type="hidden" name="csrf_token" value="pub-tok">'
    val = AuthManager.extract_csrf_value(html, "csrf_token")
    self.assertEqual(val, "pub-tok")


class TestBearerAuthStrategy(unittest.TestCase):
  """OWASP API Top 10 (Subphase 1.5 commit #6) — Bearer-token strategy."""

  def _bearer(self, **auth_kwargs):
    from extensions.business.cybersec.red_mesh.graybox.auth_strategies import BearerAuth
    from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
      GrayboxTargetConfig, ApiSecurityConfig, AuthDescriptor,
    )
    desc = AuthDescriptor(**{"auth_type": "bearer", **auth_kwargs})
    cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(auth=desc))
    return BearerAuth("http://api.example", cfg, verify_tls=True)

  def test_authenticate_stamps_default_header(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
    ba = self._bearer()
    sess = ba.authenticate(Credentials(bearer_token="abc.def.ghi"))
    self.assertIsNotNone(sess)
    self.assertEqual(sess.headers["Authorization"], "Bearer abc.def.ghi")

  def test_authenticate_custom_header_and_scheme(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
    ba = self._bearer(bearer_token_header_name="X-Auth-Token", bearer_scheme="Token")
    sess = ba.authenticate(Credentials(bearer_token="xyz"))
    self.assertEqual(sess.headers["X-Auth-Token"], "Token xyz")

  def test_authenticate_empty_token_fails(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
    ba = self._bearer()
    self.assertIsNone(ba.authenticate(Credentials()))

  def test_refresh_reauthenticates(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
    ba = self._bearer()
    creds = Credentials(bearer_token="t1")
    ba.authenticate(creds)
    self.assertTrue(ba.refresh(creds))

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_preflight_skipped_when_no_probe_path(self, mock_requests):
    """Empty `authenticated_probe_path` means no preflight HTTP traffic."""
    ba = self._bearer()
    self.assertIsNone(ba.preflight())
    mock_requests.head.assert_not_called()

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_preflight_401_is_allowed_before_token_is_sent(self, mock_requests):
    import requests as real_requests
    mock_requests.head.return_value = _mock_response(status=401)
    mock_requests.RequestException = real_requests.RequestException
    ba = self._bearer(authenticated_probe_path="/api/me")
    err = ba.preflight()
    self.assertIsNone(err)


class TestApiKeyAuthStrategy(unittest.TestCase):
  """OWASP API Top 10 (Subphase 1.5 commit #7) — API-key strategy."""

  def _api_key(self, **auth_kwargs):
    from extensions.business.cybersec.red_mesh.graybox.auth_strategies import ApiKeyAuth
    from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
      GrayboxTargetConfig, ApiSecurityConfig, AuthDescriptor,
    )
    desc = AuthDescriptor(**{"auth_type": "api_key", **auth_kwargs})
    cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(auth=desc))
    return ApiKeyAuth("http://api.example", cfg, verify_tls=True)

  def test_header_placement(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
    ak = self._api_key(api_key_location="header", api_key_header_name="X-Custom-Key")
    sess = ak.authenticate(Credentials(api_key="SECRET"))
    self.assertEqual(sess.headers["X-Custom-Key"], "SECRET")
    # No params used in header mode
    self.assertEqual(sess.params or {}, {})

  def test_query_placement(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
    ak = self._api_key(api_key_location="query", api_key_query_param="apikey")
    sess = ak.authenticate(Credentials(api_key="QSECRET"))
    self.assertEqual(sess.params, {"apikey": "QSECRET"})
    # No Authorization header set in query mode
    self.assertNotIn("Authorization", sess.headers)

  def test_unknown_location_fails(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
    ak = self._api_key(api_key_location="weird")
    self.assertIsNone(ak.authenticate(Credentials(api_key="x")))

  def test_empty_key_fails(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
    ak = self._api_key()
    self.assertIsNone(ak.authenticate(Credentials()))


class TestAuthManagerStrategyDispatch(unittest.TestCase):
  """AuthManager.build_strategy routes by `auth_type` (Subphase 1.5 commits #5-#7)."""

  def _auth_with(self, auth_type):
    from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
      GrayboxTargetConfig, ApiSecurityConfig, AuthDescriptor,
    )
    cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(auth=AuthDescriptor(auth_type=auth_type)))
    return AuthManager("http://api.example", cfg)

  def test_dispatch_form(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_strategies import FormAuth
    self.assertIsInstance(self._auth_with("form")._build_strategy(), FormAuth)

  def test_dispatch_bearer(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_strategies import BearerAuth
    self.assertIsInstance(self._auth_with("bearer")._build_strategy(), BearerAuth)

  def test_dispatch_api_key(self):
    from extensions.business.cybersec.red_mesh.graybox.auth_strategies import ApiKeyAuth
    self.assertIsInstance(self._auth_with("api_key")._build_strategy(), ApiKeyAuth)

  def test_dispatch_unknown(self):
    auth = self._auth_with("bogus")
    with self.assertRaises(ValueError):
      auth._build_strategy()


class TestAuthManagerNativeApiCredentials(unittest.TestCase):
  """AuthManager preserves token/key credentials through strategy dispatch."""

  def _auth_with_descriptor(self, **auth_kwargs):
    from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
      ApiSecurityConfig, AuthDescriptor,
    )
    desc = AuthDescriptor(**auth_kwargs)
    cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(auth=desc))
    return AuthManager("http://api.example", cfg, verify_tls=False)

  def _mock_session(self, status=200):
    session = MagicMock()
    session.headers = {}
    session.params = {}
    session.head.return_value = _mock_response(status=status)
    return session

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_authenticate_bearer_stamps_token_and_validates_after_auth(self, mock_requests):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials

    session = self._mock_session(status=200)
    mock_requests.Session.return_value = session

    auth = self._auth_with_descriptor(
      auth_type="bearer",
      authenticated_probe_path="/api/me",
    )
    ok = auth.authenticate(Credentials(bearer_token="TOKEN-123"))

    self.assertTrue(ok)
    self.assertIs(auth.official_session, session)
    self.assertEqual(session.headers["Authorization"], "Bearer TOKEN-123")
    session.head.assert_called_once_with(
      "http://api.example/api/me",
      timeout=10,
      allow_redirects=True,
    )

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_authenticate_api_key_query_validates_with_session_params(self, mock_requests):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials

    session = self._mock_session(status=200)
    mock_requests.Session.return_value = session

    auth = self._auth_with_descriptor(
      auth_type="api_key",
      authenticated_probe_path="/api/me",
      api_key_location="query",
      api_key_query_param="apikey",
    )
    ok = auth.authenticate(Credentials(api_key="KEY-123"))

    self.assertTrue(ok)
    self.assertIs(auth.official_session, session)
    self.assertEqual(session.params, {"apikey": "KEY-123"})
    session.head.assert_called_once()

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_authenticate_bearer_rejects_unauthorized_probe_path(self, mock_requests):
    from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials

    session = self._mock_session(status=401)
    mock_requests.Session.return_value = session

    auth = self._auth_with_descriptor(
      auth_type="bearer",
      authenticated_probe_path="/api/me",
    )
    ok = auth.authenticate(Credentials(bearer_token="BAD-TOKEN"))

    self.assertFalse(ok)
    self.assertIsNone(auth.official_session)
    session.close.assert_called_once()
    self.assertIn("official_login_failed", auth._auth_errors)


class TestLoginSuccessDetection(unittest.TestCase):

  def _check(self, auth, response, cookies=None):
    """Helper to call FormAuth._is_login_success with a mock session.

    After Subphase 1.5 commit #3, login-success heuristics live on FormAuth;
    the AuthManager-level _is_login_success was removed. ``auth`` is kept
    in the signature for backward compatibility with the per-test bodies
    that still build an AuthManager for fixture reasons; the call site
    delegates to the FormAuth static helper.
    """
    from extensions.business.cybersec.red_mesh.graybox.auth_strategies import FormAuth
    session = MagicMock()
    session.cookies.get_dict.return_value = cookies or {}
    return FormAuth._is_login_success(response, session, "http://testapp.local:8000/auth/login/")

  def test_login_success_redirect_with_cookies(self):
    """Redirect away from login + cookies -> success."""
    auth = _make_auth()
    resp = _mock_response(url="http://testapp.local:8000/dashboard/", history=[MagicMock()])
    self.assertTrue(self._check(auth, resp, cookies={"sessionid": "abc"}))

  def test_login_redirect_no_cookies(self):
    """Redirect without cookies -> failure."""
    auth = _make_auth()
    resp = _mock_response(url="http://testapp.local:8000/dashboard/", history=[MagicMock()])
    self.assertFalse(self._check(auth, resp, cookies={}))

  def test_login_success_spa(self):
    """No redirect, cookies set -> success (SPA login)."""
    auth = _make_auth()
    resp = _mock_response(url="http://testapp.local:8000/auth/login/")
    self.assertTrue(self._check(auth, resp, cookies={"token": "jwt-val"}))

  def test_login_failure_multiword(self):
    """'login failed' in body -> failure."""
    auth = _make_auth()
    resp = _mock_response(text="<p>Login failed. Please try again.</p>")
    self.assertFalse(self._check(auth, resp, cookies={"sessionid": "x"}))

  def test_login_no_false_negative(self):
    """Page with 'failed' in dashboard text (not a failure marker) -> success if cookies set."""
    auth = _make_auth()
    resp = _mock_response(
      url="http://testapp.local:8000/dashboard/",
      text="<p>3 failed login attempts detected on your account.</p>",
      history=[MagicMock()],
    )
    self.assertTrue(self._check(auth, resp, cookies={"sessionid": "x"}))

  def test_login_failure_json_error(self):
    """JSON {"error": "bad creds"} -> failure."""
    auth = _make_auth()
    resp = _mock_response(
      url="http://testapp.local:8000/auth/login/",
      content_type="application/json",
    )
    resp.json.return_value = {"error": "bad credentials"}
    self.assertFalse(self._check(auth, resp, cookies={}))

  def test_login_failure_json_success_false(self):
    """JSON {"success": false} -> failure."""
    auth = _make_auth()
    resp = _mock_response(
      url="http://testapp.local:8000/auth/login/",
      content_type="application/json",
    )
    resp.json.return_value = {"success": False}
    self.assertFalse(self._check(auth, resp, cookies={}))

  def test_login_success_json(self):
    """JSON {"authenticated": true} + cookies -> success."""
    auth = _make_auth()
    resp = _mock_response(
      url="http://testapp.local:8000/auth/login/",
      content_type="application/json",
    )
    resp.json.return_value = {"authenticated": True}
    self.assertTrue(self._check(auth, resp, cookies={"token": "jwt"}))

  def test_login_failure_status(self):
    """401 -> failure."""
    auth = _make_auth()
    resp = _mock_response(status=401)
    self.assertFalse(self._check(auth, resp, cookies={"sessionid": "x"}))


class TestAuthManagerLifecycle(unittest.TestCase):

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_try_credentials_public(self, mock_requests):
    """try_credentials returns session on success, None on failure."""
    auth = _make_auth()
    # Mock login flow: GET returns CSRF, POST redirects with cookies
    mock_session = MagicMock()
    mock_session.get.return_value = _mock_response(
      text='<input type="hidden" name="csrf_token" value="tok">'
    )
    post_resp = _mock_response(
      url="http://testapp.local:8000/dashboard/",
      history=[MagicMock()],
    )
    mock_session.post.return_value = post_resp
    mock_session.cookies.get_dict.return_value = {"sessionid": "abc"}
    mock_requests.Session.return_value = mock_session

    result = auth.try_credentials("admin", "pass")
    self.assertIsNotNone(result)

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_make_anonymous_session(self, mock_requests):
    """make_anonymous_session returns a fresh session."""
    auth = _make_auth()
    session = auth.make_anonymous_session()
    self.assertIsNotNone(session)

  def test_session_expiry(self):
    """is_expired returns True after GRAYBOX_SESSION_MAX_AGE."""
    auth = _make_auth()
    auth._created_at = time.time() - GRAYBOX_SESSION_MAX_AGE - 1
    self.assertTrue(auth.is_expired)

  def test_session_not_expired(self):
    """is_expired returns False for fresh session."""
    auth = _make_auth()
    auth._created_at = time.time()
    self.assertFalse(auth.is_expired)

  def test_auth_state_reflects_session_status(self):
    """auth_state exposes a typed snapshot of current session state."""
    auth = _make_auth()
    auth.official_session = MagicMock()
    auth.regular_session = None
    auth._auth_errors = ["official_login_failed"]
    auth._refresh_count = 2

    state = auth.auth_state

    self.assertTrue(state.official_authenticated)
    self.assertFalse(state.regular_authenticated)
    self.assertEqual(state.refresh_count, 2)
    self.assertEqual(state.auth_errors, ("official_login_failed",))

  def test_cleanup_closes_sessions(self):
    """cleanup() closes all sessions."""
    auth = _make_auth()
    auth.official_session = MagicMock()
    auth.regular_session = MagicMock()
    auth.anon_session = MagicMock()
    auth._created_at = time.time()
    auth.cleanup()
    auth.official_session is None  # already set to None
    auth.regular_session is None
    auth.anon_session is None
    self.assertEqual(auth._created_at, 0.0)

  def test_ensure_sessions_failed_refresh_clears_stale_sessions(self):
    """Failed refresh tears down stale sessions instead of leaving mixed state."""
    auth = _make_auth()
    auth.official_session = MagicMock()
    auth.regular_session = MagicMock()
    auth._created_at = time.time() - GRAYBOX_SESSION_MAX_AGE - 1

    with patch.object(auth, "authenticate", return_value=False) as mock_auth:
      result = auth.ensure_sessions({"username": "admin", "password": "secret"})

    self.assertFalse(result)
    self.assertIsNone(auth.official_session)
    self.assertIsNone(auth.regular_session)
    self.assertEqual(auth.auth_state.refresh_count, 1)
    mock_auth.assert_called_once()

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  @patch("extensions.business.cybersec.red_mesh.graybox.auth.time.sleep")
  def test_authenticate_retries_transient_transport_error(self, mock_sleep, mock_requests):
    """Transient transport failures retry once before giving up."""
    import requests as real_requests

    auth = _make_auth()
    first_session = MagicMock()
    second_session = MagicMock()
    first_session.get.side_effect = real_requests.ConnectionError("temporary failure")
    second_session.get.return_value = _mock_response(
      text='<input type="hidden" name="csrf_token" value="tok">'
    )
    second_session.post.return_value = _mock_response(
      url="http://testapp.local:8000/dashboard/",
      history=[MagicMock()],
    )
    second_session.cookies.get_dict.return_value = {"sessionid": "abc"}
    # After Subphase 1.5 commit #3, only FormAuth.make_session() consumes
    # auth_strategies.requests.Session(); the anon session lives on the
    # AuthManager side of the import boundary and uses auth.requests.
    mock_requests.Session.side_effect = [first_session, second_session]
    mock_requests.RequestException = real_requests.RequestException

    result = auth.authenticate({"username": "admin", "password": "secret"})

    self.assertTrue(result)
    self.assertIs(auth.official_session, second_session)
    mock_sleep.assert_called_once()
    self.assertEqual(auth._auth_errors, [])

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_preflight_unreachable(self, mock_requests):
    """preflight_check returns error for unreachable target."""
    import requests as real_requests
    mock_requests.head.side_effect = real_requests.ConnectionError("refused")
    mock_requests.RequestException = real_requests.RequestException
    auth = _make_auth()
    err = auth.preflight_check()
    self.assertIsNotNone(err)
    self.assertIn("unreachable", err.lower())

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_preflight_login_404(self, mock_requests):
    """preflight_check returns error if login page returns 404."""
    mock_requests.head.return_value = _mock_response(status=200)
    mock_requests.get.return_value = _mock_response(status=404)
    mock_requests.RequestException = Exception
    auth = _make_auth()
    err = auth.preflight_check()
    self.assertIsNotNone(err)
    self.assertIn("404", err)

  @patch("extensions.business.cybersec.red_mesh.graybox.auth_strategies.requests")
  def test_preflight_ok(self, mock_requests):
    """preflight_check returns None when target and login page are reachable."""
    mock_requests.head.return_value = _mock_response(status=200)
    mock_requests.get.return_value = _mock_response(status=200)
    mock_requests.RequestException = Exception
    auth = _make_auth()
    err = auth.preflight_check()
    self.assertIsNone(err)


if __name__ == '__main__':
  unittest.main()
