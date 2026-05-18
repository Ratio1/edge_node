"""Tests for MisconfigProbes."""

import base64
import json
import unittest
from unittest.mock import MagicMock, PropertyMock
from http.cookiejar import Cookie

from extensions.business.cybersec.red_mesh.graybox.probes.misconfig import MisconfigProbes
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig, MisconfigConfig, BusinessLogicConfig, WorkflowEndpoint,
  JwtEndpoint,
)


def _mock_response(status=200, text="", headers=None, content_type="text/html"):
  resp = MagicMock()
  resp.status_code = status
  resp.text = text
  h = {"content-type": content_type}
  if headers:
    h.update(headers)
  resp.headers = h
  return resp


def _make_probe(debug_paths=None, workflow_endpoints=None,
                official_session=None, anon_session=None,
                discovered_forms=None, login_path="/auth/login/",
                password_reset_path="", jwt_endpoints=None):
  misconfig = MisconfigConfig(
    debug_paths=debug_paths or ["/debug/"],
    jwt_endpoints=jwt_endpoints or JwtEndpoint(),
  )
  business = BusinessLogicConfig(
    workflow_endpoints=workflow_endpoints or [],
  )
  cfg = GrayboxTargetConfig(
    misconfig=misconfig,
    business_logic=business,
    login_path=login_path,
    password_reset_path=password_reset_path,
  )
  auth = MagicMock()
  auth.official_session = official_session
  auth.anon_session = anon_session or MagicMock()
  auth.detected_csrf_field = None
  auth.extract_csrf_value = MagicMock(return_value=None)
  safety = MagicMock()
  safety.throttle = MagicMock()

  probe = MisconfigProbes(
    target_url="http://testapp.local:8000",
    auth_manager=auth,
    target_config=cfg,
    safety=safety,
    discovered_forms=discovered_forms or [],
  )
  return probe


class TestDebugExposure(unittest.TestCase):

  def test_debug_exposure(self):
    """Debug endpoint returns 200 with body → vulnerable."""
    probe = _make_probe(debug_paths=["/debug/config/"])
    session = probe.auth.anon_session
    session.get.return_value = _mock_response(
      status=200, text="DEBUG_MODE=True SECRET_KEY=xxx" + "x" * 50,
    )

    probe._test_debug_exposure()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)

  def test_debug_not_found(self):
    """Debug endpoint returns 404 → not_vulnerable."""
    probe = _make_probe(debug_paths=["/debug/config/"])
    session = probe.auth.anon_session
    session.get.return_value = _mock_response(status=404, text="Not Found")

    probe._test_debug_exposure()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A02-01" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)


class TestCors(unittest.TestCase):

  def test_cors_wildcard(self):
    """Access-Control-Allow-Origin: * → vulnerable."""
    probe = _make_probe()
    session = probe.auth.anon_session
    session.get.return_value = _mock_response(
      headers={"Access-Control-Allow-Origin": "*"},
    )

    probe._test_cors()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")


class TestSecurityHeaders(unittest.TestCase):

  def test_security_headers_missing(self):
    """Missing X-Frame-Options etc. → vulnerable."""
    probe = _make_probe()
    session = probe.auth.anon_session
    session.get.return_value = _mock_response(headers={})

    probe._test_security_headers()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-03" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertIn("X-Frame-Options", vuln[0].evidence[0])


class TestCookieAttributes(unittest.TestCase):

  def _make_cookie(self, name="sessionid", secure=False, httponly=False, samesite=None):
    cookie = MagicMock()
    cookie.name = name
    cookie.secure = secure
    cookie.has_nonstandard_attr = MagicMock(return_value=httponly)
    cookie.get_nonstandard_attr = MagicMock(return_value=samesite)
    return cookie

  def test_cookie_insecure(self):
    """Missing Secure/HttpOnly → vulnerable."""
    session = MagicMock()
    session.cookies = [self._make_cookie(secure=False, httponly=False)]
    probe = _make_probe(official_session=session)

    probe._test_cookie_attributes()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-04" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)


class TestCsrfBypass(unittest.TestCase):

  def test_csrf_bypass_no_token(self):
    """POST accepted without CSRF → vulnerable."""
    session = MagicMock()
    session.post.return_value = _mock_response(status=200, text="Success")
    probe = _make_probe(
      official_session=session,
      workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
    )

    probe._test_csrf_bypass()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-05" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-352", vuln[0].cwe)

  def test_csrf_bypass_rejected(self):
    """POST rejected (403) → not_vulnerable."""
    session = MagicMock()
    session.post.return_value = _mock_response(status=403, text="CSRF token missing")
    probe = _make_probe(
      official_session=session,
      workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
    )

    probe._test_csrf_bypass()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A02-05" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_csrf_bypass_skips_login(self):
    """Login form is not tested for CSRF."""
    session = MagicMock()
    session.post.return_value = _mock_response(status=200, text="OK")
    probe = _make_probe(
      official_session=session,
      discovered_forms=["/auth/login/", "/profile/edit/"],
      login_path="/auth/login/",
    )

    probe._test_csrf_bypass()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-05" and f.status == "vulnerable"]
    # Only /profile/edit/ should be tested, not /auth/login/
    if vuln:
      for ev in vuln[0].evidence:
        if "endpoints_without_csrf" in ev:
          self.assertNotIn("/auth/login/", ev)


class TestSessionToken(unittest.TestCase):

  def _make_jwt(self, alg="none", payload=None, signature=""):
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload or {}).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.{signature}"

  def test_session_token_jwt_alg_none(self):
    """alg=none JWT → vulnerable."""
    jwt = self._make_jwt(alg="none")
    session = MagicMock()
    session.cookies.get_dict.return_value = {"token": jwt}
    probe = _make_probe(official_session=session)

    probe._test_session_token()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-06" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")

  def test_session_token_short(self):
    """Short session ID → inconclusive."""
    session = MagicMock()
    session.cookies.get_dict.return_value = {"sid": "abc123"}
    probe = _make_probe(official_session=session)

    probe._test_session_token()
    inc = [f for f in probe.findings if f.scenario_id == "PT-A02-06" and f.status == "inconclusive"]
    self.assertEqual(len(inc), 1)
    self.assertEqual(inc[0].severity, "LOW")

  def test_session_token_adequate(self):
    """Normal tokens → not_vulnerable."""
    session = MagicMock()
    session.cookies.get_dict.return_value = {
      "sessionid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    }
    probe = _make_probe(official_session=session)

    probe._test_session_token()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A02-06" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)


class TestSessionFixation(unittest.TestCase):

  def _mock_cookie_jar(self, cookie_dict):
    """Create a mock that behaves like a RequestsCookieJar."""
    jar = MagicMock()
    jar.get_dict.return_value = cookie_dict
    return jar

  def test_session_fixation_detected(self):
    """Same session cookie before and after login → vulnerable/HIGH."""
    probe = _make_probe()

    # Pre-auth session: anon_session returns a cookie
    anon = MagicMock()
    anon.get.return_value = _mock_response(text="Login page")
    anon.cookies = self._mock_cookie_jar({"sessionid": "FIXED_TOKEN_123"})
    anon.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = anon

    # Official session has the same cookie value
    official = MagicMock()
    official.cookies = self._mock_cookie_jar({"sessionid": "FIXED_TOKEN_123"})
    probe.auth.official_session = official

    probe.auth.detected_csrf_field = None

    probe._test_session_fixation()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A07-03" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-384", vuln[0].cwe)

  def test_session_fixation_rotated(self):
    """Different session cookie after login → not_vulnerable."""
    probe = _make_probe()

    anon = MagicMock()
    anon.get.return_value = _mock_response(text="Login page")
    anon.cookies = self._mock_cookie_jar({"sessionid": "PRE_AUTH_TOKEN"})
    anon.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = anon

    official = MagicMock()
    official.cookies = self._mock_cookie_jar({"sessionid": "POST_AUTH_TOKEN"})
    probe.auth.official_session = official

    probe.auth.detected_csrf_field = None

    probe._test_session_fixation()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A07-03" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_session_fixation_no_pre_cookies(self):
    """No pre-auth cookies → skip (can't test)."""
    probe = _make_probe()

    anon = MagicMock()
    anon.get.return_value = _mock_response(text="Login page")
    anon.cookies = self._mock_cookie_jar({})
    anon.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = anon
    probe.auth.official_session = MagicMock()

    probe._test_session_fixation()
    self.assertEqual(len([f for f in probe.findings if f.scenario_id == "PT-A07-03"]), 0)

  def test_session_fixation_ignores_csrf_cookie(self):
    """CSRF token cookie with same value before/after is not a fixation issue."""
    probe = _make_probe()

    anon = MagicMock()
    anon.get.return_value = _mock_response(text="Login page")
    anon.cookies = self._mock_cookie_jar({"csrftoken": "SAME_CSRF", "sessionid": "PRE_AUTH"})
    anon.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = anon

    official = MagicMock()
    official.cookies = self._mock_cookie_jar({"csrftoken": "SAME_CSRF", "sessionid": "POST_AUTH"})
    probe.auth.official_session = official

    probe.auth.detected_csrf_field = "csrfmiddlewaretoken"

    probe._test_session_fixation()
    # csrftoken same is fine; sessionid changed → not_vulnerable
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A07-03" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 0)
    clean = [f for f in probe.findings if f.scenario_id == "PT-A07-03" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)


class TestAccountEnumerationTimingPTA0217(unittest.TestCase):
  """PT-A02-17 — login response timing leak detection."""

  def _make_probe_with_timings(self, known_ms, unknown_ms):
    probe = _make_probe(login_path="/auth/login/")
    probe.regular_username = "alice"

    # Mock make_anonymous_session to return a session whose POST takes a
    # configurable number of milliseconds. A list of times is consumed
    # round-robin: even indices are 'known', odd are 'unknown'.
    timings = list(known_ms) + list(unknown_ms)
    timing_iter = iter(timings)

    def _make_session():
      sess = MagicMock()
      sess.get = MagicMock(return_value=_mock_response(status=200, text=""))
      def _post(*args, **kwargs):
        ms = next(timing_iter)
        import time
        time.sleep(ms / 1000.0)
        return _mock_response(status=200, text="")
      sess.post = MagicMock(side_effect=_post)
      sess.close = MagicMock()
      return sess

    probe.auth.make_anonymous_session = MagicMock(side_effect=_make_session)
    return probe

  def test_pt_a02_17_vulnerable_when_known_user_slower(self):
    # Known user → ~250ms, unknown → ~10ms (clear gap above 100ms threshold)
    probe = self._make_probe_with_timings([250]*6, [10]*6)
    probe._test_account_enumeration_timing()
    f = [x for x in probe.findings if x.scenario_id == "PT-A02-17"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")
    self.assertEqual(f[0].severity, "HIGH")

  def test_pt_a02_17_not_vulnerable_when_timings_match(self):
    # Both groups ~50ms — no enumeration signal
    probe = self._make_probe_with_timings([50]*6, [55]*6)
    probe._test_account_enumeration_timing()
    f = [x for x in probe.findings if x.scenario_id == "PT-A02-17"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")
    self.assertEqual(f[0].severity, "INFO")

  def test_pt_a02_17_silent_when_no_login_path(self):
    probe = _make_probe(login_path="")
    probe._test_account_enumeration_timing()
    self.assertFalse(any(f.scenario_id == "PT-A02-17" for f in probe.findings))


class TestJwtWeakAlgPTA0212(unittest.TestCase):
  """PT-A02-12 — verifier accepts alg=none."""

  def _b64url(self, b: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

  def _make_jwt_hs256(self):
    """Return a fake but well-formed three-segment JWT (signature is bogus)."""
    import json as _json
    h = self._b64url(_json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = self._b64url(_json.dumps({"sub": "alice", "is_admin": False}).encode())
    s = self._b64url(b"\x00" * 32)
    return f"{h}.{p}.{s}"

  def _setup(self, me_response):
    jwt_cfg = JwtEndpoint(
      token_path="/api/token/", protected_path="/api/me/",
      username="alice", password="alice-pass",
    )
    probe = _make_probe(jwt_endpoints=jwt_cfg)
    sess = MagicMock()
    sess.post = MagicMock(return_value=_mock_response(
      status=200, content_type="application/json"
    ))
    sess.post.return_value.json = MagicMock(return_value={
      "access_token": self._make_jwt_hs256(),
    })
    sess.get = MagicMock(return_value=me_response)
    sess.close = MagicMock()
    probe.auth.make_anonymous_session = MagicMock(return_value=sess)
    return probe

  def test_pt_a02_12_vulnerable_when_alg_none_accepted(self):
    me = _mock_response(status=200, content_type="application/json")
    me.json = MagicMock(return_value={"username": "alice", "is_admin": True, "alg": "none"})
    probe = self._setup(me)
    probe._test_jwt_weak_alg()
    f = [x for x in probe.findings if x.scenario_id == "PT-A02-12"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")
    self.assertEqual(f[0].severity, "HIGH")

  def test_pt_a02_12_not_vulnerable_when_alg_none_rejected(self):
    me = _mock_response(status=401, content_type="application/json")
    me.json = MagicMock(return_value={"error": "invalid_token"})
    probe = self._setup(me)
    probe._test_jwt_weak_alg()
    f = [x for x in probe.findings if x.scenario_id == "PT-A02-12"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")

  def test_pt_a02_12_silent_when_jwt_endpoints_unconfigured(self):
    probe = _make_probe(jwt_endpoints=JwtEndpoint())
    probe._test_jwt_weak_alg()
    self.assertFalse(any(f.scenario_id == "PT-A02-12" for f in probe.findings))

  def test_pt_a02_12_inconclusive_when_password_missing(self):
    jwt_cfg = JwtEndpoint(token_path="/api/token/", protected_path="/api/me/",
                          username="alice", password="")
    probe = _make_probe(jwt_endpoints=jwt_cfg)
    probe._test_jwt_weak_alg()
    f = [x for x in probe.findings if x.scenario_id == "PT-A02-12"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "inconclusive")


class TestPasswordResetTokenReusePTA0218(unittest.TestCase):
  """PT-A02-18 — token-not-invalidated detection via two-issue identity check."""

  def _make_session(self, post_responses):
    sess = MagicMock()
    sess.get = MagicMock(return_value=_mock_response(status=200, text=""))
    sess.post = MagicMock(side_effect=post_responses)
    sess.close = MagicMock()
    return sess

  def test_pt_a02_18_vulnerable_when_tokens_identical(self):
    probe = _make_probe(password_reset_path="/auth/password-reset/request/")
    sess = self._make_session([
      _mock_response(status=200, text="<code>reset-admin</code>"),
      _mock_response(status=200, text="<code>reset-admin</code>"),
    ])
    probe.auth.make_anonymous_session = MagicMock(return_value=sess)

    probe._test_password_reset_token_reuse()

    f = [x for x in probe.findings if x.scenario_id == "PT-A02-18"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")
    self.assertEqual(f[0].severity, "HIGH")
    self.assertTrue(any("tokens_identical=True" in e for e in f[0].evidence))

  def test_pt_a02_18_not_vulnerable_when_tokens_differ(self):
    probe = _make_probe(password_reset_path="/auth/password-reset/request/")
    sess = self._make_session([
      _mock_response(status=200, text="<code>reset-abcd1234efgh5678</code>"),
      _mock_response(status=200, text="<code>reset-zyxw9876vutsrqpo</code>"),
    ])
    probe.auth.make_anonymous_session = MagicMock(return_value=sess)

    probe._test_password_reset_token_reuse()

    f = [x for x in probe.findings if x.scenario_id == "PT-A02-18"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")
    self.assertEqual(f[0].severity, "INFO")

  def test_pt_a02_18_inconclusive_when_token_not_extractable(self):
    probe = _make_probe(password_reset_path="/auth/password-reset/request/")
    sess = self._make_session([
      _mock_response(status=200, text="<p>reset email sent</p>"),
      _mock_response(status=200, text="<p>reset email sent</p>"),
    ])
    probe.auth.make_anonymous_session = MagicMock(return_value=sess)

    probe._test_password_reset_token_reuse()

    f = [x for x in probe.findings if x.scenario_id == "PT-A02-18"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "inconclusive")
    self.assertEqual(f[0].severity, "INFO")

  def test_pt_a02_18_silent_when_no_reset_path(self):
    probe = _make_probe(password_reset_path="")
    probe._test_password_reset_token_reuse()
    self.assertFalse(any(f.scenario_id == "PT-A02-18" for f in probe.findings))


class TestAccountEnumeration(unittest.TestCase):

  def test_account_enumeration_detected(self):
    """Different error messages for valid/invalid username → vulnerable."""
    probe = _make_probe()
    probe.regular_username = "admin"

    session = MagicMock()
    session.get.return_value = _mock_response(text='<form><input name="username"></form>')
    session.close = MagicMock()

    call_count = [0]
    def mock_post(url, **kwargs):
      call_count[0] += 1
      data = kwargs.get("data", {})
      username = data.get("username", "")
      if username == "admin":
        return _mock_response(
          text='<div class="error">Invalid password for this account</div>',
        )
      else:
        return _mock_response(
          text='<div class="error">No account found with that username</div>',
        )

    session.post = MagicMock(side_effect=mock_post)
    probe.auth.make_anonymous_session.return_value = session
    probe.auth.detected_csrf_field = None
    probe.auth.extract_csrf_value = MagicMock(return_value=None)

    probe._test_account_enumeration()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A07-04" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")
    self.assertIn("CWE-204", vuln[0].cwe)

  def test_account_enumeration_consistent(self):
    """Same error messages → not_vulnerable."""
    probe = _make_probe()
    probe.regular_username = "admin"

    session = MagicMock()
    session.get.return_value = _mock_response(text='<form><input name="username"></form>')
    session.post.return_value = _mock_response(
      text='<div class="error">Invalid credentials</div>',
    )
    session.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = session
    probe.auth.detected_csrf_field = None
    probe.auth.extract_csrf_value = MagicMock(return_value=None)

    probe._test_account_enumeration()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A07-04" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_account_enumeration_status_code_diff(self):
    """Different status codes for valid/invalid → vulnerable."""
    probe = _make_probe()
    probe.regular_username = "admin"

    session = MagicMock()
    session.get.return_value = _mock_response(text='<form><input name="username"></form>')
    session.close = MagicMock()

    call_count = [0]
    def mock_post(url, **kwargs):
      call_count[0] += 1
      data = kwargs.get("data", {})
      if data.get("username") == "admin":
        return _mock_response(status=200, text="Wrong password")
      return _mock_response(status=302, text="Redirect")

    session.post = MagicMock(side_effect=mock_post)
    probe.auth.make_anonymous_session.return_value = session
    probe.auth.detected_csrf_field = None
    probe.auth.extract_csrf_value = MagicMock(return_value=None)

    probe._test_account_enumeration()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A07-04" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)


class TestCapabilities(unittest.TestCase):

  def test_capabilities(self):
    """MisconfigProbes declares correct capabilities."""
    self.assertFalse(MisconfigProbes.requires_auth)
    self.assertFalse(MisconfigProbes.requires_regular_session)
    self.assertFalse(MisconfigProbes.is_stateful)

  def test_all_findings_are_graybox(self):
    """All findings are GrayboxFinding instances."""
    probe = _make_probe(debug_paths=["/debug/"])
    probe.auth.anon_session.get.return_value = _mock_response(status=404, text="x")
    probe._test_debug_exposure()
    for f in probe.findings:
      self.assertIsInstance(f, GrayboxFinding)


if __name__ == '__main__':
  unittest.main()
