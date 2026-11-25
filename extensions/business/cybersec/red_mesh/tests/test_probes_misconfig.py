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
                primary_session=None, anon_session=None,
                discovered_forms=None, login_path="/auth/login/",
                password_reset_path="", jwt_endpoints=None,
                allow_stateful=False):
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
  auth.primary_session = primary_session
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
    allow_stateful=allow_stateful,
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
    self.assertEqual(vuln[0].severity, "LOW")


  def test_cors_reflected_origin_on_several_paths(self):
    """RM-060: a second reflecting path used to raise NameError and drop the whole finding."""
    probe = _make_probe()
    probe.discovered_routes = ["/api/a/", "/api/b/"]
    session = probe.auth.anon_session
    session.get.return_value = _mock_response(
      headers={"Access-Control-Allow-Origin": "http://evil.example.com",
               "Access-Control-Allow-Credentials": "true"},
    )
    probe._test_cors()
    self.assertGreaterEqual(session.get.call_count, 2)
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")

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
    probe = _make_probe(primary_session=session)

    probe._test_cookie_attributes()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-04" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)


class TestCsrfBypass(unittest.TestCase):

  def test_csrf_bypass_no_token(self):
    """POST accepted without CSRF → vulnerable."""
    session = MagicMock()
    session.get.return_value = _mock_response(status=200, text="form")  # GET baseline
    session.post.return_value = _mock_response(status=200, text="Success")
    probe = _make_probe(
      primary_session=session,
      workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
    )

    probe._test_csrf_bypass()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-05" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-352", vuln[0].cwe)

  def test_csrf_bypass_rejected(self):
    """allow_stateful: baseline POST with a token accepted, tokenless POST rejected (403) → not_vulnerable."""
    session = MagicMock()
    session.post.side_effect = [
      _mock_response(status=200, text="saved"),                  # baseline, valid token
      _mock_response(status=403, text="CSRF token missing"),     # tokenless
    ]
    probe = _make_probe(
      primary_session=session, allow_stateful=True,
      workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
    )

    probe._test_csrf_bypass()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A02-05" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_csrf_without_allow_stateful_baselines_with_a_get_never_a_post(self):
    """No allow_stateful: the baseline is a GET, only the tokenless POST is sent."""
    session = MagicMock()
    session.get.return_value = _mock_response(status=200, text="form")
    session.post.return_value = _mock_response(status=403, text="CSRF token missing")
    probe = _make_probe(
      primary_session=session,
      workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
    )
    probe._test_csrf_bypass()
    self.assertEqual(session.get.call_count, 1)
    self.assertEqual(session.post.call_count, 1)
    self.assertNotIn("X-CSRFToken", session.post.call_args.kwargs["headers"])
    self.assertEqual([f.status for f in probe.findings if f.scenario_id == "PT-A02-05"],
                     ["not_vulnerable"])

  def test_csrf_bare_403_without_token_baseline_is_not_clean(self):
    """No allow_stateful: a reached GET does not prove the user may POST. A
    bare 403 on the tokenless POST may be an authorization denial, so it is
    inconclusive, never not_vulnerable."""
    for admin_context, reason in (("absent", "reason=admin_context_absent"),
                                  ("provided", "reason=endpoint_denied")):
      with self.subTest(admin_context=admin_context):
        session = MagicMock()
        session.get.return_value = _mock_response(status=200, text="form")
        session.post.return_value = _mock_response(status=403, text="Forbidden")
        probe = _make_probe(
          primary_session=session,
          workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
        )
        probe.auth.admin_context = admin_context
        probe._test_csrf_bypass()
        found = [f for f in probe.findings if f.scenario_id == "PT-A02-05"]
        self.assertEqual([f.status for f in found], ["inconclusive"])
        self.assertIn(reason, found[0].evidence)

  def test_csrf_post_only_action_405_baseline_is_decided_by_the_tokenless_post(self):
    for post_status, expected in ((403, "inconclusive"), (200, "vulnerable")):
      with self.subTest(post_status=post_status):
        session = MagicMock()
        session.get.return_value = _mock_response(status=405, text="")
        session.post.return_value = _mock_response(status=post_status, text="x")
        probe = _make_probe(
          primary_session=session,
          workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
        )
        probe._test_csrf_bypass()
        self.assertEqual([f.status for f in probe.findings if f.scenario_id == "PT-A02-05"],
                         [expected])

  def test_csrf_never_posts_to_the_logout_path(self):
    """A POST to logout ends the scan session; trailing slash is normalised."""
    for allow_stateful in (False, True):
      with self.subTest(allow_stateful=allow_stateful):
        session = MagicMock()
        session.get.return_value = _mock_response(status=200, text="form")
        session.post.return_value = _mock_response(status=200, text="ok")
        probe = _make_probe(
          primary_session=session, allow_stateful=allow_stateful,
          discovered_forms=["/auth/logout", "/profile/edit/"],
        )
        probe._test_csrf_bypass()
        posted = [c.args[0] for c in session.post.call_args_list]
        self.assertTrue(posted)
        self.assertFalse(any("logout" in u for u in posted), posted)

  def test_csrf_baseline_denied_is_inconclusive(self):
    """A 403, 404 or login redirect on the baseline proves nothing about CSRF."""
    login = _mock_response(status=200, text="<input name='username'><input type='password' name='p'>")
    login.url = "http://testapp.local:8000/auth/login/?next=/api/transfer/"
    login.history = []
    cases = [
      (stateful, admin, reason, name, resp)
      for stateful in (False, True)
      for admin, reason in (("provided", "endpoint_denied"),
                            ("absent", "admin_context_absent"))
      for name, resp in (("403", _mock_response(status=403, text="Forbidden")),
                         ("404", _mock_response(status=404, text="nf")),
                         ("login", login))
    ]
    for stateful, admin, reason, name, resp in cases:
      with self.subTest(stateful=stateful, admin=admin, denial=name):
        session = MagicMock()
        # The baseline is a POST with allow_stateful, else a GET.
        (session.post if stateful else session.get).return_value = resp
        probe = _make_probe(
          primary_session=session, allow_stateful=stateful,
          workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
        )
        probe.auth.admin_context = admin
        probe._test_csrf_bypass()
        found = [f for f in probe.findings if f.scenario_id == "PT-A02-05"]
        self.assertEqual([f.status for f in found], ["inconclusive"])
        self.assertEqual(found[0].evidence, [f"reason={reason}"])

  def test_csrf_baseline_sends_a_valid_token_first(self):
    session = MagicMock()
    session.get.return_value = _mock_response(status=200, text="form")
    session.post.side_effect = [
      _mock_response(status=200, text="saved"),
      _mock_response(status=403, text="Forbidden"),
    ]
    probe = _make_probe(
      primary_session=session, allow_stateful=True,
      workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
    )
    probe.auth.detected_csrf_field = "csrfmiddlewaretoken"
    probe.auth.extract_csrf_value = MagicMock(return_value="tok123")
    probe._test_csrf_bypass()
    first, second = session.post.call_args_list
    self.assertEqual(first.kwargs["data"]["csrfmiddlewaretoken"], "tok123")
    self.assertNotIn("csrfmiddlewaretoken", second.kwargs["data"])
    self.assertEqual([f.status for f in probe.findings if f.scenario_id == "PT-A02-05"],
                     ["not_vulnerable"])

  def test_csrf_login_redirect_on_tokenless_post_is_not_a_bypass(self):
    """A login redirect on the tokenless POST is a denial, not a CSRF
    rejection: inconclusive, never not_vulnerable."""
    for stateful in (False, True):
      with self.subTest(stateful=stateful):
        session = MagicMock()
        login = _mock_response(status=302, text="")
        login.headers["Location"] = "/auth/login/"
        session.get.return_value = _mock_response(status=200, text="form")
        # With allow_stateful the valid-token baseline POST comes first.
        session.post.side_effect = (
          [_mock_response(status=200, text="saved"), login] if stateful else [login])
        probe = _make_probe(
          primary_session=session, allow_stateful=stateful,
          workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
        )
        probe.auth.admin_context = "absent"
        probe._test_csrf_bypass()
        found = [f for f in probe.findings if f.scenario_id == "PT-A02-05"]
        self.assertEqual([f.status for f in found], ["inconclusive"])
        self.assertEqual(found[0].evidence, ["reason=admin_context_absent"])

  def test_csrf_bypass_skips_login(self):
    """Login form is not tested for CSRF."""
    session = MagicMock()
    session.post.return_value = _mock_response(status=200, text="OK")
    probe = _make_probe(
      primary_session=session,
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
    probe = _make_probe(primary_session=session)

    probe._test_session_token()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-06" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")

  def test_session_token_short(self):
    """Short session ID → inconclusive."""
    session = MagicMock()
    session.cookies.get_dict.return_value = {"sid": "abc123"}
    probe = _make_probe(primary_session=session)

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
    probe = _make_probe(primary_session=session)

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
    probe.auth.primary_session = official

    probe.auth.detected_csrf_field = None

    probe._test_session_fixation()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A07-03" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")
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
    probe.auth.primary_session = official

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
    probe.auth.primary_session = MagicMock()

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
    probe.auth.primary_session = official

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
    self.assertEqual(f[0].severity, "MEDIUM")

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

  def test_pt_a02_12_is_located_at_the_protected_endpoint(self):
    """The forged token is accepted at the protected endpoint, so that is where the finding lives.
    Its evidence names both paths, which `location_from_evidence` treats as ambiguous (no asset at
    all), so the probe states the location explicitly."""
    me = _mock_response(status=200, content_type="application/json")
    me.json = MagicMock(return_value={"username": "alice", "is_admin": True, "alg": "none"})
    probe = self._setup(me)
    probe._test_jwt_weak_alg()
    f = [x for x in probe.findings if x.scenario_id == "PT-A02-12" and x.status == "vulnerable"]
    self.assertEqual(f[0].url, probe.target_url + "/api/me/")

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

  def test_pt_a02_12_never_falls_back_to_the_regular_username(self):
    """RM-219: the issuer password sent under the regular username would be a
    wrong-password login for an account the scan needs."""
    jwt_cfg = JwtEndpoint(token_path="/api/token/", protected_path="/api/me/",
                          username="", password="issuer-pass")
    probe = _make_probe(jwt_endpoints=jwt_cfg)
    probe.regular_username = "alice"
    probe.auth.make_anonymous_session = MagicMock()
    probe._test_jwt_weak_alg()
    probe.auth.make_anonymous_session.assert_not_called()
    f = [x for x in probe.findings if x.scenario_id == "PT-A02-12"]
    self.assertEqual(f[0].status, "inconclusive")


class TestPasswordResetTokenReusePTA0218(unittest.TestCase):
  """PT-A02-18 — reuse needs a real consume; issuance alone is inconclusive."""

  def _make_session(self, post_responses):
    sess = MagicMock()
    sess.get = MagicMock(return_value=_mock_response(status=200, text=""))
    sess.post = MagicMock(side_effect=post_responses)
    sess.close = MagicMock()
    return sess

  def test_pt_a02_18_identical_or_rotating_tokens_are_never_a_verdict(self):
    """Issuing twice proves nothing about reuse: one request, inconclusive."""
    for first, second in (("reset-admin", "reset-admin"),
                          ("reset-abcd1234efgh5678", "reset-zyxw9876vutsrqpo")):
      with self.subTest(first=first, second=second):
        probe = _make_probe(password_reset_path="/auth/password-reset/request/")
        sess = self._make_session([
          _mock_response(status=200, text=f"<code>{first}</code>"),
          _mock_response(status=200, text=f"<code>{second}</code>"),
        ])
        probe.auth.make_anonymous_session = MagicMock(return_value=sess)

        probe._test_password_reset_token_reuse()

        f = [x for x in probe.findings if x.scenario_id == "PT-A02-18"]
        self.assertEqual([x.status for x in f], ["inconclusive"])
        self.assertIn("reason=reset_consume_needs_current_password", f[0].evidence)
        self.assertEqual(sess.post.call_count, 1)

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


class TestResetTokenSnapshotNotAttached(unittest.TestCase):
  """The reset response body is the secret: no snapshot of it is stored."""

  def test_pt_a02_18_identical_tokens_finding_has_no_snapshot(self):
    # RM-272: identical tokens alone no longer prove reuse, so PT-A02-18 is
    # inconclusive here; the reset body must still never be snapshotted.
    probe = _make_probe(password_reset_path="/auth/password-reset/request/")
    sess = MagicMock()
    sess.get = MagicMock(return_value=_mock_response(status=200, text=""))
    sess.post = MagicMock(side_effect=[
      _mock_response(status=200, text="<code>reset-admin</code>"),
      _mock_response(status=200, text="<code>reset-admin</code>"),
    ])
    probe.auth.make_anonymous_session = MagicMock(return_value=sess)

    probe._test_password_reset_token_reuse()

    f = next(x for x in probe.findings if x.scenario_id == "PT-A02-18")
    self.assertEqual(f.status, "inconclusive")
    self.assertEqual(f.evidence_artifacts, [])

  def test_pt_a07_02_vulnerable_finding_keeps_exposure_evidence_no_snapshot(self):
    probe = _make_probe(password_reset_path="/auth/password-reset/request/")
    sess = MagicMock()
    sess.get = MagicMock(return_value=_mock_response(status=200, text=""))
    sess.post = MagicMock(return_value=_mock_response(
      status=200, text="<code>reset-admin</code>"))
    probe.auth.make_anonymous_session = MagicMock(return_value=sess)

    probe._test_password_reset_token()

    f = next(x for x in probe.findings if x.scenario_id == "PT-A07-02")
    self.assertEqual(f.status, "vulnerable")
    self.assertIn("token_exposed_in_response=True", f.evidence)
    self.assertEqual(f.evidence_artifacts, [])


class TestLoginRateLimitingPTA0207(unittest.TestCase):

  def _run(self, post_side_effect):
    probe = _make_probe()
    sess = MagicMock()
    sess.get = MagicMock(return_value=_mock_response(status=200, text=""))
    sess.post = MagicMock(side_effect=post_side_effect)
    probe.auth.make_anonymous_session = MagicMock(return_value=sess)
    probe._test_login_rate_limiting()
    return [x for x in probe.findings if x.scenario_id == "PT-A02-07"]

  def test_all_posts_raising_is_inconclusive_not_vulnerable(self):
    f = self._run(Exception("boom"))
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "inconclusive")
    self.assertIn("reason=no_login_response", f[0].evidence)

  def test_responses_without_lockout_is_vulnerable(self):
    f = self._run(lambda *a, **k: _mock_response(status=200, text="bad login"))
    self.assertEqual(f[0].status, "vulnerable")


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
