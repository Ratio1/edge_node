"""RM-273 Phase 2a: mid-family re-auth at the HTTP chokepoint and the real bearer refresh.

Client tests use a stubbed session and hook. Manager tests run a real client and AuthManager
over a small in-memory app (`_App`) that stands in for the transport by replacing
`requests.Session`, so cookies and headers are real.
"""

import json
import time
import unittest
from unittest.mock import MagicMock, patch

import requests

from extensions.business.cybersec.red_mesh.constants import GRAYBOX_REAUTH_MAX
from extensions.business.cybersec.red_mesh.graybox.auth import AuthManager
from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudgetExhausted
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.http_client import (
  GrayboxHttpClient, GrayboxScopeError,
)
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiSecurityConfig, AuthDescriptor, GrayboxTargetConfig,
)
from extensions.business.cybersec.red_mesh.tests.test_graybox_backoff import (
  _probe, _resp, _run, _setup,
)
from extensions.business.cybersec.red_mesh.graybox.safety import SafetyControls

BASE = "http://testapp.local:8000"


def _call(client, session, method="GET", **kwargs):
  return client.request(session, method, "https://h/x", **kwargs)


class TestClientRecoveryHook(unittest.TestCase):

  def _client(self, statuses, outcome):
    clock, safety, budget, client, session = _setup(statuses)
    hook = MagicMock(return_value=outcome)
    client.set_session_recovery(hook)
    return clock, safety, budget, client, session, hook

  def test_hook_runs_only_on_401_403_3xx(self):
    for status, called in ((401, True), (403, True), (302, True), (200, False),
                           (404, False), (500, False)):
      with self.subTest(status=status):
        clock, _s, _b, client, session, hook = self._client([_resp(status)], None)
        _run(clock, lambda: _call(client, session))
        self.assertEqual(hook.called, called)

  def test_hook_skipped_for_exempt_hops_and_inside_a_recovery(self):
    clock, _s, _b, client, session, hook = self._client([_resp(401)], "lost")
    _run(clock, lambda: _call(client, session, budget_exempt=True))
    hook.assert_not_called()
    inner_session = MagicMock()
    inner_session.request.return_value = _resp(401)

    def hook_sending(raw, response):
      _call(client, inner_session)  # the liveness / login request the manager sends
      return None
    client._recover = MagicMock(side_effect=hook_sending)
    session.request.side_effect = [_resp(401)]
    _run(clock, lambda: _call(client, session))
    self.assertEqual(client._recover.call_count, 1)  # the inner 401 did not recurse
    self.assertFalse(client._recovering)

  def test_get_is_replayed_once_and_both_sends_are_charged(self):
    clock, safety, budget, client, session, hook = self._client(
      [_resp(401), _resp(401)], "reauthenticated")
    response = _run(clock, lambda: _call(client, session))
    self.assertEqual(session.request.call_count, 2)
    self.assertEqual(budget.remaining, 48)
    self.assertEqual(hook.call_count, 1)  # the replayed 401 does not recover again
    self.assertEqual(response.status_code, 401)
    self.assertEqual((safety.refusals, safety.last_refusal), (1, "session_reauthenticated"))

  def test_post_is_not_replayed_and_is_flagged(self):
    clock, safety, _b, client, session, _hook = self._client(
      [_resp(401)], "reauthenticated")
    response = _run(clock, lambda: _call(client, session, "POST"))
    self.assertEqual(session.request.call_count, 1)
    self.assertEqual(response.status_code, 401)
    self.assertEqual((safety.refusals, safety.last_refusal), (1, "session_reauthenticated"))

  def test_lost_session_is_flagged_and_the_original_response_returned(self):
    clock, safety, _b, client, session, _hook = self._client([_resp(403)], "lost")
    response = _run(clock, lambda: _call(client, session))
    self.assertEqual(response.status_code, 403)
    self.assertEqual((safety.refusals, safety.last_refusal), (1, "session_lost"))

  def test_refusal_inside_the_hook_propagates(self):
    clock, _s, _b, client, session, hook = self._client([_resp(401)], None)
    hook.side_effect = RequestBudgetExhausted()
    with self.assertRaises(RequestBudgetExhausted):
      _run(clock, lambda: _call(client, session))
    self.assertFalse(client._recovering)


class TestRunGuardedDegraded(unittest.TestCase):

  def test_note_degraded_downgrades_the_clean_verdict(self):
    safety = SafetyControls(request_delay=0.0, target_is_local=True)
    probe = _probe(safety)

    def family():
      safety.note_degraded("session_lost")
      probe.findings.append(GrayboxFinding(
        scenario_id="PT-A01-05", title="t", status="not_vulnerable", severity="INFO",
        owasp="A01:2021"))
    probe._run_guarded("family", family)
    self.assertEqual(probe.findings[0].status, "inconclusive")
    self.assertEqual(probe.findings[0].evidence, ["reason=session_lost"])


# ── In-memory app ───────────────────────────────────────────────────────────

def _response(status, url, body="", headers=None, json_body=None):
  resp = requests.Response()
  resp.status_code = status
  resp.url = url
  resp.headers.update(headers or {})
  if json_body is not None:
    body = json.dumps(json_body)
    resp.headers["content-type"] = "application/json"
  resp._content = body.encode()
  resp._content_consumed = True
  return resp


class _App:
  """Form login (cookie `sessionid`), bearer (`Authorization`) and api-key (`X-Api-Key`)."""

  def __init__(self):
    self.hits = []
    self.logins = 0
    self.reject_login = False
    self.valid_cookies = set()
    self.valid_bearer = set()
    self.api_key_ok = True
    self.grants = []          # refresh tokens presented to /oauth/token
    self.grant_reply = None   # (status, body) override
    self.grant_raise = None   # exception raised by /oauth/token
    self.next_access = "tok-new-AAA"
    self.next_refresh = "rt-new-BBB"

  def count(self, path):
    return sum(1 for _m, p in self.hits if p == path)

  def handle(self, sess, method, url, data, headers):
    path = url.split(BASE, 1)[-1].split("?")[0]
    self.hits.append((method, path))
    hdr = {**sess.headers, **(headers or {})}
    if path == "/login/":
      if method != "POST":
        return _response(200, url, "<form></form>")
      if self.reject_login:
        return _response(200, url, "invalid credentials")
      self.logins += 1
      token = f"s{self.logins}"
      self.valid_cookies.add(token)
      sess.cookies.set("sessionid", token)
      return _response(302, url, headers={"Location": "/dash/"})
    if path == "/oauth/token":
      self.grants.append((data or {}).get("refresh_token"))
      if self.grant_raise:
        raise self.grant_raise
      if self.grant_reply:
        status, body = self.grant_reply
        return _response(status, url, body)
      self.valid_bearer.add(self.next_access)
      return _response(200, url, json_body={
        "access_token": self.next_access, "refresh_token": self.next_refresh})
    authed = (sess.cookies.get("sessionid") in self.valid_cookies
              or hdr.get("Authorization", "").removeprefix("Bearer ") in self.valid_bearer
              or (hdr.get("X-Api-Key") == "k" and self.api_key_ok))
    if not authed:
      if "Authorization" in hdr or "X-Api-Key" in hdr:
        return _response(401, url)
      return _response(302, url, headers={"Location": "/login/?next=" + path})
    if path == "/admin/":
      return _response(403, url)
    return _response(200, url, "ok", json_body=None)


class _FakeSession(requests.Session):
  app = None

  def request(self, method, url, data=None, headers=None, **kwargs):
    return self.app.handle(self, method, url, data, headers)


def _config(auth_type="form", **auth):
  api = ApiSecurityConfig(auth=AuthDescriptor(auth_type=auth_type, **auth))
  return GrayboxTargetConfig(login_path="/login/", api_security=api)


class _ManagerCase(unittest.TestCase):

  def setUp(self):
    self.install_app()

  def install_app(self):
    self.app = _App()
    session_cls = type("S", (_FakeSession,), {"app": self.app})
    patcher = patch("requests.Session", session_cls)
    patcher.start()
    self.addCleanup(patcher.stop)

  def manager(self, config=None):
    self.client = GrayboxHttpClient(BASE, allow_private_targets=True)
    return AuthManager(BASE, config or _config(), verify_tls=False, http_client=self.client)

  def login(self, auth, creds=None):
    creds = creds or Credentials(username="alice", password="pw")
    self.assertTrue(auth.authenticate(creds))
    return auth.official_session

  @staticmethod
  def stages(auth):
    return [d.get("stage") for d in auth._auth_diagnostics]


class TestFormRecovery(_ManagerCase):

  def test_dead_session_is_relogged_in_place_and_the_request_replayed(self):
    auth = self.manager()
    wrapper = self.login(auth)
    wrapper.cookies.clear()  # a logout that dropped the cookie
    response = wrapper.get(BASE + "/dash/")
    self.assertEqual(response.status_code, 200)  # the replay carried the new cookie
    self.assertIs(auth.official_session, wrapper)
    self.assertEqual(wrapper.cookies.get("sessionid"), "s2")
    self.assertEqual(self.app.logins, 2)
    self.assertIn("session_reauthenticated", self.stages(auth))

  def test_server_side_revoke_is_found_by_the_probe_path(self):
    auth = self.manager(_config(authenticated_probe_path="/api/me"))
    wrapper = self.login(auth)
    self.app.valid_cookies.clear()  # cookie stays, session gone
    self.assertEqual(wrapper.get(BASE + "/dash/").status_code, 200)
    self.assertEqual(wrapper.cookies.get("sessionid"), "s2")

  def test_dead_session_between_families_gets_a_full_login_not_a_renewal(self):
    auth = self.manager(_config(authenticated_probe_path="/api/me"))
    self.login(auth)
    self.app.valid_cookies.clear()  # cookie stays, session gone
    auth._liveness_checked_at = 0.0  # the next family's liveness check is due
    self.assertTrue(auth.needs_refresh())
    self.assertEqual((auth._reauth_count, self.app.logins), ({}, 1))

  def test_alive_verdict_is_cached_so_denials_cost_one_check(self):
    auth = self.manager(_config(authenticated_probe_path="/api/me"))
    wrapper = self.login(auth)
    before = self.app.count("/api/me")
    for _ in range(3):
      self.assertEqual(wrapper.get(BASE + "/admin/").status_code, 403)
    # 403 -> check once: the authenticated request and the anonymous control
    self.assertEqual(self.app.count("/api/me") - before, 2)
    self.assertEqual(self.app.logins, 1)

  def test_trigger_filter_sends_nothing(self):
    auth = self.manager()
    wrapper = self.login(auth)
    raw = wrapper._session
    hits = len(self.app.hits)

    def reply(status, location=None):
      return _response(status, BASE + "/x/", headers={"Location": location} if location else {})
    for name, session, response in (
        ("anonymous 401", auth.anon_session._session, reply(401)),
        ("200", raw, reply(200)),
        ("500", raw, reply(500)),
        ("3xx elsewhere", raw, reply(302, "/other/")),
        ("3xx off-origin", raw, reply(302, "http://evil.example/login/")),
        ("3xx no location", raw, reply(302))):
      with self.subTest(name):
        self.assertIsNone(auth._recover_session(session, response))
    self.assertEqual(len(self.app.hits), hits)

  def test_login_redirect_with_a_live_cookie_and_no_probe_path_is_alive(self):
    auth = self.manager()
    wrapper = self.login(auth)
    response = _response(302, BASE + "/x/", headers={"Location": "/login/?next=/x/"})
    self.assertIsNone(auth._recover_session(wrapper._session, response))

  def test_reauth_is_capped_and_a_failed_one_is_final_until_a_full_login(self):
    auth = self.manager()
    wrapper = self.login(auth)
    for _ in range(GRAYBOX_REAUTH_MAX):
      wrapper.cookies.clear()
      self.assertEqual(wrapper.get(BASE + "/dash/").status_code, 200)
    self.assertEqual(self.app.logins, 1 + GRAYBOX_REAUTH_MAX)
    wrapper.cookies.clear()
    hits = len(self.app.hits)
    response = _response(302, BASE + "/x/", headers={"Location": "/login/"})
    self.assertEqual(auth._recover_session(wrapper._session, response), "lost")
    self.assertEqual(len(self.app.hits), hits)  # capped: no network
    # a full authenticate() resets the per-principal state
    wrapper = self.login(auth)
    self.app.reject_login = True
    wrapper.cookies.clear()
    self.assertEqual(auth._recover_session(wrapper._session, response), "lost")
    self.app.reject_login = False
    hits = len(self.app.hits)
    self.assertEqual(auth._recover_session(wrapper._session, response), "lost")
    self.assertEqual(len(self.app.hits), hits)  # failed once: final

  def test_capped_principal_is_lost_only_when_proven_dead_and_never_logs_in(self):
    auth = self.manager(_config(authenticated_probe_path="/api/me"))
    wrapper = self.login(auth)
    auth._reauth_failed.add("official")
    response = _response(403, BASE + "/admin/")
    self.assertIsNone(auth._recover_session(wrapper._session, response))  # live: a denial
    self.app.valid_cookies.clear()
    auth._alive_at.clear()
    self.assertEqual(auth._recover_session(wrapper._session, response), "lost")
    self.assertEqual(self.app.logins, 1)  # no login request

  def test_api_key_session_is_lost_not_reauthenticated(self):
    auth = self.manager(_config("api_key", authenticated_probe_path="/api/me"))
    wrapper = self.login(auth, Credentials(api_key="k"))
    self.app.api_key_ok = False
    self.assertEqual(wrapper.get(BASE + "/api/me").status_code, 401)
    self.assertIn("authenticated_probe_rejected", self.stages(auth))
    response = _response(401, BASE + "/api/me")
    self.assertEqual(auth._recover_session(wrapper._session, response), "lost")


class TestBearerRefresh(_ManagerCase):

  OLD, OLD_RT = "tok-old-AAA", "rt-old-BBB"

  def bearer(self, **auth):
    auth.setdefault("bearer_refresh_url", "/oauth/token")
    auth.setdefault("authenticated_probe_path", "/api/me")
    manager = self.manager(_config("bearer", **auth))
    self.app.valid_bearer.add(self.OLD)
    return manager

  def creds(self):
    return Credentials(bearer_token=self.OLD, bearer_refresh_token=self.OLD_RT)

  def test_expired_token_is_refreshed_on_the_same_session_and_the_rotation_is_kept(self):
    auth = self.bearer()
    wrapper = self.login(auth, self.creds())
    self.app.valid_bearer.clear()
    self.assertEqual(wrapper.get(BASE + "/api/me").status_code, 200)
    self.assertEqual(wrapper.headers["Authorization"], "Bearer tok-new-AAA")
    self.assertIs(auth.official_session, wrapper)
    self.assertEqual(self.app.grants, [self.OLD_RT])
    # the next scan phase builds fresh Credentials from the secret payload: the rotation survives
    self.app.next_access, self.app.next_refresh = "tok-third-CCC", "rt-third-DDD"
    wrapper = self.login(auth, self.creds())
    self.assertEqual(wrapper.headers["Authorization"], "Bearer tok-new-AAA")
    self.app.valid_bearer.clear()
    wrapper.get(BASE + "/api/me")
    self.assertEqual(self.app.grants, [self.OLD_RT, "rt-new-BBB"])
    self.assertNotIn("tok-", json.dumps(auth._auth_diagnostics))
    self.assertNotIn("rt-", json.dumps(auth._auth_diagnostics))

  def test_failed_grants_are_lost_and_diagnosed_without_tokens(self):
    for name, reply in (
        ("400", (400, '{"error": "invalid_grant"}')),
        ("500", (500, "boom")),
        ("not json", (200, "<html>")),
        ("no access_token", (200, '{"token": "x"}')),
        ("empty access_token", (200, '{"access_token": ""}'))):
      with self.subTest(name):
        self.install_app()
        auth = self.bearer()
        wrapper = self.login(auth, self.creds())
        self.app.valid_bearer.clear()
        self.app.grant_reply = reply
        self.assertEqual(wrapper.get(BASE + "/api/me").status_code, 401)
        self.assertIn("bearer_refresh_failed", self.stages(auth))
        self.assertNotIn(self.OLD, json.dumps(auth._auth_diagnostics))
        self.assertNotIn(self.OLD_RT, json.dumps(auth._auth_diagnostics))

  def test_off_origin_refresh_url_is_refused_and_diagnosed(self):
    auth = self.bearer(bearer_refresh_url="http://evil.example/token")
    wrapper = self.login(auth, self.creds())
    self.app.valid_bearer.clear()
    hits = len(self.app.hits)
    self.assertEqual(wrapper.get(BASE + "/api/me").status_code, 401)
    self.assertNotIn(("POST", "/token"), self.app.hits[hits:])
    failed = [d for d in auth._auth_diagnostics if d.get("stage") == "bearer_refresh_failed"]
    self.assertEqual([d.get("error") for d in failed], ["scope_refused"])
    self.assertNotIn("evil", json.dumps(auth._auth_diagnostics))

  def test_refresh_transport_error_is_diagnosed(self):
    auth = self.bearer()
    wrapper = self.login(auth, self.creds())
    self.app.valid_bearer.clear()
    self.app.grant_raise = requests.ConnectionError("down")
    self.assertEqual(wrapper.get(BASE + "/api/me").status_code, 401)
    failed = [d for d in auth._auth_diagnostics if d.get("stage") == "bearer_refresh_failed"]
    self.assertEqual([d.get("error") for d in failed], ["transport_error"])

  def test_token_expired_between_families_is_refreshed_before_the_login_fails(self):
    auth = self.bearer()
    self.login(auth, self.creds())
    self.app.valid_bearer.clear()
    auth._liveness_checked_at = 0.0  # the next family's liveness check is due
    self.assertTrue(auth.ensure_sessions(self.creds()))
    self.assertEqual(auth.official_session.headers["Authorization"], "Bearer tok-new-AAA")
    self.assertEqual(self.app.grants, [self.OLD_RT])
    self.assertEqual(auth._reauth_count, {})  # the login-time refresh, not the mid-family hook

  def test_bearer_401_skips_the_alive_cache_but_a_403_keeps_it(self):
    auth = self.bearer()
    wrapper = self.login(auth, self.creds())
    auth._alive_at["official"] = time.time()
    self.app.valid_bearer.clear()
    self.assertIsNone(auth._recover_session(wrapper._session, _response(403, BASE + "/a")))
    self.assertEqual(wrapper.get(BASE + "/api/me").status_code, 200)  # 401: checked, refreshed
    self.assertEqual(self.app.grants, [self.OLD_RT])

  def test_bearer_trigger_rows_send_nothing(self):
    auth = self.bearer(authenticated_probe_path="")
    wrapper = self.login(auth, self.creds())
    hits = len(self.app.hits)
    for response in (
        _response(302, BASE + "/x/", headers={"Location": "/login/"}),  # form-only signal
        _response(403, BASE + "/x/")):  # live bearer, no probe path: a denial
      self.assertIsNone(auth._recover_session(wrapper._session, response))
    self.assertEqual(len(self.app.hits), hits)

  def test_final_cleanup_drops_the_rotated_tokens(self):
    auth = self.bearer()
    wrapper = self.login(auth, self.creds())
    self.app.valid_bearer.clear()
    wrapper.get(BASE + "/api/me")
    auth.cleanup()
    self.assertTrue(auth._token_overlay)  # per-family cleanup keeps them for the next login
    auth.cleanup(final=True)
    self.assertEqual(auth._token_overlay, {})

  def test_refresh_api_uses_the_grant_without_writing_the_callers_creds(self):
    auth = self.bearer()
    creds = self.creds()
    strategy = auth._build_strategy()
    self.assertTrue(strategy.refresh(creds))
    self.assertEqual(strategy.session.headers["Authorization"], "Bearer tok-new-AAA")
    self.assertEqual(creds.bearer_token, self.OLD)
    self.app.grant_reply = (400, "{}")
    self.assertFalse(strategy.refresh(creds))  # configured refresh failed: no re-stamp
