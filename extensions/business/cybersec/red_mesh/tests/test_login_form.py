"""RM-274 Phase 1: structural login-form detection and the FormAuth search."""

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.graybox.auth import AuthManager
from extensions.business.cybersec.red_mesh.graybox.auth_strategies import (
  BasicAuth, FormAuth, LOGIN_NOT_FOUND, MAX_LOGIN_SEARCH_FETCHES,
)
from extensions.business.cybersec.red_mesh.graybox.http_client import (
  GrayboxScopeError, normalize_request_url,
)
from extensions.business.cybersec.red_mesh.graybox.login_form import (
  find_login_form, login_links,
)
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiSecurityConfig, AuthDescriptor, GrayboxTargetConfig,
)

HOST = "http://lab.local:8080"

AUDIT_FORM = (
  '<form method="post" action="/signin"><input name="user_login">'
  '<input type="password" name="user_pass"><input type="hidden" name="nonce" value="n1">'
  '<input type="submit" name="go" value="Sign in"></form>')
WP_FORM = (
  '<form name="loginform" action="http://lab.local:8080/wp-login.php" method="post">'
  '<input type="text" name="log"><input type="password" name="pwd">'
  '<input type="checkbox" name="rememberme" value="forever">'
  '<input type="submit" name="wp-submit" value="Log In">'
  '<input type="submit" name="second" value="x">'
  '<input type="hidden" name="redirect_to" value="/wp-admin/">'
  '<input type="hidden" name="testcookie" value="1"></form>')
ROUNDCUBE_FORM = (
  '<form action="./?_task=login" method="post">'
  '<input type="hidden" name="_token" value="tok"><input type="hidden" name="_task" value="login">'
  '<input type="hidden" name="_action" value="login">'
  '<input name="_user" type="text"><input name="_pass" type="password">'
  '<button type="submit" name="_go" value="Login">Login</button></form>')


class TestFindLoginForm(unittest.TestCase):

  def test_non_default_names_and_hidden_fields(self):
    form = find_login_form(AUDIT_FORM, HOST + "/signin")
    self.assertEqual((form.username_field, form.password_field), ("user_login", "user_pass"))
    self.assertEqual(form.action, HOST + "/signin")
    self.assertEqual(form.fields, {"nonce": "n1", "go": "Sign in"})

  def test_wordpress_shape_submits_checked_defaults_only(self):
    form = find_login_form(WP_FORM, HOST + "/wp-login.php")
    self.assertEqual((form.username_field, form.password_field), ("log", "pwd"))
    self.assertEqual(form.fields, {
      "wp-submit": "Log In", "redirect_to": "/wp-admin/", "testcookie": "1"})

  def test_relative_query_action_resolves_against_page(self):
    form = find_login_form(ROUNDCUBE_FORM, HOST + "/")
    self.assertEqual(form.action, HOST + "/?_task=login")
    self.assertEqual((form.username_field, form.password_field), ("_user", "_pass"))
    self.assertEqual(form.fields["_go"], "Login")  # <button> is a submit
    self.assertEqual(form.fields["_token"], "tok")

  def test_empty_action_is_the_page_and_override_wins(self):
    html = ('<form method="POST"><input name="a" type="text"><input name="b" type="password">'
            '</form>')
    form = find_login_form(html, HOST + "/in?x=1", username="who", password="secret")
    self.assertEqual(form.action, HOST + "/in?x=1")
    self.assertEqual((form.username_field, form.password_field), ("who", "secret"))
    self.assertEqual(form.fields, {})

  def test_password_only_form_uses_fallback_username(self):
    html = '<form method="post"><input type="password" name="pw"></form>'
    self.assertEqual(
      find_login_form(html, HOST + "/", fallback_username="uname").username_field, "uname")

  def test_not_a_login_form(self):
    page = HOST + "/"
    get_form = '<form><input name="q"><input type="password" name="p"></form>'
    two_pw = ('<form method="post"><input type="password" name="a">'
              '<input type="password" name="b"></form>')
    search = '<form method="post"><input name="q"></form>'
    signup = ('<form method="post"><input name="u"><input type="password" name="p" '
              'autocomplete="new-password"></form>')
    for html in (get_form, two_pw, search, signup, "", None, "<form method=post><input"):
      self.assertIsNone(find_login_form(html, page))


class TestLoginLinks(unittest.TestCase):

  def test_only_login_path_segments_same_origin_max_three(self):
    html = (
      '<a href="/account/delete">Sign in</a>'           # text is ignored
      '<a href="/x?next=/login">x</a>'                   # query is ignored
      '<a href="https://evil.example/login">e</a>'
      '<a href="/signin">a</a><a href="/Auth/Login.php">b</a><a href="/signin">dup</a>'
      '<a href="/users/sign_in">c</a><a href="/log-in">d</a>')
    html += '<a href="/login?action=logout">out</a>'
    self.assertEqual(login_links(html, HOST + "/"), [
      HOST + "/signin", HOST + "/Auth/Login.php", HOST + "/users/sign_in"])


class FakeResp:
  def __init__(self, status=200, text="", headers=None, url=""):
    self.status_code, self.text, self.url = status, text, url
    self.headers, self.history = dict(headers or {}), []


class FakeSite:
  """In-memory target. pages: {path?query: (status, html[, headers])}."""

  def __init__(self, pages, target=HOST, user="alice", password="pw"):
    self.pages, self.target, self.log = pages, target, []
    self.user, self.password = user, password
    self.posts = []
    self.post_status = None  # force a status (307 test)
    self.cookies = {}

  def session(self):
    site = self
    sess = SimpleNamespace(
      headers={}, close=lambda: None,
      cookies=SimpleNamespace(get_dict=lambda: dict(site.cookies)))
    sess.get = lambda url, **kw: site.get(url, **kw)
    sess.post = lambda url, **kw: site.post(url, **kw)
    return sess

  def _resolve(self, url):
    full = normalize_request_url(self.target, url)  # raises on off-origin
    return full, full[len(HOST):] or "/"

  def get(self, url, allow_redirects=False, **kw):
    for _ in range(5):
      full, key = self._resolve(url)
      self.log.append(("GET", key))
      status, text, *extra = self.pages.get(key, (404, "nope"))
      headers = extra[0] if extra else {}
      resp = FakeResp(status, text, headers, full)
      if allow_redirects and status in (301, 302, 303):
        url = headers["Location"]
        continue
      return resp
    return resp

  def post(self, url, data=None, headers=None, allow_redirects=False, **kw):
    full, key = self._resolve(url)
    self.log.append(("POST", key))
    self.posts.append((key, dict(data or {}), allow_redirects))
    if self.post_status:
      return FakeResp(self.post_status, "", {"Location": "/dashboard"}, full)
    names = [k for k, v in (data or {}).items() if v == self.user]
    if names and self.password in (data or {}).values():
      self.cookies["sid"] = "1"
      return FakeResp(302, "", {"Location": "/dashboard"}, full)
    return FakeResp(200, "<p>Invalid credentials</p>", {}, full)

  def gets(self):
    return [k for m, k in self.log if m == "GET"]


def _creds(site):
  from extensions.business.cybersec.red_mesh.graybox.auth_credentials import Credentials
  return Credentials(username=site.user, password=site.password)


def _manager(site, cfg=None, target=HOST):
  mgr = AuthManager(target, cfg or GrayboxTargetConfig(), verify_tls=False)
  patcher = patch.object(FormAuth, "make_session", lambda self: site.session())
  patcher.start()
  return mgr, patcher


DASHBOARD = (200, "<h1>Hello</h1>")


class TestFormSearch(unittest.TestCase):

  def _login(self, site, cfg=None, target=HOST):
    mgr, patcher = _manager(site, cfg, target)
    self.addCleanup(patcher.stop)
    session, retry = mgr._try_login_attempt(_creds(site))
    return mgr, session

  def test_audit_app_found_via_root_link_without_the_delete_trap(self):
    site = FakeSite({
      "/": (200, '<a href="/account/delete">Delete account</a><a href="/signin">Sign in</a>'),
      "/signin": (200, AUDIT_FORM), "/dashboard": DASHBOARD})
    mgr, session = self._login(site)
    self.assertIsNotNone(session)
    # default path, root, one login page, POST, redirect GET
    self.assertEqual(site.log, [
      ("GET", "/auth/login/"), ("GET", "/"), ("GET", "/signin"),
      ("POST", "/signin"), ("GET", "/dashboard")])
    key, data, follow = site.posts[0]
    self.assertEqual(data, {"nonce": "n1", "go": "Sign in", "user_login": "alice", "user_pass": "pw"})
    self.assertFalse(follow)  # POST is never auto-followed
    self.assertEqual(mgr.target_config.login_path, "/signin")
    self.assertEqual(mgr.target_config.username_field, "user_login")

  def test_wordpress_found_on_data_path(self):
    site = FakeSite({"/": (200, "<p>blog</p>"), "/wp-login.php": (200, WP_FORM),
                     "/dashboard": DASHBOARD})
    _, session = self._login(site)
    self.assertIsNotNone(session)
    self.assertEqual(site.posts[0][1]["log"], "alice")
    self.assertEqual(site.posts[0][1]["redirect_to"], "/wp-admin/")
    self.assertLessEqual(len(site.gets()), MAX_LOGIN_SEARCH_FETCHES)

  def test_odoo_redirect_chain_from_the_root(self):
    odoo = ('<form action="/web/login" method="post"><input name="csrf_token" type="hidden" '
            'value="c"><input name="login"><input name="password" type="password"></form>')
    site = FakeSite({
      "/": (302, "", {"Location": "/odoo"}), "/odoo": (302, "", {"Location": "/web/login"}),
      "/web/login": (200, odoo), "/dashboard": DASHBOARD})
    mgr, session = self._login(site)
    self.assertIsNotNone(session)
    self.assertEqual(site.posts[0][0], "/web/login")
    self.assertEqual(site.posts[0][1]["csrf_token"], "c")
    self.assertEqual(mgr.target_config.login_path, "/web/login")

  def test_october_backend_redirect_to_signin(self):
    october = ('<form method="post" action=""><input type="hidden" name="_token" value="t">'
               '<input type="hidden" name="_session_key" value="k"><input name="login">'
               '<input type="password" name="password"></form>')
    site = FakeSite({
      "/backend": (302, "", {"Location": "/backend/backend/auth/signin"}),
      "/backend/backend/auth/signin": (200, october), "/dashboard": DASHBOARD})
    mgr, session = self._login(site)
    self.assertIsNotNone(session)
    self.assertEqual(site.posts[0][0], "/backend/backend/auth/signin")
    self.assertEqual(site.posts[0][1]["_session_key"], "k")
    self.assertEqual(mgr.target_config.password_field, "password")

  def test_roundcube_query_action_posts_to_it_and_writes_back_the_page(self):
    site = FakeSite({"/": (200, ROUNDCUBE_FORM), "/dashboard": DASHBOARD})
    mgr, session = self._login(site)
    self.assertIsNotNone(session)
    self.assertEqual(site.posts[0][0], "/?_task=login")
    self.assertEqual(mgr.target_config.login_path, "/")  # the page, not the POST-only action

  def test_base_path_target_has_no_path_doubling(self):
    base = HOST + "/app"
    site = FakeSite({
      "/app/": (200, '<a href="/app/signin">in</a>'),
      "/app/signin": (200, AUDIT_FORM.replace('action="/signin"', 'action="/app/signin"')),
      "/dashboard": DASHBOARD}, target=base)
    mgr, session = self._login(site, target=base)
    self.assertIsNotNone(session)
    self.assertEqual(site.posts[0][0], "/app/signin")
    self.assertEqual(mgr.target_config.login_path, "/signin")
    self.assertNotIn("/app/app/signin", [k for _, k in site.log])

  def test_off_origin_root_redirect_does_not_stop_the_search(self):
    site = FakeSite({"/": (302, "", {"Location": "https://evil.example/"}),
                     "/wp-login.php": (200, WP_FORM), "/dashboard": DASHBOARD})
    _, session = self._login(site)
    self.assertIsNotNone(session)
    self.assertEqual(site.posts[0][0], "/wp-login.php")

  def test_transport_error_on_a_candidate_skips_it_only(self):
    import requests
    site = FakeSite({"/": (200, "x"), "/wp-login.php": (200, WP_FORM), "/dashboard": DASHBOARD})
    real_get = site.get

    def flaky(url, **kw):
      if url.endswith("/login"):
        raise requests.ConnectionError("reset")
      return real_get(url, **kw)
    site.get = flaky
    _, session = self._login(site)
    self.assertIsNotNone(session)

  def test_transport_error_on_post_caches_the_target_for_the_retry(self):
    import requests
    site = FakeSite({"/": (200, '<a href="/signin">in</a>'), "/signin": (200, AUDIT_FORM),
                     "/dashboard": DASHBOARD})
    real_post = site.post
    calls = []

    def post(url, **kw):
      calls.append(url)
      if len(calls) == 1:
        raise requests.ConnectionError("reset")
      return real_post(url, **kw)
    site.post = post
    mgr, patcher = _manager(site)
    self.addCleanup(patcher.stop)
    self.assertEqual(mgr._try_login_attempt(_creds(site)), (None, True))
    site.log.clear()
    session, _ = mgr._try_login_attempt(_creds(site))
    self.assertIsNotNone(session)
    self.assertEqual(site.log[0], ("GET", "/signin"))
    self.assertNotIn(("GET", "/"), site.log)

  def test_form_action_outside_the_target_base_is_skipped(self):
    base = HOST + "/app"
    site = FakeSite({
      "/app/auth/login/": (200, AUDIT_FORM.replace('action="/signin"', 'action="/other/login"'))},
      target=base)
    self._login(site, target=base)
    self.assertTrue(all(key != "/other/login" for key, _, _ in site.posts))

  def test_basic_challenge_diagnostic(self):
    site = FakeSite({"/": (401, "", {"WWW-Authenticate": 'Basic realm="x"'})})
    mgr, session = self._login(site)
    self.assertIsNone(session)
    self.assertEqual(mgr._auth_diagnostics[-1]["stage"], "basic_challenge")

  def test_failed_login_redirected_back_to_the_login_page_is_rejected(self):
    form = AUDIT_FORM.replace('action="/signin"', 'action="/login_check"')
    site = FakeSite({"/auth/login/": (200, form), "/login": (200, form)})
    real_post = site.post

    def post(url, **kw):
      real_post(url, **kw)
      site.cookies["sid"] = "pre"
      return FakeResp(302, "", {"Location": "/auth/login/"}, HOST + "/login_check")
    site.post = post
    _, session = self._login(site)
    self.assertIsNone(session)

  def test_failed_login_back_to_a_redirected_login_page_is_rejected(self):
    """The page is where the form was served (after redirects), not the URL asked for."""
    form = AUDIT_FORM.replace('action="/signin"', 'action="/login_check"')
    site = FakeSite({"/auth/login/": (302, "", {"Location": "/login"}), "/login": (200, form)})
    real_post = site.post

    def post(url, **kw):
      real_post(url, **kw)
      site.cookies["sid"] = "pre"
      return FakeResp(302, "", {"Location": "/login"}, HOST + "/login_check")
    site.post = post
    _, session = self._login(site)
    self.assertIsNone(session)

  def test_a_transport_error_on_the_form_page_is_retryable_and_not_cached(self):
    import requests
    site = FakeSite({"/": (200, "x"), "/login": (200, AUDIT_FORM), "/dashboard": DASHBOARD})
    real_get, failed = site.get, []

    def flaky_once(url, **kw):
      if url.endswith("/login") and not failed:
        failed.append(url)
        raise requests.ConnectionError("reset")
      return real_get(url, **kw)
    site.get = flaky_once
    mgr, patcher = _manager(site)
    self.addCleanup(patcher.stop)
    self.assertEqual(mgr._try_login_attempt(_creds(site)), (None, True))  # retryable
    self.assertIsNone(mgr._login_target)  # no miss cached
    session, _ = mgr._try_login_attempt(_creds(site))
    self.assertIsNotNone(session)

  def test_the_forms_own_token_is_posted_not_another_forms(self):
    news = ('<form method="post" action="/news"><input type="hidden" name="_token" value="NEWS">'
            '<input name="email"></form>')
    login = AUDIT_FORM.replace('<input name="user_login">',
                               '<input type="hidden" name="_token" value="LOGIN"><input name="user_login">')
    site = FakeSite({"/auth/login/": (200, news + login), "/dashboard": DASHBOARD})
    self._login(site)
    self.assertEqual(site.posts[0][1]["_token"], "LOGIN")

  def test_another_forms_token_of_a_different_name_is_not_sent(self):
    news = ('<form method="post" action="/news"><input type="hidden" '
            'name="csrfmiddlewaretoken" value="NEWS"><input name="email"></form>')
    login = AUDIT_FORM.replace('<input name="user_login">',
                               '<input type="hidden" name="_token" value="LOGIN"><input name="user_login">')
    site = FakeSite({"/auth/login/": (200, news + login), "/dashboard": DASHBOARD})
    headers = []
    real_post = site.post

    def post(url, **kw):
      headers.append(kw.get("headers") or {})
      return real_post(url, **kw)
    site.post = post
    self._login(site)
    self.assertNotIn("csrfmiddlewaretoken", site.posts[0][1])
    self.assertEqual(headers[0].get("X-CSRFToken"), "LOGIN")

  def test_failed_login_back_to_the_login_page_with_a_query_is_rejected(self):
    form = AUDIT_FORM.replace('action="/signin"', 'action="/login"')
    site = FakeSite({"/auth/login/": (302, "", {"Location": "/login"}), "/login": (200, form),
                     "/login?error": (200, form)})
    real_post = site.post

    def post(url, **kw):
      real_post(url, **kw)
      site.cookies["JSESSIONID"] = "pre"
      return FakeResp(302, "", {"Location": "/login?error"}, HOST + "/login")
    site.post = post
    _, session = self._login(site)
    self.assertIsNone(session)

  def test_a_root_action_login_reaching_a_page_with_a_password_widget_succeeds(self):
    form = AUDIT_FORM.replace('action="/signin"', 'action="/"')
    site = FakeSite({
      "/": (200, form),
      "/dashboard": (200, '<form><input type="password" name="new"></form>')})
    _, session = self._login(site)
    self.assertIsNotNone(session)

  def test_search_is_capped_and_a_miss_is_cached(self):
    links = "".join(f'<a href="/login/{i}">x</a>' for i in range(5))
    site = FakeSite({"/": (200, links)})
    mgr, session = self._login(site)
    self.assertIsNone(session)
    self.assertEqual(len(site.log), MAX_LOGIN_SEARCH_FETCHES)
    self.assertEqual(site.posts, [])
    self.assertEqual(mgr._login_target, LOGIN_NOT_FOUND)
    self.assertEqual(mgr._auth_diagnostics[-1]["stage"], "login_form_not_found")
    site.log.clear()
    self.assertIsNone(mgr._try_login_attempt(_creds(site))[0])
    self.assertEqual(site.log, [])  # second attempt sends nothing

  def test_found_target_is_reused_without_a_new_search(self):
    site = FakeSite({"/": (200, '<a href="/signin">in</a>'), "/signin": (200, AUDIT_FORM),
                     "/dashboard": DASHBOARD})
    mgr, session = self._login(site)
    self.assertIsNotNone(session)
    site.log.clear()
    self.assertIsNotNone(mgr._try_login_attempt(_creds(site))[0])
    self.assertEqual(site.log[0], ("GET", "/signin"))
    self.assertNotIn(("GET", "/"), site.log)

  def test_307_is_not_replayed(self):
    site = FakeSite({"/auth/login/": (200, AUDIT_FORM)})
    site.post_status = 307
    _, session = self._login(site)
    self.assertIsNone(session)
    self.assertEqual(site.log, [("GET", "/auth/login/"), ("POST", "/signin")])

  def test_override_path_is_honoured_with_no_search(self):
    site = FakeSite({"/": (200, AUDIT_FORM)})
    cfg = GrayboxTargetConfig(login_path="/custom/login")
    _, session = self._login(site, cfg)
    self.assertIsNone(session)
    self.assertEqual(site.log, [("GET", "/custom/login")])

  def test_override_field_names_beat_detection(self):
    site = FakeSite({"/auth/login/": (200, AUDIT_FORM), "/dashboard": DASHBOARD})
    cfg = GrayboxTargetConfig(username_field="nonce", password_field="user_pass")
    site.user = "alice"
    _, session = self._login(site, cfg)
    self.assertIsNotNone(session)
    self.assertEqual(site.posts[0][1]["nonce"], "alice")
    self.assertNotIn("user_login", site.posts[0][1])

  def test_configured_page_without_a_form_keeps_the_legacy_post(self):
    site = FakeSite({"/auth/login/": (200, "<p>js app</p>"), "/dashboard": DASHBOARD})
    _, session = self._login(site)
    self.assertIsNotNone(session)
    self.assertEqual(site.log[:2], [("GET", "/auth/login/"), ("POST", "/auth/login/")])
    self.assertEqual(site.posts[0][1], {"username": "alice", "password": "pw"})

  def test_off_origin_form_action_never_gets_credentials(self):
    evil = AUDIT_FORM.replace('action="/signin"', 'action="https://evil.example/in"')
    site = FakeSite({"/auth/login/": (200, evil), "/dashboard": DASHBOARD})
    self._login(site)
    self.assertTrue(all(key == "/auth/login/" for key, _, _ in site.posts))

  def test_login_post_to_the_login_page_is_judged_after_write_back(self):
    """A probe path redirecting to the detected login page is not a session."""
    site = FakeSite({
      "/": (200, '<a href="/signin">in</a>'), "/signin": (200, AUDIT_FORM),
      "/dashboard": DASHBOARD, "/account": (302, "", {"Location": "/signin"})})
    cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(
      auth=AuthDescriptor(auth_type="form", authenticated_probe_path="/account")))
    mgr, session = self._login(site, cfg)
    self.assertIsNone(session)
    self.assertEqual(mgr._auth_diagnostics[-1]["stage"], "authenticated_probe_redirect")


class TestFormPreflight(unittest.TestCase):

  def _preflight(self, cfg, status):
    site = FakeSite({"/": (200, "x")})
    sess = site.session()
    sess.head = lambda url, **kw: FakeResp(200, "", {}, url)
    sess.get = lambda url, **kw: FakeResp(status, "", {}, url)
    strategy = FormAuth(HOST, cfg, http_client=object())
    with patch.object(FormAuth, "make_session", lambda self: sess):
      return strategy.preflight()

  def test_default_path_404_is_not_an_error(self):
    self.assertIsNone(self._preflight(GrayboxTargetConfig(), 404))


class TestBasicAuth(unittest.TestCase):

  def test_dispatch_and_header(self):
    cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(
      auth=AuthDescriptor(auth_type="basic", authenticated_probe_path="/me")))
    mgr = AuthManager(HOST, cfg, verify_tls=False)
    strategy = mgr._build_strategy()
    self.assertIsInstance(strategy, BasicAuth)
    session = strategy.authenticate(
      SimpleNamespace(username="u", password="p:w", has_form_credentials=lambda: True))
    self.assertEqual(session.headers["Authorization"], "Basic dTpwOnc=")
    self.assertIsNone(strategy.authenticate(
      SimpleNamespace(username="", password="", has_form_credentials=lambda: False)))
