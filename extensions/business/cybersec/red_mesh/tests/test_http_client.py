import ast
from pathlib import Path
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.http_client import (
  GrayboxHttpClient,
  GrayboxScopeError,
  normalize_request_url,
  path_in_scope,
  validate_target_config_paths,
)


class TestGrayboxHttpClient(unittest.TestCase):

  def _session(self, response=None):
    session = MagicMock()
    resp = response or MagicMock(status_code=200, headers={})
    session.request.return_value = resp
    return session

  def test_path_prefix_matching_is_segment_aware(self):
    self.assertTrue(path_in_scope("/api/public/users", "/api/public/"))
    self.assertFalse(path_in_scope("/api/publicity", "/api/public/"))

  def test_blocks_cross_host_without_sending_request(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      allowlist=["/api/public/"],
    )
    session = self._session()

    with self.assertRaises(GrayboxScopeError):
      client.request(session, "GET", "https://evil.example/api/public/")

    session.request.assert_not_called()

  def test_blocks_encoded_traversal_without_sending_request(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      allowlist=["/api/public/"],
    )
    session = self._session()

    with self.assertRaises(GrayboxScopeError):
      client.request(session, "GET", "/api/public/%2e%2e/admin/")

    session.request.assert_not_called()

  def test_blocks_publicity_when_public_scope_authorized(self):
    client = GrayboxHttpClient(
      "https://api.example.com",
      allowlist=["/api/public/"],
    )
    session = self._session()

    with self.assertRaises(GrayboxScopeError):
      client.request(session, "GET", "/api/publicity")

    session.request.assert_not_called()

  def test_allows_in_scope_templated_launch_path(self):
    errors = validate_target_config_paths(
      "https://api.example.com",
      {
        "login_path": "/api/public/login/",
        "logout_path": "/api/public/logout/",
        "api_security": {
          "object_endpoints": [
            {"path": "/api/public/users/{id}/"},
          ],
        },
      },
      ["/api/public/"],
    )
    self.assertEqual(errors, [])

  def test_blocks_out_of_scope_launch_path(self):
    errors = validate_target_config_paths(
      "https://api.example.com",
      {
        "login_path": "/api/public/login/",
        "logout_path": "/api/public/logout/",
        "api_security": {
          "function_endpoints": [
            {"path": "/admin/export-users/"},
          ],
        },
      },
      ["/api/public/"],
    )
    self.assertTrue(errors)
    self.assertIn("outside authorized scope", errors[0])

  def test_post_redirect_302_converts_to_get_and_drops_body(self):
    """Browser-equivalent 302 handling — Django form-login redirect target
    must not receive the original POST body, or the redirected request
    fails CSRF on the new view (the bug behind official_login_failed)."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/auth/", "/dashboard/"],
    )
    session = MagicMock()
    redirect_resp = MagicMock(
      status_code=302, headers={"Location": "/dashboard/"},
    )
    final_resp = MagicMock(status_code=200, headers={})
    session.request.side_effect = [redirect_resp, final_resp]

    result = client.request(
      session, "POST", "/auth/login/",
      data={"username": "admin", "password": "secret",
            "csrfmiddlewaretoken": "tok"},
      allow_redirects=True,
    )

    self.assertIs(result, final_resp)
    self.assertEqual(session.request.call_count, 2)
    first_call = session.request.call_args_list[0]
    self.assertEqual(first_call.args[0], "POST")
    self.assertIn("login", first_call.args[1])
    self.assertIn("data", first_call.kwargs)

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "GET")
    self.assertIn("dashboard", second_call.args[1])
    self.assertNotIn("data", second_call.kwargs)
    self.assertNotIn("json", second_call.kwargs)

  def test_post_redirect_301_converts_to_get_and_drops_body(self):
    """301 from POST is also browser-equivalent GET (matches `requests`)."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/old/", "/new/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=301, headers={"Location": "/new/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(
      session, "POST", "/old/", data={"k": "v"}, allow_redirects=True,
    )

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "GET")
    self.assertNotIn("data", second_call.kwargs)

  def test_post_redirect_307_preserves_method_and_body(self):
    """307 (and 308) explicitly preserve method + body per RFC 7231."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/api/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=307, headers={"Location": "/api/v2/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(
      session, "POST", "/api/v1/", data={"k": "v"}, allow_redirects=True,
    )

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "POST")
    self.assertEqual(second_call.kwargs.get("data"), {"k": "v"})

  def test_post_redirect_303_still_converts(self):
    """Pre-existing 303 conversion path must keep working (regression guard)."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/api/", "/done/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=303, headers={"Location": "/done/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(
      session, "POST", "/api/", data={"k": "v"}, allow_redirects=True,
    )

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "GET")
    self.assertNotIn("data", second_call.kwargs)

  def test_head_on_302_stays_head(self):
    """HEAD is idempotent + has no body; preserve method on redirect."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/a/", "/b/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=302, headers={"Location": "/b/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(session, "HEAD", "/a/", allow_redirects=True)

    second_call = session.request.call_args_list[1]
    self.assertEqual(second_call.args[0], "HEAD")

  def test_302_without_location_returns_redirect_response(self):
    """No Location header → don't loop; return the redirect response as-is."""
    client = GrayboxHttpClient("https://target.local", allowlist=["/a/"])
    session = MagicMock()
    bad_redirect = MagicMock(status_code=302, headers={})
    session.request.return_value = bad_redirect

    result = client.request(session, "POST", "/a/", allow_redirects=True)

    self.assertIs(result, bad_redirect)
    self.assertEqual(session.request.call_count, 1)

  def test_302_to_out_of_scope_location_raises_scope_error(self):
    """Redirect to a path outside the allowlist must abort, not silently follow."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/auth/"],
    )
    session = MagicMock()
    session.request.return_value = MagicMock(
      status_code=302, headers={"Location": "/admin/secret/"},
    )

    with self.assertRaises(GrayboxScopeError):
      client.request(session, "POST", "/auth/login/", allow_redirects=True)

  def test_redirect_loop_caps_at_five_hops(self):
    """A pathological redirect chain stops after 5 hops, returning the last response."""
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/loop/"],
    )
    session = MagicMock()
    session.request.return_value = MagicMock(
      status_code=302, headers={"Location": "/loop/"},
    )

    result = client.request(
      session, "POST", "/loop/", data={"k": "v"}, allow_redirects=True,
    )

    self.assertEqual(result.status_code, 302)
    self.assertEqual(session.request.call_count, 5)

  def test_chained_302_then_302_after_post_settles_on_get(self):
    """POST→302→GET; subsequent 302→GET stays GET (method conversion is sticky)."""
    client = GrayboxHttpClient(
      "https://target.local",
      allowlist=["/a/", "/b/", "/c/"],
    )
    session = MagicMock()
    session.request.side_effect = [
      MagicMock(status_code=302, headers={"Location": "/b/"}),
      MagicMock(status_code=302, headers={"Location": "/c/"}),
      MagicMock(status_code=200, headers={}),
    ]

    client.request(
      session, "POST", "/a/", data={"k": "v"}, allow_redirects=True,
    )

    self.assertEqual(session.request.call_args_list[0].args[0], "POST")
    self.assertEqual(session.request.call_args_list[1].args[0], "GET")
    self.assertNotIn("data", session.request.call_args_list[1].kwargs)
    self.assertEqual(session.request.call_args_list[2].args[0], "GET")

  def test_a_followed_chain_reports_the_hops_it_consumed(self):
    """`response.history` must carry the redirect chain this client resolved.

    We follow redirects one `allow_redirects=False` hop at a time so every hop
    re-enters `validate_url`. `requests` populates `history` only for chains it
    followed itself, so without an explicit assignment the attribute is
    permanently empty and every caller reading it concludes no redirect
    happened — which is how the login-form check in `_is_login_success` came to
    reject every authenticated session reached via a redirect.
    """
    client = GrayboxHttpClient(
      "https://target.local", allowlist=["/a/", "/b/", "/c/"],
    )
    session = MagicMock()
    first = MagicMock(status_code=302, headers={"Location": "/b/"})
    second = MagicMock(status_code=302, headers={"Location": "/c/"})
    final = MagicMock(status_code=200, headers={})
    session.request.side_effect = [first, second, final]

    result = client.request(session, "GET", "/a/", allow_redirects=True)

    self.assertIs(result, final)
    self.assertEqual(list(result.history), [first, second])

  def test_a_call_that_was_not_redirected_reports_an_empty_chain(self):
    """No redirect means no history — the same answer `requests` gives."""
    client = GrayboxHttpClient("https://target.local", allowlist=["/a/"])
    session = MagicMock()
    final = MagicMock(status_code=200, headers={})
    session.request.side_effect = [final]

    result = client.request(session, "GET", "/a/", allow_redirects=True)

    self.assertEqual(list(result.history), [])

  def test_a_chain_cut_short_by_the_budget_still_reports_its_hops(self):
    """Budget exhaustion returns the last response we did fetch, chain intact."""
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    client = GrayboxHttpClient(
      "https://target.local",
      allowlist=["/a/", "/b/", "/c/"],
      # The probe already paid for hop 0, so nothing is left for the redirect.
      request_budget=RequestBudget(remaining=0, total=1),
    )
    session = MagicMock()
    first = MagicMock(status_code=302, headers={"Location": "/b/"})
    session.request.side_effect = [first]

    result = client.request(session, "GET", "/a/", allow_redirects=True)

    self.assertIs(result, first)
    self.assertEqual(list(result.history), [])

  def test_probe_modules_do_not_call_requests_directly(self):
    root = Path("extensions/business/cybersec/red_mesh/graybox/probes")
    forbidden = {"get", "post", "put", "patch", "delete", "head", "options", "request"}
    violations = []
    for path in sorted(root.glob("*.py")):
      tree = ast.parse(path.read_text(), filename=str(path))
      for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
          continue
        func = node.func
        if (
          isinstance(func, ast.Attribute)
          and isinstance(func.value, ast.Name)
          and func.value.id == "requests"
          and func.attr in forbidden
        ):
          violations.append(f"{path}:{node.lineno}: requests.{func.attr}")
    self.assertEqual(violations, [])


class TestRequestUrlBasePathMatrix(unittest.TestCase):
  """
  Base path x link type. `normalize_request_url` resolved every relative link
  against the *origin*, discarding any base path in the target URL, while
  `discovery.py:181` resolved the same link with `urljoin` against the base.
  One link therefore produced two different URLs depending on which path
  handled it.

  Measured before the fix: 10 of 24 combinations diverged, and every one of them
  was a target carrying a base path. Scanning `https://host/app`, a relative
  link `users` was requested at `https://host/users` — which 404s, so the probe
  reports "not vulnerable" for an endpoint it never reached. A false-negative
  generator, invisible whenever the test target is a bare host, which is why it
  survived.

  Root-relative links (`/users`) must stay origin-relative; that is RFC 3986 and
  those cases were already correct.
  """

  BASES = ("https://h", "https://h/", "https://h/app", "https://h/app/")

  # (link, expected path for a bare-origin base, expected path under /app)
  LINKS = (
    ("users", "/users", "/app/users"),
    ("./users", "/users", "/app/users"),
    ("sub/users", "/sub/users", "/app/sub/users"),
    ("users?q=1", "/users?q=1", "/app/users?q=1"),
    # Root-relative and absolute forms ignore the base path, by spec.
    ("/users", "/users", "/users"),
    ("https://h/users", "/users", "/users"),
  )

  def test_a_relative_link_resolves_against_the_targets_base_path(self):
    for base in self.BASES:
      has_base_path = "/app" in base
      for link, bare_expected, app_expected in self.LINKS:
        expected = app_expected if has_base_path else bare_expected
        with self.subTest(base=base, link=link):
          self.assertEqual(
            normalize_request_url(base, link),
            f"https://h{expected}",
          )

  # (link, expected path for a bare-origin base, expected path under /app).
  # A parent-relative link is ordinary RFC 3986 resolution and `discovery.py`
  # produces them routinely. Treating a literal `..` as an attack rejected them
  # outright, so the probe reported "not vulnerable" for an endpoint it had
  # refused to request — the same false-negative class the base-path fix above
  # exists to remove, arrived at from the other direction.
  PARENT_LINKS = (
    ("../users", "/users", "/users"),
    ("../../users", "/users", "/users"),
    ("a/../b", "/b", "/app/b"),
    ("./../x", "/x", "/x"),
  )

  def test_a_parent_relative_link_resolves_rather_than_being_refused(self):
    for base in self.BASES:
      has_base_path = "/app" in base
      for link, bare_expected, app_expected in self.PARENT_LINKS:
        expected = app_expected if has_base_path else bare_expected
        with self.subTest(base=base, link=link):
          self.assertEqual(
            normalize_request_url(base, link),
            f"https://h{expected}",
          )

  def test_traversal_past_the_root_clamps_on_origin_instead_of_escaping(self):
    # The property that makes allowing `..` safe: it cannot change the netloc,
    # which is what enforces scope. `urljoin` clamps at the origin root.
    self.assertEqual(
      normalize_request_url("https://h/app/", "../../../../etc/passwd"),
      "https://h/etc/passwd",
    )

  def test_encoded_traversal_is_still_refused(self):
    # These survive `urljoin` untouched and reach the server as a literal
    # payload for it to decode. Following a discovered link never needs them.
    for hostile in ("%2e%2e/users", "..%2fusers", "%252e%252e/users",
                    "%2E%2E/users", "a/%2e%2e/b"):
      for base in self.BASES:
        with self.subTest(base=base, link=hostile):
          with self.assertRaises(GrayboxScopeError):
            normalize_request_url(base, hostile)

  def test_cross_origin_is_still_refused(self):
    for base in self.BASES:
      for hostile in ("https://evil.test/users", "http://h/users", "https://h:8443/users"):
        with self.subTest(base=base, link=hostile):
          with self.assertRaises(GrayboxScopeError):
            normalize_request_url(base, hostile)

  def test_the_base_path_was_never_the_scope_boundary(self):
    """`..` and `/` are two spellings of the same reach, and `/` was always allowed.

    A root-relative link left the base path unconditionally — `/etc/passwd` from
    a `https://h/app` target resolved and was requested. Refusing `../etc/passwd`
    while permitting `/etc/passwd` did not constrain anything; it only made the
    two spellings disagree, and rejected the one `discovery.py` emits. What
    actually bounds a scan by path is the allowlist, enforced in
    `GrayboxHttpClient.request` against `path_in_scope`.
    """
    self.assertEqual(
      normalize_request_url("https://h/app", "../../etc/passwd"),
      normalize_request_url("https://h/app", "/etc/passwd"),
    )

  def test_the_allowlist_is_what_refuses_a_path_outside_the_scan_scope(self):
    from extensions.business.cybersec.red_mesh.graybox.http_client import (
      path_in_scope, path_scopes_from_allowlist,
    )
    scopes = path_scopes_from_allowlist("https://h/app", ["https://h/app"])
    self.assertTrue(scopes, "no path scope was derived from the allowlist")
    self.assertTrue(any(path_in_scope("/app/users", scope) for scope in scopes))
    self.assertFalse(any(path_in_scope("/etc/passwd", scope) for scope in scopes))


class TestRedirectHopBudgetAccounting(unittest.TestCase):
  """
  A probe consults the shared budget once per logical call, then
  `GrayboxHttpClient.request` follows up to five redirects — each a real HTTP
  request that nobody counted. Measured: one redirecting call issued 5 requests
  against a single consume, so `budget_remaining` over-reported by 4 and the cap
  that exists to stop the scanner DoSing a target could be exceeded five-fold by
  a target that simply redirects.

  Only the *extra* hops are charged here. The probe's own consume covers the
  first request, so charging it again would double-count every ordinary call.
  """

  def _redirecting_session(self, hops):
    calls = {"n": 0}
    def fake_request(method, url, **kwargs):
      calls["n"] += 1
      resp = MagicMock()
      if calls["n"] <= hops:
        resp.status_code = 302
        resp.headers = {"Location": f"/hop{calls['n']}"}
      else:
        resp.status_code = 200
        resp.headers = {}
      return resp
    session = MagicMock()
    session.request.side_effect = fake_request
    return session, calls

  def test_every_redirect_hop_is_charged_to_the_budget(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    budget = RequestBudget(remaining=10, total=10)
    client = GrayboxHttpClient("https://h", allowlist=["h"], request_budget=budget)
    session, calls = self._redirecting_session(hops=4)
    client.request(session, "GET", "https://h/start", allow_redirects=True)
    # 5 real requests: the first plus 4 hops. The probe would have consumed the
    # first, so the client charges the 4 extra.
    self.assertEqual(calls["n"], 5)
    self.assertEqual(budget.remaining, 10 - 4)

  def test_a_chain_stops_when_the_budget_runs_out(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    budget = RequestBudget(remaining=2, total=10)
    client = GrayboxHttpClient("https://h", allowlist=["h"], request_budget=budget)
    session, calls = self._redirecting_session(hops=4)
    client.request(session, "GET", "https://h/start", allow_redirects=True)
    # First request, then only as many hops as the budget covers.
    self.assertEqual(calls["n"], 3)
    self.assertEqual(budget.remaining, 0)
    self.assertGreaterEqual(budget.exhausted_count, 1)

  def test_a_non_redirecting_call_is_not_charged(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    budget = RequestBudget(remaining=10, total=10)
    client = GrayboxHttpClient("https://h", allowlist=["h"], request_budget=budget)
    session, calls = self._redirecting_session(hops=0)
    client.request(session, "GET", "https://h/start", allow_redirects=True)
    self.assertEqual(calls["n"], 1)
    self.assertEqual(budget.remaining, 10, "the probe already paid for this one")

  def test_the_cleanup_path_is_exempt(self):
    # Budget exhaustion must never prevent a revert, which is the existing
    # contract of ProbeBase.cleanup_budget.
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
    budget = RequestBudget(remaining=0, total=10)
    client = GrayboxHttpClient("https://h", allowlist=["h"], request_budget=budget)
    session, calls = self._redirecting_session(hops=2)
    client.request(session, "GET", "https://h/revert", allow_redirects=True,
                   budget_exempt=True)
    self.assertEqual(calls["n"], 3, "a revert was blocked by an exhausted budget")

  def test_it_works_without_a_budget_configured(self):
    client = GrayboxHttpClient("https://h", allowlist=["h"])
    session, calls = self._redirecting_session(hops=2)
    client.request(session, "GET", "https://h/start", allow_redirects=True)
    self.assertEqual(calls["n"], 3)


if __name__ == "__main__":
  unittest.main()
