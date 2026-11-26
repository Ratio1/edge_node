"""Tests for DiscoveryModule."""

import unittest
from collections import deque
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.graybox.discovery import DiscoveryModule, _RouteParser
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig, DiscoveryConfig,
)
from extensions.business.cybersec.red_mesh.graybox.models import DiscoveryResult, InjectionCandidate


def _mock_response(status=200, text="", content_type="text/html"):
  resp = MagicMock()
  resp.status_code = status
  resp.text = text
  resp.headers = {"Content-Type": content_type}
  return resp


def _make_discovery(scope_prefix="", max_pages=50, max_depth=3, routes_html=None,
                    target_url="http://testapp.local:8000", logout_path=None):
  """Build a DiscoveryModule with mocked HTTP."""
  cfg = GrayboxTargetConfig(
    discovery=DiscoveryConfig(scope_prefix=scope_prefix, max_pages=max_pages, max_depth=max_depth),
    **({"logout_path": logout_path} if logout_path else {}),
  )
  auth = MagicMock()
  safety = MagicMock()
  safety.throttle = MagicMock()

  # Build mock session that returns different HTML per path
  session = MagicMock()
  routes_html = routes_html or {}

  def mock_get(url, **kwargs):
    for path, html in routes_html.items():
      if url.endswith(path) or url == "http://testapp.local:8000" + path:
        return _mock_response(text=html)
    return _mock_response(text="<html></html>")

  session.get.side_effect = mock_get
  auth.primary_session = session
  auth.anon_session = session

  disc = DiscoveryModule(
    target_url=target_url,
    auth_manager=auth,
    safety=safety,
    target_config=cfg,
  )
  return disc


class TestDiscoveryModule(unittest.TestCase):

  def test_same_origin_only(self):
    """External links are ignored."""
    disc = _make_discovery(routes_html={
      "/": '<a href="/about/">About</a><a href="https://evil.com/steal">Evil</a>',
    })
    routes, forms = disc.discover()
    self.assertIn("/about/", routes)
    # No external domain route
    for r in routes:
      self.assertFalse(r.startswith("http"), f"External route leaked: {r}")

  def test_scope_prefix(self):
    """Only routes under prefix are discovered."""
    disc = _make_discovery(
      scope_prefix="/api/",
      routes_html={
        "/": '<a href="/api/users/">Users</a><a href="/admin/">Admin</a>',
      },
    )
    # Root "/" is outside scope but is the seed — it will be visited
    # because it's the starting point. But discovered links outside scope are not followed.
    routes, forms = disc.discover()
    # /api/users/ should be in routes (it's in scope)
    self.assertIn("/api/users/", routes)
    # /admin/ should NOT be in routes (out of scope)
    self.assertNotIn("/admin/", routes)

  def test_scope_prefix_traversal(self):
    """Path traversal /api/../admin/ is normalized and blocked."""
    disc = _make_discovery(
      scope_prefix="/api/",
      routes_html={
        "/api/": '<a href="/api/../admin/secrets">Traversal</a><a href="/api/data/">Data</a>',
      },
    )
    routes, forms = disc.discover(["/api/"])
    # /admin/secrets should be blocked (normalized from /api/../admin/secrets)
    self.assertNotIn("/admin/secrets", routes)

  def test_max_pages(self):
    """Stops after page limit."""
    # Create a chain of pages that would go forever
    html_map = {}
    for i in range(100):
      html_map[f"/page/{i}/"] = f'<a href="/page/{i+1}/">Next</a>'

    disc = _make_discovery(max_pages=5, routes_html=html_map)
    routes, _ = disc.discover(["/page/0/"])
    # Should stop at 5 pages
    self.assertLessEqual(len(routes), 5)

  def test_max_depth(self):
    """Stops at depth limit."""
    disc = _make_discovery(
      max_depth=1,
      routes_html={
        "/": '<a href="/level1/">L1</a>',
        "/level1/": '<a href="/level1/level2/">L2</a>',
        "/level1/level2/": '<a href="/level1/level2/level3/">L3</a>',
      },
    )
    routes, _ = disc.discover()
    self.assertIn("/level1/", routes)
    # level2 should NOT be discovered (depth 2 > max_depth 1)
    self.assertNotIn("/level1/level2/", routes)

  def test_form_actions_recorded_not_followed(self):
    """Forms are collected but their actions are not visited."""
    disc = _make_discovery(routes_html={
      "/": '<form action="/api/submit/"></form><a href="/about/">About</a>',
    })
    routes, forms = disc.discover()
    self.assertIn("/api/submit/", forms)
    self.assertIn("/about/", routes)

  def test_discover_result_returns_typed_payload(self):
    disc = _make_discovery(routes_html={
      "/": '<a href="/about/">About</a><form action="/api/submit/"></form>',
    })
    result = disc.discover_result()
    self.assertIsInstance(result, DiscoveryResult)
    self.assertIn("/about/", result.routes)
    self.assertIn("/api/submit/", result.forms)

  def test_known_routes_included(self):
    """User-supplied routes are added to BFS queue."""
    disc = _make_discovery(routes_html={
      "/custom/": '<a href="/custom/sub/">Sub</a>',
    })
    routes, _ = disc.discover(known_routes=["/custom/"])
    self.assertIn("/custom/", routes)

  def test_empty_html(self):
    """Pages with no links still appear in routes."""
    disc = _make_discovery(routes_html={
      "/": '<html><body>Hello</body></html>',
    })
    routes, _ = disc.discover()
    self.assertIn("/", routes)
    self.assertEqual(len(routes), 1)

  def test_non_html_skipped(self):
    """Non-HTML responses are added to routes but not parsed."""
    cfg = GrayboxTargetConfig(discovery=DiscoveryConfig())
    auth = MagicMock()
    safety = MagicMock()
    session = MagicMock()

    def mock_get(url, **kwargs):
      if "/api/data" in url:
        return _mock_response(text='{"key": "value"}', content_type="application/json")
      return _mock_response(text='<a href="/api/data">API</a>')

    session.get.side_effect = mock_get
    auth.primary_session = session
    auth.anon_session = session

    disc = DiscoveryModule("http://testapp.local:8000", auth, safety, cfg)
    routes, _ = disc.discover()
    self.assertIn("/api/data", routes)


class TestRouteParser(unittest.TestCase):

  def test_extracts_links_and_forms(self):
    """Parser extracts href and form action."""
    parser = _RouteParser()
    parser.feed('<a href="/page1/">P1</a><form action="/submit/"></form>')
    self.assertEqual(parser.links, ["/page1/"])
    self.assertEqual(parser.forms, ["/submit/"])

  def test_ignores_empty_href(self):
    """Links without href are ignored."""
    parser = _RouteParser()
    parser.feed('<a class="btn">No href</a>')
    self.assertEqual(parser.links, [])


class TestNormalize(unittest.TestCase):

  def test_javascript_ignored(self):
    """javascript: links return empty string."""
    disc = _make_discovery()
    self.assertEqual(disc._normalize("javascript:void(0)"), "")

  def test_mailto_ignored(self):
    disc = _make_discovery()
    self.assertEqual(disc._normalize("mailto:a@b.com"), "")

  def test_hash_ignored(self):
    disc = _make_discovery()
    self.assertEqual(disc._normalize("#section"), "")

  def test_relative_path(self):
    disc = _make_discovery()
    result = disc._normalize("/api/users/")
    self.assertEqual(result, "/api/users/")

  def test_dotdot_collapsed(self):
    """.. segments are collapsed."""
    disc = _make_discovery()
    result = disc._normalize("/api/../admin/")
    self.assertEqual(result, "/admin/")

  def test_external_rejected(self):
    """External domain links return empty."""
    disc = _make_discovery()
    result = disc._normalize("https://other.com/path")
    self.assertEqual(result, "")


class TestABasePathTargetIsNotCrawledTwice(unittest.TestCase):
  """
  `_normalize` resolves a link against the target's base, so the paths the BFS
  queues already contain that base. Concatenating them back onto `target_url`
  doubled it — `https://h/app` + `/app/users` -> `https://h/app/app/users` —
  and the client's absolute-URL branch preserves whatever path it is handed, so
  every crawl request against a base-path target 404'd and discovery silently
  reported fewer routes than exist.

  Every other test in this file targets a bare host, where the base is empty and
  the doubling cannot appear. That is why the defect survived.
  """

  def _crawl_a_base_path_target(self):
    cfg = GrayboxTargetConfig(discovery=DiscoveryConfig())
    auth = MagicMock()
    safety = MagicMock()
    requested = []

    def mock_get(url, **kwargs):
      requested.append(url)
      if url == "http://testapp.local:8000/app/":
        return _mock_response(text='<a href="users">Users</a>')
      return _mock_response(text="<html></html>")

    session = MagicMock()
    session.get.side_effect = mock_get
    auth.primary_session = session
    auth.anon_session = session

    disc = DiscoveryModule(
      target_url="http://testapp.local:8000/app",
      auth_manager=auth,
      safety=safety,
      target_config=cfg,
    )
    routes, _forms = disc.discover()
    return routes, requested

  def test_no_requested_url_repeats_the_base_path(self):
    _routes, requested = self._crawl_a_base_path_target()
    doubled = [url for url in requested if "/app/app/" in url]
    self.assertEqual(
      doubled, [],
      "the base path was concatenated onto a path that already carried it",
    )

  def test_the_discovered_route_is_actually_fetched(self):
    routes, requested = self._crawl_a_base_path_target()
    self.assertIn("/app/users", routes)
    self.assertIn(
      "http://testapp.local:8000/app/users", requested,
      "the crawl queued the route but never requested it at its real URL",
    )



class TestDiscoveryNeverVisitsLogout(unittest.TestCase):
  """RM-219: a GET of the logout URL would end the scan session."""

  def test_logout_link_and_configured_route_are_not_fetched(self):
    disc = _make_discovery(routes_html={
      "/": '<a href="/auth/logout/">Log out</a><a href="/about/">About</a>',
    })
    routes, _ = disc.discover()
    fetched = [c.args[0] for c in disc.auth.primary_session.get.call_args_list]
    self.assertFalse(any(u.endswith("/auth/logout/") for u in fetched), fetched)
    self.assertNotIn("/auth/logout/", routes)
    self.assertIn("/about/", routes)

    disc = _make_discovery()
    disc.discover_result(known_routes=["/auth/logout/"])
    fetched = [c.args[0] for c in disc.auth.primary_session.get.call_args_list]
    self.assertFalse(any(u.endswith("/auth/logout/") for u in fetched), fetched)

  def test_logout_forms_and_slashless_logout_links_are_dropped(self):
    """`/auth/logout` equals `/auth/logout/`; a logout form action is not a target."""
    disc = _make_discovery(routes_html={
      "/": '<a href="/auth/logout">Out</a><a href="/about/">About</a>'
           '<form action="/auth/logout"></form><form action="/auth/logout/"></form>'
           '<form action="/profile/"></form>',
    })
    routes, forms = disc.discover()
    fetched = [c.args[0] for c in disc.auth.primary_session.get.call_args_list]
    self.assertFalse(any("logout" in u for u in fetched), fetched)
    self.assertFalse(any("logout" in r for r in routes), routes)
    self.assertEqual(forms, ["/profile/"])


if __name__ == '__main__':
  unittest.main()


def _spec_discovery(responses, **kw):
  """DiscoveryModule whose GET answers come from {path: (status, text, ctype)}."""
  disc = _make_discovery(**kw)
  session = disc.auth.primary_session
  requested = disc.requested = []

  def mock_get(url, **kwargs):
    path = url.replace("http://testapp.local:8000", "")
    requested.append(url)
    if path in responses:
      status, text, ctype, *extra = responses[path]
      resp = _mock_response(status=status, text=text, content_type=ctype)
      if extra:
        resp.headers["Location"] = extra[0]
      if "json" not in ctype:
        resp.json = MagicMock(side_effect=ValueError)
      elif text == "DEEP":
        resp.json = MagicMock(side_effect=RecursionError)
      else:
        resp.json = MagicMock(return_value=__import__("json").loads(text))
      return resp
    return _mock_response(status=404, text="nope", content_type="text/plain")

  session.get.side_effect = mock_get
  return disc


class TestDiscoverySeedsAndCandidates(unittest.TestCase):
  """RM-060 Phase B: robots/sitemap/OpenAPI/forms/query params feed injection."""

  def test_robots_disallow_paths_become_routes_in_scope_only(self):
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/robots.txt": (200, "User-agent: *\nDisallow: /secret/\nDisallow: /admin/*\n"
                           "Disallow: /\n", "text/plain"),
      "/secret/": (200, "<html></html>", "text/html"),
      "/admin/": (200, "<html></html>", "text/html"),
    })
    result = disc.discover_result()
    self.assertIn("/secret/", result.routes)
    self.assertIn("/admin/", result.routes)

  def test_robots_respects_scope_prefix(self):
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/robots.txt": (200, "Disallow: /secret/\nDisallow: /api/x/\n", "text/plain"),
      "/secret/": (200, "<html></html>", "text/html"),
      "/api/x/": (200, "<html></html>", "text/html"),
    }, scope_prefix="/api/")
    result = disc.discover_result()
    self.assertIn("/api/x/", result.routes)
    self.assertNotIn("/secret/", result.routes)

  def test_sitemap_and_index_one_level_same_origin_only(self):
    idx = ('<sitemapindex><sitemap><loc>http://testapp.local:8000/sm1.xml</loc></sitemap>'
           '<sitemap><loc>http://evil.example.com/sm2.xml</loc></sitemap></sitemapindex>')
    sm1 = ('<urlset><url><loc>http://testapp.local:8000/shop/?q=1</loc></url>'
           '<url><loc>http://evil.example.com/off</loc></url></urlset>')
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/sitemap.xml": (200, idx, "application/xml"),
      "/sm1.xml": (200, sm1, "application/xml"),
      "/shop/": (200, "<html></html>", "text/html"),
    })
    result = disc.discover_result()
    self.assertIn("/shop/", result.routes)
    self.assertFalse([r for r in result.routes if "evil" in r or r == "/off"])
    self.assertIn(InjectionCandidate(path="/shop/", param="q"),
                  result.candidates)

  def test_failed_seed_fetches_are_counted_not_fatal(self):
    disc = _spec_discovery({
      "/": (200, "<html><a href='/x/'>x</a></html>", "text/html"),
      "/sitemap.xml": (200, "<html>not xml</html>", "text/html"),
      "/x/": (200, "<html></html>", "text/html"),
    })
    result = disc.discover_result()
    self.assertIn("/x/", result.routes)
    self.assertGreaterEqual(result.fetch_failures, 2)  # robots 404 + non-XML sitemap

  def test_get_form_inputs_and_link_query_become_candidates(self):
    html = ('<a href="/s/?term=a&page=2">s</a>'
            '<form action="/find/" method="get"><input name="q" type="text">'
            '<input name="go" type="submit"><input name="tok" type="hidden"></form>'
            '<form action="/post/" method="post"><input name="body" type="text"></form>')
    disc = _spec_discovery({"/": (200, html, "text/html")})
    result = disc.discover_result()
    got = {(c.path, c.param) for c in result.candidates}
    self.assertIn(("/find/", "q"), got)
    self.assertIn(("/s/", "term"), got)
    self.assertIn(("/s/", "page"), got)
    self.assertNotIn(("/post/", "body"), got)  # no stateful form candidates
    self.assertNotIn(("/find/", "go"), got)
    self.assertTrue(all(c.source == "discovered" for c in result.candidates))

  def test_openapi_get_paths_and_params_become_candidates(self):
    import json
    spec = json.dumps({"openapi": "3.0.0", "paths": {
      "/api/search": {"get": {"parameters": [
        {"name": "text", "in": "query"}, {"name": "h", "in": "header"}]}},
      "/api/item/{id}": {"get": {"parameters": [{"name": "x", "in": "query"}]}},
      "/api/make": {"post": {"parameters": [{"name": "y", "in": "query"}]}},
    }})
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/openapi.json": (200, spec, "application/json"),
      "/api/search": (200, "{}", "text/plain"),
    })
    result = disc.discover_result()
    got = {(c.path, c.param) for c in result.candidates}
    self.assertEqual(got, {("/api/search", "text")})
    self.assertIn("/api/search", result.routes)

  def test_json_links_and_their_query_parameters_become_targets(self):
    import json
    body = json.dumps({"data": [{"self": "/api/items?page=2&sort=asc"},
                                {"ext": "https://evil.example/x?y=1"},
                                {"abs": "http://testapp.local:8000/api/more?q=1"}],
                       "title": "not a link"})
    disc = _spec_discovery({
      "/": (200, '<a href="/api/list">l</a>', "text/html"),
      "/api/list": (200, body, "application/json"),
      "/api/items": (200, "<html></html>", "text/html"),
      "/api/more": (200, "<html></html>", "text/html"),
    })
    result = disc.discover_result()
    got = {(c.path, c.param) for c in result.candidates}
    self.assertEqual(got, {("/api/items", "page"), ("/api/items", "sort"), ("/api/more", "q")})
    self.assertIn("/api/items", result.routes)
    self.assertIn("/api/more", result.routes)
    self.assertFalse([u for u in disc.requested if "evil" in u])

  def test_json_walk_is_bounded(self):
    nested = cur = {}
    for _ in range(20):
      cur["k"] = cur = {}
    cur["k"] = "/too-deep"
    wide = {"l": [f"/p{i}" for i in range(600)]}
    disc = _make_discovery()
    for body in (nested, wide):
      resp = MagicMock()
      resp.json.return_value = body
      links = disc._json_links(resp)
      self.assertNotIn("/too-deep", links)
      self.assertLessEqual(len(links), 500)

  def test_openapi_path_level_query_parameters(self):
    spec = _openapi_spec({"/api/s": {
      "parameters": [{"name": "shared", "in": "query"}, {"name": "h", "in": "header"}],
      "get": {"parameters": [{"name": "own", "in": "query"}]}}})
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/openapi.json": (200, spec, "application/json"),
      "/api/s": (200, "{}", "text/plain"),
    })
    got = {(c.path, c.param) for c in disc.discover_result().candidates}
    self.assertEqual(got, {("/api/s", "shared"), ("/api/s", "own")})

  def test_seeds_stay_within_max_pages(self):
    sm = "<urlset>" + "".join(
      f"<url><loc>http://testapp.local:8000/p{i}/</loc></url>" for i in range(30)
    ) + "</urlset>"
    resp = {"/": (200, "<html></html>", "text/html"),
            "/sitemap.xml": (200, sm, "application/xml")}
    for i in range(30):
      resp[f"/p{i}/"] = (200, "<html></html>", "text/html")
    disc = _spec_discovery(resp, max_pages=5)
    result = disc.discover_result()
    self.assertLessEqual(len(result.routes), 5)
    self.assertTrue([r for r in result.routes if r.startswith("/p")])  # sitemap pages crawled


def _openapi_spec(paths):
  import json
  return json.dumps({"openapi": "3.0.0", "paths": paths})


class TestSeedHardening(unittest.TestCase):
  """RM-060 Phase B fix round 1: hostile or off-scope seed input."""

  BASE = "http://testapp.local:8000/app"

  def test_openapi_fetched_under_target_base_path(self):
    disc = _spec_discovery({
      "/app/": (200, "<html></html>", "text/html"),
      "/app/openapi.json": (200, _openapi_spec(
        {"/api/s": {"get": {"parameters": [{"name": "t", "in": "query"}]}}}),
        "application/json"),
      "/app/api/s": (200, "{}", "text/plain"),
    }, target_url=self.BASE)
    result = disc.discover_result()
    self.assertIn(("/app/api/s", "t"), {(c.path, c.param) for c in result.candidates})
    self.assertIn("http://testapp.local:8000/app/openapi.json", disc.requested)
    self.assertIn("http://testapp.local:8000/robots.txt", disc.requested)

  def test_hostile_openapi_shapes_never_crash(self):
    import json
    for body in (
      "DEEP",
      json.dumps({"openapi": "3", "paths": []}),
      json.dumps({"openapi": "3", "paths": {"/a": {"get": {"parameters": 5}}}}),
      json.dumps({"openapi": "3", "paths": {"/a": {"get": {"parameters": [
        {"name": {"x": 1}, "in": "query"}]}}}}),
    ):
      disc = _spec_discovery({
        "/": (200, "<html></html>", "text/html"),
        "/openapi.json": (200, body, "application/json"),
      })
      result = disc.discover_result()
      self.assertEqual(result.candidates, [], body[:20])

  def test_sitemap_line_to_logout_is_never_fetched(self):
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/robots.txt": (200, "Sitemap: /logout\n", "text/plain"),
    }, logout_path="/logout")
    disc.discover_result()
    self.assertFalse([u for u in disc.requested if u.endswith("/logout")])

  def test_offhost_redirect_is_not_followed(self):
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/robots.txt": (302, "", "text/plain", "https://evil.example.com/r"),
    })
    result = disc.discover_result()
    self.assertFalse([u for u in disc.requested if "evil.example.com" in u])
    self.assertGreaterEqual(result.fetch_failures, 1)

  def test_redirect_to_another_scheme_is_not_followed(self):
    """http -> https on the same host is port 443, outside the job's port list."""
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/robots.txt": (302, "", "text/plain", "https://testapp.local:8000/r"),
    })
    disc.discover_result()
    self.assertFalse([u for u in disc.requested if u.startswith("https://")])

  def test_same_origin_redirect_to_logout_is_not_followed(self):
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/robots.txt": (302, "", "text/plain", "/logout"),
    }, logout_path="/logout")
    disc.discover_result()
    self.assertFalse([u for u in disc.requested if u.endswith("/logout")])

  def test_oversized_body_counts_as_failure(self):
    import requests
    disc = _spec_discovery({"/": (200, "<html></html>", "text/html")})
    import io
    from extensions.business.cybersec.red_mesh.graybox import discovery as discovery_mod
    big = requests.Response()
    big.status_code = 200  # no Content-Length: the streamed byte cap must reject it
    big.raw = io.BytesIO(b"a" * (discovery_mod.MAX_BODY_BYTES + 1))
    self.assertFalse(discovery_mod.DiscoveryModule._body_within_cap(big))
    big.raw = io.BytesIO(b"a" * (discovery_mod.MAX_BODY_BYTES + 1))
    inner = disc.auth.primary_session.get.side_effect

    def get(url, **kw):
      return big if url.endswith("/robots.txt") else inner(url, **kw)

    disc.auth.primary_session.get.side_effect = get
    result = disc.discover_result()
    self.assertGreaterEqual(result.fetch_failures, 1)

  def test_seeded_entries_are_capped(self):
    from extensions.business.cybersec.red_mesh.graybox.discovery import MAX_SEEDED_ENTRIES
    n = MAX_SEEDED_ENTRIES + 100
    sm = "<urlset>" + "".join(
      f"<url><loc>http://testapp.local:8000/q{i}/</loc></url>" for i in range(n)
    ) + "</urlset>"
    resp = {"/": (200, "<html></html>", "text/html"),
            "/sitemap.xml": (200, sm, "application/xml")}
    for i in range(n):
      resp[f"/q{i}/"] = (200, "<html></html>", "text/html")
    disc = _spec_discovery(resp, max_pages=2000)
    result = disc.discover_result()
    self.assertLessEqual(len(result.routes), MAX_SEEDED_ENTRIES + 1)

  def test_sitemap_loc_entities_are_decoded(self):
    sm = ('<urlset><url><loc>http://testapp.local:8000/s/?a=1&amp;page=2</loc></url></urlset>')
    disc = _spec_discovery({
      "/": (200, "<html></html>", "text/html"),
      "/sitemap.xml": (200, sm, "application/xml"),
      "/s/": (200, "<html></html>", "text/html"),
    })
    got = {c.param for c in disc.discover_result().candidates}
    self.assertEqual(got, {"a", "page"})
