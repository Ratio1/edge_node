"""Tests for DiscoveryModule."""

import unittest
from collections import deque
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.graybox.discovery import DiscoveryModule, _RouteParser
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig, DiscoveryConfig,
)


def _mock_response(status=200, text="", content_type="text/html"):
  resp = MagicMock()
  resp.status_code = status
  resp.text = text
  resp.headers = {"Content-Type": content_type}
  return resp


def _make_discovery(scope_prefix="", max_pages=50, max_depth=3, routes_html=None):
  """Build a DiscoveryModule with mocked HTTP."""
  cfg = GrayboxTargetConfig(
    discovery=DiscoveryConfig(scope_prefix=scope_prefix, max_pages=max_pages, max_depth=max_depth),
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
  auth.official_session = session
  auth.anon_session = session

  disc = DiscoveryModule(
    target_url="http://testapp.local:8000",
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
    auth.official_session = session
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


if __name__ == '__main__':
  unittest.main()
