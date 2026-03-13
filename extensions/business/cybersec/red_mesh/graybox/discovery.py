"""
Route and form discovery for graybox scanning.

BFS crawl with scope boundaries, page/depth limits,
and form collection without blind POSTs.
"""

import posixpath
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from .models import DiscoveryResult


class _RouteParser(HTMLParser):
  """Extract href and form action attributes from HTML."""

  def __init__(self):
    super().__init__()
    self.links = []
    self.forms = []

  def handle_starttag(self, tag, attrs):
    attrs_map = dict(attrs)
    if tag == "a" and attrs_map.get("href"):
      self.links.append(attrs_map["href"])
    if tag == "form" and attrs_map.get("action"):
      self.forms.append(attrs_map["action"])


class DiscoveryModule:
  """
  Route and form discovery with scope boundaries.

  Scope constraints:
  - Same-origin only: external domain links are ignored
  - Optional path prefix: only crawl under scope_prefix
  - Depth/page limits: prevent unbounded crawling
  - Form actions recorded but NOT followed (no blind POSTs)
  """

  def __init__(self, target_url, auth_manager, safety, target_config):
    self.target_url = target_url.rstrip("/")
    self.auth = auth_manager
    self.safety = safety
    self._target_host = urlparse(target_url).netloc
    self._scope_prefix = target_config.discovery.scope_prefix
    self._max_pages = target_config.discovery.max_pages
    self._max_depth = target_config.discovery.max_depth
    self.routes = []
    self.forms = []

  def discover(self, known_routes=None):
    """
    Discover application routes and forms.

    Combines user-supplied routes with crawled routes.
    Respects scope boundaries and page/depth limits.
    """
    visited = set()
    to_visit = deque([("/", 0)])

    if known_routes:
      for route in known_routes:
        if self._in_scope(route):
          to_visit.append((route, 0))

    all_routes = set()
    all_forms = set()

    while to_visit and len(visited) < self._max_pages:
      path, depth = to_visit.popleft()
      if path in visited:
        continue
      visited.add(path)

      self.safety.throttle()

      # Use authenticated session if available, else anonymous
      session = self.auth.official_session or self.auth.anon_session
      if session is None:
        break

      url = self.target_url + path
      try:
        resp = session.get(url, timeout=10, allow_redirects=True)
      except requests.RequestException:
        continue

      all_routes.add(path)

      if "text/html" not in resp.headers.get("Content-Type", ""):
        continue

      parser = _RouteParser()
      try:
        parser.feed(resp.text)
      except Exception:
        continue

      # Process discovered links (scope enforcement)
      if depth < self._max_depth:
        for link in parser.links:
          normalized = self._normalize(link)
          if normalized and normalized not in visited and self._in_scope(normalized):
            to_visit.append((normalized, depth + 1))

      # Record form actions but do NOT follow them
      for action in parser.forms:
        normalized = self._normalize(action)
        if normalized and self._in_scope(normalized):
          all_forms.add(normalized)

    result = self.discover_result(known_routes=known_routes)
    return result.to_tuple()

  def discover_result(self, known_routes=None) -> DiscoveryResult:
    """Discover application routes/forms and return a typed result."""
    visited = set()
    to_visit = deque([("/", 0)])

    if known_routes:
      for route in known_routes:
        if self._in_scope(route):
          to_visit.append((route, 0))

    all_routes = set()
    all_forms = set()

    while to_visit and len(visited) < self._max_pages:
      path, depth = to_visit.popleft()
      if path in visited:
        continue
      visited.add(path)

      self.safety.throttle()

      session = self.auth.official_session or self.auth.anon_session
      if session is None:
        break

      url = self.target_url + path
      try:
        resp = session.get(url, timeout=10, allow_redirects=True)
      except requests.RequestException:
        continue

      all_routes.add(path)

      if "text/html" not in resp.headers.get("Content-Type", ""):
        continue

      parser = _RouteParser()
      try:
        parser.feed(resp.text)
      except Exception:
        continue

      if depth < self._max_depth:
        for link in parser.links:
          normalized = self._normalize(link)
          if normalized and normalized not in visited and self._in_scope(normalized):
            to_visit.append((normalized, depth + 1))

      for action in parser.forms:
        normalized = self._normalize(action)
        if normalized and self._in_scope(normalized):
          all_forms.add(normalized)

    self.routes = sorted(all_routes)
    self.forms = sorted(all_forms)
    return DiscoveryResult(routes=self.routes, forms=self.forms)

  def _normalize(self, raw):
    """Normalize a link to a same-origin, canonicalized path."""
    if not raw or raw.startswith(("#", "javascript:", "mailto:")):
      return ""
    joined = urljoin(self.target_url + "/", raw)
    parsed = urlparse(joined)
    # Same-origin check
    if parsed.netloc and parsed.netloc != self._target_host:
      return ""
    # Canonicalize path to collapse ".." segments
    path = posixpath.normpath(parsed.path or "/")
    # normpath strips trailing slash; preserve it for directory-style paths
    if (parsed.path or "").endswith("/") and not path.endswith("/"):
      path += "/"
    return path

  def _in_scope(self, path):
    """Check if path is within the configured scope prefix."""
    if not self._scope_prefix:
      return True
    return path.startswith(self._scope_prefix)
