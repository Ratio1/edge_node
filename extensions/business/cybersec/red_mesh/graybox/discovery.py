"""
Route and form discovery for graybox scanning.

BFS crawl with scope boundaries, page/depth limits,
and form collection without blind POSTs.
"""

import html
import posixpath
import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

from .budget import RequestBudgetExhausted
from .models import DiscoveryResult, InjectionCandidate

# Seed fetches per scan: robots.txt (1) + sitemaps (sitemap.xml, robots
# `Sitemap:` lines, one index level; at most this many) + OpenAPI candidates
# (at most len(openapi_candidates), stops at the first spec).
MAX_SITEMAP_FETCHES = 5
# Bound on candidates kept from one scan, before the per-family cap applies.
MAX_STORED_CANDIDATES = 200
# Seeded paths (robots, sitemap, OpenAPI) queued per scan.
MAX_SEEDED_ENTRIES = 500
# Largest body read from a discovery fetch; more counts as a failed fetch.
MAX_BODY_BYTES = 5 * 1024 * 1024
MAX_REDIRECTS = 3
MAX_JSON_DEPTH = 6
MAX_JSON_STRINGS = 500
_SKIP_INPUT_TYPES = {"submit", "button", "image", "reset", "hidden", "password",
                     "file", "checkbox", "radio"}


class _RouteParser(HTMLParser):
  """Extract href and form action attributes from HTML."""

  def __init__(self):
    super().__init__()
    self.links = []
    self.forms = []
    # Per form: {"action", "method", "inputs"}; action "" = the current page.
    self.form_specs = []
    self._form = None

  def handle_starttag(self, tag, attrs):
    attrs_map = dict(attrs)
    if tag == "a" and attrs_map.get("href"):
      self.links.append(attrs_map["href"])
    if tag == "form":
      if attrs_map.get("action"):
        self.forms.append(attrs_map["action"])
      self._form = {"action": attrs_map.get("action") or "",
                    "method": (attrs_map.get("method") or "get").lower(),
                    "inputs": []}
      self.form_specs.append(self._form)
    elif (self._form is not None and tag in ("input", "textarea")
          and attrs_map.get("name")
          and (attrs_map.get("type") or "text").lower() not in _SKIP_INPUT_TYPES):
      self._form["inputs"].append(attrs_map["name"])

  def handle_endtag(self, tag):
    if tag == "form":
      self._form = None


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
    # Paths in the crawl queue are origin-absolute — `_normalize` resolves every
    # link against the target's base and returns the whole path — so requests
    # are built on the origin. Building them on `target_url` instead appended a
    # path that already carried the base to the base again.
    _parsed = urlparse(self.target_url)
    self._origin = f"{_parsed.scheme}://{_parsed.netloc}"
    self._scope_prefix = target_config.discovery.scope_prefix
    self._max_pages = target_config.discovery.max_pages
    self._max_depth = target_config.discovery.max_depth
    # Never crawl the logout URL: a GET there ends the scan session.
    logout_path = getattr(target_config, "logout_path", "") or ""
    self._logout_path = self._normalize(logout_path.lstrip("/")) if logout_path else ""
    self.routes = []
    self.forms = []
    self.fetch_failures = 0
    api = getattr(target_config, "api_security", None)
    inv = getattr(api, "inventory_paths", None)
    self._openapi_paths = list(getattr(inv, "openapi_candidates", []) or [])

  def discover(self, known_routes=None):
    """
    Discover application routes and forms.

    Combines user-supplied routes with crawled routes.
    Respects scope boundaries and page/depth limits.
    """
    visited = set()
    # The seed is the target's own root — the base path when the target carries
    # one, not the origin root — stated in the same origin-absolute form that
    # every crawled link arrives in.
    to_visit = deque([(self._normalize("./"), 0)])

    if known_routes:
      for route in known_routes:
        # Configured routes are relative to the target, so they keep resolving
        # against its base: with target `https://h/app`, `/api` stays
        # `/app/api`. The `lstrip` is what keeps it base-relative instead of
        # origin-absolute — that is the distinction `urljoin` turns on.
        path = self._normalize(route.lstrip("/"))
        if path and self._in_scope(path):
          to_visit.append((path, 0))

    all_routes = set()
    all_forms = set()

    while to_visit and len(visited) < self._max_pages:
      path, depth = to_visit.popleft()
      if path in visited:
        continue
      visited.add(path)
      if self._is_logout(path):
        continue


      # Use authenticated session if available, else anonymous
      session = self.auth.primary_session or self.auth.anon_session
      if session is None:
        break

      # Origin, not `target_url`: `path` already carries the base, and appending
      # it to the base doubled it — `https://h/app` + `/app/users` ->
      # `https://h/app/app/users`. The client's absolute-URL branch preserves
      # whatever path it is handed, so every crawl request against a base-path
      # target 404'd and discovery silently under-reported. A bare-host target
      # hides it, which is what these tests used until now.
      url = self._origin + path
      try:
        resp = self._get(session, url)
      except RequestBudgetExhausted:
        self.fetch_failures += 1  # stop the crawl, keep what was found
        break
      except requests.RequestException:
        continue
      if resp is None:
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
        if (normalized and self._in_scope(normalized)
            and not self._is_logout(normalized)):
          all_forms.add(normalized)

    result = self.discover_result(known_routes=known_routes)
    return result.to_tuple()

  def discover_result(self, known_routes=None) -> DiscoveryResult:
    """Discover application routes/forms and return a typed result."""
    visited = set()
    # The seed is the target's own root — the base path when the target carries
    # one, not the origin root — stated in the same origin-absolute form that
    # every crawled link arrives in.
    to_visit = deque([(self._normalize("./"), 0)])

    if known_routes:
      for route in known_routes:
        # Configured routes are relative to the target, so they keep resolving
        # against its base: with target `https://h/app`, `/api` stays
        # `/app/api`. The `lstrip` is what keeps it base-relative instead of
        # origin-absolute — that is the distinction `urljoin` turns on.
        path = self._normalize(route.lstrip("/"))
        if path and self._in_scope(path):
          to_visit.append((path, 0))

    all_routes = set()
    all_forms = set()
    candidates = {}
    self.fetch_failures = 0
    self._seed(to_visit, candidates)

    while to_visit and len(visited) < self._max_pages:
      path, depth = to_visit.popleft()
      if path in visited:
        continue
      visited.add(path)
      if self._is_logout(path):
        continue


      session = self.auth.primary_session or self.auth.anon_session
      if session is None:
        break

      # Same base-path doubling as the route crawl above.
      url = self._origin + path
      try:
        resp = self._get(session, url)
      except RequestBudgetExhausted:
        self.fetch_failures += 1  # stop the crawl, keep what was found
        break
      except requests.RequestException:
        continue
      if resp is None:
        continue

      all_routes.add(path)

      content_type = resp.headers.get("Content-Type", "")
      if "json" in content_type.lower():
        # A JSON response contributes its same-origin link strings and their
        # query parameters, like an HTML page's links.
        for link in self._json_links(resp):
          normalized = self._normalize(link)
          if depth < self._max_depth and normalized and normalized not in visited \
              and self._in_scope(normalized):
            to_visit.append((normalized, depth + 1))
          self._add_query_candidates(normalized, candidates, link)
        continue
      if "text/html" not in content_type:
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
        if (normalized and self._in_scope(normalized)
            and not self._is_logout(normalized)):
          all_forms.add(normalized)

      # Only GET forms and query links become injection candidates: a POST
      # form is never replayed by the reflective families.
      for link in parser.links:
        self._add_query_candidates(self._normalize(link), candidates, link)
      for spec in parser.form_specs:
        if spec["method"] != "get":
          continue
        target = self._normalize(spec["action"]) if spec["action"] else path
        for name in spec["inputs"]:
          self._add_candidate(target, name, candidates)

    self.routes = sorted(all_routes)
    self.forms = sorted(all_forms)
    return DiscoveryResult(
      routes=self.routes, forms=self.forms,
      candidates=list(candidates.values()), fetch_failures=self.fetch_failures)

  @staticmethod
  def _json_links(resp):
    """Same-origin link strings of a JSON body: depth <= 6, <= 500 strings."""
    try:
      stack, links, seen = [(resp.json(), 0)], [], 0
    except (ValueError, RecursionError):
      return []
    while stack and seen < MAX_JSON_STRINGS:
      node, depth = stack.pop()
      if isinstance(node, str):
        seen += 1
        if node.startswith(("/", "http://", "https://")):
          links.append(node)
      elif depth < MAX_JSON_DEPTH and isinstance(node, dict):
        stack.extend((v, depth + 1) for v in node.values())
      elif depth < MAX_JSON_DEPTH and isinstance(node, list):
        stack.extend((v, depth + 1) for v in node)
    return links

  # ── seeds: robots.txt, sitemap.xml, OpenAPI ──────────────────────────

  def _get(self, session, url):
    """GET without leaving the target origin.

    Redirects are followed by hand, same origin only, at most MAX_REDIRECTS,
    never to the logout path or outside the scope prefix; an off-origin
    redirect or a body over MAX_BODY_BYTES returns None, so session
    credentials never reach another host.
    """
    for _ in range(MAX_REDIRECTS + 1):
      resp = session.get(url, timeout=10, allow_redirects=False, stream=True)
      if resp.status_code in (301, 302, 303, 307, 308):
        url = urljoin(url, resp.headers.get("Location", ""))
        resp.close()
        hop = urlparse(url)
        hop_path = hop.path or "/"
        if (hop.netloc != self._target_host or self._is_logout(hop_path)
            or not self._in_scope(hop_path)):
          return None
        continue
      return resp if self._body_within_cap(resp) else None
    return None

  @staticmethod
  def _body_within_cap(resp):
    try:
      if int(resp.headers.get("Content-Length") or 0) > MAX_BODY_BYTES:
        resp.close()
        return False
    except (TypeError, ValueError):
      pass
    if isinstance(resp, requests.Response):
      body = b""
      for chunk in resp.iter_content(65536):
        body += chunk
        if len(body) > MAX_BODY_BYTES:
          resp.close()
          return False
      resp._content, resp._content_consumed = body, True
    return True

  def _fetch(self, path):
    """One bounded seed GET. Failure (error, 4xx/5xx, timeout) is counted."""
    session = self.auth.primary_session or self.auth.anon_session
    if session is None:
      return None
    try:
      resp = self._get(session, self._origin + path)
    except requests.RequestException:
      resp = None
    if resp is None or resp.status_code >= 400:
      self.fetch_failures += 1
      return None
    return resp

  def _seed(self, to_visit, candidates):
    """Queue robots/sitemap/OpenAPI paths and record spec parameters.

    Order: robots.txt, sitemaps, OpenAPI. Paths join the crawl queue, so
    max_pages and scope_prefix bound them like any crawled link; at most
    MAX_SEEDED_ENTRIES are queued. Each source is isolated: hostile input
    from one is a counted failure, never a crash.
    """
    self._seeded = 0

    def queue(raw):
      path = self._normalize(raw)
      if (path and self._in_scope(path) and not self._is_logout(path)
          and self._seeded < MAX_SEEDED_ENTRIES):
        self._seeded += 1
        to_visit.append((path, 0))
        self._add_query_candidates(path, candidates, raw)
      return path

    sitemaps = ["/sitemap.xml"]  # origin root, RFC 9309
    try:
      self._seed_robots(queue, sitemaps)
    except Exception:
      self.fetch_failures += 1
    pending = [(p, 0) for p in dict.fromkeys(sitemaps)]
    fetched = 0
    while pending and fetched < MAX_SITEMAP_FETCHES:
      sm_path, level = pending.pop(0)
      fetched += 1
      try:
        self._seed_sitemap(sm_path, level, queue, pending)
      except Exception:
        self.fetch_failures += 1
    try:
      self._seed_openapi(to_visit, candidates)
    except Exception:
      self.fetch_failures += 1

  def _seed_robots(self, queue, sitemaps):
    robots = self._fetch("/robots.txt")
    if robots is None:
      return
    if "<html" in robots.text[:200].lower():
      self.fetch_failures += 1
      return
    for line in robots.text.splitlines():
      key, _, val = line.partition(":")
      key, val = key.strip().lower(), val.strip()
      if key == "disallow" and val.startswith("/"):
        # Static prefix only: wildcard rules cannot be requested.
        queue(re.split(r"[*$]", val)[0])
      elif key == "sitemap" and val:
        path = self._normalize(val)
        if path and self._in_scope(path) and not self._is_logout(path):
          sitemaps.append(path)

  def _seed_sitemap(self, sm_path, level, queue, pending):
    resp = self._fetch(sm_path)
    if resp is None:
      return
    is_index = "<sitemapindex" in resp.text
    if not is_index and "<urlset" not in resp.text:
      self.fetch_failures += 1
      return
    for loc in re.findall(r"<loc>\s*([^<]+?)\s*</loc>", resp.text):
      loc = html.unescape(loc)
      if not is_index:
        queue(loc)
      elif level == 0:
        child = self._normalize(loc)
        if child and self._in_scope(child) and not self._is_logout(child):
          pending.append((child, 1))

  def _seed_openapi(self, to_visit, candidates):
    """One bounded fetch over openapi_candidates, under the target's base path
    like PT-OAPI9-01; spec paths resolve against the same base."""
    base = urlparse(self.target_url).path
    for cand_path in self._openapi_paths:
      resp = self._fetch(base + cand_path)
      if resp is None:
        continue
      try:
        spec = resp.json()
      except (ValueError, RecursionError):
        self.fetch_failures += 1
        continue
      if isinstance(spec, dict) and (spec.get("openapi") or spec.get("swagger")):
        self._queue_spec_paths(spec, to_visit, candidates)
        return
      self.fetch_failures += 1

  def _queue_spec_paths(self, spec, to_visit, candidates):
    paths = spec.get("paths")
    if not isinstance(paths, dict):
      self.fetch_failures += 1
      return
    for raw, item in paths.items():
      if (not isinstance(raw, str) or "{" in raw or not isinstance(item, dict)
          or self._seeded >= MAX_SEEDED_ENTRIES):
        continue  # templated paths need real ids; leave them to configured probes
      get = item.get("get")
      if not isinstance(get, dict):
        continue
      path = self._normalize(raw.lstrip("/"))
      if not path or not self._in_scope(path) or self._is_logout(path):
        continue
      self._seeded += 1
      to_visit.append((path, 0))
      shared, own = item.get("parameters"), get.get("parameters")
      params = [*(shared if isinstance(shared, list) else []),
                *(own if isinstance(own, list) else [])]
      for prm in params:
        name = prm.get("name") if isinstance(prm, dict) else None
        if isinstance(name, str) and name and prm.get("in") == "query":
          self._add_candidate(path, name, candidates)

  def _add_query_candidates(self, path, candidates, raw=""):
    """Query-string parameter names of a link become candidates."""
    if not path or not raw or "?" not in raw:
      return
    for name, _ in parse_qsl(urlparse(raw).query, keep_blank_values=True):
      self._add_candidate(path, name, candidates)

  def _add_candidate(self, path, param, candidates):
    if (path and param and self._in_scope(path) and not self._is_logout(path)
        and len(candidates) < MAX_STORED_CANDIDATES):
      candidates.setdefault(
        (path, param), InjectionCandidate(path=path, param=param))

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

  def _is_logout(self, path):
    """True for the logout URL, trailing slash ignored (`/logout` == `/logout/`)."""
    return bool(self._logout_path) and (
      path.rstrip("/") == self._logout_path.rstrip("/"))

  def _in_scope(self, path):
    """Check if path is within the configured scope prefix."""
    if not self._scope_prefix:
      return True
    return path.startswith(self._scope_prefix)
