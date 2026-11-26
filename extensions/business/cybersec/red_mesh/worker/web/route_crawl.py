"""Shared route crawl for the blackbox web injection probes (RM-275).

Adapts `graybox.discovery.DiscoveryModule` to a network worker: an anonymous session, no pacing,
one crawl per base URL shared by the XSS and SQLi probes. No second crawler lives here.
"""

import requests
from types import SimpleNamespace

from ...constants import WEB_INJECTION_CAPS
from ...graybox.discovery import DiscoveryModule, MAX_STORED_CANDIDATES
from ...graybox.models import InjectionCandidate

MAX_LABEL = 200   # chars of a target-controlled string kept in coverage
MAX_LISTED = 50   # entries of one coverage list; the rest are counted

# A network scan holds no authenticated session, so a logout link ends nothing: `logout_path` stays
# empty. It has no `allow_stateful` switch either, so POST forms are listed, never submitted (D43).
POST_NOT_TESTED = "POST forms are never submitted by a network scan (no allow_stateful switch)"


class _NoPacing:
  def throttle(self):
    pass


def label(cand):
  return f"{cand.path}?{cand.param}"


def finish_coverage(cov):
  """Bound what a hostile target put into coverage: labels cut to MAX_LABEL chars, lists to MAX_LISTED."""
  def cut(items):
    items = [str(i)[:MAX_LABEL] for i in items]
    return items[:MAX_LISTED], max(len(items) - MAX_LISTED, 0)
  for key in ("not_tested", "post_forms_not_tested", "time_skipped"):
    cov[key], more = cut(cov[key])
    if more:
      cov[f"{key}_more"] = more
  total = len(cov["inconclusive"])
  cov["inconclusive"] = {str(k)[:MAX_LABEL]: v for k, v in list(cov["inconclusive"].items())[:MAX_LISTED]}
  if total > MAX_LISTED:
    cov["inconclusive_more"] = total - MAX_LISTED
  return cov


def web_caps(worker):
  """Defaults overridden by the worker's `web_injection_caps` dict, if any."""
  return {**WEB_INJECTION_CAPS, **(getattr(worker, "web_injection_caps", None) or {})}


def crawl_routes(worker, base_url):
  """(DiscoveryResult or None, info) for `base_url`, crawled once per worker.

  A crawl that raises counts as an empty result plus a recorded error; it never fails the probe.
  The memo is a plain attribute, not `state`: `state` is checkpointed.
  """
  cache = worker.__dict__.setdefault("_web_crawl_cache", {})
  if base_url in cache:
    return cache[base_url]
  caps = web_caps(worker)
  session = requests.Session()
  session.verify = False
  config = SimpleNamespace(
    discovery=SimpleNamespace(
      scope_prefix="", max_pages=caps["crawl_max_pages"], max_depth=caps["crawl_max_depth"]),
    logout_path="")
  auth = SimpleNamespace(primary_session=None, anon_session=session)
  info = {"error": None, "pages_visited": 0, "page_cap_reached": False, "seed_fetch_failures": 0,
          "candidate_store_cap": MAX_STORED_CANDIDATES, "candidate_store_cap_reached": False}
  result = None
  try:
    module = DiscoveryModule(base_url, auth, _NoPacing(), config)
    module.fetch_timeout = worker._target_timeout(3)
    result = module.discover_result()
    info.update(
      pages_visited=module.pages_visited, page_cap_reached=module.pages_visited >= caps["crawl_max_pages"],
      seed_fetch_failures=result.fetch_failures,
      candidate_store_cap_reached=len(result.candidates) >= MAX_STORED_CANDIDATES)
  except Exception as exc:
    info["error"] = f"{type(exc).__name__}: {exc}"[:MAX_LABEL]
  finally:
    session.close()
  cache[base_url] = (result, info)
  return cache[base_url]


def plan_candidates(worker, base_url, guessed_params):
  """(candidates to test, coverage dict) for one injection probe.

  Discovered GET candidates first, then the fixed legacy names on the root path (source `guessed`),
  deduplicated on (path, param) and cut at the `candidates_per_probe` cap. What the cap cut is
  named in `not_tested`, so a clean result never hides an untested route.
  """
  caps = web_caps(worker)
  result, info = crawl_routes(worker, base_url)
  found = list(result.candidates) if result else []
  seen = {(c.path, c.param) for c in found}
  found += [InjectionCandidate(path="/", param=p, source="guessed")
            for p in guessed_params if ("/", p) not in seen]
  limit = caps["candidates_per_probe"]
  post = list(result.post_forms) if result else []
  coverage = {
    "crawl": dict(info),
    "candidates_found": len(found),
    "candidates_tested": min(len(found), limit),
    "not_tested": [label(c) for c in found[limit:]],
    "not_tested_reason": "candidates_per_probe cap" if len(found) > limit else "",
    "inconclusive": {},
    "time_skipped": [],
    "post_forms_not_tested": post,
    "post_forms_reason": POST_NOT_TESTED if post else "",
    "caps": {k: caps[k] for k in WEB_INJECTION_CAPS},
  }
  return found[:limit], coverage
