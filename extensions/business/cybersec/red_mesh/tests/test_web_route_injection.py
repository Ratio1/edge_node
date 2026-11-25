"""RM-275 phase 1: shared crawl, GET injection, context-checked XSS, baseline-gated SQLi."""
import html
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qsl, unquote, urlsplit

import requests

from extensions.business.cybersec.red_mesh.graybox import discovery as gb_discovery
from extensions.business.cybersec.red_mesh.graybox.probes import sqli as sqli_mod
from extensions.business.cybersec.red_mesh.worker.web import injection as inj
from extensions.business.cybersec.red_mesh.worker.web import route_crawl

from .conftest import DummyOwner, PentestLocalWorker

PAGE = "<html><body><p>home</p>" + "x" * 80 + "</body></html>"
ROOT_HTML = (
  '<html><body><a href="/search?q=1">s</a>'
  '<form action="/find" method="get"><input name="term"></form>'
  '<form action="/login" method="post"><input name="user"></form></body></html>')
SITE = {"/": ROOT_HTML}
SQL_ERROR = "You have an error in your SQL syntax; check the manual"


def resp(body, status=200, ctype="text/html; charset=utf-8"):
  r = SimpleNamespace(status_code=status, text=body, headers={"Content-Type": ctype})
  r.close = lambda: None
  r.iter_content = lambda n: iter([body.encode()])
  return r


class FakeSession:
  """Serves SITE to the crawl; counts instances and requests."""
  made = 0
  gets = []

  def __init__(self, site=None):
    FakeSession.made += 1
    self.site = SITE if site is None else site
    self.verify = None

  def get(self, url, timeout=None, allow_redirects=None, stream=None):
    FakeSession.gets.append((urlsplit(url).path, timeout))
    body = self.site.get(urlsplit(url).path)
    return resp(body) if body is not None else resp("nf", status=404)

  def close(self):
    pass


class Endpoint:
  """Stands in for `requests.get` of the injection probes; `handler(path, params, url)` -> response."""

  def __init__(self, handler=None):
    self.handler = handler or (lambda path, params, url: resp(PAGE))
    self.calls = []

  def __call__(self, url, params=None, timeout=None, verify=None, allow_redirects=None, **kw):
    parts = urlsplit(url)
    query = dict(parse_qsl(unquote(parts.query), keep_blank_values=True))
    query.update(params or {})
    self.calls.append({"path": parts.path, "params": query, "timeout": timeout,
                       "allow_redirects": allow_redirects})
    return self.handler(unquote(parts.path), query, url)


class RouteInjectionBase(unittest.TestCase):
  def setUp(self):
    FakeSession.made, FakeSession.gets = 0, []
    self.worker = PentestLocalWorker(
      owner=DummyOwner(), target="example.com", job_id="j", initiator="i",
      local_id_prefix="1", worker_target_ports=[80])
    self.worker.stop_event = MagicMock()
    self.worker.stop_event.is_set.return_value = False

  def run_probe(self, name, handler=None, site=None, caps=None, **patches):
    ep = Endpoint(handler)
    if caps:
      self.worker.web_injection_caps = caps
    with patch.object(route_crawl.requests, "Session", lambda: FakeSession(site)), \
         patch.object(inj.requests, "get", ep), \
         patch.object(inj, "_raw_path_get", lambda *a, **k: resp("nothing")):
      result = getattr(self.worker, name)("example.com", 80)
    self.ep = ep
    return result

  @staticmethod
  def titled(result, text):
    return [f for f in result["findings"] if text in f["title"]]


class CrawlTests(RouteInjectionBase):
  def test_discovered_get_params_are_tested(self):
    result = self.run_probe("_web_test_sql_injection")
    seen = {(c["path"], p) for c in self.ep.calls for p in c["params"]}
    self.assertIn(("/search", "q"), seen)   # a link query parameter
    self.assertIn(("/find", "term"), seen)  # a GET form field
    self.assertIn(("/", "id"), seen)        # the guessed legacy name
    cov = result["coverage"]
    self.assertEqual(cov["candidates_found"], cov["candidates_tested"])
    self.assertEqual(cov["candidates_found"], 2 + len(inj._SQLI_GUESSED_PARAMS))

  def test_post_forms_not_submitted_and_named(self):
    posts = []
    with patch.object(FakeSession, "post", lambda *a, **k: posts.append(a), create=True):
      result = self.run_probe("_web_test_sql_injection")
    self.assertEqual(posts, [])
    self.assertEqual(result["coverage"]["post_forms_not_tested"], ["/login"])
    self.assertIn("allow_stateful", result["coverage"]["post_forms_reason"])
    self.assertNotIn("/login", {c["path"] for c in self.ep.calls})

  def test_crawl_memoised_across_probes(self):
    self.run_probe("_web_test_sql_injection")
    self.run_probe("_web_test_xss")
    self.assertEqual(FakeSession.made, 1)
    self.assertEqual([g for g in FakeSession.gets if g[0] == "/robots.txt"], [("/robots.txt", 3)])
    self.assertNotIn("_web_crawl_cache", self.worker.state)

  def test_crawl_error_recorded_probe_survives(self):
    boom = MagicMock(side_effect=RuntimeError("boom" * 200))
    with patch.object(route_crawl, "DiscoveryModule", boom):
      result = self.run_probe("_web_test_xss")
    cov = result["coverage"]
    self.assertIn("RuntimeError", cov["crawl"]["error"])
    self.assertLessEqual(len(cov["crawl"]["error"]), route_crawl.MAX_LABEL)
    self.assertEqual(cov["candidates_found"], len(inj._XSS_GUESSED_PARAMS))

  def test_discovery_fetch_timeout_override(self):
    cfg = SimpleNamespace(discovery=SimpleNamespace(scope_prefix="", max_pages=1, max_depth=0), logout_path="")
    module = gb_discovery.DiscoveryModule("http://h", SimpleNamespace(), SimpleNamespace(), cfg)
    session = MagicMock()
    session.get.return_value = resp("ok")
    module._get(session, "http://h/")
    self.assertEqual(session.get.call_args.kwargs["timeout"], 10)  # graybox default unchanged
    module.fetch_timeout = 3
    module._get(session, "http://h/")
    self.assertEqual(session.get.call_args.kwargs["timeout"], 3)


class CapTests(RouteInjectionBase):
  def test_page_cap_reached_counts_failed_fetches(self):
    class Failing(FakeSession):
      def get(self, url, **kw):
        raise requests.ConnectionError("down")
    with patch.object(route_crawl.requests, "Session", lambda: Failing()):
      info = route_crawl.crawl_routes(self.worker, "http://example.com")[1]
    self.assertEqual(info["pages_visited"], 1)
    self.assertFalse(info["page_cap_reached"])
    self.worker.web_injection_caps = {"crawl_max_pages": 1}
    with patch.object(route_crawl.requests, "Session", lambda: Failing()):
      info = route_crawl.crawl_routes(self.worker, "http://other.example")[1]
    self.assertTrue(info["page_cap_reached"])

  def test_candidate_cap_lists_untested(self):
    result = self.run_probe("_web_test_sql_injection", caps={"candidates_per_probe": 2})
    cov = result["coverage"]
    self.assertEqual(cov["candidates_tested"], 2)
    self.assertEqual(cov["not_tested"], [f"/?{p}" for p in inj._SQLI_GUESSED_PARAMS])
    self.assertIn("candidates_per_probe", cov["not_tested_reason"])
    self.assertEqual(cov["caps"]["candidates_per_probe"], 2)
    self.assertEqual(cov["caps"]["crawl_max_pages"], 30)

  def test_caps_override_through_worker_attribute(self):
    self.run_probe("_web_test_xss", caps={"crawl_max_pages": 1})
    # only the root page is fetched (robots and sitemap are seed fetches, not pages)
    self.assertNotIn("/search", [g[0] for g in FakeSession.gets])

  def test_sqli_request_cap_lists_remaining(self):
    result = self.run_probe("_web_test_sql_injection", caps={"sqli_requests_per_port": 15})
    cov = result["coverage"]
    self.assertEqual(cov["inconclusive"], {"/find?term": "capped"})
    self.assertEqual(cov["candidates_tested"], 1)
    self.assertEqual(cov["not_tested"], [f"/?{p}" for p in inj._SQLI_GUESSED_PARAMS])
    self.assertIn("request_cap", cov["not_tested_reason"])
    self.assertEqual(len(self.ep.calls), 15)


def sqli_handler(error_on=None, boolean_on=None, sleep_on=None, clock=None):
  """Vulnerable only on the discovered routes: /search?q (error, sleep) and /find?term (boolean)."""
  def handler(path, params, url):
    if path not in ("/search", "/find"):
      return resp(PAGE)
    for name, value in params.items():
      if name == error_on and "'" in value:
        return resp(SQL_ERROR)
      if name == boolean_on:
        return resp(PAGE if value in ("1", "1' AND '1'='1", "1 AND 1=1") else "no rows")
      if name == sleep_on and "SLEEP(" in value:
        clock[0] += 4
    return resp(PAGE)
  return handler


class SqliTests(RouteInjectionBase):
  def test_sqli_keyword_on_static_page_is_clean(self):
    page = resp("SQL syntax guide: mysql, postgres, sqlite, ora-00001 explained")
    result = self.run_probe("_web_test_sql_injection", lambda *a: page)
    self.assertEqual(result["findings"], [])

  def test_sqli_error_hit(self):
    result = self.run_probe("_web_test_sql_injection", sqli_handler(error_on="q"))
    (f,) = self.titled(result, "SQL injection")
    self.assertEqual(f["title"], "SQL injection (error-based) via ?q=")
    self.assertEqual(f["confidence"], "firm")
    asset = f["affected_assets"][0]
    self.assertEqual((asset["url"], asset["parameter"], asset["method"]), ("/search", "q", "GET"))
    self.assertIn("http://example.com/search?q=", f["evidence"])

  def test_sqli_boolean_hit(self):
    result = self.run_probe("_web_test_sql_injection", sqli_handler(boolean_on="term"))
    (f,) = self.titled(result, "SQL injection")
    self.assertEqual(f["title"], "SQL injection (boolean-based) via ?term=")
    self.assertEqual(f["confidence"], "firm")

  def test_sqli_time_hit_uses_long_timeout(self):
    clock = [0.0]
    fake_time = SimpleNamespace(monotonic=lambda: clock[0])
    with patch.object(sqli_mod, "time", fake_time):
      result = self.run_probe("_web_test_sql_injection", sqli_handler(sleep_on="q", clock=clock))
    (f,) = self.titled(result, "SQL injection")
    self.assertEqual(f["title"], "SQL injection (time-based) via ?q=")
    self.assertEqual(f["confidence"], "tentative")
    self.assertTrue(all(c["timeout"] >= sqli_mod.TIME_DELAY + 1 for c in self.ep.calls))

  def test_sqli_boolean_hit_on_page_that_echoes_query_stays_firm(self):
    real = sqli_handler(boolean_on="term")

    def handler(path, params, url):
      page = real(path, params, url)
      return resp(page.text + f"<p>you searched {"&".join(f"{k}={v}" for k, v in params.items())}</p>")
    result = self.run_probe("_web_test_sql_injection", handler)
    (f,) = self.titled(result, "SQL injection")
    self.assertEqual((f["title"], f["confidence"]), ("SQL injection (boolean-based) via ?term=", "firm"))

  def test_finding_bounds_hostile_param_and_path(self):
    name = "n" * 300
    site = {"/": f'<a href="/{"p" * 300}?{name}=1">x</a>'}

    def handler(path, params, url):
      return resp(SQL_ERROR) if any(k == name and "'" in v for k, v in params.items()) else resp(PAGE)
    result = self.run_probe("_web_test_sql_injection", handler, site=site)
    (f,) = self.titled(result, "SQL injection")
    asset = f["affected_assets"][0]
    self.assertLessEqual(len(asset["parameter"]), inj.MAX_PARAM + 3)
    self.assertLessEqual(len(asset["url"]), inj.MAX_PATH + 3)
    self.assertLess(len(f["title"]) + len(f["description"]) + len(f["evidence"]) + len(f["remediation"]), 900)
    self.assertTrue(any(name in c["params"] for c in self.ep.calls))  # the request keeps the full name

  def test_sqli_control_failure_stays_tentative(self):
    ok = sqli_handler(error_on="q")

    def handler(path, params, url):
      if any(n.startswith("rm") for n in params):
        raise requests.ConnectionError("down")
      return ok(path, params, url)
    result = self.run_probe("_web_test_sql_injection", handler)
    (f,) = self.titled(result, "SQL injection")
    self.assertEqual(f["confidence"], "tentative")
    self.assertIn("could not run", f["description"])


class XssTests(RouteInjectionBase):
  def echo(self, template, ctype="text/html", escape=False, param="q"):
    def handler(path, params, url):
      if path == "/search" and param in params:
        value = html.escape(params[param]) if escape else params[param]
        return resp(template.format(value), ctype=ctype)
      return resp(PAGE)
    return handler

  def test_xss_firm_contexts(self):
    cases = {
      "text": "<html><p>{}</p></html>",
      "attribute": '<html><input value="{}"></html>',
      "script": "<html><script>var q = '{}';</script></html>",
    }
    for context, template in cases.items():
      with self.subTest(context):
        result = self.run_probe("_web_test_xss", self.echo(template))
        (f,) = self.titled(result, "?q=")
        self.assertEqual(f["confidence"], "firm")
        self.assertIn(f"context {context}", f["evidence"])
        asset = f["affected_assets"][0]
        self.assertEqual((asset["url"], asset["parameter"], asset["method"]), ("/search", "q", "GET"))

  def test_xss_tentative_cases(self):
    cases = {
      "textarea": ("<html><textarea>{}</textarea></html>", "text/html"),
      "comment": ("<html><!-- {} --></html>", "text/html"),
      "plain text": ("<p>{}</p>", "text/plain"),
    }
    for label, (template, ctype) in cases.items():
      with self.subTest(label):
        result = self.run_probe("_web_test_xss", self.echo(template, ctype))
        (f,) = self.titled(result, "?q=")
        self.assertEqual(f["confidence"], "tentative")

  def test_xss_escaped_echo_is_no_finding(self):
    result = self.run_probe("_web_test_xss", self.echo("<html><p>{}</p></html>", escape=True))
    self.assertEqual(result["findings"], [])

  def test_xss_path_step_tentative_on_catch_all(self):
    def echo_path(path, params, url):
      return resp(f"<html><p>{path}</p></html>")

    def only_payload_paths(path, params, url):
      return echo_path(path, params, url) if path.startswith("/'") else resp("nf", status=404)
    catch_all = self.run_probe("_web_test_xss", echo_path)
    self.assertEqual(self.titled(catch_all, "URL path")[0]["confidence"], "tentative")
    self.setUp()
    selective = self.run_probe("_web_test_xss", only_payload_paths)
    f = self.titled(selective, "URL path")[0]
    self.assertEqual(f["confidence"], "firm")
    self.assertIsNone(f["affected_assets"][0]["parameter"])


class HoneypotTests(RouteInjectionBase):
  def catch_all(self, kind):
    def handler(path, params, url):
      value = next(iter(params.values()), "")
      if "<rmx" in value:  # an XSS marker: echoed raw, so the query-step control is exercised
        return resp(f"<html><p>{unquote(path)} {value}</p></html>")
      if kind == "error" and "'" in value:
        return resp(SQL_ERROR)
      if kind == "boolean" and value not in ("1", "1' AND '1'='1", "1 AND 1=1", ""):
        return resp("no rows") if value in ("1' AND '1'='2", "1 AND 1=2") else resp(PAGE)
      return resp(f"<html><p>{unquote(path)} {value}</p></html>")
    return handler

  def test_catch_all_endpoint_gives_no_firm_sqli_or_xss(self):
    for kind in ("error", "boolean"):
      for probe in ("_web_test_sql_injection", "_web_test_xss"):
        with self.subTest(kind=kind, probe=probe):
          self.setUp()
          result = self.run_probe(probe, self.catch_all(kind))
          self.assertTrue(result["findings"], "the fake does reflect/err: findings expected, capped")
          for f in result["findings"]:
            self.assertNotIn(f["confidence"], ("firm", "certain"), f["title"])
            self.assertTrue("answers any parameter" in f["description"]
                            or "answers 200 to random paths" in f["description"], f["description"])
          if probe == "_web_test_xss":
            self.assertTrue(any("answers any parameter" in f["description"] for f in result["findings"]))


class CoverageAndLimitsTests(RouteInjectionBase):
  def test_xss_reported_marker_is_stable_across_scans(self):
    echo = XssTests.echo(self, "<html><p>{}</p></html>")
    first = self.run_probe("_web_test_xss", echo)
    self.setUp()
    second = self.run_probe("_web_test_xss", echo)
    key = lambda r: sorted((f["title"], f["evidence"], f["finding_signature"]) for f in r["findings"])
    self.assertEqual(key(first), key(second))
    self.assertTrue(first["findings"])

  def test_stop_event_lists_rest_as_stopped(self):
    self.worker.stop_event.is_set.return_value = True
    for probe in ("_web_test_sql_injection", "_web_test_xss"):
      cov = self.run_probe(probe)["coverage"]
      self.assertIn("stopped", cov["not_tested_reason"])
      self.assertEqual(len(cov["not_tested"]), cov["candidates_found"])

  def test_time_allowance_in_coverage_and_skipped_named(self):
    self.worker.__dict__["_web_sqli_time_left"] = {"s": 1}
    cov = self.run_probe("_web_test_sql_injection")["coverage"]
    self.assertEqual(cov["sqli_time_allowance_s"], {"allowance": sqli_mod.SCAN_TIME_ALLOWANCE, "left": 1})
    self.assertEqual(len(cov["time_skipped"]), cov["candidates_found"])

  def test_injection_body_is_truncated_not_dropped(self):
    real = requests.Response()
    real.status_code = 200
    real.raw = __import__("io").BytesIO(b"a" * (inj.MAX_INJECTION_BODY_BYTES + 5000))
    with patch.object(inj.requests, "get", return_value=real):
      out = inj._injection_get("http://h/", 3)
    self.assertEqual(len(out.text), inj.MAX_INJECTION_BODY_BYTES)

  def test_coverage_bounds_hostile_strings(self):
    cov = {"not_tested": ["/" + "a" * 500] * 80, "post_forms_not_tested": [], "time_skipped": [],
           "inconclusive": {"/" + "b" * 500 + f"{i}": "x" for i in range(60)}}
    out = route_crawl.finish_coverage(cov)
    self.assertEqual(len(out["not_tested"]), route_crawl.MAX_LISTED)
    self.assertEqual(out["not_tested_more"], 30)
    self.assertTrue(all(len(x) <= route_crawl.MAX_LABEL for x in out["not_tested"]))
    self.assertEqual(out["inconclusive_more"], 10)


class AssetAndRedirectTests(RouteInjectionBase):
  def test_findings_carry_affected_asset(self):
    def handler(path, params, url):
      if "file" in params and "etc/passwd" in params["file"]:
        return resp("root:x:0:0:root:/root:/bin/bash")
      if "name" in params and "{{71*73}}" in params["name"]:
        return resp("result 5183")
      return resp(PAGE)
    traversal = self.run_probe("_web_test_path_traversal", handler)
    (f,) = self.titled(traversal, "?file=")
    self.assertEqual(f["affected_assets"][0]["parameter"], "file")
    self.assertEqual(f["affected_assets"][0]["url"], "/")
    self.assertEqual(f["affected_assets"][0]["method"], "GET")
    ssti = self.run_probe("_web_test_ssti", handler)
    (f,) = self.titled(ssti, "?name=")
    self.assertEqual(f["affected_assets"][0]["parameter"], "name")
    self.assertEqual(f["affected_assets"][0]["port"], 80)

  def test_injection_requests_do_not_follow_redirects(self):
    self.run_probe("_web_test_sql_injection")
    self.run_probe("_web_test_xss")
    self.assertTrue(self.ep.calls)
    self.assertTrue(all(c["allow_redirects"] is False for c in self.ep.calls))


if __name__ == "__main__":
  unittest.main()
