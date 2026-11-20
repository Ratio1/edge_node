"""OWASP API Top 10 — Subphases 2.4 + 2.5.

`ApiConfigProbes`: API8 misconfig (5 scenarios) + API9 inventory (3).
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.probes.api_config import (
  ApiConfigProbes,
)
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiFunctionEndpoint, ApiInventoryPaths, ApiSecurityConfig,
  GrayboxTargetConfig,
)


def _resp(status=200, headers=None, json_body=None, text=""):
  r = MagicMock()
  r.status_code = status
  r.headers = headers or {}
  r.text = text or (json.dumps(json_body) if json_body is not None else "")
  if json_body is not None:
    r.json.return_value = json_body
  else:
    r.json.side_effect = ValueError("not json")
  return r


def _make_probe(**api_cfg_kwargs):
  cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(**api_cfg_kwargs))
  auth = MagicMock()
  auth.regular_session = MagicMock()
  auth.official_session = MagicMock()
  auth.primary_session = auth.official_session
  auth.make_anonymous_session = MagicMock(return_value=MagicMock())
  safety = MagicMock()
  safety.throttle = MagicMock()
  safety.sanitize_error = MagicMock(side_effect=lambda s: s)
  return ApiConfigProbes(
    target_url="http://api.example",
    auth_manager=auth, target_config=cfg, safety=safety,
  )


class TestApi8CorsMisconfig(unittest.TestCase):

  def test_wildcard_with_credentials_high(self):
    ep = ApiFunctionEndpoint(path="/api/me/")
    p = _make_probe(function_endpoints=[ep])
    p.auth.official_session.get.return_value = _resp(
      headers={
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
      },
    )
    p.run_safe("api_cors_misconfig", p._test_cors_misconfig)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI8-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")

  def test_origin_echo_with_credentials_high(self):
    ep = ApiFunctionEndpoint(path="/api/me/")
    p = _make_probe(function_endpoints=[ep])
    p.auth.official_session.get.return_value = _resp(
      headers={
        "Access-Control-Allow-Origin": "https://evil.example",
        "Access-Control-Allow-Credentials": "true",
      },
    )
    p.run_safe("api_cors_misconfig", p._test_cors_misconfig)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI8-01" and f.status == "vulnerable"]
    self.assertEqual(vuln[0].severity, "HIGH")

  def test_strict_cors_clean(self):
    ep = ApiFunctionEndpoint(path="/api/me/")
    p = _make_probe(function_endpoints=[ep])
    p.auth.official_session.get.return_value = _resp(
      headers={"Access-Control-Allow-Origin": "https://trusted.example"},
    )
    p.run_safe("api_cors_misconfig", p._test_cors_misconfig)
    clean = [f for f in p.findings
             if f.scenario_id == "PT-OAPI8-01" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)


class TestApi8SecurityHeaders(unittest.TestCase):

  def test_missing_x_content_type_options_low(self):
    ep = ApiFunctionEndpoint(path="/api/me/")
    p = _make_probe(function_endpoints=[ep])
    p.auth.official_session.get.return_value = _resp(
      headers={"Cache-Control": "no-store"},
    )
    p.run_safe("api_security_headers", p._test_security_headers)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI8-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "LOW")


def _login_page():
  r = _resp(status=200, text="<input name='username'><input type='password' name='p'>")
  r.url = "http://api.example/auth/login/?next=/api/me/"
  r.history = []
  return r


class TestApi8ReachabilityRule(unittest.TestCase):
  """PT-OAPI8-01/-02: headers on a denied response can convict, never clear."""

  CASES = [("PT-OAPI8-01", "_test_cors_misconfig"),
           ("PT-OAPI8-02", "_test_security_headers")]

  def test_denied_endpoint_with_clean_headers_is_inconclusive(self):
    good = {"Access-Control-Allow-Origin": "https://trusted.example",
            "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}
    for admin, reason in (("provided", "endpoint_denied"),
                          ("absent", "admin_context_absent")):
      for name in ("403", "404", "login"):
        for sid, method in self.CASES:
          with self.subTest(admin=admin, denial=name, sid=sid):
            p = _make_probe(function_endpoints=[ApiFunctionEndpoint(path="/api/me/")])
            p.auth.admin_context = admin
            denial = _login_page() if name == "login" else _resp(status=int(name))
            denial.headers = dict(good)
            p.auth.official_session.get.return_value = denial
            getattr(p, method)()
            found = [f for f in p.findings if f.scenario_id == sid]
            self.assertEqual([f.status for f in found], ["inconclusive"])
            self.assertEqual(found[0].evidence, [f"reason={reason}"])

  def test_bad_headers_on_a_denied_response_are_vulnerable(self):
    p = _make_probe(function_endpoints=[ApiFunctionEndpoint(path="/api/me/")])
    p.auth.admin_context = "absent"
    p.auth.official_session.get.return_value = _resp(
      status=403, headers={"Access-Control-Allow-Origin": "*",
                           "Access-Control-Allow-Credentials": "true"})
    p._test_cors_misconfig()
    p._test_security_headers()
    self.assertEqual(
      sorted((f.scenario_id, f.status) for f in p.findings),
      [("PT-OAPI8-01", "vulnerable"), ("PT-OAPI8-02", "vulnerable")])

  def test_endpoint_privilege_user_or_anon_is_tested_as_regular(self):
    eps = [ApiFunctionEndpoint(path="/api/admin/", privilege="admin"),
           ApiFunctionEndpoint(path="/api/me/", privilege="user"),
           ApiFunctionEndpoint(path="/api/open/", privilege="anon")]
    for sid, method in self.CASES:
      with self.subTest(sid=sid):
        p = _make_probe(function_endpoints=eps)
        p.auth.admin_context = "provided"
        ok = _resp(status=200, headers={"Access-Control-Allow-Origin": "x",
                                        "X-Content-Type-Options": "nosniff",
                                        "Cache-Control": "no-store"})
        p.auth.official_session.get.return_value = ok
        p.auth.regular_session.get.return_value = ok
        getattr(p, method)()
        official = {c.args[0] for c in p.auth.official_session.get.call_args_list}
        regular = {c.args[0] for c in p.auth.regular_session.get.call_args_list}
        self.assertEqual(official, {"http://api.example/api/admin/"})
        self.assertEqual(regular, {"http://api.example/api/me/",
                                   "http://api.example/api/open/"})

  def test_reached_endpoint_with_good_headers_is_clean(self):
    p = _make_probe(function_endpoints=[ApiFunctionEndpoint(path="/api/me/")])
    p.auth.official_session.get.return_value = _resp(
      headers={"Access-Control-Allow-Origin": "https://trusted.example"})
    p._test_cors_misconfig()
    self.assertEqual([f.status for f in p.findings], ["not_vulnerable"])


class TestApi8DebugEndpointExposed(unittest.TestCase):

  def test_actuator_env_emits_medium(self):
    p = _make_probe()
    p.auth.official_session.get.return_value = _resp(
      status=200,
      text='{"swagger":"2.0","DEBUG":true}',
    )
    p.run_safe("api_debug_endpoint", p._test_debug_endpoint_exposed)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI8-03" and f.status == "vulnerable"]
    self.assertTrue(len(vuln) >= 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")


class TestApi8VerboseError(unittest.TestCase):

  def test_stack_trace_in_response_medium(self):
    ep = ApiFunctionEndpoint(path="/api/me/", allow_malformed_json_probe=True)
    p = _make_probe(function_endpoints=[ep])
    p.auth.official_session.post.return_value = _resp(
      status=500,
      text='Traceback (most recent call last):\n  File "/usr/lib/python3/foo.py", line 12',
    )
    p.run_safe("api_verbose_error", p._test_verbose_error)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI8-04" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)


class TestApi8UnexpectedMethods(unittest.TestCase):

  def test_trace_method_advertised_low(self):
    ep = ApiFunctionEndpoint(path="/api/me/", method="GET")
    p = _make_probe(function_endpoints=[ep])
    p.auth.official_session.options.return_value = _resp(
      status=200, headers={"Allow": "GET, POST, TRACE, DELETE"},
    )
    p.run_safe("api_unexpected_methods", p._test_unexpected_methods)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI8-05" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)


class TestApi9OpenApiExposed(unittest.TestCase):

  def test_swagger_with_private_paths_medium(self):
    inv = ApiInventoryPaths(
      openapi_candidates=["/openapi.json"],
      private_path_patterns=["/internal/"],
    )
    p = _make_probe(inventory_paths=inv)
    p.auth.make_anonymous_session.return_value.get.return_value = _resp(
      json_body={
        "openapi": "3.0.0",
        "paths": {"/api/v2/users/": {}, "/api/internal/admin/": {}},
      },
    )
    p.run_safe("api_openapi_exposed", p._test_openapi_exposed)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI9-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")


class TestApi9VersionSprawl(unittest.TestCase):

  def test_legacy_v1_alive_emits_medium(self):
    inv = ApiInventoryPaths(
      current_version="/api/v2/",
      canonical_probe_path="/api/v2/records/1/",
      version_sibling_candidates=["/api/v1/"],
    )
    p = _make_probe(inventory_paths=inv)
    # The v2 baseline is implicit; we only probe siblings.
    p.auth.official_session.get.return_value = _resp(
      status=200, json_body={"id": 1},
    )
    p.run_safe("api_version_sprawl", p._test_version_sprawl)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI9-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)


class TestApi9DeprecatedLive(unittest.TestCase):

  def test_deprecated_returns_200_emits_medium(self):
    inv = ApiInventoryPaths(deprecated_paths=["/api/v1/legacy/"])
    p = _make_probe(inventory_paths=inv)
    p.auth.official_session.get.return_value = _resp(
      status=200, json_body={"ok": True},
    )
    p.run_safe("api_deprecated_live", p._test_deprecated_live)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI9-03" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)


if __name__ == "__main__":
  unittest.main()
