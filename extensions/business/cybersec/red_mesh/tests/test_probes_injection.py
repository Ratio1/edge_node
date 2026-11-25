"""Tests for InjectionProbes."""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.probes.injection import InjectionProbes
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig, InjectionConfig, SsrfEndpoint,
  ReflectiveEndpoint, JsonLookupEndpoint,
)


def _mock_response(status=200, text="", headers=None, content_type="text/html"):
  resp = MagicMock()
  resp.status_code = status
  resp.text = text
  h = {"content-type": content_type}
  if headers:
    h.update(headers)
  resp.headers = h
  return resp


def _make_probe(ssrf_endpoints=None, discovered_forms=None,
                primary_session=None, allow_stateful=False,
                login_path="/auth/login/", logout_path="/auth/logout/",
                xss_endpoints=None, ssti_endpoints=None,
                cmd_endpoints=None, header_endpoints=None,
                json_type_endpoints=None):
  cfg = GrayboxTargetConfig(
    injection=InjectionConfig(
      ssrf_endpoints=ssrf_endpoints or [],
      xss_endpoints=xss_endpoints or [],
      ssti_endpoints=ssti_endpoints or [],
      cmd_endpoints=cmd_endpoints or [],
      header_endpoints=header_endpoints or [],
      json_type_endpoints=json_type_endpoints or [],
    ),
    login_path=login_path,
    logout_path=logout_path,
  )
  auth = MagicMock()
  auth.primary_session = primary_session or MagicMock()
  auth.anon_session = MagicMock()
  auth.detected_csrf_field = None
  auth.extract_csrf_value = MagicMock(return_value=None)
  safety = MagicMock()
  safety.throttle = MagicMock()

  probe = InjectionProbes(
    target_url="http://testapp.local:8000",
    auth_manager=auth,
    target_config=cfg,
    safety=safety,
    discovered_forms=discovered_forms or [],
    allow_stateful=allow_stateful,
  )
  return probe


class TestSsrfProbe(unittest.TestCase):

  def test_ssrf_reflected(self):
    """Callback in response body → inconclusive (no out-of-band proof, D29)."""
    ep = SsrfEndpoint(path="/api/fetch/", param="url")
    probe = _make_probe(ssrf_endpoints=[ep])
    session = probe.auth.primary_session

    # Baseline
    baseline_resp = _mock_response(status=200, text="nothing")
    # Probe: reflected SSRF
    probe_resp = _mock_response(
      status=200, text="fetched: http://127.0.0.1:1/internal-probe data",
    )
    session.get.side_effect = [baseline_resp, probe_resp]

    probe._test_ssrf()
    found = [f for f in probe.findings if f.scenario_id == "PT-API7-01"]
    self.assertEqual([f.status for f in found], ["inconclusive"])
    self.assertIn("reason=ssrf_reflection_only", found[0].evidence)
    self.assertIn("CWE-918", found[0].cwe)

  def test_ssrf_respects_runtime_assignment_gate(self):
    ep = SsrfEndpoint(path="/api/fetch/", param="url")
    probe = _make_probe(ssrf_endpoints=[ep])
    probe.allowed_scenario_ids = {"PT-OAPI2-01"}

    probe.run_safe_scenario("PT-API7-01", "ssrf", probe._test_ssrf)

    probe.auth.primary_session.get.assert_not_called()
    self.assertFalse(
      any(f.scenario_id == "PT-API7-01" for f in probe.findings),
    )

  def test_ssrf_no_hit(self):
    """Normal response → no finding."""
    ep = SsrfEndpoint(path="/api/fetch/", param="url")
    probe = _make_probe(ssrf_endpoints=[ep])
    session = probe.auth.primary_session

    resp = _mock_response(status=200, text="safe content")
    session.get.return_value = resp

    probe._test_ssrf()
    api7 = [f for f in probe.findings if f.scenario_id == "PT-API7-01"]
    self.assertEqual(len(api7), 0)


class TestTheTwoSsrfVariantsAreSeparateFindings(unittest.TestCase):
  """
  `_test_ssrf` and `_test_ssrf_body_field` both run under `PT-API7-01`, both on
  the same endpoint, both `CWE-918`, both `API7:2023`. Severity is not part of
  identity, and neither is the title, so a target vulnerable to both the query
  parameter and the JSON body field produced two findings under one
  `finding_id` — and triage on either closed both.

  The distinguishing value is already in each probe's evidence (`ep.param` and
  `body_field`); it just was not in a typed field that reaches
  `canonical_asset_string`.
  """

  def _both_variants(self):
    import dataclasses
    from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
      ApiSecurityConfig,
    )
    ep = SsrfEndpoint(path="/api/fetch/", param="url")
    probe = _make_probe(ssrf_endpoints=[ep])
    # The config dataclasses are frozen; rebuild rather than mutate.
    probe.target_config = dataclasses.replace(
      probe.target_config,
      api_security=ApiSecurityConfig(ssrf_body_fields=["callback"]),
    )
    session = probe.auth.primary_session

    hit = _mock_response(
      status=200, text="fetched: http://127.0.0.1:1/internal-probe data",
    )
    session.get.side_effect = [_mock_response(status=200, text="nothing"), hit]
    probe._test_ssrf()
    session.post.return_value = hit
    probe._test_ssrf_body_field()

    vuln = [f for f in probe.findings
            if f.scenario_id == "PT-API7-01" and f.status == "inconclusive"]
    self.assertEqual(len(vuln), 2, "expected one finding per SSRF variant")
    return [f.to_flat_finding(8000, "http", "_graybox_injection") for f in vuln]

  def test_the_two_variants_do_not_share_a_finding_id(self):
    a, b = self._both_variants()
    self.assertNotEqual(
      a["finding_id"], b["finding_id"],
      "query-parameter and body-field SSRF on one endpoint share an id, so "
      "triaging one closes the other",
    )

  def test_each_variant_names_what_it_injected(self):
    a, b = self._both_variants()
    params = {f["affected_assets"][0]["parameter"] for f in (a, b)}
    self.assertEqual(params, {"url", "callback"})

  def test_each_variant_records_the_verb_it_actually_issued(self):
    """`method` is part of identity, so a wrong literal rotates ids silently.

    `_test_ssrf` issues `session.get`, `_test_ssrf_body_field` issues
    `session.post`; the typed fields must say so.
    """
    a, b = self._both_variants()
    self.assertEqual(
      {f["affected_assets"][0]["method"] for f in (a, b)}, {"GET", "POST"},
    )

  def test_the_variants_stay_distinct_when_the_body_field_matches_the_param(self):
    """The default config makes this the ordinary case, not the corner one.

    `ssrf_body_fields` defaults to a list beginning `url`, and `ep.param` is
    commonly `url` too — so `parameter` is identical and `method` is the only
    thing separating the two findings.
    """
    import dataclasses
    from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
      ApiSecurityConfig,
    )
    probe = _make_probe(ssrf_endpoints=[SsrfEndpoint(path="/api/fetch/", param="url")])
    probe.target_config = dataclasses.replace(
      probe.target_config, api_security=ApiSecurityConfig(ssrf_body_fields=["url"]),
    )
    session = probe.auth.primary_session
    hit = _mock_response(status=200, text="fetched: http://127.0.0.1:1/internal-probe")
    session.get.side_effect = [_mock_response(status=200, text="nothing"), hit]
    probe._test_ssrf()
    session.post.return_value = hit
    probe._test_ssrf_body_field()

    flat = [f.to_flat_finding(8000, "http", "_graybox_injection")
            for f in probe.findings if f.status == "inconclusive"]
    self.assertEqual(len(flat), 2)
    self.assertNotEqual(flat[0]["finding_id"], flat[1]["finding_id"])


class TestLoginInjection(unittest.TestCase):

  def test_login_injection_no_reflection(self):
    """No reflection → not_vulnerable."""
    probe = _make_probe()
    anon = MagicMock()
    anon.get.return_value = _mock_response(
      text='<form><input name="username"><input name="password"></form>',
    )
    anon.post.return_value = _mock_response(text="Invalid credentials")
    anon.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = anon
    probe.auth.detected_csrf_field = None

    probe._test_login_injection()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A05-01" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)


class TestAuthenticatedInjection(unittest.TestCase):

  def test_authenticated_injection(self):
    """Payload reflected in form → finding."""
    probe = _make_probe(discovered_forms=["/search/"])
    session = probe.auth.primary_session
    # GET the form page → has text input
    session.get.return_value = _mock_response(
      text='<form><input name="q" type="text"></form>',
    )
    # POST with payload → reflection
    session.post.return_value = _mock_response(
      text='Results for: <script>alert(1)</script>',
    )

    probe._test_authenticated_injection()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A03-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)

  def test_authenticated_injection_no_forms(self):
    """No forms → skip."""
    probe = _make_probe(discovered_forms=[])
    probe._test_authenticated_injection()
    self.assertEqual(len(probe.findings), 0)

  def test_authenticated_injection_skips_login(self):
    """Login form excluded from authenticated injection."""
    probe = _make_probe(
      discovered_forms=["/auth/login/", "/search/"],
      login_path="/auth/login/",
    )
    session = probe.auth.primary_session
    # Only /search/ should be tested
    session.get.return_value = _mock_response(
      text='<form><input name="q" type="text"></form>',
    )
    session.post.return_value = _mock_response(text="No reflection here")

    probe._test_authenticated_injection()
    # Should have tested 1 form (not 2)
    # Check that no vulnerable finding for login form
    for f in probe.findings:
      if f.status == "vulnerable":
        for ev in f.evidence:
          self.assertNotIn("/auth/login/", ev)


class TestStoredXss(unittest.TestCase):

  def test_stored_xss_detected(self):
    """Canary reflected unescaped → vulnerable."""
    probe = _make_probe(
      discovered_forms=["/comments/"],
      allow_stateful=True,
    )
    session = probe.auth.primary_session

    # GET form page with text input
    form_html = '<form><input name="comment" type="text"></form>'
    # On readback, the canary is reflected unescaped
    call_count = [0]

    def mock_get(url, **kwargs):
      call_count[0] += 1
      if call_count[0] == 1:
        return _mock_response(text=form_html)
      else:
        # Readback — extract the canary from the POST
        # We need to include both the canary and the full payload
        return _mock_response(
          text="<div>XSS-CANARY-12345678 <img src=x onerror=alert('XSS-CANARY-12345678')></div>",
        )

    session.get.side_effect = mock_get
    session.post.return_value = _mock_response(text="Saved")

    # Patch uuid to get predictable canary
    import unittest.mock
    with unittest.mock.patch("uuid.uuid4") as mock_uuid:
      mock_uuid.return_value.hex = "12345678abcdef01"
      probe._test_stored_xss()

    vuln = [f for f in probe.findings if f.scenario_id == "PT-A03-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")
    self.assertIn("CWE-79", vuln[0].cwe)

  def test_stored_xss_escaped(self):
    """Canary HTML-encoded → not_vulnerable."""
    probe = _make_probe(
      discovered_forms=["/comments/"],
      allow_stateful=True,
    )
    session = probe.auth.primary_session

    form_html = '<form><input name="comment" type="text"></form>'
    call_count = [0]

    def mock_get(url, **kwargs):
      call_count[0] += 1
      if call_count[0] == 1:
        return _mock_response(text=form_html)
      else:
        return _mock_response(text="<div>&lt;img src=x&gt;</div>")

    session.get.side_effect = mock_get
    session.post.return_value = _mock_response(text="Saved")

    probe._test_stored_xss()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A03-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 0)
    clean = [f for f in probe.findings if f.scenario_id == "PT-A03-02" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_stored_xss_skips_login(self):
    """Login/logout forms excluded."""
    probe = _make_probe(
      discovered_forms=["/auth/login/", "/auth/logout/"],
      allow_stateful=True,
      login_path="/auth/login/",
      logout_path="/auth/logout/",
    )

    probe._test_stored_xss()
    # No forms tested → no findings
    self.assertEqual(len(probe.findings), 0)

  def test_stored_xss_gated(self):
    """Skipped when allow_stateful=False → emits inconclusive."""
    probe = _make_probe(
      discovered_forms=["/comments/"],
      allow_stateful=False,
    )

    # The gating is in run(), not _test_stored_xss directly
    # We need to call run() and check it emits the skip finding
    # Set up minimal mocks for other probes that run() calls
    anon = MagicMock()
    anon.get.return_value = _mock_response(text="no reflection")
    anon.post.return_value = _mock_response(text="no reflection")
    anon.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = anon

    findings = probe.run()
    skip = [f for f in findings if f.scenario_id == "PT-A03-02" and f.status == "inconclusive"]
    self.assertEqual(len(skip), 1)
    self.assertIn("stateful_probes_disabled=True", skip[0].evidence)


class TestOpenRedirect(unittest.TestCase):

  def test_open_redirect_detected(self):
    """Redirect to evil domain → vulnerable/MEDIUM."""
    probe = _make_probe()
    session = probe.auth.primary_session

    # Response: 302 redirect to evil.example.com
    redirect_resp = _mock_response(status=302, text="")
    redirect_resp.headers["Location"] = "//evil.example.com"
    session.get = MagicMock(return_value=redirect_resp)

    probe._test_open_redirect()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A01-04" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")
    self.assertIn("CWE-601", vuln[0].cwe)

  def test_open_redirect_never_requests_logout_path(self):
    """RM-219: a GET of the logout URL would end the scan session."""
    probe = _make_probe()
    probe.discovered_routes = ["/auth/logout/", "/records/"]
    session = probe.auth.primary_session
    session.get = MagicMock(return_value=_mock_response(status=200, text="Normal page"))

    probe._test_open_redirect()
    urls = [c.args[0] for c in session.get.call_args_list]
    self.assertTrue(any(u.endswith("/records/") for u in urls))
    self.assertFalse(any(u.endswith("/auth/logout/") for u in urls), urls)

  def test_open_redirect_safe(self):
    """No redirect → not_vulnerable."""
    probe = _make_probe()
    session = probe.auth.primary_session
    session.get = MagicMock(return_value=_mock_response(status=200, text="Normal page"))

    probe._test_open_redirect()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A01-04" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_open_redirect_internal_redirect(self):
    """Redirect to same domain → not vulnerable."""
    probe = _make_probe()
    session = probe.auth.primary_session

    redirect_resp = _mock_response(status=302, text="")
    redirect_resp.headers["Location"] = "/dashboard/"
    session.get = MagicMock(return_value=redirect_resp)

    probe._test_open_redirect()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A01-04" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 0)


class TestPathTraversal(unittest.TestCase):

  def test_path_traversal_detected(self):
    """/etc/passwd content in response → vulnerable/HIGH."""
    probe = _make_probe()
    probe.discovered_routes = ["/download/"]
    session = probe.auth.primary_session

    normal_resp = _mock_response(status=200, text="Normal content")
    passwd_resp = _mock_response(
      status=200,
      text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin\n",
    )

    call_count = [0]
    def mock_get(url, **kwargs):
      call_count[0] += 1
      params = kwargs.get("params", {})
      for v in params.values():
        if "etc/passwd" in str(v):
          return passwd_resp
      return normal_resp

    session.get = MagicMock(side_effect=mock_get)

    probe._test_path_traversal()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A03-03" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")
    self.assertIn("CWE-22", vuln[0].cwe)

  def test_path_traversal_safe(self):
    """No file content markers → not_vulnerable."""
    probe = _make_probe()
    probe.discovered_routes = ["/page/"]
    session = probe.auth.primary_session
    session.get = MagicMock(return_value=_mock_response(status=200, text="Safe page content"))

    probe._test_path_traversal()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A03-03" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_path_traversal_no_session(self):
    """No official session → skip."""
    probe = _make_probe(primary_session=None)
    probe.auth.primary_session = None
    probe._test_path_traversal()
    self.assertEqual(len(probe.findings), 0)


class TestReflectedXssPTA0304(unittest.TestCase):
  """PT-A03-04 — reflected XSS behind authentication."""

  def test_pt_a03_04_vulnerable_when_payload_reflected(self):
    ep = ReflectiveEndpoint(path="/api/echo/", param="msg")
    probe = _make_probe(xss_endpoints=[ep])
    probe.auth.primary_session.get = MagicMock(return_value=_mock_response(
      status=200, text="<p><script>alert(1)</script></p>",
    ))
    probe._test_reflected_xss()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-04"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")

  def test_pt_a03_04_not_vulnerable_when_escaped(self):
    ep = ReflectiveEndpoint(path="/api/echo/", param="msg")
    probe = _make_probe(xss_endpoints=[ep])
    probe.auth.primary_session.get = MagicMock(return_value=_mock_response(
      status=200, text="<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>",
    ))
    probe._test_reflected_xss()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-04"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")

  def test_pt_a03_04_silent_when_no_endpoints(self):
    probe = _make_probe(xss_endpoints=[])
    probe._test_reflected_xss()
    self.assertFalse(any(f.scenario_id == "PT-A03-04" for f in probe.findings))


class TestTemplateInjectionPTA0306(unittest.TestCase):
  """PT-A03-06 — server-side template injection."""

  def test_pt_a03_06_vulnerable_when_expression_evaluated(self):
    ep = ReflectiveEndpoint(path="/api/template/", param="expr")
    probe = _make_probe(ssti_endpoints=[ep])
    probe.auth.primary_session.get = MagicMock(return_value=_mock_response(
      status=200, text="<pre>49</pre>",
    ))
    probe._test_template_injection()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-06"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")

  def test_pt_a03_06_not_vulnerable_when_payload_echoed(self):
    """Echo-only sink: body shows ``${7*7}`` literal — must not flag."""
    ep = ReflectiveEndpoint(path="/api/template/", param="expr")
    probe = _make_probe(ssti_endpoints=[ep])
    probe.auth.primary_session.get = MagicMock(return_value=_mock_response(
      status=200, text="<pre>${7*7}</pre>",
    ))
    probe._test_template_injection()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-06"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")


class TestCommandInjectionPTA0307(unittest.TestCase):
  """PT-A03-07 — OS command injection."""

  def test_pt_a03_07_vulnerable_on_uid_marker(self):
    ep = ReflectiveEndpoint(path="/api/exec/", param="cmd")
    probe = _make_probe(cmd_endpoints=[ep])
    probe.auth.primary_session.get = MagicMock(return_value=_mock_response(
      status=200, text='{"cmd":";id","output":"OK\\nuid=33(www-data) gid=33"}',
    ))
    probe._test_command_injection()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-07"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")
    self.assertEqual(f[0].severity, "HIGH")

  def test_pt_a03_07_not_vulnerable_when_no_uid_marker(self):
    ep = ReflectiveEndpoint(path="/api/exec/", param="cmd")
    probe = _make_probe(cmd_endpoints=[ep])
    probe.auth.primary_session.get = MagicMock(return_value=_mock_response(
      status=200, text='{"output":"OK"}',
    ))
    probe._test_command_injection()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-07"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")


class TestHeaderInjectionPTA0312(unittest.TestCase):
  """PT-A03-12 — CRLF header injection."""

  def test_pt_a03_12_vulnerable_when_header_set(self):
    ep = ReflectiveEndpoint(path="/api/redirect/", param="next")
    probe = _make_probe(header_endpoints=[ep])
    probe.auth.primary_session.get = MagicMock(return_value=_mock_response(
      status=302, text="",
      headers={"X-Injected": "pwned", "Location": "/safe-target"},
    ))
    probe._test_header_injection()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-12"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")

  def test_pt_a03_12_not_vulnerable_when_header_stripped(self):
    ep = ReflectiveEndpoint(path="/api/redirect/", param="next")
    probe = _make_probe(header_endpoints=[ep])
    probe.auth.primary_session.get = MagicMock(return_value=_mock_response(
      status=302, text="", headers={"Location": "/safe-target"},
    ))
    probe._test_header_injection()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-12"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")


class TestJsonTypeConfusionPTA0315(unittest.TestCase):
  """PT-A03-15 — JSON body type confusion."""

  def test_pt_a03_15_vulnerable_when_list_accepted(self):
    ep = JsonLookupEndpoint(path="/api/lookup/", field="id")
    probe = _make_probe(json_type_endpoints=[ep])
    probe.auth.primary_session.post = MagicMock(side_effect=[
      _mock_response(status=200, text='{"matched":1}'),  # baseline int
      _mock_response(status=400, text='{"error":"id_must_be_integer"}'),  # control
      _mock_response(status=200, text='{"matched":1}'),  # variant list
    ])
    probe._test_json_type_confusion()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-15"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")

  def test_pt_a03_15_inconclusive_when_endpoint_ignores_the_field(self):
    """The invalid-string control is accepted too: nothing validates the field."""
    ep = JsonLookupEndpoint(path="/api/lookup/", field="id")
    probe = _make_probe(json_type_endpoints=[ep])
    probe.auth.primary_session.post = MagicMock(
      return_value=_mock_response(status=200, text='{"matched":1}'))
    probe._test_json_type_confusion()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-15"]
    self.assertEqual([x.status for x in f], ["inconclusive"])
    self.assertIn("reason=json_type_not_validated", f[0].evidence)
    self.assertIn("endpoint=/api/lookup/", f[0].evidence)
    self.assertEqual(probe.auth.primary_session.post.call_count, 2)

  def _json_probe(self, responses):
    probe = _make_probe(json_type_endpoints=[
      JsonLookupEndpoint(path="/api/lookup/", field="id")])
    probe.auth.primary_session.post = MagicMock(side_effect=responses)
    probe._test_json_type_confusion()
    return probe, [x for x in probe.findings if x.scenario_id == "PT-A03-15"]

  def test_pt_a03_15_200_with_error_body_everywhere_is_not_vulnerable(self):
    ok = _mock_response(status=200, text='{"matched":1}')
    err = _mock_response(status=200, text='{"error":"invalid"}')
    _, f = self._json_probe([ok, err, err, err])
    self.assertEqual([x.status for x in f], ["not_vulnerable"])

  def test_pt_a03_15_control_with_null_error_counts_as_accepted(self):
    ok = _mock_response(status=200, text='{"matched":1}')
    null_err = _mock_response(status=200, text='{"error":null,"matched":0}')
    _, f = self._json_probe([ok, null_err])
    self.assertEqual([x.status for x in f], ["inconclusive"])
    self.assertIn("reason=json_type_not_validated", f[0].evidence)

  def test_pt_a03_15_5xx_control_skips_the_endpoint(self):
    ok = _mock_response(status=200, text='{"matched":1}')
    probe, f = self._json_probe([ok, _mock_response(status=500, text="boom")])
    self.assertEqual(f, [])
    self.assertEqual(probe.auth.primary_session.post.call_count, 2)

  def test_pt_a03_15_only_the_gt_variant_accepted_is_vulnerable(self):
    ok = _mock_response(status=200, text='{"matched":1}')
    bad = _mock_response(status=400, text='{"error":"id_must_be_integer"}')
    _, f = self._json_probe([ok, bad, bad, _mock_response(status=200, text='{"matched":50}')])
    self.assertEqual([x.status for x in f], ["vulnerable"])
    self.assertTrue(any("$gt" in e for e in f[0].evidence))

  def test_pt_a03_15_not_vulnerable_when_list_rejected(self):
    ep = JsonLookupEndpoint(path="/api/lookup/", field="id")
    probe = _make_probe(json_type_endpoints=[ep])
    probe.auth.primary_session.post = MagicMock(side_effect=[
      _mock_response(status=200, text='{"matched":1}'),       # baseline OK
      _mock_response(status=400, text='{"error":"id_must_be_integer"}'),  # control
      _mock_response(status=400, text='{"error":"id_must_be_integer"}'),
      _mock_response(status=400, text='{"error":"id_must_be_integer"}'),
    ])
    probe._test_json_type_confusion()
    f = [x for x in probe.findings if x.scenario_id == "PT-A03-15"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")


class TestCapabilities(unittest.TestCase):

  def test_capabilities(self):
    """InjectionProbes declares correct capabilities."""
    self.assertTrue(InjectionProbes.requires_auth)
    self.assertFalse(InjectionProbes.requires_regular_session)
    self.assertFalse(InjectionProbes.is_stateful)

  def test_all_findings_are_graybox(self):
    """All findings are GrayboxFinding."""
    probe = _make_probe(discovered_forms=["/search/"])
    session = probe.auth.primary_session
    session.get.return_value = _mock_response(
      text='<form><input name="q" type="text"></form>',
    )
    session.post.return_value = _mock_response(text="safe")

    probe._test_authenticated_injection()
    for f in probe.findings:
      self.assertIsInstance(f, GrayboxFinding)


if __name__ == '__main__':
  unittest.main()


# ── RM-219 reachability rule ────────────────────────────────────────────

LOGIN_URL = "http://testapp.local:8000/auth/login/?next=/x/"


def _denial(kind):
  """A response that did not reach the handler: 403, 404, or a login redirect."""
  if kind == "login":
    resp = _mock_response(status=200, text="<form><input name='username'>"
                          "<input type='password' name='password'></form>")
    resp.url = LOGIN_URL
    resp.history = [MagicMock(headers={"Location": "/auth/login/?next=/x/"})]
    return resp
  return _mock_response(status=int(kind), text="denied")


def _ok(text="fine"):
  resp = _mock_response(status=200, text=text)
  resp.url = "http://testapp.local:8000/x/"
  resp.history = []
  return resp


def _reason(probe, scenario_id):
  found = [f for f in probe.findings if f.scenario_id == scenario_id]
  return found, [e for f in found for e in f.evidence if e.startswith("reason=")]


class TestReachabilityRuleInjection(unittest.TestCase):
  """Every denied endpoint is inconclusive, with admin present and absent."""

  CASES = [
    ("PT-A03-01", "_test_authenticated_injection", "get"),
    ("PT-A03-02", "_test_stored_xss", "get"),
    ("PT-A03-03", "_test_path_traversal", "get"),
    ("PT-A03-04", "_test_reflected_xss", "get"),
    ("PT-A03-06", "_test_template_injection", "get"),
    ("PT-A03-07", "_test_command_injection", "get"),
    ("PT-A03-12", "_test_header_injection", "get"),
    ("PT-A03-15", "_test_json_type_confusion", "post"),
  ]

  def _probe(self, admin_context):
    ep = ReflectiveEndpoint(path="/api/x/", param="q")
    probe = _make_probe(
      discovered_forms=["/records/new/"],
      xss_endpoints=[ep], ssti_endpoints=[ep], cmd_endpoints=[ep],
      header_endpoints=[ep],
      json_type_endpoints=[JsonLookupEndpoint(path="/api/lookup/", field="id")],
    )
    probe.discovered_routes = ["/records/"]
    probe.auth.admin_context = admin_context
    return probe

  def test_denied_endpoint_is_inconclusive_with_reason(self):
    for admin, reason in (("provided", "endpoint_denied"),
                          ("absent", "admin_context_absent")):
      for kind in ("403", "404", "login"):
        for sid, method, verb in self.CASES:
          with self.subTest(admin=admin, kind=kind, sid=sid):
            probe = self._probe(admin)
            session = probe.auth.primary_session
            setattr(session, verb, MagicMock(side_effect=lambda *a, **k: _denial(kind)))
            getattr(probe, method)()
            found, reasons = _reason(probe, sid)
            self.assertEqual([f.status for f in found], ["inconclusive"])
            self.assertEqual(reasons, [f"reason={reason}"])

  def test_baseline_reached_but_payload_redirected_to_login(self):
    """GET baseline reaches the handler, the payload POST bounces to login."""
    probe = self._probe("absent")
    session = probe.auth.primary_session
    session.get = MagicMock(return_value=_ok(
      '<form><input name="title" type="text"></form>'))
    session.post = MagicMock(side_effect=lambda *a, **k: _denial("login"))
    probe._test_authenticated_injection()
    found, reasons = _reason(probe, "PT-A03-01")
    self.assertEqual([f.status for f in found], ["inconclusive"])
    self.assertEqual(reasons, ["reason=admin_context_absent"])

  def test_stored_xss_post_redirected_to_login_is_not_clean(self):
    """Form GET reaches the handler, the payload POST bounces to login: no
    clean verdict from a readback of a form that never took the payload."""
    for admin, reason in (("provided", "endpoint_denied"),
                          ("absent", "admin_context_absent")):
      with self.subTest(admin=admin):
        probe = self._probe(admin)
        session = probe.auth.primary_session
        session.get = MagicMock(return_value=_ok(
          '<form><input name="comment" type="text"></form>'))
        session.post = MagicMock(side_effect=lambda *a, **k: _denial("login"))
        probe._test_stored_xss()
        found, reasons = _reason(probe, "PT-A03-02")
        self.assertEqual([f.status for f in found], ["inconclusive"])
        self.assertEqual(reasons, [f"reason={reason}"])

  def test_stored_xss_readback_redirected_to_login_is_not_clean(self):
    """POST reached, but the readback GET bounces to login: the payload was
    never looked for, so no clean verdict."""
    probe = self._probe("absent")
    session = probe.auth.primary_session
    session.get = MagicMock(side_effect=[
      _ok('<form><input name="comment" type="text"></form>'), _denial("login")])
    session.post = MagicMock(return_value=_ok("saved"))
    probe._test_stored_xss()
    found, reasons = _reason(probe, "PT-A03-02")
    self.assertEqual([f.status for f in found], ["inconclusive"])
    self.assertEqual(reasons, ["reason=admin_context_absent"])

  def test_json_payload_redirected_to_login_after_reached_baseline(self):
    probe = self._probe("provided")
    session = probe.auth.primary_session
    session.post = MagicMock(side_effect=[_ok('{"matched":1}'), _denial("login"),
                                          _denial("login")])
    probe._test_json_type_confusion()
    found, reasons = _reason(probe, "PT-A03-15")
    self.assertEqual([f.status for f in found], ["inconclusive"])
    self.assertEqual(reasons, ["reason=endpoint_denied"])

  def test_post_only_action_405_is_decided_by_the_payload_response(self):
    """405 on the GET baseline, stateful probes allowed: the payload POST decides."""
    probe = self._probe("absent")
    probe._allow_stateful = True
    probe.auth.primary_session.get = MagicMock(return_value=_denial("405"))
    probe.auth.primary_session.post = MagicMock(
      side_effect=lambda url, data=None, **k: _ok(next(iter(data.values()))))
    probe._test_authenticated_injection()
    found, _ = _reason(probe, "PT-A03-01")
    self.assertEqual({f.status for f in found}, {"vulnerable"})
    probe = self._probe("absent")
    probe._allow_stateful = True
    probe.auth.primary_session.get = MagicMock(return_value=_denial("405"))
    probe.auth.primary_session.post = MagicMock(side_effect=lambda *a, **k: _denial("403"))
    probe._test_authenticated_injection()
    found, reasons = _reason(probe, "PT-A03-01")
    self.assertEqual([f.status for f in found], ["inconclusive"])
    self.assertEqual(reasons, ["reason=admin_context_absent"])

  def test_post_only_action_405_sends_no_post_without_allow_stateful(self):
    """POST-only actions often create or delete records: no payload POST
    unless stateful probes are allowed."""
    probe = self._probe("absent")
    probe.auth.primary_session.get = MagicMock(return_value=_denial("405"))
    probe.auth.primary_session.post = MagicMock()
    probe._test_authenticated_injection()
    probe.auth.primary_session.post.assert_not_called()

  def test_post_answered_by_redirect_to_non_login_page_is_reached(self):
    """JSON POST answered by a 3xx to a non-login page counts as reached."""
    probe = self._probe("provided")
    redirect = _mock_response(status=302, text="")
    redirect.headers["Location"] = "/records/"
    probe.auth.primary_session.post = MagicMock(side_effect=[
      redirect, _mock_response(status=400, text="bad"), redirect])
    probe._test_json_type_confusion()
    found, _ = _reason(probe, "PT-A03-15")
    self.assertEqual([f.status for f in found], ["vulnerable"])

  def test_clean_only_when_an_endpoint_was_reached(self):
    probe = _make_probe(xss_endpoints=[
      ReflectiveEndpoint(path="/api/a/", param="q"),
      ReflectiveEndpoint(path="/api/b/", param="q"),
    ])
    probe.auth.admin_context = "absent"
    ok = _ok("nothing here")
    probe.auth.primary_session.get = MagicMock(side_effect=[
      _denial("403"), ok, ok, ok,  # first endpoint denied, second reached
    ])
    probe._test_reflected_xss()
    found, _ = _reason(probe, "PT-A03-04")
    self.assertEqual([f.status for f in found], ["not_vulnerable"])

  def test_payload_denied_after_reached_baseline_is_not_clean(self):
    probe = self._probe("absent")
    probe.auth.primary_session.get = MagicMock(side_effect=[_ok(), _denial("403")])
    probe._test_template_injection()
    found, reasons = _reason(probe, "PT-A03-06")
    self.assertEqual([f.status for f in found], ["inconclusive"])


class TestOpenRedirectReachability(unittest.TestCase):

  def _probe(self, admin_context="absent"):
    probe = _make_probe()
    probe.discovered_routes = ["/records/"]
    probe.auth.admin_context = admin_context
    return probe

  def test_login_next_echo_is_not_an_open_redirect(self):
    """A login redirect that echoes ?next=//evil.example.com is not reported."""
    probe = self._probe()

    def get(url, params=None, **kw):
      resp = _mock_response(status=302, text="")
      resp.headers["Location"] = "/auth/login/?next=//evil.example.com" if params else "/auth/login/"
      return resp
    probe.auth.primary_session.get = MagicMock(side_effect=get)
    probe._test_open_redirect()
    # The login page itself was reached and handled ?next= safely; /records/
    # bounced to login and is not counted.
    self.assertEqual([f.status for f in probe.findings if f.scenario_id == "PT-A01-04"],
                     ["not_vulnerable"])

  def test_login_path_stays_a_target_judged_by_parsed_host(self):
    probe = self._probe()

    def get(url, params=None, **kw):
      resp = _mock_response(status=302 if params else 200, text="")
      if params:
        resp.headers["Location"] = params["next"] if "next" in params else "/home/"
      return resp
    probe.auth.primary_session.get = MagicMock(side_effect=get)
    probe._test_open_redirect()
    found = [f for f in probe.findings if f.scenario_id == "PT-A01-04"]
    self.assertEqual([f.status for f in found], ["vulnerable"])
    self.assertTrue(any(e.startswith("endpoint=/auth/login/") for e in found[0].evidence))

  def test_substring_host_match_is_not_enough(self):
    """Location=/x?u=evil.example.com has the string but not the host."""
    probe = self._probe()
    resp = _mock_response(status=302, text="")
    resp.headers["Location"] = "/home/?u=evil.example.com"
    probe.auth.primary_session.get = MagicMock(return_value=resp)
    probe._test_open_redirect()
    self.assertEqual([f.status for f in probe.findings if f.scenario_id == "PT-A01-04"],
                     ["not_vulnerable"])

  def test_denied_by_login_redirect_is_inconclusive_with_and_without_admin(self):
    """The login page itself is unusable, the route bounces to login."""
    for admin, reason in (("provided", "endpoint_denied"),
                          ("absent", "admin_context_absent")):
      with self.subTest(admin=admin):
        probe = self._probe(admin)

        def get(url, params=None, **kw):
          if url.endswith("/auth/login/"):
            return _mock_response(status=403, text="")
          resp = _mock_response(status=302, text="")
          resp.headers["Location"] = "/auth/login/?next=/records/"
          return resp
        probe.auth.primary_session.get = MagicMock(side_effect=get)
        probe._test_open_redirect()
        found, reasons = _reason(probe, "PT-A01-04")
        self.assertEqual([f.status for f in found], ["inconclusive"])
        self.assertEqual(reasons, [f"reason={reason}"])

  def test_denied_route_by_403_or_404_is_inconclusive(self):
    for kind in ("403", "404"):
      with self.subTest(kind=kind):
        probe = self._probe("provided")
        probe.auth.primary_session.get = MagicMock(side_effect=lambda *a, **k: _denial(kind))
        probe._test_open_redirect()
        found, reasons = _reason(probe, "PT-A01-04")
        self.assertEqual([f.status for f in found], ["inconclusive"])
        self.assertEqual(reasons, ["reason=endpoint_denied"])


class TestSsrfReplayNamesPrincipal(unittest.TestCase):

  def test_body_field_replay_names_regular_user(self):
    from extensions.business.cybersec.red_mesh.graybox.models.target_config import ApiSecurityConfig
    probe = _make_probe(ssrf_endpoints=[SsrfEndpoint(path="/api/fetch/", param="url")])
    probe.target_config = GrayboxTargetConfig(
      injection=InjectionConfig(ssrf_endpoints=[SsrfEndpoint(path="/api/fetch/", param="url")]),
      api_security=ApiSecurityConfig(ssrf_body_fields=["url"]),
    )
    probe.auth.primary_principal = "regular"
    probe.auth.primary_session.post = MagicMock(return_value=_mock_response(
      status=200, text="http://127.0.0.1:1/internal-probe"))
    probe._test_ssrf_body_field()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-API7-01"]
    self.assertEqual([f.status for f in vuln], ["inconclusive"])
    self.assertIn("Authenticate as the regular user.", vuln[0].replay_steps)
    self.assertFalse(any("official" in s for s in vuln[0].replay_steps))


class TestSharedReachabilityCheck(unittest.TestCase):
  """`ProbeBase.response_reached`: the login page is found by its resolved path."""

  def _probe(self, target_url="http://testapp.local:8000", login_path="/auth/login/"):
    probe = _make_probe(login_path=login_path)
    probe.target_url = target_url
    return probe

  def _redirect(self, location, url="https://h/app/records/"):
    resp = _mock_response(status=302, text="")
    resp.url = url
    if location is not None:
      resp.headers["Location"] = location
    return resp

  def test_base_path_target_matches_login_under_the_base_path(self):
    probe = self._probe("https://h/app", "/login/")
    self.assertFalse(probe.response_reached(self._redirect("/app/login?next=/x")))
    self.assertTrue(probe.response_reached(self._redirect("/app/records/1/")))

  def test_relative_location_resolves_against_the_request_url(self):
    probe = self._probe("https://h/app", "/login/")
    self.assertFalse(probe.response_reached(
      self._redirect("login?next=/x", url="https://h/app/records")))
    self.assertTrue(probe.response_reached(
      self._redirect("detail/", url="https://h/app/records/")))

  def test_redirect_without_location_is_not_reached(self):
    self.assertFalse(self._probe().response_reached(self._redirect(None)))

  def test_followed_login_page_is_found_by_its_final_url_under_a_base_path(self):
    probe = self._probe("https://h/app", "/login/")
    resp = _ok("<p>hello</p>")
    resp.url = "https://h/app/login/?next=/x"
    self.assertFalse(probe.response_reached(resp))

  def test_configured_auth_required_marker_makes_a_2xx_not_reached(self):
    probe = self._probe()
    resp = _ok('{"detail": "Authentication credentials were not provided"}')
    self.assertTrue(probe.response_reached(resp))
    self.assertFalse(probe.response_reached(
      resp, auth_required_marker="authentication credentials were not provided"))

  def test_inline_login_form_posting_to_itself_is_not_reached(self):
    """A login form rendered at the protected URL with an empty, "#" or
    query-only action is a denial, not the handler."""
    probe = _make_probe()
    for action in ('action=""', 'action="#"', 'action="?next=/admin/"'):
      body = (f'<form method="post" {action}><input name="username">'
              '<input type="password" name="password"></form>')
      resp = _mock_response(status=200, text=body)
      resp.url = "http://testapp.local:8000/admin/users/"
      resp.history = []
      self.assertFalse(probe.response_reached(resp), action)

  def test_profile_page_with_prefilled_username_is_not_a_login_page(self):
    probe = self._probe()
    profile = _ok(
      '<form action="/profile/password/"><input name="username" value="alice">'
      '<input type="password" name="password"></form>')
    self.assertTrue(probe.response_reached(profile))
    login = _ok(
      '<form action="/auth/login/"><input name="username">'
      '<input type="password" name="password"></form>')
    self.assertFalse(probe.response_reached(login))
