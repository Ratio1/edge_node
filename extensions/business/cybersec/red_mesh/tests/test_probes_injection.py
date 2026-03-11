"""Tests for InjectionProbes."""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.probes.injection import InjectionProbes
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig, InjectionConfig, SsrfEndpoint,
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
                official_session=None, allow_stateful=False,
                login_path="/auth/login/", logout_path="/auth/logout/"):
  cfg = GrayboxTargetConfig(
    injection=InjectionConfig(ssrf_endpoints=ssrf_endpoints or []),
    login_path=login_path,
    logout_path=logout_path,
  )
  auth = MagicMock()
  auth.official_session = official_session or MagicMock()
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
    """Callback in response body → vulnerable."""
    ep = SsrfEndpoint(path="/api/fetch/", param="url")
    probe = _make_probe(ssrf_endpoints=[ep])
    session = probe.auth.official_session

    # Baseline
    baseline_resp = _mock_response(status=200, text="nothing")
    # Probe: reflected SSRF
    probe_resp = _mock_response(
      status=200, text="fetched: http://127.0.0.1:1/internal-probe data",
    )
    session.get.side_effect = [baseline_resp, probe_resp]

    probe._test_ssrf()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-API7-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")
    self.assertIn("CWE-918", vuln[0].cwe)

  def test_ssrf_no_hit(self):
    """Normal response → no finding."""
    ep = SsrfEndpoint(path="/api/fetch/", param="url")
    probe = _make_probe(ssrf_endpoints=[ep])
    session = probe.auth.official_session

    resp = _mock_response(status=200, text="safe content")
    session.get.return_value = resp

    probe._test_ssrf()
    api7 = [f for f in probe.findings if f.scenario_id == "PT-API7-01"]
    self.assertEqual(len(api7), 0)


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
    session = probe.auth.official_session
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
    session = probe.auth.official_session
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
    session = probe.auth.official_session

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
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-79", vuln[0].cwe)

  def test_stored_xss_escaped(self):
    """Canary HTML-encoded → not_vulnerable."""
    probe = _make_probe(
      discovered_forms=["/comments/"],
      allow_stateful=True,
    )
    session = probe.auth.official_session

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
    session = probe.auth.official_session

    # Response: 302 redirect to evil.example.com
    redirect_resp = _mock_response(status=302, text="")
    redirect_resp.headers["Location"] = "//evil.example.com"
    session.get = MagicMock(return_value=redirect_resp)

    probe._test_open_redirect()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A01-04" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")
    self.assertIn("CWE-601", vuln[0].cwe)

  def test_open_redirect_safe(self):
    """No redirect → not_vulnerable."""
    probe = _make_probe()
    session = probe.auth.official_session
    session.get = MagicMock(return_value=_mock_response(status=200, text="Normal page"))

    probe._test_open_redirect()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A01-04" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_open_redirect_internal_redirect(self):
    """Redirect to same domain → not vulnerable."""
    probe = _make_probe()
    session = probe.auth.official_session

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
    session = probe.auth.official_session

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
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-22", vuln[0].cwe)

  def test_path_traversal_safe(self):
    """No file content markers → not_vulnerable."""
    probe = _make_probe()
    probe.discovered_routes = ["/page/"]
    session = probe.auth.official_session
    session.get = MagicMock(return_value=_mock_response(status=200, text="Safe page content"))

    probe._test_path_traversal()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A03-03" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_path_traversal_no_session(self):
    """No official session → skip."""
    probe = _make_probe(official_session=None)
    probe.auth.official_session = None
    probe._test_path_traversal()
    self.assertEqual(len(probe.findings), 0)


class TestCapabilities(unittest.TestCase):

  def test_capabilities(self):
    """InjectionProbes declares correct capabilities."""
    self.assertTrue(InjectionProbes.requires_auth)
    self.assertFalse(InjectionProbes.requires_regular_session)
    self.assertFalse(InjectionProbes.is_stateful)

  def test_all_findings_are_graybox(self):
    """All findings are GrayboxFinding."""
    probe = _make_probe(discovered_forms=["/search/"])
    session = probe.auth.official_session
    session.get.return_value = _mock_response(
      text='<form><input name="q" type="text"></form>',
    )
    session.post.return_value = _mock_response(text="safe")

    probe._test_authenticated_injection()
    for f in probe.findings:
      self.assertIsInstance(f, GrayboxFinding)


if __name__ == '__main__':
  unittest.main()
