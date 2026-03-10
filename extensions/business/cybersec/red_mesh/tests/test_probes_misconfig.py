"""Tests for MisconfigProbes."""

import base64
import json
import unittest
from unittest.mock import MagicMock, PropertyMock
from http.cookiejar import Cookie

from extensions.business.cybersec.red_mesh.graybox.probes.misconfig import MisconfigProbes
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig, MisconfigConfig, BusinessLogicConfig, WorkflowEndpoint,
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


def _make_probe(debug_paths=None, workflow_endpoints=None,
                official_session=None, anon_session=None,
                discovered_forms=None, login_path="/auth/login/"):
  misconfig = MisconfigConfig(debug_paths=debug_paths or ["/debug/"])
  business = BusinessLogicConfig(
    workflow_endpoints=workflow_endpoints or [],
  )
  cfg = GrayboxTargetConfig(
    misconfig=misconfig,
    business_logic=business,
    login_path=login_path,
  )
  auth = MagicMock()
  auth.official_session = official_session
  auth.anon_session = anon_session or MagicMock()
  safety = MagicMock()
  safety.throttle = MagicMock()

  probe = MisconfigProbes(
    target_url="http://testapp.local:8000",
    auth_manager=auth,
    target_config=cfg,
    safety=safety,
    discovered_forms=discovered_forms or [],
  )
  return probe


class TestDebugExposure(unittest.TestCase):

  def test_debug_exposure(self):
    """Debug endpoint returns 200 with body → vulnerable."""
    probe = _make_probe(debug_paths=["/debug/config/"])
    session = probe.auth.anon_session
    session.get.return_value = _mock_response(
      status=200, text="DEBUG_MODE=True SECRET_KEY=xxx" + "x" * 50,
    )

    probe._test_debug_exposure()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)

  def test_debug_not_found(self):
    """Debug endpoint returns 404 → not_vulnerable."""
    probe = _make_probe(debug_paths=["/debug/config/"])
    session = probe.auth.anon_session
    session.get.return_value = _mock_response(status=404, text="Not Found")

    probe._test_debug_exposure()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A02-01" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)


class TestCors(unittest.TestCase):

  def test_cors_wildcard(self):
    """Access-Control-Allow-Origin: * → vulnerable."""
    probe = _make_probe()
    session = probe.auth.anon_session
    session.get.return_value = _mock_response(
      headers={"Access-Control-Allow-Origin": "*"},
    )

    probe._test_cors()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")


class TestSecurityHeaders(unittest.TestCase):

  def test_security_headers_missing(self):
    """Missing X-Frame-Options etc. → vulnerable."""
    probe = _make_probe()
    session = probe.auth.anon_session
    session.get.return_value = _mock_response(headers={})

    probe._test_security_headers()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-03" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertIn("X-Frame-Options", vuln[0].evidence[0])


class TestCookieAttributes(unittest.TestCase):

  def _make_cookie(self, name="sessionid", secure=False, httponly=False, samesite=None):
    cookie = MagicMock()
    cookie.name = name
    cookie.secure = secure
    cookie.has_nonstandard_attr = MagicMock(return_value=httponly)
    cookie.get_nonstandard_attr = MagicMock(return_value=samesite)
    return cookie

  def test_cookie_insecure(self):
    """Missing Secure/HttpOnly → vulnerable."""
    session = MagicMock()
    session.cookies = [self._make_cookie(secure=False, httponly=False)]
    probe = _make_probe(official_session=session)

    probe._test_cookie_attributes()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-04" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)


class TestCsrfBypass(unittest.TestCase):

  def test_csrf_bypass_no_token(self):
    """POST accepted without CSRF → vulnerable."""
    session = MagicMock()
    session.post.return_value = _mock_response(status=200, text="Success")
    probe = _make_probe(
      official_session=session,
      workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
    )

    probe._test_csrf_bypass()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-05" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-352", vuln[0].cwe)

  def test_csrf_bypass_rejected(self):
    """POST rejected (403) → not_vulnerable."""
    session = MagicMock()
    session.post.return_value = _mock_response(status=403, text="CSRF token missing")
    probe = _make_probe(
      official_session=session,
      workflow_endpoints=[WorkflowEndpoint(path="/api/transfer/")],
    )

    probe._test_csrf_bypass()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A02-05" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_csrf_bypass_skips_login(self):
    """Login form is not tested for CSRF."""
    session = MagicMock()
    session.post.return_value = _mock_response(status=200, text="OK")
    probe = _make_probe(
      official_session=session,
      discovered_forms=["/auth/login/", "/profile/edit/"],
      login_path="/auth/login/",
    )

    probe._test_csrf_bypass()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-05" and f.status == "vulnerable"]
    # Only /profile/edit/ should be tested, not /auth/login/
    if vuln:
      for ev in vuln[0].evidence:
        if "endpoints_without_csrf" in ev:
          self.assertNotIn("/auth/login/", ev)


class TestSessionToken(unittest.TestCase):

  def _make_jwt(self, alg="none", payload=None, signature=""):
    header = base64.urlsafe_b64encode(json.dumps({"alg": alg}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload or {}).encode()).rstrip(b"=").decode()
    return f"{header}.{body}.{signature}"

  def test_session_token_jwt_alg_none(self):
    """alg=none JWT → vulnerable."""
    jwt = self._make_jwt(alg="none")
    session = MagicMock()
    session.cookies.get_dict.return_value = {"token": jwt}
    probe = _make_probe(official_session=session)

    probe._test_session_token()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A02-06" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")

  def test_session_token_short(self):
    """Short session ID → inconclusive."""
    session = MagicMock()
    session.cookies.get_dict.return_value = {"sid": "abc123"}
    probe = _make_probe(official_session=session)

    probe._test_session_token()
    inc = [f for f in probe.findings if f.scenario_id == "PT-A02-06" and f.status == "inconclusive"]
    self.assertEqual(len(inc), 1)
    self.assertEqual(inc[0].severity, "LOW")

  def test_session_token_adequate(self):
    """Normal tokens → not_vulnerable."""
    session = MagicMock()
    session.cookies.get_dict.return_value = {
      "sessionid": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    }
    probe = _make_probe(official_session=session)

    probe._test_session_token()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A02-06" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)


class TestCapabilities(unittest.TestCase):

  def test_capabilities(self):
    """MisconfigProbes declares correct capabilities."""
    self.assertFalse(MisconfigProbes.requires_auth)
    self.assertFalse(MisconfigProbes.requires_regular_session)
    self.assertFalse(MisconfigProbes.is_stateful)

  def test_all_findings_are_graybox(self):
    """All findings are GrayboxFinding instances."""
    probe = _make_probe(debug_paths=["/debug/"])
    probe.auth.anon_session.get.return_value = _mock_response(status=404, text="x")
    probe._test_debug_exposure()
    for f in probe.findings:
      self.assertIsInstance(f, GrayboxFinding)


if __name__ == '__main__':
  unittest.main()
