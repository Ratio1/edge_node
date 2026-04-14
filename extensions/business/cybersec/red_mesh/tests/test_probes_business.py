"""Tests for BusinessLogicProbes."""

import unittest
from unittest.mock import MagicMock, call

from extensions.business.cybersec.red_mesh.graybox.probes.business_logic import BusinessLogicProbes
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig, BusinessLogicConfig, WorkflowEndpoint,
)
from extensions.business.cybersec.red_mesh.constants import GRAYBOX_MAX_WEAK_ATTEMPTS


def _mock_response(status=200, text="", headers=None):
  resp = MagicMock()
  resp.status_code = status
  resp.text = text
  resp.headers = headers or {"content-type": "text/html"}
  return resp


def _make_probe(workflow_endpoints=None, allow_stateful=False,
                regular_session=None):
  cfg = GrayboxTargetConfig(
    business_logic=BusinessLogicConfig(
      workflow_endpoints=workflow_endpoints or [],
    ),
  )
  auth = MagicMock()
  auth.regular_session = regular_session or MagicMock()
  auth.official_session = MagicMock()
  auth.anon_session = MagicMock()
  auth.target_url = "http://testapp.local:8000"
  auth.target_config = cfg
  safety = MagicMock()
  safety.throttle = MagicMock()
  safety.throttle_auth = MagicMock()
  safety.clamp_attempts = MagicMock(side_effect=lambda x: min(x, GRAYBOX_MAX_WEAK_ATTEMPTS))

  probe = BusinessLogicProbes(
    target_url="http://testapp.local:8000",
    auth_manager=auth,
    target_config=cfg,
    safety=safety,
    allow_stateful=allow_stateful,
    regular_username="alice",
  )
  return probe


class TestStatefulGating(unittest.TestCase):

  def test_stateful_disabled(self):
    """Returns inconclusive skip finding when stateful=False."""
    probe = _make_probe(allow_stateful=False)
    findings = probe.run()
    skip = [f for f in findings if f.scenario_id == "PT-A06-01" and f.status == "inconclusive"]
    self.assertEqual(len(skip), 1)
    self.assertIn("stateful_probes_disabled=True", skip[0].evidence)

  def test_stateful_enabled(self):
    """Runs workflow probe when stateful=True."""
    ep = WorkflowEndpoint(path="/api/orders/1/force-pay/", method="POST", expected_guard="403")
    probe = _make_probe(
      workflow_endpoints=[ep],
      allow_stateful=True,
    )
    # Simulate a successful bypass: POST returns 200 instead of 403
    probe.auth.regular_session.post.return_value = _mock_response(
      status=200, text="Payment processed",
    )
    probe.auth.regular_session.get.return_value = _mock_response(status=200, text="OK")

    findings = probe.run()
    vuln = [f for f in findings if f.scenario_id == "PT-A06-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")


class TestWeakAuth(unittest.TestCase):

  def test_weak_auth_budget(self):
    """Respects hard cap from safety.clamp_attempts."""
    probe = _make_probe()
    # Request more than max — should be clamped
    probe.safety.clamp_attempts.side_effect = None
    probe.safety.clamp_attempts.return_value = 3

    # Provide 5 candidates but budget is 3
    candidates = ["u1:p1", "u2:p2", "u3:p3", "u4:p4", "u5:p5"]
    probe.auth.try_credentials.return_value = None

    # Mock the lockout check
    check_session = MagicMock()
    check_session.get.return_value = _mock_response(status=200, text="Login")
    check_session.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = check_session

    probe.run_weak_auth(candidates, max_attempts=100)
    # clamp_attempts was called with 100
    probe.safety.clamp_attempts.assert_called_with(100)
    # try_credentials should be called at most 3 times
    self.assertLessEqual(probe.auth.try_credentials.call_count, 3)

  def test_weak_auth_success(self):
    """Weak cred found → vulnerable."""
    probe = _make_probe()
    probe.safety.clamp_attempts.return_value = 10

    mock_session = MagicMock()
    mock_session.close = MagicMock()

    # First cred fails, second succeeds
    probe.auth.try_credentials.side_effect = [None, mock_session]

    check_session = MagicMock()
    check_session.get.return_value = _mock_response(status=200, text="Login page")
    check_session.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = check_session

    findings = probe.run_weak_auth(["admin:wrong", "admin:admin"], max_attempts=10)
    vuln = [f for f in findings if f.scenario_id == "PT-A07-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-307", vuln[0].cwe)

  def test_weak_auth_lockout_429(self):
    """429 response → abort + inconclusive."""
    probe = _make_probe()
    probe.safety.clamp_attempts.return_value = 10

    probe.auth.try_credentials.return_value = None

    check_session = MagicMock()
    check_session.get.return_value = _mock_response(status=429, text="Rate limited")
    check_session.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = check_session

    findings = probe.run_weak_auth(["admin:test"], max_attempts=10)
    lockout = [f for f in findings if f.scenario_id == "PT-A07-01" and f.status == "inconclusive"]
    self.assertEqual(len(lockout), 1)
    self.assertIn("Account lockout detected", lockout[0].title)

  def test_weak_auth_lockout_body(self):
    """'account locked' in body → abort."""
    probe = _make_probe()
    probe.safety.clamp_attempts.return_value = 10

    probe.auth.try_credentials.return_value = None

    check_session = MagicMock()
    check_session.get.return_value = _mock_response(
      status=200, text="Your account locked due to too many failed attempts",
    )
    check_session.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = check_session

    findings = probe.run_weak_auth(["admin:test"], max_attempts=10)
    lockout = [f for f in findings if f.scenario_id == "PT-A07-01" and f.status == "inconclusive"]
    self.assertEqual(len(lockout), 1)

  def test_weak_auth_uses_public_api(self):
    """Calls try_credentials, not _try_login."""
    probe = _make_probe()
    probe.safety.clamp_attempts.return_value = 10
    probe.auth.try_credentials.return_value = None

    check_session = MagicMock()
    check_session.get.return_value = _mock_response(status=200, text="Login")
    check_session.close = MagicMock()
    probe.auth.make_anonymous_session.return_value = check_session

    probe.run_weak_auth(["admin:pass"], max_attempts=5)
    probe.auth.try_credentials.assert_called_once_with("admin", "pass")

  def test_weak_auth_empty_candidates(self):
    """Empty candidate list → returns findings unchanged."""
    probe = _make_probe()
    findings = probe.run_weak_auth([], max_attempts=10)
    # No PT-A07-01 findings
    a07 = [f for f in findings if f.scenario_id == "PT-A07-01"]
    self.assertEqual(len(a07), 0)

  def test_weak_auth_skips_no_colon(self):
    """Candidates without ':' separator are skipped."""
    probe = _make_probe()
    probe.safety.clamp_attempts.return_value = 10

    probe.run_weak_auth(["nocolon", "also_no_colon"], max_attempts=10)
    probe.auth.try_credentials.assert_not_called()


class TestCapabilities(unittest.TestCase):

  def test_capabilities(self):
    """BusinessLogicProbes declares correct capabilities."""
    self.assertTrue(BusinessLogicProbes.requires_auth)
    self.assertTrue(BusinessLogicProbes.requires_regular_session)
    self.assertTrue(BusinessLogicProbes.is_stateful)

  def test_all_findings_are_graybox(self):
    """All findings are GrayboxFinding instances."""
    probe = _make_probe(allow_stateful=False)
    findings = probe.run()
    for f in findings:
      self.assertIsInstance(f, GrayboxFinding)


if __name__ == '__main__':
  unittest.main()
