"""Tests for AccessControlProbes."""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.probes.access_control import AccessControlProbes
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig, AccessControlConfig, IdorEndpoint, AdminEndpoint,
  BusinessLogicConfig, RecordEndpoint,
)


def _mock_response(status=200, text="", content_type="application/json", json_data=None):
  resp = MagicMock()
  resp.status_code = status
  resp.text = text
  resp.headers = {"content-type": content_type}
  resp.json.return_value = json_data or {}
  return resp


def _make_probe(idor_endpoints=None, admin_endpoints=None,
                regular_username="alice", discovered_routes=None,
                regular_session=None, allow_stateful=False):
  cfg = GrayboxTargetConfig(
    access_control=AccessControlConfig(
      idor_endpoints=idor_endpoints or [],
      admin_endpoints=admin_endpoints or [],
    ),
  )
  auth = MagicMock()
  auth.regular_session = regular_session or MagicMock()
  safety = MagicMock()
  safety.throttle = MagicMock()

  probe = AccessControlProbes(
    target_url="http://testapp.local:8000",
    auth_manager=auth,
    target_config=cfg,
    safety=safety,
    discovered_routes=discovered_routes or [],
    regular_username=regular_username,
    allow_stateful=allow_stateful,
  )
  return probe


class TestIdorProbe(unittest.TestCase):

  def test_idor_confirmed(self):
    """Owner mismatch → vulnerable/HIGH."""
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[99], owner_field="owner")
    probe = _make_probe(idor_endpoints=[ep])
    probe.auth.regular_session.get.return_value = _mock_response(
      json_data={"owner": "bob", "data": "secret"},
    )
    probe.auth.regular_session.get.return_value.json.return_value = {"owner": "bob", "data": "secret"}

    findings = probe.run()
    vuln = [f for f in findings if f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].scenario_id, "PT-A01-01")
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-639", vuln[0].cwe)

  def test_idor_not_vulnerable(self):
    """All owners match logged-in user → not_vulnerable/INFO."""
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[1], owner_field="owner")
    probe = _make_probe(idor_endpoints=[ep], regular_username="alice")
    probe.auth.regular_session.get.return_value = _mock_response(
      json_data={"owner": "alice"},
    )
    probe.auth.regular_session.get.return_value.json.return_value = {"owner": "alice"}

    findings = probe.run()
    clean = [f for f in findings if f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)
    self.assertEqual(clean[0].scenario_id, "PT-A01-01")

  def test_idor_one_finding_per_scenario(self):
    """Multiple endpoints → exactly one finding."""
    eps = [
      IdorEndpoint(path="/api/records/{id}/", test_ids=[1, 2], owner_field="owner"),
      IdorEndpoint(path="/api/users/{id}/", test_ids=[1], owner_field="owner"),
    ]
    probe = _make_probe(idor_endpoints=eps)
    probe.auth.regular_session.get.return_value = _mock_response(
      json_data={"owner": "bob"},
    )
    probe.auth.regular_session.get.return_value.json.return_value = {"owner": "bob"}

    findings = probe.run()
    a01_findings = [f for f in findings if f.scenario_id == "PT-A01-01"]
    self.assertEqual(len(a01_findings), 1)

  def test_idor_no_regular_username(self):
    """Returns without findings when regular_username is empty."""
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[1])
    probe = _make_probe(idor_endpoints=[ep], regular_username="")
    findings = probe.run()
    # No PT-A01-01 findings at all (no vulnerable, no not_vulnerable)
    a01 = [f for f in findings if f.scenario_id == "PT-A01-01"]
    self.assertEqual(len(a01), 0)

  def test_idor_inference(self):
    """/api/records/1/ inferred from discovered routes."""
    probe = _make_probe(
      discovered_routes=["/api/records/1/", "/api/records/2/", "/about/"],
    )
    probe.auth.regular_session.get.return_value = _mock_response(
      json_data={"owner": "bob"},
    )
    probe.auth.regular_session.get.return_value.json.return_value = {"owner": "bob"}

    findings = probe.run()
    a01 = [f for f in findings if f.scenario_id == "PT-A01-01"]
    self.assertEqual(len(a01), 1)
    self.assertEqual(a01[0].status, "vulnerable")

  def test_idor_no_endpoints(self):
    """No endpoints and no discoverable routes → no findings, no error."""
    probe = _make_probe(idor_endpoints=[], discovered_routes=[])
    findings = probe.run()
    a01 = [f for f in findings if f.scenario_id == "PT-A01-01"]
    self.assertEqual(len(a01), 0)


class TestPrivilegeEscProbe(unittest.TestCase):

  def test_privilege_esc_confirmed(self):
    """Admin endpoint + content markers → vulnerable/HIGH."""
    ep = AdminEndpoint(
      path="/api/admin/users/",
      method="GET",
      content_markers=["email", "role"],
    )
    probe = _make_probe(admin_endpoints=[ep])
    probe.auth.regular_session.get.return_value = _mock_response(
      status=200,
      text='{"email": "admin@x.com", "role": "superuser"}',
      content_type="text/html",
    )

    findings = probe.run()
    vuln = [f for f in findings if f.scenario_id == "PT-A01-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")

  def test_privilege_esc_inconclusive(self):
    """200 but no content markers → inconclusive/LOW."""
    ep = AdminEndpoint(
      path="/api/admin/users/",
      method="GET",
      content_markers=["secret_data"],
    )
    probe = _make_probe(admin_endpoints=[ep])
    probe.auth.regular_session.get.return_value = _mock_response(
      status=200,
      text="<html>Welcome</html>",
      content_type="text/html",
    )

    findings = probe.run()
    inc = [f for f in findings if f.scenario_id == "PT-A01-02" and f.status == "inconclusive"]
    self.assertEqual(len(inc), 1)
    self.assertEqual(inc[0].severity, "LOW")

  def test_privilege_esc_denial_body(self):
    """200 + 'access denied' in body → skip (no finding)."""
    ep = AdminEndpoint(
      path="/api/admin/users/",
      method="GET",
      content_markers=["email"],
    )
    probe = _make_probe(admin_endpoints=[ep])
    probe.auth.regular_session.get.return_value = _mock_response(
      status=200,
      text="<html>Access Denied. You are not authorized.</html>",
      content_type="text/html",
    )

    findings = probe.run()
    a02 = [f for f in findings if f.scenario_id == "PT-A01-02"]
    self.assertEqual(len(a02), 0)


class TestCapabilityDeclarations(unittest.TestCase):

  def test_capabilities(self):
    """AccessControlProbes declares correct capabilities."""
    self.assertTrue(AccessControlProbes.requires_auth)
    self.assertTrue(AccessControlProbes.requires_regular_session)
    self.assertFalse(AccessControlProbes.is_stateful)

  def test_all_findings_are_graybox(self):
    """All emitted findings are GrayboxFinding instances."""
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[1])
    probe = _make_probe(idor_endpoints=[ep])
    probe.auth.regular_session.get.return_value = _mock_response(
      json_data={"owner": "bob"},
    )
    probe.auth.regular_session.get.return_value.json.return_value = {"owner": "bob"}

    findings = probe.run()
    for f in findings:
      self.assertIsInstance(f, GrayboxFinding)


class TestMassAssignmentOwnershipPTA0402(unittest.TestCase):
  """PT-A04-02 — ownership transfer via mass-assignable field."""

  def _setup(self, before_owner, after_owner, patch_status=200):
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[2], owner_field="owner")
    probe = _make_probe(idor_endpoints=[ep], allow_stateful=True)
    sess = probe.auth.regular_session
    sess.cookies = MagicMock()
    sess.cookies.get = MagicMock(return_value="csrf123")
    # GET sequence: probe reads twice (before, after)
    get_calls = iter([
      _mock_response(status=200, json_data={"id": 2, "owner": before_owner}),
      _mock_response(status=200, json_data={"id": 2, "owner": after_owner}),
    ])
    sess.get = MagicMock(side_effect=lambda *a, **kw: next(get_calls))
    sess.patch = MagicMock(return_value=_mock_response(status=patch_status))
    probe.auth.detected_csrf_field = "csrfmiddlewaretoken"
    return probe

  def test_pt_a04_02_vulnerable_when_owner_changes(self):
    probe = self._setup(before_owner="alice", after_owner="1000")
    probe._test_mass_assignment_ownership()
    f = [x for x in probe.findings if x.scenario_id == "PT-A04-02"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")
    self.assertEqual(f[0].severity, "HIGH")

  def test_pt_a04_02_not_vulnerable_when_owner_unchanged(self):
    probe = self._setup(before_owner="alice", after_owner="alice")
    probe._test_mass_assignment_ownership()
    f = [x for x in probe.findings if x.scenario_id == "PT-A04-02"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")
    self.assertEqual(f[0].severity, "INFO")

  def test_pt_a04_02_skipped_when_stateful_disabled(self):
    """run() should emit inconclusive INFO when stateful is off."""
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[2])
    probe = _make_probe(idor_endpoints=[ep], allow_stateful=False)
    probe.run()
    f = [x for x in probe.findings if x.scenario_id == "PT-A04-02"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "inconclusive")

  def test_pt_a04_02_silent_when_no_idor_endpoints(self):
    probe = _make_probe(idor_endpoints=[], allow_stateful=True)
    probe._test_mass_assignment_ownership()
    self.assertFalse(any(f.scenario_id == "PT-A04-02" for f in probe.findings))


class TestVerbTampering(unittest.TestCase):

  def test_verb_tampering_bypass(self):
    """Admin endpoint denies GET but accepts PUT → vulnerable/HIGH."""
    ep = AdminEndpoint(path="/api/admin/users/", method="GET")
    probe = _make_probe(admin_endpoints=[ep])
    session = probe.auth.regular_session

    # Baseline GET → 403
    baseline = _mock_response(status=403, text="Forbidden")
    # PUT → 200 (bypass)
    bypass = _mock_response(status=200, text='{"users": []}')

    call_count = [0]
    def mock_request(method, url, **kwargs):
      call_count[0] += 1
      if method == "GET":
        return baseline
      return bypass

    session.request = MagicMock(side_effect=mock_request)

    probe._test_verb_tampering()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A01-03" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-650", vuln[0].cwe)

  def test_verb_tampering_all_denied(self):
    """All methods return 403 → not_vulnerable."""
    ep = AdminEndpoint(path="/api/admin/users/", method="GET")
    probe = _make_probe(admin_endpoints=[ep])
    session = probe.auth.regular_session
    session.request = MagicMock(return_value=_mock_response(status=403, text="Forbidden"))

    probe._test_verb_tampering()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A01-03" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_verb_tampering_baseline_accessible(self):
    """Endpoint already accessible via normal method → emit inconclusive INFO.

    The probe didn't actually exercise verb-tampering (no baseline-denied
    response to bypass), but it DID reach the endpoint. Emit an INFO so
    coverage accounting reflects that PT-A01-03 ran on this target.
    """
    ep = AdminEndpoint(path="/api/public/", method="GET")
    probe = _make_probe(admin_endpoints=[ep])
    session = probe.auth.regular_session
    session.request = MagicMock(return_value=_mock_response(status=200, text="Public data"))

    probe._test_verb_tampering()
    a01_03 = [f for f in probe.findings if f.scenario_id == "PT-A01-03"]
    self.assertEqual(len(a01_03), 1)
    self.assertEqual(a01_03[0].status, "inconclusive")
    self.assertEqual(a01_03[0].severity, "INFO")

  def test_verb_tampering_no_endpoints(self):
    """No admin endpoints → no findings."""
    probe = _make_probe(admin_endpoints=[])
    probe._test_verb_tampering()
    self.assertEqual(len([f for f in probe.findings if f.scenario_id == "PT-A01-03"]), 0)


class TestMassAssignment(unittest.TestCase):

  def test_mass_assignment_detected(self):
    """Privilege field persisted → vulnerable/HIGH."""
    probe = _make_probe(allow_stateful=True)
    probe.discovered_forms = ["/profile/"]
    session = probe.auth.regular_session

    form_html = '<form><input name="username" value="alice"><input type="submit"></form>'
    # After POST, GET shows is_admin in response
    verify_html = '<form><input name="username" value="alice"><input name="is_admin" value="true"></form>'

    call_count = [0]
    def mock_get(url, **kwargs):
      call_count[0] += 1
      if call_count[0] <= 1:
        return _mock_response(status=200, text=form_html)
      return _mock_response(status=200, text=verify_html)

    session.get = MagicMock(side_effect=mock_get)
    session.post = MagicMock(return_value=_mock_response(status=302, text=""))
    probe.auth.detected_csrf_field = None
    probe.auth.extract_csrf_value = MagicMock(return_value=None)

    probe._test_mass_assignment()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A04-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")
    self.assertIn("CWE-915", vuln[0].cwe)

  def test_mass_assignment_rejected(self):
    """Server rejects extra fields → not_vulnerable."""
    probe = _make_probe(allow_stateful=True)
    probe.discovered_forms = ["/profile/"]
    session = probe.auth.regular_session

    form_html = '<form><input name="username" value="alice"></form>'
    session.get = MagicMock(return_value=_mock_response(status=200, text=form_html))
    session.post = MagicMock(return_value=_mock_response(
      status=200, text="<div class='error'>Unknown field</div>",
    ))
    probe.auth.detected_csrf_field = None
    probe.auth.extract_csrf_value = MagicMock(return_value=None)

    probe._test_mass_assignment()
    clean = [f for f in probe.findings if f.scenario_id == "PT-A04-01" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_mass_assignment_gated(self):
    """Skipped when allow_stateful=False → inconclusive."""
    probe = _make_probe(allow_stateful=False)
    findings = probe.run()
    skip = [f for f in findings if f.scenario_id == "PT-A04-01" and f.status == "inconclusive"]
    self.assertEqual(len(skip), 1)
    self.assertIn("stateful_probes_disabled=True", skip[0].evidence)

  def test_mass_assignment_no_forms(self):
    """No forms → no findings."""
    probe = _make_probe(allow_stateful=True)
    probe.discovered_forms = []
    probe._test_mass_assignment()
    self.assertEqual(len([f for f in probe.findings if f.scenario_id == "PT-A04-01"]), 0)


if __name__ == '__main__':
  unittest.main()
