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


def _redirect_to(location, status=302):
  resp = _mock_response(status=status, text="")
  resp.headers["Location"] = location
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
    self.assertEqual(vuln[0].severity, "MEDIUM")
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
    clean = [f for f in findings
             if f.status == "not_vulnerable" and f.scenario_id == "PT-A01-01"]
    self.assertEqual(len(clean), 1)

  def test_idor_one_finding_per_scenario(self):
    """Read-only probe: every vulnerable endpoint gets its own finding."""
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
    self.assertEqual(len(a01_findings), 2)

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
    self.assertGreaterEqual(len(a01), 1)
    self.assertEqual({f.status for f in a01}, {"vulnerable"})

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


class TestOwnershipUpdatePTA0105(unittest.TestCase):
  """PT-A01-05 — regular user updates a non-owned record."""

  def _setup(self, before_owner, after_title, sentinel_title="redmesh-pt-a01-05-probe-marker"):
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[1], owner_field="owner")
    probe = _make_probe(idor_endpoints=[ep], allow_stateful=True, regular_username="alice")
    sess = probe.auth.regular_session
    sess.cookies = MagicMock()
    sess.cookies.get = MagicMock(return_value="csrf123")
    get_calls = iter([
      _mock_response(status=200, json_data={"id": 1, "owner": before_owner, "title": "before"}),
      _mock_response(status=200, json_data={"id": 1, "owner": before_owner, "title": after_title}),
    ])
    sess.get = MagicMock(side_effect=lambda *a, **kw: next(get_calls))
    sess.patch = MagicMock(return_value=_mock_response(status=200))
    return probe

  def test_pt_a01_05_vulnerable_when_sentinel_persisted(self):
    probe = self._setup(before_owner="bob", after_title="redmesh-pt-a01-05-probe-marker")
    probe._test_ownership_update()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-05"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")
    self.assertEqual(f[0].severity, "HIGH")

  def test_pt_a01_05_not_vulnerable_when_title_unchanged(self):
    probe = self._setup(before_owner="bob", after_title="before")
    probe._test_ownership_update()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-05"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")

  def test_pt_a01_05_skipped_when_only_self_owned(self):
    """Records owned by the probe user are skipped — nothing to test."""
    probe = self._setup(before_owner="alice", after_title="any")
    probe._test_ownership_update()
    self.assertFalse(any(f.scenario_id == "PT-A01-05" for f in probe.findings))


class TestOwnershipDeletePTA0106(unittest.TestCase):
  """PT-A01-06 — regular user deletes a non-owned record."""

  def _setup(self, before_owner, followup_status, followup_body=None):
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[1], owner_field="owner")
    probe = _make_probe(idor_endpoints=[ep], allow_stateful=True, regular_username="alice")
    sess = probe.auth.regular_session
    sess.cookies = MagicMock()
    sess.cookies.get = MagicMock(return_value="csrf123")
    get_calls = iter([
      _mock_response(status=200, json_data={"id": 1, "owner": before_owner}),
      _mock_response(status=followup_status, json_data=followup_body or {}),
    ])
    sess.get = MagicMock(side_effect=lambda *a, **kw: next(get_calls))
    sess.delete = MagicMock(return_value=_mock_response(status=200, json_data={"id": 1, "deleted": True}))
    return probe

  def test_pt_a01_06_vulnerable_when_record_gone_after_delete(self):
    probe = self._setup(before_owner="bob", followup_status=404)
    probe._test_ownership_delete()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-06"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")
    self.assertEqual(f[0].severity, "HIGH")

  def test_pt_a01_06_not_vulnerable_when_record_still_present(self):
    probe = self._setup(before_owner="bob", followup_status=200,
                        followup_body={"id": 1, "owner": "bob"})
    probe._test_ownership_delete()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-06"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")


class TestAdminPathDiscoveryPTA0109(unittest.TestCase):
  """PT-A01-09 — discovered admin-pattern routes reachable by regular user."""

  def _make_probe_with_routes(self, routes, response_for_each):
    probe = _make_probe(
      idor_endpoints=[],
      admin_endpoints=[],
      discovered_routes=routes,
      regular_username="alice",
    )
    probe.auth.regular_session.get = MagicMock(side_effect=response_for_each)
    return probe

  def test_pt_a01_09_vulnerable_when_admin_path_returns_200(self):
    probe = self._make_probe_with_routes(
      ["/admin-panel/", "/dashboard/"],
      [_mock_response(status=200, text="<h1>Admin Panel</h1>")],
    )
    probe._test_admin_path_discovery()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-09"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")

  def test_pt_a01_09_not_vulnerable_when_admin_path_denies(self):
    probe = self._make_probe_with_routes(
      ["/admin-panel/"],
      [_mock_response(status=403, text="Forbidden")],
    )
    probe._test_admin_path_discovery()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-09"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")

  def test_pt_a01_09_silent_when_no_admin_paths_in_routes(self):
    probe = self._make_probe_with_routes(["/dashboard/", "/records/"], [])
    probe._test_admin_path_discovery()
    self.assertFalse(any(f.scenario_id == "PT-A01-09" for f in probe.findings))


class TestQueryRoleOverridePTA0110(unittest.TestCase):
  """PT-A01-10 — query-param role override."""

  def test_pt_a01_10_vulnerable_when_admin_marker_appears(self):
    probe = _make_probe(
      idor_endpoints=[], admin_endpoints=[],
      discovered_routes=["/dashboard/"], regular_username="alice",
    )
    probe.auth.regular_session.get = MagicMock(side_effect=[
      _mock_response(status=200, text="<p>Hello alice</p>"),                  # baseline
      _mock_response(status=200, text="<p>Hello alice</p><a href='/admin-panel'>Admin Panel</a>"),  # ?role=admin
    ])
    probe._test_query_role_override()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-10"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")

  def test_pt_a01_10_not_vulnerable_when_baseline_unchanged(self):
    probe = _make_probe(
      idor_endpoints=[], admin_endpoints=[],
      discovered_routes=["/dashboard/"], regular_username="alice",
    )
    probe.auth.regular_session.get = MagicMock(return_value=_mock_response(
      status=200, text="<p>Hello alice</p>",
    ))
    probe._test_query_role_override()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-10"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")


class TestHiddenFieldTamperingPTA0112(unittest.TestCase):
  """PT-A01-12 — hidden auth-related field tampering."""

  def _form_with_hidden_role(self, csrf="tok"):
    return (
      f'<form><input type="hidden" name="csrfmiddlewaretoken" value="{csrf}">'
      f'<input type="hidden" name="role" value="user">'
      f'<input type="text" name="title" value="thing">'
      f'</form>'
    )

  def _make_probe_with_form(self, form_html, post_response):
    probe = _make_probe(
      idor_endpoints=[], admin_endpoints=[],
      discovered_routes=[], regular_username="alice", allow_stateful=False,
    )
    probe.discovered_forms = ["/records/1/"]
    probe.auth.detected_csrf_field = "csrfmiddlewaretoken"
    probe.auth.extract_csrf_value = MagicMock(return_value="tok")
    sess = probe.auth.regular_session
    sess.get = MagicMock(return_value=_mock_response(status=200, text=form_html))
    sess.post = MagicMock(return_value=post_response)
    return probe

  def test_pt_a01_12_vulnerable_when_tampered_value_accepted(self):
    probe = self._make_probe_with_form(
      self._form_with_hidden_role(),
      _redirect_to("/records/"),
    )
    probe._test_hidden_field_tampering()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-12"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "vulnerable")

  def test_pt_a01_12_not_vulnerable_when_form_rejected(self):
    probe = self._make_probe_with_form(
      self._form_with_hidden_role(),
      _mock_response(status=200, text="<p>Invalid value for role</p>"),
    )
    probe._test_hidden_field_tampering()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-12"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].status, "not_vulnerable")

  def test_pt_a01_12_silent_when_no_hidden_auth_fields(self):
    probe = self._make_probe_with_form(
      '<form><input type="text" name="title"></form>',
      _mock_response(status=200, text=""),
    )
    probe._test_hidden_field_tampering()
    self.assertFalse(any(f.scenario_id == "PT-A01-12" for f in probe.findings))


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
    session.post = MagicMock(return_value=_redirect_to("/profile/"))
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


# ── RM-219 reachability rule ────────────────────────────────────────────

def _login_redirect_response():
  """A redirect to the login page, already followed by `requests`."""
  resp = _mock_response(
    status=200, content_type="text/html",
    text="<form><input name='username'><input type='password' name='password'></form>",
  )
  resp.url = "http://testapp.local:8000/auth/login/?next=/api/records/99/"
  resp.history = [MagicMock(headers={"Location": "/auth/login/?next=/api/records/99/"})]
  return resp


def _reached_response(text="ok"):
  resp = _mock_response(status=200, content_type="text/html", text=text)
  resp.url = "http://testapp.local:8000/x/"
  resp.history = []
  return resp


def _set_admin(probe, admin_context, admin_status=200):
  probe.auth.admin_context = admin_context
  probe.auth.official_session = MagicMock()
  probe.auth.official_session.request = MagicMock(
    return_value=_reached_response() if admin_status == 200
    else _mock_response(status=admin_status))


class TestExemptDenialIsSecure(unittest.TestCase):
  """A denial is the secure result for PT-A01-01/-02/-03 (and -05/-06)."""

  def _idor(self, response, admin_context, admin_status=200):
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[99], owner_field="owner")
    probe = _make_probe(idor_endpoints=[ep])
    _set_admin(probe, admin_context, admin_status)
    probe.auth.regular_session.get.return_value = response
    probe._test_idor()
    return [f for f in probe.findings if f.scenario_id == "PT-A01-01"]

  def test_idor_403_and_login_redirect_are_clean_with_and_without_admin(self):
    for admin in ("provided", "absent"):
      for name, resp in (("403", _mock_response(status=403, text="no")),
                         ("login", _login_redirect_response())):
        with self.subTest(admin=admin, denial=name):
          found = self._idor(resp, admin)
          self.assertEqual([f.status for f in found], ["not_vulnerable"])

  def test_idor_404_is_clean_only_when_admin_baseline_reached(self):
    found = self._idor(_mock_response(status=404, text="nf"), "provided", 200)
    self.assertEqual([f.status for f in found], ["not_vulnerable"])

  def test_idor_404_is_skipped_without_admin_or_when_admin_also_404(self):
    for admin, admin_status in (("absent", 200), ("provided", 404)):
      with self.subTest(admin=admin, admin_status=admin_status):
        found = self._idor(_mock_response(status=404, text="nf"), admin, admin_status)
        self.assertEqual(found, [])

  def test_privilege_esc_login_page_is_not_a_finding(self):
    ep = AdminEndpoint(path="/api/admin/users/", method="GET")
    probe = _make_probe(admin_endpoints=[ep])
    _set_admin(probe, "absent")
    probe.auth.regular_session.get.return_value = _login_redirect_response()
    probe._test_privilege_esc()
    self.assertEqual([f for f in probe.findings if f.scenario_id == "PT-A01-02"], [])

  def test_verb_tampering_login_page_baseline_is_a_denied_baseline(self):
    ep = AdminEndpoint(path="/api/admin/users/", method="GET")
    probe = _make_probe(admin_endpoints=[ep])
    _set_admin(probe, "absent")
    probe.auth.regular_session.request = MagicMock(side_effect=lambda m, u, **k: (
      _login_redirect_response()))
    probe._test_verb_tampering()
    found = [f for f in probe.findings if f.scenario_id == "PT-A01-03"]
    self.assertEqual([f.status for f in found], ["not_vulnerable"])

  def test_ownership_update_404_is_skipped_not_clean(self):
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[99], owner_field="owner")
    probe = _make_probe(idor_endpoints=[ep])
    _set_admin(probe, "absent")
    probe.auth.regular_session.get.return_value = _mock_response(
      json_data={"owner": "bob", "title": "t"})
    probe.auth.regular_session.cookies.get.return_value = None
    probe.auth.regular_session.patch.return_value = _mock_response(status=404)
    probe._test_ownership_update()
    self.assertEqual([f for f in probe.findings if f.scenario_id == "PT-A01-05"], [])


class TestAdminBaselineIsAlwaysAGet(unittest.TestCase):

  def test_mutating_callers_make_the_admin_session_send_only_get(self):
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[99], owner_field="owner")
    for method, runner in (("PATCH", "_test_ownership_update"),
                           ("DELETE", "_test_ownership_delete")):
      with self.subTest(method=method):
        probe = _make_probe(idor_endpoints=[ep])
        _set_admin(probe, "provided")
        sess = probe.auth.regular_session
        sess.get.return_value = _mock_response(json_data={"owner": "bob", "title": "t"})
        sess.cookies.get.return_value = None
        sess.patch.return_value = _mock_response(status=404)
        sess.delete.return_value = _mock_response(status=404)
        getattr(probe, runner)()
        verbs = [c.args[0] for c in probe.auth.official_session.request.call_args_list]
        self.assertEqual(verbs, ["GET"])
        # 404 explained by the admin reaching the endpoint: counted as tested.
        found = [f for f in probe.findings if f.scenario_id in ("PT-A01-05", "PT-A01-06")]
        self.assertEqual([f.status for f in found], ["not_vulnerable"])


class TestHiddenFieldReachability(unittest.TestCase):

  FORM = ('<form><input type="hidden" name="role" value="user">'
          '<input type="text" name="title" value="t"></form>')

  def _probe(self, admin_context):
    probe = _make_probe()
    probe.discovered_forms = ["/records/1/"]
    probe.auth.detected_csrf_field = None
    probe.auth.extract_csrf_value = MagicMock(return_value=None)
    probe.auth.admin_context = admin_context
    return probe

  def _verdict(self, probe):
    found = [f for f in probe.findings if f.scenario_id == "PT-A01-12"]
    return ([f.status for f in found],
            [e for f in found for e in f.evidence if e.startswith("reason=")])

  def test_denied_form_by_403_404_login_is_inconclusive(self):
    for admin, reason in (("provided", "endpoint_denied"),
                          ("absent", "admin_context_absent")):
      for name, resp in (("403", _mock_response(status=403)),
                         ("404", _mock_response(status=404)),
                         ("login", _login_redirect_response())):
        with self.subTest(admin=admin, denial=name):
          probe = self._probe(admin)
          probe.auth.regular_session.get = MagicMock(return_value=resp)
          probe._test_hidden_field_tampering()
          self.assertEqual(self._verdict(probe), (["inconclusive"], [f"reason={reason}"]))

  def test_reached_get_but_payload_post_redirected_to_login(self):
    probe = self._probe("absent")
    sess = probe.auth.regular_session
    sess.get = MagicMock(return_value=_reached_response(self.FORM))
    redirect = _mock_response(status=302, text="")
    redirect.headers["Location"] = "/auth/login/?next=/records/1/"
    sess.post = MagicMock(return_value=redirect)
    probe._test_hidden_field_tampering()
    self.assertEqual(self._verdict(probe), (["inconclusive"], ["reason=admin_context_absent"]))

  def test_post_only_action_405_is_skipped_without_a_post(self):
    """405 on the GET: no form, so no hidden field to tamper with. Nothing is
    POSTed (a guessed role=admin POST would change the account) and the
    action is neither tested nor counted as denied."""
    probe = self._probe("absent")
    sess = probe.auth.regular_session
    sess.get = MagicMock(return_value=_mock_response(status=405))
    sess.post = MagicMock()
    probe._test_hidden_field_tampering()
    sess.post.assert_not_called()
    self.assertNotIn("vulnerable", self._verdict(probe)[0])

  def test_post_answered_by_redirect_to_non_login_page_is_reached(self):
    probe = self._probe("provided")
    sess = probe.auth.regular_session
    sess.get = MagicMock(return_value=_reached_response(self.FORM))
    redirect = _mock_response(status=302, text="")
    redirect.headers["Location"] = "/records/"
    sess.post = MagicMock(return_value=redirect)
    probe._test_hidden_field_tampering()
    self.assertEqual(self._verdict(probe)[0], ["vulnerable"])


class TestQueryRoleOverrideReachability(unittest.TestCase):
  """PT-A01-10: a denied route says nothing about a role override."""

  def test_denied_baseline_or_probe_is_inconclusive(self):
    for admin, reason in (("provided", "endpoint_denied"),
                          ("absent", "admin_context_absent")):
      for name, denial in (("403", lambda: _mock_response(status=403)),
                           ("404", lambda: _mock_response(status=404)),
                           ("login", _login_redirect_response)):
        for where in ("baseline", "probe"):
          with self.subTest(admin=admin, denial=name, where=where):
            probe = _make_probe(discovered_routes=["/dashboard/"])
            probe.auth.admin_context = admin
            if where == "baseline":
              probe.auth.regular_session.get = MagicMock(
                side_effect=lambda *a, **k: denial())
            else:
              probe.auth.regular_session.get = MagicMock(
                side_effect=lambda *a, **k: (
                  denial() if k.get("params") else _reached_response("<p>Hello</p>")))
            probe._test_query_role_override()
            found = [f for f in probe.findings if f.scenario_id == "PT-A01-10"]
            self.assertEqual([f.status for f in found], ["inconclusive"])
            self.assertIn(f"reason={reason}", found[0].evidence)


class TestMassAssignmentReachability(unittest.TestCase):
  """PT-A04-01: a redirect to login is not an accepted submission."""

  FORM = '<form><input name="title" value="t"></form>'

  def _probe(self, admin_context):
    probe = _make_probe(allow_stateful=True)
    probe.discovered_forms = ["/profile/"]
    probe.auth.detected_csrf_field = None
    probe.auth.extract_csrf_value = MagicMock(return_value=None)
    probe.auth.admin_context = admin_context
    return probe

  def _verdict(self, probe):
    found = [f for f in probe.findings if f.scenario_id == "PT-A04-01"]
    return ([f.status for f in found],
            [e for f in found for e in f.evidence if e.startswith("reason=")])

  def test_denied_form_or_post_is_inconclusive(self):
    for admin, reason in (("provided", "endpoint_denied"),
                          ("absent", "admin_context_absent")):
      for where in ("form", "post"):
        with self.subTest(admin=admin, where=where):
          probe = self._probe(admin)
          sess = probe.auth.regular_session
          if where == "form":
            sess.get = MagicMock(side_effect=lambda *a, **k: _login_redirect_response())
          else:
            sess.get = MagicMock(return_value=_reached_response(self.FORM))
          sess.post = MagicMock(return_value=_redirect_to("/auth/login/?next=/profile/"))
          probe._test_mass_assignment()
          self.assertEqual(self._verdict(probe), (["inconclusive"], [f"reason={reason}"]))
          if where == "form":
            sess.post.assert_not_called()


class TestCreateUserPageIsNotALoginPage(unittest.TestCase):
  """PT-A01-02: an admin "create user" form posts to itself and carries a
  username and password field, but it is the admin page, not a login page."""

  PAGES = (
    # password + confirm
    '<form method="post"><input type="hidden" name="csrf" value="t">'
    '<input name="username"><input type="password" name="password1">'
    '<input type="password" name="password2"><input type="submit"></form>',
    # one password plus email and role
    '<form method="post" action=""><input name="username">'
    '<input type="email" name="email"><input type="password" name="password">'
    '<select name="role"><option value="admin">admin</option></select>'
    '<input type="submit" value="Create"></form>',
    # unquoted explicit action, username and a single password field
    '<form method=post action=/admin/users/new/><input name="username">'
    '<input type="password" name="password"><input type="submit"></form>',
  )

  def test_create_user_page_is_reported_vulnerable(self):
    for page in self.PAGES:
      with self.subTest(page=page):
        ep = AdminEndpoint(path="/admin/users/new/", method="GET",
                           content_markers=["password"])
        probe = _make_probe(admin_endpoints=[ep])
        _set_admin(probe, "absent")
        resp = _reached_response(page)
        resp.url = "http://testapp.local:8000/admin/users/new/"
        probe.auth.regular_session.get.return_value = resp
        probe._test_privilege_esc()
        found = [f for f in probe.findings if f.scenario_id == "PT-A01-02"]
        self.assertEqual([f.status for f in found], ["vulnerable"])


class TestOwnershipUpdateEveryEndpointAndRestore(unittest.TestCase):
  """RM-060 P2.5: one finding per endpoint; stop writing once a restore fails."""

  def _probe(self, restore_status):
    eps = [
      IdorEndpoint(path="/api/a/{id}/", test_ids=[1], owner_field="owner"),
      IdorEndpoint(path="/api/b/{id}/", test_ids=[1], owner_field="owner"),
    ]
    probe = _make_probe(idor_endpoints=eps, allow_stateful=True, regular_username="alice")
    sess = probe.auth.regular_session
    sess.cookies = MagicMock()
    sess.cookies.get = MagicMock(return_value="csrf123")
    sentinel = "redmesh-pt-a01-05-probe-marker"

    def get(url, **kw):
      # Before-GET sees "before"; after-GET (second per endpoint) sees sentinel.
      get.n[url] = get.n.get(url, 0) + 1
      title = "before" if get.n[url] % 2 == 1 else sentinel
      return _mock_response(status=200, json_data={"owner": "bob", "title": title})
    get.n = {}
    sess.get = MagicMock(side_effect=get)
    # Sentinel PATCH ok (200); restore PATCH (body carries the old title) gets restore_status.
    def patch(url, data=None, **kw):
      return _mock_response(status=restore_status if '"before"' in data else 200)
    sess.patch = MagicMock(side_effect=patch)
    return probe

  def test_each_endpoint_gets_its_own_finding_when_restore_succeeds(self):
    probe = self._probe(restore_status=200)
    probe._test_ownership_update()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-05" and x.status == "vulnerable"]
    self.assertEqual(len(f), 2)
    self.assertEqual({x.rollback_status for x in f}, {"reverted"})
    self.assertEqual(
      sorted(x.evidence[0].split(";")[0] for x in f),
      ["endpoint=/api/a/1/", "endpoint=/api/b/1/"],
    )

  def test_failed_restore_stops_further_writes_and_is_recorded(self):
    probe = self._probe(restore_status=500)
    probe._test_ownership_update()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-05" and x.status == "vulnerable"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].rollback_status, "revert_failed")
    # sentinel PATCH + failed restore PATCH on the first endpoint only
    self.assertEqual(probe.auth.regular_session.patch.call_count, 2)


class TestRestoreIsVerifiedRound1(unittest.TestCase):
  """RM-060 fix round 1: a restore counts only when a re-read shows the old value."""

  def _update_probe(self, restore_shows):
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[1], owner_field="owner")
    ep2 = IdorEndpoint(path="/api/other/{id}/", test_ids=[1], owner_field="owner")
    probe = _make_probe(idor_endpoints=[ep, ep2], allow_stateful=True, regular_username="alice")
    sess = probe.auth.regular_session
    sess.cookies = MagicMock()
    sess.cookies.get = MagicMock(return_value="csrf123")
    seq = {}
    def get(url, **kw):
      n = seq[url] = seq.get(url, 0) + 1
      title = {1: "before", 2: "redmesh-pt-a01-05-probe-marker"}.get(n, restore_shows)
      return _mock_response(status=200, json_data={"owner": "bob", "title": title})
    sess.get = MagicMock(side_effect=get)
    sess.patch = MagicMock(return_value=_mock_response(status=200))
    return probe

  def test_a01_05_restore_2xx_but_value_unchanged_is_revert_failed_and_stops(self):
    probe = self._update_probe(restore_shows="redmesh-pt-a01-05-probe-marker")
    probe._test_ownership_update()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-05" and x.status == "vulnerable"]
    self.assertEqual(len(f), 1)
    self.assertEqual(f[0].rollback_status, "revert_failed")
    self.assertEqual(probe.auth.regular_session.patch.call_count, 2)

  def test_a01_05_verified_restore_continues_to_next_endpoint(self):
    probe = self._update_probe(restore_shows="before")
    probe._test_ownership_update()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-05" and x.status == "vulnerable"]
    self.assertEqual([x.rollback_status for x in f], ["reverted", "reverted"])

  def test_a01_05_record_without_title_is_never_restored_with_null(self):
    ep = IdorEndpoint(path="/api/records/{id}/", test_ids=[1], owner_field="owner")
    probe = _make_probe(idor_endpoints=[ep], allow_stateful=True, regular_username="alice")
    sess = probe.auth.regular_session
    sess.cookies = MagicMock()
    sess.cookies.get = MagicMock(return_value="c")
    gets = iter([
      _mock_response(json_data={"owner": "bob"}),
      _mock_response(json_data={"owner": "bob", "title": "redmesh-pt-a01-05-probe-marker"}),
    ])
    sess.get = MagicMock(side_effect=lambda *a, **k: next(gets))
    sess.patch = MagicMock(return_value=_mock_response(status=200))
    probe._test_ownership_update()
    f = [x for x in probe.findings if x.scenario_id == "PT-A01-05" and x.status == "vulnerable"]
    self.assertEqual(f[0].rollback_status, "revert_failed")
    self.assertEqual(sess.patch.call_count, 1)  # sentinel only, no title=null

  def _mass_probe(self, restore_owner):
    eps = [IdorEndpoint(path="/api/a/{id}/", test_ids=[2], owner_field="owner"),
           IdorEndpoint(path="/api/b/{id}/", test_ids=[2], owner_field="owner")]
    probe = _make_probe(idor_endpoints=eps, allow_stateful=True)
    sess = probe.auth.regular_session
    sess.cookies = MagicMock()
    sess.cookies.get = MagicMock(return_value="c")
    seq = {}
    def get(url, **kw):
      n = seq[url] = seq.get(url, 0) + 1
      owner = {1: "alice", 2: "1"}.get(n, restore_owner)
      return _mock_response(status=200, json_data={"owner": owner})
    sess.get = MagicMock(side_effect=get)
    sess.patch = MagicMock(return_value=_mock_response(status=200))
    return probe

  def test_a04_02_verified_restore_continues_to_next_endpoint(self):
    probe = self._mass_probe(restore_owner="alice")
    probe._test_mass_assignment_ownership()
    f = [x for x in probe.findings if x.scenario_id == "PT-A04-02" and x.status == "vulnerable"]
    self.assertEqual([x.rollback_status for x in f], ["reverted", "reverted"])

  def test_a04_02_unverified_restore_stops_further_writes(self):
    probe = self._mass_probe(restore_owner="1")
    probe._test_mass_assignment_ownership()
    f = [x for x in probe.findings if x.scenario_id == "PT-A04-02" and x.status == "vulnerable"]
    self.assertEqual([x.rollback_status for x in f], ["revert_failed"])
    self.assertEqual(probe.auth.regular_session.patch.call_count, 2)


class TestReadOnlyProbesReportEveryEndpointRound1(unittest.TestCase):

  def test_idor_one_finding_per_endpoint(self):
    eps = [IdorEndpoint(path="/api/a/{id}/", test_ids=[9], owner_field="owner"),
           IdorEndpoint(path="/api/b/{id}/", test_ids=[9], owner_field="owner")]
    probe = _make_probe(idor_endpoints=eps)
    resp = _mock_response(json_data={"owner": "bob"})
    resp.json.return_value = {"owner": "bob"}
    probe.auth.regular_session.get.return_value = resp
    probe._test_idor()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A01-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 2)
    self.assertEqual(len({f.evidence[0] for f in vuln}), 2)

  def test_query_role_override_one_finding_per_path(self):
    probe = _make_probe(discovered_routes=["/p1/", "/p2/"], regular_username="alice")
    def get(url, params=None, **kw):
      if params:
        return _mock_response(status=200, text="Admin Panel")
      return _mock_response(status=200, text="hello")
    probe.auth.regular_session.get = MagicMock(side_effect=get)
    probe._test_query_role_override()
    vuln = [f for f in probe.findings if f.scenario_id == "PT-A01-10" and f.status == "vulnerable"]
    self.assertEqual(sorted(f.evidence[0].split(";")[0] for f in vuln),
                     ["path=/p1/", "path=/p2/"])
