"""OWASP API Top 10 — Subphase 2.1 + 2.3 + 3.4.

Tests for `ApiAccessProbes` (PT-OAPI1-01 BOLA + PT-OAPI5-01..04 BFLA).
This file lands incrementally: Subphase 2.1 adds TestApi1Bola; later
subphases append TestApi5Bfla and TestApi5BflaStateful.
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.probes.api_access import (
  ApiAccessProbes,
)
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiObjectEndpoint, ApiFunctionEndpoint, ApiSecurityConfig,
  GrayboxTargetConfig,
)


def _mock_response(status=200, json_body=None, text="",
                    content_type="application/json"):
  resp = MagicMock()
  resp.status_code = status
  resp.headers = {"content-type": content_type}
  resp.text = text
  if json_body is not None:
    resp.json.return_value = json_body
    if not text:
      resp.text = json.dumps(json_body)
  else:
    resp.json.side_effect = ValueError("not json")
  return resp


def _make_probe(*, object_endpoints=None, function_endpoints=None,
                regular_username="alice", regular_session=None,
                anon_session=None, allow_stateful=False):
  cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(
    object_endpoints=list(object_endpoints or []),
    function_endpoints=list(function_endpoints or []),
  ))
  auth = MagicMock()
  auth.regular_session = regular_session if regular_session is not None else MagicMock()
  auth.official_session = MagicMock()
  if anon_session is not None:
    auth.make_anonymous_session = MagicMock(return_value=anon_session)
  else:
    # Default to a fresh MagicMock when callers don't provide one
    auth.make_anonymous_session = MagicMock(return_value=MagicMock())
  safety = MagicMock()
  safety.throttle = MagicMock()
  safety.sanitize_error = MagicMock(side_effect=lambda s: s)
  return ApiAccessProbes(
    target_url="http://api.example",
    auth_manager=auth,
    target_config=cfg,
    safety=safety,
    regular_username=regular_username,
    allow_stateful=allow_stateful,
  )


class TestApi1Bola(unittest.TestCase):

  # ── Vulnerable cases ────────────────────────────────────────────────

  def test_owner_mismatch_emits_high(self):
    """Different owner_value than authenticated user → vulnerable HIGH."""
    ep = ApiObjectEndpoint(path="/api/records/{id}/", test_ids=[42],
                            owner_field="owner")
    p = _make_probe(object_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"owner": "bob", "data": "secret"},
    )
    p.run()
    vuln = [f for f in p.findings if f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    f = vuln[0]
    self.assertEqual(f.scenario_id, "PT-OAPI1-01")
    self.assertEqual(f.severity, "HIGH")
    self.assertIn("CWE-639", f.cwe)
    # ATT&CK default from catalog (T1190, T1078)
    self.assertEqual(set(f.attack), {"T1190", "T1078"})

  def test_pii_field_escalates_to_critical(self):
    """Leaked response with `email` / `ssn` / `password` field name → CRITICAL."""
    ep = ApiObjectEndpoint(path="/api/users/{id}/", test_ids=[7],
                            owner_field="username")
    p = _make_probe(object_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"username": "bob", "email": "bob@example.com",
                 "credit_card_number": "4242-4242-4242-4242"},
    )
    p.run()
    vuln = [f for f in p.findings if f.status == "vulnerable"]
    self.assertEqual(vuln[0].severity, "CRITICAL")
    pii_evidence = next((e for e in vuln[0].evidence if e.startswith("pii_fields=")), None)
    self.assertIsNotNone(pii_evidence)
    self.assertIn("email", pii_evidence)

  def test_tenant_mismatch_emits_vulnerable(self):
    """tenant_field present in response → vulnerable even if owner matches."""
    ep = ApiObjectEndpoint(
      path="/api/records/{id}/", test_ids=[1],
      owner_field="owner", tenant_field="tenant_id",
      expected_tenant="tenant-a",
    )
    p = _make_probe(object_endpoints=[ep])
    # owner matches alice, but tenant_id leaks cross-tenant data.
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"owner": "alice", "tenant_id": "other-tenant", "x": 1},
    )
    p.run()
    vuln = [f for f in p.findings if f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertIn("tenant_field=tenant_id",
                   "\n".join(vuln[0].evidence))

  # ── Clean cases ─────────────────────────────────────────────────────

  def test_owner_matches_emits_clean(self):
    ep = ApiObjectEndpoint(path="/api/records/{id}/", test_ids=[1],
                            owner_field="owner")
    p = _make_probe(object_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"owner": "alice", "data": "ok"},
    )
    p.run()
    clean = [f for f in p.findings if f.status == "not_vulnerable"
              and f.scenario_id == "PT-OAPI1-01"]
    self.assertEqual(len(clean), 1)

  # ── Inconclusive cases (FP guards) ──────────────────────────────────

  def test_html_response_skipped(self):
    """HTML responses belong to AccessControlProbes (web IDOR), not API BOLA."""
    ep = ApiObjectEndpoint(path="/profile/{id}/", test_ids=[1],
                            owner_field="owner")
    p = _make_probe(object_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      content_type="text/html", text="<html>...</html>",
    )
    p.run()
    # No vulnerable; one inconclusive ("no_evaluable_responses") because
    # every iteration was skipped.
    self.assertEqual(
      [f for f in p.findings if f.status == "vulnerable"], [],
    )
    inconclusive = [f for f in p.findings if f.status == "inconclusive"
                    and f.scenario_id == "PT-OAPI1-01"]
    self.assertEqual(len(inconclusive), 1)
    self.assertIn("no_evaluable_responses",
                   "\n".join(inconclusive[0].evidence))

  def test_4xx_skipped(self):
    """403 / 404 means the endpoint refused — that's the correct behaviour."""
    ep = ApiObjectEndpoint(path="/api/records/{id}/", test_ids=[99],
                            owner_field="owner")
    p = _make_probe(object_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      status=403, json_body={"detail": "Forbidden"},
    )
    p.run()
    # No vulnerable; sole finding is the rolled-up inconclusive.
    statuses = [f.status for f in p.findings]
    self.assertNotIn("vulnerable", statuses)
    self.assertIn("inconclusive", statuses)

  def test_owner_field_missing_skipped(self):
    """Configured owner_field absent from response → skip (can't compare)."""
    ep = ApiObjectEndpoint(path="/api/records/{id}/", test_ids=[1],
                            owner_field="user_id")  # not in response
    p = _make_probe(object_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"id": 1, "data": "ok"},  # no user_id field
    )
    p.run()
    statuses = [f.status for f in p.findings]
    self.assertNotIn("vulnerable", statuses)

  def test_no_object_endpoints_emit_inconclusive_inventory(self):
    """Empty config still tells the operator API1/API5 were not evaluated."""
    p = _make_probe(object_endpoints=[])
    p.run()
    ids = {f.scenario_id for f in p.findings if f.status == "inconclusive"}
    self.assertIn("PT-OAPI1-01", ids)
    self.assertIn("PT-OAPI5-01", ids)

  def test_no_authenticated_session_emits_inconclusive(self):
    """No session at all → inconclusive (probe could not run)."""
    ep = ApiObjectEndpoint(path="/api/records/{id}/", test_ids=[1],
                            owner_field="owner")
    p = _make_probe(object_endpoints=[ep])
    p.auth.regular_session = None
    p.auth.official_session = None
    p.run()
    f = p.findings[0]
    self.assertEqual(f.status, "inconclusive")
    self.assertIn("no_low_privileged_session", f.evidence[0])

  def test_no_regular_session_does_not_fallback_to_official(self):
    ep = ApiObjectEndpoint(path="/api/records/{id}/", test_ids=[1],
                            owner_field="owner")
    p = _make_probe(object_endpoints=[ep])
    p.auth.regular_session = None
    p.auth.official_session.get.return_value = _mock_response(
      json_body={"owner": "bob"},
    )
    p.run()
    self.assertFalse(p.auth.official_session.get.called)
    f = next(f for f in p.findings if f.scenario_id == "PT-OAPI1-01")
    self.assertEqual(f.status, "inconclusive")
    self.assertIn("no_low_privileged_session", f.evidence[0])


class TestApi5Bfla(unittest.TestCase):
  """PT-OAPI5-01 + PT-OAPI5-02 — read-only BFLA (Subphase 2.3)."""

  def _make_function_probe(self, **kw):
    return _make_probe(**kw)

  # ── PT-OAPI5-01 — regular user reaches admin function ──────────────

  def test_regular_2xx_on_admin_function_emits_critical(self):
    """Admin path returns 200 to regular user → CRITICAL."""
    ep = ApiFunctionEndpoint(path="/api/admin/export-users/", method="GET",
                              privilege="admin")
    p = self._make_function_probe(function_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"users": [{"id": 1}]},
    )
    p.run()
    vuln = [f for f in p.findings
            if f.status == "vulnerable" and f.scenario_id == "PT-OAPI5-01"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "CRITICAL")  # /admin path
    self.assertEqual(set(vuln[0].attack), {"T1190", "T1078"})

  def test_regular_403_emits_clean(self):
    """Auth gate working → not_vulnerable."""
    ep = ApiFunctionEndpoint(path="/api/admin/export/", method="GET",
                              privilege="admin")
    p = self._make_function_probe(function_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      status=403, json_body={"detail": "Forbidden"},
    )
    p.run()
    clean = [f for f in p.findings
             if f.status == "not_vulnerable" and f.scenario_id == "PT-OAPI5-01"]
    self.assertEqual(len(clean), 1)
    # Marker reason is auth_gate_returned_4xx
    self.assertIn("auth_gate_returned_4xx",
                   "\n".join(clean[0].evidence))

  def test_auth_required_marker_in_2xx_emits_clean(self):
    """If body contains the configured auth_required_marker, treat as clean."""
    ep = ApiFunctionEndpoint(
      path="/api/admin/users/", method="GET", privilege="admin",
      auth_required_marker="login required",
    )
    p = self._make_function_probe(function_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      status=200, text="<html>Login Required to access</html>",
      content_type="text/html",
    )
    p.run()
    clean = [f for f in p.findings
             if f.status == "not_vulnerable" and f.scenario_id == "PT-OAPI5-01"]
    self.assertEqual(len(clean), 1)

  def test_non_admin_path_baseline_high(self):
    """Non-admin function path defaults to HIGH (not CRITICAL)."""
    ep = ApiFunctionEndpoint(path="/api/reports/", method="GET",
                              privilege="user")
    p = self._make_function_probe(function_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"reports": []},
    )
    p.run()
    vuln = [f for f in p.findings
            if f.status == "vulnerable" and f.scenario_id == "PT-OAPI5-01"]
    self.assertEqual(vuln[0].severity, "HIGH")

  def test_mutating_method_skipped_in_phase_2(self):
    """method=POST is deferred to PT-OAPI5-04 (Subphase 3.4)."""
    ep = ApiFunctionEndpoint(path="/api/admin/promote/", method="POST",
                              privilege="admin")
    p = self._make_function_probe(function_endpoints=[ep])
    p.auth.regular_session.post.return_value = _mock_response(json_body={})
    p.run()
    # No 5-01 vulnerable; only the rolled-up inconclusive.
    self.assertEqual(
      [f for f in p.findings
       if f.status == "vulnerable" and f.scenario_id == "PT-OAPI5-01"],
      [],
    )
    incon = [f for f in p.findings
             if f.status == "inconclusive" and f.scenario_id == "PT-OAPI5-01"]
    self.assertEqual(len(incon), 1)

  # ── PT-OAPI5-02 — anonymous reaches user function ──────────────────

  def test_anon_session_used_for_pt_oapi5_02(self):
    """PT-OAPI5-02 must use make_anonymous_session, not the regular session."""
    ep = ApiFunctionEndpoint(path="/api/me/", method="GET", privilege="user")
    anon = MagicMock()
    anon.get.return_value = _mock_response(json_body={"id": 1})
    p = self._make_function_probe(function_endpoints=[ep], anon_session=anon)
    p.run()
    vuln = [f for f in p.findings
            if f.status == "vulnerable" and f.scenario_id == "PT-OAPI5-02"]
    self.assertEqual(len(vuln), 1)
    p.auth.make_anonymous_session.assert_called()

  def test_anon_401_emits_clean(self):
    """Anon hits 401 → clean."""
    ep = ApiFunctionEndpoint(path="/api/me/", method="GET")
    anon = MagicMock()
    anon.get.return_value = _mock_response(
      status=401, json_body={"detail": "Authentication required"},
    )
    p = self._make_function_probe(function_endpoints=[ep], anon_session=anon)
    p.run()
    clean = [f for f in p.findings
             if f.status == "not_vulnerable" and f.scenario_id == "PT-OAPI5-02"]
    self.assertEqual(len(clean), 1)


class TestApi5BflaStateful(unittest.TestCase):
  """PT-OAPI5-03 + PT-OAPI5-04 stateful BFLA attribution and rollback."""

  def _stateful_probe(self, ep):
    return _make_probe(function_endpoints=[ep], allow_stateful=True)

  def test_method_override_skips_when_plain_mutating_method_allowed(self):
    ep = ApiFunctionEndpoint(
      path="/api/admin/users/7/promote/",
      method="POST",
      privilege="admin",
      revert_path="/api/admin/users/7/demote/",
      revert_body={"role": "user"},
    )
    p = self._stateful_probe(ep)
    p.auth.regular_session.post.side_effect = [
      _mock_response(status=200),
      _mock_response(status=200),
    ]

    p.run_safe("api_bfla_method_override", p._test_bfla_method_override)

    self.assertEqual(
      [f for f in p.findings
       if f.status == "vulnerable" and f.scenario_id == "PT-OAPI5-03"],
      [],
    )
    incon = [f for f in p.findings
             if f.status == "inconclusive" and f.scenario_id == "PT-OAPI5-03"]
    self.assertEqual(len(incon), 1)
    self.assertIn("plain_mutating_method_allowed", "\n".join(incon[0].evidence))
    self.assertEqual(p.auth.regular_session.post.call_count, 2)
    self.assertEqual(
      p.auth.regular_session.post.call_args_list[-1].args[0],
      "http://api.example/api/admin/users/7/demote/",
    )

  def test_method_override_reports_only_after_plain_method_rejected(self):
    ep = ApiFunctionEndpoint(
      path="/api/admin/users/7/promote/",
      method="POST",
      privilege="admin",
      revert_path="/api/admin/users/7/demote/",
    )
    p = self._stateful_probe(ep)
    p.auth.regular_session.post.side_effect = [
      _mock_response(status=403),
      _mock_response(status=200),
      _mock_response(status=200),
    ]

    p.run_safe("api_bfla_method_override", p._test_bfla_method_override)

    vuln = [f for f in p.findings
            if f.status == "vulnerable" and f.scenario_id == "PT-OAPI5-03"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].rollback_status, "reverted")
    self.assertIn("plain_status=403", "\n".join(vuln[0].evidence))
    override_call = p.auth.regular_session.post.call_args_list[1]
    self.assertEqual(
      override_call.kwargs["headers"],
      {"X-HTTP-Method-Override": "GET"},
    )

  def test_mutating_bfla_revert_failure_escalates_severity(self):
    ep = ApiFunctionEndpoint(
      path="/api/admin/users/7/promote/",
      method="POST",
      privilege="admin",
      revert_path="/api/admin/users/7/demote/",
    )
    p = self._stateful_probe(ep)
    p.auth.regular_session.post.side_effect = [
      _mock_response(status=200),
      _mock_response(status=500),
    ]

    p.run_safe("api_bfla_mutating", p._test_bfla_regular_as_admin_mutating)

    vuln = [f for f in p.findings
            if f.status == "vulnerable" and f.scenario_id == "PT-OAPI5-04"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].rollback_status, "revert_failed")
    self.assertEqual(vuln[0].severity, "CRITICAL")


if __name__ == "__main__":
  unittest.main()
