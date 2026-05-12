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
  ApiObjectEndpoint, ApiSecurityConfig, GrayboxTargetConfig,
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


def _make_probe(*, object_endpoints=None, regular_username="alice",
                regular_session=None):
  cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(
    object_endpoints=list(object_endpoints or []),
  ))
  auth = MagicMock()
  auth.regular_session = regular_session if regular_session is not None else MagicMock()
  auth.official_session = MagicMock()
  safety = MagicMock()
  safety.throttle = MagicMock()
  safety.sanitize_error = MagicMock(side_effect=lambda s: s)
  return ApiAccessProbes(
    target_url="http://api.example",
    auth_manager=auth,
    target_config=cfg,
    safety=safety,
    regular_username=regular_username,
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

  def test_no_object_endpoints_no_findings(self):
    """Empty config → run() emits nothing (no inconclusive noise)."""
    p = _make_probe(object_endpoints=[])
    p.run()
    self.assertEqual(p.findings, [])

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
    self.assertIn("no_authenticated_session", f.evidence[0])


if __name__ == "__main__":
  unittest.main()
