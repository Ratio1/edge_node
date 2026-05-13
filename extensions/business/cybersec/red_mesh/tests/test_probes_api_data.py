"""OWASP API Top 10 — Subphases 2.2 + 3.1.

Covers `ApiDataProbes`:
  PT-OAPI3-01 — excessive property exposure (read-only)
  PT-OAPI3-02 — mass-assignment property tampering (stateful)
"""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.probes.api_data import (
  ApiDataProbes,
)
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiPropertyEndpoint, ApiSecurityConfig, GrayboxTargetConfig,
)


def _mock_response(status=200, json_body=None,
                    content_type="application/json"):
  resp = MagicMock()
  resp.status_code = status
  resp.headers = {"content-type": content_type}
  if json_body is not None:
    resp.json.return_value = json_body
    resp.text = json.dumps(json_body)
  else:
    resp.json.side_effect = ValueError("not json")
    resp.text = ""
  return resp


def _make_probe(*, property_endpoints=None, allow_stateful=False,
                 sensitive_field_patterns=None, tampering_fields=None,
                 regular_username="alice"):
  api_cfg_kwargs = {
    "property_endpoints": list(property_endpoints or []),
  }
  if sensitive_field_patterns is not None:
    api_cfg_kwargs["sensitive_field_patterns"] = sensitive_field_patterns
  if tampering_fields is not None:
    api_cfg_kwargs["tampering_fields"] = tampering_fields
  cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(**api_cfg_kwargs))
  auth = MagicMock()
  auth.regular_session = MagicMock()
  auth.official_session = MagicMock()
  safety = MagicMock()
  safety.throttle = MagicMock()
  safety.sanitize_error = MagicMock(side_effect=lambda s: s)
  return ApiDataProbes(
    target_url="http://api.example",
    auth_manager=auth,
    target_config=cfg,
    safety=safety,
    regular_username=regular_username,
    allow_stateful=allow_stateful,
  )


class TestApi3PropertyExposure(unittest.TestCase):
  """PT-OAPI3-01."""

  def test_password_hash_in_response_emits_vulnerable(self):
    ep = ApiPropertyEndpoint(path="/api/profile/{id}/", test_id=1)
    p = _make_probe(property_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"username": "alice", "password_hash": "$2b$12$abc"},
    )
    p.run()
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI3-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")
    leaked = next(e for e in vuln[0].evidence if e.startswith("sensitive_fields_present="))
    self.assertIn("password_hash", leaked)

  def test_clean_response_emits_not_vulnerable(self):
    ep = ApiPropertyEndpoint(path="/api/profile/{id}/", test_id=1)
    p = _make_probe(property_endpoints=[ep])
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"username": "alice", "display_name": "Alice"},
    )
    p.run()
    clean = [f for f in p.findings
             if f.scenario_id == "PT-OAPI3-01" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)

  def test_custom_sensitive_pattern_appended(self):
    ep = ApiPropertyEndpoint(path="/api/profile/{id}/", test_id=1)
    p = _make_probe(
      property_endpoints=[ep],
      sensitive_field_patterns=[r"internal_"],
    )
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"id": 1, "internal_audit_trail": [1, 2]},
    )
    p.run()
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI3-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)


class TestApi3PropertyTampering(unittest.TestCase):
  """PT-OAPI3-02 — stateful."""

  def test_stateful_disabled_emits_inconclusive(self):
    ep = ApiPropertyEndpoint(path="/api/profile/{id}/", test_id=1)
    p = _make_probe(property_endpoints=[ep], allow_stateful=False)
    p.auth.regular_session.get.return_value = _mock_response(
      json_body={"is_admin": False},
    )
    p.run()
    incon = [f for f in p.findings
             if f.scenario_id == "PT-OAPI3-02" and f.status == "inconclusive"]
    self.assertEqual(len(incon), 1)
    self.assertIn("stateful_probes_disabled",
                   "\n".join(incon[0].evidence))

  def test_mass_assignment_confirmed_emits_vulnerable(self):
    ep = ApiPropertyEndpoint(path="/api/profile/{id}/", test_id=1,
                              method_write="PATCH")
    p = _make_probe(property_endpoints=[ep], allow_stateful=True,
                     tampering_fields=["is_admin"])
    # PT-OAPI3-01 runs first (reads the endpoint to check sensitive fields),
    # then PT-OAPI3-02 baseline + verify each call session.get once.
    p.auth.regular_session.get.side_effect = [
      _mock_response(json_body={"username": "alice"}),  # 3-01 read (clean)
      _mock_response(json_body={"is_admin": False}),     # 3-02 baseline
      _mock_response(json_body={"is_admin": True}),      # 3-02 verify
    ]
    p.auth.regular_session.patch.return_value = _mock_response(
      json_body={"is_admin": True}
    )
    p.run()
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI3-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].rollback_status, "reverted")
    self.assertEqual(vuln[0].severity, "HIGH")


if __name__ == "__main__":
  unittest.main()
