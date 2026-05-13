"""OWASP API Top 10 — Subphases 3.2 + 3.3 (ApiAbuseProbes)."""

from __future__ import annotations

import json
import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.graybox.probes.api_abuse import (
  ApiAbuseProbes,
)
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiBusinessFlow, ApiResourceEndpoint, ApiSecurityConfig, GrayboxTargetConfig,
)


def _resp(status=200, text="", headers=None):
  r = MagicMock()
  r.status_code = status
  r.text = text
  r.headers = headers or {}
  return r


def _make_probe(*, resource_endpoints=None, business_flows=None,
                 allow_stateful=False):
  cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(
    resource_endpoints=list(resource_endpoints or []),
    business_flows=list(business_flows or []),
  ))
  auth = MagicMock()
  auth.official_session = MagicMock()
  auth.regular_session = MagicMock()
  safety = MagicMock()
  safety.throttle = MagicMock()
  safety.sanitize_error = MagicMock(side_effect=lambda s: s)
  return ApiAbuseProbes(
    target_url="http://api.example",
    auth_manager=auth, target_config=cfg, safety=safety,
    allow_stateful=allow_stateful,
  )


class TestApi4NoPaginationCap(unittest.TestCase):

  def test_size_explosion_emits_medium(self):
    ep = ApiResourceEndpoint(path="/api/records/", baseline_limit=10,
                              abuse_limit=999_999)
    p = _make_probe(resource_endpoints=[ep])
    # 100B baseline → 1MB abuse response = >5× growth
    p.auth.official_session.get.side_effect = [
      _resp(status=200, text="x" * 100),
      _resp(status=200, text="y" * 1_000_000),
    ]
    p.run_safe("api_no_pagination_cap", p._test_no_pagination_cap)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI4-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "MEDIUM")


class TestApi4OversizedPayload(unittest.TestCase):

  def test_oversized_accepted_medium(self):
    ep = ApiResourceEndpoint(path="/api/notes/")
    p = _make_probe(resource_endpoints=[ep])
    p.auth.official_session.post.return_value = _resp(status=201)
    p.run_safe("api_oversized_payload", p._test_oversized_payload)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI4-02" and f.status == "vulnerable"]
    self.assertEqual(vuln[0].severity, "MEDIUM")


class TestApi4NoRateLimit(unittest.TestCase):

  def test_only_fires_when_rate_limit_expected(self):
    ep = ApiResourceEndpoint(path="/api/list/", rate_limit_expected=False)
    p = _make_probe(resource_endpoints=[ep])
    p.auth.official_session.get.return_value = _resp(status=200)
    p.run_safe("api_no_rate_limit", p._test_no_rate_limit)
    self.assertEqual(
      [f for f in p.findings if f.scenario_id == "PT-OAPI4-03"], [],
    )

  def test_10_requests_no_429_or_headers_low(self):
    ep = ApiResourceEndpoint(path="/api/list/", rate_limit_expected=True)
    p = _make_probe(resource_endpoints=[ep])
    p.auth.official_session.get.return_value = _resp(status=200)
    p.run_safe("api_no_rate_limit", p._test_no_rate_limit)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI4-03" and f.status == "vulnerable"]
    self.assertEqual(vuln[0].severity, "LOW")


class TestApi6FlowAbuse(unittest.TestCase):

  def test_stateful_disabled_emits_inconclusive(self):
    flow = ApiBusinessFlow(path="/api/auth/signup/", flow_name="signup",
                            body_template={"u": "x", "p": "p"})
    p = _make_probe(business_flows=[flow], allow_stateful=False)
    p.run_safe("api_flow_no_rate_limit", p._test_flow_no_rate_limit)
    incon = [f for f in p.findings
             if f.scenario_id == "PT-OAPI6-01" and f.status == "inconclusive"]
    self.assertEqual(len(incon), 1)
    self.assertIn("stateful_probes_disabled",
                   "\n".join(incon[0].evidence))


if __name__ == "__main__":
  unittest.main()
