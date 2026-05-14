"""OWASP API Top 10 — Subphase 2.6 + (3.x via stateful PT-OAPI2-03).

`ApiAuthProbes`: PT-OAPI2-01 alg=none, PT-OAPI2-02 weak HMAC,
PT-OAPI2-03 logout invalidation (stateful).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.graybox.probes.api_auth import (
  ApiAuthProbes, _forge_jwt,
)
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiSecurityConfig, ApiTokenEndpoint, GrayboxTargetConfig,
)


def _hs256_jwt(payload: dict, secret: str) -> str:
  return _forge_jwt({"alg": "HS256", "typ": "JWT"}, payload, secret=secret)


def _resp(status=200, json_body=None):
  r = MagicMock()
  r.status_code = status
  r.headers = {}
  if json_body is not None:
    r.json.return_value = json_body
    r.text = json.dumps(json_body)
  else:
    r.json.side_effect = ValueError("not json")
    r.text = ""
  return r


def _make_probe(*, token_endpoints, allow_stateful=False):
  cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(
    token_endpoints=token_endpoints,
  ))
  auth = MagicMock()
  auth.official_session = MagicMock()
  auth.regular_session = MagicMock()
  auth.verify_tls = True
  safety = MagicMock()
  safety.throttle = MagicMock()
  safety.sanitize_error = MagicMock(side_effect=lambda s: s)
  return ApiAuthProbes(
    target_url="http://api.example",
    auth_manager=auth, target_config=cfg, safety=safety,
    allow_stateful=allow_stateful,
  )


class TestApi2AlgNone(unittest.TestCase):

  @patch("extensions.business.cybersec.red_mesh.graybox.probes.api_auth.requests")
  def test_protected_path_accepts_forged_alg_none_critical(self, mock_requests):
    tok = ApiTokenEndpoint(
      token_path="/api/token/", protected_path="/api/me/",
    )
    p = _make_probe(token_endpoints=tok)
    real = _hs256_jwt({"sub": "alice"}, "topsecret")
    p.auth.official_session.post.return_value = _resp(
      json_body={"token": real},
    )
    p.auth.make_anonymous_session.return_value.get.return_value = _resp(
      json_body={"id": 1, "is_admin": True},
    )
    p.run_safe("api_jwt_alg_none", p._test_jwt_alg_none)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI2-01" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "CRITICAL")

  @patch("extensions.business.cybersec.red_mesh.graybox.probes.api_auth.requests")
  def test_protected_path_rejects_forged_clean(self, mock_requests):
    tok = ApiTokenEndpoint(
      token_path="/api/token/", protected_path="/api/me/",
    )
    p = _make_probe(token_endpoints=tok)
    real = _hs256_jwt({"sub": "alice"}, "topsecret")
    p.auth.official_session.post.return_value = _resp(
      json_body={"token": real},
    )
    p.auth.make_anonymous_session.return_value.get.return_value = _resp(status=401)
    p.run_safe("api_jwt_alg_none", p._test_jwt_alg_none)
    clean = [f for f in p.findings
             if f.scenario_id == "PT-OAPI2-01" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)


class TestApi2WeakHmac(unittest.TestCase):

  def test_weak_secret_detected_high(self):
    tok = ApiTokenEndpoint(
      token_path="/api/token/", protected_path="/api/me/",
      weak_secret_candidates=["changeme", "secret", "password"],
    )
    p = _make_probe(token_endpoints=tok)
    real = _hs256_jwt({"sub": "alice"}, "changeme")
    p.auth.official_session.post.return_value = _resp(
      json_body={"token": real},
    )
    p.run_safe("api_jwt_weak_hmac", p._test_jwt_weak_hmac)
    vuln = [f for f in p.findings
            if f.scenario_id == "PT-OAPI2-02" and f.status == "vulnerable"]
    self.assertEqual(len(vuln), 1)
    self.assertEqual(vuln[0].severity, "HIGH")

  def test_strong_secret_clean(self):
    tok = ApiTokenEndpoint(
      token_path="/api/token/", protected_path="/api/me/",
      weak_secret_candidates=["changeme", "secret"],
    )
    p = _make_probe(token_endpoints=tok)
    real = _hs256_jwt({"sub": "alice"}, "a-very-long-random-secret-32bytes")
    p.auth.official_session.post.return_value = _resp(
      json_body={"token": real},
    )
    p.run_safe("api_jwt_weak_hmac", p._test_jwt_weak_hmac)
    clean = [f for f in p.findings
             if f.scenario_id == "PT-OAPI2-02" and f.status == "not_vulnerable"]
    self.assertEqual(len(clean), 1)


class TestApi2LogoutInvalidation(unittest.TestCase):

  @patch("extensions.business.cybersec.red_mesh.graybox.probes.api_auth.requests")
  def test_stateful_disabled_inconclusive(self, mock_requests):
    tok = ApiTokenEndpoint(
      token_path="/api/token/", protected_path="/api/me/",
      logout_path="/api/auth/logout/",
    )
    p = _make_probe(token_endpoints=tok, allow_stateful=False)
    p.auth.official_session.post.return_value = _resp(
      json_body={"token": _hs256_jwt({"sub": "alice"}, "s")},
    )
    p.run_safe("api_token_logout_invalidation",
                p._test_token_logout_invalidation)
    incon = [f for f in p.findings
             if f.scenario_id == "PT-OAPI2-03" and f.status == "inconclusive"]
    self.assertEqual(len(incon), 1)

  def test_no_logout_path_inconclusive(self):
    tok = ApiTokenEndpoint(
      token_path="/api/token/", protected_path="/api/me/",
      logout_path="",
    )
    p = _make_probe(token_endpoints=tok, allow_stateful=True)
    p.run_safe("api_token_logout_invalidation",
                p._test_token_logout_invalidation)
    incon = [f for f in p.findings
             if f.scenario_id == "PT-OAPI2-03" and f.status == "inconclusive"]
    self.assertEqual(len(incon), 1)
    self.assertIn("no_logout_path_configured",
                   "\n".join(incon[0].evidence))


if __name__ == "__main__":
  unittest.main()
