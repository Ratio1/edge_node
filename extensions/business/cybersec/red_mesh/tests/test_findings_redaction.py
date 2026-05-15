"""OWASP API Top 10 — Subphase 1.6 commit #3.

Storage-boundary scrubber tests. Asserts that the centralised
`scrub_graybox_secrets` (and the `to_flat_finding` pass-through) strip
every documented secret pattern even when probes don't redact at
emission time.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

import requests

from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
from extensions.business.cybersec.red_mesh.graybox.safety import SafetyControls
from extensions.business.cybersec.red_mesh.graybox.findings import (
  FindingRedactionContext,
  GrayboxFinding,
  scrub_graybox_secrets,
)
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiSecurityConfig,
  AuthDescriptor,
  GrayboxTargetConfig,
)


SAMPLE_JWT = "eyJabcdefghi.payload-foo.signature-bar"
LONG_BEARER = "abcdef0123456789abcdef0123456789"


class TestScrubGenericPatterns(unittest.TestCase):

  def test_authorization_header_redacted(self):
    out = scrub_graybox_secrets(f"Authorization: Bearer {SAMPLE_JWT}")
    self.assertNotIn(SAMPLE_JWT, out)
    self.assertIn("<redacted>", out)

  def test_cookie_header_redacted(self):
    out = scrub_graybox_secrets("Cookie: sessionid=abc123def456")
    self.assertNotIn("sessionid=abc123", out)
    self.assertIn("<redacted>", out)

  def test_set_cookie_header_redacted(self):
    out = scrub_graybox_secrets("Set-Cookie: token=eyJabcdef")
    self.assertNotIn("eyJabcdef", out)

  def test_bare_jwt_redacted(self):
    out = scrub_graybox_secrets(f"server returned: {SAMPLE_JWT}")
    self.assertNotIn(SAMPLE_JWT, out)
    self.assertIn("<jwt-redacted>", out)

  def test_bare_bearer_redacted(self):
    out = scrub_graybox_secrets(f"trace: Bearer {LONG_BEARER}")
    self.assertNotIn(LONG_BEARER, out)
    self.assertIn("Bearer <redacted>", out)

  def test_password_kv_redacted(self):
    out = scrub_graybox_secrets("user=admin&password=hunter2&keep=this")
    self.assertNotIn("hunter2", out)
    self.assertIn("password=<redacted>", out)

  def test_api_key_kv_redacted(self):
    out = scrub_graybox_secrets("?api_key=ABCDEFG12345&x=1")
    self.assertNotIn("ABCDEFG12345", out)

  def test_apikey_kv_redacted(self):
    """Variant spelling."""
    out = scrub_graybox_secrets("?apikey=XYZ123ABCDEF&extra=ok")
    self.assertNotIn("XYZ123ABCDEF", out)

  def test_json_bearer_token_redacted(self):
    out = scrub_graybox_secrets('{"bearer_token": "eyJsecret.payload.sig", "user": "alice"}')
    self.assertNotIn("eyJsecret", out)
    self.assertIn("alice", out)  # non-secret values preserved

  def test_embedded_header_in_evidence_redacted(self):
    out = scrub_graybox_secrets(
      "status=200, Authorization: Bearer SECRET-TOKEN-HERE-12345, foo=bar"
    )
    self.assertNotIn("SECRET-TOKEN-HERE-12345", out)
    self.assertIn("foo=bar", out)


class TestScrubConfiguredNames(unittest.TestCase):

  def test_custom_header_redacted(self):
    out = scrub_graybox_secrets(
      "X-Customer-Api-Key: abc123secret",
      secret_field_names=("X-Customer-Api-Key",),
    )
    self.assertNotIn("abc123secret", out)

  def test_custom_query_param_redacted(self):
    out = scrub_graybox_secrets(
      "https://api.example.com/v1/me?token_param=SECRET99&page=1",
      secret_field_names=("token_param",),
    )
    self.assertNotIn("SECRET99", out)
    self.assertIn("page=1", out)


class TestScrubRecursive(unittest.TestCase):

  def test_list_recursion(self):
    out = scrub_graybox_secrets(["normal evidence", "password=secret123"])
    self.assertNotIn("secret123", str(out))

  def test_dict_recursion(self):
    out = scrub_graybox_secrets({
      "ok": "value",
      "request_snapshot": {"headers": "Authorization: Bearer eyJabcdefghi.x.y"},
    })
    self.assertNotIn("eyJabcdefghi", str(out))
    self.assertEqual(out["ok"], "value")

  def test_non_string_passthrough(self):
    self.assertEqual(scrub_graybox_secrets(42), 42)
    self.assertIsNone(scrub_graybox_secrets(None))


class TestToFlatFindingScrubs(unittest.TestCase):

  def test_evidence_scrubbed_on_flatten(self):
    f = GrayboxFinding(
      scenario_id="PT-OAPI1-01",
      title="API object-level authorization bypass (BOLA)",
      status="vulnerable",
      severity="HIGH",
      owasp="API1:2023",
      evidence=[
        "endpoint=/api/users/2",
        "Authorization: Bearer eyJsecret.payload.sig",
        "password=hunter2_leak",
      ],
      replay_steps=["GET /api/users/2 with token=abc123def456"],
      remediation="Bearer SECRET-DEFAULT-TOKEN should be rotated",
    )
    flat = f.to_flat_finding(443, "https", "_graybox_api_access")
    haystack = str(flat)
    self.assertNotIn("eyJsecret", haystack)
    self.assertNotIn("hunter2_leak", haystack)
    self.assertNotIn("abc123def456", haystack)
    self.assertNotIn("SECRET-DEFAULT-TOKEN", haystack)
    # Non-secret content preserved
    self.assertIn("/api/users/2", haystack)
    self.assertIn("PT-OAPI1-01", haystack)

  def test_flatten_context_scrubs_configured_names(self):
    f = GrayboxFinding(
      scenario_id="PT-OAPI1-01",
      title="API object-level authorization bypass (BOLA)",
      status="vulnerable",
      severity="HIGH",
      owasp="API1:2023",
      evidence=[
        "X-Customer-Api-Key: SECRET-HEADER",
        "endpoint=https://api.example/v1/users?customer_key=SECRET99&page=1",
      ],
      evidence_artifacts=[{
        "request_snapshot": (
          "GET /v1/users?customer_key=SECRET99 "
          "X-Customer-Api-Key: SECRET-HEADER"
        ),
      }],
      replay_steps=["GET /v1/users?customer_key=SECRET99"],
    )

    with FindingRedactionContext(
      secret_field_names=("X-Customer-Api-Key", "customer_key"),
    ):
      flat = f.to_flat_finding(443, "https", "_graybox_api_access")
      stored = f.to_dict()

    haystack = f"{flat} {stored}"
    self.assertNotIn("SECRET99", haystack)
    self.assertNotIn("SECRET-HEADER", haystack)
    self.assertIn("customer_key=<redacted>", haystack)
    self.assertIn("X-Customer-Api-Key: <redacted>", haystack)


class TestProbeErrorScrubsConfiguredNames(unittest.TestCase):

  def _probe(self):
    target_config = GrayboxTargetConfig(api_security=ApiSecurityConfig(
      auth=AuthDescriptor(
        auth_type="api_key",
        api_key_location="query",
        api_key_query_param="customer_key",
        api_key_header_name="X-Customer-Api-Key",
      )
    ))
    return ProbeBase(
      "https://api.example.com",
      MagicMock(),
      target_config,
      SafetyControls(),
    )

  def test_run_safe_redacts_configured_query_key_from_request_exception(self):
    probe = self._probe()

    def boom():
      raise requests.RequestException(
        "GET https://api.example.com/v1/users?customer_key=SECRET99&page=1 failed"
      )

    probe.run_safe("api_error_path", boom)

    finding = probe.findings[0]
    haystack = str(finding.to_dict())
    self.assertNotIn("SECRET99", haystack)
    self.assertIn("customer_key=<redacted>", haystack)
    self.assertIn("page=1", haystack)

  def test_connection_error_redacts_configured_header_name(self):
    probe = self._probe()

    def boom():
      raise requests.exceptions.ConnectionError(
        "request failed with X-Customer-Api-Key: SECRET-HEADER-VALUE"
      )

    probe.run_safe("api_connection", boom)

    haystack = str(probe.findings[0].to_dict())
    self.assertNotIn("SECRET-HEADER-VALUE", haystack)
    self.assertIn("target_unreachable", haystack)
    self.assertIn("X-Customer-Api-Key: <redacted>", haystack)


if __name__ == "__main__":
  unittest.main()
