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
  GatewayAuthDescriptor,
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

  def test_every_pair_of_a_multi_cookie_header_is_redacted(self):
    """A session cookie is redacted wherever it sits in the header.

    The pattern used to stop at the first `;` — a Cookie header's internal pair
    delimiter, not a field separator — so only the first pair was redacted and a
    session id in any later position reached the archive verbatim. Analytics and
    preference cookies are routinely sent first, so "any later position" is the
    common case rather than the corner one.
    """
    out = scrub_graybox_secrets(
      "Cookie: theme=dark; sessionid=s3cr3tSESSIONVALUE; csrftoken=AbCdEf123456"
    )
    self.assertNotIn("s3cr3tSESSIONVALUE", out)
    self.assertNotIn("AbCdEf123456", out)
    self.assertNotIn("dark", out)

  def test_cookie_names_survive_redaction(self):
    """Names are not secrets, and they are what makes the evidence readable."""
    out = scrub_graybox_secrets("Cookie: theme=dark; sessionid=s3cr3tSESSIONVALUE")
    self.assertIn("theme=<redacted>", out)
    self.assertIn("sessionid=<redacted>", out)

  def test_set_cookie_attribute_flags_survive_redaction(self):
    """The flags are the finding, not the secret.

    `probes/misconfig.py` reports `missing_Secure` / `missing_HttpOnly` /
    `weak_SameSite`, so redacting a whole `Set-Cookie` line to kill the value
    would redact the evidence for the cookie-hardening scenarios along with it.
    """
    out = scrub_graybox_secrets(
      "Set-Cookie: sessionid=s3cr3tSESSIONVALUE; Path=/; HttpOnly; Secure; SameSite=Lax"
    )
    self.assertNotIn("s3cr3tSESSIONVALUE", out)
    self.assertIn("sessionid=<redacted>", out)
    for attribute in ("Path=/", "HttpOnly", "Secure", "SameSite=Lax"):
      self.assertIn(attribute, out)

  def test_cookie_redaction_is_idempotent(self):
    """The scrubber runs at assembly, at emission and at the storage boundary.

    `_ALREADY_REDACTED` exists because a pattern that consumed its own
    placeholder on the second pass corrupted a curl reproduction; a cookie rule
    that is not a fixed point would do the same.
    """
    for header in (
      "Cookie: theme=dark; sessionid=s3cr3tSESSIONVALUE",
      "Set-Cookie: sessionid=s3cr3tSESSIONVALUE; Path=/; HttpOnly",
    ):
      once = scrub_graybox_secrets(header)
      self.assertEqual(once, scrub_graybox_secrets(once), header)

  def test_a_cookie_carrying_no_value_is_left_alone(self):
    out = scrub_graybox_secrets("Cookie: ")
    self.assertNotIn("<redacted>", out)

  def test_an_assembled_curl_line_survives_a_second_pass(self):
    """The rule runs to end of line, and a curl line is not a bare header.

    `_curl_reproduction` scrubs each header before `shlex.quote`ing it, so the
    assembled line already carries `<redacted>` values. It is then scrubbed
    again at emission and a third time at the storage boundary. A guard that
    only recognises a value that is *exactly* the placeholder does not fire on
    the last pair, whose value has the rest of the command glued to it — and the
    other headers, the URL and the closing quote are eaten. That is precisely
    the failure `_ALREADY_REDACTED` exists to prevent, one level down.
    """
    line = (
      "curl -i -H 'Cookie: theme=<redacted>; sessionid=<redacted>' "
      "-H 'Accept: */*' 'https://app.test/a?x=1'"
    )
    self.assertEqual(scrub_graybox_secrets(line), line)

  def test_an_opaque_cookie_with_no_name_is_still_redacted(self):
    """A segment with no `=` is a value, not a free pass."""
    for header, secret in (
      ("Cookie: OPAQUESESSIONTOKEN", "OPAQUESESSIONTOKEN"),
      ("Set-Cookie: OPAQUEVALUE", "OPAQUEVALUE"),
      ("Cookie: a=1; OPAQUETRAILER", "OPAQUETRAILER"),
    ):
      with self.subTest(header=header):
        self.assertNotIn(secret, scrub_graybox_secrets(header))

  def test_a_custom_cookie_bearing_header_is_still_matched(self):
    """`X-Auth-Cookie` matched before the rule was rewritten; keep it matching."""
    out = scrub_graybox_secrets("X-Auth-Cookie: abc123secret")
    self.assertNotIn("abc123secret", out)

  def test_attribute_names_are_not_privileged_in_a_request_cookie_header(self):
    """`path` and `secure` are attributes only in a `Set-Cookie` response.

    In a request header they are ordinary cookie names, and the allowlist that
    protects the response flags would otherwise hand their values a free pass.
    """
    out = scrub_graybox_secrets(
      "Cookie: secure=SECRETVALUE; path=SECRET2; domain=SECRET3; version=SECRET4"
    )
    for secret in ("SECRETVALUE", "SECRET2", "SECRET3", "SECRET4"):
      self.assertNotIn(secret, out)

  def test_a_set_cookie_value_named_like_an_attribute_is_still_redacted(self):
    """Only pairs *after* the first are attributes; the first is the cookie."""
    out = scrub_graybox_secrets("Set-Cookie: path=SECRETVALUE; Path=/; HttpOnly")
    self.assertNotIn("SECRETVALUE", out)
    self.assertIn("Path=/", out)
    self.assertIn("HttpOnly", out)

  def test_a_target_named_cookie_cannot_suppress_the_hardening_evidence(self):
    """`misconfig.py:222-227` builds evidence from the target's cookie *names*.

    It emits `f"{cookie.name}:missing_Secure"`, and `_flat_evidence_summary`
    joins the list with `"; "`. A cookie named `session-cookie` — or literally
    `cookie` — then matches the header rule, and a rule that reads to end of line
    eats the whole joined string. A target could suppress its own PT-A02-04
    finding by naming a cookie.

    Every real producer of a cookie *header* in this repo emits `f"{name}: {value}"`
    with a space; this evidence deliberately has none. That is the discriminator.
    """
    for name in ("session-cookie", "cookie", "Cookie"):
      with self.subTest(cookie_name=name):
        evidence = (
          f"{name}:missing_Secure; {name}:missing_HttpOnly; endpoint=/admin"
        )
        self.assertEqual(
          scrub_graybox_secrets(evidence), evidence,
          "the cookie-hardening evidence was redacted by the cookie rule",
        )

  def test_a_real_cookie_header_is_still_redacted_after_that_narrowing(self):
    for header, secret in (
      ("Cookie: theme=dark; sessionid=SECRETV", "SECRETV"),
      ("Set-Cookie: sid=SECRETV; Path=/; HttpOnly", "SECRETV"),
      ("X-Auth-Cookie: SECRETV", "SECRETV"),
      ("Cookie:  sessionid=SECRETV", "SECRETV"),
    ):
      with self.subTest(header=header):
        self.assertNotIn(secret, scrub_graybox_secrets(header))

  def test_an_empty_cookie_value_does_not_eat_the_curl_line(self):
    """`name=` with no value must not glue itself to the rest of the command.

    A kept segment ending in a bare `=` is stable on its own but not once
    `_curl_reproduction` embeds it in a larger line: the next pass reads past
    the closing quote, the trailing `csrftoken=` swallows the URL, and the
    quoting no longer balances. `http.cookiejar` emits `name=` for any
    empty-valued cookie — a cleared `csrftoken`, a consent cookie — and
    `PreparedRequest.prepare_cookies` sets `Cookie` last, so it is usually the
    final `-H`. Same root cause as the earlier truncation: reading past the
    header's actual end.
    """
    import shlex
    header = scrub_graybox_secrets("Cookie: sessionid=SECRETSESSION123; csrftoken=")
    line = f"curl -i -H '{header}' 'https://target.example/admin/report?id=7'"
    self.assertEqual(scrub_graybox_secrets(line), line)
    shlex.split(line)  # raises if the quoting was broken
    for trailing in ("Cookie: sid=<redacted>;", "Cookie: sid=<redacted>;  "):
      with self.subTest(trailing=trailing):
        embedded = f"curl -H '{trailing}' 'https://target.example/x'"
        self.assertEqual(scrub_graybox_secrets(embedded), embedded)

  def test_a_cookie_header_with_no_space_after_the_colon_is_still_redacted(self):
    """RFC 7230 permits zero whitespace after the colon.

    The space requirement that keeps `misconfig`'s `{cookie.name}:missing_Secure`
    evidence intact must not become a way to smuggle a session cookie past the
    scrubber. `sessionid`, `PHPSESSID` and `connect.sid` appear in no generic
    `name=value` pattern, so nothing else would catch it.
    """
    self.assertNotIn("SECRET123", scrub_graybox_secrets("Cookie:sessionid=SECRET123"))
    self.assertNotIn("SECRET123", scrub_graybox_secrets("Set-Cookie:sid=SECRET123; Path=/"))

  def test_a_value_beginning_with_the_placeholder_is_not_trusted(self):
    """The target chooses its own cookie values, including this one.

    A prefix test on the pair value let `sid=<redacted>SECRET123` through. The
    guard has to recognise a value that *is* the placeholder, not one that
    merely starts with it.
    """
    for header in (
      "Cookie: sid=<redacted>SECRET123",
      "Cookie: a=1; sid=<redacted>SECRET123",
      "Set-Cookie: sid=<redacted>SECRET123; Path=/",
    ):
      with self.subTest(header=header):
        self.assertNotIn("SECRET123", scrub_graybox_secrets(header))

  def test_a_comma_folded_set_cookie_does_not_hide_the_second_cookie(self):
    """`urllib3` folds duplicate `Set-Cookie` headers with ", ".

    `_string_items(response.headers)` then yields one string carrying two
    cookies. An attribute segment whose value runs across the fold
    (`Path=/, sessionid=SECRET`) was kept whole by the allowlist, so the second
    cookie survived.
    """
    for header in (
      "Set-Cookie: theme=dark; Path=/, sessionid=SECRETSESSION123; Path=/; HttpOnly",
      "Set-Cookie: pref=1; Expires=Wed, 21 Oct 2025 07:28:00 GMT, sid=SECRETSESSION123",
    ):
      with self.subTest(header=header):
        self.assertNotIn("SECRETSESSION123", scrub_graybox_secrets(header))

  def test_an_attribute_value_is_kept_but_still_meets_the_generic_patterns(self):
    """The bound on keeping `Set-Cookie` attributes, stated explicitly.

    Scoping metadata (`Path=/admin`) is preserved so the cookie-hardening
    evidence stays readable. That is a deliberate exemption from *this* rule
    only: the returned string still passes through the JWT, Bearer, named-secret
    and operator-configured patterns, so an attribute carrying anything that
    looks like a credential is still caught.
    """
    kept = scrub_graybox_secrets("Set-Cookie: sid=x; Path=/admin; SameSite=Lax")
    self.assertIn("Path=/admin", kept)
    self.assertIn("SameSite=Lax", kept)

    jwt = scrub_graybox_secrets(f"Set-Cookie: sid=x; Path={SAMPLE_JWT}")
    self.assertNotIn(SAMPLE_JWT, jwt)

    configured = scrub_graybox_secrets(
      "Set-Cookie: sid=x; Path=SECRETV", secret_field_names=("Path",),
    )
    self.assertNotIn("SECRETV", configured)

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

  def test_gateway_secret_names_are_redacted_from_probe_errors(self):
    target_config = GrayboxTargetConfig(api_security=ApiSecurityConfig(
      auth=AuthDescriptor(auth_type="form"),
      gateway_auth=GatewayAuthDescriptor(
        auth_type="api_key",
        api_key_location="query",
        api_key_query_param="gateway_key",
        api_key_header_name="X-Gateway-Key",
      ),
    ))
    probe = ProbeBase(
      "https://api.example.com",
      MagicMock(),
      target_config,
      SafetyControls(),
    )

    def boom():
      raise requests.RequestException(
        "GET https://api.example.com/v1?gateway_key=SECRET99 "
        "failed with X-Gateway-Key: SECRET-HEADER"
      )

    probe.run_safe("gateway_error_path", boom)

    haystack = str(probe.findings[0].to_dict())
    self.assertNotIn("SECRET99", haystack)
    self.assertNotIn("SECRET-HEADER", haystack)
    self.assertIn("gateway_key=<redacted>", haystack)
    self.assertIn("X-Gateway-Key: <redacted>", haystack)


class TestConfiguredNamesFromReport(unittest.TestCase):

  def test_report_secret_name_extraction_includes_gateway_auth(self):
    from extensions.business.cybersec.red_mesh.mixins.report import (
      _configured_graybox_secret_names_from_report,
    )

    names = _configured_graybox_secret_names_from_report({
      "job_config": {
        "target_config": {
          "api_security": {
            "auth": {
              "api_key_header_name": "X-App-Key",
              "api_key_query_param": "app_key",
            },
            "gateway_auth": {
              "api_key_header_name": "X-Gateway-Key",
              "api_key_query_param": "gateway_key",
              "bearer_token_header_name": "X-Gateway-Authorization",
            },
          },
        },
      },
    })

    self.assertIn("X-App-Key", names)
    self.assertIn("app_key", names)
    self.assertIn("X-Gateway-Key", names)
    self.assertIn("gateway_key", names)
    self.assertIn("X-Gateway-Authorization", names)


if __name__ == "__main__":
  unittest.main()
