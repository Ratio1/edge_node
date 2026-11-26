"""Tests for SafetyControls."""

import time
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.graybox.safety import SafetyControls
from extensions.business.cybersec.red_mesh.constants import (
  GRAYBOX_DEFAULT_DELAY,
  GRAYBOX_MAX_WEAK_ATTEMPTS,
)


class TestSafetyControls(unittest.TestCase):

  def test_clamp_attempts_respects_cap(self):
    """clamp_attempts enforces hard cap."""
    self.assertEqual(SafetyControls.clamp_attempts(5), 5)
    self.assertEqual(SafetyControls.clamp_attempts(100), GRAYBOX_MAX_WEAK_ATTEMPTS)
    self.assertEqual(SafetyControls.clamp_attempts(0), 0)
    self.assertEqual(SafetyControls.clamp_attempts(-1), 0)

  def test_validate_target_no_auth(self):
    """Unauthorized scan returns error."""
    err = SafetyControls.validate_target("http://example.com", authorized=False)
    self.assertIsNotNone(err)
    self.assertIn("not authorized", err.lower())

  def test_validate_target_blocked(self):
    """Public domains are blocked."""
    err = SafetyControls.validate_target("https://google.com", authorized=True)
    self.assertIsNotNone(err)
    self.assertIn("public service", err.lower())

  def test_validate_target_blocked_subdomain(self):
    """Subdomains of blocked domains are also blocked."""
    err = SafetyControls.validate_target("https://mail.google.com", authorized=True)
    self.assertIsNotNone(err)

  def test_validate_target_ok(self):
    """Valid URL + authorized returns None."""
    err = SafetyControls.validate_target("https://myapp.internal.com", authorized=True)
    self.assertIsNone(err)

  def test_validate_target_invalid_url(self):
    """Invalid URL returns error."""
    err = SafetyControls.validate_target("not-a-url", authorized=True)
    self.assertIsNotNone(err)

  def test_validate_target_bad_scheme(self):
    """Non-HTTP scheme returns error."""
    err = SafetyControls.validate_target("ftp://example.com", authorized=True)
    self.assertIsNotNone(err)
    self.assertIn("scheme", err.lower())

  def test_sanitize_error_password(self):
    """Password values are scrubbed."""
    msg = SafetyControls.sanitize_error('Error: password="secret123" is wrong')
    self.assertNotIn("secret123", msg)
    self.assertIn("<redacted>", msg)

  def test_sanitize_error_token(self):
    """Token values are scrubbed."""
    msg = SafetyControls.sanitize_error("token=abc123def in header")
    self.assertNotIn("abc123def", msg)
    self.assertIn("<redacted>", msg)

  def test_sanitize_error_secret(self):
    """Secret values are scrubbed."""
    msg = SafetyControls.sanitize_error("secret=mysecretvalue leaked")
    self.assertNotIn("mysecretvalue", msg)
    self.assertIn("<redacted>", msg)

  def test_sanitize_error_preserves_normal_text(self):
    """Normal text without credentials is preserved."""
    msg = SafetyControls.sanitize_error("Connection refused on port 443")
    self.assertEqual(msg, "Connection refused on port 443")

  def test_throttle_delay(self):
    """Requests are spaced by min_delay."""
    sc = SafetyControls(request_delay=0.05, target_is_local=True)
    sc.throttle()
    t1 = time.time()
    sc.throttle()
    t2 = time.time()
    self.assertGreaterEqual(t2 - t1, 0.04)  # small tolerance

  def test_throttle_preserves_fixed_delay_when_only_min_delay_is_set(self):
    """Single-delay callers retain fixed delay behavior."""
    sc = SafetyControls(request_delay=0.05, target_is_local=True)

    with patch("extensions.business.cybersec.red_mesh.graybox.safety.random.uniform") as uniform:
      self.assertEqual(sc._next_request_delay(), 0.05)

    uniform.assert_not_called()

  def test_throttle_randomizes_with_configured_delay_range(self):
    """Dune min/max delay is randomized when a range is configured."""
    sc = SafetyControls(
      request_delay=0.05,
      request_delay_max=0.10,
      target_is_local=True,
    )
    sc._last_request_at = 100.0

    with patch(
      "extensions.business.cybersec.red_mesh.graybox.safety.random.uniform",
      return_value=0.07,
    ) as uniform:
      with patch(
        "extensions.business.cybersec.red_mesh.graybox.safety.time.time",
        side_effect=[100.01, 100.08],
      ):
        with patch("extensions.business.cybersec.red_mesh.graybox.safety.time.sleep") as sleep:
          sc.throttle()

    uniform.assert_called_once_with(0.05, 0.10)
    self.assertAlmostEqual(sleep.call_args[0][0], 0.06)
    self.assertEqual(sc._last_request_at, 100.08)

  def test_min_delay_enforced_non_local(self):
    """Non-local target gets GRAYBOX_DEFAULT_DELAY minimum."""
    sc = SafetyControls(request_delay=0.01, target_is_local=False)
    self.assertEqual(sc._request_delay, GRAYBOX_DEFAULT_DELAY)

  def test_min_delay_local_bypass(self):
    """Local target allows lower delay."""
    sc = SafetyControls(request_delay=0.01, target_is_local=True)
    self.assertEqual(sc._request_delay, 0.01)

  def test_is_local_target(self):
    """Recognizes localhost variants."""
    self.assertTrue(SafetyControls.is_local_target("http://localhost:8000"))
    self.assertTrue(SafetyControls.is_local_target("http://127.0.0.1:3000"))
    self.assertTrue(SafetyControls.is_local_target("http://[::1]:8080"))
    self.assertTrue(SafetyControls.is_local_target("http://host.docker.internal"))
    self.assertFalse(SafetyControls.is_local_target("http://example.com"))


def _resolving(*addresses):
  return lambda host, port: [(2, 1, 6, "", (a, 0)) for a in addresses]


class TestPrivateTargetAuthority(unittest.TestCase):
  """RM-273 (D30): private-range targets need the engagement's allow_private_targets."""

  def test_public_address_is_allowed(self):
    self.assertIsNone(SafetyControls.private_target_reason("app.example", _resolving("93.184.216.34")))
    self.assertIsNone(SafetyControls.private_target_reason("8.8.8.8"))

  def test_each_private_range_is_refused(self):
    for address in ("10.225.0.10", "172.16.0.1", "192.168.1.1", "127.0.0.1", "169.254.169.254",
                    "100.64.0.1", "fd00::1", "fe80::1", "::1", "::ffff:10.0.0.1", "0.0.0.0",
                    "64:ff9b::a00:1", "::127.0.0.1", "::ffff:0:a00:1", "fec0::1"):
      reason = SafetyControls.private_target_reason(address)
      self.assertIn("allow_private_targets", reason or "", address)
      self.assertIn("allow_private_targets", SafetyControls.private_target_reason(
        "app.example", _resolving(address)) or "", address)

  def test_unresolvable_name_is_left_to_the_connection(self):
    def fail(host, port):
      raise OSError("no such host")
    self.assertIsNone(SafetyControls.private_target_reason("nope.example", fail))
    self.assertIn("allow_private_targets",
                  SafetyControls.private_target_reason("nope.example", fail, fail_closed=True))

  def test_public_ipv4_behind_nat64_is_allowed(self):
    self.assertIsNone(SafetyControls.private_target_reason("64:ff9b::808:808"))

  def test_client_refuses_a_name_that_does_not_resolve(self):
    from extensions.business.cybersec.red_mesh.graybox.http_client import GrayboxHttpClient, GrayboxScopeError
    def fail(host, port):
      raise OSError("no such host")
    with patch("socket.getaddrinfo", fail), self.assertRaises(GrayboxScopeError):
      GrayboxHttpClient("http://app.example").validate_url("/x")

  def test_client_refuses_private_unless_engagement_allows(self):
    from extensions.business.cybersec.red_mesh.graybox.http_client import GrayboxHttpClient, GrayboxScopeError
    with patch("socket.getaddrinfo", _resolving("10.225.0.10")):
      with self.assertRaises(GrayboxScopeError):
        GrayboxHttpClient("http://app.example", allow_private_targets=False).validate_url("/x")
      self.assertEqual(
        GrayboxHttpClient("http://app.example", allow_private_targets=True).validate_url("/x"),
        "http://app.example/x")

  def test_private_answer_is_re_checked_on_every_request(self):
    # Re-checked per request, not pinned at connect: that gap is closed by RM-273 Phase G.
    from extensions.business.cybersec.red_mesh.graybox.http_client import GrayboxHttpClient, GrayboxScopeError
    client = GrayboxHttpClient("http://app.example", allow_private_targets=False)
    answers = iter(["93.184.216.34", "10.0.0.5"])
    with patch("socket.getaddrinfo", lambda host, port: _resolving(next(answers))(host, port)):
      self.assertEqual(client.validate_url("/a"), "http://app.example/a")
      with self.assertRaises(GrayboxScopeError):
        client.validate_url("/b")


if __name__ == '__main__':
  unittest.main()
