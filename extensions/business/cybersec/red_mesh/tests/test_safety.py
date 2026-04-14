"""Tests for SafetyControls."""

import time
import unittest

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
    self.assertIn("***", msg)

  def test_sanitize_error_token(self):
    """Token values are scrubbed."""
    msg = SafetyControls.sanitize_error("token=abc123def in header")
    self.assertNotIn("abc123def", msg)
    self.assertIn("***", msg)

  def test_sanitize_error_secret(self):
    """Secret values are scrubbed."""
    msg = SafetyControls.sanitize_error("secret=mysecretvalue leaked")
    self.assertNotIn("mysecretvalue", msg)
    self.assertIn("***", msg)

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


if __name__ == '__main__':
  unittest.main()
