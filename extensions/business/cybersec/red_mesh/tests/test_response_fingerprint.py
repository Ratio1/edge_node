"""
Per-vantage response fingerprint capture (RM-050).

Covers the excerpt safety rules, DNS resolution semantics, the comparison-tier
scoping that keeps the phase off non-comparison jobs, and the aggregation
contract that keeps each vantage's evidence attributable to that vantage.
"""

import unittest
import time
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker
from extensions.business.cybersec.red_mesh.worker.response_fingerprint import (
  EXCERPT_MAX_BYTES,
  RESPONSE_BODY_MAX_BYTES,
  certificate_identity,
  excerpt_allowed,
  normalize_content_type,
  read_bounded_response_body,
  resolve_host,
  sanitize_excerpt,
)
from extensions.business.cybersec.red_mesh.constants import (
  FINGERPRINT_HTTP_TIMEOUT,
  FINGERPRINT_TIMEOUT,
)
from .conftest import DummyOwner


def _make_worker(**overrides):
  defaults = dict(
    owner=DummyOwner(),
    target="127.0.0.1",
    job_id="test-job",
    initiator="test-addr",
    local_id_prefix="1",
    worker_target_ports=[80, 443],
  )
  defaults.update(overrides)
  return PentestLocalWorker(**defaults)


class TestExcerptSanitization(unittest.TestCase):

  def test_returns_none_for_empty_body(self):
    self.assertIsNone(sanitize_excerpt(""))
    self.assertIsNone(sanitize_excerpt(None))

  def test_caps_at_byte_limit(self):
    excerpt = sanitize_excerpt("a" * 5000)
    self.assertLessEqual(len(excerpt.encode("utf-8")), EXCERPT_MAX_BYTES)

  def test_truncates_on_utf8_character_boundary(self):
    # Three-byte characters do not divide evenly into the byte cap, so a
    # naive slice would emit a partial character.
    excerpt = sanitize_excerpt("中" * 400)
    self.assertLessEqual(len(excerpt.encode("utf-8")), EXCERPT_MAX_BYTES)
    self.assertNotIn("�", excerpt)
    excerpt.encode("utf-8").decode("utf-8")

  def test_redacts_credential_key_values(self):
    excerpt = sanitize_excerpt('{"api_key": "sk-abc123def456", "ok": 1}')
    self.assertNotIn("sk-abc123def456", excerpt)
    self.assertIn("REDACTED", excerpt)

  def test_redacts_multiword_credential_values(self):
    excerpt = sanitize_excerpt('{"password": "correct horse battery staple", "ok": 1}')
    self.assertNotIn("correct horse battery staple", excerpt)

  def test_redacts_basic_authorization_values(self):
    excerpt = sanitize_excerpt("Authorization: Basic dXNlcjpwYXNz")
    self.assertNotIn("dXNlcjpwYXNz", excerpt)

  def test_redacts_common_compound_credential_keys(self):
    for key in ("client_secret", "refresh_token", "session_token", "clientSecret"):
      with self.subTest(key=key):
        excerpt = sanitize_excerpt(f'{key}="short-sensitive"')
        self.assertNotIn("short-sensitive", excerpt)

  def test_redacts_bearer_tokens(self):
    excerpt = sanitize_excerpt("Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload")
    self.assertNotIn("eyJhbGciOiJIUzI1NiJ9", excerpt)

  def test_redacts_email_addresses(self):
    excerpt = sanitize_excerpt("contact operator@example.com for access")
    self.assertNotIn("operator@example.com", excerpt)
    self.assertIn("[REDACTED_EMAIL]", excerpt)

  def test_redacts_long_hex_runs(self):
    digest = "a" * 64
    excerpt = sanitize_excerpt(f"csrf={digest}")
    self.assertNotIn(digest, excerpt)

  def test_redacts_long_base64_runs(self):
    blob = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVoxMjM0NTY3ODkw"
    excerpt = sanitize_excerpt(f"state {blob} end")
    self.assertNotIn(blob, excerpt)

  def test_redacts_long_urlsafe_base64_runs(self):
    blob = "0123456789_abcdefghijklmnopqrstuvwxyz-ABCDE"
    excerpt = sanitize_excerpt(f"state {blob} end")
    self.assertNotIn(blob, excerpt)

  def test_redaction_precedes_truncation(self):
    # A credential straddling the byte cap must not survive as a prefix.
    padding = "x" * (EXCERPT_MAX_BYTES - 20)
    excerpt = sanitize_excerpt(f"{padding} password=supersecretvalue123")
    self.assertNotIn("supersecretvalue", excerpt)


class TestContentTypeGate(unittest.TestCase):

  def test_allows_textual_types(self):
    self.assertTrue(excerpt_allowed("text/html; charset=utf-8"))
    self.assertTrue(excerpt_allowed("text/plain"))
    self.assertTrue(excerpt_allowed("application/json"))

  def test_rejects_binary_and_missing_types(self):
    self.assertFalse(excerpt_allowed("application/octet-stream"))
    self.assertFalse(excerpt_allowed("image/png"))
    self.assertFalse(excerpt_allowed(""))
    self.assertFalse(excerpt_allowed(None))

  def test_normalizes_content_type(self):
    self.assertEqual(normalize_content_type("TEXT/HTML; charset=utf-8"), "text/html")
    self.assertIsNone(normalize_content_type(None))


class TestHostResolution(unittest.TestCase):

  def test_literal_ipv4_target_yields_no_dns_answer(self):
    addresses, error = resolve_host("93.184.216.34")
    self.assertEqual(addresses, [])
    self.assertIsNone(error)

  def test_literal_ipv6_target_yields_no_dns_answer(self):
    addresses, error = resolve_host("2001:4860:4860::8888")
    self.assertEqual(addresses, [])
    self.assertIsNone(error)

  def test_resolution_failure_is_recorded_not_raised(self):
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.socket.getaddrinfo",
      side_effect=OSError("Name or service not known"),
    ):
      addresses, error = resolve_host("nonexistent.invalid")
    self.assertEqual(addresses, [])
    self.assertIn("Name or service not known", error)

  def test_addresses_are_sorted_and_deduplicated(self):
    infos = [
      (2, 1, 6, "", ("93.184.216.34", 0)),
      (2, 1, 6, "", ("93.184.216.34", 0)),
      (2, 1, 6, "", ("1.2.3.4", 0)),
    ]
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.socket.getaddrinfo",
      return_value=infos,
    ):
      addresses, error = resolve_host("example.test")
    self.assertEqual(addresses, ["1.2.3.4", "93.184.216.34"])
    self.assertIsNone(error)

  def test_resolution_timeout_is_recorded(self):
    blocker = MagicMock(side_effect=lambda *_args: time.sleep(0.2))
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.socket.getaddrinfo",
      blocker,
    ):
      addresses, error = resolve_host("slow.example", timeout=0.01)
    self.assertEqual(addresses, [])
    self.assertEqual(error, "DNS resolution timed out")


class TestCertificateIdentity(unittest.TestCase):

  def test_absent_certificate_yields_no_identity(self):
    self.assertIsNone(certificate_identity(None))
    self.assertIsNone(certificate_identity(b""))

  def test_unparseable_certificate_still_fingerprints(self):
    # An unparseable certificate must not silently match another one.
    identity = certificate_identity(b"not-a-certificate")
    self.assertIn("cert_sha256", identity)
    self.assertEqual(len(identity["cert_sha256"]), 64)


class TestComparisonTierScoping(unittest.TestCase):

  def test_phase_skipped_without_comparison_tier(self):
    worker = _make_worker()
    self.assertEqual(worker.comparison_ports, [])
    worker._fingerprint_port = MagicMock()
    worker._capture_response_fingerprint()
    worker._fingerprint_port.assert_not_called()
    self.assertNotIn("response_evidence", worker.state)

  def test_phase_probes_only_the_comparison_tier(self):
    worker = _make_worker(worker_target_ports=[8080, 9090], comparison_ports=[443, 80, 443])
    worker._check_stopped = MagicMock(return_value=False)
    worker._fingerprint_port = MagicMock(return_value={"reachable": False})
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.resolve_host",
      return_value=([], None),
    ):
      worker._capture_response_fingerprint()

    probed = sorted(call.args[0] for call in worker._fingerprint_port.call_args_list)
    self.assertEqual(probed, [80, 443])
    self.assertEqual(sorted(worker.state["response_evidence"]["ports"]), ["443", "80"])

  def test_evidence_absent_from_status_without_capture(self):
    worker = _make_worker()
    self.assertNotIn("response_evidence", worker.get_status())

  def test_evidence_present_in_status_after_capture(self):
    worker = _make_worker(comparison_ports=[443])
    worker.state["response_evidence"] = {"target_host": "example.test", "ports": {}}
    self.assertIn("response_evidence", worker.get_status())


class TestHttpCapture(unittest.TestCase):

  @staticmethod
  def _response(body=b"<html><title>Acme</title>hello</html>", **headers):
    response = MagicMock()
    response.status_code = 200
    response.url = "https://example.test/"
    response.history = []
    response.encoding = "utf-8"
    response.headers = {"Content-Type": "text/html", **headers}
    response.iter_content.return_value = [body]
    return response

  def test_http_capture_streams_and_uses_existing_timeout_constant(self):
    worker = _make_worker(comparison_ports=[443])
    worker._target_timeout = MagicMock(return_value=12)
    response = self._response(**{"Content-Length": "37", "server": "nginx"})
    session = MagicMock()
    session.get.return_value = response
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
      return_value=session,
    ):
      http, excerpt = worker._fingerprint_http("https", 443)

    worker._target_timeout.assert_called_once_with(FINGERPRINT_HTTP_TIMEOUT)
    self.assertTrue(session.get.call_args.kwargs["stream"])
    self.assertFalse(session.get.call_args.kwargs["allow_redirects"])
    self.assertLessEqual(session.get.call_args.kwargs["timeout"], 12)
    self.assertEqual(http["status"], 200)
    self.assertEqual(http["title"], "Acme")
    self.assertIsNotNone(http["body_sha256"])
    self.assertIn("hello", excerpt)
    response.close.assert_called_once()

  def test_oversized_body_is_capped_without_claiming_a_partial_hash(self):
    response = self._response(
      body=b"a" * (RESPONSE_BODY_MAX_BYTES + 1),
      **{"Content-Length": str(RESPONSE_BODY_MAX_BYTES + 100)},
    )
    worker = _make_worker(comparison_ports=[443])
    session = MagicMock()
    session.get.return_value = response
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
      return_value=session,
    ):
      http, excerpt = worker._fingerprint_http("https", 443)

    self.assertEqual(http["body_length"], RESPONSE_BODY_MAX_BYTES + 100)
    self.assertIsNone(http["body_sha256"])
    self.assertLessEqual(len(excerpt.encode("utf-8")), EXCERPT_MAX_BYTES)

  def test_unknown_response_encoding_falls_back_safely(self):
    response = self._response(body=b"plain text")
    response.encoding = "not-a-real-codec"
    worker = _make_worker(comparison_ports=[443])
    session = MagicMock()
    session.get.return_value = response
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
      return_value=session,
    ):
      http, excerpt = worker._fingerprint_http("https", 443)

    self.assertEqual(http["status"], 200)
    self.assertEqual(excerpt, "plain text")

  def test_redirect_bodies_are_never_buffered(self):
    redirect = self._response(**{"Location": "/final"})
    redirect.status_code = 302
    redirect.url = "https://example.test/start"
    redirect.iter_content.side_effect = AssertionError("redirect body must not be read")
    final = self._response()
    final.url = "https://example.test/final"
    session = MagicMock()
    session.get.side_effect = [redirect, final]
    worker = _make_worker(comparison_ports=[443])
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
      return_value=session,
    ):
      http, _excerpt = worker._fingerprint_http("https", 443)

    redirect.iter_content.assert_not_called()
    redirect.close.assert_called_once()
    self.assertEqual(http["redirect_count"], 1)
    self.assertEqual(http["final_url"], "https://example.test/final")

  def test_port_probe_uses_existing_fingerprint_timeout_constant(self):
    worker = _make_worker(comparison_ports=[443])
    worker._target_timeout = MagicMock(return_value=6)
    worker._tls_unverified_connect = MagicMock(return_value=(None, None, None))
    worker._fingerprint_http = MagicMock(return_value=(None, None))
    connection = MagicMock()
    connection.__enter__.return_value = connection
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.socket.create_connection",
      return_value=connection,
    ) as create_connection:
      worker._fingerprint_port(443)

    worker._target_timeout.assert_called_once_with(FINGERPRINT_TIMEOUT)
    self.assertEqual(create_connection.call_args.kwargs["timeout"], 6)

  def test_bounded_reader_stops_at_the_byte_cap(self):
    response = MagicMock()
    response.iter_content.return_value = [b"abc", b"def"]
    body, complete = read_bounded_response_body(response, max_bytes=4, max_seconds=10)
    self.assertEqual(body, b"abcd")
    self.assertFalse(complete)

  def test_bounded_reader_hashes_an_exact_cap_complete_body(self):
    response = MagicMock()
    response.iter_content.return_value = [b"a" * RESPONSE_BODY_MAX_BYTES]
    body, complete = read_bounded_response_body(
      response,
      max_bytes=RESPONSE_BODY_MAX_BYTES,
      max_seconds=10,
    )
    self.assertEqual(len(body), RESPONSE_BODY_MAX_BYTES)
    self.assertTrue(complete)

  def test_bounded_reader_enforces_wall_deadline(self):
    response = MagicMock()

    def delayed_chunks(**_kwargs):
      time.sleep(0.2)
      yield b"late"

    response.iter_content.side_effect = delayed_chunks
    started = time.monotonic()
    body, complete = read_bounded_response_body(response, max_bytes=10, max_seconds=0.01)
    elapsed = time.monotonic() - started
    self.assertEqual(body, b"")
    self.assertFalse(complete)
    self.assertLess(elapsed, 0.1)


class TestAggregationAttribution(unittest.TestCase):
  """
  Response evidence describes one vantage. Registering it as a cross-worker
  aggregated field would deep-merge every vantage's ports into one colliding
  structure — the defect RM-049 had to repair for findings.
  """

  def test_response_evidence_is_not_a_cross_worker_aggregated_field(self):
    fields = PentestLocalWorker.get_worker_specific_result_fields()
    self.assertNotIn("response_evidence", fields)


if __name__ == "__main__":
  unittest.main()
