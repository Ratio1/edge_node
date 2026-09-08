"""
Per-vantage response fingerprint capture (RM-050).

Covers the excerpt safety rules, DNS resolution semantics, the comparison-tier
scoping that keeps the phase off non-comparison jobs, and the aggregation
contract that keeps each vantage's evidence attributable to that vantage.
"""

import gzip
import itertools
import os
import socket
import ssl
import threading
import tracemalloc
import unittest
import time
from unittest.mock import MagicMock, patch

import requests
from requests.structures import CaseInsensitiveDict
from urllib3.connection import HTTPConnection, HTTPSConnection

from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker
from extensions.business.cybersec.red_mesh.worker.response_fingerprint import (
  EXCERPT_MAX_BYTES,
  RESPONSE_BODY_MAX_BYTES,
  certificate_identity,
  excerpt_allowed,
  normalize_content_type,
  read_bounded_response_body,
  redirect_stays_on_target,
  _SocketRecordingAdapter,
  release_response_connection,
  request_within_deadline,
  resolve_host,
  sanitize_excerpt,
)
from extensions.business.cybersec.red_mesh.constants import (
  FINGERPRINT_HTTP_TIMEOUT,
  FINGERPRINT_TIMEOUT,
)
from .conftest import DummyOwner


def _open_fds():
  """Open file descriptors for this process, so a leaked socket is visible."""
  try:
    return len(os.listdir("/proc/self/fd"))
  except OSError:
    return None


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

  def test_ordinary_prose_and_markup_survive_redaction(self):
    # Titles and excerpts are the divergence signal. If hyphenated prose is
    # redacted, two vantages serving different content both record the same
    # token and read as identical — a manufactured "no divergence".
    intact = (
      "Best-Laptops-For-Developers-2024-Review",
      "user_profile_settings_page_header_title",
      '<div class="container-fluid-main-wrapper-outer">',
    )
    for text in intact:
      with self.subTest(text=text):
        self.assertEqual(sanitize_excerpt(text), text)

  def test_underscore_prefixed_credential_keys_are_redacted(self):
    # `\b` cannot match after an underscore, so these keys escaped the
    # key/value rule entirely and archived their values verbatim.
    for pair, secret in (
      ("db_password=Tr0ub4dor", "Tr0ub4dor"),
      ("admin_password: letmein", "letmein"),
      ("jwt_secret=hunter2", "hunter2"),
      ("oauth_client_secret=cs_1", "cs_1"),
    ):
      with self.subTest(pair=pair):
        self.assertNotIn(secret, sanitize_excerpt(pair))

  def test_session_cookie_names_are_redacted(self):
    for pair, secret in (
      ("jsessionid=ABCDEF1234ZZ", "ABCDEF1234ZZ"),
      ("PHPSESSID=9f8b7c6d5e4f3a2b1c0d", "9f8b7c6d5e4f3a2b1c0d"),
      ("SAMLResponse=PHNhbWxwOl", "PHNhbWxwOl"),
    ):
      with self.subTest(pair=pair):
        self.assertNotIn(secret, sanitize_excerpt(pair))

  def test_ambiguous_english_keys_are_left_alone(self):
    # `code`, `state`, `sig` and `ticket` are ordinary words. Redacting them on
    # the key alone would destroy comparison signal the way the base64 rule
    # once did, so the value has to earn the redaction.
    for text in (
      "state: California",
      "the code: refactored yesterday",
      "ticket: renewed",
      "?state=open&sort=date",
      "?code=US&lang=en",
      "sig: abc",
      "<code>print(x)</code>",
      '<code class="language-python">x</code>',
      'data-state="collapsed"',
      # Long enough to clear the unbroken-run test, so only the absent digit
      # keeps it out of the redaction.
      "code: internationalization",
      "signature: Jonathan Featherstonehaugh",
      # The digit must sit in the *value token*, not merely somewhere later on
      # the line. API error pages carry both a long CamelCase code and an
      # unrelated number, and a line-scoped digit test redacts the whole
      # sentence — including the captive-portal and rate-limit pages that are
      # among the strongest geo-divergence signals this evidence exists to show.
      "code: internationalization v2",
      "Error code: InvalidParameterValue (request id 1234)",
      "Status code: NetworkAuthenticationRequired 511",
      "code: ServiceUnavailable retry in 30s",
      "ticket: Reisegepaeckversicherung 2024",
    ):
      with self.subTest(text=text):
        self.assertEqual(sanitize_excerpt(text), text)

  def test_ambiguous_english_keys_are_redacted_when_the_value_is_token_shaped(self):
    # These four were left out of the key table entirely because the keys are
    # English. That also archived every real OAuth code, SAML signature and
    # service ticket in the clear. The discriminator is the value's shape — an
    # unbroken alphanumeric run no prose carries — not the key.
    for pair, secret in (
      ("?code=Ab3Xk9Qz2Lm7Pw4Rt8Nv1Cd", "Ab3Xk9Qz2Lm7Pw4Rt8Nv1Cd"),
      ("state=eyJhbGciOiJIUzI1NiJ9xyz", "eyJhbGciOiJIUzI1NiJ9xyz"),
      ("sig: 9f8b7c6d5e4f3a2b1c0d9e8f", "9f8b7c6d5e4f3a2b1c0d9e8f"),
      ("ticket=ST1a2b3c4d5e6f7g8h9i0j", "ST1a2b3c4d5e6f7g8h9i0j"),
      ('{"code": "4Ab3Xk9Qz2Lm7Pw4Rt8Nv"}', "4Ab3Xk9Qz2Lm7Pw4Rt8Nv"),
      # A hyphenated UUID is the most common OAuth CSRF `state` shape by far,
      # and its longest unbroken run is 12 — under the run test — while the hex
      # rule needs 32 characters with no separators. It needs its own shape.
      ("state=550e8400-e29b-41d4-a716-446655440000",
       "550e8400-e29b-41d4-a716-446655440000"),
      ("ticket: 3f2504e0-4f89-11d3-9a0c-0305e82c3301",
       "3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
      # Percent-encoding breaks the run at the front of the value. Anchoring
      # the lookaheads to the first alphanumeric segment let every one of these
      # through, including a live Azure Storage SAS credential.
      ("?sv=2021-06-08&sig=1sxKuFq%2FT6Wm5%2BYd3Nn9Ap0Qr2St4Uv6Wx8Yz0A%3D",
       "Yd3Nn9Ap0Qr2St4Uv6Wx8Yz0A"),
      ("sig=abcdefgh%2F1234567890123456", "1234567890123456"),
    ):
      with self.subTest(pair=pair):
        self.assertNotIn(secret, sanitize_excerpt(pair))

  def test_userinfo_without_a_password_keeps_the_host(self):
    # The e-mail rule would otherwise match `TOKEN@host` and take the host with
    # it, removing the field that makes two vantages comparable.
    excerpt = sanitize_excerpt("https://SECRETTOKENabc@target.example.com/x")
    self.assertNotIn("SECRETTOKENabc", excerpt)
    self.assertIn("target.example.com", excerpt)

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


class _Peer:
  """
  A real HTTP peer driven by a chunk script.

  Every other test here mocks the socket, and a mock's close() always returns
  instantly - which is precisely why a close that blocks against a live
  connection stayed invisible behind a green suite. Bounding behaviour has to
  be measured against a real socket.

  `script` is a factory returning a fresh iterable of (payload, delay_seconds)
  applied after the header. It must be a factory, not one iterator: probing a
  single port opens three connections (reachability, TLS, then the HTTP request
  under test), and a shared iterator is part-drained by the first two, so the
  request under test would be served mid-stream bytes instead of the script.
  """

  def __init__(self, script, declared, headers=b"Content-Type: text/html\r\n",
               header_script=None):
    self._script = script
    self._declared = declared
    self._headers = headers
    self._header_script = header_script
    self._stop = threading.Event()
    self._server = socket.socket()
    self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self._server.bind(("127.0.0.1", 0))
    self._server.listen(1)
    self.port = self._server.getsockname()[1]
    threading.Thread(target=self._serve, daemon=True).start()

  @classmethod
  def serving(cls, body):
    """A peer that returns one complete body and closes."""
    return cls(lambda: [(body, 0)], declared=len(body))

  @classmethod
  def dripping(cls, prefix=b"", interval=0.05):
    """A peer that optionally bursts, then drips forever without ever ending."""
    def script():
      return itertools.chain(
        [(prefix, 0)] if prefix else [],
        itertools.repeat((b"x", interval)),
      )
    return cls(script, declared=100_000_000)

  @classmethod
  def header_dripping(cls, interval=0.5):
    """
    A peer that answers, then never finishes its header block.

    `requests`' timeout is per socket operation, so a peer that emits one header
    line just inside that window keeps resetting it. The header read is the
    phase before any response object exists, which is why the body bounding
    cannot reach it.
    """
    def header_script():
      return itertools.chain(
        [(b"HTTP/1.1 200 OK\r\n", 0)],
        ((b"X-Pad-%d: y\r\n" % i, interval) for i in itertools.count()),
      )
    return cls(lambda: [], declared=0, header_script=header_script)

  def _serve(self):
    # Accept repeatedly: `_fingerprint_port` opens a reachability probe and a
    # TLS probe before the HTTP request, and a single-shot listener would be
    # gone by the time the request under test arrives — making a bounding
    # assertion pass because nothing was ever served.
    try:
      while not self._stop.is_set():
        conn, _addr = self._server.accept()
        threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
    except Exception:
      pass
    finally:
      try:
        self._server.close()
      except Exception:
        pass

  def _handle(self, conn):
    try:
      conn.recv(65536)
      if self._header_script is not None:
        for payload, delay in self._header_script():
          if self._stop.is_set():
            break
          conn.sendall(payload)
          if delay:
            time.sleep(delay)
        return
      conn.sendall(
        b"HTTP/1.1 200 OK\r\n%sContent-Length: %d\r\n\r\n"
        % (self._headers, self._declared)
      )
      for payload, delay in self._script():
        if self._stop.is_set():
          break
        conn.sendall(payload)
        if delay:
          time.sleep(delay)
    except Exception:
      pass
    finally:
      # Only this connection: the listener is shared with the probes that
      # follow, and closing it here is what made a single-shot peer look
      # unreachable to everything after the first connect.
      try:
        conn.close()
      except Exception:
        pass

  def close(self):
    self._stop.set()
    try:
      self._server.close()
    except Exception:
      pass


class _TlsPeer(_Peer):
  """A `_Peer` behind a real TLS handshake, using an in-memory self-signed cert."""

  _context = None

  @classmethod
  def _server_context(cls):
    if cls._context is not None:
      return cls._context
    import datetime
    import tempfile
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
      x509.CertificateBuilder()
      .subject_name(name)
      .issuer_name(name)
      .public_key(key.public_key())
      .serial_number(x509.random_serial_number())
      .not_valid_before(now - datetime.timedelta(days=1))
      .not_valid_after(now + datetime.timedelta(days=1))
      .sign(key, hashes.SHA256())
    )
    # Written, loaded, then removed: `load_cert_chain` needs a path, but leaving
    # a private key in /tmp on every suite run is litter the test has no reason
    # to produce.
    bundle = tempfile.NamedTemporaryFile(suffix=".pem", delete=False)
    try:
      bundle.write(cert.public_bytes(serialization.Encoding.PEM))
      bundle.write(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
      ))
      bundle.close()
      context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
      context.load_cert_chain(bundle.name)
    finally:
      try:
        os.unlink(bundle.name)
      except OSError:
        pass
    cls._context = context
    return context

  def _serve(self):
    context = self._server_context()
    try:
      while not self._stop.is_set():
        conn, _addr = self._server.accept()
        # Handshake off the accept loop. Inline, a peer that connects and sends
        # nothing wedges the listener for every probe behind it — the same
        # "harness silently stops serving" hazard that once made a bounding
        # assertion pass in 0.02s without serving anything.
        threading.Thread(target=self._wrap_and_handle, args=(conn, context),
                         daemon=True).start()
    except Exception:
      pass
    finally:
      try:
        self._server.close()
      except Exception:
        pass

  def _wrap_and_handle(self, conn, context):
    try:
      wrapped = context.wrap_socket(conn, server_side=True)
    except Exception:
      # A probe that opens a plain TCP connection and closes it, such as the
      # reachability check, never completes a handshake.
      try:
        conn.close()
      except Exception:
        pass
      return
    self._handle(wrapped)


class _RedirectingStallPeer:
  """
  Answers `/` with a same-origin 302, then drips headers forever on the target.

  Both hops are served on one persistent connection, which is the point: the
  second hop reuses the socket the first opened, so nothing new is registered
  with the deadline watchdog.
  """

  def __init__(self, interval=0.5):
    self._interval = interval
    self.requests_served = 0
    self._stop = threading.Event()
    self._server = socket.socket()
    self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self._server.bind(("127.0.0.1", 0))
    self._server.listen(5)
    self.port = self._server.getsockname()[1]
    threading.Thread(target=self._serve, daemon=True).start()

  def _serve(self):
    try:
      while not self._stop.is_set():
        conn, _addr = self._server.accept()
        threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
    except Exception:
      pass

  def _handle(self, conn):
    try:
      while not self._stop.is_set():
        request = conn.recv(65536)
        if not request:
          return
        self.requests_served += 1
        path = request.split(b" ")[1] if b" " in request else b"/"
        if path == b"/":
          # No Connection: close — HTTP/1.1 keeps this socket for the next hop.
          conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: /stall\r\nContent-Length: 0\r\n\r\n")
          continue
        conn.sendall(b"HTTP/1.1 200 OK\r\n")
        for index in itertools.count():
          if self._stop.is_set():
            return
          conn.sendall(b"X-Pad-%d: y\r\n" % index)
          time.sleep(self._interval)
    except Exception:
      pass
    finally:
      try:
        conn.close()
      except Exception:
        pass

  def close(self):
    self._stop.set()
    try:
      self._server.close()
    except Exception:
      pass


class TestRealSocketBounding(unittest.TestCase):
  """The bounding guarantees, measured against a real connection."""

  def _read_within(self, peer, max_seconds, limit):
    """Run the bounded read off-thread so a hang fails instead of wedging."""
    response = requests.get(f"http://127.0.0.1:{peer.port}/", stream=True, timeout=30)
    self.addCleanup(response.close)
    outcome = {}

    def _read():
      started = time.monotonic()
      outcome["result"] = read_bounded_response_body(
        response, max_bytes=RESPONSE_BODY_MAX_BYTES, max_seconds=max_seconds
      )
      outcome["elapsed"] = time.monotonic() - started

    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    reader.join(timeout=limit)
    self.assertFalse(
      reader.is_alive(),
      "read_bounded_response_body never returned; a peer that keeps the "
      "connection alive can stall the scan phase indefinitely",
    )
    return outcome

  def test_a_slow_drip_peer_cannot_outlast_the_deadline(self):
    peer = _Peer.dripping()
    self.addCleanup(peer.close)
    outcome = self._read_within(peer, max_seconds=1.0, limit=15)
    self.assertLess(outcome["elapsed"], 5.0)
    self.assertFalse(outcome["result"][1])

  def test_a_peer_that_drips_after_the_cap_cannot_stall_the_teardown(self):
    # Crossing the byte cap takes a different exit path from the deadline, and
    # that path tore the connection down with a call that blocks. The drip
    # keeps the socket alive so a blocking close never returns.
    peer = _Peer.dripping(prefix=b"a" * (RESPONSE_BODY_MAX_BYTES + 65536), interval=0.2)
    self.addCleanup(peer.close)
    outcome = self._read_within(peer, max_seconds=30.0, limit=20)
    body, complete = outcome["result"]
    self.assertFalse(complete)
    self.assertEqual(len(body), RESPONSE_BODY_MAX_BYTES)
    self.assertLess(outcome["elapsed"], 10.0)

  def test_a_header_dripping_peer_cannot_outlast_the_budget(self):
    # The body bounding starts only once a response object exists. A peer that
    # never finishes its header block is read entirely inside `session.get`,
    # where `requests`' per-operation timeout is reset by every line that
    # arrives. `execute_job` has no deadline of its own and `stop()` cannot
    # interrupt a thread blocked in `socket.readinto`, so the stall is the whole
    # job, not one probe.
    peer = _Peer.header_dripping(interval=0.5)
    self.addCleanup(peer.close)
    worker = _make_worker(target="127.0.0.1", comparison_ports=[peer.port])
    budget = worker._target_timeout(FINGERPRINT_HTTP_TIMEOUT)
    outcome = {}

    def _probe():
      started = time.monotonic()
      outcome["result"] = worker._fingerprint_http("http", peer.port)
      outcome["elapsed"] = time.monotonic() - started

    prober = threading.Thread(target=_probe, daemon=True)
    prober.start()
    prober.join(timeout=budget * 8)
    self.assertFalse(
      prober.is_alive(),
      "_fingerprint_http never returned; a header-dripping peer pins the worker",
    )
    self.assertLess(
      outcome["elapsed"], budget * 3,
      "the header read is not bounded by the phase budget",
    )
    # Lower bound: a peer that silently stopped serving also returns
    # (None, None) quickly, satisfying every assertion above while proving
    # nothing about the bound.
    self.assertGreater(
      outcome["elapsed"], budget * 0.5,
      "the probe returned too fast to have been bounded by the deadline",
    )
    self.assertEqual(outcome["result"], (None, None))

  def test_fingerprint_http_survives_a_peer_that_drips_after_the_cap(self):
    # The sibling test drives read_bounded_response_body directly, so it would
    # stay green if the hang relocated into _fingerprint_http's `finally` —
    # where `resp.close()` is called on a connection the peer is still feeding.
    peer = _Peer.dripping(prefix=b"a" * (RESPONSE_BODY_MAX_BYTES + 65536), interval=0.2)
    self.addCleanup(peer.close)
    worker = _make_worker(target="127.0.0.1", comparison_ports=[peer.port])
    budget = worker._target_timeout(FINGERPRINT_HTTP_TIMEOUT)
    outcome = {}

    def _probe():
      started = time.monotonic()
      outcome["result"] = worker._fingerprint_http("http", peer.port)
      outcome["elapsed"] = time.monotonic() - started

    prober = threading.Thread(target=_probe, daemon=True)
    prober.start()
    prober.join(timeout=budget * 8)
    self.assertFalse(prober.is_alive(), "_fingerprint_http never returned")
    http, _excerpt = outcome["result"]
    self.assertIsNotNone(http, "the capture was lost rather than bounded")
    self.assertFalse(http["body_complete"])
    self.assertIsNone(http["body_sha256"])
    self.assertLess(outcome["elapsed"], budget * 3)

  def test_the_deadline_holds_over_tls(self):
    # The HTTPS branch records `self.sock` after `super().connect()`, which is
    # the TLS socket rather than the raw one — shutting the raw socket down
    # would not unblock a reader inside the wrapped stream. That reasoning was
    # only a comment; the tier probes https whenever a certificate is captured,
    # so it needs a real handshake behind it.
    peer = _TlsPeer.header_dripping(interval=0.5)
    self.addCleanup(peer.close)
    worker = _make_worker(target="127.0.0.1", comparison_ports=[peer.port])
    budget = worker._target_timeout(FINGERPRINT_HTTP_TIMEOUT)
    before = threading.active_count()
    outcome = {}

    def _probe():
      started = time.monotonic()
      outcome["result"] = worker._fingerprint_http("https", peer.port)
      outcome["elapsed"] = time.monotonic() - started

    prober = threading.Thread(target=_probe, daemon=True)
    prober.start()
    prober.join(timeout=budget * 8)
    self.assertFalse(prober.is_alive(), "_fingerprint_http never returned over TLS")
    self.assertEqual(outcome["result"], (None, None))
    # Thread count, not just elapsed time. Returning on time is satisfied by the
    # caller's own bounded wait even when the watchdog is blind, so without this
    # the test passes with the HTTPS socket registration deleted while leaking
    # three threads per probe — which is the exact reach it was written to prove.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and threading.active_count() > before:
      time.sleep(0.25)
    self.assertLessEqual(
      threading.active_count(), before,
      f"threads {before} -> {threading.active_count()}; the watchdog cannot "
      "reach the post-handshake TLS socket",
    )
    # Lower bound too: a handshake that failed instantly also returns
    # (None, None) quickly, which would satisfy the upper bound while proving
    # nothing about the deadline over TLS.
    self.assertGreater(outcome["elapsed"], budget)
    self.assertLess(outcome["elapsed"], budget * 3)

  def test_teardown_falls_through_when_the_supported_shutdown_raises(self):
    # A supported call that raised has not torn the connection down. Returning
    # there would leave the peer holding it open - the hang this prevents.
    response = MagicMock()
    response.raw = MagicMock(spec=["shutdown", "_connection"])
    response.raw.shutdown.side_effect = RuntimeError("no")
    release_response_connection(response, log=lambda *a, **k: None)
    response.raw._connection.sock.shutdown.assert_called_once()

  def test_teardown_reports_when_it_cannot_reach_a_live_connection(self):
    # urllib3 2.3 adds a supported shutdown() and this deployment pins 2.0.7.
    # If a bump ever removed the private path without providing the public one,
    # teardown would degrade to a silent no-op and the hang would return with
    # every test still green. The failure has to be audible.
    reported = []
    response = MagicMock()
    response.raw = MagicMock(spec=["_connection"])
    response.raw._connection = MagicMock(spec=[])  # a connection, but no `sock`
    release_response_connection(response, log=lambda msg, **kw: reported.append(msg))
    self.assertTrue(reported, "a failed teardown reach was swallowed")

  def test_a_multi_address_target_cannot_multiply_the_budget(self):
    # `create_connection` applies its timeout per resolved address, so a target
    # publishing N blackholed A records in its own zone costs N x the budget.
    # The watchdog cannot help: the socket is registered only after connect()
    # returns, so during the connect leg there is nothing to shut down. The
    # guarantee has to be that the probe *returns* on time.
    blackholes = [
      (socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"192.0.2.{n}", 80))
      for n in range(1, 11)
    ]
    worker = _make_worker(target="blackhole.test", comparison_ports=[80])
    budget = worker._target_timeout(FINGERPRINT_HTTP_TIMEOUT)
    outcome = {}

    def _probe():
      started = time.monotonic()
      outcome["result"] = worker._fingerprint_http("http", 80)
      outcome["elapsed"] = time.monotonic() - started

    with patch("socket.getaddrinfo", return_value=blackholes):
      prober = threading.Thread(target=_probe, daemon=True)
      prober.start()
      prober.join(timeout=budget * 8)

    self.assertFalse(prober.is_alive(), "_fingerprint_http never returned")
    self.assertEqual(outcome["result"], (None, None))
    self.assertLess(
      outcome["elapsed"], budget * 3,
      f"{len(blackholes)} A-records held the probe for "
      f"{outcome.get('elapsed', 0):.1f}s against a {budget}s budget",
    )

  def test_a_slow_connect_does_not_leak_a_thread_and_socket_per_probe(self):
    # The socket is registered only after connect() returns. A target that puts
    # one non-responsive address ahead of its live one makes connect outlast the
    # deadline, so a watchdog that fired once and retired shut down nothing and
    # left the request unkillable — turning a bounded stall into a permanent
    # thread and fd leak on every probed port, which is worse than the hang.
    peer = _Peer.header_dripping(interval=0.5)
    self.addCleanup(peer.close)
    real_getaddrinfo = socket.getaddrinfo

    def _slow_then_live(host, port, *args, **kwargs):
      # One blackhole ahead of the live address: connect spends its per-address
      # timeout on the first before reaching the second.
      return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", port)),
      ] + real_getaddrinfo("127.0.0.1", port, *args, **kwargs)

    worker = _make_worker(target="127.0.0.1", comparison_ports=[peer.port])
    before = threading.active_count()
    fds_before = _open_fds()
    with patch("socket.getaddrinfo", side_effect=_slow_then_live):
      for _ in range(3):
        worker._fingerprint_http("http", peer.port)

    # Give the watchdogs their sweep interval to break the abandoned requests.
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and threading.active_count() > before:
      time.sleep(0.25)
    self.assertLessEqual(
      threading.active_count(), before,
      f"threads {before} -> {threading.active_count()} after 3 probes; the "
      "watchdog is not breaking abandoned requests",
    )
    # The defect this guards leaked a thread *and* a socket per probe. Asserting
    # only threads would miss a regression that leaked just the fd.
    if fds_before is not None:
      self.assertLessEqual(
        _open_fds(), fds_before + 1,
        f"file descriptors {fds_before} -> {_open_fds()} after 3 probes",
      )

  def test_a_redirect_onto_a_stalling_page_does_not_leak(self):
    # HTTP/1.1 is persistent by default, so a same-origin redirect is served on
    # the connection the first hop already opened: `connect()` does not run
    # again and nothing new is registered. A watchdog scoped to "sockets added
    # since this hop began" therefore sweeps an empty slice for exactly the
    # connection that needs breaking, and one 302 leaks two threads and an fd
    # per port, permanently. This is the shape the slow-connect test misses.
    peer = _RedirectingStallPeer()
    self.addCleanup(peer.close)
    worker = _make_worker(target="127.0.0.1", comparison_ports=[peer.port])
    budget = worker._target_timeout(FINGERPRINT_HTTP_TIMEOUT)
    before = threading.active_count()
    fds_before = _open_fds()
    started = time.monotonic()
    http, _excerpt = worker._fingerprint_http("http", peer.port)
    elapsed = time.monotonic() - started

    self.assertIsNone(http, "a stalled redirect hop must not yield evidence")
    self.assertLess(elapsed, budget * 3)
    # Without these two, a peer that silently stopped serving passes: the probe
    # returns fast with no evidence and nothing was ever redirected.
    self.assertGreater(elapsed, budget * 0.5, "the probe was never bounded")
    self.assertEqual(
      peer.requests_served, 2,
      f"the peer served {peer.requests_served} requests; hop 2 never happened, "
      "so the reused-connection path was not exercised",
    )
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and threading.active_count() > before:
      time.sleep(0.25)
    self.assertLessEqual(
      threading.active_count(), before,
      f"threads {before} -> {threading.active_count()}; the watchdog cannot "
      "reach a connection reused across a redirect",
    )
    if fds_before is not None:
      self.assertLessEqual(
        _open_fds(), fds_before + 1,
        f"file descriptors {fds_before} -> {_open_fds()}",
      )

  def test_a_close_delimited_body_is_never_claimed_complete(self):
    # With neither Content-Length nor chunked framing, end-of-message is just a
    # closed connection — indistinguishable from a severed one. Claiming
    # completeness there publishes body_sha256 over whatever arrived, attributed
    # to the target as its whole response.
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def _serve():
      try:
        conn, _addr = server.accept()
        conn.recv(65536)
        conn.sendall(
          b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
          b"<html><title>Unframed</title>partial"
        )
        conn.close()
      except Exception:
        pass

    threading.Thread(target=_serve, daemon=True).start()
    self.addCleanup(server.close)
    worker = _make_worker(target="127.0.0.1", comparison_ports=[port])
    http, _excerpt = worker._fingerprint_http("http", port)

    self.assertIsNotNone(http)
    self.assertEqual(http["title"], "Unframed")
    self.assertFalse(
      http["body_complete"],
      "a close-delimited body cannot be verified complete",
    )
    self.assertIsNone(
      http["body_sha256"],
      "a hash was published over a body whose completeness is unverifiable",
    )

  def test_a_bogus_framing_header_cannot_buy_a_completeness_claim(self):
    # Testing header *presence* rather than the framing the parser accepted let
    # a target claim completeness on a body it severed at will. http.client
    # discards an unparseable or negative Content-Length and then delimits by
    # close, and it requires the exact `chunked` token, not a substring.
    for label, headers in (
      ("bogus length", b"Content-Length: abc\r\n"),
      ("negative length", b"Content-Length: -1\r\n"),
      ("substring encoding", b"Transfer-Encoding: notchunked\r\n"),
      ("substring encoding 2", b"Transfer-Encoding: chunkedx\r\n"),
    ):
      with self.subTest(framing=label):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        self.addCleanup(server.close)

        def _serve(sock=server, extra=headers):
          try:
            conn, _addr = sock.accept()
            conn.recv(65536)
            conn.sendall(
              b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n" + extra +
              b"\r\n<html><title>Severed</title>partial"
            )
            conn.close()
          except Exception:
            pass

        threading.Thread(target=_serve, daemon=True).start()
        worker = _make_worker(target="127.0.0.1", comparison_ports=[port])
        http, _excerpt = worker._fingerprint_http("http", port)
        self.assertIsNotNone(http)
        self.assertFalse(
          http["body_complete"],
          f"{label} bought a completeness claim on a close-delimited body",
        )
        self.assertIsNone(http["body_sha256"])

  def test_a_framed_body_is_still_claimed_complete(self):
    # The guard above must not cost completeness on ordinary framed responses.
    peer = _Peer.serving(b"<html><title>Framed</title>hello</html>")
    self.addCleanup(peer.close)
    worker = _make_worker(target="127.0.0.1", comparison_ports=[peer.port])
    http, _excerpt = worker._fingerprint_http("http", peer.port)
    self.assertTrue(http["body_complete"])
    self.assertIsNotNone(http["body_sha256"])

  def test_a_malformed_location_cannot_blank_a_ports_evidence(self):
    # `urljoin` raises on an unparseable Location — an unbracketed `[` is
    # enough — and that ran before the scope guard, so the exception discarded a
    # 302 already in hand. Since the scanner is deliberately attributable, a
    # target can recognise the probe and answer every vantage this way: all
    # vantages record http=None and the comparison reads "no divergence" while
    # the target serves geo-differentiated content to real users.
    for location in (b"http://[", b"//[", b"http://[::1", b"http://]"):
      with self.subTest(location=location):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        self.addCleanup(server.close)

        def _serve(sock=server, target=location):
          try:
            conn, _addr = sock.accept()
            conn.recv(65536)
            conn.sendall(
              b"HTTP/1.1 302 Found\r\nLocation: " + target +
              b"\r\nServer: nginx-fra1\r\nContent-Length: 0\r\n\r\n"
            )
            conn.close()
          except Exception:
            pass

        threading.Thread(target=_serve, daemon=True).start()
        worker = _make_worker(target="127.0.0.1", comparison_ports=[port])
        http, _excerpt = worker._fingerprint_http("http", port)
        self.assertIsNotNone(http, "a malformed Location blanked the evidence")
        self.assertEqual(http["status"], 302)
        self.assertEqual(http["headers"].get("server"), "nginx-fra1")

  def test_a_hostile_charset_cannot_blank_a_ports_evidence(self):
    # The charset comes from the target's own Content-Type. `charset=idna`
    # raises UnicodeError rather than LookupError, and letting it escape drops
    # status, headers, body hash and excerpt for the port — letting a target
    # erase its own fingerprint per vantage while still serving different
    # content to real users, which reads as "no divergence".
    for charset in ("utf-8", "idna", "undefined"):
      with self.subTest(charset=charset):
        peer = _Peer(
          lambda: [(b"<html><title>Divergent</title>hello</html>", 0)],
          declared=len(b"<html><title>Divergent</title>hello</html>"),
          headers=b"Content-Type: text/html; charset=%s\r\n" % charset.encode(),
        )
        self.addCleanup(peer.close)
        worker = _make_worker(target="127.0.0.1", comparison_ports=[peer.port])
        http, _excerpt = worker._fingerprint_http("http", peer.port)
        self.assertIsNotNone(http, f"charset={charset} blanked the evidence")
        self.assertEqual(http["status"], 200)
        self.assertEqual(http["title"], "Divergent")

  def test_a_redirect_query_string_cannot_reach_the_log(self):
    # `redirect_stays_on_target` pins host and port but not path or query, so a
    # failing hop's urllib3 error text carries a target-supplied credential.
    logged = []
    worker = _make_worker(target="127.0.0.1", comparison_ports=[9])
    worker.P = lambda msg, **kw: logged.append(str(msg))
    hop = "http://127.0.0.1:9/callback?code=AbCdEf0123456789XyZ&api_key=sk-live-9f8e7d6c"
    with patch.object(
      worker, "_target_timeout", return_value=2
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint."
      "request_within_deadline",
      side_effect=requests.ConnectionError(f"Max retries exceeded with url: {hop}"),
    ):
      worker._fingerprint_http("http", 9)
    self.assertTrue(logged, "nothing was logged")
    joined = "\n".join(logged)
    self.assertNotIn("AbCdEf0123456789XyZ", joined)
    self.assertNotIn("sk-live-9f8e7d6c", joined)

  def test_the_probe_session_ignores_environment_proxies(self):
    # requests.Session defaults to trust_env=True, and HTTPAdapter routes a
    # proxied request through proxy_manager_for(), which does NOT carry the
    # recording pool classes. With HTTP_PROXY set in the container the socket
    # registry stays empty, the watchdog shuts nothing down, and the header
    # drip hang returns silently with the whole suite green. A proxied request
    # would also report the proxy's vantage, not this node's, which is the one
    # thing this module exists to measure.
    peer = _Peer.serving(b"<html><title>Direct</title>ok</html>")
    self.addCleanup(peer.close)
    worker = _make_worker(target="127.0.0.1", comparison_ports=[peer.port])
    with patch.dict(
      "os.environ",
      {"HTTP_PROXY": "http://127.0.0.1:1", "HTTPS_PROXY": "http://127.0.0.1:1"},
    ):
      http, _excerpt = worker._fingerprint_http("http", peer.port)
    self.assertIsNotNone(http, "the probe was routed through the environment proxy")
    self.assertEqual(http["title"], "Direct")

  def test_a_watchdog_does_not_outlive_a_request_that_never_started(self):
    # `finished` is set only in `_issue`'s `finally`. If that thread cannot
    # start — reachable under thread exhaustion — a `_watch` started beside it
    # sweeps at 4 Hz for the life of the process. Unlike an abandoned request,
    # which dies with its own connect attempts, this never clears, and it is
    # self-amplifying: every later probe donates another immortal watchdog.
    session = MagicMock()
    sockets = []
    real_thread = threading.Thread

    def _fail_the_request_thread(target=None, daemon=None, **kwargs):
      # Keyed on the thread's identity rather than on call order, so this still
      # guards the defect if the two starts are ever reordered again.
      if getattr(target, "__name__", "") == "_issue":
        raise RuntimeError("can't start new thread")
      return real_thread(target=target, daemon=daemon, **kwargs)

    before = threading.active_count()
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint."
      "threading.Thread",
      side_effect=_fail_the_request_thread,
    ):
      with self.assertRaises(RuntimeError):
        request_within_deadline(session, "http://127.0.0.1/", sockets, max_seconds=1)

    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and threading.active_count() > before:
      time.sleep(0.25)
    self.assertLessEqual(
      threading.active_count(), before,
      "a watchdog outlived a request whose thread never started",
    )

  def test_an_explicit_proxy_still_records_its_socket(self):
    # `trust_env = False` closes the environment route, which is what makes the
    # proxy_manager_for override unreachable from a normal run — and therefore
    # untested. requests builds a separate ProxyManager for a proxied request,
    # with stock pool classes, so without the override the registry stays empty
    # and the deadline watchdog has nothing to shut down.
    sockets = []
    adapter = _SocketRecordingAdapter(sockets)
    manager = adapter.proxy_manager_for("http://127.0.0.1:1")
    self.assertEqual(
      sorted(manager.pool_classes_by_scheme),
      ["http", "https"],
      "the proxy manager does not carry the recording pool classes",
    )
    for scheme in ("http", "https"):
      pool_cls = manager.pool_classes_by_scheme[scheme]
      self.assertIsNot(
        pool_cls.ConnectionCls,
        HTTPConnection if scheme == "http" else HTTPSConnection,
        f"the {scheme} proxy pool uses a stock connection class",
      )

  def test_teardown_prefers_the_supported_shutdown_api(self):
    response = MagicMock()
    response.raw = MagicMock(spec=["shutdown", "_connection"])
    release_response_connection(response)
    response.raw.shutdown.assert_called_once_with()

  def test_a_compressed_bomb_cannot_outgrow_the_byte_cap(self):
    # The cap counts decoded bytes and is checked only once a chunk has been
    # materialised, so the guarantee rests entirely on urllib3 2.x capping
    # decoded output at the requested read size. urllib3 1.x has no such buffer
    # and would let one 64 KiB compressed read expand to tens of MiB. That is
    # what `urllib3>=2.0` in the requirements files pins, and this is the test
    # that fails if the floor is ever dropped.
    # 128 MiB is 128x the cap — enough to prove the bound without spending
    # seconds of suite time compressing zeros.
    decoded = 128 * 1024 * 1024
    payload = gzip.compress(b"\0" * decoded, 9)
    self.assertGreater(decoded / len(payload), 100, "not a compression bomb")
    peer = _Peer(
      lambda: [(payload, 0)],
      declared=len(payload),
      headers=b"Content-Type: text/html\r\nContent-Encoding: gzip\r\n",
    )
    self.addCleanup(peer.close)
    response = requests.get(f"http://127.0.0.1:{peer.port}/", stream=True, timeout=30)
    self.addCleanup(response.close)

    tracemalloc.start()
    try:
      body, complete = read_bounded_response_body(
        response, max_bytes=RESPONSE_BODY_MAX_BYTES, max_seconds=30
      )
      _current, peak = tracemalloc.get_traced_memory()
    finally:
      tracemalloc.stop()

    self.assertFalse(complete)
    self.assertEqual(len(body), RESPONSE_BODY_MAX_BYTES)
    self.assertLess(
      peak, RESPONSE_BODY_MAX_BYTES * 8,
      f"decoding peaked at {peak / 1048576:.1f} MiB against a "
      f"{RESPONSE_BODY_MAX_BYTES / 1048576:.0f} MiB cap",
    )

  def test_the_comparison_tier_stays_bounded_against_hostile_ports(self):
    # The tier is an operator-chosen port range walked sequentially, so a
    # per-probe bound is only useful if it composes: one hostile port must cost
    # its budget and no more, or a wide range stalls the whole job.
    peers = [_Peer.header_dripping(interval=0.5) for _ in range(2)]
    for peer in peers:
      self.addCleanup(peer.close)
    worker = _make_worker(
      target="127.0.0.1", comparison_ports=[peer.port for peer in peers]
    )
    budget = worker._target_timeout(FINGERPRINT_HTTP_TIMEOUT)
    outcome = {}

    def _tier():
      started = time.monotonic()
      worker._capture_response_fingerprint()
      outcome["elapsed"] = time.monotonic() - started

    runner = threading.Thread(target=_tier, daemon=True)
    runner.start()
    runner.join(timeout=len(peers) * budget * 8)
    self.assertFalse(runner.is_alive(), "the comparison tier never completed")
    evidence = worker.state["response_evidence"]
    self.assertEqual(len(evidence["ports"]), len(peers))
    for port, entry in evidence["ports"].items():
      # Guard against the assertion below passing for the wrong reason: an
      # unreachable port also yields http=None, having proven nothing.
      self.assertTrue(entry["reachable"], f"port {port} was never probed")
      # A reply assembled only because our watchdog cut the connection is our
      # timeout, not the target's answer, and must not be recorded as one.
      self.assertIsNone(entry["http"], f"port {port} recorded a fabricated reply")
    # Each hostile port must actually cost its budget — an instant return means
    # the probe never engaged and the bound was never exercised.
    self.assertGreater(outcome["elapsed"], budget)
    self.assertLess(
      outcome["elapsed"], len(peers) * budget * 3,
      "per-probe bounding does not compose across the tier",
    )


class TestRealSocketCapture(unittest.TestCase):
  """End-to-end capture over a real connection, exercising the streaming path."""

  def _capture(self, body):
    peer = _Peer.serving(body)
    self.addCleanup(peer.close)
    worker = _make_worker(target="127.0.0.1", comparison_ports=[peer.port])
    captured = worker._fingerprint_http("http", peer.port)
    self.assertIsNotNone(captured[0], "capture failed against the local peer")
    return captured

  def test_complete_response_is_captured_and_hashed(self):
    http, excerpt = self._capture(b"<html><title>Acme Home</title>hello world</html>")
    self.assertEqual(http["status"], 200)
    self.assertTrue(http["body_complete"])
    self.assertIsNotNone(http["body_sha256"])
    self.assertEqual(http["title"], "Acme Home")
    self.assertIn("hello world", excerpt)

  def test_oversized_response_is_truncated_without_a_hash(self):
    http, _excerpt = self._capture(b"a" * (RESPONSE_BODY_MAX_BYTES + 5000))
    self.assertFalse(http["body_complete"])
    self.assertIsNone(http["body_sha256"])


class TestRedirectScopeGuard(unittest.TestCase):
  """The guard must agree with the parser that actually dials the request."""

  def test_guard_never_allows_a_hop_requests_would_dial_elsewhere(self):
    # Parser differential: urlparse reads `http://10.0.0.1\@authorized/` as
    # host=authorized (userinfo=10.0.0.1\), while urllib3 — which requests
    # dials with — reads host=10.0.0.1. Trusting the wrong parser is a bypass.
    import requests as _requests
    from urllib3.util import parse_url

    hostile = (
      r"http://169.254.169.254\@127.0.0.1/latest/meta-data/",
      r"https://169.254.169.254\@127.0.0.1:443/x",
      r"http://127.0.0.1\@169.254.169.254/",
      "http://127.0.0.1@169.254.169.254/",
      r"http://169.254.169.254\t@127.0.0.1/",
    )
    for location in hostile:
      with self.subTest(location=location):
        allowed = redirect_stays_on_target(location, "127.0.0.1", 443)
        dialed = parse_url(_requests.Request("GET", location).prepare().url).host
        if allowed:
          # If the guard permits the hop, the host that will actually be
          # contacted must be the authorized target — no exceptions.
          self.assertEqual(dialed, "127.0.0.1")

  def test_guard_still_allows_the_legitimate_endpoint(self):
    self.assertTrue(redirect_stays_on_target("https://127.0.0.1:443/next", "127.0.0.1", 443))
    self.assertTrue(redirect_stays_on_target("https://127.0.0.1/next", "127.0.0.1", 443))


class TestHttpCapture(unittest.TestCase):

  @staticmethod
  def _response(body=b"<html><title>Acme</title>hello</html>", **headers):
    response = MagicMock()
    response.status_code = 200
    response.url = "https://example.test/"
    response.history = []
    response.encoding = "utf-8"
    # Real responses expose headers case-insensitively; a plain dict would let
    # a test pass while production lookups (e.g. "location") miss.
    response.headers = CaseInsensitiveDict({"Content-Type": "text/html", **headers})
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
    # The hop must stay on the authorized host, or it is refused before it is
    # ever followed (see test_redirect_off_the_authorized_target_is_never_fetched).
    redirect.url = "https://127.0.0.1:443/start"
    redirect.iter_content.side_effect = AssertionError("redirect body must not be read")
    final = self._response()
    final.url = "https://127.0.0.1:443/final"
    session = MagicMock()
    session.get.side_effect = [redirect, final]
    worker = _make_worker(target="127.0.0.1", comparison_ports=[443])
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
      return_value=session,
    ):
      http, _excerpt = worker._fingerprint_http("https", 443)

    redirect.iter_content.assert_not_called()
    redirect.close.assert_called_once()
    self.assertEqual(http["redirect_count"], 1)
    self.assertEqual(http["final_url"], "https://127.0.0.1:443/final")

  def test_body_completeness_is_explicit_in_the_contract(self):
    # body_length falls back to the peer's Content-Length when the body was
    # truncated, and title is body-derived. Consumers comparing two vantages
    # need to know which fields were measured and which were merely declared.
    truncated = self._response(
      body=b"a" * (RESPONSE_BODY_MAX_BYTES + 1),
      **{"Content-Length": str(RESPONSE_BODY_MAX_BYTES + 100)},
    )
    # Framed explicitly: completeness is only claimable for a body delimited by
    # a declared length or chunked encoding. Without either, end-of-message is
    # a closed connection and cannot be told apart from a severed one, so the
    # bare mock this used to pass was not a "whole response" in the first place.
    whole_body = b"<html><title>Acme</title>hello</html>"
    whole = self._response(
      body=whole_body, **{"Content-Length": str(len(whole_body))}
    )
    worker = _make_worker(target="127.0.0.1", comparison_ports=[443])
    results = []
    for response in (truncated, whole):
      session = MagicMock()
      session.get.return_value = response
      with patch(
        "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
        return_value=session,
      ):
        http, _excerpt = worker._fingerprint_http("https", 443)
      results.append(http)

    self.assertFalse(results[0]["body_complete"])
    self.assertTrue(results[1]["body_complete"])

  def test_metadata_never_persists_credentials(self):
    # final_url and title are archived alongside the excerpt, so they must pass
    # the same scrubber; otherwise userinfo and token query values survive.
    response = self._response(body=b"<html><title>access_token=sk-live-abc123</title>x</html>")
    response.url = "https://operator:hunter2@127.0.0.1:443/cb?api_key=sk-live-abc123"
    session = MagicMock()
    session.get.return_value = response
    worker = _make_worker(target="127.0.0.1", comparison_ports=[443])
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
      return_value=session,
    ):
      http, _excerpt = worker._fingerprint_http("https", 443)

    self.assertNotIn("hunter2", http["final_url"])
    self.assertNotIn("sk-live-abc123", http["final_url"])
    self.assertNotIn("sk-live-abc123", http["title"])

  def test_captured_headers_are_scrubbed(self):
    # A hop refused as off-target is kept as evidence, and its raw Location
    # commonly carries a token in the query string.
    redirect = self._response(
      **{"Location": "https://elsewhere.test/cb?access_token=sk-live-zzz999"}
    )
    redirect.status_code = 302
    redirect.url = "https://127.0.0.1:443/"
    session = MagicMock()
    session.get.side_effect = [redirect]
    worker = _make_worker(target="127.0.0.1", comparison_ports=[443])
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
      return_value=session,
    ):
      http, _excerpt = worker._fingerprint_http("https", 443)

    self.assertNotIn("sk-live-zzz999", http["headers"]["location"])

  def test_redirect_off_the_authorized_target_is_never_fetched(self):
    # A scanned target answering 302 -> cloud metadata must not make the edge
    # node fetch that endpoint. The scan is authorized for one host and port.
    redirect = self._response(**{"Location": "http://169.254.169.254/latest/meta-data/"})
    redirect.status_code = 302
    redirect.url = "https://127.0.0.1:443/"
    session = MagicMock()
    session.get.side_effect = [redirect]
    worker = _make_worker(target="127.0.0.1", comparison_ports=[443])
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
      return_value=session,
    ):
      http, _excerpt = worker._fingerprint_http("https", 443)

    requested = [call.args[0] for call in session.get.call_args_list]
    self.assertEqual(requested, ["https://127.0.0.1:443/"])
    # The refused hop is not counted as followed; the last in-scope response
    # remains the recorded evidence.
    self.assertEqual(http["status"], 302)
    self.assertEqual(http["redirect_count"], 0)

  def test_redirect_scope_covers_port_and_scheme_not_just_host(self):
    # The authorized endpoint is a host *and* a port; a hop to another port on
    # the same host, or to a non-http scheme, is a different endpoint.
    off_scope = (
      "http://127.0.0.1:8080/admin",   # same host, unauthorized port
      "gopher://127.0.0.1:443/x",      # scheme outside http(s)
      "http://127.0.0.1:99999/x",      # unparseable port must not raise
      "http://127.0.0.1@evil.test/",   # userinfo trick: real host is evil.test
      "//evil.test/x",                 # protocol-relative escape
    )
    for location in off_scope:
      with self.subTest(location=location):
        redirect = self._response(**{"Location": location})
        redirect.status_code = 302
        redirect.url = "https://127.0.0.1:443/"
        session = MagicMock()
        session.get.side_effect = [redirect]
        worker = _make_worker(target="127.0.0.1", comparison_ports=[443])
        with patch(
          "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
          return_value=session,
        ):
          http, _excerpt = worker._fingerprint_http("https", 443)
        self.assertEqual(
          [call.args[0] for call in session.get.call_args_list],
          ["https://127.0.0.1:443/"],
        )
        self.assertEqual(http["redirect_count"], 0)

  def test_same_host_and_port_redirect_is_followed(self):
    # The guard must not break the legitimate case it wraps.
    redirect = self._response(**{"Location": "https://127.0.0.1:443/next"})
    redirect.status_code = 302
    redirect.url = "https://127.0.0.1:443/"
    final = self._response()
    final.url = "https://127.0.0.1:443/next"
    session = MagicMock()
    session.get.side_effect = [redirect, final]
    worker = _make_worker(target="127.0.0.1", comparison_ports=[443])
    with patch(
      "extensions.business.cybersec.red_mesh.worker.response_fingerprint.requests.Session",
      return_value=session,
    ):
      http, _excerpt = worker._fingerprint_http("https", 443)

    self.assertEqual(http["redirect_count"], 1)
    self.assertEqual(http["final_url"], "https://127.0.0.1:443/next")

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
