"""
Per-vantage response fingerprint capture (RM-050).

Covers the excerpt safety rules, DNS resolution semantics, the comparison-tier
scoping that keeps the phase off non-comparison jobs, and the aggregation
contract that keeps each vantage's evidence attributable to that vantage.
"""

import gzip
import itertools
import socket
import threading
import tracemalloc
import unittest
import time
from unittest.mock import MagicMock, patch

import requests
from requests.structures import CaseInsensitiveDict

from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker
from extensions.business.cybersec.red_mesh.worker.response_fingerprint import (
  EXCERPT_MAX_BYTES,
  RESPONSE_BODY_MAX_BYTES,
  certificate_identity,
  excerpt_allowed,
  normalize_content_type,
  read_bounded_response_body,
  redirect_stays_on_target,
  release_response_connection,
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
    whole = self._response()
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
