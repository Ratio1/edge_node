"""Regression tests for the Heartbleed Finding's structured ``cve`` field.

When ``_tls_check_heartbleed`` (or its raw fallback) detects a leak, the
resulting Finding must populate ``cve=("CVE-2014-0160",)`` so downstream
consumers (LLM input builder, MISP export, inventory accounting) can match
on the CVE id. Prior to this fix the id was only embedded in the title
string and was invisible to those code paths.
"""
from __future__ import annotations

import struct
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.cve_db import _stamp_identity
from extensions.business.cybersec.red_mesh.worker.service.tls import _ServiceTlsMixin


def _build_leak_response(extra_bytes: int = 0x4000) -> bytes:
  """Synthesize a heartbeat-response TLS record that leaks extra_bytes.

  The probe inspects ``response[0] == 24`` (ContentType: Heartbeat) and
  ``struct.unpack(">H", response[3:5])`` (outer record length). Returning
  any record length > the request hb_msg length triggers the leak branch.
  """
  outer_len = extra_bytes + 8
  return (
    b"\x18"                                    # ContentType: Heartbeat
    + b"\x03\x03"                              # TLSv1.2
    + struct.pack(">H", outer_len)             # outer record length
    + b"\x02"                                  # HeartbeatMessageType: response
    + struct.pack(">H", extra_bytes)           # payload_length (leaked size)
    + b"\xff" * extra_bytes                    # leaked memory bytes
    + b"\x00" * 16                             # padding
  )


class TestHeartbleedFindingHasCveField(unittest.TestCase):
  """Both code paths must return a Finding with cve=('CVE-2014-0160',)."""

  def _make_probe(self):
    # Bypass __init__ — the heartbleed methods are self-contained.
    return _ServiceTlsMixin.__new__(_ServiceTlsMixin)

  def test_tls_check_heartbleed_populates_cve_field(self):
    probe = self._make_probe()

    fake_raw_after = MagicMock()
    fake_raw_after.recv.return_value = _build_leak_response()

    fake_tls_sock = MagicMock()
    fake_tls_sock.version.return_value = "TLSv1.2"
    fake_tls_sock.unwrap.return_value = fake_raw_after

    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.return_value = fake_tls_sock

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.ssl.SSLContext",
      return_value=fake_ctx,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.socket.socket",
      return_value=MagicMock(),
    ):
      result = probe._tls_check_heartbleed("10.0.0.1", 8443)

    self.assertIsNotNone(result, "leak response must produce a Finding")
    self.assertEqual(
      result.cve, ("CVE-2014-0160",),
      "Heartbleed Finding must populate the structured cve field",
    )
    self.assertIn("CVE-2014-0160", result.title)
    self.assertEqual(result.cwe_id, "CWE-126")

  def test_tls_check_heartbleed_records_the_leak_size_in_raw(self):
    """The quantified leak moved out of `evidence` (volatile in the dedup key)
    into raw_data. Review found the first version deleted it entirely — the
    helper had no raw dict, so 'moved to raw_data' was untrue at this site."""
    probe = self._make_probe()

    fake_raw_after = MagicMock()
    fake_raw_after.recv.return_value = _build_leak_response()

    fake_tls_sock = MagicMock()
    fake_tls_sock.version.return_value = "TLSv1.2"
    fake_tls_sock.unwrap.return_value = fake_raw_after

    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.return_value = fake_tls_sock

    raw = {}
    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.ssl.SSLContext",
      return_value=fake_ctx,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.socket.socket",
      return_value=MagicMock(),
    ):
      result = probe._tls_check_heartbleed("10.0.0.1", 8443, raw=raw)

    self.assertIsNotNone(result)
    self.assertGreater(raw.get("heartbleed_leaked_bytes", 0), 0)

  def test_tls_heartbleed_raw_populates_cve_field(self):
    probe = self._make_probe()

    fake_sock = MagicMock()
    fake_sock.recv.return_value = _build_leak_response()

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.socket.socket",
      return_value=fake_sock,
    ):
      result = probe._tls_heartbleed_raw("10.0.0.1", 8443, b"\x03\x03")

    self.assertIsNotNone(result, "leak response must produce a Finding")
    self.assertEqual(
      result.cve, ("CVE-2014-0160",),
      "raw-fallback Heartbleed Finding must populate the structured cve field",
    )

  def test_both_paths_take_kev_and_build_from_the_vulndb_source(self):
    """RM-169: KEV is never False when unknown. Under `static` nothing evaluated it."""
    probe = self._make_probe()
    fields = {"kev": True, "vulndb_build_id": "vulndb-aaaaaaaaaaaa"}
    fake_sock = MagicMock()
    fake_sock.recv.return_value = _build_leak_response()
    fake_raw_after = MagicMock()
    fake_raw_after.recv.return_value = _build_leak_response()
    fake_tls_sock = MagicMock()
    fake_tls_sock.unwrap.return_value = fake_raw_after
    fake_ctx = MagicMock()
    fake_ctx.wrap_socket.return_value = fake_tls_sock
    tls = "extensions.business.cybersec.red_mesh.worker.service.tls"
    with patch(tls + ".socket.socket", return_value=fake_sock):
      self.assertIsNone(probe._tls_heartbleed_raw("10.0.0.1", 8443, b"\x03\x03").kev)
    with patch(tls + ".socket.socket", return_value=fake_sock), \
         patch(tls + ".probe_cve_fields", return_value=fields) as lookup:
      raw_path = probe._tls_heartbleed_raw("10.0.0.1", 8443, b"\x03\x03")
    lookup.assert_called_once_with("CVE-2014-0160")
    with patch(tls + ".ssl.SSLContext", return_value=fake_ctx), patch(tls + ".socket.socket", return_value=MagicMock()), \
         patch(tls + ".probe_cve_fields", return_value=fields):
      main_path = probe._tls_check_heartbleed("10.0.0.1", 8443)
    for finding in (raw_path, main_path):
      self.assertEqual((finding.kev, finding.vulndb_build_id), (True, "vulndb-aaaaaaaaaaaa"))


class TestHeartbleedTriggersOpenSslCveInference(unittest.TestCase):
  """When Heartbleed fires positive, the OpenSSL package version is
  deterministically ≤1.0.1f. The TLS pass should walk the catalog at
  1.0.1f and emit every matching row in addition to the Heartbleed
  Finding itself, deduplicating CVE-2014-0160.
  """

  def test_inference_emits_openssl_cves_without_duplicate_heartbleed(self):
    from extensions.business.cybersec.red_mesh.cve_db import check_cves

    inferred = check_cves("openssl", "1.0.1f")
    inferred_cves = {c for f in inferred for c in (f.cve or ())}

    # Sanity: the catalog row for Heartbleed itself fires when querying
    # by OpenSSL version (so the dedup branch is reachable, not a no-op).
    self.assertIn(
      "CVE-2014-0160", inferred_cves,
      "check_cves('openssl', '1.0.1f') must include CVE-2014-0160 — "
      "otherwise the inference path's dedup branch is never exercised",
    )

    # The inference must contribute at least these well-known
    # OpenSSL ≤1.0.1f CVEs (a non-empty contribution beyond Heartbleed).
    additional = inferred_cves - {"CVE-2014-0160"}
    self.assertTrue(
      additional,
      f"check_cves should return more than just Heartbleed for openssl "
      f"1.0.1f; got {sorted(inferred_cves)}",
    )

  def test_service_info_tls_appends_inferred_cves_on_heartbleed(self):
    from extensions.business.cybersec.red_mesh.worker.service.tls import _ServiceTlsMixin
    from extensions.business.cybersec.red_mesh.findings import Finding, Severity

    probe = _ServiceTlsMixin.__new__(_ServiceTlsMixin)

    # Stub every sibling pass to no-op except heartbleed → positive.
    probe._tls_unverified_connect = lambda t, p: ("TLSv1.2", "ECDHE-RSA-AES256-GCM-SHA384", None)
    probe._tls_check_protocol = lambda proto, cipher: []
    probe._tls_parse_san_from_der = lambda d: ([], [])
    probe._tls_check_signature_algorithm = lambda d: []
    probe._tls_check_validity_period = lambda d: []
    probe._tls_check_certificate = lambda t, p, raw: []
    probe._tls_check_expiry = lambda raw: []
    probe._tls_check_default_cn = lambda raw: []
    probe._tls_check_downgrade = lambda t, p: []
    probe._tls_check_heartbleed = lambda t, p, raw=None: Finding(
      severity=Severity.CRITICAL,
      title="TLS Heartbleed vulnerability (CVE-2014-0160)",
      cve=("CVE-2014-0160",),
      description="leak",
      evidence="leak",
      remediation="upgrade",
      owasp_id="A06:2021",
      cwe_id="CWE-126",
      confidence="certain",
    )

    with patch("extensions.business.cybersec.red_mesh.worker.service.tls._stamp_identity", wraps=_stamp_identity) as stamp:
      result = probe._service_info_tls("10.0.0.1", 8443)
    findings = result["findings"]
    # probe_result normalizes Finding instances to JSON-safe dicts; cve is a list.
    cves = [c for f in findings for c in (f.get("cve") or []) if c]

    # Heartbleed appears exactly once (no duplicate via inference).
    self.assertEqual(
      cves.count("CVE-2014-0160"), 1,
      "Heartbleed must appear exactly once in the findings list — "
      "the inference branch dedups it",
    )

    # At least one other OpenSSL CVE was inferred.
    other_openssl = {c for c in cves if c != "CVE-2014-0160" and c.startswith("CVE-")}
    self.assertTrue(
      other_openssl,
      f"Expected at least one additional OpenSSL CVE inferred from the "
      f"Heartbleed positive, but got only {cves}",
    )

    # The rows show the proven span; identity stays on the matched version and signs the shown text.
    row = next(f for f in findings if f.get("cve") and f["cve"][0] != "CVE-2014-0160")
    self.assertIn("(openssl 1.0.1-1.0.1f)", row["title"])
    self.assertIn("openssl 1.0.1-1.0.1f is", row["description"])
    self.assertIn("Detected version: 1.0.1-1.0.1f,", row["evidence"])
    stamp.assert_called()
    self.assertEqual(stamp.call_args.args[1:3], ("openssl", "1.0.1f"))
    self.assertIn("1.0.1-1.0.1f", stamp.call_args.args[0].title)


TLS = "extensions.business.cybersec.red_mesh.worker.service.tls"
CLOSE_NOTIFY = b"\x15\x03\x03\x00\x02\x01\x00"


class TestHeartbleedReadLoop(unittest.TestCase):
  """One bounded read serves both paths: skip the shutdown alert, keep the raw fallback reachable."""

  def _probe(self):
    return _ServiceTlsMixin.__new__(_ServiceTlsMixin)

  def _check(self, unwrapped_chunks, raw_chunks=()):
    probe = self._probe()
    after, raw_sock = MagicMock(), MagicMock()
    after.recv.side_effect = list(unwrapped_chunks) + [b""]
    raw_sock.recv.side_effect = [b"\x16\x03\x01\x00\x04\x0e\x00\x00\x00"] + list(raw_chunks) + [b""]
    tls_sock = MagicMock()
    tls_sock.unwrap.return_value = after
    ctx = MagicMock()
    ctx.wrap_socket.return_value = tls_sock
    with patch(TLS + ".ssl.SSLContext", return_value=ctx), patch(TLS + ".socket.socket", return_value=raw_sock):
      return probe._tls_check_heartbleed("10.0.0.1", 8443), raw_sock

  def test_close_notify_then_heartbeat_in_separate_reads_is_found(self):
    leak = _build_leak_response()
    result, raw_sock = self._check([CLOSE_NOTIFY, leak[:3], leak[3:]])
    self.assertIsNotNone(result)
    self.assertEqual(raw_sock.connect.call_count, 1)  # the main connect only

  def test_alert_only_falls_back_to_raw_path(self):
    result, raw_sock = self._check([CLOSE_NOTIFY], [_build_leak_response()])
    self.assertIsNotNone(result)
    self.assertEqual(raw_sock.connect.call_count, 2)  # main connect plus raw fallback

  def test_short_read_and_silence_are_not_vulnerable_and_skip_raw(self):
    result, raw_sock = self._check([b"\x18\x03"])
    self.assertIsNone(result)
    self.assertEqual(raw_sock.connect.call_count, 1)  # the main connect only

  def test_read_stops_at_the_deadline(self):
    sock = MagicMock()
    sock.recv.return_value = CLOSE_NOTIFY
    with patch.object(_ServiceTlsMixin, "_deadline_in", return_value=0):
      self.assertEqual(self._probe()._tls_read_heartbeat(sock), (None, False))
    sock.recv.assert_not_called()


if __name__ == "__main__":
  unittest.main()
