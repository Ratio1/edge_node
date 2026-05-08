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
    probe._tls_check_heartbleed = lambda t, p: Finding(
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


if __name__ == "__main__":
  unittest.main()
