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


if __name__ == "__main__":
  unittest.main()
