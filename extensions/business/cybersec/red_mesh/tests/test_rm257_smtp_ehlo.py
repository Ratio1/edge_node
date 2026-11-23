"""RM-257 phase 3b: an invalid scanner identity falls back to the default EHLO domain."""
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tests.test_rm198_detection_checks import _worker
from extensions.business.cybersec.red_mesh.worker.service.common import _ehlo_domain

DEFAULT = "probe.redmesh.local"


class TestEhloDomain(unittest.TestCase):
  def test_valid_hostnames_pass_through(self):
    for name in ("probe.redmesh.local", "a", "scan-1.example.com", "a" * 63 + ".com"):
      self.assertEqual(_ehlo_domain(name), name)

  def test_invalid_identity_falls_back_to_default(self):
    for name in ("RedMesh scanner", "scänner.example", "", None, "a" * 64 + ".com",
                 ("a" * 62 + ".") * 5 + "com", "-lead.example", "trail-.example", "a..b", "host.", "x_y"):
      self.assertEqual(_ehlo_domain(name), DEFAULT, repr(name))

  def test_probe_sends_default_for_free_text_identity(self):
    sent = []

    class FakeSMTP:
      def __init__(self, timeout=5): pass
      def connect(self, target, port): return (220, b"ready")
      def ehlo(self, identity):
        sent.append(identity)
        return (250, b"mx Hello")
      def docmd(self, cmd): return (500, b"no")
      def quit(self): pass

    w = _worker(ports=(25,))
    w.scanner_identity = "Red Mesh Scanner"
    with patch("smtplib.SMTP", return_value=FakeSMTP()):
      w._service_info_smtp("example.com", 25)
    self.assertEqual(set(sent), {DEFAULT})
