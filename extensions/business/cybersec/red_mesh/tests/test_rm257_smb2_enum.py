"""RM-257 phase 3c: an SMB2 negotiation with no shares records why."""
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.tests.test_rm198_detection_checks import _worker


def _probe(magic, shares=()):
  w = _worker(ports=(445,))
  resp = bytearray(128)
  resp[0:4] = magic
  sock = MagicMock()
  sock.recv.side_effect = [b"\x00\x00\x00\x80", bytes(resp)]
  with patch.object(w, "_smb_enum_shares", return_value=list(shares)), \
       patch.object(w, "_smb_try_null_session", return_value=None), \
       patch("socket.socket", return_value=sock):
    return w._service_info_smb("10.0.0.1", 445), w


class TestSmb2OnlyEnumeration(unittest.TestCase):
  def test_smb2_negotiated_without_shares_records_reason_and_logs(self):
    result, w = _probe(b"\xfeSMB")
    self.assertEqual(result["shares_error"], "SMB2 negotiated; no shares via SMB1")
    self.assertTrue(any("no shares via SMB1" in str(c) for c in w.P.call_args_list))

  def test_smb1_server_without_shares_records_no_reason(self):
    result, _ = _probe(b"\xffSMB")
    self.assertNotIn("shares_error", result)
