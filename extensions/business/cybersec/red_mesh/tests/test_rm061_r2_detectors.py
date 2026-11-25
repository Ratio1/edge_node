"""RM-061 phase R2: Modbus reply validation, Telnet banner gate, Spring Boot JSON error evidence."""
import json
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.tests.test_rm198_detection_checks import _worker
from extensions.business.cybersec.red_mesh.worker.web.injection import _has_java_evidence

_INFRA_SOCK = "extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket"
_COMMON_SOCK = "extensions.business.cybersec.red_mesh.worker.service.common.socket.socket"


class _Sock:
  def __init__(self, reply):
    self.reply = reply
    self.sent = b""

  def settimeout(self, t): pass
  def connect(self, addr): pass
  def sendall(self, data):
    self.sent += data
  def close(self): pass

  def recv(self, n):
    r, self.reply = self.reply, b""
    return r


def _modbus(reply):
  with patch(_INFRA_SOCK, return_value=_Sock(reply)):
    return _worker(ports=(502,))._service_info_modbus("1.2.3.4", 502)["findings"]


def _telnet(reply):
  with patch(_COMMON_SOCK, return_value=_Sock(reply)):
    return _worker(ports=(23,))._service_info_telnet("1.2.3.4", 23)["findings"]


class TestModbusReply(unittest.TestCase):
  def test_valid_reply_critical_certain(self):
    for reply in (b"\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01", b"\x00\x01\x00\x00\x00\x03\x01\xab\x01"):
      f = _modbus(reply)
      self.assertEqual(len(f), 1, reply)
      self.assertEqual((f[0]["severity"], f[0]["confidence"]), ("CRITICAL", "certain"), reply)

  def test_invalid_reply_info_tentative(self):
    bad = {
      "short": b"\x00\x01\x00\x00\x00\x02\x01",
      "protocol_id": b"\x00\x01\x00\x01\x00\x05\x01\x2b\x0e\x01",
      "function": b"\x00\x01\x00\x00\x00\x05\x01\x03\x0e\x01",
      "http": b"HTTP/1.1 400 Bad Request\r\n\r\n",
    }
    for name, reply in bad.items():
      f = _modbus(reply)
      self.assertEqual(len(f), 1, name)
      self.assertEqual((f[0]["severity"], f[0]["confidence"]), ("INFO", "tentative"), name)

  def test_empty_reply_no_finding(self):
    self.assertEqual(_modbus(b""), [])


class TestTelnetGate(unittest.TestCase):
  def _exposed(self, reply):
    return [f for f in _telnet(reply) if f["title"].startswith("Telnet")]

  def test_iac_or_banner_is_medium_certain(self):
    for reply in (b"\xff\xfd\x18\xff\xfd\x20", b"Welcome to router\r\nlogin: "):
      f = self._exposed(reply)
      self.assertEqual(len(f), 1, reply)
      self.assertEqual((f[0]["severity"], f[0]["confidence"]), ("MEDIUM", "certain"), reply)

  def test_no_bytes_is_info_tentative(self):
    f = self._exposed(b"")
    self.assertEqual(len(f), 1)
    self.assertEqual((f[0]["severity"], f[0]["confidence"]), ("INFO", "tentative"))


def _r(text, headers=None):
  m = MagicMock()
  m.text, m.headers = text, headers or {}
  return m


class TestSpringBootJsonMarker(unittest.TestCase):
  BODY = {"timestamp": "2026-01-01", "status": 500, "error": "Internal Server Error", "path": "/"}

  def test_boot_error_body_accepted(self):
    self.assertTrue(_has_java_evidence(_r(json.dumps(self.BODY))))

  def test_partial_or_substring_json_rejected(self):
    self.assertFalse(_has_java_evidence(_r(json.dumps({"status": 500}))))
    self.assertFalse(_has_java_evidence(_r(json.dumps({"status": 500, "error": "x", "path": "/"}))))
    self.assertFalse(_has_java_evidence(_r("<p>timestamp status error path</p>")))

  def test_finding_names_marker(self):
    body = json.dumps(self.BODY)

    def fake_get(url, **kw):
      r = _r("<html>App</html>")
      r.status_code = 200
      if "INVALID_RM_CTRL" in url and "URLs" not in url:
        r.status_code = 400
      if "classLoader.URLs" in url:
        r.status_code, r.text = 500, body
      if "/actuator" in url:
        r.status_code, r.text = 404, ""
      r.ok = r.status_code < 400
      return r
    post = _r("")
    post.status_code, post.ok = 404, False
    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.post", return_value=post):
      res = _worker(ports=(80,))._web_test_spring_actuator("1.2.3.4", 80)
    hits = [f for f in res["findings"] if "Spring4Shell" in f["title"]]
    self.assertEqual(len(hits), 1)
    self.assertIn("java_marker=spring_boot_json_error", hits[0]["evidence"])


class TestModbusRequestFraming(unittest.TestCase):
  def test_mbap_length_matches_the_pdu(self):
    sock = _Sock(b"")
    with patch(_INFRA_SOCK, return_value=sock):
      _worker(ports=(502,))._service_info_modbus("1.2.3.4", 502)
    self.assertEqual(int.from_bytes(sock.sent[4:6], "big"), len(sock.sent) - 6)
