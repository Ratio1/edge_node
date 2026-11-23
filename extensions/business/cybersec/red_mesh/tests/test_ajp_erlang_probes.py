import hashlib
import json
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from .conftest import DummyOwner, PentestLocalWorker

DB = "extensions.business.cybersec.red_mesh.worker.service.database"
INFRA = "extensions.business.cybersec.red_mesh.worker.service.infrastructure"
PW = "extensions.business.cybersec.red_mesh.worker.pentest_worker"
COOKIE = "monster"
MY_CHALLENGE = 7


class FakeSock:
  """Socket that serves scripted inbound bytes and records what was sent."""

  def __init__(self, inbound=b"", error=None):
    self.inbound, self.sent, self.error, self.closed = inbound, b"", error, False

  def settimeout(self, _):
    pass

  def connect(self, _):
    pass

  def sendall(self, data):
    self.sent += data

  def recv(self, n):
    if self.error and not self.inbound:  # serve the scripted bytes, then fail
      raise self.error
    out, self.inbound = self.inbound[:n], self.inbound[n:]
    return out

  def close(self):
    self.closed = True


def _factory(*socks):
  queue = list(socks)
  made = []

  def make(*_a, **_k):
    sock = queue.pop(0) if queue else FakeSock()
    made.append(sock)
    return sock
  make.made = made
  return make


def _pkt16(body):
  return struct.pack(">H", len(body)) + body


def _ajp_answer(content):
  chunk = bytes([3]) + struct.pack(">H", len(content)) + content + b"\x00"
  return b"AB" + struct.pack(">H", len(chunk)) + chunk + b"AB\x00\x01\x05\x01"


def _epmd_answer(*nodes):
  return struct.pack(">I", 4369) + b"".join(f"name {n} at port {p}\n".encode() for n, p in nodes)


def _handshake_answer(status=b"sok", their_challenge=99, ack_cookie=COOKIE):
  out = _pkt16(status)
  if status == b"sok":
    out += _pkt16(b"n" + struct.pack(">HII", 5, 0, their_challenge) + b"couchdb@node")
    out += _pkt16(b"a" + hashlib.md5(ack_cookie.encode() + str(MY_CHALLENGE).encode()).digest())
  return out


class AjpErlangProbeTests(unittest.TestCase):

  def setUp(self):
    self.worker = PentestLocalWorker(
      owner=DummyOwner(), target="10.0.0.1", job_id="j", initiator="i",
      local_id_prefix="1", worker_target_ports=[8009],
    )
    self.worker.stop_event = MagicMock()
    self.worker.stop_event.is_set.return_value = False
    self.worker.job_ports = frozenset([8009, 4369, 40000])

  def _fingerprint(self, answer_for):
    w = self.worker
    w.state.update(open_ports=[1024], port_protocols={1024: "unknown"},
                   port_banners={1024: ""}, port_banner_confirmed={1024: False})

    class Sock(FakeSock):
      def sendall(self, data):
        super().sendall(data)
        self.inbound = answer_for.get(data, b"")

    with patch(f"{PW}.socket.socket", side_effect=lambda *a, **k: Sock()):
      w._active_fingerprint_ports()
    return w.state["port_protocols"][1024]

  # ── fingerprints ──
  def test_fingerprint_ajp13_and_epmd(self):
    cping, names = b"\x12\x34\x00\x01\x0a", b"\x00\x01n"
    for answer_for, protocol in (
      ({cping: b"AB\x00\x01\x09"}, "ajp13"),
      ({names: _epmd_answer(("couchdb", 40000))}, "epmd"),
      ({names: struct.pack(">I", 1024)}, "epmd"),  # empty node list: only the port, the one connected to
      ({cping: b"AB\x00\x01\x08", names: struct.pack(">I", 4369)}, "unknown"),  # not CPONG; another port
    ):
      with self.subTest(protocol=protocol, answer_for=answer_for):
        self.assertEqual(self._fingerprint(answer_for), protocol)

  # ── Ghostcat ──
  def _ajp(self, sock):
    with patch(f"{INFRA}.socket.socket", side_effect=_factory(sock)):
      return self.worker._service_info_ajp("10.0.0.1", 8009)

  def test_ajp_confirms_on_marker_and_keeps_no_file_body(self):
    body = b'<?xml version="1.0"?><web-app><display-name>SECRET-APP-NAME</display-name></web-app>'
    sock = FakeSock(_ajp_answer(body))
    result = self._ajp(sock)
    finding, = result["findings"]
    self.assertEqual(finding["cve"], ["CVE-2020-1938"])
    self.assertIn("kev", finding)
    self.assertEqual(finding["confidence"], "certain")
    self.assertIn(b"/WEB-INF/web.xml", sock.sent)
    self.assertIn(b"javax.servlet.include.path_info", sock.sent)
    self.assertIn(b"/redmesh-ajp", sock.sent)  # a URI that cannot reach the JSP servlet
    self.assertNotIn("SECRET-APP-NAME", json.dumps(result))

  def test_ajp_no_finding_without_marker(self):
    self.assertEqual(self._ajp(FakeSock(_ajp_answer(b"<html>404</html>")))["findings"], [])

  def test_ajp_endless_non_body_packets_end_promptly(self):
    sock = FakeSock(b"AB\x00\x02\x04\x00" * 5000)  # SEND_HEADERS forever, never a body or an end
    with patch(f"{INFRA}.socket.socket", side_effect=_factory(sock)):
      result = self.worker._service_info_ajp("10.0.0.1", 8009)
    self.assertEqual(result["findings"], [])
    self.assertGreater(len(sock.inbound), 0)  # the packet cap ended the read, not EOF

  def test_ajp_timeout_gives_no_finding(self):
    self.assertEqual(self._ajp(FakeSock(error=socket.timeout()))["findings"], [])

  # ── CouchDB Erlang cookie ──
  def _erlang(self, dist_answer, allowed=True, dist_error=None, epmd=_epmd_answer(("couchdb", 40000)),
              epmd_error=None):
    factory = _factory(FakeSock(epmd, error=epmd_error), FakeSock(dist_answer, error=dist_error))
    with patch(f"{DB}.socket.socket", side_effect=factory), \
         patch(f"{DB}.random.getrandbits", return_value=MY_CHALLENGE), \
         patch.object(self.worker, "_login_attempts_allowed", return_value=allowed):
      result = self.worker._service_info_erlang_dist("10.0.0.1", 4369)
    return result, factory.made

  def test_erlang_confirms_default_cookie_and_stops_after_ack(self):
    result, socks = self._erlang(_handshake_answer())
    finding, = result["findings"]
    self.assertEqual(finding["cve"], ["CVE-2022-24706"])
    self.assertIn("kev", finding)
    self.assertIn("hidden peer", finding["description"])
    self.assertEqual(result["erlang_handshake"], {"dist_port": 40000, "outcome": "authenticated"})
    sent = socks[1].sent  # send_name (flags without PUBLISHED), then challenge_reply only
    name_len = struct.unpack(">H", sent[:2])[0]
    self.assertEqual(sent[2:3], b"n")
    self.assertEqual(struct.unpack(">I", sent[5:9])[0] & 1, 0)
    self.assertEqual(sent[2 + name_len:2 + name_len + 3], struct.pack(">H", 21) + b"r")
    self.assertEqual(sent[2 + name_len + 7:], hashlib.md5(b"monster" + b"99").digest())
    self.assertEqual(len(sent), 2 + name_len + 2 + 21)
    self.assertTrue(socks[1].closed)

  def test_erlang_digest_mismatch_gives_no_finding(self):
    result, _ = self._erlang(_handshake_answer(ack_cookie="other"))
    self.assertEqual(result["findings"], [])
    self.assertEqual(result["erlang_handshake"]["outcome"], "bad_digest")

  def test_erlang_active_auth_off_sends_no_handshake(self):
    result, socks = self._erlang(_handshake_answer(), allowed=False)
    self.assertEqual(result["findings"], [])
    self.assertEqual(result["auth_control"], {"skipped": "active_auth disabled"})
    self.assertEqual(len(socks), 1)  # epmd only

  def test_erlang_dist_port_outside_scope_is_not_contacted(self):
    self.worker.job_ports = frozenset([8009, 4369])
    result, socks = self._erlang(_handshake_answer())
    self.assertEqual(result["findings"], [])
    self.assertEqual(result["erlang_handshake"]["outcome"], "out_of_scope")
    self.assertEqual(len(socks), 1)

  def test_erlang_epmd_timeout_keeps_the_complete_node_lines(self):
    epmd = _epmd_answer(("couchdb", 40000)) + b"name half at port 4"  # the last line is cut off
    result, _ = self._erlang(_handshake_answer(), epmd=epmd, epmd_error=socket.timeout())
    self.assertNotIn("epmd_error", result)
    self.assertEqual(result["epmd_nodes"], [{"name": "couchdb", "port": 40000}])
    self.assertEqual(result["erlang_handshake"]["outcome"], "authenticated")

  def test_erlang_refused_statuses_give_no_finding(self):
    new_style = _pkt16(b"sok") + _pkt16(b"N" + bytes(20))  # an OTP 25+ challenge, not the old 'n'
    for answer, outcome in (
      (_handshake_answer(b"snot_allowed"), "not_allowed"), (_handshake_answer(b"salive"), "alive"),
      (_handshake_answer(b"snok"), "nok"), (new_style, "unsupported"),
    ):
      with self.subTest(outcome=outcome):
        result, _ = self._erlang(answer)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["erlang_handshake"]["outcome"], outcome)

  def test_erlang_timeout_gives_no_finding(self):
    result, _ = self._erlang(b"", dist_error=socket.timeout())
    self.assertEqual(result["findings"], [])
    self.assertEqual(result["erlang_handshake"]["outcome"], "timeout")


if __name__ == "__main__":
  unittest.main()
