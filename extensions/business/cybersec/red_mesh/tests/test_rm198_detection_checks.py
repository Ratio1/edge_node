"""
RM-198 phase 2: detection and confirmation checks. Every check is a single-shot read.

Apache 2.4.49/2.4.50 traversal (unnormalised request line), Samba 4.6.3 maximal-access read, and the
PostgreSQL role-privilege read. OpenSSH CVE-2018-15473, Django CVE-2017-12794 and nginx CVE-2013-4547 are
dropped (reasons in the task report), so no test covers them.
"""

import socket
import struct
import threading
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.tests.test_probes import DummyOwner
from extensions.business.cybersec.red_mesh.worker.pentest_worker import PentestLocalWorker
from extensions.business.cybersec.red_mesh.worker.web.injection import _raw_path_get

_INJ = "extensions.business.cybersec.red_mesh.worker.web.injection"
PASSWD = "root:x:0:0:root:/root:/bin/bash\n"


def _worker(enabled=None, ports=(80,)):
  w = PentestLocalWorker(
    owner=DummyOwner(), target="example.com", job_id="job-198", initiator="init@example",
    local_id_prefix="1", worker_target_ports=list(ports),
  )
  w.stop_event = MagicMock()
  w.stop_event.is_set.return_value = False
  w._PentestLocalWorker__enabled_features = enabled
  w.P = MagicMock()
  return w


class TestApacheTraversal(unittest.TestCase):

  def test_request_line_is_sent_unnormalised(self):
    """The wire bytes keep `.%2e`, `%%32%65` and `..` as written; `requests` would rewrite them."""
    seen = []
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)

    def serve():
      for _ in range(3):
        conn, _ = srv.accept()
        seen.append(conn.recv(4096))
        conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        conn.close()
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    paths = ["/icons/.%2e/%2e%2e/etc/passwd", "/icons/.%%32%65/.%%32%65/etc/passwd", "/../../../../etc/passwd"]
    for path in paths:
      resp = _raw_path_get("http", "127.0.0.1", srv.getsockname()[1], path, 2)
    t.join(3)
    srv.close()
    self.assertEqual(resp.text, "ok")
    self.assertEqual([r.split(b"\r\n")[0] for r in seen], [f"GET {p} HTTP/1.1".encode() for p in paths])

  def _run(self, vulnerable_path_part):
    def fake(scheme, host, port, path, timeout):
      body = PASSWD if vulnerable_path_part in path else "not found"
      return MagicMock(status_code=200, text=body)
    with patch(f"{_INJ}._raw_path_get", side_effect=fake), \
         patch(f"{_INJ}.requests.get", return_value=MagicMock(text="nope", status_code=404)):
      return _worker()._web_test_path_traversal("example.com", 80)["findings"]

  def test_41773_payload_gives_cve_finding(self):
    found = self._run("/icons/.%2e/")
    self.assertEqual([f["cve"] for f in found], [["CVE-2021-41773"]])
    self.assertEqual(found[0]["confidence"], "certain")
    self.assertIn("kev", found[0])

  def test_42013_payload_gives_cve_finding(self):
    found = self._run(".%%32%65")
    self.assertEqual([f["cve"] for f in found], [["CVE-2021-42013"]])

  def test_no_marker_in_body_gives_no_finding(self):
    self.assertEqual(self._run("never-matches"), [])

  def test_request_error_is_logged_not_hidden(self):
    w = _worker()
    with patch(f"{_INJ}._raw_path_get", side_effect=OSError("boom")), \
         patch(f"{_INJ}.requests.get", return_value=MagicMock(text="nope", status_code=404)):
      result = w._web_test_path_traversal("example.com", 80)
    self.assertTrue(any("boom" in str(c) for c in w.P.call_args_list))
    self.assertIn("OSError: boom", result["request_errors"][0])


def _nb(payload):
  return b"\x00" + struct.pack(">I", len(payload))[1:] + payload


def _smb_reply(cmd, status=0, uid=0, words=b"\x00"):
  hdr = bytearray(32)
  hdr[0:4] = b"\xffSMB"
  hdr[4] = cmd
  struct.pack_into("<I", hdr, 5, status)
  struct.pack_into("<H", hdr, 28, uid)
  return _nb(bytes(hdr) + words)


def _tree_reply(mask, status=0):
  words = struct.pack("<BBBHHII", 7, 0xFF, 0, 0, 1, mask, 0) + struct.pack("<H", 0)
  return _smb_reply(0x75, status=status, uid=1, words=words)


class _ScriptedSock:
  """Serves canned bytes and records what the code sends."""

  def __init__(self, replies):
    self.buf = b"".join(replies)
    self.sent = []

  def settimeout(self, _):
    pass

  def connect(self, _):
    pass

  def sendall(self, data):
    self.sent.append(data)

  def recv(self, n):
    chunk, self.buf = self.buf[:n], self.buf[n:]
    return chunk

  def close(self):
    pass


class TestSambaMaximalAccess(unittest.TestCase):
  SHARES = [
    {"name": "IPC$", "type": 3, "comment": ""},
    {"name": "C$", "type": 0, "comment": ""},
    {"name": "public", "type": 0, "comment": ""},
    {"name": "docs", "type": 0, "comment": ""},
  ]

  def _access(self, tree_masks):
    replies = [_smb_reply(0x72, words=b"\x00" * 8), _smb_reply(0x73, uid=1)] + [_tree_reply(m) for m in tree_masks]
    sock = _ScriptedSock(replies)
    with patch("socket.socket", return_value=sock):
      return _worker()._smb_share_access("10.0.0.1", 445, self.SHARES), sock

  def test_reads_rights_per_disk_share_and_sends_only_negotiate_session_tree_connect(self):
    (access, error), sock = self._access([0x001F01FF, 0x001200A9])
    self.assertEqual((access, error), ({"public": 0x001F01FF, "docs": 0x001200A9}, None))
    commands = [pkt[4 + 4] for pkt in sock.sent]  # NetBIOS header (4) then the SMB command byte at 4
    self.assertEqual(commands, [0x72, 0x73, 0x75, 0x75])

  def test_unexpected_or_denied_tree_connect_frames_give_no_mask(self):
    good = _tree_reply(0x001F01FF)[4:]
    self.assertEqual(PentestLocalWorker._smb_tree_max_access(good), (0x001F01FF, None))
    wrong_cmd = bytearray(good)
    wrong_cmd[4] = 0x73
    not_smb = b"\xfeSMB" + good[4:]
    denied = _tree_reply(0, status=0xC0000022)[4:]
    self.assertEqual(PentestLocalWorker._smb_tree_max_access(bytes(wrong_cmd))[0], None)
    self.assertEqual(PentestLocalWorker._smb_tree_max_access(not_smb)[0], None)
    self.assertEqual(PentestLocalWorker._smb_tree_max_access(denied), (None, "status 0xc0000022"))

  def test_denied_share_is_recorded_per_share(self):
    replies = [_smb_reply(0x72, words=b"\x00" * 8), _smb_reply(0x73, uid=1),
               _tree_reply(0x001F01FF), _tree_reply(0, status=0xC0000022)]
    with patch("socket.socket", return_value=_ScriptedSock(replies)):
      access, error = _worker()._smb_share_access("10.0.0.1", 445, self.SHARES)
    self.assertEqual(access, {"public": 0x001F01FF, "docs": {"error": "status 0xc0000022"}})

  def test_oversized_frame_is_an_error_not_a_truncated_frame(self):
    big = b"\x00" + struct.pack(">I", 70000)[1:]
    with patch("socket.socket", return_value=_ScriptedSock([big])):
      access, error = _worker()._smb_share_access("10.0.0.1", 445, self.SHARES)
    self.assertEqual(access, {})
    self.assertIn("exceeds", error)

  def test_helper_error_is_returned_not_hidden(self):
    sock = _ScriptedSock([])
    with patch("socket.socket", return_value=sock):
      access, error = _worker()._smb_share_access("10.0.0.1", 445, self.SHARES)
    self.assertEqual(access, {})
    self.assertEqual(error, "negotiate failed")

  def _probe(self, version, access, error=None):
    w = _worker(ports=(445,))
    smb_resp = bytearray(128)
    smb_resp[0:4] = b"\xffSMB"
    smb_resp[4] = 0x72
    smb_resp[32] = 17
    sock = MagicMock()
    sock.recv.side_effect = [b"\x00\x00\x00\x80", bytes(smb_resp)]
    with patch.object(w, "_smb_enum_shares", return_value=self.SHARES), \
         patch.object(w, "_smb_try_null_session", return_value=version), \
         patch.object(w, "_smb_share_access", return_value=(access, error)), \
         patch("socket.socket", return_value=sock):
      return w._service_info_smb("10.0.0.1", 445)

  def test_writable_share_on_affected_samba_is_a_firm_cve_finding(self):
    result = self._probe("4.6.3", {"public": 0x001F01FF})
    hits = [f for f in result["findings"] if "SambaCry precondition" in f["title"]]
    self.assertEqual(len(hits), 1)
    self.assertEqual((hits[0]["confidence"], hits[0]["cve"]), ("firm", ["CVE-2017-7494"]))
    self.assertIn("kev", hits[0])

  def test_read_only_share_or_patched_samba_gives_no_probe_finding(self):
    for version, access in (("4.6.3", {"public": 0x001200A9}), ("4.10.0", {"public": 0x001F01FF})):
      result = self._probe(version, access)
      self.assertFalse([f for f in result["findings"] if "SambaCry precondition" in f["title"]], version)

  def test_access_error_lands_in_raw_data_and_log(self):
    w = _worker(ports=(445,))
    smb_resp = bytearray(128)
    smb_resp[0:4] = b"\xffSMB"
    smb_resp[32] = 17
    sock = MagicMock()
    sock.recv.side_effect = [b"\x00\x00\x00\x80", bytes(smb_resp)]
    with patch.object(w, "_smb_enum_shares", return_value=self.SHARES), \
         patch.object(w, "_smb_try_null_session", return_value="4.6.3"), \
         patch.object(w, "_smb_share_access", return_value=({}, "negotiate failed")), \
         patch("socket.socket", return_value=sock):
      result = w._service_info_smb("10.0.0.1", 445)
    self.assertEqual(result["share_access_error"], "negotiate failed")
    self.assertTrue(any("negotiate failed" in str(c) for c in w.P.call_args_list))


def _pg(kind, body=b""):
  return kind + struct.pack("!I", len(body) + 4) + body


def _datarow(*flags):
  body = struct.pack("!H", len(flags))
  for f in flags:
    body += struct.pack("!i", 1) + (b"t" if f else b"f")
  return _pg(b"D", body)


class _SeqSock(_ScriptedSock):
  """One canned reply per recv call, so message boundaries match what the code reads."""

  def __init__(self, replies):
    super().__init__([])
    self.replies = list(replies)

  def recv(self, n):
    return self.replies.pop(0) if self.replies else b""


class TestPostgresPrivilegeRead(unittest.TestCase):
  READY = _pg(b"R", struct.pack("!I", 0)) + _pg(b"Z", b"I")
  SECRET = "hunter2-secret"

  def _read(self, w, reply, raw=None):
    sock = _ScriptedSock([reply])
    raw = {} if raw is None else raw
    return w._pg_privilege_findings(sock, self.READY, "postgres", raw), sock, raw

  def test_superuser_gives_firm_cve_finding_and_only_a_select_is_sent(self):
    found, sock, raw = self._read(_worker(None), _pg(b"T") + _datarow(True, False) + _pg(b"C") + _pg(b"Z", b"I"))
    self.assertEqual(len(found), 1)
    self.assertEqual((found[0].confidence, found[0].cve), ("firm", ("CVE-2019-9193",)))
    self.assertEqual(len(sock.sent), 1)
    self.assertTrue(sock.sent[0].startswith(b"Q"))
    self.assertNotIn(b"COPY", sock.sent[0])
    self.assertEqual(raw["role_privileges"]["role"], "postgres")
    self.assertTrue(raw["role_privileges"]["rolsuper"])

  def test_role_without_privilege_gives_no_finding(self):
    found, _, raw = self._read(_worker(None), _pg(b"T") + _datarow(False, False) + _pg(b"Z", b"I"))
    self.assertEqual(found, [])
    self.assertEqual(raw["role_privileges"],
                     {"role": "postgres", "rolsuper": False, "pg_execute_server_program": False})

  def test_closed_gate_sends_nothing(self):
    found, sock, _ = self._read(_worker(["_service_info_ssh"]), b"")
    self.assertEqual((found, sock.sent), ([], []))

  def test_read_error_records_the_server_message(self):
    w = _worker(None)
    found, _, raw = self._read(w, _pg(b"E", b"SERROR\x00Mpermission denied for pg_roles\x00\x00") + _pg(b"Z", b"I"))
    self.assertEqual(found, [])
    self.assertEqual(raw["privilege_read_error"], "permission denied for pg_roles")
    self.assertTrue(any("permission denied for pg_roles" in str(c) for c in w.P.call_args_list))

  def test_cleartext_login_wires_one_finding_and_leaks_no_password(self):
    """Probe level: three accepted pairs (as under trust auth) still give one finding, and the evidence,
    description and log carry the role name only."""
    ok = _pg(b"R", struct.pack("!I", 0)) + _pg(b"Z", b"I")
    script = [_pg(b"R", struct.pack("!I", 3)), ok, _pg(b"T") + _datarow(True, True) + _pg(b"Z", b"I")]
    w = _worker(None, ports=(5432,))
    with patch("socket.socket", side_effect=lambda *a, **k: _SeqSock(script)), \
         patch.object(PentestLocalWorker, "_login_attempts_allowed", return_value=True):
      result = w._service_info_postgresql_creds("10.0.0.5", 5432)
    hits = [f for f in result["findings"] if f["title"].startswith("CVE-2019-9193")]
    self.assertEqual(len(hits), 1)
    self.assertEqual(result["role_privileges"]["role"], "postgres")


if __name__ == "__main__":
  unittest.main()
