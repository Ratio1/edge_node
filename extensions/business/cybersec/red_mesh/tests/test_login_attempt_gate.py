"""
RM-198 phase 1: the `active_auth` group is the one switch for login attempts, and the
MySQL CVE-2012-2122 loop is bounded and records why it ended.
"""

import struct
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.constants import ACTIVE_AUTH_METHODS, AUTH_SKIPPED
from extensions.business.cybersec.red_mesh.tests.test_probes import DummyOwner
from extensions.business.cybersec.red_mesh.worker.pentest_worker import PentestLocalWorker

_COMMON = "extensions.business.cybersec.red_mesh.worker.service.common"
_DB = "extensions.business.cybersec.red_mesh.worker.service.database"
_HARD = "extensions.business.cybersec.red_mesh.worker.web.hardening"
_SKIP = AUTH_SKIPPED


def _worker(enabled, ports=(21,)):
  w = PentestLocalWorker(
    owner=DummyOwner(), target="example.com", job_id="job-gate", initiator="init@example",
    local_id_prefix="1", worker_target_ports=list(ports),
  )
  w.stop_event = MagicMock()
  w.stop_event.is_set.return_value = False
  w._PentestLocalWorker__enabled_features = enabled
  return w


class TestGateHelper(unittest.TestCase):

  def test_group_is_the_three_existing_methods(self):
    self.assertEqual(set(ACTIVE_AUTH_METHODS), {
      "_service_info_mysql_creds", "_service_info_postgresql_creds", "_service_info_http_basic_auth",
    })

  def test_open_when_any_group_method_enabled_or_unrestricted(self):
    self.assertTrue(_worker(None)._login_attempts_allowed())
    self.assertTrue(_worker([])._login_attempts_allowed())
    self.assertTrue(_worker(["_service_info_http_basic_auth"])._login_attempts_allowed())

  def test_job_with_nothing_enabled_runs_no_probe_so_the_open_gate_is_moot(self):
    w = _worker([])
    self.assertEqual(w._get_enabled_feature_methods(category="service"), [])
    self.assertEqual(w._get_enabled_feature_methods(category="web"), [])

  def test_closed_when_no_group_method_enabled(self):
    self.assertFalse(_worker(["_service_info_ssh"])._login_attempts_allowed())


class TestGatedPathsSendNothing(unittest.TestCase):
  """With every group method excluded, no credential reaches the socket or library."""

  def test_ssh_sends_no_credential(self):
    client = MagicMock()
    banner = MagicMock()
    banner.recv.return_value = b"SSH-2.0-libssh_0.8.1"
    with patch(f"{_COMMON}.paramiko.SSHClient", return_value=client), \
         patch(f"{_COMMON}.socket.socket", return_value=banner), \
         patch(f"{_COMMON}._ssh_read_kexinit", return_value=None), \
         patch.object(PentestLocalWorker, "_ssh_check_libssh_bypass") as bypass:
      result = _worker(["_service_info_ssh"], ports=(22,))._service_info_ssh("example.com", 22)
    client.connect.assert_not_called()
    bypass.assert_not_called()
    self.assertEqual(result["auth_control"], _SKIP)

  def test_ftp_sends_no_credential(self):
    ftp = MagicMock()
    ftp.login.return_value = "230 ok"
    ftp.sendcmd.return_value = "234 ok"
    ftp.getwelcome.return_value = "220 test"
    with patch(f"{_COMMON}.ftplib.FTP", return_value=ftp):
      result = _worker(["_service_info_ftp"])._service_info_ftp("example.com", 21)
    # only the exempt anonymous login (`login()` with no credential) may remain
    self.assertTrue(ftp.login.call_args_list)
    for call in ftp.login.call_args_list:
      self.assertEqual((call.args, call.kwargs), ((), {}))
    self.assertEqual(result["auth_control"], _SKIP)

  def test_telnet_sends_no_credential(self):
    sock = MagicMock()
    sock.recv.return_value = b"login: "
    with patch(f"{_COMMON}.socket.socket", return_value=sock):
      result = _worker(["_service_info_telnet"], ports=(23,))._service_info_telnet("example.com", 23)
    for call in sock.sendall.call_args_list:
      self.assertNotIn(b"admin", call.args[0])
      self.assertNotIn(b"root", call.args[0])
    self.assertEqual(result["auth_control"], _SKIP)

  def test_web_form_methods_post_nothing(self):
    w = _worker(["_web_test_account_enumeration", "_web_test_rate_limiting"], ports=(80,))
    with patch(f"{_HARD}.requests.post") as post, patch(f"{_HARD}.requests.get") as get:
      enum = w._web_test_account_enumeration("example.com", 80)
      rate = w._web_test_rate_limiting("example.com", 80)
    post.assert_not_called()
    get.assert_not_called()
    for r in (enum, rate):
      self.assertEqual(r["auth_control"], _SKIP)
      self.assertEqual(r["findings"], [])


def _handshake(version=b"5.5.20"):
  payload = b"\x0a" + version + b"\x00" + b"\x01\x00\x00\x00" + b"A" * 8 + b"\x00" + b"\x00" * 19 + b"B" * 12 + b"\x00"
  return struct.pack("<I", len(payload))[:3] + b"\x00" + payload


_ERR = b"\x03\x00\x00\x02\xff\x15\x04"
_OK = b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00"


class TestMysqlCve20122122Loop(unittest.TestCase):

  def _run(self, sock_factory, **patches):
    w = _worker(None, ports=(3306,))
    trace = {}
    with patch(f"{_DB}.socket.socket", side_effect=sock_factory):
      finding = w._mysql_test_cve_2012_2122("db.test", 3306, trace=trace)
    return finding, trace

  def test_records_attempts_and_ends_exhausted(self):
    def factory(*a, **k):
      s = MagicMock()
      s.recv.side_effect = [_handshake(), _ERR]
      return s
    # first socket is the version probe: handshake only
    first = MagicMock()
    first.recv.return_value = _handshake()
    socks = iter([first])
    def f(*a, **k):
      try:
        return next(socks)
      except StopIteration:
        return factory()
    with patch.object(PentestLocalWorker, "_MYSQL_CVE_2012_2122_ATTEMPTS", 7):
      finding, trace = self._run(f)
    self.assertIsNone(finding)
    self.assertEqual(trace["attempts"], 7)
    self.assertEqual(trace["ended_by"], "attempts_exhausted")

  def test_bypass_is_confirmed(self):
    first = MagicMock()
    first.recv.return_value = _handshake()
    attempt = MagicMock()
    attempt.recv.side_effect = [_handshake(), _OK]
    socks = iter([first, attempt])
    finding, trace = self._run(lambda *a, **k: next(socks))
    self.assertEqual(finding.title, "MySQL authentication bypass confirmed (CVE-2012-2122)")
    self.assertEqual(trace["ended_by"], "bypass_confirmed")

  def test_stops_after_five_consecutive_errors_and_records_the_error(self):
    first = MagicMock()
    first.recv.return_value = _handshake()
    calls = {"n": 0}
    def f(*a, **k):
      calls["n"] += 1
      if calls["n"] == 1:
        return first
      s = MagicMock()
      s.connect.side_effect = TimeoutError("timed out")
      return s
    finding, trace = self._run(f)
    self.assertIsNone(finding)
    self.assertEqual(trace["ended_by"], "consecutive_errors")
    self.assertEqual(calls["n"], 1 + 5)
    self.assertIn("TimeoutError", trace["last_error"])

  def _error_then_greeting(self, pattern):
    """Version read succeeds; each later socket fails to connect (E) or rejects the login (R)."""
    first = MagicMock()
    first.recv.return_value = _handshake()
    state = {"n": 0}
    def f(*a, **k):
      state["n"] += 1
      if state["n"] == 1:
        return first
      s = MagicMock()
      if pattern[(state["n"] - 2) % len(pattern)] == "E":
        s.connect.side_effect = TimeoutError("timed out")
      else:
        s.recv.side_effect = [_handshake(), _ERR]
      return s
    return f

  def test_a_good_attempt_resets_the_consecutive_error_count(self):
    # E,E,E,E,R repeating never reaches 5 in a row; only the total cap (error_limit) ends it.
    finding, trace = self._run(self._error_then_greeting("EEEER"))
    self.assertIsNone(finding)
    self.assertEqual(trace["ended_by"], "error_limit")
    self.assertGreater(trace["attempts"], 0)

  def test_stops_when_the_job_is_stopped(self):
    first = MagicMock()
    first.recv.return_value = _handshake()
    w = _worker(None, ports=(3306,))
    w.stop_event.is_set.return_value = True
    trace = {}
    with patch(f"{_DB}.socket.socket", return_value=first):
      w._mysql_test_cve_2012_2122("db.test", 3306, trace=trace)
    self.assertEqual((trace["ended_by"], trace["attempts"]), ("stopped", 0))

  def test_a_failed_version_read_is_recorded(self):
    bad = MagicMock()
    bad.connect.side_effect = ConnectionRefusedError("refused")
    finding, trace = self._run(lambda *a, **k: bad)
    self.assertIsNone(finding)
    self.assertEqual(trace["ended_by"], "version_probe_error")
    self.assertIn("ConnectionRefusedError", trace["last_error"])

  def test_stops_at_the_wall_clock_limit(self):
    first = MagicMock()
    first.recv.return_value = _handshake()
    def f(*a, **k):
      if not f.used:
        f.used = True
        return first
      s = MagicMock()
      s.recv.side_effect = [_handshake(), _ERR]
      return s
    f.used = False
    ticks = {"n": 0}
    def clock():
      ticks["n"] += 1
      return 0.0 if ticks["n"] == 1 else 200.0  # start, then past the limit
    with patch("time.monotonic", side_effect=clock):
      finding, trace = self._run(f)
    self.assertIsNone(finding)
    self.assertEqual(trace["ended_by"], "time_limit")


if __name__ == "__main__":
  unittest.main()
