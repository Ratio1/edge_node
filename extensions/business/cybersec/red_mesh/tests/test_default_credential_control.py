"""
RM-069: default-credential findings are gated on the negative control and
carry proof of an authenticated action.

Client review of job 6cc55610 (2026-08-26, point 2a): a host that accepts
arbitrary credentials also produced CRITICAL default-credential findings
asserting a genuine weakness, and a successful handshake was the whole
evidence. Each probe already ran a random-pair test; its outcome never
reached the verdict.
"""

import ftplib
import socket
import unittest
from unittest.mock import MagicMock, patch

import paramiko

from extensions.business.cybersec.red_mesh.findings import Severity
from extensions.business.cybersec.red_mesh.worker.service.common import (
  CONTROL_ACCEPTED,
  CONTROL_NOT_RUN,
  CONTROL_REJECTED,
  _default_credential_findings,
  _ftp_authenticated_action,
  _ssh_authenticated_action,
)


class TestDefaultCredentialVerdict(unittest.TestCase):

  def test_control_rejected_and_proof_present_is_a_certain_critical(self):
    findings = _default_credential_findings(
      "SSH", ["root:toor"], control=CONTROL_REJECTED,
      proofs={"root:toor": "exec id -> uid=0(root) gid=0(root)"},
    )
    self.assertEqual(len(findings), 1)
    f = findings[0]
    self.assertEqual(f.severity, Severity.CRITICAL)
    self.assertEqual(f.confidence, "certain")
    self.assertEqual(f.title, "SSH default credential accepted: root:toor")
    self.assertIn("Accepted credential: root:toor; authenticated action: exec id ->", f.evidence)

  def test_control_rejected_without_proof_is_firm_not_certain(self):
    f = _default_credential_findings("FTP", ["ftp:ftp"], control=CONTROL_REJECTED)[0]
    self.assertEqual(f.severity, Severity.CRITICAL)
    self.assertEqual(f.confidence, "firm")
    self.assertIn("handshake alone", f.description)
    self.assertEqual(f.evidence, "Accepted credential: ftp:ftp")

  def test_control_accepted_downgrades_the_verdict(self):
    # Two contradictory CRITICALs on one port — "default credential accepted"
    # beside "accepts arbitrary credentials" — is what the client saw.
    f = _default_credential_findings(
      "Telnet", ["admin:admin"], control=CONTROL_ACCEPTED,
      proofs={"admin:admin": "uid=1000(admin)"},
    )[0]
    self.assertEqual(f.severity, Severity.INFO)
    self.assertEqual(f.confidence, "tentative")
    self.assertIn("(inconclusive: service accepts arbitrary credentials)", f.title)
    self.assertIn("accepts arbitrary credentials", f.description)

  def test_a_control_that_did_not_run_caps_confidence_and_says_so(self):
    # A dropped or rate-limited control is not a passed control.
    f = _default_credential_findings(
      "SSH", ["root:toor"], control=CONTROL_NOT_RUN,
      proofs={"root:toor": "exec id -> uid=0(root)"},
    )[0]
    self.assertEqual(f.severity, Severity.CRITICAL)
    self.assertEqual(f.confidence, "firm")
    self.assertIn("control could not be run", f.description)

  def test_no_accepted_pairs_yields_nothing(self):
    self.assertEqual(_default_credential_findings("SSH", [], control=CONTROL_REJECTED), [])
    self.assertEqual(_default_credential_findings("SSH", [], control=CONTROL_ACCEPTED), [])


class TestAuthenticatedActions(unittest.TestCase):

  def test_ssh_action_records_the_command_output(self):
    client = MagicMock()
    stdout = MagicMock()
    stdout.read.return_value = b"uid=0(root) gid=0(root)\n"
    client.exec_command.return_value = (MagicMock(), stdout, MagicMock())
    self.assertEqual(_ssh_authenticated_action(client, 4.5), "exec id -> uid=0(root) gid=0(root)")
    client.exec_command.assert_called_once_with("id", timeout=4.5)

  def test_ssh_action_failure_is_none_not_an_exception(self):
    client = MagicMock()
    client.exec_command.side_effect = paramiko.SSHException("no channel")
    self.assertIsNone(_ssh_authenticated_action(client, 3))

  def test_ftp_action_records_the_working_directory(self):
    ftp = MagicMock()
    ftp.pwd.return_value = "/"
    self.assertEqual(_ftp_authenticated_action(ftp), "PWD -> /")
    ftp.pwd.side_effect = OSError("closed")
    self.assertIsNone(_ftp_authenticated_action(ftp))


class TestSshProbeWiring(unittest.TestCase):
  """The SSH probe feeds its own random-pair test into the verdict."""

  def _worker(self):
    from extensions.business.cybersec.red_mesh.tests.test_probes import DummyOwner
    from extensions.business.cybersec.red_mesh.worker.pentest_worker import PentestLocalWorker
    worker = PentestLocalWorker(
      owner=DummyOwner(), target="example.com", job_id="job-1",
      initiator="init@example", local_id_prefix="1", worker_target_ports=[22],
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return worker

  def _run(self, accept):
    """Run the SSH probe with `accept(username, password) -> bool` deciding logins."""
    commands = self.commands = []
    class DummySocket:
      def __init__(self, *a, **k): pass
      def settimeout(self, t): pass
      def connect(self, addr): pass
      def recv(self, n): return b"SSH-2.0-OpenSSH_9.9p1"
      def close(self): pass

    class DummyClient:
      def set_missing_host_key_policy(self, policy): pass
      def connect(self, target, port, username, password, **kwargs):
        if not accept(username, password):
          raise paramiko.AuthenticationException("rejected")
      def exec_command(self, cmd, timeout=None):
        commands.append(cmd)
        stdout = MagicMock()
        stdout.read.return_value = b"uid=0(root)"
        return MagicMock(), stdout, MagicMock()
      def close(self): pass

    worker = self._worker()
    base = "extensions.business.cybersec.red_mesh.worker.service.common."
    with patch(base + "socket.socket", return_value=DummySocket()), \
         patch(base + "paramiko.Transport", side_effect=OSError("no transport")), \
         patch(base + "paramiko.SSHClient", DummyClient), \
         patch(base + "check_cves", return_value=[]), \
         patch.object(worker, "_ssh_check_ciphers", return_value=([], [])):
      return worker._service_info_ssh("example.com", 22)

  def test_default_pair_accepted_and_random_rejected_stands_as_critical(self):
    result = self._run(lambda user, password: (user, password) == ("root", "root"))
    titles = {f["title"]: f for f in result["findings"]}
    self.assertEqual(result["auth_control"], {"random_credentials": "rejected"})
    self.assertIn("SSH default credential accepted: root:root", titles)
    f = titles["SSH default credential accepted: root:root"]
    self.assertEqual(f["severity"], "CRITICAL")
    self.assertEqual(f["confidence"], "certain")
    self.assertIn("authenticated action: exec id -> uid=0(root)", f["evidence"])
    self.assertNotIn("SSH accepts arbitrary credentials", titles)

  def test_a_dropped_control_is_recorded_as_not_run(self):
    def accept(user, password):
      if user.startswith("probe_"):
        raise OSError("connection reset")   # the control attempt itself failed
      return (user, password) == ("root", "root")
    result = self._run(accept)
    self.assertEqual(result["auth_control"], {"random_credentials": "not_run"})
    f = next(f for f in result["findings"] if f["title"] == "SSH default credential accepted: root:root")
    self.assertEqual(f["severity"], "CRITICAL")
    self.assertEqual(f["confidence"], "firm")

  def test_everything_accepted_downgrades_the_default_pairs(self):
    result = self._run(lambda user, password: True)
    findings = result["findings"]
    self.assertEqual(result["auth_control"], {"random_credentials": "accepted"})
    self.assertTrue(any(f["title"] == "SSH accepts arbitrary credentials" and f["severity"] == "CRITICAL"
                        for f in findings))
    defaults = [f for f in findings if "default credential accepted" in f["title"]]
    self.assertTrue(defaults)
    for f in defaults:
      self.assertEqual(f["severity"], "INFO")
      self.assertIn("(inconclusive", f["title"])


class TestSshActionGate(unittest.TestCase):
  """RM-128: the authenticated action always runs."""

  _worker = TestSshProbeWiring._worker
  _run = TestSshProbeWiring._run

  def test_the_command_always_runs(self):
    self._run(lambda user, password: (user, password) == ("root", "root"))
    self.assertEqual(self.commands, ["id"])


class _FakeFtp:
  """Accepts `ftp:ftp` only; records every PWD."""
  pwd_calls = []

  def __init__(self, *a, **k):
    pass

  def connect(self, *a, **k):
    return "220 test"

  def getwelcome(self):
    return "220 test FTP"

  def login(self, user="", passwd=""):
    if (user, passwd) != ("ftp", "ftp"):
      raise ftplib.error_perm("530 Login incorrect")
    return "230 ok"

  def pwd(self):
    _FakeFtp.pwd_calls.append(True)
    return "/home/ftp"

  def sendcmd(self, cmd):
    raise ftplib.error_perm("502 not implemented")

  def __getattr__(self, name):
    return MagicMock()


class TestFtpActionGate(unittest.TestCase):
  """RM-128: the post-login command always runs."""

  def _run(self):
    _FakeFtp.pwd_calls = []
    worker = TestSshProbeWiring._worker(self)
    base = "extensions.business.cybersec.red_mesh.worker.service.common."
    with patch(base + "ftplib.FTP", _FakeFtp), patch(base + "check_cves", return_value=[]):
      return worker._service_info_ftp("example.com", 21)

  def _default_finding(self, result):
    return next(f for f in result["findings"] if f["title"] == "FTP default credential accepted: ftp:ftp")

  def test_the_command_always_runs(self):
    result = self._run()
    self.assertTrue(_FakeFtp.pwd_calls)
    self.assertIn("authenticated action: PWD -> /home/ftp", self._default_finding(result)["evidence"])


class _FakeAnonymousFtp(_FakeFtp):
  """Accepts anonymous login and uploads; records every STOR."""
  stored = []

  def login(self, user="", passwd=""):
    if user in ("", "anonymous"):
      return "230 anonymous ok"
    return super().login(user, passwd)

  def storbinary(self, cmd, fp, *a, **k):
    _FakeAnonymousFtp.stored.append(cmd)
    return "226 Transfer complete"

  def delete(self, name):
    return "250 ok"


class TestFtpAnonymousWriteGate(unittest.TestCase):
  """RM-128: the anonymous upload test always runs."""

  def _run(self):
    _FakeAnonymousFtp.stored = []
    worker = TestSshProbeWiring._worker(self)
    base = "extensions.business.cybersec.red_mesh.worker.service.common."
    with patch(base + "ftplib.FTP", _FakeAnonymousFtp), patch(base + "check_cves", return_value=[]):
      return worker._service_info_ftp("example.com", 21)

  def test_the_upload_test_always_runs(self):
    result = self._run()
    self.assertEqual(_FakeAnonymousFtp.stored, ["STOR __redmesh_probe.txt"])
    self.assertIn("FTP anonymous write access enabled (file upload possible).",
                  [f["title"] for f in result["findings"]])


class _FakeTelnet:
  """Scripted Telnet server: `root:root` logs in to a root shell; records commands."""
  sent = []

  def __init__(self, *a, **k):
    self._queue = [b"login: "]
    self._user = None
    self._stage = "user"

  def settimeout(self, t):
    pass

  def connect(self, addr):
    pass

  def close(self):
    pass

  def recv(self, n):
    if not self._queue:
      raise socket.timeout()
    return self._queue.pop(0)

  def sendall(self, data):
    line = data.decode().strip()
    if self._stage == "user":
      self._user, self._stage = line, "pass"
      self._queue = [b"Password: "]
    elif self._stage == "pass":
      self._stage = "shell"
      if (self._user, line) == ("root", "root"):
        self._queue = [b"# ", b""]
      else:
        self._queue = [b"Login incorrect\r\n", b""]
    else:
      _FakeTelnet.sent.append(line)
      if line == "id":
        self._queue = [b"uid=0(root) gid=0(root)\r\n"]
      elif line.startswith("uname"):
        self._queue = [b"Linux box 5.15.0\r\n"]


class TestTelnetActionGate(unittest.TestCase):

  def _run(self):
    _FakeTelnet.sent = []
    worker = TestSshProbeWiring._worker(self)
    base = "extensions.business.cybersec.red_mesh.worker.service.common."
    with patch(base + "socket.socket", _FakeTelnet), patch("time.sleep"):
      return worker._service_info_telnet("example.com", 23)

  def test_the_command_always_runs_and_reports_the_root_shell(self):
    result = self._run()
    self.assertEqual(_FakeTelnet.sent, ["id", "uname -a"])
    titles = [f["title"] for f in result["findings"]]
    self.assertIn("Root shell access via Telnet with root:root.", titles)

  def test_the_random_control_never_runs_a_command(self):
    # The control login is only a yes/no question.
    with patch("extensions.business.cybersec.red_mesh.worker.service.common._TELNET_DEFAULT_CREDS", []):
      self._run()
    self.assertEqual(_FakeTelnet.sent, [])


if __name__ == "__main__":
  unittest.main()
