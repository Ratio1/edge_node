"""Generator for the report-findings contract fixture (RM-118).

The Navigator report reads backend finding shapes and strings, and each repo
used to test against its own hand-written fixtures, so a backend change could
break the client report with both suites green. This builds one fixture from
real probe output, in production order — `probe_result`, then `_redact_report`
with the default `redact_credentials`, then the flat walk — so it is the
redacted default a report actually receives. Canonical copy:
`docs/resources/redmesh/contracts/fixtures/report-findings.v1.json` in the hub,
with byte-identical copies here and in Navigator (contract note
`docs/resources/redmesh/contracts/report-findings.md`).

Deterministic: `random` is seeded inside `build()` and the global state restored
after, the scan-local NVD cache is pinned to none, the CVE path is the static
database, the fake services return fixed strings, and keys are sorted.
"""

import ftplib
import json
import pathlib
import random
import struct
from unittest.mock import MagicMock, patch

import paramiko

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.findings import probe_port_scope
from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin
from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

FIXTURE_PATH = pathlib.Path(__file__).resolve().parent / "report-findings.v1.json"
TARGET = "198.51.100.20"  # RFC 5737 documentation address
SCHEMA_VERSION = 1

_SSH_PROOF = "exec id -> uid=0(root) gid=0(root)"


class _Host(_ReportMixin, _RiskScoringMixin):
  pass


def _worker(ports, authenticated_action=True):
  from extensions.business.cybersec.red_mesh.tests.conftest import DummyOwner, PentestLocalWorker
  worker = PentestLocalWorker(
    owner=DummyOwner(), target=TARGET, job_id="fixture", initiator="fixture@example",
    local_id_prefix="1", worker_target_ports=ports, authenticated_action=authenticated_action,
  )
  worker.stop_event = MagicMock()
  worker.stop_event.is_set.return_value = False
  worker.state["scan_metadata"] = {}
  return worker


def _csrf():
  page = (
    '<html><body>'
    '<form method="POST" action="/users/sign_in"><input type="text" name="user"></form>'
    '<form method="POST" action="/users?ref=nav"><input type="text" name="email"></form>'
    '</body></html>'
  )

  def fake_get(url, **_kwargs):
    resp = MagicMock()
    resp.status_code = 200 if url.endswith(TARGET) or url.endswith(TARGET + "/") else 404
    resp.text = page
    resp.headers = {}
    return resp

  with patch("requests.get", side_effect=fake_get), probe_port_scope(80):
    return _worker([80])._web_test_csrf(TARGET, 80)


_COMMON = "extensions.business.cybersec.red_mesh.worker.service.common."


def _ssh(port, banner, accept, outputs, *, authenticated_action, cves=True):
  """The real SSH probe against a fake server.

  `accept(user, password)` decides logins; `outputs[user]` is what `id` prints
  for that user's session (b"" means the action completed nothing).
  """
  class _Socket:
    def __init__(self, *a, **k): pass
    def settimeout(self, t): pass
    def connect(self, addr): pass
    def recv(self, n): return banner
    def close(self): pass

  class _Client:
    def __init__(self): self.user = None
    def set_missing_host_key_policy(self, policy): pass
    def connect(self, target, port, username, password, **kwargs):
      if not accept(username, password):
        raise paramiko.AuthenticationException("rejected")
      self.user = username
    def exec_command(self, cmd, timeout=None):
      stdout = MagicMock()
      stdout.read.return_value = outputs.get(self.user, b"")
      return MagicMock(), stdout, MagicMock()
    def close(self): pass

  worker = _worker([port], authenticated_action)
  extra = [] if cves else [patch(_COMMON + "check_cves", return_value=[])]
  with patch(_COMMON + "socket.socket", return_value=_Socket()), \
       patch(_COMMON + "paramiko.Transport", side_effect=OSError("no transport")), \
       patch(_COMMON + "paramiko.SSHClient", _Client), \
       patch.object(worker, "_ssh_check_ciphers", return_value=([], [])), \
       probe_port_scope(port):
    for p in extra:
      p.start()
    try:
      return worker._service_info_ssh(TARGET, port)
    finally:
      for p in extra:
        p.stop()


class _FixtureFtp:
  """Accepts anonymous and `ftp:ftp`; uploads succeed; directory changes are
  refused, so no MagicMock repr reaches a finding's evidence."""

  def __init__(self, *a, **k): pass
  def connect(self, *a, **k): return "220 fixture"
  def getwelcome(self): return "220 fixture FTP"
  def login(self, user="", passwd=""):
    if user in ("", "anonymous") or (user, passwd) == ("ftp", "ftp"):
      return "230 ok"
    raise ftplib.error_perm("530 Login incorrect")
  def pwd(self): return "/home/ftp"
  def sendcmd(self, cmd): raise ftplib.error_perm("502 not implemented")
  def cwd(self, _path): raise ftplib.error_perm("550 Permission denied")
  def storbinary(self, cmd, fp, *a, **k): return "226 Transfer complete"
  def delete(self, name): return "250 ok"
  def __getattr__(self, name): return MagicMock(return_value="")


def _ftp():
  with patch(_COMMON + "ftplib.FTP", _FixtureFtp), patch(_COMMON + "check_cves", return_value=[]), \
       probe_port_scope(21):
    return _worker([21])._service_info_ftp(TARGET, 21)


def _mysql():
  payload = b"\x0a" + b"5.7.0\x00" + b"\x01\x00\x00\x00" + b"A" * 8 + b"\x00" + b"\x00" * 19 + b"B" * 12 + b"\x00"
  handshake = struct.pack("<I", len(payload))[:3] + b"\x00" + payload
  ok_packet = b"\x07\x00\x00\x02" + b"\x00\x00\x00\x02\x00\x00\x00"
  sock = MagicMock()
  sock.recv.side_effect = [handshake, ok_packet] * 3
  with patch("extensions.business.cybersec.red_mesh.worker.service.database.socket.socket", return_value=sock), \
       probe_port_scope(3306):
    return _worker([3306])._service_info_mysql_creds(TARGET, 3306)


def _catch_all_withheld():
  """The backend's own record of a status-only check withheld on a catch-all host."""
  worker = _worker([80])
  worker._withhold_on_catch_all(f"http://{TARGET}", "_web_test_common", "/admin")
  return worker.state["catch_all_withheld"]


def _only_findings(result):
  return {"findings": result["findings"]}


def build():
  """The fixture as a dict: flat findings plus the backend's catch-all record."""
  saved_random = random.getstate()
  cache_token = cve_db._CURRENT_DYNAMIC_CACHE.set(None)
  random.seed(118)
  try:
    report = {
      "target": TARGET,
      "port_protocols": {"21": "ftp", "22": "ssh", "2222": "ssh", "2022": "ssh", "80": "http", "3306": "mysql"},
      "service_info": {
        "21": {"_service_info_ftp": _only_findings(_ftp())},
        # RoE permits the action: root's `id` returns output (performed), admin's
        # returns nothing (attempted). The banner is a distribution package, so
        # the CVE carries `backport_status`.
        "22": {"_service_info_ssh": _only_findings(_ssh(
          22, b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1",
          lambda u, p: (u, p) in {("root", "toor"), ("admin", "admin")},
          {"root": b"uid=0(root) gid=0(root)"}, authenticated_action=True))},
        # RoE withholds the action.
        "2222": {"_service_info_ssh": _only_findings(_ssh(
          2222, b"SSH-2.0-OpenSSH_9.9p1", lambda u, p: (u, p) == ("root", "root"),
          {}, authenticated_action=False, cves=False))},
        # A service that accepts any pair: the inconclusive variant.
        "2022": {"_service_info_ssh": _only_findings(_ssh(
          2022, b"SSH-2.0-OpenSSH_9.9p1", lambda u, p: True,
          {}, authenticated_action=False, cves=False))},
        "3306": {"_service_info_mysql_creds": _only_findings(_mysql())},
      },
      "web_tests_info": {
        "80": {"_web_test_csrf": _only_findings(_csrf())},
      },
    }
    catch_all = _catch_all_withheld()
  finally:
    cve_db._CURRENT_DYNAMIC_CACHE.reset(cache_token)
    random.setstate(saved_random)
  host = _Host()
  redacted = host._redact_report(report)
  _risk, flat = host._compute_risk_and_findings(redacted)
  flat = sorted(flat, key=lambda f: (f["probe"], f["port"], f["title"], f["finding_id"]))
  return {
    "schemaVersion": SCHEMA_VERSION,
    "target": TARGET,
    "findings": flat,
    "catch_all_withheld": catch_all,
  }


def render(fixture=None):
  return json.dumps(build() if fixture is None else fixture, indent=2, sort_keys=True) + "\n"
