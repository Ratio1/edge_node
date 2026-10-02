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

Deterministic: `random` is seeded, no scan-local NVD cache is active, the CVE
path is the static database, and keys are sorted.
"""

import json
import pathlib
import random
import struct
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.cve_db import check_cves, parse_distro_package
from extensions.business.cybersec.red_mesh.findings import probe_port_scope, probe_result
from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin
from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin
from extensions.business.cybersec.red_mesh.worker.service.common import (
  CONTROL_ACCEPTED, CONTROL_REJECTED, _default_credential_findings,
)

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


def _ssh():
  """Default-credential findings over SSH: performed, attempted, not permitted,
  and the inconclusive variant (a service that accepts any pair)."""
  with probe_port_scope(22):
    findings = (
      _default_credential_findings("SSH", ["root:toor"], control=CONTROL_REJECTED,
                                   proofs={"root:toor": _SSH_PROOF}, action_permitted=True)
      + _default_credential_findings("SSH", ["admin:admin"], control=CONTROL_REJECTED,
                                     action_permitted=True)
      + _default_credential_findings("SSH", ["pi:raspberry"], control=CONTROL_REJECTED,
                                     action_permitted=False)
      + _default_credential_findings("SSH", ["user:user"], control=CONTROL_ACCEPTED,
                                     action_permitted=True)
      + check_cves("openssh", "8.2p1",
                   package=parse_distro_package("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1"))
    )
    return probe_result(findings=findings, probe_id="_service_info_ssh")


def _ftp():
  import ftplib
  from extensions.business.cybersec.red_mesh.tests import test_default_credential_control as dcc

  class _FixtureFtp(dcc._FakeAnonymousFtp):
    """Anonymous login, upload and `ftp:ftp` accepted; directory changes refused,
    so no MagicMock reaches a finding's evidence."""
    def cwd(self, _path):
      raise ftplib.error_perm("550 Permission denied")

  dcc._FakeAnonymousFtp.stored = []
  base = "extensions.business.cybersec.red_mesh.worker.service.common."
  with patch(base + "ftplib.FTP", _FixtureFtp), patch(base + "check_cves", return_value=[]), \
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


def _only_findings(result):
  return {"findings": result["findings"]}


def build():
  """The fixture as a dict: flat findings plus one catch-all-withheld record."""
  random.seed(118)
  report = {
    "target": TARGET,
    "port_protocols": {"21": "ftp", "22": "ssh", "80": "http", "3306": "mysql"},
    "service_info": {
      "21": {"_service_info_ftp": _only_findings(_ftp())},
      "22": {"_service_info_ssh": _only_findings(_ssh())},
      "3306": {"_service_info_mysql_creds": _only_findings(_mysql())},
    },
    "web_tests_info": {
      "80": {"_web_test_csrf": _only_findings(_csrf())},
    },
  }
  host = _Host()
  redacted = host._redact_report(report)
  _risk, flat = host._compute_risk_and_findings(redacted)
  flat = sorted(flat, key=lambda f: (f["probe"], f["port"], f["title"], f["finding_id"]))
  return {
    "schemaVersion": SCHEMA_VERSION,
    "target": TARGET,
    "findings": flat,
    "catchAllWithheld": {f"http://{TARGET}": [{"path": "/admin", "probe": "_web_test_common"}]},
  }


def render(fixture=None):
  return json.dumps(build() if fixture is None else fixture, indent=2, sort_keys=True) + "\n"
