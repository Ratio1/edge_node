"""`authenticated_action`: what happened after an accepted login (RM-118).

The report read this from prose — the `; authenticated action:` evidence marker
and title phrases (RM-117) — so rewording a probe flipped a client-facing
§3.5.2 line with every test green. The probe now states it as a field, at a
closed list of sites: `_default_credential_findings` (FTP, SSH, Telnet, both
variants), the anonymous-FTP login and upload, and the MySQL / PostgreSQL
default-credential findings.
"""

import struct
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin
from extensions.business.cybersec.red_mesh.models.finding_identity import content_hash, dedup_key
from extensions.business.cybersec.red_mesh.models.finding_schema import (
  flat_finding_from_dict, validate_flat_finding,
)
from extensions.business.cybersec.red_mesh.worker.service.common import (
  CONTROL_ACCEPTED, CONTROL_REJECTED, _default_credential_findings,
)

from . import test_default_credential_control as dcc
from .conftest import DummyOwner, PentestLocalWorker


def _actions(result):
  return {f["title"]: f["authenticated_action"] for f in result["findings"]}


class TestDefaultCredentialFindings(unittest.TestCase):

  def _one(self, **kwargs):
    return _default_credential_findings("SSH", ["root:toor"], **kwargs)[0]

  def test_a_proof_is_performed(self):
    f = self._one(control=CONTROL_REJECTED, proofs={"root:toor": "exec id -> uid=0(root)"},
                  action_permitted=True)
    self.assertEqual(f.authenticated_action, "performed")

  def test_permitted_without_a_proof_is_attempted(self):
    self.assertEqual(self._one(control=CONTROL_REJECTED, action_permitted=True).authenticated_action,
                     "attempted")

  def test_withheld_by_the_roe_is_not_permitted(self):
    self.assertEqual(self._one(control=CONTROL_REJECTED, action_permitted=False).authenticated_action,
                     "not_permitted")

  def test_the_inconclusive_variant_follows_the_same_rule(self):
    f = self._one(control=CONTROL_ACCEPTED, proofs={"root:toor": "exec id -> uid=0(root)"},
                  action_permitted=True)
    self.assertIn("inconclusive", f.title)
    self.assertEqual(f.authenticated_action, "performed")


class TestAnonymousFtp(unittest.TestCase):

  def _run(self, permitted):
    dcc._FakeAnonymousFtp.stored = []
    worker = dcc.TestSshProbeWiring._worker(self, permitted)
    base = "extensions.business.cybersec.red_mesh.worker.service.common."
    with patch(base + "ftplib.FTP", dcc._FakeAnonymousFtp), patch(base + "check_cves", return_value=[]):
      return worker._service_info_ftp("example.com", 21)

  def test_login_is_attempted_and_the_upload_performed_when_permitted(self):
    actions = _actions(self._run(True))
    self.assertEqual(actions["FTP allows anonymous login."], "attempted")
    self.assertEqual(actions["FTP anonymous write access enabled (file upload possible)."], "performed")

  def test_login_is_not_permitted_when_the_roe_withholds_the_upload(self):
    actions = _actions(self._run(False))
    self.assertEqual(actions["FTP allows anonymous login."], "not_permitted")


class TestDatabaseLogins(unittest.TestCase):
  """A database login has no RoE-gated action, so `not_applicable`."""

  def _worker(self):
    worker = PentestLocalWorker(
      owner=DummyOwner(), target="db.test", job_id="job-db", initiator="init@example",
      local_id_prefix="1", worker_target_ports=[3306, 5432],
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    worker.state["scan_metadata"] = {}
    return worker

  def test_mysql(self):
    # Handshake v10 with a 20-byte scramble, then an OK packet for every login.
    handshake_payload = b"\x0a" + b"5.7.0\x00" + b"\x01\x00\x00\x00" + b"A" * 8 + b"\x00" + b"\x00" * 19 + b"B" * 12 + b"\x00"
    handshake = struct.pack("<I", len(handshake_payload))[:3] + b"\x00" + handshake_payload
    ok_packet = b"\x07\x00\x00\x02" + b"\x00\x00\x00\x02\x00\x00\x00"
    sock = MagicMock()
    sock.recv.side_effect = [handshake, ok_packet] * 3
    with patch("extensions.business.cybersec.red_mesh.worker.service.database.socket.socket", return_value=sock):
      result = self._worker()._service_info_mysql_creds("db.test", 3306)
    logins = [f for f in result["findings"] if "default credential accepted" in f["title"]]
    self.assertTrue(logins)
    self.assertEqual({f["authenticated_action"] for f in logins}, {"not_applicable"})

  def test_postgresql(self):
    md5_request = b"R" + struct.pack("!I", 12) + struct.pack("!I", 5) + b"\xab\xcd\xef\x01"
    auth_ok = b"R" + struct.pack("!I", 8) + struct.pack("!I", 0)
    calls = [0]

    def fake_recv(_size):
      calls[0] += 1
      return md5_request if calls[0] == 1 else auth_ok

    sock = MagicMock()
    sock.recv = fake_recv
    with patch("extensions.business.cybersec.red_mesh.worker.service.database.socket.socket", return_value=sock):
      result = self._worker()._service_info_postgresql_creds("db.test", 5432)
    logins = [f for f in result["findings"] if "default credential accepted" in f["title"]]
    self.assertTrue(logins)
    self.assertEqual({f["authenticated_action"] for f in logins}, {"not_applicable"})


class TestTheFieldInTheContract(unittest.TestCase):

  def _flat(self, action):
    return {
      "finding_id": "a" * 16, "title": "SSH default credential accepted: root:toor",
      "severity": "CRITICAL", "confidence": "certain", "probe": "_service_info_ssh",
      "category": "service", "port": 22,
      "evidence": "Accepted credential: root:toor; authenticated action: exec id -> uid=0(root)",
      "authenticated_action": action,
    }

  def test_it_survives_redaction_and_the_archive_read(self):
    report = {"service_info": {"22": {"_service_info_ssh": {"findings": [self._flat("performed")]}}}}
    redacted = _ReportMixin()._redact_report(report)
    finding = redacted["service_info"]["22"]["_service_info_ssh"]["findings"][0]
    self.assertNotIn("toor", finding["evidence"])
    self.assertEqual(finding["authenticated_action"], "performed")
    self.assertEqual(flat_finding_from_dict(finding).authenticated_action, "performed")
    self.assertEqual(flat_finding_from_dict(finding).to_dict()["authenticated_action"], "performed")

  def test_an_unknown_value_is_reported_not_raised(self):
    self.assertIn("authenticated_action is invalid: yes", validate_flat_finding(self._flat("yes")))
    self.assertEqual(validate_flat_finding(self._flat("attempted")), [])
    self.assertEqual(validate_flat_finding(self._flat("")), [])
    flat_finding_from_dict(self._flat("yes"))  # still readable

  def test_it_moves_neither_identity_nor_signature(self):
    a, b = self._flat("performed"), self._flat("not_permitted")
    self.assertEqual(dedup_key(a), dedup_key(b))
    self.assertEqual(content_hash(a), content_hash(b))


if __name__ == "__main__":
  unittest.main()
