"""RM-200 phase 2: banner authenticity, KEXINIT-based SSH audit, Terrapin, KEV suppression, correlation."""

import struct
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.cve_view import build_cve_view, effective_kev
from extensions.business.cybersec.red_mesh.vulndb.reader import load_vulndb
from extensions.business.cybersec.red_mesh.worker.service import common
from extensions.business.cybersec.red_mesh.worker.service.common import (
  _parse_ssh_kexinit, _smtp_banner_verdict, _ssh_banner_verdict, _ssh_read_kexinit, _ssh_terrapin,
)

from .test_probes import DummyOwner
from .test_vulndb_findings import build
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker

BASE = "extensions.business.cybersec.red_mesh.worker.service.common."


def kex(**kw):
  """A KEXINIT dict with empty lists, overridden by `kw`."""
  out = {f: [] for f in common._KEXINIT_FIELDS}
  out.update(kw)
  return out


# T-Pot ground truth (2026-11-17): cowrie announces dropbear 2017.75.
COWRIE = kex(
  kex=["curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384",
       "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1",
       "diffie-hellman-group14-sha1"],
  host_key=["ssh-rsa", "ecdsa-sha2-nistp256"],
  enc_c2s=["aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc"],
  enc_s2c=["aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc"],
  mac_c2s=["hmac-sha2-512", "hmac-sha2-384", "hmac-sha2-56", "hmac-sha1", "hmac-md5"],
  mac_s2c=["hmac-sha2-512", "hmac-sha2-384", "hmac-sha2-56", "hmac-sha1", "hmac-md5"],
)
# Port 222: real OpenSSH 8.9p1 on Ubuntu 22.04 with the Terrapin patch (3ubuntu0.5 and later).
_OPENSSH_MACS = ["umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
                 "hmac-sha2-512-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64@openssh.com",
                 "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1"]
_OPENSSH_CIPHERS = ["chacha20-poly1305@openssh.com", "aes128-ctr", "aes192-ctr", "aes256-ctr",
                    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com"]
OPENSSH_89 = kex(
  kex=["sntrup761x25519-sha512@openssh.com", "curve25519-sha256", "curve25519-sha256@libssh.org",
       "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256",
       "diffie-hellman-group16-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group14-sha256",
       "ext-info-s", "kex-strict-s-v00@openssh.com"],
  host_key=["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"],
  enc_c2s=_OPENSSH_CIPHERS, enc_s2c=_OPENSSH_CIPHERS, mac_c2s=_OPENSSH_MACS, mac_s2c=_OPENSSH_MACS,
)
# Real Dropbear 2022.83: kexguess2, no group exchange.
DROPBEAR = kex(
  kex=["curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp521", "diffie-hellman-group14-sha256",
       "diffie-hellman-group14-sha1", "kexguess2@matt.ucc.asn.au"],
  host_key=["ssh-ed25519", "ssh-rsa"],
  enc_c2s=["aes128-ctr", "aes256-ctr"], enc_s2c=["aes128-ctr", "aes256-ctr"],
  mac_c2s=["hmac-sha1", "hmac-sha2-256"], mac_s2c=["hmac-sha1", "hmac-sha2-256"],
)
# Mailoney's EHLO reply (ground truth); real Exim ends with HELP.
MAILONEY_EHLO = ["mail.example Hello probe.redmesh.local [1.2.3.4]", "SIZE 52428800", "AUTH LOGIN PLAIN"]
EXIM_EHLO = ["mail.example Hello probe [1.2.3.4]", "SIZE 52428800", "8BITMIME", "PIPELINING", "HELP"]


def packet(lists, msg=20, pad=6):
  """An unencrypted SSH binary packet carrying `lists`, as a server sends it."""
  payload = bytes([msg]) + b"\x00" * 16
  for field in common._KEXINIT_FIELDS:
    text = ",".join(lists[field]).encode()
    payload += struct.pack(">I", len(text)) + text
  payload += b"\x00" + struct.pack(">I", 0)  # first_kex_packet_follows, reserved
  body = bytes([pad]) + payload + b"\x00" * pad
  return struct.pack(">I", len(body)) + body


class FakeSock:
  def __init__(self, data, fail_connect=False):
    self.data, self.sent, self.fail_connect, self.closed = data, b"", fail_connect, False

  def settimeout(self, t): pass

  def connect(self, addr):
    if self.fail_connect:
      raise OSError("refused")

  def sendall(self, b): self.sent += b

  def recv(self, n):
    chunk, self.data = self.data[:n], self.data[n:]
    return chunk

  def close(self): self.closed = True


class KexinitReaderTests(unittest.TestCase):
  def test_parse_round_trip(self):
    self.assertEqual(_parse_ssh_kexinit(packet(COWRIE)[4:]), COWRIE)

  def test_parse_rejects_other_message_and_truncation(self):
    self.assertIsNone(_parse_ssh_kexinit(packet(COWRIE, msg=21)[4:]))
    self.assertIsNone(_parse_ssh_kexinit(packet(COWRIE)[4:40]))
    self.assertIsNone(_parse_ssh_kexinit(b""))

  def read(self, data, **kw):
    sock = FakeSock(data, **kw)
    with patch(BASE + "socket.socket", return_value=sock):
      return _ssh_read_kexinit("t", 22, 1), sock

  def test_reads_lists_after_identification_and_sends_only_an_identification(self):
    got, sock = self.read(b"welcome\r\nSSH-2.0-dropbear_2017.75\r\n" + packet(COWRIE))
    self.assertEqual(got, COWRIE)
    self.assertEqual(sock.sent, b"SSH-2.0-RedMesh_Probe\r\n")
    self.assertTrue(sock.closed)

  def test_none_on_error_oversize_and_no_identification(self):
    self.assertIsNone(self.read(b"", fail_connect=True)[0])
    self.assertIsNone(self.read(b"SSH-2.0-x\r\n" + struct.pack(">I", 35001) + b"x" * 40)[0])
    self.assertIsNone(self.read(b"SSH-2.0-x\r\n")[0])  # closes before a packet
    self.assertIsNone(self.read(b"HTTP/1.1 400 Bad\r\n" * 25)[0])  # never an SSH identification


class VerdictTests(unittest.TestCase):
  def test_cowrie_posing_as_dropbear_is_unverified(self):
    verified, why = _ssh_banner_verdict("dropbear", COWRIE)
    self.assertIs(verified, False)
    self.assertIn("kexguess2@matt.ucc.asn.au", why)

  def test_dropbear_with_group_exchange_is_unverified_even_with_kexguess(self):
    odd = kex(kex=["kexguess2@matt.ucc.asn.au", "diffie-hellman-group-exchange-sha256"])
    verified, why = _ssh_banner_verdict("dropbear", odd)
    self.assertIs(verified, False)
    self.assertIn("diffie-hellman-group-exchange-sha256", why)

  def test_real_dropbear_is_verified(self):
    self.assertEqual(_ssh_banner_verdict("dropbear", DROPBEAR), (True, ""))

  def test_openssh_is_verified_by_default_and_no_kexinit_is_unassessed(self):
    self.assertEqual(_ssh_banner_verdict("openssh", OPENSSH_89), (True, ""))
    self.assertEqual(_ssh_banner_verdict("openssh", COWRIE), (True, ""))  # no unconfigurable OpenSSH invariant
    self.assertEqual(_ssh_banner_verdict("dropbear", None), (None, ""))

  def test_mailoney_exim_is_unverified_real_exim_verified(self):
    verified, why = _smtp_banner_verdict("exim", MAILONEY_EHLO)
    self.assertIs(verified, False)
    self.assertIn("HELP", why)
    self.assertEqual(_smtp_banner_verdict("exim", EXIM_EHLO), (True, ""))

  def test_smtp_unjudged_without_ehlo_and_other_mtas_not_assessable(self):
    self.assertEqual(_smtp_banner_verdict("exim", []), (None, ""))
    # Only Exim has a check (owner ruling 2026-11-17); other MTAs keep their confidence, with or without EHLO.
    self.assertEqual(_smtp_banner_verdict("postfix", MAILONEY_EHLO), (cve_db.BANNER_NOT_ASSESSABLE, ""))
    self.assertEqual(_smtp_banner_verdict("opensmtpd", []), (cve_db.BANNER_NOT_ASSESSABLE, ""))


class TerrapinKexinitTests(unittest.TestCase):
  def test_vulnerable_chacha_without_strict(self):
    odd = kex(enc_s2c=["chacha20-poly1305@openssh.com"], kex=["curve25519-sha256"])
    vulnerable, evidence = _ssh_terrapin(odd)
    self.assertIs(vulnerable, True)
    self.assertIn("chacha20-poly1305@openssh.com", evidence)

  def test_vulnerable_cbc_with_etm_without_strict(self):
    odd = kex(enc_c2s=["aes128-cbc"], mac_c2s=["hmac-sha2-256-etm@openssh.com"])
    self.assertIs(_ssh_terrapin(odd)[0], True)

  def test_strict_kex_clears(self):
    self.assertIs(_ssh_terrapin(OPENSSH_89)[0], False)  # chacha offered, but strict KEX present

  def test_neither_mode_clears_cowrie(self):
    self.assertIs(_ssh_terrapin(COWRIE)[0], False)  # CBC without any -etm MAC
    self.assertIs(_ssh_terrapin(DROPBEAR)[0], False)

  def test_no_kexinit_is_unknown(self):
    self.assertEqual(_ssh_terrapin(None), (None, ""))


def worker(port=22):
  w = PentestLocalWorker(owner=DummyOwner(), target="example.com", job_id="j", initiator="i@e",
                         local_id_prefix="1", worker_target_ports=[port])
  w.stop_event = MagicMock()
  w.stop_event.is_set.return_value = False
  return w


class CipherAuditTests(unittest.TestCase):
  def audit(self, kexinit):
    w = worker()
    with patch(BASE + "paramiko.Transport", side_effect=OSError("no transport")):
      return w._ssh_check_ciphers("example.com", 22, kexinit)

  def titles(self, kexinit):
    return [f.title for f in self.audit(kexinit)[0]]

  def test_persona_openssh_offers_no_cbc_so_no_weak_cipher_finding(self):
    self.assertEqual(self.titles(OPENSSH_89), [])

  def test_cowrie_still_reports_its_cbc_ciphers_and_sha1_kex(self):
    titles = self.titles(COWRIE)
    self.assertIn("SSH weak ciphers: 3des-cbc, aes128-cbc", titles)
    self.assertTrue(any(t.startswith("SSH weak key exchange:") for t in titles))

  def test_no_kexinit_means_no_cipher_kex_or_dsa_finding_never_paramiko_defaults(self):
    class Opts:  # paramiko's client preference list: includes CBC, 3des and ssh-dss
      ciphers = ["3des-cbc", "aes128-cbc"]
      kex = ["diffie-hellman-group1-sha1"]
      key_types = ["ssh-dss"]

    class T:
      def __init__(self, *a, **k): pass
      def connect(self): pass
      def get_security_options(self): return Opts()
      def get_remote_server_key(self): return None
      def close(self): pass

    w = worker()
    with patch(BASE + "paramiko.Transport", return_value=T()):
      findings, labels = w._ssh_check_ciphers("example.com", 22, None)
    self.assertEqual((findings, labels), ([], []))

  def test_dsa_host_key_read_from_kexinit(self):
    findings, labels = self.audit(kex(host_key=["ssh-dss", "ssh-rsa"]))
    self.assertEqual([f.title for f in findings], ["SSH DSA host key offered (ssh-dss)"])
    self.assertEqual(labels, ["key_types: ssh-dss"])

  def test_client_to_server_only_cbc_is_not_reported(self):
    self.assertEqual(self.titles(kex(enc_c2s=["aes128-cbc"], enc_s2c=["aes128-ctr"])), [])


class SshProbeWiringTests(unittest.TestCase):
  """`_service_info_ssh` with the banner, KEXINIT and CVE matcher stubbed."""

  def run_probe(self, banner, kexinit, cve_rows=(), package_banner=None):
    w = worker()

    class Sock:
      def settimeout(self, t): pass
      def connect(self, a): pass
      def recv(self, n): return (package_banner or banner).encode()
      def close(self): pass

    calls = []

    def fake_check(product, version, **kw):
      calls.append((product, version, kw))
      return list(cve_rows)

    with patch(BASE + "socket.socket", return_value=Sock()), \
         patch(BASE + "paramiko.Transport", side_effect=OSError("x")), \
         patch(BASE + "paramiko.SSHClient", side_effect=OSError("x")), \
         patch(BASE + "_ssh_read_kexinit", return_value=kexinit), \
         patch(BASE + "check_cves", side_effect=fake_check):
      result = w._service_info_ssh("example.com", 22)
    return w, result, calls

  def test_cowrie_dropbear_banner_is_unverified_and_reaches_correlation(self):
    w, result, calls = self.run_probe("SSH-2.0-dropbear_2017.75", COWRIE)
    self.assertIs(calls[0][2]["banner_verified"], False)
    self.assertIs(result["banner_verified"], False)
    self.assertIn("ssh:22", w.state["scan_metadata"]["banner_unverified"])
    w._post_scan_correlate()
    titles = [f["title"] for f in w.state["correlation_findings"]]
    self.assertIn("Honeypot indicator: service banner contradicted by protocol behaviour", titles)

  def test_real_dropbear_verified_and_no_correlation_finding(self):
    w, result, calls = self.run_probe("SSH-2.0-dropbear_2022.83", DROPBEAR)
    self.assertIs(calls[0][2]["banner_verified"], True)
    w._post_scan_correlate()
    self.assertEqual([f for f in w.state["correlation_findings"] if "banner" in f["title"]], [])

  def test_unreadable_kexinit_is_unassessed_not_unverified(self):
    w, result, calls = self.run_probe("SSH-2.0-dropbear_2017.75", None)
    self.assertIsNone(calls[0][2]["banner_verified"])
    self.assertNotIn("banner_unverified", w.state["scan_metadata"])

  def test_terrapin_cleared_banner_row_moves_to_not_applicable(self):
    row = cve_db.check_cves("openssh", "8.9")[0]
    row = cve_db.replace(row, title="CVE-2023-48795: Terrapin (openssh 8.9)", cve=("CVE-2023-48795",))
    collector = {}
    token = cve_db.set_not_applicable_collector(collector)
    try:
      w, result, _ = self.run_probe("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", OPENSSH_89, cve_rows=[row])
    finally:
      cve_db.reset_not_applicable_collector(token)
    self.assertEqual([f for f in result["findings"] if "CVE-2023-48795" in f["title"]], [])
    self.assertEqual([r["reason"] for r in collector.values()], ["behaviour_cleared"])
    self.assertEqual(list(collector.values())[0]["cve_id"], "CVE-2023-48795")

  def test_terrapin_vulnerable_banner_row_becomes_certain_with_evidence(self):
    row = cve_db.check_cves("openssh", "8.9")[0]
    row = cve_db.replace(row, title="CVE-2023-48795: Terrapin (openssh 8.9)", cve=("CVE-2023-48795",))
    vulnerable = kex(enc_s2c=["chacha20-poly1305@openssh.com"], kex=["curve25519-sha256"])
    w, result, _ = self.run_probe("SSH-2.0-OpenSSH_8.9p1", vulnerable, cve_rows=[row])
    [f] = [f for f in result["findings"] if "CVE-2023-48795" in f["title"]]
    self.assertEqual(f["confidence"], "certain")
    self.assertIn("chacha20-poly1305@openssh.com", f["evidence"])
    self.assertEqual(f["cve"], ["CVE-2023-48795"])

  def test_terrapin_vulnerable_without_banner_row_adds_certain_finding(self):
    vulnerable = kex(enc_s2c=["chacha20-poly1305@openssh.com"], kex=["curve25519-sha256"])
    w, result, _ = self.run_probe("SSH-2.0-OpenSSH_9.0", vulnerable)
    [f] = [f for f in result["findings"] if "CVE-2023-48795" in f["title"]]
    self.assertEqual((f["confidence"], f["cve"]), ("certain", ["CVE-2023-48795"]))
    self.assertIn("kev", f)  # probe_cve_fields spread


class SmtpProbeWiringTests(unittest.TestCase):
  def run_probe(self, ehlo_lines):
    w = worker(25)
    calls = []

    class SMTP:
      def __init__(self, timeout=5): pass
      def connect(self, t, p): return (220, b"mail ESMTP Exim 4.97 Mon, 17 Nov 2026 01:00:00 -0700")
      def ehlo(self, identity): return (250, "\n".join(ehlo_lines).encode())
      def docmd(self, cmd): return (500, b"no")
      def quit(self): pass

    def fake_check(product, version, **kw):
      calls.append((product, version, kw))
      return []

    with patch("smtplib.SMTP", SMTP), patch(BASE + "check_cves", side_effect=fake_check):
      w._service_info_smtp("example.com", 25)
    return w, calls

  def test_mailoney_exim_is_unverified_and_emitted(self):
    w, calls = self.run_probe(MAILONEY_EHLO)
    self.assertIs(calls[0][2]["banner_verified"], False)
    self.assertIn("smtp:25", w.state["scan_metadata"]["banner_unverified"])

  def test_real_exim_is_verified(self):
    w, calls = self.run_probe(EXIM_EHLO)
    self.assertIs(calls[0][2]["banner_verified"], True)


class ConfidenceTests(unittest.TestCase):
  def setUp(self):
    self.addCleanup(cve_db.set_vulndb_reader, None)

  def use(self, rows):
    from .test_vulndb_reader import make_db
    import hashlib, json, sqlite3
    from pathlib import Path
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    db, pin = Path(tmp.name) / "v.sqlite", Path(tmp.name) / "v.json"
    make_db(db, rows=rows, build_id="vulndb-aaaaaaaaaaaa")
    conn = sqlite3.connect(db)
    conn.executescript("CREATE TABLE cvss(cve_id TEXT, version TEXT, vector TEXT, score REAL, source TEXT);"
                       "CREATE TABLE eol(product TEXT PRIMARY KEY, oldest_supported TEXT);")
    conn.commit(); conn.close()
    pin.write_text(json.dumps({"build_id": "vulndb-aaaaaaaaaaaa", "built_at": "2026-11-14",
                               "sha256_sqlite": hashlib.sha256(db.read_bytes()).hexdigest()}))
    reader, keys = load_vulndb("generated", db, pin)
    self.assertIsNone(keys["vulndb_load_error"])
    cve_db.set_vulndb_reader(reader)

  ROWS = [
    ("CVE-2030-0002", "dropbear", "<2018.76", "curated", "firm", "curated", 0, 0),
    ("CVE-2030-0003", "dropbear", "<2018.76", "nvd", "firm", "nvd_range", 0, 0),
    ("CVE-2030-0004", "dropbear", "<2018.76", "nvd", "tentative", "nvd_exact", 0, 0),
  ]

  def got(self, **kw):
    return {f.cve[0]: (f.confidence, f.confidence_reason) for f in cve_db.check_cves("dropbear", "2017.75", **kw)}

  def test_generated_curated_firm_only_on_verified_banner(self):
    self.use(self.ROWS)
    self.assertEqual(self.got(banner_verified=True)["CVE-2030-0002"], ("firm", "curated"))
    self.assertEqual(self.got(banner_verified=None)["CVE-2030-0002"], ("tentative", "banner_only"))
    self.assertEqual(self.got(banner_verified=None)["CVE-2030-0003"], ("tentative", "banner_only"))
    self.assertEqual(self.got(banner_verified=None)["CVE-2030-0004"], ("tentative", "nvd_exact"))

  def test_generated_service_without_an_authenticity_check_is_unchanged(self):
    self.use(self.ROWS)
    self.assertEqual(self.got()["CVE-2030-0002"], ("firm", "curated"))

  def test_generated_unverified_makes_every_row_tentative_banner_unverified(self):
    self.use(self.ROWS)
    self.assertEqual(set(self.got(banner_verified=False).values()), {("tentative", "banner_unverified")})

  def test_unverified_wins_over_platform_dependent_and_distro_package(self):
    self.use([("CVE-2030-0005", "dropbear", "<2018.76", "nvd", "firm", "nvd_range", 1, 0)])
    self.assertEqual(self.got(banner_verified=False)["CVE-2030-0005"], ("tentative", "banner_unverified"))
    self.assertEqual(self.got(banner_verified=True)["CVE-2030-0005"], ("tentative", "platform_dependent"))
    self.use([("CVE-2030-0006", "openssh", "<9.8", "nvd", "firm", "nvd_range", 0, 0)])
    package = cve_db.parse_distro_package("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
    with patch.dict(cve_db.BACKPORT_FIXES, {("openssh", "ubuntu"): {"CVE-2030-0006": (("8.9p1", "3ubuntu0.10", "USN-x"),)}}):
      firm = cve_db.check_cves("openssh", "8.9", package=package, banner_verified=True)[0]
      bad = cve_db.check_cves("openssh", "8.9", package=package, banner_verified=False)[0]
    self.assertEqual((firm.confidence, firm.confidence_reason), ("firm", "distro_package"))
    self.assertEqual((bad.confidence, bad.confidence_reason), ("tentative", "banner_unverified"))

  def test_static_unverified_tentative_and_verified_or_unassessed_unchanged(self):
    expected = {f.cve[0]: (f.confidence, f.confidence_reason) for f in cve_db.check_cves("dropbear", "2017.75")}
    for verified in (True, None):
      self.assertEqual({f.cve[0]: (f.confidence, f.confidence_reason)
                        for f in cve_db.check_cves("dropbear", "2017.75", banner_verified=verified)}, expected)
    unverified = cve_db.check_cves("dropbear", "2017.75", banner_verified=False)
    self.assertTrue(unverified)
    self.assertEqual({(f.confidence, f.confidence_reason) for f in unverified}, {("tentative", "banner_unverified")})

  def test_clear_cve_records_not_applicable_and_keeps_other_rows(self):
    rows = cve_db.check_cves("dropbear", "2017.75")
    target = rows[0]
    cve_id = target.cve[0]
    collector = {}
    token = cve_db.set_not_applicable_collector(collector)
    try:
      kept = cve_db.clear_cve(rows, cve_id, "dropbear", "2017.75", None, cve_db.NOT_APPLICABLE_BEHAVIOUR_CLEARED)
    finally:
      cve_db.reset_not_applicable_collector(token)
    self.assertEqual(len(kept), len(rows) - 1)
    [rec] = collector.values()
    self.assertEqual((rec["cve_id"], rec["reason"]), (cve_id, "behaviour_cleared"))
    self.assertEqual(rec["title"], target.title)


def view_row(n, *, confidence, reason, kev):
  cve = "CVE-2030-%04d" % n
  return {"finding_id": "id%04d" % n, "cve": [cve], "port": 22, "confidence": confidence,
          "confidence_reason": reason, "kev": kev, "cvss_score": 9.8, "cvss_version": "3.1", "cvss_source": "nvd",
          "epss_score": 0.1, "vulndb_build_id": "b1", "cvss": [],
          "evidence": "Detected version: 1, affected: <2", "description": "dropbear 1 is vulnerable to %s. x" % cve}


class KevSuppressionTests(unittest.TestCase):
  def test_effective_kev(self):
    for reason in ("platform_dependent", "banner_unverified", "local_vector"):
      self.assertFalse(effective_kev(view_row(1, confidence="tentative", reason=reason, kev=True)), reason)
    for reason in ("backport_unknown", "banner_only", "nvd_exact"):
      self.assertTrue(effective_kev(view_row(1, confidence="tentative", reason=reason, kev=True)), reason)
    self.assertTrue(effective_kev(view_row(1, confidence="firm", reason="nvd_range", kev=True)))
    self.assertFalse(effective_kev(view_row(1, confidence="firm", reason="nvd_range", kev=False)))

  def test_possible_kev_and_top_skip_suppressed_rows(self):
    rows = [view_row(1, confidence="tentative", reason="platform_dependent", kev=True),
            view_row(2, confidence="tentative", reason="banner_unverified", kev=True),
            view_row(3, confidence="tentative", reason="local_vector", kev=True),
            view_row(4, confidence="tentative", reason="backport_unknown", kev=True),
            view_row(5, confidence="tentative", reason="backport_unknown", kev=False)]
    [service] = build_cve_view(rows)["services"]
    self.assertEqual(service["possible_kev"], ["id0004"])
    self.assertEqual(service["possible"]["top"][0]["finding_id"], "id0004")
    # The `kev` field itself is untouched reference data.
    self.assertTrue(all(r["kev"] for r in rows[:4]))

  def test_listing_and_rollup_kev_ignore_suppressed_tentative_only(self):
    rows = [view_row(1, confidence="tentative", reason="banner_unverified", kev=True),
            view_row(2, confidence="firm", reason="nvd_range", kev=True)]
    [service] = build_cve_view(rows)["services"]
    self.assertEqual(service["listed"], ["id0002"])
    self.assertEqual(service["possible_kev"], [])


class ReportTotalsTests(unittest.TestCase):
  def ui(self, findings):
    from .test_finalization_aggregation import _AggHost
    return _AggHost()._compute_ui_aggregate([{"pass_nr": 1, "findings": findings}], {"open_ports": [], "service_info": {}})

  def test_totals_exclude_tentative_cve_rows_and_count_them_apart(self):
    rows = [view_row(1, confidence="tentative", reason="banner_unverified", kev=False),
            view_row(2, confidence="tentative", reason="backport_unknown", kev=False),
            view_row(3, confidence="firm", reason="nvd_range", kev=False),
            {"title": "tentative non-CVE", "severity": "LOW", "confidence": "tentative", "cve": []}]
    for r in rows[:3]:
      r["severity"] = "HIGH"
    findings = rows
    ui = self.ui(findings)
    self.assertEqual((ui.total_findings, ui.unconfirmed_version_matches), (2, 2))
    self.assertEqual(ui.findings_count, {"HIGH": 1, "LOW": 1})
    self.assertEqual(len(findings), 4)  # raw findings untouched

  def test_older_archive_loads_with_default(self):
    from extensions.business.cybersec.red_mesh.models.archive import UiAggregate
    self.assertEqual(UiAggregate.from_dict({"total_open_ports": []}).unconfirmed_version_matches, 0)


class FixRound1Tests(unittest.TestCase):
  def test_f1_dripping_server_hits_the_overall_deadline(self):
    clock = [0.0]

    class Drip(FakeSock):
      def recv(self, n):
        clock[0] += 4.0  # each recv is inside the per-recv timeout, the sum is not
        return b"S"

    with patch(BASE + "socket.socket", return_value=Drip(b"")), \
         patch(BASE + "time.monotonic", side_effect=lambda: clock[0]):
      self.assertIsNone(_ssh_read_kexinit("t", 22, 3))  # budget min(3 * 5, 15) = 15 s: stops on the 4th recv

  def test_f2_invalid_names_are_dropped_and_lists_capped(self):
    lists = {f: ["ok"] for f in common._KEXINIT_FIELDS}
    lists["kex"] = ["good-name", "bad\x1bname", "ctl\x00", "sp ace", "x" * 65, "y" * 64, "nonascii\xe9"]
    lists["enc_s2c"] = ["n%d" % i for i in range(100)]
    got = _parse_ssh_kexinit(packet(lists)[4:])
    self.assertEqual(got["kex"], ["good-name", "y" * 64])
    self.assertEqual(len(got["enc_s2c"]), 64)

  def test_f3_terrapin_on_unverified_banner_stays_tentative(self):
    w = worker()
    vulnerable = kex(enc_s2c=["chacha20-poly1305@openssh.com"], kex=["curve25519-sha256"])
    [f] = w._ssh_apply_terrapin([], vulnerable, "dropbear", "2017.75", None, False)
    self.assertEqual((f.confidence, f.confidence_reason, f.cve), ("tentative", "banner_unverified", ("CVE-2023-48795",)))
    self.assertIn("chacha20-poly1305@openssh.com", f.evidence)
    row = cve_db.replace(cve_db.check_cves("dropbear", "2017.75")[0], title="CVE-2023-48795: T (dropbear 2017.75)",
                         cve=("CVE-2023-48795",))
    [g] = w._ssh_apply_terrapin([row], vulnerable, "dropbear", "2017.75", None, False)
    self.assertEqual((g.confidence, g.confidence_reason), ("tentative", "banner_unverified"))
    [h] = w._ssh_apply_terrapin([row], vulnerable, "dropbear", "2017.75", None, True)
    self.assertEqual(h.confidence, "certain")

  def test_f11_confirmed_terrapin_withdraws_the_backport_fixed_record(self):
    w = worker()
    collector = {"22/CVE-2023-48795": {"reason": "backport_fixed"}, "22/CVE-2024-6387": {"reason": "backport_fixed"}}
    token = cve_db.set_not_applicable_collector(collector)
    try:
      with patch.object(cve_db, "current_probe_port", return_value=22):
        out = w._ssh_apply_terrapin([], kex(enc_s2c=["chacha20-poly1305@openssh.com"]), "openssh", "8.9", None, True)
    finally:
      cve_db.reset_not_applicable_collector(token)
    self.assertEqual(list(collector), ["22/CVE-2024-6387"])
    self.assertEqual(out[0].confidence, "certain")

  def test_f11_withdraw_leaves_other_reasons(self):
    collector = {"22/CVE-2023-48795": {"reason": "behaviour_cleared"}}
    token = cve_db.set_not_applicable_collector(collector)
    try:
      with patch.object(cve_db, "current_probe_port", return_value=22):
        cve_db.withdraw_not_applicable("CVE-2023-48795")
    finally:
      cve_db.reset_not_applicable_collector(token)
    self.assertEqual(len(collector), 1)

  def test_f10_llm_payloads_use_the_effective_kev_rule(self):
    from extensions.business.cybersec.red_mesh.llm_input_builder import _sanitize_finding
    from extensions.business.cybersec.red_mesh.services.llm_structured import _compact_findings_for_structured_prompt
    hidden = {**view_row(1, confidence="tentative", reason="platform_dependent", kev=True), "title": "t", "severity": "HIGH"}
    shown = {**view_row(2, confidence="tentative", reason="backport_unknown", kev=True), "title": "t", "severity": "HIGH"}
    self.assertIs(_sanitize_finding(hidden)["kev"], False)
    self.assertIs(_sanitize_finding(shown)["kev"], True)
    compact = _compact_findings_for_structured_prompt([hidden, shown])
    self.assertEqual([c.get("kev") for c in compact], [False, True])


class ReportTriageTests(unittest.TestCase):
  def ui(self, findings, triage=None):
    from .test_finalization_aggregation import _AggHost
    return _AggHost()._compute_ui_aggregate([{"pass_nr": 1, "findings": findings}], {"open_ports": [], "service_info": {}},
                                            triage=triage)

  def test_f4_triage_confirmed_row_counts_as_confirmed_everywhere(self):
    row = {**view_row(1, confidence="tentative", reason="banner_only", kev=False), "severity": "CRITICAL",
           "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8, "source": "nvd"}]}
    ui = self.ui([row])
    self.assertEqual((ui.total_findings, ui.unconfirmed_version_matches, ui.top_findings), (0, 1, None))
    ui = self.ui([row], {"id0001": {"status": "open", "confirmed": True, "confirmed_by": "a"}})
    self.assertEqual((ui.total_findings, ui.unconfirmed_version_matches), (1, 0))
    self.assertEqual(ui.findings_count, {"CRITICAL": 1})
    self.assertEqual([f["finding_id"] for f in ui.top_findings], ["id0001"])

  def test_f4_static_tentative_cve_row_never_enters_top_findings(self):
    static = {"finding_id": "s1", "title": "CVE-2018-15599: x (dropbear 2017.75)", "severity": "CRITICAL",
              "confidence": "tentative", "cve": ["CVE-2018-15599"]}  # no vulndb_build_id: not a view finding
    ui = self.ui([static])
    self.assertIsNone(ui.top_findings)
    self.assertEqual((ui.total_findings, ui.unconfirmed_version_matches), (0, 1))


class EmulatorEndToEndTests(unittest.TestCase):
  """The real `check_cves` behind the real probes: an emulator yields no firm or certain CVE row (F12)."""

  def setUp(self):
    self.addCleanup(cve_db.set_vulndb_reader, None)

  def ssh(self):
    w = worker()

    class Sock:
      def settimeout(self, t): pass
      def connect(self, a): pass
      def recv(self, n): return b"SSH-2.0-dropbear_2017.75"
      def close(self): pass

    with patch(BASE + "socket.socket", return_value=Sock()), patch(BASE + "paramiko.Transport", side_effect=OSError("x")), \
         patch(BASE + "paramiko.SSHClient", side_effect=OSError("x")), patch(BASE + "_ssh_read_kexinit", return_value=COWRIE):
      return w._service_info_ssh("example.com", 22)["findings"]

  def smtp(self):
    w = worker(25)

    class SMTP:
      def __init__(self, timeout=5): pass
      def connect(self, t, p): return (220, b"mail ESMTP Exim 4.97 Mon, 17 Nov 2026 01:00:00 -0700")
      def ehlo(self, identity): return (250, "\n".join(MAILONEY_EHLO).encode())
      def docmd(self, cmd): return (500, b"no")
      def quit(self): pass

    with patch("smtplib.SMTP", SMTP):
      return w._service_info_smtp("example.com", 25)["findings"]

  def assert_none_asserted(self, findings):
    cves = [f for f in findings if f.get("cve")]
    self.assertTrue(cves)
    self.assertEqual([f["title"] for f in cves if f["confidence"] in ("firm", "certain")], [])
    self.assertEqual({f["confidence_reason"] for f in cves}, {"banner_unverified"})

  def test_cowrie_static(self):
    self.assert_none_asserted(self.ssh())

  def test_mailoney_static(self):
    self.assert_none_asserted(self.smtp())

  def test_cowrie_and_mailoney_generated(self):
    cc = ConfidenceTests()
    cc.addCleanup = self.addCleanup
    rows = list(ConfidenceTests.ROWS) + [("CVE-2030-0020", "exim", "<4.98", "curated", "firm", "curated", 0, 0)]
    cc.use(rows)
    self.assert_none_asserted(self.ssh())
    self.assert_none_asserted(self.smtp())


if __name__ == "__main__":
  unittest.main()
