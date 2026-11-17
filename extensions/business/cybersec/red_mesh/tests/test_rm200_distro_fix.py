"""RM-200 Phase 3b: `backport_status` reads the `distro_fix` table under `generated` (contract: vulndb.md, `distro_fix`)."""
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.cve_db import (
  BACKPORT_NOT_FIXED, BACKPORT_UNKNOWN, BACKPORT_UNKNOWN_NO_PACKAGE, check_cves, parse_distro_package,
  reset_not_applicable_collector, set_not_applicable_collector, set_vulndb_reader,
)
from extensions.business.cybersec.red_mesh.findings import probe_port_scope
from extensions.business.cybersec.red_mesh.vulndb.reader import load_reader
from .test_vulndb_reader import BUILD_ID, make_db

BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
J = "1:8.9p1-3ubuntu0.%s"
# Port-222 ground truth: jammy openssh, host at 3ubuntu0.10.
AFFECTED = [(c, "openssh", "<9.8", "nvd", "firm", "nvd_range", 0, 0) for c in (
  "CVE-2023-48795", "CVE-2026-106588", "CVE-2026-60002", "CVE-2026-99999", "CVE-2024-6387", "CVE-2026-70001")]
DISTRO = [
  ("ubuntu", "jammy", "openssh", "openssh", "CVE-2023-48795", "fixed", J % "5", "ubuntu_oval"),
  ("ubuntu", "jammy", "openssh", "openssh", "CVE-2026-106588", "not_affected", None, "ubuntu_oval"),
  ("ubuntu", "jammy", "openssh", "openssh", "CVE-2026-60002", "fixed", J % "16", "ubuntu_oval"),
  ("ubuntu", "jammy", "openssh", "openssh", "CVE-2026-70001", "open", None, "ubuntu_oval"),
  ("ubuntu", "jammy", "openssh", "openssh", "CVE-2024-6387", "fixed", J % "10", "ubuntu_oval"),
  ("ubuntu", "noble", "openssh", "openssh", "CVE-2023-48795", "fixed", "1:9.6p1-3ubuntu13.1", "ubuntu_oval"),
  ("debian", "bookworm", "openssh", "openssh", "CVE-2023-48795", "fixed", "1:9.2p1-2+deb12u2", "debian_tracker"),
  ("debian", "bookworm", "openssh", "openssh", "CVE-2026-60002", "open", None, "debian_tracker"),
  ("debian", "trixie", "openssh", "openssh", "CVE-2023-48795", "fixed", "1:9.2p1-2+deb13u1", "debian_tracker"),
]
DISTRO_DDL = (
  "CREATE TABLE distro_fix(distro TEXT, release TEXT, product TEXT, package TEXT, cve_id TEXT, status TEXT,"
  " fixed_version TEXT, source TEXT)")


def build_db(directory, distro=DISTRO, meta=("snapshot_oval", "snapshot_debian"), table=True):
  db, pin = Path(directory) / "v.sqlite", Path(directory) / "pin.json"
  make_db(db, rows=AFFECTED, schema="1.0.1")
  conn = sqlite3.connect(db)
  if table:
    conn.execute(DISTRO_DDL)
    conn.executemany("INSERT INTO distro_fix VALUES (?,?,?,?,?,?,?,?)", distro)
  for k in meta:
    conn.execute("INSERT INTO meta VALUES (?, 'h')", (k,))
  conn.commit()
  conn.close()
  pin.write_text(json.dumps({"build_id": BUILD_ID, "built_at": "2026-11-14T00:00:00Z",
                             "sha256_sqlite": hashlib.sha256(db.read_bytes()).hexdigest()}))
  return db, pin


def pkg(distro, upstream, revision):
  return cve_db.DistroPackage(distro, upstream, revision)


class ReaderTests(unittest.TestCase):
  def setUp(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.dir = tmp.name

  def reader(self, **kw):
    return load_reader(*build_db(self.dir, **kw))[0]

  def test_ubuntu_release_by_upstream_and_state_by_revision(self):
    r = self.reader()
    jammy = parse_distro_package(BANNER)
    self.assertEqual(r.distro_status("openssh", "CVE-2023-48795", jammy), ("fixed", "3ubuntu0.5", "jammy", "ubuntu_oval"))
    self.assertEqual(r.distro_status("openssh", "CVE-2026-60002", jammy), ("not_fixed", "3ubuntu0.16", "jammy", "ubuntu_oval"))
    self.assertEqual(r.distro_status("openssh", "CVE-2026-106588", jammy), ("not_affected", "", "jammy", "ubuntu_oval"))
    self.assertEqual(r.distro_status("openssh", "CVE-2026-70001", jammy), ("not_fixed", None, "jammy", "ubuntu_oval"))
    self.assertEqual(r.distro_status("openssh", "CVE-2024-6387", jammy)[0], "fixed")  # equal revision
    self.assertIsNone(r.distro_status("openssh", "CVE-2026-99999", jammy))

  def test_revision_compare_is_dpkg_not_lexical(self):
    r = self.reader()
    self.assertEqual(r.distro_status("openssh", "CVE-2026-60002", pkg("ubuntu", "8.9p1", "3ubuntu0.9"))[0], "not_fixed")
    self.assertEqual(r.distro_status("openssh", "CVE-2023-48795", pkg("ubuntu", "8.9p1", "3ubuntu0.10"))[0], "fixed")

  def test_noble_by_upstream(self):
    r = self.reader()
    self.assertEqual(r.distro_status("openssh", "CVE-2023-48795", pkg("ubuntu", "9.6p1", "3ubuntu13.3"))[2], "noble")

  def test_debian_release_by_deb_marker(self):
    r = self.reader()
    self.assertEqual(r.distro_status("openssh", "CVE-2023-48795", pkg("debian", "9.2p1", "2+deb12u2")),
                     ("fixed", "2+deb12u2", "bookworm", "debian_tracker"))
    self.assertEqual(r.distro_status("openssh", "CVE-2023-48795", pkg("debian", "9.2p1", "2+deb12u1"))[0], "not_fixed")
    self.assertEqual(r.distro_status("openssh", "CVE-2026-60002", pkg("debian", "9.2p1", "2+deb12u2"))[0], "not_fixed")
    # the marker wins over the upstream, which two Debian releases share here
    self.assertEqual(r.distro_status("openssh", "CVE-2023-48795", pkg("debian", "9.2p1", "2+deb13u1"))[2], "trixie")

  def test_unknown_release_is_none(self):
    r = self.reader()
    self.assertIsNone(r.distro_status("openssh", "CVE-2023-48795", pkg("debian", "8.4p1", "5+deb11u3")))  # no bullseye
    self.assertIsNone(r.distro_status("openssh", "CVE-2023-48795", pkg("ubuntu", "7.4p1", "1ubuntu1")))  # no upstream match
    self.assertIsNone(r.distro_status("openssh", "CVE-2023-48795", None))
    self.assertIsNone(r.distro_status("php", "CVE-2023-48795", pkg("ubuntu", "8.9p1", "3ubuntu0.10")))  # no product rows

  def test_ambiguous_upstream_is_none(self):
    rows = DISTRO + [("ubuntu", "focal", "openssh", "openssh", "CVE-2023-48795", "fixed", "1:8.9p1-1ubuntu0.1", "ubuntu_oval")]
    r = self.reader(distro=rows)
    self.assertIsNone(r.distro_status("openssh", "CVE-2023-48795", parse_distro_package(BANNER)))

  def test_open_row_with_null_version_does_not_name_a_release(self):
    rows = [("ubuntu", "focal", "openssh", "openssh", "CVE-2026-70001", "open", None, "ubuntu_oval")]
    r = self.reader(distro=rows)
    self.assertIsNone(r.distro_status("openssh", "CVE-2026-70001", parse_distro_package(BANNER)))

  def test_no_table_no_meta_empty_table_mean_no_data(self):
    jammy = parse_distro_package(BANNER)
    for kw in ({"table": False}, {"meta": ()}, {"distro": []}, {"meta": ("snapshot_debian",)}):
      self.assertIsNone(self.reader(**kw).distro_status("openssh", "CVE-2023-48795", jammy), kw)
    # a Debian-only snapshot still serves Debian
    r = self.reader(meta=("snapshot_debian",))
    self.assertEqual(r.distro_status("openssh", "CVE-2023-48795", pkg("debian", "9.2p1", "2+deb12u2"))[0], "fixed")

  def status(self, rows, package, cve="CVE-1"):
    return self.reader(distro=rows).distro_status("openssh", cve, package)

  def test_f1_full_version_compare(self):
    rows = [("debian", "bookworm", "openssh", "openssh", "CVE-1", "fixed", "1:3.8.1p1-8.sarge.4", "debian_tracker")]
    self.assertEqual(self.status(rows, pkg("debian", "9.2p1", "2+deb12u3"))[:2], ("fixed", "8.sarge.4"))
    newer = [("debian", "bookworm", "openssh", "openssh", "CVE-1", "fixed", "1:9.3p1-1+deb12u1", "debian_tracker")]
    self.assertEqual(self.status(newer, pkg("debian", "9.2p1", "2+deb12u3"))[0], "not_fixed")
    # Ubuntu rows: the release comes from the upstream (14.10), the verdict from the whole version
    pg = [("ubuntu", "jammy", "openssh", "openssh", "CVE-1", "fixed", "14.15-0ubuntu0.22.04.1", "ubuntu_oval"),
          ("ubuntu", "jammy", "openssh", "openssh", "CVE-2", "fixed", "14.10-0ubuntu0.22.04.1", "ubuntu_oval")]
    r = self.reader(distro=pg)
    self.assertEqual(r.distro_status("openssh", "CVE-1", pkg("ubuntu", "14.10", "0ubuntu0.22.04.1"))[0], "not_fixed")
    self.assertEqual(r.distro_status("openssh", "CVE-2", pkg("ubuntu", "14.10", "0ubuntu0.22.04.1"))[0], "fixed")

  def test_upstream_is_compared_before_revision(self):
    rows = [("debian", "bookworm", "openssh", "openssh", "CVE-1", "fixed", "2:4.17.12+dfsg-0+deb12u2", "debian_tracker")]
    self.assertEqual(self.status(rows, pkg("debian", "4.17.12", "0+deb12u1"))[:2], ("not_fixed", "0+deb12u2"))
    self.assertEqual(self.status(rows, pkg("debian", "4.17.12+dfsg", "0+deb12u2"))[0], "fixed")

  def test_f1_highest_fix_uses_full_version(self):
    rows = [("ubuntu", "jammy", "openssh", "openssh", "CVE-1", "fixed", "1:8.9p1-3ubuntu0.5", "ubuntu_oval"),
            ("ubuntu", "jammy", "openssh", "openssh", "CVE-1", "fixed", "1:8.9p1-3ubuntu0.16", "ubuntu_oval")]
    self.assertEqual(self.status(rows, pkg("ubuntu", "8.9p1", "3ubuntu0.10"))[:2], ("not_fixed", "3ubuntu0.16"))

  def test_f2_disagreeing_packages_are_unknown_agreeing_are_not(self):
    j = "ubuntu", "jammy", "openssh"
    split = [(*j, "tomcat9", "CVE-1", "fixed", "1:8.9p1-3ubuntu0.5", "ubuntu_oval"),
             (*j, "tomcat10", "CVE-1", "not_affected", None, "ubuntu_oval")]
    self.assertIsNone(self.status(split, pkg("ubuntu", "8.9p1", "3ubuntu0.10")))
    split[1] = (*j, "tomcat10", "CVE-1", "open", None, "ubuntu_oval")
    self.assertIsNone(self.status(split, pkg("ubuntu", "8.9p1", "3ubuntu0.10")))
    same = [(*j, "a", "CVE-1", "fixed", "1:8.9p1-3ubuntu0.5", "ubuntu_oval"),
            (*j, "b", "CVE-1", "fixed", "1:8.9p1-3ubuntu0.7", "ubuntu_oval")]
    self.assertEqual(self.status(same, pkg("ubuntu", "8.9p1", "3ubuntu0.10"))[:2], ("fixed", "3ubuntu0.7"))

  def test_f2_single_package_tie_rule_open_wins_then_highest_fix(self):
    j = "ubuntu", "jammy", "openssh", "openssh"
    rows = [(*j, "CVE-1", "fixed", "1:8.9p1-3ubuntu0.5", "ubuntu_oval"), (*j, "CVE-1", "open", None, "ubuntu_oval")]
    self.assertEqual(self.status(rows, pkg("ubuntu", "8.9p1", "3ubuntu0.10"))[:2], ("not_fixed", None))
    rows = [(*j, "CVE-1", "not_affected", None, "ubuntu_oval"), (*j, "CVE-1", "fixed", "1:8.9p1-3ubuntu0.5", "ubuntu_oval")]
    self.assertEqual(self.status(rows, pkg("ubuntu", "8.9p1", "3ubuntu0.10"))[0], "fixed")

  def test_f5_unreadable_revision_is_unknown(self):
    rows = [("ubuntu", "jammy", "openssh", "openssh", "CVE-1", "fixed", "1:8.9p1-3ubuntu" + "9" * 5000, "ubuntu_oval")]
    self.assertIsNone(self.status(rows, pkg("ubuntu", "8.9p1", "3ubuntu0.10")))
    ok = [("ubuntu", "jammy", "openssh", "openssh", "CVE-1", "fixed", "1:8.9p1-3ubuntu0.5", "ubuntu_oval")]
    self.assertIsNone(self.status(ok, pkg("ubuntu", "8.9p1", "3ubuntu" + "9" * 5000)))

  def test_f8_tilde_sorts_before(self):
    rows = [("debian", "bookworm", "openssh", "openssh", "CVE-1", "fixed", "1:9.2p1-2+deb12u1", "debian_tracker")]
    self.assertEqual(self.status(rows, pkg("debian", "9.2p1", "2~deb12u1"))[0], "not_fixed")
    self.assertEqual(self.status(rows, pkg("debian", "9.2p1", "2+deb12u1"))[0], "fixed")


class CheckCvesTests(unittest.TestCase):
  def setUp(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.dir = tmp.name
    self.addCleanup(set_vulndb_reader, None)

  def run_check(self, package=parse_distro_package(BANNER), banner_verified=cve_db.BANNER_NOT_ASSESSABLE, **kw):
    set_vulndb_reader(load_reader(*build_db(self.dir, **kw))[0])
    collector = {}
    token = set_not_applicable_collector(collector)
    try:
      with probe_port_scope(222):
        findings = check_cves("openssh", "8.9", package=package, banner_verified=banner_verified)
    finally:
      reset_not_applicable_collector(token)
    return {f.cve[0]: f for f in findings}, collector

  def test_port_222_ground_truth(self):
    found, na = self.run_check()
    self.assertEqual(na["222/CVE-2023-48795"]["reason"], "backport_fixed")
    self.assertEqual((na["222/CVE-2023-48795"]["advisory"], na["222/CVE-2023-48795"]["fixed_revision"]),
                     ("ubuntu_oval", "3ubuntu0.5"))
    self.assertEqual(na["222/CVE-2026-106588"]["reason"], "distro_not_affected")
    self.assertEqual(na["222/CVE-2026-106588"]["advisory"], "ubuntu_oval")
    self.assertNotIn("CVE-2023-48795", found)
    self.assertNotIn("CVE-2026-106588", found)
    firm = found["CVE-2026-60002"]
    self.assertEqual((firm.confidence, firm.confidence_reason, firm.backport_status),
                     ("firm", "distro_package", BACKPORT_NOT_FIXED))
    self.assertEqual(found["CVE-2026-70001"].confidence_reason, "distro_package")  # open
    unknown = found["CVE-2026-99999"]
    self.assertEqual((unknown.confidence, unknown.confidence_reason, unknown.backport_status),
                     ("tentative", "backport_unknown", BACKPORT_UNKNOWN))

  def test_overlay_wins_over_table(self):
    rows = [r for r in DISTRO if r[4] != "CVE-2024-6387"] + [
      ("ubuntu", "jammy", "openssh", "openssh", "CVE-2024-6387", "open", None, "ubuntu_oval")]
    found, na = self.run_check(distro=rows)
    self.assertEqual(na["222/CVE-2024-6387"]["advisory"], "USN-6859-1")  # BACKPORT_FIXES row, not the table
    self.assertNotIn("CVE-2024-6387", found)
    older, _ = self.run_check(package=pkg("ubuntu", "8.9p1", "3ubuntu0.9"), distro=rows)
    self.assertEqual(older["CVE-2024-6387"].backport_status, BACKPORT_NOT_FIXED)

  def test_unverified_banner_stays_tentative_and_withdraw_clears_the_record(self):
    found, _ = self.run_check(banner_verified=False)
    self.assertEqual(found["CVE-2026-60002"].confidence_reason, "banner_unverified")
    self.assertEqual(found["CVE-2026-99999"].confidence_reason, "banner_unverified")
    _, na = self.run_check()
    token = set_not_applicable_collector(na)
    try:
      with probe_port_scope(222):
        cve_db.withdraw_not_applicable("CVE-2026-106588")
        cve_db.withdraw_not_applicable("CVE-2023-48795")
    finally:
      reset_not_applicable_collector(token)
    self.assertNotIn("222/CVE-2026-106588", na)
    self.assertNotIn("222/CVE-2023-48795", na)

  def test_no_distro_data_behaves_as_today(self):
    for kw in ({"table": False}, {"meta": ()}):
      found, na = self.run_check(**kw)
      self.assertIn("CVE-2023-48795", found, kw)
      self.assertEqual(found["CVE-2023-48795"].backport_status, BACKPORT_UNKNOWN)
      self.assertNotIn("222/CVE-2023-48795", na)
    found, _ = self.run_check(package=None)
    self.assertEqual(found["CVE-2023-48795"].backport_status, BACKPORT_UNKNOWN_NO_PACKAGE)

  def test_static_is_unchanged(self):
    set_vulndb_reader(None)
    self.assertEqual(cve_db.backport_status("openssh", "CVE-2023-48795", parse_distro_package(BANNER)), BACKPORT_UNKNOWN)
    self.assertEqual(cve_db.backport_status("openssh", "CVE-2024-6387", parse_distro_package(BANNER)), "fixed")

  def test_f3_unexpected_state_is_unknown(self):
    class Fake:
      def distro_status(self, *a):
        return "weird", "", "jammy", "ubuntu_oval"
    set_vulndb_reader(Fake())
    self.assertEqual(cve_db.backport_status("openssh", "CVE-1", parse_distro_package(BANNER)), BACKPORT_UNKNOWN)

  def test_f4_unverified_banner_keeps_table_fixed_and_not_affected_tentative(self):
    found, na = self.run_check(banner_verified=False)
    for cve, status in (("CVE-2023-48795", "fixed"), ("CVE-2026-106588", "not_affected")):
      self.assertEqual((found[cve].confidence, found[cve].confidence_reason, found[cve].backport_status),
                       ("tentative", "banner_unverified", status))
      self.assertNotIn("222/" + cve, na)
    for verified in (True, None):
      found, na = self.run_check(banner_verified=verified)
      self.assertNotIn("CVE-2023-48795", found)
      self.assertNotIn("CVE-2026-106588", found)
      self.assertIn("222/CVE-2023-48795", na)

  def test_f4_overlay_still_drops_on_unverified_banner(self):
    found, na = self.run_check(banner_verified=False)
    self.assertNotIn("CVE-2024-6387", found)
    self.assertEqual(na["222/CVE-2024-6387"]["advisory"], "USN-6859-1")

  def test_f5_unreadable_revision_does_not_raise_out_of_check_cves(self):
    found, _ = self.run_check(package=pkg("ubuntu", "8.9p1", "3ubuntu" + "9" * 5000))
    self.assertEqual(found["CVE-2023-48795"].backport_status, BACKPORT_UNKNOWN)

  def test_native_fixed_version_above_banner_gets_the_below_fix_note(self):
    # a fixed version with no `-` has an empty revision, which must not read as an open row
    rows = DISTRO + [("ubuntu", "jammy", "openssh", "openssh", "CVE-2026-99999", "fixed", "1:8.9p1+1", "ubuntu_oval")]
    found, _ = self.run_check(distro=rows)
    f = found["CVE-2026-99999"]
    self.assertEqual(f.backport_status, BACKPORT_NOT_FIXED)
    self.assertIn("below the revision", f.description)
    self.assertNotIn("no fixed package is published", f.description)

  def test_f7_open_note_differs_from_below_fix_note(self):
    found, _ = self.run_check()
    self.assertIn("no fixed package is published", found["CVE-2026-70001"].description)
    self.assertNotIn("below the revision", found["CVE-2026-70001"].description)
    self.assertIn("below the revision", found["CVE-2026-60002"].description)
