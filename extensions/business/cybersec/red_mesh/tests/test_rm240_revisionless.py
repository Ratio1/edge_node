"""RM-240 phase 2: a distro package without a revision (`Apache/2.4.38 (Debian)`) in the parser, the reader and both probes."""
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.cve_db import DistroPackage, parse_distro_package
from extensions.business.cybersec.red_mesh.vulndb.reader import load_reader
from extensions.business.cybersec.red_mesh.worker import PentestLocalWorker
from .test_probes import DummyOwner
from .test_rm200_distro_fix import build_db

DEB = "debian_tracker"
# Realistic shape: newer releases carry sid-derived fixed versions (`2.4.38-3`) and Ubuntu releases carry older fixes, so only a
# release's own marker (Debian) or highest fixed version (Ubuntu) names the upstream it shipped.
ROWS = [
  ("debian", "bookworm", "apache", "apache2", "CVE-1", "fixed", "2.4.38-3", DEB),
  ("debian", "bookworm", "apache", "apache2", "CVE-2", "fixed", "2.4.54-1", DEB),
  ("debian", "bookworm", "apache", "apache2", "CVE-6", "fixed", "2.4.62-1~deb12u1", DEB),
  ("debian", "bookworm", "apache", "apache2", "CVE-7", "fixed", "2.4.65-1~deb12u1", DEB),
  ("debian", "bookworm", "apache", "apache2", "CVE-8", "fixed", "2.4.57-2", DEB),  # release-day upstream, no marker
  ("debian", "trixie", "apache", "apache2", "CVE-1", "fixed", "2.4.25-3", DEB),
  ("debian", "trixie", "apache", "apache2", "CVE-7", "fixed", "2.4.65-1", DEB),  # release-day upstream, no marker
  ("debian", "trixie", "apache", "apache2", "CVE-8", "fixed", "2.4.66-1~deb13u1", DEB),  # post-release rebase, above release day
  ("debian", "buster", "apache", "apache2", "CVE-1", "fixed", "2.4.38-3+deb10u10", DEB),  # same upstream: unknown
  ("debian", "buster", "apache", "apache2", "CVE-2", "fixed", "2.4.41-1~deb10u1", DEB),   # above the banner: not_fixed
  ("debian", "buster", "apache", "apache2", "CVE-3", "fixed", "2.4.25-3+deb9u1", DEB),    # below the banner: fixed
  ("debian", "buster", "apache", "apache2", "CVE-4", "open", None, DEB),
  ("debian", "buster", "apache", "apache2", "CVE-5", "not_affected", None, DEB),
  ("debian", "bullseye", "apache", "apache2", "CVE-1", "fixed", "2.4.54-1~deb11u1", DEB),
  ("debian", "bullseye", "apache", "apache2", "CVE-6", "fixed", "2.4.56-1~deb11u2", DEB),
  ("ubuntu", "trusty", "apache", "apache2", "CVE-1", "fixed", "2.4.7-1ubuntu4.22", "ubuntu_oval"),
  ("ubuntu", "trusty", "apache", "apache2", "CVE-9", "fixed", "2.4.6-2ubuntu1", "ubuntu_oval"),
  ("ubuntu", "focal", "apache", "apache2", "CVE-1", "fixed", "2.4.41-4ubuntu3.20", "ubuntu_oval"),
  ("ubuntu", "focal", "apache", "apache2", "CVE-9", "fixed", "2.4.7-1", "ubuntu_oval"),
]


class ParseTests(unittest.TestCase):
  def test_revisionless_marker(self):
    for text, want in (("Apache/2.4.38 (Debian)", ("debian", "2.4.38")), ("Apache/2.4.7 (Ubuntu) PHP/5.5", ("ubuntu", "2.4.7")),
                       ("nginx/1.18.0 (Ubuntu)", ("ubuntu", "1.18.0"))):
      package = parse_distro_package(text)
      self.assertEqual((package.distro, package.upstream, package.revision), want + ("",), text)

  def test_other_banners_unchanged(self):
    self.assertEqual(parse_distro_package("OpenSSH_8.9p1 Ubuntu-3ubuntu0.10").revision, "3ubuntu0.10")
    for text in ("Apache/2.4.49 (Unix)", "Apache/2.4.49 (CentOS)", "Apache/2.4.49", "Apache (Debian)"):
      self.assertIsNone(parse_distro_package(text), text)


class VerdictTests(unittest.TestCase):
  def setUp(self):
    tmp = tempfile.TemporaryDirectory()
    self.addCleanup(tmp.cleanup)
    self.reader = load_reader(*build_db(tmp.name, distro=ROWS))[0]

  def status(self, package, cve):
    return self.reader.distro_status("apache", cve, package)

  def test_each_rule_for_an_empty_revision(self):
    buster = DistroPackage("debian", "2.4.38", "")
    self.assertIsNone(self.status(buster, "CVE-1"))  # same upstream: unknown, never a firm not_fixed
    self.assertEqual(self.status(buster, "CVE-2")[:3], ("not_fixed", "1~deb10u1", "buster"))
    self.assertEqual(self.status(buster, "CVE-3")[:3], ("fixed", "3+deb9u1", "buster"))
    self.assertEqual(self.status(buster, "CVE-4")[:3], ("not_fixed", None, "buster"))
    self.assertEqual(self.status(buster, "CVE-5")[:3], ("not_affected", "", "buster"))

  def test_revisioned_banner_keeps_the_full_compare(self):
    # the same upstream as CVE-1's fix: with a revision the answer is firm, as before RM-240
    self.assertEqual(self.status(DistroPackage("debian", "2.4.38", "3+deb10u9"), "CVE-1")[0], "not_fixed")
    self.assertEqual(self.status(DistroPackage("debian", "2.4.38", "3+deb10u10"), "CVE-1")[0], "fixed")

  def test_release_end_to_end(self):
    for package, release in ((DistroPackage("ubuntu", "2.4.7", ""), "trusty"), (DistroPackage("debian", "2.4.38", ""), "buster"),
                             (DistroPackage("debian", "2.4.54", ""), "bullseye"), (DistroPackage("ubuntu", "2.4.41", ""), "focal")):
      self.assertEqual(self.reader._release(package, "apache"), release)
    self.assertIsNone(self.reader._release(DistroPackage("debian", "2.4.10", ""), "apache"))  # jessie: no rows

  def test_release_is_not_named_by_another_releases_old_fix(self):
    # stretch 2.4.25: trixie's sid-derived row and buster's deb9 row mention it; no release shipped it
    self.assertIsNone(self.reader._release(DistroPackage("debian", "2.4.25", ""), "apache"))
    self.assertIsNone(self.status(DistroPackage("debian", "2.4.25", ""), "CVE-2"))
    # focal's old fix of 2.4.7 does not make a trusty banner ambiguous
    self.assertEqual(self.reader._release(DistroPackage("ubuntu", "2.4.7", ""), "apache"), "trusty")

  def test_release_day_upstream_is_a_candidate(self):
    # trixie shipped 2.4.65 as `2.4.65-1` and rebased to 2.4.66 later; bookworm rebased to 2.4.65 as `~deb12u1`: unknown
    self.assertIsNone(self.reader._release(DistroPackage("debian", "2.4.65", ""), "apache"))
    self.assertEqual(self.reader._release(DistroPackage("debian", "2.4.62", ""), "apache"), "bookworm")

  def test_parse_to_status_end_to_end(self):
    self.assertEqual(self.status(parse_distro_package("Apache/2.4.7 (Ubuntu)"), "CVE-9")[:3], ("fixed", "2ubuntu1", "trusty"))
    self.assertEqual(self.status(parse_distro_package("Apache/2.4.54 (Debian)"), "CVE-1"), None)
    self.assertEqual(self.status(parse_distro_package("Apache/2.4.54 (Debian)"), "CVE-6")[:3], ("not_fixed", "1~deb11u2", "bullseye"))

  def test_buster_marker_names_buster(self):
    self.assertEqual(self.reader._release(DistroPackage("debian", "2.4.38", "3+deb10u2"), "apache"), "buster")

  def test_unknown_keeps_backport_unknown(self):
    cve_db.set_vulndb_reader(self.reader)
    self.addCleanup(cve_db.set_vulndb_reader, None)
    package = DistroPackage("debian", "2.4.38", "")
    self.assertEqual(cve_db.backport_status("apache", "CVE-1", package), cve_db.BACKPORT_UNKNOWN)
    self.assertEqual(cve_db.backport_status("apache", "CVE-2", package), cve_db.BACKPORT_NOT_FIXED)
    self.assertEqual(cve_db._confidence_reason(cve_db.BACKPORT_UNKNOWN, None, "apache"), ("tentative", "backport_unknown"))


class StaticOverlayTests(unittest.TestCase):
  def test_revisionless_equal_upstream_is_unknown(self):
    row = ("8.9p1", "3ubuntu0.10", "USN-6859-1")
    with patch.dict(cve_db.BACKPORT_FIXES, {("openssh", "ubuntu"): {"CVE-X": (row,)}}):
      self.assertEqual(cve_db.backport_status("openssh", "CVE-X", DistroPackage("ubuntu", "8.9p1", "")), cve_db.BACKPORT_UNKNOWN)
      self.assertEqual(cve_db.backport_status("openssh", "CVE-X", DistroPackage("ubuntu", "8.9p1", "3ubuntu0.9")),
                       cve_db.BACKPORT_NOT_FIXED)


class HardeningTests(unittest.TestCase):
  def test_hostile_banner_parses_fast(self):
    start = time.monotonic()
    parse_distro_package("Apache/2.4.1 " + "_1" * 32000)
    parse_distro_package("Apache/2.4.1 " + "_1" * 32000 + " (Debian)")
    self.assertLess(time.monotonic() - start, 1.0)

  def test_a_match_clipped_by_the_cap_is_dropped(self):
    banner = "Apache/2.4.1 (Debian)"
    self.assertIsNotNone(parse_distro_package(banner))
    pad = " " * (cve_db._DISTRO_PARSE_LIMIT - len("OpenSSH_8.9p1 Ubuntu-3ubuntu0.1") - 1)
    self.assertIsNone(parse_distro_package("x" + pad + "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"))  # `.10` cut to `.1`
    self.assertIsNotNone(parse_distro_package(("x" + pad + "OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")))  # ends at the cut, input not cut

  def test_not_applicable_package_label_has_no_dangling_dash(self):
    collector = {}
    token = cve_db.set_not_applicable_collector(collector)
    self.addCleanup(cve_db.reset_not_applicable_collector, token)
    entry = type("E", (), {"cve_id": "CVE-1", "title": "t"})()
    cve_db._record_not_applicable(entry, "apache", "2.4.38", DistroPackage("debian", "2.4.38", ""), "client_side")
    self.assertEqual(collector["/CVE-1"]["package"], "debian 2.4.38")


class ProbePackageTests(unittest.TestCase):
  def seen(self, probe, port):
    worker = PentestLocalWorker(owner=DummyOwner(), target="example.com", job_id="j", initiator="i",
                                local_id_prefix="1", worker_target_ports=[port])
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    resp = MagicMock(status_code=200, reason="OK", headers={"Server": "Apache/2.4.38 (Debian)"}, text="<html></html>")
    base = "extensions.business.cybersec.red_mesh.worker.service.common."
    with patch(base + "requests.get", return_value=resp), patch(base + "requests.request", side_effect=Exception("skip")), \
         patch(base + "check_cves", return_value=[]) as check:
      getattr(worker, probe)("example.com", port)
    return [c.kwargs.get("package") for c in check.call_args_list if c.args[0] == "apache"]

  def test_package_only_when_it_names_the_matched_version(self):
    from extensions.business.cybersec.red_mesh.worker.service.common import _server_package
    self.assertIsNone(_server_package("Apache/2.2.22 (Debian) Apache/2.4.1", "2.4.1"))
    self.assertEqual(_server_package("Apache/2.4.38 (Debian)", "2.4.38"), DistroPackage("debian", "2.4.38", ""))

  def test_both_probes_pass_the_package(self):
    for probe, port in (("_service_info_http", 80), ("_service_info_https", 443)):
      self.assertEqual(self.seen(probe, port), [DistroPackage("debian", "2.4.38", "")], probe)
