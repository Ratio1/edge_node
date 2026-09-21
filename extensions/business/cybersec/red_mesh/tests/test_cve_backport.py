"""
RM-070: package-aware CVE matching.

The client job carried `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`; the matcher
compared `8.9` and reported regreSSHion, which USN-6859-1 had fixed in that
exact package revision. The upstream version cannot say whether a
distribution backported a fix; the package revision can.
"""

import unittest

from extensions.business.cybersec.red_mesh.cve_db import (
  BACKPORT_NOT_FIXED,
  BACKPORT_UNKNOWN,
  DistroPackage,
  _compare_debian_revision,
  backport_status,
  check_cves,
  parse_distro_package,
)


class TestParseDistroPackage(unittest.TestCase):

  def test_real_banner_shapes(self):
    cases = (
      ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", ("ubuntu", "8.9p1", "3ubuntu0.10")),
      ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.3", ("ubuntu", "9.6p1", "3ubuntu13.3")),
      ("SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2", ("debian", "9.2p1", "2+deb12u2")),
      ("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3", ("debian", "8.4p1", "5+deb11u3")),
    )
    for banner, expected in cases:
      with self.subTest(banner=banner):
        package = parse_distro_package(banner)
        self.assertEqual((package.distro, package.upstream, package.revision), expected)

  def test_bare_upstream_banner_has_no_package(self):
    for banner in ("SSH-2.0-OpenSSH_9.9p1", "SSH-2.0-OpenSSH_7.4", "SSH-2.0-dropbear_2022.83",
                   "SSH-2.0-OpenSSH_8.9p1 FreeBSD-20220415", None, 7):
      with self.subTest(banner=banner):
        self.assertIsNone(parse_distro_package(banner))


class TestRevisionOrdering(unittest.TestCase):

  def test_numeric_chunks_compare_numerically(self):
    # The defect that makes a tokenizer necessary: `_parse_version` reads
    # `3ubuntu0.10` and `3ubuntu0.3` as the same tuple.
    self.assertEqual(_compare_debian_revision("3ubuntu0.3", "3ubuntu0.10"), -1)
    self.assertEqual(_compare_debian_revision("3ubuntu0.10", "3ubuntu0.3"), 1)
    self.assertEqual(_compare_debian_revision("3ubuntu0.10", "3ubuntu0.10"), 0)
    self.assertEqual(_compare_debian_revision("3ubuntu13.3", "3ubuntu13.10"), -1)

  def test_debian_style_revisions(self):
    self.assertEqual(_compare_debian_revision("2+deb12u2", "2+deb12u3"), -1)
    self.assertEqual(_compare_debian_revision("5+deb11u3", "5+deb11u2"), 1)
    self.assertEqual(_compare_debian_revision("2", "2+deb12u1"), -1)

  def test_tilde_sorts_before_release(self):
    self.assertEqual(_compare_debian_revision("1~rc1", "1"), -1)
    self.assertEqual(_compare_debian_revision("1", "1~rc1"), 1)


class TestBackportStatus(unittest.TestCase):

  def test_fixed_revision_is_fixed_and_earlier_is_not(self):
    fixed = DistroPackage("ubuntu", "8.9p1", "3ubuntu0.10")
    later = DistroPackage("ubuntu", "8.9p1", "3ubuntu0.11")
    earlier = DistroPackage("ubuntu", "8.9p1", "3ubuntu0.9")
    self.assertEqual(backport_status("openssh", "CVE-2024-6387", fixed), "fixed")
    self.assertEqual(backport_status("openssh", "CVE-2024-6387", later), "fixed")
    self.assertEqual(backport_status("openssh", "CVE-2024-6387", earlier), BACKPORT_NOT_FIXED)

  def test_no_advisory_row_is_unknown_never_fixed(self):
    package = DistroPackage("ubuntu", "8.9p1", "3ubuntu0.10")
    self.assertEqual(backport_status("openssh", "CVE-2017-15906", package), BACKPORT_UNKNOWN)
    debian = DistroPackage("debian", "9.2p1", "2+deb12u2")
    self.assertEqual(backport_status("openssh", "CVE-2024-6387", debian), BACKPORT_UNKNOWN)
    other_upstream = DistroPackage("ubuntu", "8.2p1", "4ubuntu0.11")
    self.assertEqual(backport_status("openssh", "CVE-2024-6387", other_upstream), BACKPORT_UNKNOWN)

  def test_no_package_is_not_applicable(self):
    self.assertEqual(backport_status("openssh", "CVE-2024-6387", None), "")


class TestCheckCvesWithPackage(unittest.TestCase):

  def _ids(self, findings):
    return {f.cve[0] for f in findings}

  def test_the_client_job_banner_no_longer_reports_regresshion(self):
    # Job 6cc55610: `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`, USN-6859-1 applied.
    package = parse_distro_package("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10")
    without = self._ids(check_cves("openssh", "8.9"))
    with_package = self._ids(check_cves("openssh", "8.9", package=package))
    self.assertIn("CVE-2024-6387", without)
    self.assertNotIn("CVE-2024-6387", with_package)
    # Applicability gating from RM-064 still holds: the client-side CVE stays out.
    self.assertNotIn("CVE-2025-26465", with_package)
    # Nothing else is lost: every other match survives with its status stated.
    self.assertEqual(with_package, without - {"CVE-2024-6387"})

  def test_an_unpatched_revision_reports_the_cve_as_not_fixed_and_firm(self):
    package = DistroPackage("ubuntu", "8.9p1", "3ubuntu0.9")
    findings = [f for f in check_cves("openssh", "8.9", package=package) if f.cve[0] == "CVE-2024-6387"]
    self.assertEqual(len(findings), 1)
    f = findings[0]
    self.assertEqual(f.backport_status, BACKPORT_NOT_FIXED)
    self.assertEqual(f.confidence, "firm")
    self.assertIn("below the revision that carries the fix", f.description)

  def test_a_match_with_no_advisory_data_says_so(self):
    package = DistroPackage("debian", "8.9p1", "2+deb12u1")
    findings = [f for f in check_cves("openssh", "8.9", package=package) if f.cve[0] == "CVE-2024-6387"]
    self.assertEqual(len(findings), 1)
    f = findings[0]
    self.assertEqual(f.backport_status, BACKPORT_UNKNOWN)
    self.assertEqual(f.confidence, "tentative")
    self.assertIn("Backport status unknown", f.description)

  def test_callers_without_a_package_are_unchanged(self):
    findings = check_cves("openssh", "8.9")
    self.assertTrue(findings)
    for f in findings:
      self.assertEqual(f.backport_status, "")
      self.assertEqual(f.confidence, "tentative")
      self.assertIn("may be a false positive", f.description)


if __name__ == "__main__":
  unittest.main()
