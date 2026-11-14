"""Boundary tests for the catalog rows corrected in RM-168 phase 2.

Each case is a (product, version) the row's published range includes or
excludes, so a regression to a single `<X` bound or an `==` artefact fails here.
Ranges: NVD and CVE.org (CNA), checked 2026-11-14.
"""
import unittest

from extensions.business.cybersec.red_mesh.cve_db import CVE_DATABASE, check_cves


def _fires(product, version, cve_id, applicability="server"):
  found = set()
  for f in check_cves(product, version, applicability=applicability):
    found.update(f.cve or ())
  return cve_id in found


# (product, version, cve_id, expected)
CASES = [
  # The Packetbeat CVE is not an Elasticsearch CVE.
  ("elasticsearch", "5.6.0", "CVE-2017-11480", False),
  # MySQL 8.0 / 8.1-8.2.0, not 5.7.
  ("mysql", "8.0.35", "CVE-2024-20973", True),
  ("mysql", "8.0.36", "CVE-2024-20973", False),
  ("mysql", "8.2.0", "CVE-2024-20973", True),
  ("mysql", "5.7.30", "CVE-2024-20973", False),
  # MySQL authentication bypass: 5.1<5.1.63, 5.5<5.5.24, 5.6<5.6.6.
  ("mysql", "5.5.23", "CVE-2012-2122", True),
  ("mysql", "5.5.24", "CVE-2012-2122", False),
  ("mysql", "5.1.62", "CVE-2012-2122", True),
  ("mysql", "5.6.5", "CVE-2012-2122", True),
  ("mysql", "5.6.6", "CVE-2012-2122", False),
  # JBoss AS 4.x.
  ("jboss", "4.0.5", "CVE-2017-7504", True),
  ("jboss", "4.2.3", "CVE-2017-7504", True),
  ("jboss", "5.1.0", "CVE-2017-7504", False),
  # MongoDB 5.0<5.0.14, 6.0<6.0.3, 6.1.0.
  ("mongodb", "5.0.13", "CVE-2024-8207", True),
  ("mongodb", "5.0.14", "CVE-2024-8207", False),
  ("mongodb", "6.0.2", "CVE-2024-8207", True),
  ("mongodb", "6.0.3", "CVE-2024-8207", False),
  ("mongodb", "4.4.20", "CVE-2024-8207", False),
  # PostgreSQL: each branch fixed at its own minor; 11 and older are EOL and reported.
  ("postgresql", "16.4", "CVE-2024-10979", True),
  ("postgresql", "16.5", "CVE-2024-10979", False),
  ("postgresql", "16.6", "CVE-2024-10979", False),
  ("postgresql", "13.18", "CVE-2024-10976", False),
  ("postgresql", "13.16", "CVE-2024-10976", True),
  ("postgresql", "12.21", "CVE-2024-10979", False),
  ("postgresql", "12.20", "CVE-2024-10979", True),
  ("postgresql", "10.7", "CVE-2024-10979", True),
  ("postgresql", "17.1", "CVE-2024-10976", False),
  ("postgresql", "17.0", "CVE-2024-10976", True),
  # Redis: per-branch fixes; 6.2.17+ is patched; <6.2 is reported for CVE-2024-46981.
  ("redis", "6.2.17", "CVE-2024-46981", False),
  ("redis", "6.2.16", "CVE-2024-46981", True),
  ("redis", "5.0.7", "CVE-2024-46981", True),
  ("redis", "7.2.6", "CVE-2024-46981", True),
  ("redis", "7.4.1", "CVE-2024-46981", True),
  ("redis", "7.4.2", "CVE-2024-46981", False),
  ("redis", "6.2.17", "CVE-2022-35951", False),
  ("redis", "7.0.4", "CVE-2022-35951", True),
  ("redis", "7.0.5", "CVE-2022-35951", False),
  ("redis", "6.0.14", "CVE-2021-32761", True),
  ("redis", "6.0.15", "CVE-2021-32761", False),
  ("redis", "6.2.4", "CVE-2021-32761", True),
  ("redis", "6.2.5", "CVE-2021-32761", False),
  ("redis", "6.2.17", "CVE-2024-31449", False),
  ("redis", "7.4.0", "CVE-2024-31449", True),
  ("redis", "7.4.1", "CVE-2024-31449", False),
  # OpenSSL: CVE-2022-3602 is 3.0.0-3.0.6 only.
  ("openssl", "1.0.2k", "CVE-2022-3602", False),
  ("openssl", "1.1.1w", "CVE-2022-3602", False),
  ("openssl", "3.0.6", "CVE-2022-3602", True),
  ("openssl", "3.0.7", "CVE-2022-3602", False),
  # CVE-2024-4741: 1.1.1<1.1.1y (and EOL below), 3.0<3.0.14, 3.1<3.1.6, 3.2<3.2.2, 3.3.0.
  ("openssl", "1.1.1x", "CVE-2024-4741", True),
  ("openssl", "1.1.1y", "CVE-2024-4741", False),
  ("openssl", "3.1.5", "CVE-2024-4741", True),
  ("openssl", "3.1.6", "CVE-2024-4741", False),
  ("openssl", "3.3.0", "CVE-2024-4741", True),
  ("openssl", "3.3.1", "CVE-2024-4741", False),
  # CVE-2020-1971: 1.0.2<1.0.2x and 1.1.1<1.1.1i (0.9.x-1.1.0 are EOL, reported).
  ("openssl", "1.1.1h", "CVE-2020-1971", True),
  ("openssl", "1.1.1i", "CVE-2020-1971", False),
  ("openssl", "1.0.2w", "CVE-2020-1971", True),
  ("openssl", "1.0.2x", "CVE-2020-1971", False),
  ("openssl", "1.1.0l", "CVE-2020-1971", True),
  # Asterisk 18<18.24.2, 19-20<20.9.2, 21<21.4.2.
  ("asterisk", "18.24.1", "CVE-2024-42365", True),
  ("asterisk", "18.24.2", "CVE-2024-42365", False),
  ("asterisk", "20.9.2", "CVE-2024-42365", False),
  ("asterisk", "21.4.1", "CVE-2024-42365", True),
  ("asterisk", "21.4.2", "CVE-2024-42365", False),
  ("asterisk", "20.5.0", "CVE-2023-49786", True),
  ("asterisk", "20.5.1", "CVE-2023-49786", False),
  ("asterisk", "21.0.1", "CVE-2023-49786", False),
  # BIND: per-branch.
  ("bind", "9.16.13", "CVE-2022-3080", False),
  ("bind", "9.16.14", "CVE-2022-3080", True),
  ("bind", "9.16.33", "CVE-2022-3080", False),
  ("bind", "9.18.6", "CVE-2022-3080", True),
  ("bind", "9.16.46", "CVE-2023-4408", False),
  ("bind", "9.16.45", "CVE-2023-4408", True),
  ("bind", "9.18.21", "CVE-2023-4408", True),
  ("bind", "9.18.22", "CVE-2023-4408", False),
  ("bind", "9.16.42", "CVE-2023-2828", False),
  ("bind", "9.16.41", "CVE-2023-2828", True),
  ("bind", "9.16.32", "CVE-2022-2795", True),
  ("bind", "9.16.33", "CVE-2022-2795", False),
  ("bind", "9.18.7", "CVE-2022-2795", False),
  # Tomcat 11 and WebLogic 12.2.1.4 / 14.1.1 (KEV rows).
  ("tomcat", "11.0.2", "CVE-2025-24813", True),
  ("tomcat", "11.0.3", "CVE-2025-24813", False),
  ("weblogic", "12.2.1.4.0", "CVE-2023-21839", True),
  ("weblogic", "14.1.1.0.0", "CVE-2023-21839", True),
  ("weblogic", "12.2.1.3.0", "CVE-2023-21839", True),
  ("weblogic", "10.3.6.0", "CVE-2023-21839", False),
  # `==` rows regenerated as ranges: they fire across the published range, not one version.
  ("apache", "2.4.10", "CVE-2018-1312", True),
  ("apache", "2.4.29", "CVE-2018-1312", True),
  ("apache", "2.4.30", "CVE-2018-1312", False),
  ("apache", "2.2.20", "CVE-2017-3169", True),
  ("apache", "2.4.25", "CVE-2017-3169", True),
  ("apache", "2.4.26", "CVE-2017-3169", False),
  ("openssl", "1.0.1f", "CVE-2016-2177", True),
  ("openssl", "1.0.2h", "CVE-2016-2177", True),
  ("openssl", "1.0.2i", "CVE-2016-2177", False),
  ("openssl", "1.0.1t", "CVE-2016-0705", False),
  ("openssl", "1.0.1r", "CVE-2016-0705", True),
  ("openssl", "1.1.0a", "CVE-2016-6309", True),
  ("openssl", "1.1.0b", "CVE-2016-6309", False),
  ("openssl", "3.0.4", "CVE-2022-2274", True),
  ("openssl", "3.0.5", "CVE-2022-2274", False),
  ("openssh", "6.9", "CVE-2016-8858", True),
  ("openssh", "7.4", "CVE-2016-8858", False),
  # KEV additions.
  # CVE-2026-123158 (musl without PAM) is not a row: a version-only row would fire on every glibc host.
  ("openssh", "10.5", "CVE-2026-123158", False),
  ("mongodb", "7.0.27", "CVE-2025-14847", True),
  ("mongodb", "7.0.28", "CVE-2025-14847", False),
  ("exim", "4.91", "CVE-2019-10149", True),
  ("exim", "4.92", "CVE-2019-10149", False),
  ("proftpd", "1.3.5", "CVE-2015-3306", True),
  ("proftpd", "1.3.5a", "CVE-2015-3306", False),
  ("proftpd", "1.3.5e", "CVE-2015-3306", False),
  ("proftpd", "1.3.6", "CVE-2015-3306", False),
  # Other proftpd rows still evaluate with a trailing letter.
  ("proftpd", "1.3.5e", "CVE-2019-12815", True),
  ("proftpd", "1.3.6", "CVE-2019-12815", False),
  # BIND supported-preview (-S1) editions: 9.16.42-S1 etc. carry the fix of the plain release.
  ("bind", "9.16.41-S1", "CVE-2023-2828", True),
  ("bind", "9.16.42-S1", "CVE-2023-2828", False),
  ("bind", "9.16.45-S1", "CVE-2023-4408", True),
  ("bind", "9.16.46-S1", "CVE-2023-4408", False),
  ("bind", "9.18.15", "CVE-2023-2828", True),
  ("bind", "9.18.16", "CVE-2023-2828", False),
  ("bind", "9.19.13", "CVE-2023-2828", True),
  ("bind", "9.19.14", "CVE-2023-2828", False),
  ("bind", "9.19.19", "CVE-2023-4408", True),
  ("bind", "9.19.20", "CVE-2023-4408", False),
  # F7 boundaries.
  ("weblogic", "12.2.1.5.0", "CVE-2023-21839", False),
  ("weblogic", "14.1.2.0.0", "CVE-2023-21839", False),
  ("bind", "9.10.2-P2", "CVE-2015-5477", True),
  ("bind", "9.10.2-P3", "CVE-2015-5477", False),
  ("bind", "9.10.0", "CVE-2015-5477", True),
  ("mongodb", "6.1.0", "CVE-2024-8207", True),
  # MariaDB CVE-2012-2122: 5.1<5.1.62, 5.2<5.2.12, 5.3<5.3.6, 5.5<5.5.23.
  ("mariadb", "5.1.61", "CVE-2012-2122", True),
  ("mariadb", "5.1.62", "CVE-2012-2122", False),
  ("mariadb", "5.2.11", "CVE-2012-2122", True),
  ("mariadb", "5.2.12", "CVE-2012-2122", False),
  ("mariadb", "5.3.5", "CVE-2012-2122", True),
  ("mariadb", "5.3.6", "CVE-2012-2122", False),
  ("mariadb", "5.5.22", "CVE-2012-2122", True),
  ("mariadb", "5.5.23", "CVE-2012-2122", False),
  ("mariadb", "10.11.6", "CVE-2012-2122", False),
  ("mongodb", "6.1.1", "CVE-2024-8207", False),
  # Tomcat 8.5 branch, MariaDB, WebLogic 14.1.1 for CVE-2020-14882.
  ("tomcat", "8.5.100", "CVE-2025-24813", True),
  ("tomcat", "8.5.0", "CVE-2025-24813", True),
  ("weblogic", "14.1.1.0.0", "CVE-2020-14882", True),
  ("weblogic", "14.1.2.0.0", "CVE-2020-14882", False),
  ("bind", "9.9.7-P1", "CVE-2015-5477", True),
  ("bind", "9.9.7-P2", "CVE-2015-5477", False),
  ("wordpress", "6.9.4", "CVE-2026-63030", True),
  ("wordpress", "6.9.5", "CVE-2026-63030", False),
  ("wordpress", "7.0.1", "CVE-2026-60137", True),
  ("wordpress", "6.7.9", "CVE-2026-87902", False),
  ("wordpress", "6.7.8", "CVE-2026-87902", True),
]


class TestCorrectedRows(unittest.TestCase):

  def test_boundaries(self):
    for product, version, cve_id, expected in CASES:
      with self.subTest(product=product, version=version, cve=cve_id):
        self.assertEqual(_fires(product, version, cve_id), expected)

  def test_no_equality_constraint_remains(self):
    self.assertEqual([e.cve_id for e in CVE_DATABASE if "==" in e.constraint], [])

  def test_client_side_postgresql_cve_stays_off_a_server_banner(self):
    self.assertFalse(_fires("postgresql", "13.18", "CVE-2025-1094"))
    self.assertTrue(_fires("postgresql", "13.18", "CVE-2025-1094", applicability="client"))
    self.assertFalse(_fires("postgresql", "17.3", "CVE-2025-1094", applicability="client"))


class TestProftpdProbeKeepsLetter(unittest.TestCase):

  def _probe(self, banner):
    from unittest.mock import MagicMock, patch
    from .conftest import DummyOwner, PentestLocalWorker
    worker = PentestLocalWorker(
      owner=DummyOwner(), target="example.com", job_id="job-ftp",
      initiator="init@example", local_id_prefix="1", worker_target_ports=[21],
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    worker.state["scan_metadata"] = {}
    ftp = MagicMock()
    ftp.getwelcome.return_value = banner
    common = "extensions.business.cybersec.red_mesh.worker.service.common"
    with patch(f"{common}.check_cves", return_value=[]) as check, \
         patch("ftplib.FTP", return_value=ftp):
      worker._service_info_ftp("example.com", 21)
    return check

  def test_trailing_letter_reaches_matcher(self):
    for version in ("1.3.5", "1.3.5a", "1.3.5e", "1.3.6"):
      with self.subTest(version=version):
        check = self._probe(f"220 ProFTPD {version} Server (Debian) [::ffff:10.0.0.1]")
        check.assert_called_once_with("proftpd", version)

  def test_vsftpd_unchanged(self):
    check = self._probe("220 (vsFTPd 3.0.3)")
    check.assert_called_once_with("vsftpd", "3.0.3")

  def test_matcher_orders_letters(self):
    self.assertTrue(_fires("proftpd", "1.3.5", "CVE-2015-3306"))
    for version in ("1.3.5a", "1.3.5e", "1.3.6"):
      self.assertFalse(_fires("proftpd", version, "CVE-2015-3306"), version)


if __name__ == "__main__":
  unittest.main()
