"""Version matcher unit cases and CVE-2025-32433 branch boundaries (RM-168).

Cases come from RM-193 report 8 (T4). The MariaDB banner case is a probe-level
test (see test_cve_probe_routing.py), not a matcher case.
"""
import unittest

from extensions.business.cybersec.red_mesh.cve_db import _matches_constraint, check_cves

UNIT = [
  # (product, version, constraint, expected, why)
  ('', '8.9', '<8.9p1', True, 'openssh: probe drops p1; 8.9 sorts below 8.9p1'),
  ('', '8.9p1', '<8.9', False, 'p1 > base'),
  ('openssl', '1.0.1f', '<1.0.1g', True, 'openssl letter'),
  ('openssl', '1.0.1', '<1.0.1a', True, 'openssl base < a'),
  ('', '3.0.0rc1', '<3.0.0', True, 'rc before release'),
  ('', '3.0.0-beta1', '<3.0.0', True, 'beta before release'),
  ('proftpd', '1.3.6rc2', '<1.3.6', True, 'proftpd rc'),
  ('', '9.0.0.M1', '<9.0.0', True, 'tomcat milestone'),
  ('bind', '9.18.24-S1', '==9.18.24', False, 'BIND S1 is a different build'),
  ('bind', '9.18.24-S1', '>=9.18.24', True, 'BIND S1 sorts after the plain build'),
  ('', '1:8.9p1-3ubuntu0.10', '<9.8', True, 'epoch stripped'),
  ('', '2.4.57 (Ubuntu)', '<2.4.58', True, 'Server header'),
  ('', '9.4.51.v20230217', '<9.4.52', True, 'jetty stamp'),
  ('', '2022.83', '<2022.83', False, 'dropbear'),
  ('', '4.96.1', '<4.96.1', False, 'exim point'),
  ('', '10.11.6', '>=10.11.0,<10.11.7', True, 'mariadb'),
  ('php', '8.1.0-dev', '<8.1.0', True, 'php dev build before 8.1.0'),
  ('', '6.6.1p1', '<6.6.2', True, 'opensmtpd portable'),
  ('', '2.5.10.1', '<2.5.10.1', False, 'four-part'),
  ('', '1.0.2', '==1.0.2', True, 'exact'),
  ('openssl', '1.0.2', '==1.0.2a', False, 'exact letter'),
  ('', '3.0.0a1', '<3.0.0rc1', True, 'alpha before rc'),
  ('', '8.1.0-dev', '<8.1.0rc1', True, 'dev before rc'),
  ('', '3.0.0b1', '>3.0.0a1', True, 'beta after alpha'),
  ('bind', '9.10.3-P4', '>9.10.3', True, 'BIND patch level sorts after the plain build'),
  ('bind', '9.10.3-P4', '<9.10.3-P5', True, 'BIND patch levels order'),
  ('openssl', '1.0.2a', '<1.0.2b', True, 'openssl: single letter is a release, not alpha'),
  ('openssl', '1.0.2a', '>=1.0.2', True, 'openssl: letter release after base'),
]


class TestMatcherUnitCases(unittest.TestCase):

  def test_report8_unit_cases(self):
    for product, version, constraint, expected, why in UNIT:
      with self.subTest(version=version, constraint=constraint, why=why):
        self.assertEqual(_matches_constraint(version, constraint, product), expected)

  def test_product_argument_is_optional(self):
    self.assertTrue(_matches_constraint("1.4.1", "<1.4.3"))


class TestHostileBanner(unittest.TestCase):

  def test_newline_banner_returns_fast(self):
    import time
    start = time.monotonic()
    self.assertFalse(_matches_constraint("1" * 2048 + "\nx", "<1.0"))
    self.assertFalse(_matches_constraint("1" * 5000, "<1.0"))
    self.assertLess(time.monotonic() - start, 1.0)


class TestErlangCve202532433(unittest.TestCase):
  """The probe reports the ssh app version (<= 5.x) or the OTP release (>= 17)."""

  def _hit(self, version):
    return any("CVE-2025-32433" in f.title for f in check_cves("erlang_ssh", version))

  def test_affected_versions(self):
    for version in (
      "4.15.3.11", "5.0", "5.1.4.7", "5.2.2", "5.2.9",   # ssh application
      "17.0", "25.3.2.19", "26.0", "26.2.5.10", "27.0", "27.3.2",  # OTP release
    ):
      with self.subTest(version=version):
        self.assertTrue(self._hit(version))

  def test_fixed_versions(self):
    for version in (
      "4.15.3.12", "5.1.4.8", "5.2.10", "5.3.0",          # ssh application
      "25.3.2.20", "26.2.5.11", "27.3.3", "27.4",          # OTP release
    ):
      with self.subTest(version=version):
        self.assertFalse(self._hit(version))

  def test_one_finding_per_cve(self):
    ids = [f.title for f in check_cves("erlang_ssh", "5.2.9") if "CVE-2025-32433" in f.title]
    self.assertEqual(len(ids), 1)


if __name__ == "__main__":
  unittest.main()
