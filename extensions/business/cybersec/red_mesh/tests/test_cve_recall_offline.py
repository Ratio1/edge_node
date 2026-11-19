"""Offline CVE recall against the vulhub expected-CVE table (RM-168).

Catalog only, no scratch database. Each row is a vulhub environment and the
CVE it exists to demonstrate; recall is how many the live matcher reports.
Rows whose product key no probe passes ("dead keys") are reported separately.
Table source: RM-193 assessment 2026-11-13_vulndb, scripts/proto_eval2.py EXPECT.
"""
import unittest

from extensions.business.cybersec.red_mesh.detection_inventory import PRODUCTS_WITHOUT_PROBE

from extensions.business.cybersec.red_mesh.cve_db import (
  check_cves,
  parse_distro_package,
)

EXPECT = [
  ('samba', '4.6.3', 'CVE-2017-7494'), ('libssh', '0.8.1', 'CVE-2018-10933'),
  ('opensmtpd', '6.6.1p1', 'CVE-2020-7247'), ('erlang_ssh', '5.2.9', 'CVE-2025-32433'),
  ('erlang_ssh', '27.3.2', 'CVE-2025-32433'), ('mysql', '5.5.23', 'CVE-2012-2122'),
  ('postgresql', '10.7', 'CVE-2019-9193'), ('elasticsearch', '1.4.2', 'CVE-2015-1427'),
  ('couchdb', '3.2.1', 'CVE-2022-24706'), ('couchdb', '2.1.0', 'CVE-2017-12635'),
  ('couchdb', '2.1.0', 'CVE-2017-12636'), ('influxdb', '1.6.6', 'CVE-2019-20933'),
  ('wordpress', '4.6', 'CVE-2016-10033'), ('drupal', '8.5.0', 'CVE-2018-7600'),
  ('joomla', '4.2.7', 'CVE-2023-23752'), ('django', '1.11.4', 'CVE-2017-12794'),
  ('laravel_ignition', '2.5.1', 'CVE-2021-3129'), ('apache', '2.4.49', 'CVE-2021-41773'),
  ('apache', '2.4.50', 'CVE-2021-42013'), ('openssl', '1.0.1c', 'CVE-2014-0160'),
  ('tomcat', '9.0.30', 'CVE-2020-1938'), ('nginx', '1.4.2', 'CVE-2013-4547'),
  ('openssh', '7.7', 'CVE-2018-15473'), ('jboss', '6.1.0', 'CVE-2017-12149'),
  ('jboss', '4.0.5', 'CVE-2017-7504'), ('weblogic', '10.3.6.0', 'CVE-2017-10271'),
  ('weblogic', '12.2.1.3.0', 'CVE-2023-21839'), ('weblogic', '12.2.1.3.0', 'CVE-2020-14882'),
  ('struts2', '2.3.30', 'CVE-2017-5638'), ('struts2', '2.5.12', 'CVE-2017-9805'),
  ('struts2', '2.5.25', 'CVE-2020-17530'), ('spring_framework', '5.3.17', 'CVE-2022-22965'),
  ('spring_cloud_function', '3.2.2', 'CVE-2022-22963'), ('openssh', '8.9', 'CVE-2024-6387'),
]

# One source: the inventory's list of keys no probe passes (libvncserver has no EXPECT row).
DEAD_KEYS = PRODUCTS_WITHOUT_PROBE

# Measured at base 87b09e5 (before RM-168): 27 of 34 rows hit (20 of 27 live rows; all 7 dead-key rows hit).
# After the phase 1 matcher fixes and the phase 2 rows (MySQL CVE-2012-2122, JBoss CVE-2017-7504 added):
# 31 of 34 (24 of 27 live). Remaining misses: PostgreSQL CVE-2019-9193 and OpenSSH CVE-2018-15473 (no
# catalog row) and OpenSSH CVE-2024-6387 on 8.9p1 Ubuntu 3ubuntu0.10 (fixed by backport, so not reported).
# The catalog must not lower it.
BASELINE_ALL = 31
BASELINE_LIVE = 24


def _recall():
  hits = {}
  for product, version, cve in EXPECT:
    package = None
    if (product, version) == ('openssh', '8.9'):
      package = parse_distro_package('SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10')
    found = {f.cve[0] if isinstance(f.cve, (list, tuple)) else f.cve
             for f in check_cves(product, version, package=package)}
    hits[(product, version, cve)] = cve in found
  return hits


class TestOfflineRecall(unittest.TestCase):

  def test_recall_not_below_baseline(self):
    hits = _recall()
    live = {k: v for k, v in hits.items() if k[0] not in DEAD_KEYS}
    n_all, n_live = sum(hits.values()), sum(live.values())
    misses = [k for k, ok in hits.items() if not ok]
    detail = f"recall all={n_all}/{len(hits)} live={n_live}/{len(live)} misses={misses}"
    self.assertGreaterEqual(n_all, BASELINE_ALL, detail)
    self.assertGreaterEqual(n_live, BASELINE_LIVE, detail)


if __name__ == "__main__":
  unittest.main()
