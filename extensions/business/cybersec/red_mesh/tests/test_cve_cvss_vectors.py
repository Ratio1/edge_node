"""Every catalog CVE has its NVD CVSS v3.x vector, and CVE findings carry it (RM-087).

`check_cves` got a vector only from the live NVD cache, which production never
constructs, so every CVE finding read "assigned by probe policy". The vectors
now come from `cve_cvss_vectors.py`, filled from NVD by
`tools/fill_cve_vectors.py`. This test holds the table to the catalog:

- every catalog CVE has a row, or is listed as having no v3.x metric at NVD;
- every row scores;
- a CVE whose NVD band differs from the catalog label is listed below, and the
  list may only shrink: its vector is withheld (the label is the catalog's,
  not NVD's), so each entry is a label waiting for review.
"""

import unittest

from extensions.business.cybersec.red_mesh.cve_cvss_vectors import CVE_CVSS_VECTORS, CVE_WITHOUT_V3
from extensions.business.cybersec.red_mesh.cve_db import CVE_DATABASE, _build_finding, check_cves
from extensions.business.cybersec.red_mesh.cvss import cvss31_base_score, severity_band
from extensions.business.cybersec.red_mesh.findings import enrich_finding_for_probe

# cve_id -> NVD band, where it differs from the catalog label (fetched 2026-09-22).
_LABEL_DIFFERS_FROM_NVD = {
  "CVE-2014-3120": "HIGH",  # catalog CRITICAL, NVD 8.1
  "CVE-2016-7406": "CRITICAL",  # catalog HIGH, NVD 9.8
  "CVE-2016-8705": "CRITICAL",  # catalog HIGH, NVD 9.8
  "CVE-2016-8706": "HIGH",  # catalog CRITICAL, NVD 8.1
  "CVE-2017-10271": "HIGH",  # catalog CRITICAL, NVD 7.5
  "CVE-2017-11480": "HIGH",  # catalog MEDIUM, NVD 7.5
  "CVE-2017-12636": "HIGH",  # catalog CRITICAL, NVD 7.2
  "CVE-2017-7679": "CRITICAL",  # catalog HIGH, NVD 9.8
  "CVE-2017-8295": "MEDIUM",  # catalog HIGH, NVD 5.9
  "CVE-2017-9805": "HIGH",  # catalog CRITICAL, NVD 8.1
  "CVE-2019-6111": "MEDIUM",  # catalog HIGH, NVD 5.9
  "CVE-2020-1971": "MEDIUM",  # catalog HIGH, NVD 5.9
  "CVE-2020-8617": "MEDIUM",  # catalog HIGH, NVD 5.9
  "CVE-2020-8794": "CRITICAL",  # catalog HIGH, NVD 9.8
  "CVE-2021-27216": "MEDIUM",  # catalog HIGH, NVD 6.3
  "CVE-2021-40438": "CRITICAL",  # catalog HIGH, NVD 9.0
  "CVE-2021-44142": "HIGH",  # catalog CRITICAL, NVD 8.8
  "CVE-2022-35951": "CRITICAL",  # catalog HIGH, NVD 9.8
  "CVE-2023-23752": "MEDIUM",  # catalog HIGH, NVD 5.3
  "CVE-2023-42114": "MEDIUM",  # catalog HIGH, NVD 5.3
  "CVE-2023-42116": "CRITICAL",  # catalog HIGH, NVD 9.8
  "CVE-2023-49786": "MEDIUM",  # catalog HIGH, NVD 5.9
  "CVE-2024-10976": "MEDIUM",  # catalog HIGH, NVD 5.4
  "CVE-2024-12797": "MEDIUM",  # catalog HIGH, NVD 6.3
  "CVE-2024-20973": "MEDIUM",  # catalog HIGH, NVD 6.5
  "CVE-2024-39929": "MEDIUM",  # catalog CRITICAL, NVD 5.4
  "CVE-2024-40725": "MEDIUM",  # catalog HIGH, NVD 5.3
  "CVE-2024-46981": "CRITICAL",  # catalog HIGH, NVD 9.8
  "CVE-2024-6387": "HIGH",  # catalog CRITICAL, NVD 8.1
  "CVE-2024-8207": "MEDIUM",  # catalog HIGH, NVD 6.7
  "CVE-2025-26465": "MEDIUM",  # catalog HIGH, NVD 6.8
}


def _catalog_labels():
  """cve_id -> set of catalog labels (a CVE listed per range may repeat)."""
  labels = {}
  for entry in CVE_DATABASE:
    labels.setdefault(entry.cve_id, set()).add(entry.severity.value)
  return labels


def _disagreements():
  out = {}
  for cve_id, labels in _catalog_labels().items():
    vector = CVE_CVSS_VECTORS.get(cve_id)
    if vector:
      band = severity_band(cvss31_base_score(vector))
      if labels != {band}:
        out[cve_id] = band
  return out


class TestCveCvssTable(unittest.TestCase):

  def test_every_catalog_cve_has_a_row(self):
    missing = sorted(set(_catalog_labels()) - set(CVE_CVSS_VECTORS) - CVE_WITHOUT_V3)
    self.assertEqual(missing, [], "rerun tools/fill_cve_vectors.py")

  def test_no_row_outside_the_catalog(self):
    self.assertEqual(sorted((set(CVE_CVSS_VECTORS) | CVE_WITHOUT_V3) - set(_catalog_labels())), [])

  def test_every_row_scores(self):
    for cve_id, vector in CVE_CVSS_VECTORS.items():
      with self.subTest(cve_id=cve_id):
        self.assertTrue(vector.startswith(("CVSS:3.1/", "CVSS:3.0/")))
        self.assertIsNotNone(cvss31_base_score(vector))

  def test_label_disagreements_are_listed_and_only_shrink(self):
    self.assertEqual(
      _disagreements(), _LABEL_DIFFERS_FROM_NVD,
      "a catalog label and its NVD band differ (list it, or fix the label), "
      "or a listed one no longer does (remove it)",
    )


class TestCveFindingCarriesTheVector(unittest.TestCase):

  def _finding(self, product, version, cve_id):
    for f in check_cves(product, version):
      if cve_id in (f.cve or ()):
        return f
    self.fail(f"{cve_id} did not fire on {product} {version}")

  def test_agreeing_cve_is_cvss_sourced(self):
    f = self._finding("apache", "2.4.49", "CVE-2021-41773")
    self.assertEqual(f.cvss_vector, CVE_CVSS_VECTORS["CVE-2021-41773"])
    self.assertEqual(f.cvss_score, cvss31_base_score(f.cvss_vector))
    self.assertEqual(f.cvss_data_freshness, "")  # static, not fetched at scan time
    self.assertEqual(enrich_finding_for_probe(f, "_service_info_http").severity_source, "cvss")

  def test_disagreeing_cve_keeps_its_label_without_a_vector(self):
    entries = [e for e in CVE_DATABASE if e.cve_id in _LABEL_DIFFERS_FROM_NVD]
    if not entries:
      self.skipTest("no catalog label differs from NVD")
    f = _build_finding(entries[0], entries[0].product, "1.0", None)
    self.assertEqual(f.severity, entries[0].severity)
    self.assertEqual(f.cvss_vector, "")
    self.assertIsNone(f.cvss_score)
    self.assertEqual(enrich_finding_for_probe(f, "_service_info_http").severity_source, "probe_policy")


if __name__ == "__main__":
  unittest.main()
