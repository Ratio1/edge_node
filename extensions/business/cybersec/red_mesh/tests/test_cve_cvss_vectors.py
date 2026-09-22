"""Every catalog CVE has its NVD CVSS v3.x vector, and CVE findings carry it (RM-087).

`check_cves` got a vector only from the live NVD cache, which production never
constructs, so every CVE finding read "assigned by probe policy". The vectors
now come from `cve_cvss_vectors.py`, filled from NVD by
`tools/fill_cve_vectors.py`. This test holds the table to the catalog:

- every catalog CVE has a row, or is listed as having no v3.x metric at NVD;
- every row scores;
- every catalog label is the NVD v3.x band (owner decision 2026-09-22: NVD's
  severity is the reference). A refetch that moves a band fails here and
  names the CVE to relabel.
"""

import unittest

from extensions.business.cybersec.red_mesh.cve_cvss_vectors import CVE_CVSS_VECTORS, CVE_WITHOUT_V3
from extensions.business.cybersec.red_mesh.cve_db import CVE_DATABASE, _build_finding, check_cves
from extensions.business.cybersec.red_mesh.cvss import cvss31_base_score, severity_band
from extensions.business.cybersec.red_mesh.findings import enrich_finding_for_probe

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

  def test_every_catalog_label_is_the_nvd_band(self):
    self.assertEqual(
      _disagreements(), {},
      "catalog label differs from NVD's v3.x band (cve_id -> NVD band): relabel it",
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

  def test_every_catalog_cve_with_a_v3_record_gets_its_vector(self):
    for entry in CVE_DATABASE:
      if entry.cve_id in CVE_WITHOUT_V3:
        continue
      with self.subTest(cve_id=entry.cve_id):
        f = _build_finding(entry, entry.product, "1.0", None)
        self.assertEqual(f.cvss_vector, CVE_CVSS_VECTORS[entry.cve_id])


if __name__ == "__main__":
  unittest.main()
