"""Detection inventory coverage thresholds for RedMesh."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh.constants import NETWORK_FEATURE_METHODS
from extensions.business.cybersec.red_mesh.cve_db import check_cves
from extensions.business.cybersec.red_mesh.detection_inventory import build_detection_inventory
from extensions.business.cybersec.red_mesh.graybox.scenario_catalog import (
  GRAYBOX_SCENARIO_CATALOG,
)
from extensions.business.cybersec.red_mesh.worker.blackbox_detection_catalog import (
  BLACKBOX_DETECTION_CATALOG,
)


class TestDetectionInventory(unittest.TestCase):

  def test_detection_inventory_meets_coverage_targets(self):
    counts = build_detection_inventory().counts()
    self.assertGreaterEqual(counts["total"], 300)
    self.assertGreaterEqual(counts["blackbox"], 220)
    self.assertGreaterEqual(counts["graybox"], 80)
    self.assertGreaterEqual(counts["cves"], 200)

  def test_detection_ids_are_unique(self):
    inventory = build_detection_inventory()
    self.assertEqual(len(inventory.cves), inventory.counts()["cves"])
    self.assertEqual(
      len({entry["id"] for entry in BLACKBOX_DETECTION_CATALOG}),
      len(BLACKBOX_DETECTION_CATALOG),
    )
    self.assertEqual(
      len({entry["id"] for entry in GRAYBOX_SCENARIO_CATALOG}),
      len(GRAYBOX_SCENARIO_CATALOG),
    )
    self.assertEqual(
      len(inventory.total),
      len(inventory.cves) + len(inventory.blackbox_detectors) + len(inventory.graybox_scenarios),
    )

  def test_blackbox_catalog_maps_to_registered_network_methods(self):
    known_methods = set(NETWORK_FEATURE_METHODS)
    missing = [
      entry for entry in BLACKBOX_DETECTION_CATALOG
      if entry["probe"] not in known_methods
    ]
    self.assertEqual(missing, [])

  # Valid graybox scenario-id prefixes (see docs/adr/2026-05-12-scenario-id-convention.md):
  #   PT-A<NN>-<NN>     — OWASP Web Top 10 2021 scenarios (existing).
  #   PT-API7-<NN>      — legacy SSRF ID, preserved for backward compatibility.
  #   PT-OAPI<N>-<NN>   — OWASP API Top 10 2023 scenarios (new in v1).
  _SCENARIO_ID_RE = re.compile(
    r"scenario_id\s*=\s*[\"'](PT-A\d+-\d+|PT-API7-\d+|PT-OAPI\d{1,2}-\d+)[\"']"
  )

  def test_existing_graybox_emitted_scenarios_are_registered(self):
    redmesh_root = Path(__file__).resolve().parents[1]
    source_ids = set()
    for path in (redmesh_root / "graybox").rglob("*.py"):
      source_ids.update(self._SCENARIO_ID_RE.findall(path.read_text()))
    catalog_ids = {entry["id"] for entry in GRAYBOX_SCENARIO_CATALOG}
    self.assertTrue(source_ids)
    self.assertEqual(source_ids - catalog_ids, set())

  def test_scenario_id_regex_accepts_all_valid_prefixes(self):
    """Regex must accept the three valid prefixes documented in the ADR."""
    cases = [
      ('scenario_id="PT-A01-01"', "PT-A01-01"),
      ('scenario_id="PT-A07-06"', "PT-A07-06"),
      ('scenario_id="PT-API7-01"', "PT-API7-01"),
      ('scenario_id="PT-OAPI1-01"', "PT-OAPI1-01"),
      ('scenario_id="PT-OAPI9-03"', "PT-OAPI9-03"),
      ('scenario_id="PT-OAPI10-01"', "PT-OAPI10-01"),
    ]
    for source, expected in cases:
      with self.subTest(source=source):
        match = self._SCENARIO_ID_RE.search(source)
        self.assertIsNotNone(match, f"regex failed to match {source!r}")
        self.assertEqual(match.group(1), expected)

  def test_scenario_id_regex_rejects_invalid_prefixes(self):
    """Regex must reject obvious typos so they surface as catalog misses."""
    rejects = [
      'scenario_id="PT-FOO-01"',
      'scenario_id="PT-API1-01"',  # ambiguous w/ PT-A — must use PT-OAPI
      'scenario_id="OAPI1-01"',
      'scenario_id="PT-OAPI-01"',
    ]
    for source in rejects:
      with self.subTest(source=source):
        self.assertIsNone(self._SCENARIO_ID_RE.search(source))


class TestCveVersionNormalization(unittest.TestCase):

  def test_http_banner_versions_match_cves(self):
    findings = check_cves("apache", "Apache/2.4.57 (Ubuntu)")
    self.assertTrue(any("CVE-2024-38475" in f.cve for f in findings))

  def test_ssh_banner_versions_match_cves(self):
    findings = check_cves("openssh", "OpenSSH_8.9p1 Ubuntu-3")
    self.assertTrue(any("CVE-2023-38408" in f.cve for f in findings))

  def test_letter_suffix_versions_match_cves(self):
    findings = check_cves("openssl", "OpenSSL 1.0.1f")
    self.assertTrue(any("CVE-2014-0160" in f.cve for f in findings))
    fixed_findings = check_cves("openssl", "OpenSSL 1.0.1g")
    self.assertFalse(any("CVE-2014-0160" in f.cve for f in fixed_findings))


if __name__ == "__main__":
  unittest.main()
