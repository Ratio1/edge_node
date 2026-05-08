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

  def test_existing_graybox_emitted_scenarios_are_registered(self):
    redmesh_root = Path(__file__).resolve().parents[1]
    source_ids = set()
    for path in (redmesh_root / "graybox").rglob("*.py"):
      source_ids.update(re.findall(
        r"scenario_id\s*=\s*[\"'](PT-[A-Z0-9]+-\d+|PT-API7-\d+)[\"']",
        path.read_text(),
      ))
    catalog_ids = {entry["id"] for entry in GRAYBOX_SCENARIO_CATALOG}
    self.assertTrue(source_ids)
    self.assertEqual(source_ids - catalog_ids, set())


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
