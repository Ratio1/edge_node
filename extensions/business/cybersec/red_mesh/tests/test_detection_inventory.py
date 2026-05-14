"""Detection inventory coverage thresholds for RedMesh."""

from __future__ import annotations

import re
import ast
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh.constants import NETWORK_FEATURE_METHODS
from extensions.business.cybersec.red_mesh.cve_db import check_cves
from extensions.business.cybersec.red_mesh.detection_inventory import build_detection_inventory
from extensions.business.cybersec.red_mesh.graybox.scenario_catalog import (
  GRAYBOX_SCENARIO_CATALOG,
  attack_for_scenario,
)
from extensions.business.cybersec.red_mesh.worker.blackbox_detection_catalog import (
  BLACKBOX_DETECTION_CATALOG,
)


class TestDetectionInventory(unittest.TestCase):

  def test_detection_inventory_meets_coverage_targets(self):
    counts = build_detection_inventory().counts()
    self.assertGreaterEqual(counts["total"], 300)
    self.assertGreaterEqual(counts["blackbox"], 220)
    # Graybox floor bumped from 80 -> 103 by Subphase 1.2 of the API Top 10
    # plan (23 new PT-OAPI* entries). Post-implementation target is >=120
    # (continued OWASP Web Top 10 closing).
    self.assertGreaterEqual(counts["graybox"], 103)
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
  _SCENARIO_ID_VALUE_RE = re.compile(
    r"^(PT-A\d+-\d+|PT-API7-\d+|PT-OAPI\d{1,2}-\d+)$"
  )
  _SCENARIO_CALLS = {
    "emit_vulnerable",
    "emit_clean",
    "emit_inconclusive",
    "run_safe_scenario",
    "run_stateful",
  }

  @classmethod
  def _collect_ast_scenario_ids(cls, redmesh_root):
    source_ids = set()
    for path in (redmesh_root / "graybox").rglob("*.py"):
      tree = ast.parse(path.read_text(), filename=str(path))
      for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
          continue
        func = node.func
        name = ""
        if isinstance(func, ast.Attribute):
          name = func.attr
        elif isinstance(func, ast.Name):
          name = func.id
        candidates = []
        if name in cls._SCENARIO_CALLS and node.args:
          candidates.append(node.args[0])
        if name == "GrayboxFinding":
          candidates.extend(
            kw.value for kw in node.keywords
            if kw.arg == "scenario_id"
          )
        candidates.extend(
          kw.value for kw in node.keywords
          if kw.arg == "scenario_id"
        )
        for candidate in candidates:
          if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str):
            if cls._SCENARIO_ID_VALUE_RE.match(candidate.value):
              source_ids.add(candidate.value)
    return source_ids

  def test_existing_graybox_emitted_scenarios_are_registered(self):
    redmesh_root = Path(__file__).resolve().parents[1]
    source_ids = self._collect_ast_scenario_ids(redmesh_root)
    for path in (redmesh_root / "graybox").rglob("*.py"):
      source_ids.update(self._SCENARIO_ID_RE.findall(path.read_text()))
    catalog_ids = {entry["id"] for entry in GRAYBOX_SCENARIO_CATALOG}
    self.assertTrue(source_ids)
    self.assertEqual(source_ids - catalog_ids, set())

  def test_api_probe_modules_use_emit_helpers_for_findings(self):
    """New API probe families should not bypass central emission helpers."""
    redmesh_root = Path(__file__).resolve().parents[1]
    direct = []
    for path in (redmesh_root / "graybox" / "probes").glob("api_*.py"):
      tree = ast.parse(path.read_text(), filename=str(path))
      for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
          continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else ""
        if name == "GrayboxFinding":
          direct.append(f"{path.name}:{node.lineno}")
    self.assertEqual(direct, [])

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

  def test_v1_api_scenarios_have_non_empty_attack_mapping(self):
    """Every v1 OWASP API Top 10 scenario must declare ATT&CK techniques.

    Implements the mandatory ATT&CK mapping requirement from Subphase 1.2
    of the API Top 10 plan. The catalog is the single source of truth for
    `attack=[]` defaults emitted by probes via `ProbeBase.emit_vulnerable`.
    """
    # In v1, the prefix `PT-OAPI` identifies the new API Top 10 scenarios.
    # The legacy `PT-API7-01` is also subject to this requirement so the
    # SSRF probe carries an ATT&CK mapping consistent with the others.
    mandatory_prefixes = ("PT-OAPI", "PT-API7")
    missing = []
    for entry in GRAYBOX_SCENARIO_CATALOG:
      sid = entry["id"]
      if not any(sid.startswith(p) for p in mandatory_prefixes):
        continue
      attack = entry.get("attack")
      if not attack:
        missing.append(sid)
    self.assertEqual(
      missing,
      [],
      f"v1 API scenarios missing non-empty `attack` mapping: {missing}",
    )

  def test_attack_for_scenario_helper(self):
    """Helper returns catalog's `attack` list or empty for unknown/legacy IDs."""
    # Known new entry
    self.assertEqual(attack_for_scenario("PT-OAPI1-01"), ["T1190", "T1078"])
    # Legacy SSRF
    self.assertEqual(attack_for_scenario("PT-API7-01"), ["T1190"])
    # Legacy PT-A* without explicit attack -> empty
    self.assertEqual(attack_for_scenario("PT-A01-01"), [])
    # Unknown id -> empty (not KeyError)
    self.assertEqual(attack_for_scenario("PT-NOT-REAL-99"), [])

  def test_v1_api_scenario_count(self):
    """v1 catalog contains exactly 23 new PT-OAPI scenarios; no PT-OAPI10."""
    oapi_ids = {
      entry["id"] for entry in GRAYBOX_SCENARIO_CATALOG
      if entry["id"].startswith("PT-OAPI")
    }
    self.assertEqual(len(oapi_ids), 23)
    # API10 deliberately omitted in v1 (Phase 9 follow-up)
    self.assertNotIn("PT-OAPI10-01", oapi_ids)
    # Spot-check coverage per category
    for cat in (1, 2, 3, 4, 5, 6, 8, 9):
      self.assertTrue(
        any(i.startswith(f"PT-OAPI{cat}-") for i in oapi_ids),
        f"missing PT-OAPI{cat}-* entries",
      )


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
