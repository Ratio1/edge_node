"""Phase 2 PR-2.1 — static reference table integrity + CI staleness gate.

Verifies:
  - All three JSON files load and have the documented fields.
  - cwe_to_owasp keys are valid CWE IDs (positive ints).
  - cwe_to_owasp values reference only categories present in
    owasp_categories.json.
  - Every CWE referenced anywhere in cve_db.py has a mapping in
    cwe_to_owasp.json (so the report can always show OWASP for any CVE).
  - cwe_top25 contains exactly 25 ranked entries.
  - Lookup helpers (cwe_to_owasp, owasp_category, all_owasp_categories,
    is_cwe_top25, cwe_top25_rank) behave as documented.
  - Each file's last_refreshed is no older than STALENESS_THRESHOLD_DAYS
    (currently 180 / 6 months).
"""
from __future__ import annotations

import re
import unittest

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.references import (
  STALENESS_THRESHOLD_DAYS,
  all_owasp_categories,
  cwe_top25_rank,
  cwe_to_owasp,
  is_cwe_top25,
  owasp_category,
  reset_caches,
  staleness_days,
)


class TestOwaspCategoriesLoadable(unittest.TestCase):

  def setUp(self):
    reset_caches()

  def test_all_ten_categories_present(self):
    cats = all_owasp_categories()
    codes = [c.code for c in cats]
    expected = [f"A{n:02d}:2021" for n in range(1, 11)]
    self.assertEqual(sorted(codes), expected)

  def test_each_category_has_required_fields(self):
    for cat in all_owasp_categories():
      self.assertTrue(cat.code, f"{cat}: missing code")
      self.assertTrue(cat.name, f"{cat.code}: missing name")
      self.assertTrue(cat.short_name, f"{cat.code}: missing short_name")
      self.assertTrue(cat.description, f"{cat.code}: missing description")
      self.assertGreater(len(cat.description), 50, f"{cat.code}: description too terse")

  def test_unknown_category_returns_none(self):
    self.assertIsNone(owasp_category("A99:2021"))
    self.assertIsNone(owasp_category(""))


class TestCweToOwaspMappings(unittest.TestCase):

  def setUp(self):
    reset_caches()

  def test_every_value_references_known_owasp_category(self):
    cats = {c.code for c in all_owasp_categories()}
    from extensions.business.cybersec.red_mesh.references import _load_cwe_to_owasp
    data = _load_cwe_to_owasp()
    for cwe_str, owasp_codes in data.get("mappings", {}).items():
      for code in owasp_codes:
        self.assertIn(code, cats, f"CWE-{cwe_str} -> unknown category {code}")

  def test_keys_look_like_cwe_ids(self):
    from extensions.business.cybersec.red_mesh.references import _load_cwe_to_owasp
    data = _load_cwe_to_owasp()
    for key in data.get("mappings", {}).keys():
      self.assertRegex(key, r"^[1-9][0-9]*$",
                       f"non-numeric CWE id: {key!r}")

  def test_lookup_returns_tuple(self):
    self.assertEqual(cwe_to_owasp(22), ("A01:2021",))
    self.assertEqual(cwe_to_owasp(89), ("A03:2021",))
    self.assertEqual(cwe_to_owasp(918), ("A10:2021",))
    # CWE-200 maps to two categories
    self.assertEqual(set(cwe_to_owasp(200)), {"A01:2021", "A05:2021"})

  def test_unknown_cwe_returns_empty(self):
    self.assertEqual(cwe_to_owasp(999999), ())
    self.assertEqual(cwe_to_owasp(0), ())
    self.assertEqual(cwe_to_owasp(-5), ())

  def test_every_cwe_in_cve_db_has_mapping(self):
    """Coverage assertion: every CWE referenced in cve_db.py must have
    an entry in cwe_to_owasp so the report can show OWASP for any CVE."""
    missing = []
    for entry in cve_db.CVE_DATABASE:
      cwe_field = getattr(entry, "cwe_id", None)
      if cwe_field is None:
        continue
      # cwe_id may be int or list[int] depending on the schema
      cwe_ids = cwe_field if isinstance(cwe_field, (list, tuple)) else [cwe_field]
      for cwe in cwe_ids:
        if isinstance(cwe, int) and cwe > 0:
          if cwe_to_owasp(cwe) == ():
            missing.append((entry.cve_id, cwe))
    if missing:
      self.fail(
        f"{len(missing)} CWE(s) in cve_db.py have no OWASP mapping:\n  " +
        "\n  ".join(f"{cve}: CWE-{cwe}" for cve, cwe in missing[:10])
      )


class TestCweTop25(unittest.TestCase):

  def setUp(self):
    reset_caches()

  def test_exactly_25_entries(self):
    from extensions.business.cybersec.red_mesh.references import _load_cwe_top25
    data = _load_cwe_top25()
    self.assertEqual(len(data["ranked"]), 25)

  def test_ranks_are_1_to_25(self):
    from extensions.business.cybersec.red_mesh.references import _load_cwe_top25
    data = _load_cwe_top25()
    ranks = sorted(e["rank"] for e in data["ranked"])
    self.assertEqual(ranks, list(range(1, 26)))

  def test_known_top25_entries(self):
    # Per CWE Top 25 (2024), XSS is rank 1 and Out-of-bounds Write is rank 2.
    self.assertTrue(is_cwe_top25(79))
    self.assertEqual(cwe_top25_rank(79), 1)
    self.assertTrue(is_cwe_top25(787))
    self.assertEqual(cwe_top25_rank(787), 2)

  def test_non_top25_returns_false(self):
    self.assertFalse(is_cwe_top25(999999))
    self.assertIsNone(cwe_top25_rank(999999))


class TestStalenessGate(unittest.TestCase):
  """Forces a refresh roughly every 6 months."""

  def setUp(self):
    reset_caches()

  def test_files_are_not_stale(self):
    for fname in ("owasp_categories.json", "cwe_to_owasp.json", "cwe_top25.json"):
      days = staleness_days(fname)
      self.assertLessEqual(
        days, STALENESS_THRESHOLD_DAYS,
        f"{fname} is {days} days old (>{STALENESS_THRESHOLD_DAYS}). "
        f"Refresh per docs in references/README.md"
      )


if __name__ == "__main__":
  unittest.main()
