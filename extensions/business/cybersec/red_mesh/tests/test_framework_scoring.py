"""RM-120 phase 2 — `maturity_two_axis.v1` scoring rules and goldens.

Goldens are hand-computed on a seven-control mini pack whose arithmetic fits in a sentence, so the
expected numbers do not come from the module under test. The real `ro.dnsc.o1-2026` pack is used
for the structural rules (management-aspect and key-measure exclusions, exclusion limits) and for
uniform-score sanity checks whose results follow from the thresholds alone. The last test measures
the serialised size of a full Essential draft at the caps with Romanian diacritics and prints the
numbers the contract records.
"""
from __future__ import annotations

import json
import unittest
from fractions import Fraction

from extensions.business.cybersec.red_mesh.references.framework_packs import (
  controls_for_level,
  load_framework_pack,
)
from extensions.business.cybersec.red_mesh.services.framework_scoring import (
  CAPS,
  NA,
  required_remediation_items,
  score,
  validate_for_submit,
  validate_scores,
)

PACK_ID = "ro.dnsc.o1-2026"


def _control(ref_id, entry_level, key_measure=False, management_aspect=False, order=0):
  return {"ref_id": ref_id, "category": ref_id.split("-")[0], "subcategory": ref_id.rsplit(".", 1)[0],
          "entry_level": entry_level, "key_measure": key_measure, "management_aspect": management_aspect,
          "order": order}


MINI_PACK = {
  "pack_id": "mini", "levels": ["basic", "important", "essential"],
  "thresholds": {
    "basic": {"key_measure_min": 2.5, "category_min": None, "total_min": 2.5, "excluded_value": 2.5, "max_excluded": 1},
    "important": {"key_measure_min": 3.0, "category_min": None, "total_min": 3.0, "excluded_value": 3.0, "max_excluded": 3},
    "essential": {"key_measure_min": 3.0, "category_min": 3.0, "total_min": 3.5, "excluded_value": 3.0, "max_excluded": 5,
                  "management_aspect_excludable": False},
  },
  "controls": [
    _control("A.X-01.1", "basic", key_measure=True, order=1),
    _control("A.X-01.2", "basic", order=2),
    _control("A.X-02.1", "important", order=3),
    _control("A.Y-01.1", "basic", order=4),
    _control("B.Z-01.1", "important", management_aspect=True, order=5),
    _control("B.Z-01.2", "essential", key_measure=True, order=6),
    _control("B.Z-02.1", "essential", management_aspect=True, order=7),
  ],
}


def _s(doc, impl, just="ok"):
  return {"documentation": doc, "implementation": impl, "excluded": False,
          "justification": {"documentation": just, "implementation": just}}


def _x(reason="nu se aplică"):
  return {"documentation": NA, "implementation": NA, "excluded": True, "exclusion_justification": reason}


def _codes(errors):
  return [e["code"] for e in errors]


class TestBasicGolden(unittest.TestCase):
  """Basic counts A.X-01.1 (key measure), A.X-01.2, A.Y-01.1.

  Scores: key measure 2/3 (= 2.5, on the threshold); A.X-01.2 excluded (reads 2.5/2.5);
  A.Y-01.1 3/2. Subcategory A.X-01: doc (2 + 2.5)/2 = 2.25, impl (3 + 2.5)/2 = 2.75; A.Y-01: 3/2.
  Category A.X: 2.25/2.75 -> maturity 2.5; A.Y: 3/2 -> 2.5. Total (2.5 + 2.5)/2 = 2.5: passes
  exactly on the threshold. Per-axis totals: doc (2.25 + 3)/2 = 2.625, impl (2.75 + 2)/2 = 2.375.
  """

  SCORES = {"A.X-01.1": _s(2, 3), "A.X-01.2": _x(), "A.Y-01.1": _s(3, 2)}

  def test_values(self):
    self.assertEqual(validate_scores(MINI_PACK, "basic", self.SCORES), [])
    c = score(MINI_PACK, "basic", self.SCORES)
    self.assertTrue(c["complete"])
    self.assertEqual(c["subcategories"]["A.X-01"], {"documentation": 2.25, "implementation": 2.75})
    self.assertEqual(c["subcategories"]["A.Y-01"], {"documentation": 3.0, "implementation": 2.0})
    self.assertEqual(c["categories"]["A.X"]["maturity"], 2.5)
    self.assertEqual(c["categories"]["A.Y"]["maturity"], 2.5)
    self.assertEqual(c["total"], 2.5)
    self.assertEqual(c["totals_per_axis"], {"documentation": 2.625, "implementation": 2.375})
    self.assertEqual(c["key_measures"]["A.X-01.1"]["score"], 2.5)
    self.assertEqual(c["key_measures"]["A.X-01.1"]["below_target_axes"], ["documentation"])
    self.assertEqual(c["exclusions"], {"ids": ["A.X-01.2"], "count": 1, "max": 1, "excluded_value": 2.5})
    self.assertTrue(c["verdict"]["passed"])
    self.assertEqual(c["verdict"]["failing_key_measures"], [])
    self.assertEqual(c["verdict"]["failing_categories"], [])
    self.assertFalse(c["verdict"]["total_failed"])

  def test_key_measure_at_two_two_fails_and_is_named(self):
    scores = dict(self.SCORES, **{"A.X-01.1": _s(2, 2)})
    c = score(MINI_PACK, "basic", scores)
    self.assertEqual(c["key_measures"]["A.X-01.1"]["score"], 2.0)
    self.assertEqual(c["verdict"]["failing_key_measures"], ["A.X-01.1"])
    self.assertFalse(c["verdict"]["passed"])
    # A.X-01: doc (2 + 2.5)/2 = 2.25, impl (2 + 2.5)/2 = 2.25 -> A.X 2.25; total (2.25 + 2.5)/2 = 2.375
    self.assertEqual(c["total"], 2.375)
    self.assertTrue(c["verdict"]["total_failed"])
    self.assertEqual(required_remediation_items(c), ["A.X-01.1", "total"])

  def test_second_exclusion_at_basic_is_over_the_limit(self):
    scores = dict(self.SCORES, **{"A.Y-01.1": _x()})
    errors = validate_scores(MINI_PACK, "basic", scores)
    self.assertEqual(_codes(errors), ["exclusion_over_limit"])
    self.assertEqual(errors[0]["ids"], ["A.X-01.2", "A.Y-01.1"])
    self.assertEqual((errors[0]["count"], errors[0]["max"]), (2, 1))

  def test_excluding_a_key_measure_is_refused(self):
    scores = dict(self.SCORES, **{"A.X-01.1": _x(), "A.X-01.2": _s(3, 3)})
    self.assertEqual(_codes(validate_scores(MINI_PACK, "basic", scores)), ["exclusion_key_measure"])

  def test_exclusion_needs_a_justification_and_na_on_both_axes(self):
    scores = dict(self.SCORES, **{"A.X-01.2": _x("")})
    self.assertEqual(_codes(validate_scores(MINI_PACK, "basic", scores)), ["exclusion_justification_missing"])
    half = {"documentation": NA, "implementation": 3, "excluded": True, "exclusion_justification": "x"}
    scores = dict(self.SCORES, **{"A.X-01.2": half})
    self.assertEqual(_codes(validate_scores(MINI_PACK, "basic", scores)), ["excluded_not_na"])
    loose = {"documentation": NA, "implementation": 3, "excluded": False}
    scores = dict(self.SCORES, **{"A.X-01.2": loose})
    self.assertEqual(_codes(validate_scores(MINI_PACK, "basic", scores)), ["na_without_exclusion"])

  def test_off_level_and_unknown_controls_are_reported(self):
    scores = dict(self.SCORES, **{"B.Z-01.2": _s(3, 3), "ZZ.ZZ-99.9": _s(1, 1)})
    codes = _codes(validate_scores(MINI_PACK, "basic", scores))
    self.assertEqual(sorted(codes), ["control_not_in_level", "unknown_control"])

  def test_bad_values_are_refused(self):
    scores = dict(self.SCORES, **{"A.Y-01.1": {"documentation": 6, "implementation": "3", "excluded": False}})
    self.assertEqual(_codes(validate_scores(MINI_PACK, "basic", scores)), ["invalid_score_value"])
    scores = dict(self.SCORES, **{"A.Y-01.1": {"documentation": True, "implementation": 3, "excluded": False}})
    self.assertEqual(_codes(validate_scores(MINI_PACK, "basic", scores)), ["invalid_score_value"])


class TestImportantGolden(unittest.TestCase):
  """Important counts A.X-01.1 (key measure), A.X-01.2, A.X-02.1, A.Y-01.1, B.Z-01.1 (management
  aspect, excludable at Important).

  Three non-key exclusions (the limit): A.X-01.2, A.X-02.1, B.Z-01.1, each reading 3/3. Key measure
  3/3; A.Y-01.1 2/2. Subcategories: A.X-01 (3 + 3)/2 = 3 on both axes; A.X-02 3/3; A.Y-01 2/2;
  B.Z-01 3/3. Categories: A.X 3, A.Y 2, B.Z 3. Total (3 + 2 + 3)/3 = 8/3: fails the 3.0 floor with
  every key measure passing and no category floor at Important, so only `total` needs remediation.
  """

  SCORES = {"A.X-01.1": _s(3, 3), "A.X-01.2": _x(), "A.X-02.1": _x(), "A.Y-01.1": _s(2, 2), "B.Z-01.1": _x()}

  def test_values(self):
    self.assertEqual(validate_scores(MINI_PACK, "important", self.SCORES), [])
    c = score(MINI_PACK, "important", self.SCORES)
    self.assertEqual(c["exclusions"]["count"], 3)
    self.assertEqual(c["categories"]["A.X"]["maturity"], 3.0)
    self.assertEqual(c["categories"]["A.Y"]["maturity"], 2.0)
    self.assertEqual(c["categories"]["B.Z"]["maturity"], 3.0)
    self.assertEqual(c["total"], float(Fraction(8, 3)))
    self.assertEqual(c["verdict"]["failing_key_measures"], [])
    self.assertEqual(c["verdict"]["failing_categories"], [])
    self.assertTrue(c["verdict"]["total_failed"])
    self.assertFalse(c["verdict"]["passed"])
    self.assertEqual(required_remediation_items(c), ["total"])

  def test_fourth_exclusion_is_over_the_limit(self):
    scores = dict(self.SCORES, **{"A.Y-01.1": _x()})
    errors = validate_scores(MINI_PACK, "important", scores)
    self.assertEqual(_codes(errors), ["exclusion_over_limit"])
    self.assertEqual((errors[0]["count"], errors[0]["max"]), (4, 3))

  def test_submit_requires_total_remediation_signoff_and_date(self):
    draft = {"scores": self.SCORES, "completion_date": "", "management_signoff": None, "remediation": []}
    errors, computed = validate_for_submit(MINI_PACK, "important", draft)
    self.assertIsNotNone(computed)
    self.assertEqual(sorted(_codes(errors)), ["completion_date_missing", "management_signoff_missing", "remediation_missing"])
    self.assertEqual([e for e in errors if e["code"] == "remediation_missing"][0]["ids"], ["total"])
    draft = {"scores": self.SCORES, "completion_date": "2026-10-06",
             "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"},
             "remediation": [{"item": "total", "action": "plan", "deadline": "2027-01-31"}]}
    errors, computed = validate_for_submit(MINI_PACK, "important", draft)
    self.assertEqual(errors, [])
    self.assertFalse(computed["verdict"]["passed"])

  def test_remediation_item_without_deadline_does_not_count(self):
    draft = {"scores": self.SCORES, "completion_date": "2026-10-06",
             "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"},
             "remediation": [{"item": "total", "action": "plan", "deadline": ""}]}
    errors, _ = validate_for_submit(MINI_PACK, "important", draft)
    self.assertEqual(_codes(errors), ["remediation_missing"])


class TestEssentialGolden(unittest.TestCase):
  """Essential counts all seven controls. Uniform 4/3 gives every subcategory 4/3, every category
  maturity 3.5 and total 3.5: passes exactly on the floor. Setting B.Z-02.1 to 2/2 makes B.Z-02
  2/2, B.Z doc (4 + 2)/2 = 3, impl (3 + 2)/2 = 2.5, maturity 2.75 < 3 (failing category) and total
  (3.5 + 3.5 + 2.75)/3 = 3.25 < 3.5 (failing total).
  """

  def _uniform(self):
    return {c["ref_id"]: _s(4, 3) for c in MINI_PACK["controls"]}

  def test_uniform_passes_on_the_floor(self):
    c = score(MINI_PACK, "essential", self._uniform())
    self.assertEqual(c["total"], 3.5)
    self.assertTrue(c["verdict"]["passed"])
    self.assertEqual(c["verdict"]["category_min"], 3.0)

  def test_category_floor_and_total(self):
    scores = dict(self._uniform(), **{"B.Z-02.1": _s(2, 2)})
    c = score(MINI_PACK, "essential", scores)
    self.assertEqual(c["subcategories"]["B.Z-02"], {"documentation": 2.0, "implementation": 2.0})
    self.assertEqual(c["categories"]["B.Z"], {"documentation": 3.0, "implementation": 2.5, "maturity": 2.75})
    self.assertEqual(c["total"], 3.25)
    self.assertEqual(c["verdict"]["failing_categories"], ["B.Z"])
    self.assertTrue(c["verdict"]["total_failed"])
    self.assertEqual(required_remediation_items(c), ["B.Z", "total"])

  def test_management_aspect_exclusion_refused_at_essential_only(self):
    scores = dict(self._uniform(), **{"B.Z-02.1": _x()})
    self.assertEqual(_codes(validate_scores(MINI_PACK, "essential", scores)), ["exclusion_management_aspect"])
    scores_imp = {"A.X-01.1": _s(3, 3), "A.X-01.2": _s(3, 3), "A.X-02.1": _s(3, 3), "A.Y-01.1": _s(3, 3), "B.Z-01.1": _x()}
    self.assertEqual(validate_scores(MINI_PACK, "important", scores_imp), [])

  def test_key_measure_exclusion_refused_and_sixth_exclusion_over_limit(self):
    scores = dict(self._uniform(), **{"B.Z-01.2": _x()})
    self.assertEqual(_codes(validate_scores(MINI_PACK, "essential", scores)), ["exclusion_key_measure"])

  def test_unscored_controls_are_omitted_and_block_submit(self):
    scores = self._uniform()
    del scores["A.Y-01.1"]
    c = score(MINI_PACK, "essential", scores)
    self.assertFalse(c["complete"])
    self.assertEqual(c["unscored"], ["A.Y-01.1"])
    self.assertNotIn("A.Y", c["categories"])
    self.assertFalse(c["verdict"]["passed"])
    errors, _ = validate_for_submit(MINI_PACK, "essential", {"scores": scores, "completion_date": "2026-10-06",
                                                             "management_signoff": {"name": "a", "role": "b", "date": "c"}})
    self.assertIn("unscored", _codes(errors))

  def test_missing_justification_blocks_submit(self):
    scores = self._uniform()
    scores["A.Y-01.1"] = _s(4, 3, just="")
    errors, _ = validate_for_submit(MINI_PACK, "essential", {"scores": scores, "completion_date": "2026-10-06",
                                                             "management_signoff": {"name": "a", "role": "b", "date": "c"}})
    self.assertEqual(_codes(errors), ["justification_missing"])
    self.assertEqual(errors[0]["ids"], ["A.Y-01.1"])


class TestRealPack(unittest.TestCase):
  """Structural rules on `ro.dnsc.o1-2026` and uniform-score checks that follow from the thresholds."""

  def setUp(self):
    self.pack = load_framework_pack(PACK_ID)

  def _uniform(self, level, doc, impl):
    return {c["ref_id"]: _s(doc, impl) for c in controls_for_level(self.pack, level)}

  def test_basic_uniform_three_two_sits_on_the_threshold(self):
    c = score(self.pack, "basic", self._uniform("basic", 3, 2))
    self.assertEqual(c["total"], 2.5)
    self.assertEqual(len(c["key_measures"]), 13)
    self.assertTrue(all(v["score"] == 2.5 for v in c["key_measures"].values()))
    self.assertTrue(c["verdict"]["passed"])
    self.assertEqual(len(c["categories"]), 17)

  def test_important_uniform_three_three_passes(self):
    c = score(self.pack, "important", self._uniform("important", 3, 3))
    self.assertEqual(c["total"], 3.0)
    self.assertEqual(len(c["key_measures"]), 22)
    self.assertTrue(c["verdict"]["passed"])
    self.assertEqual(len(c["categories"]), 20)

  def test_essential_uniform_four_three_passes_and_three_three_fails_total(self):
    c = score(self.pack, "essential", self._uniform("essential", 4, 3))
    self.assertEqual(c["total"], 3.5)
    self.assertEqual(len(c["key_measures"]), 29)
    self.assertEqual(len(c["categories"]), 22)
    self.assertTrue(c["verdict"]["passed"])
    c = score(self.pack, "essential", self._uniform("essential", 3, 3))
    self.assertEqual(c["total"], 3.0)
    self.assertEqual(c["verdict"]["failing_categories"], [])
    self.assertTrue(c["verdict"]["total_failed"])
    self.assertEqual(required_remediation_items(c), ["total"])

  def test_management_aspect_exclusions_refused_at_essential(self):
    scores = self._uniform("essential", 4, 3)
    ma = [c["ref_id"] for c in self.pack["controls"] if c["management_aspect"] and not c["key_measure"]]
    for ref_id in ma[:5]:
      scores[ref_id] = _x()
    errors = validate_scores(self.pack, "essential", scores)
    self.assertEqual(_codes(errors), ["exclusion_management_aspect"])
    self.assertEqual(errors[0]["ids"], sorted(ma[:5]))

  def test_sixth_exclusion_refused_at_essential(self):
    scores = self._uniform("essential", 4, 3)
    plain = [c["ref_id"] for c in controls_for_level(self.pack, "essential")
             if not c["key_measure"] and not c["management_aspect"]]
    for ref_id in plain[:6]:
      scores[ref_id] = _x()
    errors = validate_scores(self.pack, "essential", scores)
    self.assertEqual(_codes(errors), ["exclusion_over_limit"])
    self.assertEqual((errors[0]["count"], errors[0]["max"]), (6, 5))
    for ref_id in plain[5:6]:
      scores[ref_id] = _s(4, 3)
    self.assertEqual(validate_scores(self.pack, "essential", scores), [])
    c = score(self.pack, "essential", scores)
    self.assertEqual(c["exclusions"]["count"], 5)

  def test_full_essential_draft_size_at_caps_with_diacritics(self):
    """Measure the row a tenant draft would occupy at every cap, written with ă/ș/ț.

    The numbers are recorded in the contract (§Schemas and data). The ceiling here is a tripwire,
    not a design limit: phase 3 decides sharding from the recorded value.
    """
    diacritic = ("ăîșț" * 125)[:CAPS["justification"]]
    scores = {}
    plain = [c for c in controls_for_level(self.pack, "essential") if not c["key_measure"] and not c["management_aspect"]]
    excluded = {c["ref_id"] for c in plain[:5]}
    for c in controls_for_level(self.pack, "essential"):
      ref_id = c["ref_id"]
      refs = [{"ref": f"engagement:eng_{i:04d}/document:ed_{i}", "review_state": "linked"} for i in range(CAPS["evidence_refs"])]
      if ref_id in excluded:
        scores[ref_id] = {"documentation": NA, "implementation": NA, "excluded": True,
                          "exclusion_justification": diacritic, "justification": {"documentation": "", "implementation": ""},
                          "evidence_refs": refs, "updated_by": "user@example.com", "updated_at": 1759760000}
      else:
        scores[ref_id] = {"documentation": 3, "implementation": 2, "excluded": False, "exclusion_justification": None,
                          "justification": {"documentation": diacritic, "implementation": diacritic},
                          "evidence_refs": refs, "updated_by": "user@example.com", "updated_at": 1759760000}
    row = {
      "tenant_id": "t_" + "x" * 30, "pack_id": PACK_ID, "pack_acts": self.pack["acts"],
      "assurance_level": "essential", "level_provenance": {"kind": "risk_score", "score": 250, "declared_by": "user@example.com"},
      "sectoral_requirements": ("ăîșț" * 500)[:CAPS["sectoral_requirements"]], "completion_date": "2026-10-06",
      "management_signoff": {"name": "Ana-Maria Popescu", "role": "Director General", "date": "2026-10-06"},
      "remediation": [{"item": "total", "action": ("ăîșț" * 125)[:CAPS["remediation_action"]], "deadline": "2027-01-31"}
                      for _ in range(CAPS["remediation_items"])],
      "state": "draft", "assessment_revision": 7, "reopened_from": 1, "pending": None,
      "scores": scores,
      "submissions": [{"revision": i, "ref": {"store": "r1fs", "ref": "bafy" + "a" * 55}, "submitted_at": 1759760000,
                       "actor": "user@example.com", "pack_acts": self.pack["acts"], "assurance_level": "essential",
                       "fingerprint": "f" * 64, "request_id": "r" * 36, "reopen_request_id": None,
                       "verdict": {"passed": False, "total": 2.5, "failing_key_measures": [], "failing_categories": []}}
                      for i in range(1, 7)],
      "updated_by": "user@example.com", "updated_at": 1759760000,
    }
    self.assertEqual(validate_scores(self.pack, "essential", scores), [])
    escaped = len(json.dumps(row, ensure_ascii=True))
    raw_utf8 = len(json.dumps(row, ensure_ascii=False).encode("utf-8"))
    print(f"\nRM-120 full Essential draft at caps: json ensure_ascii={escaped} bytes, utf-8={raw_utf8} bytes")
    self.assertLess(escaped, 2_000_000)
    self.assertLess(raw_utf8, 1_000_000)


if __name__ == "__main__":
  unittest.main()
