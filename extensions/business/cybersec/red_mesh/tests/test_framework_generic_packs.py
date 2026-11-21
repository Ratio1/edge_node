"""RM-182 phase 3: two synthetic packs (fixtures, injected) go through create, save, submit and list
on the real plugin endpoints with no pack-specific production code: a tier-less ids-only pack on a
test-only status scorer, and a CyFun-family pack on the two-axis scorer with its own levels,
thresholds and rule switches. Also the null-level gates and `field_not_in_regime`.
"""
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.references import framework_packs as packs
from extensions.business.cybersec.red_mesh.services.framework_scoring import SCORERS

from extensions.business.cybersec.red_mesh.services.framework_scoring import AssessmentInvalid

from .test_framework_assessment import PACK as DNSC, FrameworkAssessmentFixture
from .test_framework_manifest import static_dir

STATUS, CYFUN = "test.status-ids.v1", "test.cyfun-like.v1"
SIGNOFF = {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"}


STATUS_VALUES = ("met", "unmet")


def _status_normalise(pack, rules, scores, *, actor, now):
  out = {}
  for ref_id, entry in scores.items():
    if entry is not None and not (isinstance(entry, dict) and set(entry) <= {"status", "rationale"}
                                  and entry.get("status") in STATUS_VALUES):
      raise AssessmentInvalid("invalid_score_value", [ref_id])
    out[ref_id] = None if entry is None else {"status": entry["status"], "rationale": entry.get("rationale", ""),
                                              "updated_by": actor}
  return out


class GenericPackFixture(FrameworkAssessmentFixture):
  def setUp(self):
    super().setUp()
    self.tmp = static_dir(self)
    self.seen_rules = []
    stub = SimpleNamespace(
      check_pack=lambda pack, text: None,
      compute=lambda pack, level, scores, *, context=None: {"scoring": "test_status.v1", "level": level, "verdict": {"passed": None}},
      validate_for_submit=lambda pack, rules, level, draft: (
        self.seen_rules.append(rules) or [], {"scoring": "test_status.v1", "level": level, "verdict": {"passed": None}}),
      verdict_summary=lambda computed: {"passed": None}, normalise_patch=_status_normalise,
      entry_schema=lambda pack: {"fields": ["status", "rationale"], "values": list(STATUS_VALUES)},
      validate_stored_entry=lambda pack, ref_id, entry: [] if entry.get("status") in STATUS_VALUES else [{"code": "bad"}],
      pack_view_extras=lambda pack, text: {"status_values": list(STATUS_VALUES)},
      capabilities=lambda: {"has_levels": False, "has_verdict": False, "has_remediation": False, "axes": []})
    patcher = patch.dict(SCORERS, {"test_status.v1": stub})
    patcher.start()
    self.addCleanup(patcher.stop)

  def create(self, pack, level=None, provenance=None, name="Synthetic"):
    return self.plugin.create_framework_assessment(self.admin, self.tenant, pack, str(uuid4()), name, level, provenance)

  def save_to(self, pack, aid, body, expected):
    return self.plugin.save_framework_assessment_draft(self.admin, self.tenant, pack, body, expected, aid)

  def submit_to(self, pack, aid, expected):
    return self.plugin.submit_framework_assessment(self.admin, self.tenant, pack, expected, str(uuid4()), None, aid)

  def listing(self, pack):
    return self.ok(self.plugin.list_framework_assessments(self.admin, self.tenant, pack, False))


class TestTierlessStatusPack(GenericPackFixture):
  def test_create_save_submit_and_list_without_a_level(self):
    made = self.ok(self.create(STATUS))
    aid = made["assessmentId"]
    self.assertEqual((made["assuranceLevel"], made["levelProvenance"], made["packId"]), (None, None, STATUS))
    saved = self.ok(self.save_to(STATUS, aid, {"completion_date": "2026-10-06", "sectoral_requirements": "none"},
                                 made["assessmentRevision"]))
    self.assertEqual(saved["submitErrors"], [])  # no level is not `level_missing` for a pack with no levels
    done = self.ok(self.submit_to(STATUS, aid, saved["assessmentRevision"]))
    self.assertEqual((done["revision"], done["verdict"]), (1, {"passed": None}))
    self.assertEqual(self.seen_rules[-1], packs.manifest_pack(STATUS)["rules"])  # the manifest rule block reaches the scorer
    rows = self.listing(STATUS)
    self.assertEqual([(r["assessmentId"], r["status"], r["assuranceLevel"]) for r in rows], [(aid, "submitted", None)])
    self.assertIsNone(self.stored_row()["submissions"][0]["assurance_level"])

  def test_scored_entries_save_list_and_submit_and_the_other_entry_shape_is_refused(self):
    aid = self.ok(self.create(STATUS))["assessmentId"]
    saved = self.ok(self.save_to(STATUS, aid, {"scores": {"ST-01": {"status": "met", "rationale": "ok"},
                                                          "ST-02": {"status": "unmet"}}}, 1))
    self.assertEqual({r: e["status"] for r, e in saved["scores"].items()}, {"ST-01": "met", "ST-02": "unmet"})
    refused = self.save_to(STATUS, aid, {"scores": {"ST-03": {"documentation": 3, "implementation": 3}}}, saved["assessmentRevision"])
    self.refused(refused, 400, "assessment_invalid")
    self.assertEqual(refused["errors"], [{"code": "invalid_score_value", "ids": ["ST-03"]}])
    self.refused(self.save_to(STATUS, aid, {"scores": {"ST-03": {"status": "maybe"}}}, saved["assessmentRevision"]), 400, "assessment_invalid")
    self.ok(self.submit_to(STATUS, aid, saved["assessmentRevision"]))
    self.assertEqual([r["status"] for r in self.listing(STATUS)], ["submitted"])
    self.assertEqual(self.stored_row()["scores"]["ST-01"]["status"], "met")
    self.assertEqual(SCORERS["test_status.v1"].entry_schema(None)["fields"], ["status", "rationale"])

  def test_the_suggest_endpoint_runs_for_a_levelless_pack_and_stops_at_no_level_for_dnsc(self):
    aid = self.ok(self.create(STATUS))["assessmentId"]
    data = self.ok(self.plugin.suggest_framework_assessment_evidence(self.admin, self.tenant, STATUS, aid))
    self.assertIsNone(data["reason"])  # computed, not the `level_missing` stub
    dnsc = self.ok(self.plugin.suggest_framework_assessment_evidence(self.admin, self.tenant, DNSC, ""))
    self.assertEqual(dnsc["reason"], "level_missing")

  def test_it_ships_no_text_and_the_pack_view_still_renders(self):
    aid = self.ok(self.create(STATUS))["assessmentId"]
    data = self.ok(self.plugin.get_framework_assessment(self.admin, self.tenant, STATUS, aid))
    self.assertEqual([c["refId"] for c in data["pack"]["controls"]], [f"ST-0{i}" for i in range(1, 5)])
    self.assertEqual((data["pack"]["controls"][0]["requirement"], data["pack"]["language"]), (None, "en"))

  def test_a_level_or_provenance_is_refused_for_a_pack_with_no_levels(self):
    self.refused(self.create(STATUS, provenance={"kind": "declared"}), 400, "assessment_invalid")
    self.refused(self.create(STATUS, level="basic"), 400, "assessment_invalid")
    made = self.ok(self.create(STATUS))
    self.refused(self.save_to(STATUS, made["assessmentId"], {"level_provenance": {"kind": "declared"}}, 1), 400, "assessment_invalid")
    self.refused(self.save_to(STATUS, made["assessmentId"], {"assurance_level": "basic"}, made["assessmentRevision"]),
                 400, "assessment_invalid")

  def test_a_null_level_is_still_refused_for_dnsc_at_create_submit_and_scoring(self):
    self.refused(self.plugin.create_framework_assessment(self.admin, self.tenant, DNSC, str(uuid4()), "X", None, None),
                 400, "assessment_invalid")
    view = self.ok(self.get())
    self.assertEqual((view["assuranceLevel"], view["computed"], view["submitErrors"]), (None, None, [{"code": "level_missing"}]))
    with self.assertRaises(packs.FrameworkPackError):
      packs.controls_for_level(packs.load_framework_pack(DNSC), None)
    self.assertEqual(len(packs.controls_for_level(packs.load_framework_pack(STATUS), None)), 4)


class TestCyfunFamilyPack(GenericPackFixture):
  def scores(self, level, value=2):
    return {c["ref_id"]: {"documentation": value, "implementation": value, "excluded": False}
            for c in packs.controls_for_level(packs.load_framework_pack(CYFUN), level)}

  def test_its_own_levels_thresholds_and_rule_switches_decide_the_submit(self):
    made = self.ok(self.create(CYFUN, level="base"))
    aid = made["assessmentId"]
    self.assertEqual(made["levelProvenance"]["kind"], "declared")
    # No justification, no sign-off, no remediation: the pack's rule block switches all of them off.
    saved = self.ok(self.save_to(CYFUN, aid, {"scores": self.scores("base"), "completion_date": "2026-10-06"},
                                 made["assessmentRevision"]))
    self.assertEqual(saved["submitErrors"], [])
    self.assertEqual((saved["computed"]["verdict"]["passed"], saved["computed"]["verdict"]["total_min"]), (True, 2.0))
    self.assertEqual(self.ok(self.submit_to(CYFUN, aid, saved["assessmentRevision"]))["verdict"]["passed"], True)
    self.assertEqual([r["assessmentId"] for r in self.listing(CYFUN)], [aid])

  def test_the_extended_level_fails_below_its_thresholds_and_asks_for_no_remediation(self):
    made = self.ok(self.create(CYFUN, level="extended"))
    saved = self.ok(self.save_to(CYFUN, made["assessmentId"], {"scores": self.scores("extended"), "completion_date": "2026-10-06"},
                                 made["assessmentRevision"]))
    self.assertEqual(saved["computed"]["verdict"]["total_min"], 3.0)
    self.assertFalse(saved["computed"]["verdict"]["passed"])
    self.assertEqual(saved["submitErrors"], [])  # remediation_on_fail is off
    self.assertEqual(self.ok(self.submit_to(CYFUN, made["assessmentId"], saved["assessmentRevision"]))["verdict"]["passed"], False)

  def test_an_exclusion_needs_no_reason_here_and_the_cap_is_the_packs_own(self):
    made = self.ok(self.create(CYFUN, level="base"))
    scores = self.scores("base")
    for ref in ("TC.A-01.2", "TC.B-01.1"):
      scores[ref] = {"documentation": "N/A", "implementation": "N/A", "excluded": True}
    saved = self.ok(self.save_to(CYFUN, made["assessmentId"], {"scores": scores, "completion_date": "2026-10-06"},
                                 made["assessmentRevision"]))
    self.assertEqual([e["code"] for e in saved["submitErrors"]], ["exclusion_key_measure"])  # B-01.1 is a key measure

  def test_a_status_shaped_entry_is_refused_on_the_two_axis_pack(self):
    made = self.ok(self.create(CYFUN, level="base"))
    refused = self.save_to(CYFUN, made["assessmentId"], {"scores": {"TC.A-01.1": {"status": "met"}}}, made["assessmentRevision"])
    self.refused(refused, 400, "assessment_invalid")
    self.assertEqual(refused["errors"], [{"code": "invalid_score_value", "ids": ["TC.A-01.1"]}])

  def test_levels_are_the_packs_not_the_dnsc_ones(self):
    self.refused(self.create(CYFUN, level="basic"), 400, "assessment_invalid")
    self.refused(self.create(CYFUN, level="base", provenance={"kind": "risk_score", "score": 5}), 400, "assessment_invalid")

  def test_a_dnsc_only_field_is_refused_on_this_pack_and_accepted_on_dnsc(self):
    made = self.ok(self.create(CYFUN, level="base"))
    refused = self.save_to(CYFUN, made["assessmentId"], {"dnsc_unique_id": "DNSC-1", "external_supplier": "X"},
                           made["assessmentRevision"])
    self.refused(refused, 400, "assessment_invalid")
    self.assertEqual(refused["errors"], [{"code": "field_not_in_regime", "ids": ["dnsc_unique_id", "external_supplier"]}])
    self.ok(self.save_to(CYFUN, made["assessmentId"], {"sectoral_requirements": "common fields stay accepted"},
                         made["assessmentRevision"]))
    data = self.ok(self.save({"dnsc_unique_id": "DNSC-1", "external_supplier": "Furnizor"}, 1))
    self.assertEqual((data["dnscUniqueId"], data["externalSupplier"]), ("DNSC-1", "Furnizor"))

  def test_the_pack_view_carries_the_generic_hierarchy_and_per_control_text(self):
    aid = self.ok(self.create(CYFUN, level="base"))["assessmentId"]
    pack = self.ok(self.plugin.get_framework_assessment(self.admin, self.tenant, CYFUN, aid))["pack"]
    self.assertEqual([n["id"] for n in pack["hierarchy"]], ["TC", "TC.A", "TC.A-01", "TC.B"])
    texts = {c["refId"]: (c["requirement"], c["guidance"]) for c in pack["controls"]}
    self.assertEqual(texts["TC.A-01.1"], ("Synthetic requirement text.", None))
    self.assertEqual(texts["TC.A-01.2"], (None, None))

  def test_the_view_carries_scorer_levels_and_rules_and_entity_keys_only_where_listed(self):
    """RM-194: the form picks itself from the read; the DNSC read keeps its entity keys, the CyFun-like read has none."""
    aid = self.ok(self.create(CYFUN, level="base"))["assessmentId"]
    data = self.ok(self.plugin.get_framework_assessment(self.admin, self.tenant, CYFUN, aid))
    self.assertEqual((data["pack"]["scoring"], data["pack"]["levels"]), ("maturity_two_axis.v1", ["base", "extended"]))
    self.assertEqual(data["pack"]["rules"]["entity_fields"], [])
    self.assertNotIn("exports", data["pack"]["rules"])
    self.assertFalse({"dnscUniqueId", "externalSupplier"} & set(data))
    dnsc = self.ok(self.plugin.get_framework_assessment(self.admin, self.tenant, DNSC, "default"))
    self.assertEqual(dnsc["pack"]["rules"]["entity_fields"], ["dnsc_unique_id", "external_supplier"])
    self.assertEqual((dnsc["dnscUniqueId"], dnsc["externalSupplier"]), ("", ""))
