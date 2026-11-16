"""Production status scorer contract and deterministic counts."""
import copy
import json
import unittest
from pathlib import Path
from ..services import framework_status_scoring as status
from ..services.framework_scoring import AssessmentInvalid, scorer_for
from ..references.framework_packs import load_framework_pack, pack_rules

PACK = "eu.ec.ir-2024-2690"

class TestStatusScoring(unittest.TestCase):
  def setUp(self):
    self.pack = load_framework_pack(PACK)
    self.rules = pack_rules(self.pack)
    self.ids = [c["ref_id"] for c in self.pack["controls"]]

  def normalise(self, entries):
    return status.normalise_patch(self.pack, self.rules, entries, actor="initial", now="2026-11-16T00:00:00Z")

  def test_goldens(self):
    fixture = json.loads((Path(__file__).parent / "fixtures/framework_status_goldens.json").read_text())
    for case in fixture:
      with self.subTest(case=case["name"]):
        scores = {ref: copy.deepcopy(case["default_entry"]) for ref in self.ids} if case["default_entry"] else {}
        scores.update({self.ids[int(index)]: entry for index, entry in case["entries"].items()})
        normalized = self.normalise(scores)
        self.assertEqual(normalized, case["scores"])
        self.assertEqual(status.compute(self.pack, None, normalized), case["computed"])
        errors, computed = status.validate_for_submit(self.pack, self.rules, None, {"scores": normalized})
        self.assertEqual([e["code"] for e in errors], case["submit_error_codes"])
        self.assertEqual(computed, case["computed"])

  def test_invalid_entries_and_caps(self):
    for entry in ({"status":"unknown"}, {"documentation":3}, {"status":[]},
                  {"rationale":"x"*501}, {"evidence_refs":["contract"]*6},
                  {"status":"na", "rationale":"  "}):
      with self.subTest(entry=entry), self.assertRaises(AssessmentInvalid):
        self.normalise({self.ids[0]:entry})
    good = self.normalise({self.ids[0]:{"status":"partial", "rationale":"x"*500, "evidence_refs":["contract"],
                                       "updated_by":"forged", "updated_at":"forged"}})[self.ids[0]]
    self.assertEqual(good["updated_by"], "initial")
    self.assertEqual(good["updated_at"], "2026-11-16T00:00:00Z")
    self.assertEqual(status.validate_stored_entry(self.pack, self.ids[0], good), [])
    for broken in ({**good,"extra":1}, {**good,"status":"wat"}, {**good,"rationale":" x "},
                   {**good,"evidence_refs":["contract"]}, {**good,"updated_by":None},
                   {k:v for k,v in good.items() if k!="updated_at"}):
      self.assertTrue(status.validate_stored_entry(self.pack,self.ids[0],broken))
    self.assertTrue(status.validate_stored_entry(self.pack,"unknown",good))
    self.assertEqual(self.normalise({self.ids[0]:None}), {self.ids[0]:None})

  def test_unencodable_rationale_is_refused_on_input_and_stored_read(self):
    ref = self.ids[0]
    for surrogate in ("\ud800", "\udfff"):
      with self.subTest(codepoint=ord(surrogate)):
        with self.assertRaises(AssessmentInvalid):
          self.normalise({ref: {"status": "partial", "rationale": surrogate}})
        entry = {"status": "partial", "rationale": surrogate, "evidence_refs": [],
                 "updated_by": "initial", "updated_at": "2026-11-16T00:00:00Z"}
        self.assertTrue(status.validate_stored_entry(self.pack, ref, entry))

  def test_manifest_switches_and_stored_na_policy(self):
    ref = self.ids[0]
    with self.assertRaises(AssessmentInvalid):
      status.normalise_patch(self.pack, {**self.rules, "justification_required": True},
                             {ref: {"status": "partial"}}, actor="initial", now="now")
    scores = status.normalise_patch(self.pack, {**self.rules, "exclusion_reason_required": False},
                                    {ref: {"status": "na"}}, actor="initial", now="now")
    self.assertEqual(status.validate_stored_entry(self.pack, ref, scores[ref]), [])
    errors, _ = status.validate_for_submit(self.pack, self.rules, None, {"scores": scores})
    self.assertIn("exclusion_justification_missing", [e["code"] for e in errors])

  def test_registration_and_neutral_capabilities(self):
    self.assertIs(scorer_for(self.pack), status)
    self.assertEqual(status.capabilities(), {"has_levels":False,"has_verdict":False,"has_remediation":False,"axes":[]})
    self.assertEqual(status.entry_schema(self.pack)["caps"], {"rationale":500,"evidence_refs":5})
    self.assertEqual(status.verdict_summary(status.compute(self.pack,None,{})),
                     {"passed":None,"counts":{"implemented":0,"partial":0,"not_implemented":0,"na":0,"unanswered":161}})
