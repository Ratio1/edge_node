"""RM-184: a worst-case assessment row of each pack against the 2,097,152-character sender guard.

The guard counts the characters of the final signed JSON, which is written with
`ensure_ascii=False`; there a control character such as `\x01` is the widest accepted character
(six characters escaped). Every assessable control carries maximum-width accepted text; 49
submissions are recorded and the 50th is pending, so `pending` holds the full frozen context.
Every save and submit goes through the real plugin paths and must succeed.
"""
import json
from uuid import uuid4

from ..references import framework_packs as packs
from ..services import framework_csf_scoring as csf
from ..tenancy import compliance as c
from .test_framework_assessment import FrameworkAssessmentFixture

SENDER_GUARD = 2097152
WIDE = "\x01"  # accepted in free text; six characters in `json.dumps(..., ensure_ascii=False)`
NAME = "x" * 120  # a name refuses control characters
PACKS = ("ro.dnsc.o1-2026", "eu.ec.ir-2024-2690", "us.nist.csf-2.0")
COUNTRY = {"ro.dnsc.o1-2026": "RO", "eu.ec.ir-2024-2690": "DE", "us.nist.csf-2.0": "US"}


def refs():
  return [{"ref": "nis2:%s:%06d" % ("a" * 79 + str(i), 999990 + i), "review_state": "linked"} for i in range(5)]


class TestWorstCaseRow(FrameworkAssessmentFixture):
  def worst_scores(self, pack, level):
    controls = packs.controls_for_level(pack, level) if level else pack["controls"]
    wide = WIDE * 500
    out = {}
    for control in controls:
      ref = control["ref_id"]
      if pack["scoring"] == csf.SCORING_ID:
        out[ref] = {"included": True, "rationale": wide, "current_rating": 1, "target_rating": 5, "evidence_refs": refs()}
      elif level:
        out[ref] = {"documentation": 5, "implementation": 5, "excluded": False, "evidence_refs": refs(),
                    "justification": {"documentation": wide, "implementation": wide}, "exclusion_justification": wide}
      else:
        out[ref] = {"status": "implemented", "rationale": wide, "evidence_refs": refs()}
    return out

  def worst_draft(self, pack, level):
    wide = WIDE * 500
    body = {"sectoral_requirements": WIDE * c.CAPS["sectoral_requirements"],
            "remediation": [{"item": WIDE * c.REMEDIATION_ITEM_MAX, "action": wide, "deadline": "2027-01-31"}
                            for _ in range(c.CAPS["remediation_items"])],
            "scores": self.worst_scores(pack, level)}
    if level:
      body["assurance_level"] = level
      body["level_provenance"] = {"kind": "risk_score", "score": 42}
    if pack["scoring"] == csf.SCORING_ID:
      body["function_tiers"] = {f: {"current": 1, "target": 4} for f in csf.FUNCTIONS}
    for field, limit in c.REGIME_FIELDS.items():
      if field in c.pack_rules(pack)["entity_fields"]:
        body[field] = WIDE * limit
    return body

  def signoff(self):
    return {"completion_date": "2026-10-06", "management_signoff": {
      "first_name": WIDE * 99, "last_name": WIDE * 100, "role": WIDE * c.TEXT_MAX, "date": "2026-10-06"}}

  def serialized_row(self):
    rows = [v for v in self.compliance_rows().values() if v is not None and v.get("kind") == c.KIND]
    self.assertEqual(len(rows), 1)
    return json.dumps(rows[0], sort_keys=True, allow_nan=False, ensure_ascii=False)  # the sender metric

  def measure(self, pack_id, recorded):
    pack = packs.load_framework_pack(pack_id)
    levels = packs.pack_levels(pack)
    level = max(levels, key=lambda lv: len(packs.controls_for_level(pack, lv))) if levels else None
    p, a = self.plugin, self.admin
    aid = self.ok(p.create_framework_assessment(a, self.tenant, pack_id, str(uuid4()), NAME,
                                                level, {"kind": "risk_score", "score": 42} if level else None,
                                                COUNTRY[pack_id]))["assessmentId"]
    rev = self.ok(p.save_framework_assessment_draft(a, self.tenant, pack_id, {**self.worst_draft(pack, level), **self.signoff()}, 1, aid))["assessmentRevision"]
    for _ in range(recorded):
      rev = self.ok(p.submit_framework_assessment(a, self.tenant, pack_id, rev, str(uuid4()), None, aid))["assessmentRevision"]
      rev = self.ok(p.reopen_framework_assessment(a, self.tenant, pack_id, rev, str(uuid4()), aid))["assessmentRevision"]
      rev = self.ok(p.save_framework_assessment_draft(a, self.tenant, pack_id, self.signoff(), rev, aid))["assessmentRevision"]
    if recorded:
      self.documents.fail = True  # the next submit stops after the pending mark: `pending` holds the full context
      self.refused(p.submit_framework_assessment(a, self.tenant, pack_id, rev, str(uuid4()), None, aid), 503, "unavailable")
      row = self.stored_row()
      self.assertEqual(len(row["submissions"]), recorded)
      self.assertIn("historical_context", row["pending"])
    return len(self.serialized_row())

  def test_csf(self):
    size = self.measure(PACKS[2], c.MAX_SUBMISSIONS - 1)
    self.assertLess(size, SENDER_GUARD, "CSF worst case with 49 recorded + pending: %d characters" % size)

  def test_ir(self):
    size = self.measure(PACKS[1], c.MAX_SUBMISSIONS - 1)
    self.assertLess(size, SENDER_GUARD, "IR worst case with 49 recorded + pending: %d characters" % size)

  def test_dnsc_draft_alone_is_over_the_guard(self):
    # The known RM-120 DNSC answer-text limit: independent of submissions; see RM-180 codex-audit.
    # This flips when someone bounds the DNSC row; then replace it with an `assertLess` like the others.
    size = self.measure(PACKS[0], 0)
    self.assertGreater(size, SENDER_GUARD, "known RM-120 DNSC answer-text limit; independent of submissions; "
                       "see RM-180 codex-audit (measured %d characters)" % size)

  def test_dnsc_with_forty_nine_recorded_and_pending(self):
    size = self.measure(PACKS[0], c.MAX_SUBMISSIONS - 1)
    self.assertGreater(size, SENDER_GUARD, "known RM-120 DNSC answer-text limit (measured %d characters)" % size)
