"""RM-182 phase 2: byte-for-byte goldens of the DNSC pack output (`computed`, assessment DTO, snapshot
envelope, intent digest), recorded on the code before the scorer registry. Regenerate only on purpose:
`REDMESH_RECORD_GOLDENS=1 python3 -m unittest ...test_framework_goldens`.
"""
import hashlib
import json
import os
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh.references.framework_packs import (
  FrameworkPackError,
  controls_for_level,
  load_framework_pack,
  load_framework_text,
)
from extensions.business.cybersec.red_mesh.services.framework_scoring import SCORERS, required_remediation_items, scorer_for
from extensions.business.cybersec.red_mesh.tenancy import compliance

PACK = "ro.dnsc.o1-2026"
GOLDENS = Path(__file__).parent / "fixtures" / "framework_goldens"
NOW = "2026-11-14T10:00:00Z"
TENANT = {"legal": {"name": "Example SRL", "registration_id": "RO123", "signer_name": "Ana Pop", "signer_role": "Director"}}
SIGNOFF = {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"}
PROVENANCE = {"kind": "risk_score", "score": 42, "declared_by": "initial"}
PENDING = {"request_id": "11111111-1111-4111-8111-111111111111", "actor": "initial", "intent_digest": "d",
           "revision": 1, "submitted_at": NOW, "started_at": 1}


def _scores(pack, doc, impl, only=None):
  refs = [c["ref_id"] for c in controls_for_level(pack, "basic")]
  return {r: {"documentation": doc, "implementation": impl, "excluded": False,
              "justification": {"documentation": "politica", "implementation": "proces"}}
          for r in (refs[:only] if only else refs)}


def _row(pack, **fields):
  return {**compliance.new_row("tn_golden", pack, actor="initial", now=NOW), **fields}


def _scenarios(pack):
  basic = {"assurance_level": "basic", "level_provenance": PROVENANCE}
  full = {**basic, "scores": _scores(pack, 3, 2), "completion_date": "2026-10-06", "management_signoff": SIGNOFF}
  failing = {**basic, "scores": _scores(pack, 1, 1), "completion_date": "2026-10-06", "management_signoff": SIGNOFF}
  yield "empty", _row(pack)
  yield "partial", _row(pack, **basic, scores=_scores(pack, 4, 3, only=5), dnsc_unique_id="DNSC-1")
  yield "complete", _row(pack, **full, external_supplier="Furnizor SRL", name="Evaluare", assessment_id="fa_golden")
  yield "failing_with_remediation", _row(pack, **failing)
  yield "submitted", _row(pack, **full, state="submitted", assessment_revision=2)


def _record(name, row, pack, text):
  view = compliance.assessment_view(row, pack, can_manage=True, tenant=TENANT)
  computed = view["computed"]
  if name == "failing_with_remediation":  # remediation rows the verdict asks for, then the view again
    row = {**row, "remediation": [{"item": i, "action": "fix", "deadline": "2026-12-31"}
                                  for i in required_remediation_items(computed)]}
    view = compliance.assessment_view(row, pack, can_manage=True, tenant=TENANT)
  if name == "submitted":
    submission = {"revision": 1, "ref": {"store": "s", "ref": "r"}, "submitted_at": NOW, "actor": "initial",
                  "pack_acts": list(row["pack_acts"]), "assurance_level": "basic", "fingerprint": "f",
                  "request_id": PENDING["request_id"], "reopen_request_id": None,
                  "verdict": scorer_for(pack).verdict_summary(computed)}
    row = {**row, "submissions": [submission]}
    view = compliance.assessment_view(row, pack, can_manage=True, tenant=TENANT)
  digest = compliance.intent_digest(row)
  pending = {**PENDING, "intent_digest": digest}
  out = {"computed": computed, "view": view, "intent_digest": digest,
         "snapshot_envelope": compliance.build_snapshot(row, TENANT, computed, pending) if computed else None,
         "pack_view_sha256": None}
  with_text = compliance.assessment_view(row, pack, can_manage=True, text=text, tenant=TENANT)
  out["pack_view_sha256"] = hashlib.sha256(json.dumps(with_text["pack"], sort_keys=True).encode()).hexdigest()
  # view and snapshot repeat `computed` and `scores`: assert the repeats, store each value once
  assert view["computed"] == computed and view["scores"] == row["scores"]
  del view["computed"], view["scores"]
  snapshot = (out["snapshot_envelope"] or {}).get("snapshot")
  if snapshot:
    assert snapshot["computed"] == computed and snapshot["scores"] == row["scores"]
    del snapshot["computed"], snapshot["scores"]
  return out


class TestDnscGoldens(unittest.TestCase):
  def test_outputs_match_goldens(self):
    pack, text = load_framework_pack(PACK), load_framework_text(PACK)
    record = os.environ.get("REDMESH_RECORD_GOLDENS") == "1"
    complete_computed = None
    for name, row in _scenarios(pack):
      out = _record(name, row, pack, text)
      if name == "complete":
        complete_computed = out["computed"]
      if name == "submitted":  # same scenario as complete plus a submission: store a marker, assert the copy
        self.assertEqual(out["computed"], complete_computed)
        out["computed"] = {"same_as": "complete"}
      rendered = json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False) + "\n"
      path = GOLDENS / f"{name}.json"
      if record:
        path.write_text(rendered, encoding="utf-8")
      with self.subTest(name):
        self.assertEqual(path.read_text(encoding="utf-8"), rendered)


class TestScorerRegistry(unittest.TestCase):
  def test_dnsc_pack_dispatches_to_two_axis(self):
    self.assertIs(scorer_for(load_framework_pack(PACK)), SCORERS["maturity_two_axis.v1"])

  def test_unknown_scoring_is_a_pack_error(self):
    with self.assertRaises(FrameworkPackError):
      scorer_for({"scoring": "nope.v1"})


if __name__ == "__main__":
  unittest.main()
