"""RM-120 phase 3: framework maturity self-assessment through the real plugin endpoints, the
administration service, the compliance CStore adapter and an in-memory document store.

Covers the contract's submit protocol (replayed / resume / superseded / stale pending / save refused
while pending), reopen, the artifact read, the role rows, refusal audits, that no read ever carries
a document reference, and tenant delete with assessment rows.
"""
import base64
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.references.framework_packs import controls_for_level, load_framework_pack
from extensions.business.cybersec.red_mesh.tenancy import compliance

from .contract_fixture import install_contract
from .test_tenant_administration import FakeAdministrationStore

PACK = "ro.dnsc.o1-2026"
COMPLIANCE_HKEY = '["redmesh","tenancy-compliance",1,"deployment"]'
TENANCY_HKEY = '["redmesh","tenancy",1,"deployment"]'


def _no_refs(value, path="$"):
  """Every key named `ref`/`store`/`cid` anywhere in a DTO is a leak of a document reference."""
  if isinstance(value, dict):
    for key, inner in value.items():
      assert key not in ("ref", "store", "cid"), f"{path}.{key} leaks a reference"
      _no_refs(inner, f"{path}.{key}")
  elif isinstance(value, list):
    for index, inner in enumerate(value):
      _no_refs(inner, f"{path}[{index}]")


class TestFrameworkAssessment(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin
    cls.pack = load_framework_pack(PACK)

  def setUp(self):
    environment = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    environment.start()
    self.addCleanup(environment.stop)
    self.storage = FakeAdministrationStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.cfg_instance_id = "jobs"
    self.plugin.P = lambda *args, **kwargs: None
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.storage, name))
    self.events = []
    self.plugin._log_audit_event = lambda event, details: self.events.append((event, details))
    self.creator = {"account_id": "creator"}
    request = str(uuid4())
    prepared = self.plugin.prepare_tenant(self.creator, request, "Example", "example", "initial",
                                          **install_contract(self.plugin))
    self.assertTrue(prepared["success"], prepared)
    self.tenant = prepared["data"]["tenantId"]
    self.storage.grant("initial", self.tenant)
    self.assertTrue(self.plugin.activate_tenant(self.creator, request)["success"])
    # Allow Pentester on, so a tenant_pentester is a member the policy denies (403), not a stranger (404).
    self.assertTrue(self.plugin.update_tenant_allow_pentester(self.creator, self.tenant, True)["success"])
    self.documents = self.plugin._document_store()
    self.plugin.configured_peers_reader = None
    self.admin = {"account_id": "initial"}
    self.storage.account("viewer", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    self.storage.account("pentester", memberships=[{"role": "tenant_pentester", "tenant_id": self.tenant}])
    self.storage.account("stranger", memberships=[{"role": "tenant_admin", "tenant_id": "tn_" + str(uuid4())}])
    self.viewer, self.pentester, self.stranger = {"account_id": "viewer"}, {"account_id": "pentester"}, {"account_id": "stranger"}
    self.events.clear()

  # -- helpers ----------------------------------------------------------------------------------

  def get(self, actor=None):
    return self.plugin.get_framework_assessment(actor or self.admin, self.tenant, PACK)

  def save(self, patch_body, expected, actor=None):
    return self.plugin.save_framework_assessment_draft(actor or self.admin, self.tenant, PACK, patch_body, expected)

  def submit(self, expected, request_id, actor=None, action=None):
    return self.plugin.submit_framework_assessment(actor or self.admin, self.tenant, PACK, expected, request_id, action)

  def reopen(self, expected, request_id, actor=None):
    return self.plugin.reopen_framework_assessment(actor or self.admin, self.tenant, PACK, expected, request_id)

  def artifact(self, revision, actor=None):
    return self.plugin.get_framework_assessment_artifact(actor or self.admin, self.tenant, PACK, revision)

  def refused(self, result, status, error):
    self.assertFalse(result["success"], result)
    self.assertEqual((result["status_code"], result["error"]), (status, error), result)

  def ok(self, result):
    self.assertTrue(result["success"], result)
    return result["data"]

  def basic_scores(self, doc=3, impl=2):
    return {c["ref_id"]: {"documentation": doc, "implementation": impl, "excluded": False,
                          "justification": {"documentation": "politica scrisă și aprobată",
                                            "implementation": "proces aplicat, dovezi în ședința lunară"}}
            for c in controls_for_level(self.pack, "basic")}

  def complete_basic_draft(self):
    """A submittable Basic draft (uniform 3/2 sits on the threshold and passes)."""
    data = self.ok(self.save({"assurance_level": "basic",
                              "level_provenance": {"kind": "risk_score", "score": 42, "declared_by": "initial"},
                              "scores": self.basic_scores(), "completion_date": "2026-10-06",
                              "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"}}, 1))
    self.assertEqual(data["submitErrors"], [])
    return data["assessmentRevision"]

  def compliance_rows(self):
    return {key: value for (hkey, key), value in self.storage.data.items() if hkey == COMPLIANCE_HKEY}

  def stored_row(self):
    rows = [value for value in self.compliance_rows().values() if value is not None]
    self.assertEqual(len(rows), 1)
    return rows[0]

  def write_row(self, row):
    key = json.dumps([compliance.KIND, "deployment", self.tenant, PACK], separators=(",", ":"))
    self.storage.data[(COMPLIANCE_HKEY, key)] = row

  # -- reads and roles --------------------------------------------------------------------------

  def test_get_returns_an_empty_draft_without_writing(self):
    writes = len(self.storage.writes)
    data = self.ok(self.get())
    self.assertEqual((data["state"], data["assessmentRevision"], data["scores"], data["history"]), ("draft", 1, {}, []))
    self.assertEqual(data["packId"], PACK)
    self.assertEqual(data["submitErrors"], [{"code": "level_missing"}])
    self.assertTrue(data["canManage"])
    self.assertFalse(self.ok(self.get(self.viewer))["canManage"])
    self.assertEqual(len(self.storage.writes), writes)
    self.assertEqual(self.compliance_rows(), {})
    _no_refs(data)

  def test_pentesters_and_strangers_are_refused_and_the_refusals_are_audited(self):
    self.refused(self.get(self.pentester), 403, "forbidden")
    self.refused(self.get(self.stranger), 404, "not_found")
    self.refused(self.save({"assurance_level": "basic"}, 1, self.viewer), 403, "forbidden")
    self.refused(self.artifact(1, self.pentester), 403, "forbidden")
    # A refused save is not audited (contract: get, submit, reopen, artifact and clear-pending are).
    self.assertEqual([e for e, _ in self.events], ["framework_assessment_refused"] * 3)
    self.assertEqual(self.events[0][1], {"operation": "get", "actor": "pentester", "tenant_id": self.tenant,
                                         "pack_id": PACK, "status_code": 403, "error": "forbidden"})
    self.assertEqual(self.events[1][1]["status_code"], 404)
    self.assertEqual(self.events[2][1]["operation"], "artifact")

  def test_unknown_pack_is_not_found(self):
    self.refused(self.plugin.get_framework_assessment(self.admin, self.tenant, "cyfun.2025"), 404, "assessment_not_found")

  # -- draft ------------------------------------------------------------------------------------

  def test_save_validates_bumps_the_revision_and_is_audited(self):
    data = self.ok(self.save({"assurance_level": "basic", "scores": {"GV.OC-03.1": {"documentation": 3, "implementation": 2}}}, 1))
    self.assertEqual(data["assessmentRevision"], 2)
    self.assertEqual(data["scores"]["GV.OC-03.1"]["documentation"], 3)
    self.assertEqual(data["scores"]["GV.OC-03.1"]["updated_by"], "initial")
    self.assertIn("unscored", [e["code"] for e in data["submitErrors"]])
    self.assertEqual(data["computed"]["unscored"][:2], ["GV.PO-01.1", "GV.RM-03.1"])
    self.assertEqual(self.events[-1][0], "framework_assessment_saved")
    self.assertEqual(self.events[-1][1], {"tenant_id": self.tenant, "pack_id": PACK, "actor": "initial", "assessment_revision": 2})
    stale = self.save({"sectoral_requirements": "x"}, 1)
    self.refused(stale, 409, "assessment_stale")
    self.assertEqual(stale["current_assessment_revision"], 2)
    bad = self.save({"scores": {"GV.OC-03.1": {"documentation": 6, "implementation": 2}}}, 2)
    self.refused(bad, 400, "assessment_invalid")
    self.assertEqual(bad["errors"], [{"code": "invalid_score_value", "ids": ["GV.OC-03.1"]}])
    unknown = self.save({"scores": {"ZZ.ZZ-99.9": {"documentation": 1, "implementation": 1}}}, 2)
    self.assertEqual(unknown["errors"], [{"code": "unknown_control", "ids": ["ZZ.ZZ-99.9"]}])
    self.refused(self.save({"nope": 1}, 2), 400, "assessment_invalid")
    self.refused(self.save({"assurance_level": "platinum"}, 2), 400, "assessment_invalid")
    too_many = self.save({"scores": {"GV.OC-03.1": {"documentation": 3, "implementation": 2,
                                                     "evidence_refs": ["contract"] * 6}}}, 2)
    self.assertEqual(too_many["errors"], [{"code": "evidence_ref_invalid", "ids": ["GV.OC-03.1"]}])
    refs = self.ok(self.save({"scores": {"GV.OC-03.1": {"documentation": 3, "implementation": 2,
                                                         "evidence_refs": ["contract", "engagement:eng_1/document:ed_2",
                                                                           "nis2:job-1:3", "job:job-1:2"]}}}, 2))
    self.assertEqual([r["review_state"] for r in refs["scores"]["GV.OC-03.1"]["evidence_refs"]], ["linked"] * 4)
    removed = self.ok(self.save({"scores": {"GV.OC-03.1": None}}, 3))
    self.assertEqual(removed["scores"], {})

  def test_exclusion_rules_are_enforced_at_submit_not_at_save(self):
    scores = self.basic_scores()
    scores["PR.AA-01.1"] = {"documentation": "N/A", "implementation": "N/A", "excluded": True,
                            "exclusion_justification": "nu se aplică"}  # a key measure
    self.ok(self.save({"assurance_level": "basic", "scores": scores, "completion_date": "2026-10-06",
                       "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"}}, 1))
    result = self.submit(2, str(uuid4()))
    self.refused(result, 400, "assessment_invalid")
    self.assertEqual(result["errors"], [{"code": "exclusion_key_measure", "ids": ["PR.AA-01.1"]}])
    self.assertIsNone(self.stored_row()["pending"])

  # -- submit protocol --------------------------------------------------------------------------

  def test_submit_creates_revision_one_and_replays_without_a_second_write(self):
    revision = self.complete_basic_draft()
    request = str(uuid4())
    data = self.ok(self.submit(revision, request))
    self.assertEqual((data["revision"], data["replayed"], data["verdict"]["passed"]), (1, False, True))
    self.assertNotIn("actor", data)
    row = self.stored_row()
    self.assertEqual((row["state"], row["pending"], len(row["submissions"])), ("submitted", None, 1))
    self.assertEqual(row["submissions"][0]["ref"], {"store": "fake", "ref": "doc-1"})  # the contract is the seeded doc-fixture
    envelope = self.documents.envelopes["doc-1"]
    self.assertEqual((envelope["kind"], envelope["schema"], envelope["revision"]),
                     ("redmesh_framework_assessment", "redmesh.framework_assessment.v1", 1))
    self.assertEqual(envelope["snapshot"]["claimant"]["legal_name"], "Example Holdings SRL")
    self.assertEqual(envelope["snapshot"]["computed"]["total"], 2.5)
    _no_refs(envelope["snapshot"])
    self.assertEqual(self.events[-1][0], "framework_assessment_submitted")
    self.assertEqual(self.events[-1][1], {"tenant_id": self.tenant, "pack_id": PACK, "actor": "initial",
                                          "revision": 1, "passed": True})
    puts = len(self.documents.puts)
    replay = self.ok(self.submit(revision, request))
    self.assertEqual((replay["revision"], replay["replayed"]), (1, True))
    self.assertEqual(len(self.documents.puts), puts)
    self.refused(self.submit(revision, str(uuid4())), 409, "conflict")
    view = self.ok(self.get(self.viewer))
    self.assertEqual((view["state"], view["latestRevision"], view["history"][0]["revision"]), ("submitted", 1, 1))
    self.assertEqual(view["history"][0]["verdict"]["passed"], True)
    _no_refs(view)
    self.refused(self.save({"sectoral_requirements": "x"}, view["assessmentRevision"]), 409, "conflict")

  def test_incomplete_draft_is_refused_with_the_missing_ids_and_no_pending(self):
    self.ok(self.save({"assurance_level": "basic"}, 1))
    result = self.submit(2, str(uuid4()))
    self.refused(result, 400, "assessment_invalid")
    codes = {e["code"] for e in result["errors"]}
    self.assertEqual(codes, {"unscored", "management_signoff_missing", "completion_date_missing"})
    self.assertEqual(len([e for e in result["errors"] if e["code"] == "unscored"][0]["ids"]), 34)
    self.assertIsNone(self.stored_row()["pending"])
    self.assertEqual(self.events[-1][1]["step"], "prepare")

  def test_failed_verdict_needs_remediation_items_before_submit(self):
    scores = self.basic_scores(2, 2)  # key measures at 2.0, total 2.0
    self.ok(self.save({"assurance_level": "basic", "scores": scores, "completion_date": "2026-10-06",
                       "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"}}, 1))
    result = self.submit(2, str(uuid4()))
    self.refused(result, 400, "assessment_invalid")
    missing = [e for e in result["errors"] if e["code"] == "remediation_missing"][0]["ids"]
    self.assertIn("total", missing)
    self.assertEqual(len(missing), 14)  # 13 key measures and the total
    items = [{"item": item, "action": "plan de remediere", "deadline": "2027-01-31"} for item in missing]
    self.ok(self.save({"remediation": items}, 2))
    data = self.ok(self.submit(3, str(uuid4())))
    self.assertFalse(data["verdict"]["passed"])
    self.assertEqual(len(data["verdict"]["failing_key_measures"]), 13)

  def test_document_store_failure_keeps_the_pending_marker_and_the_retry_resumes(self):
    revision = self.complete_basic_draft()
    request = str(uuid4())
    self.documents.fail = True
    self.refused(self.submit(revision, request), 503, "unavailable")
    row = self.stored_row()
    self.assertEqual((row["state"], row["pending"]["request_id"], row["pending"]["revision"]), ("draft", request, 1))
    self.assertEqual(row["assessment_revision"], revision + 1)
    pending_refusal = self.save({"sectoral_requirements": "x"}, revision + 1)
    self.refused(pending_refusal, 409, "assessment_submit_pending")
    self.assertEqual(pending_refusal["pending"]["requestId"], request)
    self.refused(self.submit(revision + 1, str(uuid4())), 409, "assessment_submit_pending")
    self.documents.fail = False
    data = self.ok(self.submit(revision, request))  # the original expected revision: replay is checked first
    self.assertEqual((data["revision"], data["replayed"]), (1, False))
    self.assertEqual(len(self.documents.puts), 1)
    self.assertEqual(len(self.stored_row()["submissions"]), 1)

  def test_crash_between_put_and_record_leaves_an_orphan_and_the_retry_resumes(self):
    revision = self.complete_basic_draft()
    request = str(uuid4())
    real = self.Plugin._call_tenant_administration
    calls = {"record": 0}

    def record_fails_once(plugin, operation, *args, **kwargs):
      if operation == "record_framework_assessment_submit" and calls["record"] == 0:
        calls["record"] += 1
        return {"success": False, "status": "error", "status_code": 503, "error": "unavailable"}
      return real(plugin, operation, *args, **kwargs)
    with patch.object(self.Plugin, "_call_tenant_administration", record_fails_once):
      self.refused(self.submit(revision, request), 503, "unavailable")
    self.assertEqual(len(self.documents.puts), 1)
    self.assertIsNotNone(self.stored_row()["pending"])
    data = self.ok(self.submit(revision, request))
    self.assertEqual((data["revision"], data["replayed"]), (1, False))
    self.assertEqual(len(self.documents.puts), 2)  # one orphan, accepted
    row = self.stored_row()
    self.assertEqual(len(row["submissions"]), 1)
    self.assertEqual(row["submissions"][0]["ref"]["ref"], "doc-2")
    self.assertEqual(self.documents.envelopes["doc-1"]["snapshot"]["submission"]["submitted_at"],
                     self.documents.envelopes["doc-2"]["snapshot"]["submission"]["submitted_at"])

  def test_a_stale_pending_can_be_cleared_by_another_manager_and_the_old_submit_is_superseded(self):
    revision = self.complete_basic_draft()
    request = str(uuid4())
    self.documents.fail = True
    self.refused(self.submit(revision, request), 503, "unavailable")
    self.documents.fail = False
    young = self.submit(None, None, self.creator, action="clear_pending")
    self.refused(young, 409, "assessment_submit_pending")
    row = self.stored_row()
    self.write_row({**row, "pending": {**row["pending"], "started_at": row["pending"]["started_at"] - 16 * 60}})
    cleared = self.ok(self.submit(None, None, self.creator, action="clear_pending"))
    self.assertEqual((cleared["cleared"], cleared["clearedRequestId"], cleared["clearedActor"]), (True, request, "initial"))
    self.assertEqual(self.events[-1][0], "framework_assessment_pending_cleared")
    self.assertEqual(self.events[-1][1]["actor"], "creator")
    self.assertIsNone(self.stored_row()["pending"])
    # The original client retries: no pending to resume, and its expected revision is from before
    # the bump, so the compare-and-set refuses it.
    stale = self.submit(revision, request)
    self.refused(stale, 409, "assessment_stale")
    self.assertEqual(stale["current_assessment_revision"], revision + 1)
    self.ok(self.submit(revision + 1, str(uuid4())))

  def test_record_is_superseded_when_the_pending_was_replaced(self):
    revision = self.complete_basic_draft()
    request = str(uuid4())
    real = self.Plugin._call_tenant_administration

    def replace_pending_before_record(plugin, operation, *args, **kwargs):
      if operation == "record_framework_assessment_submit":
        row = self.stored_row()
        self.write_row({**row, "pending": {**row["pending"], "request_id": str(uuid4()), "actor": "creator"}})
      return real(plugin, operation, *args, **kwargs)
    with patch.object(self.Plugin, "_call_tenant_administration", replace_pending_before_record):
      self.refused(self.submit(revision, request), 409, "assessment_submit_superseded")
    self.assertEqual(self.stored_row()["submissions"], [])
    self.assertEqual(self.events[-1][1]["step"], "record")
    self.assertNotIn("framework_assessment_submitted", [e for e, _ in self.events])

  def test_record_is_superseded_when_the_tenant_is_being_deleted(self):
    revision = self.complete_basic_draft()
    real = self.Plugin._call_tenant_administration

    def mark_deleting_before_record(plugin, operation, *args, **kwargs):
      if operation == "record_framework_assessment_submit":
        for (hkey, key), value in list(self.storage.data.items()):
          if hkey == TENANCY_HKEY and json.loads(key)[0] == "tenant" and value is not None:
            self.storage.data[(hkey, key)] = {**value, "active": False,
                                              "deleting": {"by": "creator", "at": "now", "deleted_refs": []}}
      return real(plugin, operation, *args, **kwargs)
    with patch.object(self.Plugin, "_call_tenant_administration", mark_deleting_before_record):
      self.refused(self.submit(revision, str(uuid4())), 409, "assessment_submit_superseded")

  # -- reopen -----------------------------------------------------------------------------------

  def test_reopen_flips_to_draft_clears_the_signoff_and_replays(self):
    revision = self.complete_basic_draft()
    self.ok(self.submit(revision, str(uuid4())))
    current = self.ok(self.get())["assessmentRevision"]
    self.refused(self.reopen(current - 1, str(uuid4())), 409, "assessment_stale")
    reopen_request = str(uuid4())
    data = self.ok(self.reopen(current, reopen_request))
    self.assertEqual((data["state"], data["reopenedFrom"], data["managementSignoff"], data["completionDate"],
                      data["replayed"]), ("draft", 1, None, "", False))
    self.assertEqual(data["scores"]["GV.OC-03.1"]["documentation"], 3)
    self.assertEqual(self.events[-1][0], "framework_assessment_reopened")
    replay = self.ok(self.reopen(current, reopen_request))
    self.assertTrue(replay["replayed"])
    self.refused(self.reopen(data["assessmentRevision"], str(uuid4())), 409, "conflict")
    second = self.submit(data["assessmentRevision"], str(uuid4()))
    self.refused(second, 400, "assessment_invalid")
    self.assertEqual({e["code"] for e in second["errors"]}, {"management_signoff_missing", "completion_date_missing"})
    saved = self.ok(self.save({"completion_date": "2026-11-01",
                               "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-11-01"}},
                              data["assessmentRevision"]))
    data2 = self.ok(self.submit(saved["assessmentRevision"], str(uuid4())))
    self.assertEqual(data2["revision"], 2)
    view = self.ok(self.get())
    self.assertEqual([h["revision"] for h in view["history"]], [2, 1])
    _no_refs(view)

  # -- artifact ---------------------------------------------------------------------------------

  def test_artifact_is_read_by_revision_and_checked_against_the_row(self):
    revision = self.complete_basic_draft()
    self.ok(self.submit(revision, str(uuid4())))
    data = self.ok(self.artifact(1, self.viewer))
    self.assertEqual((data["revision"], data["schema"]), (1, "redmesh.framework_assessment.v1"))
    self.assertEqual(data["snapshot"]["submission"]["revision"], 1)
    self.assertEqual(data["snapshot"]["computed"]["verdict"]["passed"], True)
    _no_refs(data)
    self.refused(self.artifact(2), 404, "assessment_not_found")
    self.refused(self.artifact("1"), 404, "assessment_not_found")
    self.documents.envelopes["doc-1"]["revision"] = 7
    self.refused(self.artifact(1), 409, "document_integrity")

  # -- purge ------------------------------------------------------------------------------------

  def test_delete_tenant_removes_the_assessment_row_and_its_snapshots(self):
    revision = self.complete_basic_draft()
    self.ok(self.submit(revision, str(uuid4())))
    self.storage.account("initial", memberships=[])
    self.storage.account("viewer", memberships=[])
    self.storage.account("pentester", memberships=[])
    result = self.plugin.delete_tenant(self.creator, self.tenant)
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"]["assessments"], 1)
    self.assertIn("doc-1", self.documents.deleted)
    self.assertEqual([v for v in self.compliance_rows().values() if v is not None], [])


if __name__ == "__main__":
  unittest.main()
