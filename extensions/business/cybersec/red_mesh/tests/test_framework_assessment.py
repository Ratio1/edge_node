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


class FrameworkAssessmentFixture(unittest.TestCase):
  """The plugin, a tenant, four actors and the helpers; the test classes below and phase 5's share it."""

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
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hkeys", "chainstore_hset"):
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



class TestFrameworkAssessment(FrameworkAssessmentFixture):
  # -- reads and roles --------------------------------------------------------------------------

  # -- names (phase 8): resolved at read time, never stored ------------------------------------

  def name_admin(self, full_name="Ana Admin"):
    self.ok(self.plugin.update_account_profile(self.admin, "initial", {"full_name": full_name}))

  def test_updated_by_name_history_and_pending_names_resolve_from_the_profile(self):
    self.name_admin()
    revision = self.complete_basic_draft()
    self.assertEqual(self.ok(self.get())["updatedByName"], "Ana Admin")
    self.assertEqual(self.ok(self.get(self.viewer))["updatedByName"], "Ana Admin")
    request = str(uuid4())
    self.documents.fail = True
    self.refused(self.submit(revision, request), 503, "unavailable")
    self.documents.fail = False
    pending = self.ok(self.get())["pending"]
    self.assertEqual((pending["actor"], pending["actorName"]), ("initial", "Ana Admin"))
    young = self.submit(None, None, self.creator, action="clear_pending")
    self.refused(young, 409, "assessment_submit_pending")
    self.assertEqual(young["pending"]["actorName"], "Ana Admin")
    self.ok(self.submit(revision, request))
    entry = self.ok(self.get())["history"][0]
    self.assertEqual((entry["actor"], entry["actorName"]), ("initial", "Ana Admin"))
    self.assertNotIn("Ana Admin", json.dumps(self.stored_row()))  # read-time only
    self.name_admin("Ana Renamed")
    self.assertEqual(self.ok(self.get())["history"][0]["actorName"], "Ana Renamed")

  def test_names_are_none_without_a_profile_or_with_an_empty_name_or_a_missing_account(self):
    revision = self.complete_basic_draft()
    view = self.ok(self.get())
    self.assertIsNone(view["updatedByName"])
    self.name_admin("")
    self.assertIsNone(self.ok(self.get())["updatedByName"])
    self.ok(self.submit(revision, str(uuid4())))
    self.assertIsNone(self.ok(self.get())["history"][0]["actorName"])
    row = self.stored_row()
    self.write_row({**row, "updated_by": "gone", "submissions": [{**row["submissions"][0], "actor": "gone"}]})
    view = self.ok(self.get())
    self.assertEqual((view["updatedBy"], view["updatedByName"], view["history"][0]["actorName"]), ("gone", None, None))

  def test_a_profile_store_failure_leaves_the_names_none_and_the_read_succeeds(self):
    self.name_admin()
    self.complete_basic_draft()
    from extensions.business.cybersec.red_mesh.tenancy import account_profile
    from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
    original_hget = self.storage.chainstore_hget

    def hget(*args, **kwargs):
      if account_profile.KIND in str(args) + str(kwargs):  # only the profile read is broken
        raise TenantStoreError("down")
      return original_hget(*args, **kwargs)
    self.plugin.chainstore_hget = hget
    view = self.ok(self.get())
    self.assertEqual((view["updatedBy"], view["updatedByName"]), ("initial", None))

  def test_get_returns_an_empty_draft_without_writing(self):
    writes = len(self.storage.writes)
    data = self.ok(self.get())
    self.assertEqual((data["state"], data["assessmentRevision"], data["scores"], data["history"]), ("draft", 1, {}, []))
    self.assertEqual(data["packId"], PACK)
    self.assertEqual(data["submitErrors"], [{"code": "level_missing"}])
    self.assertTrue(data["canManage"])
    # The pack rides along on a read: the whole catalogue before a level is chosen, with the text.
    self.assertEqual(len(data["pack"]["controls"]), 218)
    self.assertEqual(data["pack"]["controls"][0]["refId"], "GV.OC-01.1")
    self.assertTrue(data["pack"]["controls"][0]["requirement"].startswith("Misiunea organizației"))
    self.assertEqual([m["name"] for m in data["pack"]["maturityLevels"]][:2], ["Inițial", "Repetabil"])
    self.assertEqual(data["pack"]["categories"]["GV.OC"]["title"], "CONTEXT ORGANIZAȚIONAL")
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
    self.assertIsNone(data["pack"])  # a save answers without the pack; the client keeps its copy
    self.assertEqual(len(self.ok(self.get())["pack"]["controls"]), 34)
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
    # A `job:` ref needs a scan this tenant owns and has finalized (phase 5, test_framework_evidence).
    refs = self.ok(self.save({"scores": {"GV.OC-03.1": {"documentation": 3, "implementation": 2,
                                                         "evidence_refs": ["contract", "engagement:eng_1/document:ed_2",
                                                                           "nis2:job-1:3"]}}}, 2))
    self.assertEqual([r["review_state"] for r in refs["scores"]["GV.OC-03.1"]["evidence_refs"]], ["linked"] * 3)
    removed = self.ok(self.save({"scores": {"GV.OC-03.1": None}}, 3))
    self.assertEqual(removed["scores"], {})

  def test_level_provenance_is_stamped_with_the_actor_and_a_level_change_prunes_off_level_scores(self):
    data = self.ok(self.save({"assurance_level": "important", "level_provenance": {"kind": "declared", "declared_by": "someone else"},
                              "scores": {"GV.OC-01.1": {"documentation": 3, "implementation": 3}}}, 1))
    self.assertEqual(data["levelProvenance"], {"kind": "declared", "declared_by": "initial"})
    self.assertIn("GV.OC-01.1", data["scores"])  # an Important control
    data = self.ok(self.save({"assurance_level": "basic"}, data["assessmentRevision"]))
    self.assertNotIn("GV.OC-01.1", data["scores"])  # rule 1: it does not count at Basic, so it is pruned
    self.assertEqual(data["packActs"], self.pack["acts"])

  def test_pack_amendment_refuses_submit_until_the_draft_is_saved_again(self):
    revision = self.complete_basic_draft()
    row = self.stored_row()
    self.write_row({**row, "pack_acts": ["MO 712 bis/2026-08-27"]})  # a draft from before Order 2/2026
    stale = self.submit(revision, str(uuid4()))
    self.refused(stale, 409, "assessment_pack_stale")
    self.assertEqual(stale["current_pack_acts"], self.pack["acts"])
    self.assertTrue(self.ok(self.get())["stale"]["newerPackActs"])
    saved = self.ok(self.save({"sectoral_requirements": "-"}, revision))  # any save adopts the current acts
    self.assertFalse(saved["stale"]["newerPackActs"])
    self.ok(self.submit(saved["assessmentRevision"], str(uuid4())))

  def test_replay_after_reopen_or_by_another_actor_is_a_conflict(self):
    revision = self.complete_basic_draft()
    request = str(uuid4())
    self.ok(self.submit(revision, request))
    self.refused(self.submit(revision, request, self.creator), 409, "conflict")  # same id, another actor
    current = self.ok(self.get())["assessmentRevision"]
    self.ok(self.reopen(current, str(uuid4())))
    self.refused(self.submit(revision, request), 409, "conflict")  # the match is no longer submitted

  def test_submit_reopen_and_clear_pending_are_refused_for_viewers_and_pentesters_and_audited(self):
    revision = self.complete_basic_draft()
    self.events.clear()
    self.refused(self.submit(revision, str(uuid4()), self.viewer), 403, "forbidden")
    self.refused(self.submit(revision, str(uuid4()), self.pentester), 403, "forbidden")
    self.refused(self.submit(None, None, self.viewer, action="clear_pending"), 403, "forbidden")
    self.refused(self.reopen(revision, str(uuid4()), self.viewer), 403, "forbidden")
    self.assertEqual([(e, d["operation"]) for e, d in self.events],
                     [("framework_assessment_refused", "submit"), ("framework_assessment_refused", "submit"),
                      ("framework_assessment_refused", "clear_pending"), ("framework_assessment_refused", "reopen")])

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
    self.assertEqual((self.events[-1][0], self.events[-1][1]["step"]), ("framework_assessment_refused", "put"))
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

# The digest of a pre-RM-120-9b row (sign-off name/role/date only), computed before the entity fields existed.
PRE_UPGRADE_DIGEST = "873bb5be735899fb4a7033292635fd70d30936793f5322f4e218edc3d7a4c7e7"


class TestEntityFieldsAndSignoffNames(FrameworkAssessmentFixture):
  """RM-120 phase 9b: first/last name sign-off, DNSC id, external supplier, claimant in the view."""

  SIGN = {"role": "Director", "date": "2026-10-06"}

  def fixture_row(self):
    return {"tenant_id": "tn_x", "pack_id": "p", "pack_acts": ["a"], "assurance_level": "basic",
            "level_provenance": None, "sectoral_requirements": "s", "completion_date": "2026-10-06",
            "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"},
            "remediation": [], "scores": {}}

  def test_signoff_first_and_last_compose_the_name_and_store_both(self):
    data = self.ok(self.save({"management_signoff": {"name": "ignored", "first_name": " Ana ", "last_name": "Pop", **self.SIGN}}, 1))
    expected = {"name": "Ana Pop", "first_name": "Ana", "last_name": "Pop", **self.SIGN}
    self.assertEqual(data["managementSignoff"], expected)
    self.assertEqual(self.stored_row()["management_signoff"], expected)

  def test_signoff_with_only_one_of_first_and_last_is_invalid(self):
    for part in ({"first_name": "Ana"}, {"last_name": "Pop"}, {"first_name": "Ana", "last_name": "  "}):
      result = self.save({"management_signoff": {"name": "Ana Pop", **part, **self.SIGN}}, 1)
      self.refused(result, 400, "assessment_invalid")

  def test_signoff_name_length_caps(self):
    long = "x" * (compliance.TEXT_MAX + 1)
    self.refused(self.save({"management_signoff": {"first_name": long, "last_name": "Pop", **self.SIGN}}, 1),
                 400, "assessment_invalid")
    half = "x" * (compliance.TEXT_MAX // 2)  # each part fits, the composed name does not
    self.refused(self.save({"management_signoff": {"first_name": half, "last_name": half, **self.SIGN}}, 1),
                 400, "assessment_invalid")

  def test_legacy_name_only_signoff_is_stored_unchanged(self):
    self.ok(self.save({"management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"}}, 1))
    self.assertEqual(self.stored_row()["management_signoff"], {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"})
    self.refused(self.save({"management_signoff": {"role": "Director", "date": "2026-10-06"}}, 2), 400, "assessment_invalid")

  def test_entity_fields_set_cap_and_clear(self):
    data = self.ok(self.save({"dnsc_unique_id": " ID-123 ", "external_supplier": "Furnizor SRL"}, 1))
    self.assertEqual((data["dnscUniqueId"], data["externalSupplier"]), ("ID-123", "Furnizor SRL"))
    row = self.stored_row()
    self.assertEqual((row["dnsc_unique_id"], row["external_supplier"]), ("ID-123", "Furnizor SRL"))
    self.refused(self.save({"dnsc_unique_id": "x" * 65}, 2), 400, "assessment_invalid")
    self.refused(self.save({"external_supplier": "x" * (compliance.TEXT_MAX + 1)}, 2), 400, "assessment_invalid")
    self.ok(self.save({"dnsc_unique_id": "x" * 64}, 2))
    data = self.ok(self.save({"dnsc_unique_id": "", "external_supplier": ""}, 3))
    row = self.stored_row()
    self.assertNotIn("dnsc_unique_id", row)
    self.assertNotIn("external_supplier", row)
    self.assertEqual((data["dnscUniqueId"], data["externalSupplier"]), ("", ""))

  def test_unknown_patch_key_is_still_rejected(self):
    result = self.save({"dnsc_unique": "x"}, 1)
    self.refused(result, 400, "assessment_invalid")

  def test_digest_is_unchanged_for_a_pre_upgrade_row_and_changes_with_a_new_field(self):
    row = self.fixture_row()
    self.assertEqual(compliance.intent_digest(row), PRE_UPGRADE_DIGEST)
    self.assertNotEqual(compliance.intent_digest({**row, "dnsc_unique_id": "ID-1"}), PRE_UPGRADE_DIGEST)
    self.assertNotEqual(compliance.intent_digest({**row, "external_supplier": "S"}), PRE_UPGRADE_DIGEST)
    self.assertEqual(compliance.intent_digest({**row, "dnsc_unique_id": "", "external_supplier": ""}), PRE_UPGRADE_DIGEST)

  def test_snapshot_and_reopen_carry_the_entity_fields(self):
    self.ok(self.save({"dnsc_unique_id": "ID-123", "external_supplier": "Furnizor SRL"}, 1))
    revision = self.ok(self.save({"assurance_level": "basic",
                                  "level_provenance": {"kind": "risk_score", "score": 42, "declared_by": "initial"},
                                  "scores": self.basic_scores(), "completion_date": "2026-10-06",
                                  "management_signoff": {"first_name": "Ana", "last_name": "Pop", **self.SIGN}}, 2))["assessmentRevision"]
    self.ok(self.submit(revision, str(uuid4())))
    snapshot = self.documents.envelopes["doc-1"]["snapshot"]
    self.assertEqual((snapshot["dnsc_unique_id"], snapshot["external_supplier"]), ("ID-123", "Furnizor SRL"))
    self.assertEqual(snapshot["management_signoff"]["last_name"], "Pop")
    data = self.ok(self.reopen(self.ok(self.get())["assessmentRevision"], str(uuid4())))
    self.assertEqual((data["dnscUniqueId"], data["externalSupplier"], data["managementSignoff"]),
                     ("ID-123", "Furnizor SRL", None))

  def test_snapshot_of_a_row_without_the_fields_has_empty_strings(self):
    revision = self.complete_basic_draft()
    self.ok(self.submit(revision, str(uuid4())))
    snapshot = self.documents.envelopes["doc-1"]["snapshot"]
    self.assertEqual((snapshot["dnsc_unique_id"], snapshot["external_supplier"]), ("", ""))

  def test_view_carries_empty_defaults_and_a_two_key_claimant(self):
    data = self.ok(self.get())
    self.assertEqual((data["dnscUniqueId"], data["externalSupplier"]), ("", ""))
    self.assertEqual(set(data["claimant"]), {"legal_name", "registration_id"})
    self.assertEqual(data["claimant"]["legal_name"], "Example Holdings SRL")
    self.assertIsNotNone(data["claimant"]["registration_id"])

  def test_view_claimant_is_null_without_a_legal_record(self):
    row = {**self.fixture_row(), "state": "draft", "assessment_revision": 1, "reopened_from": None, "pending": None,
           "submissions": [], "updated_by": "u", "updated_at": "now"}
    row.update(tenant_id=self.tenant, pack_id=PACK, pack_acts=list(self.pack["acts"]))
    for tenant in (None, {}, {"legal": None}):
      self.assertIsNone(compliance.assessment_view(row, self.pack, can_manage=True, tenant=tenant)["claimant"])
    legal = {"legal": {"name": "N", "registration_id": "R", "signer_name": "S", "signer_role": "T"}}
    self.assertEqual(compliance.assessment_view(row, self.pack, can_manage=True, tenant=legal)["claimant"],
                     {"legal_name": "N", "registration_id": "R"})




FA = "fa_11111111-1111-4111-8111-111111111111"
FB = "fa_22222222-2222-4222-8222-222222222222"


class TestSeveralAssessments(FrameworkAssessmentFixture):
  """RM-120 phase 10a: the default assessment keeps the 4-element key; `fa_<uuid>` rows take a 5th element."""

  def store(self):
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_compliance import CstoreComplianceStore
    return CstoreComplianceStore(self.plugin, "deployment")

  def put_fa(self, assessment_id=FA, **extra):
    row = compliance.new_row(self.tenant, self.pack, actor="initial", now="2026-11-11T00:00:00+00:00")
    row.update(assessment_id=assessment_id, name="Evaluare 2026", create_request_id=str(uuid4()), **extra)
    return self.store().put(compliance.KIND, self.tenant, PACK, assessment_id, record=row)

  def call(self, operation, assessment_id, actor=None, **kwargs):
    return self.plugin._call_tenant_administration(operation, actor or self.admin, tenant_id=self.tenant,
                                                    pack_id=PACK, assessment_id=assessment_id, **kwargs)

  def fa_key(self, assessment_id=FA):
    return json.dumps([compliance.KIND, "deployment", self.tenant, PACK, assessment_id], separators=(",", ":"))

  def fa_draft(self, assessment_id=FA):
    row = self.put_fa(assessment_id)
    data = self.ok(self.call("save_framework_assessment_draft", assessment_id, patch={
      "assurance_level": "basic", "level_provenance": {"kind": "risk_score", "score": 42, "declared_by": "initial"},
      "scores": self.basic_scores(), "completion_date": "2026-10-06",
      "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"}},
      expected_assessment_revision=row["assessment_revision"]))
    return data["assessmentRevision"]

  # -- storage ----------------------------------------------------------------------------------

  def test_fa_row_is_stored_on_a_five_element_field_and_default_stays_on_four(self):
    revision = self.complete_basic_draft()
    self.put_fa()
    keys = sorted(k for k, v in self.compliance_rows().items() if v is not None)
    self.assertEqual(sorted(len(json.loads(k)) for k in keys), [4, 5])
    self.assertIn(self.fa_key(), keys)
    self.assertEqual(self.ok(self.get())["assessmentRevision"], revision)
    self.assertEqual(self.ok(self.call("get_framework_assessment", FA))["assessmentRevision"], 1)

  def test_location_refuses_a_third_id_that_is_not_fa_uuid(self):
    from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
    for bad in ("default", "fa_x", "fa_" + "G" * 36, "fa_" + "-" * 36, "fa_ABCDEF12-1111-4111-8111-111111111111", FA + "\n", FA + "0", "xx_" + FA[3:]):
      with self.assertRaises(TenantStoreError, msg=bad):
        self.store().get(compliance.KIND, self.tenant, PACK, bad)
    with self.assertRaises(TenantStoreError):
      self.store().get(compliance.KIND, self.tenant, PACK, FA, "extra")

  def test_validator_binds_the_assessment_id_and_refuses_it_on_a_four_element_row(self):
    from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
    row = compliance.new_row(self.tenant, self.pack, actor="initial", now="2026-11-11T00:00:00+00:00")
    with self.assertRaises(TenantStoreError):  # assessment_id on the default row
      self.store().put(compliance.KIND, self.tenant, PACK, record={**row, "assessment_id": FA})
    with self.assertRaises(TenantStoreError):  # even a null assessment_id on the default row
      self.store().put(compliance.KIND, self.tenant, PACK, record={**row, "assessment_id": None})
    with self.assertRaises(TenantStoreError):  # fa row without its id
      self.store().put(compliance.KIND, self.tenant, PACK, FA, record=row)
    with self.assertRaises(TenantStoreError):  # fa row naming another id
      self.store().put(compliance.KIND, self.tenant, PACK, FA, record={**row, "assessment_id": FB})
    self.assertEqual(self.put_fa()["assessment_id"], FA)

  def test_tenant_record_ids_lists_both_shapes_skips_tombstones_and_other_tenants(self):
    self.complete_basic_draft()
    self.put_fa(FA)
    self.put_fa(FB)
    self.store().delete(compliance.KIND, self.tenant, PACK, FB)  # tombstone: listed by hkeys, skipped
    other = json.dumps([compliance.KIND, "deployment", "tn_other", PACK, FA], separators=(",", ":"))
    self.storage.data[(COMPLIANCE_HKEY, other)] = {"raw": True}
    self.storage.data[(COMPLIANCE_HKEY, "not json")] = {"raw": True}
    self.storage.data[(COMPLIANCE_HKEY, json.dumps([compliance.KIND, "deployment", self.tenant, PACK, "bad"]))] = {"x": 1}
    ids = sorted(self.store().tenant_record_ids(compliance.KIND, self.tenant))
    self.assertEqual(ids, sorted([[self.tenant, PACK], [self.tenant, PACK, FA]]))

  def test_tenant_record_ids_does_not_hgetall(self):
    self.put_fa()
    self.plugin.chainstore_hgetall = lambda **kwargs: self.fail("hgetall on enumeration")
    self.assertEqual(self.store().tenant_record_ids(compliance.KIND, self.tenant), [[self.tenant, PACK, FA]])

  # -- legacy row unchanged ---------------------------------------------------------------------

  def test_legacy_row_reads_saves_submits_and_reopens_unchanged_end_to_end(self):
    revision = self.complete_basic_draft()
    self.ok(self.submit(revision, str(uuid4())))
    envelope = self.documents.envelopes["doc-1"]
    self.assertNotIn("assessment_id", envelope)
    self.assertNotIn("assessment_id", envelope["snapshot"])
    self.assertNotIn("name", envelope["snapshot"])
    self.assertEqual(self.ok(self.artifact(1))["snapshot"], envelope["snapshot"])
    data = self.ok(self.reopen(self.ok(self.get())["assessmentRevision"], str(uuid4())))
    self.assertEqual(data["state"], "draft")
    self.assertNotIn("assessment_id", self.stored_row())

  def test_golden_digest_of_a_legacy_row_with_9b_fields_unset(self):
    row = {"tenant_id": "tn_x", "pack_id": "p", "pack_acts": ["a"], "assurance_level": "basic",
           "level_provenance": None, "sectoral_requirements": "s", "completion_date": "2026-10-06",
           "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"},
           "remediation": [], "scores": {}}
    self.assertEqual(compliance.intent_digest(row), PRE_UPGRADE_DIGEST)
    self.assertEqual(compliance.intent_digest({**row, "name": "", "assessment_id": None}), PRE_UPGRADE_DIGEST)
    self.assertNotEqual(compliance.intent_digest({**row, "name": "A"}), PRE_UPGRADE_DIGEST)
    self.assertNotEqual(compliance.intent_digest({**row, "assessment_id": FA}), PRE_UPGRADE_DIGEST)

  # -- fa rows through every operation ----------------------------------------------------------

  def test_fa_row_save_submit_artifact_reopen_and_envelope_carries_the_id(self):
    revision = self.fa_draft()
    request = str(uuid4())
    prepared = self.ok(self.call("prepare_framework_assessment_submit", FA, expected_assessment_revision=revision,
                                 request_id=request))
    self.assertEqual(prepared["outcome"], "prepared")
    envelope = prepared["envelope"]
    self.assertEqual(envelope["assessment_id"], FA)
    self.assertEqual(envelope["snapshot"]["assessment_id"], FA)
    self.assertEqual(envelope["snapshot"]["name"], "Evaluare 2026")
    ref = {"store": self.documents.name, "ref": self.documents.put(envelope)}
    recorded = self.ok(self.call("record_framework_assessment_submit", FA, request_id=request, ref=ref,
                                 expected_assessment_revision=prepared["assessment_revision"]))
    self.assertEqual(recorded["revision"], 1)
    resolved = self.ok(self.call("framework_assessment_artifact_ref", FA, revision=1))
    stored = self.documents.get(resolved["ref"]["ref"])
    self.assertIsNotNone(compliance.verify_snapshot_envelope(stored, tenant_id=self.tenant, pack_id=PACK,
                                                              revision=1, assessment_id=FA))
    reopened = self.ok(self.call("reopen_framework_assessment", FA,
                                 expected_assessment_revision=recorded["assessmentRevision"], request_id=str(uuid4())))
    self.assertEqual(reopened["state"], "draft")
    self.assertEqual(self.storage.data[(COMPLIANCE_HKEY, self.fa_key())]["assessment_id"], FA)

  def test_cross_id_envelope_is_refused(self):
    revision = self.fa_draft()
    request = str(uuid4())
    envelope = self.ok(self.call("prepare_framework_assessment_submit", FA, expected_assessment_revision=revision,
                                 request_id=request))["envelope"]
    verify = lambda env, aid: compliance.verify_snapshot_envelope(env, tenant_id=self.tenant, pack_id=PACK,
                                                                  revision=1, assessment_id=aid)
    self.assertIsNotNone(verify(envelope, FA))
    self.assertIsNone(verify(envelope, FB))        # another assessment's artifact
    self.assertIsNone(verify(envelope, "default"))  # fa envelope read as the default
    legacy = {k: v for k, v in envelope.items() if k != "assessment_id"}
    self.assertIsNone(verify(legacy, FA))           # default envelope read as an fa row
    self.assertIsNotNone(verify(legacy, "default"))

  def test_pending_resume_on_an_fa_row(self):
    revision = self.fa_draft()
    request = str(uuid4())
    first = self.ok(self.call("prepare_framework_assessment_submit", FA, expected_assessment_revision=revision,
                              request_id=request))
    again = self.ok(self.call("prepare_framework_assessment_submit", FA, expected_assessment_revision=revision,
                              request_id=request))
    self.assertEqual(again["outcome"], "resume")
    self.assertEqual(again["envelope"], first["envelope"])
    self.assertEqual(self.ok(self.call("get_framework_assessment", FA))["pending"]["requestId"], request)
    self.refused(self.call("save_framework_assessment_draft", FA, patch={}, expected_assessment_revision=first["assessment_revision"]),
                 409, "assessment_submit_pending")
    self.refused(self.call("clear_framework_assessment_pending", FA), 409, "assessment_submit_pending")

  def test_missing_fa_row_is_404_for_every_operation(self):
    ops = {
      "get_framework_assessment": {},
      "save_framework_assessment_draft": {"patch": {}, "expected_assessment_revision": 1},
      "prepare_framework_assessment_submit": {"expected_assessment_revision": 1, "request_id": str(uuid4())},
      "record_framework_assessment_submit": {"request_id": str(uuid4()), "ref": {"store": "fake", "ref": "r"},
                                             "expected_assessment_revision": 1},
      "clear_framework_assessment_pending": {},
      "reopen_framework_assessment": {"expected_assessment_revision": 1, "request_id": str(uuid4())},
      "framework_assessment_artifact_ref": {"revision": 1},
    }
    for operation, kwargs in ops.items():
      for aid in (FA, "fa_bad"):
        self.refused(self.call(operation, aid, **kwargs), 404, "assessment_not_found")
    self.assertEqual(self.compliance_rows(), {})  # nothing created lazily

  def test_default_still_creates_lazily_on_first_save(self):
    self.assertEqual(self.ok(self.get())["assessmentRevision"], 1)
    self.ok(self.save({"sectoral_requirements": "x"}, 1))
    self.assertEqual(len(self.compliance_rows()), 1)

  def test_fa_rows_are_independent_of_the_default_row(self):
    self.complete_basic_draft()
    self.fa_draft(FA)
    self.assertEqual(self.ok(self.call("get_framework_assessment", FA))["assuranceLevel"], "basic")
    self.assertEqual(self.ok(self.call("get_framework_assessment", "default"))["assuranceLevel"], "basic")
    self.refused(self.call("get_framework_assessment", FB), 404, "assessment_not_found")

  # -- purge ------------------------------------------------------------------------------------

  def test_delete_tenant_clears_both_shapes_and_their_snapshots(self):
    revision = self.complete_basic_draft()
    self.ok(self.submit(revision, str(uuid4())))
    fa_revision = self.fa_draft()
    request = str(uuid4())
    prepared = self.ok(self.call("prepare_framework_assessment_submit", FA, expected_assessment_revision=fa_revision,
                                 request_id=request))
    ref = {"store": self.documents.name, "ref": self.documents.put(prepared["envelope"])}
    self.ok(self.call("record_framework_assessment_submit", FA, request_id=request, ref=ref,
                      expected_assessment_revision=prepared["assessment_revision"]))
    self.storage.account("initial", memberships=[])
    self.storage.account("viewer", memberships=[])
    self.storage.account("pentester", memberships=[])
    result = self.plugin.delete_tenant(self.creator, self.tenant)
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"]["assessments"], 2)
    self.assertTrue({"doc-1", "doc-2"} <= set(self.documents.deleted))
    self.assertEqual([v for v in self.compliance_rows().values() if v is not None], [])


if __name__ == "__main__":
  unittest.main()
