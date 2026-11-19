"""RM-120 phase 10b: several assessments per framework pack, through the real plugin endpoints.

Covers list (statuses, archived, order, no references), create (replay, conflict, cap, name, level),
archive and unarchive (CAS, pending, read-only refusals), the optional `assessment_id` on the six
existing endpoints, the role rows, the cross-tenant refusal and the audit events.
"""
import json
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy import compliance

from .test_framework_assessment import COMPLIANCE_HKEY, PACK, FrameworkAssessmentFixture, _no_refs


class TestAssessmentCatalogue(FrameworkAssessmentFixture):

  def setUp(self):
    super().setUp()
    self.storage.account("admin2", memberships=[{"role": "tenant_admin", "tenant_id": self.tenant}])
    self.admin2 = {"account_id": "admin2"}

  # -- helpers ----------------------------------------------------------------------------------

  def create(self, name="Evaluare 2026", level="basic", request_id=None, actor=None, provenance=None, pack=PACK):
    return self.plugin.create_framework_assessment(actor or self.admin, self.tenant, pack,
                                                   request_id or str(uuid4()), name, level, provenance)

  def made(self, name="Evaluare 2026", **kwargs):
    return self.ok(self.create(name, **kwargs))

  def listing(self, actor=None, include_archived=False, pack=PACK):
    return self.plugin.list_framework_assessments(actor or self.admin, self.tenant, pack, include_archived)

  def rows(self, **kwargs):
    return self.ok(self.listing(**kwargs))

  def archive(self, assessment_id, archived, expected, actor=None):
    return self.plugin.archive_framework_assessment(actor or self.admin, self.tenant, PACK, assessment_id,
                                                    archived, expected)

  def get_fa(self, assessment_id, actor=None):
    return self.plugin.get_framework_assessment(actor or self.admin, self.tenant, PACK, assessment_id)

  def save_fa(self, assessment_id, patch_body, expected, actor=None):
    return self.plugin.save_framework_assessment_draft(actor or self.admin, self.tenant, PACK, patch_body,
                                                       expected, assessment_id)

  def submit_fa(self, assessment_id, expected, request_id, actor=None):
    return self.plugin.submit_framework_assessment(actor or self.admin, self.tenant, PACK, expected, request_id,
                                                   None, assessment_id)

  def reopen_fa(self, assessment_id, expected, request_id, actor=None):
    return self.plugin.reopen_framework_assessment(actor or self.admin, self.tenant, PACK, expected, request_id,
                                                   assessment_id)

  def artifact_fa(self, assessment_id, revision, actor=None):
    return self.plugin.get_framework_assessment_artifact(actor or self.admin, self.tenant, PACK, revision,
                                                         assessment_id)

  def complete_fa(self, assessment_id, expected=1):
    return self.ok(self.save_fa(assessment_id, {
      "level_provenance": {"kind": "risk_score", "score": 42, "declared_by": "initial"},
      "scores": self.basic_scores(), "completion_date": "2026-10-06",
      "management_signoff": {"name": "Ana Pop", "role": "Director", "date": "2026-10-06"}},
      expected))["assessmentRevision"]

  def submitted_fa(self, name="Evaluare 2026"):
    data = self.made(name)
    aid = data["assessmentId"]
    revision = self.complete_fa(aid, data["assessmentRevision"])
    self.ok(self.submit_fa(aid, revision, str(uuid4())))
    return aid

  def events_named(self, name):
    return [details for event, details in self.events if event == name]

  # -- create -----------------------------------------------------------------------------------

  def test_create_stores_a_five_element_row_and_returns_the_view_and_audits(self):
    request = str(uuid4())
    data = self.made("  Evaluare 2026  ", request_id=request)
    self.assertEqual(data["assessmentId"], "fa_" + request)
    self.assertEqual((data["name"], data["archived"], data["state"], data["assessmentRevision"]),
                     ("Evaluare 2026", False, "draft", 1))
    self.assertEqual(data["assuranceLevel"], "basic")
    self.assertEqual(data["levelProvenance"], {"kind": "declared", "declared_by": "initial"})
    _no_refs(data)
    keys = [k for k, v in self.compliance_rows().items() if v is not None]
    self.assertEqual([len(json.loads(k)) for k in keys], [5])
    self.assertEqual(self.events_named("framework_assessment_created"),
                     [{"tenant_id": self.tenant, "pack_id": PACK, "actor": "initial",
                       "assessment_id": "fa_" + request}])

  def test_create_keeps_a_sent_provenance_with_the_acting_account(self):
    data = self.made(provenance={"kind": "risk_score", "score": 42, "declared_by": "someone-else"})
    self.assertEqual(data["levelProvenance"], {"kind": "risk_score", "score": 42, "declared_by": "initial"})

  def test_create_requires_a_valid_level(self):
    for level in (None, "extreme", 3):
      result = self.create(level=level)
      self.assertEqual((result["status_code"], result["error"]), (400, "assessment_invalid"), level)
    self.assertEqual(self.compliance_rows(), {})

  def test_create_name_is_required_trimmed_and_at_most_120_characters(self):
    for name in ("", "   ", None, 5, "x" * 121):
      result = self.create(name=name)
      self.assertEqual((result["status_code"], result["error"]), (400, "assessment_invalid"), name)
    self.assertEqual(self.made("x" * 120)["name"], "x" * 120)

  def test_create_name_refuses_control_and_invisible_format_characters(self):
    for name in ("Q1\u200b", "Q1\u202e2026", "\ufeffQ1", "Q1\nQ2", "Q1\x07"):
      result = self.create(name=name)
      self.assertEqual((result["status_code"], result["error"]), (400, "assessment_invalid"), repr(name))

  def test_name_uniqueness_folds_compatibility_forms(self):
    self.made("Evaluare 2026")
    self.refused(self.create("Ｅｖａｌｕａｒｅ　２０２６"), 409, "assessment_name_taken")  # full-width forms, NFKC

  def test_create_refuses_a_bad_request_id_and_an_unknown_pack(self):
    self.refused(self.create(request_id="not-a-uuid"), 400, "invalid_request")
    self.refused(self.create(request_id=str(uuid4()).upper()), 400, "invalid_request")
    self.refused(self.create(pack="cyfun.2025"), 404, "assessment_not_found")

  def test_create_name_is_unique_among_non_archived_rows_case_insensitively(self):
    first = self.made("Evaluare 2026")
    self.refused(self.create("  evaluare 2026 "), 409, "assessment_name_taken")
    self.ok(self.archive(first["assessmentId"], True, first["assessmentRevision"]))
    self.assertEqual(self.made("EVALUARE 2026")["name"], "EVALUARE 2026")  # an archived name is free again

  def test_create_replay_returns_the_stored_row_without_a_second_row(self):
    request = str(uuid4())
    first = self.made(request_id=request)
    again = self.ok(self.create(request_id=request))
    self.assertEqual(again["assessmentId"], first["assessmentId"])
    self.assertTrue(again["replayed"])
    self.assertFalse(first["replayed"])
    self.assertEqual(len([v for v in self.compliance_rows().values() if v is not None]), 1)
    self.assertEqual(len(self.events_named("framework_assessment_created")), 1)  # a replay is not audited again

  def test_create_replay_of_an_archived_row_returns_it_and_comes_before_the_name_check(self):
    request = str(uuid4())
    first = self.made("A", request_id=request)
    self.ok(self.archive(first["assessmentId"], True, 1))
    self.made("A")  # the freed name is now taken by another row
    again = self.ok(self.create("A", request_id=request))
    self.assertTrue(again["archived"])
    self.assertEqual(again["assessmentId"], first["assessmentId"])

  def test_create_replay_comes_before_the_cap(self):
    request = str(uuid4())
    self.made("n0", request_id=request)
    for index in range(1, 20):
      self.made(f"n{index}")
    self.refused(self.create("n20"), 409, "assessment_limit")
    self.assertEqual(self.ok(self.create("n0", request_id=request))["name"], "n0")

  def test_create_replay_with_other_inputs_or_another_actor_is_a_conflict(self):
    request = str(uuid4())
    self.made("A", request_id=request)
    self.refused(self.create("B", request_id=request), 409, "conflict")
    self.refused(self.create("A", level="important", request_id=request), 409, "conflict")
    self.refused(self.create("A", request_id=request, provenance={"kind": "risk_score", "score": 1}), 409, "conflict")
    self.refused(self.create("A", request_id=request, actor=self.admin2), 409, "conflict")

  def test_create_cap_is_twenty_with_archived_included(self):
    for index in range(20):
      self.made(f"n{index}")
    self.refused(self.create("n20"), 409, "assessment_limit")
    first = self.rows()[0]
    self.ok(self.archive(first["assessmentId"], True, first["assessmentRevision"]))
    self.refused(self.create("n20"), 409, "assessment_limit")  # archived rows still count
    self.assertEqual(len(self.rows(include_archived=True)), 20)

  def test_cap_is_checked_before_the_name(self):
    for index in range(20):
      self.made(f"n{index}")
    self.refused(self.create("n0"), 409, "assessment_limit")

  def test_create_never_makes_the_default(self):
    self.made()
    self.assertNotIn("default", [r["assessmentId"] for r in self.rows()])
    self.assertEqual([k for k in self.compliance_rows() if len(json.loads(k)) == 4], [])

  # -- rename -----------------------------------------------------------------------------------

  def test_rename_while_draft_checks_uniqueness_and_refuses_an_empty_name_on_an_fa_row(self):
    a, b = self.made("A"), self.made("B")
    renamed = self.ok(self.save_fa(a["assessmentId"], {"name": " a-2027 "}, 1))
    self.assertEqual(renamed["name"], "a-2027")
    self.refused(self.save_fa(b["assessmentId"], {"name": "A-2027"}, 1), 409, "assessment_name_taken")
    self.assertEqual(self.ok(self.save_fa(a["assessmentId"], {"name": "A-2027"}, 2))["name"], "A-2027")  # own name, new case
    for bad in ("", "  ", "x" * 121, 7):
      self.refused(self.save_fa(b["assessmentId"], {"name": bad}, 1), 400, "assessment_invalid")

  def test_the_default_row_can_be_named_and_keep_an_empty_name(self):
    self.ok(self.save({"sectoral_requirements": "x"}, 1))
    self.assertEqual(self.ok(self.get())["name"], "")
    self.assertEqual(self.ok(self.save({"name": "Prima evaluare"}, 2))["name"], "Prima evaluare")
    self.assertEqual(self.ok(self.save({"name": ""}, 3))["name"], "")
    self.refused(self.save({"name": "x" * 121}, 4), 400, "assessment_invalid")

  def test_a_submitted_revision_keeps_its_name_after_a_rename(self):
    aid = self.submitted_fa("Evaluare 2026")
    row = self.ok(self.get_fa(aid))
    reopened = self.ok(self.reopen_fa(aid, row["assessmentRevision"], str(uuid4())))
    self.ok(self.save_fa(aid, {"name": "Evaluare 2027"}, reopened["assessmentRevision"]))
    self.assertEqual(self.ok(self.artifact_fa(aid, 1))["snapshot"]["name"], "Evaluare 2026")

  def test_a_submitted_row_refuses_a_rename(self):
    aid = self.submitted_fa()
    row = self.ok(self.get_fa(aid))
    self.refused(self.save_fa(aid, {"name": "Other"}, row["assessmentRevision"]), 409, "conflict")

  # -- archive ----------------------------------------------------------------------------------

  def test_archive_and_unarchive_bump_the_revision_and_are_audited(self):
    data = self.made()
    aid = data["assessmentId"]
    archived = self.ok(self.archive(aid, True, 1))
    self.assertEqual((archived["archived"], archived["assessmentRevision"], archived["assessmentId"]), (True, 2, aid))
    self.assertEqual(self.ok(self.get_fa(aid))["archived"], True)
    restored = self.ok(self.archive(aid, False, 2))
    self.assertEqual((restored["archived"], restored["assessmentRevision"]), (False, 3))
    self.assertEqual(self.events_named("framework_assessment_archived"),
                     [{"tenant_id": self.tenant, "pack_id": PACK, "actor": "initial", "assessment_id": aid,
                       "archived": True},
                      {"tenant_id": self.tenant, "pack_id": PACK, "actor": "initial", "assessment_id": aid,
                       "archived": False}])

  def test_archive_checks_the_expected_revision(self):
    aid = self.made()["assessmentId"]
    for bad in (2, 0, None, "1", True):
      result = self.archive(aid, True, bad)
      self.refused(result, 409, "assessment_stale")
    self.assertEqual(result["current_assessment_revision"], 1)

  def test_archive_repeat_in_the_same_state_is_a_no_op_without_a_write_or_audit(self):
    aid = self.made()["assessmentId"]
    self.ok(self.archive(aid, True, 1))
    self.events.clear()
    again = self.ok(self.archive(aid, True, 2))
    self.assertEqual((again["archived"], again["assessmentRevision"]), (True, 2))
    self.assertEqual(self.events_named("framework_assessment_archived"), [])

  def test_archive_needs_a_boolean_flag(self):
    aid = self.made()["assessmentId"]
    for bad in (None, "true", 1):
      self.refused(self.archive(aid, bad, 1), 400, "invalid_request")

  def test_archive_is_refused_while_a_submit_is_pending(self):
    data = self.made()
    aid = data["assessmentId"]
    revision = self.complete_fa(aid, 1)
    prepared = self.ok(self.plugin._call_tenant_administration(
      "prepare_framework_assessment_submit", self.admin, tenant_id=self.tenant, pack_id=PACK, assessment_id=aid,
      expected_assessment_revision=revision, request_id=str(uuid4())))
    result = self.archive(aid, True, prepared["assessment_revision"])
    self.refused(result, 409, "assessment_submit_pending")
    self.assertFalse(self.ok(self.get_fa(aid))["archived"])

  def test_archived_rows_refuse_save_submit_and_reopen_but_still_read(self):
    aid = self.submitted_fa()
    row = self.ok(self.get_fa(aid))
    reopened = self.ok(self.reopen_fa(aid, row["assessmentRevision"], str(uuid4())))
    archived = self.ok(self.archive(aid, True, reopened["assessmentRevision"]))
    revision = archived["assessmentRevision"]
    self.refused(self.save_fa(aid, {"sectoral_requirements": "x"}, revision), 409, "assessment_archived")
    self.refused(self.submit_fa(aid, revision, str(uuid4())), 409, "assessment_archived")
    self.assertEqual(self.ok(self.get_fa(aid))["archived"], True)
    self.assertEqual(self.ok(self.artifact_fa(aid, 1))["revision"], 1)
    # reopen on an archived submitted row
    aid2 = self.submitted_fa("Second")
    row2 = self.ok(self.get_fa(aid2))
    done = self.ok(self.archive(aid2, True, row2["assessmentRevision"]))
    self.refused(self.reopen_fa(aid2, done["assessmentRevision"], str(uuid4())), 409, "assessment_archived")

  def test_clear_pending_on_an_archived_row_is_harmless(self):
    aid = self.made()["assessmentId"]
    self.ok(self.archive(aid, True, 1))
    result = self.plugin.submit_framework_assessment(self.admin, self.tenant, PACK, None, None, "clear_pending", aid)
    self.assertFalse(self.ok(result)["cleared"])

  def test_unarchive_refuses_a_name_taken_in_the_meantime(self):
    a = self.made("A")
    self.ok(self.archive(a["assessmentId"], True, 1))
    self.made("a")
    self.refused(self.archive(a["assessmentId"], False, 2), 409, "assessment_name_taken")
    self.assertTrue(self.ok(self.get_fa(a["assessmentId"]))["archived"])

  def test_the_default_can_be_archived_once_it_exists_and_not_before(self):
    self.refused(self.archive("default", True, 1), 404, "assessment_not_found")
    self.ok(self.save({"sectoral_requirements": "x"}, 1))
    self.assertTrue(self.ok(self.archive("default", True, 2))["archived"])
    self.assertEqual(self.ok(self.get())["assessmentId"], "default")
    self.refused(self.save({"sectoral_requirements": "y"}, 3), 409, "assessment_archived")
    self.assertEqual([r["assessmentId"] for r in self.rows()], [])
    self.assertEqual([r["assessmentId"] for r in self.rows(include_archived=True)], ["default"])

  def test_archive_of_a_missing_or_malformed_fa_row_is_404(self):
    self.refused(self.archive("fa_11111111-1111-4111-8111-111111111111", True, 1), 404, "assessment_not_found")
    self.refused(self.archive("fa_bad", True, 1), 404, "assessment_not_found")

  # -- list -------------------------------------------------------------------------------------

  def test_list_is_empty_before_anything_is_stored_and_never_writes(self):
    self.assertEqual(self.rows(), [])
    self.assertEqual(self.compliance_rows(), {})

  def test_list_carries_status_and_summary_fields_only(self):
    created = self.made("Evaluare 2026")
    row = self.rows()[0]
    self.assertEqual(set(row), {"assessmentId", "packId", "name", "assuranceLevel", "status", "latestRevision",
                                "assessmentRevision", "archived", "updatedBy", "updatedByName", "updatedAt",
                                "createdAt", "canManage"})
    self.assertEqual((row["assessmentId"], row["packId"], row["name"], row["assuranceLevel"], row["status"],
                      row["latestRevision"], row["archived"], row["canManage"]),
                     (created["assessmentId"], PACK, "Evaluare 2026", "basic", "not_started", 0, False, True))
    _no_refs(row)

  def test_list_statuses_not_started_draft_submitted_pending(self):
    fresh = self.made("fresh")["assessmentId"]
    drafted = self.made("drafted")
    self.ok(self.save_fa(drafted["assessmentId"], {"scores": dict(list(self.basic_scores().items())[:1])}, 1))
    submitted = self.submitted_fa("submitted")
    pending = self.made("pending")
    revision = self.complete_fa(pending["assessmentId"], 1)
    self.ok(self.plugin._call_tenant_administration(
      "prepare_framework_assessment_submit", self.admin, tenant_id=self.tenant, pack_id=PACK,
      assessment_id=pending["assessmentId"], expected_assessment_revision=revision, request_id=str(uuid4())))
    status = {r["name"]: r["status"] for r in self.rows()}
    self.assertEqual(status, {"fresh": "not_started", "drafted": "draft", "submitted": "submitted",
                              "pending": "pending"})
    self.assertEqual({r["assessmentId"]: r["latestRevision"] for r in self.rows()}[submitted], 1)
    # reopened after a submit is a draft, not "not_started"
    row = self.ok(self.get_fa(submitted))
    self.ok(self.reopen_fa(submitted, row["assessmentRevision"], str(uuid4())))
    self.assertEqual({r["name"]: r["status"] for r in self.rows()}["submitted"], "draft")
    self.assertIn(fresh, [r["assessmentId"] for r in self.rows()])

  def test_archive_and_unarchive_of_an_untouched_assessment_still_list_not_started(self):
    a = self.made("A")["assessmentId"]
    self.ok(self.archive(a, True, 1))
    self.ok(self.archive(a, False, 2))
    self.assertEqual({r["name"]: (r["status"], r["assessmentRevision"]) for r in self.rows()}, {"A": ("not_started", 3)})

  def test_list_hides_archived_unless_asked_and_orders_by_update_time_descending(self):
    a, b, c = self.made("A"), self.made("B"), self.made("C")
    stamps = {a["assessmentId"]: "2026-01-01T00:00:00+00:00", b["assessmentId"]: "2026-03-01T00:00:00+00:00",
              c["assessmentId"]: "2026-02-01T00:00:00+00:00"}
    for aid, stamp in stamps.items():
      key = json.dumps([compliance.KIND, "deployment", self.tenant, PACK, aid], separators=(",", ":"))
      self.storage.data[(COMPLIANCE_HKEY, key)]["updated_at"] = stamp
    self.assertEqual([r["name"] for r in self.rows()], ["B", "C", "A"])
    self.ok(self.archive(c["assessmentId"], True, 1))
    self.assertEqual([r["name"] for r in self.rows()], ["B", "A"])
    self.assertNotIn("C", [r["name"] for r in self.rows()])
    with_archived = self.rows(include_archived=True)
    self.assertIn("C", [r["name"] for r in with_archived])
    self.assertEqual([r["archived"] for r in with_archived if r["name"] == "C"], [True])

  def test_list_shows_the_default_once_saved_and_filters_by_pack(self):
    self.made("A")
    self.ok(self.save({"sectoral_requirements": "x"}, 1))
    ids = [r["assessmentId"] for r in self.rows()]
    self.assertIn("default", ids)
    self.assertEqual(len(ids), 2)
    self.assertEqual(len(self.rows(pack="")), 2)
    self.refused(self.listing(pack="cyfun.2025"), 404, "assessment_not_found")

  def test_list_rejects_a_non_boolean_include_archived(self):
    for bad in ("true", 1, None):
      self.refused(self.plugin.list_framework_assessments(self.admin, self.tenant, PACK, bad), 400, "invalid_request")

  def test_list_resolves_updated_by_names_and_reads_only_this_tenants_rows(self):
    self.ok(self.plugin.update_account_profile(self.admin, "initial", {"full_name": "Ana Admin"}))
    self.made("A")
    other = json.dumps([compliance.KIND, "deployment", "tn_" + str(uuid4()), PACK,
                        "fa_11111111-1111-4111-8111-111111111111"], separators=(",", ":"))
    self.storage.data[(COMPLIANCE_HKEY, other)] = {"raw": "not a row"}
    rows = self.rows()
    self.assertEqual([(r["name"], r["updatedByName"]) for r in rows], [("A", "Ana Admin")])

  # -- roles and tenants ------------------------------------------------------------------------

  def test_tenant_user_may_list_but_not_create_or_archive(self):
    created = self.made()
    rows = self.rows(actor=self.viewer)
    self.assertEqual([(r["name"], r["canManage"]) for r in rows], [("Evaluare 2026", False)])
    self.refused(self.create("B", actor=self.viewer), 403, "forbidden")
    self.refused(self.archive(created["assessmentId"], True, 1, actor=self.viewer), 403, "forbidden")
    self.assertEqual(len(self.rows()), 1)

  def test_pentesters_may_not_list_and_strangers_see_nothing_and_every_refusal_is_audited(self):
    created = self.made()
    self.events.clear()
    self.refused(self.listing(actor=self.pentester), 403, "forbidden")
    self.refused(self.listing(actor=self.stranger), 404, "not_found")
    self.refused(self.create("B", actor=self.stranger), 404, "not_found")
    self.refused(self.archive(created["assessmentId"], True, 1, actor=self.stranger), 404, "not_found")
    self.refused(self.create("B", actor=self.pentester), 403, "forbidden")
    refusals = self.events_named("framework_assessment_refused")
    self.assertEqual([(d["operation"], d["status_code"]) for d in refusals],
                     [("list", 403), ("list", 404), ("create", 404), ("archive", 404), ("create", 403)])
    self.assertEqual(len(self.rows()), 1)

  def test_another_tenants_assessment_is_not_reachable_by_id(self):
    created = self.made()
    self.storage.account("outsider", memberships=[{"role": "tenant_admin", "tenant_id": "tn_other"}])
    outsider = {"account_id": "outsider"}
    self.refused(self.plugin.get_framework_assessment(outsider, self.tenant, PACK, created["assessmentId"]), 404,
                 "not_found")
    self.refused(self.plugin.get_framework_assessment(outsider, "tn_other", PACK, created["assessmentId"]), 404,
                 "not_found")

  # -- assessment_id on the six existing endpoints ---------------------------------------------

  def test_empty_assessment_id_means_the_default_on_every_endpoint(self):
    revision = self.complete_basic_draft()
    self.assertEqual(self.ok(self.plugin.get_framework_assessment(self.admin, self.tenant, PACK, ""))
                     ["assessmentId"], "default")
    self.ok(self.submit_fa("", revision, str(uuid4())))
    self.assertEqual(self.ok(self.artifact_fa("", 1))["revision"], 1)
    row = self.ok(self.get())
    self.ok(self.reopen_fa("", row["assessmentRevision"], str(uuid4())))
    self.assertEqual(self.ok(self.get())["name"], "")

  def test_every_endpoint_answers_404_for_an_unknown_fa_id(self):
    missing = "fa_11111111-1111-4111-8111-111111111111"
    calls = [
      self.get_fa(missing), self.save_fa(missing, {}, 1), self.submit_fa(missing, 1, str(uuid4())),
      self.plugin.submit_framework_assessment(self.admin, self.tenant, PACK, None, None, "clear_pending", missing),
      self.reopen_fa(missing, 1, str(uuid4())), self.artifact_fa(missing, 1),
      self.plugin.suggest_framework_assessment_evidence(self.admin, self.tenant, PACK, missing),
    ]
    for result in calls:
      self.refused(result, 404, "assessment_not_found")
    self.assertEqual(self.compliance_rows(), {})

  def test_submit_artifact_and_reopen_run_on_an_fa_row_and_the_default_is_untouched(self):
    self.complete_basic_draft()
    aid = self.submitted_fa()
    self.assertEqual(self.ok(self.artifact_fa(aid, 1))["snapshot"]["assessment_id"], aid)
    self.assertEqual(self.ok(self.get())["latestRevision"], 0)  # the default row did not move
    self.assertEqual(self.ok(self.get_fa(aid))["latestRevision"], 1)

  def test_artifact_of_another_assessments_snapshot_is_a_document_integrity_error(self):
    a, b = self.submitted_fa("A"), self.submitted_fa("B")
    key_a = json.dumps([compliance.KIND, "deployment", self.tenant, PACK, a], separators=(",", ":"))
    key_b = json.dumps([compliance.KIND, "deployment", self.tenant, PACK, b], separators=(",", ":"))
    row_b = self.storage.data[(COMPLIANCE_HKEY, key_b)]
    row_b["submissions"][0]["ref"] = self.storage.data[(COMPLIANCE_HKEY, key_a)]["submissions"][0]["ref"]
    self.refused(self.artifact_fa(b, 1), 409, "document_integrity")
    self.assertEqual(self.ok(self.artifact_fa(a, 1))["snapshot"]["assessment_id"], a)

  def test_suggestions_read_the_level_of_the_named_assessment(self):
    aid = self.made()["assessmentId"]
    data = self.ok(self.plugin.suggest_framework_assessment_evidence(self.admin, self.tenant, PACK, aid))
    self.assertEqual(data["packId"], PACK)

  def test_events_and_refusals_carry_a_bounded_assessment_id(self):
    aid = self.made()["assessmentId"]
    self.events.clear()
    self.ok(self.save_fa(aid, {"sectoral_requirements": "x"}, 1))
    saved = self.events_named("framework_assessment_saved")[0]
    self.assertEqual(saved["assessment_id"], aid)
    self.ok(self.get())  # default: no event on success
    self.save({"assurance_level": "basic"}, 1, self.viewer)
    self.get_fa("x" * 500, self.admin)
    self.plugin.get_framework_assessment(self.pentester, self.tenant, PACK, aid)
    refusals = self.events_named("framework_assessment_refused")
    self.assertEqual(refusals[-1]["assessment_id"], aid)
    self.assertEqual(refusals[-2]["assessment_id"], "x" * 128)

  def test_default_events_name_the_default(self):
    revision = self.complete_basic_draft()
    self.ok(self.submit(revision, str(uuid4())))
    self.assertEqual({d["assessment_id"] for e, d in self.events
                      if e in ("framework_assessment_saved", "framework_assessment_submitted")}, {"default"})
