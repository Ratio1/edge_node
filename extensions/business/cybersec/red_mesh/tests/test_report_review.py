"""Report review 2.0.0 (RM-088): a per-pass verdict on a job's report.

Service-level, on the same owner double the rulebook review tests use. The
tenant admission of the three endpoints is covered by the scope matrix in
`test_tenant_rulebook_scope.py`, which lists them beside the rulebook ones.
Contract: `docs/resources/redmesh/contracts/report-review.md` (project-red-mesh).
"""
import unittest

from .conftest import mock_plugin_modules  # noqa: F401  (installs the plugin stubs)
from .test_rulebook_assessment import _Owner, _sample_job_specs, checked_read_producer
from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
from extensions.business.cybersec.red_mesh.services.report_review import (
  EVENT_APPROVED,
  EVENT_REJECTED,
  approve_report,
  get_report_review,
  reject_report,
)


class TestReportReviewVerdicts(unittest.TestCase):

  def test_a_finalized_job_without_a_verdict_is_pending(self):
    owner = _Owner()
    view = get_report_review(owner, "job-1")
    self.assertEqual(view["status"], "ok")
    self.assertEqual(view["review_status"], "pending")
    self.assertIsNone(view["review"])
    self.assertEqual(view["review_revision"], 0)
    self.assertEqual(view["latest_pass_nr"], 1)
    self.assertEqual(view["history"], [])

  def test_a_job_that_is_not_finalized_is_not_reviewable(self):
    owner = _Owner(job_specs=_sample_job_specs(job_status="RUNNING"))
    view = get_report_review(owner, "job-1")
    self.assertIsNone(view["review_status"])
    self.assertFalse(view["can_approve"])
    self.assertEqual([item["code"] for item in view["approve_blocked"]], ["job_not_finalized"])

  def test_approve_records_the_signer_for_the_latest_pass(self):
    owner = _Owner()
    view = approve_report(owner, "job-1", expected_review_revision=0, note="Looks right", actor="alice")
    self.assertEqual(view["status"], "ok", view)
    self.assertEqual(view["review_status"], "approved")
    self.assertEqual(view["review_revision"], 1)
    review = view["review"]
    self.assertEqual(review["state"], "approved")
    self.assertEqual(review["pass_nr"], 1)
    self.assertEqual(review["reviewer"], "alice")
    self.assertEqual(review["note"], "Looks right")
    self.assertEqual(review["nis2_submission_ref"], "")
    self.assertTrue(review["decided_at"].endswith("Z"))
    self.assertEqual([event for event, _ in owner.audit_events], [EVENT_APPROVED])
    audit = JobStateRepository(owner).get_report_review_audit("job-1")
    self.assertEqual([(row["event_type"], row["pass_nr"]) for row in audit], [(EVENT_APPROVED, 1)])

  def test_reject_requires_a_note(self):
    owner = _Owner()
    for note in ("", "   ", None):
      result = reject_report(owner, "job-1", expected_review_revision=0, note=note, actor="alice")
      self.assertEqual(result["error"], "note_required")
    self.assertEqual(get_report_review(owner, "job-1")["review_status"], "pending")

  def test_reject_then_approve_under_the_fence(self):
    owner = _Owner()
    rejected = reject_report(owner, "job-1", expected_review_revision=0,
                             note="Findings 3 and 4 are duplicates", actor="alice")
    self.assertEqual(rejected["review_status"], "rejected", rejected)
    self.assertEqual(rejected["review"]["note"], "Findings 3 and 4 are duplicates")
    self.assertEqual(rejected["review_revision"], 1)
    approved = approve_report(owner, "job-1", expected_review_revision=1, actor="bob")
    self.assertEqual(approved["review_status"], "approved", approved)
    self.assertEqual(approved["review"]["reviewer"], "bob")
    self.assertEqual(approved["review"]["note"], "")
    self.assertEqual(approved["review_revision"], 2)
    self.assertEqual([event for event, _ in owner.audit_events], [EVENT_REJECTED, EVENT_APPROVED])

  def test_a_stale_revision_is_a_typed_conflict_and_a_repeat_is_a_replay(self):
    owner = _Owner()
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    wrong = approve_report(owner, "job-1", expected_review_revision=0, actor="bob")
    self.assertEqual(wrong["error"], "review_revision_conflict")
    self.assertEqual(wrong["current_review_revision"], 1)
    wrong = reject_report(owner, "job-1", expected_review_revision=0, note="no", actor="bob")
    self.assertEqual(wrong["error"], "review_revision_conflict")
    replay = approve_report(owner, "job-1", expected_review_revision=1, actor="bob")
    self.assertTrue(replay.get("idempotent_replay"), replay)
    self.assertEqual(replay["review"]["reviewer"], "alice")
    self.assertEqual(replay["review_revision"], 1)
    for bad in (None, "x", -1):
      self.assertEqual(
        approve_report(owner, "job-1", expected_review_revision=bad, actor="bob")["error"],
        "review_revision_conflict",
      )

  def test_a_newer_pass_is_pending_and_keeps_the_earlier_verdict_as_history(self):
    # A finalized record is the pruned CStoreJobFinalized: `pass_count`, no
    # `pass_reports`. Nothing re-runs a FINALIZED job today, so this pins the
    # rule for the day a re-run path exists (contract §State model).
    owner = _Owner()
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    owner.job_specs = _sample_job_specs(pass_count=2)
    view = get_report_review(owner, "job-1")
    self.assertEqual(view["review_status"], "pending")
    self.assertEqual(view["latest_pass_nr"], 2)
    self.assertIsNone(view["review"])
    self.assertEqual(view["review_revision"], 0)
    self.assertEqual([(row["pass_nr"], row["state"]) for row in view["history"]], [(1, "approved")])
    rejected = reject_report(owner, "job-1", expected_review_revision=0, note="Pass 2 regressed", actor="bob")
    self.assertEqual(rejected["review"]["pass_nr"], 2)
    self.assertEqual(rejected["review_revision"], 1)
    self.assertEqual(rejected["history"][0]["state"], "approved")

  def test_verdicts_are_refused_on_a_job_that_is_not_finalized(self):
    owner = _Owner(job_specs=_sample_job_specs(job_status="RUNNING"))
    self.assertEqual(
      approve_report(owner, "job-1", expected_review_revision=0, actor="alice")["error"],
      "job_not_finalized")
    self.assertEqual(
      reject_report(owner, "job-1", expected_review_revision=0, note="no", actor="alice")["error"],
      "job_not_finalized")

  def test_verdicts_are_refused_without_a_server_derived_actor(self):
    owner = _Owner()
    for actor in ("", None, "Not An Id!"):
      self.assertEqual(
        approve_report(owner, "job-1", expected_review_revision=0, actor=actor)["error"],
        "invalid_review_actor")
      self.assertEqual(
        reject_report(owner, "job-1", expected_review_revision=0, note="no", actor=actor)["error"],
        "invalid_review_actor")
    self.assertIsNone(get_report_review(owner, "job-1")["review"])

  def test_an_account_id_shaped_like_an_ip_is_stored_as_itself(self):
    # `_safe_text` would pseudonymise it; the signer is validated as an id instead.
    owner = _Owner()
    view = approve_report(owner, "job-1", expected_review_revision=0, actor="10.0.0.1")
    self.assertEqual(view["review"]["reviewer"], "10.0.0.1")

  def test_the_note_passes_through_the_redaction_rule(self):
    owner = _Owner()
    view = reject_report(
      owner, "job-1", expected_review_revision=0, actor="alice",
      note="checked; password=hunter2 was the shipped default",
    )
    self.assertNotIn("hunter2", view["review"]["note"])
    self.assertIn("<redacted>", view["review"]["note"])

  def test_purge_removes_every_pass_row_and_the_audit(self):
    from extensions.business.cybersec.red_mesh.services.control import purge_job
    owner = _Owner()
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    owner.job_specs = _sample_job_specs(pass_count=2)
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    owner.records[(owner.cfg_instance_id, "job-1")] = owner.job_specs
    result = purge_job(owner, "job-1")
    self.assertEqual(result["status"], "success", result)
    hkey = f"{owner.cfg_instance_id}:report_review"
    self.assertEqual(owner.chainstore_hgetall(hkey), {})
    self.assertIsNone(owner.records[(f"{hkey}:audit", "job-1")])

  def test_an_unknown_contract_version_is_refused_not_misread(self):
    owner = _Owner()
    owner.chainstore_hset(f"{owner.cfg_instance_id}:report_review", "job-1:1",
                          {"job_id": "job-1", "pass_nr": 1, "state": "approved",
                           "contract_version": "1.0.0"})
    self.assertEqual(get_report_review(owner, "job-1")["error"], "review_contract_unsupported")

  def test_a_1_0_0_row_under_the_old_key_is_ignored(self):
    owner = _Owner()
    owner.chainstore_hset(f"{owner.cfg_instance_id}:report_review", "job-1",
                          {"job_id": "job-1", "state": "approved", "contract_version": "1.0.0",
                           "approved_pass_nr": 1})
    self.assertEqual(get_report_review(owner, "job-1")["review_status"], "pending")


class TestReportReviewNis2Gate(unittest.TestCase):
  """Approve waits for the NIS2 review of the same pass (contract §Approve gate).

  `checked_read_producer` drives the real rulebook writers; its fixture archive's
  latest pass is 3, so the job record is given `pass_count=3` to agree with it.
  """

  def _owner(self, nis2_state, pass_count=3):
    owner = checked_read_producer(nis2_state)
    owner.job_specs = {**owner.job_specs, "pass_count": pass_count}
    return owner

  def _codes(self, view):
    return [item["code"] for item in view["approve_blocked"]]

  def test_a_job_without_a_nis2_assessment_is_approvable(self):
    owner = self._owner("missing")
    view = get_report_review(owner, "job-1")
    self.assertTrue(view["can_approve"], view)
    self.assertEqual(view["approve_blocked"], [])
    approved = approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    self.assertEqual(approved["review_status"], "approved", approved)
    self.assertEqual(approved["review"]["nis2_submission_ref"], "")

  def test_an_assessment_without_a_submitted_review_blocks_approve(self):
    for nis2_state in ("generated", "draft", "reopened"):
      with self.subTest(nis2_state=nis2_state):
        owner = self._owner(nis2_state)
        view = get_report_review(owner, "job-1")
        self.assertFalse(view["can_approve"])
        self.assertEqual(view["approve_blocked"], [{
          "code": "nis2_review_not_submitted",
          "detail": {"profile_id": "nis2.eu_baseline.v1", "pass_nr": 3},
        }])
        refused = approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
        self.assertEqual(refused["error"], "approve_blocked")
        self.assertEqual(self._codes(refused), ["nis2_review_not_submitted"])
        self.assertEqual(get_report_review(owner, "job-1")["review_status"], "pending")

  def test_reject_is_never_gated_on_nis2(self):
    owner = self._owner("generated")
    view = reject_report(owner, "job-1", expected_review_revision=0, note="Not ready", actor="alice")
    self.assertEqual(view["review_status"], "rejected", view)

  def test_a_submission_for_an_older_pass_is_stale(self):
    owner = self._owner("submitted", pass_count=4)
    view = get_report_review(owner, "job-1")
    self.assertEqual(view["approve_blocked"], [{
      "code": "nis2_submission_stale",
      "detail": {"profile_id": "nis2.eu_baseline.v1", "submitted_pass_nr": 3, "latest_pass_nr": 4},
    }])

  def test_a_failed_submission_keeps_the_gate_shut(self):
    # The registry holds a pending entry with its error; the NIS2 view reads draft.
    owner = self._owner("submission_failed")
    self.assertEqual(self._codes(get_report_review(owner, "job-1")), ["nis2_review_not_submitted"])

  def test_an_unreadable_nis2_registry_keeps_the_gate_shut(self):
    owner = self._owner("submitted")
    owner.chainstore_hset(f"{owner.cfg_instance_id}:rulebook_review:submissions",
                          "job-1:nis2.eu_baseline.v1", {"contract_version": "9.9.9"})
    self.assertEqual(self._codes(get_report_review(owner, "job-1")), ["nis2_review_not_submitted"])

  def test_a_legacy_reviewed_state_counts_as_submitted_for_its_pass(self):
    owner = self._owner("legacy")
    self.assertTrue(get_report_review(owner, "job-1")["can_approve"])

  def test_a_legacy_reviewed_state_with_no_recorded_pass_is_not_submitted(self):
    owner = self._owner("legacy")
    meta = dict(owner.job_specs["rulebook_assessments"]["nis2.eu_baseline.v1"])
    meta.pop("pass_nr"); meta.pop("latest_pass_nr")
    owner.job_specs = {**owner.job_specs, "rulebook_assessments": {"nis2.eu_baseline.v1": meta}}
    self.assertEqual(self._codes(get_report_review(owner, "job-1")), ["nis2_review_not_submitted"])

  def test_a_current_submission_admits_approve_and_is_recorded(self):
    owner = self._owner("submitted")
    view = get_report_review(owner, "job-1")
    self.assertTrue(view["can_approve"], view)
    approved = approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    self.assertEqual(approved["review_status"], "approved", approved)
    ref = approved["review"]["nis2_submission_ref"]
    self.assertEqual(ref["profile_id"], "nis2.eu_baseline.v1")
    self.assertEqual(ref["revision"], 1)
    self.assertTrue(ref["cid"].startswith("QmRulebook"), ref)


class TestReportReviewSupersededByNis2(unittest.TestCase):
  """An approval rests on the NIS2 submission current when it was given (owner decision,
  RM-088): once the NIS2 review is reopened or resubmitted, the approval no longer
  counts and the pass reads `reopened`, a derived state; the stored row stays approved."""

  def setUp(self):
    self.owner = checked_read_producer("submitted")
    self.owner.job_specs = {**self.owner.job_specs, "pass_count": 3}
    approved = approve_report(self.owner, "job-1", expected_review_revision=0, actor="alice")
    self.assertEqual(approved["review_status"], "approved", approved)
    self.approved_ref = approved["review"]["nis2_submission_ref"]

  def _nis2_revision(self):
    from extensions.business.cybersec.red_mesh.services.rulebook_assessment import get_rulebook_review
    return get_rulebook_review(self.owner, "job-1")["review_revision"]

  def _reopen_nis2(self):
    from extensions.business.cybersec.red_mesh.services.rulebook_assessment import reopen_rulebook_review
    result = reopen_rulebook_review(self.owner, "job-1", expected_review_revision=self._nis2_revision(),
                                    idempotency_key="reopen-1", actor="fixture-reviewer")
    self.assertEqual(result["status"], "ok", result)

  def _resubmit_nis2(self):
    from extensions.business.cybersec.red_mesh.services.rulebook_assessment import submit_rulebook_review
    result = submit_rulebook_review(self.owner, "job-1", expected_review_revision=self._nis2_revision(),
                                    expected_pass_nr=3, expected_profile_version="1.0.0",
                                    idempotency_key="resubmit-1", actor="fixture-reviewer")
    self.assertIsNone(result.get("error"), result)

  def test_a_reopened_nis2_review_reopens_the_approval(self):
    self._reopen_nis2()
    view = get_report_review(self.owner, "job-1")
    self.assertEqual(view["review_status"], "reopened")
    self.assertIsNone(view["review"])
    self.assertEqual(view["review_revision"], 1)
    self.assertEqual(view["reopened"]["review"]["state"], "approved")
    self.assertEqual(view["reopened"]["code"], "nis2_review_changed")
    self.assertEqual(view["reopened"]["detail"], {
      "approved_submission_revision": self.approved_ref["revision"], "current_submission_revision": None})
    self.assertEqual([item["code"] for item in view["approve_blocked"]], ["nis2_review_not_submitted"])
    from extensions.business.cybersec.red_mesh.services.query import get_job_data, list_network_jobs
    self.owner.records[(self.owner.cfg_instance_id, "job-1")] = self.owner.job_specs
    self.assertEqual(list_network_jobs(self.owner)["job-1"]["review"]["review_status"], "reopened")
    self.assertEqual(get_job_data(self.owner, "job-1")["job"]["review"]["review_status"], "reopened")

  def test_a_resubmitted_nis2_review_needs_a_fresh_approval(self):
    self._reopen_nis2()
    self._resubmit_nis2()
    view = get_report_review(self.owner, "job-1")
    self.assertEqual(view["review_status"], "reopened")
    self.assertTrue(view["can_approve"], view)
    detail = view["reopened"]["detail"]
    self.assertEqual(detail["approved_submission_revision"], self.approved_ref["revision"])
    self.assertGreater(detail["current_submission_revision"], self.approved_ref["revision"])
    again = approve_report(self.owner, "job-1", expected_review_revision=1, actor="bob")
    self.assertFalse(again.get("idempotent_replay"), again)
    self.assertEqual(again["review_status"], "approved", again)
    self.assertEqual(again["review_revision"], 2)
    self.assertGreater(again["review"]["nis2_submission_ref"]["revision"], self.approved_ref["revision"])
    self.assertIsNone(again["reopened"])

  def test_a_rejection_is_not_superseded_by_nis2(self):
    reject_report(self.owner, "job-1", expected_review_revision=1, note="Wrong target", actor="bob")
    self._reopen_nis2()
    view = get_report_review(self.owner, "job-1")
    self.assertEqual(view["review_status"], "rejected")
    self.assertIsNone(view["reopened"])


class TestReportReviewOnTheJobsList(unittest.TestCase):

  def _list(self, owner):
    from extensions.business.cybersec.red_mesh.services.query import list_network_jobs
    owner.records[(owner.cfg_instance_id, "job-1")] = owner.job_specs
    return list_network_jobs(owner)

  def test_a_finalized_job_lists_pending_then_its_verdict(self):
    owner = _Owner()
    self.assertEqual(self._list(owner)["job-1"]["review"], {
      "review_status": "pending", "pass_nr": 1, "reviewer": "", "decided_at": ""})
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    review = self._list(owner)["job-1"]["review"]
    self.assertEqual((review["review_status"], review["pass_nr"], review["reviewer"]),
                     ("approved", 1, "alice"))
    self.assertTrue(review["decided_at"].endswith("Z"))

  def test_a_verdict_on_an_earlier_pass_lists_as_pending(self):
    owner = _Owner()
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    owner.job_specs = _sample_job_specs(pass_count=2)
    self.assertEqual(self._list(owner)["job-1"]["review"]["review_status"], "pending")

  def test_the_finalized_job_read_carries_the_same_summary(self):
    from extensions.business.cybersec.red_mesh.services.query import get_job_data
    owner = _Owner()
    reject_report(owner, "job-1", expected_review_revision=0, note="Duplicates", actor="bob")
    review = get_job_data(owner, "job-1")["job"]["review"]
    self.assertEqual((review["review_status"], review["pass_nr"], review["reviewer"]), ("rejected", 1, "bob"))

  def test_a_running_job_lists_no_review(self):
    owner = _Owner(job_specs=_sample_job_specs(job_status="RUNNING", job_cid=None))
    self.assertIsNone(self._list(owner)["job-1"]["review"])


if __name__ == "__main__":
  unittest.main()
