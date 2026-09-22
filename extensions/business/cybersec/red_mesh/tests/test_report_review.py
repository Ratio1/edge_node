"""Report-level review (RM-086 item 4): approve / reopen a job's report as a whole.

Service-level, on the same owner double the rulebook review tests use. The
tenant admission of the three endpoints is covered by the scope matrix in
`test_tenant_rulebook_scope.py`, which lists them beside the rulebook ones.
"""
import unittest

from .conftest import mock_plugin_modules  # noqa: F401  (installs the plugin stubs)
from .test_rulebook_assessment import _Owner, _sample_job_specs
from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
from extensions.business.cybersec.red_mesh.services.report_review import (
  EVENT_APPROVED,
  EVENT_REOPENED,
  approve_report,
  get_report_review,
  reopen_report_review,
)


class TestReportReview(unittest.TestCase):

  def test_no_review_reads_as_absent_and_not_approved(self):
    owner = _Owner()
    view = get_report_review(owner, "job-1")
    self.assertEqual(view["status"], "ok")
    self.assertIsNone(view["review"])
    self.assertEqual(view["review_revision"], 0)
    self.assertFalse(view["approved"])
    self.assertEqual(view["latest_pass_nr"], 1)

  def test_approve_records_the_signer_pinned_to_the_newest_pass(self):
    owner = _Owner()
    view = approve_report(owner, "job-1", expected_review_revision=0, note="Looks right", actor="alice")
    self.assertEqual(view["status"], "ok", view)
    self.assertTrue(view["approved"])
    self.assertEqual(view["review_revision"], 1)
    review = view["review"]
    self.assertEqual(review["state"], "approved")
    self.assertEqual(review["reviewer"], "alice")
    self.assertEqual(review["note"], "Looks right")
    self.assertEqual(review["approved_pass_nr"], 1)
    self.assertTrue(review["approved_at"].endswith("Z"))
    self.assertEqual([event for event, _ in owner.audit_events], [EVENT_APPROVED])
    audit = JobStateRepository(owner).get_report_review_audit("job-1")
    self.assertEqual([row["event_type"] for row in audit], [EVENT_APPROVED])

  def test_approve_is_refused_without_a_server_derived_actor(self):
    owner = _Owner()
    result = approve_report(owner, "job-1", expected_review_revision=0, actor="")
    self.assertEqual(result["error"], "invalid_review_actor")
    self.assertIsNone(get_report_review(owner, "job-1")["review"])

  def test_approve_is_refused_on_a_job_that_is_not_finalized(self):
    owner = _Owner(job_specs=_sample_job_specs(job_status="RUNNING"))
    result = approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    self.assertEqual(result["error"], "job_not_finalized")

  def test_a_stale_revision_is_a_typed_conflict(self):
    owner = _Owner()
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    for operation in (approve_report, reopen_report_review):
      wrong = operation(owner, "job-1", expected_review_revision=0, actor="bob")
      self.assertEqual(wrong["error"], "review_revision_conflict")
      self.assertEqual(wrong["current_review_revision"], 1)
    # At the current revision, still covering the newest pass: a replay, not a
    # second approval, and alice stays the reviewer.
    replay = approve_report(owner, "job-1", expected_review_revision=1, actor="bob")
    self.assertTrue(replay.get("idempotent_replay"), replay)
    self.assertEqual(replay["review"]["reviewer"], "alice")
    self.assertEqual(replay["review_revision"], 1)
    for bad in (None, "x", -1):
      self.assertEqual(
        approve_report(owner, "job-1", expected_review_revision=bad, actor="bob")["error"],
        "review_revision_conflict",
      )

  def test_reopen_withdraws_the_approval_and_keeps_who_approved(self):
    owner = _Owner()
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    view = reopen_report_review(owner, "job-1", expected_review_revision=1, actor="bob")
    self.assertEqual(view["status"], "ok", view)
    self.assertFalse(view["approved"])
    self.assertEqual(view["review_revision"], 2)
    self.assertEqual(view["review"]["state"], "reopened")
    self.assertEqual(view["review"]["reviewer"], "alice")
    self.assertEqual(view["review"]["reopened_by"], "bob")
    self.assertEqual([event for event, _ in owner.audit_events], [EVENT_APPROVED, EVENT_REOPENED])
    # And a fresh approval starts from the bumped revision.
    again = approve_report(owner, "job-1", expected_review_revision=2, actor="carol")
    self.assertTrue(again["approved"])
    self.assertEqual(again["review"]["reviewer"], "carol")
    self.assertEqual(again["review"]["reopened_by"], "")

  def test_reopen_without_an_approval_is_refused(self):
    owner = _Owner()
    self.assertEqual(
      reopen_report_review(owner, "job-1", expected_review_revision=0, actor="bob")["error"],
      "not_approved",
    )

  def test_a_newer_pass_makes_the_approval_stale_and_re_approval_re_pins_it(self):
    owner = _Owner()
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    owner.job_specs = _sample_job_specs(pass_reports=[{"pass_nr": 1}, {"pass_nr": 2}])
    view = get_report_review(owner, "job-1")
    self.assertTrue(view["stale"])
    self.assertEqual(view["stale_reasons"], ["newer_scan_pass"])
    self.assertFalse(view["approved"])
    self.assertEqual(view["latest_pass_nr"], 2)
    again = approve_report(owner, "job-1", expected_review_revision=1, actor="alice")
    self.assertTrue(again["approved"])
    self.assertEqual(again["review"]["approved_pass_nr"], 2)
    self.assertEqual(again["review_revision"], 2)

  def test_the_note_and_actor_pass_through_the_redaction_rule(self):
    owner = _Owner()
    view = approve_report(
      owner, "job-1", expected_review_revision=0, actor="alice",
      note="checked; password=hunter2 was the shipped default",
    )
    self.assertNotIn("hunter2", view["review"]["note"])
    self.assertIn("<redacted>", view["review"]["note"])

  def test_purge_deletes_the_row_and_its_audit(self):
    owner = _Owner()
    approve_report(owner, "job-1", expected_review_revision=0, actor="alice")
    repo = JobStateRepository(owner)
    self.assertIsNotNone(repo.get_report_review("job-1"))
    repo.delete_job_report_review("job-1")
    self.assertIsNone(repo.get_report_review_model("job-1"))
    self.assertEqual(repo.get_report_review_audit("job-1"), [])

  def test_an_unknown_contract_version_is_refused_not_misread(self):
    owner = _Owner()
    owner.chainstore_hset(f"{owner.cfg_instance_id}:report_review", "job-1",
                          {"job_id": "job-1", "state": "approved", "contract_version": "9.0.0"})
    self.assertEqual(get_report_review(owner, "job-1")["error"], "review_contract_unsupported")


if __name__ == "__main__":
  unittest.main()
