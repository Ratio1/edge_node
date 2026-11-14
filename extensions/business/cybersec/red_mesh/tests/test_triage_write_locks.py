"""Step 4a S3b: the triage write's cross-job locks and the pending-submission fence on the host's sibling jobs."""
import threading
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.services import rulebook_assessment
from .test_triage_store import TENANT_A, TENANT_B
from .test_triage_write import _Owner, write


class TestTriageWriteLocks(unittest.TestCase):
  def setUp(self):
    self.owner = _Owner()
    self.owner.add_job("job-1")
    self.hkey = f"inst:triage:t:{TENANT_A}"

  def test_pending_submission_on_a_sibling_job_blocks_the_write(self):
    self.owner.add_job("job-0")
    self.owner.pending("job-0")
    result, _ = write(self.owner)
    self.assertEqual(result["error"], "submission_in_progress")
    self.assertNotIn(self.hkey, self.owner.hashes)

  def test_pending_submission_of_another_tenants_or_hosts_job_does_not_block(self):
    self.owner.add_job("job-b", tenant=TENANT_B)
    self.owner.add_job("job-h", host="192.0.2.99")
    self.owner.pending("job-b")
    self.owner.pending("job-h")
    result, _ = write(self.owner)
    self.assertNotIn("error", result, result)

  def test_locks_are_taken_in_sorted_job_then_profile_order(self):
    for job_id in ("job-0", "job-9"):
      self.owner.add_job(job_id)
    taken = []
    real = rulebook_assessment._submission_lock
    with patch.object(rulebook_assessment, "_submission_lock",
                      side_effect=lambda owner, job_id, profile: (taken.append((job_id, profile)), real(owner, job_id, profile))[1]):
      write(self.owner)
    self.assertEqual(taken, sorted(taken))
    self.assertEqual({job for job, _ in taken}, {"job-0", "job-1", "job-9"})

  def test_a_sibling_that_appears_while_locking_is_locked_too(self):
    real = rulebook_assessment._submission_lock
    calls = []

    def lock(owner, job_id, profile):
      calls.append((job_id, profile))
      if len(calls) == 1:
        owner.add_job("job-0")  # launched between the enumeration and the lock
      return real(owner, job_id, profile)
    with patch.object(rulebook_assessment, "_submission_lock", side_effect=lock):
      result, _ = write(self.owner)
    self.assertNotIn("error", result, result)
    self.assertIn("job-0", {job for job, _ in calls})

  def test_a_held_sibling_lock_makes_the_write_wait(self):
    self.owner.add_job("job-0")
    profile = rulebook_assessment.list_rulebook_profiles()[0]["profile_id"]
    held, release, done = threading.Event(), threading.Event(), threading.Event()

    def hold():
      with rulebook_assessment._submission_lock(self.owner, "job-0", profile):
        held.set()
        release.wait(5)
    holder = threading.Thread(target=hold)
    holder.start()
    held.wait(5)

    def run():
      write(self.owner)
      done.set()
    writer = threading.Thread(target=run)
    writer.start()
    self.assertFalse(done.wait(0.3))
    release.set()
    holder.join(5)
    writer.join(5)
    self.assertTrue(done.is_set())


if __name__ == "__main__":
  unittest.main()
