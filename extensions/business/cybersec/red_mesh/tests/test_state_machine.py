import unittest

from extensions.business.cybersec.red_mesh.constants import (
  JOB_STATUS_ANALYZING,
  JOB_STATUS_COLLECTING,
  JOB_STATUS_FINALIZED,
  JOB_STATUS_FINALIZING,
  JOB_STATUS_RUNNING,
  JOB_STATUS_SCHEDULED_FOR_STOP,
  JOB_STATUS_STOPPED,
)
from extensions.business.cybersec.red_mesh.services.state_machine import (
  can_transition_job_status,
  is_intermediate_job_status,
  is_terminal_job_status,
  set_job_status,
)


class TestJobStateMachine(unittest.TestCase):

  def test_allows_linear_finalization_flow(self):
    job_specs = {"job_status": JOB_STATUS_RUNNING}

    set_job_status(job_specs, JOB_STATUS_COLLECTING)
    set_job_status(job_specs, JOB_STATUS_ANALYZING)
    set_job_status(job_specs, JOB_STATUS_FINALIZING)
    set_job_status(job_specs, JOB_STATUS_FINALIZED)

    self.assertEqual(job_specs["job_status"], JOB_STATUS_FINALIZED)
    self.assertTrue(is_terminal_job_status(job_specs["job_status"]))

  def test_allows_continuous_jobs_to_return_to_running_after_finalizing(self):
    job_specs = {"job_status": JOB_STATUS_RUNNING}

    set_job_status(job_specs, JOB_STATUS_COLLECTING)
    set_job_status(job_specs, JOB_STATUS_FINALIZING)
    set_job_status(job_specs, JOB_STATUS_RUNNING)

    self.assertEqual(job_specs["job_status"], JOB_STATUS_RUNNING)

  def test_rejects_invalid_transition(self):
    job_specs = {"job_status": JOB_STATUS_RUNNING}

    with self.assertRaisesRegex(ValueError, "Invalid job status transition"):
      set_job_status(job_specs, JOB_STATUS_FINALIZED)

  def test_hard_stop_is_allowed_from_intermediate_states(self):
    self.assertTrue(can_transition_job_status(JOB_STATUS_COLLECTING, JOB_STATUS_STOPPED))
    self.assertTrue(can_transition_job_status(JOB_STATUS_ANALYZING, JOB_STATUS_STOPPED))
    self.assertTrue(can_transition_job_status(JOB_STATUS_FINALIZING, JOB_STATUS_STOPPED))

  def test_state_classification_helpers(self):
    self.assertTrue(is_intermediate_job_status(JOB_STATUS_COLLECTING))
    self.assertTrue(is_intermediate_job_status(JOB_STATUS_ANALYZING))
    self.assertTrue(is_intermediate_job_status(JOB_STATUS_FINALIZING))
    self.assertFalse(is_intermediate_job_status(JOB_STATUS_RUNNING))
    self.assertFalse(is_terminal_job_status(JOB_STATUS_SCHEDULED_FOR_STOP))
    self.assertTrue(is_terminal_job_status(JOB_STATUS_STOPPED))
