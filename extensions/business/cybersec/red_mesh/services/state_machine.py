from ..constants import (
  JOB_STATUS_ANALYZING,
  JOB_STATUS_COLLECTING,
  JOB_STATUS_FINALIZED,
  JOB_STATUS_FINALIZING,
  JOB_STATUS_RUNNING,
  JOB_STATUS_SCHEDULED_FOR_STOP,
  JOB_STATUS_STOPPED,
)


JOB_STATUS_TRANSITIONS = {
  JOB_STATUS_RUNNING: {
    JOB_STATUS_COLLECTING,
    JOB_STATUS_SCHEDULED_FOR_STOP,
    JOB_STATUS_STOPPED,
  },
  JOB_STATUS_SCHEDULED_FOR_STOP: {
    JOB_STATUS_COLLECTING,
    JOB_STATUS_STOPPED,
  },
  JOB_STATUS_COLLECTING: {
    JOB_STATUS_ANALYZING,
    JOB_STATUS_FINALIZING,
    JOB_STATUS_STOPPED,
  },
  JOB_STATUS_ANALYZING: {
    JOB_STATUS_FINALIZING,
    JOB_STATUS_STOPPED,
  },
  JOB_STATUS_FINALIZING: {
    JOB_STATUS_RUNNING,
    JOB_STATUS_FINALIZED,
    JOB_STATUS_STOPPED,
  },
  JOB_STATUS_FINALIZED: set(),
  JOB_STATUS_STOPPED: set(),
}

TERMINAL_JOB_STATUSES = {
  JOB_STATUS_FINALIZED,
  JOB_STATUS_STOPPED,
}

INTERMEDIATE_JOB_STATUSES = {
  JOB_STATUS_COLLECTING,
  JOB_STATUS_ANALYZING,
  JOB_STATUS_FINALIZING,
}


def can_transition_job_status(current_status: str, next_status: str) -> bool:
  if current_status == next_status:
    return True
  allowed = JOB_STATUS_TRANSITIONS.get(current_status, set())
  return next_status in allowed


def set_job_status(job_specs: dict, next_status: str) -> dict:
  current_status = job_specs.get("job_status", JOB_STATUS_RUNNING)
  if not can_transition_job_status(current_status, next_status):
    raise ValueError(f"Invalid job status transition: {current_status} -> {next_status}")
  job_specs["job_status"] = next_status
  return job_specs


def is_terminal_job_status(status: str) -> bool:
  return status in TERMINAL_JOB_STATUSES


def is_intermediate_job_status(status: str) -> bool:
  return status in INTERMEDIATE_JOB_STATUSES
