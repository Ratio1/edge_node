"""Constants and small helpers for the Model Testing job family."""

MODEL_TEST_JOB_TYPE = "model_test"

MODEL_TEST_PROGRESS_SCHEMA = "model_test_progress_v1"

MODEL_TEST_PHASE_QUEUED = "model_test_queued"
MODEL_TEST_PHASE_NODE_SELECTED = "model_test_node_selected"
MODEL_TEST_PHASE_RUNNING = "model_test_running"
MODEL_TEST_PHASE_EVALUATING = "model_test_evaluating"
MODEL_TEST_PHASE_FINALIZING = "model_test_finalizing"
MODEL_TEST_PHASE_DONE = "done"
MODEL_TEST_PHASE_FAILED = "failed"
MODEL_TEST_PHASE_CANCELED = "canceled"

MODEL_TEST_PHASE_INDEX = {
  MODEL_TEST_PHASE_QUEUED: 1,
  MODEL_TEST_PHASE_NODE_SELECTED: 2,
  MODEL_TEST_PHASE_RUNNING: 3,
  MODEL_TEST_PHASE_EVALUATING: 4,
  MODEL_TEST_PHASE_FINALIZING: 5,
  MODEL_TEST_PHASE_DONE: 5,
  MODEL_TEST_PHASE_FAILED: 5,
  MODEL_TEST_PHASE_CANCELED: 5,
}

MODEL_TEST_PHASE_ALIASES = {
  "queued": MODEL_TEST_PHASE_QUEUED,
  "running": MODEL_TEST_PHASE_RUNNING,
  "evaluating": MODEL_TEST_PHASE_EVALUATING,
  "finalizing": MODEL_TEST_PHASE_FINALIZING,
}

MODEL_TEST_ERROR_PROVIDER_AUTH_FAILED = "provider_auth_failed"
MODEL_TEST_ERROR_PROVIDER_TIMEOUT = "provider_timeout"
MODEL_TEST_ERROR_PROVIDER_UNREACHABLE = "provider_unreachable"
MODEL_TEST_ERROR_PROVIDER_RATE_LIMITED = "provider_rate_limited"
MODEL_TEST_ERROR_PROVIDER_RESPONSE_INVALID = "provider_response_invalid"
MODEL_TEST_ERROR_EVALUATOR_PARSE_FAILED = "evaluator_parse_failed"
MODEL_TEST_ERROR_EVALUATOR_POLICY_FAILED = "evaluator_policy_failed"
MODEL_TEST_ERROR_WORKER_LOST = "worker_lost"
MODEL_TEST_ERROR_ASSIGNMENT_STALE = "assignment_stale"
MODEL_TEST_ERROR_FINALIZATION_FAILED = "finalization_failed"
MODEL_TEST_ERROR_ARCHIVE_READ_FAILED = "archive_read_failed"
MODEL_TEST_ERROR_UNSUPPORTED_JOB_TYPE = "unsupported_job_type"
MODEL_TEST_ERROR_CANCELED_BY_USER = "canceled_by_user"

MODEL_TEST_SAFE_ERROR_CLASSES = {
  MODEL_TEST_ERROR_PROVIDER_AUTH_FAILED,
  MODEL_TEST_ERROR_PROVIDER_TIMEOUT,
  MODEL_TEST_ERROR_PROVIDER_UNREACHABLE,
  MODEL_TEST_ERROR_PROVIDER_RATE_LIMITED,
  MODEL_TEST_ERROR_PROVIDER_RESPONSE_INVALID,
  MODEL_TEST_ERROR_EVALUATOR_PARSE_FAILED,
  MODEL_TEST_ERROR_EVALUATOR_POLICY_FAILED,
  MODEL_TEST_ERROR_WORKER_LOST,
  MODEL_TEST_ERROR_ASSIGNMENT_STALE,
  MODEL_TEST_ERROR_FINALIZATION_FAILED,
  MODEL_TEST_ERROR_ARCHIVE_READ_FAILED,
  MODEL_TEST_ERROR_UNSUPPORTED_JOB_TYPE,
  MODEL_TEST_ERROR_CANCELED_BY_USER,
}


def is_model_test_job(job_specs):
  """Return whether a job payload belongs to the Model Testing family."""
  return isinstance(job_specs, dict) and (
    job_specs.get("job_type") == MODEL_TEST_JOB_TYPE
    or job_specs.get("scan_type") == MODEL_TEST_JOB_TYPE
  )


def normalize_model_test_phase(phase):
  """Return a canonical Model Testing progress phase."""
  return MODEL_TEST_PHASE_ALIASES.get(phase, phase or MODEL_TEST_PHASE_NODE_SELECTED)


def selected_model_test_worker_addr(job_specs, fallback=None):
  """Return the selected execution node for a model-test job."""
  if not isinstance(job_specs, dict):
    return fallback
  workers = job_specs.get("workers") or {}
  node_selection = job_specs.get("model_test_node_selection") or {}
  selected = node_selection.get("selected_execution_node")
  if selected and (not workers or selected in workers):
    return selected
  if isinstance(workers, dict) and len(workers) == 1:
    return next(iter(workers))
  if fallback and isinstance(workers, dict) and fallback in workers:
    return fallback
  return selected or fallback
