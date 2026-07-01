"""Shared guards for scan-only service entry points."""

from ..model_testing.constants import (
  MODEL_TEST_ERROR_UNSUPPORTED_JOB_TYPE,
  MODEL_TEST_JOB_TYPE,
  is_model_test_job,
)


def unsupported_model_test_response(job_id, operation):
  """Return a sanitized unsupported-job-type response for model-test jobs."""
  return {
    "status": "error",
    "error": MODEL_TEST_ERROR_UNSUPPORTED_JOB_TYPE,
    "error_class": MODEL_TEST_ERROR_UNSUPPORTED_JOB_TYPE,
    "message": "Model Testing jobs are not supported by this scan-only operation.",
    "job_id": job_id,
    "job_type": MODEL_TEST_JOB_TYPE,
    "operation": operation,
  }


def reject_model_test_for_scan_operation(job_specs, job_id, operation):
  """Return an unsupported response when a scan-only path receives a model-test job."""
  if is_model_test_job(job_specs):
    return unsupported_model_test_response(job_id, operation)
  return None
