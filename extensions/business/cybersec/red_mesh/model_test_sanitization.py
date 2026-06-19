"""Safe model-test payload helpers for generic storage and API readback."""

MODEL_TEST_JOB_TYPE = "model_test"
MODEL_TEST_PROGRESS_SCHEMA = "model_test_progress_v1"

MODEL_TEST_SAFE_ERROR_CLASSES = {
  "provider_auth_failed",
  "provider_timeout",
  "provider_unreachable",
  "provider_rate_limited",
  "provider_response_invalid",
  "evaluator_parse_failed",
  "evaluator_policy_failed",
  "worker_lost",
  "assignment_stale",
  "finalization_failed",
  "archive_read_failed",
  "unsupported_job_type",
  "canceled_by_user",
}

SAFE_MODEL_TEST_RESULT_KEYS = {
  "overall_status",
  "case_id",
  "id",
  "category",
  "status",
  "verdict",
  "error_class",
  "duration_ms",
  "latency_ms",
  "attempts",
  "score",
}

SAFE_MODEL_TEST_SUMMARY_KEYS = {
  "overall_status",
  "total_cases",
  "cases_total",
  "completed_cases",
  "cases_completed",
  "evaluated_cases",
  "execution_failed_cases",
  "evaluation_failed_cases",
  "passed_cases",
  "failed_cases",
  "skipped_cases",
  "delayed_worker_warning",
  "delayed_worker_at",
  "error_class",
}


def _safe_scalar(value):
  if isinstance(value, bool) or value is None:
    return value
  if isinstance(value, (int, float)):
    return value
  if isinstance(value, str):
    return value[:512]
  return None


def sanitize_model_test_error_class(value):
  """Return a stable model-test error class, never raw provider text."""
  if not isinstance(value, str) or not value:
    return None
  return value if value in MODEL_TEST_SAFE_ERROR_CLASSES else "unknown_error"


def sanitize_model_test_summary(summary) -> dict:
  """Return a bounded summary that never contains raw provider/evaluator output."""
  if not isinstance(summary, dict):
    return {}
  sanitized = {}
  for key in SAFE_MODEL_TEST_SUMMARY_KEYS:
    if key not in summary:
      continue
    if key == "error_class":
      error_class = sanitize_model_test_error_class(summary.get(key))
      if error_class:
        sanitized[key] = error_class
      continue
    value = _safe_scalar(summary.get(key))
    if value is not None:
      sanitized[key] = value
  return sanitized


def _sanitize_model_test_case(case) -> dict:
  if not isinstance(case, dict):
    return {}
  sanitized = {}
  for key in SAFE_MODEL_TEST_RESULT_KEYS:
    if key not in case:
      continue
    if key == "error_class":
      error_class = sanitize_model_test_error_class(case.get(key))
      if error_class:
        sanitized[key] = error_class
      continue
    value = _safe_scalar(case.get(key))
    if value is not None:
      sanitized[key] = value
  return sanitized


def sanitize_model_test_results(results) -> dict:
  """Allowlist model-test result fields safe for CStore, archive, and UI download."""
  if not isinstance(results, dict):
    return {}
  sanitized = {}
  overall_status = _safe_scalar(results.get("overall_status"))
  if overall_status is not None:
    sanitized["overall_status"] = overall_status
  cases = results.get("cases")
  if isinstance(cases, list):
    sanitized["cases"] = [
      case
      for case in (_sanitize_model_test_case(entry) for entry in cases)
      if case
    ]
  return sanitized
