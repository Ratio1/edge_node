"""Safe model-test payload helpers for generic storage and API readback."""

MODEL_TEST_JOB_TYPE = "model_test"
MODEL_TEST_PROGRESS_SCHEMA = "model_test_progress_v1"

RAW_EVIDENCE_STATUS_NOT_REQUESTED = "not_requested"
RAW_EVIDENCE_STATUS_DISABLED_BY_POLICY = "disabled_by_policy"
RAW_EVIDENCE_STATUS_PENDING = "pending"
RAW_EVIDENCE_STATUS_AVAILABLE = "available"
RAW_EVIDENCE_STATUS_CAPTURE_FAILED = "capture_failed"
RAW_EVIDENCE_STATUS_EXPIRED = "expired"
RAW_EVIDENCE_STATUS_DELETE_PENDING = "delete_pending"
RAW_EVIDENCE_STATUS_DELETED = "deleted"
RAW_EVIDENCE_STATUS_DELETE_FAILED = "delete_failed"

RAW_EVIDENCE_STATUSES = {
  RAW_EVIDENCE_STATUS_NOT_REQUESTED,
  RAW_EVIDENCE_STATUS_DISABLED_BY_POLICY,
  RAW_EVIDENCE_STATUS_PENDING,
  RAW_EVIDENCE_STATUS_AVAILABLE,
  RAW_EVIDENCE_STATUS_CAPTURE_FAILED,
  RAW_EVIDENCE_STATUS_EXPIRED,
  RAW_EVIDENCE_STATUS_DELETE_PENDING,
  RAW_EVIDENCE_STATUS_DELETED,
  RAW_EVIDENCE_STATUS_DELETE_FAILED,
}

RAW_EVIDENCE_ERROR_DISABLED = "raw_evidence_disabled"
RAW_EVIDENCE_ERROR_CAPTURE_UNAVAILABLE = "raw_evidence_capture_unavailable"
RAW_EVIDENCE_ERROR_STORAGE_UNAVAILABLE = "raw_evidence_storage_unavailable"
RAW_EVIDENCE_ERROR_DELETE_FAILED = "raw_evidence_delete_failed"

RAW_EVIDENCE_SAFE_ERROR_CLASSES = {
  RAW_EVIDENCE_ERROR_DISABLED,
  RAW_EVIDENCE_ERROR_CAPTURE_UNAVAILABLE,
  RAW_EVIDENCE_ERROR_STORAGE_UNAVAILABLE,
  RAW_EVIDENCE_ERROR_DELETE_FAILED,
}

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
  "test_set_id",
  "test_sets",
  "test_set_name",
  "topic_id",
  "topic_label",
  "case_id",
  "id",
  "category",
  "prompt_summary",
  "status",
  "verdict",
  "safety_aligned",
  "intended_behavior_correct",
  "rationale",
  "rationale_omitted_reason",
  "sanitized_excerpt",
  "excerpt_omitted_reason",
  "tested_response_hash",
  "evaluator_response_hash",
  "error_class",
  "duration_ms",
  "latency_ms",
  "attempts",
  "score",
  "evaluator_id",
  "evaluator_kind",
  "evaluator_method",
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
  "test_set_id",
  "test_sets",
  "selected_test_set_metadata",
  "aggregate_score",
  "evaluator_id",
  "evaluator_kind",
  "evaluator_method",
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


def raw_evidence_requested(raw_evidence):
  """Return whether launch/config metadata requested restricted raw evidence."""
  return isinstance(raw_evidence, dict) and bool(
    raw_evidence.get("enabled") or raw_evidence.get("requested")
  )


def sanitize_raw_evidence_error_class(value):
  if not isinstance(value, str) or not value:
    return None
  return value if value in RAW_EVIDENCE_SAFE_ERROR_CLASSES else None


def sanitize_raw_evidence_status(value):
  if not isinstance(value, str) or not value:
    return None
  return value if value in RAW_EVIDENCE_STATUSES else None


def sanitize_raw_evidence_metadata(metadata, *, request_config=None, backend_enabled=False):
  """Return safe raw-evidence metadata for normal job/archive surfaces."""
  meta = metadata if isinstance(metadata, dict) else {}
  requested = (
    raw_evidence_requested(meta)
    or raw_evidence_requested(request_config)
  )
  backend_enabled = bool(
    meta.get("backend_enabled")
    or meta.get("raw_evidence_enabled")
    or backend_enabled
  )
  status = sanitize_raw_evidence_status(meta.get("status") or meta.get("raw_evidence_status"))
  available = bool(meta.get("available") or meta.get("raw_evidence_available"))
  if not requested:
    status = status or RAW_EVIDENCE_STATUS_NOT_REQUESTED
    available = False
  elif not backend_enabled:
    status = status or RAW_EVIDENCE_STATUS_DISABLED_BY_POLICY
    available = False
  elif not status:
    status = RAW_EVIDENCE_STATUS_AVAILABLE if available else RAW_EVIDENCE_STATUS_PENDING
  if status != RAW_EVIDENCE_STATUS_AVAILABLE:
    available = False

  payload = {
    "requested": requested,
    "backend_enabled": backend_enabled,
    "status": status,
    "available": available,
  }
  retention_until = meta.get("retention_until") or meta.get("retentionUntil")
  if isinstance(retention_until, str) and retention_until.strip():
    payload["retention_until"] = retention_until.strip()[:80]
  hashes = meta.get("hashes")
  if isinstance(hashes, list):
    safe_hashes = [
      item[:160]
      for item in hashes
      if isinstance(item, str) and item.startswith("sha256:") and len(item) <= 160
    ]
    if safe_hashes:
      payload["hashes"] = safe_hashes
  error_class = sanitize_raw_evidence_error_class(
    meta.get("error_class") or meta.get("raw_evidence_error_class")
  )
  if error_class:
    payload["error_class"] = error_class
  return payload


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
  if isinstance(summary.get("test_sets"), list):
    sanitized["test_sets"] = _sanitize_test_sets(summary.get("test_sets"))
  if isinstance(summary.get("selected_test_set_metadata"), list):
    sanitized["selected_test_set_metadata"] = _sanitize_test_set_metadata(summary.get("selected_test_set_metadata"))
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


def _sanitize_test_sets(entries):
  sanitized = []
  for entry in entries or []:
    if not isinstance(entry, dict):
      continue
    set_id = _safe_scalar(entry.get("id"))
    if not isinstance(set_id, str) or not set_id:
      continue
    topics = []
    if isinstance(entry.get("topic_ids"), list):
      topics = [
        topic for topic in (_safe_scalar(topic) for topic in entry.get("topic_ids"))
        if isinstance(topic, str) and topic
      ]
    sanitized.append({"id": set_id, "topic_ids": topics})
  return sanitized


def _sanitize_test_set_metadata(entries):
  sanitized = []
  for entry in entries or []:
    if not isinstance(entry, dict):
      continue
    set_id = _safe_scalar(entry.get("id"))
    if not isinstance(set_id, str) or not set_id:
      continue
    payload = {"id": set_id}
    name = _safe_scalar(entry.get("name"))
    if isinstance(name, str) and name:
      payload["name"] = name
    case_count = _safe_scalar(entry.get("case_count"))
    if isinstance(case_count, (int, float)) and not isinstance(case_count, bool):
      payload["case_count"] = case_count
    topics = []
    if isinstance(entry.get("topics"), list):
      for topic in entry.get("topics"):
        if not isinstance(topic, dict):
          continue
        topic_id = _safe_scalar(topic.get("id"))
        if not isinstance(topic_id, str) or not topic_id:
          continue
        topic_payload = {"id": topic_id}
        topic_name = _safe_scalar(topic.get("name"))
        if isinstance(topic_name, str) and topic_name:
          topic_payload["name"] = topic_name
        topic_count = _safe_scalar(topic.get("case_count"))
        if isinstance(topic_count, (int, float)) and not isinstance(topic_count, bool):
          topic_payload["case_count"] = topic_count
        topics.append(topic_payload)
    payload["topics"] = topics
    sanitized.append(payload)
  return sanitized


def sanitize_model_test_results(results) -> dict:
  """Allowlist model-test result fields safe for CStore, archive, and UI download."""
  if not isinstance(results, dict):
    return {}
  sanitized = {}
  overall_status = _safe_scalar(results.get("overall_status"))
  if overall_status is not None:
    sanitized["overall_status"] = overall_status
  test_set_id = _safe_scalar(results.get("test_set_id"))
  if isinstance(test_set_id, str) and test_set_id:
    sanitized["test_set_id"] = test_set_id
  cases = results.get("cases")
  if isinstance(cases, list):
    sanitized["cases"] = [
      case
      for case in (_sanitize_model_test_case(entry) for entry in cases)
      if case
    ]
  if isinstance(results.get("test_sets"), list):
    sanitized["test_sets"] = _sanitize_test_sets(results.get("test_sets"))
  return sanitized
