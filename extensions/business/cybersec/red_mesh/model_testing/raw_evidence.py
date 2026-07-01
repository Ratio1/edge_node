"""Restricted raw Model Testing evidence helpers.

This module intentionally separates normal safe metadata from restricted raw
artifacts. Normal job/archive payloads may carry only the sanitized metadata
returned by these helpers; raw CIDs/artifact ids stay in a restricted backend
metadata lane once the artifact writer lands.
"""

from ..model_test_sanitization import (
  RAW_EVIDENCE_ERROR_CAPTURE_UNAVAILABLE,
  RAW_EVIDENCE_ERROR_DISABLED,
  RAW_EVIDENCE_ERROR_DELETE_FAILED,
  RAW_EVIDENCE_ERROR_STORAGE_UNAVAILABLE,
  RAW_EVIDENCE_SAFE_ERROR_CLASSES,
  RAW_EVIDENCE_STATUS_AVAILABLE,
  RAW_EVIDENCE_STATUS_CAPTURE_FAILED,
  RAW_EVIDENCE_STATUS_DELETED,
  RAW_EVIDENCE_STATUS_DELETE_FAILED,
  RAW_EVIDENCE_STATUS_DELETE_PENDING,
  RAW_EVIDENCE_STATUS_DISABLED_BY_POLICY,
  RAW_EVIDENCE_STATUS_EXPIRED,
  RAW_EVIDENCE_STATUS_NOT_REQUESTED,
  RAW_EVIDENCE_STATUS_PENDING,
  RAW_EVIDENCE_STATUSES,
  raw_evidence_requested,
  sanitize_raw_evidence_error_class,
  sanitize_raw_evidence_metadata,
  sanitize_raw_evidence_status,
)

RAW_MODEL_TEST_EVIDENCE_KIND = "redmesh_model_test_raw_evidence"


def is_restricted_raw_evidence_artifact(payload):
  """Return True when payload is a restricted raw model-test artifact."""
  return isinstance(payload, dict) and payload.get("kind") == RAW_MODEL_TEST_EVIDENCE_KIND


def initial_raw_evidence_metadata(job_config, cfg):
  """Return launch-time safe metadata for model-test raw evidence."""
  request_config = (job_config or {}).get("raw_evidence")
  return sanitize_raw_evidence_metadata(
    None,
    request_config=request_config,
    backend_enabled=bool((cfg or {}).get("RAW_EVIDENCE_ENABLED")),
  )


def terminal_raw_evidence_metadata(job_config, cfg, existing=None):
  """Return terminal safe metadata when no restricted artifact writer produced one."""
  metadata = sanitize_raw_evidence_metadata(
    existing,
    request_config=(job_config or {}).get("raw_evidence"),
    backend_enabled=bool((cfg or {}).get("RAW_EVIDENCE_ENABLED")),
  )
  if (
      metadata.get("requested")
      and metadata.get("backend_enabled")
      and metadata.get("status") == RAW_EVIDENCE_STATUS_PENDING
  ):
    metadata["status"] = RAW_EVIDENCE_STATUS_CAPTURE_FAILED
    metadata["available"] = False
    metadata["error_class"] = RAW_EVIDENCE_ERROR_CAPTURE_UNAVAILABLE
  return metadata
