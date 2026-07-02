"""Restricted raw Model Testing evidence helpers.

This module intentionally separates normal safe metadata from restricted raw
artifacts. Normal job/archive payloads may carry only the sanitized metadata
returned by these helpers; raw CIDs/artifact ids stay in a restricted backend
metadata lane once the artifact writer lands.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import time

from ..services.config import get_model_testing_config
from ..services.secrets import R1fsSecretStore
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
RAW_MODEL_TEST_EVIDENCE_SCHEMA = "model_test_raw_evidence_v1"


def is_restricted_raw_evidence_artifact(payload):
  """Return True when payload is a restricted raw model-test artifact."""
  return isinstance(payload, dict) and payload.get("kind") == RAW_MODEL_TEST_EVIDENCE_KIND


def _now(owner):
  time_fn = getattr(owner, "time", None)
  if callable(time_fn):
    try:
      return float(time_fn())
    except (TypeError, ValueError):
      pass
  return time.time()


def _iso_timestamp(value):
  try:
    return datetime.fromtimestamp(float(value), timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
  except (TypeError, ValueError, OSError):
    return ""


def _safe_int(value, default=0):
  try:
    return int(value)
  except (TypeError, ValueError):
    return default


def _sha256_json(payload):
  encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
  return "sha256:" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _retention_until(owner, cfg):
  days = _safe_int((cfg or {}).get("RAW_EVIDENCE_DEFAULT_RETENTION_DAYS"), 7)
  max_days = _safe_int((cfg or {}).get("RAW_EVIDENCE_MAX_RETENTION_DAYS"), 30)
  if days <= 0:
    days = 1
  if max_days <= 0:
    max_days = 30
  days = min(days, max_days)
  return _iso_timestamp(_now(owner) + days * 86400)


def _storage_failure_metadata(job_config, cfg, error_class=RAW_EVIDENCE_ERROR_STORAGE_UNAVAILABLE):
  return sanitize_raw_evidence_metadata(
    {
      "requested": raw_evidence_requested((job_config or {}).get("raw_evidence")),
      "backend_enabled": bool((cfg or {}).get("RAW_EVIDENCE_ENABLED")),
      "status": RAW_EVIDENCE_STATUS_CAPTURE_FAILED,
      "available": False,
      "error_class": error_class,
    },
    request_config=(job_config or {}).get("raw_evidence"),
    backend_enabled=bool((cfg or {}).get("RAW_EVIDENCE_ENABLED")),
  )


def _restricted_metadata_repo(owner):
  from ..repositories import JobStateRepository

  return JobStateRepository(owner)


def _artifact_repo(owner):
  from .artifacts import ModelTestArtifactRepository

  return ModelTestArtifactRepository(owner)


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


def write_raw_evidence_artifact(owner, job_id, job_config, raw_evidence_payload, cfg=None):
  """Write restricted raw evidence and persist backend-only pointer metadata."""
  cfg = cfg or get_model_testing_config(owner)
  request_config = (job_config or {}).get("raw_evidence")
  if not raw_evidence_requested(request_config):
    return sanitize_raw_evidence_metadata(
      None,
      request_config=request_config,
      backend_enabled=bool(cfg.get("RAW_EVIDENCE_ENABLED")),
    )
  if not cfg.get("RAW_EVIDENCE_ENABLED"):
    return sanitize_raw_evidence_metadata(
      {
        "requested": True,
        "backend_enabled": False,
        "status": RAW_EVIDENCE_STATUS_DISABLED_BY_POLICY,
        "available": False,
        "error_class": RAW_EVIDENCE_ERROR_DISABLED,
      },
      request_config=request_config,
      backend_enabled=False,
    )
  existing_metadata = _restricted_metadata_repo(owner).get_model_test_raw_evidence(job_id)
  existing_safe_metadata = sanitize_raw_evidence_metadata(
    existing_metadata,
    request_config=request_config,
    backend_enabled=True,
  )
  if existing_safe_metadata.get("available"):
    return existing_safe_metadata
  if not isinstance(raw_evidence_payload, dict) or not raw_evidence_payload.get("cases"):
    return _storage_failure_metadata(
      job_config,
      cfg,
      error_class=RAW_EVIDENCE_ERROR_CAPTURE_UNAVAILABLE,
    )

  created_at = _now(owner)
  artifact_payload = {
    "kind": RAW_MODEL_TEST_EVIDENCE_KIND,
    "schema_version": RAW_MODEL_TEST_EVIDENCE_SCHEMA,
    "job_id": job_id,
    "created_at": created_at,
    "created_at_iso": _iso_timestamp(created_at),
    "retention_until": _retention_until(owner, cfg),
    "evaluator_raw_included": False,
    "cases": list(raw_evidence_payload.get("cases") or []),
  }
  payload_hash = _sha256_json(artifact_payload)

  try:
    secret_store = R1fsSecretStore(owner)
    secret_key, key_metadata = secret_store.resolve_secret_store_key()
    if not secret_key:
      return _storage_failure_metadata(job_config, cfg)
    artifact_cid = _artifact_repo(owner).put_json(
      artifact_payload,
      show_logs=False,
      secret=secret_key,
    )
    if not artifact_cid:
      return _storage_failure_metadata(job_config, cfg)

    backend_metadata = {
      "job_id": job_id,
      "requested": True,
      "backend_enabled": True,
      "status": RAW_EVIDENCE_STATUS_AVAILABLE,
      "available": True,
      "artifact_cid": artifact_cid,
      "artifact_kind": RAW_MODEL_TEST_EVIDENCE_KIND,
      "schema_version": RAW_MODEL_TEST_EVIDENCE_SCHEMA,
      "created_at": created_at,
      "retention_until": artifact_payload["retention_until"],
      "hashes": [payload_hash],
      "storage_mode": "encrypted_r1fs_json_v1",
      "key_id": (key_metadata or {}).get("key_id", ""),
      "key_version": (key_metadata or {}).get("key_version", ""),
      "key_source": (key_metadata or {}).get("key_source", ""),
      "unsafe_key_fallback": bool((key_metadata or {}).get("unsafe_fallback", False)),
    }
    _restricted_metadata_repo(owner).put_model_test_raw_evidence(job_id, backend_metadata)
    return sanitize_raw_evidence_metadata(
      backend_metadata,
      request_config=request_config,
      backend_enabled=True,
    )
  except Exception as exc:
    printer = getattr(owner, "P", None)
    if callable(printer):
      printer(f"Failed to store restricted raw model-test evidence for {job_id}: {exc}", color='r')
    return _storage_failure_metadata(job_config, cfg)


def get_raw_evidence_artifact(owner, job_id):
  """Return restricted raw evidence by job id using backend-only metadata."""
  repo = _restricted_metadata_repo(owner)
  metadata = repo.get_model_test_raw_evidence(job_id)
  if not isinstance(metadata, dict):
    return {
      "job_id": job_id,
      "error": "raw_evidence_unavailable",
      "model_test_raw_evidence": sanitize_raw_evidence_metadata(
        {"requested": True, "backend_enabled": True, "status": RAW_EVIDENCE_STATUS_CAPTURE_FAILED, "available": False,
         "error_class": RAW_EVIDENCE_ERROR_CAPTURE_UNAVAILABLE},
        backend_enabled=True,
      ),
    }

  safe_metadata = sanitize_raw_evidence_metadata(metadata, backend_enabled=True)
  if not safe_metadata.get("available"):
    return {
      "job_id": job_id,
      "error": "raw_evidence_unavailable",
      "model_test_raw_evidence": safe_metadata,
    }

  artifact_cid = metadata.get("artifact_cid")
  try:
    secret_key, _key_metadata = R1fsSecretStore(owner).resolve_secret_store_key()
    payload = _artifact_repo(owner).get_json(artifact_cid, secret=secret_key)
  except Exception as exc:
    printer = getattr(owner, "P", None)
    if callable(printer):
      printer(f"Failed to read restricted raw model-test evidence for {job_id}: {exc}", color='r')
    return {
      "job_id": job_id,
      "error": "raw_evidence_read_failed",
      "model_test_raw_evidence": {
        **safe_metadata,
        "status": RAW_EVIDENCE_STATUS_CAPTURE_FAILED,
        "available": False,
        "error_class": RAW_EVIDENCE_ERROR_STORAGE_UNAVAILABLE,
      },
    }

  if not is_restricted_raw_evidence_artifact(payload) or payload.get("job_id") != job_id:
    return {
      "job_id": job_id,
      "error": "raw_evidence_invalid",
      "model_test_raw_evidence": {
        **safe_metadata,
        "status": RAW_EVIDENCE_STATUS_CAPTURE_FAILED,
        "available": False,
        "error_class": RAW_EVIDENCE_ERROR_STORAGE_UNAVAILABLE,
      },
    }

  return {
    "job_id": job_id,
    "model_test_raw_evidence": safe_metadata,
    "payload": payload,
  }
