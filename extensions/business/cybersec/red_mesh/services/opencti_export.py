from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

from ..repositories import ArtifactRepository, JobStateRepository
from .auth import AuthError, build_auth_provider
from .config import get_opencti_export_config
from .event_hooks import emit_export_status_event
from .integration_status import record_integration_status
from .stix_export import build_stix_bundle


OPENCTI_EXPORT_SCHEMA_VERSION = "1.0.0"
OPENCTI_IMPORT_MUTATION = """
mutation RedMeshOpenCtiImport($file: Upload!) {
  uploadImport(file: $file) {
    id
    name
    uploadStatus
  }
}
"""


def _utc_timestamp():
  return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _artifact_repo(owner):
  getter = getattr(type(owner), "_get_artifact_repository", None)
  if callable(getter):
    return getter(owner)
  return ArtifactRepository(owner)


def _job_repo(owner):
  getter = getattr(type(owner), "_get_job_state_repository", None)
  if callable(getter):
    return getter(owner)
  return JobStateRepository(owner)


def _write_job_record(owner, job_id, job_specs, context):
  writer = getattr(type(owner), "_write_job_record", None)
  if callable(writer):
    return writer(owner, job_id, job_specs, context=context)
  return _job_repo(owner).put_job(job_id, job_specs)


def _redacted_host(url):
  try:
    return urlsplit(str(url or "")).hostname or ""
  except ValueError:
    return ""


def _graphql_url(base_url):
  raw = str(base_url or "").strip().rstrip("/")
  if raw.endswith("/graphql"):
    return raw
  return f"{raw}/graphql"


def _token(cfg):
  return str(os.environ.get(cfg["TOKEN_ENV"]) or "").strip()


def _config_error(cfg):
  if not cfg["ENABLED"]:
    return "disabled"
  if not cfg["URL"]:
    return "missing_url"
  # OpenCTI only supports AUTH_MODE=static (UUID API tokens). An empty env
  # value is a misconfig — surface it before bothering to build a bundle.
  if not _token(cfg):
    return "missing_token"
  return None


def _persist_bundle(owner, bundle):
  return _artifact_repo(owner).put_json(bundle, show_logs=False)


def _bundle_summary(result, artifact_cid=None):
  return {
    "bundle_id": result.get("bundle_id"),
    "artifact_cid": artifact_cid,
    "pass_nr": result.get("pass_nr"),
    "object_count": result.get("object_count"),
    "finding_count": result.get("finding_count"),
    "observed_data_count": result.get("observed_data_count"),
  }


def _prepare_opencti_export(owner, job_id, pass_nr=None):
  cfg = get_opencti_export_config(owner)
  config_error = _config_error(cfg)
  if config_error == "disabled":
    return None, None, {"status": "disabled", "error": "OpenCTI export is disabled", "job_id": job_id}
  if config_error:
    record_integration_status(owner, "opencti", outcome="failure", error_class=config_error)
    return None, None, {"status": "not_configured", "error": config_error, "job_id": job_id}

  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    record_integration_status(owner, "opencti", outcome="failure", error_class="job_not_found")
    return None, None, {"status": "error", "error": "job_not_found", "job_id": job_id}

  result = build_stix_bundle(owner, job_id, pass_nr=pass_nr)
  if result.get("status") != "ok":
    error = result.get("error") or "stix_build_failed"
    record_integration_status(owner, "opencti", outcome="failure", error_class=error)
    return None, None, result

  return cfg, job_specs, result


def dry_run_opencti_export(owner, job_id, pass_nr=None):
  cfg, job_specs, result = _prepare_opencti_export(owner, job_id, pass_nr=pass_nr)
  if result.get("status") != "ok":
    return result

  artifact_cid = _persist_bundle(owner, result["bundle"])
  summary = {
    "schema_version": OPENCTI_EXPORT_SCHEMA_VERSION,
    "status": "dry_run",
    "dry_run": True,
    "job_id": job_id,
    "generated_at": _utc_timestamp(),
    "destination_label": "opencti",
    "redacted_host": _redacted_host(cfg["URL"]),
    **_bundle_summary(result, artifact_cid=artifact_cid),
  }
  job_specs["opencti_export"] = summary
  _write_job_record(owner, job_id, job_specs, context="opencti_dry_run")
  record_integration_status(
    owner,
    "opencti",
    outcome="success",
    event_id=result["bundle_id"],
    artifact_cid=artifact_cid,
    dry_run=True,
  )
  return {**summary, "status": "ok", "dry_run": True, "job_id": job_id}


def push_to_opencti(owner, job_id, pass_nr=None):
  cfg, job_specs, result = _prepare_opencti_export(owner, job_id, pass_nr=pass_nr)
  if result.get("status") != "ok":
    return result
  if cfg["PUSH_MODE"] == "dry_run":
    return dry_run_opencti_export(owner, job_id, pass_nr=pass_nr)

  artifact_cid = _persist_bundle(owner, result["bundle"])
  if not artifact_cid:
    record_integration_status(owner, "opencti", outcome="failure", error_class="artifact_write_failed")
    return {"status": "error", "error": "artifact_write_failed", "job_id": job_id}

  bundle_json = json.dumps(result["bundle"], sort_keys=True)
  operations = {
    "query": OPENCTI_IMPORT_MUTATION,
    "variables": {"file": None},
  }
  files = {
    "0": (
      f"redmesh-stix-{job_id}.json",
      bundle_json.encode("utf-8"),
      "application/json",
    ),
  }
  data = {
    "operations": json.dumps(operations),
    "map": json.dumps({"0": ["variables.file"]}),
  }
  try:
    headers = build_auth_provider(cfg).headers()
  except AuthError as exc:
    record_integration_status(owner, "opencti", outcome="failure", error_class="invalid_auth_config")
    return {"status": "error", "error": "invalid_auth_config", "detail": str(exc), "job_id": job_id}

  try:
    response = requests.post(
      _graphql_url(cfg["URL"]),
      headers=headers,
      data=data,
      files=files,
      timeout=30,
    )
  except requests.exceptions.Timeout:
    record_integration_status(owner, "opencti", outcome="failure", error_class="timeout")
    return {"status": "error", "error": "timeout", "job_id": job_id, "retryable": True}
  except requests.exceptions.RequestException as exc:
    record_integration_status(owner, "opencti", outcome="failure", error_class=type(exc).__name__)
    return {"status": "error", "error": type(exc).__name__, "job_id": job_id, "retryable": True}

  if response.status_code >= 400:
    error_class = f"http_{response.status_code}"
    record_integration_status(owner, "opencti", outcome="failure", error_class=error_class, artifact_cid=artifact_cid)
    return {
      "status": "error",
      "error": error_class,
      "job_id": job_id,
      "retryable": response.status_code >= 500,
      "artifact_cid": artifact_cid,
    }

  try:
    payload = response.json()
  except ValueError:
    payload = {}
  errors = payload.get("errors") if isinstance(payload, dict) else None
  if errors:
    record_integration_status(owner, "opencti", outcome="failure", error_class="graphql_error", artifact_cid=artifact_cid)
    return {
      "status": "error",
      "error": "graphql_error",
      "job_id": job_id,
      "artifact_cid": artifact_cid,
      "retryable": False,
    }

  upload = ((payload.get("data") or {}).get("uploadImport") or {}) if isinstance(payload, dict) else {}
  opencti_file_id = upload.get("id")
  upload_status = upload.get("uploadStatus")
  pushed_at = _utc_timestamp()
  export_meta = {
    "schema_version": OPENCTI_EXPORT_SCHEMA_VERSION,
    "status": "pushed",
    "dry_run": False,
    "job_id": job_id,
    "pushed_at": pushed_at,
    "destination_label": "opencti",
    "redacted_host": _redacted_host(cfg["URL"]),
    "opencti_file_id": opencti_file_id,
    "upload_status": upload_status,
    **_bundle_summary(result, artifact_cid=artifact_cid),
  }
  job_specs["opencti_export"] = export_meta
  emit_export_status_event(
    owner,
    job_specs,
    adapter_type="opencti",
    status="completed",
    pass_nr=result.get("pass_nr"),
    destination_label="opencti",
    artifact_refs={
      "opencti_file_id": opencti_file_id,
      "stix_bundle_id": result.get("bundle_id"),
      "stix_bundle_cid": artifact_cid,
    },
  )
  _write_job_record(owner, job_id, job_specs, context="opencti_export")
  record_integration_status(
    owner,
    "opencti",
    outcome="success",
    event_id=opencti_file_id or result["bundle_id"],
    artifact_cid=artifact_cid,
  )
  return {
    "status": "ok",
    "job_id": job_id,
    "opencti_file_id": opencti_file_id,
    "upload_status": upload_status,
    "pushed_at": pushed_at,
    "redacted_host": _redacted_host(cfg["URL"]),
    **_bundle_summary(result, artifact_cid=artifact_cid),
  }


def get_opencti_export_status(owner, job_id):
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return {"job_id": job_id, "found": False, "exported": False}
  export_meta = job_specs.get("opencti_export")
  if not isinstance(export_meta, dict) or not export_meta:
    return {"job_id": job_id, "found": True, "exported": False}
  return {
    "job_id": job_id,
    "found": True,
    "exported": export_meta.get("status") == "pushed",
    **export_meta,
  }
