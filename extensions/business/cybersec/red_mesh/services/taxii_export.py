from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import requests

from ..repositories import ArtifactRepository, JobStateRepository
from .auth import AuthError, build_auth_provider, credentials_missing
from .config import get_taxii_export_config
from .event_hooks import emit_export_status_event
from .integration_status import record_integration_status
from .stix_export import build_stix_bundle


TAXII_EXPORT_SCHEMA_VERSION = "1.0.0"
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"


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


def _token(cfg):
  return str(os.environ.get(cfg["TOKEN_ENV"]) or "").strip()


def _objects_url(server_url, collection_id):
  base = str(server_url or "").strip().rstrip("/")
  if not base:
    return ""
  path = urlsplit(base).path.rstrip("/")
  if path.endswith("/objects"):
    return f"{base}/"
  if "/collections/" in path:
    return f"{base}/objects/"
  collection = quote(str(collection_id or "").strip(), safe="")
  return f"{base}/collections/{collection}/objects/"


def _config_error(cfg):
  if not cfg["ENABLED"]:
    return "disabled"
  if cfg["MODE"] != "publish_manual":
    return "unsupported_mode"
  if not cfg["SERVER_URL"]:
    return "missing_server_url"
  if not cfg["COLLECTION_ID"]:
    return "missing_collection_id"
  credentials_error = credentials_missing(cfg)
  if credentials_error:
    return credentials_error
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


def _prepare_taxii_export(owner, job_id, pass_nr=None):
  cfg = get_taxii_export_config(owner)
  config_error = _config_error(cfg)
  if config_error == "disabled":
    return None, None, {"status": "disabled", "error": "TAXII export is disabled", "job_id": job_id}
  if config_error:
    record_integration_status(owner, "taxii", outcome="failure", error_class=config_error)
    return None, None, {"status": "not_configured", "error": config_error, "job_id": job_id}

  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    record_integration_status(owner, "taxii", outcome="failure", error_class="job_not_found")
    return None, None, {"status": "error", "error": "job_not_found", "job_id": job_id}

  result = build_stix_bundle(owner, job_id, pass_nr=pass_nr)
  if result.get("status") != "ok":
    error = result.get("error") or "stix_build_failed"
    record_integration_status(owner, "taxii", outcome="failure", error_class=error)
    return None, None, result

  return cfg, job_specs, result


def dry_run_taxii_export(owner, job_id, pass_nr=None):
  """Build and persist a TAXII-ready STIX bundle without publishing it."""
  cfg, job_specs, result = _prepare_taxii_export(owner, job_id, pass_nr=pass_nr)
  if result.get("status") != "ok":
    return result

  artifact_cid = _persist_bundle(owner, result["bundle"])
  summary = {
    "schema_version": TAXII_EXPORT_SCHEMA_VERSION,
    "status": "dry_run",
    "dry_run": True,
    "job_id": job_id,
    "generated_at": _utc_timestamp(),
    "destination_label": "taxii-2.1",
    "redacted_host": _redacted_host(cfg["SERVER_URL"]),
    "collection_id": cfg["COLLECTION_ID"],
    **_bundle_summary(result, artifact_cid=artifact_cid),
  }
  job_specs["taxii_export"] = summary
  _write_job_record(owner, job_id, job_specs, context="taxii_dry_run")
  record_integration_status(
    owner,
    "taxii",
    outcome="success",
    event_id=result["bundle_id"],
    artifact_cid=artifact_cid,
    dry_run=True,
  )
  return {**summary, "status": "ok", "dry_run": True, "job_id": job_id}


def publish_to_taxii(owner, job_id, pass_nr=None):
  """Manually publish a redacted STIX bundle to the configured TAXII 2.1 collection."""
  cfg, job_specs, result = _prepare_taxii_export(owner, job_id, pass_nr=pass_nr)
  if result.get("status") != "ok":
    return result

  artifact_cid = _persist_bundle(owner, result["bundle"])
  if not artifact_cid:
    record_integration_status(owner, "taxii", outcome="failure", error_class="artifact_write_failed")
    return {"status": "error", "error": "artifact_write_failed", "job_id": job_id}

  try:
    auth_headers = build_auth_provider(cfg).headers()
  except AuthError as exc:
    record_integration_status(owner, "taxii", outcome="failure", error_class="invalid_auth_config", artifact_cid=artifact_cid)
    return {"status": "error", "error": "invalid_auth_config", "detail": str(exc), "job_id": job_id, "artifact_cid": artifact_cid}

  headers = {
    "Accept": TAXII_MEDIA_TYPE,
    "Content-Type": STIX_MEDIA_TYPE,
    **auth_headers,
  }
  try:
    response = requests.post(
      _objects_url(cfg["SERVER_URL"], cfg["COLLECTION_ID"]),
      headers=headers,
      data=json.dumps(result["bundle"], sort_keys=True),
      timeout=cfg["TIMEOUT_SECONDS"],
    )
  except requests.exceptions.Timeout:
    record_integration_status(owner, "taxii", outcome="failure", error_class="timeout", artifact_cid=artifact_cid)
    return {"status": "error", "error": "timeout", "job_id": job_id, "retryable": True, "artifact_cid": artifact_cid}
  except requests.exceptions.RequestException as exc:
    error_class = type(exc).__name__
    record_integration_status(owner, "taxii", outcome="failure", error_class=error_class, artifact_cid=artifact_cid)
    return {"status": "error", "error": error_class, "job_id": job_id, "retryable": True, "artifact_cid": artifact_cid}

  if response.status_code not in {200, 201, 202}:
    error_class = f"http_{response.status_code}"
    record_integration_status(owner, "taxii", outcome="failure", error_class=error_class, artifact_cid=artifact_cid)
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
  status_id = payload.get("id") if isinstance(payload, dict) else None
  published_at = _utc_timestamp()
  export_meta = {
    "schema_version": TAXII_EXPORT_SCHEMA_VERSION,
    "status": "published",
    "dry_run": False,
    "job_id": job_id,
    "published_at": published_at,
    "destination_label": "taxii-2.1",
    "redacted_host": _redacted_host(cfg["SERVER_URL"]),
    "collection_id": cfg["COLLECTION_ID"],
    "taxii_status_id": status_id,
    "taxii_status": payload.get("status") if isinstance(payload, dict) else None,
    "success_count": payload.get("success_count") if isinstance(payload, dict) else None,
    "failure_count": payload.get("failure_count") if isinstance(payload, dict) else None,
    "pending_count": payload.get("pending_count") if isinstance(payload, dict) else None,
    **_bundle_summary(result, artifact_cid=artifact_cid),
  }
  job_specs["taxii_export"] = export_meta
  emit_export_status_event(
    owner,
    job_specs,
    adapter_type="taxii",
    status="completed",
    pass_nr=result.get("pass_nr"),
    destination_label="taxii-2.1",
    artifact_refs={
      "taxii_status_id": status_id,
      "stix_bundle_id": result.get("bundle_id"),
      "stix_bundle_cid": artifact_cid,
    },
  )
  _write_job_record(owner, job_id, job_specs, context="taxii_publish")
  record_integration_status(
    owner,
    "taxii",
    outcome="success",
    event_id=status_id or result["bundle_id"],
    artifact_cid=artifact_cid,
  )
  return {
    "status": "ok",
    "job_id": job_id,
    "taxii_status_id": status_id,
    "taxii_status": export_meta["taxii_status"],
    "published_at": published_at,
    "redacted_host": _redacted_host(cfg["SERVER_URL"]),
    "collection_id": cfg["COLLECTION_ID"],
    "success_count": export_meta["success_count"],
    "failure_count": export_meta["failure_count"],
    "pending_count": export_meta["pending_count"],
    **_bundle_summary(result, artifact_cid=artifact_cid),
  }


def probe_taxii(owner):
  """Read-only connectivity probe for the TAXII Test button.

  GETs the configured SERVER_URL (the api root) with the integration's
  auth header + the required TAXII Accept header. Doesn't publish or
  read any objects; just validates reachability + auth + that the api
  root exists.
  """
  cfg = get_taxii_export_config(owner)
  config_error = _config_error(cfg)
  if config_error == "disabled":
    return {"status": "disabled", "integration_id": "taxii", "error": "disabled"}
  if config_error:
    record_integration_status(owner, "taxii", outcome="failure", error_class=config_error)
    return {"status": "not_configured", "integration_id": "taxii", "error": config_error}

  try:
    auth_headers = build_auth_provider(cfg).headers()
  except AuthError as exc:
    record_integration_status(owner, "taxii", outcome="failure", error_class="invalid_auth_config")
    return {
      "status": "error",
      "integration_id": "taxii",
      "error": "invalid_auth_config",
      "detail": str(exc),
    }

  headers = {
    "Accept": TAXII_MEDIA_TYPE,
    "User-Agent": "RedMesh/1.0",
    **auth_headers,
  }

  # medallion responds 308 -> http:// (scheme-downgrade) when the api root
  # is requested without a trailing slash; requests then drops the
  # Authorization header on the cross-scheme redirect and we get a spurious
  # 401. Always probe the slash-terminated URL.
  probe_url = cfg["SERVER_URL"]
  if not probe_url.endswith("/"):
    probe_url = probe_url + "/"

  try:
    response = requests.get(probe_url, headers=headers, timeout=10)
  except requests.exceptions.Timeout:
    record_integration_status(owner, "taxii", outcome="failure", error_class="timeout")
    return {"status": "error", "integration_id": "taxii", "error": "timeout"}
  except requests.exceptions.RequestException as exc:
    error_class = type(exc).__name__
    record_integration_status(owner, "taxii", outcome="failure", error_class=error_class)
    return {"status": "error", "integration_id": "taxii", "error": error_class}

  if response.status_code >= 400:
    error_class = f"http_{response.status_code}"
    record_integration_status(owner, "taxii", outcome="failure", error_class=error_class)
    return {"status": "error", "integration_id": "taxii", "error": error_class}

  try:
    payload = response.json()
  except ValueError:
    payload = {}
  api_root_title = payload.get("title") if isinstance(payload, dict) else None
  api_root_versions = payload.get("versions") if isinstance(payload, dict) else None

  record_integration_status(
    owner,
    "taxii",
    outcome="success",
    event_id=cfg.get("COLLECTION_ID") or None,
    dry_run=True,
  )
  return {
    "status": "ok",
    "dry_run": True,
    "integration_id": "taxii",
    "api_root_title": api_root_title,
    "api_root_versions": api_root_versions,
    "collection_id": cfg["COLLECTION_ID"],
  }


def get_taxii_export_status(owner, job_id):
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return {"job_id": job_id, "found": False, "exported": False}
  export_meta = job_specs.get("taxii_export")
  if not isinstance(export_meta, dict) or not export_meta:
    return {"job_id": job_id, "found": True, "exported": False}
  return {
    "job_id": job_id,
    "found": True,
    "exported": export_meta.get("status") == "published",
    **export_meta,
  }
