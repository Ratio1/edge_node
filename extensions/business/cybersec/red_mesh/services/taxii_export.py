from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

import requests

from ..repositories import ArtifactRepository, JobStateRepository
from ..tenancy.administration import AdministrationDenied
from ..tenancy.job_artifacts import checked_job_snapshot, validate_snapshot_mode
from ..tenancy.ports import TenantStoreError
from .auth import AuthError, build_auth_provider, credentials_missing
from .config import get_taxii_export_config
from ..tenancy.effects import EffectState
from .event_hooks import emit_export_status_event
from .integration_status import record_integration_status
from .scan_guards import reject_model_test_for_scan_operation
from .stix_export import build_stix_bundle


_UNSET = object()


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


def _prepare_taxii_export(owner, job_id, pass_nr=None, *, checked_job=_UNSET):
  cfg = get_taxii_export_config(owner)
  config_error = _config_error(cfg)
  if config_error == "disabled":
    return None, None, {"status": "disabled", "error": "TAXII export is disabled", "job_id": job_id}
  if config_error:
    # Operator visibility when reached through _effect_operation. publish_to_taxii still calls this
    # with no requester until B2, so do not read this as universally post-admission.
    record_integration_status(owner, "taxii", outcome="failure", error_class=config_error)
    return None, None, {"status": "not_configured", "error": config_error, "job_id": job_id}

  # Checked snapshot replaces the unscoped global lookup (RM-026 I1b).
  job_specs = owner._get_job_from_cstore(job_id) if checked_job is _UNSET else checked_job
  if not isinstance(job_specs, dict):
    record_integration_status(owner, "taxii", outcome="failure", error_class="job_not_found")
    return None, None, {"status": "error", "error": "job_not_found", "job_id": job_id}
  unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "taxii_export")
  if unsupported:
    return None, None, unsupported

  # Never forward this module's own _UNSET: stix_export compares against its own sentinel object,
  # so a foreign sentinel would be mistaken for a job record.
  result = (build_stix_bundle(owner, job_id, pass_nr=pass_nr) if checked_job is _UNSET
            else build_stix_bundle(owner, job_id, pass_nr=pass_nr, checked_job=checked_job))
  if result.get("status") != "ok":
    error = result.get("error") or "stix_build_failed"
    record_integration_status(owner, "taxii", outcome="failure", error_class=error)
    return None, None, result

  return cfg, job_specs, result


def dry_run_taxii_export(owner, job_id, pass_nr=None, *, checked_job=_UNSET, ledger=None):
  """Build and persist a TAXII-ready STIX bundle without publishing it."""
  cfg, job_specs, result = _prepare_taxii_export(owner, job_id, pass_nr=pass_nr,
                                                 checked_job=checked_job)
  if result.get("status") != "ok":
    return result

  if ledger is not None:
    ledger.checkpoint()
  artifact_cid = _persist_bundle(owner, result["bundle"])
  if ledger is not None and artifact_cid:
    ledger.record(EffectState.PERSISTED)
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
  if ledger is not None:
    # The job document is about to be mutated whether or not the bundle persisted, so
    # revalidate here and record it: a later fault must not report "nothing happened".
    ledger.checkpoint()
    ledger.record(EffectState.PERSISTED)
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


def publish_to_taxii(owner, job_id, pass_nr=None, *, checked_job=_UNSET, ledger=None):
  """Manually publish a redacted STIX bundle to the configured TAXII 2.1 collection."""
  cfg, job_specs, result = _prepare_taxii_export(owner, job_id, pass_nr=pass_nr,
                                                 checked_job=checked_job)
  if result.get("status") != "ok":
    return result

  if ledger is not None:
    ledger.checkpoint()
  artifact_cid = _persist_bundle(owner, result["bundle"])
  if ledger is not None and artifact_cid:
    ledger.record(EffectState.PERSISTED)
  if not artifact_cid:
    record_integration_status(owner, "taxii", outcome="failure", error_class="artifact_write_failed")
    return {"status": "error", "error": "artifact_write_failed", "job_id": job_id}

  if ledger is not None:
    # Last revalidation before data leaves the deployment.
    ledger.checkpoint()
  try:
    auth_headers = build_auth_provider(cfg).headers()
  except AuthError as exc:
    record_integration_status(owner, "taxii", outcome="failure", error_class="invalid_auth_config", artifact_cid=artifact_cid)
    return {"status": "error", "error": "invalid_auth_config", "detail": str(exc), "job_id": job_id, "artifact_cid": artifact_cid}

  headers = {
    "Accept": TAXII_MEDIA_TYPE,
    "Content-Type": TAXII_MEDIA_TYPE,
    **auth_headers,
  }
  bundle_objects = (result.get("bundle") or {}).get("objects") or []
  envelope = {"objects": bundle_objects}
  try:
    response = requests.post(
      _objects_url(cfg["SERVER_URL"], cfg["COLLECTION_ID"]),
      headers=headers,
      data=json.dumps(envelope, sort_keys=True),
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
  if ledger is not None:
    # 200/201/202 all mean the objects left the node. 202 is pending acceptance, not a failure to
    # deliver, so it counts: a retry would duplicate them either way.
    ledger.record(EffectState.DELIVERED)
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


def get_taxii_export_status(owner, job_id, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  checked = checked_job is not _UNSET
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked)
  job_specs = (checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
               if checked else owner._get_job_from_cstore(job_id))
  if not isinstance(job_specs, dict):
    return {"job_id": job_id, "found": False, "exported": False}
  unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "taxii_export_status")
  if unsupported:
    if checked:
      raise AdministrationDenied(400, "unsupported_job_type")
    return {**unsupported, "found": True, "exported": False}
  export_meta = job_specs.get("taxii_export")
  if checked and export_meta is not None:
    if (not isinstance(export_meta, dict)
        or "job_id" in export_meta and export_meta["job_id"] != job_id
        or any(field in export_meta for field in ("success", "error", "status_code", "result",
               "detail", "exception_metadata", "execution_binding", "found", "exported"))):
      raise TenantStoreError("Export status is unavailable")
  if not isinstance(export_meta, dict) or not export_meta:
    return {"job_id": job_id, "found": True, "exported": False}
  return {
    "job_id": job_id,
    "found": True,
    "exported": export_meta.get("status") == "published",
    **export_meta,
  }
