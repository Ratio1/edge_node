from __future__ import annotations

import os
from datetime import datetime, timezone

from .config import get_event_export_config, get_suricata_correlation_config, get_wazuh_export_config
from .event_builder import (
  build_assessment_window,
  build_attestation_event,
  build_export_status_event,
  build_finding_event,
  build_lifecycle_event,
)
from .integration_status import record_integration_status
from .log_export import deliver_redmesh_event


SOC_EVENT_STATUS_SCHEMA_VERSION = "1.0.0"
SOC_EVENT_HISTORY_LIMIT = 20


def _utc_timestamp():
  return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _tenant_id(owner):
  return str(getattr(owner, "cfg_instance_id", "") or "")


def _environment(owner):
  return str(getattr(owner, "cfg_ee_node_network", "") or "")


def _job_specs_for_event(owner, job_specs):
  specs = dict(job_specs or {})
  config = {}
  getter = getattr(owner, "_get_job_config", None)
  if callable(getter):
    try:
      config = getter(job_specs, resolve_secrets=False) or {}
    except Exception:
      config = {}
  if not isinstance(config, dict):
    config = {}
  if not specs.get("authorized"):
    specs["authorized"] = bool(config.get("authorized", False))
  if not specs.get("authorization_id"):
    specs["authorization_id"] = config.get("scope_id") or config.get("authorization_id")
  if not specs.get("authorization_ref"):
    typed_auth = config.get("authorization") if isinstance(config.get("authorization"), dict) else {}
    specs["authorization_ref"] = (
      config.get("authorization_ref")
      or typed_auth.get("document_cid")
    )
  return specs


def _event_export_secret(owner):
  cfg = get_event_export_config(owner)
  if not cfg["ENABLED"]:
    return "redmesh-event-export-disabled", None
  secret = os.environ.get(cfg["HMAC_SECRET_ENV"])
  if secret:
    return secret, None
  return "redmesh-event-redaction-fallback", None


def _automatic_export_enabled(owner):
  event_cfg = get_event_export_config(owner)
  wazuh_cfg = get_wazuh_export_config(owner)
  if not event_cfg["ENABLED"]:
    return False, "event_export_disabled"
  if not wazuh_cfg["ENABLED"]:
    return False, "wazuh_disabled"
  return True, None


def _safe_timeline(owner, job_specs, event_type, label, meta):
  emit = getattr(owner, "_emit_timeline_event", None)
  if not callable(emit) or not isinstance(job_specs, dict):
    return
  try:
    emit(job_specs, event_type, label, actor_type="system", meta=meta)
  except Exception:
    return


def _record_job_soc_status(owner, job_specs, event, result):
  if not isinstance(job_specs, dict) or not isinstance(event, dict) or not isinstance(result, dict):
    return

  status = dict(job_specs.get("soc_event_status") or {})
  status["schema_version"] = SOC_EVENT_STATUS_SCHEMA_VERSION
  status["last_updated_at"] = _utc_timestamp()
  status["last_adapter"] = result.get("integration_id") or "wazuh"
  status["last_status"] = result.get("status")
  status["last_event_id"] = event.get("event_id")
  status["last_event_type"] = event.get("event_type")
  status["last_error_class"] = result.get("error")
  if result.get("artifact_cid"):
    status["last_artifact_cid"] = result.get("artifact_cid")
  if result.get("status") == "sent":
    status["last_success_at"] = status["last_updated_at"]
  elif result.get("status") in {"error", "disabled"}:
    status["last_failure_at"] = status["last_updated_at"]

  event_type = str(event.get("event_type") or "")
  if event_type == "redmesh.job.started":
    status["assessment_notice_status"] = result.get("status")
  if event_type.startswith("redmesh.export."):
    status["last_siem_export_status"] = result.get("status")
    status["last_siem_export_event_id"] = event.get("event_id")
  if event_type.startswith("redmesh.attestation."):
    status["last_attestation_event_status"] = result.get("status")
    status["last_attestation_event_id"] = event.get("event_id")

  history = list(status.get("history") or [])
  history.append({
    "at": status["last_updated_at"],
    "adapter": status["last_adapter"],
    "status": status["last_status"],
    "event_id": event.get("event_id"),
    "event_type": event.get("event_type"),
    "error_class": result.get("error"),
    "artifact_cid": result.get("artifact_cid"),
  })
  status["history"] = history[-SOC_EVENT_HISTORY_LIMIT:]
  job_specs["soc_event_status"] = status

  _safe_timeline(
    owner,
    job_specs,
    "soc_event_export",
    f"SOC event {result.get('status') or 'updated'}",
    meta={
      "adapter": status["last_adapter"],
      "status": status["last_status"],
      "event_id": event.get("event_id"),
      "event_type": event.get("event_type"),
      "error_class": result.get("error"),
      "artifact_cid": result.get("artifact_cid"),
    },
  )


def _skip_result(reason):
  return {"status": "skipped", "integration_id": "wazuh", "error": reason}


def _assessment_window(
  owner,
  job_specs,
  hmac_secret,
  *,
  pass_nr=None,
  started_at=None,
  expected_end_at=None,
  actual_end_at=None,
  expected_egress_ips=None,
  report_refs=None,
):
  cfg = get_suricata_correlation_config(owner)
  return build_assessment_window(
    job_specs,
    hmac_secret=hmac_secret,
    pass_nr=pass_nr,
    started_at=started_at,
    expected_end_at=expected_end_at,
    actual_end_at=actual_end_at,
    expected_egress_ips=expected_egress_ips,
    report_refs=report_refs,
    grace_seconds=cfg["MATCH_WINDOW_SECONDS"],
    clock_skew_seconds=cfg["CLOCK_SKEW_SECONDS"],
  )


def emit_redmesh_event(owner, job_specs, event):
  """Best-effort automatic SOC event delivery. Never raises into scan paths."""
  enabled, reason = _automatic_export_enabled(owner)
  if not enabled:
    result = _skip_result(reason)
    _record_job_soc_status(owner, job_specs, event, result)
    return result

  try:
    result = deliver_redmesh_event(owner, event, integration_id="wazuh")
  except Exception as exc:
    result = {
      "status": "error",
      "integration_id": "wazuh",
      "event_id": (event or {}).get("event_id"),
      "error": type(exc).__name__,
    }
    record_integration_status(
      owner,
      "wazuh",
      outcome="failure",
      event_id=result.get("event_id"),
      error_class=result["error"],
    )

  _record_job_soc_status(owner, job_specs, event, result)
  return result


def emit_lifecycle_event(
  owner,
  job_specs,
  *,
  event_type,
  event_action,
  event_outcome="success",
  pass_nr=None,
  started_at=None,
  expected_end_at=None,
  actual_end_at=None,
  expected_egress_ips=None,
  report_refs=None,
):
  secret, error = _event_export_secret(owner)
  if error:
    record_integration_status(owner, "wazuh", outcome="failure", error_class=error)
    return _skip_result(error)
  if actual_end_at is None and event_type in {"redmesh.job.pass_completed", "redmesh.job.stopped"}:
    time_fn = getattr(owner, "time", None)
    if callable(time_fn):
      candidate = time_fn()
      if isinstance(candidate, (int, float, str)):
        actual_end_at = candidate
  event_specs = _job_specs_for_event(owner, job_specs)
  window = _assessment_window(
    owner,
    event_specs,
    secret,
    pass_nr=pass_nr,
    started_at=started_at,
    expected_end_at=expected_end_at,
    actual_end_at=actual_end_at,
    expected_egress_ips=expected_egress_ips,
    report_refs=report_refs,
  )
  event = build_lifecycle_event(
    event_specs,
    event_type=event_type,
    event_action=event_action,
    event_outcome=event_outcome,
    hmac_secret=secret,
    tenant_id=_tenant_id(owner),
    environment=_environment(owner),
    pass_nr=pass_nr,
    assessment_window=window,
    artifact_refs=report_refs,
  )
  return emit_redmesh_event(owner, job_specs, event)


def emit_finding_event(owner, job_specs, *, finding, event_action="created", pass_nr=None):
  secret, error = _event_export_secret(owner)
  if error:
    record_integration_status(owner, "wazuh", outcome="failure", error_class=error)
    return _skip_result(error)
  event = build_finding_event(
    job_specs,
    finding=finding,
    event_action=event_action,
    hmac_secret=secret,
    tenant_id=_tenant_id(owner),
    environment=_environment(owner),
    pass_nr=pass_nr,
  )
  return emit_redmesh_event(owner, job_specs, event)


def emit_export_status_event(owner, job_specs, *, adapter_type, status, pass_nr=None, destination_label=None, artifact_refs=None):
  secret, error = _event_export_secret(owner)
  if error:
    record_integration_status(owner, "wazuh", outcome="failure", error_class=error)
    return _skip_result(error)
  event = build_export_status_event(
    job_specs,
    adapter_type=adapter_type,
    status=status,
    hmac_secret=secret,
    tenant_id=_tenant_id(owner),
    environment=_environment(owner),
    pass_nr=pass_nr,
    destination_label=destination_label,
    artifact_refs=artifact_refs,
  )
  return emit_redmesh_event(owner, job_specs, event)


def emit_attestation_status_event(owner, job_specs, *, state, network=None, tx_hash=None, pass_nr=None):
  secret, error = _event_export_secret(owner)
  if error:
    record_integration_status(owner, "wazuh", outcome="failure", error_class=error)
    return _skip_result(error)
  event = build_attestation_event(
    job_specs,
    state=state,
    hmac_secret=secret,
    tenant_id=_tenant_id(owner),
    environment=_environment(owner),
    network=network,
    tx_hash=tx_hash,
    pass_nr=pass_nr,
  )
  return emit_redmesh_event(owner, job_specs, event)
