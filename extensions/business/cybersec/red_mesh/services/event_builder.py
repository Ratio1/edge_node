from __future__ import annotations

import uuid
from datetime import datetime, timezone

from ..models.event_schema import (
  EVENT_OUTCOMES,
  EVENT_SEVERITIES,
  REDMESH_EVENT_SCHEMA,
  REDMESH_EVENT_SCHEMA_VERSION,
  RedMeshEvent,
)
from .event_redaction import redact_event_payload, stable_hmac_pseudonym


DEFAULT_PRODUCER_NAME = "PENTESTER_API_01"
DEFAULT_PRODUCER_VERSION = "unknown"


def _utc_timestamp():
  return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _normalized_severity(value):
  normalized = str(value or "INFO").strip().upper()
  return normalized if normalized in EVENT_SEVERITIES else "INFO"


def _normalized_outcome(value):
  normalized = str(value or "unknown").strip().lower()
  return normalized if normalized in EVENT_OUTCOMES else "unknown"


def _outcome_from_status(value):
  normalized = str(value or "unknown").strip().lower()
  if normalized in {"completed", "sent", "submitted", "ok"}:
    return "success"
  if normalized in {"failed", "error"}:
    return "failure"
  return _normalized_outcome(normalized)


def _producer(name=None, version=None):
  return {
    "name": name or DEFAULT_PRODUCER_NAME,
    "version": version or DEFAULT_PRODUCER_VERSION,
  }


def _labels(extra=None):
  result = ["redmesh", "authorized-assessment"]
  for label in extra or []:
    if label not in result:
      result.append(label)
  return result


def _dedupe_key(job_id, pass_nr, event_type, event_action, fingerprint=""):
  parts = [
    str(job_id or ""),
    str(pass_nr) if pass_nr is not None else "none",
    str(event_type or ""),
    str(event_action or ""),
    str(fingerprint or ""),
  ]
  return ":".join(parts)


def build_target_ref(target_value, *, hmac_secret, target_type="host", include_display=False):
  if not target_value:
    return None
  target = {
    "type": target_type,
    "pseudonym": stable_hmac_pseudonym(target_value, hmac_secret, prefix="target"),
    "display": str(target_value) if include_display else None,
  }
  return target


def build_redmesh_event(
  *,
  event_type,
  event_action,
  job_id,
  hmac_secret,
  tenant_id="",
  environment="",
  pass_nr=None,
  scan_type="network",
  run_mode=None,
  event_outcome="unknown",
  severity="INFO",
  authorized=False,
  authorization_id=None,
  authorization_ref=None,
  redaction_mode="hash_only",
  tlp="amber",
  target=None,
  worker=None,
  window=None,
  observation=None,
  finding=None,
  artifact_refs=None,
  attestation=None,
  destination=None,
  correlation=None,
  producer_name=None,
  producer_version=None,
  labels=None,
  dedupe_fingerprint="",
):
  event = RedMeshEvent(
    schema=REDMESH_EVENT_SCHEMA,
    schema_version=REDMESH_EVENT_SCHEMA_VERSION,
    event_id=str(uuid.uuid4()),
    timestamp=_utc_timestamp(),
    producer=_producer(producer_name, producer_version),
    tenant_id=str(tenant_id or ""),
    environment=str(environment or ""),
    job_id=str(job_id or ""),
    pass_nr=pass_nr,
    scan_type=str(scan_type or "network"),
    run_mode=run_mode,
    event_type=str(event_type or ""),
    event_action=str(event_action or ""),
    event_outcome=_normalized_outcome(event_outcome),
    severity=_normalized_severity(severity),
    authorized=bool(authorized),
    authorization_id=authorization_id,
    authorization_ref=authorization_ref,
    redaction_mode=redaction_mode,
    dedupe_key=_dedupe_key(job_id, pass_nr, event_type, event_action, dedupe_fingerprint),
    tlp=tlp,
    labels=_labels(labels),
    target=target,
    worker=worker,
    window=window,
    observation=observation,
    finding=finding,
    artifact_refs=artifact_refs,
    attestation=attestation,
    destination=destination,
    correlation=correlation,
    redaction={
      "credentials_excluded": True,
      "cookies_excluded": True,
      "tokens_excluded": True,
      "raw_responses_excluded": True,
      "exploit_payloads_excluded": True,
    },
  ).to_dict()
  return redact_event_payload(event, hmac_secret=hmac_secret)


def build_test_event(*, hmac_secret, tenant_id="", environment=""):
  target = build_target_ref("198.51.100.10", hmac_secret=hmac_secret)
  return build_redmesh_event(
    event_type="redmesh.integration.test",
    event_action="tested",
    event_outcome="success",
    severity="INFO",
    job_id="integration-test",
    tenant_id=tenant_id,
    environment=environment,
    hmac_secret=hmac_secret,
    target=target,
    dedupe_fingerprint="integration-test",
  )


def build_lifecycle_event(
  job_specs,
  *,
  event_type,
  event_action,
  event_outcome="success",
  hmac_secret,
  tenant_id="",
  environment="",
  pass_nr=None,
):
  job_specs = job_specs or {}
  target = build_target_ref(job_specs.get("target"), hmac_secret=hmac_secret)
  return build_redmesh_event(
    event_type=event_type,
    event_action=event_action,
    event_outcome=event_outcome,
    severity="INFO",
    job_id=job_specs.get("job_id", ""),
    pass_nr=pass_nr if pass_nr is not None else job_specs.get("job_pass"),
    scan_type=job_specs.get("scan_type", "network"),
    run_mode=job_specs.get("run_mode"),
    authorized=bool(job_specs.get("authorized", False)),
    authorization_id=job_specs.get("authorization_id"),
    authorization_ref=job_specs.get("authorization_ref"),
    target=target,
    tenant_id=tenant_id,
    environment=environment,
    hmac_secret=hmac_secret,
  )


def build_service_observed_event(
  job_specs,
  *,
  service,
  hmac_secret,
  tenant_id="",
  environment="",
  pass_nr=None,
):
  job_specs = job_specs or {}
  service = service or {}
  port = service.get("port")
  protocol = service.get("protocol")
  observation = {
    "protocol": protocol,
    "port": port,
    "service_name": service.get("service_name") or service.get("name"),
    "service_version": service.get("service_version") or service.get("version"),
    "http_status": service.get("http_status"),
    "title_hash": service.get("title_hash"),
    "banner": service.get("banner"),
    "raw_response": service.get("raw_response"),
  }
  fingerprint = f"{port}/{protocol}/{observation.get('service_name') or ''}"
  return build_redmesh_event(
    event_type="redmesh.service.observed",
    event_action="observed",
    event_outcome="success",
    severity="INFO",
    job_id=job_specs.get("job_id", ""),
    pass_nr=pass_nr if pass_nr is not None else job_specs.get("job_pass"),
    scan_type=job_specs.get("scan_type", "network"),
    run_mode=job_specs.get("run_mode"),
    authorized=bool(job_specs.get("authorized", False)),
    target=build_target_ref(job_specs.get("target"), hmac_secret=hmac_secret),
    observation=observation,
    tenant_id=tenant_id,
    environment=environment,
    hmac_secret=hmac_secret,
    dedupe_fingerprint=fingerprint,
  )


def build_finding_event(
  job_specs,
  *,
  finding,
  event_action="created",
  hmac_secret,
  tenant_id="",
  environment="",
  pass_nr=None,
):
  job_specs = job_specs or {}
  finding = finding or {}
  finding_payload = {
    "finding_id": finding.get("finding_id"),
    "title": finding.get("title"),
    "severity": _normalized_severity(finding.get("severity")),
    "confidence": finding.get("confidence"),
    "category": finding.get("category"),
    "cwe_id": finding.get("cwe_id"),
    "owasp_id": finding.get("owasp_id"),
    "attack_ids": finding.get("attack_ids") or [],
    "triage_state": finding.get("triage_state"),
    "fingerprint": finding.get("fingerprint") or finding.get("finding_id"),
    "evidence": finding.get("evidence"),
  }
  return build_redmesh_event(
    event_type=f"redmesh.finding.{event_action}",
    event_action=event_action,
    event_outcome="success",
    severity=finding_payload["severity"],
    job_id=job_specs.get("job_id", ""),
    pass_nr=pass_nr if pass_nr is not None else job_specs.get("job_pass"),
    scan_type=job_specs.get("scan_type", "network"),
    run_mode=job_specs.get("run_mode"),
    authorized=bool(job_specs.get("authorized", False)),
    target=build_target_ref(job_specs.get("target"), hmac_secret=hmac_secret),
    finding=finding_payload,
    tenant_id=tenant_id,
    environment=environment,
    hmac_secret=hmac_secret,
    dedupe_fingerprint=finding_payload.get("fingerprint") or "",
  )


def build_export_status_event(
  job_specs,
  *,
  adapter_type,
  status,
  hmac_secret,
  tenant_id="",
  environment="",
  pass_nr=None,
  destination_label=None,
  artifact_refs=None,
):
  job_specs = job_specs or {}
  return build_redmesh_event(
    event_type=f"redmesh.export.{adapter_type}.{status}",
    event_action=str(status or "unknown"),
    event_outcome=_outcome_from_status(status),
    severity="INFO",
    job_id=job_specs.get("job_id", ""),
    pass_nr=pass_nr if pass_nr is not None else job_specs.get("job_pass"),
    scan_type=job_specs.get("scan_type", "network"),
    run_mode=job_specs.get("run_mode"),
    authorized=bool(job_specs.get("authorized", False)),
    target=build_target_ref(job_specs.get("target"), hmac_secret=hmac_secret),
    destination={"adapter_type": adapter_type, "label": destination_label},
    artifact_refs=artifact_refs,
    tenant_id=tenant_id,
    environment=environment,
    hmac_secret=hmac_secret,
  )


def build_attestation_event(
  job_specs,
  *,
  state,
  hmac_secret,
  tenant_id="",
  environment="",
  network=None,
  tx_hash=None,
  pass_nr=None,
):
  job_specs = job_specs or {}
  return build_redmesh_event(
    event_type=f"redmesh.attestation.{state}",
    event_action=str(state or "unknown"),
    event_outcome=_outcome_from_status(state),
    severity="INFO",
    job_id=job_specs.get("job_id", ""),
    pass_nr=pass_nr if pass_nr is not None else job_specs.get("job_pass"),
    scan_type=job_specs.get("scan_type", "network"),
    run_mode=job_specs.get("run_mode"),
    authorized=bool(job_specs.get("authorized", False)),
    target=build_target_ref(job_specs.get("target"), hmac_secret=hmac_secret),
    attestation={"network": network, "tx_hash": tx_hash, "state": state},
    tenant_id=tenant_id,
    environment=environment,
    hmac_secret=hmac_secret,
    dedupe_fingerprint=tx_hash or state,
  )
