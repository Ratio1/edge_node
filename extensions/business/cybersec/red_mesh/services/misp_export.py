"""
MISP export service — builds MISPEvent objects from RedMesh scan data
and pushes them to a MISP server or exports as JSON.

Export metadata is stored in CStore (mutable) on the job record:
  job_specs["misp_export"] = {
      "event_uuid": "...",
      "event_id": 123,
      "misp_url": "https://...",
      "last_exported_at": 1712600000.0,
      "passes_exported": [1, 2, 3],
  }
"""

import time as _time
import math

from pymisp import MISPEvent, MISPObject, MISPAttribute, PyMISP

from ..repositories import ArtifactRepository, JobStateRepository
from ..tenancy.administration import AdministrationDenied
from ..tenancy.effects import EffectState
from ..tenancy.job_artifacts import TenantJobArtifacts, checked_job_snapshot, validate_snapshot_mode
from ..tenancy.ports import TenantStoreError
from .misp_config import get_misp_export_config, SEVERITY_LEVELS
from .event_hooks import emit_export_status_event
from .scan_guards import reject_model_test_for_scan_operation


_UNSET = object()


def _job_repo(owner):
  getter = getattr(type(owner), "_get_job_state_repository", None)
  if callable(getter):
    return getter(owner)
  return JobStateRepository(owner)


def _artifact_repo(owner):
  getter = getattr(type(owner), "_get_artifact_repository", None)
  if callable(getter):
    return getter(owner)
  return ArtifactRepository(owner)


def _write_job_record(owner, job_key, job_specs, context):
  write_job_record = getattr(type(owner), "_write_job_record", None)
  if callable(write_job_record):
    return write_job_record(owner, job_key, job_specs, context=context)
  return job_specs


# ── Severity helpers ──

_SEVERITY_INDEX = {s: i for i, s in enumerate(SEVERITY_LEVELS)}


def _passes_severity_filter(finding, min_severity):
  """Return True if finding severity is >= min_severity."""
  finding_sev = (finding.get("severity") or "INFO").upper()
  min_idx = _SEVERITY_INDEX.get(min_severity, 3)  # default LOW
  finding_idx = _SEVERITY_INDEX.get(finding_sev, 4)  # default INFO
  return finding_idx <= min_idx


_SEVERITY_TO_THREAT_LEVEL = {
  "CRITICAL": 1,  # High
  "HIGH": 1,
  "MEDIUM": 2,    # Medium
  "LOW": 3,       # Low
  "INFO": 4,      # Undefined
}


# ── MISP event building ──

def _build_misp_event(target, scan_type, task_name, job_id, risk_score,
                      report_cid, distribution, findings, open_ports,
                      port_banners, port_protocols, quick_summary,
                      tls_data=None):
  """
  Construct a MISPEvent from RedMesh scan data.

  Returns a fully populated MISPEvent ready for push or JSON export.
  """
  event = MISPEvent()

  # Event metadata
  scan_label = scan_type or "network"
  info_parts = [f"RedMesh Scan: {target} ({scan_label})"]
  if task_name:
    info_parts.append(f"— {task_name}")
  event.info = " ".join(info_parts)
  event.distribution = distribution

  # Determine threat level from highest-severity finding
  max_threat = 4
  for f in findings:
    sev = (f.get("severity") or "INFO").upper()
    threat = _SEVERITY_TO_THREAT_LEVEL.get(sev, 4)
    if threat < max_threat:
      max_threat = threat
  event.threat_level_id = max_threat
  event.analysis = 2  # Completed

  # Tags
  event.add_tag(f"redmesh:job_id={job_id}")
  if report_cid:
    event.add_tag(f"redmesh:report_cid={report_cid}")
  event.add_tag(f"redmesh:scan_type={scan_label}")
  event.add_tag(f"redmesh:risk_score={risk_score}")
  event.add_tag("tlp:amber")

  # Target IP/domain attribute
  event.add_attribute("ip-dst", target, comment="Scan target")

  # Quick summary as text attribute
  if quick_summary:
    event.add_attribute("text", quick_summary, comment="RedMesh AI summary")

  # Risk score as comment attribute
  event.add_attribute("comment", f"RedMesh risk score: {risk_score}/100",
                      comment="Risk assessment")

  # ── ip-port objects ──
  banners = port_banners or {}
  protocols = port_protocols or {}
  for port in sorted(open_ports or []):
    port_str = str(port)
    ip_port = MISPObject("ip-port")
    ip_port.add_attribute("ip", target)
    ip_port.add_attribute("dst-port", port)
    ip_port.add_attribute("protocol", "tcp")
    banner = banners.get(port_str, "")
    if banner:
      ip_port.add_attribute("text", str(banner)[:1024])
    service = protocols.get(port_str, "")
    if service:
      ip_port.comment = f"Service: {service}"
    event.add_object(ip_port)

  # ── vulnerability objects ──
  for finding in findings:
    vuln = MISPObject("vulnerability")

    finding_id = finding.get("finding_id", "")
    title = finding.get("title", "Unknown")
    description = finding.get("description", "")
    cwe_id = finding.get("cwe_id", "")
    owasp_id = finding.get("owasp_id", "")
    cvss = finding.get("cvss_score")
    severity = (finding.get("severity") or "INFO").upper()
    confidence = finding.get("confidence", "firm")
    port = finding.get("port", "")
    protocol = finding.get("protocol", "")
    probe = finding.get("probe", "")
    category = finding.get("category", "")

    vuln.add_attribute("id", finding_id or title)
    vuln.add_attribute("summary", title)
    if description:
      vuln.add_attribute("description", description[:4096])
    if cvss is not None:
      vuln.add_attribute("cvss-score", str(cvss))

    # References as individual link attributes
    if cwe_id:
      vuln.add_attribute("references", f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html")
    if owasp_id:
      vuln.add_attribute("references", f"https://owasp.org/Top10/A{owasp_id.split(':')[0].replace('A', '')}")

    vuln.add_attribute("state", "Published")

    # Comment with context
    comment_parts = []
    if port:
      comment_parts.append(f"Port: {port}/{protocol}")
    if probe:
      comment_parts.append(f"Probe: {probe}")
    if category:
      comment_parts.append(f"Category: {category}")
    comment_parts.append(f"Confidence: {confidence}")
    vuln.comment = ", ".join(comment_parts)

    # Tags on the id attribute (objects can't have tags directly)
    id_attr = [a for a in vuln.attributes if a.object_relation == "id"]
    if id_attr:
      id_attr[0].add_tag(f"redmesh:severity={severity}")
      if finding_id:
        id_attr[0].add_tag(f"redmesh:finding_id={finding_id}")
      for attack_id in finding.get("attack_ids", []) or []:
        id_attr[0].add_tag(f"mitre-attack:{attack_id}")

    event.add_object(vuln)

  # ── x509 objects (if TLS data available) ──
  for cert_info in (tls_data or []):
    if not isinstance(cert_info, dict):
      continue
    x509 = MISPObject("x509")
    if cert_info.get("issuer"):
      x509.add_attribute("issuer", str(cert_info["issuer"])[:512])
    if cert_info.get("subject"):
      x509.add_attribute("subject", str(cert_info["subject"])[:512])
    if cert_info.get("serial"):
      x509.add_attribute("serial-number", str(cert_info["serial"]))
    if cert_info.get("not_before"):
      x509.add_attribute("validity-not-before", str(cert_info["not_before"]))
    if cert_info.get("not_after"):
      x509.add_attribute("validity-not-after", str(cert_info["not_after"]))
    port = cert_info.get("port", 443)
    x509.comment = f"TLS on port {port}"
    event.add_object(x509)

  return event


def _extract_tls_data(aggregated):
  """Extract structured TLS certificate data from service_info probe results."""
  tls_certs = []
  service_info = aggregated.get("service_info") or {}
  for port_key, probes in service_info.items():
    if not isinstance(probes, dict):
      continue
    tls_probe = probes.get("_service_info_tls")
    if not isinstance(tls_probe, dict):
      continue
    cert = tls_probe.get("certificate") or tls_probe.get("cert_info") or {}
    if not isinstance(cert, dict):
      continue
    # Only create x509 object if we have structured fields
    if cert.get("issuer") or cert.get("subject"):
      try:
        port = int(port_key.split("/")[0])
      except (ValueError, IndexError):
        port = 443
      tls_certs.append({**cert, "port": port})
  return tls_certs


def _checked_export_json(value, job_id):
  """Check consumed JSON before conversion can stringify invalid numbers or hide ownership."""
  if isinstance(value, dict):
    if (any(key in value for key in ("execution_binding", "executionBinding", "tenant_id", "tenantId",
                                    "asset_id", "assetId", "raw_evidence_payload"))
        or "job_id" in value and value["job_id"] != job_id
        or value.get("kind") == "redmesh_model_test_raw_evidence"):
      raise TenantStoreError("MISP export unavailable")
    for key, item in value.items():
      if not isinstance(key, str):
        raise TenantStoreError("MISP export unavailable")
      _checked_export_json(item, job_id)
  elif isinstance(value, list):
    for item in value:
      _checked_export_json(item, job_id)
  elif isinstance(value, (int, float)):
    try:
      if not math.isfinite(value):
        raise TenantStoreError("MISP export unavailable")
    except OverflowError:
      raise TenantStoreError("MISP export unavailable") from None
  elif value is not None and not isinstance(value, str):
    raise TenantStoreError("MISP export unavailable")


def _resolve_pass_data(owner, job_id, pass_nr=None, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  """
  Fetch job archive and resolve the target pass's data.

  Returns (job_config, pass_report, aggregated, error_dict).
  On error, the first three are None and error_dict contains the error.
  """
  checked = checked_job is not _UNSET
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked)
  if checked:
    job_specs = checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
    if pass_nr is not None and (type(pass_nr) is not int or pass_nr < 1):
      raise AdministrationDenied(400, "invalid_request")
    if reject_model_test_for_scan_operation(job_specs, job_id, "misp_export"):
      raise AdministrationDenied(400, "unsupported_job_type")
    artifacts = TenantJobArtifacts(job_specs, _artifact_repo(owner).get_json, snapshot_mode=snapshot_mode)
    archive = artifacts.archive()
    passes = archive["passes"] if archive is not None else job_specs.get("pass_reports", [])
    selected = (next((entry for entry in passes if entry["pass_nr"] == pass_nr), None)
                if pass_nr is not None else passes[-1] if passes else None)
    if selected is None:
      raise AdministrationDenied(404, "not_found")
    if archive is None and (not isinstance(selected.get("report_cid"), str) or not selected["report_cid"].strip()):
      raise TenantStoreError("MISP export unavailable")
    pass_data = selected if archive is not None else artifacts.report(selected["report_cid"])
    job_config = artifacts.job_config()
    aggregate_cid = pass_data.get("aggregated_report_cid")
    aggregated = artifacts.report(aggregate_cid) if aggregate_cid else {}
    for payload in (job_config, pass_data, aggregated):
      _checked_export_json(payload, job_id)
    return job_config, pass_data, aggregated, None
  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return None, None, None, {"status": "error", "error": f"Job {job_id} not found"}
  unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "misp_export")
  if unsupported:
    return None, None, None, unsupported

  job_cid = job_specs.get("job_cid")
  if not job_cid:
    # Job still running — try pass_reports from CStore
    pass_reports = job_specs.get("pass_reports", [])
    if not pass_reports:
      return None, None, None, {
        "status": "error",
        "error": f"Job {job_id} has no completed passes yet",
      }
    # For running jobs, fetch the pass report directly
    if pass_nr is not None:
      target_ref = next((r for r in pass_reports if r.get("pass_nr") == pass_nr), None)
    else:
      target_ref = pass_reports[-1]
    if not target_ref:
      return None, None, None, {
        "status": "error",
        "error": f"Pass {pass_nr} not found",
        "available_passes": [r.get("pass_nr") for r in pass_reports],
      }
    report_cid = target_ref.get("report_cid")
    if not report_cid:
      return None, None, None, {"status": "error", "error": "No report CID for pass"}
    pass_data = _artifact_repo(owner).get_json(report_cid)
    if not isinstance(pass_data, dict):
      return None, None, None, {"status": "error", "error": "Failed to fetch pass report"}
    agg_cid = pass_data.get("aggregated_report_cid")
    aggregated = _artifact_repo(owner).get_json(agg_cid) if agg_cid else {}
    job_config = _artifact_repo(owner).get_job_config(job_specs) or {}
    return job_config, pass_data, aggregated or {}, None

  # Finalized job — use archive
  archive = _artifact_repo(owner).get_archive(job_specs)
  if not isinstance(archive, dict):
    return None, None, None, {"status": "error", "error": "Failed to fetch job archive"}

  job_config = archive.get("job_config", {})
  passes = archive.get("passes", []) or []
  if not passes:
    return None, None, None, {"status": "error", "error": "No passes in archive"}

  if pass_nr is not None:
    target_pass = next((p for p in passes if p.get("pass_nr") == pass_nr), None)
  else:
    target_pass = passes[-1]

  if not target_pass:
    return None, None, None, {
      "status": "error",
      "error": f"Pass {pass_nr} not found",
      "available_passes": [p.get("pass_nr") for p in passes],
    }

  agg_cid = target_pass.get("aggregated_report_cid")
  aggregated = _artifact_repo(owner).get_json(agg_cid) if agg_cid else {}
  return job_config, target_pass, aggregated or {}, None


# ── Public API ──

def build_misp_event(owner, job_id, pass_nr=None, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  """
  Build a MISPEvent from a job's scan results.

  Returns {"status": "ok", "event": <MISPEvent>, "job_id": ..., "pass_nr": ...}
  or {"status": "error", "error": "..."}.
  """
  cfg = get_misp_export_config(owner)
  min_severity = cfg["MIN_SEVERITY"]
  distribution = cfg["MISP_DISTRIBUTION"]

  job_config, pass_data, aggregated, err = _resolve_pass_data(owner, job_id, pass_nr,
    checked_job=checked_job, snapshot_mode=snapshot_mode)
  if err:
    return err

  target = job_config.get("target", "unknown")
  scan_type = job_config.get("scan_type", "network")
  task_name = job_config.get("task_name", "")
  actual_pass_nr = pass_data.get("pass_nr", 1)
  risk_score = pass_data.get("risk_score", 0)
  report_cid = pass_data.get("aggregated_report_cid", "")
  quick_summary = pass_data.get("quick_summary")
  findings = pass_data.get("findings") or []

  # Filter by severity
  filtered_findings = [f for f in findings if _passes_severity_filter(f, min_severity)]

  # Extract port data from aggregated scan data
  open_ports = aggregated.get("open_ports", [])
  port_banners = aggregated.get("port_banners", {})
  port_protocols = aggregated.get("port_protocols", {})

  # Extract TLS certs
  tls_data = _extract_tls_data(aggregated)

  event = _build_misp_event(
    target=target,
    scan_type=scan_type,
    task_name=task_name,
    job_id=job_id,
    risk_score=risk_score,
    report_cid=report_cid,
    distribution=distribution,
    findings=filtered_findings,
    open_ports=open_ports,
    port_banners=port_banners,
    port_protocols=port_protocols,
    quick_summary=quick_summary,
    tls_data=tls_data,
  )

  return {
    "status": "ok",
    "event": event,
    "job_id": job_id,
    "pass_nr": actual_pass_nr,
    "target": target,
    "findings_exported": len(filtered_findings),
    "findings_total": len(findings),
    "ports_exported": len(open_ports),
    **({"report_cid": report_cid} if checked_job is not _UNSET else {}),
  }


def push_to_misp(owner, job_id, pass_nr=None, *, checked_job=_UNSET,
                 snapshot_mode="tenant_bound", ledger=None):
  """
  Build a MISP event and push it to the configured MISP server.

  For continuous monitoring jobs, if a MISP event already exists (stored
  event_uuid in CStore), updates the existing event with new pass data.
  """
  cfg = get_misp_export_config(owner)
  # Checked snapshot replaces the unscoped global lookup (RM-026 I1b). Seam one of two.
  job_specs = owner._get_job_from_cstore(job_id) if checked_job is _UNSET else checked_job
  unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "misp_export")
  if unsupported:
    return unsupported

  def _record_export_status(status, artifact_refs=None):
    if not job_specs:
      return
    if ledger is not None:
      # A SOC emission plus a job-record write is an effect: revalidate, and record it so a later
      # failure cannot report "nothing happened" after the event left the node.
      ledger.checkpoint()
    emit_export_status_event(
      owner,
      job_specs,
      adapter_type="misp",
      status=status,
      pass_nr=pass_nr,
      destination_label="misp",
      artifact_refs=artifact_refs,
    )
    _write_job_record(owner, job_id, job_specs, context="misp_export_status")
    if ledger is not None:
      ledger.record(EffectState.PERSISTED)

  if not cfg["ENABLED"]:
    # Deliberately no _record_export_status here. Routing export_misp through _effect_operation
    # makes this branch live for the first time, and emitting a SOC event plus a job-record write
    # on a disabled integration would be a new behaviour OpenCTI and TAXII do not have.
    return {"status": "disabled", "disabled_reason": "misp_export_disabled"}
  if not cfg["MISP_URL"] or not cfg["MISP_API_KEY"]:
    # Twin of the disabled branch above, and equally dead before this slice: _export_to_misp
    # returned not_configured before push_to_misp was reached. Emitting here would ship the same
    # behaviour change the plan rejected for its twin -- a SOC event and a job-record write on a
    # misconfigured integration. The decision applies to both branches, not one.
    return {"status": "not_configured", "error": "missing_credentials"}

  # Build the event
  # Seam two: build_misp_event reaches the store again through _resolve_pass_data.
  result = (build_misp_event(owner, job_id, pass_nr=pass_nr) if checked_job is _UNSET
            else build_misp_event(owner, job_id, pass_nr=pass_nr, checked_job=checked_job,
                                  snapshot_mode=snapshot_mode))
  if result["status"] != "ok":
    _record_export_status("failed")
    return result
  event = result["event"]
  actual_pass_nr = result["pass_nr"]

  # Connect to MISP
  if ledger is not None:
    # Last revalidation before anything can reach the third-party server. build_misp_event above
    # spans an archive fetch and several artifact reads, so the window is real.
    ledger.checkpoint()
  try:
    misp = PyMISP(cfg["MISP_URL"], cfg["MISP_API_KEY"],
                  ssl=cfg["MISP_VERIFY_TLS"], timeout=cfg["TIMEOUT"])
  except Exception as exc:
    _record_export_status("failed")
    # Typed code, not prose: the exception text can carry the configured MISP URL.
    return {"status": "error", "error": "connection_failed", "retryable": True}

  # Check for existing event (re-export / continuous monitoring)
  existing_export = (job_specs or {}).get("misp_export", {})
  existing_uuid = existing_export.get("event_uuid")
  passes_exported = list(existing_export.get("passes_exported", []))

  try:
    if existing_uuid:
      # Try to update existing event
      try:
        existing_event = misp.get_event(existing_uuid, pythonify=True)
        if isinstance(existing_event, MISPEvent) and existing_event.uuid:
          # Add new objects to existing event
          accepted_objects = 0
          for obj in event.objects:
            added = misp.add_object(existing_event, obj, pythonify=True)
            if isinstance(added, MISPObject) or (isinstance(added, MISPEvent) and added.uuid):
              accepted_objects += 1
              if ledger is not None:
                # The remote now holds part of this export. A failure past this point must not
                # report "nothing happened": a retry would duplicate what was already added.
                ledger.record(EffectState.DELIVERED)
          # Update tags
          for tag in event.tags:
            existing_event.add_tag(tag)
          updated = misp.update_event(existing_event, pythonify=True)
          # Acceptance evidence, not the locally held event: assigning existing_event unconditionally
          # made the isinstance check below vacuous, so a fully rejected re-export reported ok.
          if isinstance(updated, MISPEvent) and updated.uuid:
            response_event = updated
          elif accepted_objects:
            response_event = existing_event
          else:
            response_event = updated
        else:
          # Event deleted on MISP side — create new
          response_event = misp.add_event(event, pythonify=True)
      except Exception:
        # Event not found — create new
        response_event = misp.add_event(event, pythonify=True)
    else:
      response_event = misp.add_event(event, pythonify=True)

    if not isinstance(response_event, MISPEvent):
      # PyMISP returns dict on error
      error_msg = str(response_event)
      if isinstance(response_event, dict):
        error_msg = response_event.get("message", response_event.get("errors", str(response_event)))
      _record_export_status("failed")
      return {"status": "error", "error": "api_error", "retryable": False}

    if ledger is not None and response_event.uuid:
      # PyMISP has no status code: a MISPEvent *with a uuid* is the only acceptance evidence.
      # isinstance alone is not enough -- str(None) would publish the string "None" as an id.
      ledger.record(EffectState.DELIVERED)
    event_uuid = str(response_event.uuid)
    event_id = int(response_event.id) if response_event.id else 0

    # Publish if configured
    if cfg["MISP_PUBLISH"]:
      try:
        misp.publish(response_event)
      except Exception:
        pass  # Non-fatal

  except Exception as exc:
    error_str = str(exc)
    retryable = not any(code in error_str for code in ["401", "403", "404"])
    _record_export_status("failed")
    return {"status": "error", "error": "push_failed", "retryable": retryable}

  # Store export metadata in CStore
  if actual_pass_nr not in passes_exported:
    passes_exported.append(actual_pass_nr)

  misp_export_meta = {
    "event_uuid": event_uuid,
    "event_id": event_id,
    "misp_url": cfg["MISP_URL"],
    "last_exported_at": _time.time(),
    "passes_exported": sorted(passes_exported),
  }

  if job_specs:
    job_specs["misp_export"] = misp_export_meta
    emit_export_status_event(
      owner,
      job_specs,
      adapter_type="misp",
      status="completed",
      pass_nr=actual_pass_nr,
      destination_label="misp",
      artifact_refs={"misp_event_uuid": event_uuid, "misp_event_id": event_id},
    )
    job_key = job_id
    _write_job_record(owner, job_key, job_specs, context="misp_export")

  return {
    "status": "ok",
    "event_uuid": event_uuid,
    "event_id": event_id,
    "misp_url": cfg["MISP_URL"],
    "pass_nr": actual_pass_nr,
    "findings_exported": result["findings_exported"],
    "findings_total": result["findings_total"],
    "ports_exported": result["ports_exported"],
  }


def export_misp_json(owner, job_id, pass_nr=None, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  """
  Build a MISP event and return it as a JSON-serializable dict.

  No MISP server connection needed.
  """
  result = build_misp_event(owner, job_id, pass_nr=pass_nr,
    checked_job=checked_job, snapshot_mode=snapshot_mode)
  if checked_job is not _UNSET and (not isinstance(result, dict)
      or result.get("status") != "ok" or result.get("job_id") != job_id):
    raise TenantStoreError("MISP export unavailable")
  if result["status"] != "ok":
    return result

  event = result["event"]
  payload = {
    "status": "ok",
    "misp_event": event.to_dict(),
    "job_id": job_id,
    "pass_nr": result["pass_nr"],
    "target": result["target"],
    "findings_exported": result["findings_exported"],
    "findings_total": result["findings_total"],
    "ports_exported": result["ports_exported"],
  }
  if checked_job is not _UNSET:
    from fastapi.encoders import jsonable_encoder
    payload = jsonable_encoder(payload)
    _checked_export_json(payload, job_id)
    event = payload["misp_event"]
    if (payload["job_id"] != job_id or type(payload["pass_nr"]) is not int or payload["pass_nr"] < 1
        or pass_nr is not None and payload["pass_nr"] != pass_nr or not isinstance(payload["target"], str)
        or any(type(payload[key]) is not int or payload[key] < 0
               for key in ("findings_exported", "findings_total", "ports_exported"))
        or payload["findings_exported"] > payload["findings_total"] or not isinstance(event, dict)):
      raise TenantStoreError("MISP export unavailable")
    tags = event.get("Tag")
    if not isinstance(tags, list) or any(not isinstance(tag, dict) or not isinstance(tag.get("name"), str) for tag in tags):
      raise TenantStoreError("MISP export unavailable")
    names = [tag["name"] for tag in tags]
    for prefix, expected in (("redmesh:job_id=", job_id), ("redmesh:report_cid=", result["report_cid"])):
      if [name for name in names if name.startswith(prefix)] != ([prefix + expected] if expected else []):
        raise TenantStoreError("MISP export unavailable")
  return payload


def get_misp_export_status(owner, job_id, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  """
  Check whether a job has been exported to MISP.

  Reads the misp_export metadata from CStore.
  """
  checked = checked_job is not _UNSET
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked)
  job_specs = (checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
               if checked else owner._get_job_from_cstore(job_id))
  if not job_specs:
    return {"job_id": job_id, "found": False, "exported": False}
  unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "misp_export_status")
  if unsupported:
    if checked:
      raise AdministrationDenied(400, "unsupported_job_type")
    return {**unsupported, "found": True, "exported": False}

  export_meta = job_specs.get("misp_export")
  if checked and export_meta is not None:
    if (not isinstance(export_meta, dict)
        or "job_id" in export_meta and export_meta["job_id"] != job_id
        or any(field in export_meta for field in ("success", "error", "status_code", "result",
               "detail", "exception_metadata", "execution_binding", "found", "exported"))):
      raise TenantStoreError("Export status is unavailable")
  if not export_meta or not isinstance(export_meta, dict):
    return {"job_id": job_id, "found": True, "exported": False}

  return {
    "job_id": job_id,
    "found": True,
    "exported": True,
    "event_uuid": export_meta.get("event_uuid"),
    "event_id": export_meta.get("event_id"),
    "misp_url": export_meta.get("misp_url"),
    "last_exported_at": export_meta.get("last_exported_at"),
    "passes_exported": export_meta.get("passes_exported", []),
  }
