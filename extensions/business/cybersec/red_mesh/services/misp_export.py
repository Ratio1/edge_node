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

from pymisp import MISPEvent, MISPObject, MISPAttribute, PyMISP

from ..repositories import ArtifactRepository, JobStateRepository
from .misp_config import get_misp_export_config, SEVERITY_LEVELS


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


def _resolve_pass_data(owner, job_id, pass_nr=None):
  """
  Fetch job archive and resolve the target pass's data.

  Returns (job_config, pass_report, aggregated, error_dict).
  On error, the first three are None and error_dict contains the error.
  """
  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return None, None, None, {"status": "error", "error": f"Job {job_id} not found"}

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

def build_misp_event(owner, job_id, pass_nr=None):
  """
  Build a MISPEvent from a job's scan results.

  Returns {"status": "ok", "event": <MISPEvent>, "job_id": ..., "pass_nr": ...}
  or {"status": "error", "error": "..."}.
  """
  cfg = get_misp_export_config(owner)
  min_severity = cfg["MIN_SEVERITY"]
  distribution = cfg["MISP_DISTRIBUTION"]

  job_config, pass_data, aggregated, err = _resolve_pass_data(owner, job_id, pass_nr)
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
  }


def push_to_misp(owner, job_id, pass_nr=None):
  """
  Build a MISP event and push it to the configured MISP server.

  For continuous monitoring jobs, if a MISP event already exists (stored
  event_uuid in CStore), updates the existing event with new pass data.
  """
  cfg = get_misp_export_config(owner)
  if not cfg["ENABLED"]:
    return {"status": "disabled", "error": "MISP export is disabled"}
  if not cfg["MISP_URL"] or not cfg["MISP_API_KEY"]:
    return {"status": "not_configured", "error": "MISP URL or API key not configured"}

  # Build the event
  result = build_misp_event(owner, job_id, pass_nr=pass_nr)
  if result["status"] != "ok":
    return result
  event = result["event"]
  actual_pass_nr = result["pass_nr"]

  # Connect to MISP
  try:
    misp = PyMISP(cfg["MISP_URL"], cfg["MISP_API_KEY"],
                  ssl=cfg["MISP_VERIFY_TLS"], timeout=cfg["TIMEOUT"])
  except Exception as exc:
    return {"status": "error", "error": f"MISP connection failed: {exc}", "retryable": True}

  # Check for existing event (re-export / continuous monitoring)
  job_specs = owner._get_job_from_cstore(job_id)
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
          for obj in event.objects:
            misp.add_object(existing_event, obj, pythonify=True)
          # Update tags
          for tag in event.tags:
            existing_event.add_tag(tag)
          misp.update_event(existing_event, pythonify=True)
          response_event = existing_event
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
      return {"status": "error", "error": f"MISP API error: {error_msg}", "retryable": False}

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
    return {"status": "error", "error": f"MISP push failed: {error_str}", "retryable": retryable}

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


def export_misp_json(owner, job_id, pass_nr=None):
  """
  Build a MISP event and return it as a JSON-serializable dict.

  No MISP server connection needed.
  """
  cfg = get_misp_export_config(owner)
  if not cfg["ENABLED"]:
    return {"status": "disabled", "error": "MISP export is disabled"}

  result = build_misp_event(owner, job_id, pass_nr=pass_nr)
  if result["status"] != "ok":
    return result

  event = result["event"]
  return {
    "status": "ok",
    "misp_event": event.to_dict(),
    "job_id": job_id,
    "pass_nr": result["pass_nr"],
    "target": result["target"],
    "findings_exported": result["findings_exported"],
    "findings_total": result["findings_total"],
    "ports_exported": result["ports_exported"],
  }


def get_misp_export_status(owner, job_id):
  """
  Check whether a job has been exported to MISP.

  Reads the misp_export metadata from CStore.
  """
  job_specs = owner._get_job_from_cstore(job_id)
  if not job_specs:
    return {"job_id": job_id, "found": False, "exported": False}

  export_meta = job_specs.get("misp_export")
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
