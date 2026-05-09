from __future__ import annotations

import copy
import re
import time as _time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..repositories import ArtifactRepository, JobStateRepository
from .config import get_stix_export_config
from .event_hooks import emit_export_status_event
from .event_redaction import stable_hmac_pseudonym, stable_sha256, strip_sensitive_fields
from .integration_status import record_integration_status


STIX_EXPORT_SCHEMA_VERSION = "1.0.0"

_IPV4_RE = re.compile(
  r"(?<![\w.])"
  r"(?:25[0-5]|2[0-4]\d|1?\d?\d)"
  r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}"
  r"(?![\w.])"
)

_TLP_MARKINGS = {
  "clear": ("marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487", "TLP:CLEAR", "clear"),
  "green": ("marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da", "TLP:GREEN", "green"),
  "amber": ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "TLP:AMBER", "amber"),
  "amber_strict": ("marking-definition--f88d31f6-486f-44da-b317-01333bde0b82", "TLP:AMBER", "amber"),
  "red": ("marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed", "TLP:RED", "red"),
}


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


def _resolve_pass_data(owner, job_id, pass_nr=None):
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return None, None, None, {"status": "error", "error": "job_not_found", "job_id": job_id}

  artifacts = _artifact_repo(owner)
  job_cid = job_specs.get("job_cid")
  if not job_cid:
    pass_reports = job_specs.get("pass_reports") or []
    if not pass_reports:
      return None, None, None, {
        "status": "error",
        "error": "no_completed_passes",
        "job_id": job_id,
      }
    if pass_nr is not None:
      target_ref = next((ref for ref in pass_reports if ref.get("pass_nr") == pass_nr), None)
    else:
      target_ref = pass_reports[-1]
    if not target_ref:
      return None, None, None, {
        "status": "error",
        "error": "pass_not_found",
        "job_id": job_id,
        "available_passes": [ref.get("pass_nr") for ref in pass_reports],
      }
    pass_data = artifacts.get_json(target_ref.get("report_cid"))
    if not isinstance(pass_data, dict):
      return None, None, None, {
        "status": "error",
        "error": "pass_report_not_found",
        "job_id": job_id,
      }
    agg_cid = pass_data.get("aggregated_report_cid")
    aggregated = artifacts.get_json(agg_cid) if agg_cid else {}
    job_config = artifacts.get_job_config(job_specs) or {}
    return job_config, pass_data, aggregated or {}, None

  archive = artifacts.get_archive(job_specs)
  if not isinstance(archive, dict):
    return None, None, None, {"status": "error", "error": "archive_not_found", "job_id": job_id}

  job_config = archive.get("job_config") or {}
  passes = archive.get("passes") or []
  if not passes:
    return None, None, None, {"status": "error", "error": "no_passes", "job_id": job_id}
  if pass_nr is not None:
    pass_data = next((item for item in passes if item.get("pass_nr") == pass_nr), None)
  else:
    pass_data = passes[-1]
  if not pass_data:
    return None, None, None, {
      "status": "error",
      "error": "pass_not_found",
      "job_id": job_id,
      "available_passes": [item.get("pass_nr") for item in passes],
    }
  agg_cid = pass_data.get("aggregated_report_cid")
  aggregated = artifacts.get_json(agg_cid) if agg_cid else {}
  return job_config, pass_data, aggregated or {}, None


def _utc_timestamp(epoch=None):
  if epoch is None:
    dt = datetime.now(timezone.utc)
  else:
    dt = datetime.fromtimestamp(float(epoch), timezone.utc)
  return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _stix_id(type_name, *parts):
  seed = "|".join(str(part) for part in parts if part is not None)
  return f"{type_name}--{uuid.uuid5(uuid.NAMESPACE_URL, seed)}"


def _compact_dict(payload):
  return {
    key: value
    for key, value in (payload or {}).items()
    if value not in (None, "", [], {})
  }


def _target_values(job_config, job_specs=None):
  values = []
  for payload in (job_config or {}, job_specs or {}):
    for key in ("target", "target_url"):
      value = payload.get(key)
      if value:
        values.append(str(value))
        try:
          host = urlsplit(str(value)).hostname
        except ValueError:
          host = None
        if host:
          values.append(host)
  return [value for value in dict.fromkeys(values) if value]


def _safe_text(value, *, hmac_secret, redaction_values=None, max_len=4096):
  if value is None:
    return ""
  if isinstance(value, (dict, list)):
    value = strip_sensitive_fields(copy.deepcopy(value))
    text = str(value)
  else:
    text = str(value)
  for raw in sorted(set(redaction_values or []), key=len, reverse=True):
    if not raw:
      continue
    text = text.replace(raw, stable_hmac_pseudonym(raw, hmac_secret, prefix="target"))

  def _replace_ip(match):
    return stable_hmac_pseudonym(match.group(0), hmac_secret, prefix="ip")

  text = _IPV4_RE.sub(_replace_ip, text)
  text = " ".join(text.split())
  return text[:max_len]


def _finding_refs(finding):
  refs = []
  cwe_id = str(finding.get("cwe_id") or "").strip()
  if cwe_id:
    refs.append({
      "source_name": "cwe",
      "external_id": cwe_id,
      "url": f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
    })

  owasp_id = str(finding.get("owasp_id") or "").strip()
  if owasp_id:
    refs.append({
      "source_name": "owasp",
      "external_id": owasp_id,
    })

  cves = []
  for key in ("cve_id", "cve"):
    if finding.get(key):
      cves.append(finding.get(key))
  for cve in finding.get("cves") or []:
    cves.append(cve)
  for cve in dict.fromkeys(str(item).strip() for item in cves if str(item).strip()):
    refs.append({
      "source_name": "cve",
      "external_id": cve,
      "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
    })

  for ref in finding.get("references") or []:
    url = str(ref or "").strip()
    if not url:
      continue
    try:
      parsed = urlsplit(url)
    except ValueError:
      continue
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password:
      continue
    refs.append({"source_name": "reference", "url": url})

  return refs[:20]


def _tlp_marking(tlp):
  marking_id, name, tlp_value = _TLP_MARKINGS.get(str(tlp or "amber").lower(), _TLP_MARKINGS["amber"])
  return {
    "type": "marking-definition",
    "spec_version": "2.1",
    "id": marking_id,
    "created": "2017-01-20T00:00:00Z",
    "definition_type": "tlp",
    "name": name,
    "definition": {"tlp": tlp_value},
  }


def _vulnerability_object(finding, *, job_id, pass_nr, created, marking_id,
                          hmac_secret, redaction_values):
  finding_id = str(finding.get("finding_id") or finding.get("id") or "").strip()
  title = _safe_text(
    finding.get("title") or finding_id or "RedMesh finding",
    hmac_secret=hmac_secret,
    redaction_values=redaction_values,
    max_len=256,
  )
  description = _safe_text(
    finding.get("description") or finding.get("summary") or title,
    hmac_secret=hmac_secret,
    redaction_values=redaction_values,
  )
  labels = ["redmesh"]
  for key in ("severity", "category", "confidence"):
    value = str(finding.get(key) or "").strip().lower()
    if value:
      labels.append(value)

  custom_context = _compact_dict({
    "finding_id": finding_id,
    "severity": finding.get("severity"),
    "confidence": finding.get("confidence"),
    "cvss_score": finding.get("cvss_score"),
    "cvss_vector": finding.get("cvss_vector"),
    "port": finding.get("port"),
    "protocol": finding.get("protocol"),
    "probe": finding.get("probe"),
    "category": finding.get("category"),
    "scenario_id": finding.get("scenario_id"),
    "attack_ids": finding.get("attack_ids"),
  })
  vuln = {
    "type": "vulnerability",
    "spec_version": "2.1",
    "id": _stix_id("vulnerability", "redmesh", job_id, pass_nr, finding_id or title),
    "created": created,
    "modified": created,
    "name": title,
    "description": description,
    "labels": sorted(set(labels)),
    "external_references": _finding_refs(finding),
    "object_marking_refs": [marking_id],
    "x_redmesh_context": strip_sensitive_fields(custom_context),
  }
  return _compact_dict(vuln)


def _indicator_objects(findings, *, job_id, pass_nr, created, marking_id, hmac_secret,
                       redaction_values, mode):
  if mode == "never":
    return []

  indicators = []
  seen = set()
  for finding in findings:
    port = finding.get("port")
    try:
      port = int(port)
    except (TypeError, ValueError):
      port = None
    if port is None:
      continue
    has_cve = bool(finding.get("cve") or finding.get("cve_id") or finding.get("cves"))
    if mode == "ioc_only" and not has_cve:
      continue
    key = (port, str(finding.get("protocol") or "tcp").lower())
    if key in seen:
      continue
    seen.add(key)
    name = _safe_text(
      f"RedMesh observed service indicator {key[1]}/{port}",
      hmac_secret=hmac_secret,
      redaction_values=redaction_values,
      max_len=256,
    )
    indicators.append({
      "type": "indicator",
      "spec_version": "2.1",
      "id": _stix_id("indicator", "redmesh", job_id, pass_nr, key[1], port),
      "created": created,
      "modified": created,
      "name": name,
      "indicator_types": ["unknown"],
      "pattern": f"[network-traffic:dst_port = {port}]",
      "pattern_type": "stix",
      "valid_from": created,
      "object_marking_refs": [marking_id],
    })
  return indicators


def _observed_service_objects(aggregated, *, job_id, pass_nr, first_observed,
                              last_observed, created, marking_id, target_pseudonym):
  open_ports = aggregated.get("open_ports") or []
  banners = aggregated.get("port_banners") or {}
  protocols = aggregated.get("port_protocols") or {}
  objects = []
  for port in sorted(open_ports, key=lambda item: int(item) if str(item).isdigit() else str(item)):
    port_text = str(port)
    try:
      port_value = int(port)
    except (TypeError, ValueError):
      port_value = port_text
    service = str(protocols.get(port_text) or protocols.get(port_value) or "").strip()
    banner = banners.get(port_text) or banners.get(port_value)
    service_obj_id = _stix_id("x-redmesh-service-observation", "redmesh", job_id, pass_nr, port_text, service)
    service_obj = _compact_dict({
      "type": "x-redmesh-service-observation",
      "id": service_obj_id,
      "created": created,
      "modified": created,
      "name": f"{service or 'tcp'}/{port_text}",
      "x_redmesh_target_pseudonym": target_pseudonym,
      "x_redmesh_port": port_value,
      "x_redmesh_protocol": "tcp",
      "x_redmesh_service": service,
      "x_redmesh_banner_hash": stable_sha256(banner) if banner else None,
      "object_marking_refs": [marking_id],
    })
    observed = {
      "type": "observed-data",
      "spec_version": "2.1",
      "id": _stix_id("observed-data", "redmesh", job_id, pass_nr, port_text, service),
      "created": created,
      "modified": created,
      "first_observed": first_observed,
      "last_observed": last_observed,
      "number_observed": 1,
      "object_refs": [service_obj_id],
      "object_marking_refs": [marking_id],
    }
    objects.extend([service_obj, observed])
  return objects


def build_stix_bundle(owner, job_id, pass_nr=None):
  """Build an isolated STIX 2.1 bundle for a RedMesh job/pass."""
  cfg = get_stix_export_config(owner)
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return {"status": "error", "error": "job_not_found", "job_id": job_id}

  job_config, pass_data, aggregated, err = _resolve_pass_data(owner, job_id, pass_nr)
  if err:
    return err

  actual_pass_nr = pass_data.get("pass_nr", pass_nr or 1)
  created = _utc_timestamp()
  first_observed = _utc_timestamp(pass_data.get("date_started") or job_specs.get("date_created") or _time.time())
  last_observed = _utc_timestamp(pass_data.get("date_completed") or job_specs.get("date_completed") or _time.time())
  marking = _tlp_marking(cfg["DEFAULT_TLP"])
  marking_id = marking["id"]
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-stix-export")
  redaction_values = _target_values(job_config, job_specs)
  target_value = (redaction_values or ["unknown"])[0]
  target_pseudonym = stable_hmac_pseudonym(target_value, hmac_secret, prefix="target")
  findings = pass_data.get("findings") or []

  vulnerabilities = [
    _vulnerability_object(
      finding,
      job_id=job_id,
      pass_nr=actual_pass_nr,
      created=created,
      marking_id=marking_id,
      hmac_secret=hmac_secret,
      redaction_values=redaction_values,
    )
    for finding in findings
    if isinstance(finding, dict)
  ]
  indicators = _indicator_objects(
    findings,
    job_id=job_id,
    pass_nr=actual_pass_nr,
    created=created,
    marking_id=marking_id,
    hmac_secret=hmac_secret,
    redaction_values=redaction_values,
    mode=cfg["INCLUDE_INDICATORS"],
  )
  observed = (
    _observed_service_objects(
      aggregated or {},
      job_id=job_id,
      pass_nr=actual_pass_nr,
      first_observed=first_observed,
      last_observed=last_observed,
      created=created,
      marking_id=marking_id,
      target_pseudonym=target_pseudonym,
    )
    if cfg["INCLUDE_OBSERVED_DATA"]
    else []
  )

  referenced = vulnerabilities + indicators + observed
  report = _compact_dict({
    "type": "report",
    "spec_version": "2.1",
    "id": _stix_id("report", "redmesh", job_id, actual_pass_nr),
    "created": created,
    "modified": created,
    "published": created,
    "name": f"RedMesh assessment {job_id} pass {actual_pass_nr}",
    "description": _safe_text(
      pass_data.get("quick_summary") or "RedMesh security assessment results.",
      hmac_secret=hmac_secret,
      redaction_values=redaction_values,
    ),
    "report_types": ["vulnerability"],
    "object_refs": [obj["id"] for obj in referenced],
    "external_references": [{
      "source_name": "redmesh",
      "external_id": str(job_id),
      "description": f"RedMesh job {job_id}, pass {actual_pass_nr}",
    }],
    "object_marking_refs": [marking_id],
    "x_redmesh_schema_version": STIX_EXPORT_SCHEMA_VERSION,
    "x_redmesh_target_pseudonym": target_pseudonym,
    "x_redmesh_report_cid": pass_data.get("aggregated_report_cid"),
    "x_redmesh_finding_count": len(vulnerabilities),
  })

  objects = [marking, report] + referenced
  bundle = {
    "type": "bundle",
    "id": _stix_id("bundle", "redmesh", job_id, actual_pass_nr, created),
    "objects": objects,
  }
  return {
    "status": "ok",
    "schema_version": STIX_EXPORT_SCHEMA_VERSION,
    "job_id": job_id,
    "pass_nr": actual_pass_nr,
    "bundle": bundle,
    "bundle_id": bundle["id"],
    "object_count": len(objects),
    "finding_count": len(vulnerabilities),
    "observed_data_count": sum(1 for obj in observed if obj.get("type") == "observed-data"),
    "target_pseudonym": target_pseudonym,
  }


def export_stix_bundle(owner, job_id, pass_nr=None, persist=True):
  """Build and optionally persist a STIX 2.1 bundle for manual export."""
  cfg = get_stix_export_config(owner)
  if not cfg["ENABLED"]:
    return {"status": "disabled", "error": "STIX export is disabled", "job_id": job_id}

  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    record_integration_status(owner, "stix", outcome="failure", error_class="job_not_found")
    return {"status": "error", "error": "job_not_found", "job_id": job_id}

  result = build_stix_bundle(owner, job_id, pass_nr=pass_nr)
  if result.get("status") != "ok":
    record_integration_status(owner, "stix", outcome="failure", error_class=result.get("error") or "build_failed")
    return result

  artifact_cid = None
  if persist:
    artifact_cid = _artifact_repo(owner).put_json(result["bundle"], show_logs=False)
    if not artifact_cid:
      record_integration_status(owner, "stix", outcome="failure", error_class="artifact_write_failed")
      return {"status": "error", "error": "artifact_write_failed", "job_id": job_id}

  exported_at = _utc_timestamp()
  export_meta = {
    "schema_version": STIX_EXPORT_SCHEMA_VERSION,
    "bundle_id": result["bundle_id"],
    "artifact_cid": artifact_cid,
    "last_exported_at": exported_at,
    "pass_nr": result["pass_nr"],
    "object_count": result["object_count"],
    "finding_count": result["finding_count"],
    "observed_data_count": result["observed_data_count"],
  }
  job_specs["stix_export"] = export_meta
  emit_export_status_event(
    owner,
    job_specs,
    adapter_type="stix",
    status="completed",
    pass_nr=result["pass_nr"],
    destination_label="stix-2.1",
    artifact_refs={"stix_bundle_id": result["bundle_id"], "stix_bundle_cid": artifact_cid},
  )
  _write_job_record(owner, job_id, job_specs, context="stix_export")
  record_integration_status(
    owner,
    "stix",
    outcome="success",
    event_id=result["bundle_id"],
    artifact_cid=artifact_cid,
  )
  return {
    "status": "ok",
    "job_id": job_id,
    "pass_nr": result["pass_nr"],
    "bundle_id": result["bundle_id"],
    "artifact_cid": artifact_cid,
    "last_exported_at": exported_at,
    "object_count": result["object_count"],
    "finding_count": result["finding_count"],
    "observed_data_count": result["observed_data_count"],
    "stix_bundle": result["bundle"],
  }


def get_stix_export_status(owner, job_id):
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return {"job_id": job_id, "found": False, "exported": False}

  export_meta = job_specs.get("stix_export")
  if not isinstance(export_meta, dict) or not export_meta:
    return {"job_id": job_id, "found": True, "exported": False}

  return {
    "job_id": job_id,
    "found": True,
    "exported": True,
    **export_meta,
  }
