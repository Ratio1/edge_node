from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..repositories import ArtifactRepository, JobStateRepository
from .config import get_suricata_correlation_config
from .event_redaction import stable_hmac_pseudonym
from .integration_status import record_integration_status


DETECTION_CORRELATION_SCHEMA_VERSION = "1.0.0"
MAX_EVE_JSONL_BYTES = 25 * 1024 * 1024
MAX_EVE_EVENTS = 100000


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


def _write_job_record(owner, job_id, job_specs):
  writer = getattr(type(owner), "_write_job_record", None)
  if callable(writer):
    return writer(owner, job_id, job_specs, context="suricata_correlation")
  return _job_repo(owner).put_job(job_id, job_specs)


def _coerce_epoch(value):
  if value in (None, ""):
    return None
  if isinstance(value, (int, float)):
    return float(value)
  text = str(value).strip()
  if not text:
    return None
  try:
    return float(text)
  except ValueError:
    pass
  if text.endswith("Z"):
    text = text[:-1] + "+00:00"
  try:
    return datetime.fromisoformat(text).timestamp()
  except ValueError:
    return None


def _iso_from_epoch(value):
  epoch = _coerce_epoch(value)
  if epoch is None:
    return None
  return datetime.fromtimestamp(epoch, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _target_candidates(job_specs, archive=None):
  candidates = []
  for payload in (job_specs or {}, (archive or {}).get("job_config") or {}):
    for key in ("target", "target_url"):
      value = payload.get(key)
      if not value:
        continue
      candidates.append(str(value))
      parsed = urlparse(str(value))
      if parsed.hostname:
        candidates.append(parsed.hostname)
  return {item for item in candidates if item}


def _port_range(job_specs, archive=None):
  cfg = (archive or {}).get("job_config") or {}
  start = int((job_specs or {}).get("start_port") or cfg.get("start_port") or 0)
  end = int((job_specs or {}).get("end_port") or cfg.get("end_port") or start)
  return start, end


def _job_window(job_specs, archive=None, pass_nr=None, cfg=None):
  cfg = cfg or {}
  start = (job_specs or {}).get("date_created")
  end = (job_specs or {}).get("date_completed")
  if archive:
    start = archive.get("date_created", start)
    end = archive.get("date_completed", end)
    passes = archive.get("passes") or []
    target_pass = None
    if pass_nr is not None:
      target_pass = next((p for p in passes if p.get("pass_nr") == pass_nr), None)
    elif passes:
      target_pass = passes[-1]
    if target_pass:
      start = target_pass.get("date_started", start)
      end = target_pass.get("date_completed", end)
  start_epoch = _coerce_epoch(start)
  end_epoch = _coerce_epoch(end)
  skew = int(cfg.get("CLOCK_SKEW_SECONDS", 60) or 0)
  grace = int(cfg.get("MATCH_WINDOW_SECONDS", 300) or 0)
  return {
    "start_epoch": start_epoch - skew if start_epoch is not None else None,
    "end_epoch": end_epoch + grace if end_epoch is not None else None,
    "started_at": _iso_from_epoch(start),
    "ended_at": _iso_from_epoch(end),
    "clock_skew_seconds": skew,
    "grace_seconds": grace,
  }


def _parse_eve_jsonl(eve_jsonl):
  if eve_jsonl is None:
    return []
  if isinstance(eve_jsonl, list):
    return [event for event in eve_jsonl if isinstance(event, dict)][:MAX_EVE_EVENTS]
  if isinstance(eve_jsonl, dict):
    return [eve_jsonl]
  payload = str(eve_jsonl)
  if len(payload.encode("utf-8")) > MAX_EVE_JSONL_BYTES:
    raise ValueError("eve_jsonl_too_large")
  events = []
  for line_nr, line in enumerate(payload.splitlines(), start=1):
    stripped = line.strip()
    if not stripped:
      continue
    try:
      event = json.loads(stripped)
    except json.JSONDecodeError as exc:
      raise ValueError(f"invalid_jsonl_line_{line_nr}") from exc
    if isinstance(event, dict):
      events.append(event)
    if len(events) >= MAX_EVE_EVENTS:
      break
  return events


def _event_time(event):
  return _coerce_epoch(event.get("timestamp") or event.get("@timestamp"))


def _event_sensor(event):
  return (
    event.get("sensor_name")
    or event.get("host")
    or (event.get("observer") or {}).get("hostname")
    or event.get("in_iface")
  )


def _event_matches(event, *, target_values, start_port, end_port, window, source_ips):
  ts = _event_time(event)
  if window["start_epoch"] is not None and ts is not None and ts < window["start_epoch"]:
    return False
  if window["end_epoch"] is not None and ts is not None and ts > window["end_epoch"]:
    return False

  dest_ip = event.get("dest_ip") or event.get("destination", {}).get("ip")
  dest_host = event.get("dest_host") or event.get("http", {}).get("hostname")
  if target_values and dest_ip not in target_values and dest_host not in target_values:
    return False

  dest_port = event.get("dest_port") or event.get("destination", {}).get("port")
  try:
    dest_port = int(dest_port)
  except (TypeError, ValueError):
    dest_port = None
  if dest_port is not None and start_port and end_port and not (start_port <= dest_port <= end_port):
    return False

  if source_ips:
    src_ip = event.get("src_ip") or event.get("source", {}).get("ip")
    if src_ip not in source_ips:
      return False

  return True


def _redacted_event(event, hmac_secret):
  alert = event.get("alert") if isinstance(event.get("alert"), dict) else {}
  src_ip = event.get("src_ip") or event.get("source", {}).get("ip")
  dest_ip = event.get("dest_ip") or event.get("destination", {}).get("ip")
  return {
    "timestamp": event.get("timestamp") or event.get("@timestamp"),
    "event_type": event.get("event_type"),
    "proto": event.get("proto") or event.get("network", {}).get("transport"),
    "app_proto": event.get("app_proto"),
    "src_ip_pseudonym": stable_hmac_pseudonym(src_ip, hmac_secret, prefix="ip") if src_ip else None,
    "dest_ip_pseudonym": stable_hmac_pseudonym(dest_ip, hmac_secret, prefix="target") if dest_ip else None,
    "dest_port": event.get("dest_port") or event.get("destination", {}).get("port"),
    "flow_id_hash": hashlib.sha256(str(event.get("flow_id", "")).encode("utf-8")).hexdigest()[:24] if event.get("flow_id") else None,
    "sensor_id": _event_sensor(event),
    "alert": {
      "signature": alert.get("signature"),
      "category": alert.get("category"),
      "severity": alert.get("severity"),
    } if alert else None,
  }


def _confidence(matched_alerts, matched_flows, source_ips):
  if matched_alerts > 0 and source_ips:
    return "high"
  if matched_alerts > 0 or matched_flows > 0:
    return "medium"
  return "low"


def _load_archive(owner, job_specs):
  if not (job_specs or {}).get("job_cid"):
    return None
  try:
    archive = _artifact_repo(owner).get_archive(job_specs)
    return archive if isinstance(archive, dict) else None
  except Exception:
    return None


def get_detection_correlation(owner, job_id):
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    return {"job_id": job_id, "found": False, "status": "not_found"}
  summary = job_specs.get("detection_correlation")
  return {
    "job_id": job_id,
    "found": True,
    "correlation": summary,
  }


def correlate_suricata_eve(owner, job_id, *, eve_jsonl="", pass_nr=None, source_ips=None, sensor_id=""):
  job_specs = owner._get_job_from_cstore(job_id)
  if not isinstance(job_specs, dict):
    record_integration_status(owner, "suricata", outcome="failure", error_class="job_not_found")
    return {"status": "error", "error": "job_not_found", "job_id": job_id}

  cfg = get_suricata_correlation_config(owner)
  hmac_secret = str(getattr(owner, "cfg_instance_id", "") or "redmesh-suricata-correlation")
  try:
    events = _parse_eve_jsonl(eve_jsonl)
  except ValueError as exc:
    record_integration_status(owner, "suricata", outcome="failure", error_class=str(exc))
    return {"status": "error", "error": str(exc), "job_id": job_id}

  archive = _load_archive(owner, job_specs)
  target_values = _target_candidates(job_specs, archive)
  start_port, end_port = _port_range(job_specs, archive)
  source_ips = set(str(ip).strip() for ip in (source_ips or []) if str(ip).strip())
  window = _job_window(job_specs, archive, pass_nr=pass_nr, cfg=cfg)

  matches = [
    event for event in events
    if _event_matches(
      event,
      target_values=target_values,
      start_port=start_port,
      end_port=end_port,
      window=window,
      source_ips=source_ips,
    )
  ]
  alerts = [event for event in matches if event.get("event_type") == "alert"]
  flows = [event for event in matches if event.get("event_type") == "flow"]
  high_signal_unmatched = [
    event for event in events
    if event not in matches and event.get("event_type") in {"alert", "anomaly"}
  ]
  sensors = sorted({
    str(sensor)
    for sensor in [_event_sensor(event) for event in matches]
    if sensor
  })
  if sensor_id and sensor_id not in sensors:
    sensors.append(sensor_id)
    sensors.sort()

  redacted_matches = [_redacted_event(event, hmac_secret) for event in matches[:500]]
  evidence = {
    "kind": "redmesh_suricata_correlation_v1",
    "schema_version": DETECTION_CORRELATION_SCHEMA_VERSION,
    "job_id": job_id,
    "pass_nr": pass_nr,
    "generated_at": _utc_timestamp(),
    "window": window,
    "matched_events": redacted_matches,
    "counts": {
      "events_received": len(events),
      "matched_events": len(matches),
      "matched_alerts": len(alerts),
      "matched_flows": len(flows),
      "unmatched_high_signal": len(high_signal_unmatched),
    },
  }
  artifact_cid = _artifact_repo(owner).put_json(evidence, show_logs=False) if redacted_matches else None

  status = "completed" if matches else "empty"
  summary = {
    "schema_version": DETECTION_CORRELATION_SCHEMA_VERSION,
    "status": status,
    "generated_at": evidence["generated_at"],
    "job_id": job_id,
    "pass_nr": pass_nr,
    "artifact_cid": artifact_cid,
    "window": window,
    "counts": evidence["counts"],
    "sensors_observed": sensors,
    "confidence": _confidence(len(alerts), len(flows), source_ips),
    "message": (
      "Matched Suricata/Security Onion telemetry for this RedMesh window."
      if matches
      else "No matching IDS telemetry was provided for this RedMesh window; this is not proof of non-detection."
    ),
  }
  job_specs["detection_correlation"] = summary
  _write_job_record(owner, job_id, job_specs)
  record_integration_status(
    owner,
    "suricata",
    outcome="success",
    artifact_cid=artifact_cid,
    event_id=f"{job_id}:{pass_nr or 'latest'}",
  )
  return {"status": "ok", "job_id": job_id, "correlation": summary}
