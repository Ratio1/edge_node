"""
SIEM/Wazuh events pure download — the `redmesh.event.v1` events finalization would emit for a job
pass, returned as JSON with no destination, no persistence and no delivery (RM-093 phase 6).
"""

from __future__ import annotations

from ..models.event_schema import REDMESH_EVENT_SCHEMA
from ..tenancy.administration import AdministrationDenied
from ..tenancy.job_artifacts import checked_job_snapshot, validate_snapshot_mode
from .event_hooks import build_finding_event_for_emission, build_lifecycle_event_for_emission
from .scan_guards import reject_model_test_for_scan_operation
from .stix_export import _resolve_pass_data


_UNSET = object()


def _pass_egress_ips(pass_data):
  worker_reports = pass_data.get("worker_reports")
  if not isinstance(worker_reports, dict):
    return None
  ips = [meta.get("node_ip") for meta in worker_reports.values()
         if isinstance(meta, dict) and meta.get("node_ip")]
  return ips or None


def _pass_report_refs(job_specs, pass_data, actual_pass_nr):
  refs = {}
  for entry in job_specs.get("pass_reports") or []:
    if isinstance(entry, dict) and entry.get("pass_nr") == actual_pass_nr and entry.get("report_cid"):
      refs["pass_report_cid"] = entry["report_cid"]
      break
  if pass_data.get("aggregated_report_cid"):
    refs["aggregated_report_cid"] = pass_data["aggregated_report_cid"]
  return refs or None


def export_siem_events_json(owner, job_id, pass_nr=None, *, checked_job=_UNSET, snapshot_mode="tenant_bound"):
  """
  Return the SIEM/Wazuh events finalization would emit for one job pass, as a pure read.

  One `redmesh.job.pass_completed` lifecycle event and one `redmesh.finding.created` event per
  finding of the pass, coverage results excluded — built with the same builders and redaction as
  live emission. No R1FS write, no job-record mutation, no delivery, no integration-status record,
  and it never contacts a destination.
  """
  checked = checked_job is not _UNSET
  validate_snapshot_mode(snapshot_mode, snapshot_supplied=checked)
  if checked:
    job_specs = checked_job_snapshot(checked_job, job_id, snapshot_mode=snapshot_mode)
    if pass_nr is not None and (type(pass_nr) is not int or pass_nr < 1):
      raise AdministrationDenied(400, "invalid_request")
    unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "siem_events_export")
    if unsupported:
      raise AdministrationDenied(400, "unsupported_job_type")
  else:
    job_specs = owner._get_job_from_cstore(job_id)
    if not isinstance(job_specs, dict):
      return {"status": "error", "error": "job_not_found", "job_id": job_id}
    unsupported = reject_model_test_for_scan_operation(job_specs, job_id, "siem_events_export")
    if unsupported:
      return unsupported

  _job_config, pass_data, _aggregated, err = _resolve_pass_data(
    owner, job_id, pass_nr, checked_job=job_specs)
  if err:
    return err

  actual_pass_nr = pass_data.get("pass_nr", pass_nr or 1)
  findings = [finding for finding in (pass_data.get("findings") or []) if isinstance(finding, dict)]

  lifecycle_event, _error = build_lifecycle_event_for_emission(
    owner,
    job_specs,
    event_type="redmesh.job.pass_completed",
    event_action="pass_completed",
    event_outcome="success",
    pass_nr=actual_pass_nr,
    started_at=pass_data.get("date_started"),
    actual_end_at=pass_data.get("date_completed"),
    expected_egress_ips=_pass_egress_ips(pass_data),
    report_refs=_pass_report_refs(job_specs, pass_data, actual_pass_nr),
  )
  events = [lifecycle_event] if lifecycle_event is not None else []
  for finding in findings:
    event, _error = build_finding_event_for_emission(
      owner, job_specs, finding=finding, event_action="created", pass_nr=actual_pass_nr)
    if event is not None:
      events.append(event)

  return {
    "status": "ok",
    "job_id": job_id,
    "pass_nr": actual_pass_nr,
    "schema": REDMESH_EVENT_SCHEMA,
    "event_count": len(events),
    "events": events,
  }
