"""
Report aggregation mixin for RedMesh pentester API.

Handles merging worker results, credential redaction, and pre-computing
the UI aggregate view for the frontend.
"""

from .pentest_worker import PentestLocalWorker
from .models import UiAggregate


class _ReportMixin:
  """Report aggregation and UI view methods for PentesterApi01Plugin."""

  SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
  CONFIDENCE_ORDER = {"certain": 0, "firm": 1, "tentative": 2}

  def _get_aggregated_report(self, local_jobs):
    """
    Aggregate results from multiple local workers.

    Parameters
    ----------
    local_jobs : dict
      Mapping of worker id to result dicts.

    Returns
    -------
    dict
      Aggregated report with merged open ports, service info, etc.
    """
    dct_aggregated_report = {}
    type_or_func, field = None, None
    try:
      if local_jobs:
        self.P(f"Aggregating reports from {len(local_jobs)} local jobs...")
        for local_worker_id, local_job_status in local_jobs.items():
          aggregation_fields = PentestLocalWorker.get_worker_specific_result_fields()
          for field in local_job_status:
            if field not in dct_aggregated_report:
              dct_aggregated_report[field] = local_job_status[field]
            elif field in aggregation_fields:
              type_or_func = aggregation_fields[field]
              if field not in dct_aggregated_report:
                field_type = type(local_job_status[field])
                dct_aggregated_report[field] = field_type()
              #endif
              if isinstance(dct_aggregated_report[field], list):
                existing = set(dct_aggregated_report[field])
                merged = existing.union(local_job_status[field])
                try:
                  dct_aggregated_report[field] = sorted(merged)
                except TypeError:
                  dct_aggregated_report[field] = list(merged)
              elif isinstance(dct_aggregated_report[field], dict):
                dct_aggregated_report[field] = self.merge_objects_deep(
                  dct_aggregated_report[field],
                  local_job_status[field])
              else:
                _existing = dct_aggregated_report[field]
                _new = local_job_status[field]
                dct_aggregated_report[field] = type_or_func([_existing, _new])
              # end if aggregation type
            # end if standard (one time) or aggregated fields
          # for each field in this local job
        # for each local job
        self.P(f"Report aggregation done.")
      # endif we have local jobs
    except Exception as exc:
      self.P("Error during report aggregation: {}:\n{}\n{}\ntype_or_func={}, field={}".format(
        exc, self.trace_info(),
        self.json_dumps(dct_aggregated_report, indent=2),
        type_or_func, field
      ))
    return dct_aggregated_report

  def merge_objects_deep(self, obj_a, obj_b):
    """
    Deeply merge two objects (dicts, lists, sets).

    Parameters
    ----------
    obj_a : Any
      First object.
    obj_b : Any
      Second object.

    Returns
    -------
    Any
      Merged object.
    """
    if isinstance(obj_a, dict) and isinstance(obj_b, dict):
      merged = dict(obj_a)
      for key, value_b in obj_b.items():
        if key in merged:
          merged[key] = self.merge_objects_deep(merged[key], value_b)
        else:
          merged[key] = value_b
      return merged
    elif isinstance(obj_a, list) and isinstance(obj_b, list):
      try:
        return list(set(obj_a).union(set(obj_b)))
      except TypeError:
        import json as _json
        seen = set()
        merged = []
        for item in obj_a + obj_b:
          try:
            key = _json.dumps(item, sort_keys=True, default=str)
          except (TypeError, ValueError):
            key = id(item)
          if key not in seen:
            seen.add(key)
            merged.append(item)
        return merged
    elif isinstance(obj_a, set) and isinstance(obj_b, set):
      return obj_a.union(obj_b)
    else:
      return obj_b  # Prefer obj_b in case of conflict

  def _redact_report(self, report):
    """
    Redact credentials from a report before persistence.

    Deep-copies the report and masks password values in findings and
    accepted_credentials lists so that sensitive data is not written
    to R1FS or CStore.

    Parameters
    ----------
    report : dict
      Aggregated scan report.

    Returns
    -------
    dict
      Redacted copy of the report.
    """
    import re as _re
    from copy import deepcopy
    redacted = deepcopy(report)
    service_info = redacted.get("service_info", {})
    for port_key, methods in service_info.items():
      if not isinstance(methods, dict):
        continue
      for method_key, method_data in methods.items():
        if not isinstance(method_data, dict):
          continue
        # Redact findings evidence
        for finding in method_data.get("findings", []):
          if not isinstance(finding, dict):
            continue
          evidence = finding.get("evidence", "")
          if isinstance(evidence, str):
            evidence = _re.sub(
              r'(Accepted credential:\s*\S+?):(\S+)',
              r'\1:***', evidence
            )
            evidence = _re.sub(
              r'(Accepted random creds\s*\S+?):(\S+)',
              r'\1:***', evidence
            )
            finding["evidence"] = evidence
        # Redact accepted_credentials lists
        creds = method_data.get("accepted_credentials", [])
        if isinstance(creds, list):
          method_data["accepted_credentials"] = [
            _re.sub(r'^(\S+?):(.+)$', r'\1:***', c) if isinstance(c, str) else c
            for c in creds
          ]
    return redacted

  def _compute_ui_aggregate(self, passes, latest_aggregated):
    """Compute pre-aggregated view for frontend from pass reports.

    Parameters
    ----------
    passes : list
      List of pass report dicts (PassReport.to_dict()).
    latest_aggregated : dict
      AggregatedScanData dict for the latest pass.

    Returns
    -------
    UiAggregate
    """
    from collections import Counter

    latest = passes[-1]
    agg = latest_aggregated
    findings = latest.get("findings", []) or []

    # Severity breakdown
    findings_count = dict(Counter(f.get("severity", "INFO") for f in findings))

    # Top findings: CRITICAL + HIGH, sorted by severity then confidence, capped at 10
    crit_high = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    crit_high.sort(key=lambda f: (
      self.SEVERITY_ORDER.get(f.get("severity"), 9),
      self.CONFIDENCE_ORDER.get(f.get("confidence"), 9),
    ))
    top_findings = crit_high[:10]

    # Finding timeline: track persistence across passes (continuous monitoring)
    finding_timeline = {}
    for p in passes:
      pass_nr = p.get("pass_nr", 0)
      for f in (p.get("findings") or []):
        fid = f.get("finding_id")
        if not fid:
          continue
        if fid not in finding_timeline:
          finding_timeline[fid] = {"first_seen": pass_nr, "last_seen": pass_nr, "pass_count": 1}
        else:
          finding_timeline[fid]["last_seen"] = pass_nr
          finding_timeline[fid]["pass_count"] += 1

    return UiAggregate(
      total_open_ports=sorted(set(agg.get("open_ports", []))),
      total_services=self._count_services(agg.get("service_info", {})),
      total_findings=len(findings),
      findings_count=findings_count if findings_count else None,
      top_findings=top_findings if top_findings else None,
      finding_timeline=finding_timeline if finding_timeline else None,
      latest_risk_score=latest.get("risk_score"),
      latest_risk_breakdown=latest.get("risk_breakdown"),
      latest_quick_summary=latest.get("quick_summary"),
      worker_activity=[
        {
          "id": addr,
          "start_port": w["start_port"],
          "end_port": w["end_port"],
          "open_ports": w.get("open_ports", []),
        }
        for addr, w in (latest.get("worker_reports") or {}).items()
      ] or None,
    )
