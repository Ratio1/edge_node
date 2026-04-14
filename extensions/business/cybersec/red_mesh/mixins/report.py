"""
Report aggregation mixin for RedMesh pentester API.

Handles merging worker results, credential redaction, and pre-computing
the UI aggregate view for the frontend.
"""

from ..worker import PentestLocalWorker
from ..models import UiAggregate


class _ReportMixin:
  """Report aggregation and UI view methods for PentesterApi01Plugin."""

  SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
  CONFIDENCE_ORDER = {"certain": 0, "firm": 1, "tentative": 2}

  @staticmethod
  def _count_nested_findings(section):
    """Count findings in a nested {port: {probe: {findings: []}}} section."""
    total = 0
    for per_port in (section or {}).values():
      if not isinstance(per_port, dict):
        continue
      for per_probe in per_port.values():
        if isinstance(per_probe, dict):
          total += len(per_probe.get("findings", []))
    return total

  def _count_all_findings(self, report):
    """Count all findings emitted by network and graybox reporting sections."""
    if not isinstance(report, dict):
      return 0
    return (
      self._count_nested_findings(report.get("service_info")) +
      self._count_nested_findings(report.get("web_tests_info")) +
      len(report.get("correlation_findings") or []) +
      self._count_nested_findings(report.get("graybox_results"))
    )

  @staticmethod
  def _dedupe_items(items):
    """Deduplicate mixed scalar/dict items while preserving first-seen order."""
    import json as _json

    deduped = []
    seen = set()
    for item in items:
      try:
        key = _json.dumps(item, sort_keys=True, default=str)
      except (TypeError, ValueError):
        key = str(item)
      if key in seen:
        continue
      seen.add(key)
      deduped.append(item)
    return deduped

  def _extract_graybox_ui_stats(self, aggregated, latest_pass=None):
    """Extract graybox-specific archive summary values from aggregated data."""
    latest_pass = latest_pass or {}
    scan_metrics = latest_pass.get("scan_metrics") or {}

    service_info = aggregated.get("service_info") or {}
    graybox_results = aggregated.get("graybox_results") or {}

    routes = []
    forms = []
    for methods in service_info.values():
      if not isinstance(methods, dict):
        continue
      discovery = methods.get("_graybox_discovery")
      if not isinstance(discovery, dict):
        continue
      routes.extend(discovery.get("routes") or [])
      forms.extend(discovery.get("forms") or [])

    scenario_total = 0
    scenario_vulnerable = 0
    for probes in graybox_results.values():
      if not isinstance(probes, dict):
        continue
      for probe_data in probes.values():
        if not isinstance(probe_data, dict):
          continue
        for finding in probe_data.get("findings", []):
          if not isinstance(finding, dict):
            continue
          status = finding.get("status")
          if not status:
            continue
          scenario_total += 1
          if status == "vulnerable":
            scenario_vulnerable += 1

    if scan_metrics:
      scenario_total = max(scenario_total, scan_metrics.get("scenarios_total", 0) or 0)
      scenario_vulnerable = max(
        scenario_vulnerable,
        scan_metrics.get("scenarios_vulnerable", 0) or 0,
      )

    return {
      "total_routes_discovered": len(self._dedupe_items(routes)),
      "total_forms_discovered": len(self._dedupe_items(forms)),
      "total_scenarios": scenario_total,
      "total_scenarios_vulnerable": scenario_vulnerable,
    }

  def _get_aggregated_report(self, local_jobs, worker_cls=None):
    """
    Aggregate results from multiple local workers.

    Parameters
    ----------
    local_jobs : dict
      Mapping of worker id to result dicts.
    worker_cls : type, optional
      Worker class to resolve aggregation fields from. Defaults to
      PentestLocalWorker for backward compat.

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
          if worker_cls and hasattr(worker_cls, 'get_worker_specific_result_fields'):
            aggregation_fields = worker_cls.get_worker_specific_result_fields()
          else:
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
    # Redact graybox_results credential evidence
    _CRED_RE = _re.compile(r'(\S+?):(\S+)')
    _PASSWORD_RE = _re.compile(r'((?:password|passwd|pwd)["\']?\s*[:=]\s*)(["\']?)[^\s"\'&]+', _re.I)

    def _redact_graybox_text(value):
      if not isinstance(value, str):
        return value
      value = _CRED_RE.sub(r'\1:***', value)
      value = _PASSWORD_RE.sub(r'\1\2***', value)
      return value

    graybox_results = redacted.get("graybox_results", {})
    for port_key, probes in graybox_results.items():
      if not isinstance(probes, dict):
        continue
      for probe_name, probe_data in probes.items():
        if not isinstance(probe_data, dict):
          continue
        for finding in probe_data.get("findings", []):
          if not isinstance(finding, dict):
            continue
          evidence = finding.get("evidence", [])
          if isinstance(evidence, list):
            finding["evidence"] = [
              _redact_graybox_text(e)
              for e in evidence
            ]
          artifacts = finding.get("evidence_artifacts", [])
          if isinstance(artifacts, list):
            finding["evidence_artifacts"] = [
              {
                **artifact,
                "summary": _redact_graybox_text(artifact.get("summary", "")),
                "request_snapshot": _redact_graybox_text(artifact.get("request_snapshot", "")),
                "response_snapshot": _redact_graybox_text(artifact.get("response_snapshot", "")),
              }
              if isinstance(artifact, dict) else artifact
              for artifact in artifacts
            ]
        artifacts = probe_data.get("artifacts", [])
        if isinstance(artifacts, list):
          probe_data["artifacts"] = [
            {
              **artifact,
              "summary": _redact_graybox_text(artifact.get("summary", "")),
              "request_snapshot": _redact_graybox_text(artifact.get("request_snapshot", "")),
              "response_snapshot": _redact_graybox_text(artifact.get("response_snapshot", "")),
            }
            if isinstance(artifact, dict) else artifact
            for artifact in artifacts
          ]
    return redacted

  @staticmethod
  def _redact_job_config(config_dict):
    """
    Redact credential fields from a job config dict before persistence.

    Parameters
    ----------
    config_dict : dict
      JobConfig.to_dict() output.

    Returns
    -------
    dict
      Copy with official_password, regular_password, and weak_candidates masked.
    """
    redacted = dict(config_dict)
    if redacted.get("official_password"):
      redacted["official_password"] = "***"
    if redacted.get("regular_password"):
      redacted["regular_password"] = "***"
    if redacted.get("weak_candidates"):
      redacted["weak_candidates"] = ["***"] * len(redacted["weak_candidates"])
    redacted.pop("secret_ref", None)
    return redacted

  def _compute_ui_aggregate(self, passes, latest_aggregated, job_config=None):
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
    scan_type = (job_config or {}).get("scan_type", "network")
    graybox_stats = {
      "total_routes_discovered": 0,
      "total_forms_discovered": 0,
      "total_scenarios": 0,
      "total_scenarios_vulnerable": 0,
    }
    if scan_type == "webapp":
      graybox_stats = self._extract_graybox_ui_stats(agg, latest)

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
      scan_type=scan_type,
      total_routes_discovered=graybox_stats["total_routes_discovered"],
      total_forms_discovered=graybox_stats["total_forms_discovered"],
      total_scenarios=graybox_stats["total_scenarios"],
      total_scenarios_vulnerable=graybox_stats["total_scenarios_vulnerable"],
    )
