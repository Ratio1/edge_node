"""
LLM Agent API Mixin for RedMesh Pentester.

This mixin provides LLM integration methods for analyzing scan results
via the RedMesh LLM Agent API (DeepSeek).

Usage:
  class PentesterApi01Plugin(_LlmAgentMixin, BasePlugin):
    ...
"""

import requests
from typing import Optional

from ..constants import RUN_MODE_SINGLEPASS
from ..services.config import get_llm_agent_config
from ..services.resilience import run_bounded_retry

_NON_RETRYABLE_HTTP_STATUSES = {400, 401, 403, 404, 409, 410, 413, 422}
_NON_RETRYABLE_PROVIDER_STATUSES = _NON_RETRYABLE_HTTP_STATUSES
_LLM_EVIDENCE_MAX_CHARS = 240
_LLM_BANNER_MAX_CHARS = 120
_LLM_SERVICE_LIMIT = 40
_LLM_TOP_FINDINGS_LIMIT = 80


class _RedMeshLlmAgentMixin(object):
  """
  Mixin providing LLM Agent API integration for RedMesh plugins.

  This mixin expects the host class to have the following config attributes:
  - cfg_llm_agent: dict-like nested config block, or equivalent config_data/CONFIG block
  - cfg_llm_agent_api_host: str
  - cfg_llm_agent_api_port: int

  And the following methods/attributes:
  - self.r1fs: R1FS instance
  - self.P(): logging method
  - self.Pd(): debug logging method
  - self._get_aggregated_report(): report aggregation method
  """

  def __init__(self, **kwargs):
    super(_RedMeshLlmAgentMixin, self).__init__(**kwargs)
    return

  def _get_llm_agent_config(self) -> dict:
    return get_llm_agent_config(self)

  @staticmethod
  def _llm_trim_text(value, max_chars):
    if value is None:
      return ""
    text = str(value).strip()
    if len(text) <= max_chars:
      return text
    return text[: max_chars - 3].rstrip() + "..."

  def _extract_report_findings(self, report: dict) -> list[dict]:
    findings = []
    if not isinstance(report, dict):
      return findings

    direct = report.get("findings")
    if isinstance(direct, list):
      findings.extend(item for item in direct if isinstance(item, dict))

    correlation = report.get("correlation_findings")
    if isinstance(correlation, list):
      findings.extend(item for item in correlation if isinstance(item, dict))

    service_info = report.get("service_info")
    if isinstance(service_info, dict):
      for service_entry in service_info.values():
        if not isinstance(service_entry, dict):
          continue
        nested = service_entry.get("findings")
        if isinstance(nested, list):
          findings.extend(item for item in nested if isinstance(item, dict))

    web_tests = report.get("web_tests_info")
    if isinstance(web_tests, dict):
      for web_entry in web_tests.values():
        if not isinstance(web_entry, dict):
          continue
        nested = web_entry.get("findings")
        if isinstance(nested, list):
          findings.extend(item for item in nested if isinstance(item, dict))

    return findings

  def _build_llm_metadata(self, job_id: str, target: str, scan_type: str, job_config: dict) -> dict:
    metadata = {
      "job_id": job_id,
      "target": target,
      "scan_type": scan_type,
      "run_mode": job_config.get("run_mode", RUN_MODE_SINGLEPASS),
    }
    if scan_type == "webapp":
      metadata["target_url"] = job_config.get("target_url")
      metadata["excluded_features"] = list(job_config.get("excluded_features", []) or [])
      metadata["app_routes_count"] = len(job_config.get("app_routes", []) or [])
    else:
      metadata["start_port"] = job_config.get("start_port")
      metadata["end_port"] = job_config.get("end_port")
      metadata["enabled_features_count"] = len(job_config.get("enabled_features", []) or [])
    return metadata

  def _build_network_service_summary(self, aggregated_report: dict) -> list[dict]:
    services = []
    service_info = aggregated_report.get("service_info")
    if not isinstance(service_info, dict):
      return services

    for raw_port, raw_entry in sorted(service_info.items(), key=lambda item: int(item[0]) if str(item[0]).isdigit() else str(item[0])):
      if not isinstance(raw_entry, dict):
        continue
      entry = {
        "port": raw_entry.get("port", raw_port),
        "protocol": raw_entry.get("protocol"),
        "service": raw_entry.get("service"),
        "product": raw_entry.get("product") or raw_entry.get("server") or raw_entry.get("ssh_library"),
        "version": raw_entry.get("version") or raw_entry.get("ssh_version"),
        "banner": self._llm_trim_text(raw_entry.get("banner") or raw_entry.get("server") or "", _LLM_BANNER_MAX_CHARS),
        "finding_count": len(raw_entry.get("findings") or []),
      }
      if raw_entry.get("findings"):
        entry["top_titles"] = [
          self._llm_trim_text(finding.get("title", ""), 100)
          for finding in raw_entry.get("findings", [])[:3]
          if isinstance(finding, dict) and finding.get("title")
        ]
      services.append(entry)
      if len(services) >= _LLM_SERVICE_LIMIT:
        break
    return services

  def _build_llm_top_findings(self, aggregated_report: dict) -> list[dict]:
    findings = self._extract_report_findings(aggregated_report)
    compact = []
    for finding in findings[:_LLM_TOP_FINDINGS_LIMIT]:
      compact.append({
        "severity": finding.get("severity"),
        "title": self._llm_trim_text(finding.get("title", ""), 160),
        "port": finding.get("port"),
        "protocol": finding.get("protocol"),
        "probe": finding.get("probe"),
        "cve": finding.get("cve_id") or finding.get("cve"),
        "cwe": finding.get("cwe_id"),
        "owasp": finding.get("owasp_id"),
        "evidence": self._llm_trim_text(finding.get("evidence", ""), _LLM_EVIDENCE_MAX_CHARS),
      })
    return compact

  def _build_llm_findings_summary(self, aggregated_report: dict) -> dict:
    findings = self._extract_report_findings(aggregated_report)
    counts = {}
    for finding in findings:
      severity = str(finding.get("severity") or "UNKNOWN").upper()
      counts[severity] = counts.get(severity, 0) + 1
    return {
      "total_findings": len(findings),
      "by_severity": counts,
    }

  def _build_llm_coverage_summary(self, aggregated_report: dict) -> dict:
    open_ports = aggregated_report.get("open_ports") or []
    worker_activity = aggregated_report.get("worker_activity") or []
    return {
      "ports_scanned": aggregated_report.get("ports_scanned"),
      "open_ports_count": len(open_ports),
      "open_ports_sample": list(open_ports[:40]),
      "workers": [
        {
          "id": worker.get("id"),
          "start_port": worker.get("start_port"),
          "end_port": worker.get("end_port"),
          "open_ports_count": len(worker.get("open_ports") or []),
        }
        for worker in worker_activity
        if isinstance(worker, dict)
      ],
    }

  def _build_llm_analysis_payload(self, job_id: str, aggregated_report: dict, job_config: dict, analysis_type: str) -> dict:
    scan_type = job_config.get("scan_type", "network")
    target = job_config.get("target_url") if scan_type == "webapp" else job_config.get("target", "unknown")
    if scan_type != "webapp":
      return {
        "metadata": self._build_llm_metadata(job_id, target, scan_type, job_config),
        "stats": {
          "nr_open_ports": aggregated_report.get("nr_open_ports"),
          "ports_scanned": aggregated_report.get("ports_scanned"),
          "scan_metrics": aggregated_report.get("scan_metrics"),
          "analysis_type": analysis_type,
        },
        "services": self._build_network_service_summary(aggregated_report),
        "top_findings": self._build_llm_top_findings(aggregated_report),
        "coverage": self._build_llm_coverage_summary(aggregated_report),
        "truncation": {
          "service_limit": _LLM_SERVICE_LIMIT,
          "finding_limit": _LLM_TOP_FINDINGS_LIMIT,
        },
        "findings_summary": self._build_llm_findings_summary(aggregated_report),
      }

    report_with_meta = {k: v for k, v in aggregated_report.items() if k != "node_ip"}
    report_with_meta["_job_metadata"] = self._build_llm_metadata(job_id, target, scan_type, job_config)
    return report_with_meta

  def _maybe_resolve_llm_agent_from_semaphore(self):
    """
    If SEMAPHORED_KEYS is configured and LLM Agent is enabled,
    read API_IP and API_PORT from semaphore env published by
    the LLM Agent API plugin. Overrides static config values.
    """
    llm_cfg = self._get_llm_agent_config()
    if not llm_cfg["ENABLED"]:
      return False
    semaphored_keys = getattr(self, 'cfg_semaphored_keys', None)
    if not semaphored_keys:
      return False
    if not self.semaphore_is_ready():
      return False
    env = self.semaphore_get_env()
    if not env:
      return False
    api_host = env.get('API_IP') or env.get('API_HOST') or env.get('HOST')
    api_port = env.get('PORT') or env.get('API_PORT')
    if api_host and api_port:
      self.P("Resolved LLM Agent API from semaphore: {}:{}".format(api_host, api_port))
      self.config_data['LLM_AGENT_API_HOST'] = api_host
      self.config_data['LLM_AGENT_API_PORT'] = int(api_port)
      return True
    return False

  def _get_llm_agent_api_url(self, endpoint: str) -> str:
    """
    Build URL for LLM Agent API endpoint.

    Parameters
    ----------
    endpoint : str
      API endpoint path (e.g., "/chat", "/analyze_scan").

    Returns
    -------
    str
      Full URL to the endpoint.
    """
    host = self.cfg_llm_agent_api_host
    port = self.cfg_llm_agent_api_port
    endpoint = endpoint.lstrip("/")
    return f"http://{host}:{port}/{endpoint}"

  def _extract_provider_http_status(self, error_details) -> int | None:
    """Best-effort extraction of an upstream provider HTTP status from error details."""
    if isinstance(error_details, dict):
      for key in ("status_code", "http_status", "provider_status"):
        value = error_details.get(key)
        if isinstance(value, int):
          return value
      detail = error_details.get("detail") or error_details.get("error")
      if isinstance(detail, str):
        return self._extract_provider_http_status(detail)

    if isinstance(error_details, str):
      marker = "status "
      if marker in error_details:
        tail = error_details.split(marker, 1)[1]
        digits = "".join(ch for ch in tail if ch.isdigit())
        if digits:
          try:
            return int(digits)
          except ValueError:
            return None
    return None

  def _is_non_retryable_llm_error(self, result: dict | None) -> bool:
    """Return True when an LLM/API error is permanent and retrying is wasteful."""
    if not isinstance(result, dict) or "error" not in result:
      return False

    http_status = result.get("http_status")
    if isinstance(http_status, int) and http_status in _NON_RETRYABLE_HTTP_STATUSES:
      return True

    provider_status = result.get("provider_status")
    if isinstance(provider_status, int) and provider_status in _NON_RETRYABLE_PROVIDER_STATUSES:
      return True

    return result.get("status") in {"api_request_error", "provider_request_error"}

  def _call_llm_agent_api(
      self,
      endpoint: str,
      method: str = "POST",
      payload: dict = None,
      timeout: int = None
  ) -> dict:
    """
    Make HTTP request to the LLM Agent API.

    Parameters
    ----------
    endpoint : str
      API endpoint to call (e.g., "/analyze_scan", "/health").
    method : str, optional
      HTTP method (default: "POST").
    payload : dict, optional
      JSON payload for POST requests.
    timeout : int, optional
      Request timeout in seconds.

    Returns
    -------
    dict
      API response or error object.
    """
    llm_cfg = self._get_llm_agent_config()
    if not llm_cfg["ENABLED"]:
      return {"error": "LLM Agent API is not enabled", "status": "disabled"}

    if not self.cfg_llm_agent_api_port:
      return {"error": "LLM Agent API port not configured", "status": "config_error"}

    url = self._get_llm_agent_api_url(endpoint)
    timeout = timeout or llm_cfg["TIMEOUT"]
    retries = max(int(getattr(self, "cfg_llm_api_retries", 1) or 1), 1)

    def _attempt():
      self.Pd(f"Calling LLM Agent API: {method} {url}")

      if method.upper() == "GET":
        response = requests.get(url, timeout=timeout)
      else:
        response = requests.post(
          url,
          json=payload or {},
          headers={"Content-Type": "application/json"},
          timeout=timeout
        )

      if response.status_code != 200:
        details = response.text
        try:
          details = response.json()
        except Exception:
          pass

        result = {
          "error": f"LLM Agent API returned status {response.status_code}",
          "status": "api_error",
          "details": details,
          "http_status": response.status_code,
        }
        if response.status_code in _NON_RETRYABLE_HTTP_STATUSES:
          result["status"] = "api_request_error"

        provider_status = self._extract_provider_http_status(details)
        if provider_status is not None:
          result["provider_status"] = provider_status
          if provider_status in _NON_RETRYABLE_PROVIDER_STATUSES:
            result["status"] = "provider_request_error"

        return {
          **result,
          "retryable": not self._is_non_retryable_llm_error(result),
        }

      # Unwrap response if FastAPI wrapped it (extract 'result' from envelope)
      response_data = response.json()
      if isinstance(response_data, dict) and "result" in response_data:
        return response_data["result"]
      return response_data

    def _is_success(response_data):
      if not isinstance(response_data, dict):
        return False
      if "error" not in response_data:
        return True
      return self._is_non_retryable_llm_error(response_data)

    try:
      result = run_bounded_retry(self, "llm_agent_api", retries, _attempt, is_success=_is_success)
    except requests.exceptions.ConnectionError:
      self.P(f"LLM Agent API not reachable at {url}", color='y')
      return {"error": "LLM Agent API not reachable", "status": "connection_error"}
    except requests.exceptions.Timeout:
      self.P("LLM Agent API request timed out", color='y')
      return {"error": "LLM Agent API request timed out", "status": "timeout"}
    except Exception as e:
      self.P(f"Error calling LLM Agent API: {e}", color='r')
      return {"error": str(e), "status": "error"}

    if isinstance(result, dict) and "error" in result:
      status = result.get("status")
      if status == "connection_error":
        self.P(f"LLM Agent API not reachable at {url}", color='y')
      elif status == "timeout":
        self.P("LLM Agent API request timed out", color='y')
      elif self._is_non_retryable_llm_error(result):
        provider_status = result.get("provider_status")
        detail = result.get("details")
        suffix = f" (provider_status={provider_status})" if provider_status else ""
        self.P(f"LLM Agent API request rejected{suffix}: {result.get('error')}", color='y')
        if detail:
          self.Pd(f"LLM Agent API rejection details: {detail}")
      else:
        self.P(f"LLM Agent API call failed: {result.get('error')}", color='y')
      return result
    return result

  def _auto_analyze_report(
      self, job_id: str, report: dict, target: str, scan_type: str = "network", analysis_type: str = None,
  ) -> Optional[dict]:
    """
    Automatically analyze a completed scan report using LLM Agent API.

    Parameters
    ----------
    job_id : str
      Identifier of the completed job.
    report : dict
      Aggregated scan report to analyze.
    target : str
      Target hostname/IP that was scanned.
    scan_type : str, optional
      "network" or "webapp" — selects the prompt set.

    Returns
    -------
    dict or None
      LLM analysis result or None if disabled/failed.
    """
    llm_cfg = self._get_llm_agent_config()
    if not llm_cfg["ENABLED"]:
      self.Pd("LLM auto-analysis skipped (not enabled)")
      return None

    self.P(f"Running LLM auto-analysis for job {job_id}, target {target} (scan_type={scan_type})...")

    analysis_result = self._call_llm_agent_api(
      endpoint="/analyze_scan",
      method="POST",
      payload={
        "scan_results": report,
        "analysis_type": analysis_type or llm_cfg["AUTO_ANALYSIS_TYPE"],
        "scan_type": scan_type,
        "focus_areas": None,
      }
    )

    if "error" in analysis_result:
      self.P(f"LLM auto-analysis failed for job {job_id}: {analysis_result.get('error')}", color='y')
    else:
      self.P(f"LLM auto-analysis completed for job {job_id}")

    return analysis_result

  def _collect_node_reports(self, workers: dict) -> dict:
    """
    Collect individual node reports from all workers.

    Parameters
    ----------
    workers : dict
      Worker entries from job_specs containing report_cid or result.

    Returns
    -------
    dict
      Mapping {addr: report_dict} for each worker with data.
    """
    all_reports = {}

    for addr, worker_entry in workers.items():
      report = None
      report_cid = worker_entry.get("report_cid")

      # Try to fetch from R1FS first
      if report_cid:
        try:
          report = self.r1fs.get_json(report_cid)
          self.Pd(f"Fetched report from R1FS for worker {addr}: CID {report_cid}")
        except Exception as e:
          self.P(f"Failed to fetch report from R1FS for {addr}: {e}", color='y')

      # Fallback to direct result
      if not report:
        report = worker_entry.get("result")

      if report:
        all_reports[addr] = report

    if not all_reports:
      self.P("No reports found to collect", color='y')

    return all_reports

  def _run_aggregated_llm_analysis(
      self,
      job_id: str,
      aggregated_report: dict,
      job_config: dict,
  ) -> str | None:
    """
    Run LLM analysis on a pre-aggregated report.

    The caller aggregates once and passes the result. This method
    no longer fetches node reports or saves to R1FS.

    Parameters
    ----------
    job_id : str
      Identifier of the job.
    aggregated_report : dict
      Pre-aggregated scan data from all workers.
    job_config : dict
      Job configuration (from R1FS).

    Returns
    -------
    str or None
      LLM analysis markdown text if successful, None otherwise.
    """
    scan_type = job_config.get("scan_type", "network")
    target = job_config.get("target_url") if scan_type == "webapp" else job_config.get("target", "unknown")
    self.P(f"Running aggregated LLM analysis for job {job_id}, target {target}...")

    if not aggregated_report:
      self.P(f"No data to analyze for job {job_id}", color='y')
      return None

    report_with_meta = self._build_llm_analysis_payload(
      job_id,
      aggregated_report,
      job_config,
      self._get_llm_agent_config()["AUTO_ANALYSIS_TYPE"],
    )

    # Call LLM analysis
    llm_analysis = self._auto_analyze_report(job_id, report_with_meta, target, scan_type=scan_type)
    self._last_llm_analysis_status = llm_analysis.get("status") if isinstance(llm_analysis, dict) else None

    if not llm_analysis or "error" in llm_analysis:
      self.P(
        f"LLM analysis failed for job {job_id}: {llm_analysis.get('error') if llm_analysis else 'No response'}",
        color='y'
      )
      return None

    # Extract the markdown text from the analysis result
    if isinstance(llm_analysis, dict):
      return llm_analysis.get("content", llm_analysis.get("analysis", llm_analysis.get("markdown", str(llm_analysis))))
    return str(llm_analysis)

  def _run_quick_summary_analysis(
      self,
      job_id: str,
      aggregated_report: dict,
      job_config: dict,
  ) -> str | None:
    """
    Run a short (2-4 sentence) AI quick summary on a pre-aggregated report.

    The caller aggregates once and passes the result. This method
    no longer fetches node reports or saves to R1FS.

    Parameters
    ----------
    job_id : str
      Identifier of the job.
    aggregated_report : dict
      Pre-aggregated scan data from all workers.
    job_config : dict
      Job configuration (from R1FS).

    Returns
    -------
    str or None
      Quick summary text if successful, None otherwise.
    """
    scan_type = job_config.get("scan_type", "network")
    target = job_config.get("target_url") if scan_type == "webapp" else job_config.get("target", "unknown")
    self.P(f"Running quick summary analysis for job {job_id}, target {target}...")

    if not aggregated_report:
      self.P(f"No data for quick summary for job {job_id}", color='y')
      return None

    report_with_meta = self._build_llm_analysis_payload(
      job_id,
      aggregated_report,
      job_config,
      "quick_summary",
    )

    # Call LLM analysis with quick_summary type
    analysis_result = self._call_llm_agent_api(
      endpoint="/analyze_scan",
      method="POST",
      payload={
        "scan_results": report_with_meta,
        "analysis_type": "quick_summary",
        "scan_type": scan_type,
        "focus_areas": None,
      }
    )
    self._last_llm_summary_status = analysis_result.get("status") if isinstance(analysis_result, dict) else None

    if not analysis_result or "error" in analysis_result:
      self.P(
        f"Quick summary failed for job {job_id}: {analysis_result.get('error') if analysis_result else 'No response'}",
        color='y'
      )
      return None

    # Extract the summary text from the result
    if isinstance(analysis_result, dict):
      return analysis_result.get("content", analysis_result.get("summary", analysis_result.get("analysis", str(analysis_result))))
    return str(analysis_result)

  def _get_llm_health_status(self) -> dict:
    """
    Check health of the LLM Agent API connection.

    Returns
    -------
    dict
      Health status of the LLM Agent API.
    """
    llm_cfg = self._get_llm_agent_config()
    if not llm_cfg["ENABLED"]:
      return {
        "enabled": False,
        "status": "disabled",
        "message": "LLM Agent API integration is disabled",
      }

    if not self.cfg_llm_agent_api_port:
      return {
        "enabled": True,
        "status": "config_error",
        "message": "LLM Agent API port not configured",
      }

    result = self._call_llm_agent_api(endpoint="/health", method="GET", timeout=5)

    if "error" in result:
      return {
        "enabled": True,
        "status": result.get("status", "error"),
        "message": result.get("error"),
        "host": self.cfg_llm_agent_api_host,
        "port": self.cfg_llm_agent_api_port,
      }

    return {
      "enabled": True,
      "status": "ok",
      "host": self.cfg_llm_agent_api_host,
      "port": self.cfg_llm_agent_api_port,
      "llm_agent_health": result,
    }
