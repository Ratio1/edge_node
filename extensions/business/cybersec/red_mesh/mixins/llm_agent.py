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
from ..services.resilience import run_bounded_retry


class _RedMeshLlmAgentMixin(object):
  """
  Mixin providing LLM Agent API integration for RedMesh plugins.

  This mixin expects the host class to have the following config attributes:
  - cfg_llm_agent_api_enabled: bool
  - cfg_llm_agent_api_host: str
  - cfg_llm_agent_api_port: int
  - cfg_llm_agent_api_timeout: int
  - cfg_llm_auto_analysis_type: str

  And the following methods/attributes:
  - self.r1fs: R1FS instance
  - self.P(): logging method
  - self.Pd(): debug logging method
  - self._get_aggregated_report(): report aggregation method
  """

  def __init__(self, **kwargs):
    super(_RedMeshLlmAgentMixin, self).__init__(**kwargs)
    return

  def _maybe_resolve_llm_agent_from_semaphore(self):
    """
    If SEMAPHORED_KEYS is configured and LLM Agent is enabled,
    read API_IP and API_PORT from semaphore env published by
    the LLM Agent API plugin. Overrides static config values.
    """
    if not self.cfg_llm_agent_api_enabled:
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
    if not self.cfg_llm_agent_api_enabled:
      return {"error": "LLM Agent API is not enabled", "status": "disabled"}

    if not self.cfg_llm_agent_api_port:
      return {"error": "LLM Agent API port not configured", "status": "config_error"}

    url = self._get_llm_agent_api_url(endpoint)
    timeout = timeout or self.cfg_llm_agent_api_timeout
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
        return {
          "error": f"LLM Agent API returned status {response.status_code}",
          "status": "api_error",
          "details": response.text
        }

      # Unwrap response if FastAPI wrapped it (extract 'result' from envelope)
      response_data = response.json()
      if isinstance(response_data, dict) and "result" in response_data:
        return response_data["result"]
      return response_data

    def _is_success(response_data):
      return isinstance(response_data, dict) and "error" not in response_data

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
      else:
        self.P(f"LLM Agent API call failed: {result.get('error')}", color='y')
      return result
    return result

  def _auto_analyze_report(
      self, job_id: str, report: dict, target: str, scan_type: str = "network",
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
    if not self.cfg_llm_agent_api_enabled:
      self.Pd("LLM auto-analysis skipped (not enabled)")
      return None

    self.P(f"Running LLM auto-analysis for job {job_id}, target {target} (scan_type={scan_type})...")

    analysis_result = self._call_llm_agent_api(
      endpoint="/analyze_scan",
      method="POST",
      payload={
        "scan_results": report,
        "analysis_type": self.cfg_llm_auto_analysis_type,
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

    # Add job metadata to report for context (strip node_ip — never send to LLM)
    report_with_meta = {k: v for k, v in aggregated_report.items() if k != "node_ip"}

    # Build scan-type-aware metadata
    metadata = {
      "job_id": job_id,
      "target": target,
      "scan_type": scan_type,
      "run_mode": job_config.get("run_mode", RUN_MODE_SINGLEPASS),
    }
    if scan_type == "webapp":
      metadata["target_url"] = job_config.get("target_url")
      metadata["app_routes"] = job_config.get("app_routes", [])
      metadata["excluded_features"] = job_config.get("excluded_features", [])
    else:
      metadata["start_port"] = job_config.get("start_port")
      metadata["end_port"] = job_config.get("end_port")
      metadata["enabled_features"] = job_config.get("enabled_features", [])
    report_with_meta["_job_metadata"] = metadata

    # Call LLM analysis
    llm_analysis = self._auto_analyze_report(job_id, report_with_meta, target, scan_type=scan_type)

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

    # Add job metadata to report for context (strip node_ip — never send to LLM)
    report_with_meta = {k: v for k, v in aggregated_report.items() if k != "node_ip"}

    # Build scan-type-aware metadata
    metadata = {
      "job_id": job_id,
      "target": target,
      "scan_type": scan_type,
      "run_mode": job_config.get("run_mode", RUN_MODE_SINGLEPASS),
    }
    if scan_type == "webapp":
      metadata["target_url"] = job_config.get("target_url")
      metadata["app_routes"] = job_config.get("app_routes", [])
      metadata["excluded_features"] = job_config.get("excluded_features", [])
    else:
      metadata["start_port"] = job_config.get("start_port")
      metadata["end_port"] = job_config.get("end_port")
      metadata["enabled_features"] = job_config.get("enabled_features", [])
    report_with_meta["_job_metadata"] = metadata

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
    if not self.cfg_llm_agent_api_enabled:
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
