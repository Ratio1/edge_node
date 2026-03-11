"""
RedMesh LLM Agent API Plugin

Local API for DeepSeek LLM integration in RedMesh workflows.
Provides chat completion and scan analysis endpoints that proxy to DeepSeek API.

Pipeline configuration example:
```json
{
  "NAME": "redmesh_llm_agent",
  "TYPE": "Void",
  "PLUGINS": [
    {
      "SIGNATURE": "REDMESH_LLM_AGENT_API",
      "INSTANCES": [
        {
          "INSTANCE_ID": "llm_agent",
          "PORT": 5050,
          "DEEPSEEK_MODEL": "deepseek-chat"
        }
      ]
    }
  ]
}
```

Available Endpoints:
- POST /chat - Chat completion via DeepSeek API
- POST /analyze_scan - Analyze RedMesh scan results with LLM
- GET /health - Health check with API key status
- GET /status - Request metrics

Environment Variables:
- DEEPSEEK_API_KEY: API key for DeepSeek (required)
"""

import json
import requests
import traceback

from typing import Any, Dict, List, Optional

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

from .constants import (
  LLM_API_STATUS_OK,
  LLM_API_STATUS_ERROR,
  LLM_API_STATUS_TIMEOUT,
  LLM_ANALYSIS_SECURITY_ASSESSMENT,
  LLM_ANALYSIS_VULNERABILITY_SUMMARY,
  LLM_ANALYSIS_REMEDIATION_PLAN,
  LLM_ANALYSIS_QUICK_SUMMARY,
)

__VER__ = '0.1.0'

_CONFIG = {
  **BasePlugin.CONFIG,

  # Local-only mode (no tunneling, no auth needed)
  "TUNNEL_ENGINE_ENABLED": False,
  "ALLOW_EMPTY_INPUTS": True,

  # Return raw responses without node metadata wrapper
  "RESPONSE_FORMAT": "RAW",

  "PORT": None,

  # API metadata
  "API_TITLE": "RedMesh LLM Agent API",
  "API_SUMMARY": "Local API for DeepSeek LLM integration in RedMesh workflows.",

  # DeepSeek configuration
  "DEEPSEEK_API_URL": "https://api.deepseek.com/chat/completions",
  "DEEPSEEK_API_KEY": None,  # API key (can be provided directly via config)
  "DEEPSEEK_API_KEY_ENV": "DEEPSEEK_API_KEY",  # Fallback: env var name if key not in config
  "DEEPSEEK_MODEL": "deepseek-chat",

  # Request defaults
  "DEFAULT_TEMPERATURE": 0.7,
  "DEFAULT_MAX_TOKENS": 1024,
  "DEFAULT_TOP_P": 1.0,

  # HTTP timeouts
  "REQUEST_TIMEOUT_SECONDS": 120,

  # Debug/logging
  "REDMESH_VERBOSE": 10,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}

# System prompts for scan analysis — network (blackbox port scanning)
_NETWORK_PROMPTS = {
  LLM_ANALYSIS_SECURITY_ASSESSMENT: """You are a senior penetration tester analyzing blackbox network scan results. The scan probed TCP ports on the target, fingerprinted services, tested for known CVEs, checked default credentials, and ran protocol-specific probes (HTTP, SSH, TLS, DNS, SMTP, databases, ICS/SCADA).

Provide a comprehensive security assessment. Structure your response as:

1. **Executive Summary** — One paragraph: overall security posture, number of open ports, number and severity distribution of findings, and whether the target is internet-facing or internal.
2. **Critical & High Findings** — For each finding: what was found, why it matters (business impact, not just technical), exploitability (is a public exploit available? is it authenticated or unauthenticated?), and the specific evidence from scan data (port, service, banner, CVE ID).
3. **Attack Surface Analysis** — Map the exposed services to potential attack chains. Identify lateral movement opportunities (e.g., exposed database + weak credentials → data exfiltration). Note any ICS/SCADA indicators.
4. **Medium & Low Findings** — Briefly list with one-line impact statements.
5. **Risk Rating** — Rate as Critical/High/Medium/Low with a one-sentence justification. Factor in: number of critical findings, presence of default credentials, unpatched CVEs with public exploits, and exposed management interfaces.

Reference specific ports, services, CVE IDs, and banners from the scan data. Do not make generic recommendations — be specific to what was actually found.""",

  LLM_ANALYSIS_VULNERABILITY_SUMMARY: """You are a senior penetration tester analyzing blackbox network scan results. The scan probed TCP ports, fingerprinted services, and tested for known CVEs and misconfigurations.

Provide a prioritized vulnerability summary. Structure your response as:

1. **Findings by Severity** — Group findings into Critical, High, Medium, Low. For each:
   - One-line title (e.g., "OpenSSH 7.4 — CVE-2023-38408 (RCE)")
   - Port/service where found
   - CVSS score or exploitability assessment (unauthenticated RCE > authenticated info disclosure)
   - Real-world impact (data breach, lateral movement, denial of service)
2. **Quick Wins** — Top 3-5 fixes with highest security impact and lowest effort (e.g., disable SSLv3, change default password, restrict management port to VPN).
3. **CVE Cross-Reference** — Table of all CVEs found with affected service, version, and whether a public exploit exists.

Rank findings by exploitability first, then severity. An unauthenticated RCE on a public-facing service is always the top priority, regardless of CVSS score.""",

  LLM_ANALYSIS_REMEDIATION_PLAN: """You are a senior penetration tester creating a remediation plan from blackbox network scan results. The scan probed TCP ports, fingerprinted services, and tested for CVEs and misconfigurations.

Provide a remediation plan that a system administrator can execute. Structure your response as:

1. **Immediate Actions (24-48 hours)** — Critical and easily exploitable findings. For each:
   - What to fix and where (specific port, service, config file)
   - Exact command or configuration change (copy-paste ready)
   - Verification step to confirm the fix worked
2. **Short-Term (1-2 weeks)** — High findings, patch deployments, credential rotations.
3. **Medium-Term (1-3 months)** — Architecture improvements, network segmentation, hardening.
4. **Dependencies** — Note where one fix must happen before another (e.g., "patch OpenSSH before rotating SSH keys").
5. **Compensating Controls** — If a fix requires downtime or coordination, suggest interim mitigations (e.g., firewall rule to restrict access while waiting for patch window).

Be specific to the services and versions found. Do not suggest generic hardening guides — reference the actual findings.""",

  LLM_ANALYSIS_QUICK_SUMMARY: """You are a senior penetration tester. Based on the network scan results below, write an executive summary in exactly 2-4 sentences.

Cover: number of open ports, number of services identified, overall risk posture (Critical/High/Medium/Low), and the single most important finding or action item. Mention specific CVEs or service names if critical findings exist. This is a dashboard glance summary — be specific but extremely concise.""",
}


# System prompts for scan analysis — webapp (authenticated graybox testing)
_WEBAPP_PROMPTS = {
  LLM_ANALYSIS_SECURITY_ASSESSMENT: """You are a senior web application security specialist analyzing authenticated graybox scan results. The scan authenticated to the target web application with admin and optionally regular-user credentials, discovered routes and forms via crawling, and ran OWASP Top 10 probes including:

- **A01 (Broken Access Control)**: IDOR/BOLA testing, privilege escalation from regular to admin endpoints
- **A02 (Security Misconfiguration)**: Debug endpoint exposure, CORS policy, security headers, cookie attributes, CSRF protection, session token quality (JWT alg=none, short tokens)
- **A03 (Injection)**: Reflected XSS and SQL injection in login and authenticated forms, stored XSS via form submission and readback
- **A05 (Broken Access Control)**: Login form injection testing
- **A06 (Insecure Design)**: Workflow bypass testing on state-changing endpoints
- **A07 (Identification & Auth Failures)**: Bounded weak credential testing with lockout detection
- **API7 (SSRF)**: Server-side request forgery on URL-fetch endpoints

Each finding has a status (vulnerable / not_vulnerable / inconclusive), severity, OWASP category, CWE IDs, evidence, and replay steps.

Provide a comprehensive security assessment. Structure your response as:

1. **Executive Summary** — One paragraph: overall application security posture, how many scenarios were tested, how many are vulnerable, and the OWASP categories with the most findings. Note the authentication context (which user roles were tested).
2. **Critical & High Findings** — For each vulnerable finding:
   - Scenario ID and title
   - Business impact (e.g., "Unauthorized access to other users' records", "Session hijacking via XSS", "Admin functionality accessible to regular users")
   - Exploitability: Is it trivially reproducible? Does it require authentication? Can it be chained with other findings?
   - Evidence from the scan (endpoint, payload, response)
   - Replay steps (from the scan data) so the development team can reproduce
3. **OWASP Coverage Analysis** — Which OWASP categories were tested and what the outcomes were. Flag any categories that were skipped (probes disabled, missing configuration, no forms discovered) — these represent blind spots.
4. **Attack Chain Analysis** — Identify how individual findings could be chained (e.g., XSS + missing CSRF → account takeover, IDOR + weak auth → mass data exfiltration).
5. **Medium & Low Findings** — Missing security headers, cookie attribute issues, inconclusive results that warrant manual verification.
6. **Risk Rating** — Rate as Critical/High/Medium/Low. A single IDOR or privilege escalation finding on a production app with real user data makes this Critical regardless of other findings.

Reference specific scenario IDs, endpoints, and evidence from the scan data. For inconclusive findings, explain what manual testing would confirm or rule out the issue.""",

  LLM_ANALYSIS_VULNERABILITY_SUMMARY: """You are a senior web application security specialist analyzing authenticated graybox scan results. The scan tested OWASP Top 10 categories (A01-A07, API7) against the target application using admin and regular-user sessions.

Each finding has: scenario_id, status (vulnerable/not_vulnerable/inconclusive), severity, OWASP category, CWE IDs, evidence, and replay steps.

Provide a prioritized vulnerability summary. Structure your response as:

1. **Vulnerable Findings by Severity** — Group by Critical, High, Medium, Low. For each:
   - Scenario ID and title
   - OWASP category and CWE
   - One-line business impact
   - Whether the finding is confirmed (status=vulnerable) or needs manual verification (status=inconclusive)
2. **Quick Wins** — Top 3-5 fixes with highest security impact and lowest development effort. Examples: add CSRF tokens, set HttpOnly/Secure on cookies, add Content-Security-Policy header, fix CORS wildcard.
3. **Inconclusive Findings Requiring Manual Review** — List findings with status=inconclusive and explain what additional testing would confirm them (e.g., "JWT signature weakness detected — manually verify if the signing key is brute-forceable").
4. **Untested Areas** — Probes that were skipped (stateful probes disabled, no SSRF endpoints configured, no forms discovered). These are coverage gaps the team should address manually.

Rank confirmed vulnerabilities above inconclusive ones. Rank by business impact: access control failures > injection > misconfigurations.""",

  LLM_ANALYSIS_REMEDIATION_PLAN: """You are a senior web application security specialist creating a remediation plan from authenticated graybox scan results. The scan tested OWASP Top 10 categories against the target application.

Each finding includes: scenario_id, OWASP category, CWE IDs, evidence, and replay steps for reproduction.

Provide a remediation plan for the development team. Structure your response as:

1. **Immediate Actions (next sprint)** — Critical and High findings. For each:
   - What to fix, referencing the specific endpoint and CWE
   - Code-level fix guidance (e.g., "Add @login_required + object ownership check on /api/records/{id}/", "Escape output with django.utils.html.escape()", "Set SameSite=Strict on session cookie")
   - Framework-specific guidance where possible (Django, Flask, Rails, Express patterns)
   - Verification: how to confirm the fix using the replay steps from the scan
2. **Short-Term (1-2 sprints)** — Medium findings, security header additions, cookie hardening.
3. **Architecture Improvements** — Systemic fixes that prevent entire vulnerability classes:
   - CSRF: framework-level middleware enforcement (not per-endpoint)
   - Access control: centralized authorization middleware (not per-view checks)
   - Injection: parameterized queries + output encoding at the template layer
   - Security headers: middleware/reverse-proxy level (one config change covers all endpoints)
4. **Testing Improvements** — Suggest integration tests the team should add to prevent regressions (e.g., "Add test that regular user gets 403 on /api/admin/export-users/").

Reference the specific scenario IDs and endpoints from the scan. Provide copy-paste code snippets where possible.""",

  LLM_ANALYSIS_QUICK_SUMMARY: """You are a senior web application security specialist. Based on the authenticated graybox scan results below, write an executive summary in exactly 2-4 sentences.

Cover: how many OWASP scenarios were tested, how many are vulnerable, the highest-severity finding (mention the specific vulnerability type — e.g., IDOR, XSS, CSRF bypass), and the single most important action item for the development team. This is a dashboard glance summary — be specific but extremely concise.""",
}


def _get_analysis_prompts(scan_type: str) -> dict:
  """Select prompt set based on scan type."""
  if scan_type == "webapp":
    return _WEBAPP_PROMPTS
  return _NETWORK_PROMPTS


# Default prompts (network) for backward compatibility
ANALYSIS_PROMPTS = _NETWORK_PROMPTS


class RedmeshLlmAgentApiPlugin(BasePlugin):
  """
  RedMesh LLM Agent API plugin for DeepSeek integration.

  This plugin exposes FastAPI endpoints for:
  - General chat completion via DeepSeek API
  - Automated analysis of RedMesh scan results

  Attributes
  ----------
  CONFIG : dict
    Plugin configuration merged with BasePlugin defaults.
  _api_key : str or None
    DeepSeek API key loaded from environment.
  _request_count : int
    Total number of API requests made.
  _error_count : int
    Total number of failed requests.
  """
  CONFIG = _CONFIG

  def on_init(self):
    """Initialize plugin and validate DeepSeek API key."""
    super(RedmeshLlmAgentApiPlugin, self).on_init()
    self._api_key = self._load_api_key()
    self._request_count = 0
    self._error_count = 0
    self._last_request_time = None

    if not self._api_key:
      self.P("WARNING: DeepSeek API key not configured! Set the DEEPSEEK_API_KEY environment variable.", color='r')
    else:
      self.P(f"RedMesh LLM Agent API initialized. Model: {self.cfg_deepseek_model}")
    return

  def _setup_semaphore_env(self):
    """Set semaphore environment variables for paired plugins."""
    super(RedMeshLlmAgentApiPlugin, self)._setup_semaphore_env()
    localhost_ip = self.log.get_localhost_ip()
    try:
      port = self.port or self.cfg_port
    except Exception as exc:
      self.P(f"Failed to resolve runtime port: {exc}", color='y')
      port = None
    self.semaphore_set_env('HOST', localhost_ip)
    self.semaphore_set_env('API_HOST', localhost_ip)
    if port:
      self.semaphore_set_env('PORT', str(port))
      self.semaphore_set_env('URL', 'http://{}:{}'.format(localhost_ip, port))
      self.semaphore_set_env('API_PORT', str(port))
      self.semaphore_set_env('API_URL', 'http://{}:{}'.format(localhost_ip, port))
    return

  def get_additional_fastapi_data(self):
    """Override to return empty dict - no node metadata in responses."""
    return {}

  def _load_api_key(self) -> Optional[str]:
    """
    Load API key from config or environment variable.

    Priority:
    1. DEEPSEEK_API_KEY config parameter (direct)
    2. Environment variable specified by DEEPSEEK_API_KEY_ENV

    Returns
    -------
    str or None
      The API key if found, otherwise None.
    """
    # First check if API key is provided directly in config
    api_key = self.cfg_deepseek_api_key
    if api_key:
      api_key = api_key.strip()
      if api_key:
        self.Pd("Using API key from config")
        return api_key

    # Fallback to environment variable
    env_name = self.cfg_deepseek_api_key_env
    api_key = self.os_environ.get(env_name, None)
    if api_key:
      api_key = api_key.strip()
      if api_key:
        self.Pd(f"Using API key from environment variable {env_name}")
        return api_key

    return None

  def P(self, s, *args, **kwargs):
    """Prefixed logger for RedMesh LLM messages."""
    s = "[REDMESH_LLM] " + str(s)
    return super(RedmeshLlmAgentApiPlugin, self).P(s, *args, **kwargs)

  def Pd(self, s, *args, score=-1, **kwargs):
    """Debug logging with verbosity control."""
    if self.cfg_redmesh_verbose > score:
      s = "[DEBUG] " + str(s)
      self.P(s, *args, **kwargs)
    return

  def _build_deepseek_request(
      self,
      messages: List[Dict],
      model: Optional[str] = None,
      temperature: Optional[float] = None,
      max_tokens: Optional[int] = None,
      top_p: Optional[float] = None,
  ) -> Dict:
    """
    Build the payload for DeepSeek API.

    Parameters
    ----------
    messages : list of dict
      Chat messages in OpenAI format.
    model : str, optional
      Model name override.
    temperature : float, optional
      Sampling temperature override.
    max_tokens : int, optional
      Max tokens override.
    top_p : float, optional
      Nucleus sampling override.

    Returns
    -------
    dict
      DeepSeek API request payload.
    """
    return {
      "model": model or self.cfg_deepseek_model,
      "messages": messages,
      "temperature": temperature if temperature is not None else self.cfg_default_temperature,
      "max_tokens": max_tokens if max_tokens is not None else self.cfg_default_max_tokens,
      "top_p": top_p if top_p is not None else self.cfg_default_top_p,
      "stream": False,
    }

  def _call_deepseek_api(self, payload: Dict) -> Dict:
    """
    Execute HTTP request to DeepSeek API.

    Parameters
    ----------
    payload : dict
      Request payload for DeepSeek API.

    Returns
    -------
    dict
      API response or error object.
    """
    if not self._api_key:
      return {
        "error": "DeepSeek API key not configured",
        "status": LLM_API_STATUS_ERROR,
      }

    headers = {
      "Content-Type": "application/json",
      "Authorization": f"Bearer {self._api_key}"
    }

    self._request_count += 1
    self._last_request_time = self.time()

    try:
      self.Pd(f"Calling DeepSeek API: {self.cfg_deepseek_api_url}")
      response = requests.post(
        self.cfg_deepseek_api_url,
        headers=headers,
        json=payload,
        timeout=self.cfg_request_timeout_seconds
      )

      if response.status_code != 200:
        self._error_count += 1
        error_detail = response.text
        try:
          error_detail = response.json()
        except Exception:
          pass
        return {
          "error": f"DeepSeek API returned status {response.status_code}",
          "status": LLM_API_STATUS_ERROR,
          "details": error_detail,
        }

      return response.json()

    except requests.exceptions.Timeout:
      self._error_count += 1
      self.P("DeepSeek API request timed out", color='r')
      return {
        "error": "DeepSeek API request timed out",
        "status": LLM_API_STATUS_TIMEOUT,
      }
    except requests.exceptions.RequestException as e:
      self._error_count += 1
      self.P(f"DeepSeek API request failed: {e}", color='r')
      return {
        "error": str(e),
        "status": LLM_API_STATUS_ERROR,
      }
    except Exception as e:
      self._error_count += 1
      self.P(f"Unexpected error calling DeepSeek API: {e}\n{traceback.format_exc()}", color='r')
      return {
        "error": f"Unexpected error: {e}",
        "status": LLM_API_STATUS_ERROR,
      }

  def _validate_messages(self, messages: List[Dict]) -> Optional[str]:
    """
    Validate chat messages format.

    Parameters
    ----------
    messages : list of dict
      Messages to validate.

    Returns
    -------
    str or None
      Error message if validation fails, otherwise None.
    """
    if not isinstance(messages, list) or len(messages) == 0:
      return "`messages` must be a non-empty list of message dicts."

    for idx, message in enumerate(messages):
      if not isinstance(message, dict):
        return f"Message at index {idx} must be a dict."

      role = message.get('role', None)
      content = message.get('content', None)

      if role not in {'system', 'user', 'assistant'}:
        return f"Message {idx} has invalid role '{role}'. Must be 'system', 'user', or 'assistant'."

      if not isinstance(content, str) or not content.strip():
        return f"Message {idx} content must be a non-empty string."

    return None

  """API ENDPOINTS"""

  @BasePlugin.endpoint(method="GET")
  def health(self) -> Dict:
    """
    Check API health and DeepSeek configuration.

    Returns
    -------
    dict
      Health status including API key presence and metrics.
    """
    return {
      "status": LLM_API_STATUS_OK,
      "api_key_configured": self._api_key is not None,
      "model": self.cfg_deepseek_model,
      "api_url": self.cfg_deepseek_api_url,
      "uptime_seconds": self.time() - self.start_time if hasattr(self, 'start_time') else 0,
      "version": __VER__,
    }

  @BasePlugin.endpoint(method="GET")
  def status(self) -> Dict:
    """
    Get detailed API status including request metrics.

    Returns
    -------
    dict
      Status with request counts and configuration.
    """
    return {
      "status": LLM_API_STATUS_OK,
      "metrics": {
        "total_requests": self._request_count,
        "failed_requests": self._error_count,
        "success_rate": (
          (self._request_count - self._error_count) / self._request_count * 100
          if self._request_count > 0 else 100.0
        ),
        "last_request_time": self._last_request_time,
      },
      "config": {
        "model": self.cfg_deepseek_model,
        "default_temperature": self.cfg_default_temperature,
        "default_max_tokens": self.cfg_default_max_tokens,
        "timeout_seconds": self.cfg_request_timeout_seconds,
      },
    }

  @BasePlugin.endpoint(method="POST")
  def chat(
      self,
      messages: List[Dict[str, Any]],
      model: Optional[str] = None,
      temperature: Optional[float] = None,
      max_tokens: Optional[int] = None,
      top_p: Optional[float] = None,
      **kwargs
  ) -> Dict:
    """
    Send a chat completion request to DeepSeek API.

    Parameters
    ----------
    messages : list of dict
      Chat messages in OpenAI format: [{"role": "user", "content": "..."}]
    model : str, optional
      Model name (default: deepseek-chat)
    temperature : float, optional
      Sampling temperature 0-2 (default: 0.7)
    max_tokens : int, optional
      Max tokens to generate (default: 1024)
    top_p : float, optional
      Nucleus sampling (default: 1.0)

    Returns
    -------
    dict
      DeepSeek API response or error object.
    """
    # Validate messages
    err = self._validate_messages(messages)
    if err is not None:
      return {
        "error": err,
        "status": LLM_API_STATUS_ERROR,
      }

    # Build and send request
    payload = self._build_deepseek_request(
      messages=messages,
      model=model,
      temperature=temperature,
      max_tokens=max_tokens,
      top_p=top_p,
    )

    self.Pd(f"Chat request: {len(messages)} messages, model={payload['model']}")
    return self._call_deepseek_api(payload)

  @BasePlugin.endpoint(method="POST")
  def analyze_scan(
      self,
      scan_results: Dict[str, Any],
      analysis_type: str = LLM_ANALYSIS_SECURITY_ASSESSMENT,
      scan_type: str = "network",
      focus_areas: Optional[List[str]] = None,
      model: Optional[str] = None,
      temperature: Optional[float] = None,
      max_tokens: Optional[int] = None,
      **kwargs
  ) -> Dict:
    """
    Analyze RedMesh scan results using DeepSeek LLM.

    Parameters
    ----------
    scan_results : dict
      RedMesh scan output containing open_ports, service_info, web_tests_info.
    analysis_type : str, optional
      Type of analysis to perform:
      - "security_assessment" (default): Overall security posture evaluation
      - "vulnerability_summary": Prioritized list of findings with severity
      - "remediation_plan": Actionable steps to fix identified issues
    scan_type : str, optional
      Scan type: "network" (blackbox port scan) or "webapp" (authenticated graybox).
      Selects the appropriate prompt set for the analysis.
    focus_areas : list of str, optional
      Specific areas to focus on: ["web", "network", "databases", "authentication"]
    model : str, optional
      Model name override.
    temperature : float, optional
      Sampling temperature override.
    max_tokens : int, optional
      Max tokens override.

    Returns
    -------
    dict
      LLM analysis response or error object.
    """
    # Validate scan_results
    if not isinstance(scan_results, dict):
      return {
        "error": "`scan_results` must be a dict containing scan data.",
        "status": LLM_API_STATUS_ERROR,
      }

    # Validate analysis_type
    valid_types = [
      LLM_ANALYSIS_SECURITY_ASSESSMENT,
      LLM_ANALYSIS_VULNERABILITY_SUMMARY,
      LLM_ANALYSIS_REMEDIATION_PLAN,
      LLM_ANALYSIS_QUICK_SUMMARY,
    ]
    if analysis_type not in valid_types:
      return {
        "error": f"Invalid analysis_type '{analysis_type}'. Must be one of: {valid_types}",
        "status": LLM_API_STATUS_ERROR,
      }

    # Get system prompt for analysis type (scan-type-aware)
    prompts = _get_analysis_prompts(scan_type or "network")
    system_prompt = prompts.get(analysis_type, prompts[LLM_ANALYSIS_SECURITY_ASSESSMENT])

    # Add focus areas if provided
    if focus_areas:
      focus_str = ", ".join(focus_areas)
      system_prompt += f"\n\nFocus your analysis on these areas: {focus_str}"

    # Format scan results for LLM
    try:
      scan_json = json.dumps(scan_results, indent=2, default=str)
    except Exception as e:
      return {
        "error": f"Failed to serialize scan_results: {e}",
        "status": LLM_API_STATUS_ERROR,
      }

    # Build messages
    messages = [
      {"role": "system", "content": system_prompt},
      {"role": "user", "content": f"Analyze the following scan results:\n\n```json\n{scan_json}\n```"},
    ]

    # Build and send request
    # Use higher max_tokens for analysis by default
    if max_tokens is not None:
      effective_max_tokens = max_tokens
    elif analysis_type == LLM_ANALYSIS_QUICK_SUMMARY:
      effective_max_tokens = 256
    else:
      effective_max_tokens = 2048

    payload = self._build_deepseek_request(
      messages=messages,
      model=model,
      temperature=temperature,
      max_tokens=effective_max_tokens,
    )

    self.Pd(f"Analyze scan request: type={analysis_type}, focus={focus_areas}")
    response = self._call_deepseek_api(payload)

    # Extract only what we need from the response
    if "error" not in response:
      # Get the analysis content from DeepSeek response
      content = None
      choices = response.get("choices", [])
      if choices:
        content = choices[0].get("message", {}).get("content", "")

      # Get token usage for cost tracking
      usage = response.get("usage", {})

      # Build scan summary (scan-type-aware)
      scan_summary = {
        "scan_type": scan_type or "network",
      }
      if scan_type == "webapp":
        graybox = scan_results.get("graybox_results", {})
        scenarios = graybox.get("scenarios", [])
        scan_summary["total_scenarios"] = len(scenarios)
        scan_summary["vulnerable"] = sum(1 for s in scenarios if s.get("status") == "vulnerable")
        scan_summary["not_vulnerable"] = sum(1 for s in scenarios if s.get("status") == "not_vulnerable")
        scan_summary["inconclusive"] = sum(1 for s in scenarios if s.get("status") == "inconclusive")
        scan_summary["has_graybox_results"] = bool(scenarios)
      else:
        scan_summary["open_ports"] = len(scan_results.get("open_ports", []))
        scan_summary["has_service_info"] = "service_info" in scan_results
        scan_summary["has_web_tests"] = "web_tests_info" in scan_results

      # Return clean, minimal structure
      return {
        "analysis_type": analysis_type,
        "scan_type": scan_type or "network",
        "focus_areas": focus_areas,
        "model": response.get("model"),
        "content": content,
        "usage": {
          "prompt_tokens": usage.get("prompt_tokens"),
          "completion_tokens": usage.get("completion_tokens"),
          "total_tokens": usage.get("total_tokens"),
        },
        "scan_summary": scan_summary,
        "created_at": self.time(),
      }

    return response

  """END API ENDPOINTS"""

  def process(self):
    """Main plugin loop (minimal for this API-only plugin)."""
    super(RedmeshLlmAgentApiPlugin, self).process()
    return
