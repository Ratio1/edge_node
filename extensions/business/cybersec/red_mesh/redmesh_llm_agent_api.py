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

# System prompts for scan analysis
ANALYSIS_PROMPTS = {
  LLM_ANALYSIS_SECURITY_ASSESSMENT: """You are a cybersecurity expert analyzing network scan results.
Provide a comprehensive security assessment of the target based on the scan data.
Include:
1. Executive summary of security posture
2. Key findings organized by severity (Critical, High, Medium, Low)
3. Attack surface analysis
4. Overall risk rating

Be specific and reference the actual findings from the scan data.""",

  LLM_ANALYSIS_VULNERABILITY_SUMMARY: """You are a cybersecurity expert analyzing network scan results.
Provide a prioritized vulnerability summary based on the scan data.
Include:
1. Vulnerabilities ranked by severity and exploitability
2. CVE references where applicable
3. Potential impact of each vulnerability
4. Quick wins (easy fixes with high impact)

Focus on actionable findings.""",

  LLM_ANALYSIS_REMEDIATION_PLAN: """You are a cybersecurity expert analyzing network scan results.
Provide a detailed remediation plan based on the scan data.
Include:
1. Prioritized remediation steps
2. Specific commands or configurations to fix issues
3. Estimated effort for each fix
4. Dependencies between fixes
5. Verification steps to confirm remediation

Be practical and provide copy-paste ready solutions where possible.""",

  LLM_ANALYSIS_QUICK_SUMMARY: """You are a cybersecurity expert. Based on the scan results below, write a quick executive summary in exactly 2-4 sentences. Cover: how many ports/services were found, the overall risk posture (critical/high/medium/low), and the single most important finding or action item. Be specific but extremely concise -- this is a dashboard glance summary, not a full report.""",
}


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

    # Get system prompt for analysis type
    system_prompt = ANALYSIS_PROMPTS.get(analysis_type, ANALYSIS_PROMPTS[LLM_ANALYSIS_SECURITY_ASSESSMENT])

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

      # Return clean, minimal structure
      return {
        "analysis_type": analysis_type,
        "focus_areas": focus_areas,
        "model": response.get("model"),
        "content": content,
        "usage": {
          "prompt_tokens": usage.get("prompt_tokens"),
          "completion_tokens": usage.get("completion_tokens"),
          "total_tokens": usage.get("total_tokens"),
        },
        "scan_summary": {
          "open_ports": len(scan_results.get("open_ports", [])),
          "has_service_info": "service_info" in scan_results,
          "has_web_tests": "web_tests_info" in scan_results,
        },
        "created_at": self.time(),
      }

    return response

  """END API ENDPOINTS"""

  def process(self):
    """Main plugin loop (minimal for this API-only plugin)."""
    super(RedmeshLlmAgentApiPlugin, self).process()
    return
