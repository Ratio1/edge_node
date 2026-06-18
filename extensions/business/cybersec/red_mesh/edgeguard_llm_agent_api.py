"""EdgeGuard LLM Agent API Plugin.

This plugin calls a local LLM_INFERENCE_API instance and enforces the EdgeGuard
direct text-to-Cypher contract with schema/read-only validation and bounded
retry correction.
"""

from __future__ import annotations

import requests
import traceback

from typing import Any, Dict, List, Optional
from urllib.parse import urlsplit, urlunsplit

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

from .edgeguard_cypher_guard import (
  DEFAULT_SCHEMA_RETRY_LIMIT,
  SCHEMA_VERSION,
  analyze_generated_cypher,
  build_direct_cypher_system_prompt,
  build_schema_correction_prompt,
  canonical_schema_surface,
)

__VER__ = '0.1.0.0'

EDGEGUARD_MODEL_REPO = "ratio1/edgeguard-cypher-qwen3-4b-v0.5-preview-gguf"
EDGEGUARD_MODEL_FILE = "edgeguard-cypher-qwen3-4b-v0.5-preview.Q4_K_M.gguf"
EDGEGUARD_MODEL_DISPLAY_NAME = "EdgeGuard Cypher Qwen3 4B v0.5 Preview GGUF"
EDGEGUARD_MODEL_ARTIFACT_SHA256 = "1d92a276e3608252197b7f64af3e31b825b7f6accd5cf9cd0ba491f4cf5c8258"
EDGEGUARD_SOURCE_ADAPTER_SHA256 = "d1adf925ccf39cf699d3cc62f6f51af336a5b86d5907692e719405b1dde750df"
EDGEGUARD_RUNTIME_HARNESS_VERSION = "EGM-019 v0.5.10"
EDGEGUARD_RUNTIME_LIVE_GATE_RESULT = "34 / 38 = 89.47%"

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"
STATUS_TIMEOUT = "timeout"


_CONFIG = {
  **BasePlugin.CONFIG,

  "TUNNEL_ENGINE_ENABLED": False,
  "ALLOW_EMPTY_INPUTS": True,
  "RESPONSE_FORMAT": "RAW",
  "PORT": None,

  "API_TITLE": "EdgeGuard LLM Agent API",
  "API_SUMMARY": "Local guarded text-to-Cypher API for EdgeGuard.",

  "LOCAL_LLM_API_URL": None,
  "LOCAL_LLM_API_HOST": "127.0.0.1",
  "LOCAL_LLM_API_PORT": None,
  "LOCAL_LLM_API_PATH": "/create_chat_completion",
  "LOCAL_LLM_API_TOKEN": None,
  "LOCAL_LLM_API_TOKEN_ENV": "LLM_API_TOKEN",
  "LOCAL_LLM_MODEL": EDGEGUARD_MODEL_FILE,

  "DEFAULT_TEMPERATURE": 0.0,
  "DEFAULT_MAX_TOKENS": 512,
  "DEFAULT_TOP_P": 1.0,
  "SCHEMA_RETRY_LIMIT": DEFAULT_SCHEMA_RETRY_LIMIT,
  "MAX_REQUEST_CHARS": 4000,

  "REQUEST_TIMEOUT_SECONDS": 120,
  "EDGEGUARD_VERBOSE": 10,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class EdgeguardLlmAgentApiPlugin(BasePlugin):
  CONFIG = _CONFIG

  def on_init(self):
    super(EdgeguardLlmAgentApiPlugin, self).on_init()
    self._request_count = 0
    self._error_count = 0
    self._last_request_time = None
    self._local_api_token = self._resolve_secret(
      explicit=self.cfg_local_llm_api_token,
      env_name=self.cfg_local_llm_api_token_env,
    )
    return

  def _setup_semaphore_env(self):
    """Set semaphore environment variables for paired API/container plugins."""
    super(EdgeguardLlmAgentApiPlugin, self)._setup_semaphore_env()
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

  def Pd(self, message, **kwargs):
    if self.cfg_edgeguard_verbose:
      self.P(message, **kwargs)

  def _resolve_secret(self, explicit: Optional[str], env_name: Optional[str]) -> Optional[str]:
    if explicit:
      return explicit
    if not env_name:
      return None
    value = self.os_environ.get(env_name, None)
    if isinstance(value, str) and value.strip():
      return value.strip()
    return None

  def _redact_url(self, url: Optional[str]) -> Optional[str]:
    if not url:
      return url
    parts = urlsplit(url)
    if not parts.username and not parts.password:
      return url
    host = parts.hostname or ""
    if parts.port:
      host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))

  def _local_llm_url(self, path: Optional[str] = None) -> Optional[str]:
    configured_url = self.cfg_local_llm_api_url
    endpoint = path if path is not None else self.cfg_local_llm_api_path
    endpoint = str(endpoint or "/create_chat_completion").strip()
    if not endpoint.startswith("/"):
      endpoint = "/" + endpoint
    if configured_url:
      url = str(configured_url).rstrip("/")
      if url.endswith(endpoint):
        return url
      return url + endpoint
    host = self.cfg_local_llm_api_host
    port = self.cfg_local_llm_api_port
    if not host or not port:
      return None
    return f"http://{host}:{int(port)}{endpoint}"

  def _local_headers(self) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if self._local_api_token:
      headers["Authorization"] = f"Bearer {self._local_api_token}"
    return headers

  def _extract_content(self, response: Dict[str, Any]) -> str:
    choices = response.get("choices")
    if isinstance(choices, list) and choices:
      first = choices[0]
      if isinstance(first, dict):
        message = first.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
          return message["content"]
        if isinstance(first.get("text"), str):
          return first["text"]
    for key in ("TEXT_RESPONSE", "FULL_OUTPUT", "text", "content", "response"):
      value = response.get(key)
      if isinstance(value, str):
        return value
    return ""

  def _normalize_local_response(self, response: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(response, dict) and isinstance(response.get("result"), dict):
      response = response["result"]
    if "choices" in response and isinstance(response.get("choices"), list):
      response.setdefault("model", self.cfg_local_llm_model)
      response.setdefault("provider", "local")
      return response
    content = self._extract_content(response)
    return {
      "id": response.get("REQUEST_ID") or response.get("id"),
      "model": response.get("MODEL_NAME") or response.get("model") or self.cfg_local_llm_model,
      "choices": [{
        "index": 0,
        "message": {"role": "assistant", "content": content},
        "finish_reason": response.get("finish_reason", "stop"),
      }],
      "usage": response.get("usage", {}),
      "provider": "local",
    }

  def _call_local_llm_api(self, payload: Dict[str, Any]) -> Dict[str, Any]:
    self._request_count += 1
    self._last_request_time = self.time()
    url = self._local_llm_url()
    if not url:
      self._error_count += 1
      return {
        "status": "config_error",
        "provider": "local",
        "error": "Local LLM API port or URL not configured",
      }
    try:
      self.Pd(f"Calling EdgeGuard local LLM API: {self._redact_url(url)}")
      response = requests.post(
        url,
        headers=self._local_headers(),
        json=payload,
        timeout=self.cfg_request_timeout_seconds,
      )
      if response.status_code != 200:
        self._error_count += 1
        detail = response.text
        try:
          detail = response.json()
        except Exception:
          pass
        return {
          "status": STATUS_ERROR,
          "provider": "local",
          "error": f"Local LLM API returned status {response.status_code}",
          "details": detail,
          "provider_status": response.status_code,
        }
      return self._normalize_local_response(response.json())
    except requests.exceptions.Timeout:
      self._error_count += 1
      return {"status": STATUS_TIMEOUT, "provider": "local", "error": "Local LLM API request timed out"}
    except requests.exceptions.RequestException as exc:
      self._error_count += 1
      return {"status": STATUS_ERROR, "provider": "local", "error": str(exc)}
    except Exception as exc:
      self._error_count += 1
      self.P(f"Unexpected EdgeGuard LLM call error: {exc}\n{traceback.format_exc()}", color='r')
      return {"status": STATUS_ERROR, "provider": "local", "error": f"Unexpected error: {exc}"}

  def _build_payload(
    self,
    messages: List[Dict[str, str]],
    temperature: Optional[float],
    max_tokens: Optional[int],
    top_p: Optional[float],
  ) -> Dict[str, Any]:
    return {
      "messages": messages,
      "temperature": self.cfg_default_temperature if temperature is None else temperature,
      "max_tokens": min(int(max_tokens or self.cfg_default_max_tokens), int(self.cfg_default_max_tokens)),
      "top_p": self.cfg_default_top_p if top_p is None else top_p,
      "metadata": {
        "task": "edgeguard_direct_cypher",
        "schema_version": SCHEMA_VERSION,
      },
    }

  def _attempt_record(self, attempt: int, kind: str, raw_output: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
    return {
      "attempt": attempt,
      "kind": kind,
      "raw_output": raw_output,
      "candidate_cypher": analysis["candidate"],
      "accepted": analysis["accepted"],
      "query_only": analysis["query_only"],
      "read_only_static": analysis["read_only_static"],
      "schema_compatible": analysis["schema_compatible"],
      "schema_unknown": analysis["schema_unknown"],
      "invented_temporal_properties": analysis["invented_temporal_properties"],
      "validation_feedback": analysis["validation_feedback"],
    }

  def _validate_request(self, request: str) -> Optional[str]:
    if not isinstance(request, str) or not request.strip():
      return "`request` must be a non-empty string."
    if len(request) > int(self.cfg_max_request_chars):
      return f"`request` is too long; max {self.cfg_max_request_chars} characters."
    return None

  @BasePlugin.endpoint(method="GET")
  def health(self) -> Dict[str, Any]:
    local_base = self._local_llm_url(path="/health")
    return {
      "status": STATUS_OK,
      "version": __VER__,
      "model": self.cfg_local_llm_model,
      "schema_version": SCHEMA_VERSION,
      "schema_retry_limit": self.cfg_schema_retry_limit,
      "local_llm_api_url": self._redact_url(local_base),
      "local_llm_api_configured": bool(local_base),
      "auth_token_configured": self._local_api_token is not None,
      "metrics": {
        "total_requests": self._request_count,
        "failed_requests": self._error_count,
        "last_request_time": self._last_request_time,
      },
    }

  @BasePlugin.endpoint(method="GET")
  def model(self) -> Dict[str, Any]:
    return {
      "display_name": EDGEGUARD_MODEL_DISPLAY_NAME,
      "model_repo": EDGEGUARD_MODEL_REPO,
      "model_file": EDGEGUARD_MODEL_FILE,
      "format": "GGUF",
      "quantization": "Q4_K_M",
      "base_model": "Qwen/Qwen3-4B-Instruct-2507",
      "continuation_of": "ratio1/edgeguard-cypher-qwen3-4b-v0.4-gguf",
      "artifact_sha256": EDGEGUARD_MODEL_ARTIFACT_SHA256,
      "schema_version": SCHEMA_VERSION,
      "schema": canonical_schema_surface(),
      "guard": {
        "read_only_static": True,
        "schema_compatible": True,
        "retry_limit": self.cfg_schema_retry_limit,
        "output_contract": "one Cypher query string only",
      },
      "quality": {
        "training_method": "QLoRA SFT",
        "dataset": "qwen-prompt-cypher-v0.5.3-generated-live-anchor-correction",
        "source_adapter": "EGM-013 v0.5.3",
        "source_adapter_sha256": EDGEGUARD_SOURCE_ADAPTER_SHA256,
        "generated_live_with_live_repair": "30 / 38 = 78.95%",
        "generated_live_with_empty_result_broadening": EDGEGUARD_RUNTIME_LIVE_GATE_RESULT,
        "planner_failures": 0,
        "scalar_projection_regressions": 0,
        "promotion_status": "Runtime harness passes the 80% generated-live extractable-graph gate; semantic-fidelity review is still required before production promotion.",
        "known_limits": [
          "Must run behind schema/read-only guard.",
          "The v0.5.10 live-retry and empty-result broadening harness is required to reproduce 34/38; it is not baked into the GGUF weights.",
          "Unsupported temporal predicates are mapped to the closest supported query without invented time fields.",
          "Deterministic broadening improves graph extractability but can be semantically wider than the original request.",
        ],
      },
      "runtime_harness": {
        "version": EDGEGUARD_RUNTIME_HARNESS_VERSION,
        "empty_result_broadening": True,
        "empty_result_broadening_strategy": "first_allowed_label_first_allowed_relationship_type",
        "weights_note": "The deployed GGUF weights are still the v0.5 preview artifact; the 34/38 result depends on backend runtime handling.",
      },
      "resources": {
        "cpu_target": "4 CPU threads",
        "context_length": 4096,
        "artifact_size_bytes": 2497278816,
      },
    }

  @BasePlugin.endpoint(method="POST")
  def generate(
    self,
    request: str,
    retry_limit: Optional[int] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    top_p: Optional[float] = None,
    **kwargs,
  ) -> Dict[str, Any]:
    err = self._validate_request(request)
    if err:
      self._error_count += 1
      return {"status": STATUS_ERROR, "accepted": False, "error": err, "attempts": []}

    retries = int(self.cfg_schema_retry_limit if retry_limit is None else retry_limit)
    retries = max(0, min(retries, int(self.cfg_schema_retry_limit)))
    attempts = []
    messages = [
      {"role": "system", "content": build_direct_cypher_system_prompt()},
      {"role": "user", "content": request.strip()},
    ]
    last_feedback = ""
    last_candidate = ""
    model = self.cfg_local_llm_model

    for attempt_idx in range(retries + 1):
      kind = "initial" if attempt_idx == 0 else "schema_correction"
      if attempt_idx > 0:
        messages = [
          {"role": "system", "content": build_direct_cypher_system_prompt()},
          {
            "role": "user",
            "content": build_schema_correction_prompt(
              original_user_prompt=request.strip(),
              rejected_cypher=last_candidate,
              validation_feedback=last_feedback,
              retry_index=attempt_idx,
              retry_limit=retries,
            ),
          },
        ]
      payload = self._build_payload(messages, temperature, max_tokens, top_p)
      response = self._call_local_llm_api(payload)
      if response.get("status") in {STATUS_ERROR, STATUS_TIMEOUT, "config_error"}:
        return {
          "status": response.get("status", STATUS_ERROR),
          "accepted": False,
          "error": response.get("error", "LLM provider error"),
          "provider": response.get("provider", "local"),
          "attempts": attempts,
        }
      model = response.get("model") or model
      raw_output = self._extract_content(response)
      analysis = analyze_generated_cypher(raw_output)
      attempts.append(self._attempt_record(attempt_idx, kind, raw_output, analysis))
      if analysis["accepted"]:
        return {
          "status": STATUS_ACCEPTED,
          "accepted": True,
          "accepted_cypher": analysis["accepted_cypher"],
          "attempts": attempts,
          "model": model,
          "provider": response.get("provider", "local"),
          "schema_version": SCHEMA_VERSION,
        }
      last_feedback = analysis["validation_feedback"]
      last_candidate = analysis["candidate"]

    self._error_count += 1
    return {
      "status": STATUS_REJECTED,
      "accepted": False,
      "accepted_cypher": None,
      "attempts": attempts,
      "model": model,
      "provider": "local",
      "schema_version": SCHEMA_VERSION,
      "validation_feedback": last_feedback,
    }
