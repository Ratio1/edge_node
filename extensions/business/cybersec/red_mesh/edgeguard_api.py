"""EdgeGuard playground API plugin.

The API exposes model metadata, guarded generation, local validation, and
request-scoped Neo4j connection/query helpers for the colleague playground.
"""

from __future__ import annotations

import traceback
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

from .edgeguard_cypher_guard import (
  SCHEMA_VERSION,
  analyze_generated_cypher,
  build_empty_result_broadening_cypher,
  canonical_schema_surface,
)
from .edgeguard_llm_agent_api import (
  EDGEGUARD_MODEL_ARTIFACT_SHA256,
  EDGEGUARD_MODEL_DISPLAY_NAME,
  EDGEGUARD_MODEL_FILE,
  EDGEGUARD_MODEL_REPO,
  EDGEGUARD_RUNTIME_HARNESS_VERSION,
  EDGEGUARD_RUNTIME_LIVE_GATE_RESULT,
  EDGEGUARD_SOURCE_ADAPTER_SHA256,
  STATUS_ACCEPTED,
  STATUS_ERROR,
  STATUS_OK,
  STATUS_REJECTED,
)

try:
  from neo4j import GraphDatabase
except Exception:  # pragma: no cover - exercised through dependency-missing tests.
  GraphDatabase = None

__VER__ = '0.1.0.0'

NEO4J_SCHEMES = {"bolt", "bolt+s", "neo4j", "neo4j+s"}


_CONFIG = {
  **BasePlugin.CONFIG,

  "TUNNEL_ENGINE_ENABLED": False,
  "ALLOW_EMPTY_INPUTS": True,
  "RESPONSE_FORMAT": "RAW",
  "PORT": None,

  "API_TITLE": "EdgeGuard API",
  "API_SUMMARY": "Guarded EdgeGuard text-to-Cypher and playground Neo4j API.",

  "EDGEGUARD_LLM_AGENT_URL": None,
  "EDGEGUARD_LLM_AGENT_HOST": "127.0.0.1",
  "EDGEGUARD_LLM_AGENT_PORT": None,
  "EDGEGUARD_LLM_AGENT_PATH": "/generate",
  "EDGEGUARD_LLM_AGENT_TOKEN": None,
  "EDGEGUARD_LLM_AGENT_TOKEN_ENV": "EDGEGUARD_LLM_AGENT_TOKEN",

  "NEO4J_MAX_ROWS": 100,
  "NEO4J_QUERY_TIMEOUT_SECONDS": 30,
  "LIVE_EMPTY_RESULT_BROADENING": True,
  "REQUEST_TIMEOUT_SECONDS": 120,
  "EDGEGUARD_VERBOSE": 10,

  'VALIDATION_RULES': {
    **BasePlugin.CONFIG['VALIDATION_RULES'],
  },
}


class EdgeguardApiPlugin(BasePlugin):
  CONFIG = _CONFIG

  def on_init(self):
    super(EdgeguardApiPlugin, self).on_init()
    self._request_count = 0
    self._error_count = 0
    self._last_request_time = None
    self._agent_token = self._resolve_secret(
      explicit=self.cfg_edgeguard_llm_agent_token,
      env_name=self.cfg_edgeguard_llm_agent_token_env,
    )
    return

  def _setup_semaphore_env(self):
    """Set semaphore environment variables for paired UI/container plugins."""
    super(EdgeguardApiPlugin, self)._setup_semaphore_env()
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

  def _agent_url(self, path: Optional[str] = None) -> Optional[str]:
    endpoint = path if path is not None else self.cfg_edgeguard_llm_agent_path
    endpoint = str(endpoint or "/generate").strip()
    if not endpoint.startswith("/"):
      endpoint = "/" + endpoint
    configured_url = self.cfg_edgeguard_llm_agent_url
    if configured_url:
      url = str(configured_url).rstrip("/")
      if url.endswith(endpoint):
        return url
      return url + endpoint
    host = self.cfg_edgeguard_llm_agent_host
    port = self.cfg_edgeguard_llm_agent_port
    if not host or not port:
      return None
    return f"http://{host}:{int(port)}{endpoint}"

  def _headers(self) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if self._agent_token:
      headers["Authorization"] = f"Bearer {self._agent_token}"
    return headers

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

  def _sanitize_error(self, error: Exception | str, secret: str = "") -> str:
    message = str(error)
    if secret:
      message = message.replace(secret, "<redacted>")
    return message

  @BasePlugin.endpoint(method="GET")
  def health(self) -> Dict[str, Any]:
    agent_url = self._agent_url()
    return {
      "status": STATUS_OK,
      "version": __VER__,
      "schema_version": SCHEMA_VERSION,
      "model_repo": EDGEGUARD_MODEL_REPO,
      "model_file": EDGEGUARD_MODEL_FILE,
      "agent_url": self._redact_url(agent_url),
      "agent_configured": bool(agent_url),
      "neo4j_driver_available": GraphDatabase is not None,
      "live_empty_result_broadening": bool(self.cfg_live_empty_result_broadening),
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
        "execution_revalidates": True,
        "live_empty_result_broadening": bool(self.cfg_live_empty_result_broadening),
        "live_empty_result_broadening_strategy": "first_allowed_label_first_allowed_relationship_type",
        "output_contract": "one Cypher query string only",
      },
      "fine_tuning": {
        "method": "QLoRA SFT",
        "dataset": "qwen-prompt-cypher-v0.5.3-generated-live-anchor-correction",
        "source_adapter": "EGM-013 v0.5.3",
        "source_adapter_sha256": EDGEGUARD_SOURCE_ADAPTER_SHA256,
      },
      "quality": {
        "generated_live_with_live_repair": "30 / 38 = 78.95%",
        "generated_live_with_empty_result_broadening": EDGEGUARD_RUNTIME_LIVE_GATE_RESULT,
        "planner_failures": 0,
        "scalar_projection_regressions": 0,
        "promotion_status": "Runtime harness passes the 80% generated-live extractable-graph gate; semantic-fidelity review is still required before production promotion.",
        "live_repair_note": "The v0.5.10 live-retry and empty-result broadening harness is required to reproduce 34/38; it is not baked into the GGUF weights.",
        "semantic_fidelity_risk": "Deterministic broadening can return a wider graph than the original request when the first live query is empty.",
      },
      "runtime_harness": {
        "version": EDGEGUARD_RUNTIME_HARNESS_VERSION,
        "empty_result_broadening": bool(self.cfg_live_empty_result_broadening),
        "empty_result_broadening_strategy": "first_allowed_label_first_allowed_relationship_type",
        "weights_note": "The deployed GGUF weights are still the v0.5 preview artifact; the 34/38 result depends on backend runtime handling.",
      },
    }

  @BasePlugin.endpoint(method="POST")
  def check_cypher(self, cypher: str, **kwargs) -> Dict[str, Any]:
    analysis = analyze_generated_cypher(cypher)
    return {
      "status": STATUS_ACCEPTED if analysis["accepted"] else STATUS_REJECTED,
      **analysis,
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
    self._request_count += 1
    self._last_request_time = self.time()
    agent_url = self._agent_url()
    if not agent_url:
      self._error_count += 1
      return {
        "status": "config_error",
        "accepted": False,
        "error": "EdgeGuard LLM agent port or URL not configured",
      }
    payload = {
      "request": request,
      "retry_limit": retry_limit,
      "temperature": temperature,
      "max_tokens": max_tokens,
      "top_p": top_p,
    }
    try:
      response = requests.post(
        agent_url,
        headers=self._headers(),
        json=payload,
        timeout=self.cfg_request_timeout_seconds,
      )
      if response.status_code != 200:
        self._error_count += 1
        return {
          "status": STATUS_ERROR,
          "accepted": False,
          "error": f"EdgeGuard LLM agent returned status {response.status_code}",
        }
      result = response.json()
      accepted_cypher = result.get("accepted_cypher")
      if result.get("accepted") and accepted_cypher:
        analysis = analyze_generated_cypher(accepted_cypher)
        if not analysis["accepted"]:
          self._error_count += 1
          result["status"] = STATUS_REJECTED
          result["accepted"] = False
          result["accepted_cypher"] = None
          result["api_revalidation"] = analysis
          result["validation_feedback"] = analysis["validation_feedback"]
      return result
    except requests.exceptions.Timeout:
      self._error_count += 1
      return {"status": "timeout", "accepted": False, "error": "EdgeGuard LLM agent request timed out"}
    except requests.exceptions.RequestException as exc:
      self._error_count += 1
      return {"status": STATUS_ERROR, "accepted": False, "error": str(exc)}
    except Exception as exc:
      self._error_count += 1
      self.P(f"Unexpected EdgeGuard API generation error: {exc}\n{traceback.format_exc()}", color='r')
      return {"status": STATUS_ERROR, "accepted": False, "error": f"Unexpected error: {exc}"}

  def _normalize_neo4j_uri(self, uri: str, scheme: str = "bolt+s") -> tuple[Optional[str], Optional[str]]:
    if not isinstance(uri, str) or not uri.strip():
      return None, "`uri` must be a non-empty string."
    selected_scheme = str(scheme or "bolt+s").strip()
    if selected_scheme not in NEO4J_SCHEMES:
      return None, f"`scheme` must be one of {sorted(NEO4J_SCHEMES)}."
    normalized = uri.strip()
    if "://" not in normalized:
      normalized = f"{selected_scheme}://{normalized}"
    parsed = urlsplit(normalized)
    if parsed.scheme not in NEO4J_SCHEMES:
      return None, f"Neo4j URI scheme must be one of {sorted(NEO4J_SCHEMES)}."
    if parsed.scheme != selected_scheme:
      return None, "`scheme` must match the URI scheme."
    if not parsed.hostname:
      return None, "Neo4j URI must include a host."
    return normalized, None

  def _neo4j_unavailable(self) -> Dict[str, Any]:
    return {
      "status": STATUS_ERROR,
      "ok": False,
      "error": "Neo4j Python driver is not installed in this edge-node runtime.",
    }

  def _neo4j_driver(self, uri: str, username: str, password: str):
    if GraphDatabase is None:
      return None
    return GraphDatabase.driver(uri, auth=(username, password))

  def _close_neo4j_driver(self, driver) -> None:
    if driver is None:
      return
    try:
      driver.close()
    except Exception as exc:
      self.Pd(f"Failed to close Neo4j driver cleanly: {exc}", color='y')

  def _run_neo4j_query(self, driver, cypher: str, row_limit: int) -> Dict[str, Any]:
    rows = []
    columns = []
    with driver.session() as session:
      result = session.run(cypher)
      columns = list(getattr(result, "keys", lambda: [])())
      for idx, record in enumerate(result):
        if idx >= row_limit:
          break
        rows.append(record.data() if hasattr(record, "data") else dict(record))
    return {
      "columns": columns,
      "rows": rows,
      "row_count": len(rows),
      "truncated": len(rows) >= row_limit,
    }

  def _empty_result_broadening_state(
    self,
    enabled: bool,
    attempted: bool = False,
    applied: bool = False,
    reason: Optional[str] = None,
    strategy: Optional[str] = None,
    broadening_cypher: Optional[str] = None,
    error: Optional[str] = None,
  ) -> Dict[str, Any]:
    return {
      "enabled": enabled,
      "attempted": attempted,
      "applied": applied,
      "reason": reason,
      "strategy": "deterministic_empty_result_broadening" if applied else None,
      "deterministic_empty_result_broadening_strategy": strategy,
      "broadening_cypher": broadening_cypher,
      "error": error,
    }

  @BasePlugin.endpoint(method="POST")
  def neo4j_test(
    self,
    uri: str,
    username: str,
    password: str,
    scheme: str = "bolt+s",
    **kwargs,
  ) -> Dict[str, Any]:
    normalized_uri, err = self._normalize_neo4j_uri(uri, scheme)
    if err:
      return {"status": STATUS_ERROR, "ok": False, "error": err}
    if not username or not password:
      return {"status": STATUS_ERROR, "ok": False, "error": "Neo4j username and password are required."}
    if GraphDatabase is None:
      return self._neo4j_unavailable()
    driver = None
    try:
      driver = self._neo4j_driver(normalized_uri, username, password)
      with driver.session() as session:
        record = session.run("RETURN 1 AS ok").single()
      return {
        "status": STATUS_OK,
        "ok": bool(record and record.get("ok") == 1),
        "uri": self._redact_url(normalized_uri),
      }
    except Exception as exc:
      return {"status": STATUS_ERROR, "ok": False, "error": self._sanitize_error(exc, password)}
    finally:
      self._close_neo4j_driver(driver)

  @BasePlugin.endpoint(method="POST")
  def neo4j_query(
    self,
    uri: str,
    username: str,
    password: str,
    cypher: str,
    scheme: str = "bolt+s",
    max_rows: Optional[int] = None,
    enable_empty_result_broadening: Optional[bool] = None,
    **kwargs,
  ) -> Dict[str, Any]:
    analysis = analyze_generated_cypher(cypher)
    if not analysis["accepted"]:
      return {
        "status": STATUS_REJECTED,
        "ok": False,
        "executed": False,
        "validation": analysis,
        "error": "Cypher rejected by EdgeGuard guard; query was not executed.",
      }
    normalized_uri, err = self._normalize_neo4j_uri(uri, scheme)
    if err:
      return {"status": STATUS_ERROR, "ok": False, "executed": False, "error": err}
    if not username or not password:
      return {
        "status": STATUS_ERROR,
        "ok": False,
        "executed": False,
        "error": "Neo4j username and password are required.",
      }
    if GraphDatabase is None:
      unavailable = self._neo4j_unavailable()
      unavailable["executed"] = False
      return unavailable
    row_limit = max(1, min(int(max_rows or self.cfg_neo4j_max_rows), int(self.cfg_neo4j_max_rows)))
    broadening_enabled = (
      bool(self.cfg_live_empty_result_broadening)
      if enable_empty_result_broadening is None
      else bool(enable_empty_result_broadening)
    )
    driver = None
    try:
      driver = self._neo4j_driver(normalized_uri, username, password)
      query_result = self._run_neo4j_query(driver, analysis["accepted_cypher"], row_limit)
      live_retry = self._empty_result_broadening_state(enabled=broadening_enabled)
      if broadening_enabled and not query_result["rows"]:
        broadened = build_empty_result_broadening_cypher(analysis["accepted_cypher"])
        if broadened is None:
          live_retry = self._empty_result_broadening_state(
            enabled=True,
            attempted=True,
            reason="empty_result_without_allowed_label_relationship_pair",
          )
        else:
          try:
            query_result = self._run_neo4j_query(driver, broadened["cypher"], row_limit)
            live_retry = self._empty_result_broadening_state(
              enabled=True,
              attempted=True,
              applied=True,
              reason="executed_no_rows",
              strategy=broadened["strategy"],
              broadening_cypher=broadened["cypher"],
            )
          except Exception as exc:
            live_retry = self._empty_result_broadening_state(
              enabled=True,
              attempted=True,
              reason="broadening_execution_failed",
              strategy=broadened["strategy"],
              broadening_cypher=broadened["cypher"],
              error=self._sanitize_error(exc, password),
            )
      return {
        "status": STATUS_OK,
        "ok": True,
        "executed": True,
        **query_result,
        "validation": analysis,
        "live_retry": live_retry,
      }
    except Exception as exc:
      return {
        "status": STATUS_ERROR,
        "ok": False,
        "executed": False,
        "error": self._sanitize_error(exc, password),
        "validation": analysis,
      }
    finally:
      self._close_neo4j_driver(driver)
