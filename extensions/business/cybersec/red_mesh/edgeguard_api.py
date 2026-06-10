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
  canonical_schema_surface,
)
from .edgeguard_llm_agent_api import (
  EDGEGUARD_MODEL_FILE,
  EDGEGUARD_MODEL_REPO,
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
      "metrics": {
        "total_requests": self._request_count,
        "failed_requests": self._error_count,
        "last_request_time": self._last_request_time,
      },
    }

  @BasePlugin.endpoint(method="GET")
  def model(self) -> Dict[str, Any]:
    return {
      "model_repo": EDGEGUARD_MODEL_REPO,
      "model_file": EDGEGUARD_MODEL_FILE,
      "format": "GGUF",
      "quantization": "Q4_K_M",
      "base_model": "Qwen/Qwen3-4B-Instruct-2507",
      "schema_version": SCHEMA_VERSION,
      "schema": canonical_schema_surface(),
      "guard": {
        "read_only_static": True,
        "schema_compatible": True,
        "execution_revalidates": True,
        "output_contract": "one Cypher query string only",
      },
      "fine_tuning": {
        "method": "QLoRA SFT",
        "dataset": "qwen-prompt-cypher-v0.4",
        "source_adapter_sha256": "cfa7d84b71b95e076f6d7e85719db1da39e65812cb84b489255a49b31fd4f2e8",
      },
      "quality": {
        "combined_post_retry_acceptance": "2386 / 2410",
        "final_rejects_after_two_retries": 24,
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
      if driver is not None:
        driver.close()

  @BasePlugin.endpoint(method="POST")
  def neo4j_query(
    self,
    uri: str,
    username: str,
    password: str,
    cypher: str,
    scheme: str = "bolt+s",
    max_rows: Optional[int] = None,
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
    driver = None
    try:
      driver = self._neo4j_driver(normalized_uri, username, password)
      rows = []
      columns = []
      with driver.session() as session:
        result = session.run(analysis["accepted_cypher"])
        columns = list(getattr(result, "keys", lambda: [])())
        for idx, record in enumerate(result):
          if idx >= row_limit:
            break
          rows.append(record.data() if hasattr(record, "data") else dict(record))
      return {
        "status": STATUS_OK,
        "ok": True,
        "executed": True,
        "columns": columns,
        "rows": rows,
        "row_count": len(rows),
        "truncated": len(rows) >= row_limit,
        "validation": analysis,
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
      if driver is not None:
        driver.close()
