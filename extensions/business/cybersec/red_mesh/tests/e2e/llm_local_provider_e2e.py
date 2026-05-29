#!/usr/bin/env python3
"""
E2E-style smoke test for RedMesh local LLM provider routing.

This does not download or run the GGUF model. Instead, it starts a local HTTP
server that mimics the LLM_INFERENCE_API contract and verifies the RedMesh LLM
agent uses that local endpoint for /chat and /analyze_scan without relying on
DeepSeek credentials or network access.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[6]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

from extensions.business.cybersec.red_mesh.tests.conftest import mock_plugin_modules  # noqa: E402


mock_plugin_modules()

from extensions.business.cybersec.red_mesh.redmesh_llm_agent_api import (  # noqa: E402
  RedMeshLlmAgentApiPlugin,
)


class _FakeLlmInferenceHandler(BaseHTTPRequestHandler):
  requests_seen = []

  def _send_json(self, status_code: int, payload: dict):
    body = json.dumps(payload).encode("utf-8")
    self.send_response(status_code)
    self.send_header("Content-Type", "application/json")
    self.send_header("Content-Length", str(len(body)))
    self.end_headers()
    self.wfile.write(body)

  def do_GET(self):  # noqa: N802
    if self.path == "/health":
      self._send_json(200, {
        "status": "ok",
        "model": "cybersec_qwen_4b",
        "token": "seeded-health-token",
        "prompt": "seeded raw prompt",
      })
      return
    self._send_json(404, {"error": "not found"})

  def do_POST(self):  # noqa: N802
    raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
    payload = json.loads(raw.decode("utf-8") or "{}")
    self.requests_seen.append({
      "path": self.path,
      "payload": payload,
      "authorization": self.headers.get("Authorization"),
    })
    content = "local e2e response"
    if payload.get("metadata", {}).get("source") == "redmesh_llm_agent_api":
      content = "local e2e analysis"
    self._send_json(200, {
      "id": "local-e2e-1",
      "model": "cybersec_qwen_4b",
      "choices": [
        {
          "index": 0,
          "message": {"role": "assistant", "content": content},
          "finish_reason": "stop",
        }
      ],
      "usage": {"prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10},
    })

  def log_message(self, *_args):
    return


def _make_plugin(port: int):
  plugin = RedMeshLlmAgentApiPlugin.__new__(RedMeshLlmAgentApiPlugin)
  plugin.cfg_llm_provider = "local"
  plugin.cfg_local_llm_api_url = None
  plugin.cfg_local_llm_api_host = "127.0.0.1"
  plugin.cfg_local_llm_api_port = port
  plugin.cfg_local_llm_api_path = "/create_chat_completion"
  plugin.cfg_local_llm_api_token = None
  plugin.cfg_local_llm_api_token_env = "LLM_API_TOKEN"
  plugin.cfg_local_llm_model = "CyberSecQwen-4B.Q4_K_M.gguf"
  plugin.cfg_local_llm_max_tokens = 4096
  plugin.cfg_deepseek_api_url = "https://should-not-be-called.invalid/chat/completions"
  plugin.cfg_deepseek_api_key = None
  plugin.cfg_deepseek_api_key_env = "DEEPSEEK_API_KEY"
  plugin.cfg_remote_llm_model = "deepseek-chat"
  plugin.cfg_deepseek_model = "deepseek-chat"
  plugin.cfg_default_temperature = 0.7
  plugin.cfg_default_max_tokens = 1024
  plugin.cfg_default_top_p = 1.0
  plugin.cfg_request_timeout_seconds = 10
  plugin.cfg_redmesh_verbose = 0
  plugin.os_environ = {}
  plugin._provider = plugin._normalize_provider(plugin.cfg_llm_provider)
  plugin._api_key = None
  plugin._local_api_token = None
  plugin._request_count = 0
  plugin._error_count = 0
  plugin._last_request_time = None
  plugin.start_time = 900
  plugin.time = lambda: 1000
  plugin.P = lambda *_args, **_kwargs: None
  plugin.Pd = lambda *_args, **_kwargs: None
  return plugin


def main() -> int:
  _FakeLlmInferenceHandler.requests_seen = []
  server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeLlmInferenceHandler)
  thread = threading.Thread(target=server.serve_forever, daemon=True)
  thread.start()
  try:
    plugin = _make_plugin(server.server_port)

    health = plugin.health()
    assert health["status"] == "ok", health
    assert health["provider"] == "local", health
    assert health["available"] is True, health
    assert "seeded-health-token" not in str(health), health
    assert "seeded raw prompt" not in str(health), health

    chat = plugin.chat(messages=[{"role": "user", "content": "hello"}], max_tokens=9000)
    assert chat["provider"] == "local", chat
    assert chat["choices"][0]["message"]["content"] == "local e2e analysis", chat

    analysis = plugin.analyze_scan(
      scan_results={"open_ports": [80], "service_info": {"80": {"service": "http"}}},
      analysis_type="quick_summary",
    )
    assert analysis["provider"] == "local", analysis
    assert analysis["content"] == "local e2e analysis", analysis
    assert analysis["scan_summary"]["open_ports"] == 1, analysis

    seen = _FakeLlmInferenceHandler.requests_seen
    assert len(seen) == 2, seen
    assert all(item["path"] == "/create_chat_completion" for item in seen), seen
    assert all(item["authorization"] is None for item in seen), seen
    assert all(item["payload"]["max_tokens"] <= 4096 for item in seen), seen
    print("OK local RedMesh LLM provider e2e")
    return 0
  finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


if __name__ == "__main__":
  raise SystemExit(main())
