import unittest
import sys
from unittest.mock import MagicMock, patch

def mock_plugin_modules():
  def endpoint_decorator(*args, **kwargs):
    if args and callable(args[0]):
      return args[0]
    def wrapper(fn):
      return fn
    return wrapper

  class FakeBasePlugin:
    CONFIG = {'VALIDATION_RULES': {}}
    endpoint = staticmethod(endpoint_decorator)

  class FakeModule:
    FastApiWebAppPlugin = FakeBasePlugin

  sys.modules.setdefault('naeural_core', type(sys)('naeural_core'))
  sys.modules.setdefault('naeural_core.business', type(sys)('naeural_core.business'))
  sys.modules.setdefault('naeural_core.business.default', type(sys)('naeural_core.business.default'))
  sys.modules.setdefault('naeural_core.business.default.web_app', type(sys)('naeural_core.business.default.web_app'))
  sys.modules['naeural_core.business.default.web_app.fast_api_web_app'] = FakeModule()


mock_plugin_modules()

from extensions.business.cybersec.red_mesh.edgeguard_api import EdgeguardApiPlugin  # noqa: E402
from extensions.business.cybersec.red_mesh.edgeguard_llm_agent_api import (  # noqa: E402
  EdgeguardLlmAgentApiPlugin,
)


class _Response:
  def __init__(self, status_code=200, payload=None, text=""):
    self.status_code = status_code
    self._payload = payload or {}
    self.text = text

  def json(self):
    return self._payload


class _Result(list):
  def keys(self):
    return ["value"]


def _make_agent(**overrides):
  plugin = EdgeguardLlmAgentApiPlugin.__new__(EdgeguardLlmAgentApiPlugin)
  plugin.cfg_local_llm_api_url = overrides.get("local_llm_api_url")
  plugin.cfg_local_llm_api_host = overrides.get("local_llm_api_host", "127.0.0.1")
  plugin.cfg_local_llm_api_port = overrides.get("local_llm_api_port", 5090)
  plugin.cfg_local_llm_api_path = overrides.get("local_llm_api_path", "/create_chat_completion")
  plugin.cfg_local_llm_api_token = overrides.get("local_llm_api_token")
  plugin.cfg_local_llm_api_token_env = overrides.get("local_llm_api_token_env", "LLM_API_TOKEN")
  plugin.cfg_local_llm_model = overrides.get(
    "local_llm_model",
    "edgeguard-cypher-qwen3-4b-v0.4.Q4_K_M.gguf",
  )
  plugin.cfg_default_temperature = overrides.get("default_temperature", 0.0)
  plugin.cfg_default_max_tokens = overrides.get("default_max_tokens", 512)
  plugin.cfg_default_top_p = overrides.get("default_top_p", 1.0)
  plugin.cfg_schema_retry_limit = overrides.get("schema_retry_limit", 2)
  plugin.cfg_max_request_chars = overrides.get("max_request_chars", 4000)
  plugin.cfg_request_timeout_seconds = overrides.get("request_timeout_seconds", 120)
  plugin.cfg_edgeguard_verbose = 0
  plugin.os_environ = overrides.get("os_environ", {})
  plugin._local_api_token = overrides.get("local_api_token")
  plugin._request_count = 0
  plugin._error_count = 0
  plugin._last_request_time = None
  plugin.time = lambda: 1000
  plugin.P = lambda *_args, **_kwargs: None
  plugin.Pd = lambda *_args, **_kwargs: None
  return plugin


def _make_api(**overrides):
  plugin = EdgeguardApiPlugin.__new__(EdgeguardApiPlugin)
  plugin.cfg_edgeguard_llm_agent_url = overrides.get("edgeguard_llm_agent_url")
  plugin.cfg_edgeguard_llm_agent_host = overrides.get("edgeguard_llm_agent_host", "127.0.0.1")
  plugin.cfg_edgeguard_llm_agent_port = overrides.get("edgeguard_llm_agent_port", 5060)
  plugin.cfg_edgeguard_llm_agent_path = overrides.get("edgeguard_llm_agent_path", "/generate")
  plugin.cfg_edgeguard_llm_agent_token = overrides.get("edgeguard_llm_agent_token")
  plugin.cfg_edgeguard_llm_agent_token_env = overrides.get("edgeguard_llm_agent_token_env", "EDGEGUARD_LLM_AGENT_TOKEN")
  plugin.cfg_neo4j_max_rows = overrides.get("neo4j_max_rows", 100)
  plugin.cfg_neo4j_query_timeout_seconds = overrides.get("neo4j_query_timeout_seconds", 30)
  plugin.cfg_request_timeout_seconds = overrides.get("request_timeout_seconds", 120)
  plugin.cfg_edgeguard_verbose = 0
  plugin.os_environ = overrides.get("os_environ", {})
  plugin._agent_token = overrides.get("agent_token")
  plugin._request_count = 0
  plugin._error_count = 0
  plugin._last_request_time = None
  plugin.time = lambda: 1000
  plugin.P = lambda *_args, **_kwargs: None
  plugin.Pd = lambda *_args, **_kwargs: None
  return plugin


class EdgeGuardAgentTests(unittest.TestCase):
  def test_agent_accepts_valid_first_output(self):
    plugin = _make_agent()
    payload = {
      "model": "edgeguard_qwen_4b",
      "choices": [{
        "message": {
          "content": "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10",
        },
      }],
    }

    with patch(
      "extensions.business.cybersec.red_mesh.edgeguard_llm_agent_api.requests.post",
      return_value=_Response(payload=payload),
    ) as mocked_post:
      result = plugin.generate(request="Show indicators")

    self.assertTrue(result["accepted"])
    self.assertEqual(result["status"], "accepted")
    self.assertEqual(len(result["attempts"]), 1)
    self.assertEqual(
      result["accepted_cypher"],
      "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10",
    )
    call_payload = mocked_post.call_args.kwargs["json"]
    self.assertEqual(call_payload["temperature"], 0.0)
    self.assertIn("Allowed EdgeGuard Cypher schema", call_payload["messages"][0]["content"])

  def test_agent_retries_after_schema_rejection(self):
    plugin = _make_agent()
    responses = [
      _Response(payload={
        "choices": [{
          "message": {
            "content": "MATCH (i:InternetFacing) WHERE i.cve IS NOT NULL RETURN i.hostname AS hostname",
          },
        }],
      }),
      _Response(payload={
        "choices": [{
          "message": {
            "content": "MATCH (v:Vulnerability) RETURN v.cve_id AS cve_id, v.severity AS severity LIMIT 10",
          },
        }],
      }),
    ]

    with patch(
      "extensions.business.cybersec.red_mesh.edgeguard_llm_agent_api.requests.post",
      side_effect=responses,
    ) as mocked_post:
      result = plugin.generate(request="Show internet-facing assets with critical vulnerabilities")

    self.assertTrue(result["accepted"])
    self.assertEqual(len(result["attempts"]), 2)
    self.assertEqual(result["attempts"][1]["kind"], "schema_correction")
    retry_prompt = mocked_post.call_args_list[1].kwargs["json"]["messages"][1]["content"]
    self.assertIn("Unknown labels: InternetFacing", retry_prompt)

  def test_agent_rejects_after_retry_limit(self):
    plugin = _make_agent(schema_retry_limit=1)

    with patch(
      "extensions.business.cybersec.red_mesh.edgeguard_llm_agent_api.requests.post",
      return_value=_Response(payload={
        "choices": [{"message": {"content": "Here is the query: MATCH (i:Indicator) RETURN i.value"}}],
      }),
    ):
      result = plugin.generate(request="Show indicators")

    self.assertFalse(result["accepted"])
    self.assertEqual(result["status"], "rejected")
    self.assertEqual(len(result["attempts"]), 2)


class EdgeGuardApiTests(unittest.TestCase):
  def test_edgeguard_ai_engine_is_registered(self):
    from extensions.serving.ai_engines.stable import AI_ENGINES

    self.assertEqual(
      AI_ENGINES["edgeguard_qwen_4b"],
      {"SERVING_PROCESS": "llama_cpp_edgeguard_qwen_4b"},
    )

  def test_api_revalidates_agent_accepted_cypher(self):
    plugin = _make_api()
    agent_payload = {
      "status": "accepted",
      "accepted": True,
      "accepted_cypher": "MATCH (i:InternetFacing) RETURN i.hostname AS hostname",
      "attempts": [],
    }

    with patch(
      "extensions.business.cybersec.red_mesh.edgeguard_api.requests.post",
      return_value=_Response(payload=agent_payload),
    ):
      result = plugin.generate(request="Show hosts")

    self.assertFalse(result["accepted"])
    self.assertEqual(result["status"], "rejected")
    self.assertIsNone(result["accepted_cypher"])
    self.assertIn("api_revalidation", result)

  def test_api_validate_accepts_schema_query(self):
    plugin = _make_api()

    result = plugin.validate(cypher="MATCH (i:Indicator) RETURN i.value AS value LIMIT 10")

    self.assertEqual(result["status"], "accepted")
    self.assertTrue(result["accepted"])

  def test_neo4j_query_rejects_invalid_cypher_without_driver(self):
    plugin = _make_api()

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      result = plugin.neo4j_query(
        uri="example.com:7687",
        scheme="bolt+s",
        username="neo4j",
        password="secret",
        cypher="MATCH (i:InternetFacing) RETURN i.hostname AS hostname",
      )

    self.assertFalse(result["executed"])
    self.assertEqual(result["status"], "rejected")
    mocked_driver.assert_not_called()

  def test_neo4j_query_uses_driver_for_accepted_cypher(self):
    plugin = _make_api()
    fake_record = MagicMock()
    fake_record.data.return_value = {"value": "1.2.3.4"}
    fake_result = _Result([fake_record])
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.return_value = fake_result
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.red_mesh.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver) as mocked_driver:
        result = plugin.neo4j_query(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:Indicator) RETURN i.value AS value LIMIT 10",
        )

    self.assertTrue(result["executed"])
    self.assertEqual(result["rows"], [{"value": "1.2.3.4"}])
    mocked_driver.assert_called_once()
    fake_session.run.assert_called_once_with("MATCH (i:Indicator) RETURN i.value AS value LIMIT 10")
    fake_driver.close.assert_called_once()
