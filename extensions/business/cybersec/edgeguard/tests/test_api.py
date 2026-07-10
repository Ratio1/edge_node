import json
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
    def _setup_semaphore_env(self):
      return

  class FakeModule:
    FastApiWebAppPlugin = FakeBasePlugin

  sys.modules.setdefault('naeural_core', type(sys)('naeural_core'))
  sys.modules.setdefault('naeural_core.business', type(sys)('naeural_core.business'))
  sys.modules.setdefault('naeural_core.business.default', type(sys)('naeural_core.business.default'))
  sys.modules.setdefault('naeural_core.business.default.web_app', type(sys)('naeural_core.business.default.web_app'))
  sys.modules['naeural_core.business.default.web_app.fast_api_web_app'] = FakeModule()


mock_plugin_modules()

from extensions.business.cybersec.edgeguard.edgeguard_api import EdgeguardApiPlugin  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_packet_and_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_llm_agent_api import (  # noqa: E402
  EDGEGUARD_REQUEST_TIMEOUT_SECONDS,
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
  def __init__(self, rows=None, keys=None):
    super().__init__(rows or [])
    self._keys = keys or ["value"]

  def keys(self):
    return self._keys


class _GraphNode:
  def __init__(self, element_id, labels, properties):
    self.element_id = element_id
    self.labels = labels
    self._properties = properties

  def items(self):
    return self._properties.items()


class _GraphRelationship:
  def __init__(self, element_id, rel_type, start_node, end_node, properties=None):
    self.element_id = element_id
    self.type = rel_type
    self.start_node = start_node
    self.end_node = end_node
    self._properties = properties or {}

  def items(self):
    return self._properties.items()


class _GraphPath:
  def __init__(self, nodes, relationships):
    self.nodes = nodes
    self.relationships = relationships


def _graph_record():
  indicator = _GraphNode("indicator-1", ["Indicator"], {"value": "example.org", "type": "domain"})
  source = _GraphNode("source-1", ["Source"], {"name": "AlienVault OTX"})
  rel = _GraphRelationship("rel-1", "SOURCED_FROM", indicator, source, {"confidence": "medium"})
  path = _GraphPath([indicator, source], [rel])
  fake_record = MagicMock()
  fake_record.data.return_value = {"p": path}
  return fake_record


def _explanation_for_packet(packet, caveat_types=None):
  caveat_types = list(caveat_types or [])
  nodes = packet["graph"]["nodes"]
  rels = packet["graph"]["relationships"]
  indicator = next(node for node in nodes if "Indicator" in node["labels"])
  source = next(node for node in nodes if "Source" in node["labels"])
  rel = rels[0]
  evidence_ids = [indicator["id"], rel["id"], source["id"]]
  return {
    "schema_version": "edgeguard.case_explanation.v1",
    "summary": {
      "text": "The packet links an indicator to a source.",
      "evidence_ids": evidence_ids,
    },
    "key_paths": [{
      "title": "Indicator source path",
      "path_evidence_ids": evidence_ids,
      "interpretation": "The indicator is present with source provenance in the packet.",
      "confidence": "medium",
    }],
    "entity_findings": [{
      "entity_id": indicator["id"],
      "role": "seed_indicator",
      "finding": "The indicator is present in the graph packet.",
      "evidence_ids": [indicator["id"]],
    }],
    "risk_interpretation": [{
      "claim": "The packet supports a bounded informational finding only.",
      "severity": "informational",
      "evidence_ids": evidence_ids,
      "limits": "The packet does not prove malicious activity by itself.",
    }],
    "provenance": [{
      "source_node_id": source["id"],
      "source_name": "AlienVault OTX",
      "supports": [indicator["id"]],
      "caveat": "Source confidence is inherited only from packet fields.",
    }],
    "caveats": [
      {"type": caveat_type, "message": f"{caveat_type} caveat.", "evidence_ids": []}
      for caveat_type in caveat_types
    ],
    "missing_context": [{
      "gap": "No malware or actor node is present in this packet.",
      "suggested_check": "Run an indicator malware actor neighborhood pivot.",
    }],
    "next_pivots": [{
      "question": "Which malware or actor nodes are linked to this indicator?",
      "suggested_query_intent": "indicator_to_malware_actor_neighborhood",
      "priority": "high",
    }],
  }


def _driver_with_results(*results):
  fake_session = MagicMock()
  fake_session.__enter__.return_value = fake_session
  fake_session.run.side_effect = list(results)
  fake_driver = MagicMock()
  fake_driver.session.return_value = fake_session
  return fake_driver, fake_session


def _provider_response_for_packet(packet, caveat_types=None):
  explanation = _explanation_for_packet(packet, caveat_types=caveat_types)
  return _Response(payload={
    "model": "qwen2.5-1.5b-instruct",
    "choices": [{
      "message": {"content": json.dumps(explanation)},
    }],
  })


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
    "edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf",
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
  plugin.log = MagicMock()
  plugin.log.get_localhost_ip.return_value = "127.0.0.1"
  plugin.port = overrides.get("port", 5060)
  plugin.cfg_port = overrides.get("cfg_port", 5060)
  plugin.semaphore_env = {}
  plugin.semaphore_set_env = lambda key, value: plugin.semaphore_env.__setitem__(key, str(value))
  return plugin


def _make_api(**overrides):
  plugin = EdgeguardApiPlugin.__new__(EdgeguardApiPlugin)
  plugin.cfg_edgeguard_llm_agent_url = overrides.get("edgeguard_llm_agent_url")
  plugin.cfg_edgeguard_llm_agent_host = overrides.get("edgeguard_llm_agent_host", "127.0.0.1")
  plugin.cfg_edgeguard_llm_agent_port = overrides.get("edgeguard_llm_agent_port", 5060)
  plugin.cfg_edgeguard_llm_agent_path = overrides.get("edgeguard_llm_agent_path", "/generate")
  plugin.cfg_edgeguard_llm_agent_token = overrides.get("edgeguard_llm_agent_token")
  plugin.cfg_edgeguard_llm_agent_token_env = overrides.get("edgeguard_llm_agent_token_env", "EDGEGUARD_LLM_AGENT_TOKEN")
  plugin.cfg_edgeguard_explanation_model_url = overrides.get("edgeguard_explanation_model_url")
  plugin.cfg_edgeguard_explanation_model_host = overrides.get("edgeguard_explanation_model_host", "127.0.0.1")
  plugin.cfg_edgeguard_explanation_model_port = overrides.get("edgeguard_explanation_model_port", 5090)
  plugin.cfg_edgeguard_explanation_model_path = overrides.get("edgeguard_explanation_model_path", "/create_chat_completion")
  plugin.cfg_edgeguard_explanation_model_token = overrides.get("edgeguard_explanation_model_token")
  plugin.cfg_edgeguard_explanation_model_token_env = overrides.get("edgeguard_explanation_model_token_env", "EDGEGUARD_EXPLANATION_MODEL_TOKEN")
  plugin.cfg_edgeguard_explanation_model = overrides.get("edgeguard_explanation_model", "qwen2.5-1.5b-instruct")
  plugin.cfg_edgeguard_explanation_default_rows = overrides.get("edgeguard_explanation_default_rows", 25)
  plugin.cfg_edgeguard_explanation_max_rows = overrides.get("edgeguard_explanation_max_rows", 100)
  plugin.cfg_edgeguard_explanation_max_tokens = overrides.get("edgeguard_explanation_max_tokens", 1600)
  plugin.cfg_edgeguard_explanation_temperature = overrides.get("edgeguard_explanation_temperature", 0.0)
  plugin.cfg_edgeguard_explanation_top_p = overrides.get("edgeguard_explanation_top_p", 1.0)
  plugin.cfg_neo4j_max_rows = overrides.get("neo4j_max_rows", 100)
  plugin.cfg_neo4j_query_timeout_seconds = overrides.get("neo4j_query_timeout_seconds", 30)
  plugin.cfg_live_empty_result_broadening = overrides.get("live_empty_result_broadening", True)
  plugin.cfg_request_timeout_seconds = overrides.get("request_timeout_seconds", 120)
  plugin.cfg_edgeguard_verbose = 0
  plugin.os_environ = overrides.get("os_environ", {})
  plugin._agent_token = overrides.get("agent_token")
  plugin._explanation_token = overrides.get("explanation_token")
  plugin._request_count = 0
  plugin._error_count = 0
  plugin._last_request_time = None
  plugin.time = lambda: 1000
  plugin.P = lambda *_args, **_kwargs: None
  plugin.Pd = lambda *_args, **_kwargs: None
  plugin.log = MagicMock()
  plugin.log.get_localhost_ip.return_value = "127.0.0.1"
  plugin.port = overrides.get("port", 5055)
  plugin.cfg_port = overrides.get("cfg_port", 5055)
  plugin.semaphore_env = {}
  plugin.semaphore_set_env = lambda key, value: plugin.semaphore_env.__setitem__(key, str(value))
  return plugin


class EdgeGuardAgentTests(unittest.TestCase):
  def test_edgeguard_api_timeout_defaults_share_long_generation_budget(self):
    self.assertEqual(EDGEGUARD_REQUEST_TIMEOUT_SECONDS, 600)
    self.assertEqual(EdgeguardLlmAgentApiPlugin.CONFIG["REQUEST_TIMEOUT"], 600)
    self.assertEqual(EdgeguardLlmAgentApiPlugin.CONFIG["REQUEST_TIMEOUT_SECONDS"], 600)
    self.assertEqual(EdgeguardApiPlugin.CONFIG["REQUEST_TIMEOUT"], 600)
    self.assertEqual(EdgeguardApiPlugin.CONFIG["REQUEST_TIMEOUT_SECONDS"], 600)

  def test_agent_exports_api_url_for_semaphore_consumers(self):
    plugin = _make_agent(port=5060)

    plugin._setup_semaphore_env()

    self.assertEqual(plugin.semaphore_env["API_HOST"], "127.0.0.1")
    self.assertEqual(plugin.semaphore_env["API_PORT"], "5060")
    self.assertEqual(plugin.semaphore_env["API_URL"], "http://127.0.0.1:5060")

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
      "extensions.business.cybersec.edgeguard.edgeguard_llm_agent_api.requests.post",
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

  def test_agent_normalizes_user_literals_before_model_call(self):
    plugin = _make_agent()
    payload = {
      "model": "edgeguard_qwen_4b",
      "choices": [{
        "message": {
          "content": "MATCH (c:CVE) WHERE c.cve_id = 'CVE-2024-12345' RETURN c LIMIT 5",
        },
      }],
    }

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_llm_agent_api.requests.post",
      return_value=_Response(payload=payload),
    ) as mocked_post:
      result = plugin.generate(request="Find cve-2024-12345 from hxxp://bad[.]test")

    self.assertTrue(result["accepted"])
    call_payload = mocked_post.call_args.kwargs["json"]
    self.assertEqual(
      call_payload["messages"][1]["content"],
      "Find CVE-2024-12345 from http://bad.test",
    )

  def test_agent_unwraps_local_inference_api_result_envelope(self):
    plugin = _make_agent()
    payload = {
      "result": {
        "REQUEST_ID": "req-1",
        "MODEL_NAME": "edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf",
        "TEXT_RESPONSE": "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10",
      },
    }

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_llm_agent_api.requests.post",
      return_value=_Response(payload=payload),
    ):
      result = plugin.generate(request="Show internet-facing hosts and their IP addresses")

    self.assertTrue(result["accepted"])
    self.assertEqual(result["status"], "accepted")
    self.assertEqual(
      result["accepted_cypher"],
      "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10",
    )

  def test_agent_propagates_local_inference_failure_envelope(self):
    plugin = _make_agent()
    payload = {
      "result": {
        "request_id": "req-1",
        "status": "failed",
        "error": "Local LLM returned an invalid empty response.",
      },
    }

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_llm_agent_api.requests.post",
      return_value=_Response(payload=payload),
    ):
      result = plugin.generate(request="Show indicators")

    self.assertFalse(result["accepted"])
    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "Local LLM returned an invalid empty response.")

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
      "extensions.business.cybersec.edgeguard.edgeguard_llm_agent_api.requests.post",
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
      "extensions.business.cybersec.edgeguard.edgeguard_llm_agent_api.requests.post",
      return_value=_Response(payload={
        "choices": [{"message": {"content": "Here is the query: MATCH (i:Indicator) RETURN i.value"}}],
      }),
    ):
      result = plugin.generate(request="Show indicators")

    self.assertFalse(result["accepted"])
    self.assertEqual(result["status"], "rejected")
    self.assertEqual(len(result["attempts"]), 2)


class EdgeGuardApiTests(unittest.TestCase):
  def test_api_exports_api_url_for_semaphore_consumers(self):
    plugin = _make_api(port=5055)

    plugin._setup_semaphore_env()

    self.assertEqual(plugin.semaphore_env["API_HOST"], "127.0.0.1")
    self.assertEqual(plugin.semaphore_env["API_PORT"], "5055")
    self.assertEqual(plugin.semaphore_env["API_URL"], "http://127.0.0.1:5055")

  def test_edgeguard_ai_engine_is_registered(self):
    from extensions.serving.ai_engines.stable import AI_ENGINES

    self.assertEqual(
      AI_ENGINES["edgeguard_qwen_4b"],
      {"SERVING_PROCESS": "llama_cpp_edgeguard_qwen_4b"},
    )

  def test_api_model_metadata_uses_v010_graph_intent_artifact(self):
    plugin = _make_api()

    model = plugin.model()

    self.assertEqual(model["display_name"], "EdgeGuard Cypher Qwen3 4B v0.10 Graph-Intent GGUF")
    self.assertEqual(model["model_repo"], "ratio1/edgeguard-cypher-qwen3-4b-v0.10-graph-intent-gguf")
    self.assertEqual(model["model_file"], "edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf")
    self.assertEqual(model["schema_version"], "edgeguard-cypher-schema-v0.10")
    self.assertEqual(model["quality"]["robustness_expected_labels_covered"], "96.06% (+16.54pp vs v0.9)")
    self.assertEqual(model["quality"]["robustness_expected_relationships_covered"], "85.83% (+7.87pp vs v0.9)")
    self.assertEqual(model["quality"]["training_corpus"], "3,588 accepted graph rows (2,868 train / 360 validation / 360 test)")
    self.assertEqual(model["quality"]["planner_failures"], 0)
    self.assertTrue(model["runtime_harness"]["empty_result_broadening"])

  def test_api_revalidates_agent_accepted_cypher(self):
    plugin = _make_api()
    agent_payload = {
      "status": "accepted",
      "accepted": True,
      "accepted_cypher": "MATCH (i:InternetFacing) RETURN i.hostname AS hostname",
      "attempts": [],
    }

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.post",
      return_value=_Response(payload=agent_payload),
    ):
      result = plugin.generate(request="Show hosts")

    self.assertFalse(result["accepted"])
    self.assertEqual(result["status"], "rejected")
    self.assertIsNone(result["accepted_cypher"])
    self.assertIn("api_revalidation", result)

  def test_api_validate_accepts_schema_query(self):
    plugin = _make_api()

    result = plugin.check_cypher(cypher="MATCH (i:Indicator) RETURN i.value AS value LIMIT 10")

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

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
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
    self.assertFalse(result["live_retry"]["attempted"])
    mocked_driver.assert_called_once()
    fake_session.run.assert_called_once_with("MATCH (i:Indicator) RETURN i.value AS value LIMIT 10")
    fake_driver.close.assert_called_once()

  def test_neo4j_query_broadens_empty_result_once(self):
    plugin = _make_api()
    fake_record = MagicMock()
    fake_record.data.return_value = {"p": "graph-path"}
    empty_result = _Result([], keys=["value"])
    broadened_result = _Result([fake_record], keys=["p"])
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.side_effect = [empty_result, broadened_result]
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:Indicator)-[:INDICATES]->(a:Alert) RETURN i.value AS value LIMIT 10",
        )

    self.assertTrue(result["executed"])
    self.assertEqual(result["columns"], ["p"])
    self.assertEqual(result["rows"], [{"p": "graph-path"}])
    self.assertTrue(result["live_retry"]["attempted"])
    self.assertTrue(result["live_retry"]["applied"])
    self.assertEqual(
      result["live_retry"]["deterministic_empty_result_broadening_strategy"],
      "first_allowed_label_first_allowed_relationship_type",
    )
    self.assertEqual(fake_session.run.call_count, 2)
    self.assertEqual(
      fake_session.run.call_args_list[1].args[0],
      "MATCH p=(n:Indicator)-[:INDICATES]-() RETURN p LIMIT 5",
    )

  def test_neo4j_query_can_disable_empty_result_broadening(self):
    plugin = _make_api()
    empty_result = _Result([], keys=["value"])
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.return_value = empty_result
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:Indicator)-[:INDICATES]->(a:Alert) RETURN i.value AS value LIMIT 10",
          enable_empty_result_broadening=False,
        )

    self.assertTrue(result["executed"])
    self.assertEqual(result["rows"], [])
    self.assertFalse(result["live_retry"]["enabled"])
    self.assertFalse(result["live_retry"]["attempted"])
    fake_session.run.assert_called_once_with(
      "MATCH (i:Indicator)-[:INDICATES]->(a:Alert) RETURN i.value AS value LIMIT 10"
    )

  def test_neo4j_query_returns_structured_error_when_driver_fails(self):
    plugin = _make_api()
    fake_driver = MagicMock()
    fake_driver.session.side_effect = RuntimeError("connection failed for secret")
    fake_driver.close.side_effect = RuntimeError("close failed")

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:Indicator) RETURN i.value AS value LIMIT 10",
        )

    self.assertEqual(result["status"], "error")
    self.assertFalse(result["ok"])
    self.assertFalse(result["executed"])
    self.assertNotIn("secret", result["error"])

  def test_explain_graph_executes_with_explanation_limit_and_validates_output(self):
    plugin = _make_api()
    fake_driver, fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    def provider_side_effect(*_args, **kwargs):
      packet = json.loads(kwargs["json"]["messages"][1]["content"])
      return _provider_response_for_packet(packet, caveat_types=["limit_adjusted"])

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          side_effect=provider_side_effect,
        ) as mocked_post:
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            request="Explain indicator provenance",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
          )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["explained"])
    self.assertEqual(result["packet"]["limit_policy"]["generated_limit"], 10)
    self.assertEqual(result["packet"]["limit_policy"]["executed_limit"], 25)
    self.assertTrue(result["packet"]["limit_policy"]["limit_adjusted"])
    self.assertTrue(result["packet"]["executed_cypher"].endswith("LIMIT 25"))
    fake_session.run.assert_called_once_with("MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25")
    call_payload = mocked_post.call_args.kwargs["json"]
    self.assertEqual(call_payload["model"], "qwen2.5-1.5b-instruct")
    self.assertEqual(call_payload["response_format"]["type"], "json_schema")
    self.assertEqual(call_payload["metadata"]["schema_version"], "edgeguard.case_explanation.v1")

  def test_explain_graph_rejects_invalid_cypher_before_provider_or_driver(self):
    plugin = _make_api()

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post") as mocked_post:
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:InternetFacing) RETURN i.hostname AS hostname",
        )

    self.assertEqual(result["status"], "rejected")
    self.assertFalse(result["executed"])
    mocked_driver.assert_not_called()
    mocked_post.assert_not_called()

  def test_explain_graph_requires_local_explanation_provider(self):
    plugin = _make_api(edgeguard_explanation_model_url="https://example.test/v1/chat/completions")

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      result = plugin.explain_graph(
        uri="example.com:7687",
        scheme="bolt+s",
        username="neo4j",
        password="secret",
        cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      )

    self.assertEqual(result["status"], "config_error")
    self.assertFalse(result["executed"])
    self.assertIn("local-only", result["error"])
    mocked_driver.assert_not_called()

  def test_explanation_model_call_disables_environment_proxies(self):
    plugin = _make_api()
    packet = {
      "schema_version": "edgeguard.graph_evidence_packet.v1",
      "request": "Explain graph.",
      "accepted_cypher": "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
      "executed_cypher": "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
      "limit_policy": {
        "generated_limit": 25,
        "executed_limit": 25,
        "server_max_rows": 100,
        "limit_adjusted": False,
      },
      "execution": {
        "status": "executed",
        "row_count": 1,
        "truncated": False,
        "broadened": False,
        "live_retry_reason": None,
      },
      "graph": {
        "nodes": [
          {"id": "n:indicator", "labels": ["Indicator"], "caption": "example.org", "properties": {"value": "example.org"}},
          {"id": "n:source", "labels": ["Source"], "caption": "AlienVault OTX", "properties": {"name": "AlienVault OTX"}},
        ],
        "relationships": [
          {"id": "r:source", "type": "SOURCED_FROM", "startNodeId": "n:indicator", "endNodeId": "n:source", "caption": "SOURCED_FROM", "properties": {}},
        ],
        "truncated": False,
      },
      "redaction": {
        "policy": "edgeguard_graph_packet_private_v1",
        "contains_customer_evidence": False,
        "contains_raw_misp_payload": False,
      },
    }
    fake_session = MagicMock()
    fake_session.post.return_value = _provider_response_for_packet(packet)

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=fake_session):
      result = plugin._call_explanation_model(packet)

    self.assertEqual(result["status"], "accepted")
    self.assertIs(fake_session.trust_env, False)
    fake_session.post.assert_called_once()

  def test_explain_graph_broadens_empty_result_and_validates_caveat(self):
    plugin = _make_api()
    fake_driver, fake_session = _driver_with_results(
      _Result([], keys=["p"]),
      _Result([_graph_record()], keys=["p"]),
    )

    def provider_side_effect(*_args, **kwargs):
      packet = json.loads(kwargs["json"]["messages"][1]["content"])
      return _provider_response_for_packet(packet, caveat_types=["broadening", "limit_adjusted"])

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          side_effect=provider_side_effect,
        ):
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
          )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["packet"]["execution"]["broadened"])
    self.assertEqual(result["packet"]["execution"]["live_retry_reason"], "executed_no_rows")
    self.assertTrue(result["live_retry"]["applied"])
    self.assertEqual(fake_session.run.call_count, 2)
    self.assertEqual(
      fake_session.run.call_args_list[1].args[0],
      "MATCH p=(n:Indicator)-[:SOURCED_FROM]-() RETURN p LIMIT 25",
    )

  def test_explain_graph_marks_truncated_packet_and_requires_caveat(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(
      _Result([_graph_record() for _idx in range(25)], keys=["p"]),
    )

    def provider_side_effect(*_args, **kwargs):
      packet = json.loads(kwargs["json"]["messages"][1]["content"])
      return _provider_response_for_packet(packet, caveat_types=["truncation"])

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          side_effect=provider_side_effect,
        ):
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
          )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["packet"]["execution"]["truncated"])
    self.assertTrue(result["packet"]["graph"]["truncated"])
    self.assertEqual(result["packet"]["execution"]["row_count"], 25)

  def test_explain_graph_rejects_missing_required_caveat(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    def provider_side_effect(*_args, **kwargs):
      packet = json.loads(kwargs["json"]["messages"][1]["content"])
      return _provider_response_for_packet(packet, caveat_types=[])

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          side_effect=provider_side_effect,
        ):
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
          )

    self.assertEqual(result["status"], "rejected")
    self.assertFalse(result["explained"])
    self.assertIn("missing_required_caveat", {item["code"] for item in result["validation_errors"]})

  def test_explain_graph_rejects_malformed_json_output(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          return_value=_Response(payload={"choices": [{"message": {"content": "not json"}}]}),
        ):
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
          )

    self.assertEqual(result["status"], "rejected")
    self.assertIn("malformed_json", {item["code"] for item in result["validation_errors"]})

  def test_explain_graph_rejects_nested_schema_invalid_output(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    def provider_side_effect(*_args, **kwargs):
      packet = json.loads(kwargs["json"]["messages"][1]["content"])
      explanation = _explanation_for_packet(packet)
      explanation["summary"].pop("text")
      explanation["key_paths"][0]["confidence"] = "certain"
      explanation["next_pivots"][0]["priority"] = "urgent"
      return _Response(payload={"choices": [{"message": {"content": json.dumps(explanation)}}]})

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          side_effect=provider_side_effect,
        ):
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
          )

    codes = {item["code"] for item in result["validation_errors"]}
    self.assertEqual(result["status"], "rejected")
    self.assertIn("schema_required", codes)
    self.assertIn("schema_enum", codes)

  def test_explain_graph_rejects_unsupported_high_severity(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    def provider_side_effect(*_args, **kwargs):
      packet = json.loads(kwargs["json"]["messages"][1]["content"])
      explanation = _explanation_for_packet(packet)
      explanation["risk_interpretation"][0]["severity"] = "high"
      return _Response(payload={"choices": [{"message": {"content": json.dumps(explanation)}}]})

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          side_effect=provider_side_effect,
        ):
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
          )

    self.assertEqual(result["status"], "rejected")
    self.assertIn("severity_escalation_unsupported", {item["code"] for item in result["validation_errors"]})

  def test_explain_graph_rejects_absent_evidence_invented_source_and_unsafe_pivot(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    def provider_side_effect(*_args, **kwargs):
      packet = json.loads(kwargs["json"]["messages"][1]["content"])
      explanation = _explanation_for_packet(packet, caveat_types=["limit_adjusted"])
      explanation["summary"]["evidence_ids"] = ["n:absent"]
      explanation["provenance"][0]["source_name"] = "Invented Source"
      explanation["next_pivots"][0]["question"] = "CALL apoc.load.json to fetch more data"
      return _Response(payload={
        "choices": [{"message": {"content": json.dumps(explanation)}}],
      })

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          side_effect=provider_side_effect,
        ):
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
          )

    codes = {item["code"] for item in result["validation_errors"]}
    self.assertEqual(result["status"], "rejected")
    self.assertIn("unknown_evidence_id", codes)
    self.assertIn("invented_source_name", codes)
    self.assertIn("unsafe_pivot", codes)

  def test_explain_graph_returns_provider_error_after_packet_build(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          return_value=_Response(status_code=500, text="failed"),
        ):
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
          )

    self.assertEqual(result["status"], "error")
    self.assertTrue(result["executed"])
    self.assertFalse(result["explained"])
    self.assertEqual(result["provider_status"], 500)
    self.assertIn("packet", result)

  def test_case_explanation_validator_rejects_redaction_flags(self):
    packet = {
      "schema_version": "edgeguard.graph_evidence_packet.v1",
      "request": "Explain graph.",
      "accepted_cypher": "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
      "executed_cypher": "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
      "limit_policy": {
        "generated_limit": 25,
        "executed_limit": 25,
        "server_max_rows": 100,
        "limit_adjusted": False,
      },
      "execution": {
        "status": "executed",
        "row_count": 1,
        "truncated": False,
        "broadened": False,
        "live_retry_reason": None,
      },
      "graph": {
        "nodes": [
          {"id": "n:indicator", "labels": ["Indicator"], "caption": "example.org", "properties": {"value": "example.org"}},
          {"id": "n:source", "labels": ["Source"], "caption": "AlienVault OTX", "properties": {"name": "AlienVault OTX"}},
        ],
        "relationships": [
          {"id": "r:source", "type": "SOURCED_FROM", "startNodeId": "n:indicator", "endNodeId": "n:source", "caption": "SOURCED_FROM", "properties": {}},
        ],
        "truncated": False,
      },
      "redaction": {
        "policy": "edgeguard_graph_packet_private_v1",
        "contains_customer_evidence": True,
        "contains_raw_misp_payload": False,
      },
    }
    explanation = {
      "schema_version": "edgeguard.case_explanation.v1",
      "summary": {"text": "Indicator has source provenance.", "evidence_ids": ["n:indicator", "r:source", "n:source"]},
      "key_paths": [],
      "entity_findings": [{"entity_id": "n:indicator", "role": "seed_indicator", "finding": "Indicator is present.", "evidence_ids": ["n:indicator"]}],
      "risk_interpretation": [],
      "provenance": [{"source_node_id": "n:source", "source_name": "AlienVault OTX", "supports": ["n:indicator"], "caveat": "Packet only."}],
      "caveats": [],
      "missing_context": [],
      "next_pivots": [{"question": "Which actor is linked?", "suggested_query_intent": "indicator_to_actor_neighborhood", "priority": "medium"}],
    }

    errors, _context = _validate_packet_and_explanation(packet, explanation)

    self.assertIn("customer_evidence_not_allowed", {item["code"] for item in errors})
