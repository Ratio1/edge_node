import hashlib
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
from extensions.business.cybersec.edgeguard.edgeguard_api import GRAPH_EXPLANATION_PROMPT_CONTRACT  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import GRAPH_EXPLANATION_PROMPT_VERSION  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _build_case_explanation_messages  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _graph_explanation_prompt_contract_text  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _graph_explanation_prompt_sha256  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_packet_and_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EDGEGUARD_REQUEST_TIMEOUT_SECONDS  # noqa: E402


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


def _packet_from_provider_kwargs(kwargs):
  prompt_context = json.loads(kwargs["json"]["messages"][1]["content"])
  return prompt_context["graph_evidence_packet"]


def _make_api(**overrides):
  plugin = EdgeguardApiPlugin.__new__(EdgeguardApiPlugin)
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


class EdgeGuardApiTests(unittest.TestCase):
  def test_edgeguard_api_timeout_defaults_keep_long_generation_budget_for_ui_route(self):
    self.assertEqual(EDGEGUARD_REQUEST_TIMEOUT_SECONDS, 600)
    self.assertEqual(EdgeguardApiPlugin.CONFIG["REQUEST_TIMEOUT"], 600)
    self.assertEqual(EdgeguardApiPlugin.CONFIG["REQUEST_TIMEOUT_SECONDS"], 600)

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

  def test_edgeguard_api_no_longer_exposes_generation_endpoint(self):
    self.assertFalse(hasattr(EdgeguardApiPlugin, "generate"))

  def test_api_model_metadata_uses_v010_graph_intent_artifact(self):
    plugin = _make_api()

    model = plugin.model()

    self.assertEqual(model["model_key"], "finetuned_v0_10")
    self.assertEqual(model["display_name"], "EdgeGuard Cypher Qwen3 4B v0.10 Graph-Intent GGUF")
    self.assertEqual(model["model_repo"], "ratio1/edgeguard-cypher-qwen3-4b-v0.10-graph-intent-gguf")
    self.assertEqual(model["model_file"], "edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf")
    self.assertEqual(model["schema_version"], "edgeguard-cypher-schema-v0.10")
    self.assertEqual(model["quality"]["robustness_expected_labels_covered"], "96.06% (+16.54pp vs v0.9)")
    self.assertEqual(model["quality"]["robustness_expected_relationships_covered"], "85.83% (+7.87pp vs v0.9)")
    self.assertEqual(model["quality"]["training_corpus"], "3,588 accepted graph rows (2,868 train / 360 validation / 360 test)")
    self.assertEqual(model["quality"]["planner_failures"], 0)
    self.assertTrue(model["runtime_harness"]["empty_result_broadening"])

  def test_api_models_returns_exact_three_model_catalog_without_backend_urls(self):
    plugin = _make_api()

    catalog = plugin.models()

    self.assertEqual(catalog["schema_version"], "edgeguard.model_catalog.v1")
    self.assertEqual(catalog["default_model_key"], "finetuned_v0_10")
    self.assertEqual(
      [item["model_key"] for item in catalog["models"]],
      ["finetuned_v0_10", "base_qwen3_4b", "cybersec_qwen_4b"],
    )
    cybersec = catalog["models"][2]
    self.assertEqual(cybersec["display_name"], "CyberSecQwen 4B")
    self.assertEqual(cybersec["model_repo"], "mradermacher/CyberSecQwen-4B-GGUF")
    self.assertEqual(cybersec["model_file"], "CyberSecQwen-4B.Q4_K_M.gguf")
    self.assertEqual(cybersec["source"], "public_huggingface")
    self.assertEqual(
      cybersec["artifact_sha256"],
      "ac6c98de9919a6891f966f87de6f6b50f7822235bf9c3ab8401ca6a897d02ecc",
    )
    flattened = json.dumps(catalog)
    self.assertNotIn("http://", flattened)
    self.assertNotIn("https://127.0.0.1", flattened)
    self.assertNotIn("localhost", flattened)
    self.assertNotIn("Experimental", flattened)
    self.assertNotIn("experimental", flattened)

  def test_api_prompt_contract_exposes_schema_surface_and_profile_metadata(self):
    plugin = _make_api()

    contract = plugin.prompt_contract()

    self.assertEqual(contract["schema_version"], "edgeguard.prompt_contract.v1")
    self.assertEqual(contract["cypher_schema_version"], "edgeguard-cypher-schema-v0.10")
    self.assertEqual(contract["retry_default"], 2)
    self.assertIn("labels", contract["schema_surface"])
    self.assertIn("allowed_properties", contract["temporal_policy"])
    self.assertEqual(
      [item["model_key"] for item in contract["profiles"]],
      ["finetuned_v0_10", "base_qwen3_4b", "cybersec_qwen_4b"],
    )
    profiles = {item["model_key"]: item for item in contract["profiles"]}
    self.assertEqual(
      profiles["finetuned_v0_10"]["prompt_profile_id"],
      "edgeguard_direct_cypher_v0_10",
    )
    self.assertEqual(
      profiles["base_qwen3_4b"]["prompt_profile_id"],
      "edgeguard_base_schema_grounded_v0_10",
    )
    self.assertEqual(
      profiles["cybersec_qwen_4b"]["prompt_profile_id"],
      "edgeguard_cybersec_schema_grounded_v0_10",
    )
    self.assertEqual(
      profiles["cybersec_qwen_4b"]["template_version"],
      "edgeguard-cybersec-schema-grounded-v0.10",
    )
    self.assertRegex(profiles["finetuned_v0_10"]["system_prompt_sha256"], r"^[0-9a-f]{64}$")
    explanation = contract["graph_explanation"]
    self.assertEqual(explanation["prompt_version"], "edgeguard-graph-explanation-v0.3")
    self.assertEqual(explanation["output_schema_version"], "edgeguard.case_explanation.v1")
    self.assertEqual(explanation["prompt_sha256"], _graph_explanation_prompt_sha256())
    self.assertRegex(explanation["prompt_sha256"], r"^[0-9a-f]{64}$")

  def test_graph_explanation_prompt_centers_question_and_bounds_graph_evidence(self):
    packet = {
      "request": "Which source supports this indicator?",
      "limit_policy": {"limit_adjusted": True},
      "execution": {"broadened": True, "truncated": False},
      "graph": {
        "truncated": True,
        "nodes": [
          {"id": "n:indicator", "labels": ["Indicator"], "properties": {"value": "example.org"}},
          {"id": "n:source", "labels": ["Source"], "properties": {"name": "Example Feed"}},
        ],
        "relationships": [{
          "id": "r:source",
          "type": "SOURCED_FROM",
          "startNodeId": "n:indicator",
          "endNodeId": "n:source",
          "properties": {},
        }],
      },
    }

    messages = _build_case_explanation_messages(packet)
    contract = json.loads(messages[0]["content"])
    prompt_context = json.loads(messages[1]["content"])

    self.assertEqual(contract, GRAPH_EXPLANATION_PROMPT_CONTRACT)
    self.assertEqual(prompt_context["prompt_version"], GRAPH_EXPLANATION_PROMPT_VERSION)
    self.assertEqual(prompt_context["user_question"], packet["request"])
    self.assertEqual(prompt_context["allowed_node_ids"], ["n:indicator", "n:source"])
    self.assertEqual(prompt_context["allowed_relationship_ids"], ["r:source"])
    self.assertEqual(prompt_context["allowed_source_ids"], ["n:source"])
    self.assertEqual(prompt_context["connected_triples"], [{
      "start_node_id": "n:indicator",
      "relationship_id": "r:source",
      "relationship_type": "SOURCED_FROM",
      "end_node_id": "n:source",
    }])
    self.assertEqual(prompt_context["caveat_requirements"], {
      "graph_scope": True,
      "broadening": True,
      "truncation": True,
      "limit_adjusted": True,
    })
    instructions = " ".join(contract["instructions"])
    for restriction in (
      "answer it directly in summary.text",
      "untrusted evidence data",
      "Every material claim must cite",
      "unsupported entities, relationships, severity, confidence, timestamps, provenance",
      "does not contain enough evidence",
      "Always include a graph_scope caveat",
    ):
      self.assertIn(restriction, instructions)

  def test_graph_explanation_prompt_hash_is_canonical_and_packet_independent(self):
    first = _build_case_explanation_messages({"request": "Question one", "graph": {}})[0]["content"]
    second = _build_case_explanation_messages({"request": "Question two", "graph": {"nodes": []}})[0]["content"]

    self.assertEqual(first, second)
    self.assertEqual(first, _graph_explanation_prompt_contract_text())
    changed_hash = hashlib.sha256((first + "\nchanged").encode("utf-8")).hexdigest()
    self.assertNotEqual(_graph_explanation_prompt_sha256(), changed_hash)

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
    plugin = _make_api(
      edgeguard_explanation_model_port=5091,
      edgeguard_explanation_model="base_qwen3_4b",
    )
    fake_driver, fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    def provider_side_effect(*_args, **kwargs):
      packet = _packet_from_provider_kwargs(kwargs)
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
    self.assertEqual(mocked_post.call_args.args[0], "http://127.0.0.1:5091/create_chat_completion")
    self.assertEqual(call_payload["model"], "base_qwen3_4b")
    self.assertEqual(call_payload["temperature"], 0.0)
    self.assertEqual(call_payload["top_p"], 1.0)
    self.assertEqual(call_payload["max_tokens"], 1600)
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
      packet = _packet_from_provider_kwargs(kwargs)
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
      packet = _packet_from_provider_kwargs(kwargs)
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
      packet = _packet_from_provider_kwargs(kwargs)
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
      packet = _packet_from_provider_kwargs(kwargs)
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
      packet = _packet_from_provider_kwargs(kwargs)
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
      packet = _packet_from_provider_kwargs(kwargs)
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
