import hashlib
import json
import requests
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
from extensions.business.cybersec.edgeguard.edgeguard_api import _construct_case_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _graph_explanation_prompt_contract_text  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _graph_explanation_prompt_sha256  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _sha256_text  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_case_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_case_explanation_draft_bounds  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_graph_evidence_packet  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_packet_and_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EDGEGUARD_REQUEST_TIMEOUT_SECONDS  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EXPLANATION_MAX_PROMPT_USER_BYTES  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EXPLANATION_MAX_OUTPUT_TOKENS  # noqa: E402


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


def _serialized_execution(executed_cypher, *, broadened=False, primary_row_count=1):
  return {
    "executed_cypher": executed_cypher,
    "primary_row_count": primary_row_count,
    "row_count": 1,
    "truncated": False,
    "broadened": broadened,
    "graph": {
      "nodes": [
        {
          "id": "4:indicator-raw-id",
          "labels": ["Indicator"],
          "properties": {"value": "example.org", "type": "domain", "raw_payload": "drop me"},
          "caption": "untrusted caption",
        },
        {
          "id": "4:source-raw-id",
          "labels": ["Source"],
          "properties": {"name": "AlienVault OTX"},
          "caption": "untrusted source caption",
        },
      ],
      "relationships": [{
        "id": "5:relationship-raw-id",
        "type": "SOURCED_FROM",
        "startNodeId": "4:indicator-raw-id",
        "endNodeId": "4:source-raw-id",
        "properties": {"confidence": "medium"},
        "caption": "untrusted relationship caption",
      }],
      "truncated": False,
    },
  }


def _case_explanation_packet():
  return {
    "schema_version": "edgeguard.graph_evidence_packet.v1",
    "request": "Which source supports this indicator?",
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
        {
          "id": "n:indicator",
          "labels": ["Indicator"],
          "caption": "example.org",
          "properties": {"value": "example.org"},
        },
        {
          "id": "n:source",
          "labels": ["Source"],
          "caption": "AlienVault OTX",
          "properties": {"name": "AlienVault OTX"},
        },
      ],
      "relationships": [{
        "id": "r:source",
        "type": "SOURCED_FROM",
        "startNodeId": "n:indicator",
        "endNodeId": "n:source",
        "caption": "SOURCED_FROM",
        "properties": {},
      }],
      "truncated": False,
    },
    "redaction": {
      "policy": "edgeguard_graph_packet_private_v1",
      "contains_customer_evidence": False,
      "contains_raw_misp_payload": False,
    },
  }


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


def _draft_for_packet(packet):
  draft = _explanation_for_packet(packet)
  draft.pop("schema_version")
  draft.pop("caveats")
  draft["entity_findings"] = []
  draft["missing_context"] = []
  return draft


def _driver_with_results(*results):
  fake_session = MagicMock()
  fake_session.__enter__.return_value = fake_session
  fake_session.run.side_effect = list(results)
  fake_driver = MagicMock()
  fake_driver.session.return_value = fake_session
  return fake_driver, fake_session


def _provider_response_for_packet(packet, caveat_types=None):
  explanation = _draft_for_packet(packet)
  return _Response(payload={
    "model": "qwen2.5-1.5b-instruct",
    "choices": [{
      "message": {"content": json.dumps(explanation)},
    }],
  })


def _nested_provider_response(content, *, finish_reason="stop", completion_tokens=32):
  return _Response(payload={
    "result": {
      "TEXT_RESPONSE": content,
      "FULL_OUTPUT": {
        "choices": [{
          "message": {"content": content},
          "finish_reason": finish_reason,
        }],
        "usage": {"completion_tokens": completion_tokens},
      },
    },
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
  plugin.cfg_edgeguard_explanation_max_tokens = overrides.get(
    "edgeguard_explanation_max_tokens",
    EXPLANATION_MAX_OUTPUT_TOKENS,
  )
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
    self.assertEqual(explanation["prompt_version"], "edgeguard-graph-explanation-v0.5")
    self.assertEqual(explanation["draft_schema_version"], "edgeguard.case_explanation_draft.v2")
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
    self.assertEqual(prompt_context["server_caveat_flags"], {
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
      "Do not emit schema_version or caveats",
      "one bounded CaseExplanationDraft JSON object",
    ):
      self.assertIn(restriction, instructions)

  def test_graph_explanation_prompt_projects_large_graph_into_context_budget(self):
    nodes = [{
      "id": f"n:indicator-{index}",
      "labels": ["Indicator"],
      "caption": f"indicator-{index}",
      "properties": {
        "value": f"indicator-{index}.example.org",
        "description": "x" * 500,
        "extra": "y" * 500,
      },
    } for index in range(100)]
    relationships = [{
      "id": f"r:related-{index}",
      "type": "RELATED_TO",
      "startNodeId": f"n:indicator-{index}",
      "endNodeId": f"n:indicator-{index + 1}",
      "caption": "RELATED_TO",
      "properties": {"description": "z" * 500},
    } for index in range(99)]
    packet = {
      "schema_version": "edgeguard.graph_evidence_packet.v1",
      "request": "How are these indicators connected?",
      "accepted_cypher": "MATCH p=(i:Indicator)-[*1..2]-(j:Indicator) RETURN p LIMIT 100",
      "executed_cypher": "MATCH p=(i:Indicator)-[*1..2]-(j:Indicator) RETURN p LIMIT 100",
      "limit_policy": {
        "generated_limit": 100,
        "executed_limit": 100,
        "server_max_rows": 100,
        "limit_adjusted": False,
      },
      "execution": {
        "status": "executed",
        "row_count": 100,
        "truncated": False,
        "broadened": False,
        "live_retry_reason": None,
      },
      "graph": {"nodes": nodes, "relationships": relationships, "truncated": False},
      "redaction": {
        "policy": "edgeguard_graph_packet_private_v1",
        "contains_customer_evidence": False,
        "contains_raw_misp_payload": False,
      },
    }

    user_content = _build_case_explanation_messages(packet)[1]["content"]
    prompt_context = json.loads(user_content)
    prompt_packet = prompt_context["graph_evidence_packet"]
    selected_node_ids = {node["id"] for node in prompt_packet["graph"]["nodes"]}

    self.assertLessEqual(len(user_content.encode("utf-8")), EXPLANATION_MAX_PROMPT_USER_BYTES)
    self.assertLess(len(selected_node_ids), len(nodes))
    self.assertTrue(prompt_packet["graph"]["truncated"])
    self.assertTrue(prompt_packet["execution"]["truncated"])
    self.assertTrue(prompt_context["server_caveat_flags"]["truncation"])
    self.assertTrue(prompt_packet["graph"]["relationships"])
    for relationship in prompt_packet["graph"]["relationships"]:
      self.assertIn(relationship["startNodeId"], selected_node_ids)
      self.assertIn(relationship["endNodeId"], selected_node_ids)

  def test_graph_explanation_prompt_hash_is_canonical_and_packet_independent(self):
    first = _build_case_explanation_messages({"request": "Question one", "graph": {}})[0]["content"]
    second = _build_case_explanation_messages({"request": "Question two", "graph": {"nodes": []}})[0]["content"]

    self.assertEqual(first, second)
    self.assertEqual(first, _graph_explanation_prompt_contract_text())
    changed_hash = hashlib.sha256((first + "\nchanged").encode("utf-8")).hexdigest()
    self.assertNotEqual(_graph_explanation_prompt_sha256(), changed_hash)

  def test_case_explanation_draft_defaults_optional_sections_and_adds_deterministic_caveats(self):
    packet = _case_explanation_packet()
    effective_packet = json.loads(json.dumps(packet))
    effective_packet["limit_policy"].update({
      "generated_limit": 10,
      "executed_limit": 25,
      "limit_adjusted": True,
    })
    effective_packet["execution"].update({
      "broadened": True,
      "truncated": True,
      "live_retry_reason": "executed_no_rows",
    })
    effective_packet["graph"]["truncated"] = True
    draft = {
      "summary": {
        "text": "AlienVault OTX supports the returned indicator.",
        "evidence_ids": ["n:indicator", "r:source", "n:source"],
      },
    }

    explanation, errors = _construct_case_explanation(draft, packet, effective_packet)

    self.assertEqual(errors, [])
    self.assertEqual(explanation["schema_version"], "edgeguard.case_explanation.v1")
    for section in (
      "key_paths",
      "entity_findings",
      "risk_interpretation",
      "provenance",
      "missing_context",
      "next_pivots",
    ):
      self.assertEqual(explanation[section], [])
    self.assertEqual(explanation["caveats"], [
      {
        "type": "graph_scope",
        "message": "This explanation is limited to the graph evidence returned for the submitted query.",
        "evidence_ids": [],
      },
      {
        "type": "broadening",
        "message": "The original query returned no rows, so deterministic broadening supplied this graph evidence.",
        "evidence_ids": [],
      },
      {
        "type": "truncation",
        "message": "The graph evidence was truncated or projected to fit explanation limits.",
        "evidence_ids": [],
      },
      {
        "type": "limit_adjusted",
        "message": "The requested query limit was adjusted by the server explanation row policy.",
        "evidence_ids": [],
      },
    ])

  def test_case_explanation_draft_rejects_server_owned_and_unexpected_keys(self):
    packet = _case_explanation_packet()
    summary = {
      "text": "The packet links the indicator to a source.",
      "evidence_ids": ["n:indicator", "r:source", "n:source"],
    }

    for forbidden in ("schema_version", "caveats", "unexpected"):
      with self.subTest(forbidden=forbidden):
        explanation, errors = _construct_case_explanation(
          {"summary": summary, forbidden: []},
          packet,
          packet,
        )
        self.assertIsNone(explanation)
        self.assertIn("schema_additional_property", {item["code"] for item in errors})

  def test_case_explanation_draft_v2_enforces_summary_and_global_bounds(self):
    summary = {"text": " ".join(["word"] * 80), "evidence_ids": [f"n:{index}" for index in range(8)]}
    at_limit = {
      "summary": summary,
      "entity_findings": [{}, {}],
      "provenance": [{}, {}],
    }

    self.assertNotIn(
      "draft_word_limit",
      {item["code"] for item in _validate_case_explanation_draft_bounds(at_limit)},
    )
    self.assertNotIn(
      "draft_optional_object_limit",
      {item["code"] for item in _validate_case_explanation_draft_bounds(at_limit)},
    )

    over_limit = json.loads(json.dumps(at_limit))
    over_limit["summary"]["text"] += " extra"
    over_limit["summary"]["evidence_ids"].append("n:8")
    over_limit["risk_interpretation"] = [{}]
    codes = {item["code"] for item in _validate_case_explanation_draft_bounds(over_limit)}

    self.assertIn("draft_word_limit", codes)
    self.assertIn("draft_evidence_limit", codes)
    self.assertIn("draft_optional_object_limit", codes)

  def test_case_explanation_draft_v2_counts_unicode_hyphenated_compounds_as_words(self):
    at_limit = {
      "summary": {
        "text": " ".join(["non\u2011breaking"] * 80),
        "evidence_ids": [],
      },
    }
    self.assertNotIn(
      "draft_word_limit",
      {item["code"] for item in _validate_case_explanation_draft_bounds(at_limit)},
    )

    at_limit["summary"]["text"] += " extra"
    self.assertIn(
      "draft_word_limit",
      {item["code"] for item in _validate_case_explanation_draft_bounds(at_limit)},
    )

  def test_case_explanation_draft_v2_enforces_every_section_cardinality(self):
    maxima = {
      "key_paths": 1,
      "entity_findings": 2,
      "risk_interpretation": 1,
      "provenance": 2,
      "missing_context": 1,
      "next_pivots": 1,
    }
    for section, maximum in maxima.items():
      with self.subTest(section=section):
        at_limit = {"summary": {}, section: [{} for _index in range(maximum)]}
        over_limit = {"summary": {}, section: [{} for _index in range(maximum + 1)]}
        self.assertNotIn(
          "draft_cardinality_limit",
          {item["code"] for item in _validate_case_explanation_draft_bounds(at_limit)},
        )
        self.assertIn(
          "draft_cardinality_limit",
          {item["code"] for item in _validate_case_explanation_draft_bounds(over_limit)},
        )

  def test_case_explanation_draft_v2_enforces_combined_narrative_and_claim_evidence_bounds(self):
    sections = {
      "key_paths": (("title", "interpretation"), 40, "path_evidence_ids"),
      "entity_findings": (("finding",), 40, "evidence_ids"),
      "risk_interpretation": (("claim", "limits"), 30, "evidence_ids"),
      "provenance": (("source_name", "caveat"), 30, "supports"),
      "missing_context": (("gap", "suggested_check"), 30, None),
      "next_pivots": (("question", "suggested_query_intent"), 25, None),
    }
    for section, (fields, maximum, evidence_field) in sections.items():
      with self.subTest(section=section):
        item = {field: "" for field in fields}
        item[fields[0]] = " ".join(["word"] * maximum)
        if evidence_field:
          item[evidence_field] = [f"n:{index}" for index in range(6)]
        at_limit = {"summary": {}, section: [item]}
        self.assertEqual(_validate_case_explanation_draft_bounds(at_limit), [])

        item[fields[0]] += " extra"
        if evidence_field:
          item[evidence_field].append("n:6")
        codes = {entry["code"] for entry in _validate_case_explanation_draft_bounds(at_limit)}
        self.assertIn("draft_word_limit", codes)
        if evidence_field:
          self.assertIn("draft_evidence_limit", codes)

  def test_case_explanation_projection_truncation_is_disclosed(self):
    packet = _case_explanation_packet()
    for index in range(60):
      packet["graph"]["nodes"].append({
        "id": f"n:extra-{index}",
        "labels": ["Indicator"],
        "caption": f"extra-{index}",
        "properties": {"value": f"extra-{index}.example.org", "description": "x" * 500},
      })
    prompt_packet = json.loads(_build_case_explanation_messages(packet)[1]["content"])["graph_evidence_packet"]
    draft = {
      "summary": {
        "text": "The returned graph includes the requested indicator.",
        "evidence_ids": ["n:indicator"],
      },
    }

    explanation, errors = _construct_case_explanation(draft, packet, prompt_packet)

    self.assertEqual(errors, [])
    self.assertTrue(prompt_packet["graph"]["truncated"])
    self.assertIn("truncation", {item["type"] for item in explanation["caveats"]})

  def test_case_explanation_draft_rejects_path_with_missing_endpoint_without_repair(self):
    packet = _case_explanation_packet()
    draft = {
      "summary": {
        "text": "The packet links the indicator to a source.",
        "evidence_ids": ["n:indicator", "r:source", "n:source"],
      },
      "key_paths": [{
        "title": "Disconnected path",
        "path_evidence_ids": ["n:indicator", "r:source"],
        "interpretation": "The path omits the relationship endpoint.",
        "confidence": "medium",
      }],
    }

    explanation, errors = _construct_case_explanation(draft, packet, packet)

    self.assertIsNone(explanation)
    self.assertIn("path_relationship_not_connected", {item["code"] for item in errors})

  def test_case_explanation_draft_rejects_disconnected_path_components(self):
    packet = _case_explanation_packet()
    packet["graph"]["nodes"].extend([
      {
        "id": "n:indicator-2",
        "labels": ["Indicator"],
        "caption": "second.example.org",
        "properties": {"value": "second.example.org"},
      },
      {
        "id": "n:source-2",
        "labels": ["Source"],
        "caption": "Second Feed",
        "properties": {"name": "Second Feed"},
      },
    ])
    packet["graph"]["relationships"].append({
      "id": "r:source-2",
      "type": "SOURCED_FROM",
      "startNodeId": "n:indicator-2",
      "endNodeId": "n:source-2",
      "caption": "SOURCED_FROM",
      "properties": {},
    })
    draft = {
      "summary": {
        "text": "The packet contains two separate indicator-source relationships.",
        "evidence_ids": [
          "n:indicator",
          "r:source",
          "n:source",
          "n:indicator-2",
          "r:source-2",
          "n:source-2",
        ],
      },
      "key_paths": [{
        "title": "Two disconnected components",
        "path_evidence_ids": [
          "n:indicator",
          "r:source",
          "n:source",
          "n:indicator-2",
          "r:source-2",
          "n:source-2",
        ],
        "interpretation": "These relationships do not form one connected path.",
        "confidence": "medium",
      }],
    }

    explanation, errors = _construct_case_explanation(draft, packet, packet)

    self.assertIsNone(explanation)
    self.assertIn("path_relationship_not_connected", {item["code"] for item in errors})

  def test_case_explanation_draft_rejects_malformed_nested_types_without_exception(self):
    packet = _case_explanation_packet()
    mutations = {
      "evidence_id_object": lambda draft: draft["summary"].update({"evidence_ids": [{"id": "n:indicator"}]}),
      "confidence_array": lambda draft: draft["key_paths"][0].update({"confidence": []}),
      "severity_object": lambda draft: draft["risk_interpretation"][0].update({"severity": {}}),
      "high_severity_evidence_object": lambda draft: draft["risk_interpretation"][0].update({
        "severity": "high",
        "evidence_ids": [{"id": "n:indicator"}],
      }),
      "source_name_array": lambda draft: draft["provenance"][0].update({"source_name": []}),
      "priority_object": lambda draft: draft["next_pivots"][0].update({"priority": {}}),
    }

    for label, mutate in mutations.items():
      with self.subTest(label=label):
        draft = _draft_for_packet(packet)
        mutate(draft)
        explanation, errors = _construct_case_explanation(draft, packet, packet)
        self.assertIsNone(explanation)
        self.assertTrue(errors)
        self.assertTrue({item["code"] for item in errors}.intersection({
          "invalid_evidence_id",
          "schema_enum",
          "schema_type",
          "invented_source_name",
        }))

  def test_case_explanation_draft_rejects_scalar_optional_sections_without_exception(self):
    packet = _case_explanation_packet()
    for section in (
      "key_paths",
      "entity_findings",
      "risk_interpretation",
      "provenance",
      "missing_context",
      "next_pivots",
    ):
      with self.subTest(section=section):
        draft = _draft_for_packet(packet)
        draft[section] = 17
        explanation, errors = _construct_case_explanation(draft, packet, packet)
        self.assertIsNone(explanation)
        self.assertIn("schema_type", {item["code"] for item in errors})

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
    self.assertEqual(call_payload["max_tokens"], 1024)
    self.assertEqual(call_payload["response_format"], {"type": "json_object"})
    self.assertNotIn("schema", call_payload["response_format"])
    self.assertEqual(call_payload["metadata"]["schema_version"], "edgeguard.case_explanation_draft.v2")

  def test_explanation_payload_caps_output_and_honors_smaller_positive_limit(self):
    plugin = _make_api(edgeguard_explanation_max_tokens=1600)
    packet = {"request": "Explain this graph.", "graph": {"nodes": [], "relationships": []}}

    default_payload = plugin._build_explanation_payload(packet)
    smaller_payload = plugin._build_explanation_payload(packet, max_tokens=64)
    larger_payload = plugin._build_explanation_payload(packet, max_tokens=2048)
    non_positive_payload = plugin._build_explanation_payload(packet, max_tokens=0)
    negative_payload = plugin._build_explanation_payload(packet, max_tokens=-1)

    self.assertEqual(default_payload["max_tokens"], 1024)
    self.assertEqual(smaller_payload["max_tokens"], 64)
    self.assertEqual(larger_payload["max_tokens"], 1024)
    self.assertEqual(non_positive_payload["max_tokens"], 1024)
    self.assertEqual(negative_payload["max_tokens"], 1024)
    for payload in (default_payload, smaller_payload, larger_payload, non_positive_payload, negative_payload):
      self.assertEqual(payload["response_format"], {"type": "json_object"})

  def test_prepare_graph_explanation_returns_credential_free_primary_and_broadening_plan(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)

    result = plugin.prepare_graph_explanation(
      cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
      explanation_rows=25,
      enable_empty_result_broadening=True,
    )

    self.assertEqual(result["status"], "accepted")
    self.assertEqual(
      result["executed_cypher"],
      "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
    )
    self.assertEqual(
      result["broadening"]["cypher"],
      "MATCH p=(n:Indicator)-[:SOURCED_FROM]-() RETURN p LIMIT 25",
    )
    self.assertEqual(result["limit_policy"], {
      "generated_limit": 10,
      "executed_limit": 25,
      "server_max_rows": 100,
      "limit_adjusted": True,
    })
    flattened = json.dumps(result)
    for forbidden in ("username", "password", "neo4j-bolt.edgeguard.org"):
      self.assertNotIn(forbidden, flattened)

  def test_prepare_graph_explanation_rejects_before_execution_when_provider_is_unconfigured(self):
    plugin = _make_api(edgeguard_explanation_model_port=None)

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      result = plugin.prepare_graph_explanation(
        cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      )

    self.assertEqual(result["status"], "config_error")
    mocked_driver.assert_not_called()

  def test_prepare_graph_explanation_rejects_forwarded_credentials(self):
    plugin = _make_api()

    result = plugin.prepare_graph_explanation(
      cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      username="neo4j",
      password="test-password",
    )

    self.assertEqual(result["status"], "rejected")
    self.assertIn("credential_field_not_allowed", {item["code"] for item in result["validation_errors"]})

    authorization = plugin.prepare_graph_explanation(
      cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      authorization="Bearer should-not-cross",
    )
    self.assertEqual(authorization["status"], "rejected")
    self.assertIn("credential_field_not_allowed", {item["code"] for item in authorization["validation_errors"]})

    mixed_case = plugin.prepare_graph_explanation(
      cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      Authorization="Bearer should-not-cross",
    )
    self.assertEqual(mixed_case["status"], "rejected")
    self.assertNotIn("should-not-cross", json.dumps(mixed_case))

  def test_explain_graph_ingests_bounded_evidence_remaps_ids_redacts_and_never_opens_driver(self):
    plugin = _make_api(
      edgeguard_explanation_model_port=5091,
      edgeguard_explanation_model="base_qwen3_4b",
    )
    cypher = "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25"
    execution_result = _serialized_execution(cypher)

    def provider_side_effect(*_args, **kwargs):
      packet = _packet_from_provider_kwargs(kwargs)
      return _provider_response_for_packet(packet, caveat_types=[])

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      with patch(
        "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
        side_effect=provider_side_effect,
      ):
        result = plugin.explain_graph(
          cypher=cypher,
          request="Which source supports this indicator?",
          execution_result=execution_result,
          enable_empty_result_broadening=True,
        )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["explained"])
    mocked_driver.assert_not_called()
    packet = result["packet"]
    packet_json = json.dumps(packet)
    self.assertNotIn("4:indicator-raw-id", packet_json)
    self.assertNotIn("5:relationship-raw-id", packet_json)
    self.assertNotIn("raw_payload", packet_json)
    self.assertNotIn("untrusted caption", packet_json)
    self.assertEqual(result["packet_meta"]["dropped_forbidden_properties"], 1)
    self.assertTrue(all(node["id"].startswith("n:") for node in packet["graph"]["nodes"]))
    self.assertTrue(all(rel["id"].startswith("r:") for rel in packet["graph"]["relationships"]))

  def test_explain_graph_evidence_mode_rejects_forwarded_connection_fields(self):
    plugin = _make_api()
    cypher = "MATCH (i:Indicator) RETURN i LIMIT 25"

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      result = plugin.explain_graph(
        cypher=cypher,
        uri="neo4j-bolt.edgeguard.org",
        username="neo4j",
        password="test-password",
        scheme="bolt+s",
        execution_result=_serialized_execution(cypher),
      )

    self.assertEqual(result["status"], "rejected")
    self.assertIn("credential_field_not_allowed", {item["code"] for item in result["validation_errors"]})
    mocked_driver.assert_not_called()

  def test_explain_graph_evidence_mode_rejects_inconsistent_query_and_broadening_flags(self):
    plugin = _make_api()
    cypher = "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25"
    execution_result = _serialized_execution("MATCH (i:Indicator) RETURN i LIMIT 1")

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      mismatch = plugin.explain_graph(cypher=cypher, execution_result=execution_result)
      broadened = plugin.prepare_graph_explanation(
        cypher=cypher,
        enable_empty_result_broadening=True,
      )["broadening"]["cypher"]
      bad_broadening = plugin.explain_graph(
        cypher=cypher,
        enable_empty_result_broadening=True,
        execution_result=_serialized_execution(broadened, broadened=True, primary_row_count=1),
      )

    self.assertIn("executed_cypher_mismatch", {item["code"] for item in mismatch["validation_errors"]})
    self.assertIn("broadening_primary_not_empty", {item["code"] for item in bad_broadening["validation_errors"]})
    mocked_driver.assert_not_called()

  def test_explain_graph_evidence_mode_rejects_malformed_and_oversized_graphs(self):
    plugin = _make_api()
    cypher = "MATCH (i:Indicator) RETURN i LIMIT 25"
    malformed = _serialized_execution(cypher)
    malformed["graph"]["relationships"][0]["endNodeId"] = "missing-node"
    oversized = _serialized_execution(cypher)
    oversized["graph"]["nodes"] = [
      {"id": f"node-{index}", "labels": ["Indicator"], "properties": {}, "caption": "node"}
      for index in range(161)
    ]
    oversized["graph"]["relationships"] = []

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      malformed_result = plugin.explain_graph(cypher=cypher, execution_result=malformed)
      oversized_result = plugin.explain_graph(cypher=cypher, execution_result=oversized)

    self.assertIn(
      "serialized_relationship_endpoint_missing",
      {item["code"] for item in malformed_result["validation_errors"]},
    )
    self.assertIn("graph_node_limit", {item["code"] for item in oversized_result["validation_errors"]})
    mocked_driver.assert_not_called()

  def test_explain_graph_evidence_mode_rejects_nested_properties_and_recursive_credentials(self):
    plugin = _make_api()
    cypher = "MATCH (i:Indicator) RETURN i LIMIT 25"
    nested = _serialized_execution(cypher)
    nested["graph"]["nodes"][0]["properties"] = {"details": {"nested": True}}
    credential = _serialized_execution(cypher)
    credential["graph"]["nodes"][0]["properties"] = {"username": "should-not-cross"}

    nested_result = plugin.explain_graph(cypher=cypher, execution_result=nested)
    credential_result = plugin.explain_graph(cypher=cypher, execution_result=credential)

    self.assertIn(
      "invalid_serialized_property_value",
      {item["code"] for item in nested_result["validation_errors"]},
    )
    self.assertIn(
      "credential_field_not_allowed",
      {item["code"] for item in credential_result["validation_errors"]},
    )

  def test_explain_graph_evidence_mode_rejects_all_top_level_credential_aliases(self):
    plugin = _make_api()
    cypher = "MATCH (i:Indicator) RETURN i LIMIT 25"

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      for field in ("authorization", "credential", "credentials", "Authorization", "Credentials"):
        result = plugin.explain_graph(
          cypher=cypher,
          execution_result=_serialized_execution(cypher),
          **{field: "should-not-cross"},
        )
        self.assertEqual(result["status"], "rejected")
        self.assertIn("credential_field_not_allowed", {item["code"] for item in result["validation_errors"]})
      mocked_driver.assert_not_called()

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
    plugin.Pd = MagicMock()
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
    self.assertEqual(result["provider"], "local")
    self.assertEqual(result["model"], "qwen2.5-1.5b-instruct")
    self.assertIs(fake_session.trust_env, False)
    fake_session.post.assert_called_once()
    self.assertNotIn("127.0.0.1", " ".join(str(call) for call in plugin.Pd.call_args_list))

  def test_explanation_model_failures_do_not_expose_provider_internals(self):
    plugin = _make_api()
    plugin.P = MagicMock()
    packet = {"schema_version": "edgeguard.graph_evidence_packet.v1"}
    provider_internal = "http://127.0.0.1:5091/create_chat_completion?token=secret"
    fake_session = MagicMock()
    fake_session.post.return_value = _Response(payload={
      "status": "error",
      "error": f"failed at {provider_internal}",
      "provider": provider_internal,
    })

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=fake_session):
      provider_error = plugin._call_explanation_model(packet)
      fake_session.post.side_effect = requests.exceptions.ConnectionError(provider_internal)
      request_error = plugin._call_explanation_model(packet)
      fake_session.post.side_effect = RuntimeError(provider_internal)
      unexpected_error = plugin._call_explanation_model(packet)

    for result in (provider_error, request_error, unexpected_error):
      self.assertNotIn(provider_internal, json.dumps(result))
      self.assertNotIn("token=secret", json.dumps(result))
    self.assertEqual(provider_error["provider"], "local")
    self.assertEqual(request_error["error"], "EdgeGuard explanation model request failed")
    self.assertEqual(unexpected_error["error"], "Unexpected explanation model failure")
    self.assertNotIn(provider_internal, " ".join(str(call) for call in plugin.P.call_args_list))

  def test_explanation_model_context_overflow_returns_specific_safe_rejection(self):
    plugin = _make_api()
    fake_session = MagicMock()
    fake_session.post.return_value = _Response(payload={
      "result": {
        "result": {
          "status": "failed",
          "error": "Model context window exceeded.",
        },
      },
    })

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=fake_session):
      result = plugin._call_explanation_model({"schema_version": "edgeguard.graph_evidence_packet.v1"})

    self.assertEqual(result["status"], "rejected")
    self.assertEqual(result["error"], "Graph explanation evidence exceeds the model context window.")
    self.assertEqual(result["validation_errors"], [{
      "code": "context_window_exceeded",
      "detail": "Reduce the returned graph or explanation row limit.",
    }])

  def test_explanation_model_nested_timeout_returns_specific_safe_timeout(self):
    plugin = _make_api()
    fake_session = MagicMock()
    fake_session.post.return_value = _Response(payload={
      "result": {
        "result": {
          "status": "timeout",
          "error": "private provider timeout detail",
        },
      },
    })

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=fake_session):
      result = plugin._call_explanation_model({"schema_version": "edgeguard.graph_evidence_packet.v1"})

    self.assertEqual(result["status"], "timeout")
    self.assertEqual(result["error"], "EdgeGuard explanation model request timed out")
    self.assertNotIn("private provider timeout detail", json.dumps(result))

  def test_health_does_not_expose_explanation_provider_location(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)

    health = plugin.health()

    self.assertTrue(health["explanation_model_configured"])
    self.assertTrue(health["explanation_model_config_valid"])
    flattened = json.dumps(health)
    self.assertNotIn("explanation_model_url", health)
    self.assertNotIn("127.0.0.1", flattened)
    self.assertNotIn("5091", flattened)

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

  def test_canonical_validator_still_rejects_missing_required_caveat(self):
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

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["explained"])
    explanation = result["explanation"]
    self.assertIn("limit_adjusted", {item["type"] for item in explanation["caveats"]})
    explanation["caveats"] = [
      caveat for caveat in explanation["caveats"] if caveat["type"] != "limit_adjusted"
    ]
    packet_errors, context = _validate_graph_evidence_packet(result["packet"])
    self.assertEqual(packet_errors, [])
    validation_errors = _validate_case_explanation(explanation, context)
    self.assertIn("missing_required_caveat", {item["code"] for item in validation_errors})

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
    self.assertNotIn("raw_output", result)

  def test_explanation_provider_length_finish_rejects_before_parsing_without_raw_output(self):
    plugin = _make_api()
    plugin.Pd = MagicMock()
    packet = _case_explanation_packet()
    partial = '{"summary":{"text":"partial-secret"'

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=_nested_provider_response(partial, finish_reason="length", completion_tokens=1024),
    ):
      result = plugin._call_explanation_model(packet)

    self.assertEqual(result["status"], "rejected")
    self.assertEqual({item["code"] for item in result["validation_errors"]}, {"output_truncated"})
    self.assertEqual(result["error"], "Graph explanation output was truncated at the safe token limit.")
    self.assertNotIn("partial-secret", json.dumps(result))
    self.assertNotIn("raw_output", result)
    audit_log = " ".join(str(call) for call in plugin.Pd.call_args_list)
    self.assertIn('"completion_tokens":1024', audit_log)
    self.assertIn('"finish_reason":"length"', audit_log)
    self.assertIn('"max_tokens":1024', audit_log)
    self.assertIn(f'"request_sha256":"{_sha256_text(packet["request"])}"', audit_log)
    self.assertNotIn("partial-secret", audit_log)

  def test_explanation_provider_usage_at_effective_cap_rejects_malformed_output_as_truncated(self):
    plugin = _make_api()
    packet = _case_explanation_packet()

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=_nested_provider_response("{", finish_reason="stop", completion_tokens=64),
    ) as mocked_post:
      result = plugin._call_explanation_model(packet, max_tokens=64)

    self.assertEqual(mocked_post.call_args.kwargs["json"]["max_tokens"], 64)
    self.assertEqual({item["code"] for item in result["validation_errors"]}, {"output_truncated"})
    self.assertNotIn("raw_output", result)

  def test_explanation_provider_usage_at_1024_cap_rejects_malformed_output_without_disclosure(self):
    plugin = _make_api()
    plugin.Pd = MagicMock()
    packet = _case_explanation_packet()
    partial = '{"summary":{"text":"cap-secret"'

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=_nested_provider_response(partial, finish_reason="stop", completion_tokens=1024),
    ):
      result = plugin._call_explanation_model(packet)

    self.assertEqual({item["code"] for item in result["validation_errors"]}, {"output_truncated"})
    self.assertNotIn("cap-secret", json.dumps(result))
    self.assertNotIn("cap-secret", " ".join(str(call) for call in plugin.Pd.call_args_list))

  def test_explanation_provider_normal_stop_accepts_valid_json_above_old_token_cap(self):
    plugin = _make_api()
    plugin.Pd = MagicMock()
    packet = _case_explanation_packet()
    draft = _draft_for_packet(packet)

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=_nested_provider_response(
        json.dumps(draft),
        finish_reason="stop",
        completion_tokens=700,
      ),
    ):
      result = plugin._call_explanation_model(packet)

    self.assertEqual(result["status"], "accepted")
    self.assertEqual(result["explanation"]["schema_version"], "edgeguard.case_explanation.v1")
    audit_log = " ".join(str(call) for call in plugin.Pd.call_args_list)
    self.assertIn('"completion_tokens":700', audit_log)
    self.assertIn('"finish_reason":"stop"', audit_log)
    self.assertIn('"max_tokens":1024', audit_log)
    self.assertNotIn(packet["request"], audit_log)

  def test_explanation_provider_malformed_below_cap_stays_distinct(self):
    plugin = _make_api()
    packet = _case_explanation_packet()

    responses = {
      "below_cap": _nested_provider_response("{", finish_reason="stop", completion_tokens=1023),
      "missing_metadata": _Response(payload={"result": {"TEXT_RESPONSE": "{"}}),
    }
    for label, provider_response in responses.items():
      with self.subTest(label=label):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          return_value=provider_response,
        ):
          result = plugin._call_explanation_model(packet)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual({item["code"] for item in result["validation_errors"]}, {"malformed_json"})
        self.assertNotIn("raw_output", result)

  def test_explanation_provider_ignores_outer_termination_metadata(self):
    plugin = _make_api()
    packet = _case_explanation_packet()
    response = _Response(payload={
      "choices": [{
        "message": {"content": "{"},
        "finish_reason": "length",
      }],
      "usage": {"completion_tokens": 1024},
    })

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=response,
    ):
      result = plugin._call_explanation_model(packet)

    self.assertEqual({item["code"] for item in result["validation_errors"]}, {"malformed_json"})
    self.assertNotIn("raw_output", result)

  def test_explanation_provider_full_output_precedes_deeper_direct_content(self):
    plugin = _make_api()
    packet = _case_explanation_packet()
    partial = '{"summary":{"text":"partial-secret"'
    response = _Response(payload={
      "result": {
        "FULL_OUTPUT": {
          "choices": [{
            "message": {"content": partial},
            "finish_reason": "length",
          }],
          "usage": {"completion_tokens": 1024},
        },
        "result": {
          "choices": [{
            "message": {"content": json.dumps(_draft_for_packet(packet))},
            "finish_reason": "stop",
          }],
          "usage": {"completion_tokens": 32},
        },
      },
    })

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=response,
    ):
      result = plugin._call_explanation_model(packet)

    self.assertEqual({item["code"] for item in result["validation_errors"]}, {"output_truncated"})
    self.assertNotIn("partial-secret", json.dumps(result))

  def test_explain_graph_preserves_paired_truncation_transport_envelope(self):
    plugin = _make_api()
    cypher = "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25"

    with patch.object(plugin, "_call_explanation_model", return_value={
      "status": "rejected",
      "error": "Graph explanation output was truncated at the safe token limit.",
      "validation_errors": [{
        "code": "output_truncated",
        "message": "Graph explanation output was truncated at the safe token limit.",
      }],
    }):
      result = plugin.explain_graph(
        cypher=cypher,
        request="Which source supports this indicator?",
        execution_result=_serialized_execution(cypher),
      )

    self.assertEqual(result["status_code"], 500)
    self.assertEqual(result["result"]["error"], "Graph explanation output was truncated at the safe token limit.")
    self.assertEqual(
      {item["code"] for item in result["result"]["validation_errors"]},
      {"output_truncated"},
    )
    self.assertNotIn("packet", result["result"])

  def test_explain_graph_rejects_nested_schema_invalid_output(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    def provider_side_effect(*_args, **kwargs):
      packet = _packet_from_provider_kwargs(kwargs)
      explanation = _draft_for_packet(packet)
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
      explanation = _draft_for_packet(packet)
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
      explanation = _draft_for_packet(packet)
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
    self.assertIsNone(result.get("explanation"))

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
