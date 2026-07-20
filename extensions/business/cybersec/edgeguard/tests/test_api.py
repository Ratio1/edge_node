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
from extensions.business.cybersec.edgeguard.edgeguard_api import _graph_explanation_user_content  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _sha256_text  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_case_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_case_explanation_draft_bounds  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_graph_evidence_packet  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_packet_and_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _valid_temporal_value  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EDGEGUARD_REQUEST_TIMEOUT_SECONDS  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EXPLANATION_MAX_PROMPT_USER_BYTES  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EXPLANATION_MAX_OUTPUT_TOKENS  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _ResultEvidenceError  # noqa: E402


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
  fake_record = MagicMock()
  fake_record.data.return_value = {"i": indicator, "s": source}
  return fake_record


def _graph_path_record():
  indicator = _GraphNode("indicator-1", ["Indicator"], {"value": "example.org", "type": "domain"})
  source = _GraphNode("source-1", ["Source"], {"name": "AlienVault OTX"})
  rel = _GraphRelationship("rel-1", "SOURCED_FROM", indicator, source, {"confidence": "medium"})
  path = _GraphPath([indicator, source], [rel])
  fake_record = MagicMock()
  fake_record.data.return_value = {"p": path}
  return fake_record


def _serialized_execution(executed_cypher, *, broadened=False, primary_row_count=1):
  return_clause = executed_cypher.split(" RETURN ", 1)[1].rsplit(" LIMIT ", 1)[0]
  columns = []
  expressions = [item.strip() for item in return_clause.split(",")]
  base_expressions = []
  for expression in expressions:
    parts = expression.split(" AS ")
    base_expressions.append(parts[0].strip())
    columns.append(parts[-1].strip())
  indicator = {
    "id": "4:indicator-raw-id",
    "labels": ["Indicator"],
    "properties": {"value": "example.org", "type": "domain", "raw_payload": "drop me"},
    "caption": "untrusted caption",
  }
  source = {
    "id": "4:source-raw-id",
    "labels": ["Source"],
    "properties": {"name": "AlienVault OTX"},
    "caption": "untrusted source caption",
  }
  relationship = {
    "id": "5:relationship-raw-id",
    "type": "SOURCED_FROM",
    "startNodeId": "4:indicator-raw-id",
    "endNodeId": "4:source-raw-id",
    "properties": {"confidence": "medium"},
    "caption": "untrusted relationship caption",
  }
  tagged_values = {
    "i": {"type": "node", "ref": indicator["id"]},
    "s": {"type": "node", "ref": source["id"]},
    "r": {"type": "relationship", "ref": relationship["id"]},
    "p": {
      "type": "path",
      "start_node_ref": indicator["id"],
      "end_node_ref": source["id"],
      "segments": [{
        "start_node_ref": indicator["id"],
        "relationship_ref": relationship["id"],
        "end_node_ref": source["id"],
      }],
    },
  }
  graph_nodes = [indicator]
  graph_relationships = []
  if any(expression in {"s", "r", "p"} for expression in base_expressions):
    graph_nodes.append(source)
  if any(expression in {"r", "p"} for expression in base_expressions):
    graph_relationships.append(relationship)
  return {
    "executed_cypher": executed_cypher,
    "primary_row_count": primary_row_count,
    "row_count": 1,
    "truncated": False,
    "broadened": broadened,
    "graph": {
      "nodes": graph_nodes,
      "relationships": graph_relationships,
      "truncated": False,
    },
    "query_result_evidence": {
      "schema_version": "edgeguard.query_result_evidence.v1",
      "columns": columns,
      "rows": [{
        "ordinal": 0,
        "values": [
          tagged_values.get(expression, {"type": "string", "value": "example"})
          for expression in base_expressions
        ],
      }],
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


def _tag_test_value(value):
  if value is None:
    return {"type": "null"}
  if isinstance(value, bool):
    return {"type": "boolean", "value": value}
  if isinstance(value, str):
    return {"type": "string", "value": value}
  if isinstance(value, int):
    return {"type": "integer", "value": str(value)}
  if isinstance(value, float):
    return {"type": "float", "value": value}
  if isinstance(value, list):
    return {"type": "list", "items": [_tag_test_value(item) for item in value]}
  return {
    "type": "map",
    "entries": [
      {"key": str(key), "value": _tag_test_value(item)}
      for key, item in value.items()
    ],
  }


def _untag_test_value(value):
  value_type = value.get("type")
  if value_type == "null":
    return None
  if value_type in {"boolean", "string", "float"}:
    return value["value"]
  if value_type == "integer":
    return int(value["value"])
  if value_type == "list":
    return [_untag_test_value(item) for item in value["items"]]
  if value_type == "map":
    return {
      entry["key"]: _untag_test_value(entry["value"])
      for entry in value["entries"]
      if entry["value"].get("type") != "redacted"
    }
  return None


def _prompt_evidence_for_packet(packet):
  graph = packet.get("graph") or {}
  nodes = graph.get("nodes") or []
  relationships = graph.get("relationships") or []
  values = [
    *({"type": "node", "ref": node["id"]} for node in nodes),
    *({"type": "relationship", "ref": relationship["id"]} for relationship in relationships),
  ]
  if not values:
    values = [{"type": "null"}]
  return {
    "schema_version": "edgeguard.query_result_evidence.v1",
    "columns": [f"value_{index}" for index in range(len(values))],
    "rows": [{"ordinal": 0, "values": values}],
  }, {
    "nodes": [
      {
        "id": node["id"],
        "labels": node.get("labels") or [],
        "properties": _tag_test_value(node.get("properties") or {}),
      }
      for node in nodes
    ],
    "relationships": [
      {
        "id": relationship["id"],
        "type": relationship.get("type"),
        "startNodeId": relationship.get("startNodeId"),
        "endNodeId": relationship.get("endNodeId"),
        "properties": _tag_test_value(relationship.get("properties") or {}),
      }
      for relationship in relationships
    ],
  }


def _call_model(plugin, packet, **kwargs):
  query_result, catalog = _prompt_evidence_for_packet(packet)
  return plugin._call_explanation_model(packet, query_result, catalog, **kwargs)


def _build_payload(plugin, packet, **kwargs):
  query_result, catalog = _prompt_evidence_for_packet(packet)
  return plugin._build_explanation_payload(packet, query_result, catalog, **kwargs)


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
  if not packet["graph"]["relationships"]:
    nodes = packet["graph"]["nodes"]
    indicator = next(node for node in nodes if "Indicator" in node["labels"])
    source = next(node for node in nodes if "Source" in node["labels"])
    return {
      "summary": {
        "text": "The returned row pairs the indicator with its source.",
        "evidence_ids": [indicator["id"], source["id"]],
      },
      "entity_findings": [{
        "entity_id": indicator["id"],
        "role": "seed_indicator",
        "finding": "The indicator is paired with the source in the returned row.",
        "evidence_ids": [indicator["id"], source["id"]],
      }],
      "provenance": [{
        "source_node_id": source["id"],
        "source_name": source["properties"].get("name", source["caption"]),
        "supports": [indicator["id"]],
        "caveat": "The result establishes only this bounded row pairing.",
      }],
      "risk_interpretation": [{
        "claim": "The bounded row supports an informational finding only.",
        "severity": "informational",
        "evidence_ids": [indicator["id"], source["id"]],
        "limits": "The returned row does not prove malicious activity.",
      }],
      "next_pivots": [{
        "question": "Which malware is paired with this indicator?",
        "suggested_query_intent": "indicator_to_malware",
        "priority": "medium",
      }],
    }
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


def _diagnostics(
  *,
  stage,
  reason,
  finish_reason="missing",
  completion_tokens=None,
  max_tokens=1024,
  validation_codes=None,
):
  codes = sorted(set(validation_codes or []))
  return {
    "schema_version": "edgeguard.graph_explanation_diagnostic.v1",
    "reference": "egx-0123456789abcdef",
    "stage": stage,
    "reason": reason,
    "completion": {
      "finish_reason": finish_reason,
      "completion_tokens": completion_tokens,
      "max_tokens": max_tokens,
    },
    "validation_codes": codes,
    "validation_code_count": len(codes),
  }


def _packet_from_provider_kwargs(kwargs):
  prompt_context = json.loads(kwargs["json"]["messages"][1]["content"])
  catalog = prompt_context["evidence_catalog"]
  catalog_nodes = []
  for node in catalog["nodes"]:
    properties = _untag_test_value(node["properties"])
    caption = (
      properties.get("name")
      or properties.get("value")
      or (node["labels"][0] if node["labels"] else "Entity")
    )
    catalog_nodes.append({
      "id": node["id"],
      "labels": node["labels"],
      "caption": caption,
      "properties": properties,
    })
  return {
    **_case_explanation_packet(),
    "request": prompt_context["user_question"],
    "accepted_cypher": prompt_context["query"]["accepted_cypher"],
    "executed_cypher": prompt_context["query"]["executed_cypher"],
    "graph": {
      "nodes": catalog_nodes,
      "relationships": [
        {
          "id": relationship["id"],
          "type": relationship["type"],
          "startNodeId": relationship["startNodeId"],
          "endNodeId": relationship["endNodeId"],
          "caption": relationship["type"],
          "properties": {},
        }
        for relationship in catalog["relationships"]
      ],
      "truncated": False,
    },
  }


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
  plugin.cfg_edgeguard_explanation_output_mode = overrides.get(
    "edgeguard_explanation_output_mode",
    "json_object",
  )
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
    self.assertEqual(explanation["prompt_version"], "edgeguard-graph-explanation-v0.7")
    self.assertEqual(explanation["draft_schema_version"], "edgeguard.case_explanation_draft.v2")
    self.assertEqual(explanation["output_schema_version"], "edgeguard.case_explanation.v1")
    self.assertEqual(explanation["candidate_output_modes"], ["json_object", "json_schema"])
    self.assertEqual(explanation["configured_output_mode"], "json_object")
    self.assertEqual(explanation["selection_status"], "provisional_pending_phase_28_measurement")
    self.assertEqual(explanation["prompt_sha256"], _graph_explanation_prompt_sha256())
    self.assertRegex(explanation["prompt_sha256"], r"^[0-9a-f]{64}$")

  def test_graph_explanation_prompt_centers_question_and_bounds_graph_evidence(self):
    packet = _case_explanation_packet()
    query_result, catalog = _prompt_evidence_for_packet(packet)
    messages = _build_case_explanation_messages(packet, query_result, catalog)
    contract = json.loads(messages[0]["content"])
    prompt_context = json.loads(messages[1]["content"])

    self.assertEqual(contract, GRAPH_EXPLANATION_PROMPT_CONTRACT)
    self.assertEqual(prompt_context["prompt_version"], GRAPH_EXPLANATION_PROMPT_VERSION)
    self.assertEqual(prompt_context["user_question"], packet["request"])
    self.assertEqual(prompt_context["complete_query_result"], query_result)
    self.assertEqual(prompt_context["evidence_catalog"], catalog)
    self.assertEqual(prompt_context["query"], {
      "accepted_cypher": packet["accepted_cypher"],
      "executed_cypher": packet["executed_cypher"],
    })
    self.assertNotIn("graph_evidence_packet", prompt_context)
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

  def test_graph_explanation_prompt_rejects_large_complete_result_instead_of_projecting(self):
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

    query_result, catalog = _prompt_evidence_for_packet(packet)

    with self.assertRaises(_ResultEvidenceError) as raised:
      _build_case_explanation_messages(packet, query_result, catalog)

    self.assertEqual(raised.exception.code, "complete_result_prompt_bytes")

  def test_graph_explanation_prompt_hash_is_canonical_and_packet_independent(self):
    first = _build_case_explanation_messages({"request": "Question one"}, {}, {})[0]["content"]
    second = _build_case_explanation_messages({"request": "Question two"}, {}, {})[0]["content"]

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

  def test_case_explanation_complete_prompt_overflow_is_not_projected(self):
    packet = _case_explanation_packet()
    for index in range(60):
      packet["graph"]["nodes"].append({
        "id": f"n:extra-{index}",
        "labels": ["Indicator"],
        "caption": f"extra-{index}",
        "properties": {"value": f"extra-{index}.example.org", "description": "x" * 500},
      })
    query_result, catalog = _prompt_evidence_for_packet(packet)

    with self.assertRaises(_ResultEvidenceError):
      _build_case_explanation_messages(packet, query_result, catalog)

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

    default_payload = _build_payload(plugin, packet)
    smaller_payload = _build_payload(plugin, packet, max_tokens=64)
    larger_payload = _build_payload(plugin, packet, max_tokens=2048)
    non_positive_payload = _build_payload(plugin, packet, max_tokens=0)
    negative_payload = _build_payload(plugin, packet, max_tokens=-1)

    self.assertEqual(default_payload["max_tokens"], 1024)
    self.assertEqual(smaller_payload["max_tokens"], 64)
    self.assertEqual(larger_payload["max_tokens"], 1024)
    self.assertEqual(non_positive_payload["max_tokens"], 1024)
    self.assertEqual(negative_payload["max_tokens"], 1024)
    for payload in (default_payload, smaller_payload, larger_payload, non_positive_payload, negative_payload):
      self.assertEqual(payload["response_format"], {"type": "json_object"})

    schema_payload = _build_payload(plugin, packet, output_mode="json_schema")
    self.assertEqual(schema_payload["response_format"]["type"], "json_object")
    self.assertEqual(schema_payload["response_format"]["schema"]["required"], ["summary"])
    self.assertFalse(schema_payload["response_format"]["schema"]["additionalProperties"])
    self.assertEqual(schema_payload["metadata"]["output_mode"], "json_schema")

  def test_complete_prompt_accepts_exact_byte_limit_and_rejects_one_byte_more(self):
    packet = _case_explanation_packet()
    query_result, catalog = _prompt_evidence_for_packet(packet)
    packet["request"] = "q"
    base = _graph_explanation_user_content(packet, query_result, catalog)
    packet["request"] = "x" * (
      EXPLANATION_MAX_PROMPT_USER_BYTES - len(base.encode("utf-8")) + 1
    )

    at_limit = _graph_explanation_user_content(packet, query_result, catalog)
    self.assertEqual(len(at_limit.encode("utf-8")), EXPLANATION_MAX_PROMPT_USER_BYTES)

    packet["request"] += "x"
    with self.assertRaises(_ResultEvidenceError) as raised:
      _graph_explanation_user_content(packet, query_result, catalog)
    self.assertEqual(raised.exception.code, "complete_result_prompt_bytes")

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

  def test_prepare_graph_explanation_rejects_dynamic_properties_procedures_and_ambiguous_columns(self):
    plugin = _make_api()
    queries = [
      'MATCH (n:Indicator) WITH n, "value" AS k RETURN n[k] AS safe LIMIT 5',
      "MATCH (n:Indicator) CALL db.propertyKeys() YIELD propertyKey RETURN n, propertyKey LIMIT 5",
      "MATCH (n:Indicator) RETURN count(*) LIMIT 5",
    ]

    for cypher in queries:
      with self.subTest(cypher=cypher):
        result = plugin.prepare_graph_explanation(cypher=cypher)
        self.assertEqual(result["status"], "rejected")
        self.assertIn(
          "unsafe_result_projection",
          {item["code"] for item in result["validation_errors"]},
        )

  def test_legacy_explanation_applies_projection_checks_before_opening_driver(self):
    plugin = _make_api()

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver") as mocked_driver:
        result = plugin.explain_graph(
          uri="example.com:7687",
          username="neo4j",
          password="secret",
          cypher='MATCH (n:Indicator) WITH n, "value" AS k RETURN n[k] AS safe LIMIT 5',
        )

    self.assertEqual(result["status"], "rejected")
    self.assertIn(
      "unsafe_result_projection",
      {item["code"] for item in result["validation_errors"]},
    )
    mocked_driver.assert_not_called()

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

  def test_explain_graph_rejects_result_columns_that_do_not_match_return_projection(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = "MATCH (i:Indicator) RETURN i LIMIT 25"
    execution_result = _serialized_execution(cypher)
    execution_result["query_result_evidence"]["columns"] = ["spoofed"]

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
    ) as mocked_post:
      result = plugin.explain_graph(cypher=cypher, execution_result=execution_result)

    self.assertIn(
      "result_columns_mismatch",
      {item["code"] for item in result["validation_errors"]},
    )
    mocked_post.assert_not_called()

  def test_explain_graph_preserves_pairings_duplicates_nulls_scalars_maps_lists_and_reverse_path(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = (
      "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) "
      "RETURN s AS source, i AS indicator, i.value AS nullable, i.value AS total, "
      "i.value AS ratio, i.value AS items, i.value AS aggregate, p AS path LIMIT 25"
    )
    execution_result = _serialized_execution(cypher, primary_row_count=2)
    execution_result["row_count"] = 2
    relationship = execution_result["graph"]["relationships"][0]
    row_values = [
      {"type": "node", "ref": "4:source-raw-id"},
      {"type": "node", "ref": "4:indicator-raw-id"},
      {"type": "null"},
      {"type": "integer", "value": "9007199254740993"},
      {"type": "float", "value": 1.5},
      {"type": "list", "items": [{"type": "string", "value": "a"}, {"type": "null"}]},
      {
        "type": "map",
        "entries": [
          {"key": "count", "value": {"type": "integer", "value": "2"}},
          {"key": "api_token", "value": {"type": "string", "value": "must-redact"}},
        ],
      },
      {
        "type": "path",
        "start_node_ref": "4:source-raw-id",
        "end_node_ref": "4:indicator-raw-id",
        "segments": [{
          "start_node_ref": "4:source-raw-id",
          "relationship_ref": relationship["id"],
          "end_node_ref": "4:indicator-raw-id",
        }],
      },
    ]
    execution_result["query_result_evidence"] = {
      "schema_version": "edgeguard.query_result_evidence.v1",
      "columns": ["source", "indicator", "nullable", "total", "ratio", "items", "aggregate", "path"],
      "rows": [
        {"ordinal": 0, "values": row_values},
        {"ordinal": 1, "values": json.loads(json.dumps(row_values))},
      ],
    }
    captured = {}

    def provider_side_effect(*_args, **kwargs):
      captured.update(json.loads(kwargs["json"]["messages"][1]["content"]))
      return _provider_response_for_packet(_packet_from_provider_kwargs(kwargs))

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      side_effect=provider_side_effect,
    ):
      result = plugin.explain_graph(
        cypher=cypher,
        request="Explain the exact returned pairs.",
        execution_result=execution_result,
      )

    self.assertEqual(result["status"], "ok")
    complete = captured["complete_query_result"]
    self.assertEqual(complete["columns"], execution_result["query_result_evidence"]["columns"])
    self.assertEqual(
      complete["rows"][0]["values"][:6],
      complete["rows"][1]["values"][:6],
    )
    self.assertEqual(
      complete["rows"][0]["values"][7],
      complete["rows"][1]["values"][7],
    )
    self.assertEqual(
      complete["rows"][1]["values"][6]["entries"][1]["value"]["type"],
      "redacted",
    )
    self.assertEqual(complete["rows"][0]["values"][2], {"type": "null"})
    self.assertEqual(complete["rows"][0]["values"][3]["value"], "9007199254740993")
    redacted = complete["rows"][0]["values"][6]["entries"][1]["value"]
    self.assertEqual(redacted["type"], "redacted")
    self.assertEqual(redacted["reason"], "security_policy")
    self.assertNotIn("must-redact", json.dumps(captured))
    reverse_path = complete["rows"][0]["values"][7]
    self.assertEqual(reverse_path["start_node_ref"], complete["rows"][0]["values"][0]["ref"])
    self.assertEqual(reverse_path["end_node_ref"], complete["rows"][0]["values"][1]["ref"])
    self.assertEqual(len(captured["evidence_catalog"]["relationships"]), 1)

  def test_explain_graph_rejects_incomplete_or_oversized_evidence_without_model_call(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = "MATCH (i:Indicator) RETURN i LIMIT 25"
    truncated = _serialized_execution(cypher)
    truncated["truncated"] = True
    oversized = _serialized_execution(cypher)
    oversized["query_result_evidence"]["rows"][0]["values"][0] = {
      "type": "string",
      "value": "x" * 525_000,
    }

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
    ) as mocked_post:
      truncated_result = plugin.explain_graph(cypher=cypher, execution_result=truncated)
      oversized_result = plugin.explain_graph(cypher=cypher, execution_result=oversized)

    self.assertIn(
      "incomplete_execution_result",
      {item["code"] for item in truncated_result["validation_errors"]},
    )
    self.assertIn(
      "execution_result_size",
      {item["code"] for item in oversized_result["validation_errors"]},
    )
    mocked_post.assert_not_called()

  def test_explain_graph_rejects_unresolved_references_and_evidence_id_collisions(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25"
    unresolved = _serialized_execution(cypher)
    unresolved["query_result_evidence"]["rows"][0]["values"][0]["ref"] = "missing"
    collision = _serialized_execution(cypher)

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
    ) as mocked_post:
      unresolved_result = plugin.explain_graph(cypher=cypher, execution_result=unresolved)
      with patch(
        "extensions.business.cybersec.edgeguard.edgeguard_api._evidence_id",
        side_effect=lambda prefix, _key: f"{prefix}:collision",
      ):
        collision_result = plugin.explain_graph(cypher=cypher, execution_result=collision)

    self.assertIn(
      "unresolved_node_reference",
      {item["code"] for item in unresolved_result["validation_errors"]},
    )
    self.assertIn(
      "evidence_id_collision",
      {item["code"] for item in collision_result["validation_errors"]},
    )
    mocked_post.assert_not_called()

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
    cypher = (
      "MATCH (i:Indicator)-[r:SOURCED_FROM]->(s:Source) "
      "RETURN i, s, r LIMIT 25"
    )
    malformed = _serialized_execution(cypher)
    malformed["graph"]["relationships"][0]["endNodeId"] = "missing-node"
    oversized = _serialized_execution(cypher)
    oversized["graph"]["nodes"] = [
      {"id": f"node-{index}", "labels": ["Indicator"], "properties": {}, "caption": "node"}
      for index in range(161)
    ]
    oversized["graph"]["relationships"] = []
    too_many_relationships = _serialized_execution(cypher)
    too_many_relationships["graph"]["relationships"] = [
      {
        "id": f"relationship-{index}",
        "type": "SOURCED_FROM",
        "startNodeId": "4:indicator-raw-id",
        "endNodeId": "4:source-raw-id",
        "properties": {},
        "caption": "SOURCED_FROM",
      }
      for index in range(241)
    ]

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      malformed_result = plugin.explain_graph(cypher=cypher, execution_result=malformed)
      oversized_result = plugin.explain_graph(cypher=cypher, execution_result=oversized)
      relationships_result = plugin.explain_graph(
        cypher=cypher,
        execution_result=too_many_relationships,
      )

    self.assertIn(
      "serialized_relationship_endpoint_missing",
      {item["code"] for item in malformed_result["validation_errors"]},
    )
    self.assertIn("graph_node_limit", {item["code"] for item in oversized_result["validation_errors"]})
    self.assertIn(
      "graph_relationship_limit",
      {item["code"] for item in relationships_result["validation_errors"]},
    )
    mocked_driver.assert_not_called()

  def test_explain_graph_evidence_mode_rejects_nested_properties_and_redacts_sensitive_properties(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25"
    nested = _serialized_execution(cypher)
    nested["graph"]["nodes"][0]["properties"] = {"details": {"nested": True}}
    credential = _serialized_execution(cypher)
    credential["graph"]["nodes"][0]["properties"] = {"api_token": "should-not-cross"}

    nested_result = plugin.explain_graph(cypher=cypher, execution_result=nested)
    captured = {}

    def provider_side_effect(*_args, **kwargs):
      captured.update(json.loads(kwargs["json"]["messages"][1]["content"]))
      return _provider_response_for_packet(_packet_from_provider_kwargs(kwargs))

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      side_effect=provider_side_effect,
    ):
      credential_result = plugin.explain_graph(cypher=cypher, execution_result=credential)

    self.assertIn(
      "invalid_serialized_property_value",
      {item["code"] for item in nested_result["validation_errors"]},
    )
    self.assertEqual(credential_result["status"], "ok")
    flattened = json.dumps(captured)
    self.assertNotIn("should-not-cross", flattened)
    self.assertIn('"type": "redacted"', flattened)
    self.assertIn('"reason": "security_policy"', flattened)
    self.assertIn("/evidence_catalog/nodes/", flattened)

  def test_forbidden_result_values_are_validated_before_server_redaction(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = "MATCH (i:Indicator) RETURN i.value AS api_token LIMIT 25"

    for invalid_value, expected_code in (
      ({"type": "redacted", "reason": "security_policy", "path": "/client"}, "client_redaction_not_allowed"),
      ({}, "unsupported_query_result_value"),
    ):
      with self.subTest(expected_code=expected_code):
        execution_result = _serialized_execution(cypher)
        execution_result["query_result_evidence"]["rows"][0]["values"][0] = invalid_value
        result = plugin.explain_graph(cypher=cypher, execution_result=execution_result)
        self.assertIn(
          expected_code,
          {item["code"] for item in result["validation_errors"]},
        )

    map_cypher = "MATCH (i:Indicator) RETURN i, i.value AS mapping LIMIT 25"
    map_result = _serialized_execution(map_cypher)
    map_result["query_result_evidence"]["rows"][0]["values"][1] = {
      "type": "map",
      "entries": [{
        "key": "api_token",
        "value": {"type": "redacted", "reason": "security_policy", "path": "/client"},
      }],
    }
    rejected_map = plugin.explain_graph(cypher=map_cypher, execution_result=map_result)
    self.assertIn(
      "client_redaction_not_allowed",
      {item["code"] for item in rejected_map["validation_errors"]},
    )

  def test_canonical_integer_temporal_and_point_values_fail_closed(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = "MATCH (i:Indicator) RETURN i, i.value AS value LIMIT 25"
    invalid_values = [
      ({"type": "integer", "value": "-0"}, "invalid_result_integer"),
      (
        {"type": "temporal", "temporal_type": "date", "value": "not-a-date"},
        "invalid_result_temporal",
      ),
      ({"type": "point", "srid": "4326", "x": float("inf"), "y": 1.0}, "invalid_result_point"),
    ]
    for value, expected_code in invalid_values:
      with self.subTest(value=value):
        execution_result = _serialized_execution(cypher)
        execution_result["query_result_evidence"]["rows"][0]["values"][1] = value
        result = plugin.explain_graph(cypher=cypher, execution_result=execution_result)
        self.assertIn(
          expected_code,
          {item["code"] for item in result["validation_errors"]},
        )

    valid_temporals = {
      "date": "2026-07-20",
      "date_time": "2026-07-20T12:30:00Z",
      "duration": "P1DT2H",
      "local_date_time": "2026-07-20T12:30:00",
      "local_time": "12:30:00",
      "time": "12:30:00+00:00",
    }
    self.assertTrue(all(
      _valid_temporal_value(temporal_type, value)
      for temporal_type, value in valid_temporals.items()
    ))
    self.assertFalse(_valid_temporal_value("date_time", "2026-07-20T12:30:00"))
    self.assertFalse(_valid_temporal_value("local_time", "12:30:00Z"))

  def test_nested_map_and_row_invariants_fail_closed(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = "MATCH (i:Indicator) RETURN i, i.value AS value LIMIT 25"
    nested = {"type": "string", "value": "leaf"}
    for _index in range(10):
      nested = {"type": "list", "items": [nested]}
    cases = [
      (nested, "result_nesting_limit"),
      (
        {
          "type": "map",
          "entries": [
            {"key": "same", "value": {"type": "null"}},
            {"key": "same", "value": {"type": "null"}},
          ],
        },
        "invalid_result_map",
      ),
    ]
    for value, expected_code in cases:
      with self.subTest(expected_code=expected_code):
        execution_result = _serialized_execution(cypher)
        execution_result["query_result_evidence"]["rows"][0]["values"][1] = value
        result = plugin.explain_graph(cypher=cypher, execution_result=execution_result)
        self.assertIn(
          expected_code,
          {item["code"] for item in result["validation_errors"]},
        )

    bad_ordinal = _serialized_execution(cypher)
    bad_ordinal["query_result_evidence"]["rows"][0]["ordinal"] = 1
    result = plugin.explain_graph(cypher=cypher, execution_result=bad_ordinal)
    self.assertIn(
      "invalid_result_row",
      {item["code"] for item in result["validation_errors"]},
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

  def test_explain_graph_reports_unconfigured_provider_as_safe_terminal_failure(self):
    plugin = _make_api(edgeguard_explanation_model_url="https://example.test/v1/chat/completions")
    plugin.P = MagicMock()

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      result = plugin.explain_graph(
        uri="example.com:7687",
        scheme="bolt+s",
        username="neo4j",
        password="secret",
        cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      )

    self.assertEqual(result["status_code"], 500)
    self.assertTrue(result["logged"])
    self.assertEqual(result["result"]["status"], "error")
    self.assertEqual(result["result"]["diagnostics"]["stage"], "configuration")
    self.assertEqual(result["result"]["diagnostics"]["reason"], "model_not_configured")
    self.assertEqual(
      " ".join(str(call) for call in plugin.P.call_args_list).count(
        "EDGEGUARD_EXPLANATION_OUTCOME"
      ),
      1,
    )
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
      result = _call_model(plugin, packet)

    self.assertEqual(result["status"], "accepted")
    self.assertEqual(result["provider"], "local")
    self.assertEqual(result["model"], "qwen2.5-1.5b-instruct")
    self.assertIs(fake_session.trust_env, False)
    fake_session.post.assert_called_once()
    self.assertNotIn("127.0.0.1", " ".join(str(call) for call in plugin.Pd.call_args_list))

  def test_explanation_model_configuration_failure_emits_one_safe_outcome(self):
    plugin = _make_api(edgeguard_explanation_model_host=None, edgeguard_explanation_model_port=None)
    plugin.P = MagicMock()

    result = _call_model(plugin, _case_explanation_packet())

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["diagnostics"]["stage"], "configuration")
    self.assertEqual(result["diagnostics"]["reason"], "model_not_configured")
    outcome_log = " ".join(str(call) for call in plugin.P.call_args_list)
    self.assertEqual(outcome_log.count("EDGEGUARD_EXPLANATION_OUTCOME"), 1)
    self.assertNotIn("port or URL", outcome_log)

  def test_malformed_explanation_model_configuration_emits_one_safe_outcome(self):
    plugin = _make_api(
      edgeguard_explanation_model_url=None,
      edgeguard_explanation_model_host="127.0.0.1",
      edgeguard_explanation_model_port="not-a-port",
    )
    plugin.P = MagicMock()

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      result = plugin.explain_graph(
        cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
        request="Explain graph.",
      )

    self.assertEqual(result["status_code"], 500)
    self.assertEqual(result["result"]["status"], "error")
    self.assertEqual(result["result"]["diagnostics"]["stage"], "configuration")
    self.assertEqual(result["result"]["diagnostics"]["reason"], "model_not_configured")
    outcome_log = " ".join(str(call) for call in plugin.P.call_args_list)
    self.assertEqual(outcome_log.count("EDGEGUARD_EXPLANATION_OUTCOME"), 1)
    self.assertNotIn("not-a-port", outcome_log)
    mocked_driver.assert_not_called()

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
      provider_error = _call_model(plugin, packet)
      fake_session.post.side_effect = requests.exceptions.ConnectionError(provider_internal)
      request_error = _call_model(plugin, packet)
      fake_session.post.side_effect = RuntimeError(provider_internal)
      unexpected_error = _call_model(plugin, packet)

    for result in (provider_error, request_error, unexpected_error):
      self.assertNotIn(provider_internal, json.dumps(result))
      self.assertNotIn("token=secret", json.dumps(result))
      self.assertRegex(result["diagnostics"]["reference"], r"^egx-[0-9a-f]{16}$")
    self.assertEqual(provider_error["provider"], "local")
    self.assertEqual(request_error["error"], "EdgeGuard explanation model request failed")
    self.assertEqual(unexpected_error["error"], "Unexpected explanation model failure")
    outcome_log = " ".join(str(call) for call in plugin.P.call_args_list)
    self.assertEqual(outcome_log.count("EDGEGUARD_EXPLANATION_OUTCOME"), 3)
    self.assertNotIn(provider_internal, outcome_log)

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
      result = _call_model(plugin, {"schema_version": "edgeguard.graph_evidence_packet.v1"})

    self.assertEqual(result["status"], "rejected")
    self.assertEqual(result["error"], "Graph explanation evidence exceeds the model context window.")
    self.assertEqual(result["validation_errors"], [{
      "code": "context_window_exceeded",
      "detail": "Reduce the returned graph or explanation row limit.",
    }])
    self.assertEqual(result["diagnostics"]["stage"], "provider")
    self.assertEqual(result["diagnostics"]["reason"], "context_window_exceeded")
    self.assertEqual(result["diagnostics"]["validation_codes"], ["context_window_exceeded"])

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
      result = _call_model(plugin, {"schema_version": "edgeguard.graph_evidence_packet.v1"})

    self.assertEqual(result["status"], "timeout")
    self.assertEqual(result["error"], "EdgeGuard explanation model request timed out")
    self.assertEqual(result["diagnostics"]["stage"], "provider")
    self.assertEqual(result["diagnostics"]["reason"], "provider_timeout")
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
      _Result([_graph_path_record()], keys=["p"]),
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

  def test_explain_graph_rejects_truncated_execution_without_model_call(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(
      _Result([_graph_record() for _idx in range(25)], keys=["p"]),
    )

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
        ) as mocked_post:
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
          )

    self.assertEqual(result["status"], "rejected")
    self.assertIn(
      "incomplete_execution_result",
      {item["code"] for item in result["validation_errors"]},
    )
    mocked_post.assert_not_called()

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

    self.assertEqual(result["status_code"], 500)
    self.assertTrue(result["logged"])
    self.assertEqual(result["result"]["status"], "rejected")
    self.assertEqual(result["result"]["diagnostics"]["reason"], "malformed_json")
    self.assertEqual(result["result"]["diagnostics"]["validation_codes"], ["malformed_json"])
    self.assertNotIn("validation_errors", result["result"])
    self.assertNotIn("packet", result["result"])
    self.assertNotIn("raw_output", result)

  def test_explanation_provider_length_finish_rejects_before_parsing_without_raw_output(self):
    plugin = _make_api()
    plugin.P = MagicMock()
    packet = _case_explanation_packet()
    partial = '{"summary":{"text":"partial-secret"'

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=_nested_provider_response(partial, finish_reason="length", completion_tokens=1024),
    ):
      result = _call_model(plugin, packet)

    self.assertEqual(result["status"], "rejected")
    self.assertEqual({item["code"] for item in result["validation_errors"]}, {"output_truncated"})
    self.assertEqual(result["error"], "Graph explanation output was truncated at the safe token limit.")
    self.assertNotIn("partial-secret", json.dumps(result))
    self.assertNotIn("raw_output", result)
    audit_log = " ".join(str(call) for call in plugin.P.call_args_list)
    self.assertEqual(audit_log.count("EDGEGUARD_EXPLANATION_OUTCOME"), 1)
    self.assertRegex(audit_log, r'"reference":"egx-[0-9a-f]{16}"')
    self.assertIn('"reason":"output_truncated"', audit_log)
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
      result = _call_model(plugin, packet, max_tokens=64)

    self.assertEqual(mocked_post.call_args.kwargs["json"]["max_tokens"], 64)
    self.assertEqual({item["code"] for item in result["validation_errors"]}, {"output_truncated"})
    self.assertNotIn("raw_output", result)

  def test_explanation_provider_usage_at_1024_cap_rejects_malformed_output_without_disclosure(self):
    plugin = _make_api()
    plugin.P = MagicMock()
    packet = _case_explanation_packet()
    partial = '{"summary":{"text":"cap-secret"'

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=_nested_provider_response(partial, finish_reason="stop", completion_tokens=1024),
    ):
      result = _call_model(plugin, packet)

    self.assertEqual({item["code"] for item in result["validation_errors"]}, {"output_truncated"})
    self.assertNotIn("cap-secret", json.dumps(result))
    self.assertNotIn("cap-secret", " ".join(str(call) for call in plugin.P.call_args_list))

  def test_explanation_provider_normal_stop_accepts_valid_json_above_old_token_cap(self):
    plugin = _make_api()
    plugin.P = MagicMock()
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
      result = _call_model(plugin, packet)

    self.assertEqual(result["status"], "accepted")
    self.assertEqual(result["explanation"]["schema_version"], "edgeguard.case_explanation.v1")
    audit_log = " ".join(str(call) for call in plugin.P.call_args_list)
    self.assertEqual(audit_log.count("EDGEGUARD_EXPLANATION_OUTCOME"), 1)
    self.assertRegex(audit_log, r'"reference":"egx-[0-9a-f]{16}"')
    self.assertIn('"reason":"accepted"', audit_log)
    self.assertIn('"completion_tokens":700', audit_log)
    self.assertIn('"finish_reason":"stop"', audit_log)
    self.assertIn('"max_tokens":1024', audit_log)
    self.assertNotIn(packet["request"], audit_log)

  def test_explanation_normal_stop_validation_rejection_emits_one_safe_outcome(self):
    plugin = _make_api()
    plugin.P = MagicMock()
    packet = _case_explanation_packet()
    draft = _draft_for_packet(packet)
    draft["summary"]["evidence_ids"] = ["n:private-evidence-sentinel"]

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=_nested_provider_response(
        json.dumps(draft),
        finish_reason="stop",
        completion_tokens=589,
      ),
    ):
      result = _call_model(plugin, packet)

    self.assertEqual(result["status"], "rejected")
    diagnostics = result["diagnostics"]
    self.assertEqual(diagnostics["stage"], "validation")
    self.assertEqual(diagnostics["reason"], "deterministic_validation_failed")
    self.assertEqual(diagnostics["completion"], {
      "finish_reason": "stop",
      "completion_tokens": 589,
      "max_tokens": 1024,
    })
    self.assertIn("unknown_evidence_id", diagnostics["validation_codes"])
    self.assertEqual(
      diagnostics["validation_codes"],
      sorted(set(diagnostics["validation_codes"])),
    )
    self.assertEqual(diagnostics["validation_code_count"], len(diagnostics["validation_codes"]))
    self.assertRegex(diagnostics["reference"], r"^egx-[0-9a-f]{16}$")

    outcome_log = " ".join(str(call) for call in plugin.P.call_args_list)
    self.assertEqual(outcome_log.count("EDGEGUARD_EXPLANATION_OUTCOME"), 1)
    self.assertIn('"completion_tokens":589', outcome_log)
    self.assertIn('"finish_reason":"stop"', outcome_log)
    self.assertIn('"reason":"deterministic_validation_failed"', outcome_log)
    for forbidden in (
      packet["request"],
      packet["accepted_cypher"],
      "n:private-evidence-sentinel",
      "unknown evidence id",
    ):
      self.assertNotIn(forbidden, outcome_log)

    transport = plugin._explanation_failure_transport(result)
    flattened = json.dumps(transport)
    self.assertEqual(transport["status_code"], 500)
    self.assertTrue(transport["logged"])
    self.assertEqual(
      transport["result"]["diagnostics"]["reference"],
      diagnostics["reference"],
    )
    self.assertNotIn("validation_errors", transport["result"])
    for forbidden in (
      "packet",
      "provider",
      "model",
      "n:private-evidence-sentinel",
      packet["accepted_cypher"],
    ):
      self.assertNotIn(forbidden, flattened)

  def test_explanation_terminal_failures_emit_one_outcome_with_fixed_reason(self):
    packet = _case_explanation_packet()
    cases = {
      "missing_content": (
        _Response(payload={"result": {"FULL_OUTPUT": {"usage": {"completion_tokens": 0}}}}),
        "completion",
        "missing_content",
      ),
      "provider_http_error": (
        _Response(status_code=503, text="provider-secret"),
        "provider",
        "provider_http_error",
      ),
    }
    for label, (provider_response, stage, reason) in cases.items():
      with self.subTest(label=label):
        plugin = _make_api()
        plugin.P = MagicMock()
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          return_value=provider_response,
        ):
          result = _call_model(plugin, packet)
        self.assertEqual(result["diagnostics"]["stage"], stage)
        self.assertEqual(result["diagnostics"]["reason"], reason)
        outcome_log = " ".join(str(call) for call in plugin.P.call_args_list)
        self.assertEqual(outcome_log.count("EDGEGUARD_EXPLANATION_OUTCOME"), 1)
        self.assertNotIn("provider-secret", outcome_log)

  def test_explanation_timeout_and_unexpected_failure_emit_safe_outcomes(self):
    packet = _case_explanation_packet()
    cases = {
      "timeout": (requests.exceptions.Timeout(), "provider", "provider_timeout"),
      "unexpected": (RuntimeError("exception-secret /tmp/private"), "internal", "unexpected_failure"),
    }
    for label, (failure, stage, reason) in cases.items():
      with self.subTest(label=label):
        plugin = _make_api()
        plugin.P = MagicMock()
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
          side_effect=failure,
        ):
          result = _call_model(plugin, packet)
        self.assertEqual(result["diagnostics"]["stage"], stage)
        self.assertEqual(result["diagnostics"]["reason"], reason)
        outcome_log = " ".join(str(call) for call in plugin.P.call_args_list)
        self.assertEqual(outcome_log.count("EDGEGUARD_EXPLANATION_OUTCOME"), 1)
        self.assertNotIn("exception-secret", outcome_log)
        self.assertNotIn("/tmp/private", outcome_log)

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
          result = _call_model(plugin, packet)
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
      result = _call_model(plugin, packet)

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
      result = _call_model(plugin, packet)

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
      "diagnostics": _diagnostics(
        stage="completion",
        reason="output_truncated",
        finish_reason="length",
        completion_tokens=1024,
        validation_codes=["output_truncated"],
      ),
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
    self.assertTrue(result["logged"])
    self.assertEqual(result["result"]["diagnostics"]["reason"], "output_truncated")
    self.assertNotIn("packet", result["result"])

  def test_explain_graph_rejects_nested_schema_invalid_output(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    def provider_side_effect(*_args, **kwargs):
      packet = _packet_from_provider_kwargs(kwargs)
      explanation = _draft_for_packet(packet)
      explanation["summary"].pop("text")
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

    diagnostics = result["result"]["diagnostics"]
    codes = set(diagnostics["validation_codes"])
    self.assertEqual(result["status_code"], 500)
    self.assertTrue(result["logged"])
    self.assertEqual(diagnostics["stage"], "validation")
    self.assertEqual(diagnostics["reason"], "deterministic_validation_failed")
    self.assertIn("schema_required", codes)
    self.assertIn("schema_enum", codes)
    self.assertNotIn("validation_errors", result["result"])

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

    self.assertEqual(result["status_code"], 500)
    self.assertIn(
      "severity_escalation_unsupported",
      set(result["result"]["diagnostics"]["validation_codes"]),
    )
    self.assertNotIn("validation_errors", result["result"])

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

    codes = set(result["result"]["diagnostics"]["validation_codes"])
    self.assertEqual(result["status_code"], 500)
    self.assertIn("unknown_evidence_id", codes)
    self.assertIn("invented_source_name", codes)
    self.assertIn("unsafe_pivot", codes)
    self.assertNotIn("explanation", result["result"])
    self.assertNotIn("validation_errors", result["result"])

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

    self.assertEqual(result["status_code"], 500)
    self.assertTrue(result["logged"])
    self.assertEqual(result["result"]["status"], "error")
    self.assertTrue(result["result"]["executed"])
    self.assertFalse(result["result"]["explained"])
    self.assertEqual(result["result"]["diagnostics"]["stage"], "provider")
    self.assertEqual(result["result"]["diagnostics"]["reason"], "provider_http_error")
    self.assertNotIn("provider_status", result["result"])
    self.assertNotIn("packet", result["result"])

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
