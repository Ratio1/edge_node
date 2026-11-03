import hashlib
import json
import os
import re
import requests
import threading
import unittest
import sys
import time
from pathlib import Path
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
from extensions.business.cybersec.edgeguard.edgeguard_api import _build_graph_evidence_packet  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _build_graph_evidence_packet_from_execution  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _construct_case_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _graph_explanation_prompt_contract_text  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _graph_explanation_prompt_sha256  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _graph_explanation_user_content  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _sha256_text  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _tag_serialized_property  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_case_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_case_explanation_draft_bounds  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_graph_evidence_packet  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _validate_packet_and_explanation  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _valid_temporal_value  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EDGEGUARD_REQUEST_TIMEOUT_SECONDS  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EXPLANATION_MAX_PROMPT_USER_BYTES  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EXPLANATION_MAX_OUTPUT_TOKENS  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import EXPLANATION_SERVER_MAX_ROWS  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _ResultEvidenceError  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import Neo4jAuthError  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import Neo4jClientError  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _neo4j_row_json_safe  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import GENERATION_MAX_TOKENS  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import GENERATION_MAX_REQUEST_CHARS  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import CYPHER_MAX_CHARS  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import PROMPT_PROFILE_V0_11_PATTERN_SCHEMA  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _prepare_graph_explanation_plan  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_api import _WRAPPER_STATUS_CODE_KEY  # noqa: E402
from extensions.business.cybersec.edgeguard.graph_first_runtime import GraphFirstRuntimeError, render_chat  # noqa: E402
from extensions.business.cybersec.edgeguard.edgeguard_cypher_guard import (  # noqa: E402
  build_direct_cypher_system_prompt,
  build_schema_correction_prompt,
  build_v0_11_correction_prompt,
  build_v0_11_pattern_schema_system_prompt,
  canonical_schema_surface,
  SCHEMA_VERSION,
)
from extensions.business.cybersec.edgeguard import literal_classes  # noqa: E402


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


class _DriverRecord:
  def __init__(self, values, exported):
    self._values = values
    self._exported = exported

  def keys(self):
    return list(self._values)

  def __getitem__(self, key):
    return self._values[key]

  def data(self):
    return self._exported


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


class DateTime:
  def __str__(self):
    return "2026-08-03T17:00:00Z"


def _graph_record():
  indicator = _GraphNode("indicator-1", ["Indicator"], {"value": "example.org", "type": "domain"})
  source = _GraphNode("source-1", ["Source"], {"name": "AlienVault OTX"})
  return _DriverRecord(
    {"i": indicator, "s": source},
    {"i": {"value": "example.org", "type": "domain"}, "s": {"name": "AlienVault OTX"}},
  )


def _graph_path_record():
  indicator = _GraphNode("indicator-1", ["Indicator"], {"value": "example.org", "type": "domain"})
  source = _GraphNode("source-1", ["Source"], {"name": "AlienVault OTX"})
  rel = _GraphRelationship("rel-1", "SOURCED_FROM", indicator, source, {"confidence": "medium"})
  path = _GraphPath([indicator, source], [rel])
  return _DriverRecord(
    {"p": path},
    {"p": [{"value": "example.org", "type": "domain"}, "SOURCED_FROM", {"name": "AlienVault OTX"}]},
  )


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


def _graph_first_payload(result):
  if isinstance(result, dict) and set(result) == {"status_code", "result", "logged"}:
    return result["result"]
  return result


def _case_explanation_packet():
  return {
    "schema_version": "edgeguard.graph_evidence_packet.v1",
    "request": "Which source supports this indicator?",
    "accepted_cypher": "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
    "executed_cypher": "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
    "limit_policy": {
      "generated_limit": 25,
      "executed_limit": 25,
      "server_max_rows": 50,
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


def _run_text(call):
  """Cypher text passed to session.run, whether wrapped in neo4j.Query or not."""
  query = call.args[0]
  return getattr(query, "text", query)


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


def _graph_first_provider(payload):
  """Return a valid EEL/1 map or synthesis completion for API tests."""
  task = payload["metadata"]["task"]
  user = payload["messages"][-1]["content"]
  data = json.loads(user.split("\nDATA\n", 1)[1])
  if task == "edgeguard_graph_first_synthesis":
    content = {
      "status": "supported",
      "text": "The returned graph evidence supports the investigation finding.",
      "maps": [finding["id"] for finding in data],
    }
  else:
    content = {
      "status": "supported",
      "text": "The returned graph evidence supports the investigation finding.",
      "anchor": data["nodes"][0][0],
      "rows": [row[0] for row in data["rows"]],
    }
  return {
    "content": json.dumps(content, separators=(",", ":")),
    "finish_reason": "stop",
    "completion_tokens": 16,
    "duration_ms": 1.0,
  }


# A deployment-supplied model entry. The repository ships public models only;
# this fixture stands in for whatever private or experimental model a pipeline
# adds to EDGEGUARD_GENERATION_WORKERS. Listed first, so it is the default.
PRIVATE_MODEL_KEY = "private-model-a"
PRIVATE_WORKER_SEMAPHORE = "edgeguard_llm_private"
TEST_GENERATION_WORKERS = {
  PRIVATE_MODEL_KEY: {
    "SEMAPHORE": PRIVATE_WORKER_SEMAPHORE,
    "PATH": "/create_chat_completion",
    "PROMPT_PROFILE": "direct_cypher",
    "DISPLAY_NAME": "Private fixture model",
    "DESCRIPTION": "Deployment-supplied fine-tuned GGUF fixture.",
    "MODEL_REPO": "example-org/private-fixture-gguf",
    "MODEL_FILE": "private-fixture.Q4_K_M.gguf",
    "FORMAT": "GGUF",
    "QUANTIZATION": "Q4_K_M",
    "BASE_MODEL": "Qwen/Qwen3-4B-Instruct-2507",
    "ARTIFACT_SHA256": "0" * 64,
    "SOURCE": "private_deployment",
    "MODEL_CARD": {"method": "QLoRA SFT"},
  },
  **EdgeguardApiPlugin.CONFIG["EDGEGUARD_GENERATION_WORKERS"],
}

# A second deployment-supplied fixture, fine-tuned on the v0.11 artifact
# (EGM-059 phase 2 slice C). Kept out of `TEST_GENERATION_WORKERS` so the
# existing "exactly three models" catalog pin is untouched; tests that need
# it pass `edgeguard_generation_workers=` explicitly.
V0_11_MODEL_KEY = "v0-11-fixture-model"
V0_11_WORKER_SEMAPHORE = "edgeguard_llm_v0_11"
TEST_GENERATION_WORKERS_WITH_V0_11 = {
  V0_11_MODEL_KEY: {
    "SEMAPHORE": V0_11_WORKER_SEMAPHORE,
    "PATH": "/create_chat_completion",
    "PROMPT_PROFILE": PROMPT_PROFILE_V0_11_PATTERN_SCHEMA,
    "DISPLAY_NAME": "Private v0.11 fixture model",
    "DESCRIPTION": "Deployment-supplied fine-tuned-on-v0.11 GGUF fixture.",
    "MODEL_REPO": "example-org/private-v0-11-fixture-gguf",
    "MODEL_FILE": "private-v0-11-fixture.Q4_K_M.gguf",
    "FORMAT": "GGUF",
    "QUANTIZATION": "Q4_K_M",
    "BASE_MODEL": "Qwen/Qwen3-4B-Instruct-2507",
    "ARTIFACT_SHA256": "1" * 64,
    "SOURCE": "private_deployment",
    "MODEL_CARD": {"method": "QLoRA SFT"},
  },
  **TEST_GENERATION_WORKERS,
}


def _make_api(**overrides):
  plugin = EdgeguardApiPlugin.__new__(EdgeguardApiPlugin)
  plugin.cfg_edgeguard_generation_workers = overrides.get(
    "edgeguard_generation_workers",
    TEST_GENERATION_WORKERS,
  )
  plugin.cfg_edgeguard_default_model = overrides.get("edgeguard_default_model")
  plugin.cfg_edgeguard_explanation_worker = overrides.get("edgeguard_explanation_worker", {})
  plugin.cfg_edgeguard_explanation_model_url = overrides.get("edgeguard_explanation_model_url")
  plugin.cfg_edgeguard_explanation_model_host = overrides.get("edgeguard_explanation_model_host", "127.0.0.1")
  plugin.cfg_edgeguard_explanation_model_port = overrides.get("edgeguard_explanation_model_port", 5090)
  plugin.cfg_edgeguard_explanation_model_path = overrides.get("edgeguard_explanation_model_path", "/create_chat_completion")
  plugin.cfg_edgeguard_explanation_model_token = overrides.get("edgeguard_explanation_model_token")
  plugin.cfg_edgeguard_explanation_model_token_env = overrides.get("edgeguard_explanation_model_token_env", "EDGEGUARD_EXPLANATION_MODEL_TOKEN")
  plugin.cfg_edgeguard_explanation_model = overrides.get("edgeguard_explanation_model", "base_qwen3_4b")
  plugin.cfg_edgeguard_explanation_default_rows = overrides.get("edgeguard_explanation_default_rows", 25)
  plugin.cfg_edgeguard_explanation_max_rows = overrides.get("edgeguard_explanation_max_rows", 50)
  plugin.cfg_edgeguard_explanation_max_tokens = overrides.get(
    "edgeguard_explanation_max_tokens",
    1024,
  )
  plugin.cfg_edgeguard_explanation_temperature = overrides.get("edgeguard_explanation_temperature", 0.1)
  plugin.cfg_edgeguard_direction_corrector = overrides.get("edgeguard_direction_corrector", True)
  plugin.cfg_edgeguard_explanation_top_p = overrides.get("edgeguard_explanation_top_p", 1.0)
  plugin.cfg_edgeguard_explanation_output_mode = overrides.get(
    "edgeguard_explanation_output_mode",
    "json_object",
  )
  plugin.cfg_edgeguard_explanation_strategy = overrides.get(
    "edgeguard_explanation_strategy",
    "eel_compatibility",
  )
  plugin.cfg_edgeguard_explanation_tokenizer_path = overrides.get(
    "edgeguard_explanation_tokenizer_path",
    "/test/tokenizer.json",
  )
  plugin._graph_first_token_counter_for_tests = overrides.get(
    "graph_first_token_counter",
    lambda messages: len(render_chat(messages).encode("utf-8")),
  )
  plugin._graph_first_provider_for_tests = overrides.get(
    "graph_first_provider",
    _graph_first_provider,
  )
  plugin.cfg_neo4j_max_rows = overrides.get("neo4j_max_rows", 100)
  plugin.cfg_neo4j_query_timeout_seconds = overrides.get("neo4j_query_timeout_seconds", 30)
  # Ruling R4: the production default is `False` (unsafe with an unpatched
  # playground); tests that need the `misp_enrichment` machinery keep the
  # old effective default explicitly.
  plugin.cfg_misp_enrichment_enabled = overrides.get("misp_enrichment_enabled", True)
  plugin.cfg_misp_enrichment_timeout_seconds = overrides.get("misp_enrichment_timeout_seconds", 5)
  plugin.cfg_neo4j_default_connection = overrides.get("neo4j_default_connection", {})
  # Contract §6: broadening is off by default from EGM-059 phase 2; tests
  # that exercise the old True default now pass it explicitly.
  plugin.cfg_live_empty_result_broadening = overrides.get("live_empty_result_broadening", False)
  plugin.cfg_request_timeout_seconds = overrides.get("request_timeout_seconds", 120)
  plugin.cfg_edgeguard_verbose = 0
  plugin.os_environ = overrides.get("os_environ", {})
  plugin._explanation_token = overrides.get("explanation_token")
  plugin._metrics_lock = threading.Lock()
  plugin._request_count = 0
  plugin._error_count = 0
  plugin._last_request_time = None
  plugin._misp_enrichment_error_count = 0
  plugin._misp_citation_drop_count = 0
  plugin._misp_ref_drop_count = 0
  plugin._misp_ref_withheld_count = 0
  plugin._misp_bad_templates_logged = set()
  plugin._misp_enrichment_last_error = None
  plugin.time = lambda: 1000
  plugin.P = lambda *_args, **_kwargs: None
  plugin.Pd = lambda *_args, **_kwargs: None
  plugin.log = MagicMock()
  plugin.log.get_localhost_ip.return_value = "127.0.0.1"
  plugin.port = overrides.get("port", 5055)
  plugin.cfg_port = overrides.get("cfg_port", 5055)
  plugin.semaphore_env = {}
  plugin.semaphore_set_env = lambda key, value: plugin.semaphore_env.__setitem__(key, str(value))
  plugin.worker_semaphore_env = overrides.get("worker_semaphore_env", {})
  plugin.semaphore_get_env_value = lambda semaphore, key: plugin.worker_semaphore_env.get(
    semaphore, {}
  ).get(key, "")
  return plugin


class EdgeGuardApiTests(unittest.TestCase):
  def test_worker_runtime_readiness_requires_serving_ready_signal(self):
    plugin = _make_api(worker_semaphore_env={
      PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"},
    })
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": False}})

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=session):
      self.assertFalse(plugin._worker_runtime_ready(
        TEST_GENERATION_WORKERS[PRIVATE_MODEL_KEY]
      ))

    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session", return_value=session):
      self.assertTrue(plugin._worker_runtime_ready(
        TEST_GENERATION_WORKERS[PRIVATE_MODEL_KEY]
      ))

  def test_explain_fails_fast_with_retryable_503_while_model_is_starting(self):
    worker = EdgeguardApiPlugin.CONFIG["EDGEGUARD_EXPLANATION_WORKER"]
    plugin = _make_api(
      edgeguard_explanation_worker=worker,
      worker_semaphore_env={
        "edgeguard_llm_base": {"API_HOST": "127.0.0.1", "API_PORT": "53001"},
      },
    )
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": False}})

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
            result = plugin.explain_graph(
        request="Show indicators",
        cypher="MATCH (i:Indicator) RETURN i LIMIT 5",
        explanation_mode="fast",
      )

    self.assertEqual(result["status_code"], 503)
    self.assertFalse(result["result"]["executed"])
    self.assertEqual(result["result"]["diagnostics"]["reason"], "model_not_ready")
    session.post.assert_not_called()

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

  def test_generic_gguf_ai_engine_is_registered_and_no_private_engine_exists(self):
    from extensions.serving.ai_engines.stable import AI_ENGINES

    self.assertEqual(AI_ENGINES["llama_cpp_gguf"], {"SERVING_PROCESS": "llama_cpp_gguf"})
    self.assertNotIn("edgeguard_qwen_4b", AI_ENGINES)

  def test_shipped_model_catalog_defaults_are_public_models_only(self):
    workers = EdgeguardApiPlugin.CONFIG["EDGEGUARD_GENERATION_WORKERS"]

    self.assertEqual(list(workers), ["base_qwen3_4b", "cybersec_qwen_4b"])
    self.assertTrue(all(entry["SOURCE"] == "public_huggingface" for entry in workers.values()))
    self.assertIsNone(EdgeguardApiPlugin.CONFIG["EDGEGUARD_DEFAULT_MODEL"])
    self.assertNotIn("ratio1/", json.dumps(EdgeguardApiPlugin.CONFIG))

  def test_default_model_falls_back_to_first_configured_key(self):
    plugin = _make_api(edgeguard_generation_workers=EdgeguardApiPlugin.CONFIG["EDGEGUARD_GENERATION_WORKERS"])
    self.assertEqual(plugin._default_model_key(), "base_qwen3_4b")

    plugin = _make_api(edgeguard_default_model="cybersec_qwen_4b")
    self.assertEqual(plugin._default_model_key(), "cybersec_qwen_4b")
    self.assertEqual(plugin.model()["model_key"], "cybersec_qwen_4b")

  def test_pipeline_shorthand_public_entry_keeps_shipped_catalog_metadata(self):
    plugin = _make_api(edgeguard_generation_workers={
      "cybersec_qwen_4b": {"SEMAPHORE": "edgeguard_llm_cybersec"},
    })

    catalog = plugin.models()["models"]

    self.assertEqual([item["model_key"] for item in catalog], ["cybersec_qwen_4b"])
    self.assertEqual(catalog[0]["model_repo"], "mradermacher/CyberSecQwen-4B-GGUF")
    self.assertEqual(catalog[0]["prompt_profile"], "cybersec_schema_grounded")
    self.assertNotIn("base_qwen3_4b", plugin._configured_model_keys())

  def test_default_model_key_falls_back_when_configured_key_is_unknown(self):
    plugin = _make_api(edgeguard_default_model="private_model")
    warnings = []
    plugin.P = lambda message, *args, **kwargs: warnings.append(str(message))

    self.assertEqual(plugin._default_model_key(), PRIVATE_MODEL_KEY)
    self.assertEqual(plugin.models()["default_model_key"], PRIVATE_MODEL_KEY)
    self.assertEqual(plugin.model()["model_key"], PRIVATE_MODEL_KEY)
    self.assertEqual(len([m for m in warnings if "private_model" in m]), 1)

  def test_unknown_prompt_profile_warns_once_and_falls_back(self):
    plugin = _make_api(edgeguard_generation_workers={
      "model-x": {"SEMAPHORE": "edgeguard_llm_private", "PROMPT_PROFILE": "direct-cypher"},
      "model-y": {"SEMAPHORE": "edgeguard_llm_base"},
    })
    warnings = []
    plugin.P = lambda message, *args, **kwargs: warnings.append(str(message))

    first = plugin._prompt_profile("model-x")
    plugin._prompt_profile("model-x")
    silent = plugin._prompt_profile("model-y")

    self.assertEqual(first["name"], "schema_grounded")
    self.assertEqual(silent["name"], "schema_grounded")
    self.assertEqual(len([m for m in warnings if "direct-cypher" in m]), 1)
    self.assertFalse(any("model-y" in m for m in warnings))

  def test_generate_rejects_unconfigured_model_key(self):
    plugin = _make_api()

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post") as post:
      result = plugin.generate(request="Show indicators", model_key="not-configured")

    # Fix round 6: unsupported model key is now a deliberate 400 via the
    # wrapper-safe transport, not a bare top-level `error` key.
    self.assertEqual(result["status_code"], 400)
    self.assertEqual(_graph_first_payload(result)["diagnostics"]["code"], "unsupported_model")
    post.assert_not_called()

  def test_edgeguard_api_owns_generation_endpoint(self):
    self.assertTrue(hasattr(EdgeguardApiPlugin, "generate"))

  def test_explanation_worker_defaults_to_base_qwen_semaphore(self):
    self.assertEqual(
      EdgeguardApiPlugin.CONFIG["EDGEGUARD_EXPLANATION_WORKER"]["SEMAPHORE"],
      "edgeguard_llm_base",
    )
    self.assertEqual(EdgeguardApiPlugin.CONFIG["EDGEGUARD_EXPLANATION_MODEL"], "base_qwen3_4b")

  def test_generate_fails_before_model_call_when_selected_worker_is_not_ready(self):
    plugin = _make_api()

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post") as post:
      result = plugin.generate(request="Show indicators", model_key=PRIVATE_MODEL_KEY)

    # Fix round 6: the worker not being ready is now a deliberate 503 via
    # the wrapper-safe transport, not a bare top-level `error` key.
    self.assertEqual(result["status_code"], 503)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "error")
    self.assertEqual(payload["diagnostics"]["code"], "worker_not_ready")
    post.assert_not_called()

  def test_generate_uses_semaphore_worker_and_validates_model_output(self):
    plugin = _make_api(worker_semaphore_env={
      PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"},
    })
    response = _Response(payload={
      "result": {
        "TEXT_RESPONSE": "MATCH (i:Indicator) RETURN i LIMIT 10",
        "FULL_OUTPUT": {
          "choices": [{
            "message": {"content": "MATCH (i:Indicator) RETURN i LIMIT 10"},
            "finish_reason": "stop",
          }],
          "usage": {"completion_tokens": 10},
        },
      },
    })
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.return_value = response

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(request="Show indicators", model_key=PRIVATE_MODEL_KEY)

    self.assertEqual(result["status"], "accepted")
    self.assertEqual(result["accepted_cypher"], "MATCH (i:Indicator) RETURN i LIMIT 10")
    self.assertEqual(result["attempts"][0]["validated_by"], "EDGEGUARD_API /check_cypher")
    self.assertIn("edgeguard_api_ms", result["metrics"])
    self.assertEqual(session.post.call_args.args[0], "http://127.0.0.1:53001/create_chat_completion")
    self.assertEqual(session.post.call_args.kwargs["json"]["temperature"], 0.0)
    self.assertEqual(session.post.call_args.kwargs["json"]["max_tokens"], 384)
    self.assertEqual(session.post.call_args.kwargs["json"]["model"], PRIVATE_MODEL_KEY)
    self.assertEqual(result["attempts"][0]["finish_reason"], "stop")
    self.assertEqual(result["attempts"][0]["completion_tokens"], 10)

  def test_generate_rejects_length_completion_before_accepting_corrected_query(self):
    plugin = _make_api(worker_semaphore_env={
      PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"},
    })
    truncated = _Response(payload={
      "result": {
        "TEXT_RESPONSE": "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source)",
        "FULL_OUTPUT": {
          "choices": [{
            "message": {"content": "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source)"},
            "finish_reason": "length",
          }],
          "usage": {"completion_tokens": 64},
        },
      },
    })
    corrected = _Response(payload={
      "result": {
        "TEXT_RESPONSE": "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 5",
        "FULL_OUTPUT": {
          "choices": [{
            "message": {"content": "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 5"},
            "finish_reason": "stop",
          }],
          "usage": {"completion_tokens": 24},
        },
      },
    })
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.side_effect = [truncated, corrected]

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(
        request="Show indicators and their source reports",
        model_key=PRIVATE_MODEL_KEY,
      )

    self.assertTrue(result["accepted"])
    self.assertEqual(len(result["attempts"]), 2)
    self.assertFalse(result["attempts"][0]["accepted"])
    self.assertEqual(result["attempts"][0]["finish_reason"], "length")
    self.assertIn("did not stop cleanly", result["attempts"][0]["validation_feedback"])
    self.assertTrue(result["attempts"][1]["accepted"])
    self.assertEqual(session.post.call_count, 2)

  def _length_then_stop_responses(self):
    truncated = _Response(payload={
      "result": {
        "TEXT_RESPONSE": "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source)",
        "FULL_OUTPUT": {
          "choices": [{
            "message": {"content": "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source)"},
            "finish_reason": "length",
          }],
          "usage": {"completion_tokens": 64},
        },
      },
    })
    corrected = _Response(payload={
      "result": {
        "TEXT_RESPONSE": "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 5",
        "FULL_OUTPUT": {
          "choices": [{
            "message": {"content": "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 5"},
            "finish_reason": "stop",
          }],
          "usage": {"completion_tokens": 24},
        },
      },
    })
    return truncated, corrected

  def _generate_with_fake_clock(self, plugin, responses, seconds_per_call):
    """Run generate() under a fake monotonic clock that each worker call advances."""
    clock = {"now": 1000.0}
    timeouts = []
    payload_timeouts = []
    queue = list(responses)

    def _post(*_args, **kwargs):
      timeouts.append(kwargs.get("timeout"))
      payload_timeouts.append(kwargs.get("json", {}).get("timeout"))
      clock["now"] += seconds_per_call
      return queue.pop(0)

    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.side_effect = _post
    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ), patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.time.monotonic",
      side_effect=lambda: clock["now"],
    ):
      result = plugin.generate(request="Show indicators", model_key=PRIVATE_MODEL_KEY)
    self._last_payload_timeouts = payload_timeouts
    return result, session, timeouts

  def test_generate_stops_retrying_when_request_budget_is_exhausted(self):
    plugin = _make_api(
      worker_semaphore_env={PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"}},
      request_timeout_seconds=120,
    )
    truncated, _corrected = self._length_then_stop_responses()

    result, session, timeouts = self._generate_with_fake_clock(plugin, [truncated, truncated], 119.5)

    # Fix round 6: exhausting the budget is a generation-service failure,
    # 502 via the wrapper-safe transport.
    self.assertEqual(result["status_code"], 502)
    payload = _graph_first_payload(result)
    self.assertEqual(session.post.call_count, 1)
    self.assertEqual(payload["status"], "error")
    self.assertEqual(
      payload["diagnostics"],
      {"stage": "worker", "code": "generation_deadline_exceeded", "retryable": True},
    )
    self.assertEqual(len(payload["attempts"]), 1)
    self.assertEqual(timeouts, [120.0])

  def test_generate_passes_remaining_budget_as_http_timeout(self):
    plugin = _make_api(
      worker_semaphore_env={PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"}},
      request_timeout_seconds=120,
    )
    truncated, corrected = self._length_then_stop_responses()

    result, session, timeouts = self._generate_with_fake_clock(plugin, [truncated, corrected], 30.0)

    self.assertTrue(result["accepted"])
    self.assertEqual(session.post.call_count, 2)
    self.assertEqual(timeouts, [120.0, 90.0])
    self.assertEqual(self._last_payload_timeouts, [120, 90])

  def test_generate_refuses_first_attempt_below_deadline_floor(self):
    plugin = _make_api(
      worker_semaphore_env={PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"}},
      request_timeout_seconds=0,
    )

    result, session, timeouts = self._generate_with_fake_clock(plugin, [], 0.0)

    session.post.assert_not_called()
    # Fix round 6: same generation-service-failure transport, 502.
    self.assertEqual(result["status_code"], 502)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["diagnostics"]["code"], "generation_deadline_exceeded")
    self.assertEqual(payload["attempts"], [])
    self.assertEqual(timeouts, [])

  def test_generate_fails_fast_while_model_process_is_starting(self):
    plugin = _make_api(worker_semaphore_env={
      PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"},
    })
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": False}})

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(request="Show indicators", model_key=PRIVATE_MODEL_KEY)

    # Fix round 6: the model still starting is a deliberate 503 via the
    # wrapper-safe transport.
    self.assertEqual(result["status_code"], 503)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["diagnostics"]["code"], "model_not_ready")
    self.assertTrue(payload["diagnostics"]["retryable"])
    session.post.assert_not_called()

  def test_neo4j_connection_uses_complete_default_or_complete_override(self):
    plugin = _make_api(neo4j_default_connection={
      "uri": "default.example:7687",
      "username": "default-user",
      "password": "default-secret",
      "scheme": "bolt+s",
    })

    default, error = plugin._resolve_neo4j_connection(None, None, None, None)
    self.assertIsNone(error)
    self.assertEqual(default["uri"], "default.example:7687")

    override, error = plugin._resolve_neo4j_connection(
      "override.example:7687", "override-user", "override-secret", "neo4j+s",
    )
    self.assertIsNone(error)
    self.assertEqual(override["password"], "override-secret")

    incomplete, error = plugin._resolve_neo4j_connection(
      "override.example:7687", None, None, "neo4j+s",
    )
    self.assertIsNone(incomplete)
    self.assertIn("must include", error)

  def test_neo4j_api_config_defaults_to_encrypted_bolt_scheme(self):
    self.assertEqual(
      EdgeguardApiPlugin.CONFIG["NEO4J_DEFAULT_CONNECTION"],
      {"scheme": "bolt+s"},
    )

  def test_neo4j_default_resolves_strict_environment_references(self):
    plugin = _make_api(neo4j_default_connection={
      "uri": "$EE_NEO4J_URI",
      "username": "$EE_NEO4J_USERNAME",
      "password": "$EE_NEO4J_PASSWORD",
      "scheme": "$EE_NEO4J_SCHEME",
    })

    with patch.dict(os.environ, {
      "EE_NEO4J_URI": "default.example:7687",
      "EE_NEO4J_USERNAME": "default-user",
      "EE_NEO4J_PASSWORD": "default-secret",
      "EE_NEO4J_SCHEME": "bolt+s",
    }):
      connection, error = plugin._resolve_neo4j_connection(None, None, None, None)

    self.assertIsNone(error)
    self.assertEqual(connection["uri"], "default.example:7687")
    self.assertEqual(connection["scheme"], "bolt+s")

  def test_health_reports_only_sanitized_neo4j_default_connection_status(self):
    plugin = _make_api(neo4j_default_connection={
      "uri": "bolt+s://uri-user:uri-secret@default.example:8443/private?token=hidden#fragment",
      "username": "default-user",
      "password": "default-secret",
      "scheme": "bolt+s",
    })

    status = plugin.health()["neo4j"]

    self.assertEqual(status, {
      "schema_version": "edgeguard.neo4j_connection_status.v1",
      "default_connection": {
        "configured": True,
        "endpoint": "bolt+s://default.example:8443",
        "method": "bolt_over_wss",
      },
    })
    flattened = json.dumps(status)
    for private_value in (
      "uri-user", "uri-secret", "default-user", "default-secret", "private", "hidden", "fragment",
    ):
      self.assertNotIn(private_value, flattened)

  def test_health_reports_unavailable_neo4j_default_without_private_reason(self):
    plugin = _make_api(neo4j_default_connection={
      "uri": "$EE_NEO4J_URI",
      "username": "$EE_NEO4J_USERNAME",
      "password": "$EE_NEO4J_PASSWORD",
      "scheme": "$EE_NEO4J_SCHEME",
    })

    with patch.dict(os.environ, {}, clear=True):
      status = plugin.health()["neo4j"]

    self.assertEqual(status, {
      "schema_version": "edgeguard.neo4j_connection_status.v1",
      "default_connection": {
        "configured": False,
        "endpoint": None,
        "method": None,
      },
    })
    self.assertNotIn("EE_NEO4J", json.dumps(status))

  def test_neo4j_bolt_over_wss_uses_local_bridge_and_closes_it(self):
    plugin = _make_api(neo4j_query_timeout_seconds=17)
    raw_driver = MagicMock()
    bridge = MagicMock()
    bridge.start.return_value = "bolt://127.0.0.1:45123"
    graph_database = MagicMock()
    graph_database.driver.return_value = raw_driver

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api._BoltOverWssBridge",
      return_value=bridge,
    ) as bridge_type, patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase",
      graph_database,
    ):
      driver = plugin._neo4j_driver(
        "bolt+s://neo4j-bolt.example:443", "user", "secret", "bolt_over_wss",
      )
      driver.close()

    bridge_type.assert_called_once_with("wss://neo4j-bolt.example", 17)
    graph_database.driver.assert_called_once_with(
      "bolt://127.0.0.1:45123",
      auth=("user", "secret"),
      connection_timeout=17,
    )
    raw_driver.close.assert_called_once_with()
    bridge.close.assert_called_once_with()

  def test_api_model_metadata_describes_the_configured_default_model(self):
    plugin = _make_api(live_empty_result_broadening=True)

    model = plugin.model()

    self.assertEqual(model["model_key"], PRIVATE_MODEL_KEY)
    self.assertEqual(model["display_name"], "Private fixture model")
    self.assertEqual(model["model_repo"], "example-org/private-fixture-gguf")
    self.assertEqual(model["model_file"], "private-fixture.Q4_K_M.gguf")
    self.assertEqual(model["prompt_profile_id"], "edgeguard_direct_cypher_v0_10")
    self.assertEqual(model["model_card"], {"method": "QLoRA SFT"})
    self.assertEqual(model["schema_version"], "edgeguard-cypher-schema-v0.10")
    self.assertTrue(model["runtime_harness"]["empty_result_broadening"])
    for hardcoded_section in ("quality", "fine_tuning", "continuation_of"):
      self.assertNotIn(hardcoded_section, model)
    self.assertNotIn("SEMAPHORE", json.dumps(model))

  def test_api_models_returns_exact_three_model_catalog_without_backend_urls(self):
    plugin = _make_api()

    catalog = plugin.models()

    self.assertEqual(catalog["schema_version"], "edgeguard.model_catalog.v1")
    self.assertEqual(catalog["default_model_key"], PRIVATE_MODEL_KEY)
    self.assertEqual(
      [item["model_key"] for item in catalog["models"]],
      [PRIVATE_MODEL_KEY, "base_qwen3_4b", "cybersec_qwen_4b"],
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
      [PRIVATE_MODEL_KEY, "base_qwen3_4b", "cybersec_qwen_4b"],
    )
    profiles = {item["model_key"]: item for item in contract["profiles"]}
    self.assertEqual(
      profiles[PRIVATE_MODEL_KEY]["prompt_profile_id"],
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
    self.assertRegex(profiles[PRIVATE_MODEL_KEY]["system_prompt_sha256"], r"^[0-9a-f]{64}$")
    # Contract §5.4: every profile gets a real `system_prompt_sha256`, not
    # just the profile without a suffix — `base_qwen3_4b` and
    # `cybersec_qwen_4b` used to report `None` here.
    self.assertRegex(profiles["base_qwen3_4b"]["system_prompt_sha256"], r"^[0-9a-f]{64}$")
    self.assertRegex(profiles["cybersec_qwen_4b"]["system_prompt_sha256"], r"^[0-9a-f]{64}$")
    explanation = contract["graph_explanation"]
    self.assertEqual(explanation["prompt_version"], "edgeguard-graph-first-v1")
    self.assertEqual(explanation["profile_id"], "EEL/1")
    self.assertEqual(explanation["candidate_id"], "JSON-CB/1")
    self.assertEqual(explanation["output_schema_version"], "edgeguard.case_explanation.v1")
    self.assertEqual(explanation["coverage_schema_version"], "edgeguard.explanation_coverage.v1")
    self.assertEqual(explanation["explanation_trace_schema_version"], "edgeguard.explanation_trace.v1")
    self.assertEqual(explanation["selection_status"], "selected_egm_043")
    self.assertRegex(explanation["profile_sha256"], r"^[0-9a-f]{64}$")

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

  def test_check_cypher_accepts_v0_11_sets_and_optional_limit_with_a_v0_11_model_key(self):
    # Review finding 1, round 2: `check_cypher` must accept what `generate`
    # accepts for the v0.11 profile — v0.11-only sets, `LIMIT` optional for
    # the `graph` shape — via the same shared resolver `/neo4j_query` uses.
    plugin = _make_api(edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11)
    cypher = "MATCH p=(c:CVE)-[:HAS_CVSS_v2]->(s:CVSSv2) RETURN p"

    with_v0_11 = plugin.check_cypher(cypher=cypher, model_key=V0_11_MODEL_KEY)
    without_model_key = plugin.check_cypher(cypher=cypher)

    self.assertEqual(with_v0_11["status"], "accepted")
    self.assertTrue(with_v0_11["accepted"], with_v0_11["validation_feedback"])
    self.assertEqual(with_v0_11["schema_version"], "edgeguard-cypher-schema-v0.11")
    self.assertEqual(without_model_key["status"], "rejected")
    self.assertFalse(without_model_key["accepted"])
    self.assertEqual(without_model_key["schema_version"], SCHEMA_VERSION)

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

    # Fix round 5: a guard rejection is a deliberate 422 via the
    # wrapper-safe transport, not a bare 500.
    self.assertEqual(result["status_code"], 422)
    payload = _graph_first_payload(result)
    self.assertFalse(payload["executed"])
    self.assertEqual(payload["status"], "rejected")
    # Contract §4.3: `validation.result_shape` is set even on a rejected
    # query — it is a static text classification, not an acceptance gate.
    self.assertEqual(payload["validation"]["result_shape"], "other")
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
    self.assertEqual(fake_session.run.call_count, 1)
    self.assertEqual(_run_text(fake_session.run.call_args), "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10")
    fake_driver.close.assert_called_once()

  def test_neo4j_query_projects_returned_path_into_ui_graph(self):
    plugin = _make_api()
    fake_result = _Result([_graph_path_record()], keys=["p"])
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.return_value = fake_result
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10",
        )

    self.assertTrue(result["executed"])
    self.assertEqual(len(result["graph"]["nodes"]), 2)
    self.assertEqual(len(result["graph"]["relationships"]), 1)
    self.assertFalse(result["graph"]["truncated"])

  def test_graph_packet_canonicalizes_driver_temporal_properties_without_truncation(self):
    indicator = _GraphNode(
      "indicator-temporal",
      ["Indicator"],
      {"value": "example.org", "last_updated": DateTime()},
    )
    source = _GraphNode("source-temporal", ["Source"], {"name": "Example source"})
    relationship = _GraphRelationship(
      "rel-temporal", "SOURCED_FROM", indicator, source,
    )
    path = _GraphPath([indicator, source], [relationship])

    packet, meta = _build_graph_evidence_packet(
      request="Explain indicator provenance",
      accepted_cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 5",
      executed_cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 5",
      records=[{"p": path}],
      generated_limit=5,
      executed_limit=5,
      limit_adjusted=False,
    )

    indicator_packet = next(
      node for node in packet["graph"]["nodes"] if "Indicator" in node["labels"]
    )
    self.assertEqual(indicator_packet["properties"]["last_updated"], "2026-08-03T17:00:00Z")
    self.assertEqual(meta["truncated_properties"], 0)
    self.assertFalse(packet["execution"]["truncated"])
    self.assertEqual(
      _tag_serialized_property(DateTime(), "/node/last_updated"),
      {
        "type": "temporal",
        "temporal_type": "date_time",
        "value": "2026-08-03T17:00:00Z",
      },
    )

  def test_neo4j_query_returns_complete_rows_by_design(self):
    """Rows are the operator's table view and stay complete; redaction applies to
    the graph packet and to model-bound evidence only (PR #477 review, F1 decision)."""
    plugin = _make_api()
    node = _GraphNode(
      "indicator-1",
      ["Indicator"],
      {"value": "example.org", "password": "sentinel-password", "raw_data": "sentinel-raw"},
    )
    record = _DriverRecord({"i": node}, {"i": dict(node.items())})
    fake_driver, _session = _driver_with_results(_Result([record], keys=["i"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:Indicator) RETURN i LIMIT 10",
        )

    self.assertTrue(result["executed"])
    row_properties = dict(result["rows"][0]["i"].items())
    self.assertEqual(row_properties["password"], "sentinel-password")
    self.assertEqual(row_properties["raw_data"], "sentinel-raw")
    graph_properties = result["graph"]["nodes"][0]["properties"]
    self.assertEqual(graph_properties, {"value": "example.org"})
    self.assertNotIn("sentinel", json.dumps(result["graph"]))

  def test_neo4j_query_returns_json_safe_rows_for_a_path_with_temporal_properties(self):
    """Regression for the HTTP 500 in
    `.no-commit/edgeguard-t2c-resilmesh-2026-09-26/ip_crashed_run.log` (query
    [13]/[14]): a `RETURN p` path whose node carries a Neo4j temporal
    property crashed JSON serialization because `_run_neo4j_query` put the
    raw `neo4j.graph.Path` / `neo4j.time.DateTime` driver objects straight
    into `rows`. Synthetic values only, per contract §4.3 (no prod CVE ids,
    no prod dates); the two fixture node/relationship types below already
    stand in for the real driver's `Node`/`Relationship`/`Path` classes
    elsewhere in this file (`_graph_path_record`, `test_graph_packet_...`)."""
    plugin = _make_api()
    cve = _GraphNode(
      "cve-1",
      ["CVE"],
      {"cve_id": "CVE-2021-00000", "cisa_action_due": DateTime()},
    )
    cvss = _GraphNode("cvss-1", ["CVSSv31"], {"base_score": 9.8})
    relationship = _GraphRelationship("rel-1", "HAS_CVSS_v31", cve, cvss)
    path = _GraphPath([cve, cvss], [relationship])
    record = _DriverRecord({"p": path}, {"p": "unused"})
    fake_driver, _session = _driver_with_results(_Result([record], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher=(
            "MATCH p=(c:CVE)-[:HAS_CVSS_v31]->(s:CVSSv31) "
            "WHERE c.cve_id = 'CVE-2021-00000' RETURN p LIMIT 5"
          ),
        )

    self.assertTrue(result["executed"])
    # Before the fix this line raised TypeError ("Object of type _GraphPath /
    # DateTime is not JSON serializable") — the exact shape of the crash.
    encoded = json.dumps(result)
    row_path = result["rows"][0]["p"]
    self.assertEqual(
      {node["cve_id"] for node in row_path["nodes"] if "cve_id" in node},
      {"CVE-2021-00000"},
    )
    self.assertEqual(
      next(node for node in row_path["nodes"] if "cve_id" in node)["cisa_action_due"],
      "2026-08-03T17:00:00Z",
    )
    self.assertEqual(row_path["relationships"], [{}])
    # The graph packet (redacted, ref-based) still builds from the same raw
    # Path unaffected by the row conversion.
    self.assertEqual(result["graph"]["nodes"][0]["properties"]["cisa_action_due"], "2026-08-03T17:00:00Z")
    self.assertIn("CVE-2021-00000", encoded)

  def test_neo4j_row_json_safe_converts_bytes_to_hex(self):
    # Review finding Q5: a single `bytes` value used to fall through to the
    # generic "unsupported" rejection and turn an executed query into
    # `status: error, executed: false`.
    self.assertEqual(_neo4j_row_json_safe(b"\x00\x01\xff"), "0001ff")
    self.assertEqual(_neo4j_row_json_safe(bytearray(b"\xab\xcd")), "abcd")
    self.assertEqual(_neo4j_row_json_safe({"payload": b"\x01"}), {"payload": "01"})

  def test_neo4j_row_json_safe_raises_a_distinct_code_for_a_truly_unsupported_value(self):
    with self.assertRaises(_ResultEvidenceError) as raised:
      _neo4j_row_json_safe({1, 2, 3})
    self.assertEqual(raised.exception.code, "unsupported_query_result_value")

  def test_neo4j_query_surfaces_a_distinct_error_code_for_an_unsupported_result_value(self):
    plugin = _make_api()
    record = _DriverRecord({"blob": {1, 2, 3}}, {"blob": "unused"})
    fake_driver, _session = _driver_with_results(_Result([record], keys=["blob"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:Indicator) RETURN i.value AS blob LIMIT 5",
        )

    # Fix round 4 (re-review-3 finding 3): serialization failure stays a
    # 500, but through the wrapper-safe transport, not a raw `error` key.
    self.assertEqual(result["status_code"], 500)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "error")
    # Review finding 3, round 2: the query ran against Neo4j — only turning
    # its rows into a JSON-safe response failed afterward — so `executed`
    # is `True`; `error_code` is what tells the caller the row was unusable.
    self.assertTrue(payload["executed"])
    self.assertEqual(payload["error_code"], "unsupported_query_result_value")

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
          enable_empty_result_broadening=True,
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
      _run_text(fake_session.run.call_args_list[1]),
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
          cypher="MATCH (i:Indicator)-[:INDICATES]->(m:Malware) RETURN i.value AS value LIMIT 10",
          enable_empty_result_broadening=False,
        )

    self.assertTrue(result["executed"])
    self.assertEqual(result["rows"], [])
    self.assertFalse(result["live_retry"]["enabled"])
    self.assertFalse(result["live_retry"]["attempted"])
    # Contract §6: every empty result carries a reason; INDICATES, Indicator
    # and Malware are all populated-surface (review finding 4 gives `Alert` a
    # topology-only label classification of its own, so this test uses
    # `Malware` to keep exercising the plain `no_match` branch), so this is a
    # legitimate no-match, not a topology gap.
    self.assertEqual(result["empty_reason"], "no_match")
    self.assertEqual(fake_session.run.call_count, 1)
    self.assertEqual(
      _run_text(fake_session.run.call_args),
      "MATCH (i:Indicator)-[:INDICATES]->(m:Malware) RETURN i.value AS value LIMIT 10",
    )

  def test_neo4j_query_empty_topology_surface_result_carries_the_contract_reason(self):
    """Contract §6's own acceptance query: `MATCH p=(c:CVE)-[:AFFECTS]->
    (m:Mission) ... RETURN p`, with no `LIMIT` (contract §4.1: optional for
    the `graph` shape once the caller names the v0.11 profile) — `Mission`
    is a topology-only label the v0.10 schema does not even know, so this
    also exercises review finding 1 (the v0.11 flat sets)."""
    plugin = _make_api(edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11)
    empty_result = _Result([], keys=["p"])
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
          cypher="MATCH p=(c:CVE)-[:AFFECTS]->(m:Mission) RETURN p",
          model_key=V0_11_MODEL_KEY,
        )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["executed"])
    self.assertEqual(result["rows"], [])
    self.assertEqual(result["empty_reason"], "topology_surface_no_data")
    self.assertFalse(result["live_retry"]["enabled"])
    self.assertEqual(result["validation"]["result_shape"], "graph")
    self.assertEqual(result["validation"]["schema_version"], "edgeguard-cypher-schema-v0.11")
    # Review finding 4, round 2: with no `LIMIT`, the runtime bounds rows at
    # `NEO4J_MAX_ROWS` (contract §4.1) — the applied bound is reported back
    # in `metrics`, not left implicit.
    self.assertEqual(result["metrics"]["row_bound"], plugin.cfg_neo4j_max_rows)

  def test_neo4j_query_without_a_v0_11_model_key_still_requires_limit_on_v0_10_sets(self):
    """The same no-`LIMIT`, `Mission`-labelled query is rejected by default
    (no `model_key`): `/neo4j_query` states the choice by falling back to
    the v0.10 schema, which does not even know the `Mission` label."""
    plugin = _make_api()

    result = plugin.neo4j_query(
      uri="example.com:7687",
      scheme="bolt+s",
      username="neo4j",
      password="secret",
      cypher="MATCH p=(c:CVE)-[:AFFECTS]->(m:Mission) RETURN p",
    )

    self.assertEqual(result["status_code"], 422)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "rejected")
    self.assertFalse(payload["executed"])
    self.assertEqual(payload["validation"]["schema_version"], "edgeguard-cypher-schema-v0.10")

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

    # Fix round 4 (re-review-3 finding 3): a driver/connection failure below
    # Neo4j's own statement validation is connectivity/service-unavailable,
    # not the caller's query content — 503 via the wrapper-safe transport.
    self.assertEqual(result["status_code"], 503)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "error")
    self.assertFalse(payload["ok"])
    self.assertFalse(payload["executed"])
    self.assertEqual(payload["error_code"], "neo4j_connection_error")
    self.assertNotIn("secret", payload["error"])

  def test_legacy_query_marks_truncation_only_after_observing_an_extra_row(self):
    plugin = _make_api()
    exact_driver, _exact_session = _driver_with_results(
      _Result([_graph_record() for _index in range(25)], keys=["i", "s"]),
    )
    overflow_driver, _overflow_session = _driver_with_results(
      _Result([_graph_record() for _index in range(26)], keys=["i", "s"]),
    )

    exact = plugin._run_neo4j_query(exact_driver, "RETURN i, s LIMIT 25", 25)
    overflow = plugin._run_neo4j_query(overflow_driver, "RETURN i, s LIMIT 25", 25)

    self.assertEqual(exact["row_count"], 25)
    self.assertFalse(exact["truncated"])
    self.assertEqual(overflow["row_count"], 25)
    self.assertTrue(overflow["truncated"])

  def test_explain_graph_executes_with_explanation_limit_and_validates_output(self):
    captured_payloads = []

    def graph_first_provider(payload):
      captured_payloads.append(payload)
      return _graph_first_provider(payload)

    plugin = _make_api(
      edgeguard_explanation_model_port=5091,
      edgeguard_explanation_model="base_qwen3_4b",
      graph_first_provider=graph_first_provider,
    )
    fake_driver, fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="Explain indicator provenance",
          cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
        )

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["result_digest"]["query_scope"]["mode"], "exact")
    self.assertTrue(result["result_digest"]["query_scope"]["accepted_equals_executed"])
    self.assertTrue(result["explained"])
    self.assertNotIn("explanation_model_url", result)
    self.assertNotIn("mode", result)
    self.assertNotIn("metrics", result)
    self.assertEqual(result["packet"]["limit_policy"]["generated_limit"], 10)
    self.assertEqual(result["packet"]["limit_policy"]["executed_limit"], 10)
    self.assertFalse(result["packet"]["limit_policy"]["limit_adjusted"])
    self.assertTrue(result["packet"]["executed_cypher"].endswith("LIMIT 10"))
    self.assertEqual(result["result_digest"]["counts"]["returned_rows"], 1)
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertEqual(fake_session.run.call_count, 1)
    self.assertEqual(_run_text(fake_session.run.call_args), "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10")
    call_payload = captured_payloads[0]
    self.assertEqual(call_payload["model"], "base_qwen3_4b")
    self.assertEqual(call_payload["temperature"], 0.1)
    self.assertEqual(call_payload["top_p"], 1.0)
    self.assertEqual(call_payload["max_tokens"], 127)
    self.assertEqual(call_payload["response_format"], {"type": "json_object"})
    self.assertEqual(call_payload["metadata"], {
      "candidate_id": "JSON-CB/1",
      "profile_id": "EEL/1",
      "task": "edgeguard_graph_first_map",
    })
    self.assertEqual(
      {
        key: result["explanation_trace"]["calls"][0]["request"][key]
        for key in ("temperature", "top_p", "max_tokens")
      },
      {"temperature": 0.1, "top_p": 1.0, "max_tokens": 127},
    )
    self.assertEqual(result["explanation_trace"]["calls"][0]["kind"], "map")

  def test_one_call_strategy_uses_complete_digest_and_no_retry(self):
    payloads = []

    def provider(payload):
      payloads.append(payload)
      digest_document = json.loads(payload["messages"][1]["content"])["result_view"]
      return {
          "content": json.dumps({
            "text": "The SOURCED FROM branch is fully represented by the deterministic digest.",
          }),
        "finish_reason": "stop",
        "completion_tokens": 21,
      }

    plugin = _make_api(
      edgeguard_explanation_strategy="one_call",
      graph_first_provider=provider,
    )
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_path_record()], keys=["p"]))
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="Explain all returned branches.",
          cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10",
        )

    self.assertEqual(len(payloads), 1)
    self.assertEqual(payloads[0]["metadata"], {
      "profile_id": "EAB/1",
      "task": "edgeguard_result_digest_analyst_brief",
    })
    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["explained"])
    self.assertEqual(result["analyst_brief"]["strategy"], "one_call")
    self.assertEqual(result["analyst_brief"]["configured_max_tokens"], 127)
    self.assertEqual(
      result["analyst_brief"]["group_ids"],
      [item["id"] for item in result["result_digest"]["groups"]],
    )
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertNotIn("explanation", result)
    self.assertEqual(result["explanation_trace"]["schema_version"], "edgeguard.analyst_brief_trace.v1")

  def test_one_call_failure_keeps_digest_without_raw_content_or_retry(self):
    calls = 0

    def provider(_payload):
      nonlocal calls
      calls += 1
      return {"content": "private malformed output", "finish_reason": "stop", "completion_tokens": 3}

    plugin = _make_api(edgeguard_explanation_strategy="one_call", graph_first_provider=provider)
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_path_record()], keys=["p"]))
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10",
        )

    self.assertEqual(calls, 1)
    self.assertEqual(result["status"], "ok")
    self.assertFalse(result["explained"])
    self.assertEqual(result["analyst_brief"]["status"], "unavailable")
    self.assertEqual(result["analyst_brief"]["diagnostics"]["reason"], "invalid_brief_json")
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 1)
    self.assertEqual(result["explanation_trace"]["outcome"]["completed_calls"], 1)
    self.assertEqual(result["explanation_trace"]["calls"][0]["status"], "completed")
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertNotIn("private malformed output", json.dumps(result))

  def test_one_call_deadline_admission_degrades_before_dispatch(self):
    calls = 0

    def provider(_payload):
      nonlocal calls
      calls += 1
      raise AssertionError("provider must not be called")

    plugin = _make_api(edgeguard_explanation_strategy="one_call", graph_first_provider=provider)
    result = plugin._run_digest_analyst_brief(
      digest={
        "schema_version": "edgeguard.result_digest.v1",
        "groups": [],
        "coverage": {"complete": True},
      },
      packet={},
      packet_meta={},
      validation={"accepted": True},
      live_retry={},
      request="Explain.",
      deadline=time.monotonic() + 259,
    )

    self.assertEqual(calls, 0)
    self.assertFalse(result["explained"])
    self.assertEqual(result["analyst_brief"]["diagnostics"]["reason"], "insufficient_deadline_budget")
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 0)
    self.assertEqual(result["explanation_trace"]["outcome"]["completed_calls"], 0)

  def test_api_owned_complete_evidence_dispatches_balanced_map_map_synthesis_to_base_qwen(self):
    from extensions.business.cybersec.edgeguard.graph_first_explanation import resolve_mode
    from extensions.business.cybersec.edgeguard.tests.test_graph_first_explanation import fixtures

    evidence, catalog = fixtures(disconnected=True)
    evidence["rows"][0]["values"][1] = {"type": "string", "value": "a" * 800}
    evidence["rows"][1]["values"][1] = {"type": "string", "value": "b" * 800}
    payloads = []

    def provider(payload):
      payloads.append(payload)
      return _graph_first_provider(payload)

    plugin = _make_api(graph_first_provider=provider)
    cypher = "MATCH p=()--() RETURN p LIMIT 25"
    result = plugin._run_graph_first(
      plan={
        "accepted_cypher": cypher,
        "projection_descriptors": [],
        "limit_policy": {"limit_adjusted": False},
      },
      execution_result={
        "executed_cypher": cypher,
        "row_count": 2,
        "truncated": False,
        "broadened": False,
        "execution_trace": {
          "selected": "primary",
          "executions": [{
            "id": "primary",
            "executed_cypher": cypher,
            "row_count": 2,
            "truncated": False,
            "duration_ms": 1.0,
            "method": "native_driver",
          }],
        },
      },
      packet={},
      query_result_evidence=evidence,
      evidence_catalog=catalog,
      request="Explain both disconnected branches.",
      mode_plan=resolve_mode("balanced"),
      deadline=1e20,
    )

    self.assertEqual(
      [payload["metadata"]["task"] for payload in payloads],
      [
        "edgeguard_graph_first_map",
        "edgeguard_graph_first_map",
        "edgeguard_graph_first_synthesis",
      ],
    )
    self.assertTrue(all(payload["model"] == "base_qwen3_4b" for payload in payloads))
    self.assertTrue(all(payload["temperature"] == 0.1 for payload in payloads))
    self.assertTrue(all(payload["top_p"] == 1.0 for payload in payloads))
    self.assertTrue(all(payload["max_tokens"] == 127 for payload in payloads))
    self.assertEqual(
      [call["kind"] for call in result["explanation_trace"]["calls"]],
      ["map", "map", "synthesis"],
    )
    self.assertTrue(all("gates" not in call for call in result["explanation_trace"]["calls"]))
    self.assertEqual(result["coverage"]["calls"], {"map": 2, "synthesis": 1, "total": 3})
    self.assertEqual(len(result["explanation"]["entity_findings"]), 2)
    union = []
    for finding in result["explanation"]["entity_findings"]:
      for evidence_id in finding["evidence_ids"]:
        if evidence_id not in union:
          union.append(evidence_id)
    self.assertEqual(result["explanation"]["summary"]["evidence_ids"], union)
    self.assertEqual(
      result["explanation_trace"]["calls"][-1]["parsed"]["maps"],
      ["F0", "F1"],
    )
    self.assertEqual(result["neo4j_trace"]["result"]["rows"], evidence["rows"])

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
      "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
    )
    self.assertEqual(
      result["broadening"]["cypher"],
      "MATCH p=(n:Indicator)-[:SOURCED_FROM]-() RETURN p LIMIT 25",
    )

    self.assertEqual(result["limit_policy"], {
      "generated_limit": 10,
      "executed_limit": 10,
      "transport_row_cap": 25,
      "server_max_rows": 50,
      "limit_adjusted": False,
      "query_rewritten": False,
    })
    self.assertEqual(result["explanation_contract"], {
      "schema_version": "edgeguard.graph_first_prepare.v1",
      "profile_id": "EEL/1",
      "candidate_id": "JSON-CB/1",
      "profile_sha256": "865f47894e13b1ff9242fd121b760994d413f7220db99c57851c0008f61d64e3",
      "case_explanation_schema_version": "edgeguard.case_explanation.v1",
      "coverage_schema_version": "edgeguard.explanation_coverage.v1",
      "neo4j_trace_schema_version": "edgeguard.neo4j_trace.v1",
      "explanation_trace_schema_version": "edgeguard.explanation_trace.v1",
      "resolved_mode": {
        "requested": "balanced",
        "effective": "balanced",
        "row_limit": 25,
        "map_call_cap": 2,
        "max_tokens": 127,
      },
    })

  def test_prepare_graph_explanation_accepts_v0_11_sets_and_optional_limit_with_a_v0_11_model_key(self):
    # Review finding 1, round 2: `prepare_graph_explanation` (through
    # `_prepare_graph_explanation_plan`) must accept what `generate` accepts
    # for the v0.11 profile — v0.11-only sets, `LIMIT` optional for `graph`.
    plugin = _make_api(
      edgeguard_explanation_strategy="one_call",
      edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11,
    )
    cypher = "MATCH p=(c:CVE)-[:HAS_CVSS_v2]->(s:CVSSv2) RETURN p"

    with_v0_11 = plugin.prepare_graph_explanation(cypher=cypher, model_key=V0_11_MODEL_KEY)
    without_model_key = plugin.prepare_graph_explanation(cypher=cypher)

    self.assertEqual(with_v0_11["status"], "accepted")
    self.assertTrue(with_v0_11["ok"], with_v0_11.get("error"))
    self.assertEqual(with_v0_11["validation"]["schema_version"], "edgeguard-cypher-schema-v0.11")
    # Fix round 5: the guard rejection on the v0.10 fallback profile is now a
    # deliberate 422 via the wrapper-safe transport, not a bare 500.
    self.assertEqual(without_model_key["status_code"], 422)
    without_model_key_payload = _graph_first_payload(without_model_key)
    self.assertEqual(without_model_key_payload["status"], "rejected")
    self.assertFalse(without_model_key_payload["ok"])

  def test_one_call_prepare_contract_has_distinct_identity_and_cap(self):
    plugin = _make_api(edgeguard_explanation_strategy="one_call")
    result = plugin.prepare_graph_explanation(
      cypher="MATCH (i:Indicator) RETURN i LIMIT 10",
      explanation_mode="balanced",
      enable_empty_result_broadening=False,
    )

    self.assertTrue(result["ok"])
    contract = result["explanation_contract"]
    self.assertEqual(contract["schema_version"], "edgeguard.result_digest_prepare.v1")
    self.assertEqual(contract["profile_id"], "EAB/1")
    self.assertEqual(
      contract["digest_coverage_schema_version"],
      "edgeguard.result_digest_coverage.v2",
    )
    self.assertEqual(contract["strategy"], "one_call")
    self.assertEqual(contract["max_tokens"], 127)
    self.assertEqual(contract["resolved_mode"]["map_call_cap"], 0)
    self.assertEqual(contract["resolved_mode"]["row_limit"], 25)
    self.assertEqual(result["accepted_cypher"], result["executed_cypher"])
    flattened = json.dumps(result)
    for forbidden in ("username", "password", "neo4j-bolt.edgeguard.org"):
      self.assertNotIn(forbidden, flattened)

  def test_one_call_prepare_accepts_when_model_is_unconfigured(self):
    plugin = _make_api(
      edgeguard_explanation_strategy="one_call",
      edgeguard_explanation_model_port=None,
    )

    result = plugin.prepare_graph_explanation(
      cypher="MATCH (i:Indicator) RETURN i LIMIT 10",
    )

    self.assertTrue(result["ok"])
    self.assertEqual(result["status"], "accepted")
    self.assertEqual(result["explanation_contract"]["profile_id"], "EAB/1")
    self.assertFalse(result["broadening"]["enabled"])

  def test_one_call_model_not_ready_returns_digest_after_exact_execution(self):
    plugin = _make_api(edgeguard_explanation_strategy="one_call")
    fake_driver, fake_session = _driver_with_results(_Result([_graph_path_record()], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch.object(plugin, "_explanation_worker_ready", return_value=False):
          result = plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            request="Explain the exact graph.",
            cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10",
          )

    self.assertTrue(result["ok"])
    self.assertTrue(result["executed"])
    self.assertFalse(result["explained"])
    self.assertEqual(result["analyst_brief"]["diagnostics"]["reason"], "model_not_ready")
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 0)
    self.assertEqual(result["result_digest"]["query_scope"]["mode"], "exact")
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertEqual(fake_session.run.call_count, 1)

  def test_explain_graph_default_scope_does_not_broaden_an_empty_result(self):
    plugin = _make_api(edgeguard_explanation_strategy="one_call")
    fake_driver, fake_session = _driver_with_results(
      _Result([], keys=["p"]),
      _Result([_graph_path_record()], keys=["p"]),
    )

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10",
        )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["ok"])
    self.assertTrue(result["executed"])
    self.assertFalse(result["explained"])
    self.assertFalse(result["live_retry"]["enabled"])
    self.assertEqual(result["result_digest"]["counts"]["returned_rows"], 0)
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertEqual(
      result["result_digest"]["summary"]["text"],
      "The exact query returned no rows and therefore no graph evidence.",
    )
    self.assertEqual(result["analyst_brief"]["call_count"], 0)
    self.assertEqual(result["analyst_brief"]["diagnostics"]["reason"], "no_graph_evidence")
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 0)
    self.assertEqual(fake_session.run.call_count, 1)
    # Contract §6, review finding 6 (S5=Q9): explain routes carry an
    # `empty_reason` too, not just `/neo4j_query`. SOURCED_FROM is a
    # populated-surface relationship type, so this is a legitimate no-match.
    self.assertEqual(result["validation"]["empty_reason"], "no_match")

  def test_explain_graph_topology_surface_empty_result_carries_the_contract_reason(self):
    """Contract §6's own acceptance query, through `/explain_graph`: `Mission`
    is a topology-only label (review finding 4), so the zero-row result is
    `topology_surface_no_data`, not `no_match` (review finding 6, S5=Q9)."""
    plugin = _make_api(edgeguard_explanation_strategy="one_call")
    fake_driver, fake_session = _driver_with_results(
      _Result([], keys=["p"]),
    )

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH p=(c:CVE)-[:AFFECTS]->(m:Mission) RETURN p LIMIT 10",
        )

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["result_digest"]["counts"]["returned_rows"], 0)
    self.assertEqual(result["validation"]["empty_reason"], "topology_surface_no_data")

  def test_explain_graph_accepts_v0_11_sets_and_optional_limit_with_a_v0_11_model_key(self):
    # Review finding 1, round 2: `explain_graph`'s live-connection path
    # must accept what `generate` accepts for the v0.11 profile — the same
    # no-`LIMIT` `CVSSv2`/`HAS_CVSS_v2` query `/neo4j_query` already covers.
    plugin = _make_api(
      edgeguard_explanation_strategy="one_call",
      edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11,
    )
    cypher = "MATCH p=(c:CVE)-[:HAS_CVSS_v2]->(s:CVSSv2) RETURN p"
    fake_driver, fake_session = _driver_with_results(_Result([], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with_v0_11 = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher=cypher,
          model_key=V0_11_MODEL_KEY,
        )
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        without_model_key = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher=cypher,
        )

    self.assertEqual(with_v0_11["status"], "ok")
    self.assertTrue(with_v0_11["executed"])
    self.assertEqual(with_v0_11["validation"]["schema_version"], "edgeguard-cypher-schema-v0.11")
    # Fix round 5: the guard rejection on the v0.10 fallback profile is now a
    # deliberate 422 via the wrapper-safe transport, not a bare 500.
    self.assertEqual(without_model_key["status_code"], 422)
    without_model_key_payload = _graph_first_payload(without_model_key)
    self.assertEqual(without_model_key_payload["status"], "rejected")
    self.assertFalse(without_model_key_payload["executed"])

  def test_explain_graph_scalar_only_result_succeeds_under_insight_brief(self):
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    fake_driver, fake_session = _driver_with_results(_Result(
      [
        _DriverRecord({"name": "quietsieve"}, {"name": "quietsieve"}),
        _DriverRecord({"name": "plaintee"}, {"name": "plaintee"}),
      ],
      keys=["name"],
    ))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="List malware names.",
          cypher="MATCH (m:Malware) RETURN m.name AS name LIMIT 10",
        )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["ok"])
    self.assertTrue(result["executed"])
    self.assertFalse(result["explained"])
    self.assertNotIn("validation_errors", result)
    self.assertEqual(result["result_digest"]["counts"]["returned_rows"], 2)
    self.assertEqual(result["result_digest"]["counts"]["nodes"], 0)
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertEqual(result["explanation_trace"]["outcome"]["safe_code"], "tabular_result")
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 0)
    self.assertEqual(result["case_explanation"]["provenance"]["mode"], "deterministic_fallback")
    self.assertIn("tabular/scalar", result["case_explanation"]["assessment"]["text"])
    self.assertEqual(fake_session.run.call_count, 1)

  def test_explain_graph_ranked_projection_calls_the_model_under_insight_brief(self):
    # Contract §4.2-§4.4: a `ranked_projection` result has no graph nodes
    # either, but must call the model (no `tabular_result` fallback) and
    # ground the brief against `projection_digest`.
    payloads = []

    def provider(payload):
      payloads.append(payload)
      return {
        "content": json.dumps({"text": "CVE-2024-0001 ranks highest under cvss_v31_desc."}),
        "finish_reason": "stop",
        "completion_tokens": 14,
      }

    plugin = _make_api(edgeguard_explanation_strategy="insight_brief", graph_first_provider=provider)
    fake_driver, fake_session = _driver_with_results(_Result(
      [
        _DriverRecord({"cve_id": "CVE-2024-0001", "cvss_v31": 9.8}, {"cve_id": "CVE-2024-0001", "cvss_v31": 9.8}),
        _DriverRecord({"cve_id": "CVE-2024-0002", "cvss_v31": 7.5}, {"cve_id": "CVE-2024-0002", "cvss_v31": 7.5}),
      ],
      keys=["cve_id", "cvss_v31"],
    ))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="Which CVE ranks highest by CVSS?",
          cypher=(
            "MATCH (c:CVE)-[:HAS_CVSS_v31]->(s:CVSSv31) WITH c, s "
            "ORDER BY s.base_score DESC "
            "RETURN c.cve_id AS cve_id, s.base_score AS cvss_v31 LIMIT 5"
          ),
        )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["executed"])
    self.assertTrue(result["explained"])
    self.assertEqual(result["validation"]["result_shape"], "ranked_projection")
    self.assertEqual(len(payloads), 1)
    self.assertNotIn("case_explanation", result)
    self.assertEqual(result["analyst_brief"]["strategy"], "one_call")
    self.assertEqual(result["explanation_trace"]["outcome"]["status"], "supported")
    self.assertNotEqual(result["explanation_trace"]["outcome"]["safe_code"], "tabular_result")
    self.assertEqual(result["result_digest"]["counts"]["nodes"], 0)
    projection_digest = result["projection_digest"]
    self.assertEqual(projection_digest["schema_version"], "edgeguard.projection_digest.v1")
    self.assertEqual(projection_digest["columns"], ["cve_id", "cvss_v31"])
    self.assertEqual(projection_digest["ranking_rule"], "cvss_v31_desc")
    self.assertEqual(projection_digest["rows"][0]["values"][0], {"type": "string", "value": "CVE-2024-0001"})
    self.assertEqual(fake_session.run.call_count, 1)

  def test_explain_prepared_execution_ranked_projection_calls_the_model_under_insight_brief(self):
    # Same fix on the `execution_result=`-supplied dispatch path
    # (`_explain_prepared_execution`), used by the JSON-execution-evidence
    # contract and its own harnesses.
    from extensions.business.cybersec.edgeguard.graph_first_explanation import resolve_mode

    payloads = []

    def provider(payload):
      payloads.append(payload)
      return {
        "content": json.dumps({"text": "CVE-2024-0001 ranks highest under cvss_v31_desc."}),
        "finish_reason": "stop",
        "completion_tokens": 12,
      }

    plugin = _make_api(edgeguard_explanation_strategy="insight_brief", graph_first_provider=provider)
    cypher = (
      "MATCH (c:CVE)-[:HAS_CVSS_v31]->(s:CVSSv31) WITH c, s "
      "ORDER BY s.base_score DESC "
      "RETURN c.cve_id AS cve_id, s.base_score AS cvss_v31 LIMIT 5"
    )
    plan = {
      "accepted_cypher": cypher,
      "executed_cypher": cypher,
      "result_columns": ["cve_id", "cvss_v31"],
      "projection_descriptors": [],
      "limit_policy": {
        "generated_limit": 5,
        "executed_limit": 5,
        "transport_row_cap": 25,
        "server_max_rows": EXPLANATION_SERVER_MAX_ROWS,
        "limit_adjusted": False,
        "query_rewritten": False,
      },
      "broadening": {"enabled": False, "cypher": None, "strategy": None, "result_columns": None},
      "validation": {"result_shape": "ranked_projection"},
    }
    execution_result = {
      "executed_cypher": cypher,
      "primary_row_count": 2,
      "row_count": 2,
      "truncated": False,
      "broadened": False,
      "graph": {"nodes": [], "relationships": [], "truncated": False},
      "query_result_evidence": {
        "schema_version": "edgeguard.query_result_evidence.v1",
        "columns": ["cve_id", "cvss_v31"],
        "rows": [
          {"ordinal": 0, "values": [{"type": "string", "value": "CVE-2024-0001"}, {"type": "float", "value": 9.8}]},
          {"ordinal": 1, "values": [{"type": "string", "value": "CVE-2024-0002"}, {"type": "float", "value": 7.5}]},
        ],
      },
      "execution_trace": {"selected": "primary", "executions": []},
    }

    result = plugin._explain_prepared_execution(
      plan=plan,
      execution_result=execution_result,
      request="Which CVE ranks highest by CVSS?",
      mode_plan=resolve_mode("balanced"),
      deadline=1e20,
    )

    self.assertTrue(result["explained"])
    self.assertEqual(len(payloads), 1)
    self.assertEqual(result["analyst_brief"]["strategy"], "one_call")
    self.assertIn("projection_digest", result)
    self.assertEqual(result["projection_digest"]["ranking_rule"], "cvss_v31_desc")
    self.assertEqual(result["projection_digest"]["row_count"], 2)

  def test_explain_prepared_execution_carries_empty_reason_for_zero_rows(self):
    # Carry-over from review finding 6 (S5=Q9): the `execution_result=`
    # supplied-evidence path (`_explain_prepared_execution`) never set
    # `empty_reason` at all, unlike the live-connection path
    # (`test_explain_graph_topology_surface_empty_result_carries_the_contract_reason`).
    # `Mission` is the same topology-only label used there.
    from extensions.business.cybersec.edgeguard.graph_first_explanation import resolve_mode

    plugin = _make_api(edgeguard_explanation_strategy="one_call")
    cypher = "MATCH p=(c:CVE)-[:AFFECTS]->(m:Mission) RETURN p LIMIT 10"
    plan = {
      "accepted_cypher": cypher,
      "executed_cypher": cypher,
      "result_columns": ["p"],
      "projection_descriptors": [],
      "limit_policy": {
        "generated_limit": 10,
        "executed_limit": 10,
        "transport_row_cap": 25,
        "server_max_rows": EXPLANATION_SERVER_MAX_ROWS,
        "limit_adjusted": False,
        "query_rewritten": False,
      },
      "broadening": {"enabled": False, "cypher": None, "strategy": None, "result_columns": None},
      "validation": {"result_shape": "graph"},
    }
    execution_result = {
      "executed_cypher": cypher,
      "primary_row_count": 0,
      "row_count": 0,
      "truncated": False,
      "broadened": False,
      "graph": {"nodes": [], "relationships": [], "truncated": False},
      "query_result_evidence": {
        "schema_version": "edgeguard.query_result_evidence.v1",
        "columns": ["p"],
        "rows": [],
      },
      "execution_trace": {"selected": "primary", "executions": []},
    }

    result = plugin._explain_prepared_execution(
      plan=plan,
      execution_result=execution_result,
      request="Explain the returned investigation graph.",
      mode_plan=resolve_mode("balanced"),
      deadline=1e20,
    )

    self.assertEqual(result["validation"]["empty_reason"], "topology_surface_no_data")

  def test_explain_graph_scalar_only_non_ranked_result_still_falls_back_under_insight_brief(self):
    # `other` (scalar, non-ranked) keeps today's deterministic fallback: only
    # `ranked_projection` is rerouted to the digest analyst brief.
    fake_driver, _fake_session = _driver_with_results(_Result(
      [_DriverRecord({"name": "quietsieve"}, {"name": "quietsieve"})], keys=["name"],
    ))
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="List malware names.",
          cypher="MATCH (m:Malware) RETURN m.name AS name LIMIT 10",
        )

    self.assertEqual(result["validation"]["result_shape"], "other")
    self.assertEqual(result["explanation_trace"]["outcome"]["safe_code"], "tabular_result")
    self.assertNotIn("projection_digest", result)

  def test_explain_graph_scalar_only_result_succeeds_under_one_call(self):
    payloads = []

    def provider(payload):
      payloads.append(payload)
      return {
        "content": json.dumps({"text": "The deterministic digest lists the returned malware name values."}),
        "finish_reason": "stop",
        "completion_tokens": 12,
      }

    plugin = _make_api(
      edgeguard_explanation_strategy="one_call",
      graph_first_provider=provider,
    )
    fake_driver, fake_session = _driver_with_results(_Result(
      [_DriverRecord({"name": "quietsieve"}, {"name": "quietsieve"})],
      keys=["name"],
    ))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="List malware names.",
          cypher="MATCH (m:Malware) RETURN m.name AS name LIMIT 10",
        )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["ok"])
    self.assertTrue(result["executed"])
    self.assertTrue(result["explained"])
    self.assertEqual(len(payloads), 1)
    self.assertEqual(result["result_digest"]["counts"]["returned_rows"], 1)
    self.assertEqual(result["result_digest"]["counts"]["nodes"], 0)
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertEqual(result["analyst_brief"]["strategy"], "one_call")
    self.assertEqual(fake_session.run.call_count, 1)

  def test_sanitize_query_result_evidence_still_rejects_unresolved_catalog_entities(self):
    from extensions.business.cybersec.edgeguard.edgeguard_api import (
      _ResultEvidenceError,
      _sanitize_query_result_evidence,
    )

    with self.assertRaises(_ResultEvidenceError) as ctx:
      _sanitize_query_result_evidence(
        value={
          "schema_version": "edgeguard.query_result_evidence.v1",
          "columns": ["name"],
          "rows": [{"ordinal": 0, "values": [{"type": "string", "value": "quietsieve"}]}],
        },
        row_count=1,
        expected_columns=["name"],
        node_refs={},
        relationship_refs={},
        graph_nodes={"n:a": {"id": "n:a", "labels": ["Indicator"], "properties": {}}},
        graph_relationships={},
        raw_nodes={},
        raw_relationships={},
      )
    self.assertEqual(ctx.exception.code, "incomplete_evidence_catalog")

  def test_one_call_prepared_empty_result_returns_complete_zero_call_digest(self):
    plugin = _make_api(edgeguard_explanation_strategy="one_call")
    cypher = "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10"
    execution_result = _serialized_execution(cypher, primary_row_count=0)
    execution_result.update({
      "row_count": 0,
      "graph": {"nodes": [], "relationships": [], "truncated": False},
    })
    execution_result["query_result_evidence"]["rows"] = []

    result = plugin.explain_graph(
      cypher=cypher,
      request="Explain the exact graph.",
      execution_result=execution_result,
    )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["ok"])
    self.assertTrue(result["executed"])
    self.assertFalse(result["explained"])
    self.assertEqual(result["result_digest"]["counts"]["returned_rows"], 0)
    self.assertEqual(
      result["result_digest"]["coverage"]["schema_version"],
      "edgeguard.result_digest_coverage.v2",
    )
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertEqual(result["analyst_brief"]["call_count"], 0)
    self.assertEqual(result["analyst_brief"]["diagnostics"]["reason"], "no_graph_evidence")
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 0)
    self.assertEqual(result["explanation_trace"]["outcome"]["completed_calls"], 0)

  def test_prepare_graph_explanation_rejects_before_execution_when_provider_is_unconfigured(self):
    plugin = _make_api(edgeguard_explanation_model_port=None)

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      result = plugin.prepare_graph_explanation(
        cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      )

    # Fix round 5: the explanation model endpoint is a server-side
    # dependency, 503 via the wrapper-safe transport, not a bare 500.
    self.assertEqual(result["status_code"], 503)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "config_error")
    self.assertEqual(
      payload["explanation_contract"]["schema_version"],
      "edgeguard.graph_first_prepare.v1",
    )
    self.assertEqual(
      payload["explanation_contract"]["resolved_mode"]["effective"],
      "balanced",
    )
    mocked_driver.assert_not_called()

  def test_graph_first_provider_receipt_is_content_free_and_preserves_metadata_type(self):
    plugin = _make_api(graph_first_provider=None)
    plugin.P = MagicMock()
    content = '{"status":"supported","text":"receipt-secret"}'
    response = _nested_provider_response(content, completion_tokens="16")
    payload = {
      "metadata": {
        "candidate_id": "JSON-CB/1",
        "profile_id": "EEL/1",
        "task": "edgeguard_graph_first_map",
      },
    }

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=response,
    ):
      completion = plugin._call_graph_first_provider(payload)

    self.assertIsNone(completion["completion_tokens"])
    receipt_logs = [
      call.args[0]
      for call in plugin.P.call_args_list
      if call.args and str(call.args[0]).startswith("EDGEGUARD_GRAPH_FIRST_PROVIDER_RECEIPT ")
    ]
    self.assertEqual(len(receipt_logs), 1)
    receipt = json.loads(receipt_logs[0].split(" ", 1)[1])
    self.assertEqual(receipt, {
      "schema_version": "edgeguard.graph_first_provider_receipt.v1",
      "task_kind": "map",
      "envelope_path": "$.result.FULL_OUTPUT",
      "content_bytes": len(content.encode("utf-8")),
      "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
      "finish_reason": "stop",
      "completion_tokens_type": "string",
      "completion_tokens": None,
      "duration_ms": receipt["duration_ms"],
    })
    self.assertIsInstance(receipt["duration_ms"], float)
    self.assertNotIn("receipt-secret", " ".join(receipt_logs))

  def test_graph_first_provider_receipt_normalizes_hostile_finish_reason(self):
    plugin = _make_api(graph_first_provider=None)
    plugin.P = MagicMock()
    hostile_finish = "\nprovider-controlled-" + ("x" * 10_000)
    response = _nested_provider_response(
      '{"status":"supported","text":"safe"}',
      finish_reason=hostile_finish,
      completion_tokens=16,
    )
    payload = {
      "metadata": {
        "candidate_id": "JSON-CB/1",
        "profile_id": "EEL/1",
        "task": "edgeguard_graph_first_synthesis",
      },
    }

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
      return_value=response,
    ):
      completion = plugin._call_graph_first_provider(payload)

    self.assertEqual(completion["finish_reason"], hostile_finish)
    receipt_logs = [
      call.args[0]
      for call in plugin.P.call_args_list
      if call.args and str(call.args[0]).startswith("EDGEGUARD_GRAPH_FIRST_PROVIDER_RECEIPT ")
    ]
    self.assertEqual(len(receipt_logs), 1)
    receipt = json.loads(receipt_logs[0].split(" ", 1)[1])
    self.assertEqual(receipt["finish_reason"], "invalid")
    self.assertNotIn("provider-controlled", receipt_logs[0])
    self.assertLess(len(receipt_logs[0]), 1_000)

  def test_graph_first_request_fields_are_exact_types_before_execution(self):
    provider = MagicMock(side_effect=_graph_first_provider)
    plugin = _make_api(graph_first_provider=provider)
    invalid_requests = (
      {"cypher": 7},
      {"cypher": "MATCH (i:Indicator) RETURN i LIMIT 25", "explanation_rows": "10"},
      {"cypher": "MATCH (i:Indicator) RETURN i LIMIT 25", "max_rows": True},
      {"cypher": "MATCH (i:Indicator) RETURN i LIMIT 25", "temperature": "0.1"},
      {"cypher": "MATCH (i:Indicator) RETURN i LIMIT 25", "enable_empty_result_broadening": "false"},
      {"cypher": "MATCH (i:Indicator) RETURN i LIMIT 25", "scheme": False},
      {"cypher": "MATCH (i:Indicator) RETURN i LIMIT 25", "uri": 7},
      {"cypher": "MATCH (i:Indicator) RETURN i LIMIT 25", "execution_result": []},
      {"cypher": "MATCH (i:Indicator) RETURN i LIMIT 25", "unexpected": "field"},
    )
    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      for kwargs in invalid_requests:
        with self.subTest(kwargs=kwargs):
          result = plugin.explain_graph(**kwargs)
          # Fix round 5: malformed request shape/type is now a deliberate
          # 400 via the wrapper-safe transport, not a bare 500.
          self.assertEqual(result["status_code"], 400)
          self.assertFalse(_graph_first_payload(result)["ok"])
    mocked_driver.assert_not_called()
    provider.assert_not_called()

  def test_total_graph_first_success_response_cap_fails_without_output_echo(self):
    plugin = _make_api()
    value = {
      "explanation_trace": {
        "calls": [{"raw_output": "partial-secret", "parsed": {"text": "partial-secret"}, "status": "supported"}],
        "outcome": {"attempted_calls": 1, "completed_calls": 1},
      },
      "large": "x" * 200,
    }
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.RESPONSE_MAX_BYTES", 32):
      with self.assertRaises(GraphFirstRuntimeError) as raised:
        plugin._bounded_graph_first_success(value)
    self.assertEqual(raised.exception.code, "explanation_response_size")
    serialized = json.dumps(raised.exception.trace)
    self.assertNotIn("partial-secret", serialized)
    self.assertNotIn("raw_output", serialized)
    self.assertNotIn("parsed", serialized)

  def test_prepare_graph_explanation_rejects_forwarded_credentials(self):
    plugin = _make_api()

    result = plugin.prepare_graph_explanation(
      cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      username="neo4j",
      password="test-password",
    )

    # Fix round 5: unexpected/forwarded connection fields are malformed
    # request bodies, 400 via the wrapper-safe transport.
    self.assertEqual(result["status_code"], 400)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "rejected")
    self.assertIn("credential_field_not_allowed", {item["code"] for item in payload["validation_errors"]})

    authorization = plugin.prepare_graph_explanation(
      cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      authorization="Bearer should-not-cross",
    )
    self.assertEqual(authorization["status_code"], 400)
    authorization_payload = _graph_first_payload(authorization)
    self.assertEqual(authorization_payload["status"], "rejected")
    self.assertIn(
      "credential_field_not_allowed",
      {item["code"] for item in authorization_payload["validation_errors"]},
    )

    mixed_case = plugin.prepare_graph_explanation(
      cypher="MATCH (i:Indicator) RETURN i LIMIT 25",
      Authorization="Bearer should-not-cross",
    )
    self.assertEqual(mixed_case["status_code"], 400)
    self.assertEqual(_graph_first_payload(mixed_case)["status"], "rejected")
    self.assertNotIn("should-not-cross", json.dumps(mixed_case))

  def test_prepare_graph_explanation_rejects_dynamic_properties_procedures_and_ambiguous_columns(self):
    plugin = _make_api()
    queries = [
      'MATCH (n:Indicator) WITH n, "value" AS k RETURN n[k] AS safe LIMIT 5',
      "MATCH (n:Indicator) CALL db.propertyKeys() YIELD propertyKey RETURN n, propertyKey LIMIT 5",
      "MATCH (n:Indicator) RETURN count(*) LIMIT 5",
      "MATCH (i:Indicator), (m:Malware) RETURN i, m{.*} AS mapping LIMIT 5",
      (
        "MATCH (i:Indicator), (m:Malware) "
        "RETURN i, m{name:{name:1}, .*} AS mapping LIMIT 5"
      ),
      (
        "MATCH (i:Indicator), (m:Malware) "
        "RETURN i, apoc.convert.toJson(m) AS mapping LIMIT 5"
      ),
    ]

    for cypher in queries:
      with self.subTest(cypher=cypher):
        with patch.object(plugin, "_neo4j_driver") as mocked_driver:
          with patch(
            "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post"
          ) as mocked_post:
            result = plugin.prepare_graph_explanation(cypher=cypher)
        # Fix round 5: every rejection this plan builder returns (guard
        # content rejection or the unsafe-result-projection checks) is a
        # deliberate 422 via the wrapper-safe transport, not a bare 500.
        self.assertEqual(result["status_code"], 422)
        payload = _graph_first_payload(result)
        self.assertEqual(payload["status"], "rejected")
        # Projection safety moved into the shared guard (EG-013): guard-level
        # rejections carry execution_safety_error/read_only_error in the
        # validation verdict; the remaining plan-only checks keep the
        # unsafe_result_projection validation_errors code.
        codes = {item["code"] for item in payload.get("validation_errors", [])}
        validation = payload.get("validation") or {}
        self.assertTrue(
          "unsafe_result_projection" in codes
          or validation.get("execution_safety_error")
          or validation.get("read_only_error"),
          f"no rejection mechanism recorded for {cypher!r}: {payload}",
        )
        mocked_driver.assert_not_called()
        mocked_post.assert_not_called()

  def test_legacy_explanation_applies_projection_checks_before_opening_driver(self):
    plugin = _make_api()

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver") as mocked_driver:
        result = plugin.explain_graph(
          uri="example.com:7687",
          username="neo4j",
          password="secret",
          scheme="bolt+s",
          cypher='MATCH (n:Indicator) WITH n, "value" AS k RETURN n[k] AS safe LIMIT 5',
        )

    # Fix round 5: guard rejection is a deliberate 422 via the wrapper-safe
    # transport, not a bare 500.
    self.assertEqual(result["status_code"], 422)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "rejected")
    self.assertIn(
      "dynamic or bracket property access",
      str((payload.get("validation") or {}).get("execution_safety_error")),
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

  def test_explain_graph_supplied_execution_result_accepts_optional_limit_with_a_v0_11_model_key(self):
    # Review finding 1, round 2: the `execution_result=`-supplied path
    # (`_explain_prepared_execution`) must accept what `generate` accepts
    # for the v0.11 profile too, not only the live-connection path above.
    plugin = _make_api(
      edgeguard_explanation_model_port=5091,
      edgeguard_explanation_model="base_qwen3_4b",
      edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11,
    )
    cypher = "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p"
    execution_result = _serialized_execution(cypher)

    def provider_side_effect(*_args, **kwargs):
      packet = _packet_from_provider_kwargs(kwargs)
      return _provider_response_for_packet(packet, caveat_types=[])

    with patch.object(plugin, "_neo4j_driver") as mocked_driver:
      with patch(
        "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
        side_effect=provider_side_effect,
      ):
        with_v0_11 = plugin.explain_graph(
          cypher=cypher,
          execution_result=execution_result,
          model_key=V0_11_MODEL_KEY,
        )
        without_model_key = plugin.explain_graph(
          cypher=cypher,
          execution_result=execution_result,
        )

    self.assertEqual(with_v0_11["status"], "ok")
    self.assertTrue(with_v0_11["explained"])
    mocked_driver.assert_not_called()
    # Fix round 5: the guard rejection on the v0.10 fallback profile is now a
    # deliberate 422 via the wrapper-safe transport, not a bare 500.
    self.assertEqual(without_model_key["status_code"], 422)
    without_model_key_payload = _graph_first_payload(without_model_key)
    self.assertEqual(without_model_key_payload["status"], "rejected")
    self.assertFalse(without_model_key_payload["explained"])

  def test_explain_graph_rejects_result_columns_that_do_not_match_return_projection(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = "MATCH (i:Indicator) RETURN i LIMIT 25"
    execution_result = _serialized_execution(cypher)
    execution_result["query_result_evidence"]["columns"] = ["spoofed"]

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post",
    ) as mocked_post:
      result = plugin.explain_graph(cypher=cypher, execution_result=execution_result)

    self.assertEqual(set(result), {"status_code", "result", "logged"})
    self.assertEqual(result["status_code"], 500)
    self.assertTrue(result["logged"])
    self.assertIn(
      "result_columns_mismatch",
      {item["code"] for item in result["result"]["validation_errors"]},
    )
    self.assertEqual(result["result"]["diagnostics"]["stage"], "validation")
    self.assertEqual(
      result["result"]["diagnostics"]["validation_codes"],
      ["result_columns_mismatch"],
    )
    self.assertEqual(result["result"]["explanation_trace"]["calls"], [])
    mocked_post.assert_not_called()

  def test_explain_graph_preserves_pairings_duplicates_nulls_scalars_maps_lists_and_reverse_path(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = (
      "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) "
      "RETURN s AS source, i AS indicator, coalesce(i.value, null) AS nullable, "
      "toInteger(i.value) AS total, toFloat(i.value) AS ratio, [i.value] AS items, "
      "coalesce(i.value, i.value) AS aggregate, p AS path LIMIT 25"
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
    result = plugin.explain_graph(
      cypher=cypher,
      request="Explain the exact returned pairs.",
      execution_result=execution_result,
    )

    self.assertEqual(result["status"], "ok")
    complete = result["neo4j_trace"]["result"]
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
    self.assertNotIn("must-redact", json.dumps(complete))
    reverse_path = complete["rows"][0]["values"][7]
    self.assertEqual(reverse_path["start_node_ref"], complete["rows"][0]["values"][0]["ref"])
    self.assertEqual(reverse_path["end_node_ref"], complete["rows"][0]["values"][1]["ref"])
    self.assertEqual(len(complete["relationships"]), 1)

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
      {item["code"] for item in _graph_first_payload(truncated_result)["validation_errors"]},
    )
    self.assertIn(
      "execution_result_size",
      {item["code"] for item in _graph_first_payload(oversized_result)["validation_errors"]},
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
      {item["code"] for item in _graph_first_payload(unresolved_result)["validation_errors"]},
    )
    self.assertIn(
      "evidence_id_collision",
      {item["code"] for item in _graph_first_payload(collision_result)["validation_errors"]},
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

    # Fix round 5: unexpected connection fields in execution-evidence mode
    # are a malformed request body, 400 via the wrapper-safe transport.
    self.assertEqual(result["status_code"], 400)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "rejected")
    self.assertIn("credential_field_not_allowed", {item["code"] for item in payload["validation_errors"]})
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

    self.assertIn(
      "executed_cypher_mismatch",
      {item["code"] for item in _graph_first_payload(mismatch)["validation_errors"]},
    )
    self.assertIn(
      "broadening_primary_not_empty",
      {item["code"] for item in _graph_first_payload(bad_broadening)["validation_errors"]},
    )
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
      {item["code"] for item in _graph_first_payload(malformed_result)["validation_errors"]},
    )
    self.assertIn(
      "graph_node_limit",
      {item["code"] for item in _graph_first_payload(oversized_result)["validation_errors"]},
    )
    self.assertIn(
      "graph_relationship_limit",
      {item["code"] for item in _graph_first_payload(relationships_result)["validation_errors"]},
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
    credential_result = plugin.explain_graph(cypher=cypher, execution_result=credential)

    self.assertIn(
      "invalid_serialized_property_value",
      {item["code"] for item in _graph_first_payload(nested_result)["validation_errors"]},
    )
    self.assertEqual(credential_result["status"], "ok")
    flattened = json.dumps(credential_result["neo4j_trace"])
    self.assertNotIn("should-not-cross", flattened)
    self.assertIn('"type": "redacted"', flattened)
    self.assertIn('"reason": "security_policy"', flattened)
    self.assertIn("/evidence_catalog/nodes/", flattened)

  def test_graph_first_evidence_preserves_bounded_scalar_lists_larger_than_twenty(self):
    plugin = _make_api(edgeguard_explanation_model_port=5091)
    cypher = "MATCH (i:Indicator) RETURN i LIMIT 25"
    plan = plugin.prepare_graph_explanation(cypher=cypher)

    for item_count in (20, 21, 50):
      with self.subTest(item_count=item_count):
        execution = _serialized_execution(cypher)
        values = [f"T{index:04d}" for index in range(item_count)]
        execution["graph"]["nodes"][0]["properties"] = {"uses_techniques": values}

        packet, packet_meta, errors = _build_graph_evidence_packet_from_execution(
          request="Show the returned indicator.",
          plan=plan,
          execution_result=execution,
        )

        self.assertEqual(errors, [])
        self.assertIsNotNone(packet)
        packet_properties = packet["graph"]["nodes"][0]["properties"]
        self.assertEqual(
          "uses_techniques" in packet_properties,
          item_count <= 20,
        )
        catalog_properties = packet_meta["_evidence_catalog"]["nodes"][0]["properties"]
        tagged_list = catalog_properties["entries"][0]["value"]
        self.assertEqual(tagged_list["type"], "list")
        self.assertEqual(len(tagged_list["items"]), item_count)

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
          {item["code"] for item in _graph_first_payload(result)["validation_errors"]},
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
      {item["code"] for item in _graph_first_payload(rejected_map)["validation_errors"]},
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
          {item["code"] for item in _graph_first_payload(result)["validation_errors"]},
        )

    valid_temporals = {
      "date": "2026-07-20",
      "date_time": "2026-07-20T12:30:00.123456789Z",
      "duration": "P-1Y-2M-3DT-1H-1M-1.123456789S",
      "local_date_time": "2026-07-20T12:30:00.123456789",
      "local_time": "12:30:00.123456789",
      "time": "12:30:00.123456789+00:00",
    }
    self.assertTrue(all(
      _valid_temporal_value(temporal_type, value)
      for temporal_type, value in valid_temporals.items()
    ))
    self.assertFalse(_valid_temporal_value("date_time", "2026-07-20T12:30:00"))
    self.assertFalse(_valid_temporal_value("local_time", "12:30:00Z"))
    self.assertFalse(_valid_temporal_value("duration", "P1Y2Y"))
    self.assertFalse(_valid_temporal_value("date_time", "2026-07-20 12:30:00Z"))
    self.assertFalse(_valid_temporal_value("date_time", "20260720T123000Z"))
    self.assertTrue(_valid_temporal_value("duration", "P1DT"))
    self.assertTrue(_valid_temporal_value(
      "date_time",
      "2026-07-20T12:30:00+02:00[Europe/Paris]",
    ))

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
          {item["code"] for item in _graph_first_payload(result)["validation_errors"]},
        )

    bad_ordinal = _serialized_execution(cypher)
    bad_ordinal["query_result_evidence"]["rows"][0]["ordinal"] = 1
    result = plugin.explain_graph(cypher=cypher, execution_result=bad_ordinal)
    self.assertIn(
      "invalid_result_row",
      {item["code"] for item in _graph_first_payload(result)["validation_errors"]},
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
        # Fix round 5: unexpected connection/credential fields in
        # execution-evidence mode are a malformed request body, 400.
        self.assertEqual(result["status_code"], 400)
        payload = _graph_first_payload(result)
        self.assertEqual(payload["status"], "rejected")
        self.assertIn("credential_field_not_allowed", {item["code"] for item in payload["validation_errors"]})
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

    # Fix round 5: guard rejection is a deliberate 422 via the wrapper-safe
    # transport, not a bare 500.
    self.assertEqual(result["status_code"], 422)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "rejected")
    self.assertFalse(payload["executed"])
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
    self.assertEqual(result["result"]["explanation_trace"]["mode"]["requested"], "balanced")
    self.assertEqual(result["result"]["explanation_trace"]["calls"], [])
    self.assertEqual(result["result"]["explanation_trace"]["outcome"]["safe_code"], "model_not_configured")
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
      "server_max_rows": 50,
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
    self.assertEqual(result["model"], "base_qwen3_4b")
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

  def test_explanation_model_rejects_unselected_output_mode_without_provider_call(self):
    plugin = _make_api(edgeguard_explanation_output_mode=None)
    plugin.P = MagicMock()

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post"
    ) as mocked_post:
      result = _call_model(plugin, _case_explanation_packet())

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["diagnostics"]["stage"], "configuration")
    self.assertEqual(result["diagnostics"]["reason"], "output_mode_not_selected")
    mocked_post.assert_not_called()
    outcome_log = " ".join(str(call) for call in plugin.P.call_args_list)
    self.assertEqual(outcome_log.count("EDGEGUARD_EXPLANATION_OUTCOME"), 1)

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
    self.assertEqual(result["result"]["explanation_trace"]["mode"]["requested"], "balanced")
    self.assertEqual(result["result"]["explanation_trace"]["calls"], [])
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
              enable_empty_result_broadening=True,
            )

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["result_digest"]["query_scope"]["mode"], "expand")
    self.assertFalse(result["result_digest"]["query_scope"]["accepted_equals_executed"])
    self.assertTrue(result["packet"]["execution"]["broadened"])
    self.assertEqual(result["packet"]["execution"]["live_retry_reason"], "executed_no_rows")
    self.assertTrue(result["live_retry"]["applied"])
    self.assertEqual(fake_session.run.call_count, 2)
    self.assertEqual(
      _run_text(fake_session.run.call_args_list[1]),
      "MATCH p=(n:Indicator)-[:SOURCED_FROM]-() RETURN p LIMIT 25",
    )
    # Contract §6, review finding 6 (S5=Q9): with opt-in broadening, the
    # requested (primary) query's `empty_reason` is still reported even
    # though the broadened query went on to return rows.
    self.assertEqual(result["validation"]["empty_reason"], "no_match")

  def test_explain_graph_returns_truthful_truncated_digest_without_model_call(self):
    plugin = _make_api()
    fake_driver, _fake_session = _driver_with_results(
      _Result([_graph_record() for _idx in range(26)], keys=["i", "s"]),
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

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["ok"])
    self.assertFalse(result["explained"])
    self.assertTrue(result["result_digest"]["query_scope"]["truncated"])
    self.assertEqual(result["result_digest"]["counts"]["returned_rows"], 25)
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertEqual(
      result["analyst_brief"]["diagnostics"]["validation_codes"],
      ["transport_truncated"],
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
    self.assertNotIn("limit_adjusted", {item["type"] for item in explanation["caveats"]})
    packet_errors, context = _validate_graph_evidence_packet(result["packet"])
    self.assertEqual(packet_errors, [])
    validation_errors = _validate_case_explanation(explanation, context)
    self.assertNotIn("missing_required_caveat", {item["code"] for item in validation_errors})

  def test_explain_graph_rejects_malformed_json_output(self):
    plugin = _make_api(graph_first_provider=lambda _payload: {
      "content": "not json",
      "finish_reason": "stop",
      "completion_tokens": 2,
      "duration_ms": 1.0,
    })
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
        )

    self.assertEqual(result["status"], "ok")
    self.assertFalse(result["explained"])
    diagnostics = result["analyst_brief"]["diagnostics"]
    self.assertEqual(diagnostics["reason"], "malformed_json")
    self.assertEqual(diagnostics["validation_codes"], ["invalid_model_output"])
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertNotIn("raw_output", json.dumps(result["explanation_trace"]))

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
    plugin = _make_api(graph_first_provider=lambda _payload: {
      "content": '{"status":"supported"',
      "finish_reason": "length",
      "completion_tokens": 127,
      "duration_ms": 1.0,
    })
    cypher = "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25"

    result = plugin.explain_graph(
      cypher=cypher,
      request="Which source supports this indicator?",
      execution_result=_serialized_execution(cypher),
    )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["ok"])
    self.assertTrue(result["executed"])
    self.assertFalse(result["explained"])
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertEqual(result["analyst_brief"]["status"], "unavailable")
    self.assertEqual(result["analyst_brief"]["diagnostics"]["reason"], "output_truncated")
    self.assertNotIn("raw_output", json.dumps(result["explanation_trace"]))

  def test_explain_graph_rejects_extra_map_output_keys_without_retry(self):
    def invalid_provider(payload):
      valid = json.loads(_graph_first_provider(payload)["content"])
      valid["extra"] = "not allowed"
      return {
        "content": json.dumps(valid),
        "finish_reason": "stop",
        "completion_tokens": 16,
        "duration_ms": 1.0,
      }

    plugin = _make_api(graph_first_provider=invalid_provider)
    plugin.P = MagicMock()
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="private-question-sentinel",
          cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
        )

    diagnostics = result["analyst_brief"]["diagnostics"]
    codes = set(diagnostics["validation_codes"])
    self.assertEqual(result["status"], "ok")
    self.assertFalse(result["explained"])
    self.assertEqual(diagnostics["stage"], "response_parse")
    self.assertEqual(diagnostics["reason"], "malformed_json")
    self.assertEqual(codes, {"invalid_map_output"})
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 1)
    serialized_result = json.dumps(result)
    serialized_logs = " ".join(str(call) for call in plugin.P.call_args_list)
    self.assertNotIn("raw_output", serialized_result)
    self.assertNotIn("private-question-sentinel", serialized_logs)
    self.assertNotIn("example.org", serialized_logs)

  def test_explain_graph_rejects_unknown_map_anchor_without_retry(self):
    def invalid_provider(payload):
      valid = json.loads(_graph_first_provider(payload)["content"])
      valid["anchor"] = "N999"
      return {
        "content": json.dumps(valid),
        "finish_reason": "stop",
        "completion_tokens": 16,
        "duration_ms": 1.0,
      }

    plugin = _make_api(graph_first_provider=invalid_provider)
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
        )

    self.assertEqual(result["status"], "ok")
    codes = set(result["analyst_brief"]["diagnostics"]["validation_codes"])
    self.assertEqual(codes, {"invalid_map_citation"})
    self.assertEqual(result["analyst_brief"]["diagnostics"]["reason"], "malformed_json")
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 1)

  def test_explain_graph_rejects_incomplete_map_row_citations_without_retry(self):
    def invalid_provider(payload):
      valid = json.loads(_graph_first_provider(payload)["content"])
      valid["rows"] = []
      return {
        "content": json.dumps(valid),
        "finish_reason": "stop",
        "completion_tokens": 16,
        "duration_ms": 1.0,
      }

    plugin = _make_api(graph_first_provider=invalid_provider)
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_record()], keys=["p"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          cypher="MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 10",
        )

    codes = set(result["analyst_brief"]["diagnostics"]["validation_codes"])
    self.assertEqual(result["status"], "ok")
    self.assertEqual(codes, {"invalid_map_citation"})
    self.assertNotIn("explanation", result)
    self.assertTrue(result["result_digest"]["coverage"]["complete"])
    self.assertEqual(result["explanation_trace"]["outcome"]["attempted_calls"], 1)

  def test_explain_graph_returns_provider_error_after_packet_build(self):
    plugin = _make_api(graph_first_provider=None)
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

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["executed"])
    self.assertFalse(result["explained"])
    self.assertEqual(result["analyst_brief"]["diagnostics"]["stage"], "provider")
    self.assertEqual(result["analyst_brief"]["diagnostics"]["reason"], "provider_http_error")
    self.assertNotIn("provider_status", result)
    self.assertTrue(result["result_digest"]["coverage"]["complete"])

  def test_case_explanation_validator_rejects_redaction_flags(self):
    packet = {
      "schema_version": "edgeguard.graph_evidence_packet.v1",
      "request": "Explain graph.",
      "accepted_cypher": "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
      "executed_cypher": "MATCH (i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN i, s LIMIT 25",
      "limit_policy": {
        "generated_limit": 25,
        "executed_limit": 25,
      "server_max_rows": 50,
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


class _FakeNeo4jQuery:
  def __init__(self, text, timeout=None):
    self.text = text
    self.timeout = timeout


class EdgeGuardExecutionBoundaryTests(unittest.TestCase):
  """EG-013 P3: database-side timeout, read routing, recursive evidence privacy."""

  def test_run_neo4j_query_sends_transaction_timeout_and_read_access(self):
    plugin = _make_api(neo4j_query_timeout_seconds=30)
    fake_driver, fake_session = _driver_with_results(_Result([], keys=["value"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.Query", _FakeNeo4jQuery):
      with patch("extensions.business.cybersec.edgeguard.edgeguard_api.READ_ACCESS", "READ"):
        plugin._run_neo4j_query(fake_driver, "MATCH (i:Indicator) RETURN i.value AS value LIMIT 5", 5)

    fake_driver.session.assert_called_once_with(default_access_mode="READ")
    query = fake_session.run.call_args[0][0]
    self.assertIsInstance(query, _FakeNeo4jQuery)
    self.assertEqual(query.text, "MATCH (i:Indicator) RETURN i.value AS value LIMIT 5")
    self.assertEqual(query.timeout, 30)

  def test_run_neo4j_query_falls_back_to_raw_text_without_neo4j_query(self):
    plugin = _make_api()
    fake_driver, fake_session = _driver_with_results(_Result([], keys=["value"]))

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.Query", None):
      plugin._run_neo4j_query(fake_driver, "MATCH (i:Indicator) RETURN i.value AS value LIMIT 5", 5)

    self.assertEqual(
      fake_session.run.call_args[0][0],
      "MATCH (i:Indicator) RETURN i.value AS value LIMIT 5",
    )

  def test_query_timeout_failure_returns_sanitized_error(self):
    plugin = _make_api()
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.side_effect = RuntimeError("transaction timeout reached for secret@host")
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          cypher="MATCH (i:Indicator) RETURN i.value AS value LIMIT 5",
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
        )

    # Fix round 4 (re-review-3 finding 3): a driver/connection failure is
    # connectivity/service-unavailable — 503 via the wrapper-safe transport.
    self.assertEqual(result["status_code"], 503)
    payload = _graph_first_payload(result)
    self.assertFalse(payload["ok"])
    self.assertEqual(payload["error_code"], "neo4j_connection_error")
    self.assertNotIn("secret", json.dumps(result))

  def test_neo4j_client_error_returns_structured_status_error_not_a_500(self):
    # Fix round 3, L2a: a Neo4j client/syntax error (accepted by the guard,
    # rejected by Neo4j itself) must come back as a structured `status:
    # error` with a distinct `error_code`, never let the driver's exception
    # escape `/neo4j_query` uncaught.
    plugin = _make_api()
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.side_effect = Neo4jClientError(
      "{code: Neo.ClientError.Statement.SyntaxError} {message: PatternExpressions are not "
      "allowed to introduce new variables: 'i'.}"
    )
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          cypher=(
            "MATCH p=(c:CVE)-[:HAS_CVSS_v31]->(cvss:CVSSv31) WHERE c.cve_id IN ['CVE-2024-99999'] "
            "AND EXISTS { MATCH (c)-[:EXPLOITS]->(i:Indicator) WHERE i.value STARTS WITH '203.0.113.' } "
            "RETURN p ORDER BY cvss.base_score DESC LIMIT 5"
          ),
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
        )

    # Fix round 4 (re-review-3 finding 3): the platform's FastAPI wrapper
    # maps any plugin result carrying a top-level `error` key to HTTP 500
    # unless `status_code` says otherwise — 422 states the query content is
    # at fault, via the wrapper-safe transport.
    self.assertEqual(result["status_code"], 422)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "error")
    self.assertFalse(payload["ok"])
    self.assertEqual(payload["error_code"], "neo4j_client_error")
    self.assertIn("PatternExpressions", payload["error"])

  def test_neo4j_auth_error_returns_service_unavailable_not_a_500(self):
    # Fix round 4 (re-review-3 finding 6): `AuthError`/`Forbidden`/
    # `TokenExpired` are `ClientError` subclasses but report a rejected
    # driver credential, not a malformed query — a server-side
    # misconfiguration, so this must be 503 with a distinct `error_code`,
    # never the 422 given to a Cypher syntax/type/constraint error.
    plugin = _make_api()
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.side_effect = Neo4jAuthError(
      "{code: Neo.ClientError.Security.Unauthorized} {message: The client is unauthorized due to "
      "authentication failure.}"
    )
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          cypher="MATCH (i:Indicator) RETURN i.value AS value LIMIT 5",
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
        )

    self.assertEqual(result["status_code"], 503)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "error")
    self.assertFalse(payload["ok"])
    self.assertEqual(payload["error_code"], "neo4j_auth_error")
    self.assertIn("Unauthorized", payload["error"])

  def test_prepared_execution_rejects_nested_connection_fields(self):
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    cypher = "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10"
    for path_label, mutate in (
      ("row map", lambda er: er["query_result_evidence"]["rows"][0]["values"].append(
        {"type": "map", "entries": [{"key": "uri", "value": {"type": "string", "value": "bolt://sentinel-host"}}]},
      )),
      ("graph properties", lambda er: er["graph"]["nodes"][0]["properties"].update(
        {"password": "sentinel-value"},
      )),
    ):
      with self.subTest(path=path_label):
        execution_result = _serialized_execution(cypher)
        mutate(execution_result)

        provider_calls = []
        plugin._graph_first_provider_for_tests = lambda payload: provider_calls.append(payload)
        result = plugin.explain_graph(
          cypher=cypher,
          request="Explain the exact graph.",
          execution_result=execution_result,
        )

        serialized = json.dumps(result)
        self.assertNotIn("sentinel-host", serialized)
        self.assertNotIn("sentinel-value", serialized)
        self.assertEqual(provider_calls, [])
        self.assertFalse(result.get("explained"))
        self.assertIn("credential_field_not_allowed", serialized)

  def test_live_path_rejects_nested_connection_fields_before_evidence(self):
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    leaky = _GraphNode("indicator-1", ["Indicator"], {"value": "example.org", "uri": "bolt://sentinel-host"})
    source = _GraphNode("source-1", ["Source"], {"name": "AlienVault OTX"})
    rel = _GraphRelationship("rel-1", "SOURCED_FROM", leaky, source, {})
    record = _DriverRecord({"p": _GraphPath([leaky, source], [rel])}, {"p": ["x"]})
    fake_driver, fake_session = _driver_with_results(_Result([record], keys=["p"]))

    provider_calls = []
    plugin._graph_first_provider_for_tests = lambda payload: provider_calls.append(payload)
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="Explain the returned graph.",
          cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10",
        )

    serialized = json.dumps(result)
    self.assertNotIn("sentinel-host", serialized)
    self.assertEqual(provider_calls, [])
    self.assertFalse(result.get("explained"))
    self.assertIn("credential_field_not_allowed", serialized)

  def test_explain_graph_neo4j_client_error_returns_structured_status_error(self):
    # Fix round 3, L2a: the explain route shares `_run_neo4j_query` with
    # `/neo4j_query` and must give the same distinct `error_code` for a
    # Neo4j client/syntax error, never let it escape as an unhandled 500.
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    fake_driver, _fake_session = _driver_with_results(
      Neo4jClientError(
        "{code: Neo.ClientError.Statement.SyntaxError} {message: PatternExpressions are not "
        "allowed to introduce new variables: 'i'.}"
      ),
    )

    provider_calls = []
    plugin._graph_first_provider_for_tests = lambda payload: provider_calls.append(payload)
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="Explain the returned graph.",
          cypher=(
            "MATCH p=(c:CVE)-[:HAS_CVSS_v31]->(cvss:CVSSv31) WHERE c.cve_id IN ['CVE-2024-99999'] "
            "AND EXISTS { MATCH (c)-[:EXPLOITS]->(i:Indicator) WHERE i.value STARTS WITH '203.0.113.' } "
            "RETURN p ORDER BY cvss.base_score DESC LIMIT 5"
          ),
        )

    # Fix round 4 (re-review-3 finding 3): same wrapper-safe transport and
    # 422 as `/neo4j_query`'s identical branch.
    self.assertEqual(result["status_code"], 422)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "error")
    self.assertFalse(payload["ok"])
    self.assertEqual(payload["error_code"], "neo4j_client_error")
    self.assertEqual(provider_calls, [])

  def test_explain_graph_neo4j_auth_error_returns_service_unavailable(self):
    # Fix round 4 (re-review-3 finding 6): same auth/credential family as
    # `/neo4j_query` — 503 with a distinct `error_code`, not 422.
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    fake_driver, _fake_session = _driver_with_results(
      Neo4jAuthError(
        "{code: Neo.ClientError.Security.Unauthorized} {message: The client is unauthorized due to "
        "authentication failure.}"
      ),
    )

    provider_calls = []
    plugin._graph_first_provider_for_tests = lambda payload: provider_calls.append(payload)
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.explain_graph(
          uri="example.com:7687",
          scheme="bolt+s",
          username="neo4j",
          password="secret",
          request="Explain the returned graph.",
          cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10",
        )

    self.assertEqual(result["status_code"], 503)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "error")
    self.assertFalse(payload["ok"])
    self.assertEqual(payload["error_code"], "neo4j_auth_error")
    self.assertEqual(provider_calls, [])

  @staticmethod
  def _simulated_wrapper_status(result):
    # Fix round 4 (re-review-3 finding 3): the platform's generated FastAPI
    # wrapper (`/tmp/tmp*/main.py:229-245` inside the edg3 container; see
    # `docs/tasks_manager/_runs/EGM-059/phase-2/re-review-3.md`) does, for
    # each plugin endpoint result dict: if `status_code` is present and not
    # 2xx, raise an HTTP error with that code; elif `"error" in result`,
    # raise HTTP 500; else respond 200. This four-line replica proves the
    # actual `neo4j_query`/`explain_graph` return values never fall into the
    # bare-500 branch for a client- or auth-class Neo4j failure.
    status_code = result.get("status_code")
    if status_code is not None and not (200 <= status_code < 300):
      return status_code
    if "error" in result:
      return 500
    return 200

  def test_neo4j_client_and_auth_errors_never_reach_the_wrappers_bare_500(self):
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session
    cypher = "MATCH (i:Indicator) RETURN i.value AS value LIMIT 5"

    cases = (
      (Neo4jClientError("{code: Neo.ClientError.Statement.SyntaxError} {message: bad}"), 422),
      (Neo4jAuthError("{code: Neo.ClientError.Security.Unauthorized} {message: bad}"), 503),
      (RuntimeError("connection failed"), 503),
    )
    for exc, expected_status in cases:
      with self.subTest(exc=type(exc).__name__):
        plugin = _make_api()
        fake_session.run.side_effect = exc
        with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
          with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
            result = plugin.neo4j_query(
              cypher=cypher,
              uri="example.com:7687",
              scheme="bolt+s",
              username="neo4j",
              password="secret",
            )
        self.assertIn("error", _graph_first_payload(result))
        self.assertEqual(self._simulated_wrapper_status(result), expected_status)

  # Fix round 5: extends the round-4 wrapper-rule replica
  # (`_simulated_wrapper_status`) to every remaining `/neo4j_query`,
  # `prepare_graph_explanation` and `explain_graph` error/rejection path
  # that carries a top-level `error` key without `status_code` — the exact
  # shape the platform's FastAPI wrapper turns into a bare HTTP 500.

  ACCEPTED_ROWS_CYPHER = "MATCH (i:Indicator) RETURN i.value AS value LIMIT 5"
  GUARD_REJECTED_CYPHER = "MATCH (i:InternetFacing) RETURN i.hostname AS hostname"

  def test_neo4j_query_every_error_path_resolves_to_a_deliberate_status_code(self):
    def guard_rejection(plugin):
      return plugin.neo4j_query(cypher=self.GUARD_REJECTED_CYPHER)

    def bad_connection_override(plugin):
      # `_resolve_neo4j_connection`: an incomplete override (missing
      # username/password) is caller input, not a driver failure.
      return plugin.neo4j_query(
        cypher=self.ACCEPTED_ROWS_CYPHER,
        uri="override.example:7687",
        scheme="neo4j+s",
      )

    def bad_uri_scheme(plugin):
      # `_normalize_neo4j_uri`: a scheme outside `NEO4J_SCHEMES`.
      return plugin.neo4j_query(
        cypher=self.ACCEPTED_ROWS_CYPHER,
        uri="override.example:7687",
        username="neo4j",
        password="secret",
        scheme="ftp",
      )

    def driver_missing(plugin):
      # `GraphDatabase is None` (the neo4j driver package is not installed
      # in this runtime) — unpatched, matching the module's own default.
      return plugin.neo4j_query(
        cypher=self.ACCEPTED_ROWS_CYPHER,
        uri="override.example:7687",
        username="neo4j",
        password="secret",
        scheme="bolt+s",
      )

    cases = (
      ("guard_rejection", guard_rejection, 422),
      ("bad_connection_override", bad_connection_override, 400),
      ("bad_uri_scheme", bad_uri_scheme, 400),
      ("driver_missing", driver_missing, 503),
    )
    for name, make_result, expected_status in cases:
      with self.subTest(case=name):
        plugin = _make_api()
        result = make_result(plugin)
        self.assertEqual(result["status_code"], expected_status)
        payload = _graph_first_payload(result)
        self.assertIn("error", payload)
        self.assertEqual(self._simulated_wrapper_status(result), expected_status)

  def test_prepare_graph_explanation_every_error_path_resolves_to_a_deliberate_status_code(self):
    def empty_cypher(plugin):
      return plugin.prepare_graph_explanation(cypher="")

    def forwarded_connection_field(plugin):
      return plugin.prepare_graph_explanation(cypher=self.ACCEPTED_ROWS_CYPHER, username="neo4j")

    def invalid_broadening_type(plugin):
      return plugin.prepare_graph_explanation(
        cypher=self.ACCEPTED_ROWS_CYPHER, enable_empty_result_broadening="nope",
      )

    def invalid_mode_config(plugin):
      return plugin.prepare_graph_explanation(cypher=self.ACCEPTED_ROWS_CYPHER, explanation_mode="bogus")

    def guard_rejection(plugin):
      return plugin.prepare_graph_explanation(cypher=self.GUARD_REJECTED_CYPHER)

    def unsafe_projection(plugin):
      # Reaches the plan's own projection-safety checks (contract §4.3) via
      # a bracket-property-access candidate the shared guard's own
      # execution-safety stage may also independently reject; either
      # mechanism resolves to the same deliberate 422.
      return plugin.prepare_graph_explanation(
        cypher='MATCH (n:Indicator) WITH n, "value" AS k RETURN n[k] AS safe LIMIT 5',
      )

    def tokenizer_unavailable(plugin_factory):
      plugin = plugin_factory(
        graph_first_token_counter=None,
        edgeguard_explanation_tokenizer_path=None,
      )
      return plugin.prepare_graph_explanation(cypher=self.ACCEPTED_ROWS_CYPHER)

    cases = (
      ("empty_cypher", lambda factory: empty_cypher(factory()), 400),
      ("forwarded_connection_field", lambda factory: forwarded_connection_field(factory()), 400),
      ("invalid_broadening_type", lambda factory: invalid_broadening_type(factory()), 400),
      ("invalid_mode_config", lambda factory: invalid_mode_config(factory()), 400),
      ("guard_rejection", lambda factory: guard_rejection(factory()), 422),
      ("unsafe_projection", lambda factory: unsafe_projection(factory()), 422),
      ("tokenizer_unavailable", tokenizer_unavailable, 503),
    )
    for name, run, expected_status in cases:
      with self.subTest(case=name):
        result = run(_make_api)
        self.assertEqual(result["status_code"], expected_status)
        payload = _graph_first_payload(result)
        self.assertIn("error", payload)
        self.assertEqual(self._simulated_wrapper_status(result), expected_status)

  def test_explain_graph_every_early_error_path_resolves_to_a_deliberate_status_code(self):
    def empty_cypher(plugin):
      return plugin.explain_graph(cypher="")

    def empty_request(plugin):
      return plugin.explain_graph(cypher=self.ACCEPTED_ROWS_CYPHER, request="")

    def invalid_fields(plugin):
      return plugin.explain_graph(cypher=self.ACCEPTED_ROWS_CYPHER, method="carrier-pigeon")

    def invalid_broadening_type(plugin):
      return plugin.explain_graph(
        cypher=self.ACCEPTED_ROWS_CYPHER, enable_empty_result_broadening="nope",
      )

    def invalid_mode_config(plugin):
      return plugin.explain_graph(cypher=self.ACCEPTED_ROWS_CYPHER, explanation_mode="bogus")

    def guard_rejection(plugin):
      return plugin.explain_graph(cypher=self.GUARD_REJECTED_CYPHER)

    def tokenizer_unavailable(factory):
      plugin = factory(graph_first_token_counter=None, edgeguard_explanation_tokenizer_path=None)
      return plugin.explain_graph(cypher=self.ACCEPTED_ROWS_CYPHER)

    cases = (
      ("empty_cypher", lambda: empty_cypher(_make_api()), 400),
      ("empty_request", lambda: empty_request(_make_api()), 400),
      ("invalid_fields", lambda: invalid_fields(_make_api()), 400),
      ("invalid_broadening_type", lambda: invalid_broadening_type(_make_api()), 400),
      ("invalid_mode_config", lambda: invalid_mode_config(_make_api()), 400),
      ("guard_rejection", lambda: guard_rejection(_make_api()), 422),
      ("tokenizer_unavailable", lambda: tokenizer_unavailable(_make_api), 503),
    )
    for name, run, expected_status in cases:
      with self.subTest(case=name):
        result = run()
        self.assertEqual(result["status_code"], expected_status)
        payload = _graph_first_payload(result)
        self.assertIn("error", payload)
        self.assertEqual(self._simulated_wrapper_status(result), expected_status)

  def test_explain_graph_live_connection_error_paths_resolve_to_a_deliberate_status_code(self):
    # Fix round 5: the `insight_brief` strategy skips the `eel_compatibility`
    # explanation-model gate (already wrapper-safe, untouched by this round)
    # so these cases isolate the live-connection branches this round fixed.
    def bad_connection_override(plugin):
      return plugin.explain_graph(
        cypher=self.ACCEPTED_ROWS_CYPHER, uri="override.example:7687", scheme="neo4j+s",
      )

    def bad_uri_scheme(plugin):
      return plugin.explain_graph(
        cypher=self.ACCEPTED_ROWS_CYPHER,
        uri="override.example:7687", username="neo4j", password="secret", scheme="ftp",
      )

    def driver_missing(plugin):
      return plugin.explain_graph(
        cypher=self.ACCEPTED_ROWS_CYPHER,
        uri="override.example:7687", username="neo4j", password="secret", scheme="bolt+s",
      )

    cases = (
      ("bad_connection_override", bad_connection_override, 400),
      ("bad_uri_scheme", bad_uri_scheme, 400),
      ("driver_missing", driver_missing, 503),
    )
    for name, make_result, expected_status in cases:
      with self.subTest(case=name):
        plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
        result = make_result(plugin)
        self.assertEqual(result["status_code"], expected_status)
        payload = _graph_first_payload(result)
        self.assertIn("error", payload)
        self.assertEqual(self._simulated_wrapper_status(result), expected_status)

  def test_explain_graph_execution_result_forwarded_connection_field_is_400(self):
    plugin = _make_api(
      edgeguard_explanation_model_port=5091,
      edgeguard_explanation_model="base_qwen3_4b",
    )
    result = plugin.explain_graph(
      cypher=self.ACCEPTED_ROWS_CYPHER,
      execution_result=_serialized_execution(self.ACCEPTED_ROWS_CYPHER),
      username="neo4j",
    )
    self.assertEqual(result["status_code"], 400)
    payload = _graph_first_payload(result)
    self.assertIn("error", payload)
    self.assertEqual(self._simulated_wrapper_status(result), 400)

  def test_plan_not_ok_status_code_is_popped_from_the_plan_and_never_leaks(self):
    # Fix round 5: `_prepare_graph_explanation_plan` tags the intended HTTP
    # status on `_WRAPPER_STATUS_CODE_KEY`; every one of its three callers
    # (`prepare_graph_explanation`, `explain_graph`'s execution-result and
    # live branches) must pop it — both when the plan supplies one and when
    # it falls back to the 422 default — and never let the key reach the
    # response body.
    tagged_plan = {
      "ok": False,
      "status": "rejected",
      "error": "forced test rejection",
      _WRAPPER_STATUS_CODE_KEY: 400,
    }
    untagged_plan = {"ok": False, "status": "rejected", "error": "forced test rejection"}

    for plan, expected_status in ((tagged_plan, 400), (untagged_plan, 422)):
      with self.subTest(tagged=(_WRAPPER_STATUS_CODE_KEY in plan)):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api._prepare_graph_explanation_plan",
          # Fix round 5 test note: a fresh dict per call — each of the three
          # call sites below pops `_WRAPPER_STATUS_CODE_KEY` from its own
          # plan, and a shared `return_value` dict would let the first pop
          # silently strip it before the next call site ever sees it.
          side_effect=lambda *args, **kwargs: dict(plan),
        ):
          plugin = _make_api(
            edgeguard_explanation_model_port=5091,
            edgeguard_explanation_model="base_qwen3_4b",
          )
          prepare_result = plugin.prepare_graph_explanation(cypher=self.ACCEPTED_ROWS_CYPHER)
          execution_result_call = plugin.explain_graph(
            cypher=self.ACCEPTED_ROWS_CYPHER,
            execution_result=_serialized_execution(self.ACCEPTED_ROWS_CYPHER),
          )
          live_plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
          with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
            with patch.object(live_plugin, "_neo4j_driver"):
              live_call = live_plugin.explain_graph(
                cypher=self.ACCEPTED_ROWS_CYPHER,
                uri="override.example:7687",
                username="neo4j",
                password="secret",
                scheme="bolt+s",
              )

        for result in (prepare_result, execution_result_call, live_call):
          self.assertEqual(result["status_code"], expected_status)
          payload = _graph_first_payload(result)
          self.assertIn("error", payload)
          self.assertNotIn(_WRAPPER_STATUS_CODE_KEY, payload)
          self.assertEqual(self._simulated_wrapper_status(result), expected_status)

  def test_explain_graph_live_forbidden_execution_field_is_422_not_a_bare_500(self):
    # Fix round 5: EG-013's recursive no-connection-data invariant on the
    # live-query path — forcing `_forbidden_execution_field` to fire proves
    # the branch resolves to the deliberate 422 (packet/evidence validation
    # rejection), not the wrapper's bare 500, without depending on a
    # specific Cypher shape to organically trigger it.
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.return_value = _Result([], keys=["value"])
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api._forbidden_execution_field",
          return_value="password",
        ):
          result = plugin.explain_graph(
            cypher=self.ACCEPTED_ROWS_CYPHER,
            uri="override.example:7687",
            username="neo4j",
            password="secret",
            scheme="bolt+s",
          )

    self.assertEqual(result["status_code"], 422)
    payload = _graph_first_payload(result)
    self.assertIn("error", payload)
    self.assertEqual(
      {item["code"] for item in payload["validation_errors"]},
      {"credential_field_not_allowed"},
    )
    self.assertEqual(self._simulated_wrapper_status(result), 422)

  # Fix round 6: extends the round-4/5 wrapper-rule replica
  # (`_simulated_wrapper_status`) to `/generate` and `/neo4j_test` —
  # every remaining error path that carried a top-level `error` key without
  # `status_code`, the exact shape the platform's FastAPI wrapper turns
  # into a bare HTTP 500.

  def test_generate_every_early_error_path_resolves_to_a_deliberate_status_code(self):
    def benchmark_mode_disabled():
      plugin = _make_api()
      return plugin.generate(request="Show indicators", benchmark_mode=True)

    def invalid_request():
      plugin = _make_api()
      return plugin.generate(request="")

    def request_too_large():
      plugin = _make_api()
      return plugin.generate(request="x" * (GENERATION_MAX_REQUEST_CHARS + 1))

    def unsupported_model():
      plugin = _make_api()
      return plugin.generate(request="Show indicators", model_key="not-configured")

    def worker_not_ready():
      # No `worker_semaphore_env` configured for `PRIVATE_MODEL_KEY` — the
      # worker URL itself cannot be resolved, distinct from `model_not_ready`
      # below (a configured worker that has not finished starting).
      plugin = _make_api()
      with patch("extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session.post"):
        return plugin.generate(request="Show indicators", model_key=PRIVATE_MODEL_KEY)

    def model_not_ready():
      plugin = _make_api(worker_semaphore_env={
        PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"},
      })
      session = MagicMock()
      session.get.return_value = _Response(payload={"result": {"serving_ready": False}})
      with patch(
        "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
        return_value=session,
      ):
        return plugin.generate(request="Show indicators", model_key=PRIVATE_MODEL_KEY)

    cases = (
      ("benchmark_mode_disabled", benchmark_mode_disabled, 403),
      ("invalid_request", invalid_request, 400),
      ("request_too_large", request_too_large, 413),
      ("unsupported_model", unsupported_model, 400),
      ("worker_not_ready", worker_not_ready, 503),
      ("model_not_ready", model_not_ready, 503),
    )
    for name, run, expected_status in cases:
      with self.subTest(case=name):
        result = run()
        self.assertEqual(result["status_code"], expected_status)
        payload = _graph_first_payload(result)
        self.assertIn("error", payload)
        self.assertEqual(self._simulated_wrapper_status(result), expected_status)
    # `worker_not_ready` and `model_not_ready` both resolve to 503 but are
    # distinct diagnostics codes — pin that they are not silently collapsed
    # into the same branch.
    self.assertEqual(
      _graph_first_payload(worker_not_ready())["diagnostics"]["code"], "worker_not_ready",
    )
    self.assertEqual(
      _graph_first_payload(model_not_ready())["diagnostics"]["code"], "model_not_ready",
    )

  def test_neo4j_test_every_error_path_resolves_to_a_deliberate_status_code(self):
    def bad_connection_override(plugin):
      # `_resolve_neo4j_connection`: an incomplete override (missing
      # username/password) is caller input, not a driver failure.
      return plugin.neo4j_test(uri="override.example:7687", scheme="neo4j+s")

    def bad_uri_scheme(plugin):
      # `_normalize_neo4j_uri`: a scheme outside `NEO4J_SCHEMES`.
      return plugin.neo4j_test(
        uri="override.example:7687", username="neo4j", password="secret", scheme="ftp",
      )

    def driver_missing(plugin):
      # `GraphDatabase is None` (the neo4j driver package is not installed
      # in this runtime) — unpatched, matching the module's own default.
      return plugin.neo4j_test(
        uri="override.example:7687", username="neo4j", password="secret", scheme="bolt+s",
      )

    def connection_failure(plugin):
      # The driver is present but the connection attempt itself fails —
      # a Neo4j-service-side failure, not caller input.
      with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
        with patch.object(plugin, "_neo4j_driver", side_effect=RuntimeError("connection failed")):
          return plugin.neo4j_test(
            uri="override.example:7687", username="neo4j", password="secret", scheme="bolt+s",
          )

    cases = (
      ("bad_connection_override", bad_connection_override, 400),
      ("bad_uri_scheme", bad_uri_scheme, 400),
      ("driver_missing", driver_missing, 503),
      ("connection_failure", connection_failure, 503),
    )
    for name, make_result, expected_status in cases:
      with self.subTest(case=name):
        plugin = _make_api()
        result = make_result(plugin)
        self.assertEqual(result["status_code"], expected_status)
        payload = _graph_first_payload(result)
        self.assertIn("error", payload)
        self.assertEqual(self._simulated_wrapper_status(result), expected_status)


class EdgeGuardHealthMetricsTests(unittest.TestCase):
  """EG-013 P4: truthful process-lifetime request metrics."""

  def _metrics(self, plugin):
    with patch.object(plugin, "_explanation_url", return_value=(None, "off")):
      with patch.object(plugin, "_worker_readiness", return_value={}):
        with patch.object(plugin, "_explanation_worker_ready", return_value=False):
          return plugin.health()["metrics"]

  def test_success_increments_total_only(self):
    plugin = _make_api()
    plugin.models()
    metrics = self._metrics(plugin)
    self.assertEqual(metrics["total_requests"], 1)
    self.assertEqual(metrics["failed_requests"], 0)
    self.assertEqual(metrics["last_request_time"], 1000)

  def test_guard_rejection_counts_as_failed_exactly_once(self):
    plugin = _make_api()
    result = plugin.check_cypher(cypher="MATCH (i:Indicator) RETURN i.value AS value")
    self.assertEqual(result["status"], "rejected")
    metrics = self._metrics(plugin)
    self.assertEqual(metrics["total_requests"], 1)
    self.assertEqual(metrics["failed_requests"], 1)

  def test_raised_exception_counts_as_failed_and_reraises(self):
    from extensions.business.cybersec.edgeguard.edgeguard_api import _tracked_endpoint

    plugin = _make_api()

    @_tracked_endpoint
    def exploding(self):
      raise RuntimeError("boom")

    with self.assertRaises(RuntimeError):
      exploding(plugin)
    metrics = self._metrics(plugin)
    self.assertEqual(metrics["total_requests"], 1)
    self.assertEqual(metrics["failed_requests"], 1)

  def test_health_is_excluded_from_tracking(self):
    plugin = _make_api()
    self._metrics(plugin)
    metrics = self._metrics(plugin)
    self.assertEqual(metrics["total_requests"], 0)
    self.assertIsNone(metrics["last_request_time"])

  def test_counters_reset_semantics_are_process_local(self):
    plugin = _make_api()
    plugin.models()
    plugin._metrics_lock = threading.Lock()
    plugin._request_count = 0
    plugin._error_count = 0
    plugin._last_request_time = None
    metrics = self._metrics(plugin)
    self.assertEqual(metrics["total_requests"], 0)

  def test_concurrent_increments_are_exact(self):
    plugin = _make_api()
    workers = 8
    calls_per_worker = 25

    def hammer():
      for _ in range(calls_per_worker):
        plugin.models()

    threads = [threading.Thread(target=hammer) for _ in range(workers)]
    for thread in threads:
      thread.start()
    for thread in threads:
      thread.join()
    metrics = self._metrics(plugin)
    self.assertEqual(metrics["total_requests"], workers * calls_per_worker)
    self.assertEqual(metrics["failed_requests"], 0)


class EdgeGuardModeBudgetThreadingTests(unittest.TestCase):
  def test_explain_graph_threads_thorough_mode_into_insight_brief(self):
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    fake_driver, _fake_session = _driver_with_results(_Result([_graph_path_record()], keys=["p"]))
    stub_result = {
      "case_explanation": {"schema_version": "edgeguard.case_explanation.v2"},
      "explanation_trace": {"outcome": {"status": "supported"}},
    }

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        with patch(
          "extensions.business.cybersec.edgeguard.edgeguard_api.egx2.run_insight_brief",
          return_value=stub_result,
        ) as run_brief:
          plugin.explain_graph(
            uri="example.com:7687",
            scheme="bolt+s",
            username="neo4j",
            password="secret",
            request="Explain thoroughly.",
            cypher="MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10",
            explanation_mode="thorough",
          )

    self.assertEqual(run_brief.call_args.kwargs["mode"], "thorough")


def _literal_class_vectors():
  path = Path(__file__).parent / "fixtures" / "literal_class_vectors.json"
  with open(path, "r", encoding="utf-8") as handle:
    return json.load(handle)


class LiteralGroundingGuardTests(unittest.TestCase):
  """Contract §3: `_apply_literal_grounding_guard` accepts closed-vocabulary
  filters implied by request wording (not just a request substring) and
  rejects a free literal absent from the request, naming it."""

  def _accepted_validation(self, cypher):
    return {"accepted": True, "accepted_cypher": cypher, "candidate": cypher}

  def test_ip_synonym_filter_is_accepted_on_the_first_attempt(self):
    plugin = _make_api()
    cypher = "MATCH (i:Indicator) WHERE i.indicator_type = 'ipv4' RETURN i.value AS value LIMIT 10"

    result = plugin._apply_literal_grounding_guard(
      self._accepted_validation(cypher), cypher, "Which IP addresses are indicators of compromise?",
    )

    self.assertTrue(result["accepted"])
    self.assertEqual(result["accepted_cypher"], cypher)

  def test_free_literal_absent_from_request_is_rejected_with_the_literal_named(self):
    plugin = _make_api()
    cypher = "MATCH (c:CVE) WHERE c.cisa_vulnerability_name = 'CISA Vuls' RETURN c LIMIT 5"

    result = plugin._apply_literal_grounding_guard(
      self._accepted_validation(cypher), cypher, "Show me CVE details for this vulnerability.",
    )

    self.assertFalse(result["accepted"])
    self.assertIsNone(result["accepted_cypher"])
    self.assertEqual(
      result["validation_feedback"],
      "Literal 'CISA Vuls' (free) is not in the request.\n"
      "Remove the WHERE condition or property filter using each literal named above and "
      "return the requested pattern without it.",
    )

  def test_v0_11_profile_names_the_literal_and_gives_an_actionable_instruction(self):
    # Fix round 3, L1: naming the literal alone is not actionable enough —
    # the v0.11 profile gets a concise instruction appended after the named
    # literal(s), same default as the call above with `use_v0_11` explicit.
    plugin = _make_api()
    cypher = "MATCH (c:CVE) WHERE c.cisa_vulnerability_name = 'CISA Vuls' RETURN c LIMIT 5"

    result = plugin._apply_literal_grounding_guard(
      self._accepted_validation(cypher), cypher, "Show me CVE details for this vulnerability.",
      use_v0_11=True,
    )

    self.assertFalse(result["accepted"])
    self.assertIn("Literal 'CISA Vuls' (free) is not in the request.", result["validation_feedback"])
    self.assertIn("Remove the WHERE condition or property filter", result["validation_feedback"])

  def test_v0_10_profile_keeps_the_pre_v0_11_instruction_sentence_verbatim(self):
    # Fix round 3, L1 (2 of 20 questions regressed live on edg3): the v0.10
    # fine-tuned model was trained on this exact sentence; the bare
    # `Literal 'X' (class) is not in the request.` left it without an
    # instruction it recognised and it repeated the same rejected Cypher on
    # every retry attempt. `use_v0_11=False` restores the sentence verbatim,
    # followed by the named literal(s).
    plugin = _make_api()
    cypher = "MATCH (c:CVE) WHERE c.cisa_vulnerability_name = 'CISA Vuls' RETURN c LIMIT 5"

    result = plugin._apply_literal_grounding_guard(
      self._accepted_validation(cypher), cypher, "Show me CVE details for this vulnerability.",
      use_v0_11=False,
    )

    self.assertFalse(result["accepted"])
    self.assertEqual(
      result["validation_feedback"],
      "The query introduced a literal value or filter that was not present in the user "
      "request. Remove unrequested WHERE filters and return the requested unfiltered "
      "graph pattern.\n"
      "Literal 'CISA Vuls' (free) is not in the request.",
    )

  def test_v0_10_profile_names_every_literal_after_the_verbatim_sentence(self):
    plugin = _make_api()
    cypher = (
      "MATCH (i:Indicator) WHERE i.value = '203.0.113.5' AND i.source = 'CISA Vuls' "
      "RETURN i LIMIT 5"
    )

    result = plugin._apply_literal_grounding_guard(
      self._accepted_validation(cypher), cypher, "Show me indicators.",
      use_v0_11=False,
    )

    self.assertFalse(result["accepted"])
    lines = result["validation_feedback"].splitlines()
    self.assertEqual(
      lines[0],
      "The query introduced a literal value or filter that was not present in the user "
      "request. Remove unrequested WHERE filters and return the requested unfiltered "
      "graph pattern.",
    )
    self.assertIn("Literal '203.0.113.5' (free) is not in the request.", lines[1:])
    self.assertIn("Literal 'CISA Vuls' (free) is not in the request.", lines[1:])

  def test_shared_vector_file_accept_and_reject_cases(self):
    plugin = _make_api()
    vectors = _literal_class_vectors()
    self.assertGreaterEqual(len(vectors["accept"]), 20)
    self.assertGreaterEqual(len(vectors["reject"]), 20)

    for vector in vectors["accept"]:
      with self.subTest(literal=vector["literal"], request=vector["request"]):
        cypher = f"MATCH (i:Indicator) WHERE i.value = '{vector['literal']}' RETURN i.value AS value LIMIT 5"
        result = plugin._apply_literal_grounding_guard(
          self._accepted_validation(cypher), cypher, vector["request"],
        )
        self.assertTrue(result["accepted"], f"{vector}: {result.get('validation_feedback')}")

    for vector in vectors["reject"]:
      with self.subTest(literal=vector["literal"], request=vector["request"]):
        cypher = f"MATCH (i:Indicator) WHERE i.value = '{vector['literal']}' RETURN i.value AS value LIMIT 5"
        result = plugin._apply_literal_grounding_guard(
          self._accepted_validation(cypher), cypher, vector["request"],
        )
        self.assertFalse(result["accepted"], vector)
        self.assertIn(vector["literal"], result["validation_feedback"])
        self.assertIn(vector["class"], result["validation_feedback"])

  def test_accepted_attempt_reports_its_grounded_closed_vocabulary_literals(self):
    plugin = _make_api()
    cypher = "MATCH (i:Indicator) WHERE i.indicator_type = 'ipv4' RETURN i.value AS value LIMIT 10"

    result = plugin._apply_literal_grounding_guard(
      self._accepted_validation(cypher), cypher, "Which IP addresses are indicators of compromise?",
    )

    self.assertTrue(result["accepted"])
    self.assertEqual(result["grounded_closed_vocabulary_literals"], ["ipv4"])

  def test_retained_closed_vocabulary_literal_missing_from_a_later_attempt_is_rejected(self):
    # Contract §3.2: a correction attempt may not remove a closed-vocabulary
    # literal that was accepted (grounded) on an earlier attempt, even if
    # that earlier attempt was rejected overall for an unrelated reason.
    plugin = _make_api()
    first_cypher = (
      "MATCH (c:CVE) WHERE c.indicator_type = 'ipv4' AND c.cisa_vulnerability_name = 'CISA Vuls' "
      "RETURN c LIMIT 5"
    )
    first = plugin._apply_literal_grounding_guard(
      self._accepted_validation(first_cypher), first_cypher,
      "Which IP addresses relate to this CVE?",
    )
    self.assertFalse(first["accepted"])
    self.assertIn("CISA Vuls", first["validation_feedback"])
    retained = set(first["grounded_closed_vocabulary_literals"])
    self.assertEqual(retained, {"ipv4"})

    corrected_cypher = "MATCH (c:CVE) RETURN c LIMIT 5"
    second = plugin._apply_literal_grounding_guard(
      self._accepted_validation(corrected_cypher), corrected_cypher,
      "Which IP addresses relate to this CVE?",
      frozenset(retained),
    )

    self.assertFalse(second["accepted"])
    self.assertIn("ipv4", second["validation_feedback"])
    self.assertIn("must not be removed", second["validation_feedback"])

  def test_retained_closed_vocabulary_literal_kept_is_accepted(self):
    plugin = _make_api()
    retained = frozenset({"ipv4"})
    corrected_cypher = "MATCH (c:CVE) WHERE c.indicator_type = 'ipv4' RETURN c LIMIT 5"

    result = plugin._apply_literal_grounding_guard(
      self._accepted_validation(corrected_cypher), corrected_cypher,
      "Which IP addresses relate to this CVE?",
      retained,
    )

    self.assertTrue(result["accepted"])

  def test_generate_retry_loop_rejects_a_correction_that_drops_the_grounded_literal(self):
    # End-to-end through `generate()`'s retry loop (not just the guard
    # method directly): attempt 1 is rejected for the free literal, attempt
    # 2 drops the grounded closed-vocabulary filter too and is rejected
    # again (naming the dropped filter), attempt 3 restores it and accepts.
    plugin = _make_api(worker_semaphore_env={
      PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"},
    })

    def _response(cypher):
      return _Response(payload={
        "result": {
          "TEXT_RESPONSE": cypher,
          "FULL_OUTPUT": {
            "choices": [{"message": {"content": cypher}, "finish_reason": "stop"}],
            "usage": {"completion_tokens": 12},
          },
        },
      })

    attempt_1 = (
      "MATCH (i:Indicator) WHERE i.indicator_type = 'ipv4' AND i.source = 'CISA Vuls' "
      "RETURN i.value AS value LIMIT 10"
    )
    attempt_2 = "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10"
    attempt_3 = "MATCH (i:Indicator) WHERE i.indicator_type = 'ipv4' RETURN i.value AS value LIMIT 10"
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.side_effect = [_response(attempt_1), _response(attempt_2), _response(attempt_3)]

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(
        request="Which IP addresses are indicators of compromise?", model_key=PRIVATE_MODEL_KEY,
      )

    self.assertTrue(result["accepted"])
    self.assertEqual(len(result["attempts"]), 3)
    self.assertFalse(result["attempts"][0]["accepted"])
    self.assertIn("CISA Vuls", result["attempts"][0]["validation_feedback"])
    self.assertFalse(result["attempts"][1]["accepted"])
    self.assertIn("ipv4", result["attempts"][1]["validation_feedback"])
    self.assertIn("must not be removed", result["attempts"][1]["validation_feedback"])
    self.assertTrue(result["attempts"][2]["accepted"])

  def test_generate_rejection_feedback_keeps_the_pre_v0_11_sentence_on_the_v0_10_profile(self):
    # Fix round 3, L1: through `generate()`'s retry loop, not just the guard
    # method directly, the v0.10 (`direct_cypher`) profile's rejection
    # feedback must include the verbatim pre-v0.11 instruction sentence the
    # fine-tuned model was trained on, not just the bare literal name.
    plugin = _make_api(worker_semaphore_env={
      PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53001"},
    })

    def _response(cypher):
      return _Response(payload={
        "result": {
          "TEXT_RESPONSE": cypher,
          "FULL_OUTPUT": {
            "choices": [{"message": {"content": cypher}, "finish_reason": "stop"}],
            "usage": {"completion_tokens": 12},
          },
        },
      })

    rejected_cypher = (
      "MATCH (i:Indicator) WHERE i.value = '203.0.113.5' AND m.name = 'Fixture Malware' "
      "RETURN i.value AS value LIMIT 10"
    )
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.side_effect = [_response(rejected_cypher)] * 4

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(
        request="Show me indicators.", model_key=PRIVATE_MODEL_KEY,
      )

    self.assertFalse(result["accepted"])
    feedback = result["attempts"][0]["validation_feedback"]
    self.assertIn(
      "The query introduced a literal value or filter that was not present in the user "
      "request. Remove unrequested WHERE filters and return the requested unfiltered "
      "graph pattern.",
      feedback,
    )
    self.assertIn("Literal '203.0.113.5' (free) is not in the request.", feedback)
    self.assertIn("Literal 'Fixture Malware' (free) is not in the request.", feedback)


class V0_11GenerateRuntimeTests(unittest.TestCase):
  """Review findings 1, 5, 7: `generate()` on the v0.11 profile validates
  against the v0.11 flat sets, allows a `graph`-shape candidate to omit
  `LIMIT`, rejects an `other`-shape candidate with feedback, and reports
  v0.11 `schema_version`/`cypher_schema_version`/`schema_surface`."""

  def _make_v0_11_api(self):
    return _make_api(
      edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11,
      worker_semaphore_env={V0_11_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53002"}},
    )

  def _response(self, cypher):
    return _Response(payload={
      "result": {
        "TEXT_RESPONSE": cypher,
        "FULL_OUTPUT": {
          "choices": [{"message": {"content": cypher}, "finish_reason": "stop"}],
          "usage": {"completion_tokens": 12},
        },
      },
    })

  def test_graph_shape_without_limit_is_accepted_against_the_v0_11_flat_sets(self):
    plugin = self._make_v0_11_api()
    # `Mission` is a topology-only label the v0.10 schema does not know, and
    # there is no `LIMIT` (contract §4.1, optional for `graph` on this
    # profile).
    cypher = "MATCH p=(c:CVE)-[:AFFECTS]->(m:Mission) RETURN p"
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.return_value = self._response(cypher)

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(request="Show CVEs affecting missions.", model_key=V0_11_MODEL_KEY)

    self.assertTrue(result["accepted"], result)
    self.assertEqual(result["accepted_cypher"], cypher)
    self.assertEqual(result["validation"]["result_shape"], "graph")
    self.assertEqual(result["schema_version"], "edgeguard-cypher-schema-v0.11")
    self.assertEqual(result["cypher_schema_version"], "edgeguard-cypher-schema-v0.11")
    self.assertIn("Mission", result["schema_surface"]["labels"])

  def test_other_shape_is_rejected_with_feedback_naming_the_two_accepted_shapes(self):
    plugin = self._make_v0_11_api()
    # Schema-compatible, has `LIMIT`, read-only — the guard would accept it —
    # but it mixes a pattern-variable and a scalar projection: `other`
    # (contract §4.3), rejected for model output on this profile.
    cypher = "MATCH (i:Indicator) RETURN i, i.value AS value LIMIT 10"
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.side_effect = [self._response(cypher)] * 3

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(request="Show indicators.", model_key=V0_11_MODEL_KEY)

    self.assertFalse(result["accepted"])
    self.assertIsNone(result["accepted_cypher"])
    self.assertEqual(result["validation"]["result_shape"], "other")
    for attempt in result["attempts"]:
      self.assertFalse(attempt["accepted"])
      self.assertEqual(attempt["result_shape"], "other")
    self.assertIn("graph", result["validation_feedback"])
    self.assertIn("ranked_projection", result["validation_feedback"])

  def _generate_v0_11(self, outputs, **overrides):
    plugin = _make_api(
      edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11,
      worker_semaphore_env={V0_11_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53002"}},
      **overrides,
    )
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.side_effect = [self._response(cypher) for cypher in outputs]
    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(request="Which tactics do techniques belong to?", model_key=V0_11_MODEL_KEY)
    return result, session

  def test_reversed_arrow_is_corrected_in_place_without_a_correction_turn(self):
    reversed_cypher = "MATCH p=(ta:Tactic)-[:IN_TACTIC]->(t:Technique) RETURN p LIMIT 5"
    result, session = self._generate_v0_11([reversed_cypher])

    self.assertTrue(result["accepted"], result)
    self.assertEqual(result["accepted_cypher"], "MATCH p=(ta:Tactic)<-[:IN_TACTIC]-(t:Technique) RETURN p LIMIT 5")
    self.assertEqual(len(result["attempts"]), 1)
    self.assertEqual(session.post.call_count, 1)
    attempt = result["attempts"][0]
    self.assertEqual(attempt["raw_output"], reversed_cypher)
    self.assertEqual(attempt["auto_corrected"], {
      "kind": "relationship_direction", "flips": 1, "uncorrected_cypher": reversed_cypher,
    })

  def test_direction_corrector_off_keeps_reject_and_retry(self):
    reversed_cypher = "MATCH p=(ta:Tactic)-[:IN_TACTIC]->(t:Technique) RETURN p LIMIT 5"
    fixed = "MATCH p=(ta:Tactic)<-[:IN_TACTIC]-(t:Technique) RETURN p LIMIT 5"
    result, _ = self._generate_v0_11([reversed_cypher, fixed], edgeguard_direction_corrector=False)

    self.assertTrue(result["accepted"])
    self.assertEqual(len(result["attempts"]), 2)
    self.assertIn("reverse the arrow", result["attempts"][0]["validation_feedback"])
    self.assertIsNone(result["attempts"][0]["auto_corrected"])

  def test_corrected_query_still_goes_through_literal_grounding(self):
    # The flip fixes the arrow, but the literal is not in the request, so the
    # attempt stays rejected and the corrected text is what the retry sees.
    reversed_cypher = (
      "MATCH p=(ta:Tactic {name: 'Nowhere Tactic'})-[:IN_TACTIC]->(t:Technique) RETURN p LIMIT 5"
    )
    good = "MATCH p=(ta:Tactic)<-[:IN_TACTIC]-(t:Technique) RETURN p LIMIT 5"
    result, _ = self._generate_v0_11([reversed_cypher, good])

    first = result["attempts"][0]
    self.assertFalse(first["accepted"])
    self.assertIn("Nowhere Tactic", first["validation_feedback"])
    self.assertNotIn("reverse the arrow", first["validation_feedback"])
    self.assertIn("<-[:IN_TACTIC]-", first["candidate_cypher"])
    self.assertTrue(result["accepted"])

  def test_corrector_failure_keeps_the_plain_rejection(self):
    reversed_cypher = "MATCH p=(ta:Tactic)-[:IN_TACTIC]->(t:Technique) RETURN p LIMIT 5"
    fixed = "MATCH p=(ta:Tactic)<-[:IN_TACTIC]-(t:Technique) RETURN p LIMIT 5"
    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.correct_reversed_relationship_arrows",
      side_effect=RuntimeError("boom"),
    ):
      result, _ = self._generate_v0_11([reversed_cypher, fixed])
    self.assertTrue(result["accepted"])
    self.assertEqual(len(result["attempts"]), 2)
    self.assertIn("reverse the arrow", result["attempts"][0]["validation_feedback"])

  def test_wrong_relationship_type_is_not_corrected(self):
    # `EMPLOYS_TECHNIQUE` from an Indicator is a wrong type, not a reversed
    # arrow: no flip makes it valid, so the guard's feedback stands.
    wrong = "MATCH p=(i:Indicator)-[:EMPLOYS_TECHNIQUE]->(t:Technique) RETURN p LIMIT 5"
    result, _ = self._generate_v0_11([wrong] * 3)

    self.assertFalse(result["accepted"])
    for attempt in result["attempts"]:
      self.assertIsNone(attempt["auto_corrected"])

  def test_v0_10_profile_generate_response_is_unaffected(self):
    plugin = _make_api(worker_semaphore_env={
      PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53003"},
    })
    cypher = "MATCH (i:Indicator) RETURN i.value AS value LIMIT 10"
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.return_value = self._response(cypher)

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(request="Show indicators.", model_key=PRIVATE_MODEL_KEY)

    self.assertTrue(result["accepted"])
    self.assertEqual(result["schema_version"], "edgeguard-cypher-schema-v0.10")
    self.assertEqual(result["cypher_schema_version"], "edgeguard-cypher-schema-v0.10")
    self.assertEqual(result["schema_surface"], canonical_schema_surface())


class PatternEndpointFixRound1ApiTests(unittest.TestCase):
  """EGM-059 phase 4 slice 4b, fix round 1 (findings-4b-1.md items 2, 10,
  11): `execution_safety_error`/`execution_safety_error_code` on `/generate`
  attempts, the `enforce_pattern_endpoints` flag actually wired at the
  `/generate` and `/neo4j_query` call sites, and the Cypher length cap at
  `/check_cypher`, `/neo4j_query`, `/explain_graph`."""

  SEEDED_CYPHER = "MATCH (i:Indicator)-[:EMPLOYS_TECHNIQUE]->(t:Technique) RETURN i, t LIMIT 5"

  def _make_v0_11_api(self):
    return _make_api(
      edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11,
      worker_semaphore_env={V0_11_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53002"}},
    )

  def _response(self, cypher):
    return _Response(payload={
      "result": {
        "TEXT_RESPONSE": cypher,
        "FULL_OUTPUT": {
          "choices": [{"message": {"content": cypher}, "finish_reason": "stop"}],
          "usage": {"completion_tokens": 12},
        },
      },
    })

  def test_generate_v0_11_rejects_the_seeded_case_with_the_code_on_every_attempt(self):
    plugin = self._make_v0_11_api()
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.side_effect = [self._response(self.SEEDED_CYPHER)] * 3

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(request="Which techniques does this indicator use?", model_key=V0_11_MODEL_KEY)

    self.assertFalse(result["accepted"])
    self.assertEqual(len(result["attempts"]), 3)
    for attempt in result["attempts"]:
      self.assertFalse(attempt["accepted"])
      self.assertEqual(attempt["execution_safety_error_code"], "pattern_endpoint_mismatch")
      self.assertIn("USES_TECHNIQUE", attempt["execution_safety_error"])

  def test_generate_v0_10_accepts_the_same_candidate(self):
    plugin = _make_api(worker_semaphore_env={
      PRIVATE_WORKER_SEMAPHORE: {"API_HOST": "127.0.0.1", "API_PORT": "53004"},
    })
    session = MagicMock()
    session.get.return_value = _Response(payload={"result": {"serving_ready": True}})
    session.post.return_value = self._response(self.SEEDED_CYPHER)

    with patch(
      "extensions.business.cybersec.edgeguard.edgeguard_api.requests.Session",
      return_value=session,
    ):
      result = plugin.generate(request="Which techniques does this indicator use?", model_key=PRIVATE_MODEL_KEY)

    self.assertTrue(result["accepted"], result)
    self.assertEqual(result["accepted_cypher"], self.SEEDED_CYPHER)

  def test_neo4j_query_v0_11_rejects_the_seeded_case(self):
    plugin = self._make_v0_11_api()

    result = plugin.neo4j_query(
      uri="example.com:7687", scheme="bolt+s", username="neo4j", password="secret",
      cypher=self.SEEDED_CYPHER, model_key=V0_11_MODEL_KEY,
    )

    payload = _graph_first_payload(result)
    self.assertEqual(payload["status"], "rejected")
    self.assertFalse(payload["executed"])
    self.assertEqual(
      payload["validation"]["execution_safety_error_code"], "pattern_endpoint_mismatch",
    )

  def test_neo4j_query_v0_10_accepts_the_same_candidate(self):
    plugin = _make_api()
    empty_result = _Result([], keys=["i", "t"])
    fake_session = MagicMock()
    fake_session.__enter__.return_value = fake_session
    fake_session.run.return_value = empty_result
    fake_driver = MagicMock()
    fake_driver.session.return_value = fake_session

    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin.neo4j_query(
          uri="example.com:7687", scheme="bolt+s", username="neo4j", password="secret",
          cypher=self.SEEDED_CYPHER,
        )

    self.assertEqual(result["status"], "ok")
    self.assertTrue(result["executed"])

  def test_check_cypher_rejects_a_cypher_string_over_the_length_cap(self):
    plugin = _make_api()
    oversized = "MATCH (i:Indicator) RETURN i LIMIT 5" + " " * CYPHER_MAX_CHARS

    result = plugin.check_cypher(cypher=oversized)

    self.assertEqual(result["status_code"], 413)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["diagnostics"]["code"], "cypher_too_large")

  def test_neo4j_query_rejects_a_cypher_string_over_the_length_cap(self):
    plugin = _make_api()
    oversized = "MATCH (i:Indicator) RETURN i LIMIT 5" + " " * CYPHER_MAX_CHARS

    result = plugin.neo4j_query(
      uri="example.com:7687", scheme="bolt+s", username="neo4j", password="secret",
      cypher=oversized,
    )

    self.assertEqual(result["status_code"], 413)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["diagnostics"]["code"], "cypher_too_large")

  def test_explain_graph_rejects_a_cypher_string_over_the_length_cap(self):
    plugin = _make_api()
    oversized = "MATCH (i:Indicator) RETURN i LIMIT 5" + " " * CYPHER_MAX_CHARS

    result = plugin.explain_graph(cypher=oversized, request="Explain this.")

    self.assertEqual(result["status_code"], 413)
    payload = _graph_first_payload(result)
    self.assertEqual(
      {item["code"] for item in payload["validation_errors"]}, {"cypher_too_large"},
    )


class PatternEndpointFixRound2ApiTests(unittest.TestCase):
  """EGM-059 phase 4 slice 4b, fix round 2 (findings-4b-2.md items 2, 3)."""

  def test_prepare_graph_explanation_rejects_a_cypher_string_over_the_length_cap(self):
    plugin = _make_api()
    oversized = "MATCH (i:Indicator) RETURN i LIMIT 5" + " " * CYPHER_MAX_CHARS

    result = plugin.prepare_graph_explanation(cypher=oversized)

    self.assertEqual(result["status_code"], 413)
    payload = _graph_first_payload(result)
    self.assertEqual(
      {item["code"] for item in payload["validation_errors"]}, {"cypher_too_large"},
    )

  def test_check_cypher_rejects_a_non_string_cypher_with_400(self):
    plugin = _make_api()

    result = plugin.check_cypher(cypher=["not", "a", "string"])

    self.assertEqual(result["status_code"], 400)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["diagnostics"]["code"], "invalid_cypher")

  def test_neo4j_query_rejects_a_non_string_cypher_with_400(self):
    plugin = _make_api()

    result = plugin.neo4j_query(
      uri="example.com:7687", scheme="bolt+s", username="neo4j", password="secret",
      cypher={"not": "a string"},
    )

    self.assertEqual(result["status_code"], 400)
    payload = _graph_first_payload(result)
    self.assertEqual(payload["diagnostics"]["code"], "invalid_cypher")


class PromptProfileDispatchTests(unittest.TestCase):
  """Contract §5.1/§5.2: `_generation_messages` dispatches the system prompt
  and the correction turn per profile."""

  def test_v0_10_profile_served_system_prompt_is_unchanged(self):
    plugin = _make_api()

    messages = plugin._generation_messages(PRIVATE_MODEL_KEY, "Show indicators")

    self.assertEqual(messages[0]["role"], "system")
    self.assertEqual(messages[0]["content"], build_direct_cypher_system_prompt())

  def test_v0_10_profile_correction_turn_still_re_embeds_the_schema(self):
    plugin = _make_api()

    messages = plugin._generation_messages(
      PRIVATE_MODEL_KEY, "Show indicators",
      rejected_cypher="MATCH (i:Indicator) RETURN i.bogus",
      validation_feedback="unknown property 'bogus'",
      retry_index=1,
      retry_limit=2,
    )

    self.assertEqual(
      messages[1]["content"],
      build_schema_correction_prompt(
        original_user_prompt="Show indicators",
        rejected_cypher="MATCH (i:Indicator) RETURN i.bogus",
        validation_feedback="unknown property 'bogus'",
        retry_index=1,
        retry_limit=2,
      ),
    )
    self.assertIn("Allowed EdgeGuard Cypher schema:", messages[1]["content"])

  def test_v0_11_profile_served_system_prompt_is_the_pattern_schema_builder(self):
    plugin = _make_api(edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11)

    messages = plugin._generation_messages(V0_11_MODEL_KEY, "Show indicators")

    self.assertEqual(messages[0]["content"], build_v0_11_pattern_schema_system_prompt())

  def test_v0_11_profile_correction_turn_preserves_the_original_request_and_rejected_attempt(self):
    """Contract §5.2 (review finding 2, S3=Q1): the v0.11 retry conversation
    is [system, user:request, assistant:rejected, user:correction] — the
    correction *turn itself* still carries no schema and no re-embedded
    request (both are already earlier turns in the same conversation)."""
    plugin = _make_api(edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11)

    messages = plugin._generation_messages(
      V0_11_MODEL_KEY, "Show indicators",
      rejected_cypher="MATCH (i:Indicator) RETURN i.bogus",
      validation_feedback="unknown property 'bogus'",
      retry_index=1,
      retry_limit=2,
    )

    self.assertEqual(
      [message["role"] for message in messages],
      ["system", "user", "assistant", "user"],
    )
    self.assertEqual(messages[1]["content"], "Show indicators")
    self.assertEqual(messages[2]["content"], "MATCH (i:Indicator) RETURN i.bogus")
    self.assertEqual(
      messages[3]["content"],
      build_v0_11_correction_prompt(
        rejected_cypher="MATCH (i:Indicator) RETURN i.bogus",
        validation_feedback="unknown property 'bogus'",
        retry_index=1,
        retry_limit=2,
      ),
    )
    self.assertNotIn("Allowed EdgeGuard Cypher schema:", messages[3]["content"])
    self.assertNotIn("Populated graph patterns:", messages[3]["content"])
    self.assertNotIn("Original user request:", messages[3]["content"])


class PromptContractProfileShaTests(unittest.TestCase):
  """Contract §5.4: `/prompt_contract` exposes `system_prompt_sha256` per
  profile, including profiles that append a suffix (previously `None`)."""

  def test_every_profile_gets_a_real_system_prompt_sha256(self):
    plugin = _make_api(edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11)

    contract = plugin.prompt_contract()

    profiles = {item["model_key"]: item for item in contract["profiles"]}
    for model_key in (V0_11_MODEL_KEY, PRIVATE_MODEL_KEY, "base_qwen3_4b", "cybersec_qwen_4b"):
      self.assertRegex(
        profiles[model_key]["system_prompt_sha256"], r"^[0-9a-f]{64}$", model_key,
      )

  def test_v0_10_profile_sha_matches_the_pinned_builder_output(self):
    plugin = _make_api()

    contract = plugin.prompt_contract()

    profiles = {item["model_key"]: item for item in contract["profiles"]}
    self.assertEqual(
      profiles[PRIVATE_MODEL_KEY]["system_prompt_sha256"],
      _sha256_text(build_direct_cypher_system_prompt()),
    )

  def test_v0_11_profile_sha_matches_the_pattern_schema_builder_output(self):
    plugin = _make_api(edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11)

    contract = plugin.prompt_contract()

    profiles = {item["model_key"]: item for item in contract["profiles"]}
    self.assertEqual(
      profiles[V0_11_MODEL_KEY]["system_prompt_sha256"],
      _sha256_text(build_v0_11_pattern_schema_system_prompt()),
    )

  def test_v0_11_profile_correction_sha_does_not_match_the_v0_10_correction_sha(self):
    plugin = _make_api(edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11)

    contract = plugin.prompt_contract()

    profiles = {item["model_key"]: item for item in contract["profiles"]}
    self.assertNotEqual(
      profiles[V0_11_MODEL_KEY]["correction_prompt_sha256"],
      profiles[PRIVATE_MODEL_KEY]["correction_prompt_sha256"],
    )

  def test_v0_11_profile_reports_v0_11_schema_version_and_surface(self):
    """Review finding 7 (S8): the v0.11 profile's `/prompt_contract` entry
    names the v0.11 artifact's schema_version and schema_surface, not the
    v0.10 defaults every other profile still reports."""
    plugin = _make_api(edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11)

    contract = plugin.prompt_contract()

    profiles = {item["model_key"]: item for item in contract["profiles"]}
    self.assertEqual(
      profiles[V0_11_MODEL_KEY]["cypher_schema_version"], "edgeguard-cypher-schema-v0.11",
    )
    self.assertIn("Mission", profiles[V0_11_MODEL_KEY]["schema_surface"]["labels"])
    self.assertEqual(
      profiles[PRIVATE_MODEL_KEY]["cypher_schema_version"], "edgeguard-cypher-schema-v0.10",
    )
    self.assertEqual(
      profiles[PRIVATE_MODEL_KEY]["schema_surface"], canonical_schema_surface(),
    )

  def test_every_profile_pins_the_literal_classes_module_sha(self):
    """Contract §3.2 (review finding 7, S8): "both [the guard and the
    validator] pin its sha in their reports" — every profile reports the
    same, freshly-recomputed `literal_classes.py` sha (the guard applies
    the literal-grounding fix regardless of profile)."""
    plugin = _make_api(edgeguard_generation_workers=TEST_GENERATION_WORKERS_WITH_V0_11)

    contract = plugin.prompt_contract()

    with open(literal_classes.__file__, "rb") as handle:
      expected = hashlib.sha256(handle.read()).hexdigest()
    for profile in contract["profiles"]:
      self.assertEqual(profile["literal_classes_sha256"], expected, profile["model_key"])
    self.assertRegex(expected, r"^[0-9a-f]{64}$")


class GenerationMaxTokensPinTests(unittest.TestCase):
  """Contract §5.4/§6 (code half): `GENERATION_MAX_TOKENS = 384`."""

  def test_generation_max_tokens_is_384(self):
    self.assertEqual(GENERATION_MAX_TOKENS, 384)


class EdgeGuardExplainJobTests(unittest.TestCase):
  """EG-028: `/explain_graph_start` + `/explain_graph_status`."""

  PATH_CYPHER = "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) RETURN p LIMIT 10"

  def _body(self, **overrides):
    body = {
      "uri": "example.com:7687",
      "scheme": "bolt+s",
      "username": "neo4j",
      "password": "secret",
      "request": "Explain the returned graph.",
      "cypher": self.PATH_CYPHER,
    }
    body.update(overrides)
    return body

  @staticmethod
  def _without_timings(value):
    return {key: item for key, item in value.items() if key != "metrics"}

  @staticmethod
  def _wait_done(plugin, job_id, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
      status = plugin.explain_graph_status(job_id=job_id)
      if status.get("done"):
        return status
      time.sleep(0.01)
    raise AssertionError("explain job did not finish")

  @staticmethod
  def _gated_impl(gate, phases=()):
    """A stand-in for `_explain_graph_impl` that reports `phases`, then waits."""
    def impl(progress=None, **_body):
      for phase, detail in phases:
        progress(phase, detail)
      assert gate.wait(10)
      return {"status": "ok", "ok": True, "executed": True, "explained": True}
    return impl

  def test_start_returns_a_url_safe_job_id_at_once(self):
    plugin = _make_api()
    gate = threading.Event()
    impl = self._gated_impl(gate, [("neo4j", None)])
    with patch.object(plugin, "_explain_graph_impl", side_effect=impl):
      started = plugin.explain_graph_start(**self._body())
      self.assertEqual(set(started), {"job_id"})
      self.assertRegex(started["job_id"], r"^[A-Za-z0-9_-]{32}$")
      status = plugin.explain_graph_status(job_id=started["job_id"])
      self.assertEqual(status, {"phase": "neo4j", "detail": None, "done": False})
      gate.set()
      self._wait_done(plugin, started["job_id"])

  def test_status_walks_the_phases_and_ends_with_the_result(self):
    plugin = _make_api()
    advance = threading.Event()
    steps = []

    def impl(progress=None, **_body):
      progress("neo4j", None)
      progress("neo4j", {"row_count": 7})
      assert advance.wait(10)
      progress("brief", {"attempt": 2})
      return {"status": "ok", "ok": True, "executed": True, "explained": True}

    with patch.object(plugin, "_explain_graph_impl", side_effect=impl):
      job_id = plugin.explain_graph_start(**self._body())["job_id"]
      deadline = time.monotonic() + 5
      while plugin.explain_graph_status(job_id=job_id)["detail"] != {"row_count": 7}:
        self.assertLess(time.monotonic(), deadline)
        time.sleep(0.01)
      steps.append(plugin.explain_graph_status(job_id=job_id))
      advance.set()
      final = self._wait_done(plugin, job_id)
    self.assertEqual(steps[0], {"phase": "neo4j", "detail": {"row_count": 7}, "done": False})
    self.assertNotIn("result", steps[0])
    self.assertEqual(final["phase"], "done")
    self.assertTrue(final["done"])
    self.assertEqual(final["result_status_code"], 200)
    self.assertEqual(final["result"]["status"], "ok")

  def test_real_explain_phases_and_result_match_explain_graph(self):
    calls = []

    def provider(payload):
      calls.append(payload)
      return {"content": "not json", "finish_reason": "stop", "completion_tokens": 3}

    def two_failed_attempts(*, provider_call, **_kwargs):
      # Stands in for `egx2.run_insight_brief`: two model calls whose output
      # fails the gates, then the deterministic fallback.
      provider_call({"messages": []})
      provider_call({"messages": []})
      return {
        "case_explanation": {"provenance": {"mode": "deterministic_fallback"}},
        "explanation_trace": {"outcome": {"status": "fallback", "safe_code": "deterministic_validation_failed"}},
      }

    plugin = _make_api(edgeguard_explanation_strategy="insight_brief", graph_first_provider=provider)
    plugin._explanation_url = lambda path=None: ("http://127.0.0.1:1/chat", None)
    plugin._explanation_worker_ready = lambda: True
    seen = []
    original = plugin._set_explain_job_phase

    def record(job_id, phase, detail):
      seen.append((phase, detail))
      return original(job_id, phase, detail)

    plugin._set_explain_job_phase = record
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch(
        "extensions.business.cybersec.edgeguard.edgeguard_api.egx2.run_insight_brief",
        side_effect=two_failed_attempts,
      ):
        fake_driver, _ = _driver_with_results(_Result([_graph_path_record()], keys=["p"]))
        with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
          direct = plugin.explain_graph(**self._body())
        fake_driver, _ = _driver_with_results(_Result([_graph_path_record()], keys=["p"]))
        with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
          job_id = plugin.explain_graph_start(**self._body())["job_id"]
          final = self._wait_done(plugin, job_id)

    self.assertEqual(seen, [
      ("guard", None),
      ("neo4j", None),
      ("neo4j", {"row_count": 1}),
      ("evidence", None),
      ("misp", None),
      ("brief", {"attempt": 1}), ("checks", {"attempt": 1}),
      ("brief", {"attempt": 2}), ("checks", {"attempt": 2}),
      ("fallback", {"reason": "deterministic_validation_failed"}),
    ])
    self.assertEqual(len(calls), 4)  # two per run, the direct call included
    self.assertEqual(final["result_status_code"], 200)
    self.assertEqual(self._without_timings(final["result"]), self._without_timings(direct))
    self.assertEqual(final["result"]["case_explanation"]["provenance"]["mode"], "deterministic_fallback")

  def test_error_envelope_status_code_is_split_from_the_result(self):
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    fake_driver, _ = _driver_with_results(Neo4jAuthError("unauthorized"))
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        direct = plugin.explain_graph(**self._body())
        fake_driver, _ = _driver_with_results(Neo4jAuthError("unauthorized"))
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        errors_before = plugin._error_count
        job_id = plugin.explain_graph_start(**self._body())["job_id"]
        final = self._wait_done(plugin, job_id)
    self.assertEqual(direct["status_code"], 503)
    self.assertEqual(final["result_status_code"], 503)
    self.assertEqual(self._without_timings(final["result"]), self._without_timings(direct["result"]))
    self.assertEqual(plugin._error_count, errors_before + 1)  # the failed job is counted once

  def test_synchronous_rejection_is_returned_by_start_without_a_job(self):
    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    direct = plugin.explain_graph(**self._body(cypher="  "))
    started = plugin.explain_graph_start(**self._body(cypher="  "))
    self.assertEqual(direct["status_code"], 400)
    self.assertEqual(started, direct)
    too_long = "MATCH (n) RETURN n " + "x" * (CYPHER_MAX_CHARS + 1)
    self.assertEqual(plugin.explain_graph_start(**self._body(cypher=too_long))["status_code"], 413)
    self.assertEqual(plugin._explain_job_state()["jobs"], {})

  def test_second_start_while_one_runs_gets_429_with_a_retry_hint(self):
    plugin = _make_api()
    gate = threading.Event()
    impl = self._gated_impl(gate, [("neo4j", None)])
    with patch.object(plugin, "_explain_graph_impl", side_effect=impl):
      first = plugin.explain_graph_start(**self._body())
      second = plugin.explain_graph_start(**self._body())
      self.assertEqual(second["status_code"], 429)
      self.assertEqual(second["result"]["retry_after_seconds"], 30)
      self.assertFalse(second["result"]["ok"])
      gate.set()
      self._wait_done(plugin, first["job_id"])
      third = plugin.explain_graph_start(**self._body())
      self.assertIn("job_id", third)
      self._wait_done(plugin, third["job_id"])

  def test_unknown_expired_and_malformed_ids_get_404(self):
    plugin = _make_api()
    gate = threading.Event()
    gate.set()
    with patch.object(plugin, "_explain_graph_impl", side_effect=self._gated_impl(gate, [("neo4j", None)])):
      job_id = plugin.explain_graph_start(**self._body())["job_id"]
      self._wait_done(plugin, job_id)
    for missing in ("A" * 32, "", None):
      self.assertEqual(plugin.explain_graph_status(job_id=missing)["status_code"], 404)
    state = plugin._explain_job_state()
    state["jobs"][job_id]["finished_at"] -= 16 * 60
    expired = plugin.explain_graph_status(job_id=job_id)
    self.assertEqual(expired["status_code"], 404)
    self.assertEqual(expired["result"]["status"], "not_found")
    self.assertNotIn(job_id, state["jobs"])

  def test_finished_jobs_are_capped_at_twenty_oldest_dropped_first(self):
    plugin = _make_api()
    gate = threading.Event()
    gate.set()
    ids = []
    with patch.object(plugin, "_explain_graph_impl", side_effect=self._gated_impl(gate, [("neo4j", None)])):
      for _ in range(23):
        job_id = plugin.explain_graph_start(**self._body())["job_id"]
        self._wait_done(plugin, job_id)
        ids.append(job_id)
        time.sleep(0.002)
    self.assertEqual(len(plugin._explain_job_state()["jobs"]), 20)
    for dropped in ids[:3]:
      self.assertEqual(plugin.explain_graph_status(job_id=dropped)["status_code"], 404)
    self.assertTrue(plugin.explain_graph_status(job_id=ids[-1])["done"])

  def test_a_stuck_job_is_closed_so_it_cannot_hold_the_slot_forever(self):
    plugin = _make_api()
    gate = threading.Event()
    with patch.object(plugin, "_explain_graph_impl", side_effect=self._gated_impl(gate, [("neo4j", None)])):
      job_id = plugin.explain_graph_start(**self._body())["job_id"]
      plugin._explain_job_state()["jobs"][job_id]["created"] -= 2 * EDGEGUARD_REQUEST_TIMEOUT_SECONDS + 1
      status = plugin.explain_graph_status(job_id=job_id)
      self.assertTrue(status["done"])
      self.assertEqual(status["result_status_code"], 504)
      gate.set()

  def test_a_stuck_closed_job_still_holds_the_slot_while_its_thread_lives(self):
    plugin = _make_api()
    gate = threading.Event()
    with patch.object(plugin, "_explain_graph_impl", side_effect=self._gated_impl(gate, [("neo4j", None)])):
      job_id = plugin.explain_graph_start(**self._body())["job_id"]
      plugin._explain_job_state()["jobs"][job_id]["created"] -= 2 * EDGEGUARD_REQUEST_TIMEOUT_SECONDS + 1
      self.assertEqual(plugin.explain_graph_status(job_id=job_id)["result_status_code"], 504)
      busy = plugin.explain_graph_start(**self._body())
      self.assertEqual(busy["status_code"], 429)
      gate.set()
      deadline = time.monotonic() + 10
      while plugin._explain_job_state()["jobs"][job_id]["worker_active"] and time.monotonic() < deadline:
        time.sleep(0.01)
      # The late finish did not overwrite the 504, and the slot is free again.
      self.assertEqual(plugin.explain_graph_status(job_id=job_id)["result_status_code"], 504)
      again = plugin.explain_graph_start(**self._body())
      self.assertIn("job_id", again)
      self._wait_done(plugin, again["job_id"])

  def test_thread_start_failure_pops_the_job_and_returns_503(self):
    plugin = _make_api()
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.threading.Thread") as thread:
      thread.return_value.start.side_effect = RuntimeError("can't start new thread")
      response = plugin.explain_graph_start(**self._body())
    self.assertEqual(response["status_code"], 503)
    self.assertEqual(plugin._explain_job_state()["jobs"], {})

  def test_unexpected_worker_exception_is_logged_server_side_without_the_password(self):
    plugin = _make_api()
    logged = []
    plugin.P = lambda message, *args, **kwargs: logged.append(str(message))

    def boom(progress=None, **_body):
      progress("neo4j", None)
      raise RuntimeError("failed with secret-pw in text")

    with patch.object(plugin, "_explain_graph_impl", side_effect=boom):
      job_id = plugin.explain_graph_start(**self._body(password="secret-pw"))["job_id"]
      self._wait_done(plugin, job_id)
    text = "\n".join(logged)
    self.assertIn("RuntimeError", text)
    self.assertIn("Traceback", text)
    self.assertNotIn("secret-pw", text)

  def test_unexpected_worker_exception_log_redacts_the_configured_password(self):
    plugin = _make_api(neo4j_default_connection={
      "uri": "example.com:7687", "username": "neo4j", "password": "cfg-secret-pw", "scheme": "bolt+s",
    })
    logged = []
    plugin.P = lambda message, *args, **kwargs: logged.append(str(message))

    def boom(progress=None, **_body):
      progress("neo4j", None)
      raise RuntimeError("failed with cfg-secret-pw in text")

    body = {key: value for key, value in self._body().items() if key not in ("uri", "username", "password", "scheme")}
    with patch.object(plugin, "_explain_graph_impl", side_effect=boom):
      job_id = plugin.explain_graph_start(**body)["job_id"]
      self._wait_done(plugin, job_id)
    text = "\n".join(logged)
    self.assertIn("Traceback", text)
    self.assertNotIn("cfg-secret-pw", text)

  def test_one_call_path_reports_brief_attempt_one_then_done(self):
    plugin = _make_api(edgeguard_explanation_strategy="one_call")
    phases = []
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      fake_driver, _ = _driver_with_results(_Result([_graph_path_record()], keys=["p"]))
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver), \
          patch.object(plugin, "_explanation_dispatch_strategy", return_value="one_call"), \
          patch.object(plugin, "_run_digest_analyst_brief", return_value={"status": "ok", "ok": True}):
        plugin._explain_graph_impl(
          progress=lambda phase, detail=None: phases.append((phase, detail)), **self._body(),
        )
    names = [phase for phase, _ in phases]
    self.assertEqual(names, ["guard", "neo4j", "neo4j", "evidence", "misp", "brief"])
    self.assertEqual(phases[-1], ("brief", {"attempt": 1}))

  def test_unexpected_worker_exception_becomes_a_500_result_without_details(self):
    plugin = _make_api()

    def boom(progress=None, **_body):
      progress("neo4j", None)
      raise RuntimeError("secret-host.internal exploded")

    with patch.object(plugin, "_explain_graph_impl", side_effect=boom):
      job_id = plugin.explain_graph_start(**self._body())["job_id"]
      final = self._wait_done(plugin, job_id)
    self.assertEqual(final["result_status_code"], 500)
    self.assertNotIn("secret-host", json.dumps(final))

  def test_explain_graph_passes_no_progress_callback(self):
    plugin = _make_api()
    with patch.object(plugin, "_explain_graph_impl", return_value={"ok": True}) as impl:
      plugin.explain_graph(**self._body())
    self.assertIsNone(impl.call_args.kwargs["progress"])

  def test_a_failing_progress_callback_cannot_break_the_explain(self):
    def bad(_phase, _detail=None):
      raise RuntimeError("boom")

    plugin = _make_api(edgeguard_explanation_strategy="insight_brief")
    with patch("extensions.business.cybersec.edgeguard.edgeguard_api.GraphDatabase", object()):
      fake_driver, _ = _driver_with_results(_Result([_graph_path_record()], keys=["p"]))
      with patch.object(plugin, "_neo4j_driver", return_value=fake_driver):
        result = plugin._explain_graph_impl(progress=bad, **self._body())
    self.assertEqual(result["status"], "ok")
