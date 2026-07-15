"""EdgeGuard playground API plugin.

The API exposes model metadata, prompt contract metadata, deterministic Cypher
validation, and request-scoped Neo4j connection/query helpers for the
colleague playground. Text-to-Cypher generation is owned by the playground
server route, which calls model-specific LLM_INFERENCE_API workers directly.
"""

from __future__ import annotations

import traceback
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from urllib.parse import urlsplit, urlunsplit

import requests

from naeural_core.business.default.web_app.fast_api_web_app import FastApiWebAppPlugin as BasePlugin

from .edgeguard_cypher_guard import (
  DEFAULT_SCHEMA_RETRY_LIMIT,
  EDGEGUARD_SCHEMA,
  SCHEMA_VERSION,
  analyze_generated_cypher,
  build_empty_result_broadening_cypher,
  build_direct_cypher_system_prompt,
  build_schema_correction_prompt,
  canonical_schema_surface,
)

try:
  from neo4j import GraphDatabase
except Exception:  # pragma: no cover - exercised through dependency-missing tests.
  GraphDatabase = None

__VER__ = '0.1.0.0'

NEO4J_SCHEMES = {"bolt", "bolt+s", "neo4j", "neo4j+s"}
LOCAL_EXPLANATION_HOSTS = {"127.0.0.1", "localhost", "::1"}
GRAPH_PACKET_SCHEMA_VERSION = "edgeguard.graph_evidence_packet.v1"
CASE_EXPLANATION_SCHEMA_VERSION = "edgeguard.case_explanation.v1"
GRAPH_PACKET_REDACTION_POLICY = "edgeguard_graph_packet_private_v1"
EXPLANATION_DEFAULT_ROWS = 25
EXPLANATION_SERVER_MAX_ROWS = 100
LIMIT_RE = re.compile(r"\bLIMIT\s+(\d+)\b", re.IGNORECASE)
IDENT_RE = re.compile(r"[^A-Za-z0-9_]+")
EVIDENCE_ID_RE = re.compile(r"\b[nr]:[A-Za-z0-9_.:-]+\b")
NODE_ID_RE = re.compile(r"^n:[A-Za-z0-9_.:-]+$")
RELATIONSHIP_ID_RE = re.compile(r"^r:[A-Za-z0-9_.:-]+$")
SAFE_INTENT_RE = re.compile(r"^[a-z][a-z0-9_:-]{2,119}$")
ROLE_RE = re.compile(r"^[a-z][a-z0-9_:-]{0,79}$")
WRITE_OR_ADMIN_RE = re.compile(
  r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|ALTER|LOAD\s+CSV|"
  r"FOREACH|GRANT|DENY|REVOKE|CALL\s+[A-Za-z0-9_]+\s*\.|"
  r"START\s+DATABASE|STOP\s+DATABASE)\b",
  re.IGNORECASE,
)
FORBIDDEN_PACKET_PROPERTY_RE = re.compile(
  r"(raw|payload|body|content|header|authorization|cookie|password|secret|token|api_key|"
  r"credential|log|screenshot|stack|request|response)",
  re.IGNORECASE,
)
SEVERITY_EVIDENCE_KEYS = {
  "severity",
  "risk",
  "risk_score",
  "score",
  "cvss_score",
  "cvss_base_score",
}
CAPTION_KEYS = (
  "value",
  "name",
  "title",
  "cve_id",
  "type",
  "source_name",
  "external_id",
  "mitre_id",
)

CASE_EXPLANATION_KEYS = {
  "schema_version",
  "summary",
  "key_paths",
  "entity_findings",
  "risk_interpretation",
  "provenance",
  "caveats",
  "missing_context",
  "next_pivots",
}
SUMMARY_KEYS = {"text", "evidence_ids"}
KEY_PATH_KEYS = {"title", "path_evidence_ids", "interpretation", "confidence"}
ENTITY_FINDING_KEYS = {"entity_id", "role", "finding", "evidence_ids"}
RISK_KEYS = {"claim", "severity", "evidence_ids", "limits"}
PROVENANCE_KEYS = {"source_node_id", "source_name", "supports", "caveat"}
CAVEAT_KEYS = {"type", "message", "evidence_ids"}
MISSING_CONTEXT_KEYS = {"gap", "suggested_check"}
NEXT_PIVOT_KEYS = {"question", "suggested_query_intent", "priority"}
CONFIDENCE_VALUES = {"low", "medium", "high"}
SEVERITY_VALUES = {"informational", "low", "medium", "high", "critical"}
CAVEAT_TYPES = {
  "graph_scope",
  "broadening",
  "truncation",
  "limit_adjusted",
  "source_confidence",
  "missing_context",
  "redaction_scope",
}
PRIORITY_VALUES = {"low", "medium", "high"}

STATUS_OK = "ok"
STATUS_ERROR = "error"
STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"
STATUS_TIMEOUT = "timeout"

EDGEGUARD_REQUEST_TIMEOUT_SECONDS = 600

FINETUNED_MODEL_KEY = "finetuned_v0_10"
BASE_MODEL_KEY = "base_qwen3_4b"
CYBERSEC_MODEL_KEY = "cybersec_qwen_4b"
FINETUNED_PROMPT_PROFILE_ID = "edgeguard_direct_cypher_v0_10"
BASE_PROMPT_PROFILE_ID = "edgeguard_base_schema_grounded_v0_10"
CYBERSEC_PROMPT_PROFILE_ID = "edgeguard_cybersec_schema_grounded_v0_10"

EDGEGUARD_MODEL_REPO = "ratio1/edgeguard-cypher-qwen3-4b-v0.10-graph-intent-gguf"
EDGEGUARD_MODEL_FILE = "edgeguard-cypher-qwen3-4b-v0.10-graph-intent.Q4_K_M.gguf"
EDGEGUARD_MODEL_DISPLAY_NAME = "EdgeGuard Cypher Qwen3 4B v0.10 Graph-Intent GGUF"
EDGEGUARD_MODEL_ARTIFACT_SHA256 = "7f7ed0f4d3341d36204d17343a07e3b6d99ec135a4ce67da66ad09b8eba2a91b"
EDGEGUARD_SOURCE_ADAPTER_SHA256 = "419161efd86e63cb62c368fd18c6da84c923923d13774f7b6ea57f1196f65fba"
EDGEGUARD_RUNTIME_HARNESS_VERSION = "EGM-029 v0.10"
EDGEGUARD_RUNTIME_LIVE_GATE_RESULT = "v0.9 baseline 44 / 45 = 97.78%"
EDGEGUARD_DATASET = "qwen-prompt-cypher-v0.10-graph-intent-coverage-v1"
EDGEGUARD_SOURCE_ADAPTER = "EGM-029 v0.10 graph-intent from v0.9"
EDGEGUARD_ROBUSTNESS_LABEL_COVERAGE = "96.06% (+16.54pp vs v0.9)"
EDGEGUARD_ROBUSTNESS_RELATIONSHIP_COVERAGE = "85.83% (+7.87pp vs v0.9)"
EDGEGUARD_ROBUSTNESS_SUBGRAPH_ACCEPTED = "100% (+7.09pp vs v0.9)"
EDGEGUARD_TEST_LABEL_COVERAGE = "97.50% (+16.25pp vs v0.9)"
EDGEGUARD_TEST_RELATIONSHIP_COVERAGE = "76.25% (+5.00pp vs v0.9)"
EDGEGUARD_CORPUS = "3,588 accepted graph rows (2,868 train / 360 validation / 360 test)"

EDGEGUARD_MODEL_CATALOG = [
  {
    "model_key": FINETUNED_MODEL_KEY,
    "display_name": "Finetuned v0.10",
    "description": "Private Ratio1 EdgeGuard text-to-Cypher Qwen3 4B v0.10 GGUF.",
    "model_repo": EDGEGUARD_MODEL_REPO,
    "model_file": EDGEGUARD_MODEL_FILE,
    "format": "GGUF",
    "quantization": "Q4_K_M",
    "base_model": "Qwen/Qwen3-4B-Instruct-2507",
    "artifact_sha256": EDGEGUARD_MODEL_ARTIFACT_SHA256,
    "prompt_profile_id": FINETUNED_PROMPT_PROFILE_ID,
    "prompt_contract": "one read-only Cypher query string only",
    "source": "private_ratio1",
  },
  {
    "model_key": BASE_MODEL_KEY,
    "display_name": "Base Qwen3 4B",
    "description": "Public base Qwen3 4B Instruct GGUF for side-by-side prompt comparison.",
    "model_repo": "MaziyarPanahi/Qwen3-4B-Instruct-2507-GGUF",
    "model_file": "Qwen3-4B-Instruct-2507.Q4_K_M.gguf",
    "format": "GGUF",
    "quantization": "Q4_K_M",
    "base_model": "Qwen/Qwen3-4B-Instruct-2507",
    "artifact_sha256": None,
    "prompt_profile_id": BASE_PROMPT_PROFILE_ID,
    "prompt_contract": "schema-grounded read-only Cypher query string only",
    "source": "public_huggingface",
  },
]

CYBERSEC_MODEL_CATALOG_ENTRY = {
  "model_key": CYBERSEC_MODEL_KEY,
  "display_name": "CyberSecQwen 4B · Experimental",
  "description": "Public security-specialized Qwen 4B GGUF for experimental prompt comparison.",
  "model_repo": "mradermacher/CyberSecQwen-4B-GGUF",
  "model_file": "CyberSecQwen-4B.Q4_K_M.gguf",
  "format": "GGUF",
  "quantization": "Q4_K_M",
  "base_model": "lablab-ai-amd-developer-hackathon/CyberSecQwen-4B",
  "artifact_sha256": "ac6c98de9919a6891f966f87de6f6b50f7822235bf9c3ab8401ca6a897d02ecc",
  "prompt_profile_id": CYBERSEC_PROMPT_PROFILE_ID,
  "prompt_contract": "schema-grounded read-only Cypher query string only",
  "source": "public_huggingface_experimental",
}

CASE_EXPLANATION_RESPONSE_SCHEMA = {
  "type": "object",
  "additionalProperties": False,
  "required": sorted(CASE_EXPLANATION_KEYS),
  "properties": {
    "schema_version": {"const": CASE_EXPLANATION_SCHEMA_VERSION},
    "summary": {
      "type": "object",
      "additionalProperties": False,
      "required": sorted(SUMMARY_KEYS),
      "properties": {
        "text": {"type": "string", "minLength": 1, "maxLength": 2000},
        "evidence_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 40},
      },
    },
    "key_paths": {
      "type": "array",
      "maxItems": 12,
      "items": {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(KEY_PATH_KEYS),
        "properties": {
          "title": {"type": "string", "minLength": 1, "maxLength": 2000},
          "path_evidence_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 40},
          "interpretation": {"type": "string", "minLength": 1, "maxLength": 2000},
          "confidence": {"enum": sorted(CONFIDENCE_VALUES)},
        },
      },
    },
    "entity_findings": {
      "type": "array",
      "maxItems": 40,
      "items": {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(ENTITY_FINDING_KEYS),
        "properties": {
          "entity_id": {"type": "string", "pattern": "^n:[A-Za-z0-9_.:-]+$"},
          "role": {"type": "string", "pattern": "^[a-z][a-z0-9_:-]*$", "maxLength": 80},
          "finding": {"type": "string", "minLength": 1, "maxLength": 2000},
          "evidence_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 40},
        },
      },
    },
    "risk_interpretation": {
      "type": "array",
      "maxItems": 12,
      "items": {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(RISK_KEYS),
        "properties": {
          "claim": {"type": "string", "minLength": 1, "maxLength": 2000},
          "severity": {"enum": sorted(SEVERITY_VALUES)},
          "evidence_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 40},
          "limits": {"type": "string", "minLength": 1, "maxLength": 2000},
        },
      },
    },
    "provenance": {
      "type": "array",
      "maxItems": 20,
      "items": {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(PROVENANCE_KEYS),
        "properties": {
          "source_node_id": {"type": "string", "pattern": "^n:[A-Za-z0-9_.:-]+$"},
          "source_name": {"type": "string", "minLength": 1, "maxLength": 160},
          "supports": {"type": "array", "items": {"type": "string"}, "maxItems": 40},
          "caveat": {"type": "string", "minLength": 1, "maxLength": 2000},
        },
      },
    },
    "caveats": {
      "type": "array",
      "maxItems": 16,
      "items": {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(CAVEAT_KEYS),
        "properties": {
          "type": {"enum": sorted(CAVEAT_TYPES)},
          "message": {"type": "string", "minLength": 1, "maxLength": 2000},
          "evidence_ids": {"type": "array", "items": {"type": "string"}, "maxItems": 40},
        },
      },
    },
    "missing_context": {
      "type": "array",
      "maxItems": 16,
      "items": {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(MISSING_CONTEXT_KEYS),
        "properties": {
          "gap": {"type": "string", "minLength": 1, "maxLength": 2000},
          "suggested_check": {"type": "string", "minLength": 1, "maxLength": 2000},
        },
      },
    },
    "next_pivots": {
      "type": "array",
      "maxItems": 12,
      "items": {
        "type": "object",
        "additionalProperties": False,
        "required": sorted(NEXT_PIVOT_KEYS),
        "properties": {
          "question": {"type": "string", "minLength": 1, "maxLength": 2000},
          "suggested_query_intent": {"type": "string", "pattern": "^[a-z][a-z0-9_:-]*$", "maxLength": 120},
          "priority": {"enum": sorted(PRIORITY_VALUES)},
        },
      },
    },
  },
}


@dataclass
class _GraphPacketState:
  nodes: Dict[str, Dict[str, Any]] = field(default_factory=dict)
  relationships: Dict[str, Dict[str, Any]] = field(default_factory=dict)
  node_keys: Dict[str, str] = field(default_factory=dict)
  relationship_keys: Dict[str, str] = field(default_factory=dict)
  dropped_forbidden_properties: int = 0
  truncated_properties: int = 0
  graph_truncated: bool = False


def _contract_error(code: str, detail: str) -> Dict[str, str]:
  return {"code": code, "detail": detail}


def _sha256_text(value: str) -> str:
  return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _compact_text(value: Any, max_chars: int) -> str:
  text = " ".join(str(value).replace("\r", " ").replace("\n", " ").split())
  if len(text) <= max_chars:
    return text
  return text[:max_chars].rstrip()


def _replace_last_limit(cypher: str, new_limit: int) -> str:
  matches = list(LIMIT_RE.finditer(cypher))
  if not matches:
    return cypher.rstrip().rstrip(";") + f" LIMIT {new_limit}"
  match = matches[-1]
  return cypher[: match.start()] + f"LIMIT {new_limit}" + cypher[match.end() :]


def _normalize_explanation_cypher_limit(
  cypher: str,
  requested_limit: Optional[int] = None,
) -> tuple[str, int, int, bool]:
  target_limit = EXPLANATION_DEFAULT_ROWS if requested_limit is None else int(requested_limit)
  target_limit = max(1, min(target_limit, EXPLANATION_SERVER_MAX_ROWS))
  matches = list(LIMIT_RE.finditer(cypher))
  generated_limit = int(matches[-1].group(1)) if matches else target_limit
  if requested_limit is None:
    executed_limit = min(max(generated_limit, EXPLANATION_DEFAULT_ROWS), EXPLANATION_SERVER_MAX_ROWS)
  else:
    executed_limit = target_limit
  executed_cypher = _replace_last_limit(cypher, executed_limit)
  return executed_cypher, generated_limit, executed_limit, generated_limit != executed_limit


def _is_scalar(value: Any) -> bool:
  return value is None or isinstance(value, (str, int, float, bool))


def _safe_identifier(value: str, default: str) -> str:
  candidate = IDENT_RE.sub("_", value).strip("_")
  if not candidate:
    return default
  if not candidate[0].isalpha():
    candidate = default + "_" + candidate
  return candidate[:80]


def _object_items(value: Any) -> Dict[str, Any]:
  if hasattr(value, "items"):
    try:
      return dict(value.items())
    except Exception:  # noqa: BLE001 - Neo4j driver object best effort.
      return {}
  return {}


def _object_key(value: Any, prefix: str) -> str:
  for attr in ("element_id", "elementId", "id"):
    item = getattr(value, attr, None)
    if item not in (None, ""):
      return f"{prefix}:{item}"
  return f"{prefix}:{repr(value)}"


def _evidence_id(prefix: str, key: str) -> str:
  return f"{prefix}:{_sha256_text(key)[:16]}"


def _sanitize_packet_properties(properties: Dict[str, Any], state: _GraphPacketState) -> Dict[str, Any]:
  clean: Dict[str, Any] = {}
  for key, value in properties.items():
    key_text = str(key)
    if not key_text or FORBIDDEN_PACKET_PROPERTY_RE.search(key_text):
      state.dropped_forbidden_properties += 1
      continue
    if isinstance(value, str):
      if len(value) > 500:
        state.truncated_properties += 1
      clean[key_text] = _compact_text(value, 500)
    elif _is_scalar(value):
      clean[key_text] = value
    elif isinstance(value, list):
      scalar_items = [item for item in value if _is_scalar(item)]
      if len(scalar_items) != len(value) or len(scalar_items) > 20:
        state.truncated_properties += 1
      clean[key_text] = [
        _compact_text(item, 500) if isinstance(item, str) else item
        for item in scalar_items[:20]
      ]
    else:
      state.truncated_properties += 1
  return clean


def _is_path_like(value: Any) -> bool:
  return hasattr(value, "nodes") and hasattr(value, "relationships")


def _is_relationship_like(value: Any) -> bool:
  return hasattr(value, "type") and hasattr(value, "start_node") and hasattr(value, "end_node")


def _is_node_like(value: Any) -> bool:
  return hasattr(value, "labels") and hasattr(value, "items") and not _is_relationship_like(value)


def _node_caption(labels: list[str], properties: Dict[str, Any]) -> str:
  for key in CAPTION_KEYS:
    item = properties.get(key)
    if isinstance(item, str) and item.strip():
      return _compact_text(item, 240)
  for item in properties.values():
    if _is_scalar(item) and item not in (None, ""):
      return _compact_text(item, 240)
  return labels[0] if labels else "Entity"


def _add_graph_node(value: Any, state: _GraphPacketState) -> Optional[str]:
  if value is None:
    return None
  key = _object_key(value, "node")
  if key in state.node_keys:
    return state.node_keys[key]
  if len(state.nodes) >= 160:
    state.graph_truncated = True
    return None
  labels = sorted(_safe_identifier(str(label), "Entity") for label in getattr(value, "labels", []) or [])
  labels = [label for label in labels if label][:8] or ["Entity"]
  properties = _sanitize_packet_properties(_object_items(value), state)
  node_id = _evidence_id("n", key)
  state.node_keys[key] = node_id
  state.nodes[node_id] = {
    "id": node_id,
    "labels": labels,
    "caption": _node_caption(labels, properties),
    "properties": properties,
  }
  return node_id


def _add_graph_relationship(value: Any, state: _GraphPacketState) -> Optional[str]:
  key = _object_key(value, "relationship")
  if key in state.relationship_keys:
    return state.relationship_keys[key]
  if len(state.relationships) >= 240:
    state.graph_truncated = True
    return None
  start_id = _add_graph_node(getattr(value, "start_node", None), state)
  end_id = _add_graph_node(getattr(value, "end_node", None), state)
  if not start_id or not end_id:
    state.graph_truncated = True
    return None
  rel_id = _evidence_id("r", key)
  rel_type = _safe_identifier(str(getattr(value, "type", "") or "RELATED_TO").upper(), "RELATED_TO")
  properties = _sanitize_packet_properties(_object_items(value), state)
  state.relationship_keys[key] = rel_id
  state.relationships[rel_id] = {
    "id": rel_id,
    "type": rel_type,
    "startNodeId": start_id,
    "endNodeId": end_id,
    "caption": rel_type,
    "properties": properties,
  }
  return rel_id


def _collect_graph(value: Any, state: _GraphPacketState) -> None:
  if value is None:
    return
  if _is_path_like(value):
    for node in list(getattr(value, "nodes", []) or []):
      _add_graph_node(node, state)
    for relationship in list(getattr(value, "relationships", []) or []):
      _add_graph_relationship(relationship, state)
    return
  if _is_relationship_like(value):
    _add_graph_relationship(value, state)
    return
  if _is_node_like(value):
    _add_graph_node(value, state)
    return
  if isinstance(value, dict):
    for item in value.values():
      _collect_graph(item, state)
    return
  if isinstance(value, (list, tuple, set)):
    for item in value:
      _collect_graph(item, state)


def _build_graph_evidence_packet(
  *,
  request: str,
  accepted_cypher: str,
  executed_cypher: str,
  records: list[Dict[str, Any]],
  generated_limit: int,
  executed_limit: int,
  limit_adjusted: bool,
  execution_truncated: bool = False,
  broadened: bool = False,
  live_retry_reason: Optional[str] = None,
) -> tuple[Dict[str, Any], Dict[str, Any]]:
  state = _GraphPacketState()
  for record in records:
    _collect_graph(record, state)
  graph_truncated = bool(execution_truncated or state.graph_truncated)
  packet = {
    "schema_version": GRAPH_PACKET_SCHEMA_VERSION,
    "request": _compact_text(request or "Explain the returned investigation graph.", 2000),
    "accepted_cypher": accepted_cypher,
    "executed_cypher": executed_cypher,
    "limit_policy": {
      "generated_limit": generated_limit,
      "executed_limit": executed_limit,
      "server_max_rows": EXPLANATION_SERVER_MAX_ROWS,
      "limit_adjusted": bool(limit_adjusted),
    },
    "execution": {
      "status": "executed" if records else "empty",
      "row_count": min(len(records), EXPLANATION_SERVER_MAX_ROWS),
      "truncated": graph_truncated,
      "broadened": bool(broadened),
      "live_retry_reason": live_retry_reason if broadened else None,
    },
    "graph": {
      "nodes": list(state.nodes.values()),
      "relationships": list(state.relationships.values()),
      "truncated": graph_truncated,
    },
    "redaction": {
      "policy": GRAPH_PACKET_REDACTION_POLICY,
      "contains_customer_evidence": False,
      "contains_raw_misp_payload": False,
    },
  }
  meta = {
    "dropped_forbidden_properties": state.dropped_forbidden_properties,
    "truncated_properties": state.truncated_properties,
    "node_count": len(state.nodes),
    "relationship_count": len(state.relationships),
  }
  return packet, meta


def _validate_property_map(path: str, properties: Any, errors: list[Dict[str, str]]) -> None:
  if not isinstance(properties, dict):
    errors.append(_contract_error("invalid_property_map", f"{path}: properties must be an object"))
    return
  for key, value in properties.items():
    if not isinstance(key, str) or not key:
      errors.append(_contract_error("invalid_property_key", f"{path}: property key must be a non-empty string"))
      continue
    if FORBIDDEN_PACKET_PROPERTY_RE.search(key):
      errors.append(_contract_error("forbidden_property_key", f"{path}.{key}: forbidden raw or credential field"))
    if isinstance(value, str) and len(value) > 500:
      errors.append(_contract_error("oversized_property_string", f"{path}.{key}: string exceeds 500 characters"))
      continue
    if _is_scalar(value):
      continue
    if isinstance(value, list) and len(value) <= 20 and all(_is_scalar(item) for item in value):
      continue
    errors.append(_contract_error("invalid_property_value", f"{path}.{key}: nested objects and large arrays are not allowed"))


def _validate_graph_evidence_packet(packet: Any) -> tuple[list[Dict[str, str]], Dict[str, Any]]:
  errors: list[Dict[str, str]] = []
  context: Dict[str, Any] = {
    "evidence_ids": set(),
    "node_ids": set(),
    "relationship_ids": set(),
    "relationships": {},
    "nodes": {},
    "source_names": {},
    "severity_evidence_ids": set(),
    "flags": {
      "broadened": False,
      "truncated": False,
      "limit_adjusted": False,
    },
  }
  if not isinstance(packet, dict):
    return [_contract_error("invalid_packet", "packet must be an object")], context
  if packet.get("schema_version") != GRAPH_PACKET_SCHEMA_VERSION:
    errors.append(_contract_error("packet_schema_version", "unexpected packet schema_version"))

  limit_policy = packet.get("limit_policy")
  if not isinstance(limit_policy, dict):
    errors.append(_contract_error("limit_policy_missing", "limit_policy must be an object"))
  else:
    generated_limit = limit_policy.get("generated_limit")
    executed_limit = limit_policy.get("executed_limit")
    limit_adjusted = limit_policy.get("limit_adjusted")
    if not isinstance(generated_limit, int) or not 1 <= generated_limit <= EXPLANATION_SERVER_MAX_ROWS:
      errors.append(_contract_error("invalid_limit", "generated_limit must be an integer in 1..100"))
    if not isinstance(executed_limit, int) or not 1 <= executed_limit <= EXPLANATION_SERVER_MAX_ROWS:
      errors.append(_contract_error("invalid_limit", "executed_limit must be an integer in 1..100"))
    if limit_policy.get("server_max_rows") != EXPLANATION_SERVER_MAX_ROWS:
      errors.append(_contract_error("invalid_server_max_rows", "server_max_rows must be 100"))
    if isinstance(generated_limit, int) and isinstance(executed_limit, int):
      if limit_adjusted is not (generated_limit != executed_limit):
        errors.append(_contract_error("limit_adjusted_mismatch", "limit_adjusted must match generated/executed limit difference"))
      context["flags"]["limit_adjusted"] = bool(limit_adjusted)

  execution = packet.get("execution")
  if not isinstance(execution, dict):
    errors.append(_contract_error("execution_missing", "execution must be an object"))
  else:
    row_count = execution.get("row_count")
    if not isinstance(row_count, int) or not 0 <= row_count <= EXPLANATION_SERVER_MAX_ROWS:
      errors.append(_contract_error("invalid_row_count", "row_count must be an integer in 0..100"))
    context["flags"]["broadened"] = bool(execution.get("broadened"))
    context["flags"]["truncated"] = bool(execution.get("truncated"))
    if execution.get("broadened") and not execution.get("live_retry_reason"):
      errors.append(_contract_error("missing_live_retry_reason", "broadened packets require live_retry_reason"))

  graph = packet.get("graph")
  if not isinstance(graph, dict):
    errors.append(_contract_error("graph_missing", "graph must be an object"))
  else:
    nodes = graph.get("nodes") if isinstance(graph.get("nodes"), list) else []
    relationships = graph.get("relationships") if isinstance(graph.get("relationships"), list) else []
    if not isinstance(graph.get("nodes"), list):
      errors.append(_contract_error("invalid_nodes", "graph.nodes must be a list"))
    if not isinstance(graph.get("relationships"), list):
      errors.append(_contract_error("invalid_relationships", "graph.relationships must be a list"))
    if bool(graph.get("truncated")):
      context["flags"]["truncated"] = True
    for index, node in enumerate(nodes):
      if not isinstance(node, dict):
        errors.append(_contract_error("invalid_node", f"node[{index}] must be an object"))
        continue
      node_id = node.get("id")
      if not isinstance(node_id, str) or not NODE_ID_RE.match(node_id):
        errors.append(_contract_error("invalid_node_id", f"node[{index}] has invalid id"))
        continue
      if node_id in context["evidence_ids"]:
        errors.append(_contract_error("duplicate_evidence_id", f"duplicate evidence id {node_id}"))
      context["evidence_ids"].add(node_id)
      context["node_ids"].add(node_id)
      context["nodes"][node_id] = node
      _validate_property_map(f"node[{node_id}]", node.get("properties"), errors)
      labels = node.get("labels") if isinstance(node.get("labels"), list) else []
      properties = node.get("properties") if isinstance(node.get("properties"), dict) else {}
      if "Source" in labels:
        names = {str(node.get("caption", ""))}
        for key in ("name", "source_name", "value"):
          value = properties.get(key)
          if isinstance(value, str):
            names.add(value)
        context["source_names"][node_id] = {name for name in names if name}
      if any(str(key).lower() in SEVERITY_EVIDENCE_KEYS for key in properties):
        context["severity_evidence_ids"].add(node_id)

    for index, relationship in enumerate(relationships):
      if not isinstance(relationship, dict):
        errors.append(_contract_error("invalid_relationship", f"relationship[{index}] must be an object"))
        continue
      rel_id = relationship.get("id")
      if not isinstance(rel_id, str) or not RELATIONSHIP_ID_RE.match(rel_id):
        errors.append(_contract_error("invalid_relationship_id", f"relationship[{index}] has invalid id"))
        continue
      if rel_id in context["evidence_ids"]:
        errors.append(_contract_error("duplicate_evidence_id", f"duplicate evidence id {rel_id}"))
      context["evidence_ids"].add(rel_id)
      context["relationship_ids"].add(rel_id)
      context["relationships"][rel_id] = relationship
      start_id = relationship.get("startNodeId")
      end_id = relationship.get("endNodeId")
      if start_id not in context["node_ids"] or end_id not in context["node_ids"]:
        errors.append(_contract_error("relationship_endpoint_missing", f"{rel_id}: endpoint not present in graph nodes"))
      _validate_property_map(f"relationship[{rel_id}]", relationship.get("properties"), errors)
      properties = relationship.get("properties") if isinstance(relationship.get("properties"), dict) else {}
      if any(str(key).lower() in SEVERITY_EVIDENCE_KEYS for key in properties):
        context["severity_evidence_ids"].add(rel_id)

  redaction = packet.get("redaction")
  if not isinstance(redaction, dict):
    errors.append(_contract_error("redaction_missing", "redaction must be an object"))
  else:
    if redaction.get("policy") != GRAPH_PACKET_REDACTION_POLICY:
      errors.append(_contract_error("redaction_policy", "unexpected redaction policy"))
    if redaction.get("contains_customer_evidence") is not False:
      errors.append(_contract_error("customer_evidence_not_allowed", "customer evidence is not allowed in v0.1 model input"))
    if redaction.get("contains_raw_misp_payload") is not False:
      errors.append(_contract_error("raw_misp_payload_not_allowed", "raw MISP payloads are not allowed in v0.1 model input"))

  return errors, context


def _unexpected_keys(value: Dict[str, Any], allowed: set[str], where: str, errors: list[Dict[str, str]]) -> None:
  for key in sorted(set(value).difference(allowed)):
    errors.append(_contract_error("schema_additional_property", f"{where}: unexpected property {key}"))


def _require_keys(value: Dict[str, Any], required: set[str], where: str, errors: list[Dict[str, str]]) -> None:
  for key in sorted(required):
    if key not in value:
      errors.append(_contract_error("schema_required", f"{where}: missing required property {key}"))


def _validate_text_field(value: Any, where: str, errors: list[Dict[str, str]], max_chars: int = 2000) -> None:
  if not isinstance(value, str) or not value.strip():
    errors.append(_contract_error("schema_type", f"{where}: must be a non-empty string"))
    return
  if len(value) > max_chars:
    errors.append(_contract_error("schema_max_length", f"{where}: string exceeds {max_chars} characters"))


def _validate_enum(value: Any, allowed: set[str], where: str, errors: list[Dict[str, str]]) -> None:
  if value not in allowed:
    errors.append(_contract_error("schema_enum", f"{where}: value must be one of {sorted(allowed)}"))


def _evidence_errors(ids: Any, context: Dict[str, Any], where: str) -> list[Dict[str, str]]:
  errors: list[Dict[str, str]] = []
  if not isinstance(ids, list):
    return [_contract_error("invalid_evidence_ids", f"{where}: evidence IDs must be a list")]
  if len(ids) > 40:
    errors.append(_contract_error("schema_max_items", f"{where}: evidence IDs exceed 40 items"))
  seen = set()
  for evidence in ids:
    if evidence in seen:
      errors.append(_contract_error("duplicate_evidence_id", f"{where}: duplicate evidence id {evidence}"))
    seen.add(evidence)
    if not isinstance(evidence, str) or not EVIDENCE_ID_RE.fullmatch(evidence):
      errors.append(_contract_error("invalid_evidence_id", f"{where}: {evidence!r} is not a valid evidence id"))
      continue
    if evidence not in context["evidence_ids"]:
      errors.append(_contract_error("unknown_evidence_id", f"{where}: {evidence} is not present in the packet"))
  return errors


def _text_values(value: Any) -> list[str]:
  if isinstance(value, str):
    return [value]
  if isinstance(value, list):
    values: list[str] = []
    for item in value:
      values.extend(_text_values(item))
    return values
  if isinstance(value, dict):
    values: list[str] = []
    for item in value.values():
      values.extend(_text_values(item))
    return values
  return []


def _validate_text_embedded_ids(explanation: Dict[str, Any], context: Dict[str, Any], errors: list[Dict[str, str]]) -> None:
  for text in _text_values(explanation):
    for item in EVIDENCE_ID_RE.findall(text):
      if item not in context["evidence_ids"]:
        errors.append(_contract_error("unknown_evidence_id", f"text references absent evidence id {item}"))


def _validate_path_connectivity(path_ids: Any, context: Dict[str, Any], where: str, errors: list[Dict[str, str]]) -> None:
  if not isinstance(path_ids, list):
    errors.append(_contract_error("invalid_path_ids", f"{where}: path_evidence_ids must be a list"))
    return
  path_node_ids = {item for item in path_ids if isinstance(item, str) and item.startswith("n:")}
  for item in path_ids:
    if not isinstance(item, str) or not item.startswith("r:"):
      continue
    relationship = context["relationships"].get(item)
    if relationship and (
      relationship.get("startNodeId") not in path_node_ids
      or relationship.get("endNodeId") not in path_node_ids
    ):
      errors.append(_contract_error("path_relationship_not_connected", f"{where}: {item} endpoints are not both in the path"))


def _validate_case_explanation(explanation: Any, context: Dict[str, Any]) -> list[Dict[str, str]]:
  errors: list[Dict[str, str]] = []
  if not isinstance(explanation, dict):
    return [_contract_error("invalid_explanation", "explanation must be an object")]
  _unexpected_keys(explanation, CASE_EXPLANATION_KEYS, "explanation", errors)
  for key in CASE_EXPLANATION_KEYS:
    if key not in explanation:
      errors.append(_contract_error("schema_required", f"explanation: missing required property {key}"))
  if explanation.get("schema_version") != CASE_EXPLANATION_SCHEMA_VERSION:
    errors.append(_contract_error("explanation_schema_version", "unexpected explanation schema_version"))

  summary = explanation.get("summary")
  if not isinstance(summary, dict):
    errors.append(_contract_error("summary_missing", "summary must be an object"))
  else:
    _unexpected_keys(summary, SUMMARY_KEYS, "summary", errors)
    _require_keys(summary, SUMMARY_KEYS, "summary", errors)
    _validate_text_field(summary.get("text"), "summary.text", errors)
    errors.extend(_evidence_errors(summary.get("evidence_ids"), context, "summary"))
    if not summary.get("evidence_ids"):
      errors.append(_contract_error("material_claim_missing_evidence", "summary must cite evidence"))

  for section in ("key_paths", "entity_findings", "risk_interpretation", "provenance", "caveats", "missing_context", "next_pivots"):
    if not isinstance(explanation.get(section), list):
      errors.append(_contract_error("schema_type", f"{section}: must be a list"))

  for index, path in enumerate(explanation.get("key_paths") or []):
    if not isinstance(path, dict):
      errors.append(_contract_error("invalid_key_path", f"key_paths[{index}] must be an object"))
      continue
    _unexpected_keys(path, KEY_PATH_KEYS, f"key_paths[{index}]", errors)
    _require_keys(path, KEY_PATH_KEYS, f"key_paths[{index}]", errors)
    _validate_text_field(path.get("title"), f"key_paths[{index}].title", errors)
    _validate_text_field(path.get("interpretation"), f"key_paths[{index}].interpretation", errors)
    _validate_enum(path.get("confidence"), CONFIDENCE_VALUES, f"key_paths[{index}].confidence", errors)
    ids = path.get("path_evidence_ids")
    errors.extend(_evidence_errors(ids, context, f"key_paths[{index}]"))
    if not ids:
      errors.append(_contract_error("material_claim_missing_evidence", f"key_paths[{index}] must cite evidence"))
    _validate_path_connectivity(ids, context, f"key_paths[{index}]", errors)

  for index, finding in enumerate(explanation.get("entity_findings") or []):
    if not isinstance(finding, dict):
      errors.append(_contract_error("invalid_entity_finding", f"entity_findings[{index}] must be an object"))
      continue
    _unexpected_keys(finding, ENTITY_FINDING_KEYS, f"entity_findings[{index}]", errors)
    _require_keys(finding, ENTITY_FINDING_KEYS, f"entity_findings[{index}]", errors)
    _validate_text_field(finding.get("finding"), f"entity_findings[{index}].finding", errors)
    role = finding.get("role")
    if not isinstance(role, str) or not ROLE_RE.match(role):
      errors.append(_contract_error("schema_pattern", f"entity_findings[{index}].role: invalid role label"))
    if finding.get("entity_id") not in context["node_ids"]:
      errors.append(_contract_error("entity_not_found", f"entity_findings[{index}]: entity_id must reference a packet node"))
    ids = finding.get("evidence_ids")
    errors.extend(_evidence_errors(ids, context, f"entity_findings[{index}]"))
    if not ids:
      errors.append(_contract_error("material_claim_missing_evidence", f"entity_findings[{index}] must cite evidence"))

  for index, risk in enumerate(explanation.get("risk_interpretation") or []):
    if not isinstance(risk, dict):
      errors.append(_contract_error("invalid_risk_interpretation", f"risk_interpretation[{index}] must be an object"))
      continue
    _unexpected_keys(risk, RISK_KEYS, f"risk_interpretation[{index}]", errors)
    _require_keys(risk, RISK_KEYS, f"risk_interpretation[{index}]", errors)
    _validate_text_field(risk.get("claim"), f"risk_interpretation[{index}].claim", errors)
    _validate_text_field(risk.get("limits"), f"risk_interpretation[{index}].limits", errors)
    _validate_enum(risk.get("severity"), SEVERITY_VALUES, f"risk_interpretation[{index}].severity", errors)
    ids = risk.get("evidence_ids")
    errors.extend(_evidence_errors(ids, context, f"risk_interpretation[{index}]"))
    if not ids:
      errors.append(_contract_error("material_claim_missing_evidence", f"risk_interpretation[{index}] must cite evidence"))
    if risk.get("severity") in {"high", "critical"}:
      cited_ids = set(ids if isinstance(ids, list) else [])
      if not cited_ids.intersection(context["severity_evidence_ids"]):
        errors.append(_contract_error("severity_escalation_unsupported", f"risk_interpretation[{index}]: severity lacks severity evidence"))

  for index, provenance in enumerate(explanation.get("provenance") or []):
    if not isinstance(provenance, dict):
      errors.append(_contract_error("invalid_provenance", f"provenance[{index}] must be an object"))
      continue
    _unexpected_keys(provenance, PROVENANCE_KEYS, f"provenance[{index}]", errors)
    _require_keys(provenance, PROVENANCE_KEYS, f"provenance[{index}]", errors)
    _validate_text_field(provenance.get("source_name"), f"provenance[{index}].source_name", errors, max_chars=160)
    _validate_text_field(provenance.get("caveat"), f"provenance[{index}].caveat", errors)
    source_node_id = provenance.get("source_node_id")
    if source_node_id not in context["node_ids"]:
      errors.append(_contract_error("source_not_found", f"provenance[{index}]: source_node_id is absent"))
    elif source_node_id not in context["source_names"]:
      errors.append(_contract_error("source_label_missing", f"provenance[{index}]: source_node_id must reference a Source node"))
    elif provenance.get("source_name") not in context["source_names"][source_node_id]:
      errors.append(_contract_error("invented_source_name", f"provenance[{index}]: source_name does not match packet source node"))
    supports = provenance.get("supports")
    errors.extend(_evidence_errors(supports, context, f"provenance[{index}]"))
    if not supports:
      errors.append(_contract_error("material_claim_missing_evidence", f"provenance[{index}] must cite supporting evidence"))

  caveat_types = {
    caveat.get("type")
    for caveat in (explanation.get("caveats") or [])
    if isinstance(caveat, dict)
  }
  required_caveats = set()
  if context["flags"]["broadened"]:
    required_caveats.add("broadening")
  if context["flags"]["truncated"]:
    required_caveats.add("truncation")
  if context["flags"]["limit_adjusted"]:
    required_caveats.add("limit_adjusted")
  for caveat_type in sorted(required_caveats):
    if caveat_type not in caveat_types:
      errors.append(_contract_error("missing_required_caveat", f"missing required caveat type {caveat_type}"))
  for index, caveat in enumerate(explanation.get("caveats") or []):
    if not isinstance(caveat, dict):
      errors.append(_contract_error("invalid_caveat", f"caveats[{index}] must be an object"))
      continue
    _unexpected_keys(caveat, CAVEAT_KEYS, f"caveats[{index}]", errors)
    _require_keys(caveat, CAVEAT_KEYS, f"caveats[{index}]", errors)
    _validate_enum(caveat.get("type"), CAVEAT_TYPES, f"caveats[{index}].type", errors)
    _validate_text_field(caveat.get("message"), f"caveats[{index}].message", errors)
    errors.extend(_evidence_errors(caveat.get("evidence_ids"), context, f"caveats[{index}]"))

  for index, missing in enumerate(explanation.get("missing_context") or []):
    if not isinstance(missing, dict):
      errors.append(_contract_error("invalid_missing_context", f"missing_context[{index}] must be an object"))
      continue
    _unexpected_keys(missing, MISSING_CONTEXT_KEYS, f"missing_context[{index}]", errors)
    _require_keys(missing, MISSING_CONTEXT_KEYS, f"missing_context[{index}]", errors)
    _validate_text_field(missing.get("gap"), f"missing_context[{index}].gap", errors)
    _validate_text_field(missing.get("suggested_check"), f"missing_context[{index}].suggested_check", errors)
    if WRITE_OR_ADMIN_RE.search(str(missing.get("suggested_check", ""))):
      errors.append(_contract_error("unsafe_pivot", f"missing_context[{index}]: suggested_check contains write/admin/procedure language"))

  for index, pivot in enumerate(explanation.get("next_pivots") or []):
    if not isinstance(pivot, dict):
      errors.append(_contract_error("invalid_next_pivot", f"next_pivots[{index}] must be an object"))
      continue
    _unexpected_keys(pivot, NEXT_PIVOT_KEYS, f"next_pivots[{index}]", errors)
    _require_keys(pivot, NEXT_PIVOT_KEYS, f"next_pivots[{index}]", errors)
    _validate_text_field(pivot.get("question"), f"next_pivots[{index}].question", errors)
    _validate_enum(pivot.get("priority"), PRIORITY_VALUES, f"next_pivots[{index}].priority", errors)
    intent = pivot.get("suggested_query_intent")
    question = pivot.get("question", "")
    if not isinstance(intent, str) or not SAFE_INTENT_RE.match(intent):
      errors.append(_contract_error("unsafe_pivot", f"next_pivots[{index}]: suggested_query_intent is not a safe intent label"))
    if WRITE_OR_ADMIN_RE.search(str(intent)) or WRITE_OR_ADMIN_RE.search(str(question)):
      errors.append(_contract_error("unsafe_pivot", f"next_pivots[{index}]: pivot contains write/admin/procedure language"))

  _validate_text_embedded_ids(explanation, context, errors)
  return errors


def _validate_packet_and_explanation(packet: Any, explanation: Any) -> tuple[list[Dict[str, str]], Dict[str, Any]]:
  packet_errors, context = _validate_graph_evidence_packet(packet)
  if packet_errors:
    return packet_errors, context
  return _validate_case_explanation(explanation, context), context


def _case_explanation_response_format() -> Dict[str, Any]:
  return {
    "type": "json_schema",
    "schema": CASE_EXPLANATION_RESPONSE_SCHEMA,
  }


def _build_case_explanation_messages(packet: Dict[str, Any]) -> list[Dict[str, str]]:
  return [
    {
      "role": "system",
      "content": "\n".join([
        "You explain bounded EdgeGuard graph evidence for a security analyst.",
        "Return only strict JSON with schema_version edgeguard.case_explanation.v1.",
        "Use only facts present in the graph evidence packet.",
        "Every material claim must cite packet node or relationship evidence IDs.",
        "Do not invent sources, entities, relationships, severity, confidence, or timestamps.",
        "Include caveat types broadening, truncation, and limit_adjusted whenever packet flags require them.",
        "next_pivots.suggested_query_intent must be a safe intent label, not executable Cypher.",
      ]),
    },
    {
      "role": "user",
      "content": json.dumps(packet, sort_keys=True),
    },
  ]


_CONFIG = {
  **BasePlugin.CONFIG,

  "TUNNEL_ENGINE_ENABLED": False,
  "ALLOW_EMPTY_INPUTS": True,
  "RESPONSE_FORMAT": "RAW",
  "PORT": None,

  "API_TITLE": "EdgeGuard API",
  "API_SUMMARY": "Guarded EdgeGuard text-to-Cypher and playground Neo4j API.",

  "EDGEGUARD_EXPLANATION_MODEL_URL": None,
  "EDGEGUARD_EXPLANATION_MODEL_HOST": "127.0.0.1",
  "EDGEGUARD_EXPLANATION_MODEL_PORT": None,
  "EDGEGUARD_EXPLANATION_MODEL_PATH": "/create_chat_completion",
  "EDGEGUARD_EXPLANATION_MODEL_TOKEN": None,
  "EDGEGUARD_EXPLANATION_MODEL_TOKEN_ENV": "EDGEGUARD_EXPLANATION_MODEL_TOKEN",
  "EDGEGUARD_EXPLANATION_MODEL": None,
  "EDGEGUARD_EXPLANATION_DEFAULT_ROWS": EXPLANATION_DEFAULT_ROWS,
  "EDGEGUARD_EXPLANATION_MAX_ROWS": EXPLANATION_SERVER_MAX_ROWS,
  "EDGEGUARD_EXPLANATION_MAX_TOKENS": 1600,
  "EDGEGUARD_EXPLANATION_TEMPERATURE": 0.0,
  "EDGEGUARD_EXPLANATION_TOP_P": 1.0,

  "NEO4J_MAX_ROWS": 100,
  "NEO4J_QUERY_TIMEOUT_SECONDS": 30,
  "LIVE_EMPTY_RESULT_BROADENING": True,
  "REQUEST_TIMEOUT": EDGEGUARD_REQUEST_TIMEOUT_SECONDS,
  "REQUEST_TIMEOUT_SECONDS": EDGEGUARD_REQUEST_TIMEOUT_SECONDS,
  "EDGEGUARD_VERBOSE": 10,
  "ENABLE_CYBERSEC_EXPERIMENTAL_MODEL": False,

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
    self._explanation_token = self._resolve_secret(
      explicit=self.cfg_edgeguard_explanation_model_token,
      env_name=self.cfg_edgeguard_explanation_model_token_env,
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

  def _explanation_headers(self) -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if self._explanation_token:
      headers["Authorization"] = f"Bearer {self._explanation_token}"
    return headers

  def _explanation_url(self, path: Optional[str] = None) -> tuple[Optional[str], Optional[str]]:
    endpoint = path if path is not None else self.cfg_edgeguard_explanation_model_path
    endpoint = str(endpoint or "/create_chat_completion").strip()
    if not endpoint.startswith("/"):
      endpoint = "/" + endpoint
    configured_url = self.cfg_edgeguard_explanation_model_url
    if configured_url:
      url = str(configured_url).rstrip("/")
      if not url.endswith(endpoint):
        url = url + endpoint
    else:
      host = self.cfg_edgeguard_explanation_model_host
      port = self.cfg_edgeguard_explanation_model_port
      if not host or not port:
        return None, "EdgeGuard explanation model port or URL not configured"
      url = f"http://{host}:{int(port)}{endpoint}"
    parsed = urlsplit(url)
    if parsed.hostname not in LOCAL_EXPLANATION_HOSTS:
      return None, "EdgeGuard graph explanation packets are local-only; configure a localhost explanation endpoint"
    return url, None

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

  def _extract_assistant_content(self, response: Dict[str, Any]) -> Optional[str]:
    if not isinstance(response, dict):
      return None
    if isinstance(response.get("result"), dict):
      return self._extract_assistant_content(response["result"])
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
    return None

  def _build_explanation_payload(
    self,
    packet: Dict[str, Any],
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    top_p: Optional[float] = None,
  ) -> Dict[str, Any]:
    payload = {
      "messages": _build_case_explanation_messages(packet),
      "temperature": self.cfg_edgeguard_explanation_temperature if temperature is None else temperature,
      "max_tokens": min(
        int(max_tokens or self.cfg_edgeguard_explanation_max_tokens),
        int(self.cfg_edgeguard_explanation_max_tokens),
      ),
      "top_p": self.cfg_edgeguard_explanation_top_p if top_p is None else top_p,
      "response_format": _case_explanation_response_format(),
      "metadata": {
        "task": "edgeguard_graph_explanation",
        "schema_version": CASE_EXPLANATION_SCHEMA_VERSION,
      },
    }
    if self.cfg_edgeguard_explanation_model:
      payload["model"] = self.cfg_edgeguard_explanation_model
    return payload

  def _call_explanation_model(
    self,
    packet: Dict[str, Any],
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    top_p: Optional[float] = None,
  ) -> Dict[str, Any]:
    url, err = self._explanation_url()
    if err:
      return {"status": "config_error", "error": err}
    try:
      self.Pd(f"Calling EdgeGuard explanation model API: {self._redact_url(url)}")
      session = requests.Session()
      session.trust_env = False
      response = session.post(
        url,
        headers=self._explanation_headers(),
        json=self._build_explanation_payload(packet, temperature, max_tokens, top_p),
        timeout=self.cfg_request_timeout_seconds,
      )
      if response.status_code != 200:
        return {
          "status": STATUS_ERROR,
          "error": f"EdgeGuard explanation model returned status {response.status_code}",
          "provider_status": response.status_code,
        }
      data = response.json()
      if isinstance(data, dict) and data.get("status") in {STATUS_ERROR, STATUS_TIMEOUT, "failed", "config_error"}:
        return {
          "status": STATUS_ERROR,
          "error": data.get("error") or data.get("result") or "EdgeGuard explanation model failed",
          "provider": data.get("provider", "local"),
        }
      content = self._extract_assistant_content(data)
      if content is None:
        return {
          "status": STATUS_ERROR,
          "error": "EdgeGuard explanation model response did not contain assistant content",
        }
      try:
        explanation = json.loads(content)
      except json.JSONDecodeError as exc:
        return {
          "status": STATUS_REJECTED,
          "error": "EdgeGuard explanation model returned malformed JSON",
          "validation_errors": [_contract_error("malformed_json", str(exc))],
          "raw_output": content,
        }
      if not isinstance(explanation, dict):
        return {
          "status": STATUS_REJECTED,
          "error": "EdgeGuard explanation model returned non-object JSON",
          "validation_errors": [_contract_error("invalid_explanation", "explanation must be an object")],
          "raw_output": content,
        }
      errors, _context = _validate_packet_and_explanation(packet, explanation)
      if errors:
        return {
          "status": STATUS_REJECTED,
          "error": "EdgeGuard explanation failed deterministic validation",
          "validation_errors": errors,
          "explanation": explanation,
        }
      return {
        "status": STATUS_ACCEPTED,
        "explanation": explanation,
        "provider": data.get("provider", "local") if isinstance(data, dict) else "local",
        "model": data.get("model") if isinstance(data, dict) else self.cfg_edgeguard_explanation_model,
      }
    except requests.exceptions.Timeout:
      return {"status": STATUS_TIMEOUT, "error": "EdgeGuard explanation model request timed out"}
    except requests.exceptions.RequestException as exc:
      return {"status": STATUS_ERROR, "error": str(exc)}
    except Exception as exc:
      self.P(f"Unexpected EdgeGuard explanation model error: {exc}\n{traceback.format_exc()}", color='r')
      return {"status": STATUS_ERROR, "error": f"Unexpected explanation model error: {exc}"}

  @BasePlugin.endpoint(method="GET")
  def health(self) -> Dict[str, Any]:
    explanation_url, explanation_error = self._explanation_url()
    return {
      "status": STATUS_OK,
      "version": __VER__,
      "schema_version": SCHEMA_VERSION,
      "graph_explanation_schema_version": CASE_EXPLANATION_SCHEMA_VERSION,
      "model_repo": EDGEGUARD_MODEL_REPO,
      "model_file": EDGEGUARD_MODEL_FILE,
      "generation_orchestrator": "playground_server_route",
      "explanation_model_url": self._redact_url(explanation_url),
      "explanation_model_configured": bool(explanation_url),
      "explanation_model_config_error": explanation_error,
      "neo4j_driver_available": GraphDatabase is not None,
      "live_empty_result_broadening": bool(self.cfg_live_empty_result_broadening),
      "metrics": {
        "total_requests": self._request_count,
        "failed_requests": self._error_count,
        "last_request_time": self._last_request_time,
      },
    }

  @BasePlugin.endpoint(method="GET")
  def models(self) -> Dict[str, Any]:
    models = list(EDGEGUARD_MODEL_CATALOG)
    if self.cfg_enable_cybersec_experimental_model:
      models.append(CYBERSEC_MODEL_CATALOG_ENTRY)
    return {
      "schema_version": "edgeguard.model_catalog.v1",
      "default_model_key": FINETUNED_MODEL_KEY,
      "models": models,
    }

  @BasePlugin.endpoint(method="GET")
  def prompt_contract(self) -> Dict[str, Any]:
    direct_system_prompt = build_direct_cypher_system_prompt()
    correction_prompt = build_schema_correction_prompt(
      original_user_prompt="{normalized_request}",
      rejected_cypher="{candidate_cypher}",
      validation_feedback="{validation_feedback}",
      retry_index=1,
      retry_limit=DEFAULT_SCHEMA_RETRY_LIMIT,
    )
    profiles = [
      {
        "prompt_profile_id": FINETUNED_PROMPT_PROFILE_ID,
        "model_key": FINETUNED_MODEL_KEY,
        "template_version": "edgeguard-direct-cypher-v0.10",
        "system_prompt_sha256": _sha256_text(direct_system_prompt),
        "correction_prompt_sha256": _sha256_text(correction_prompt),
        "expected_output": "one read-only Cypher query string only",
      },
      {
        "prompt_profile_id": BASE_PROMPT_PROFILE_ID,
        "model_key": BASE_MODEL_KEY,
        "template_version": "edgeguard-base-schema-grounded-v0.10",
        "system_prompt_sha256": None,
        "correction_prompt_sha256": _sha256_text(correction_prompt),
        "expected_output": "one schema-grounded read-only Cypher query string only",
      },
    ]
    if self.cfg_enable_cybersec_experimental_model:
      profiles.append({
        "prompt_profile_id": CYBERSEC_PROMPT_PROFILE_ID,
        "model_key": CYBERSEC_MODEL_KEY,
        "template_version": "edgeguard-cybersec-schema-grounded-v0.10",
        "system_prompt_sha256": None,
        "correction_prompt_sha256": _sha256_text(correction_prompt),
        "expected_output": "one schema-grounded read-only Cypher query string only",
      })
    return {
      "schema_version": "edgeguard.prompt_contract.v1",
      "cypher_schema_version": SCHEMA_VERSION,
      "schema_surface": canonical_schema_surface(),
      "temporal_policy": EDGEGUARD_SCHEMA["unsupported"]["temporal_predicates"],
      "retry_default": DEFAULT_SCHEMA_RETRY_LIMIT,
      "profiles": profiles,
    }

  @BasePlugin.endpoint(method="GET")
  def model(self) -> Dict[str, Any]:
    return {
      "model_key": FINETUNED_MODEL_KEY,
      "display_name": EDGEGUARD_MODEL_DISPLAY_NAME,
      "model_repo": EDGEGUARD_MODEL_REPO,
      "model_file": EDGEGUARD_MODEL_FILE,
      "format": "GGUF",
      "quantization": "Q4_K_M",
      "base_model": "Qwen/Qwen3-4B-Instruct-2507",
      "continuation_of": "ratio1/edgeguard-cypher-qwen3-4b-v0.9-graph-intent-gguf",
      "artifact_sha256": EDGEGUARD_MODEL_ARTIFACT_SHA256,
      "schema_version": SCHEMA_VERSION,
      "schema": canonical_schema_surface(),
      "prompt_profile_id": FINETUNED_PROMPT_PROFILE_ID,
      "guard": {
        "read_only_static": True,
        "schema_compatible": True,
        "generation_validation_owner": "playground_server_route_via_check_cypher",
        "execution_revalidates": True,
        "live_empty_result_broadening": bool(self.cfg_live_empty_result_broadening),
        "live_empty_result_broadening_strategy": "first_allowed_label_first_allowed_relationship_type",
        "output_contract": "one Cypher query string only",
      },
      "graph_explanation": {
        "status": "prototype",
        "packet_schema_version": GRAPH_PACKET_SCHEMA_VERSION,
        "case_explanation_schema_version": CASE_EXPLANATION_SCHEMA_VERSION,
        "provider_config_separate": True,
        "provider_default": "local-only",
        "default_rows": int(self.cfg_edgeguard_explanation_default_rows),
        "server_max_rows": int(self.cfg_edgeguard_explanation_max_rows),
        "quality": "EGM-030 Phase 1 lower-bound baseline only; not promoted for fine-tuning.",
      },
      "fine_tuning": {
        "method": "QLoRA SFT",
        "dataset": EDGEGUARD_DATASET,
        "source_adapter": EDGEGUARD_SOURCE_ADAPTER,
        "source_adapter_sha256": EDGEGUARD_SOURCE_ADAPTER_SHA256,
      },
      "quality": {
        "generated_live_with_live_repair": "not applicable",
        "generated_live_with_empty_result_broadening": EDGEGUARD_RUNTIME_LIVE_GATE_RESULT,
        "robustness_expected_labels_covered": EDGEGUARD_ROBUSTNESS_LABEL_COVERAGE,
        "robustness_expected_relationships_covered": EDGEGUARD_ROBUSTNESS_RELATIONSHIP_COVERAGE,
        "robustness_subgraph_accepted": EDGEGUARD_ROBUSTNESS_SUBGRAPH_ACCEPTED,
        "test_expected_labels_covered": EDGEGUARD_TEST_LABEL_COVERAGE,
        "test_expected_relationships_covered": EDGEGUARD_TEST_RELATIONSHIP_COVERAGE,
        "training_corpus": EDGEGUARD_CORPUS,
        "planner_failures": 0,
        "scalar_projection_regressions": 0,
        "promotion_status": "Private v0.10 graph-intent candidate for EdgeGuard playground text-to-Cypher testing.",
        "live_repair_note": "The v0.10 graph-intent GGUF is the deployed model artifact.",
        "semantic_fidelity_risk": "Deterministic broadening can return a wider graph than the original request when the first live query is empty.",
      },
      "runtime_harness": {
        "version": EDGEGUARD_RUNTIME_HARNESS_VERSION,
        "empty_result_broadening": bool(self.cfg_live_empty_result_broadening),
        "empty_result_broadening_strategy": "first_allowed_label_first_allowed_relationship_type",
        "weights_note": "The deployed GGUF weights are the v0.10 graph-intent artifact.",
      },
    }

  @BasePlugin.endpoint(method="POST")
  def check_cypher(self, cypher: str, **kwargs) -> Dict[str, Any]:
    analysis = analyze_generated_cypher(cypher)
    return {
      "status": STATUS_ACCEPTED if analysis["accepted"] else STATUS_REJECTED,
      **analysis,
    }

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
    truncated = False
    with driver.session() as session:
      result = session.run(cypher)
      columns = list(getattr(result, "keys", lambda: [])())
      for idx, record in enumerate(result):
        if idx >= row_limit:
          truncated = True
          break
        rows.append(record.data() if hasattr(record, "data") else dict(record))
    return {
      "columns": columns,
      "rows": rows,
      "row_count": len(rows),
      "truncated": bool(truncated or len(rows) >= row_limit),
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

  @BasePlugin.endpoint(method="POST")
  def explain_graph(
    self,
    uri: str,
    username: str,
    password: str,
    cypher: str,
    request: str = "Explain the returned investigation graph.",
    scheme: str = "bolt+s",
    explanation_rows: Optional[int] = None,
    max_rows: Optional[int] = None,
    enable_empty_result_broadening: Optional[bool] = None,
    temperature: Optional[float] = None,
    max_tokens: Optional[int] = None,
    top_p: Optional[float] = None,
    **kwargs,
  ) -> Dict[str, Any]:
    analysis = analyze_generated_cypher(cypher)
    if not analysis["accepted"]:
      return {
        "status": STATUS_REJECTED,
        "ok": False,
        "executed": False,
        "explained": False,
        "validation": analysis,
        "error": "Cypher rejected by EdgeGuard guard; graph explanation was not executed.",
      }

    explanation_url, explanation_err = self._explanation_url()
    if explanation_err:
      return {
        "status": "config_error",
        "ok": False,
        "executed": False,
        "explained": False,
        "error": explanation_err,
      }

    normalized_uri, err = self._normalize_neo4j_uri(uri, scheme)
    if err:
      return {"status": STATUS_ERROR, "ok": False, "executed": False, "explained": False, "error": err}
    if not username or not password:
      return {
        "status": STATUS_ERROR,
        "ok": False,
        "executed": False,
        "explained": False,
        "error": "Neo4j username and password are required.",
      }
    if GraphDatabase is None:
      unavailable = self._neo4j_unavailable()
      unavailable.update({"executed": False, "explained": False})
      return unavailable

    requested_limit = explanation_rows if explanation_rows is not None else max_rows
    try:
      executed_cypher, generated_limit, executed_limit, limit_adjusted = _normalize_explanation_cypher_limit(
        analysis["accepted_cypher"],
        requested_limit=requested_limit,
      )
    except Exception as exc:
      return {
        "status": STATUS_ERROR,
        "ok": False,
        "executed": False,
        "explained": False,
        "error": f"Invalid explanation row limit: {exc}",
      }

    broadening_enabled = (
      bool(self.cfg_live_empty_result_broadening)
      if enable_empty_result_broadening is None
      else bool(enable_empty_result_broadening)
    )
    driver = None
    try:
      driver = self._neo4j_driver(normalized_uri, username, password)
      query_result = self._run_neo4j_query(driver, executed_cypher, executed_limit)
      live_retry = self._empty_result_broadening_state(enabled=broadening_enabled)
      final_executed_cypher = executed_cypher
      broadened_applied = False
      if broadening_enabled and not query_result["rows"]:
        broadened = build_empty_result_broadening_cypher(analysis["accepted_cypher"])
        if broadened is None:
          live_retry = self._empty_result_broadening_state(
            enabled=True,
            attempted=True,
            reason="empty_result_without_allowed_label_relationship_pair",
          )
        else:
          broadened_cypher = _replace_last_limit(broadened["cypher"], executed_limit)
          try:
            query_result = self._run_neo4j_query(driver, broadened_cypher, executed_limit)
            final_executed_cypher = broadened_cypher
            broadened_applied = True
            live_retry = self._empty_result_broadening_state(
              enabled=True,
              attempted=True,
              applied=True,
              reason="executed_no_rows",
              strategy=broadened["strategy"],
              broadening_cypher=broadened_cypher,
            )
          except Exception as exc:
            live_retry = self._empty_result_broadening_state(
              enabled=True,
              attempted=True,
              reason="broadening_execution_failed",
              strategy=broadened["strategy"],
              broadening_cypher=broadened_cypher,
              error=self._sanitize_error(exc, password),
            )

      packet, packet_meta = _build_graph_evidence_packet(
        request=request,
        accepted_cypher=analysis["accepted_cypher"],
        executed_cypher=final_executed_cypher,
        records=query_result["rows"],
        generated_limit=generated_limit,
        executed_limit=executed_limit,
        limit_adjusted=limit_adjusted,
        execution_truncated=bool(query_result.get("truncated")),
        broadened=broadened_applied,
        live_retry_reason=live_retry.get("reason") if broadened_applied else None,
      )
      packet_errors, _context = _validate_graph_evidence_packet(packet)
      if packet_errors:
        return {
          "status": STATUS_REJECTED,
          "ok": False,
          "executed": True,
          "explained": False,
          "error": "GraphEvidencePacket failed deterministic validation",
          "validation_errors": packet_errors,
          "packet": packet,
          "packet_meta": packet_meta,
          "live_retry": live_retry,
        }
      if not packet["graph"]["nodes"]:
        return {
          "status": "empty_graph",
          "ok": False,
          "executed": True,
          "explained": False,
          "error": "No graph evidence nodes were returned for explanation.",
          "packet": packet,
          "packet_meta": packet_meta,
          "validation": analysis,
          "live_retry": live_retry,
        }

      explanation_result = self._call_explanation_model(packet, temperature, max_tokens, top_p)
      if explanation_result.get("status") != STATUS_ACCEPTED:
        return {
          "status": explanation_result.get("status", STATUS_ERROR),
          "ok": False,
          "executed": True,
          "explained": False,
          "error": explanation_result.get("error", "EdgeGuard graph explanation failed"),
          "validation_errors": explanation_result.get("validation_errors", []),
          "packet": packet,
          "packet_meta": packet_meta,
          "validation": analysis,
          "live_retry": live_retry,
          "provider": explanation_result.get("provider"),
          "provider_status": explanation_result.get("provider_status"),
          "explanation": explanation_result.get("explanation"),
        }
      return {
        "status": STATUS_OK,
        "ok": True,
        "executed": True,
        "explained": True,
        "packet": packet,
        "packet_meta": packet_meta,
        "explanation": explanation_result["explanation"],
        "validation": analysis,
        "live_retry": live_retry,
        "provider": explanation_result.get("provider"),
        "model": explanation_result.get("model"),
        "explanation_model_url": self._redact_url(explanation_url),
      }
    except Exception as exc:
      return {
        "status": STATUS_ERROR,
        "ok": False,
        "executed": False,
        "explained": False,
        "error": self._sanitize_error(exc, password),
        "validation": analysis,
      }
    finally:
      self._close_neo4j_driver(driver)
