"""Credential-free EGM-038 output-mode gate against the local Qwen worker."""

from __future__ import annotations

import hashlib
import json
import sys
import time
from copy import deepcopy
from pathlib import Path
from typing import Any

import requests


ROOT = Path(__file__).resolve().parents[5]
if str(ROOT) not in sys.path:
  sys.path.insert(0, str(ROOT))

# The test module installs the same minimal import seam used by deterministic tests.
from extensions.business.cybersec.edgeguard.tests import test_api as _test_api  # noqa: E402,F401
from extensions.business.cybersec.edgeguard.edgeguard_api import (  # noqa: E402
  CASE_EXPLANATION_DRAFT_SCHEMA_VERSION,
  EXPLANATION_MAX_OUTPUT_TOKENS,
  EXPLANATION_MAX_PROMPT_USER_BYTES,
  EXPLANATION_OUTPUT_MODE_JSON_OBJECT,
  EXPLANATION_OUTPUT_MODE_JSON_SCHEMA,
  GRAPH_EXPLANATION_PROMPT_VERSION,
  QUERY_RESULT_EVIDENCE_SCHEMA_VERSION,
  EdgeguardApiPlugin,
  _build_graph_evidence_packet_from_execution,
  _construct_case_explanation,
  _explanation_validation_codes,
  _graph_explanation_prompt_sha256,
  _graph_explanation_user_content,
  _prepare_graph_explanation_plan,
  _validate_graph_evidence_packet,
)


MODEL_URL = "http://127.0.0.1:5091/create_chat_completion"
HEALTH_URL = "http://127.0.0.1:5091/health"
CALL_TIMEOUT_SECONDS = 480
IDLE_TIMEOUT_SECONDS = 630


def _sha256_json(value: Any) -> str:
  canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
  return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _node(raw_id: str, label: str, **properties: Any) -> dict[str, Any]:
  return {
    "id": raw_id,
    "labels": [label],
    "properties": properties,
    "caption": next((str(value) for value in properties.values() if value), label),
  }


def _five_pair_execution(cypher: str) -> dict[str, Any]:
  nodes = [
    _node("indicator-1", "Indicator", value="alpha.example"),
    _node("indicator-2", "Indicator", value="beta.example"),
    _node("indicator-3", "Indicator", value="gamma.example"),
    _node("malware-1", "Malware", name="ExampleLoader"),
    _node("malware-2", "Malware", name="ExampleStealer"),
  ]
  pairs = [
    ("indicator-1", "malware-1"),
    ("indicator-1", "malware-2"),
    ("indicator-2", "malware-1"),
    ("indicator-3", "malware-2"),
    ("indicator-1", "malware-1"),
  ]
  return {
    "executed_cypher": cypher,
    "primary_row_count": len(pairs),
    "row_count": len(pairs),
    "truncated": False,
    "broadened": False,
    "graph": {
      "nodes": nodes,
      "relationships": [],
      "truncated": False,
    },
    "query_result_evidence": {
      "schema_version": QUERY_RESULT_EVIDENCE_SCHEMA_VERSION,
      "columns": ["indicator", "malware"],
      "rows": [
        {
          "ordinal": ordinal,
          "values": [
            {"type": "node", "ref": indicator},
            {"type": "node", "ref": malware},
          ],
        }
        for ordinal, (indicator, malware) in enumerate(pairs)
      ],
    },
  }


def _mixed_execution(cypher: str, filler: str) -> dict[str, Any]:
  return {
    "executed_cypher": cypher,
    "primary_row_count": 1,
    "row_count": 1,
    "truncated": False,
    "broadened": False,
    "graph": {
      "nodes": [
        _node("indicator-mixed", "Indicator", value="mixed.example"),
        _node("source-mixed", "Source", name="Example Feed"),
      ],
      "relationships": [{
        "id": "relationship-mixed",
        "type": "SOURCED_FROM",
        "startNodeId": "indicator-mixed",
        "endNodeId": "source-mixed",
        "properties": {"confidence": "medium"},
        "caption": "SOURCED_FROM",
      }],
      "truncated": False,
    },
    "query_result_evidence": {
      "schema_version": QUERY_RESULT_EVIDENCE_SCHEMA_VERSION,
      "columns": [
        "path",
        "nullable",
        "aggregate",
        "ratio",
        "observed_at",
        "point",
        "items",
        "mapping",
        "note",
      ],
      "rows": [{
        "ordinal": 0,
        "values": [
          {
            "type": "path",
            "start_node_ref": "indicator-mixed",
            "end_node_ref": "source-mixed",
            "segments": [{
              "start_node_ref": "indicator-mixed",
              "relationship_ref": "relationship-mixed",
              "end_node_ref": "source-mixed",
            }],
          },
          {"type": "null"},
          {"type": "integer", "value": "9007199254740993"},
          {"type": "float", "value": 0.875},
          {"type": "temporal", "temporal_type": "date_time", "value": "2026-07-20T00:00:00Z"},
          {"type": "point", "srid": "4326", "x": 13.405, "y": 52.52},
          {
            "type": "list",
            "items": [
              {"type": "string", "value": "mixed.example"},
              {"type": "null"},
              {"type": "integer", "value": "2"},
            ],
          },
          {
            "type": "map",
            "entries": [
              {"key": "source", "value": {"type": "string", "value": "Example Feed"}},
              {"key": "count", "value": {"type": "integer", "value": "2"}},
            ],
          },
          {"type": "string", "value": filler},
        ],
      }],
    },
  }


def _ingest_fixture(
  *,
  name: str,
  question: str,
  cypher: str,
  execution_result: dict[str, Any],
) -> dict[str, Any]:
  plan = _prepare_graph_explanation_plan(cypher)
  if not plan.get("ok"):
    raise RuntimeError(f"{name}: fixture Cypher was rejected")
  packet, meta, errors = _build_graph_evidence_packet_from_execution(
    request=question,
    plan=plan,
    execution_result=execution_result,
  )
  if errors:
    raise RuntimeError(f"{name}: ingestion failed with {_explanation_validation_codes(errors)}")
  query_result = meta.pop("_query_result_evidence")
  catalog = meta.pop("_evidence_catalog")
  packet_errors, _context = _validate_graph_evidence_packet(packet)
  if packet_errors:
    raise RuntimeError(f"{name}: packet failed with {_explanation_validation_codes(packet_errors)}")
  user_content = _graph_explanation_user_content(packet, query_result, catalog)
  return {
    "name": name,
    "packet": packet,
    "query_result": query_result,
    "catalog": catalog,
    "user_bytes": len(user_content.encode("utf-8")),
    "fixture_sha256": _sha256_json({
      "packet": packet,
      "query_result": query_result,
      "catalog": catalog,
    }),
    "user_prompt_sha256": hashlib.sha256(user_content.encode("utf-8")).hexdigest(),
  }


def _build_fixtures() -> dict[str, dict[str, Any]]:
  pair_cypher = (
    "MATCH (i:Indicator)-[:INDICATES]->(m:Malware) "
    "RETURN i AS indicator, m AS malware LIMIT 25"
  )
  pair = _ingest_fixture(
    name="five_pairs",
    question="Which malware is paired with each returned indicator?",
    cypher=pair_cypher,
    execution_result=_five_pair_execution(pair_cypher),
  )

  mixed_cypher = (
    "MATCH p=(i:Indicator)-[:SOURCED_FROM]->(s:Source) "
    "RETURN p AS path, i.value AS nullable, count(*) AS aggregate, "
    "i.value AS ratio, i.value AS observed_at, i.value AS point, "
    "i.value AS items, s.name AS mapping, s.name AS note LIMIT 25"
  )
  base = _ingest_fixture(
    name="mixed_near_limit",
    question="Summarize the mixed returned evidence and its provenance.",
    cypher=mixed_cypher,
    execution_result=_mixed_execution(mixed_cypher, ""),
  )
  filler_bytes = EXPLANATION_MAX_PROMPT_USER_BYTES - base["user_bytes"]
  selected = _ingest_fixture(
    name="mixed_near_limit",
    question="Summarize the mixed returned evidence and its provenance.",
    cypher=mixed_cypher,
    execution_result=_mixed_execution(mixed_cypher, "x" * filler_bytes),
  )
  if selected["user_bytes"] != EXPLANATION_MAX_PROMPT_USER_BYTES:
    raise RuntimeError("mixed fixture could not be tuned to exactly 3,300 UTF-8 bytes")
  return {"five_pairs": pair, "mixed_near_limit": selected}


def _active_requests() -> int:
  response = requests.get(HEALTH_URL, timeout=10)
  response.raise_for_status()
  body = response.json()
  return int(body["result"]["metrics"]["requests_active"])


def _wait_for_idle() -> None:
  deadline = time.monotonic() + IDLE_TIMEOUT_SECONDS
  while time.monotonic() < deadline:
    if _active_requests() == 0:
      return
    time.sleep(2)
  raise RuntimeError("Qwen worker did not return to zero active requests")


def _plugin() -> EdgeguardApiPlugin:
  plugin = EdgeguardApiPlugin.__new__(EdgeguardApiPlugin)
  plugin.cfg_edgeguard_explanation_max_tokens = EXPLANATION_MAX_OUTPUT_TOKENS
  plugin.cfg_edgeguard_explanation_temperature = 0.0
  plugin.cfg_edgeguard_explanation_top_p = 1.0
  plugin.cfg_edgeguard_explanation_model = None
  plugin.cfg_edgeguard_explanation_output_mode = EXPLANATION_OUTPUT_MODE_JSON_OBJECT
  return plugin


def _score_call(
  plugin: EdgeguardApiPlugin,
  fixture: dict[str, Any],
  output_mode: str,
) -> dict[str, Any]:
  _wait_for_idle()
  payload = plugin._build_explanation_payload(
    fixture["packet"],
    fixture["query_result"],
    fixture["catalog"],
    output_mode=output_mode,
  )
  started = time.monotonic()
  response = requests.post(MODEL_URL, json=payload, timeout=CALL_TIMEOUT_SECONDS)
  elapsed = time.monotonic() - started
  response.raise_for_status()
  completion = plugin._extract_explanation_completion(response.json())
  content = completion.get("content")
  errors = []
  if not isinstance(content, str):
    errors = [{"code": "missing_content"}]
  else:
    try:
      draft = json.loads(content)
    except json.JSONDecodeError:
      errors = [{"code": "malformed_json"}]
    else:
      _explanation, errors = _construct_case_explanation(
        draft,
        fixture["packet"],
        fixture["packet"],
      )
  finish_reason = completion.get("finish_reason")
  completion_tokens = completion.get("completion_tokens")
  validation_codes = _explanation_validation_codes(errors)
  passed = (
    elapsed < CALL_TIMEOUT_SECONDS
    and finish_reason == "stop"
    and isinstance(completion_tokens, int)
    and not isinstance(completion_tokens, bool)
    and completion_tokens < EXPLANATION_MAX_OUTPUT_TOKENS
    and not validation_codes
  )
  _wait_for_idle()
  return {
    "fixture": fixture["name"],
    "mode": output_mode,
    "elapsed_seconds": round(elapsed, 3),
    "finish_reason": finish_reason,
    "completion_tokens": completion_tokens,
    "validation_codes": validation_codes,
    "passed": passed,
  }


def main() -> int:
  fixtures = _build_fixtures()
  print(json.dumps({
    "event": "gate_start",
    "prompt_version": GRAPH_EXPLANATION_PROMPT_VERSION,
    "prompt_sha256": _graph_explanation_prompt_sha256(),
    "draft_schema_version": CASE_EXPLANATION_DRAFT_SCHEMA_VERSION,
    "fixtures": {
      name: {
        "fixture_sha256": fixture["fixture_sha256"],
        "user_prompt_sha256": fixture["user_prompt_sha256"],
        "user_bytes": fixture["user_bytes"],
      }
      for name, fixture in fixtures.items()
    },
  }, sort_keys=True))

  schedule = [
    ("five_pairs", EXPLANATION_OUTPUT_MODE_JSON_SCHEMA),
    ("mixed_near_limit", EXPLANATION_OUTPUT_MODE_JSON_OBJECT),
    ("mixed_near_limit", EXPLANATION_OUTPUT_MODE_JSON_SCHEMA),
    ("five_pairs", EXPLANATION_OUTPUT_MODE_JSON_OBJECT),
    ("five_pairs", EXPLANATION_OUTPUT_MODE_JSON_SCHEMA),
    ("mixed_near_limit", EXPLANATION_OUTPUT_MODE_JSON_OBJECT),
    ("mixed_near_limit", EXPLANATION_OUTPUT_MODE_JSON_SCHEMA),
    ("five_pairs", EXPLANATION_OUTPUT_MODE_JSON_OBJECT),
  ]
  plugin = _plugin()
  results = []
  try:
    for index, (fixture_name, output_mode) in enumerate(schedule, start=1):
      result = _score_call(plugin, fixtures[fixture_name], output_mode)
      result["call"] = index
      results.append(result)
      print(json.dumps({"event": "call_result", **result}, sort_keys=True))
  except requests.exceptions.Timeout:
    print(json.dumps({"event": "gate_stopped", "reason": "caller_timeout"}, sort_keys=True))
    _wait_for_idle()
    return 2

  mode_passes = {
    mode: all(
      result["passed"]
      for result in results
      if result["mode"] == mode
    )
    for mode in (EXPLANATION_OUTPUT_MODE_JSON_SCHEMA, EXPLANATION_OUTPUT_MODE_JSON_OBJECT)
  }
  selected_mode = (
    EXPLANATION_OUTPUT_MODE_JSON_SCHEMA
    if mode_passes[EXPLANATION_OUTPUT_MODE_JSON_SCHEMA]
    else (
      EXPLANATION_OUTPUT_MODE_JSON_OBJECT
      if mode_passes[EXPLANATION_OUTPUT_MODE_JSON_OBJECT]
      else None
    )
  )
  print(json.dumps({
    "event": "gate_complete",
    "calls": len(results),
    "mode_passes": mode_passes,
    "selected_mode": selected_mode,
  }, sort_keys=True))
  return 0 if selected_mode else 1


if __name__ == "__main__":
  raise SystemExit(main())
