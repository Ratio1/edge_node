"""Deterministic, lossless presentation digest for validated Neo4j results.

The digest is deliberately built before inference.  It groups duplicate rows for
concise presentation while retaining every source ordinal and every canonical
entity/path reference, so a model failure cannot erase query-result coverage.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .graph_first_explanation import build_evidence_ir, thaw


DIGEST_SCHEMA_VERSION = "edgeguard.result_digest.v1"
DIGEST_COVERAGE_SCHEMA_VERSION = "edgeguard.result_digest_coverage.v2"
PROJECTION_DIGEST_SCHEMA_VERSION = "edgeguard.projection_digest.v1"
# Contract §4.3, playground validator (`explanation-contract-v1.ts`): the
# response transport caps for a `ranked_projection` result.
PROJECTION_DIGEST_MAX_ROWS = 50
PROJECTION_DIGEST_MAX_COLUMNS = 64


def _properties(entity: Any) -> list[list[Any]]:
  return [[key, thaw(value)] for key, value in entity.properties]


def build_result_digest(
  query_result_evidence: Mapping[str, Any],
  evidence_catalog: Mapping[str, Any],
  *,
  accepted_cypher: str,
  executed_cypher: str,
  transport_row_cap: int,
  truncated: bool,
  query_scope: str = "exact",
) -> dict[str, Any]:
  """Return a byte-stable digest in canonical alias/source order."""
  ir = build_evidence_ir(query_result_evidence, evidence_catalog)
  relationship_by_alias = {item.alias: item for item in ir.relationships}
  path_by_alias = {item.alias: item for item in ir.paths}
  returned_ordinals = tuple(range(len(query_result_evidence["rows"])))
  represented_ordinals = tuple(
    ordinal for row in ir.rows for ordinal in row.ordinals
  )
  groups = []
  relationship_types = set()
  for row in ir.rows:
    row_types = {
      relationship_by_alias[alias].type for alias in row.relationship_aliases
    }
    path_shapes = []
    for alias in row.path_aliases:
      path = path_by_alias[alias]
      types = [relationship_by_alias[step[1]].type for step in path.steps]
      row_types.update(types)
      path_shapes.append({
        "path_ref": alias,
        "start_ref": path.start_alias,
        "end_ref": path.end_alias,
        "relationship_types": types,
      })
    relationship_types.update(row_types)
    groups.append({
      "id": row.alias,
      "row_ordinals": list(row.ordinals),
      "occurrences": len(row.ordinals),
      "node_refs": list(row.node_aliases),
      "relationship_refs": list(row.relationship_aliases),
      "path_refs": list(row.path_aliases),
      "relationship_types": sorted(row_types),
      "path_shapes": path_shapes,
      "values": thaw(row.values),
    })
  returned_row_set = set(returned_ordinals)
  represented_row_set = set(represented_ordinals)
  missing = sorted(returned_row_set.difference(represented_row_set))
  unexpected = sorted(represented_row_set.difference(returned_row_set))
  repeated = sorted({ordinal for ordinal in represented_ordinals if represented_ordinals.count(ordinal) > 1})
  returned_paths = [item.alias for item in ir.paths]
  represented_path_set = {alias for row in ir.rows for alias in row.path_aliases}
  represented_paths = [alias for alias in returned_paths if alias in represented_path_set]
  missing_paths = sorted(set(returned_paths).difference(represented_paths))
  returned_nodes = [item.alias for item in ir.nodes]
  represented_node_set = {alias for row in ir.rows for alias in row.node_aliases}
  represented_nodes = [alias for alias in returned_nodes if alias in represented_node_set]
  missing_nodes = sorted(set(returned_nodes).difference(represented_nodes))
  returned_relationships = [item.alias for item in ir.relationships]
  represented_relationship_set = {alias for row in ir.rows for alias in row.relationship_aliases}
  represented_relationships = [alias for alias in returned_relationships if alias in represented_relationship_set]
  missing_relationships = sorted(set(returned_relationships).difference(represented_relationships))
  returned_components = [f"C{index}" for index in range(len(ir.components))]
  represented_component_set = {f"C{index}" for row in ir.rows for index in row.component_ids}
  represented_components = [alias for alias in returned_components if alias in represented_component_set]
  missing_components = sorted(set(returned_components).difference(represented_components))
  returned_property_slots = sorted(
    [[item.alias, key] for item in (*ir.nodes, *ir.relationships) for key, _value in item.properties]
  )
  represented_entity_refs = set(represented_nodes) | set(represented_relationships)
  represented_property_slots = [
    slot for slot in returned_property_slots if slot[0] in represented_entity_refs
  ]
  missing_property_slots = [
    slot for slot in returned_property_slots if slot not in represented_property_slots
  ]
  coverage_complete = not any((
    missing,
    unexpected,
    repeated,
    missing_paths,
    missing_nodes,
    missing_relationships,
    missing_components,
    missing_property_slots,
  ))
  duplicated = sum(max(0, len(row.ordinals) - 1) for row in ir.rows)
  type_list = sorted(relationship_types)
  summary_text = (
    "The exact query returned no rows and therefore no graph evidence."
    if not returned_ordinals
    else (
      f"The exact query returned {len(returned_ordinals)} rows represented by "
      f"{len(ir.rows)} distinct row groups, {len(ir.nodes)} nodes, "
      f"{len(ir.relationships)} relationships, and {len(ir.components)} topology components."
    )
  )
  if type_list:
    summary_text += " Relationship types: " + ", ".join(type_list) + "."
  if duplicated:
    summary_text += f" {duplicated} duplicate row occurrences are retained in the coverage ledger."
  if truncated:
    summary_text += f" The transport stopped at its {transport_row_cap}-row safety cap."
  return {
    "schema_version": DIGEST_SCHEMA_VERSION,
    "semantic_sha256": ir.semantic_sha256,
    "query_scope": {
      "mode": query_scope,
      "accepted_equals_executed": accepted_cypher == executed_cypher,
      "transport_row_cap": transport_row_cap,
      "truncated": bool(truncated),
    },
    "summary": {
      "text": summary_text,
      "relationship_types": type_list,
    },
    "counts": {
      "returned_rows": len(returned_ordinals),
      "distinct_row_groups": len(ir.rows),
      "duplicate_row_occurrences": duplicated,
      "nodes": len(ir.nodes),
      "relationships": len(ir.relationships),
      "paths": len(ir.paths),
      "topology_components": len(ir.components),
    },
    "coverage": {
      "schema_version": DIGEST_COVERAGE_SCHEMA_VERSION,
      "rows": {
        "returned": list(returned_ordinals),
        "represented": sorted(represented_ordinals),
        "missing": missing,
        "unexpected": unexpected,
        "repeated": repeated,
      },
      "paths": {
        "returned": returned_paths,
        "represented": represented_paths,
        "missing": missing_paths,
      },
      "nodes": {
        "returned": returned_nodes,
        "represented": represented_nodes,
        "missing": missing_nodes,
      },
      "relationships": {
        "returned": returned_relationships,
        "represented": represented_relationships,
        "missing": missing_relationships,
      },
      "topology_components": {
        "returned": returned_components,
        "represented": represented_components,
        "missing": missing_components,
      },
      "property_slots": {
        "returned": returned_property_slots,
        "represented": represented_property_slots,
        "missing": missing_property_slots,
      },
      "complete": coverage_complete,
    },
    "groups": groups,
    "exact_inventory": {
      "columns": list(ir.columns),
      "nodes": [
        {
          "ref": item.alias,
          "labels": list(item.labels),
          "properties": _properties(item),
        }
        for item in ir.nodes
      ],
      "relationships": [
        {
          "ref": item.alias,
          "type": item.type,
          "start_ref": item.start_alias,
          "end_ref": item.end_alias,
          "properties": _properties(item),
        }
        for item in ir.relationships
      ],
      "paths": [
        {
          "ref": item.alias,
          "start_ref": item.start_alias,
          "end_ref": item.end_alias,
          "steps": [list(step) for step in item.steps],
        }
        for item in ir.paths
      ],
    },
  }


def build_projection_digest(
  query_result_evidence: Mapping[str, Any],
  *,
  ranking_rule: str,
  truncated: bool = False,
) -> dict[str, Any]:
  """Contract §4.2, §4.3: `columns`, tagged rows (the same tagger
  `_legacy_query_result_value` uses for `result_digest`), `row_count`,
  `truncated`, `ranking_rule`, `sha256` — emitted beside `result_digest` for
  `ranked_projection` results only.

  Unlike `result_digest`, rows are kept in their exact returned order and are
  never grouped or deduplicated: a `ranked_projection`'s row order *is* the
  ranking. Truncation and column counts stay inside the playground contract
  validator's caps (`PROJECTION_DIGEST_MAX_ROWS`/`_COLUMNS`).
  """
  columns = [str(column) for column in query_result_evidence.get("columns", [])]
  if len(columns) > PROJECTION_DIGEST_MAX_COLUMNS:
    raise ValueError("projection_digest columns exceed the playground contract cap")
  source_rows = list(query_result_evidence.get("rows", []))
  row_truncated = bool(truncated) or len(source_rows) > PROJECTION_DIGEST_MAX_ROWS
  rows = []
  for row in source_rows[:PROJECTION_DIGEST_MAX_ROWS]:
    values = list(row["values"])
    if len(values) != len(columns):
      raise ValueError("projection_digest row values do not match its declared columns")
    rows.append({"ordinal": len(rows), "values": values})
  ranking_rule_text = str(ranking_rule or "").strip() or "unranked"
  payload = {
    "schema_version": PROJECTION_DIGEST_SCHEMA_VERSION,
    "columns": columns,
    "rows": rows,
    "row_count": len(rows),
    "truncated": bool(row_truncated),
    "ranking_rule": ranking_rule_text,
  }
  sha256 = hashlib.sha256(
    json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
  ).hexdigest()
  return {**payload, "sha256": sha256}
