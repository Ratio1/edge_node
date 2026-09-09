"""Codec-neutral graph-first evidence core for EGM-042.

This module is deliberately not imported by ``edgeguard_api`` until a tournament
winner is selected.  It accepts pure renderer/measurement callbacks so research
codecs and tokenizer loaders cannot become production dependencies accidentally.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
import unicodedata
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any, Optional


IR_VERSION = "edgeguard.evidence_ir.v1"
COVERAGE_VERSION = "edgeguard.explanation_coverage.v1"
CASE_EXPLANATION_VERSION = "edgeguard.case_explanation.v1"
PROPERTY_PROFILE_VERSION = "edgeguard.property_view.v1"
PROPERTY_PROFILE_SHA256 = "7143453d0857456a3e30fa8e3261a95e8f7f03442958223c4ccfc14a472ea964"
MODEL_MESSAGE_LIMIT = 2_200
TRANSPORT_LIMIT = 3_300
COMPLETION_TOKEN_LIMIT = 128
MAX_ROW_GROUPS_PER_BATCH = 8
IDENTITY_KEYS = frozenset({"cve_id", "element_id", "id", "indicator", "name", "value"})
BAND2_KEYS = frozenset({
  "confidence", "created_at", "cvss_score", "provenance", "severity", "source",
  "timestamp", "updated_at",
})
MODE_CAPS = {
  "fast": (10, 1),
  "balanced": (25, 2),
  "thorough": (50, 3),
}
ALIAS_RE = {
  "node": re.compile(r"N(?:0|[1-9][0-9]*)\Z"),
  "relationship": re.compile(r"E(?:0|[1-9][0-9]*)\Z"),
  "path": re.compile(r"P(?:0|[1-9][0-9]*)\Z"),
  "row": re.compile(r"R(?:0|[1-9][0-9]*)\Z"),
}
CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")


class GraphFirstContractError(ValueError):
  """Stable fail-closed contract error."""

  def __init__(self, code: str, detail: str):
    super().__init__(detail)
    self.code = code
    self.detail = detail


@dataclasses.dataclass(frozen=True)
class FrozenList:
  items: tuple[Any, ...]


@dataclasses.dataclass(frozen=True)
class FrozenMap:
  entries: tuple[tuple[str, Any], ...]


@dataclasses.dataclass(frozen=True)
class ModePlan:
  mode: str
  row_limit: int
  map_call_cap: int
  max_tokens: int


@dataclasses.dataclass(frozen=True)
class EvidenceNode:
  alias: str
  source_id: str
  labels: tuple[str, ...]
  properties: tuple[tuple[str, Any], ...]


@dataclasses.dataclass(frozen=True)
class EvidenceRelationship:
  alias: str
  source_id: str
  type: str
  start_alias: str
  end_alias: str
  properties: tuple[tuple[str, Any], ...]


@dataclasses.dataclass(frozen=True)
class EvidencePath:
  alias: str
  start_alias: str
  end_alias: str
  steps: tuple[tuple[str, str, str, bool], ...]


@dataclasses.dataclass(frozen=True)
class RowGroup:
  alias: str
  ordinals: tuple[int, ...]
  values: FrozenList
  node_aliases: tuple[str, ...]
  relationship_aliases: tuple[str, ...]
  path_aliases: tuple[str, ...]
  component_ids: tuple[int, ...]


@dataclasses.dataclass(frozen=True)
class EvidenceIR:
  version: str
  columns: tuple[str, ...]
  nodes: tuple[EvidenceNode, ...]
  relationships: tuple[EvidenceRelationship, ...]
  paths: tuple[EvidencePath, ...]
  rows: tuple[RowGroup, ...]
  entity_order: tuple[tuple[str, str], ...]
  components: tuple[tuple[str, ...], ...]
  projected_slots: frozenset[tuple[str, str]]
  semantic_sha256: str


@dataclasses.dataclass(frozen=True)
class PropertyView:
  included: frozenset[tuple[str, str]]
  omitted: tuple[tuple[str, str], ...]
  bands: tuple[tuple[tuple[str, str], int], ...]
  profile_sha256: str = PROPERTY_PROFILE_SHA256


@dataclasses.dataclass(frozen=True)
class BatchMeasurement:
  message_bytes: int
  transport_bytes: int
  chat_tokens: int

  @property
  def fits(self) -> bool:
    return self.message_bytes <= MODEL_MESSAGE_LIMIT and self.transport_bytes <= TRANSPORT_LIMIT


@dataclasses.dataclass(frozen=True)
class EvidenceBatch:
  ordinal: int
  row_aliases: tuple[str, ...]
  node_aliases: tuple[str, ...]
  relationship_aliases: tuple[str, ...]
  path_aliases: tuple[str, ...]
  measurement: BatchMeasurement


@dataclasses.dataclass(frozen=True)
class BatchPlan:
  batches: tuple[EvidenceBatch, ...]
  omitted_row_aliases: tuple[str, ...]
  closure_owners: tuple[tuple[str, int], ...]
  repeated_boundaries: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class MapFinding:
  status: str
  text: str
  anchor: Optional[str]
  rows: tuple[str, ...]


@dataclasses.dataclass(frozen=True)
class SynthesisFinding:
  text: str
  maps: tuple[str, ...]


def _fail(code: str, detail: str) -> None:
  raise GraphFirstContractError(code, detail)


def canonical_json(value: Any) -> str:
  return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def freeze(value: Any, depth: int = 0) -> Any:
  if depth > 16:
    _fail("evidence_depth", "evidence nesting exceeds the canonical depth")
  if isinstance(value, Mapping):
    entries = []
    seen = set()
    for key, item in value.items():
      if not isinstance(key, str) or key in seen:
        _fail("invalid_map", "map keys must be unique strings")
      seen.add(key)
      entries.append((key, freeze(item, depth + 1)))
    return FrozenMap(tuple(entries))
  if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
    return FrozenList(tuple(freeze(item, depth + 1) for item in value))
  if value is None or isinstance(value, (bool, str, int)):
    return value
  if isinstance(value, float) and math.isfinite(value):
    return value
  _fail("unsupported_value", f"unsupported evidence value {type(value).__name__}")


def thaw(value: Any) -> Any:
  if isinstance(value, FrozenMap):
    return {key: thaw(item) for key, item in value.entries}
  if isinstance(value, FrozenList):
    return [thaw(item) for item in value.items]
  return value


def _strict_positive_integer(value: Any, name: str) -> Optional[int]:
  if value is None:
    return None
  if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
    _fail("invalid_explanation_limit", f"{name} must be a positive integer")
  return value


def resolve_mode(
  explanation_mode: Any = None,
  explanation_rows: Any = None,
  max_rows: Any = None,
  *,
  temperature: Any = None,
  top_p: Any = None,
  max_tokens: Any = None,
) -> ModePlan:
  rows = _strict_positive_integer(explanation_rows, "explanation_rows")
  legacy_max = _strict_positive_integer(max_rows, "max_rows")
  if rows is not None and legacy_max is not None and rows != legacy_max:
    _fail("conflicting_explanation_limits", "legacy explanation row limits must be equal")
  legacy = rows if rows is not None else legacy_max
  if legacy is not None and legacy > 50:
    _fail("explanation_limit_exceeded", "graph-first explanation supports at most 50 rows")
  if explanation_mode is not None:
    if not isinstance(explanation_mode, str) or explanation_mode not in MODE_CAPS:
      _fail("invalid_explanation_mode", "explanation_mode must be fast, balanced, or thorough")
    mode = explanation_mode
  elif legacy is None or legacy > 10:
    mode = "balanced" if legacy is None or legacy <= 25 else "thorough"
  else:
    mode = "fast"
  cap, map_calls = MODE_CAPS[mode]
  row_limit = min(cap, legacy) if legacy is not None else cap
  if temperature is not None and (
    isinstance(temperature, bool) or not isinstance(temperature, (int, float))
    or not math.isfinite(float(temperature)) or float(temperature) != 0.1
  ):
    _fail("explanation_configuration_drift", "temperature must be 0.1")
  if top_p is not None and (
    isinstance(top_p, bool) or not isinstance(top_p, (int, float))
    or not math.isfinite(float(top_p)) or float(top_p) != 1.0
  ):
    _fail("explanation_configuration_drift", "top_p must be 1.0")
  selected_tokens = 127 if max_tokens is None else _strict_positive_integer(max_tokens, "max_tokens")
  if selected_tokens != 127:
    _fail("explanation_configuration_drift", "max_tokens must be 127")
  return ModePlan(mode, row_limit, map_calls, selected_tokens)


def _exact_keys(value: Any, keys: set[str], path: str) -> dict[str, Any]:
  if not isinstance(value, dict) or set(value) != keys:
    _fail("invalid_evidence_shape", f"{path} has invalid keys")
  return value


def _validate_tagged(value: Any, path: str, depth: int = 0) -> None:
  if depth > 8 or not isinstance(value, dict) or not isinstance(value.get("type"), str):
    _fail("invalid_tagged_value", f"{path} is not a bounded tagged value")
  kind = value["type"]
  if kind == "null":
    _exact_keys(value, {"type"}, path)
  elif kind == "redacted":
    _exact_keys(value, {"type", "reason", "path"}, path)
    if value["reason"] != "security_policy" or not isinstance(value["path"], str):
      _fail("invalid_tagged_value", f"{path} has invalid redaction metadata")
  elif kind in {"boolean", "string", "float"}:
    _exact_keys(value, {"type", "value"}, path)
    expected = {"boolean": bool, "string": str, "float": (int, float)}[kind]
    if not isinstance(value["value"], expected) or isinstance(value["value"], bool) and kind == "float":
      _fail("invalid_tagged_value", f"{path} has an invalid {kind}")
    if kind == "float" and not math.isfinite(float(value["value"])):
      _fail("invalid_tagged_value", f"{path} has a non-finite float")
  elif kind == "integer":
    _exact_keys(value, {"type", "value"}, path)
    if not isinstance(value["value"], str) or re.fullmatch(r"(?:0|-?[1-9][0-9]*)", value["value"]) is None:
      _fail("invalid_tagged_value", f"{path} has a non-canonical integer")
  elif kind == "temporal":
    _exact_keys(value, {"type", "temporal_type", "value"}, path)
    if not isinstance(value["temporal_type"], str) or not isinstance(value["value"], str):
      _fail("invalid_tagged_value", f"{path} has invalid temporal data")
  elif kind == "point":
    allowed = {"type", "srid", "x", "y"} | ({"z"} if "z" in value else set())
    _exact_keys(value, allowed, path)
    if not isinstance(value["srid"], str) or re.fullmatch(r"(?:0|[1-9][0-9]*)", value["srid"]) is None:
      _fail("invalid_tagged_value", f"{path} has invalid point SRID")
    if any(isinstance(value[key], bool) or not isinstance(value[key], (int, float)) or not math.isfinite(value[key]) for key in allowed & {"x", "y", "z"}):
      _fail("invalid_tagged_value", f"{path} has invalid point coordinates")
  elif kind in {"node", "relationship"}:
    _exact_keys(value, {"type", "ref"}, path)
    if not isinstance(value["ref"], str) or not value["ref"]:
      _fail("invalid_tagged_value", f"{path} has an invalid entity reference")
  elif kind == "path":
    _exact_keys(value, {"type", "start_node_ref", "end_node_ref", "segments"}, path)
    if not isinstance(value["segments"], list):
      _fail("invalid_tagged_value", f"{path} has invalid path segments")
    for index, segment in enumerate(value["segments"]):
      _exact_keys(segment, {"start_node_ref", "relationship_ref", "end_node_ref"}, f"{path}/segments/{index}")
  elif kind == "list":
    _exact_keys(value, {"type", "items"}, path)
    if not isinstance(value["items"], list):
      _fail("invalid_tagged_value", f"{path} has invalid list items")
    for index, item in enumerate(value["items"]):
      _validate_tagged(item, f"{path}/items/{index}", depth + 1)
  elif kind == "map":
    _exact_keys(value, {"type", "entries"}, path)
    if not isinstance(value["entries"], list):
      _fail("invalid_tagged_value", f"{path} has invalid map entries")
    seen = set()
    for index, entry in enumerate(value["entries"]):
      _exact_keys(entry, {"key", "value"}, f"{path}/entries/{index}")
      if not isinstance(entry["key"], str) or entry["key"] in seen:
        _fail("invalid_tagged_value", f"{path} has duplicate or invalid map keys")
      seen.add(entry["key"])
      _validate_tagged(entry["value"], f"{path}/entries/{index}/value", depth + 1)
  else:
    _fail("invalid_tagged_value", f"{path} uses unsupported type {kind}")


class _AliasState:
  def __init__(self, nodes: dict[str, dict[str, Any]], relationships: dict[str, dict[str, Any]]):
    self.raw_nodes = nodes
    self.raw_relationships = relationships
    self.node_aliases: dict[str, str] = {}
    self.relationship_aliases: dict[str, str] = {}
    self.paths: dict[str, EvidencePath] = {}
    self.entity_encounter: list[tuple[str, str]] = []

  def node(self, source_id: str) -> str:
    if source_id not in self.raw_nodes:
      _fail("unresolved_node_reference", "node reference does not resolve")
    if source_id not in self.node_aliases:
      self.node_aliases[source_id] = f"N{len(self.node_aliases)}"
      self.entity_encounter.append(("node", source_id))
    return self.node_aliases[source_id]

  def relationship(self, source_id: str) -> str:
    relationship = self.raw_relationships.get(source_id)
    if relationship is None:
      _fail("unresolved_relationship_reference", "relationship reference does not resolve")
    if source_id not in self.relationship_aliases:
      self.relationship_aliases[source_id] = f"E{len(self.relationship_aliases)}"
      self.entity_encounter.append(("relationship", source_id))
    self.node(relationship["startNodeId"])
    self.node(relationship["endNodeId"])
    return self.relationship_aliases[source_id]

  def path(self, value: dict[str, Any]) -> str:
    start = self.node(value["start_node_ref"])
    end = self.node(value["end_node_ref"])
    steps = []
    expected = start
    for segment in value["segments"]:
      segment_start = self.node(segment["start_node_ref"])
      segment_end = self.node(segment["end_node_ref"])
      relationship_alias = self.relationship(segment["relationship_ref"])
      relationship = self.raw_relationships[segment["relationship_ref"]]
      stored_start = self.node(relationship["startNodeId"])
      stored_end = self.node(relationship["endNodeId"])
      if segment_start != expected or {segment_start, segment_end} != {stored_start, stored_end}:
        _fail("invalid_path", "path traversal is disconnected from stored relationship endpoints")
      steps.append((segment_start, relationship_alias, segment_end, segment_start == stored_start))
      expected = segment_end
    if expected != end:
      _fail("invalid_path", "path end does not match traversal")
    key = canonical_json([start, end, steps])
    if key not in self.paths:
      alias = f"P{len(self.paths)}"
      self.paths[key] = EvidencePath(alias, start, end, tuple(steps))
    return self.paths[key].alias


def _alias_tagged(value: dict[str, Any], aliases: _AliasState) -> dict[str, Any]:
  kind = value["type"]
  if kind == "node":
    return {"type": "node", "ref": aliases.node(value["ref"])}
  if kind == "relationship":
    return {"type": "relationship", "ref": aliases.relationship(value["ref"])}
  if kind == "path":
    return {"type": "path", "ref": aliases.path(value)}
  if kind == "list":
    return {"type": "list", "items": [_alias_tagged(item, aliases) for item in value["items"]]}
  if kind == "map":
    return {"type": "map", "entries": [
      {"key": entry["key"], "value": _alias_tagged(entry["value"], aliases)}
      for entry in value["entries"]
    ]}
  return dict(value)


def _refs(value: Any, result: dict[str, set[str]]) -> None:
  if isinstance(value, dict):
    kind = value.get("type")
    if kind in {"node", "relationship", "path"} and isinstance(value.get("ref"), str):
      result[kind].add(value["ref"])
    for item in value.values():
      _refs(item, result)
  elif isinstance(value, list):
    for item in value:
      _refs(item, result)


def _property_pairs(value: Any, path: str) -> tuple[tuple[str, Any], ...]:
  if not isinstance(value, dict) or value.get("type") != "map" or not isinstance(value.get("entries"), list):
    _fail("invalid_entity_properties", f"{path} must be a tagged map")
  pairs = []
  for index, entry in enumerate(value["entries"]):
    _exact_keys(entry, {"key", "value"}, f"{path}/{index}")
    _validate_tagged(entry["value"], f"{path}/{index}/value")
    pairs.append((entry["key"], freeze(entry["value"])))
  return tuple(pairs)


def _components(nodes: tuple[EvidenceNode, ...], relationships: tuple[EvidenceRelationship, ...]) -> tuple[tuple[str, ...], ...]:
  parent = {node.alias: node.alias for node in nodes}

  def find(item: str) -> str:
    while parent[item] != item:
      parent[item] = parent[parent[item]]
      item = parent[item]
    return item

  def union(left: str, right: str) -> None:
    a, b = find(left), find(right)
    if a != b:
      parent[max(a, b)] = min(a, b)

  for relationship in relationships:
    union(relationship.start_alias, relationship.end_alias)
  groups: dict[str, list[str]] = {}
  for alias in parent:
    groups.setdefault(find(alias), []).append(alias)
  return tuple(tuple(sorted(group, key=_alias_number)) for _, group in sorted(groups.items(), key=lambda item: _alias_number(item[0])))


def _alias_number(alias: str) -> tuple[str, int]:
  return alias[0], int(alias[1:])


def build_evidence_ir(
  query_result_evidence: Any,
  evidence_catalog: Any,
  *,
  projected_slots: Iterable[tuple[str, str]] = (),
) -> EvidenceIR:
  evidence = _exact_keys(query_result_evidence, {"schema_version", "columns", "rows"}, "query_result_evidence")
  catalog = _exact_keys(evidence_catalog, {"nodes", "relationships"}, "evidence_catalog")
  if not isinstance(evidence["columns"], list) or not isinstance(evidence["rows"], list):
    _fail("invalid_evidence_shape", "columns and rows must be arrays")
  if any(not isinstance(column, str) or not column or CONTROL_RE.search(column) for column in evidence["columns"]):
    _fail("invalid_evidence_shape", "columns must be non-empty control-free strings")
  columns = tuple(evidence["columns"])
  raw_nodes = {}
  for index, node in enumerate(catalog["nodes"]):
    _exact_keys(node, {"id", "labels", "properties"}, f"nodes/{index}")
    if not isinstance(node["id"], str) or node["id"] in raw_nodes or not isinstance(node["labels"], list):
      _fail("invalid_evidence_catalog", "node IDs and labels must be valid")
    raw_nodes[node["id"]] = node
  raw_relationships = {}
  for index, relationship in enumerate(catalog["relationships"]):
    _exact_keys(relationship, {"id", "type", "startNodeId", "endNodeId", "properties"}, f"relationships/{index}")
    if not isinstance(relationship["id"], str) or relationship["id"] in raw_relationships:
      _fail("invalid_evidence_catalog", "relationship IDs must be unique strings")
    raw_relationships[relationship["id"]] = relationship
  aliases = _AliasState(raw_nodes, raw_relationships)
  grouped: dict[str, tuple[list[int], FrozenList]] = {}
  order: list[str] = []
  for expected_ordinal, row in enumerate(evidence["rows"]):
    _exact_keys(row, {"ordinal", "values"}, f"rows/{expected_ordinal}")
    if row["ordinal"] != expected_ordinal or not isinstance(row["values"], list) or len(row["values"]) != len(evidence["columns"]):
      _fail("invalid_result_row", "row ordinals and column alignment must be exact")
    normalized = []
    for index, value in enumerate(row["values"]):
      _validate_tagged(value, f"rows/{expected_ordinal}/values/{index}")
      normalized.append(_alias_tagged(value, aliases))
    key = canonical_json(normalized)
    if key not in grouped:
      grouped[key] = ([], freeze(normalized))
      order.append(key)
    grouped[key][0].append(expected_ordinal)
  # Complete any endpoint aliases deterministically after row traversal.
  for source_id in raw_nodes:
    aliases.node(source_id)
  for source_id in raw_relationships:
    aliases.relationship(source_id)
  nodes = tuple(
    EvidenceNode(alias, source_id, tuple(raw_nodes[source_id]["labels"]), _property_pairs(raw_nodes[source_id]["properties"], f"node/{source_id}/properties"))
    for source_id, alias in sorted(aliases.node_aliases.items(), key=lambda item: _alias_number(item[1]))
  )
  relationships = tuple(
    EvidenceRelationship(
      alias, source_id, raw_relationships[source_id]["type"],
      aliases.node(raw_relationships[source_id]["startNodeId"]),
      aliases.node(raw_relationships[source_id]["endNodeId"]),
      _property_pairs(raw_relationships[source_id]["properties"], f"relationship/{source_id}/properties"),
    )
    for source_id, alias in sorted(aliases.relationship_aliases.items(), key=lambda item: _alias_number(item[1]))
  )
  paths = tuple(sorted(aliases.paths.values(), key=lambda item: _alias_number(item.alias)))
  components = _components(nodes, relationships)
  component_by_node = {node: index for index, group in enumerate(components) for node in group}
  relationship_by_alias = {relationship.alias: relationship for relationship in relationships}
  path_by_alias = {path.alias: path for path in paths}
  rows = []
  for index, key in enumerate(order):
    ordinals, values = grouped[key]
    refs = {"node": set(), "relationship": set(), "path": set()}
    _refs(thaw(values), refs)
    for relationship_alias in tuple(refs["relationship"]):
      relationship = relationship_by_alias[relationship_alias]
      refs["node"].update({relationship.start_alias, relationship.end_alias})
    for path_alias in tuple(refs["path"]):
      path = path_by_alias[path_alias]
      refs["node"].update({path.start_alias, path.end_alias})
      refs["relationship"].update(step[1] for step in path.steps)
      refs["node"].update(step[0] for step in path.steps)
      refs["node"].update(step[2] for step in path.steps)
    component_ids = tuple(sorted({component_by_node[alias] for alias in refs["node"]}))
    rows.append(RowGroup(
      f"R{index}", tuple(ordinals), values,
      tuple(sorted(refs["node"], key=_alias_number)),
      tuple(sorted(refs["relationship"], key=_alias_number)),
      tuple(sorted(refs["path"], key=_alias_number)), component_ids,
    ))
  projected = frozenset(projected_slots)
  known_slots = {(node.source_id, key) for node in nodes for key, _ in node.properties} | {
    (relationship.source_id, key) for relationship in relationships for key, _ in relationship.properties
  }
  if not projected.issubset(known_slots):
    _fail("invalid_projected_property", "projected property ownership does not resolve")
  semantic = canonical_json({
    "columns": columns,
    "entity_order": aliases.entity_encounter,
    "nodes": [[item.alias, item.source_id, item.labels, [[key, thaw(value)] for key, value in item.properties]] for item in nodes],
    "relationships": [[item.alias, item.source_id, item.type, item.start_alias, item.end_alias, [[key, thaw(value)] for key, value in item.properties]] for item in relationships],
    "paths": [[item.alias, item.start_alias, item.end_alias, item.steps] for item in paths],
    "rows": [[item.alias, item.ordinals, thaw(item.values)] for item in rows],
  })
  return EvidenceIR(
    IR_VERSION, columns, nodes, relationships, paths, tuple(rows), tuple(aliases.entity_encounter), components, projected,
    hashlib.sha256(semantic.encode("utf-8")).hexdigest(),
  )


def _slot_band(key: str, value: Any, projected: bool) -> int:
  normalized = key.casefold()
  if projected or normalized in IDENTITY_KEYS:
    return 1
  if normalized in BAND2_KEYS:
    return 2
  thawed = thaw(value)
  if thawed.get("type") not in {"list", "map"} and len(canonical_json(thawed).encode("utf-8")) <= 96:
    return 3
  return 4


def freeze_property_view(
  ir: EvidenceIR,
  fits_minimal_closure: Callable[[frozenset[tuple[str, str]], str], bool],
) -> PropertyView:
  ordered = []
  alias_to_source = {node.alias: node.source_id for node in ir.nodes} | {relationship.alias: relationship.source_id for relationship in ir.relationships}
  entities_by_key = {
    **{("node", entity.source_id): entity for entity in ir.nodes},
    **{("relationship", entity.source_id): entity for entity in ir.relationships},
  }
  entities = [entities_by_key[key] for key in ir.entity_order]
  for entity in entities:
    for key, value in entity.properties:
      slot = (entity.source_id, key)
      ordered.append((slot, _slot_band(key, value, slot in ir.projected_slots)))
  ordered.sort(key=lambda item: item[1])  # stable: entity encounter and property order within band
  mandatory = frozenset(slot for slot, band in ordered if band == 1)
  if any(not fits_minimal_closure(mandatory, row.alias) for row in ir.rows):
    _fail("minimal_closure_oversized", "mandatory structural evidence does not fit")
  included = set(mandatory)
  for slot, band in ordered:
    if band == 1:
      continue
    trial = frozenset(included | {slot})
    if any(not fits_minimal_closure(trial, row.alias) for row in ir.rows):
      break
    included.add(slot)
  omitted = tuple(slot for slot, _ in ordered if slot not in included)
  return PropertyView(frozenset(included), omitted, tuple(ordered))


def _normalized_match_value(value: str) -> str:
  return unicodedata.normalize("NFKC", value).casefold()


def _contains_exact_value(text: str, value: str) -> bool:
  normalized = _normalized_match_value(text)
  if not value:
    return False
  boundary = r"\w.:/@+-"
  return re.search(rf"(?<![{boundary}]){re.escape(value)}(?![{boundary}])", normalized) is not None


def _identity_values(ir: EvidenceIR, view: PropertyView, row: RowGroup) -> frozenset[str]:
  by_alias = {node.alias: node for node in ir.nodes} | {relationship.alias: relationship for relationship in ir.relationships}
  values = set()
  for alias in (*row.node_aliases, *row.relationship_aliases):
    entity = by_alias[alias]
    for key, value in entity.properties:
      if (entity.source_id, key) not in view.included or key.casefold() not in IDENTITY_KEYS:
        continue
      thawed = thaw(value)
      scalar = thawed.get("value")
      if isinstance(scalar, (str, int, float)) and not isinstance(scalar, bool):
        values.add(unicodedata.normalize("NFKC", str(scalar)).casefold())
  return frozenset(values)


def _batch_refs(rows: Sequence[RowGroup]) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
  nodes = {alias for row in rows for alias in row.node_aliases}
  relationships = {alias for row in rows for alias in row.relationship_aliases}
  paths = {alias for row in rows for alias in row.path_aliases}
  return (
    tuple(sorted(nodes, key=_alias_number)),
    tuple(sorted(relationships, key=_alias_number)),
    tuple(sorted(paths, key=_alias_number)),
  )


def build_batch_document(
  ir: EvidenceIR,
  view: PropertyView,
  row_aliases: tuple[str, ...],
) -> dict[str, Any]:
  """Return the canonical candidate-neutral sparse-alias batch document."""
  if not 1 <= len(row_aliases) <= MAX_ROW_GROUPS_PER_BATCH or len(set(row_aliases)) != len(row_aliases):
    _fail("invalid_batch_rows", "a batch requires one to eight unique canonical row aliases")
  rows_by_alias = {row.alias: row for row in ir.rows}
  try:
    rows = [rows_by_alias[alias] for alias in row_aliases]
  except KeyError as exc:
    raise GraphFirstContractError("invalid_batch_rows", "batch row alias is unknown") from exc
  expected_order = tuple(row.alias for row in ir.rows if row.alias in set(row_aliases))
  if row_aliases != expected_order:
    _fail("invalid_batch_rows", "batch row aliases must retain canonical source order")
  node_aliases, relationship_aliases, path_aliases = _batch_refs(rows)
  nodes_by_alias = {node.alias: node for node in ir.nodes}
  relationships_by_alias = {relationship.alias: relationship for relationship in ir.relationships}
  paths_by_alias = {path.alias: path for path in ir.paths}

  def properties(entity: Any) -> list[list[Any]]:
    return [
      [key, thaw(value)] for key, value in entity.properties
      if (entity.source_id, key) in view.included
    ]

  return {
    "columns": list(ir.columns),
    "nodes": [
      [alias, list(nodes_by_alias[alias].labels), properties(nodes_by_alias[alias])]
      for alias in node_aliases
    ],
    "relationships": [
      [
        alias, relationships_by_alias[alias].type,
        relationships_by_alias[alias].start_alias, relationships_by_alias[alias].end_alias,
        properties(relationships_by_alias[alias]),
      ]
      for alias in relationship_aliases
    ],
    "paths": [
      [
        alias, paths_by_alias[alias].start_alias, paths_by_alias[alias].end_alias,
        [list(step) for step in paths_by_alias[alias].steps],
      ]
      for alias in path_aliases
    ],
    "rows": [[row.alias, list(row.ordinals), thaw(row.values)] for row in rows],
  }


def measure_candidate_batch(
  user_message: str,
  transport_payload: Mapping[str, Any],
  *,
  token_counter: Callable[[str], int],
  transport_serializer: Callable[[Mapping[str, Any]], str] = canonical_json,
) -> BatchMeasurement:
  if not isinstance(user_message, str) or not user_message or CONTROL_RE.search(user_message):
    _fail("invalid_model_message", "candidate user message must be non-empty and control-free")
  transport = transport_serializer(transport_payload)
  tokens = token_counter(user_message)
  if not isinstance(transport, str) or isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
    _fail("invalid_measurement", "injected serializer and token counter returned invalid values")
  return BatchMeasurement(
    len(user_message.encode("utf-8")),
    len(transport.encode("utf-8")),
    tokens,
  )


def validate_dispatch_budget(remaining_time_seconds: Any, current_and_future_required_calls: Any) -> None:
  if (
    isinstance(remaining_time_seconds, bool) or not isinstance(remaining_time_seconds, (int, float))
    or not math.isfinite(float(remaining_time_seconds)) or remaining_time_seconds < 0
    or isinstance(current_and_future_required_calls, bool)
    or not isinstance(current_and_future_required_calls, int)
    or current_and_future_required_calls <= 0
  ):
    _fail("invalid_deadline_budget", "deadline budget inputs are invalid")
  required = 120 * current_and_future_required_calls + 30
  if remaining_time_seconds < required:
    _fail("insufficient_deadline_budget", "remaining request time cannot cover all required calls")


def plan_batches(
  ir: EvidenceIR,
  view: PropertyView,
  *,
  map_call_cap: int,
  measure: Callable[[tuple[str, ...], PropertyView], BatchMeasurement],
  question: str = "",
  cypher: str = "",
  schema_names: Iterable[str] = (),
) -> BatchPlan:
  if not 1 <= map_call_cap <= 3:
    _fail("invalid_map_cap", "map call cap must be between one and three")
  rows_by_alias = {row.alias: row for row in ir.rows}
  remaining = list(ir.rows)
  batches = []
  owners = []
  anchor_texts = (question, cypher)
  allowlisted = {_normalized_match_value(name) for name in schema_names}
  nodes_by_alias = {node.alias: node for node in ir.nodes}
  relationships_by_alias = {relationship.alias: relationship for relationship in ir.relationships}
  for batch_ordinal in range(map_call_cap):
    selected: list[RowGroup] = []
    selected_components: set[int] = set()
    selected_nodes: set[str] = set()
    selected_relationships: set[str] = set()
    selected_slots: set[tuple[str, str]] = set()
    while remaining and len(selected) < MAX_ROW_GROUPS_PER_BATCH:
      candidates = []
      canonical_selected = sorted(selected, key=lambda item: min(item.ordinals))
      before_tokens = measure(tuple(row.alias for row in canonical_selected), view).chat_tokens if selected else 0
      for row in remaining:
        trial = sorted([*selected, row], key=lambda item: min(item.ordinals))
        trial_aliases = tuple(item.alias for item in trial)
        measurement = measure(trial_aliases, view)
        if not measurement.fits:
          continue
        identities = _identity_values(ir, view, row)
        closure_schema = set()
        for alias in row.node_aliases:
          node = nodes_by_alias[alias]
          closure_schema.update(unicodedata.normalize("NFKC", label).casefold() for label in node.labels)
          closure_schema.update(
            unicodedata.normalize("NFKC", key).casefold()
            for key, _ in node.properties if (node.source_id, key) in view.included
          )
        for alias in row.relationship_aliases:
          relationship = relationships_by_alias[alias]
          closure_schema.add(unicodedata.normalize("NFKC", relationship.type).casefold())
          closure_schema.update(
            unicodedata.normalize("NFKC", key).casefold()
            for key, _ in relationship.properties if (relationship.source_id, key) in view.included
          )
        anchors = identities | (closure_schema & allowlisted)
        matches = sum(1 for anchor in anchors if any(_contains_exact_value(text, anchor) for text in anchor_texts))
        band_slots = {1: set(), 2: set()}
        sources = {item.alias: item.source_id for item in ir.nodes} | {item.alias: item.source_id for item in ir.relationships}
        aliases = {item.alias: item for item in ir.nodes} | {item.alias: item for item in ir.relationships}
        for alias in (*row.node_aliases, *row.relationship_aliases):
          entity = aliases[alias]
          for key, value in entity.properties:
            slot = (sources[alias], key)
            band = _slot_band(key, value, slot in ir.projected_slots)
            if slot in view.included and band in band_slots:
              band_slots[band].add(slot)
        score = (
          matches,
          len(set(row.component_ids) - selected_components),
          len((set(row.node_aliases) | set(row.relationship_aliases)) & (selected_nodes | selected_relationships)),
          len(set(row.relationship_aliases) - selected_relationships),
          len(set(row.node_aliases) - selected_nodes),
          len(band_slots[1] - selected_slots), len(band_slots[2] - selected_slots),
          -(measurement.chat_tokens - before_tokens),
          -min(row.ordinals),
        )
        candidates.append((score, row, measurement))
      if not candidates:
        break
      _score, chosen, _measurement = max(candidates, key=lambda item: item[0])
      selected.append(chosen)
      remaining.remove(chosen)
      selected_components.update(chosen.component_ids)
      selected_nodes.update(chosen.node_aliases)
      selected_relationships.update(chosen.relationship_aliases)
      for alias in (*chosen.node_aliases, *chosen.relationship_aliases):
        entity = ({item.alias: item for item in ir.nodes} | {item.alias: item for item in ir.relationships})[alias]
        selected_slots.update(
          (entity.source_id, key) for key, _value in entity.properties
          if (entity.source_id, key) in view.included
        )
    if not selected:
      if batches:
        break
      _fail("minimal_closure_oversized", "no complete row closure fits the selected envelope")
    canonical_selected = sorted(selected, key=lambda item: min(item.ordinals))
    row_aliases = tuple(row.alias for row in canonical_selected)
    nodes, relationships, paths = _batch_refs(canonical_selected)
    measurement = measure(row_aliases, view)
    batches.append(EvidenceBatch(batch_ordinal, row_aliases, nodes, relationships, paths, measurement))
    owners.extend((row.alias, batch_ordinal) for row in selected)
    if not remaining:
      break
  occurrence: dict[str, int] = {}
  for batch in batches:
    for alias in (*batch.node_aliases, *batch.relationship_aliases):
      occurrence[alias] = occurrence.get(alias, 0) + 1
  repeated = tuple(sorted((alias for alias, count in occurrence.items() if count > 1), key=_alias_number))
  owned = {alias for alias, _ in owners}
  return BatchPlan(
    tuple(batches), tuple(row.alias for row in ir.rows if row.alias not in owned), tuple(owners), repeated,
  )


def validate_boundary(measurement: BatchMeasurement, completion_tokens: Optional[int] = None) -> None:
  if measurement.message_bytes > MODEL_MESSAGE_LIMIT:
    _fail("model_message_bytes", "model user message exceeds 2,200 bytes")
  if measurement.transport_bytes > TRANSPORT_LIMIT:
    _fail("transport_bytes", "transport body exceeds 3,300 bytes")
  if completion_tokens is not None and (
    isinstance(completion_tokens, bool) or not isinstance(completion_tokens, int)
    or completion_tokens < 0 or completion_tokens >= COMPLETION_TOKEN_LIMIT
  ):
    _fail("completion_tokens", "completion must use fewer than 128 tokens")


def _strict_json_object(text: Any) -> dict[str, Any]:
  if not isinstance(text, str) or not text or CONTROL_RE.search(text):
    _fail("invalid_model_output", "model output must be non-empty control-free JSON")

  def pairs(pairs_value: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs_value:
      if key in result:
        _fail("duplicate_model_key", "model output contains a duplicate key")
      result[key] = value
    return result

  try:
    value = json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: _fail("invalid_model_output", "non-finite JSON value"))
  except GraphFirstContractError:
    raise
  except (json.JSONDecodeError, TypeError, ValueError) as exc:
    raise GraphFirstContractError("invalid_model_output", "model output is not one JSON object") from exc
  if not isinstance(value, dict):
    _fail("invalid_model_output", "model output must be an object")
  return value


def _word_count(text: Any, maximum: int) -> None:
  if not isinstance(text, str) or not 1 <= len(text.split()) <= maximum or CONTROL_RE.search(text):
    _fail("invalid_model_text", f"model text must contain 1-{maximum} whitespace-delimited words")


def parse_map_output(text: str, batch: EvidenceBatch, ir: EvidenceIR) -> MapFinding:
  value = _strict_json_object(text)
  if set(value) != {"status", "text", "anchor", "rows"} or value["status"] not in {"supported", "insufficient"}:
    _fail("invalid_map_output", "map output keys or status are invalid")
  if value["status"] == "insufficient":
    _word_count(value["text"], 24)
    if value["anchor"] is not None or value["rows"] != []:
      _fail("invalid_map_output", "insufficient map must have null anchor and no rows")
    return MapFinding("insufficient", value["text"], None, ())
  _word_count(value["text"], 36)
  if not isinstance(value["rows"], list) or value["rows"] != list(batch.row_aliases):
    _fail("invalid_map_citation", "supported map must cite every canonical batch row")
  if not isinstance(value["anchor"], str) or ALIAS_RE["node"].fullmatch(value["anchor"]) is None:
    _fail("invalid_map_citation", "supported map anchor must be a node alias")
  row_by_alias = {row.alias: row for row in ir.rows}
  cited_nodes = {node for alias in batch.row_aliases for node in row_by_alias[alias].node_aliases}
  if value["anchor"] not in cited_nodes:
    _fail("invalid_map_citation", "map anchor does not occur in a cited row")
  return MapFinding("supported", value["text"], value["anchor"], tuple(value["rows"]))


def parse_synthesis_output(text: str, map_ids: tuple[str, ...]) -> SynthesisFinding:
  value = _strict_json_object(text)
  if set(value) != {"status", "text", "maps"} or value["status"] != "supported":
    _fail("invalid_synthesis_output", "synthesis keys or status are invalid")
  _word_count(value["text"], 36)
  if value["maps"] != list(map_ids):
    _fail("invalid_synthesis_citation", "synthesis must cite every supported map in order")
  return SynthesisFinding(value["text"], map_ids)


def _source_evidence_ids(ir: EvidenceIR, row_aliases: Iterable[str]) -> list[str]:
  rows = {row.alias: row for row in ir.rows}
  nodes = {node.alias: node.source_id for node in ir.nodes}
  relationships = {relationship.alias: relationship.source_id for relationship in ir.relationships}
  result = []
  for row_alias in row_aliases:
    row = rows[row_alias]
    for alias in (*row.node_aliases, *row.relationship_aliases):
      source_id = nodes.get(alias, relationships.get(alias))
      if source_id is not None and source_id not in result:
        result.append(source_id)
  return result


def assemble_case_explanation(
  ir: EvidenceIR,
  maps: tuple[MapFinding, ...],
  synthesis: Optional[SynthesisFinding] = None,
  *,
  caveats: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
  supported = tuple(item for item in maps if item.status == "supported")
  if len(supported) >= 2:
    expected_ids = tuple(f"F{index}" for index in range(len(supported)))
    if synthesis is None or synthesis.maps != expected_ids:
      _fail("missing_synthesis", "multiple supported maps require exact synthesis")
    summary_text = synthesis.text
  elif len(supported) == 1:
    if synthesis is not None:
      _fail("unexpected_synthesis", "one supported map must not synthesize")
    summary_text = supported[0].text
  else:
    if synthesis is not None:
      _fail("unexpected_synthesis", "zero supported maps must not synthesize")
    summary_text = "The bounded query result did not provide sufficient evidence for an explanation."
  cited_rows = tuple(alias for item in supported for alias in item.rows)
  summary_ids = _source_evidence_ids(ir, cited_rows)
  node_sources = {node.alias: node.source_id for node in ir.nodes}
  findings = []
  for item in supported:
    evidence_ids = _source_evidence_ids(ir, item.rows)
    findings.append({
      "entity_id": node_sources[item.anchor],
      "role": "evidence_anchor",
      "finding": item.text,
      "evidence_ids": evidence_ids,
    })
  return {
    "schema_version": CASE_EXPLANATION_VERSION,
    "summary": {"text": summary_text, "evidence_ids": summary_ids},
    "key_paths": [],
    "entity_findings": findings,
    "risk_interpretation": [],
    "provenance": [],
    "caveats": list(caveats),
    "missing_context": [],
    "next_pivots": [],
  }


def _safe_ratio(numerator: int, denominator: int) -> float:
  return 1.0 if denominator == 0 else round(numerator / denominator, 6)


def build_coverage(
  ir: EvidenceIR,
  view: PropertyView,
  plan: BatchPlan,
  maps: Sequence[MapFinding],
  *,
  synthesis_calls: int = 0,
) -> dict[str, Any]:
  row_by_alias = {row.alias: row for row in ir.rows}
  admitted_aliases = {alias for batch in plan.batches for alias in batch.row_aliases}
  cited_aliases = {alias for item in maps if item.status == "supported" for alias in item.rows}

  def objects(row_aliases: set[str], kind: str) -> set[str]:
    attribute = {"paths": "path_aliases", "nodes": "node_aliases", "relationships": "relationship_aliases"}[kind]
    return {alias for row_alias in row_aliases for alias in getattr(row_by_alias[row_alias], attribute)}

  all_rows = set(row_by_alias)
  returned = {
    "rows": {ordinal for row in ir.rows for ordinal in row.ordinals},
    "paths": {path.alias for path in ir.paths},
    "nodes": {node.alias for node in ir.nodes},
    "relationships": {relationship.alias for relationship in ir.relationships},
  }
  admitted = {
    "rows": {ordinal for alias in admitted_aliases for ordinal in row_by_alias[alias].ordinals},
    "paths": objects(admitted_aliases, "paths"),
    "nodes": objects(admitted_aliases, "nodes"),
    "relationships": objects(admitted_aliases, "relationships"),
  }
  cited = {
    "rows": {ordinal for alias in cited_aliases for ordinal in row_by_alias[alias].ordinals},
    "paths": objects(cited_aliases, "paths"),
    "nodes": objects(cited_aliases, "nodes"),
    "relationships": objects(cited_aliases, "relationships"),
  }
  all_slots = {(node.source_id, key) for node in ir.nodes for key, _ in node.properties} | {
    (relationship.source_id, key) for relationship in ir.relationships for key, _ in relationship.properties
  }
  source_by_alias = {node.alias: node.source_id for node in ir.nodes} | {relationship.alias: relationship.source_id for relationship in ir.relationships}

  def slots(entity_aliases: set[str]) -> set[tuple[str, str]]:
    sources = {source_by_alias[alias] for alias in entity_aliases}
    return {slot for slot in view.included if slot[0] in sources}

  returned["property_slots"] = all_slots
  admitted["property_slots"] = slots(admitted["nodes"] | admitted["relationships"])
  cited["property_slots"] = slots(cited["nodes"] | cited["relationships"])
  counts = {}
  for kind in ("rows", "paths", "nodes", "relationships", "property_slots"):
    counts[kind] = {
      "returned": len(returned[kind]),
      "admitted": len(admitted[kind]),
      "cited": len(cited[kind]),
      "omitted": len(returned[kind]) - len(admitted[kind]),
    }
  component_rows = {index: {row.alias for row in ir.rows if index in row.component_ids} for index in range(len(ir.components))}
  component_states = []
  for index, component in enumerate(ir.components):
    component_entities = set(component)
    component_relationships = {
      relationship.alias for relationship in ir.relationships
      if relationship.start_alias in component_entities and relationship.end_alias in component_entities
    }
    required_rows = component_rows[index]
    admitted_entities = (admitted["nodes"] & component_entities) | (admitted["relationships"] & component_relationships)
    total_entities = component_entities | component_relationships
    if total_entities.issubset(admitted_entities) and required_rows.issubset(admitted_aliases):
      component_states.append("complete")
    elif not admitted_entities and not (required_rows & admitted_aliases):
      component_states.append("omitted")
    else:
      component_states.append("partial")
  topology_denominator = len(returned["nodes"]) + len(returned["relationships"])
  topology_numerator = len(admitted["nodes"]) + len(admitted["relationships"])
  completeness = {
    "row": _safe_ratio(len(admitted["rows"]), len(returned["rows"])),
    "topology": _safe_ratio(topology_numerator, topology_denominator),
    "property": _safe_ratio(len(admitted["property_slots"]), len(returned["property_slots"])),
  }
  completeness["overall"] = min(completeness.values())
  map_calls = len(plan.batches)
  return {
    "schema_version": COVERAGE_VERSION,
    "scope": "bounded_query_result",
    "counts": counts,
    "topology_components": {
      "returned": len(ir.components),
      "complete": component_states.count("complete"),
      "partial": component_states.count("partial"),
      "omitted": component_states.count("omitted"),
    },
    "calls": {"map": map_calls, "synthesis": synthesis_calls, "total": map_calls + synthesis_calls},
    "completeness": completeness,
  }
