"""EGX/1 deterministic Stage A-D relevance selection + token budgeter.

Ported from `workbooks/egm-047-notation-bakeoff/harness/selection.py` (EGM-047
Phase 2/3). Pure functions: graph in, graph out, plus a machine-readable
selection trace (a flat list of dicts) recording what was dropped or
tightened and why. No I/O, no randomness, no network/model calls.

Stages (see `docs/resources/edgeguard-models/specs/edgeguard-explain-v2-egx1.md`):

- Stage A (`stage_a_sanitize`, always on): drop embedding/vector/raw_data-style
  and corpus-measured-noise properties, truncate list properties to
  `list_cap` (default 10) with an explicit trailing `(+N more)` marker, and
  deduplicate nodes/relationships by id into a registry (first-encounter
  order preserved).
- Stage B (`stage_b_salience`, deterministic, non-destructive): rank every
  remaining property into a salience tier -- 0 = identity property
  (undroppable) or RETURN-projected column, 1 = name/value shares a token
  with the question, 2 = everything else.
- Stage C (`stage_c_structural`, only consumed when nodes must be cut):
  anchors = nodes whose name/label shares a token with the question; keep
  nodes on relationships touching an anchor; rank the remainder by
  in-result degree with per-label round-robin.
- Stage D (`stage_d_budget`, always on): count tokens with the caller's
  tokenizer via `render_fn`; degrade in order -- drop Stage-B tier-2
  properties, tighten list caps 10 -> 5 -> 3, tighten string caps
  280 -> 140 -> 80, drop low-rank nodes with their relationships -- until
  under budget or nothing left to drop. Never truncates mid-string.

`run_pipeline` runs A -> B -> C -> D end to end and is the runtime's normal
entry point.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Callable, Mapping, Optional, Sequence


FORBIDDEN_PROPERTY_TOKENS = ("embedding", "vector", "raw_data")
# Corpus-measured noise (EGM-047 P1 property-dominance audit): identifier and
# import-bookkeeping fields that never carry explanation content.
# `first_imported_at` is deliberately kept as the one provenance-recency
# timestamp.
NOISE_PROPERTY_NAMES = frozenset({
  "uuid", "misp_attribute_ids", "misp_event_ids", "imported_at",
  "last_imported_from", "last_updated", "last_modified", "created_at",
  "updated_at", "source_reported_first_at", "source_reported_last_at",
})
LIST_CAP_STAGE_A = 10
LIST_CAP_DEGRADE_STEPS = (5, 3)
STRING_CAP_DEGRADE_STEPS = (140, 80)
# Identity properties are the entity's displayable name; renderers resolve
# names through these, so Stage D must never drop them (tier 0, undroppable).
IDENTITY_PROPERTY_NAMES = frozenset({"value", "name", "cve_id", "mitre_id", "caption", "hostname", "shortname"})
# Long free-text properties (`description` is 46-80% of node-property bytes in
# the real corpus) are capped at a word boundary with an explicit marker --
# the value survives in truncated form because it carries real explanation
# content.
STRING_CAP_STAGE_A = 280
_STRING_MARKER = " (+truncated)"

_MARKER_RE = re.compile(r"^\(\+(\d+) more\)$")


def _is_forbidden_property(key: str) -> bool:
  lowered = key.lower()
  return any(token in lowered for token in FORBIDDEN_PROPERTY_TOKENS)


def _is_noise_property(key: str) -> bool:
  return key.lower() in NOISE_PROPERTY_NAMES


def _cap_string(value: str, cap: int = STRING_CAP_STAGE_A) -> str:
  """Cap a long string at a word boundary with an explicit marker; idempotent."""
  if len(value) <= cap:
    return value
  base = value[: cap - len(_STRING_MARKER)]
  cut = base.rsplit(" ", 1)[0] if " " in base else base
  return cut + _STRING_MARKER


def _tokenize(value: Any) -> set[str]:
  return set(re.findall(r"[a-z0-9]+", str(value).lower()))


def _split_marker(value: list) -> tuple[list, int]:
  """Split a possibly-already-truncated list into (real_items, prior_more_count)."""
  if value and isinstance(value[-1], str):
    match = _MARKER_RE.match(value[-1])
    if match:
      return list(value[:-1]), int(match.group(1))
  return list(value), 0


def _slice_with_marker(value: list, cap: int) -> list:
  """Slice a list to `cap` items with an explicit trailing (+N more) marker.

  Idempotent under re-tightening: re-slicing an already-marked list to a
  smaller cap accumulates the omitted count correctly instead of losing it.
  """
  real, prior_more = _split_marker(value)
  if len(real) <= cap:
    return real + [f"(+{prior_more} more)"] if prior_more else real
  dropped_now = len(real) - cap
  return real[:cap] + [f"(+{prior_more + dropped_now} more)"]


def _node_id(node: Mapping[str, Any]) -> str:
  return node["id"]


def _rel_id(rel: Mapping[str, Any], index: int) -> str:
  return rel.get("id", f"__rel_index_{index}")


# --------------------------------------------------------------------------
# Stage A: sanitize
# --------------------------------------------------------------------------

def stage_a_sanitize(graph: Mapping[str, Any], list_cap: int = LIST_CAP_STAGE_A) -> tuple[dict, list]:
  """Drop embedding/vector/raw_data-style and noise properties, truncate
  list properties to `list_cap`, and deduplicate nodes/relationships by id."""
  trace = []
  seen_node_ids = set()
  out_nodes = []
  for node in graph.get("nodes", []):
    node_id = _node_id(node)
    if node_id in seen_node_ids:
      trace.append({"stage": "A", "action": "dedupe_node", "node_id": node_id})
      continue
    seen_node_ids.add(node_id)
    props = {}
    for key, value in (node.get("properties") or {}).items():
      if _is_forbidden_property(key):
        trace.append({"stage": "A", "action": "drop_property", "scope": "node", "id": node_id, "property": key, "reason": "forbidden_property_name"})
        continue
      if _is_noise_property(key):
        trace.append({"stage": "A", "action": "drop_property", "scope": "node", "id": node_id, "property": key, "reason": "noise_property_name"})
        continue
      if isinstance(value, list):
        truncated = _slice_with_marker(value, list_cap)
        if len(truncated) != len(value):
          trace.append({"stage": "A", "action": "truncate_list", "scope": "node", "id": node_id, "property": key, "kept": list_cap, "dropped": len(value) - list_cap})
        props[key] = truncated
      elif isinstance(value, str) and len(value) > STRING_CAP_STAGE_A:
        props[key] = _cap_string(value)
        trace.append({"stage": "A", "action": "cap_string", "scope": "node", "id": node_id, "property": key, "kept_chars": len(props[key]), "original_chars": len(value)})
      else:
        props[key] = value
    out_nodes.append({**node, "properties": props})

  seen_rel_ids = set()
  out_rels = []
  for i, rel in enumerate(graph.get("relationships", [])):
    rel_id = _rel_id(rel, i)
    if rel_id in seen_rel_ids:
      trace.append({"stage": "A", "action": "dedupe_relationship", "relationship_id": rel_id})
      continue
    seen_rel_ids.add(rel_id)
    props = {}
    for key, value in (rel.get("properties") or {}).items():
      if _is_forbidden_property(key):
        trace.append({"stage": "A", "action": "drop_property", "scope": "relationship", "id": rel_id, "property": key, "reason": "forbidden_property_name"})
        continue
      if _is_noise_property(key):
        trace.append({"stage": "A", "action": "drop_property", "scope": "relationship", "id": rel_id, "property": key, "reason": "noise_property_name"})
        continue
      if isinstance(value, list):
        truncated = _slice_with_marker(value, list_cap)
        if len(truncated) != len(value):
          trace.append({"stage": "A", "action": "truncate_list", "scope": "relationship", "id": rel_id, "property": key, "kept": list_cap, "dropped": len(value) - list_cap})
        props[key] = truncated
      elif isinstance(value, str) and len(value) > STRING_CAP_STAGE_A:
        props[key] = _cap_string(value)
        trace.append({"stage": "A", "action": "cap_string", "scope": "relationship", "id": rel_id, "property": key, "kept_chars": len(props[key]), "original_chars": len(value)})
      else:
        props[key] = value
    out_rels.append({**rel, "properties": props})

  sanitized = {"nodes": out_nodes, "relationships": out_rels}
  return sanitized, trace


# --------------------------------------------------------------------------
# Stage B: query-aware salience (annotation only, nothing dropped)
# --------------------------------------------------------------------------

def stage_b_salience(graph: Mapping[str, Any], question: str = "", projected_columns: Sequence[str] = ()) -> tuple[dict, list]:
  """Rank every property into a salience tier: 0 = identity/RETURN-projected
  column, 1 = name/value shares a token with the question, 2 = other.
  Returns `{(scope, id, property): tier}` plus a trace; nothing is dropped.
  """
  trace = []
  projected = {str(c).lower() for c in projected_columns}
  q_tokens = _tokenize(question)
  salience = {}

  def tier_for(key, value):
    if key.lower() in IDENTITY_PROPERTY_NAMES:
      return 0
    if key.lower() in projected:
      return 0
    if (_tokenize(key) | _tokenize(value)) & q_tokens:
      return 1
    return 2

  for node in graph.get("nodes", []):
    node_id = _node_id(node)
    for key, value in (node.get("properties") or {}).items():
      tier = tier_for(key, value)
      salience[("node", node_id, key)] = tier
      trace.append({"stage": "B", "action": "assign_salience_tier", "scope": "node", "id": node_id, "property": key, "tier": tier})

  for i, rel in enumerate(graph.get("relationships", [])):
    rel_id = _rel_id(rel, i)
    for key, value in (rel.get("properties") or {}).items():
      tier = tier_for(key, value)
      salience[("relationship", rel_id, key)] = tier
      trace.append({"stage": "B", "action": "assign_salience_tier", "scope": "relationship", "id": rel_id, "property": key, "tier": tier})

  return salience, trace


# --------------------------------------------------------------------------
# Stage C: graph-structural salience (ranking only; consumed by Stage D)
# --------------------------------------------------------------------------

def stage_c_structural(graph: Mapping[str, Any], question: str = "") -> tuple[list, list]:
  """Rank nodes for cutting: anchors (name/label matches a question term)
  first, then nodes on a relationship touching an anchor, then the rest by
  in-result degree with per-label round-robin. Returns an ordered list of
  node ids, most-keep-worthy first, plus a trace."""
  from .explain_notation import name_of  # local import: notation depends on nothing selection-specific

  trace = []
  q_tokens = _tokenize(question)
  nodes = graph.get("nodes", [])
  byid = {n["id"]: n for n in nodes}

  def matches_question(node):
    label_tokens = set()
    for label in node.get("labels") or []:
      label_tokens |= _tokenize(label)
    return bool((_tokenize(name_of(node)) | label_tokens) & q_tokens) if q_tokens else False

  anchors = {n["id"] for n in nodes if matches_question(n)}
  degree = {n["id"]: 0 for n in nodes}
  touches_anchor = set()
  for rel in graph.get("relationships", []):
    s, o = rel.get("startNodeId"), rel.get("endNodeId")
    if s in degree:
      degree[s] += 1
    if o in degree:
      degree[o] += 1
    if s in anchors and o in byid:
      touches_anchor.add(o)
    if o in anchors and s in byid:
      touches_anchor.add(s)
  touches_anchor -= anchors

  def tier_of(node_id):
    if node_id in anchors:
      return 0
    if node_id in touches_anchor:
      return 1
    return 2

  ordered = sorted(nodes, key=lambda n: (tier_of(n["id"]), -degree[n["id"]]))
  head = [n for n in ordered if tier_of(n["id"]) in (0, 1)]
  tail = [n for n in ordered if tier_of(n["id"]) == 2]

  by_label_queues: dict[str, list] = {}
  for node in tail:
    by_label_queues.setdefault(_label_of(node), []).append(node)
  round_robin = []
  while any(by_label_queues.values()):
    for label in list(by_label_queues.keys()):
      queue = by_label_queues[label]
      if queue:
        round_robin.append(queue.pop(0))
      if not queue:
        del by_label_queues[label]

  ranked_ids = [n["id"] for n in head] + [n["id"] for n in round_robin]
  trace.append({"stage": "C", "action": "rank_nodes", "anchors": sorted(anchors), "order": ranked_ids})
  return ranked_ids, trace


def _label_of(node: Mapping[str, Any]) -> str:
  labels = node.get("labels") or []
  return labels[0] if labels else "?"


# --------------------------------------------------------------------------
# Stage D: token budgeter
# --------------------------------------------------------------------------

def _drop_property(graph: dict, scope: str, ref_id: str, key: str) -> bool:
  collection = graph["nodes"] if scope == "node" else graph["relationships"]
  for item in collection:
    if item["id"] != ref_id:
      continue
    props = item.get("properties") or {}
    if key in props:
      del props[key]
      return True
  return False


def _tighten_all_lists(graph: dict, cap: int) -> bool:
  changed = False
  for collection_key in ("nodes", "relationships"):
    for item in graph.get(collection_key, []):
      props = item.get("properties") or {}
      for key, value in list(props.items()):
        if isinstance(value, list):
          new_value = _slice_with_marker(value, cap)
          if new_value != value:
            props[key] = new_value
            changed = True
  return changed


def _tighten_all_strings(graph: dict, cap: int) -> bool:
  changed = False
  for collection_key in ("nodes", "relationships"):
    for item in graph.get(collection_key, []):
      props = item.get("properties") or {}
      for key, value in list(props.items()):
        if isinstance(value, str) and len(value) > cap:
          new_value = _cap_string(value, cap)
          if new_value != value:
            props[key] = new_value
            changed = True
  return changed


def _drop_node(graph: dict, node_id: str) -> bool:
  nodes = graph.get("nodes", [])
  kept = [n for n in nodes if n["id"] != node_id]
  if len(kept) == len(nodes):
    return False
  graph["nodes"] = kept
  graph["relationships"] = [
    r for r in graph.get("relationships", [])
    if r.get("startNodeId") != node_id and r.get("endNodeId") != node_id
  ]
  return True


def stage_d_budget(
  graph: Mapping[str, Any],
  token_counter: Callable[[str], int],
  budget: int,
  render_fn: Callable[[dict], str],
  salience_map: Optional[Mapping[tuple, int]] = None,
  node_rank: Optional[Sequence[str]] = None,
) -> tuple[dict, list]:
  """Degrade `graph` until `token_counter(render_fn(graph)) <= budget`.

  Degradation order: (1) drop Stage-B tier-2 properties, latest-encountered
  first; (2) tighten list caps 10 -> 5 -> 3; (3) tighten string caps
  280 -> 140 -> 80; (4) drop Stage-C low-rank nodes (and any relationship
  touching a dropped node), lowest rank first. Stops as soon as the budget is
  met, or when there is nothing left to drop. Never truncates mid-string.
  """
  graph = copy.deepcopy(graph)
  trace = []

  def tokens():
    return token_counter(render_fn(graph))

  current = tokens()
  trace.append({"stage": "D", "action": "measure", "tokens": current, "budget": budget})
  if current <= budget:
    return graph, trace

  if salience_map:
    low_salience = [ref for ref, tier in salience_map.items() if tier >= 2]
    for scope, ref_id, key in reversed(low_salience):
      if current <= budget:
        break
      if _drop_property(graph, scope, ref_id, key):
        trace.append({"stage": "D", "action": "drop_low_salience_property", "scope": scope, "id": ref_id, "property": key})
        current = tokens()

  for cap in LIST_CAP_DEGRADE_STEPS:
    if current <= budget:
      break
    if _tighten_all_lists(graph, cap):
      trace.append({"stage": "D", "action": "tighten_list_cap", "cap": cap})
      current = tokens()

  for scap in STRING_CAP_DEGRADE_STEPS:
    if current <= budget:
      break
    if _tighten_all_strings(graph, scap):
      trace.append({"stage": "D", "action": "tighten_string_cap", "cap": scap})
      current = tokens()

  if node_rank and current > budget:
    for node_id in reversed(node_rank):
      if current <= budget:
        break
      if _drop_node(graph, node_id):
        trace.append({"stage": "D", "action": "drop_low_rank_node", "node_id": node_id})
        current = tokens()

  trace.append({"stage": "D", "action": "final", "tokens": current, "budget": budget, "under_budget": current <= budget})
  return graph, trace


# --------------------------------------------------------------------------
# End-to-end pipeline
# --------------------------------------------------------------------------

def run_pipeline(
  graph: Mapping[str, Any],
  question: str = "",
  projected_columns: Sequence[str] = (),
  token_counter: Optional[Callable[[str], int]] = None,
  budget: Optional[int] = None,
  render_fn: Optional[Callable[[dict], str]] = None,
  list_cap: int = LIST_CAP_STAGE_A,
) -> tuple[dict, list]:
  """Stage A -> B -> C -> D end to end.

  `render_fn(graph) -> str` measures the candidate rendering for the Stage D
  budgeter; it defaults to `explain_notation.render_numbered_facts`.
  `token_counter(str) -> int` is required whenever `budget` is not None.
  If `budget` is None, Stage D is skipped (Stage A-C only).
  """
  if render_fn is None:
    from .explain_notation import render_numbered_facts
    render_fn = lambda g: render_numbered_facts(g).text  # noqa: E731

  trace = []
  sanitized, a_trace = stage_a_sanitize(graph, list_cap=list_cap)
  trace += a_trace
  salience_map, b_trace = stage_b_salience(sanitized, question, projected_columns)
  trace += b_trace
  ranked_ids, c_trace = stage_c_structural(sanitized, question)
  trace += c_trace

  if budget is None:
    return sanitized, trace
  if token_counter is None:
    raise ValueError("token_counter is required when budget is not None")

  final_graph, d_trace = stage_d_budget(sanitized, token_counter, budget, render_fn, salience_map=salience_map, node_rank=ranked_ids)
  trace += d_trace
  return final_graph, trace


def referential_integrity_ok(graph: Mapping[str, Any]) -> bool:
  """True if every relationship's endpoints reference a node still present."""
  node_ids = {n["id"] for n in graph.get("nodes", [])}
  return all(
    rel.get("startNodeId") in node_ids and rel.get("endNodeId") in node_ids
    for rel in graph.get("relationships", [])
  )
