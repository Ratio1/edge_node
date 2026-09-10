"""EGX/1 evidence notation renderers (edge-node production).

Ported from `workbooks/egm-047-notation-bakeoff/harness/renderers.py` (EGM-047
Phase 2/3 bake-off winner). Renders a sanitized/selected `GraphEvidencePacket
v1`-shaped graph dict (`{"nodes": [...], "relationships": [...]}`) into a
notation. Two notations are registered: `numbered_facts` (the production
default, `EGX/1`'s `notation_id`) and `entity_cards` (the registered
alternate -- swapping the production notation is a one-module change plus a
profile-manifest hash bump, never a UI lockstep change).

Determinism contract (mirrors the bake-off harness, see
`tests/test_explain_v2.py::NotationDeterminismTests`):
- facts/cards render in first-encounter order of the input graph; the caller
  (`explain_selection`) is responsible for any de-duplication/ordering before
  a graph reaches a renderer.
- real entity names use the caption fallback chain: `caption`, then
  `properties.value` / `properties.name` / `properties.cve_id` /
  `properties.mitre_id`, then the raw node id.
- list-valued properties are truncated to the top 10 items with an explicit
  trailing `(+N more)` marker (a rendering safety net; the primary list cap
  lives in `explain_selection` Stage A/D).
- same input rendered twice with the same renderer produces byte-identical
  output.

`RenderedEvidence.fact_members`/`fact_subject` expose the fact -> underlying
graph-entity mapping the runtime needs for `CaseExplanation v1` assembly:
`numbered_facts` cites `F#` fact IDs, so `entity_findings[].entity_id` (a
single node/relationship source id) and `evidence_ids` (a set of source ids)
must be recovered from a citation ID through this map rather than being a
citation ID itself.
"""
from __future__ import annotations

import dataclasses
from typing import Any, Mapping, Optional, Sequence


LIST_CAP = 10
# Real-entity-name fallback chain (narrower than `explain_selection`'s
# IDENTITY_PROPERTY_NAMES tier-0 set, which also protects hostname/shortname
# from Stage D degradation without necessarily using them as the display name).
ID_PROPS = ("value", "name", "cve_id", "mitre_id")


@dataclasses.dataclass(frozen=True)
class RenderedEvidence:
  """Rendered evidence text plus the citation-ID universe it exposes.

  `fact_subject[citation_id]` is the single anchor entity/relationship source
  id for that citation (used for `entity_findings[].entity_id`).
  `fact_members[citation_id]` is the full tuple of member entity/relationship
  source ids that citation touches (used for `evidence_ids` union).
  """

  notation: str
  text: str
  fact_ids: tuple[str, ...]
  fact_subject: Mapping[str, str]
  fact_members: Mapping[str, tuple[str, ...]]

  def citation_universe(self) -> set[str]:
    return set(self.fact_ids)

  def citation_subject(self, citation_id: str) -> Optional[str]:
    return self.fact_subject.get(citation_id)

  def citation_members(self, citation_id: str) -> tuple[str, ...]:
    return self.fact_members.get(citation_id, ())


def name_of(node: Mapping[str, Any]) -> str:
  """Real entity name via the caption fallback chain."""
  props = node.get("properties") or {}
  return (
    node.get("caption")
    or props.get("value")
    or props.get("name")
    or props.get("cve_id")
    or props.get("mitre_id")
    or node["id"]
  )


def fmt_val(value: Any, list_cap: int = LIST_CAP) -> str:
  if isinstance(value, list):
    if value and isinstance(value[-1], str) and value[-1].startswith("(+") and value[-1].endswith("more)"):
      # already carries a selection-stage truncation marker; render as-is
      return "|".join(str(item) for item in value)
    head = "|".join(str(item) for item in value[:list_cap])
    if len(value) > list_cap:
      head += f" (+{len(value) - list_cap} more)"
    return head
  return str(value)


def extras(node: Mapping[str, Any]) -> dict[str, Any]:
  """Node properties other than the ones already surfaced as the name."""
  return {k: v for k, v in (node.get("properties") or {}).items() if k not in ID_PROPS}


def _by_id(graph: Mapping[str, Any]) -> dict[str, Any]:
  return {n["id"]: n for n in graph.get("nodes", [])}


def _rel_key(rel: Mapping[str, Any], index: int) -> str:
  return rel.get("id", f"__rel_index_{index}")


def _label_of(node: Mapping[str, Any]) -> str:
  labels = node.get("labels") or []
  return labels[0] if labels else "?"


def _assign_citation_ids(graph: Mapping[str, Any]) -> tuple[dict[str, str], dict[str, str]]:
  """Assign the shared E#/L# citation IDs, by first-encounter graph order."""
  node_ids: dict[str, str] = {}
  for i, node in enumerate(graph.get("nodes", [])):
    node_ids.setdefault(node["id"], f"E{i + 1}")
  rel_ids: dict[str, str] = {}
  for i, rel in enumerate(graph.get("relationships", [])):
    key = _rel_key(rel, i)
    rel_ids.setdefault(key, f"L{i + 1}")
  return node_ids, rel_ids


def render_numbered_facts(graph: Mapping[str, Any], _question: Optional[str] = None) -> RenderedEvidence:
  """One atomic fact per line: relationship facts first, then property
  facts. Cite by `Fid`."""
  byid = _by_id(graph)
  lines: list[str] = []
  fact_ids: list[str] = []
  fact_subject: dict[str, str] = {}
  fact_members: dict[str, tuple[str, ...]] = {}
  k = 0
  for rel in graph.get("relationships", []):
    s = byid.get(rel.get("startNodeId"))
    o = byid.get(rel.get("endNodeId"))
    if s is None or o is None:
      continue
    k += 1
    fid = f"F{k}"
    fact_ids.append(fid)
    lines.append(f'{fid}: {_label_of(s)} "{name_of(s)}" {rel["type"]} {_label_of(o)} "{name_of(o)}".')
    fact_subject[fid] = s["id"]
    members = [s["id"]]
    rel_id = rel.get("id")
    if isinstance(rel_id, str) and rel_id not in members:
      members.append(rel_id)
    if o["id"] not in members:
      members.append(o["id"])
    fact_members[fid] = tuple(members)
  for node in graph.get("nodes", []):
    ex = extras(node)
    if not ex:
      continue
    k += 1
    fid = f"F{k}"
    fact_ids.append(fid)
    props_text = "; ".join(f"{key}={fmt_val(value)}" for key, value in ex.items())
    lines.append(f'{fid}: {_label_of(node)} "{name_of(node)}" has {props_text}.')
    fact_subject[fid] = node["id"]
    fact_members[fid] = (node["id"],)
  text = "\n".join(lines)
  return RenderedEvidence("numbered_facts", text, tuple(fact_ids), fact_subject, fact_members)


def render_entity_cards(graph: Mapping[str, Any], _question: Optional[str] = None) -> RenderedEvidence:
  """One card per node with its outgoing edges indented underneath; edges
  cite both endpoint (`Eid`) and relationship (`Lid`)."""
  node_ids, rel_ids = _assign_citation_ids(graph)
  byid = _by_id(graph)
  lines: list[str] = []
  fact_ids: list[str] = []
  fact_subject: dict[str, str] = {}
  fact_members: dict[str, tuple[str, ...]] = {}
  for node in graph.get("nodes", []):
    eid = node_ids[node["id"]]
    if eid not in fact_ids:
      fact_ids.append(eid)
      fact_subject[eid] = node["id"]
      fact_members[eid] = (node["id"],)
    ex = ", ".join(f"{k}: {fmt_val(v)}" for k, v in extras(node).items())
    lines.append(f'[{eid}] {_label_of(node)} "{name_of(node)}"' + (f" ({ex})" if ex else ""))
    for i, rel in enumerate(graph.get("relationships", [])):
      if rel.get("startNodeId") != node["id"]:
        continue
      other = byid.get(rel.get("endNodeId"))
      if other is None:
        continue
      lid = rel_ids[_rel_key(rel, i)]
      other_eid = node_ids[other["id"]]
      lines.append(f"      {rel['type']} [{lid}] -> [{other_eid}] {name_of(other)}")
      if lid not in fact_ids:
        fact_ids.append(lid)
        fact_subject[lid] = node["id"]
        members = [node["id"]]
        rel_id = rel.get("id")
        if isinstance(rel_id, str) and rel_id not in members:
          members.append(rel_id)
        if other["id"] not in members:
          members.append(other["id"])
        fact_members[lid] = tuple(members)
  text = "\n".join(lines)
  return RenderedEvidence("entity_cards", text, tuple(fact_ids), fact_subject, fact_members)


NOTATIONS = {
  "numbered_facts": render_numbered_facts,
  "entity_cards": render_entity_cards,
}
DEFAULT_NOTATION = "numbered_facts"


def render(notation: str, graph: Mapping[str, Any], question: Optional[str] = None) -> RenderedEvidence:
  return NOTATIONS[notation](graph, question)
