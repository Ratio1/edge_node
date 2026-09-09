"""EGM-049 Phase 1: deterministic insight layer.

Runs after Stage A-D selection over the catalogued field views and emits a typed
insight sheet the model narrates (it never computes insights itself). Five core
primitives on data we already have, plus one optional intra-result-set lookalike
primitive (no external brand list). Every insight is checkable in code:
`{id, kind, dimension, text_hint, entities[], exemplars[<=3], count,
supporting_ids[]}`.
"""
from __future__ import annotations

import hashlib
import json

from . import field_catalog as fc

MAX_EXEMPLARS = 3

# Corroboration / confidence → LCA tier thresholds (FIRST LCA scale).
LCA_HIGH = 0.8
LCA_MODERATE = 0.6


def _node_index(graph):
    return {n["id"]: n for n in graph.get("nodes", [])}


def _display(node):
    v = fc.project(node)
    return v.get("name") or v.get("value") or v.get("cve_id") or v.get("mitre_id") or node["id"]


def _exemplars(names):
    names = list(dict.fromkeys(names))  # dedupe, keep order
    head = names[:MAX_EXEMPLARS]
    extra = len(names) - len(head)
    return head, extra


# Surfacing 2-3 REAL exemplars (plus "and N others") is the anti-recitation
# mechanism: it counters the wall-of-IOCs complaint while preventing the model
# from inventing plausible-looking names when it has none. Empirically,
# suppressing exemplars caused hallucinated domains (caught by the gate but a
# wasted call), so every insight surfaces its real exemplars. The blinded A/B
# measures whether naming a raw value (e.g. one hash) reads worse than a count.
_VALUE_EXEMPLAR_KINDS = set()


def _insight(kind, dimension, text_hint, entities, count, supporting_ids):
    head, extra = _exemplars(entities)
    return {
        "kind": kind,
        "dimension": dimension,
        "text_hint": text_hint,
        "count": count,
        "exemplars": head,
        "others": max(0, extra),
        "nameable": kind not in _VALUE_EXEMPLAR_KINDS,
        "entities": list(dict.fromkeys(entities)),
        "supporting_ids": sorted(set(supporting_ids)),
    }


# --------------------------------------------------------------------------
# P1: group-by aggregation with top-k
# --------------------------------------------------------------------------

def group_by_aggregation(graph):
    idx = _node_index(graph)
    out = []
    # By indicator_type among Indicators
    by_type = {}
    for n in graph.get("nodes", []):
        if fc.label_of(n) != "Indicator":
            continue
        v = fc.project(n)
        by_type.setdefault(v.get("indicator_type", "unknown"), []).append(n)
    if by_type and sum(len(v) for v in by_type.values()) >= 2:
        total = sum(len(v) for v in by_type.values())
        breakdown = ", ".join(f"{len(v)} {k}" for k, v in sorted(by_type.items(), key=lambda kv: -len(kv[1])))
        allnodes = [m for v in by_type.values() for m in v]
        out.append(_insight(
            "indicator_type_breakdown", "indicator", f"{total} indicators: {breakdown}",
            [_display(m) for m in allnodes], total, [m["id"] for m in allnodes],
        ))
    # By targeted zone/sector across all entities that carry `zone`
    by_zone = {}
    for n in graph.get("nodes", []):
        for z in (fc.project(n).get("zone") or []):
            if z == "global":
                continue
            by_zone.setdefault(z, []).append(n)
    for zone, members in sorted(by_zone.items(), key=lambda kv: -len(kv[1])):
        if len(members) < 2:
            continue
        out.append(_insight(
            "sector_targeting", "sector", f"{len(members)} entities associated with the \"{zone}\" sector",
            [_display(m) for m in members], len(members), [m["id"] for m in members],
        ))
    return out


# --------------------------------------------------------------------------
# P2: convergence / co-targeting (shared-neighbor >= 2, same source type)
# --------------------------------------------------------------------------

def _plural_verb(rel: str, count: int) -> str:
    """`INDICATES` -> `indicate` for a plural subject; leaves phrases like
    `sourced from` untouched (only a trailing `s` on the first word drops)."""
    words = rel.lower().replace("_", " ").split()
    if count > 1 and words and words[0].endswith("s") and not words[0].endswith("ss"):
        words[0] = words[0][:-1]
    return " ".join(words)


def _member_confidence(members):
    scores = [
        fc.project(m).get("confidence_score")
        for m in members
    ]
    scores = [s for s in scores if isinstance(s, (int, float))]
    if not scores:
        return None
    return round(sum(scores) / len(scores), 2)


def convergence(graph):
    idx = _node_index(graph)
    out = []
    # target id -> list of (source node, rel type), grouped by source label
    incoming = {}
    for r in graph.get("relationships", []):
        s = idx.get(r.get("startNodeId"))
        t = r.get("endNodeId")
        if s is None or t not in idx:
            continue
        incoming.setdefault((t, r.get("type"), fc.label_of(s)), []).append(s)
    for (target_id, rel, src_label), sources in incoming.items():
        uniq = list({s["id"]: s for s in sources}.values())
        if len(uniq) < 2:
            continue
        target = idx[target_id]
        # Sector convergence is already reported by the sector_targeting
        # aggregate; skip it here to avoid a duplicate insight.
        if fc.label_of(target) == "Sector":
            continue
        verb = _plural_verb(rel, len(uniq))
        hint = f"{len(uniq)} {src_label.lower()}s {verb} {fc.label_of(target).lower()} \"{_display(target)}\""
        group_confidence = _member_confidence(uniq)
        if group_confidence is not None:
            hint += f" (member source-data confidence mean {group_confidence:.2f})"
        ins = _insight(
            "convergence", "relationship", hint,
            [_display(s) for s in uniq],  # exemplars/others count sources only
            len(uniq), [s["id"] for s in uniq] + [target_id],
        )
        ins["target"] = _display(target)
        if group_confidence is not None:
            ins["group_confidence"] = group_confidence
        out.append(ins)
    return out


# --------------------------------------------------------------------------
# P2b: shared-origin chains (two-hop corroboration through a common member)
# --------------------------------------------------------------------------

MAX_CHAIN_INSIGHTS = 3


def shared_origin_chains(graph):
    """Members that reach TWO distinct targets stitch a corroboration chain:
    e.g. `8 indicators indicate malware "kyber" and are sourced from source
    "AlienVault OTX"`. Deterministic co-occurrence over the packet graph."""
    idx = _node_index(graph)
    outgoing = {}
    for r in graph.get("relationships", []):
        s = r.get("startNodeId")
        t = r.get("endNodeId")
        if s not in idx or t not in idx:
            continue
        outgoing.setdefault(s, set()).add((r.get("type"), t))
    combos = {}
    for start, edges in outgoing.items():
        edges = sorted(edges)
        for i in range(len(edges)):
            for j in range(i + 1, len(edges)):
                (rel1, t1), (rel2, t2) = edges[i], edges[j]
                if t1 == t2:
                    continue
                combos.setdefault((rel1, t1, rel2, t2), set()).add(start)
    out = []
    ranked = sorted(combos.items(), key=lambda kv: -len(kv[1]))
    for (rel1, t1, rel2, t2), starts in ranked[:MAX_CHAIN_INSIGHTS]:
        if len(starts) < 2:
            continue
        members = [idx[s] for s in sorted(starts)]
        src_label = fc.label_of(members[0])
        target1, target2 = idx[t1], idx[t2]
        verb1 = _plural_verb(rel1, len(members))
        verb2 = _plural_verb(rel2, len(members))
        hint = (
            f"{len(members)} {src_label.lower()}s both {verb1} "
            f"{fc.label_of(target1).lower()} \"{_display(target1)}\" and {verb2} "
            f"{fc.label_of(target2).lower()} \"{_display(target2)}\""
        )
        out.append(_insight(
            "chain", "relationship", hint,
            [_display(m) for m in members], len(members),
            [m["id"] for m in members] + [t1, t2],
        ))
    return out


# --------------------------------------------------------------------------
# P3: ATT&CK tactic-spread
# --------------------------------------------------------------------------

def tactic_spread(graph):
    phases = {}
    ids = []
    for n in graph.get("nodes", []):
        if fc.label_of(n) != "Technique":
            continue
        v = fc.project(n)
        for p in (v.get("tactic_phases") or []):
            phases.setdefault(p, 0)
            phases[p] += 1
        ids.append(n["id"])
    if len(phases) < 2:
        return []
    ordered = sorted(phases, key=lambda p: -phases[p])
    return [_insight(
        "tactic_spread", "attack", f"observed techniques span {len(phases)} ATT&CK tactics: {', '.join(ordered)}",
        ordered, len(phases), ids,
    )]


# --------------------------------------------------------------------------
# P4: CVE severity / KEV notability
# --------------------------------------------------------------------------

def cve_notability(graph):
    cves = [n for n in graph.get("nodes", []) if fc.label_of(n) == "CVE"]
    if not cves:
        return []
    out = []
    kev = [n for n in cves if fc.project(n).get("cisa_kev")]
    def score(n):
        v = fc.project(n)
        s = v.get("cvss_score")
        return s if isinstance(s, (int, float)) else 0.0
    high = [n for n in cves if score(n) >= 7.0 or str(fc.project(n).get("severity", "")).upper() in ("HIGH", "CRITICAL")]
    if kev:
        out.append(_insight(
            "kev", "cve", f"{len(kev)} of {len(cves)} CVEs are on CISA's Known Exploited Vulnerabilities list (actively exploited)",
            [fc.project(n).get("cve_id") or n["id"] for n in kev], len(kev), [n["id"] for n in kev],
        ))
    if high:
        out.append(_insight(
            "high_severity", "cve", f"{len(high)} of {len(cves)} CVEs are high or critical severity",
            [fc.project(n).get("cve_id") or n["id"] for n in high], len(high), [n["id"] for n in high],
        ))
    return out


# --------------------------------------------------------------------------
# P5: confidence corroboration → LCA tier (result-level, one insight)
# --------------------------------------------------------------------------

def confidence_tier(graph):
    scores = []
    sources = set()
    for n in graph.get("nodes", []):
        v = fc.project(n)
        c = v.get("confidence_score")
        if isinstance(c, (int, float)):
            scores.append(c)
        for s in (n.get("properties", {}).get("source") or []):
            sources.add(s)
    if not scores:
        return []
    mean = sum(scores) / len(scores)
    corroborated = len(sources) >= 2
    if mean >= LCA_HIGH and corroborated:
        tier = "high"
    elif mean >= LCA_MODERATE:
        tier = "moderate"
    else:
        tier = "low"
    ins = _insight(
        "confidence", "confidence",
        f"source-data confidence is {tier} (mean {mean:.2f} across {len(scores)} entities from {len(sources)} source(s)) - this reflects the sources' confidence in the data, not analytic certainty in any judgment",
        sorted(sources), len(scores), [],
    )
    ins["tier"] = tier
    ins["mean"] = round(mean, 3)
    ins["sources"] = sorted(sources)
    return [ins]


# --------------------------------------------------------------------------
# P6 (optional): intra-result-set lookalike domains — NO brand/reference list
# --------------------------------------------------------------------------

def _registrable(value):
    v = str(value).lower().strip()
    if "://" in v:
        v = v.split("://", 1)[1]
    v = v.split("/", 1)[0].split(":", 1)[0]
    return v


def _damerau(a, b, cap=2):
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev[j - 1])  # transposition approx
        prev = cur
        if min(prev) > cap:
            return cap + 1
    return prev[-1]


def lookalike_intraset(graph):
    domains = []
    for n in graph.get("nodes", []):
        v = fc.project(n)
        if v.get("indicator_type") == "domain":
            d = _registrable(v.get("value", ""))
            if len(d) >= 8:
                domains.append((d, n))
    out = []
    seen = set()
    for i in range(len(domains)):
        for j in range(i + 1, len(domains)):
            a, na = domains[i]
            b, nb = domains[j]
            if a == b:
                continue
            key = tuple(sorted((a, b)))
            if key in seen:
                continue
            if _damerau(a, b, 2) <= 2:
                seen.add(key)
                out.append(_insight(
                    "lookalike", "indicator", f"domains \"{a}\" and \"{b}\" are lookalikes (near-identical spelling)",
                    [a, b], 2, [na["id"], nb["id"]],
                ))
    return out


PRIMITIVES_CORE = [group_by_aggregation, convergence, shared_origin_chains, tactic_spread, cve_notability, confidence_tier]
PRIMITIVES_OPTIONAL = [lookalike_intraset]


def build_insight_sheet(graph, include_optional=True):
    """Run the primitives and return an ordered, id-assigned insight sheet."""
    insights = []
    for prim in PRIMITIVES_CORE + (PRIMITIVES_OPTIONAL if include_optional else []):
        insights.extend(prim(graph))
    # Stable ordering by a notability rank: convergence and KEV first, then
    # aggregates, then confidence last (it is the basis line, not a headline).
    rank = {"convergence": 0, "chain": 1, "kev": 1, "high_severity": 2, "lookalike": 3,
            "tactic_spread": 4, "sector_targeting": 5, "indicator_type_breakdown": 6, "confidence": 9}
    insights.sort(key=lambda x: (rank.get(x["kind"], 7), -x["count"]))
    for i, ins in enumerate(insights):
        ins["id"] = f"I{i + 1}"
    return insights


import re as _re

_QUOTED = _re.compile(r'"([^"]+)"')


def sheet_entities(sheet):
    """The set of entity strings the model may name (for the entity-linking
    gate). Includes exemplars, entity lists, the convergence target, and every
    double-quoted named entity in the text_hint (malware/actor/sector names the
    primitives surface in prose but not in the exemplar list)."""
    out = set()
    for ins in sheet:
        out.update(str(e) for e in ins.get("entities", []))
        out.update(str(e) for e in ins.get("exemplars", []))
        if ins.get("target"):
            out.add(str(ins["target"]))
        out.update(_QUOTED.findall(ins.get("text_hint", "")))
    return out


def sheet_counts(sheet):
    """Map of the countable aggregates the model may state (for the count gate)."""
    return {ins["id"]: ins["count"] for ins in sheet}


def sheet_sha256(sheet):
    payload = [{k: ins[k] for k in ("id", "kind", "count", "entities")} for ins in sheet]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
