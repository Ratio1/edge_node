"""EGM-049 Phase 1: deterministic gates for the analyst brief.

These replace EGX/1's verbatim-quote incentive. They grade the model's TYPED
output fields against the precomputed insight sheet, so the model is free to
paraphrase around entities and counts but cannot invent them. Fail-closed gates
(entity-linking, count) are hard; estimative-language and insight-coverage are
advisory for the Phase 1 A/B and promote to fail-closed only if measured pass
rates support it.

A brief is `{assessment, observations:[{text, insight_ids, exemplar_entities}],
why_it_matters, next_checks:[{text, insight_ids}], confidence:{tier, basis}}`.
"""
from __future__ import annotations

import re

from . import insights as I
from .. import misp_enrichment as misp

# FIRST estimative (WEP) and confidence (LCA) whitelists.
WEP_TERMS = {
    "almost no chance", "highly unlikely", "unlikely", "roughly even chance",
    "likely", "probable", "very likely", "highly likely", "almost certain",
    "possible",  # allowed as a softener; kept in-vocabulary
}
LCA_TIERS = {"low", "moderate", "high"}

# Numerals whose head noun we do NOT treat as a count claim (they are values,
# not aggregates): CVSS scores, version numbers, MITRE IDs, CVE ids, TLDs.
_EXCLUDE_NUMERAL = re.compile(
    r"(?:CVE-\d{4}-\d+|T\d{4}(?:\.\d+)?|CWE-\d+|\bv?\d+\.\d+\b|CVSS[:\s]?\S+|\.\w{2,})",
    re.IGNORECASE,
)
_COUNT_CLAIM = re.compile(r"\b(\d+)\s+(?:of\s+(\d+)\s+)?([a-zA-Z][a-zA-Z\- ]{2,30})")
# Unambiguous entity tokens we can reliably detect in prose (the critic conceded
# these are regexable; actor/malware NAMES are checked via exemplar_entities).
_PROSE_ENTITY = re.compile(r"\b(CVE-\d{4}-\d+|T\d{4}(?:\.\d+)?|CWE-\d+)\b")


def _brief_texts(brief):
    """All model-authored prose fields, for lexical checks."""
    parts = [brief.get("assessment", ""), brief.get("why_it_matters", "")]
    for o in brief.get("observations", []) or []:
        parts.append(o.get("text", ""))
    for c in brief.get("next_checks", []) or []:
        parts.append(c.get("text", ""))
    conf = brief.get("confidence") or {}
    parts.append(conf.get("basis", ""))
    return [p for p in parts if isinstance(p, str)]


# Generic descriptors that are not entities (indicator types, bucket labels).
# Naming these in exemplar_entities is describing, not hallucinating.
_GENERIC_DESCRIPTORS = {
    "unknown", "other", "others", "domain", "domains", "hash", "hashes",
    "url", "urls", "ipv4", "ip", "ips", "indicator", "indicators",
}
_OTHERS_PHRASE = re.compile(r"^(and\s+)?\d+\s+(others?|more)$", re.IGNORECASE)


def enrichment_nodes(enrichment):
    """Explanation spec v0.2: `{entity (lower-cased): view node}` for the
    `misp_enrichment` model view the prompt carried (empty without one)."""
    nodes = {}
    for node in (enrichment or {}).get("nodes") or []:
        entity = node.get("entity") if isinstance(node, dict) else None
        if isinstance(entity, str) and entity:
            nodes.setdefault(entity.lower(), node)
    return nodes


def entity_linking(brief, sheet, enrichment=None):
    """Every named exemplar entity must exist in the insight sheet. Reads the
    typed `exemplar_entities` fields — no prose parsing needed. Generic type
    words (unknown/domain/hash/...) are descriptors, not entities. With a
    `misp_enrichment` view, its `entity` names are nameable too (never its
    feed-authored field values). CWE ids in prose are graded by
    `enrichment_grounding` (`ungrounded_cwe`), against the sheet and view."""
    universe = {e.lower() for e in I.sheet_entities(sheet)} | _GENERIC_DESCRIPTORS
    universe.update(enrichment_nodes(enrichment))
    unknown = []
    for o in brief.get("observations", []) or []:
        for e in o.get("exemplar_entities", []) or []:
            s = str(e).strip()
            # The "and N others" summary phrase sometimes leaks into the array;
            # it is not an entity.
            if _OTHERS_PHRASE.match(s):
                continue
            if s.lower() not in universe:
                unknown.append(s)
    # Also catch unambiguous entity IDs typed directly into any prose field, so
    # a fabricated CVE/technique cannot slip through by not being declared as an
    # exemplar. Names (actors/malware) are covered by exemplar_entities above.
    for text in _brief_texts(brief):
        for tok in _PROSE_ENTITY.findall(text):
            if tok.upper().startswith("CWE-"):
                continue
            if tok.lower() not in universe:
                unknown.append(tok)
    if unknown:
        return False, f"named entities not in the insight sheet: {sorted(set(unknown))[:5]}"
    return True, f"all named entities resolve ({len(universe)} in sheet)"


def insight_id_validity(brief, sheet, enrichment=None):
    """Every cited insight ID must exist."""
    valid = {ins["id"] for ins in sheet}
    cited = []
    for key in ("observations", "next_checks"):
        for item in brief.get(key, []) or []:
            cited += [str(x) for x in (item.get("insight_ids") or [])]
    bad = [c for c in cited if c not in valid]
    if bad:
        return False, f"unknown insight IDs cited: {bad[:5]}"
    return True, f"{len(set(cited))} insight IDs cited, all valid"


def count_claims(brief, sheet, enrichment=None):
    """Every count claim in prose must equal a precomputed aggregate. Numerals
    that are values (CVSS, versions, MITRE/CVE IDs, TLDs) are excluded."""
    aggregates = set(I.sheet_counts(sheet).values())
    # The model may restate any integer the insight layer itself computed:
    # every whole number that appears in an insight's text_hint is admissible
    # (covers "of N" totals, source counts, tactic counts, etc.).
    for ins in sheet:
        for tok in re.findall(r"(?<![.\d])(\d+)(?!\.\d)", ins["text_hint"]):
            aggregates.add(int(tok))
    max_agg = max(aggregates) if aggregates else 0
    bad = []
    for text in _brief_texts(brief):
        masked = _EXCLUDE_NUMERAL.sub(" ", text)
        for m in _COUNT_CLAIM.finditer(masked):
            n = int(m.group(1))
            total = int(m.group(2)) if m.group(2) else None
            noun = m.group(3).strip().lower()
            # "N others"/"N more"/"N other" = an aggregate minus the named
            # exemplars, so it is always strictly less than some aggregate.
            if noun.startswith(("other", "more")):
                if n >= max_agg:
                    bad.append(f"{n} {noun} (exceeds every aggregate)")
                continue
            if n > 1 and n not in aggregates:
                bad.append(f"{n} {noun}")
            if total is not None and total not in aggregates:
                bad.append(f"total {total} in \"{n} of {total} {noun}\"")
    if bad:
        return False, f"count claims not backed by an aggregate: {bad[:5]}"
    return True, "all count claims match a precomputed aggregate"


def estimative_language(brief, sheet):
    """ADVISORY: the assessment should use a whitelisted WEP term, and the stated
    confidence tier should equal the precomputed one."""
    assessment = (brief.get("assessment") or "").lower()
    used = [t for t in WEP_TERMS if t in assessment]
    tier = ((brief.get("confidence") or {}).get("tier") or "").lower()
    precomputed = next((ins.get("tier") for ins in sheet if ins["kind"] == "confidence"), None)
    problems = []
    if tier and tier not in LCA_TIERS:
        problems.append(f"confidence tier '{tier}' not in {sorted(LCA_TIERS)}")
    if precomputed and tier and tier != precomputed:
        problems.append(f"stated tier '{tier}' != precomputed '{precomputed}'")
    if problems:
        return False, "; ".join(problems)
    note = "uses a whitelisted estimative term" if used else "no WEP term in assessment"
    return True, note


def insight_coverage(brief, sheet, k=None):
    """ADVISORY: at least k top-ranked insights are cited; k is adaptive to the
    number of available insights so small results never fail."""
    if not sheet:
        return True, "no insights to cover"
    if k is None:
        k = min(2, max(1, len(sheet) - 1))  # adaptive, never exceeds available
    top = {ins["id"] for ins in sheet[:max(k, 1)]}
    cited = set()
    for key in ("observations", "next_checks"):
        for item in brief.get(key, []) or []:
            cited.update(str(x) for x in (item.get("insight_ids") or []))
    hit = len(top & cited)
    if hit < k:
        return False, f"cited {hit}/{k} of the top insights"
    return True, f"covered {hit}/{k} top insights"


_SUPERLATIVE_TERMS = {"lowest", "highest", "least", "most"}
_COMPARATIVE_TERMS = {"lower", "higher", "greater", "smaller", "better", "worse"}
_CONFIDENCE_COMPARATIVE = re.compile(
    r"\b(lowest|highest|lower|higher|least|most|greater|smaller|better|worse)\b[^.!?]*\bconfidence\b"
    r"|\bconfidence\b[^.!?]*\b(lowest|highest|lower|higher|least|most|greater|smaller|better|worse)\b",
    re.IGNORECASE,
)


def confidence_comparisons(brief, sheet, enrichment=None):
    """Comparative/superlative confidence claims must be backed by the sheet's
    per-member confidence values ("member source-data confidence mean") and
    must match them: a superlative names the entity that actually holds the
    extreme; a pairwise comparative respects the computed order. Anything the
    sheet cannot verify is rejected (fail-closed)."""
    groups = {}
    for ins in sheet:
        value = ins.get("group_confidence")
        if isinstance(value, (int, float)) and ins.get("target"):
            groups[str(ins["target"]).lower()] = float(value)
    problems = []
    for text in _brief_texts(brief):
        for sentence in re.split(r"[.!?]", text):
            m = _CONFIDENCE_COMPARATIVE.search(sentence)
            if not m:
                continue
            term = (m.group(1) or m.group(2) or "").lower()
            wants_min = term in {"lowest", "least", "lower", "smaller", "worse"}
            if len(groups) < 2:
                problems.append("comparative confidence claim without per-member confidence values in the sheet")
                continue
            lowered = sentence.lower()
            named = sorted(
                (name for name in groups if name in lowered),
                key=lambda name: lowered.index(name),
            )
            if not named:
                problems.append("comparative confidence claim names no sheet entity")
            elif term in _SUPERLATIVE_TERMS:
                extreme = min(groups, key=groups.get) if wants_min else max(groups, key=groups.get)
                if extreme not in named:
                    problems.append("claimed confidence extreme does not match the computed per-member values")
            elif len(named) >= 2:
                first, second = groups[named[0]], groups[named[1]]
                ordered = first < second if wants_min else first > second
                if not ordered:
                    problems.append("pairwise confidence comparison contradicts the computed per-member values")
            else:
                problems.append("pairwise confidence comparison names fewer than two sheet entities")
    if problems:
        return False, "; ".join(sorted(set(problems))[:3])
    return True, "no unbacked confidence comparisons"


def _grounding_findings(brief, sheet, enrichment=None):
    """`[(code, detail)]` for `enrichment_grounding`: one entry per failed
    citation check, plus the shared lexical code if any. The code is a fixed
    string chosen here (never built from model output); the detail is the
    human text that feeds the retry note only."""
    nodes = enrichment_nodes(enrichment)
    findings = []
    claims = []
    for o in brief.get("observations", []) or []:
        about = {str(e).strip().lower() for e in o.get("exemplar_entities", []) or []}
        claims.append((o.get("text", ""), about))
        for c in o.get("misp_citations", []) or []:
            entity = str(c.get("entity", "")).strip().lower()
            field = c.get("field")
            value = c.get("value")
            node = nodes.get(entity)
            if entity not in about:
                findings.append(("citation_entity_not_exemplar", f"citation entity '{c.get('entity')}' is not an exemplar of its observation"))
            elif node is None:
                findings.append(("citation_entity_no_enrichment", f"citation entity '{c.get('entity')}' has no enrichment"))
            elif field != "misp_event_ids" and field not in (node.get("fields") or {}):
                findings.append(("citation_field_not_in_node", f"field '{field}' is not in the enrichment of '{c.get('entity')}'"))
            else:
                items = (node.get("misp_event_ids") or []) if field == "misp_event_ids" else node["fields"][field]
                if not any(str(item) == str(value).strip() for item in (items if isinstance(items, list) else [items])):
                    findings.append(("citation_value_mismatch", f"cited value is not the enrichment {field} of '{c.get('entity')}'"))
    other_texts = [brief.get("assessment", ""), brief.get("why_it_matters", "")]
    other_texts += [c.get("text", "") for c in brief.get("next_checks", []) or []]
    other_texts.append((brief.get("confidence") or {}).get("basis", ""))
    claims += [(text, set()) for text in other_texts if isinstance(text, str)]
    sheet_entities = sorted(str(e) for e in I.sheet_entities(sheet))
    code = misp.enrichment_grounding_error(
        claims,
        evidence_texts=[str(ins.get("text_hint", "")) for ins in sheet] + sheet_entities,
        view=enrichment,
        names_by_ref={
            node["node_ref"]: {entity}
            for entity, node in nodes.items() if isinstance(node.get("node_ref"), str)
        },
        known_names=sheet_entities + sorted(nodes),
    )
    if code is not None:
        findings.append((code, code))
    return findings


def enrichment_grounding(brief, sheet, enrichment=None):
    """Explanation spec v0.2 §5. Fail-closed:

    - every `misp_citations` entry names an entity listed in the same
      observation's `exemplar_entities` (the entity the claim is about),
      that entity has a node in the enrichment view, and the cited value is
      that node's value for the cited field (verbatim, or one item of it);
    - the shared lexical rules (`misp_enrichment.enrichment_grounding_error`):
      every brief text is about each sheet or view entity it mentions, and an
      observation also about all of its exemplar entities, enriched or not;
      evidence is the sheet text and entities.
    """
    problems = [detail for _code, detail in _grounding_findings(brief, sheet, enrichment)]
    if problems:
        return False, "; ".join(sorted(set(problems))[:3])
    return True, "enrichment citations, URLs and CWE ids resolve"


HARD_GATES = {
    "entity_linking": entity_linking,
    "insight_id_validity": insight_id_validity,
    "count_claims": count_claims,
    "confidence_comparisons": confidence_comparisons,
    "enrichment_grounding": enrichment_grounding,
}
ADVISORY_GATES = {
    "estimative_language": estimative_language,
    "insight_coverage": insight_coverage,
}


def grade(brief, sheet, enrichment=None):
    """Return {gate: (passed, detail)} for all gates; the caller decides which
    are fail-closed. Advisory gates are labelled so the A/B can measure them.
    `enrichment` is the `misp_enrichment` model view the prompt carried."""
    out = {}
    for name, fn in HARD_GATES.items():
        out[name] = fn(brief, sheet, enrichment=enrichment) + ("hard",)
    for name, fn in ADVISORY_GATES.items():
        out[name] = fn(brief, sheet) + ("advisory",)
    return out


# Explanation spec v0.3 §5: fixed, value-free reason codes for the hard gates
# other than `enrichment_grounding` (which has one code per failure branch).
GATE_FAILURE_CODES = {
    "entity_linking": "entity_not_in_sheet",
    "insight_id_validity": "unknown_insight_id",
    "count_claims": "count_not_in_sheet",
    "confidence_comparisons": "unbacked_comparison",
}
MAX_FAILURE_CODES_PER_GATE = 8


def failure_codes(brief, sheet, enrichment=None):
    """`{hard gate: [fixed codes]}` for the hard gates that fail, sorted and
    de-duplicated, at most 8 per gate. A gate is listed exactly when `grade()`
    reports it as a hard failure (a test pins the two together). Codes never
    contain model output, entity names or values."""
    out = {}
    for name, fn in HARD_GATES.items():
        if name == "enrichment_grounding":
            codes = sorted({code for code, _detail in _grounding_findings(brief, sheet, enrichment)})
        else:
            passed, _detail = fn(brief, sheet, enrichment=enrichment)
            codes = [] if passed else [GATE_FAILURE_CODES[name]]
        if codes:
            out[name] = codes[:MAX_FAILURE_CODES_PER_GATE]
    return out
