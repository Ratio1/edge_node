"""EGX/1 deterministic semantic gates (server-side, fail-closed).

Ported from `workbooks/egm-047-notation-bakeoff/harness/gates.py` (EGM-047
Phase 2/3). Fail-closed gates over a model response dict
`{"citations": [...], "finding": "..."}` given the rendered evidence for that
call. Every gate returns `(passed: bool, detail: str)`. Pure string/set
comparisons -- no network, no model calls, no randomness.

Gate names travel to the client as diagnostic validation codes; the `detail`
string is server-log-only and must never be transported (see
`explain_runtime_v2.py` trace assembly and `edgeguard_api.py`'s failure
transport, which only forward gate *names*).
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Sequence


QUOTED_RE = re.compile(r'"([^"]+)"')
INLINE_ID_RE = re.compile(r"\[(E\d+|L\d+|F\d+)\]")

DUPLICATE_JACCARD_THRESHOLD = 0.8
REDUNDANCY_JACCARD_THRESHOLD = 0.8


def citation_membership(response: Mapping[str, Any], evidence_citation_ids) -> tuple[bool, str]:
  """Gate (a): every ID in `response["citations"]` exists in the rendered
  evidence's citation-ID universe."""
  citations = response.get("citations") or []
  universe = set(evidence_citation_ids)
  missing = [c for c in citations if c not in universe]
  if missing:
    return False, f"citation(s) not present in rendered evidence: {missing}"
  return True, f"all {len(citations)} citation(s) resolve in the evidence"


def lexical_grounding(response: Mapping[str, Any], evidence_text: str) -> tuple[bool, str]:
  """Gate (b): every double-quoted string in the finding is a
  case-insensitive substring of the rendered evidence text."""
  finding = response.get("finding") or ""
  haystack = evidence_text.lower()
  quoted = QUOTED_RE.findall(finding)
  ungrounded = [q for q in quoted if q.lower() not in haystack]
  if ungrounded:
    return False, f"quoted string(s) not found in evidence: {ungrounded}"
  return True, f"all {len(quoted)} quoted string(s) grounded in evidence"


def inline_id_validity(response: Mapping[str, Any], evidence_citation_ids) -> tuple[bool, str]:
  """Gate (c): inline `[E#]`/`[L#]`/`[F#]` tokens in the finding text must
  resolve in the rendered evidence's citation-ID universe. Catches
  fabricated entities/relationships introduced via a fake inline ID even
  when the surrounding text is not quoted (lexical_grounding only checks
  quoted strings)."""
  finding = response.get("finding") or ""
  universe = set(evidence_citation_ids)
  inline_ids = INLINE_ID_RE.findall(finding)
  invalid = [i for i in inline_ids if i not in universe]
  if invalid:
    return False, f"inline citation token(s) not present in rendered evidence: {invalid}"
  return True, f"all {len(inline_ids)} inline citation token(s) resolve in the evidence"


def _normalize(text: Any) -> str:
  return re.sub(r"\s+", " ", (text or "").strip().lower())


def _jaccard(text_a: str, text_b: str) -> float:
  tokens_a = set(re.findall(r"[a-z0-9]+", text_a.lower()))
  tokens_b = set(re.findall(r"[a-z0-9]+", text_b.lower()))
  if not tokens_a and not tokens_b:
    return 1.0
  if not tokens_a or not tokens_b:
    return 0.0
  return len(tokens_a & tokens_b) / len(tokens_a | tokens_b)


def duplicate_findings(findings: Sequence[Mapping[str, Any]], jaccard_threshold: float = DUPLICATE_JACCARD_THRESHOLD) -> tuple[bool, str]:
  """Gate (d): no two findings may be near-duplicates -- normalized-text
  equality, or > `jaccard_threshold` token-overlap. Vacuously passes for a
  single-pass response (one finding, no pairs to compare)."""
  dupes = []
  for i in range(len(findings)):
    for j in range(i + 1, len(findings)):
      text_i = findings[i].get("finding") or ""
      text_j = findings[j].get("finding") or ""
      if _normalize(text_i) == _normalize(text_j):
        dupes.append((i, j, "exact"))
        continue
      score = _jaccard(text_i, text_j)
      if score > jaccard_threshold:
        dupes.append((i, j, f"jaccard={score:.2f}"))
  if dupes:
    return False, f"duplicate finding pair(s): {dupes}"
  return True, f"no duplicates among {len(findings)} finding(s)"


def distinct_anchors(findings: Sequence[Mapping[str, Any]], redundancy_jaccard: float = REDUNDANCY_JACCARD_THRESHOLD) -> tuple[bool, str]:
  """Gate (e): findings may legitimately share an anchor (hub-shaped
  evidence: one actor with many techniques), so a shared first-cited ID is
  only a failure when the two findings' full citation SETS are also
  near-identical -- that is redundancy, not perspective. Vacuously passes for
  a single-pass response (one finding, no pairs to compare)."""
  anchored = []
  unanchored = 0
  for i, finding in enumerate(findings):
    citations = finding.get("citations") or []
    if citations:
      anchored.append((i, citations[0], set(citations)))
    else:
      unanchored += 1

  redundant = []
  for a in range(len(anchored)):
    for b in range(a + 1, len(anchored)):
      i, first_i, set_i = anchored[a]
      j, first_j, set_j = anchored[b]
      if first_i != first_j:
        continue
      union = set_i | set_j
      jaccard = (len(set_i & set_j) / len(union)) if union else 1.0
      if jaccard >= redundancy_jaccard:
        redundant.append((i, j, first_i, round(jaccard, 2)))

  if redundant:
    return False, f"redundant findings sharing anchor and near-identical citations: {redundant}; {unanchored} unanchored"
  return True, f"{len(anchored)} anchored finding(s), no redundant anchor pairs; {unanchored} unanchored"


GATES = {
  "citation_membership": citation_membership,
  "lexical_grounding": lexical_grounding,
  "inline_id_validity": inline_id_validity,
  "duplicate_findings": duplicate_findings,
  "distinct_anchors": distinct_anchors,
}
GATE_NAMES = tuple(GATES.keys())


def evaluate_all(response: Mapping[str, Any], rendered) -> dict[str, tuple[bool, str]]:
  """Evaluate all five gates for a single-pass (one-finding) response.

  `rendered` exposes `.text` and `.citation_universe()` (see
  `explain_notation.RenderedEvidence`).
  """
  universe = rendered.citation_universe()
  findings = [response]
  return {
    "citation_membership": citation_membership(response, universe),
    "lexical_grounding": lexical_grounding(response, rendered.text),
    "inline_id_validity": inline_id_validity(response, universe),
    "duplicate_findings": duplicate_findings(findings),
    "distinct_anchors": distinct_anchors(findings),
  }
