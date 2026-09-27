"""EdgeGuard literal classes and synonym lookup (contract v0.11 §3).

Stdlib only, no imports from the `edgeguard` package: this module holds no
file paths and does no I/O, so it can be vendored by sha into the hub dataset
validator without pulling in edge_node's plugin machinery (EGM-059 phase 5).
Callers load the schema artifact JSON themselves and pass the resulting dict
in.

Contract §3.1 defines two literal classes:
- `closed_vocabulary`: a value of a small enumerated property (`indicator_type`,
  `Sector.name`, `base_severity`, tactic ids). Exempt from substring grounding
  when the request uses wording the artifact's synonym table maps to that
  value.
- `free`: everything else (indicator values, ids, names, dates). Must appear
  in the request text (case-folded), a campaign literal matched with and
  without its trailing " Campaign" suffix.
"""

from __future__ import annotations

import re
from typing import Any, Mapping

__VER__ = "0.1.0.0"

CLOSED_VOCABULARY = "closed_vocabulary"
FREE = "free"

_CAMPAIGN_SUFFIX = " campaign"

# A single-word tactic/value name that is also a common noun inside an
# unrelated compound security term: a request naming that noun as part of the
# compound (e.g. "remote code execution", a CWE/CVE concept) must not ground
# the ATT&CK tactic id (`edgeguard_cypher_guard.py` v0.11 review finding 3).
# Keyed by the casefolded wording; value is the set of casefolded words that,
# immediately preceding the match, invalidate it.
_DENIED_PRECEDING_WORD = {
  "execution": {"code"},
}


def _token_boundary_match(phrase_cf: str, request_cf: str) -> bool:
  """True when `phrase_cf` (already casefolded) occurs in `request_cf` as a
  whole run of words, not embedded inside a longer word ("ip" inside
  "relationship", "link" inside "linked", "high" inside "highest", "impact"
  inside "impacted") and not immediately preceded by a word on its own
  deny-list (see `_DENIED_PRECEDING_WORD`)."""
  if not phrase_cf:
    return False
  pattern = re.compile(r"(?<!\w)" + re.escape(phrase_cf) + r"(?!\w)")
  denylist = _DENIED_PRECEDING_WORD.get(phrase_cf)
  for match in pattern.finditer(request_cf):
    if denylist:
      preceding = request_cf[:match.start()].rstrip()
      preceding_word = preceding.rsplit(None, 1)[-1] if preceding else ""
      if preceding_word.strip(".,;:!?\"'()[]{}") in denylist:
        continue
    return True
  return False


def _vocabulary_values(entries: Any) -> list[str]:
  """Vocabulary entries are `{value: count_or_name}` in the schema artifact;
  accept a list of `[value, ...]` pairs too, for callers that pass a reduced
  fixture instead of the full artifact."""
  if isinstance(entries, Mapping):
    return [str(value) for value in entries.keys()]
  if isinstance(entries, (list, tuple)):
    return [str(entry[0]) if isinstance(entry, (list, tuple)) else str(entry) for entry in entries]
  return []


# Review finding Q8: the schema artifact is loaded once per process and the
# same object is passed on every call (`EDGEGUARD_SCHEMA_V0_11`), so
# rescanning its full vocabulary/synonym table on every literal check is
# wasted work. Single-slot cache keyed by the artifact object's identity —
# a different artifact object (a test fixture, say) always recomputes.
_closed_vocabulary_index_cache: tuple[Any, dict[str, list[dict[str, str]]]] | None = None
_synonym_index_cache: tuple[Any, dict[tuple[str, str], list[str]]] | None = None


def build_closed_vocabulary_index(artifact: Mapping[str, Any] | None) -> dict[str, list[dict[str, str]]]:
  """casefolded literal value -> list of `{"property": "Label.field", "value": value}`."""
  global _closed_vocabulary_index_cache
  if _closed_vocabulary_index_cache is not None and _closed_vocabulary_index_cache[0] is artifact:
    return _closed_vocabulary_index_cache[1]
  source = artifact or {}
  index: dict[str, list[dict[str, str]]] = {}
  for prop, entries in (source.get("vocabularies") or {}).items():
    for value in _vocabulary_values(entries):
      index.setdefault(value.casefold(), []).append({"property": str(prop), "value": value})
  _closed_vocabulary_index_cache = (artifact, index)
  return index


def build_synonym_index(artifact: Mapping[str, Any] | None) -> dict[tuple[str, str], list[str]]:
  """`(property, casefolded value)` -> wordings that imply that value.

  `property` may be a `*.field` wildcard row (contract §3.1: severity applies
  the same way across every CVSS label)."""
  global _synonym_index_cache
  if _synonym_index_cache is not None and _synonym_index_cache[0] is artifact:
    return _synonym_index_cache[1]
  source = artifact or {}
  index: dict[tuple[str, str], list[str]] = {}
  for row in source.get("synonyms") or []:
    prop = str(row.get("property", ""))
    wording = [str(word) for word in row.get("wording", [])]
    for value in row.get("values", []):
      key = (prop, str(value).casefold())
      index.setdefault(key, []).extend(wording)
  _synonym_index_cache = (artifact, index)
  return index


def classify_literal(literal: str, artifact: Mapping[str, Any] | None = None) -> dict[str, Any]:
  """Contract §3.1: `closed_vocabulary` when the literal is a value of a
  closed-vocabulary property on the schema artifact, `free` otherwise."""
  candidates = build_closed_vocabulary_index(artifact).get(str(literal).strip().casefold(), [])
  if candidates:
    return {"class": CLOSED_VOCABULARY, "candidates": candidates}
  return {"class": FREE, "candidates": []}


def _wildcard_property(prop: str) -> str | None:
  if "." not in prop:
    return None
  _, field = prop.split(".", 1)
  return f"*.{field}"


def literal_is_grounded(
  literal: str,
  request_text: str,
  artifact: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
  """Contract §3.2: is `literal` grounded in `request_text`?

  Returns the classification (`class`, `candidates`) plus `grounded`, the
  `matched_wording` (`None` when the literal itself was the match rather than
  a synonym wording) and `grounded_properties` (the closed-vocabulary
  property or properties the match grounds this literal for; empty for
  `free` or an ungrounded result) — used by the retry-retention rule (§3.2)
  to key a grounded value by property, not by value text alone.

  Closed-vocabulary matching (the literal itself or a synonym wording) is
  token-boundary: the phrase must occur as a whole run of words, not
  embedded inside a longer word ("ip" inside "relationship" or "ship",
  "link" inside "linked", "low" inside "allow", "high" inside "highest",
  "impact" inside "impacted"). `free` literals keep substring matching
  (indicator values, ids, names and dates are copied verbatim, so a
  defanged/quoted variant may not sit on a word boundary).
  """
  classification = classify_literal(literal, artifact)
  literal_cf = str(literal).strip().casefold()
  request_cf = str(request_text or "").casefold()

  if classification["class"] == CLOSED_VOCABULARY:
    if literal_cf and _token_boundary_match(literal_cf, request_cf):
      properties = sorted({candidate["property"] for candidate in classification["candidates"]})
      return {
        **classification, "grounded": True, "matched_wording": None,
        "grounded_properties": properties,
      }
    synonyms = build_synonym_index(artifact)
    for candidate in classification["candidates"]:
      prop = candidate["property"]
      value_cf = candidate["value"].casefold()
      keys = [(prop, value_cf)]
      wildcard = _wildcard_property(prop)
      if wildcard:
        keys.append((wildcard, value_cf))
      for key in keys:
        for wording in synonyms.get(key, []):
          if _token_boundary_match(str(wording).casefold(), request_cf):
            return {
              **classification, "grounded": True, "matched_wording": wording,
              "grounded_properties": [prop],
            }
    return {**classification, "grounded": False, "matched_wording": None, "grounded_properties": []}

  # free: a campaign literal is matched with and without the trailing
  # " Campaign" (contract §3.1).
  if literal_cf and literal_cf in request_cf:
    return {**classification, "grounded": True, "matched_wording": None, "grounded_properties": []}
  if literal_cf.endswith(_CAMPAIGN_SUFFIX):
    trimmed = literal_cf[: -len(_CAMPAIGN_SUFFIX)]
    if trimmed and trimmed in request_cf:
      return {**classification, "grounded": True, "matched_wording": None, "grounded_properties": []}
  elif literal_cf and f"{literal_cf}{_CAMPAIGN_SUFFIX}" in request_cf:
    return {**classification, "grounded": True, "matched_wording": None, "grounded_properties": []}
  return {**classification, "grounded": False, "matched_wording": None, "grounded_properties": []}


def format_literal_rejection(literal: str, literal_class: str) -> str:
  """Contract §3.2 rejection template, naming the literal and its class."""
  return f"Literal '{literal}' ({literal_class}) is not in the request."
