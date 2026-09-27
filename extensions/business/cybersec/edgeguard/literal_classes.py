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

from typing import Any, Mapping

__VER__ = "0.1.0.0"

CLOSED_VOCABULARY = "closed_vocabulary"
FREE = "free"

_CAMPAIGN_SUFFIX = " campaign"


def _vocabulary_values(entries: Any) -> list[str]:
  """Vocabulary entries are `{value: count_or_name}` in the schema artifact;
  accept a list of `[value, ...]` pairs too, for callers that pass a reduced
  fixture instead of the full artifact."""
  if isinstance(entries, Mapping):
    return [str(value) for value in entries.keys()]
  if isinstance(entries, (list, tuple)):
    return [str(entry[0]) if isinstance(entry, (list, tuple)) else str(entry) for entry in entries]
  return []


def build_closed_vocabulary_index(artifact: Mapping[str, Any] | None) -> dict[str, list[dict[str, str]]]:
  """casefolded literal value -> list of `{"property": "Label.field", "value": value}`."""
  artifact = artifact or {}
  index: dict[str, list[dict[str, str]]] = {}
  for prop, entries in (artifact.get("vocabularies") or {}).items():
    for value in _vocabulary_values(entries):
      index.setdefault(value.casefold(), []).append({"property": str(prop), "value": value})
  return index


def build_synonym_index(artifact: Mapping[str, Any] | None) -> dict[tuple[str, str], list[str]]:
  """`(property, casefolded value)` -> wordings that imply that value.

  `property` may be a `*.field` wildcard row (contract §3.1: severity applies
  the same way across every CVSS label)."""
  artifact = artifact or {}
  index: dict[tuple[str, str], list[str]] = {}
  for row in artifact.get("synonyms") or []:
    prop = str(row.get("property", ""))
    wording = [str(word) for word in row.get("wording", [])]
    for value in row.get("values", []):
      key = (prop, str(value).casefold())
      index.setdefault(key, []).extend(wording)
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

  Returns the classification (`class`, `candidates`) plus `grounded` and the
  `matched_wording` (`None` when the literal itself was the match rather than
  a synonym wording).
  """
  classification = classify_literal(literal, artifact)
  literal_cf = str(literal).strip().casefold()
  request_cf = str(request_text or "").casefold()

  if literal_cf and literal_cf in request_cf:
    return {**classification, "grounded": True, "matched_wording": None}

  if classification["class"] == CLOSED_VOCABULARY:
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
          if str(wording).casefold() in request_cf:
            return {**classification, "grounded": True, "matched_wording": wording}
    return {**classification, "grounded": False, "matched_wording": None}

  # free: a campaign literal is matched with and without the trailing
  # " Campaign" (contract §3.1).
  if literal_cf.endswith(_CAMPAIGN_SUFFIX):
    trimmed = literal_cf[: -len(_CAMPAIGN_SUFFIX)]
    if trimmed and trimmed in request_cf:
      return {**classification, "grounded": True, "matched_wording": None}
  elif literal_cf and f"{literal_cf}{_CAMPAIGN_SUFFIX}" in request_cf:
    return {**classification, "grounded": True, "matched_wording": None}
  return {**classification, "grounded": False, "matched_wording": None}


def format_literal_rejection(literal: str, literal_class: str) -> str:
  """Contract §3.2 rejection template, naming the literal and its class."""
  return f"Literal '{literal}' ({literal_class}) is not in the request."
