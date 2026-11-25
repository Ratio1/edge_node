"""CVSS entries of a finding, normalised for the outward exporters (LLM input, STIX, MISP)."""
from __future__ import annotations

import re
from typing import Any

# Metric values are one capital letter, except the v4.0 supplemental Provider Urgency (U:Clear|Green|Amber|Red).
CVSS_VECTOR_RE = re.compile(r"^CVSS:[0-9.]+(/(?:U:(?:Clear|Green|Amber|Red)|[A-Z]+:[A-Z]))+$")
MAX_CVSS_VECTOR_CHARS = 256
_VERSION_ORDER = {"3.1": 0, "3.0": 1, "4.0": 2}


def is_cvss_vector(value: Any) -> bool:
  """True for a string that follows the CVSS vector grammar and fits the length bound."""
  return isinstance(value, str) and len(value) <= MAX_CVSS_VECTOR_CHARS and bool(CVSS_VECTOR_RE.match(value))


def cvss_entries(finding: dict) -> list[dict]:
  """`cvss[]` entries with version 3.0/3.1/4.0 and a valid vector, deduplicated by (version, vector).

  Order is v3.1, v3.0, v4.0. Each entry has `version` (str), `vector`, and `score`/`source` when set.
  """
  seen, out = set(), []
  for entry in (finding or {}).get("cvss") or ():
    if not isinstance(entry, dict):
      continue
    version = entry.get("version")
    if isinstance(version, (int, float)) and not isinstance(version, bool):
      version = f"{float(version):.1f}"
    version = str(version) if version is not None else ""
    vector = entry.get("vector")
    if version not in _VERSION_ORDER or not is_cvss_vector(vector) or (version, vector) in seen:
      continue
    seen.add((version, vector))
    item = {"version": version, "vector": vector}
    score = entry.get("score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
      item["score"] = score
    if entry.get("source"):
      item["source"] = str(entry["source"])
    out.append(item)
  return sorted(out, key=lambda e: _VERSION_ORDER[e["version"]])
