"""CVSS entries of a finding, normalised for the outward exporters (LLM input, STIX, MISP)."""
from __future__ import annotations

import re
from typing import Any

# Metric values are one capital letter, except the v4.0 supplemental Provider Urgency (U:Clear|Green|Amber|Red).
CVSS_VECTOR_RE = re.compile(r"^CVSS:[0-9.]+(/(?:U:(?:Clear|Green|Amber|Red)|[A-Z]+:[A-Z]))+$")
MAX_CVSS_VECTOR_CHARS = 256
_VERSION_ORDER = {"3.1": 0, "3.0": 1, "4.0": 2}
# v4.0 threat metric (E) and environmental metrics; `X` means "not defined". Supplemental metrics do not count.
_V4_THREAT = {"E"}
_V4_ENV = {"CR", "IR", "AR", "MAV", "MAC", "MAT", "MPR", "MUI", "MVC", "MVI", "MVA", "MSC", "MSI", "MSA"}


def cvss_v4_nomenclature(vector: str) -> str:
  """CVSS v4.0 nomenclature of a vector (spec section 1.3): CVSS-B, CVSS-BT, CVSS-BE or CVSS-BTE."""
  metrics = {m for m, _, v in (p.partition(":") for p in vector.split("/")[1:]) if v != "X"}
  return "CVSS-B" + ("T" if metrics & _V4_THREAT else "") + ("E" if metrics & _V4_ENV else "")


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
    if (version not in _VERSION_ORDER or not is_cvss_vector(vector)
        or not vector.startswith(f"CVSS:{version}/") or (version, vector) in seen):
      continue
    seen.add((version, vector))
    item = {"version": version, "vector": vector}
    score = entry.get("score")
    if isinstance(score, (int, float)) and not isinstance(score, bool):
      item["score"] = score
    if entry.get("source"):
      item["source"] = str(entry["source"])[:32]
    if version == "4.0":
      item["nomenclature"] = cvss_v4_nomenclature(vector)
    out.append(item)
  return sorted(out, key=lambda e: _VERSION_ORDER[e["version"]])
