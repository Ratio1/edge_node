"""Reference data — static + dynamic.

Phase 2 of the PTES rebuild splits reference data into two tiers:

  static/  —  in-repo JSON, version-controlled, refresh quarterly.
              CWE -> OWASP mappings, OWASP category names + descriptions,
              CWE Top 25. These change rarely and shipping them in-repo
              keeps lookups deterministic across environments.

  dynamic/ —  fetched at scan time, cached, persisted to scan record.
              CVSS scores from NVD, CISA KEV status, FIRST EPSS.
              These change frequently — quarterly-stale CVSS in a
              security report is unprofessional. Each finding's
              CVSS line carries a freshness timestamp.

This module exposes the static lookups; dynamic.py (Phase 2 PR-2.2)
will expose the dynamic side.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

_STATIC_DIR = Path(__file__).parent / "static"


@dataclass(frozen=True)
class OwaspCategoryInfo:
  code: str           # "A01:2021"
  name: str           # "Broken Access Control"
  short_name: str
  description: str


@dataclass(frozen=True)
class CweTop25Entry:
  rank: int
  cwe: int
  name: str


# --- File loaders, cached ---


@lru_cache(maxsize=1)
def _load_owasp_categories() -> dict:
  with (_STATIC_DIR / "owasp_categories.json").open() as fh:
    return json.load(fh)


@lru_cache(maxsize=1)
def _load_cwe_to_owasp() -> dict:
  with (_STATIC_DIR / "cwe_to_owasp.json").open() as fh:
    return json.load(fh)


@lru_cache(maxsize=1)
def _load_cwe_top25() -> dict:
  with (_STATIC_DIR / "cwe_top25.json").open() as fh:
    return json.load(fh)


# --- Public lookups ---


def cwe_to_owasp(cwe: int) -> tuple[str, ...]:
  """Map a CWE id to its OWASP Top 10 category code(s).

  Returns an empty tuple when the CWE has no mapping. Most CWEs map
  to a single category; some (e.g., CWE-200) span two.
  """
  if not isinstance(cwe, int) or cwe <= 0:
    return ()
  data = _load_cwe_to_owasp()
  result = data.get("mappings", {}).get(str(cwe), [])
  return tuple(result)


def owasp_category(code: str) -> OwaspCategoryInfo | None:
  """Return the OwaspCategoryInfo for an OWASP Top 10 category code,
  or None for unknown codes."""
  data = _load_owasp_categories()
  raw = data.get("categories", {}).get(code)
  if raw is None:
    return None
  return OwaspCategoryInfo(
    code=raw["code"],
    name=raw["name"],
    short_name=raw["short_name"],
    description=raw["description"],
  )


def all_owasp_categories() -> list[OwaspCategoryInfo]:
  """List every OWASP Top 10 category, in code order."""
  data = _load_owasp_categories()
  result = []
  for code in sorted(data.get("categories", {}).keys()):
    info = owasp_category(code)
    if info:
      result.append(info)
  return result


def is_cwe_top25(cwe: int) -> bool:
  """True if CWE-{cwe} is in the MITRE Top 25 most dangerous list."""
  if not isinstance(cwe, int) or cwe <= 0:
    return False
  data = _load_cwe_top25()
  return any(entry["cwe"] == cwe for entry in data.get("ranked", []))


def cwe_top25_rank(cwe: int) -> int | None:
  """Return the rank (1-25) for a CWE in the Top 25 list, else None."""
  if not isinstance(cwe, int) or cwe <= 0:
    return None
  data = _load_cwe_top25()
  for entry in data.get("ranked", []):
    if entry["cwe"] == cwe:
      return entry["rank"]
  return None


# --- CI gate: refresh-staleness check ---


STALENESS_THRESHOLD_DAYS = 180  # 6 months


def staleness_days(file_basename: str) -> int:
  """Return the number of days since file_basename's last_refreshed
  field. Used by the CI staleness check (test_static_references)."""
  loader = {
    "owasp_categories.json": _load_owasp_categories,
    "cwe_to_owasp.json": _load_cwe_to_owasp,
    "cwe_top25.json": _load_cwe_top25,
  }.get(file_basename)
  if loader is None:
    raise ValueError(f"unknown reference file: {file_basename}")
  data = loader()
  refreshed = data.get("last_refreshed")
  if not refreshed:
    raise RuntimeError(f"{file_basename}: missing last_refreshed field")
  refreshed_dt = datetime.strptime(refreshed, "%Y-%m-%d").replace(tzinfo=timezone.utc)
  now = datetime.now(timezone.utc)
  return (now - refreshed_dt).days


def reset_caches() -> None:
  """Test-only helper to clear @lru_cache instances."""
  _load_owasp_categories.cache_clear()
  _load_cwe_to_owasp.cache_clear()
  _load_cwe_top25.cache_clear()
