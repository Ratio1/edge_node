"""Framework maturity packs — static, generated, never hand-edited.

A framework pack is the read-only catalogue a tenant-scoped maturity self-assessment is scored
against (contract: `project-red-mesh:docs/resources/redmesh/contracts/framework-assessment.md`).
Each pack is two JSON files under `static/`:

  framework-pack.<pack_id>.json   ids, hierarchy, entry level, key-measure and management-aspect
                                  flags, thresholds per assurance level, the acts it derives from
  framework-text.<pack_id>.json   the official requirement and guidance text per control, the
                                  category and subcategory titles, the five maturity definitions

Both are produced by the hub workbook `project-red-mesh:workbooks/redmesh-framework-pack/` from
the official texts and committed here with a provenance header. Scoring rules live in
`services/framework_scoring.py`, not in the pack. There is no staleness gate: a pack changes only
when the issuing authority amends the act, and the amendment is appended to `acts`.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_STATIC_DIR = Path(__file__).parent / "static"

FRAMEWORK_PACK_IDS: tuple[str, ...] = ("ro.dnsc.o1-2026",)
FRAMEWORK_LEVELS: tuple[str, ...] = ("basic", "important", "essential")

_PACK_KEYS = ("pack_id", "catalogue", "scoring", "language", "acts", "levels", "thresholds", "counts",
              "provenance", "controls", "source", "version", "last_refreshed")
_CONTROL_KEYS = ("ref_id", "category", "subcategory", "entry_level", "key_measure", "management_aspect", "order")
_THRESHOLD_KEYS = ("key_measure_min", "category_min", "total_min", "excluded_value", "max_excluded")
_TEXT_KEYS = ("pack_id", "language", "provenance", "maturity_levels", "functions", "categories",
              "subcategories", "controls")


class FrameworkPackError(ValueError):
  """A pack file is missing, unknown or malformed."""


def _require_known(pack_id: str) -> str:
  if not isinstance(pack_id, str) or pack_id not in FRAMEWORK_PACK_IDS:
    raise FrameworkPackError(f"unknown framework pack: {pack_id!r}")
  return pack_id


def _read(path: Path) -> dict:
  if not path.is_file():
    raise FrameworkPackError(f"missing pack file: {path.name}")
  with path.open(encoding="utf-8") as fh:
    data = json.load(fh)
  if not isinstance(data, dict):
    raise FrameworkPackError(f"{path.name}: top level is not an object")
  return data


def _validate_pack(data: dict, pack_id: str) -> dict:
  missing = [k for k in _PACK_KEYS if k not in data]
  if missing:
    raise FrameworkPackError(f"{pack_id}: pack missing keys {missing}")
  if data["pack_id"] != pack_id:
    raise FrameworkPackError(f"{pack_id}: pack_id field is {data['pack_id']!r}")
  if list(data["levels"]) != list(FRAMEWORK_LEVELS):
    raise FrameworkPackError(f"{pack_id}: levels {data['levels']} != {list(FRAMEWORK_LEVELS)}")
  for level in FRAMEWORK_LEVELS:
    th = data["thresholds"].get(level)
    if not isinstance(th, dict) or any(k not in th for k in _THRESHOLD_KEYS):
      raise FrameworkPackError(f"{pack_id}: thresholds for {level} incomplete")
  seen = set()
  for control in data["controls"]:
    if any(k not in control for k in _CONTROL_KEYS):
      raise FrameworkPackError(f"{pack_id}: control {control.get('ref_id')!r} incomplete")
    if control["entry_level"] not in FRAMEWORK_LEVELS:
      raise FrameworkPackError(f"{pack_id}: {control['ref_id']} has entry level {control['entry_level']!r}")
    if control["ref_id"] in seen:
      raise FrameworkPackError(f"{pack_id}: duplicate control {control['ref_id']}")
    seen.add(control["ref_id"])
  if data["counts"].get("controls") != len(data["controls"]):
    raise FrameworkPackError(f"{pack_id}: counts.controls {data['counts'].get('controls')} != {len(data['controls'])}")
  return data


def _validate_text(data: dict, pack_id: str, pack: dict) -> dict:
  missing = [k for k in _TEXT_KEYS if k not in data]
  if missing:
    raise FrameworkPackError(f"{pack_id}: text missing keys {missing}")
  if data["pack_id"] != pack_id:
    raise FrameworkPackError(f"{pack_id}: text pack_id field is {data['pack_id']!r}")
  ids = {c["ref_id"] for c in pack["controls"]}
  if set(data["controls"]) != ids:
    raise FrameworkPackError(f"{pack_id}: text ids differ from pack ids")
  for ref_id, entry in data["controls"].items():
    if not entry.get("requirement") or not entry.get("guidance"):
      raise FrameworkPackError(f"{pack_id}: {ref_id} has empty text")
  if [m.get("value") for m in data["maturity_levels"]] != [1, 2, 3, 4, 5]:
    raise FrameworkPackError(f"{pack_id}: maturity_levels must be 1..5")
  return data


@lru_cache(maxsize=8)
def load_framework_pack(pack_id: str) -> dict:
  """Return the pack dict for `pack_id`. Treat the result as read-only."""
  pack_id = _require_known(pack_id)
  return _validate_pack(_read(_STATIC_DIR / f"framework-pack.{pack_id}.json"), pack_id)


@lru_cache(maxsize=8)
def load_framework_text(pack_id: str) -> dict:
  """Return the official text dict for `pack_id`. Treat the result as read-only."""
  pack_id = _require_known(pack_id)
  pack = load_framework_pack(pack_id)
  return _validate_text(_read(_STATIC_DIR / f"framework-text.{pack_id}.json"), pack_id, pack)


def list_framework_pack_ids() -> tuple[str, ...]:
  return FRAMEWORK_PACK_IDS


def level_index(level: str) -> int:
  if level not in FRAMEWORK_LEVELS:
    raise FrameworkPackError(f"unknown assurance level: {level!r}")
  return FRAMEWORK_LEVELS.index(level)


def controls_for_level(pack: dict, level: str) -> list[dict]:
  """Controls counted at `level`: entry level at or below it (levels are cumulative), in pack order."""
  limit = level_index(level)
  return [c for c in pack["controls"] if level_index(c["entry_level"]) <= limit]


def reset_framework_caches() -> None:
  """Test-only helper to clear the @lru_cache instances."""
  load_framework_pack.cache_clear()
  load_framework_text.cache_clear()
