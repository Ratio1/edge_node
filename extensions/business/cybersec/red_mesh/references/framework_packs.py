"""Framework maturity packs — static, generated, never hand-edited.

A framework pack is the read-only catalogue a tenant-scoped maturity self-assessment is scored
against (contract: `project-red-mesh:docs/resources/redmesh/contracts/framework-assessment.md`).
Each pack is a pack file and an optional text file under `static/`; `framework-manifest.json` lists them:

  framework-pack.<pack_id>.json   ids, hierarchy, entry level, key-measure and management-aspect
                                  flags, thresholds per assurance level, the acts it derives from
  framework-text.<pack_id>.json   the official requirement and guidance text per control, the
                                  category and subcategory titles, the five maturity definitions

Both are produced by the hub workbook `project-red-mesh:workbooks/redmesh-framework-pack/` from
the official texts and committed here with a provenance header. Scoring rules live in
`services/framework_scoring.py`, not in the pack; the pack's scorer validates it. There is no staleness gate: a pack changes only
when the issuing authority amends the act, and the amendment is appended to `acts`.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_STATIC_DIR = Path(__file__).parent / "static"

MANIFEST_SCHEMA = "redmesh.framework_manifest.v1"
PACK_SCHEMAS = ("redmesh.framework_pack.v1",)
TEXT_SCHEMAS = ("redmesh.framework_text.v1",)
# Draft fields only some regimes accept; a pack lists the ones it takes in `rules.entity_fields`.
REGIME_FIELDS = ("dnsc_unique_id", "external_supplier")
_RULE_SWITCHES = ("justification_required", "exclusion_reason_required", "remediation_on_fail", "signoff_required")
_RULE_LISTS = ("level_provenance_kinds", "exports")
_ENTRY_KEYS = ("country", "jurisdiction", "sectors", "legal_force", "accepted_alternatives", "source_url",
               "legal_reference", "verified_at", "verified_by")
_PACK_KEYS = ("pack_id", "catalogue", "scoring", "language", "controls")
_TEXT_KEYS = ("pack_id", "language", "controls")


class FrameworkPackError(ValueError):
  """A pack file is missing, unknown or malformed."""


def _read(path: Path) -> dict:
  if not path.is_file():
    raise FrameworkPackError(f"missing pack file: {path.name}")
  with path.open(encoding="utf-8") as fh:
    data = json.load(fh)
  if not isinstance(data, dict):
    raise FrameworkPackError(f"{path.name}: top level is not an object")
  return data


def _validate_manifest_pack(pack: dict) -> None:
  pid = pack.get("pack_id") if isinstance(pack, dict) else None
  if not isinstance(pid, str):
    raise FrameworkPackError(f"manifest pack {pid!r}: bad pack_id")
  licence, rules = pack.get("licence"), pack.get("rules")
  licence, rules = licence if isinstance(licence, dict) else {}, rules if isinstance(rules, dict) else {}
  checks = {
    "version": type(pack.get("version")) is int,
    "status": pack.get("status") in ("active", "retired"),
    "supersedes": "supersedes" in pack, "derived_from": "derived_from" in pack,
    "scoring": isinstance(pack.get("scoring"), str),
    "pack_schema": pack.get("pack_schema") in PACK_SCHEMAS, "text_schema": pack.get("text_schema") in TEXT_SCHEMAS,
    "pack_sha256": isinstance(pack.get("pack_sha256"), str), "text_sha256": isinstance(pack.get("text_sha256"), dict),
    "languages": isinstance(pack.get("languages"), list) and bool(pack["languages"]),
    "licence.id": isinstance(licence.get("id"), str), "licence.attribution": isinstance(licence.get("attribution"), str),
    "licence.ship_text": type(licence.get("ship_text")) is bool,
    "entries": isinstance(pack.get("entries"), list),
    **{f"rules.{k}": type(rules.get(k)) is bool for k in _RULE_SWITCHES},
    **{f"rules.{k}": isinstance(rules.get(k), list) for k in _RULE_LISTS},
    "rules.entity_fields": isinstance(rules.get("entity_fields"), list) and set(rules["entity_fields"]) <= set(REGIME_FIELDS),
  }
  for key, ok in checks.items():
    if not ok:
      raise FrameworkPackError(f"manifest pack {pid}: bad or missing {key}")
  for entry in pack["entries"]:
    missing = [k for k in _ENTRY_KEYS if not isinstance(entry, dict) or k not in entry]
    if missing or bool(entry["country"]) == bool(entry["jurisdiction"]) or entry["jurisdiction"] not in (None, "EU"):
      raise FrameworkPackError(f"manifest pack {pid}: bad applicability entry (missing {missing}; "
                               "needs a country or jurisdiction EU)")


@lru_cache(maxsize=1)
def load_manifest() -> dict:
  """The applicability manifest (contract `redmesh.framework_manifest.v1`), validated once."""
  data = _read(_STATIC_DIR / "framework-manifest.json")
  if (data.get("schema") != MANIFEST_SCHEMA or type(data.get("manifest_version")) is not int
      or not isinstance(data.get("packs"), list)):
    raise FrameworkPackError("framework manifest: bad schema, version or packs")
  for pack in data["packs"]:
    _validate_manifest_pack(pack)
  if len({p["pack_id"] for p in data["packs"]}) != len(data["packs"]):
    raise FrameworkPackError("framework manifest: duplicate pack id")
  return data


def manifest_pack(pack_id: str) -> dict:
  for entry in load_manifest()["packs"]:
    if entry["pack_id"] == pack_id:
      return entry
  raise FrameworkPackError(f"unknown framework pack: {pack_id!r}")


def pack_rules(pack: dict) -> dict:
  """The manifest rule block of `pack` (a loaded pack dict). Treat as read-only."""
  return manifest_pack(pack["pack_id"])["rules"]


def _validate_pack(data: dict, pack_id: str) -> dict:
  from ..services.framework_scoring import scorer_for  # the scorer registry; imports this module
  missing = [k for k in _PACK_KEYS if k not in data]
  if missing:
    raise FrameworkPackError(f"{pack_id}: pack missing keys {missing}")
  if data["pack_id"] != pack_id:
    raise FrameworkPackError(f"{pack_id}: pack_id field is {data['pack_id']!r}")
  levels = data.get("levels") or []
  if not isinstance(levels, list) or not all(isinstance(v, str) for v in levels) or len(set(levels)) != len(levels):
    raise FrameworkPackError(f"{pack_id}: levels must be a list of distinct ids")
  if not isinstance(data["controls"], list):
    raise FrameworkPackError(f"{pack_id}: controls is not a list")
  seen = set()
  for control in data["controls"]:
    if not isinstance(control, dict) or not isinstance(control.get("ref_id"), str) or type(control.get("order")) is not int:
      raise FrameworkPackError(f"{pack_id}: control {control!r} incomplete")
    if levels and control.get("entry_level") not in levels:
      raise FrameworkPackError(f"{pack_id}: {control['ref_id']} has entry level {control.get('entry_level')!r}")
    if control["ref_id"] in seen:
      raise FrameworkPackError(f"{pack_id}: duplicate control {control['ref_id']}")
    seen.add(control["ref_id"])
  scorer_for(data).check_pack(data, None)
  return data


def _validate_hierarchy(nodes, pack_id: str) -> None:
  ids = [n.get("id") for n in nodes] if isinstance(nodes, list) and all(isinstance(n, dict) for n in nodes) else None
  if ids is None or not all(isinstance(i, str) for i in ids) or len(set(ids)) != len(ids):
    raise FrameworkPackError(f"{pack_id}: text hierarchy needs unique string node ids")
  parent = {n["id"]: n.get("parent") for n in nodes}
  for node_id in ids:
    hops, cursor = 0, parent[node_id]
    while cursor is not None:
      hops, cursor = hops + 1, parent.get(cursor, "")
      if cursor == "" or hops > len(ids):
        raise FrameworkPackError(f"{pack_id}: text hierarchy node {node_id} has an unknown parent or a cycle")


def _validate_text(data: dict, pack_id: str, pack: dict) -> dict:
  from ..services.framework_scoring import scorer_for
  missing = [k for k in _TEXT_KEYS if k not in data]
  if missing:
    raise FrameworkPackError(f"{pack_id}: text missing keys {missing}")
  if data["pack_id"] != pack_id:
    raise FrameworkPackError(f"{pack_id}: text pack_id field is {data['pack_id']!r}")
  controls = data["controls"]
  if not isinstance(controls, dict) or not all(isinstance(e, dict) for e in controls.values()):
    raise FrameworkPackError(f"{pack_id}: text controls must map ids to objects")
  if set(controls) - {c["ref_id"] for c in pack["controls"]}:
    raise FrameworkPackError(f"{pack_id}: text ids are not all pack ids")
  if "hierarchy" in data:
    _validate_hierarchy(data["hierarchy"], pack_id)
  scorer_for(pack).check_pack(pack, data)
  return data


@lru_cache(maxsize=8)
def load_framework_pack(pack_id: str) -> dict:
  """Return the pack dict for `pack_id`. Treat the result as read-only."""
  entry = manifest_pack(pack_id)
  data = _read(_STATIC_DIR / f"framework-pack.{pack_id}.json")
  if data.get("scoring") != entry["scoring"]:
    raise FrameworkPackError(f"{pack_id}: pack scoring {data.get('scoring')!r} != manifest {entry['scoring']!r}")
  return _validate_pack(data, pack_id)


@lru_cache(maxsize=16)
def load_framework_text(pack_id: str, language: str | None = None) -> dict | None:
  """The text dict of `pack_id` in `language` (default: the first manifest language), or None when the
  licence ships no text and no file exists. The first language may sit in `framework-text.<id>.json`."""
  entry, pack = manifest_pack(pack_id), load_framework_pack(pack_id)
  language = language or entry["languages"][0]
  if language not in entry["languages"]:
    raise FrameworkPackError(f"{pack_id}: no text language {language!r}")
  names = [f"framework-text.{pack_id}.{language}.json"]
  if language == entry["languages"][0]:
    names.append(f"framework-text.{pack_id}.json")
  path = next((_STATIC_DIR / n for n in names if (_STATIC_DIR / n).is_file()), None)
  if path is None:
    if entry["licence"]["ship_text"]:
      raise FrameworkPackError(f"missing pack file: {names[0]}")
    return None
  return _validate_text(_read(path), pack_id, pack)


def list_framework_pack_ids(include_retired: bool = False) -> tuple[str, ...]:
  return tuple(p["pack_id"] for p in load_manifest()["packs"] if include_retired or p["status"] == "active")


def pack_levels(pack: dict) -> tuple[str, ...]:
  """The pack's level ids in cumulative order; empty for a tier-less pack."""
  return tuple(pack.get("levels") or ())


def level_index(pack: dict, level: str) -> int:
  levels = pack_levels(pack)
  if level not in levels:
    raise FrameworkPackError(f"unknown assurance level: {level!r}")
  return levels.index(level)


def controls_for_level(pack: dict, level: str | None) -> list[dict]:
  """Controls counted at `level`: entry level at or below it (levels are cumulative), in pack order.
  `level` may be None only for a pack with no levels, which counts every control."""
  if level is None and not pack_levels(pack):
    return list(pack["controls"])
  limit = level_index(pack, level)
  return [c for c in pack["controls"] if level_index(pack, c["entry_level"]) <= limit]


def reset_framework_caches() -> None:
  """Test-only helper to clear the @lru_cache instances."""
  load_manifest.cache_clear()
  load_framework_pack.cache_clear()
  load_framework_text.cache_clear()
