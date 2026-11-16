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
import re
from functools import lru_cache
from pathlib import Path

_STATIC_DIR = Path(__file__).parent / "static"

MANIFEST_SCHEMA = "redmesh.framework_manifest.v1"
PACK_SCHEMAS = ("redmesh.framework_pack.v1",)
TEXT_SCHEMAS = ("redmesh.framework_text.v1",)
# Draft fields only some regimes accept; a pack lists the ones it takes in `rules.entity_fields`.
REGIME_FIELDS = ("dnsc_unique_id", "external_supplier")
# The member states a `jurisdiction: "EU"` entry covers (ISO 3166-1 alpha-2; Greece is `GR`).
EU_MEMBER_STATES = frozenset("AT BE BG HR CY CZ DK EE FI FR DE GR HU IE IT LV LT LU MT NL PL PT RO SK SI ES SE".split())
# ISO 3166-1 alpha-2 labels; worldwide scope still refuses arbitrary two-letter strings.
COUNTRY_CODES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ
BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM
DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS
GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN
KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ
MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM
PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV
SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI
VN VU WF WS YE YT ZA ZM ZW
""".split())
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


def _validate_manifest_pack(pack: dict, taxonomy: dict) -> None:
  pid = pack.get("pack_id") if isinstance(pack, dict) else None
  if not isinstance(pid, str):
    raise FrameworkPackError(f"manifest pack {pid!r}: bad pack_id")
  licence, rules = pack.get("licence"), pack.get("rules")
  licence, rules = licence if isinstance(licence, dict) else {}, rules if isinstance(rules, dict) else {}
  checks = {
    "title": isinstance(pack.get("title"), str) and 0 < len(pack["title"]) <= 120,
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
    if (missing or bool(entry["country"]) == bool(entry["jurisdiction"]) or entry["jurisdiction"] not in (None, "EU", "WORLDWIDE")
        or (entry["country"] is not None and (not isinstance(entry["country"], str) or entry["country"] not in COUNTRY_CODES))):
      raise FrameworkPackError(f"manifest pack {pid}: bad applicability entry (missing {missing}; "
                               "needs a valid country or jurisdiction EU/WORLDWIDE)")

    codes = entry["sectors"]
    coverage = entry.get("sector_coverage", "unknown")
    ref = {"id": taxonomy["id"], "version": taxonomy["version"]}
    supplied_ref = entry.get("sector_taxonomy", ref if coverage == "unknown" else None)
    if (coverage not in ("listed", "cross_sector", "unknown")
        or not isinstance(codes, list) or any(not isinstance(c, str) for c in codes)
        or len(set(codes)) != len(codes) or not set(codes) <= {s["code"] for s in taxonomy["sectors"]}
        or (bool(codes) != (coverage == "listed"))
        or not isinstance(supplied_ref, dict) or supplied_ref != ref
        or type(supplied_ref.get("version")) is not int
        or not isinstance(entry.get("sector_scope_note", ""), str)
        or len(entry.get("sector_scope_note", "")) > 1000):
      raise FrameworkPackError(f"manifest pack {pid}: bad sector coverage")
    entry.setdefault("sector_coverage", "unknown")
    entry.setdefault("sector_taxonomy", ref)


def _validate_taxonomy(taxonomy):
  if (not isinstance(taxonomy, dict) or taxonomy.get("id") != "redmesh.nis2-sectors"
      or type(taxonomy.get("version")) is not int or taxonomy["version"] != 1
      or not isinstance(taxonomy.get("source_url"), str) or not taxonomy["source_url"].startswith("https://")
      or not isinstance(taxonomy.get("sectors"), list) or len(taxonomy["sectors"]) != 18):
    raise FrameworkPackError("framework manifest: bad sector taxonomy")
  codes = set()
  for sector in taxonomy["sectors"]:
    if (not isinstance(sector, dict) or any(not isinstance(sector.get(k), str) or not 0 < len(sector[k]) <= 200
        for k in ("code", "label", "title", "source_location"))
        or re.fullmatch(r"rm\.nis2\.[a-z][a-z-]*", sector["code"]) is None
        or re.fullmatch(r"I\.([1-9]|10|11)|II\.[1-7]", sector["source_location"]) is None
        or sector["code"] in codes):
      raise FrameworkPackError("framework manifest: bad sector declaration")
    codes.add(sector["code"])


@lru_cache(maxsize=1)
def load_manifest() -> dict:
  """The applicability manifest (contract `redmesh.framework_manifest.v1`), validated once."""
  data = _read(_STATIC_DIR / "framework-manifest.json")
  if (data.get("schema") != MANIFEST_SCHEMA or type(data.get("manifest_version")) is not int
      or not isinstance(data.get("packs"), list)):
    raise FrameworkPackError("framework manifest: bad schema, version or packs")
  _validate_taxonomy(data.get("sector_taxonomy"))
  for pack in data["packs"]:
    _validate_manifest_pack(pack, data["sector_taxonomy"])
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
