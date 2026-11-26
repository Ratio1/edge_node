"""Scoring `maturity_two_axis.v1` for framework maturity self-assessments (RM-120).

Pure functions, no I/O. Contract:
`project-red-mesh:docs/resources/redmesh/contracts/framework-assessment.md` §Scoring.

Rules, in order:
  1. Only controls whose entry level is at or below the chosen level count (levels are cumulative).
  2. Exclusion is a validation error when the control is a key measure, when it is a
     management-aspect control and the level forbids it (Essential), when the count exceeds the
     level's `max_excluded`, or when the justification is empty. An excluded control takes
     `excluded_value` on both axes.
  3. Subcategory per axis = mean of counted controls; category per axis = mean of subcategories;
     category maturity = mean of the two axes; total = mean of category maturities; key-measure
     score = mean of the control's two axes (an assumption: the order does not define it, the
     official tool uses the mean; the per-axis view is computed and reported too). Empty groups
     are omitted from means.
  4. Verdict: every key measure >= key_measure_min; every category >= category_min when set;
     total >= total_min. Failing items are listed.
  5. At submit (validate_for_submit): an unscored non-excluded control, a missing justification on
     a scored axis, a missing management sign-off or completion date is an error; when the verdict
     fails, `remediation` must hold one item per failing key measure, per failing category and
     `total` when the total fails, each with an action and a deadline.

Arithmetic is exact (`Fraction`); the verdict is taken from the exact values; `computed` carries
`float` at full precision; display rounding is the caller's job.
"""
from __future__ import annotations

from fractions import Fraction
from types import SimpleNamespace

from extensions.business.cybersec.red_mesh.references.framework_packs import (
  FrameworkPackError,
  controls_for_level,
  pack_levels,
)

from .framework_entry_validation import (
  CAPS, JOB_REF, _EVIDENCE_REF, AssessmentInvalid, bounded_text, normalize_evidence_refs,
)

SCORING_ID = "maturity_two_axis.v1"
AXES = ("documentation", "implementation")
NA = "N/A"
SCORE_VALUES = (1, 2, 3, 4, 5)
_THRESHOLD_KEYS = ("key_measure_min", "category_min", "total_min", "excluded_value", "max_excluded")
_CONTROL_KEYS = ("category", "subcategory", "entry_level", "key_measure", "management_aspect")

def _err(code: str, ids=None, **extra) -> dict:
  out = {"code": code}
  if ids:
    out["ids"] = sorted(ids)
  out.update(extra)
  return out


def _rule(rules: dict | None, key: str) -> bool:
  """A manifest rule switch; absent means on, which is how the DNSC pack has always run.
  Direct callers of `validate_for_submit` / `validate_scores` with no rule block (the scoring unit tests)
  rely on this default; every pack reached through the registry carries a full manifest rule block."""
  return bool((rules or {}).get(key, True))


def _mean(values: list[Fraction]) -> Fraction | None:
  if not values:
    return None
  return sum(values, Fraction(0)) / len(values)


def _f(value: Fraction | None):
  return None if value is None else float(value)


def _is_excluded(entry: dict) -> bool:
  return bool(isinstance(entry, dict) and entry.get("excluded"))


def _axis_value(entry: dict, axis: str):
  return entry.get(axis) if isinstance(entry, dict) else None


def validate_scores(pack: dict, level: str, scores: dict, rules: dict | None = None) -> list[dict]:
  """Shape and exclusion rules (rules 1 and 2). Returns a list of error dicts; empty means valid.

  Unscored controls are not an error here (they are at submit, see validate_for_submit).
  """
  errors: list[dict] = []
  if level not in pack_levels(pack):
    return [_err("unknown_level", level=level)]
  counted = {c["ref_id"]: c for c in controls_for_level(pack, level)}
  all_ids = {c["ref_id"] for c in pack["controls"]}
  scores = scores if isinstance(scores, dict) else {}
  unknown = [k for k in scores if k not in all_ids]
  if unknown:
    errors.append(_err("unknown_control", unknown))
  off_level = [k for k in scores if k in all_ids and k not in counted]
  if off_level:
    errors.append(_err("control_not_in_level", off_level))

  bad_values, excluded_not_na, na_not_excluded = [], [], []
  excl_km, excl_ma, excl_no_just = [], [], []
  excluded_ids = []
  for ref_id, control in counted.items():
    entry = scores.get(ref_id)
    if entry is None:
      continue
    if not isinstance(entry, dict):
      bad_values.append(ref_id)
      continue
    excluded = _is_excluded(entry)
    for axis in AXES:
      v = _axis_value(entry, axis)
      if v is None:
        continue
      if v == NA:
        if not excluded:
          na_not_excluded.append(ref_id)
      elif not (isinstance(v, int) and not isinstance(v, bool) and v in SCORE_VALUES):
        bad_values.append(ref_id)
    if excluded:
      excluded_ids.append(ref_id)
      if any(_axis_value(entry, a) != NA for a in AXES):
        excluded_not_na.append(ref_id)
      if control["key_measure"]:
        excl_km.append(ref_id)
      th = pack["thresholds"][level]
      if control["management_aspect"] and th.get("management_aspect_excludable") is False:
        excl_ma.append(ref_id)
      if _rule(rules, "exclusion_reason_required") and not str(entry.get("exclusion_justification") or "").strip():
        excl_no_just.append(ref_id)
  if bad_values:
    errors.append(_err("invalid_score_value", set(bad_values)))
  if na_not_excluded:
    errors.append(_err("na_without_exclusion", set(na_not_excluded)))
  if excluded_not_na:
    errors.append(_err("excluded_not_na", set(excluded_not_na)))
  if excl_km:
    errors.append(_err("exclusion_key_measure", excl_km))
  if excl_ma:
    errors.append(_err("exclusion_management_aspect", excl_ma))
  max_excluded = pack["thresholds"][level]["max_excluded"]
  if len(excluded_ids) > max_excluded:
    errors.append(_err("exclusion_over_limit", excluded_ids, count=len(excluded_ids), max=max_excluded))
  if excl_no_just:
    errors.append(_err("exclusion_justification_missing", excl_no_just))
  return errors


def score(pack: dict, level: str, scores: dict, *, context=None) -> dict:
  """Compute rollups and the verdict (rules 1, 3, 4) for the scored controls of `level`.

  Callers run validate_scores first; this function assumes the exclusion rules hold and treats
  any control without two usable values as unscored (omitted from the means, listed in
  `unscored`, and `complete` is False).
  """
  th = pack["thresholds"][level]
  excluded_value = Fraction(str(th["excluded_value"]))
  counted = controls_for_level(pack, level)
  scores = scores if isinstance(scores, dict) else {}

  per_control: dict[str, dict[str, Fraction]] = {}
  unscored: list[str] = []
  excluded_ids: list[str] = []
  for control in counted:
    ref_id = control["ref_id"]
    entry = scores.get(ref_id)
    if _is_excluded(entry):
      per_control[ref_id] = {a: excluded_value for a in AXES}
      excluded_ids.append(ref_id)
      continue
    values = {}
    for axis in AXES:
      v = _axis_value(entry, axis)
      if isinstance(v, int) and not isinstance(v, bool) and v in SCORE_VALUES:
        values[axis] = Fraction(v)
    if len(values) == len(AXES):
      per_control[ref_id] = values
    else:
      unscored.append(ref_id)

  # subcategory -> category -> total, per axis
  sub_members: dict[str, list[str]] = {}
  cat_subs: dict[str, list[str]] = {}
  for control in counted:
    sub_members.setdefault(control["subcategory"], []).append(control["ref_id"])
    cat_subs.setdefault(control["category"], [])
    if control["subcategory"] not in cat_subs[control["category"]]:
      cat_subs[control["category"]].append(control["subcategory"])

  subcategories: dict[str, dict[str, Fraction]] = {}
  for sub, members in sub_members.items():
    vals = {a: _mean([per_control[m][a] for m in members if m in per_control]) for a in AXES}
    if all(v is not None for v in vals.values()):
      subcategories[sub] = vals

  categories: dict[str, dict[str, Fraction]] = {}
  for cat, subs in cat_subs.items():
    vals = {a: _mean([subcategories[s][a] for s in subs if s in subcategories]) for a in AXES}
    if all(v is not None for v in vals.values()):
      vals["maturity"] = (vals["documentation"] + vals["implementation"]) / 2
      categories[cat] = vals

  total = _mean([c["maturity"] for c in categories.values()])
  totals_per_axis = {a: _mean([c[a] for c in categories.values()]) for a in AXES}

  km_min = Fraction(str(th["key_measure_min"]))
  key_measures: dict[str, dict] = {}
  failing_km: list[str] = []
  for control in counted:
    if not control["key_measure"]:
      continue
    ref_id = control["ref_id"]
    if ref_id not in per_control:
      continue
    v = per_control[ref_id]
    km_score = (v["documentation"] + v["implementation"]) / 2
    below_axes = [a for a in AXES if v[a] < km_min]
    key_measures[ref_id] = {
      "documentation": _f(v["documentation"]), "implementation": _f(v["implementation"]),
      "score": _f(km_score), "target": _f(km_min), "below_target_axes": below_axes,
    }
    if km_score < km_min:
      failing_km.append(ref_id)

  cat_min = None if th.get("category_min") is None else Fraction(str(th["category_min"]))
  failing_cats = [cat for cat, v in categories.items() if cat_min is not None and v["maturity"] < cat_min]
  total_min = Fraction(str(th["total_min"]))
  total_failed = total is None or total < total_min
  passed = not failing_km and not failing_cats and not total_failed and not unscored

  return {
    "scoring": SCORING_ID,
    "level": level,
    "complete": not unscored,
    "unscored": unscored,
    "exclusions": {"ids": excluded_ids, "count": len(excluded_ids), "max": th["max_excluded"],
                   "excluded_value": _f(excluded_value)},
    "subcategories": {s: {a: _f(v[a]) for a in AXES} for s, v in subcategories.items()},
    "categories": {c: {"documentation": _f(v["documentation"]), "implementation": _f(v["implementation"]),
                       "maturity": _f(v["maturity"])} for c, v in categories.items()},
    "totals_per_axis": {a: _f(v) for a, v in totals_per_axis.items()},
    "total": _f(total),
    "key_measures": key_measures,
    "verdict": {
      "passed": passed,
      "total": _f(total),
      "total_min": _f(total_min),
      "category_min": _f(cat_min),
      "key_measure_min": _f(km_min),
      "failing_key_measures": failing_km,
      "failing_categories": failing_cats,
      "total_failed": total_failed,
    },
  }


def required_remediation_items(computed: dict) -> list[str]:
  """The `item` values a failed verdict needs in `remediation`: control ids, category ids, `total`."""
  verdict = computed["verdict"]
  items = list(verdict["failing_key_measures"]) + list(verdict["failing_categories"])
  if verdict["total_failed"] and computed["total"] is not None:
    items.append("total")
  return items


def validate_for_submit(pack: dict, level: str, draft: dict, rules: dict | None = None) -> tuple[list[dict], dict | None]:
  """Rule 5 plus rules 1 and 2. Returns (errors, computed); computed is None on shape errors.
  `rules` is the manifest rule block: its switches turn the justification, sign-off and remediation checks off."""
  scores = draft.get("scores") if isinstance(draft, dict) else None
  errors = validate_scores(pack, level, scores or {}, rules)
  if errors:
    return errors, None
  computed = score(pack, level, scores or {})
  if computed["unscored"]:
    errors.append(_err("unscored", computed["unscored"]))
  missing_just = []
  for ref_id in {c["ref_id"] for c in controls_for_level(pack, level)}:
    entry = (scores or {}).get(ref_id)
    if not _rule(rules, "justification_required") or not isinstance(entry, dict) or _is_excluded(entry):
      continue
    just = entry.get("justification") if isinstance(entry.get("justification"), dict) else {}
    for axis in AXES:
      v = _axis_value(entry, axis)
      if isinstance(v, int) and not isinstance(v, bool) and not str(just.get(axis) or "").strip():
        missing_just.append(ref_id)
        break
  if missing_just:
    errors.append(_err("justification_missing", set(missing_just)))
  signoff = draft.get("management_signoff") if isinstance(draft, dict) else None
  if _rule(rules, "signoff_required") and not (
      isinstance(signoff, dict) and str(signoff.get("name") or "").strip()
      and str(signoff.get("role") or "").strip() and str(signoff.get("date") or "").strip()):
    errors.append(_err("management_signoff_missing"))
  if not str((draft or {}).get("completion_date") or "").strip():
    errors.append(_err("completion_date_missing"))
  if _rule(rules, "remediation_on_fail") and not computed["verdict"]["passed"] and not computed["unscored"]:
    needed = required_remediation_items(computed)
    items = (draft or {}).get("remediation") or []
    present = set()
    for item in items if isinstance(items, list) else []:
      if (isinstance(item, dict) and str(item.get("action") or "").strip()
          and str(item.get("deadline") or "").strip()):
        present.add(str(item.get("item") or ""))
    missing = [i for i in needed if i not in present]
    if missing:
      errors.append(_err("remediation_missing", missing))
  return errors, computed


# -- entry hooks: the caller's `scores[ref_id]` in, the stored entry out --------------------------------
# (moved here from `tenancy/compliance.py`; `compliance` re-exports the names it and the tests use)

_ENTRY_KEYS = frozenset({"documentation", "implementation", "excluded", "justification", "exclusion_justification",
                         "evidence_refs", "updated_by", "updated_at"})


def _axis(value):
  if value is None or value == NA:
    return value
  if type(value) is int and value in SCORE_VALUES:
    return value
  raise AssessmentInvalid("invalid_score_value")


def normalize_score_entry(entry, *, actor, now):
  """One control's entry as the caller sends it, with its justifications and references."""
  if not isinstance(entry, dict):
    raise AssessmentInvalid("invalid_score_value")
  excluded = entry.get("excluded", False)
  if type(excluded) is not bool:
    raise AssessmentInvalid("invalid_score_value")
  justification = entry.get("justification") or {}
  if not isinstance(justification, dict):
    raise AssessmentInvalid("invalid_request")
  return {
    "documentation": _axis(entry.get("documentation")),
    "implementation": _axis(entry.get("implementation")),
    "excluded": excluded,
    "justification": {axis: bounded_text(justification.get(axis), CAPS["justification"]) for axis in AXES},
    "exclusion_justification": (bounded_text(entry.get("exclusion_justification"), CAPS["exclusion_justification"])
                                or None),
    "evidence_refs": normalize_evidence_refs(entry.get("evidence_refs")),
    "updated_by": actor,
    "updated_at": now,
  }


def normalise_patch(pack: dict, rules: dict, scores: dict, *, actor: str, now: str) -> dict:
  """Hook: the `scores` of a save patch (`ref_id -> entry | None`), normalised; None removes the entry.
  An error names the control; a key of another scorer's entry shape is refused."""
  out = {}
  for ref_id, entry in scores.items():
    if entry is None:
      out[ref_id] = None
      continue
    try:
      if isinstance(entry, dict) and set(entry) - _ENTRY_KEYS:
        raise AssessmentInvalid("invalid_score_value")
      out[ref_id] = normalize_score_entry(entry, actor=actor, now=now)
    except AssessmentInvalid as exc:
      raise AssessmentInvalid(exc.code, exc.ids or [ref_id], **exc.extra) from None
  return out


def validate_stored_entry(pack: dict, ref_id: str, entry: dict) -> list[dict]:
  """Hook: store validator for one stored entry (read path and RM-108 classification)."""
  if not isinstance(entry, dict) or not isinstance(entry.get("justification"), dict):
    return [_err("invalid_stored_entry", [ref_id])]
  return []


def entry_schema(pack: dict) -> dict:
  """Hook: shape and caps of one `scores[ref_id]` entry."""
  return {"axes": list(AXES), "values": [*SCORE_VALUES, NA], "caps": dict(CAPS)}


def verdict_summary(computed: dict) -> dict:
  """The compact verdict kept in `history[]`."""
  verdict = computed["verdict"]
  return {"passed": verdict["passed"], "total": verdict["total"],
          "failing_key_measures": list(verdict["failing_key_measures"]),
          "failing_categories": list(verdict["failing_categories"]),
          "total_failed": verdict["total_failed"]}


def pack_view_extras(pack: dict, text: dict | None) -> dict:
  """Hook: the scorer-specific part of the pack view (the per-level thresholds)."""
  return {"thresholds": {level: dict(th) for level, th in (pack.get("thresholds") or {}).items()}}


def capabilities() -> dict:
  """Hook: the flags the Navigator reads for a pack on this scorer."""
  return {"has_levels": True, "has_verdict": True, "has_remediation": True, "axes": list(AXES)}


def check_pack(pack: dict, text: dict | None) -> None:
  """Scorer-owned schema check, called twice per pack: with `text` None when the pack file loads (levels,
  thresholds, control keys), and with the text dict when a text file loads (only the maturity scale)."""
  pid = pack["pack_id"]
  if text is not None:
    if "maturity_levels" in text and [m.get("value") for m in text["maturity_levels"]] != list(SCORE_VALUES):
      raise FrameworkPackError(f"{pid}: maturity_levels must be 1..5")
    return
  if not pack_levels(pack):
    raise FrameworkPackError(f"{pid}: {SCORING_ID} needs levels")
  for level in pack_levels(pack):
    th = (pack.get("thresholds") or {}).get(level)
    if not isinstance(th, dict) or any(k not in th for k in _THRESHOLD_KEYS):
      raise FrameworkPackError(f"{pid}: thresholds for {level} incomplete")
  for control in pack["controls"]:
    if any(k not in control for k in _CONTROL_KEYS):
      raise FrameworkPackError(f"{pid}: control {control.get('ref_id')!r} incomplete")
  if "counts" in pack and pack["counts"].get("controls") != len(pack["controls"]):
    raise FrameworkPackError(f"{pid}: counts.controls {pack['counts'].get('controls')} != {len(pack['controls'])}")


# Scorer registry (contract `redmesh.framework_scorer.v1`, §Generalisation): keyed by `pack["scoring"]`.
# Hooks: `check_pack`, `entry_schema`, `normalise_patch`, `validate_stored_entry`, `compute`, `validate_for_submit` (with the manifest `rules`), `verdict_summary`, `pack_view_extras`, `capabilities`.
SCORERS: dict = {}


def register_scorer(scoring_id: str, scorer) -> None:
  SCORERS[scoring_id] = scorer


def scorer_for(pack: dict):
  try:
    return SCORERS[pack.get("scoring")]
  except KeyError:
    raise FrameworkPackError(f"unknown scoring {pack.get('scoring')!r}") from None


register_scorer(SCORING_ID, SimpleNamespace(
  check_pack=check_pack,
  entry_schema=entry_schema,
  normalise_patch=normalise_patch,
  validate_stored_entry=validate_stored_entry,
  compute=score,
  validate_for_submit=lambda pack, rules, level, draft: validate_for_submit(pack, level, draft, rules),
  verdict_summary=verdict_summary,
  pack_view_extras=pack_view_extras,
  capabilities=capabilities,
))

# Status implementation depends only on shared entry validators, never this registry.
from . import framework_status_scoring
register_scorer(framework_status_scoring.SCORING_ID, framework_status_scoring)

from . import framework_csf_scoring
register_scorer(framework_csf_scoring.SCORING_ID, framework_csf_scoring)
