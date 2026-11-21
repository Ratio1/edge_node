"""Neutral Annex self-assessment statuses; no legal pass/fail or applicability inference."""
from ..references.framework_packs import FrameworkPackError, pack_levels
from .framework_entry_validation import AssessmentInvalid, bounded_text, normalize_evidence_refs

SCORING_ID = "compliance_status.v1"
STATUS_VALUES = ("implemented", "partial", "not_implemented", "na")
CAPS = {"rationale": 500, "evidence_refs": 5}
_ENTRY_KEYS = frozenset({"status", "rationale", "evidence_refs", "updated_by", "updated_at"})


def check_pack(pack, text):
  if pack_levels(pack):
    raise FrameworkPackError(f"{pack['pack_id']}: {SCORING_ID} requires no levels")
  if "counts" in pack and pack["counts"].get("controls") != len(pack["controls"]):
    raise FrameworkPackError(f"{pack['pack_id']}: counts.controls mismatch")


def _entry(entry, *, actor, now, rules):
  if not isinstance(entry, dict) or set(entry) - _ENTRY_KEYS:
    raise AssessmentInvalid("invalid_score_value")
  value = entry.get("status")
  if value is not None and (not isinstance(value, str) or value not in STATUS_VALUES):
    raise AssessmentInvalid("invalid_score_value")
  rationale = bounded_text(entry.get("rationale"), CAPS["rationale"])
  try:
    rationale.encode("utf-8")
  except UnicodeEncodeError:
    raise AssessmentInvalid("invalid_request") from None
  if value == "na" and rules.get("exclusion_reason_required", True) and not rationale:
    raise AssessmentInvalid("exclusion_justification_missing")
  if value is not None and value != "na" and rules.get("justification_required", False) and not rationale:
    raise AssessmentInvalid("justification_missing")
  return {"status": value, "rationale": rationale,
          "evidence_refs": normalize_evidence_refs(entry.get("evidence_refs")),
          "updated_by": actor, "updated_at": now}


def normalise_patch(pack, rules, scores, *, actor, now):
  out = {}
  for ref_id, entry in scores.items():
    try:
      out[ref_id] = None if entry is None else _entry(entry, actor=actor, now=now, rules=rules)
    except AssessmentInvalid as exc:
      raise AssessmentInvalid(exc.code, [ref_id], **exc.extra) from None
  return out


def validate_stored_entry(pack, ref_id, entry):
  try:
    if (ref_id not in {c["ref_id"] for c in pack["controls"]} or not isinstance(entry, dict)
        or set(entry) != _ENTRY_KEYS or not all(isinstance(entry[k], str) for k in ("updated_by", "updated_at"))):
      raise AssessmentInvalid("invalid_stored_entry")
    # Shape/canonicalization only: submission policy is checked separately using manifest rules.
    expected = _entry(entry, actor=entry["updated_by"], now=entry["updated_at"],
                      rules={"exclusion_reason_required": False})
    if expected != entry:
      raise AssessmentInvalid("invalid_stored_entry")
  except (AssessmentInvalid, TypeError, ValueError):
    return [{"code": "invalid_stored_entry", "ids": [ref_id]}]
  return []


def compute(pack, level, scores, *, context=None):
  counts = {key: 0 for key in (*STATUS_VALUES, "unanswered")}
  for control in pack["controls"]:
    value = (scores.get(control["ref_id"]) or {}).get("status")
    counts[value if value in STATUS_VALUES else "unanswered"] += 1
  return {"scoring": SCORING_ID, "counts": counts, "verdict": {"passed": None}}


def validate_for_submit(pack, rules, level, draft):
  scores = draft.get("scores") or {}
  errors = []
  if level is not None:
    errors.append({"code": "unknown_level", "level": level})
  for ref_id, entry in scores.items():
    errors.extend(validate_stored_entry(pack, ref_id, entry))
  if errors:
    return errors, None
  missing = [c["ref_id"] for c in pack["controls"] if (scores.get(c["ref_id"]) or {}).get("status") is None]
  if missing:
    errors.append({"code": "unscored", "ids": sorted(missing)})
  for ref_id, entry in scores.items():
    try:
      _entry(entry, actor=entry["updated_by"], now=entry["updated_at"], rules=rules)
    except AssessmentInvalid as exc:
      errors.append({"code": exc.code, "ids": [ref_id]})
  if rules.get("signoff_required", False) and not draft.get("management_signoff"):
    errors.append({"code": "management_signoff_missing"})
  return errors, compute(pack, level, scores)


def entry_schema(pack):
  return {"fields": ["status", "rationale", "evidence_refs"], "values": [None, *STATUS_VALUES], "caps": dict(CAPS)}


def verdict_summary(computed):
  return {"passed": None, "counts": dict(computed["counts"])}


def pack_view_extras(pack, text):
  return {"status_values": list(STATUS_VALUES), "assessment_label": "Annex self-assessment"}


def capabilities():
  return {"has_levels": False, "has_verdict": False, "has_remediation": False, "axes": []}
