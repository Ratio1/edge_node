"""Shared bounded text and canonical evidence validators; no scorer dependency."""
import re

CAPS = {
  "justification": 500,
  "exclusion_justification": 500,
  "evidence_refs": 5,
  "sectoral_requirements": 2000,
  "remediation_items": 50,
  "remediation_action": 500,
}

JOB_REF = re.compile(r"job:([A-Za-z0-9_-]{1,80}):[0-9]{1,6}\Z")
_EVIDENCE_REF = re.compile(
  r"(?:engagement:[A-Za-z0-9_-]{1,80}/document:ed_[0-9]{1,4}|contract"
  r"|nis2:[A-Za-z0-9_-]{1,80}:[0-9]{1,6}|" + JOB_REF.pattern[:-2] + r")\Z")
_REVIEW_STATES = ("linked",)

class AssessmentInvalid(ValueError):
  def __init__(self, code, ids=None, **extra):
    super().__init__(code)
    self.code = code
    self.ids = sorted(ids) if ids else None
    self.extra = extra

  def as_error(self):
    out = {"code": self.code}
    if self.ids:
      out["ids"] = self.ids
    out.update(self.extra)
    return out


def bounded_text(value, limit, *, required=False):
  if value is None:
    value = ""
  if not isinstance(value, str):
    raise AssessmentInvalid("invalid_request")
  value = value.strip()
  if len(value) > limit or (required and not value):
    raise AssessmentInvalid("invalid_request")
  return value


def normalize_evidence_refs(value):
  if value is None:
    return []
  if not isinstance(value, list) or len(value) > CAPS["evidence_refs"]:
    raise AssessmentInvalid("evidence_ref_invalid")
  refs = []
  seen = set()
  for entry in value:
    ref = entry.get("ref") if isinstance(entry, dict) else entry
    if not isinstance(ref, str) or not _EVIDENCE_REF.match(ref) or ref in seen:
      raise AssessmentInvalid("evidence_ref_invalid")
    state = entry.get("review_state", "linked") if isinstance(entry, dict) else "linked"
    if state not in _REVIEW_STATES:
      raise AssessmentInvalid("evidence_ref_invalid")
    seen.add(ref)
    refs.append({"ref": ref, "review_state": state})
  return refs
