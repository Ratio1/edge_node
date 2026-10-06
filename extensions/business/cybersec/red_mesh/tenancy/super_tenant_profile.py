"""RM-110 phase 1: the super-tenant profile, the provider party of every generated pack.

One record per deployment (kind `super_tenant_profile`, `ids = ["deployment"]`): the provider block
of outline 01 C1/C6/C9, 03 A3 and 04 D3. Vocabulary, formats, the stored-record validator and the
DTO; no storage I/O (contract: `onboarding-drafts.md` §Super-tenant profile). Every field may be
empty here; generation (Navigator) refuses `profile_required` on the ones a pack needs.
"""
from .drafts import DraftInvalid, _LEGAL_MAX, _nonempty_text, _text

RECORD_ID = "deployment"
FIELDS = ("legal_name", "registration_id", "vat_id", "address", "signer_name", "signer_role", "contact_email",
          "contact_phone")
DTO_FIELDS = (*FIELDS, "updated_by", "updated_at")


def empty_profile():
  """What a deployment without a stored row answers: every field empty, never written."""
  return {**{key: "" for key in FIELDS}, "updated_by": None, "updated_at": None}


def apply_changes(row, changes):
  """The row with the partial `changes` applied (`update_super_tenant_profile`) and the keys whose
  value changed. Formats are checked, emptiness is allowed; an unknown key is refused."""
  if not isinstance(changes, dict) or any(key not in FIELDS for key in changes):
    raise DraftInvalid()
  changed = {key: _text(text, _LEGAL_MAX) for key, text in changes.items()}
  return {**row, **changed}, sorted(key for key, text in changed.items() if row[key] != text)


def profile_dto(row):
  return {key: row[key] for key in DTO_FIELDS}


def _same(value):
  try:
    return _text(value, _LEGAL_MAX) == value
  except DraftInvalid:
    return False


def validate_super_tenant_profile(row, ids):
  """Refuse a stored profile the operations could not have written. Unknown fields are kept."""
  if (list(ids) != [RECORD_ID] or any(not _same(row.get(key)) for key in FIELDS)
      or not all(_nonempty_text(row.get(key)) for key in ("updated_by", "updated_at"))):
    raise ValueError("Invalid super-tenant profile record")
  return row
