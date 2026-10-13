"""RM-134 phase 1: the super-tenant branding, the deployment's logo and interface theme.

One record per deployment (kind `super_tenant_branding`, `ids = ["deployment"]`): the theme and the
reference of the stored logo. Vocabulary, the stored-record validator, the change rules and the DTO;
no storage I/O (contract: `onboarding-drafts.md` §Branding). Every active account reads the DTO,
which names the logo by hash only, never by its reference or filename.
"""
from .drafts import DraftInvalid, nonempty_text

RECORD_ID = "deployment"
# Only the neutrals change between themes (Navigator `globals.css`); `dark` is today's console.
THEMES = ("midnight", "dark", "navy", "umber", "light")
DEFAULT_THEME = "dark"
LOGO_FORMATS = ("image/png", "image/jpeg")
LOGO_MAX_BYTES = 512 * 1024
LOGO_MAX_WIDTH, LOGO_MAX_HEIGHT = 1024, 256
_LOGO_FIELDS = ("store", "ref", "sha256", "filename", "mime", "size_bytes", "uploaded_at", "uploaded_by")


def empty_branding():
  """What a deployment without a stored row answers: the default theme, no logo, never written."""
  return {"theme": DEFAULT_THEME, "logo": None, "updated_by": None, "updated_at": None}


def apply_changes(row, changes):
  """The row with `changes` (`theme` and/or `logo`, a stored document reference or None) applied,
  and the keys whose value changed. The plugin builds `logo` from its own store call; a caller's
  request never reaches here as a reference."""
  if not isinstance(changes, dict) or not changes or any(key not in ("theme", "logo") for key in changes):
    raise DraftInvalid()
  if "theme" in changes and changes["theme"] not in THEMES:
    raise DraftInvalid()
  if "logo" in changes and changes["logo"] is not None and not _logo_ref(changes["logo"]):
    raise DraftInvalid()
  merged = {**row, **changes}
  return merged, sorted(key for key in changes if row[key] != merged[key])


def branding_dto(row):
  logo = row["logo"]
  return {"theme": row["theme"],
          "logo": None if logo is None else {key: logo[key] for key in ("sha256", "mime", "size_bytes")}}


def _logo_ref(logo):
  return (isinstance(logo, dict) and set(logo) == set(_LOGO_FIELDS)
          and all(nonempty_text(logo[key]) for key in ("store", "ref", "sha256", "filename", "uploaded_at", "uploaded_by"))
          and logo["mime"] in LOGO_FORMATS
          and type(logo["size_bytes"]) is int and 0 < logo["size_bytes"] <= LOGO_MAX_BYTES)


def validate_super_tenant_branding(row, ids):
  """Refuse a stored branding row the operations could not have written. Unknown fields are kept."""
  if (list(ids) != [RECORD_ID] or row.get("theme") not in THEMES
      or (row.get("logo") is not None and not _logo_ref(row["logo"]))
      or not all(nonempty_text(row.get(key)) for key in ("updated_by", "updated_at"))):
    raise ValueError("Invalid super-tenant branding record")
  return row
