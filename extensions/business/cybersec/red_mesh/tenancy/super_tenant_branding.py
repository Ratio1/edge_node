"""RM-134 phase 1: the super-tenant branding, the deployment's logo and interface theme.

One record per deployment (kind `super_tenant_branding`, `ids = ["deployment"]`): the theme and the
reference of the stored logo. Vocabulary, the stored-record validator, the change rules and the DTO;
no storage I/O (contract: `onboarding-drafts.md` §Branding). Every active account reads the DTO,
which names the logo by hash only, never by its reference or filename.
"""
import unicodedata

from .drafts import DraftInvalid, nonempty_text

RECORD_ID = "deployment"
# Only the neutrals change between themes (Navigator `globals.css`); `dark` is today's console.
THEMES = ("midnight", "dark", "navy", "umber", "light")
DEFAULT_THEME = "dark"
LOGO_FORMATS = ("image/png", "image/jpeg")
LOGO_MAX_BYTES = 2 * 1024 * 1024
LOGO_MAX_WIDTH, LOGO_MAX_HEIGHT = 2048, 512
DISPLAY_NAME_MAX = 80
NAME_IN_KEYS = ("title", "header")
_LOGO_FIELDS = ("store", "ref", "sha256", "filename", "mime", "size_bytes", "uploaded_at", "uploaded_by")


def empty_branding():
  """What a deployment without a stored row answers: the default theme, no logo, no name, never written."""
  return {"theme": DEFAULT_THEME, "logo": None, "display_name": "", "name_in": _no_name_in(),
          "updated_by": None, "updated_at": None}


def _no_name_in():
  return {key: False for key in NAME_IN_KEYS}


# Control, format (bidi override, zero width, BOM), surrogate, private use, unassigned, line and paragraph separators.
_REFUSED_CATEGORIES = frozenset(("Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"))


def _display_name_ok(value):
  """A string already stripped and in NFC, at most 80 characters, with no invisible or control
  character, and (when not empty) at least one character that is not a space or a combining mark."""
  return (isinstance(value, str) and value == value.strip() and value == unicodedata.normalize("NFC", value)
          and len(value) <= DISPLAY_NAME_MAX
          and not any(unicodedata.category(char) in _REFUSED_CATEGORIES for char in value)
          and (not value or any(unicodedata.category(char)[0] not in "ZM" for char in value)))


def _name_in_ok(value):
  return isinstance(value, dict) and set(value) == set(NAME_IN_KEYS) and all(type(v) is bool for v in value.values())


def _with_name_defaults(row):
  """A row stored before the name existed reads with the defaults; nothing is written for it."""
  return {**row, "display_name": row.get("display_name", ""), "name_in": row.get("name_in", _no_name_in())}


def apply_changes(row, changes):
  """The row with `changes` (`theme`, `logo` a stored document reference or None, `display_name`,
  `name_in`) applied, and the keys whose value changed. The plugin builds `logo` from its own store
  call; a caller's request never reaches here as a reference. `display_name` is stripped; `name_in`
  is replaced whole (both keys, no partial merge)."""
  if (not isinstance(changes, dict) or not changes
      or any(key not in ("theme", "logo", "display_name", "name_in") for key in changes)):
    raise DraftInvalid()
  changes = dict(changes)
  if isinstance(changes.get("display_name"), str):
    changes["display_name"] = unicodedata.normalize("NFC", changes["display_name"].strip())
  if "display_name" in changes and not _display_name_ok(changes["display_name"]):
    raise DraftInvalid()
  if "name_in" in changes and not _name_in_ok(changes["name_in"]):
    raise DraftInvalid()
  if "theme" in changes and changes["theme"] not in THEMES:
    raise DraftInvalid()
  if "logo" in changes and changes["logo"] is not None and not _logo_ref(changes["logo"]):
    raise DraftInvalid()
  current = _with_name_defaults(row)
  merged = {**row, **changes}
  return merged, sorted(key for key in changes if current[key] != changes[key])


def branding_dto(row):
  row = _with_name_defaults(row)
  logo = row["logo"]
  return {"theme": row["theme"],
          "logo": None if logo is None else {key: logo[key] for key in ("sha256", "mime", "size_bytes")},
          "display_name": row["display_name"], "name_in": dict(row["name_in"])}


def _logo_ref(logo):
  return (isinstance(logo, dict) and set(logo) == set(_LOGO_FIELDS)
          and all(nonempty_text(logo[key]) for key in ("store", "ref", "sha256", "filename", "uploaded_at", "uploaded_by"))
          and logo["mime"] in LOGO_FORMATS
          and type(logo["size_bytes"]) is int and 0 < logo["size_bytes"] <= LOGO_MAX_BYTES)


def validate_super_tenant_branding(row, ids):
  """Refuse a stored branding row the operations could not have written. Unknown fields are kept."""
  if (list(ids) != [RECORD_ID] or row.get("theme") not in THEMES
      or (row.get("logo") is not None and not _logo_ref(row["logo"]))
      or ("display_name" in row and not _display_name_ok(row["display_name"]))
      or ("name_in" in row and not _name_in_ok(row["name_in"]))
      or not all(nonempty_text(row.get(key)) for key in ("updated_by", "updated_at"))):
    raise ValueError("Invalid super-tenant branding record")
  return row
