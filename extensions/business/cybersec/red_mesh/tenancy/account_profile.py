"""RM-155 phase 1: the account profile, the person behind an account id.

One record per account (kind `account_profile`, `ids = [account_id]`): full name, position,
organization, contact e-mail, signature line, qualifications (with an optional uploaded certificate
each) and the `report_reviewer` designation. Vocabulary, the stored-record validator, the change rules
and the DTO; no storage I/O. The account record itself stays v1: the profile lives beside it.

The row stores the account's `created_at`. A row whose value does not match the current account
record is treated as absent (`row_for`), so an account id that is deleted and created again never
inherits the earlier person's profile or reviewer designation.
"""
from datetime import date, datetime, timedelta
import re
import unicodedata
import uuid

from .drafts import DraftInvalid, email_text, nonempty_text, text as _free_text
from .identity import canonical_account_id

KIND = "account_profile"
TEXT_MAX = 200
TEXT_FIELDS = ("full_name", "position", "organization", "contact_email", "signature")
QUALIFICATION_FIELDS = ("name", "issuer", "credential_id", "issued_on", "expires_on")
MAX_QUALIFICATIONS = 20
EXPIRING_DAYS = 30
CERTIFICATE_FIELDS = ("document_id", "store", "ref", "sha256", "filename", "mime", "size_bytes", "uploaded_at",
                      "uploaded_by")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_QUALIFICATION_ID = re.compile(r"^q[1-9][0-9]{0,3}$")


def new_row(account_created_at):
  """A profile with nothing in it, bound to one incarnation of the account."""
  return {"account_created_at": account_created_at, **{key: "" for key in TEXT_FIELDS}, "qualifications": [],
          "report_reviewer": False, "updated_by": None, "updated_at": None}


def row_for(row, account_created_at):
  """The stored row when it belongs to this incarnation of the account, else None (absent)."""
  if isinstance(row, dict) and account_created_at and row.get("account_created_at") == account_created_at:
    return row
  return None


_NAME_JOINERS = {"‌", "‍"}  # ZWNJ, ZWJ: part of Persian and Indic spellings


def _plain(value):
  """Unicode format characters (category Cf: bidi overrides, zero-width space, BOM) are refused in
  profile text: it is printed in a report's reviewer block and must read as it is typed. The two
  joiners real names use are kept."""
  if isinstance(value, str) and any(
      unicodedata.category(ch) == "Cf" and ch not in _NAME_JOINERS for ch in value):
    raise DraftInvalid()
  return value


def text(value, maximum):
  return _free_text(_plain(value), maximum)


def _email(value):
  return email_text(_plain(value))


def _date(value):
  if not isinstance(value, str):
    raise DraftInvalid()
  if value == "":
    return ""
  try:
    if not _DATE.match(value):
      raise ValueError
    datetime.strptime(value, "%Y-%m-%d")
  except ValueError:
    raise DraftInvalid("invalid_date") from None
  return value


def _qualification(entry):
  """One normalized qualification body; the certificate is never taken from input."""
  if not isinstance(entry, dict) or not set(entry) <= {"qualification_id", *QUALIFICATION_FIELDS}:
    raise DraftInvalid()
  name = text(entry.get("name", ""), TEXT_MAX)
  if not name:
    raise DraftInvalid("qualification_name_required")
  out = {"name": name,
         "issuer": text(entry.get("issuer", ""), TEXT_MAX),
         "credential_id": text(entry.get("credential_id", ""), TEXT_MAX),
         "issued_on": _date(entry.get("issued_on", "")),
         "expires_on": _date(entry.get("expires_on", ""))}
  if out["issued_on"] and out["expires_on"] and out["expires_on"] < out["issued_on"]:
    raise DraftInvalid("invalid_date")
  return out


def apply_changes(row, changes):
  """`(row, changed, dropped)`: the row with the partial `changes` applied, the keys whose value
  changed, and the certificates of qualifications the new list no longer holds (their files go once
  the row is written). `qualifications` replaces the list; an entry naming an existing
  `qualification_id` keeps its certificate. An unknown key is refused."""
  if not isinstance(changes, dict) or any(key not in (*TEXT_FIELDS, "qualifications") for key in changes):
    raise DraftInvalid()
  new = {}
  for key in TEXT_FIELDS:
    if key in changes:
      new[key] = _email(changes[key]) if key == "contact_email" else text(changes[key], TEXT_MAX)
  dropped = []
  if "qualifications" in changes:
    entries = changes["qualifications"]
    if not isinstance(entries, list) or len(entries) > MAX_QUALIFICATIONS:
      raise DraftInvalid()
    current = {q["qualification_id"]: q for q in row["qualifications"]}
    seen, rebuilt = set(), []
    numbers = [int(i[1:]) for i in current]
    next_number = max(numbers, default=0) + 1
    for entry in entries:
      given = entry.get("qualification_id") if isinstance(entry, dict) else None
      if given is not None and (not isinstance(given, str) or given not in current or given in seen):
        raise DraftInvalid()
      body = _qualification(entry)
      if given is None:
        given, next_number = f"q{next_number}", next_number + 1
      seen.add(given)
      rebuilt.append({"qualification_id": given, **body,
                      "certificate": current[given]["certificate"] if given in current else None})
    dropped = [q["certificate"] for i, q in current.items() if i not in seen and q["certificate"] is not None]
    new["qualifications"] = rebuilt
  changed = sorted(key for key, value in new.items() if row[key] != value)
  return {**row, **new}, changed, dropped


def certificate_block(document, *, uploaded_by, uploaded_at):
  """The stored certificate reference from a validated document and its store reference."""
  return {"document_id": "cd_" + uuid.uuid4().hex[:16], "store": document["store"], "ref": document["ref"],
          "sha256": document["sha256"], "filename": document["filename"], "mime": document["mime"],
          "size_bytes": document["size_bytes"], "uploaded_at": uploaded_at, "uploaded_by": uploaded_by}


def find_certificate(row, document_id):
  """`(qualification, certificate)` for a document id of the row, else `(None, None)`."""
  for qualification in row["qualifications"]:
    certificate = qualification["certificate"]
    if certificate is not None and certificate["document_id"] == document_id:
      return qualification, certificate
  return None, None


def certificate_refs(row):
  return [q["certificate"]["ref"] for q in row["qualifications"] if q["certificate"] is not None]


def qualification_state(expires_on, today):
  """`valid`, `expiring` (within 30 days) or `expired`, from the expiry date and today (a `date`).
  No expiry date never expires."""
  if not expires_on:
    return "valid"
  expiry = date.fromisoformat(expires_on)
  if expiry < today:
    return "expired"
  return "expiring" if expiry <= today + timedelta(days=EXPIRING_DAYS) else "valid"


def effective_signature(row):
  """The stored signature line, else "<full name>, <position>" (or the name alone)."""
  if row["signature"]:
    return row["signature"]
  name, position = row["full_name"], row["position"]
  return f"{name}, {position}" if name and position else name


def profile_dto(row, today, organization_default=""):
  """What a reader sees. A certificate is named by `{document_id, filename, sha256}`, never by its
  store reference. `organization` is the stored value, else the prefill (`organization_default`)."""
  qualifications = []
  for q in row["qualifications"]:
    cert = q["certificate"]
    qualifications.append({
      **{key: q[key] for key in ("qualification_id", *QUALIFICATION_FIELDS)},
      "state": qualification_state(q["expires_on"], today),
      "certificate": None if cert is None else {key: cert[key] for key in
                                                ("document_id", "filename", "sha256", "mime", "size_bytes")}})
  return {"full_name": row["full_name"], "position": row["position"],
          "organization": row["organization"] or organization_default,
          "organization_default": organization_default, "contact_email": row["contact_email"],
          "signature": effective_signature(row), "qualifications": qualifications,
          "report_reviewer": row["report_reviewer"], "profile_complete": bool(row["full_name"]),
          "updated_by": row["updated_by"], "updated_at": row["updated_at"]}


def _same(value):
  try:
    return text(value, TEXT_MAX) == value
  except DraftInvalid:
    return False


def _valid_email(value):
  try:
    return _email(value) == value
  except DraftInvalid:
    return False


def _valid_date(value):
  try:
    return _date(value) == value
  except DraftInvalid:
    return False


def _valid_certificate(cert):
  return (isinstance(cert, dict) and set(cert) == set(CERTIFICATE_FIELDS)
          and all(nonempty_text(cert[key]) for key in CERTIFICATE_FIELDS if key != "size_bytes")
          and type(cert["size_bytes"]) is int and cert["size_bytes"] > 0)


def _valid_qualification(q):
  return (isinstance(q, dict) and set(q) == {"qualification_id", *QUALIFICATION_FIELDS, "certificate"}
          and isinstance(q["qualification_id"], str) and bool(_QUALIFICATION_ID.match(q["qualification_id"]))
          and nonempty_text(q["name"]) and _same(q["name"])
          and all(_same(q[key]) for key in ("issuer", "credential_id"))
          and all(_valid_date(q[key]) for key in ("issued_on", "expires_on"))
          and (q["certificate"] is None or _valid_certificate(q["certificate"])))


def validate_account_profile(row, ids):
  """Refuse a stored profile the operations could not have written. Unknown fields are kept."""
  qualifications = row.get("qualifications")
  if (len(ids) != 1 or canonical_account_id(ids[0]) != ids[0]
      or not nonempty_text(row.get("account_created_at"))
      or any(not _same(row.get(key)) for key in TEXT_FIELDS)
      or not _valid_email(row["contact_email"])
      or type(row.get("report_reviewer")) is not bool
      or not isinstance(qualifications, list) or len(qualifications) > MAX_QUALIFICATIONS
      or not all(_valid_qualification(q) for q in qualifications)
      or len({q["qualification_id"] for q in qualifications}) != len(qualifications)
      or not all(nonempty_text(row.get(key)) for key in ("updated_by", "updated_at"))):
    raise ValueError("Invalid account profile record")
  return row
