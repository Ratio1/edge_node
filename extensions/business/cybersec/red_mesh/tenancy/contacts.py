"""RM-132: the e-mail and phone formats every contact field is checked against on write.

Pure predicates, shared by the tenant party block, the super-tenant profile (`drafts.py`) and the
engagement contacts (`engagements.py`); the callers choose the refusal code. ASCII only, on purpose:
`user@localhost`, IP-literal domains, extensions (`ext. 12`) and non-ASCII digits are refused. Empty
is for the caller to allow. The accept/refuse table lives in `tests/fixtures/contact_formats.json`
(contract: `onboarding-drafts.md` §Contact formats).
"""
import re

EMAIL_MAX = 200
_LOCAL = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+\Z")
_LABEL = re.compile(r"[A-Za-z0-9-]+\Z")
_PHONE = re.compile(r"\+?[0-9 ().-]+\Z")
PHONE_MIN_DIGITS = 6
PHONE_MAX_DIGITS = 20


def valid_email(value):
  """Exactly one `@`, a non-empty ASCII local part, a dotted domain of `[A-Za-z0-9-]` labels whose
  last one carries a letter (so an IP literal is not a domain)."""
  if not isinstance(value, str) or not value.isascii() or len(value) > EMAIL_MAX or value.count("@") != 1:
    return False
  local, domain = value.split("@")
  labels = domain.split(".")
  return (_LOCAL.match(local) is not None and len(labels) >= 2
          and all(_LABEL.match(label) is not None for label in labels)
          and any(ch.isalpha() for ch in labels[-1]))


def valid_phone(value):
  """An optional leading `+`, then ASCII digits with spaces, `-`, `(`, `)`, `.`; 6-20 digits."""
  if not isinstance(value, str) or not value.isascii() or _PHONE.match(value) is None:
    return False
  return PHONE_MIN_DIGITS <= sum(ch.isdigit() for ch in value) <= PHONE_MAX_DIGITS
