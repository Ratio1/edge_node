"""
Credential redaction for probe-authored finding text.

Kept dependency-free and separate from `mixins.report` so it can also be applied
at egress boundaries — notably the SIEM event builder — without importing the
worker and report machinery.

Default-credential probes interpolate the plaintext pair straight into the
finding text, `title` above all. The title is what reaches the customer's SIEM,
the PDF cover, the MISP export and the LLM input, so a leak here is a credential
egress event and a rotation event for the customer, not a rendering defect.
"""

import re

# Anchoring on the credential *phrasing* rather than on a bare `a:b` shape is
# deliberate. The MySQL description reads "MySQL on {host}:{port} accepts
# {user}:{pass}", so a shape-only rule would mask the host and port too and
# destroy the field saying which service was affected.
#
# The phrasings come from the probes themselves: worker/service/common.py :480,
# :751, :932, :1620, :1632 and worker/service/database.py :239-240, :928-929,
# :954-955. A probe that invents new wording leaks until its phrasing is added
# here, which is why the tests pin the exact strings each probe emits.
CREDENTIAL_CONTEXT_RE = re.compile(
  r"(?i)(?P<lead>"
  r"(?:default|accepted|weak|valid)\s+credentials?(?:\s+accepted)?\s*[:=]?\s*"
  r"|accepted\s+random\s+creds\s+"
  r"|auth(?:\s+response)?\s+ok\s+for\s+"
  # `Auth code 0 for <pair>` — the PostgreSQL trust-auth path at
  # worker/service/database.py:909, which the first version of this table
  # missed while enumerating its siblings at :239, :928 and :954.
  r"|auth\s+code\s+\d+\s+for\s+"
  r"|password\s+auth\s+accepted\s+for\s+"
  r"|\baccepts\s+"
  r"|\bwith\s+"
  r")"
  # The secret runs to whitespace or a closing bracket, and stops at a `.` or
  # `,` only when that character ends the sentence. Treating every `.` as a
  # terminator truncated the mask mid-password: `admin:P@ssw0rd.1` became
  # `admin:***.1`, publishing the tail of the secret.
  r"(?P<user>[^\s:]{1,64}):(?P<secret>\S+?)(?=[\s;)\]}]|[.,](?:\s|$)|$)"
)

# Fields on a blackbox finding carrying probe-authored prose, and so capable of
# carrying an interpolated credential. `evidence` was the only one redacted
# before; `title` is the one that actually leaked.
CREDENTIAL_TEXT_FIELDS = ("title", "description", "remediation", "evidence", "error")


def redact_credential_text(value):
  """Mask the secret half of any credential pair introduced by known phrasing."""
  if not isinstance(value, str):
    return value
  return CREDENTIAL_CONTEXT_RE.sub(r"\g<lead>\g<user>:***", value)
