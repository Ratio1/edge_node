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

# One credential pair. The user half runs to the colon; the secret runs to
# whitespace or a closing bracket, and stops at a `.` or `,` only when that
# character ends the sentence. Treating every `.` as a terminator truncated the
# mask mid-password: `admin:P@ssw0rd.1` became `admin:***.1`, publishing the
# tail of the secret.
#
# `(?![\s/])` after the colon is the URL guard: without it the `with` lead
# turned `with https://host:8443/x` into `with https:***`, the same defect
# `mixins/report.py` records as already fixed on `_CRED_RE`. There is
# deliberately *no* port guard here, unlike `_CRED_RE`: the HTTP Basic evidence
# reads `GET … with admin:1234 → HTTP 200` and `("admin", "1234")` is in the
# default list, so a port-shaped secret after a lead must still be masked. The
# cost is that a probe writing `with host:8443` (no path) would be over-masked;
# no emitter does, and the tests pin the URL form.
# `\S*?`, not `\S+?`: an empty secret is still a secret. `("root", "")` is a
# live MySQL default and `("admin", "")` an HTTP Basic one; printing `root:`
# tells the reader the password is blank, which is the whole pair. The
# `(?![\s/])` guard still applies, so `with https://…` and `Content-Type:
# application/json` are untouched, but `Auth OK for root:` becomes `root:***`.
_PAIR_TEMPLATE = (
  r"(?P<user>[^\s:]{1,64}):(?![/])%s(?P<secret>\S*?)(?=[\s;)\]}]|[.,](?:\s|$)|$)"
)
_PAIR = _PAIR_TEMPLATE % ""
# A pair whose secret is not already the mask. The continuation rule below
# consumes the `:***` of the previous pair as its lead, so if it also accepted
# `***` as a secret it would eat `b:***` and leave `; c:three` with no lead.
_UNMASKED_PAIR = _PAIR_TEMPLATE % r"(?!\*\*\*)"

# Anchoring on the credential *phrasing* rather than on a bare `a:b` shape is
# deliberate. The MySQL description reads "MySQL on {host}:{port} accepts
# {user}:{pass}", so a shape-only rule would mask the host and port too and
# destroy the field saying which service was affected.
#
# The phrasings come from the probes themselves: worker/service/common.py :480,
# :755, :945, :1633, :1645 and worker/service/database.py :242-244, :918,
# :937-939, :963-965. A probe that invents new wording leaks until its phrasing
# is added here, which is why the tests pin the exact strings each probe emits.
CREDENTIAL_CONTEXT_RE = re.compile(
  r"(?i)(?P<lead>"
  r"(?:default|accepted|weak|valid)\s+credentials?(?:\s+accepted)?\s*[:=]?\s*"
  r"|accepted\s+random\s+creds\s+"
  r"|auth(?:\s+response)?\s+ok\s+for\s+"
  # `Auth code 0 for <pair>` — the PostgreSQL trust-auth path at
  # worker/service/database.py:918, which the first version of this table
  # missed while enumerating its siblings at :242, :937 and :963.
  r"|auth\s+code\s+\d+\s+for\s+"
  r"|password\s+auth\s+accepted\s+for\s+"
  r"|\baccepts\s+"
  r"|\bwith\s+"
  r")"
  + _PAIR
)

# A pair listed after an already-masked one: `admin:***, admin:password`. Each
# match of the rule above needs its own lead, so a comma-separated list masked
# only its first entry. The lead here is the mask itself plus a list separator,
# and it is applied until the text stops changing.
_CONTINUATION_RE = re.compile(
  r"(?i)(?P<lead>:\*\*\*(?:\s*[,;]\s*|\s+(?:and|or)\s+))" + _UNMASKED_PAIR
)

# Fields on a blackbox finding carrying probe-authored prose, and so capable of
# carrying an interpolated credential. `evidence` was the only one redacted
# before; `title` is the one that actually leaked.
CREDENTIAL_TEXT_FIELDS = ("title", "description", "remediation", "evidence", "error")


def redact_credential_text(value):
  """Mask the secret half of any credential pair introduced by known phrasing."""
  if not isinstance(value, str):
    return value
  text = CREDENTIAL_CONTEXT_RE.sub(r"\g<lead>\g<user>:***", value)
  while True:
    masked = _CONTINUATION_RE.sub(r"\g<lead>\g<user>:***", text)
    if masked == text:
      return text
    text = masked


# Keys whose subtree is policy-bound or an identity, never probe prose:
# hashes, ids, enums. The walker below skips them. They are listed for
# clarity rather than safety — a hex hash or `CRITICAL` cannot match a
# phrasing-anchored rule anyway — so a key missing from this list is
# masked, not leaked. That is the point.
IDENTITY_KEYS = frozenset({
  "finding_id", "finding_signature", "dedup_key", "content_hash", "fingerprint",
  "dedupe_fingerprint", "cid", "artifact_cid", "schema", "schema_version",
  "severity", "confidence", "status", "category", "kind",
  "owasp_id", "cwe_id", "cve_id", "cvss_vector", "scenario_id",
  "probe", "probe_name", "_source_probe",
})


def redact_credential_strings(obj, *, allow_keys=IDENTITY_KEYS):
  """Apply `redact_credential_text` to every string in `obj`, in place.

  Deny-by-default over *fields*: dicts, lists and tuples are walked and every
  string leaf goes through the rule unless it sits under a key in
  `allow_keys`. The three field-allowlist scrubbers this backs
  (`_scrub_flat_finding`, `_redact_report`, `build_finding_event`) each
  carry a comment naming a field that leaked because it was not on their
  list — `evidence_items`, `affected_assets`, `vulnerabilities`, `accepted`,
  `web_tests_info`. The next field added leaks by default under an
  allowlist; under this walk it is masked by default.

  Safe to run over whole reports because the rule is phrasing-anchored:
  `host:port`, URLs and timestamps carry no lead and pass through unchanged.
  The cost is the two ambiguous leads: prose of the form `with X:Y` where
  `Y` is not a path (`with nginx:1.25`, `with SHA256:abcd`, `with 10:30:00
  UTC`) is masked to `X:***`. No emitter writes that shape today (audited
  2026-09-21); a probe that needs it should phrase it without `with`.
  Dicts and lists are mutated in place and returned; tuples and strings are
  returned as new values.
  """
  if isinstance(obj, str):
    return redact_credential_text(obj)
  if isinstance(obj, dict):
    for key, value in obj.items():
      if key in allow_keys:
        continue
      obj[key] = redact_credential_strings(value, allow_keys=allow_keys)
    return obj
  if isinstance(obj, list):
    for index, value in enumerate(obj):
      obj[index] = redact_credential_strings(value, allow_keys=allow_keys)
    return obj
  if isinstance(obj, tuple):
    return tuple(redact_credential_strings(value, allow_keys=allow_keys) for value in obj)
  return obj
