"""
CVSS v3.1 base vectors for probe and graybox findings, one per kind of weakness.

A probe's registry `cvss_template` is one vector for everything the probe
reports, and one probe reports findings from CRITICAL to LOW. Where the
template's band disagrees with a finding's label it is withheld (RM-064) and
the label is shown as probe policy (RM-086). A `Finding` that passes one of
these constants as `cvss_vector` gets a vector for *its* weakness instead;
`enrich_finding_for_probe` scores it and stamps `severity_source` as before.

Each constant's band is asserted in `tests/test_cvss_coverage.py`, and every
non-INFO `Finding(` under `worker/` must either pass one of these or inherit
an agreeing template (RM-087). Temporal and environmental metrics are not
used: the scanner does not know exploit maturity or the target's context.

Graybox scenarios name theirs in `graybox/scenario_catalog.py`. Those tests run
as a logged-in regular user, so a weakness they find needs that login:
`PR:L`, which caps an unscoped vector at 8.8 (HIGH).
"""

# --- CRITICAL ---------------------------------------------------------------

# Unauthenticated network access with full control: accepted default or
# arbitrary credentials, auth bypass, an open admin/datastore API, confirmed RCE.
UNAUTHENTICATED_FULL_CONTROL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
# Unauthenticated read and write of data, no availability claim: anonymous
# upload, an open file share or datastore, a credential printed in page source.
UNAUTHENTICATED_READ_WRITE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 9.1
# Server-side request forgery that reaches internal resources (scope change).
SSRF_TO_INTERNAL = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"  # 9.3

# --- HIGH -------------------------------------------------------------------

# Unauthenticated read of sensitive data: secrets files, source, memory
# (Heartbleed, the NVD vector), directory traversal, open indices, debug output.
SENSITIVE_DATA_EXPOSED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
# Unauthenticated write without read: HTTP PUT/DELETE, open mail relay.
UNAUTHENTICATED_WRITE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"  # 7.5
# An administrative interface reachable from the network; login may still be
# required, so each of C/I/A is limited.
ADMIN_INTERFACE_EXPOSED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"  # 7.3
# Injection or access-control bypass that reads data and alters some of it:
# SQL injection, an API accepting an invalid token.
INJECTION_DATA_ACCESS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"  # 8.2
# Reflected XSS: the victim must follow a link; the script reads what the
# victim sees in the application.
XSS_REFLECTED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"  # 7.1
# A code-execution weakness indicated but not confirmed (framework or endpoint
# present, version or configuration unknown): AC:H stands for the conditions
# the scan could not establish. Also used for end-of-life software with
# published RCEs.
RCE_UNCONFIRMED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 8.1
# Cryptography an attacker in the path can break: obsolete TLS/SSL, weak TLS
# ciphers, a factorable host key, predictable authentication salt.
WEAK_CRYPTO_BREAKABLE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 7.4
# Credentialed cross-origin reads: CORS reflecting any origin with credentials.
CORS_CREDENTIALED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"  # 8.1
# Active mixed content: a script fetched over HTTP on an HTTPS page.
MIXED_CONTENT_ACTIVE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N"  # 8.0
# A regular user reaches a function or data reserved for another role and can
# act on it: function-level bypass, role override, mass assignment of a role.
AUTHZ_BYPASS_AUTHENTICATED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"  # 8.1
# A regular user deletes another user's object.
OBJECT_DELETE_AUTHENTICATED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H"  # 8.1
# A regular user changes another user's object, or its owner; the response
# shows part of it.
OBJECT_TAMPER_AUTHENTICATED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N"  # 7.1
# SQL injection reachable after login.
INJECTION_DATA_ACCESS_AUTHENTICATED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"  # 7.1
# Command injection reachable after login.
RCE_AUTHENTICATED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"  # 8.8
# Template injection indicated after login, execution not confirmed (AC:H).
RCE_UNCONFIRMED_AUTHENTICATED = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"  # 7.5
# Server-side request forgery reaching internal resources, after login.
SSRF_AUTHENTICATED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N"  # 8.5
# Cross-site request forgery on a state-changing form (NVD's usual vector).
CSRF = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"  # 8.8
# Authentication an attacker defeats under a condition the scan did not
# establish: a weak or unsigned token, a guessable password, a reset token
# that is predictable or still valid. Account takeover once it holds (AC:H).
AUTH_DEFEATABLE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"  # 7.4

# --- MEDIUM -----------------------------------------------------------------

# Disclosure that helps an attacker but does not itself grant access:
# internal addresses, share or name lists, schema introspection, an exposed
# service or a protected admin path.
INFO_DISCLOSURE_MEDIUM = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 5.3
# Readable by an attacker in the path: cleartext or legacy protocols, weak SSH
# ciphers or key exchange, CBC under TLS 1.0, weak certificate signatures.
WEAK_TRANSPORT = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 5.9
# A certificate a client cannot validate: self-signed, wrong host, expired.
# Exploiting it needs a user to accept the warning and a position in the path.
CERT_UNTRUSTED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"  # 6.8
# Authentication without attempt throttling: credential guessing succeeds
# only against weak passwords, hence AC:H and limited impact.
BRUTE_FORCE_UNTHROTTLED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"  # 4.8
# SMB signing not required: NTLM relay lets an attacker act as a relayed user.
NTLM_RELAY = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"  # 5.3
# Open recursive DNS resolver: usable for amplification against third parties.
OPEN_RESOLVER = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L"  # 5.8
# Open redirect, reported where it could be chained into SSRF.
OPEN_REDIRECT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # 6.1
# A runtime or product past end of life with no specific CVE confirmed.
UNSUPPORTED_SOFTWARE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L"  # 5.6
# A third-party script loaded without Subresource Integrity.
SRI_SCRIPT_MISSING = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:L/A:N"  # 4.7
# A regular user reads data that is not theirs: another user's object, a
# path outside the web root, properties the API should not return.
DATA_EXPOSED_AUTHENTICATED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"  # 6.5
# A regular user skips a workflow step or submits a value the business rules
# forbid (a negative amount).
BUSINESS_LOGIC_BYPASS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"  # 6.5
# A regular user repeats a business flow without limit or uniqueness check.
BUSINESS_FLOW_ABUSE = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N"  # 4.3
# Input of an unexpected type accepted after login (JSON type confusion).
INPUT_VALIDATION_BYPASS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"  # 5.4
# Script or header injection reflected to a logged-in victim (NVD's usual
# authenticated XSS vector; header injection leads to response splitting).
XSS_AUTHENTICATED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"  # 5.4
# Script injection on a page served before login (NVD's usual XSS vector).
XSS_UNAUTHENTICATED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"  # 6.1
# Session identifier not rotated at login: fixation needs a victim to log in
# on a planted identifier.
SESSION_FIXATION = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"  # 6.8
# A token that stays valid after logout: useful only to whoever already holds it.
SESSION_NOT_REVOKED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"  # 4.8
# An API that returns or accepts unbounded amounts of data for a regular user.
RESOURCE_UNBOUNDED = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L"  # 4.3

# --- LOW --------------------------------------------------------------------

# Version, banner, framework or path disclosure: useful only together with a
# separate weakness, hence AC:H.
INFO_DISCLOSURE_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 3.7
# Key sizes below current guidance but not practically breakable.
WEAK_CRYPTO_MARGINAL = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 3.7
# Certificate hygiene: placeholder names, long validity, near expiry.
CERT_HYGIENE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1
# A defence-in-depth header or cookie attribute missing where the rest of the
# page is sound.
MISSING_HEADER_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1
# A third-party stylesheet loaded without Subresource Integrity.
SRI_STYLESHEET_MISSING = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 3.1
# Data durability: a datastore that never or rarely persists to disk.
DATA_DURABILITY = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"  # 3.7
# POODLE (CVE-2014-3566), the NVD vector.
SSLV3_POODLE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N"  # 3.4
# CORS that allows any origin without credentials: only what the page shows
# a visitor without a session is readable cross-origin.
CORS_UNCREDENTIALED = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1
# No request rate limit on an API endpoint for a regular user.
RATE_LIMIT_MISSING = "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:L"  # 3.1
