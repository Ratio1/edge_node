"""
CVSS v3.1 base vectors for probe findings, one per kind of weakness.

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

# --- LOW --------------------------------------------------------------------

# Version, banner, framework or path disclosure: useful only together with a
# separate weakness, hence AC:H.
INFO_DISCLOSURE_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 3.7
# Key sizes below current guidance but not practically breakable.
WEAK_CRYPTO_MARGINAL = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N"  # 3.7
# Certificate hygiene: placeholder names, long validity, near expiry.
CERT_HYGIENE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1
# A defence-in-depth header missing where the rest of the page is sound.
MISSING_HEADER_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"  # 3.1
# A third-party stylesheet loaded without Subresource Integrity.
SRI_STYLESHEET_MISSING = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # 3.1
# Data durability: a datastore that never or rarely persists to disk.
DATA_DURABILITY = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L"  # 3.7
# POODLE (CVE-2014-3566), the NVD vector.
SSLV3_POODLE = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N"  # 3.4
