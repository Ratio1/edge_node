"""
Declarative CVE database for RedMesh version-based vulnerability matching.

Each entry maps a product + version constraint to a known CVE.  The
``check_cves()`` helper returns ``Finding`` instances that feed directly
into ``probe_result()``.

Phase 2 PR-2.2b: ``check_cves()`` accepts an optional
``DynamicReferenceCache`` (NVD CVSS + CISA KEV + FIRST EPSS) and
populates the corresponding Finding fields when a cache is provided.
Without a cache the function behaves as before — static severity only
— so legacy callers remain unaffected.
"""

import re
from contextvars import ContextVar
from dataclasses import dataclass
from .cve_catalog_expansion import EXPANDED_CVE_ROWS
from .cve_cvss_vectors import CVE_CVSS_VECTORS
from .cvss import cvss31_base_score
from .findings import Finding, Remediation, Severity, _template_band_agrees, current_probe_port
from .references import cwe_to_owasp

CVE_DB_LAST_UPDATED = "2026-11-14"
_CURRENT_DYNAMIC_CACHE: ContextVar = ContextVar("redmesh_dynamic_reference_cache", default=None)
_VULNDB_READER = None  # `generated` source (RM-169); None means the frozen `CVE_DATABASE`
# Scan-local `{"<port>/<cve_id>": entry}` of CVEs the matcher evaluated and
# skipped as not applicable (RM-103 item 6). None outside a worker run.
_CURRENT_NOT_APPLICABLE: ContextVar = ContextVar("redmesh_cves_not_applicable", default=None)


@dataclass(frozen=True)
class CveEntry:
  product: str
  constraint: str      # "<1.4.3", ">=2.4.49,<2.4.51", "<7.0"
  cve_id: str
  severity: Severity
  title: str
  cwe_id: str = ""
  # "server" | "client" — which component of the product the weakness lives in.
  # Left empty here and resolved through CLIENT_SIDE_CVE_IDS, so the separate
  # expansion catalog (a table of plain tuples) is covered by the same rule
  # rather than needing the field threaded through it too.
  applicability: str = ""


# CVEs whose weakness is in the *client* side of the product. Everything a probe
# fingerprints is a listening service, so matching these off a server banner
# asserts a weakness the evidence cannot support: a running sshd says nothing
# about whether anyone on that host ever runs `scp` or `ssh-add`.
CLIENT_SIDE_CVE_IDS = frozenset({
  "CVE-2019-6111",    # scp client-side file overwrite
  "CVE-2025-26465",   # client VerifyHostKeyDNS bypass
  "CVE-2023-28531",   # ssh-add destination constraint bypass
  "CVE-2023-38408",   # ssh-agent PKCS#11 search path code execution
  "CVE-2016-10009",   # ssh-agent untrusted search path
  "CVE-2021-28041",   # ssh-agent double free
  "CVE-2016-0778",    # roaming client memory disclosure
  "CVE-2020-12062",   # scp duplicate response mishandling
  "CVE-2020-15778",   # scp command injection
  # NVD: "The client in OpenSSH before 7.2 mishandles failed cookie generation
  # for untrusted X11 forwarding" — a client weakness, and CRITICAL, so it was
  # the highest-severity instance of the over-match this set exists to stop.
  "CVE-2016-1908",
  # PostgreSQL: PQescapeLiteral / PQescapeIdentifier quoting in libpq, reached
  # through psql — the client library, not the listening server.
  "CVE-2025-1094",
})

SERVER_APPLICABILITY = "server"
CLIENT_APPLICABILITY = "client"


def entry_applicability(entry) -> str:
  """Resolve which component of the product an entry's weakness lives in."""
  declared = getattr(entry, "applicability", "") or ""
  if declared:
    return declared
  cve_id = getattr(entry, "cve_id", "") or ""
  return CLIENT_APPLICABILITY if cve_id in CLIENT_SIDE_CVE_IDS else SERVER_APPLICABILITY


CVE_DATABASE: list = [
  # ── Elasticsearch ──────────────────────────────────────────────────
  CveEntry("elasticsearch", "<1.2",   "CVE-2014-3120", Severity.HIGH, "MVEL scripting RCE", "CWE-94"),
  CveEntry("elasticsearch", "<1.4.3", "CVE-2015-1427", Severity.CRITICAL, "Groovy sandbox escape RCE", "CWE-94"),
  CveEntry("elasticsearch", "<1.4.5", "CVE-2015-3337", Severity.HIGH, "Directory traversal via site plugin", "CWE-22"),
  CveEntry("elasticsearch", "<6.4.3", "CVE-2018-17244", Severity.MEDIUM, "Security bypass in token generation", "CWE-287"),
  CveEntry("elasticsearch", ">=7.0.0,<7.17.19", "CVE-2024-23450", Severity.HIGH, "Ingest pipeline DoS via deep nesting", "CWE-400"),

  # ── OpenSSH ────────────────────────────────────────────────────────
  # Two rows because the published scope is a disjunction — `<4.4p1` OR
  # `>=8.5p1,<9.8p1` — and a constraint string joins with AND. Encoded as a
  # single `<9.3` it both over-matched (4.4p1 through 8.5p1 are not affected)
  # and under-matched (9.3 through 9.8p1 are).
  #
  # Bounds are written WITHOUT the `p` suffix on purpose. `_SSH_LIBRARY_PATTERNS`
  # captures `(\d+\.\d+(?:\.\d+)?)`, so the matcher is handed "9.8", never
  # "9.8p1" — and `_parse_version` ranks the suffix in the key's tail,
  # making 9.8 sort *below* 9.8p1. Writing the published `p`-suffixed bounds
  # here shifted both boundaries by a release: a patched 9.8p1 server reported
  # CRITICAL, and vulnerable 8.5p1 servers were missed.
  CveEntry("openssh", "<4.4", "CVE-2024-6387", Severity.HIGH, "regreSSHion: signal handler race RCE", "CWE-362"),
  CveEntry("openssh", ">=8.5,<9.8", "CVE-2024-6387", Severity.HIGH, "regreSSHion: signal handler race RCE", "CWE-362"),
  CveEntry("openssh", ">=6.8,<9.9.2", "CVE-2025-26465", Severity.MEDIUM, "MitM via VerifyHostKeyDNS bypass", "CWE-305",
           applicability=CLIENT_APPLICABILITY),
  CveEntry("openssh", "<8.1",  "CVE-2019-6111", Severity.MEDIUM, "SCP client-side file overwrite", "CWE-20",
           applicability=CLIENT_APPLICABILITY),
  CveEntry("openssh", "<7.6",  "CVE-2017-15906", Severity.MEDIUM, "Improper write restriction in readonly mode", "CWE-732"),
  CveEntry("openssh", "<7.0",  "CVE-2016-6210", Severity.MEDIUM, "User enumeration via timing", "CWE-200"),

  # ── Redis ──────────────────────────────────────────────────────────
  # One row per branch: a single `<X` bound across branches fired on patched
  # servers of the other branches. Ranges are the vendor's (CVE.org CNA) and
  # NVD's; the lowest branch of each CVE keeps the CNA's open lower bound.
  CveEntry("redis", ">=2.2,<5.0.13",  "CVE-2021-32761", Severity.HIGH, "BITFIELD integer overflow (32-bit builds only)", "CWE-190"),
  CveEntry("redis", ">=6.0,<6.0.15",  "CVE-2021-32761", Severity.HIGH, "BITFIELD integer overflow (32-bit builds only)", "CWE-190"),
  CveEntry("redis", ">=6.2,<6.2.5",   "CVE-2021-32761", Severity.HIGH, "BITFIELD integer overflow (32-bit builds only)", "CWE-190"),
  CveEntry("redis", "<6.2.7",  "CVE-2022-24735", Severity.HIGH, "Lua sandbox escape via EVAL", "CWE-94"),
  CveEntry("redis", ">=7.0.0,<7.0.5", "CVE-2022-35951", Severity.CRITICAL, "Integer overflow in XAUTOCLAIM", "CWE-190"),
  CveEntry("redis", ">=2.6,<6.2.16",  "CVE-2024-31449", Severity.HIGH, "Lua bit library stack buffer overflow RCE", "CWE-121"),
  CveEntry("redis", ">=7.0.0,<7.2.6", "CVE-2024-31449", Severity.HIGH, "Lua bit library stack buffer overflow RCE", "CWE-121"),
  CveEntry("redis", ">=7.3.0,<7.4.1", "CVE-2024-31449", Severity.HIGH, "Lua bit library stack buffer overflow RCE", "CWE-121"),
  # `<6.2.17` has no lower bound on purpose: 6.0 and earlier are end-of-life and
  # unassessed by the vendor, and are reported (RM-169 labels them `eol_unassessed`).
  CveEntry("redis", "<6.2.17",  "CVE-2024-46981", Severity.CRITICAL, "Lua GC use-after-free RCE", "CWE-416"),
  CveEntry("redis", ">=7.2.0,<7.2.7", "CVE-2024-46981", Severity.CRITICAL, "Lua GC use-after-free RCE", "CWE-416"),
  CveEntry("redis", ">=7.4.0,<7.4.2", "CVE-2024-46981", Severity.CRITICAL, "Lua GC use-after-free RCE", "CWE-416"),

  # ── MySQL ──────────────────────────────────────────────────────────
  CveEntry("mysql", ">=5.5,<5.5.52",  "CVE-2016-6662", Severity.CRITICAL, "Config file injection RCE", "CWE-94"),
  CveEntry("mysql", ">=5.6,<5.6.33",  "CVE-2016-6662", Severity.CRITICAL, "Config file injection RCE", "CWE-94"),
  CveEntry("mysql", ">=5.7,<5.7.15",  "CVE-2016-6662", Severity.CRITICAL, "Config file injection RCE", "CWE-94"),
  CveEntry("mysql", ">=5.5,<5.5.52",  "CVE-2016-6664", Severity.HIGH, "Privilege escalation via mysqld_safe", "CWE-269"),
  CveEntry("mysql", ">=8.0,<8.0.23",  "CVE-2021-2022", Severity.MEDIUM, "InnoDB buffer pool corruption", "CWE-787"),
  CveEntry("mysql", ">=8.0.0,<=8.0.35", "CVE-2024-20973", Severity.MEDIUM, "Optimizer DoS via low-privilege network attack", "CWE-404"),
  CveEntry("mysql", ">=8.1.0,<=8.2.0",  "CVE-2024-20973", Severity.MEDIUM, "Optimizer DoS via low-privilege network attack", "CWE-404"),
  # Oracle MySQL 5.1.x before 5.1.63, 5.5.x before 5.5.24, 5.6.x before 5.6.6 (NVD
  # description). NVD publishes a v2 vector only (MEDIUM).
  CveEntry("mysql", ">=5.1,<5.1.63", "CVE-2012-2122", Severity.MEDIUM, "Authentication bypass via memcmp token comparison", "CWE-287"),
  CveEntry("mysql", ">=5.5,<5.5.24", "CVE-2012-2122", Severity.MEDIUM, "Authentication bypass via memcmp token comparison", "CWE-287"),
  CveEntry("mysql", ">=5.6,<5.6.6",  "CVE-2012-2122", Severity.MEDIUM, "Authentication bypass via memcmp token comparison", "CWE-287"),
  CveEntry("mariadb", ">=5.1,<5.1.62",  "CVE-2012-2122", Severity.MEDIUM, "Authentication bypass via memcmp token comparison", "CWE-287"),
  CveEntry("mariadb", ">=5.2,<5.2.12",  "CVE-2012-2122", Severity.MEDIUM, "Authentication bypass via memcmp token comparison", "CWE-287"),
  CveEntry("mariadb", ">=5.3,<5.3.6",  "CVE-2012-2122", Severity.MEDIUM, "Authentication bypass via memcmp token comparison", "CWE-287"),
  CveEntry("mariadb", ">=5.5,<5.5.23",  "CVE-2012-2122", Severity.MEDIUM, "Authentication bypass via memcmp token comparison", "CWE-287"),

  # ── PostgreSQL (new) ───────────────────────────────────────────────
  # One row per supported branch, each at its own fixed minor. The lowest branch
  # has no lower bound: 11 and older are end-of-life and unassessed by the
  # vendor, and are reported (RM-169 labels them `eol_unassessed`).
  CveEntry("postgresql", "<13.19",  "CVE-2025-1094", Severity.HIGH, "libpq quoting SQL injection leading to RCE", "CWE-89",
           applicability=CLIENT_APPLICABILITY),
  CveEntry("postgresql", ">=14.0,<14.16", "CVE-2025-1094", Severity.HIGH, "libpq quoting SQL injection leading to RCE", "CWE-89",
           applicability=CLIENT_APPLICABILITY),
  CveEntry("postgresql", ">=15.0,<15.11", "CVE-2025-1094", Severity.HIGH, "libpq quoting SQL injection leading to RCE", "CWE-89",
           applicability=CLIENT_APPLICABILITY),
  CveEntry("postgresql", ">=16.0,<16.7", "CVE-2025-1094", Severity.HIGH, "libpq quoting SQL injection leading to RCE", "CWE-89",
           applicability=CLIENT_APPLICABILITY),
  CveEntry("postgresql", ">=17.0,<17.3", "CVE-2025-1094", Severity.HIGH, "libpq quoting SQL injection leading to RCE", "CWE-89",
           applicability=CLIENT_APPLICABILITY),
  CveEntry("postgresql", "<12.21", "CVE-2024-10979", Severity.HIGH, "PL/Perl env variable manipulation to RCE", "CWE-94"),
  CveEntry("postgresql", ">=13.0,<13.17", "CVE-2024-10979", Severity.HIGH, "PL/Perl env variable manipulation to RCE", "CWE-94"),
  CveEntry("postgresql", ">=14.0,<14.14", "CVE-2024-10979", Severity.HIGH, "PL/Perl env variable manipulation to RCE", "CWE-94"),
  CveEntry("postgresql", ">=15.0,<15.9", "CVE-2024-10979", Severity.HIGH, "PL/Perl env variable manipulation to RCE", "CWE-94"),
  CveEntry("postgresql", ">=16.0,<16.5", "CVE-2024-10979", Severity.HIGH, "PL/Perl env variable manipulation to RCE", "CWE-94"),
  CveEntry("postgresql", ">=17.0,<17.1", "CVE-2024-10979", Severity.HIGH, "PL/Perl env variable manipulation to RCE", "CWE-94"),
  CveEntry("postgresql", "<12.21", "CVE-2024-10976", Severity.MEDIUM, "Row security policy bypass via role confusion", "CWE-862"),
  CveEntry("postgresql", ">=13.0,<13.17", "CVE-2024-10976", Severity.MEDIUM, "Row security policy bypass via role confusion", "CWE-862"),
  CveEntry("postgresql", ">=14.0,<14.14", "CVE-2024-10976", Severity.MEDIUM, "Row security policy bypass via role confusion", "CWE-862"),
  CveEntry("postgresql", ">=15.0,<15.9", "CVE-2024-10976", Severity.MEDIUM, "Row security policy bypass via role confusion", "CWE-862"),
  CveEntry("postgresql", ">=16.0,<16.5", "CVE-2024-10976", Severity.MEDIUM, "Row security policy bypass via role confusion", "CWE-862"),
  CveEntry("postgresql", ">=17.0,<17.1", "CVE-2024-10976", Severity.MEDIUM, "Row security policy bypass via role confusion", "CWE-862"),

  # ── MongoDB (new) ──────────────────────────────────────────────────
  CveEntry("mongodb", ">=5.0.0,<5.0.14", "CVE-2024-8207", Severity.MEDIUM, "Privilege escalation via untrusted library load", "CWE-284"),
  CveEntry("mongodb", ">=6.0.0,<6.0.3",  "CVE-2024-8207", Severity.MEDIUM, "Privilege escalation via untrusted library load", "CWE-284"),
  CveEntry("mongodb", ">=6.1.0,<6.1.1",  "CVE-2024-8207", Severity.MEDIUM, "Privilege escalation via untrusted library load", "CWE-284"),

  # ── Exim ───────────────────────────────────────────────────────────
  CveEntry("exim", "<4.98",   "CVE-2024-39929", Severity.MEDIUM, "RFC 2231 header parsing bypass — malware delivery", "CWE-20"),
  CveEntry("exim", "<4.96.1", "CVE-2023-42115", Severity.CRITICAL, "AUTH out-of-bounds write", "CWE-787"),
  CveEntry("exim", "<4.96.1", "CVE-2023-42116", Severity.CRITICAL, "NTLM challenge stack buffer overflow", "CWE-121"),
  CveEntry("exim", "<4.96.1", "CVE-2023-42114", Severity.MEDIUM, "NTLM challenge out-of-bounds read", "CWE-125"),
  CveEntry("exim", "<4.94.2", "CVE-2021-27216", Severity.MEDIUM, "Privilege escalation via symlink attack", "CWE-59"),

  # ── Apache httpd ───────────────────────────────────────────────────
  CveEntry("apache", ">=2.4.0,<2.4.60",  "CVE-2024-38475", Severity.CRITICAL, "mod_rewrite escaping flaw — SSRF / RCE", "CWE-116"),
  CveEntry("apache", ">=2.4.0,<2.4.60",  "CVE-2024-38476", Severity.CRITICAL, "Backend header exploit — SSRF / local script exec", "CWE-829"),
  CveEntry("apache", ">=2.4.49,<2.4.51", "CVE-2021-41773", Severity.CRITICAL, "Path traversal + RCE", "CWE-22"),
  CveEntry("apache", ">=2.4.0,<2.4.52",  "CVE-2021-44790", Severity.CRITICAL, "mod_lua buffer overflow", "CWE-787"),
  CveEntry("apache", ">=2.4.0,<2.4.62",  "CVE-2024-40725", Severity.MEDIUM, "HTTP request smuggling via mod_proxy", "CWE-444"),
  CveEntry("apache", "<2.4.49",           "CVE-2021-40438", Severity.CRITICAL, "mod_proxy SSRF", "CWE-918"),
  CveEntry("apache", "<2.2.34",           "CVE-2017-7679", Severity.CRITICAL, "mod_mime buffer overread", "CWE-126"),

  # ── nginx ──────────────────────────────────────────────────────────
  CveEntry("nginx", "<1.17.7", "CVE-2019-20372", Severity.MEDIUM, "HTTP request smuggling", "CWE-444"),
  CveEntry("nginx", "<1.5.7",  "CVE-2013-4547", Severity.HIGH, "URI processing security bypass", "CWE-20"),
  CveEntry("nginx", ">=1.25.0,<1.25.4", "CVE-2024-24989", Severity.HIGH, "HTTP/3 QUIC null pointer crash", "CWE-476"),
  CveEntry("nginx", ">=1.25.0,<1.25.4", "CVE-2024-24990", Severity.HIGH, "HTTP/3 use-after-free crash", "CWE-416"),

  # ── Postfix ────────────────────────────────────────────────────────
  CveEntry("postfix", "<3.5.23", "CVE-2023-51764", Severity.MEDIUM, "SMTP smuggling via pipelining", "CWE-345"),

  # ── OpenSSL ────────────────────────────────────────────────────────
  # Branch ranges as published (NVD, CVE.org CNA). Where a row has no lower
  # bound it is on purpose: 0.9.x to 1.1.0 are end-of-life branches the vendor
  # never assessed, and they are reported (RM-169 labels them `eol_unassessed`).
  CveEntry("openssl", "<1.0.2x",  "CVE-2020-1971", Severity.MEDIUM, "NULL dereference in GENERAL_NAME_cmp", "CWE-476"),
  CveEntry("openssl", ">=1.1.0,<1.1.1i",  "CVE-2020-1971", Severity.MEDIUM, "NULL dereference in GENERAL_NAME_cmp", "CWE-476"),
  CveEntry("openssl", ">=3.0.0,<3.0.7",  "CVE-2022-3602", Severity.HIGH, "X.509 email address buffer overflow", "CWE-120"),
  CveEntry("openssl", ">=3.2.0,<3.2.4",  "CVE-2024-12797", Severity.HIGH, "RPK verification bypass enabling MitM", "CWE-392"),
  CveEntry("openssl", "<1.1.1y", "CVE-2024-4741", Severity.CRITICAL, "SSL_free_buffers use-after-free", "CWE-416"),
  CveEntry("openssl", ">=3.0.0,<3.0.14", "CVE-2024-4741", Severity.CRITICAL, "SSL_free_buffers use-after-free", "CWE-416"),
  CveEntry("openssl", ">=3.1.0,<3.1.6", "CVE-2024-4741", Severity.CRITICAL, "SSL_free_buffers use-after-free", "CWE-416"),
  CveEntry("openssl", ">=3.2.0,<3.2.2", "CVE-2024-4741", Severity.CRITICAL, "SSL_free_buffers use-after-free", "CWE-416"),
  CveEntry("openssl", ">=3.3.0,<3.3.1", "CVE-2024-4741", Severity.CRITICAL, "SSL_free_buffers use-after-free", "CWE-416"),

  # ── ProFTPD ────────────────────────────────────────────────────────
  CveEntry("proftpd", "<1.3.6",  "CVE-2019-12815", Severity.CRITICAL, "Arbitrary file copy via mod_copy", "CWE-284"),
  CveEntry("proftpd", "<1.3.8",  "CVE-2024-48651", Severity.HIGH, "Supplemental group inherits GID 0 (root group)", "CWE-269"),

  # ── vsftpd ─────────────────────────────────────────────────────────
  CveEntry("vsftpd", ">=2.3.4,<2.3.5", "CVE-2011-2523", Severity.CRITICAL, "Backdoor command execution", "CWE-506"),

  # ── Memcached (new) ────────────────────────────────────────────────
  CveEntry("memcached", "<1.4.33", "CVE-2016-8704", Severity.CRITICAL, "process_bin_append integer overflow RCE", "CWE-190"),
  CveEntry("memcached", "<1.4.33", "CVE-2016-8705", Severity.CRITICAL, "process_bin_update integer overflow RCE", "CWE-190"),
  CveEntry("memcached", "<1.4.33", "CVE-2016-8706", Severity.HIGH, "SASL auth integer overflow RCE", "CWE-190"),

  # ── VNC (new) ──────────────────────────────────────────────────────
  CveEntry("tightvnc", "<=1.3.10", "CVE-2019-15678", Severity.CRITICAL, "rfbServerCutText heap buffer overflow RCE", "CWE-122"),
  CveEntry("tightvnc", "<=1.3.10", "CVE-2019-15679", Severity.CRITICAL, "InitialiseRFBConnection heap overflow RCE", "CWE-122"),
  CveEntry("libvncserver", "<0.9.13", "CVE-2019-20788", Severity.CRITICAL, "HandleCursorShape integer overflow RCE", "CWE-190"),

  # ── Samba (new — for SMB deep enumeration) ─────────────────────────
  CveEntry("samba", ">=4.16.0,<4.17.12", "CVE-2023-3961", Severity.CRITICAL, "Pipe name validation bypass — root socket access", "CWE-22"),
  CveEntry("samba", "<4.13.17", "CVE-2021-44142", Severity.HIGH, "vfs_fruit heap overflow RCE", "CWE-787"),
  CveEntry("samba", ">=3.5.0,<4.6.4", "CVE-2017-7494", Severity.CRITICAL, "SambaCry — writable share RCE via shared library upload", "CWE-94"),

  # ── Asterisk / FreePBX (new — for SIP probe) ──────────────────────
  CveEntry("asterisk", "<18.24.2", "CVE-2024-42365", Severity.HIGH, "AMI manager injection via caller ID", "CWE-94"),
  CveEntry("asterisk", ">=19.0.0,<20.9.2", "CVE-2024-42365", Severity.HIGH, "AMI manager injection via caller ID", "CWE-94"),
  CveEntry("asterisk", ">=21.0.0,<21.4.2", "CVE-2024-42365", Severity.HIGH, "AMI manager injection via caller ID", "CWE-94"),
  CveEntry("asterisk", "<18.20.1", "CVE-2023-49786", Severity.MEDIUM, "PJSIP request smuggling via multipart parser", "CWE-444"),
  CveEntry("asterisk", ">=19.0.0,<20.5.1", "CVE-2023-49786", Severity.MEDIUM, "PJSIP request smuggling via multipart parser", "CWE-444"),
  CveEntry("asterisk", ">=21.0.0,<21.0.1", "CVE-2023-49786", Severity.MEDIUM, "PJSIP request smuggling via multipart parser", "CWE-444"),

  # ── OpenSMTPD ────────────────────────────────────────────────────
  CveEntry("opensmtpd", "<6.6.2",  "CVE-2020-7247", Severity.CRITICAL, "RCE via crafted MAIL FROM command", "CWE-78"),
  CveEntry("opensmtpd", "<6.6.4",  "CVE-2020-8794", Severity.CRITICAL, "Out-of-bounds read in MTA bounce handling", "CWE-125"),

  # ── libssh ───────────────────────────────────────────────────────
  CveEntry("libssh", "<0.7.6",  "CVE-2018-10933", Severity.CRITICAL, "Authentication bypass via MSG_USERAUTH_SUCCESS", "CWE-287"),
  CveEntry("libssh", ">=0.8.0,<0.8.4", "CVE-2018-10933", Severity.CRITICAL, "Authentication bypass via MSG_USERAUTH_SUCCESS", "CWE-287"),

  # ── Dropbear ─────────────────────────────────────────────────────
  CveEntry("dropbear", "<2018.76", "CVE-2018-15599", Severity.MEDIUM, "Username enumeration via response size", "CWE-203"),
  # NVD's summary names dbclient, but the 2016.74 changelog is explicit that the
  # same format string in the message printout lets an attacker "run arbitrary
  # code as root when connecting to Dropbear server" when usernames containing
  # "%" exist on the host (validated by getpwnam()). A server CVE with a
  # precondition, so it fires on a server banner and the precondition is in
  # the title. Classing it client-only (first RM-090 cut) dropped a real finding.
  CveEntry("dropbear", "<2016.74", "CVE-2016-7406", Severity.CRITICAL,
           "Format string in message printout (server: root code execution when usernames containing % exist; also dbclient)",
           "CWE-134"),

  # ── Erlang OTP SSH ──────────────────────────────────────────────
  # The probe reports whichever number the banner carries: the ssh application
  # version (`Erlang/5.2.9`, <= 5.x) or the OTP release (`Erlang/27.3.2`, >= 17).
  # The two ranges do not overlap, so each branch gets its own rows. Fixed in
  # ssh 5.2.10 / 5.1.4.8 / 4.15.3.12 and OTP 27.3.3 / 26.2.5.11 / 25.3.2.20
  # (Erlang/OTP security advisory for CVE-2025-32433); every older release is affected.
  CveEntry("erlang_ssh", "<4.15.3.12", "CVE-2025-32433", Severity.CRITICAL, "Pre-auth RCE via SSH protocol message sequence", "CWE-306"),
  CveEntry("erlang_ssh", ">=5.0,<5.1.4.8", "CVE-2025-32433", Severity.CRITICAL, "Pre-auth RCE via SSH protocol message sequence", "CWE-306"),
  CveEntry("erlang_ssh", ">=5.2,<5.2.10", "CVE-2025-32433", Severity.CRITICAL, "Pre-auth RCE via SSH protocol message sequence", "CWE-306"),
  CveEntry("erlang_ssh", ">=17,<25.3.2.20", "CVE-2025-32433", Severity.CRITICAL, "Pre-auth RCE via SSH protocol message sequence", "CWE-306"),
  CveEntry("erlang_ssh", ">=26,<26.2.5.11", "CVE-2025-32433", Severity.CRITICAL, "Pre-auth RCE via SSH protocol message sequence", "CWE-306"),
  CveEntry("erlang_ssh", ">=27,<27.3.3", "CVE-2025-32433", Severity.CRITICAL, "Pre-auth RCE via SSH protocol message sequence", "CWE-306"),

  # ── CouchDB ──────────────────────────────────────────────────────
  CveEntry("couchdb", "<3.2.2",           "CVE-2022-24706", Severity.CRITICAL, "Default Erlang cookie RCE via cluster protocol", "CWE-1188"),
  CveEntry("couchdb", ">=3.0.0,<3.1.2",   "CVE-2021-38295", Severity.HIGH, "Privilege escalation via cluster API", "CWE-269"),
  CveEntry("couchdb", "<2.1.1",           "CVE-2017-12635", Severity.CRITICAL, "Admin creation race condition bypass", "CWE-269"),
  CveEntry("couchdb", "<2.1.1",           "CVE-2017-12636", Severity.HIGH, "OS command injection via query server config", "CWE-78"),

  # ── InfluxDB ────────────────────────────────────────────────────
  CveEntry("influxdb", "<1.7.6",  "CVE-2019-20933", Severity.CRITICAL, "JWT auth bypass via empty shared secret", "CWE-287"),

  # ── Drupal ─────────────────────────────────────────────────────
  CveEntry("drupal", ">=7.0,<7.58",      "CVE-2018-7600", Severity.CRITICAL, "Drupalgeddon2: RCE via Form API", "CWE-20"),
  CveEntry("drupal", ">=8.0.0,<8.3.9",   "CVE-2018-7600", Severity.CRITICAL, "Drupalgeddon2: RCE via Form API", "CWE-20"),
  CveEntry("drupal", ">=8.4.0,<8.4.6",   "CVE-2018-7600", Severity.CRITICAL, "Drupalgeddon2: RCE via Form API", "CWE-20"),
  CveEntry("drupal", ">=8.5.0,<8.5.1",   "CVE-2018-7600", Severity.CRITICAL, "Drupalgeddon2: RCE via Form API", "CWE-20"),
  CveEntry("drupal", ">=7.0,<7.59",      "CVE-2018-7602", Severity.CRITICAL, "Drupalgeddon3: RCE via Contextual links", "CWE-20"),
  CveEntry("drupal", ">=8.0.0,<8.4.8",   "CVE-2018-7602", Severity.CRITICAL, "Drupalgeddon3: RCE via Contextual links", "CWE-20"),
  CveEntry("drupal", ">=8.5.0,<8.5.3",   "CVE-2018-7602", Severity.CRITICAL, "Drupalgeddon3: RCE via Contextual links", "CWE-20"),
  CveEntry("drupal", ">=7.0,<7.32",      "CVE-2014-3704", Severity.CRITICAL, "SQL injection via expand_arguments()", "CWE-89"),

  # ── WordPress ──────────────────────────────────────────────────
  CveEntry("wordpress", "<4.7.1",         "CVE-2016-10033", Severity.CRITICAL, "PHPMailer RCE via wp_mail()", "CWE-78"),
  CveEntry("wordpress", "<4.7.4",         "CVE-2017-8295", Severity.MEDIUM, "Host header password reset hijack", "CWE-640"),
  CveEntry("wordpress", ">=4.7.0,<4.7.2", "CVE-2017-1001000", Severity.HIGH, "REST API content injection", "CWE-284"),

  # ── Joomla ─────────────────────────────────────────────────────
  CveEntry("joomla", ">=4.0.0,<4.2.8",   "CVE-2023-23752", Severity.MEDIUM, "Unauthenticated information disclosure via REST API", "CWE-284"),

  # ── Django ─────────────────────────────────────────────────────
  CveEntry("django", "<1.11.5",          "CVE-2017-12794", Severity.MEDIUM, "Debug page XSS via invalid URL parameter", "CWE-79"),

  # ── Laravel / Ignition ─────────────────────────────────────────
  CveEntry("laravel_ignition", "<2.5.2",  "CVE-2021-3129", Severity.CRITICAL, "Ignition debug mode RCE via file_put_contents", "CWE-94"),

  # ── Apache Struts2 ─────────────────────────────────────────────
  CveEntry("struts2", ">=2.3.5,<2.3.32",   "CVE-2017-5638", Severity.CRITICAL, "S2-045: OGNL injection via Content-Type header RCE", "CWE-94"),
  CveEntry("struts2", ">=2.5.0,<2.5.10.1", "CVE-2017-5638", Severity.CRITICAL, "S2-045: OGNL injection via Content-Type header RCE", "CWE-94"),
  CveEntry("struts2", ">=2.3.5,<2.3.33",   "CVE-2017-9805", Severity.HIGH, "S2-052: XML deserialization RCE via REST plugin", "CWE-502"),
  CveEntry("struts2", ">=2.5.0,<2.5.13",   "CVE-2017-9805", Severity.HIGH, "S2-052: XML deserialization RCE via REST plugin", "CWE-502"),
  CveEntry("struts2", ">=2.0.0,<2.5.26",   "CVE-2020-17530", Severity.CRITICAL, "S2-061: Forced OGNL evaluation via tag attributes", "CWE-94"),

  # ── Oracle WebLogic ──────────────────────────────────────────
  CveEntry("weblogic", ">=10.3.6.0,<10.3.6.1", "CVE-2017-10271", Severity.HIGH, "XMLDecoder deserialization RCE via wls-wsat", "CWE-502"),
  CveEntry("weblogic", ">=12.1.3.0,<12.1.3.1", "CVE-2017-10271", Severity.HIGH, "XMLDecoder deserialization RCE via wls-wsat", "CWE-502"),
  CveEntry("weblogic", ">=10.3.6.0,<10.3.6.1", "CVE-2020-14882", Severity.CRITICAL, "Console unauthenticated takeover RCE", "CWE-306"),
  CveEntry("weblogic", ">=12.1.3.0,<12.2.1.5", "CVE-2020-14882", Severity.CRITICAL, "Console unauthenticated takeover RCE", "CWE-306"),
  CveEntry("weblogic", ">=14.1.1.0,<14.1.1.1", "CVE-2020-14882", Severity.CRITICAL, "Console unauthenticated takeover RCE", "CWE-306"),
  # Oracle lists 12.2.1.3.0, 12.2.1.4.0 and 14.1.1.0.0; 12.2.1.4 and 14.1.1 are the current KEV targets.
  CveEntry("weblogic", ">=12.2.1.3,<12.2.1.5", "CVE-2023-21839", Severity.HIGH, "IIOP/T3 protocol deserialization RCE", "CWE-502"),
  CveEntry("weblogic", ">=14.1.1.0,<14.1.2", "CVE-2023-21839", Severity.HIGH, "IIOP/T3 protocol deserialization RCE", "CWE-502"),

  # ── Apache Tomcat ────────────────────────────────────────────
  CveEntry("tomcat", ">=9.0.0,<9.0.31",   "CVE-2020-1938", Severity.CRITICAL, "Ghostcat: AJP connector file read/inclusion RCE", "CWE-20"),
  CveEntry("tomcat", ">=8.5.0,<8.5.51",   "CVE-2020-1938", Severity.CRITICAL, "Ghostcat: AJP connector file read/inclusion RCE", "CWE-20"),
  CveEntry("tomcat", ">=7.0.0,<7.0.100",  "CVE-2020-1938", Severity.CRITICAL, "Ghostcat: AJP connector file read/inclusion RCE", "CWE-20"),
  CveEntry("tomcat", ">=7.0.0,<7.0.81",   "CVE-2017-12615", Severity.HIGH, "PUT method JSP file upload RCE", "CWE-434"),
  CveEntry("tomcat", ">=8.5.0,<=8.5.100", "CVE-2025-24813", Severity.CRITICAL, "Partial PUT deserialization RCE", "CWE-502"),
  CveEntry("tomcat", ">=9.0.0,<9.0.99",   "CVE-2025-24813", Severity.CRITICAL, "Partial PUT deserialization RCE", "CWE-502"),
  CveEntry("tomcat", ">=10.1.0,<10.1.35", "CVE-2025-24813", Severity.CRITICAL, "Partial PUT deserialization RCE", "CWE-502"),
  CveEntry("tomcat", ">=11.0.0,<11.0.3",  "CVE-2025-24813", Severity.CRITICAL, "Partial PUT deserialization RCE", "CWE-502"),

  # ── JBoss Application Server ─────────────────────────────────
  CveEntry("jboss", ">=4.0,<7.0",   "CVE-2017-12149", Severity.CRITICAL, "Java deserialization RCE via /invoker/readonly", "CWE-502"),
  # NVD: "Red Hat Jboss Application Server <= Jboss 4.X" (CPE up to 4.0, CNA "4.x").
  CveEntry("jboss", "<5.0", "CVE-2017-7504", Severity.CRITICAL, "JbossMQ HTTP invocation layer deserialization RCE", "CWE-502"),

  # ── Spring Framework ─────────────────────────────────────────
  CveEntry("spring_framework", ">=5.3.0,<5.3.18", "CVE-2022-22965", Severity.CRITICAL, "Spring4Shell: ClassLoader manipulation RCE", "CWE-94"),
  CveEntry("spring_framework", ">=5.2.0,<5.2.20", "CVE-2022-22965", Severity.CRITICAL, "Spring4Shell: ClassLoader manipulation RCE", "CWE-94"),

  # ── Spring Cloud Function ────────────────────────────────────
  CveEntry("spring_cloud_function", ">=3.0.0,<3.1.7", "CVE-2022-22963", Severity.CRITICAL, "SpEL injection via routing header RCE", "CWE-94"),
  CveEntry("spring_cloud_function", ">=3.2.0,<3.2.3", "CVE-2022-22963", Severity.CRITICAL, "SpEL injection via routing header RCE", "CWE-94"),

  # ── Eclipse Jetty ─────────────────────────────────────────────
  CveEntry("jetty", ">=9.4.0,<9.4.52", "CVE-2023-26048", Severity.MEDIUM, "Request large content denial-of-service via multipart", "CWE-400"),
  CveEntry("jetty", ">=9.4.0,<9.4.52", "CVE-2023-26049", Severity.MEDIUM, "Cookie parsing allows exfiltration of HttpOnly cookies", "CWE-200"),
  CveEntry("jetty", ">=9.4.0,<9.4.54", "CVE-2023-36478", Severity.HIGH, "HTTP/2 HPACK integer overflow leads to buffer overflow", "CWE-190"),
  CveEntry("jetty", ">=9.4.0,<9.4.51", "CVE-2023-40167", Severity.MEDIUM, "HTTP request smuggling via invalid Transfer-Encoding", "CWE-444"),

  # ── BIND (DNS) ──────────────────────────────────────────────────
  # One row per branch (NVD, ISC CNA). `-S` and `-P` editions sort after the plain release.
  CveEntry("bind", ">=9.0.0,<9.16.33",  "CVE-2022-2795", Severity.MEDIUM, "Flooding targeted resolver with queries DoS", "CWE-400"),
  CveEntry("bind", ">=9.18.0,<9.18.7",  "CVE-2022-2795", Severity.MEDIUM, "Flooding targeted resolver with queries DoS", "CWE-400"),
  CveEntry("bind", ">=9.19.0,<9.19.5",  "CVE-2022-2795", Severity.MEDIUM, "Flooding targeted resolver with queries DoS", "CWE-400"),
  CveEntry("bind", ">=9.16.14,<9.16.33",  "CVE-2022-3080", Severity.HIGH, "TKEY assertion failure DoS on DNAME resolution", "CWE-617"),
  CveEntry("bind", ">=9.18.0,<9.18.7",  "CVE-2022-3080", Severity.HIGH, "TKEY assertion failure DoS on DNAME resolution", "CWE-617"),
  CveEntry("bind", ">=9.19.0,<9.19.5",  "CVE-2022-3080", Severity.HIGH, "TKEY assertion failure DoS on DNAME resolution", "CWE-617"),
  CveEntry("bind", ">=9.11.0,<9.16.42",  "CVE-2023-2828", Severity.HIGH, "Cache exhaustion DoS via crafted queries", "CWE-770"),
  CveEntry("bind", ">=9.18.0,<9.18.16",  "CVE-2023-2828", Severity.HIGH, "Cache exhaustion DoS via crafted queries", "CWE-770"),
  CveEntry("bind", ">=9.19.0,<9.19.14",  "CVE-2023-2828", Severity.HIGH, "Cache exhaustion DoS via crafted queries", "CWE-770"),
  CveEntry("bind", ">=9.0.0,<9.16.46",  "CVE-2023-4408", Severity.HIGH, "DNS message parsing CPU exhaustion DoS", "CWE-400"),
  CveEntry("bind", ">=9.18.0,<9.18.22",  "CVE-2023-4408", Severity.HIGH, "DNS message parsing CPU exhaustion DoS", "CWE-400"),
  CveEntry("bind", ">=9.19.0,<9.19.20",  "CVE-2023-4408", Severity.HIGH, "DNS message parsing CPU exhaustion DoS", "CWE-400"),
  CveEntry("bind", "<9.11.31",  "CVE-2021-25216", Severity.CRITICAL, "GSSAPI SPNEGO buffer overflow RCE", "CWE-120"),
  CveEntry("bind", "<9.11.19",  "CVE-2020-8617", Severity.MEDIUM, "TSIG validity check assertion failure DoS", "CWE-617"),
  CveEntry("bind", "<9.10.4",   "CVE-2016-2776", Severity.HIGH, "Crafted query buffer.c assertion failure DoS", "CWE-617"),
]


for _product, _constraint, _cve_id, _severity, _title, _cwe_id in EXPANDED_CVE_ROWS:
  CVE_DATABASE.append(CveEntry(
    _product,
    _constraint,
    _cve_id,
    Severity[_severity],
    _title,
    _cwe_id,
  ))


@dataclass(frozen=True)
class DistroPackage:
  """A distribution build of a product, as a banner announces it.

  `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` is upstream 8.9p1 at Ubuntu revision
  3ubuntu0.10. The upstream version alone is what the matcher compared
  before RM-070; the revision is where the distribution's backported fixes
  live, so it is the only thing that can say whether a CVE the upstream
  version matches has in fact been patched on this host.
  """
  distro: str      # "ubuntu" | "debian"
  upstream: str    # "8.9p1"
  revision: str    # "3ubuntu0.10", "5+deb11u2"


_DISTRO_PACKAGE_RE = re.compile(
  r"[_\s/](?P<upstream>\d[\w.]*?)\s+(?P<distro>Ubuntu|Debian)-(?P<revision>[\w.+~]+)",
  re.IGNORECASE,
)


def parse_distro_package(text):
  """The distribution package a banner or version string announces, or None.

  None means "no distribution suffix": an upstream build, or a distribution
  that does not stamp its revision into the banner. It does not mean
  "not backported"; that state is `unknown` below.
  """
  if not isinstance(text, str):
    return None
  m = _DISTRO_PACKAGE_RE.search(text)
  if not m:
    return None
  return DistroPackage(
    distro=m.group("distro").lower(),
    upstream=m.group("upstream"),
    revision=m.group("revision"),
  )


def _revision_chunks(revision: str):
  # dpkg's ordering, reduced to what package revisions use: alternate
  # non-digit and digit runs, digits compare numerically, `~` sorts before
  # anything (so `1~rc1` < `1`), and a missing chunk sorts before a present
  # one. `0.10` > `0.3`, which `_parse_version` cannot say: it reads
  # `3ubuntu0.10` and `3ubuntu0.3` as the same tuple.
  return [
    (int(chunk) if chunk.isdigit() else chunk)
    for chunk in re.findall(r"\d+|[^\d]+", revision or "")
  ]


def _compare_debian_revision(a: str, b: str) -> int:
  """-1, 0 or 1 as package revision `a` sorts before, equal to or after `b`."""
  left, right = _revision_chunks(a), _revision_chunks(b)
  for x, y in zip(left, right):
    if x == y:
      continue
    if isinstance(x, int) and isinstance(y, int):
      return -1 if x < y else 1
    x_text, y_text = str(x), str(y)
    # `~` sorts before the empty string, which sorts before everything else.
    if x_text.startswith("~") != y_text.startswith("~"):
      return -1 if x_text.startswith("~") else 1
    return -1 if x_text < y_text else 1
  if len(left) == len(right):
    return 0
  longer = left if len(left) > len(right) else right
  extra = longer[min(len(left), len(right))]
  if isinstance(extra, str) and extra.startswith("~"):
    return 1 if longer is right else -1
  return -1 if longer is right else 1


# Distribution security updates that fix a CVE by backport without moving the
# upstream version: (product, distro) -> cve_id -> rows of
# (upstream, first fixed revision, advisory). A host whose package is at or
# past the fixed revision is not vulnerable, whatever the upstream version
# says. Static and deliberately small — the rows here are the ones needed to
# stop the false positives observed on real scans; a USN/DSA/OVAL feed is the
# follow-up recorded on RM-070. Any (product, CVE) with no row is `unknown`,
# never silently `fixed`.
BACKPORT_FIXES = {
  ("openssh", "ubuntu"): {
    # USN-6859-1 (2024-07-01): regreSSHion.
    "CVE-2024-6387": (
      ("8.9p1", "3ubuntu0.10", "USN-6859-1"),   # 22.04 LTS
      ("9.6p1", "3ubuntu13.3", "USN-6859-1"),   # 24.04 LTS
    ),
  },
}

BACKPORT_FIXED = "fixed"
BACKPORT_NOT_FIXED = "not_fixed"
BACKPORT_UNKNOWN = "unknown"
# The banner announced no distribution package at all, so there is nothing to
# assess. Stated rather than left as "" so a report can always print a state.
BACKPORT_UNKNOWN_NO_PACKAGE = "unknown_no_package"


def _backport_row(product: str, cve_id: str, package):
  """The `(upstream, fixed_revision, advisory)` row for this package's upstream, or None."""
  if package is None:
    return None
  rows = BACKPORT_FIXES.get((product, package.distro), {}).get(cve_id, ())
  for row in rows:
    if row[0] == package.upstream:
      return row
  return None


def backport_status(product: str, cve_id: str, package) -> str:
  """`fixed`, `not_fixed`, `unknown` or `unknown_no_package` for a CVE on a distribution package."""
  if package is None:
    return BACKPORT_UNKNOWN_NO_PACKAGE
  row = _backport_row(product, cve_id, package)
  if row is None:
    return BACKPORT_UNKNOWN
  if _compare_debian_revision(package.revision, row[1]) >= 0:
    return BACKPORT_FIXED
  return BACKPORT_NOT_FIXED


# Why a CVE whose version range matched was still not reported.
NOT_APPLICABLE_CLIENT_SIDE = "client_side"
NOT_APPLICABLE_BACKPORT_FIXED = "backport_fixed"


def _record_not_applicable(entry, product: str, version: str, package, reason: str) -> None:
  """Note a matched-but-skipped CVE in the scan-local collector, if one is set.

  Only the two reasons a reader could dispute are recorded. A version outside
  the CVE's range was never a candidate, so listing it would bury these rows
  under the whole catalog for the product.
  """
  collector = _CURRENT_NOT_APPLICABLE.get()
  if collector is None:
    return
  port = current_probe_port()
  key = f"{port if port is not None else ''}/{entry.cve_id}"
  if key in collector:
    return
  row = _backport_row(product, entry.cve_id, package) if reason == NOT_APPLICABLE_BACKPORT_FIXED else None
  collector[key] = {
    "cve_id": entry.cve_id,
    "title": entry.title,
    "product": product,
    "version": version,
    "package": f"{package.distro} {package.upstream}-{package.revision}" if package else "",
    "port": port,
    "reason": reason,
    "advisory": row[2] if row else "",
    "fixed_revision": row[1] if row else "",
  }


def check_cves(
  product: str,
  version: str,
  *,
  applicability: str = SERVER_APPLICABILITY,
  dynamic_cache=None,
  package=None,
  inferred_span=None,
) -> list:
  """Match version against CVE database. Returns list of Findings.

  When ``dynamic_cache`` is a ``DynamicReferenceCache`` instance,
  every emitted Finding is enriched with live NVD CVSS, CISA KEV
  status, FIRST EPSS score, and OWASP Top 10 mapping (looked up via
  the static cwe_to_owasp table). When no cache is provided, the
  legacy behavior is preserved (static severity only).

  ``package`` is the ``DistroPackage`` the banner announced, when it
  announced one. A CVE the distribution has fixed by backport at or below
  the package's revision is not reported; every other match on a
  distribution package states its backport status explicitly (RM-070).

  ``inferred_span`` is a pair of versions a probe proved (Heartbleed: ``1.0.1`` to ``1.0.1f``). Under
  ``generated`` only rows that hold across the span keep their confidence; the rest are tentative
  ``inferred_version``. ``static`` ignores it.
  """
  if dynamic_cache is None:
    dynamic_cache = get_dynamic_reference_cache()

  findings = []
  seen_cves = set()
  reader = _VULNDB_READER
  if reader is not None:
    # `generated`: the reader returns one row per CVE, strongest first, so no `seen_cves` here.
    for match in reader.query(product, version, inferred_span):
      if applicability and (CLIENT_APPLICABILITY if match.client_side else SERVER_APPLICABILITY) != applicability:
        if match.client_side:
          _record_not_applicable(match, product, version, package, NOT_APPLICABLE_CLIENT_SIDE)
        continue
      status = backport_status(product, match.cve_id, package)
      if status == BACKPORT_FIXED:
        _record_not_applicable(match, product, version, package, NOT_APPLICABLE_BACKPORT_FIXED)
        continue
      findings.append(_build_finding(match, product, version, dynamic_cache, backport_status=status, reader=reader))
    oldest = reader.unsupported(product, version) if applicability in ("", SERVER_APPLICABILITY) else None
    if oldest:
      findings.append(_unsupported_finding(product, version, oldest, reader))
    return findings
  for entry in CVE_DATABASE:
    if entry.product != product:
      continue
    # Range first, so an entry skipped below is one the version did match and
    # the skip can be recorded as a judgement rather than a non-match.
    if not _matches_constraint(version, entry.constraint, product):
      continue
    if applicability and entry_applicability(entry) != applicability:
      if entry_applicability(entry) == CLIENT_APPLICABILITY:
        _record_not_applicable(entry, product, version, package, NOT_APPLICABLE_CLIENT_SIDE)
      continue
    # A CVE whose published scope is a disjunction is carried as one row per
    # range, so it must still be reported once.
    if entry.cve_id in seen_cves:
      continue
    seen_cves.add(entry.cve_id)
    status = backport_status(product, entry.cve_id, package)
    if status == BACKPORT_FIXED:
      _record_not_applicable(entry, product, version, package, NOT_APPLICABLE_BACKPORT_FIXED)
      continue
    findings.append(_build_finding(entry, product, version, dynamic_cache, backport_status=status))
  return findings


def set_vulndb_reader(reader) -> None:
  """Select the source for `check_cves`: a `VulndbReader` (`generated`) or None (`static`).

  Deployment-wide, set once at plugin init: probes run on worker threads, so a ContextVar would not reach them.
  """
  global _VULNDB_READER
  _VULNDB_READER = reader


def set_dynamic_reference_cache(dynamic_cache):
  """Set the scan-local dynamic reference cache for check_cves callers."""
  return _CURRENT_DYNAMIC_CACHE.set(dynamic_cache)


def reset_dynamic_reference_cache(token) -> None:
  """Reset the scan-local dynamic reference cache token."""
  _CURRENT_DYNAMIC_CACHE.reset(token)


def get_dynamic_reference_cache():
  """Return the scan-local dynamic reference cache, if one is active."""
  return _CURRENT_DYNAMIC_CACHE.get()


def set_not_applicable_collector(collector: dict):
  """Set the scan-local not-applicable CVE collector; returns the reset token."""
  return _CURRENT_NOT_APPLICABLE.set(collector)


def reset_not_applicable_collector(token) -> None:
  """Reset the scan-local not-applicable CVE collector token."""
  _CURRENT_NOT_APPLICABLE.reset(token)


# Products distributions package and backport fixes for, so a plain banner cannot settle `generated` rows (RM-169).
_BACKPORTED_PRODUCTS = frozenset({
  "openssh", "openssl", "apache", "nginx", "mysql", "mariadb", "postgresql", "php", "bind", "samba", "exim",
  "proftpd", "redis", "memcached", "mongodb", "couchdb", "tomcat", "vsftpd", "dovecot", "postfix",
})
# Order in which one reason wins when several apply (report-findings.md, Per-finding fields).
_TENTATIVE_REASON_ORDER = ("eol_unassessed", "inferred_version", "platform_dependent", "local_vector", "backport_unknown", "banner_only", "nvd_exact", "cna_range")


def _static_cwe_id(cve_id: str) -> str:
  """The static catalog classification of a CVE: frozen into finding identity whichever source made the finding."""
  global _STATIC_CWE
  if _STATIC_CWE is None:
    _STATIC_CWE = {}
    for e in CVE_DATABASE:
      if e.cwe_id and e.cve_id not in _STATIC_CWE:
        _STATIC_CWE[e.cve_id] = e.cwe_id
  return _STATIC_CWE.get(cve_id, "")


_STATIC_CWE = None


def _local_vector_only(match) -> bool:
  """True when the CVE has v3 vectors and every one is AV:L or AV:P: a network banner cannot show it applies."""
  vectors = [str(c.get("vector", "")) for c in (getattr(match, "cvss", None) or ()) if str(c.get("version", "")).startswith("3.")]
  return bool(vectors) and all(re.search(r"/AV:[LP](/|$)", v) for v in vectors)


def _confidence_reason(backport_status: str, match, product: str) -> tuple:
  """`(confidence, reason)` of a CVE finding. `match` is a reader `Match`, or None under `static`."""
  if backport_status == BACKPORT_NOT_FIXED and not (match and match.platform_dependent):
    return "firm", "distro_package"
  if match is None:
    return "tentative", "backport_unknown" if backport_status == BACKPORT_UNKNOWN else "banner_only"
  reasons = set()
  if match.platform_dependent:
    reasons.add("platform_dependent")
  if _local_vector_only(match):
    reasons.add("local_vector")
  if product in _BACKPORTED_PRODUCTS and backport_status != BACKPORT_NOT_FIXED:
    reasons.add("backport_unknown" if backport_status == BACKPORT_UNKNOWN else "banner_only")
  if match.confidence == "tentative":
    reasons.add(match.reason)  # a reason this node does not know passes through (readers ignore it)
  for reason in _TENTATIVE_REASON_ORDER + tuple(sorted(reasons - set(_TENTATIVE_REASON_ORDER))):
    if reason in reasons:
      return "tentative", reason
  return match.confidence, match.reason


def _build_finding(entry, product: str, version: str, dynamic_cache, backport_status: str = "", reader=None):
  """Construct a Finding for a matched CveEntry, optionally enriched
  via the dynamic reference cache. With a `reader`, `entry` is a reader `Match` (`generated`)."""
  generated = reader is not None
  # Parse the legacy "CWE-22" format into an int CWE id for the
  # list-form `cwe` field on Finding.
  cwe_int = _parse_cwe_int(entry.cwe if generated else entry.cwe_id)
  cwe_list = (cwe_int,) if cwe_int else ()

  # Static OWASP mapping from the cwe_to_owasp reference table.
  owasp_top10 = cwe_to_owasp(cwe_int) if cwe_int else ()

  # Defaults (no dynamic cache or upstream miss).
  cvss_score = None
  cvss_vector = ""
  cvss_score_env = None
  cvss_vector_env = ""
  cvss_version = "3.1"
  cvss_source = ""
  cvss_freshness = ""
  # `None` is "not evaluated": nothing consulted a database or a live cache (report-findings.md, KEV).
  kev = None
  epss_score = None
  references_list: list[str] = [f"https://nvd.nist.gov/vuln/detail/{entry.cve_id}"]
  severity = entry.severity
  cvss_list = ()
  if generated:
    # The database is the only source: the dynamic cache is not consulted. UNKNOWN (no score, no overlay
    # severity) lists as MEDIUM so an unscored CVE is not hidden.
    dynamic_cache = None
    severity = Severity(entry.severity) if entry.severity in Severity.__members__ else Severity.MEDIUM
    kev = bool(entry.kev)
    epss_score = entry.epss
    cvss_list = tuple(dict(c) for c in entry.cvss)
    cvss_freshness = reader.built_at or ""
    # The label is v3.x only; a 4.0 or 2.0 display CVSS stays in `cvss[]` (report-findings.md).
    if str(entry.cvss_version or "").startswith("3."):
      cvss_score, cvss_version, cvss_source = entry.cvss_score, entry.cvss_version, entry.cvss_source or ""
      cvss_vector = next((c["vector"] for c in cvss_list
                          if c["version"] == cvss_version and c["source"] == cvss_source and c["score"] == cvss_score), "")

  if dynamic_cache is not None:
    try:
      cvss_rec = dynamic_cache.get_cvss(entry.cve_id)
      kev_rec = dynamic_cache.get_kev(entry.cve_id)
      epss_rec = dynamic_cache.get_epss(entry.cve_id)
    except Exception:
      cvss_rec = kev_rec = epss_rec = None
    if cvss_rec and cvss_rec.cve_id:
      cvss_score = cvss_rec.score
      cvss_vector = cvss_rec.vector
      cvss_version = cvss_rec.version or cvss_version
      cvss_source = "nvd" if cvss_rec.vector else ""
      cvss_freshness = cvss_rec.fetched_at
      if cvss_rec.source_url:
        references_list.append(cvss_rec.source_url)
      # Trust NVD's qualitative severity over our static one when
      # available, since NVD adjusts post-publication.
      if cvss_rec.severity:
        try:
          severity = Severity(cvss_rec.severity.upper())
        except ValueError:
          pass
    if kev_rec and kev_rec.cve_id:
      kev = bool(kev_rec.in_kev)
    if epss_rec and epss_rec.cve_id and epss_rec.score is not None:
      epss_score = float(epss_rec.score)

  # No live NVD record (production runs without the dynamic cache): the NVD
  # vector fetched into the static table, so the label is CVSS-backed (RM-087).
  # Catalog labels are NVD's band (`test_cve_cvss_vectors.py`); the band check
  # still guards a refetched table that moved ahead of the catalog, withholding
  # the vector as a disagreeing probe template is (RM-064).
  if not generated and not cvss_vector and cvss_score is None:
    static_vector = CVE_CVSS_VECTORS.get(entry.cve_id, "")
    if static_vector and _template_band_agrees(static_vector, severity):
      cvss_vector = static_vector
      cvss_score = cvss31_base_score(static_vector)
      cvss_version = static_vector.split("/", 1)[0].removeprefix("CVSS:")
      cvss_source = "nvd"
      cvss_freshness = ""  # static, not fetched at scan time

  # What the distribution package says about this match, stated rather than
  # left to the reader (RM-070). `not_fixed` is the one case the evidence
  # supports beyond the upstream version, so it is the one case that is not
  # `tentative`.
  confidence, confidence_reason = _confidence_reason(backport_status, entry if generated else None, product)
  if backport_status == BACKPORT_NOT_FIXED:
    backport_note = (
      " The distribution package is below the revision that carries the fix, "
      "so the backport does not apply."
    )
  elif backport_status == BACKPORT_UNKNOWN:
    backport_note = (
      " Backport status unknown: a distribution package was detected but no "
      "advisory data covers this CVE for it, so the fix may already be applied."
    )
  else:
    # BACKPORT_UNKNOWN_NO_PACKAGE, or "" from a caller that passed no status.
    backport_note = (
      " No distribution package was announced in the banner, so backport "
      "status could not be assessed. NOTE: Linux distributions backport "
      "security fixes without changing the upstream version number — this "
      "may be a false positive."
    )
    backport_status = backport_status or BACKPORT_UNKNOWN_NO_PACKAGE

  finding = Finding(
    severity=severity,
    title=f"{entry.cve_id}: {entry.title} ({product} {version})",
    description=f"{product} {version} is vulnerable to {entry.cve_id}.{backport_note}",
    evidence=f"Detected version: {version}, affected: {entry.constraint}",
    remediation=f"Upgrade {product} to a patched version, or verify backport status with the OS vendor.",
    cwe_id=_static_cwe_id(entry.cve_id) if generated else entry.cwe_id,
    confidence=confidence,
    confidence_reason=confidence_reason,
    vulndb_build_id=reader.build_id if generated else None,
    cvss=cvss_list,
    backport_status=backport_status,
    # Phase 1 / Phase 2 enriched fields
    cvss_score=cvss_score,
    cvss_vector=cvss_vector,
    cvss_version=cvss_version,
    cvss_source=cvss_source,
    cvss_score_env=cvss_score_env,
    cvss_vector_env=cvss_vector_env,
    cvss_data_freshness=cvss_freshness,
    kev=kev,
    epss_score=epss_score,
    cwe=cwe_list,
    cve=(entry.cve_id,),
    owasp_top10=tuple(owasp_top10),
    references=tuple(references_list),
    remediation_structured=Remediation(
      primary=f"Upgrade {product} to a patched version, or verify backport status with the OS vendor.",
      mitigation="Restrict exposure to trusted networks until patch status is confirmed.",
      compensating="Use host or network controls to reduce exploitability for the affected service.",
    ),
  )
  # Both keys, over the same basis. A CVE finding is identified by
  # `product:version:cve_id` rather than by an `AffectedAsset` — that is the
  # whole reason `asset_canonical` exists. Stamping only the signature left the
  # dedup key to be recomputed downstream by `enrich_finding_for_probe` from the
  # *probe* name with no override, so the finding travelled with a signature
  # built over one identity basis and a dedup key built over another.
  identity = {
    "probe_id": f"cve:{product}",
    "asset_canonical": f"{product}:{version}:{entry.cve_id}",
  }
  return finding.with_identity(
    finding_signature=finding.compute_signature(**identity),
    finding_id=finding.compute_dedup_key(**identity),
  )


def _unsupported_finding(product: str, version: str, oldest: str, reader):
  """HIGH finding: `version` is older than the oldest branch the vendor supports (`eol` table).

  Not a CVE finding: no `cve`, so it is outside the CVE view's `raw`; the `vulndb_eol` tag lets the view name it.
  """
  finding = Finding(
    severity=Severity.HIGH,
    title=f"Unsupported version: {product} {version} (oldest supported {oldest})",
    description=f"{product} {version} is older than the oldest supported branch ({oldest}); it no longer receives security fixes.",
    evidence=f"Detected version: {version}, oldest supported: {oldest}",
    remediation=f"Upgrade {product} to a supported release (>= {oldest}).",
    confidence="firm",
    confidence_reason="eol",
    vulndb_build_id=reader.build_id,
    tags=("vulndb_eol", product),
    kev=False,
  )
  identity = {"probe_id": f"cve:{product}", "asset_canonical": f"{product}:{version}:eol"}
  return finding.with_identity(
    finding_signature=finding.compute_signature(**identity),
    finding_id=finding.compute_dedup_key(**identity),
  )


def _parse_cwe_int(cwe_str: str) -> int:
  """Extract the integer CWE id from a string like 'CWE-22' or 'CWE-639'.

  Returns 0 when the string is empty or not in the expected form.
  """
  if not isinstance(cwe_str, str) or not cwe_str:
    return 0
  m = re.match(r"^CWE-(\d+)$", cwe_str.strip())
  if not m:
    return 0
  try:
    return int(m.group(1))
  except (TypeError, ValueError):
    return 0


def _matches_constraint(version: str, constraint: str, product: str = "") -> bool:
  """Parse version constraint string and compare.

  Supports: ``<1.4.3``, ``>=2.4.49,<2.4.51``, ``<7.0``.
  Comma-separated constraints are ANDed. ``product`` selects the product-specific
  reading of single-letter release tags (see ``_parse_version``).
  """
  parts = [c.strip() for c in constraint.split(",")]
  parsed = _parse_version(version, product)
  if parsed is None:
    return False
  for part in parts:
    if not _check_single(parsed, part, product):
      return False
  return True


# Pre-release tags sort BEFORE the release they precede. Ascending rank:
# dev < alpha < beta < milestone < rc/pre/preview/prerelease; `a`/`b` are alpha/beta.
_PRE_RANK = {
  "dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2,
  "milestone": 3, "m": 3, "rc": 4, "pre": 4, "preview": 4, "prerelease": 4,
}
# Products whose single-letter suffix is a release (openssl 1.0.1f, proftpd
# 1.3.5b), not a pre-release.
_LETTER_RELEASE_PRODUCTS = ("openssl", "proftpd", "samba")


def _parse_version(version: str, product: str = ""):
  """Reduce a banner or constraint version to a comparable key ``(numbers, tail)``.

  Handles values like ``Apache/2.4.57 (Ubuntu)``, ``OpenSSH_8.9p1``,
  ``nginx/1.22.1``, ``1:8.9p1-3ubuntu0.10`` and pre-releases such as
  ``3.0.0rc1``, ``1.4.3-beta``, ``9.0.0.M1``, ``8.1.0-dev``.

  ``tail`` orders what follows the numbers: a pre-release ``(-1, tag, n)`` sorts
  before the release ``(0, 0, 0)``; a letter suffix ``9.8p1`` / ``1.0.1f`` or a
  BIND edition or patch level (``-S1``, ``-P4``) sorts after it. Compare keys with ``_compare_versions``.
  """
  if not isinstance(version, str):
    return None
  # Banners are untrusted: bound the work and the digit runs `int()` must parse.
  version = version[:128].strip()
  # Strip a Debian/RPM epoch before searching. `1:8.9p1-3ubuntu0.10` otherwise
  # matches on the leading `1` and returns (1,), reading the epoch as the
  # upstream version — which makes an OpenSSH 8.9 host match every CVE for 1.x.
  version = re.sub(r"^\s*\d+:", "", version)
  m = re.search(r"(\d+(?:\.\d+)*)(.*)$", version, re.DOTALL)
  if not m:
    return None
  numbers = [int(x) for x in m.group(1).split(".")]
  rest = m.group(2).lower()
  tail = (0, 0, 0)
  # `(?![a-z])`: the tag ends there, so `-precise` and `-devel` are not `pre` and `dev`.
  pre = re.match(r"^[-_.~]?(alpha|beta|rc|prerelease|preview|pre|dev|milestone|m|a|b)(\d*)(?![a-z])", rest)
  if pre:
    tag, num = pre.group(1), pre.group(2)
    # A bare single letter is a release letter, not a pre-release, unless a
    # number follows (`1.0a1`, `9.0.0.M1`) and the product does not use letter
    # releases.
    single = len(tag) == 1
    if (not single or num) and not (single and product in _LETTER_RELEASE_PRODUCTS):
      tail = (-1, _PRE_RANK[tag], int(num or 0))
  if tail == (0, 0, 0):
    edition = re.match(r"^-([sp])(\d+)(?![a-z0-9])", rest)  # BIND `-S1` edition, `-P4` patch level
    letter = re.match(r"^([a-z]{1,2})(\d*)(?=$|[-_.~+ ])", rest)  # 1.0.1f, 8.9p1, 1.3.5b
    if edition:
      tail = (1, ord(edition.group(1)) - 96, int(edition.group(2)))
    elif letter:
      value = 0
      for char in letter.group(1):
        value = value * 26 + ord(char) - 96
      tail = (1, value, int(letter.group(2) or 0))
  return numbers, tail


def _compare_versions(a, b) -> int:
  """Three-way compare of two ``_parse_version`` keys."""
  na, ta = a
  nb, tb = b
  size = max(len(na), len(nb))
  na = na + [0] * (size - len(na))
  nb = nb + [0] * (size - len(nb))
  if na != nb:
    return -1 if na < nb else 1
  return (ta > tb) - (ta < tb)


def _check_single(parsed, expr: str, product: str = "") -> bool:
  """Evaluate one comparison like '<1.4.3' or '>=2.4.49'."""
  m = re.match(r"(>=|<=|>|<|==)(.+)", expr.strip())
  if not m:
    return False
  op, ver_str = m.group(1), m.group(2)
  target = _parse_version(ver_str, product)
  if target is None:
    return False
  c = _compare_versions(parsed, target)
  if op == "<":
    return c < 0
  elif op == "<=":
    return c <= 0
  elif op == ">":
    return c > 0
  elif op == ">=":
    return c >= 0
  elif op == "==":
    return c == 0
  return False
