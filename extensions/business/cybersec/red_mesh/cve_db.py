"""
Declarative CVE database for RedMesh version-based vulnerability matching.

Each entry maps a product + version constraint to a known CVE.  The
``check_cves()`` helper returns ``Finding`` instances that feed directly
into ``probe_result()``.
"""

import re
from dataclasses import dataclass
from .findings import Finding, Severity

CVE_DB_LAST_UPDATED = "2026-02-20"


@dataclass(frozen=True)
class CveEntry:
  product: str
  constraint: str      # "<1.4.3", ">=2.4.49,<2.4.51", "<7.0"
  cve_id: str
  severity: Severity
  title: str
  cwe_id: str = ""


CVE_DATABASE: list = [
  # ── Elasticsearch ──────────────────────────────────────────────────
  CveEntry("elasticsearch", "<1.2",   "CVE-2014-3120", Severity.CRITICAL, "MVEL scripting RCE", "CWE-94"),
  CveEntry("elasticsearch", "<1.4.3", "CVE-2015-1427", Severity.CRITICAL, "Groovy sandbox escape RCE", "CWE-94"),
  CveEntry("elasticsearch", "<1.4.5", "CVE-2015-3337", Severity.HIGH, "Directory traversal via site plugin", "CWE-22"),
  CveEntry("elasticsearch", "<5.6.5", "CVE-2017-11480", Severity.MEDIUM, "XSS via URL access control bypass", "CWE-79"),
  CveEntry("elasticsearch", "<6.4.3", "CVE-2018-17244", Severity.MEDIUM, "Security bypass in token generation", "CWE-287"),
  CveEntry("elasticsearch", ">=7.0.0,<7.17.19", "CVE-2024-23450", Severity.HIGH, "Ingest pipeline DoS via deep nesting", "CWE-400"),

  # ── OpenSSH ────────────────────────────────────────────────────────
  CveEntry("openssh", "<9.3",  "CVE-2024-6387", Severity.CRITICAL, "regreSSHion: signal handler race RCE", "CWE-362"),
  CveEntry("openssh", ">=6.8,<9.9.2", "CVE-2025-26465", Severity.HIGH, "MitM via VerifyHostKeyDNS bypass", "CWE-305"),
  CveEntry("openssh", "<8.1",  "CVE-2019-6111", Severity.HIGH, "SCP client-side file overwrite", "CWE-20"),
  CveEntry("openssh", "<7.6",  "CVE-2017-15906", Severity.MEDIUM, "Improper write restriction in readonly mode", "CWE-732"),
  CveEntry("openssh", "<7.0",  "CVE-2016-6210", Severity.MEDIUM, "User enumeration via timing", "CWE-200"),

  # ── Redis ──────────────────────────────────────────────────────────
  CveEntry("redis", "<6.0.8",  "CVE-2021-32761", Severity.HIGH, "Integer overflow in BITFIELD", "CWE-190"),
  CveEntry("redis", "<6.2.7",  "CVE-2022-24735", Severity.HIGH, "Lua sandbox escape via EVAL", "CWE-94"),
  CveEntry("redis", "<7.0.5",  "CVE-2022-35951", Severity.HIGH, "Integer overflow in XAUTOCLAIM", "CWE-190"),
  CveEntry("redis", "<6.2.16", "CVE-2024-31449", Severity.HIGH, "Lua bit library stack buffer overflow RCE", "CWE-121"),
  CveEntry("redis", "<7.2.7",  "CVE-2024-46981", Severity.HIGH, "Lua GC use-after-free RCE", "CWE-416"),

  # ── MySQL ──────────────────────────────────────────────────────────
  CveEntry("mysql", ">=5.7,<5.7.20",  "CVE-2016-6662", Severity.CRITICAL, "Config file injection RCE", "CWE-94"),
  CveEntry("mysql", ">=5.5,<5.5.52",  "CVE-2016-6664", Severity.HIGH, "Privilege escalation via mysqld_safe", "CWE-269"),
  CveEntry("mysql", ">=8.0,<8.0.23",  "CVE-2021-2022", Severity.MEDIUM, "InnoDB buffer pool corruption", "CWE-787"),
  CveEntry("mysql", ">=5.7,<5.7.44",  "CVE-2024-20973", Severity.HIGH, "Optimizer DoS via low-privilege network attack", "CWE-404"),

  # ── PostgreSQL (new) ───────────────────────────────────────────────
  CveEntry("postgresql", "<17.3",  "CVE-2025-1094", Severity.HIGH, "libpq quoting SQL injection leading to RCE", "CWE-89"),
  CveEntry("postgresql", "<17.1",  "CVE-2024-10979", Severity.HIGH, "PL/Perl env variable manipulation to RCE", "CWE-94"),
  CveEntry("postgresql", "<17.1",  "CVE-2024-10976", Severity.HIGH, "Row security policy bypass via role confusion", "CWE-862"),

  # ── MongoDB (new) ──────────────────────────────────────────────────
  CveEntry("mongodb", "<4.4.30", "CVE-2024-8207", Severity.HIGH, "Privilege escalation via untrusted library load", "CWE-284"),

  # ── Exim ───────────────────────────────────────────────────────────
  CveEntry("exim", "<4.98",   "CVE-2024-39929", Severity.CRITICAL, "RFC 2231 header parsing bypass — malware delivery", "CWE-20"),
  CveEntry("exim", "<4.97.1", "CVE-2023-42115", Severity.CRITICAL, "AUTH out-of-bounds write", "CWE-787"),
  CveEntry("exim", "<4.96.1", "CVE-2023-42116", Severity.HIGH, "NTLM challenge stack buffer overflow", "CWE-121"),
  CveEntry("exim", "<4.96.1", "CVE-2023-42114", Severity.HIGH, "NTLM challenge out-of-bounds read", "CWE-125"),
  CveEntry("exim", "<4.94.2", "CVE-2021-27216", Severity.HIGH, "Privilege escalation via symlink attack", "CWE-59"),

  # ── Apache httpd ───────────────────────────────────────────────────
  CveEntry("apache", ">=2.4.0,<2.4.60",  "CVE-2024-38475", Severity.CRITICAL, "mod_rewrite escaping flaw — SSRF / RCE", "CWE-116"),
  CveEntry("apache", ">=2.4.0,<2.4.60",  "CVE-2024-38476", Severity.CRITICAL, "Backend header exploit — SSRF / local script exec", "CWE-829"),
  CveEntry("apache", ">=2.4.49,<2.4.51", "CVE-2021-41773", Severity.CRITICAL, "Path traversal + RCE", "CWE-22"),
  CveEntry("apache", ">=2.4.0,<2.4.52",  "CVE-2021-44790", Severity.CRITICAL, "mod_lua buffer overflow", "CWE-787"),
  CveEntry("apache", ">=2.4.0,<2.4.62",  "CVE-2024-40725", Severity.HIGH, "HTTP request smuggling via mod_proxy", "CWE-444"),
  CveEntry("apache", "<2.4.49",           "CVE-2021-40438", Severity.HIGH, "mod_proxy SSRF", "CWE-918"),
  CveEntry("apache", "<2.2.34",           "CVE-2017-7679", Severity.HIGH, "mod_mime buffer overread", "CWE-126"),

  # ── nginx ──────────────────────────────────────────────────────────
  CveEntry("nginx", "<1.17.7", "CVE-2019-20372", Severity.MEDIUM, "HTTP request smuggling", "CWE-444"),
  CveEntry("nginx", "<1.5.7",  "CVE-2013-4547", Severity.HIGH, "URI processing security bypass", "CWE-20"),
  CveEntry("nginx", ">=1.25.0,<1.25.4", "CVE-2024-24989", Severity.HIGH, "HTTP/3 QUIC null pointer crash", "CWE-476"),
  CveEntry("nginx", ">=1.25.0,<1.25.4", "CVE-2024-24990", Severity.HIGH, "HTTP/3 use-after-free crash", "CWE-416"),

  # ── Postfix ────────────────────────────────────────────────────────
  CveEntry("postfix", "<3.5.23", "CVE-2023-51764", Severity.MEDIUM, "SMTP smuggling via pipelining", "CWE-345"),

  # ── OpenSSL ────────────────────────────────────────────────────────
  CveEntry("openssl", "<1.1.1",  "CVE-2020-1971", Severity.HIGH, "NULL dereference in GENERAL_NAME_cmp", "CWE-476"),
  CveEntry("openssl", "<3.0.7",  "CVE-2022-3602", Severity.HIGH, "X.509 email address buffer overflow", "CWE-120"),
  CveEntry("openssl", ">=3.2.0,<3.2.4",  "CVE-2024-12797", Severity.HIGH, "RPK verification bypass enabling MitM", "CWE-392"),
  CveEntry("openssl", "<3.0.14", "CVE-2024-4741", Severity.HIGH, "SSL_free_buffers use-after-free", "CWE-416"),

  # ── ProFTPD ────────────────────────────────────────────────────────
  CveEntry("proftpd", "<1.3.6",  "CVE-2019-12815", Severity.CRITICAL, "Arbitrary file copy via mod_copy", "CWE-284"),
  CveEntry("proftpd", "<1.3.8",  "CVE-2024-48651", Severity.HIGH, "Supplemental group inherits GID 0 (root group)", "CWE-269"),

  # ── vsftpd ─────────────────────────────────────────────────────────
  CveEntry("vsftpd", ">=2.3.4,<2.3.5", "CVE-2011-2523", Severity.CRITICAL, "Backdoor command execution", "CWE-506"),

  # ── Memcached (new) ────────────────────────────────────────────────
  CveEntry("memcached", "<1.4.33", "CVE-2016-8704", Severity.CRITICAL, "process_bin_append integer overflow RCE", "CWE-190"),
  CveEntry("memcached", "<1.4.33", "CVE-2016-8705", Severity.HIGH, "process_bin_update integer overflow RCE", "CWE-190"),
  CveEntry("memcached", "<1.4.33", "CVE-2016-8706", Severity.CRITICAL, "SASL auth integer overflow RCE", "CWE-190"),

  # ── VNC (new) ──────────────────────────────────────────────────────
  CveEntry("tightvnc", "<=1.3.10", "CVE-2019-15678", Severity.CRITICAL, "rfbServerCutText heap buffer overflow RCE", "CWE-122"),
  CveEntry("tightvnc", "<=1.3.10", "CVE-2019-15679", Severity.CRITICAL, "InitialiseRFBConnection heap overflow RCE", "CWE-122"),
  CveEntry("libvncserver", "<0.9.13", "CVE-2019-20788", Severity.CRITICAL, "HandleCursorShape integer overflow RCE", "CWE-190"),

  # ── Samba (new — for SMB deep enumeration) ─────────────────────────
  CveEntry("samba", ">=4.16.0,<4.17.12", "CVE-2023-3961", Severity.CRITICAL, "Pipe name validation bypass — root socket access", "CWE-22"),
  CveEntry("samba", "<4.13.17", "CVE-2021-44142", Severity.CRITICAL, "vfs_fruit heap overflow RCE", "CWE-787"),
  CveEntry("samba", "<4.6.1",   "CVE-2017-7494", Severity.CRITICAL, "SambaCry — writable share RCE via shared library upload", "CWE-94"),

  # ── Asterisk / FreePBX (new — for SIP probe) ──────────────────────
  CveEntry("asterisk", "<20.11.0", "CVE-2024-42365", Severity.HIGH, "AMI manager injection via caller ID", "CWE-94"),
  CveEntry("asterisk", "<18.24.0", "CVE-2023-49786", Severity.HIGH, "PJSIP request smuggling via multipart parser", "CWE-444"),
]


def check_cves(product: str, version: str) -> list:
  """Match version against CVE database. Returns list of Findings."""
  findings = []
  for entry in CVE_DATABASE:
    if entry.product != product:
      continue
    if _matches_constraint(version, entry.constraint):
      findings.append(Finding(
        severity=entry.severity,
        title=f"{entry.cve_id}: {entry.title} ({product} {version})",
        description=f"{product} {version} is vulnerable to {entry.cve_id}. "
                    "NOTE: Linux distributions backport security fixes without changing "
                    "the upstream version number — this may be a false positive.",
        evidence=f"Detected version: {version}, affected: {entry.constraint}",
        remediation=f"Upgrade {product} to a patched version, or verify backport status with the OS vendor.",
        cwe_id=entry.cwe_id,
        confidence="tentative",
      ))
  return findings


def _matches_constraint(version: str, constraint: str) -> bool:
  """Parse version constraint string and compare.

  Supports: ``<1.4.3``, ``>=2.4.49,<2.4.51``, ``<7.0``.
  Comma-separated constraints are ANDed.
  """
  parts = [c.strip() for c in constraint.split(",")]
  parsed = _parse_version(version)
  if parsed is None:
    return False
  for part in parts:
    if not _check_single(parsed, part):
      return False
  return True


def _parse_version(version: str):
  """Extract leading numeric version tuple from a string like '1.4.3-beta'."""
  m = re.match(r"(\d+(?:\.\d+)*)", version.strip())
  if not m:
    return None
  return tuple(int(x) for x in m.group(1).split("."))


def _check_single(parsed: tuple, expr: str) -> bool:
  """Evaluate one comparison like '<1.4.3' or '>=2.4.49'."""
  m = re.match(r"(>=|<=|>|<|==)(.+)", expr.strip())
  if not m:
    return False
  op, ver_str = m.group(1), m.group(2)
  target = _parse_version(ver_str)
  if target is None:
    return False
  # Normalize lengths for comparison
  max_len = max(len(parsed), len(target))
  a = parsed + (0,) * (max_len - len(parsed))
  b = target + (0,) * (max_len - len(target))
  if op == "<":
    return a < b
  elif op == "<=":
    return a <= b
  elif op == ">":
    return a > b
  elif op == ">=":
    return a >= b
  elif op == "==":
    return a == b
  return False
