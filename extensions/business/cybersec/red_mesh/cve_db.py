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
from .findings import Finding, Remediation, Severity
from .references import cwe_to_owasp

CVE_DB_LAST_UPDATED = "2026-03-08"
_CURRENT_DYNAMIC_CACHE: ContextVar = ContextVar("redmesh_dynamic_reference_cache", default=None)


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
  CveEntry("mysql", ">=5.5,<5.5.52",  "CVE-2016-6662", Severity.CRITICAL, "Config file injection RCE", "CWE-94"),
  CveEntry("mysql", ">=5.6,<5.6.33",  "CVE-2016-6662", Severity.CRITICAL, "Config file injection RCE", "CWE-94"),
  CveEntry("mysql", ">=5.7,<5.7.15",  "CVE-2016-6662", Severity.CRITICAL, "Config file injection RCE", "CWE-94"),
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
  CveEntry("samba", ">=3.5.0,<4.6.4", "CVE-2017-7494", Severity.CRITICAL, "SambaCry — writable share RCE via shared library upload", "CWE-94"),

  # ── Asterisk / FreePBX (new — for SIP probe) ──────────────────────
  CveEntry("asterisk", "<20.11.0", "CVE-2024-42365", Severity.HIGH, "AMI manager injection via caller ID", "CWE-94"),
  CveEntry("asterisk", "<18.24.0", "CVE-2023-49786", Severity.HIGH, "PJSIP request smuggling via multipart parser", "CWE-444"),

  # ── OpenSMTPD ────────────────────────────────────────────────────
  CveEntry("opensmtpd", "<6.6.2",  "CVE-2020-7247", Severity.CRITICAL, "RCE via crafted MAIL FROM command", "CWE-78"),
  CveEntry("opensmtpd", "<6.6.4",  "CVE-2020-8794", Severity.HIGH, "Out-of-bounds read in MTA bounce handling", "CWE-125"),

  # ── libssh ───────────────────────────────────────────────────────
  CveEntry("libssh", "<0.7.6",  "CVE-2018-10933", Severity.CRITICAL, "Authentication bypass via MSG_USERAUTH_SUCCESS", "CWE-287"),
  CveEntry("libssh", ">=0.8.0,<0.8.4", "CVE-2018-10933", Severity.CRITICAL, "Authentication bypass via MSG_USERAUTH_SUCCESS", "CWE-287"),

  # ── Dropbear ─────────────────────────────────────────────────────
  CveEntry("dropbear", "<2018.76", "CVE-2018-15599", Severity.MEDIUM, "Username enumeration via response size", "CWE-203"),
  CveEntry("dropbear", "<2016.74", "CVE-2016-7406", Severity.HIGH, "Format string vulnerability in dbclient", "CWE-134"),

  # ── Erlang OTP SSH ──────────────────────────────────────────────
  CveEntry("erlang_ssh", "<5.2.2", "CVE-2025-32433", Severity.CRITICAL, "Pre-auth RCE via SSH protocol message sequence", "CWE-306"),

  # ── CouchDB ──────────────────────────────────────────────────────
  CveEntry("couchdb", "<3.2.2",           "CVE-2022-24706", Severity.CRITICAL, "Default Erlang cookie RCE via cluster protocol", "CWE-1188"),
  CveEntry("couchdb", ">=3.0.0,<3.1.2",   "CVE-2021-38295", Severity.HIGH, "Privilege escalation via cluster API", "CWE-269"),
  CveEntry("couchdb", "<2.1.1",           "CVE-2017-12635", Severity.CRITICAL, "Admin creation race condition bypass", "CWE-269"),
  CveEntry("couchdb", "<2.1.1",           "CVE-2017-12636", Severity.CRITICAL, "OS command injection via query server config", "CWE-78"),

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
  CveEntry("wordpress", "<4.7.4",         "CVE-2017-8295", Severity.HIGH, "Host header password reset hijack", "CWE-640"),
  CveEntry("wordpress", ">=4.7.0,<4.7.2", "CVE-2017-1001000", Severity.HIGH, "REST API content injection", "CWE-284"),

  # ── Joomla ─────────────────────────────────────────────────────
  CveEntry("joomla", ">=4.0.0,<4.2.8",   "CVE-2023-23752", Severity.HIGH, "Unauthenticated information disclosure via REST API", "CWE-284"),

  # ── Django ─────────────────────────────────────────────────────
  CveEntry("django", "<1.11.5",          "CVE-2017-12794", Severity.MEDIUM, "Debug page XSS via invalid URL parameter", "CWE-79"),

  # ── Laravel / Ignition ─────────────────────────────────────────
  CveEntry("laravel_ignition", "<2.5.2",  "CVE-2021-3129", Severity.CRITICAL, "Ignition debug mode RCE via file_put_contents", "CWE-94"),

  # ── Apache Struts2 ─────────────────────────────────────────────
  CveEntry("struts2", ">=2.3.5,<2.3.32",   "CVE-2017-5638", Severity.CRITICAL, "S2-045: OGNL injection via Content-Type header RCE", "CWE-94"),
  CveEntry("struts2", ">=2.5.0,<2.5.10.1", "CVE-2017-5638", Severity.CRITICAL, "S2-045: OGNL injection via Content-Type header RCE", "CWE-94"),
  CveEntry("struts2", ">=2.3.5,<2.3.33",   "CVE-2017-9805", Severity.CRITICAL, "S2-052: XML deserialization RCE via REST plugin", "CWE-502"),
  CveEntry("struts2", ">=2.5.0,<2.5.13",   "CVE-2017-9805", Severity.CRITICAL, "S2-052: XML deserialization RCE via REST plugin", "CWE-502"),
  CveEntry("struts2", ">=2.0.0,<2.5.26",   "CVE-2020-17530", Severity.CRITICAL, "S2-061: Forced OGNL evaluation via tag attributes", "CWE-94"),

  # ── Oracle WebLogic ──────────────────────────────────────────
  CveEntry("weblogic", ">=10.3.6.0,<10.3.6.1", "CVE-2017-10271", Severity.CRITICAL, "XMLDecoder deserialization RCE via wls-wsat", "CWE-502"),
  CveEntry("weblogic", ">=12.1.3.0,<12.1.3.1", "CVE-2017-10271", Severity.CRITICAL, "XMLDecoder deserialization RCE via wls-wsat", "CWE-502"),
  CveEntry("weblogic", ">=10.3.6.0,<10.3.6.1", "CVE-2020-14882", Severity.CRITICAL, "Console unauthenticated takeover RCE", "CWE-306"),
  CveEntry("weblogic", ">=12.1.3.0,<12.2.1.5", "CVE-2020-14882", Severity.CRITICAL, "Console unauthenticated takeover RCE", "CWE-306"),
  CveEntry("weblogic", ">=12.2.1.3,<12.2.1.4", "CVE-2023-21839", Severity.HIGH, "IIOP/T3 protocol deserialization RCE", "CWE-502"),

  # ── Apache Tomcat ────────────────────────────────────────────
  CveEntry("tomcat", ">=9.0.0,<9.0.31",   "CVE-2020-1938", Severity.CRITICAL, "Ghostcat: AJP connector file read/inclusion RCE", "CWE-20"),
  CveEntry("tomcat", ">=8.5.0,<8.5.51",   "CVE-2020-1938", Severity.CRITICAL, "Ghostcat: AJP connector file read/inclusion RCE", "CWE-20"),
  CveEntry("tomcat", ">=7.0.0,<7.0.100",  "CVE-2020-1938", Severity.CRITICAL, "Ghostcat: AJP connector file read/inclusion RCE", "CWE-20"),
  CveEntry("tomcat", ">=7.0.0,<7.0.81",   "CVE-2017-12615", Severity.HIGH, "PUT method JSP file upload RCE", "CWE-434"),
  CveEntry("tomcat", ">=9.0.0,<9.0.99",   "CVE-2025-24813", Severity.CRITICAL, "Partial PUT deserialization RCE", "CWE-502"),
  CveEntry("tomcat", ">=10.1.0,<10.1.35", "CVE-2025-24813", Severity.CRITICAL, "Partial PUT deserialization RCE", "CWE-502"),

  # ── JBoss Application Server ─────────────────────────────────
  CveEntry("jboss", ">=4.0,<7.0",   "CVE-2017-12149", Severity.CRITICAL, "Java deserialization RCE via /invoker/readonly", "CWE-502"),

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
  CveEntry("bind", "<9.11.37",  "CVE-2022-2795", Severity.MEDIUM, "Flooding targeted resolver with queries DoS", "CWE-400"),
  CveEntry("bind", "<9.16.33",  "CVE-2022-3080", Severity.HIGH, "TKEY assertion failure DoS on DNAME resolution", "CWE-617"),
  CveEntry("bind", "<9.16.42",  "CVE-2023-2828", Severity.HIGH, "Cache exhaustion DoS via crafted queries", "CWE-770"),
  CveEntry("bind", "<9.18.24",  "CVE-2023-4408", Severity.HIGH, "DNS message parsing CPU exhaustion DoS", "CWE-400"),
  CveEntry("bind", "<9.11.31",  "CVE-2021-25216", Severity.CRITICAL, "GSSAPI SPNEGO buffer overflow RCE", "CWE-120"),
  CveEntry("bind", "<9.11.19",  "CVE-2020-8617", Severity.HIGH, "TSIG validity check assertion failure DoS", "CWE-617"),
  CveEntry("bind", "<9.10.4",   "CVE-2016-2776", Severity.HIGH, "Crafted query buffer.c assertion failure DoS", "CWE-617"),
]


def check_cves(product: str, version: str, *, dynamic_cache=None) -> list:
  """Match version against CVE database. Returns list of Findings.

  When ``dynamic_cache`` is a ``DynamicReferenceCache`` instance,
  every emitted Finding is enriched with live NVD CVSS, CISA KEV
  status, FIRST EPSS score, and OWASP Top 10 mapping (looked up via
  the static cwe_to_owasp table). When no cache is provided, the
  legacy behavior is preserved (static severity only).
  """
  if dynamic_cache is None:
    dynamic_cache = get_dynamic_reference_cache()

  findings = []
  for entry in CVE_DATABASE:
    if entry.product != product:
      continue
    if not _matches_constraint(version, entry.constraint):
      continue
    findings.append(_build_finding(entry, product, version, dynamic_cache))
  return findings


def set_dynamic_reference_cache(dynamic_cache):
  """Set the scan-local dynamic reference cache for check_cves callers."""
  return _CURRENT_DYNAMIC_CACHE.set(dynamic_cache)


def reset_dynamic_reference_cache(token) -> None:
  """Reset the scan-local dynamic reference cache token."""
  _CURRENT_DYNAMIC_CACHE.reset(token)


def get_dynamic_reference_cache():
  """Return the scan-local dynamic reference cache, if one is active."""
  return _CURRENT_DYNAMIC_CACHE.get()


def _build_finding(entry, product: str, version: str, dynamic_cache):
  """Construct a Finding for a matched CveEntry, optionally enriched
  via the dynamic reference cache."""
  # Parse the legacy "CWE-22" format into an int CWE id for the
  # list-form `cwe` field on Finding.
  cwe_int = _parse_cwe_int(entry.cwe_id)
  cwe_list = (cwe_int,) if cwe_int else ()

  # Static OWASP mapping from the cwe_to_owasp reference table.
  owasp_top10 = cwe_to_owasp(cwe_int) if cwe_int else ()

  # Defaults (no dynamic cache or upstream miss).
  cvss_score = None
  cvss_vector = ""
  cvss_score_env = None
  cvss_vector_env = ""
  cvss_version = "3.1"
  cvss_freshness = ""
  kev = False
  epss_score = None
  references_list: list[str] = [f"https://nvd.nist.gov/vuln/detail/{entry.cve_id}"]
  severity = entry.severity

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

  finding = Finding(
    severity=severity,
    title=f"{entry.cve_id}: {entry.title} ({product} {version})",
    description=f"{product} {version} is vulnerable to {entry.cve_id}. "
                "NOTE: Linux distributions backport security fixes without changing "
                "the upstream version number — this may be a false positive.",
    evidence=f"Detected version: {version}, affected: {entry.constraint}",
    remediation=f"Upgrade {product} to a patched version, or verify backport status with the OS vendor.",
    cwe_id=entry.cwe_id,
    confidence="tentative",
    # Phase 1 / Phase 2 enriched fields
    cvss_score=cvss_score,
    cvss_vector=cvss_vector,
    cvss_version=cvss_version,
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
  return finding.with_signature(
    finding.compute_signature(
      probe_id=f"cve:{product}",
      asset_canonical=f"{product}:{version}:{entry.cve_id}",
    )
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
