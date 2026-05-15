"""
RedMesh constants and feature catalog definitions.
"""

from enum import Enum


class ScanType(str, Enum):
  """Scan type enum — extensible for future scan types (api, mobile, etc.)."""
  NETWORK = "network"
  WEBAPP = "webapp"


# Graybox probe registry — decouples probe addition from worker code.
# Adding a new probe = new probe file + new registry entry. No worker changes.
# Capabilities (requires_auth, requires_regular_session, is_stateful) live on
# the ProbeBase subclass, not in the registry — single source of truth.
GRAYBOX_PROBE_REGISTRY = [
  {"key": "_graybox_access_control",  "cls": "access_control.AccessControlProbes"},
  {"key": "_graybox_misconfig",       "cls": "misconfig.MisconfigProbes"},
  {"key": "_graybox_injection",       "cls": "injection.InjectionProbes"},
  {"key": "_graybox_business_logic",  "cls": "business_logic.BusinessLogicProbes"},
  # OWASP API Top 10 2023 — five themed families (Subphase 1.3).
  {"key": "_graybox_api_access",      "cls": "api_access.ApiAccessProbes"},
  {"key": "_graybox_api_auth",        "cls": "api_auth.ApiAuthProbes"},
  {"key": "_graybox_api_data",        "cls": "api_data.ApiDataProbes"},
  {"key": "_graybox_api_config",      "cls": "api_config.ApiConfigProbes"},
  {"key": "_graybox_api_abuse",       "cls": "api_abuse.ApiAbuseProbes"},
]

# Graybox timing and limits
GRAYBOX_DEFAULT_DELAY = 0.2
GRAYBOX_WEAK_AUTH_DELAY = 1.0
GRAYBOX_MAX_WEAK_ATTEMPTS = 20
GRAYBOX_SESSION_MAX_AGE = 1800


FEATURE_CATALOG = [
  {
    "id": "service_info_common",
    "label": "Service fingerprinting",
    "description": "Collect banner and version data for common network services.",
    "category": "service",
    "methods": [
      "_service_info_http",
      "_service_info_https",
      "_service_info_http_alt",
      "_service_info_ftp",
      "_service_info_ssh",
      "_service_info_telnet",
      "_service_info_smtp",
      "_service_info_dns",
      "_service_info_snmp",
      "_service_info_smb",
      "_service_info_wins",
      "_service_info_rsync",
      "_service_info_generic"
    ]
  },
  {
    "id": "service_info_advanced",
    "label": "TLS/SSL & database diagnostics",
    "description": "Evaluate TLS configuration, database services, and industrial protocols.",
    "category": "service",
    "methods": [
      "_service_info_tls",
      "_service_info_mssql",
      "_service_info_mysql",
      "_service_info_rdp",
      "_service_info_postgresql",
      "_service_info_vnc",
      "_service_info_redis",
      "_service_info_elasticsearch",
      "_service_info_memcached",
      "_service_info_mongodb",
      "_service_info_modbus",
      "_service_info_couchdb",
      "_service_info_influxdb"
    ]
  },
  {
    "id": "web_discovery",
    "label": "Discovery",
    "description": "Enumerate exposed files, admin panels, homepage secrets, tech fingerprinting, and VPN endpoints (OWASP WSTG-INFO).",
    "category": "web",
    "methods": ["_web_test_common", "_web_test_homepage", "_web_test_tech_fingerprint", "_web_test_vpn_endpoints", "_web_test_cms_fingerprint", "_web_test_verbose_errors", "_web_test_java_servers"]
  },
  {
    "id": "web_hardening",
    "label": "Hardening audit",
    "description": "Audit cookie flags, security headers, CORS policy, CSRF tokens, and HTTP methods (OWASP WSTG-CONF).",
    "category": "web",
    "methods": ["_web_test_flags", "_web_test_security_headers", "_web_test_cors_misconfiguration", "_web_test_http_methods", "_web_test_csrf"]
  },
  {
    "id": "web_api_exposure",
    "label": "API exposure",
    "description": "Detect GraphQL introspection leaks, cloud metadata endpoints, and API auth bypass (OWASP WSTG-APIT).",
    "category": "web",
    "methods": ["_web_test_graphql_introspection", "_web_test_metadata_endpoints", "_web_test_api_auth_bypass"]
  },
  {
    "id": "web_injection",
    "label": "Injection probes",
    "description": "Non-destructive probes for path traversal, reflected XSS, SQL injection, SSRF, and open redirect (OWASP WSTG-INPV).",
    "category": "web",
    "methods": ["_web_test_path_traversal", "_web_test_xss", "_web_test_sql_injection", "_web_test_ssti", "_web_test_shellshock", "_web_test_php_cgi", "_web_test_ognl_injection", "_web_test_java_deserialization", "_web_test_spring_actuator", "_web_test_open_redirect", "_web_test_ssrf_basic"]
  },
  {
    "id": "web_auth_design",
    "label": "Authentication & design flaws",
    "description": "Detect account enumeration, missing rate limiting, and IDOR indicators (OWASP A04).",
    "category": "web",
    "methods": ["_web_test_account_enumeration", "_web_test_rate_limiting", "_web_test_idor_indicators"]
  },
  {
    "id": "web_integrity",
    "label": "Software integrity",
    "description": "Check subresource integrity, mixed content, and client-side library versions (OWASP A08).",
    "category": "web",
    "methods": ["_web_test_subresource_integrity", "_web_test_mixed_content", "_web_test_js_library_versions"]
  },
  {
    "id": "active_auth",
    "label": "Credential testing",
    "description": "Test default/weak credentials on database and remote access services. May trigger account lockout.",
    "category": "service",
    "methods": ["_service_info_mysql_creds", "_service_info_postgresql_creds", "_service_info_http_basic_auth"]
  },
  {
    "id": "post_scan_correlation",
    "label": "Cross-service correlation",
    "description": "Post-scan analysis: honeypot detection, OS consistency, infrastructure leak aggregation.",
    "category": "correlation",
    "methods": ["_post_scan_correlate"]
  },
  {
    "id": "graybox",
    "label": "Authenticated webapp testing",
    "description": "OWASP-mapped application probes requiring login credentials: IDOR, privilege escalation, business logic, misconfiguration, injection, SSRF, and weak authentication.",
    "category": "graybox",
    "methods": [entry["key"] for entry in GRAYBOX_PROBE_REGISTRY] + ["_graybox_weak_auth"],
  },
]


NETWORK_FEATURE_CATEGORIES = ("service", "web", "correlation")
NETWORK_FEATURE_REGISTRY = {
  category: tuple(
    method
    for item in FEATURE_CATALOG
    if item.get("category") == category
    for method in item.get("methods", [])
  )
  for category in NETWORK_FEATURE_CATEGORIES
}
NETWORK_FEATURE_METHODS = tuple(
  method
  for category in NETWORK_FEATURE_CATEGORIES
  for method in NETWORK_FEATURE_REGISTRY[category]
)

# Job status constants
JOB_STATUS_RUNNING = "RUNNING"
JOB_STATUS_COLLECTING = "COLLECTING"        # Launcher merging worker reports
JOB_STATUS_ANALYZING = "ANALYZING"          # Running LLM analysis
JOB_STATUS_FINALIZING = "FINALIZING"        # Computing risk, writing archive
JOB_STATUS_SCHEDULED_FOR_STOP = "SCHEDULED_FOR_STOP"
JOB_STATUS_STOPPED = "STOPPED"
JOB_STATUS_FINALIZED = "FINALIZED"

# Run mode constants
RUN_MODE_SINGLEPASS = "SINGLEPASS"
RUN_MODE_CONTINUOUS_MONITORING = "CONTINUOUS_MONITORING"

# Distribution strategy constants
DISTRIBUTION_SLICE = "SLICE"
DISTRIBUTION_MIRROR = "MIRROR"

# Port order constants
PORT_ORDER_SHUFFLE = "SHUFFLE"
PORT_ORDER_SEQUENTIAL = "SEQUENTIAL"

# LLM Agent API status constants
LLM_API_STATUS_OK = "ok"
LLM_API_STATUS_ERROR = "error"
LLM_API_STATUS_TIMEOUT = "timeout"

# LLM Analysis types
LLM_ANALYSIS_SECURITY_ASSESSMENT = "security_assessment"
LLM_ANALYSIS_VULNERABILITY_SUMMARY = "vulnerability_summary"
LLM_ANALYSIS_REMEDIATION_PLAN = "remediation_plan"
LLM_ANALYSIS_QUICK_SUMMARY = "quick_summary"
# Phase 4 PR-4.3 — full structured output conforming to
# LlmReportSections (background_draft, overall_posture,
# recommendation_summary[], strategic_roadmap{}, attack_chain_narratives[],
# coverage_gaps[], conclusion). Used by the Phase 6/7 PDF rewrite to
# render the labelled Executive Summary + AI-disclosure sections.
LLM_ANALYSIS_EXEC_SUMMARY_PACKAGE = "exec_summary_package"

# Prompt-template version. Stored on every emitted LlmReportSections
# so the report's AI-disclosure appendix can show which template
# version produced the narrative. Bump on any prompt change.
LLM_PROMPT_VERSION_EXEC_SUMMARY = "exec-summary-v1"

# =====================================================================
# Protocol fingerprinting and probe routing
# =====================================================================

# Fingerprint configuration
SCAN_PORT_TIMEOUT = 0.3        # seconds — connect timeout during port scanning
FINGERPRINT_TIMEOUT = 2        # seconds — passive banner grab timeout
FINGERPRINT_MAX_BANNER = 512   # bytes — max banner stored per port
FINGERPRINT_HTTP_TIMEOUT = 4   # seconds — active HTTP probe timeout (honeypots may be slow)
FINGERPRINT_NUDGE_TIMEOUT = 3  # seconds — generic \r\n nudge probe timeout

# Well-known TCP port → protocol (fallback when banner is unrecognized)
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 42: "wins",
    53: "dns", 80: "http", 81: "http", 110: "pop3", 137: "nbns", 139: "smb", 143: "imap",
    873: "rsync",
    161: "snmp", 443: "https", 445: "smb", 465: "smtp",  # SMTPS
    502: "modbus", 587: "smtp", 993: "imap", 995: "pop3",  # TLS-wrapped mail
    1433: "mssql", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8000: "http", 8008: "http",
    8080: "http", 8081: "http", 8443: "https", 8888: "http",
    9200: "http", 11211: "memcached", 27017: "mongodb",
}

# Protocols where web vulnerability tests are applicable
WEB_PROTOCOLS = frozenset({"http", "https"})

# Which protocols each service probe is designed to test.
# Probes not listed here run unconditionally (forward-compatible with new probes).
PROBE_PROTOCOL_MAP = {
    "_service_info_ftp":      frozenset({"ftp"}),
    "_service_info_ssh":      frozenset({"ssh"}),
    "_service_info_telnet":      frozenset({"telnet"}),
    "_service_info_smtp":      frozenset({"smtp"}),
    "_service_info_dns":      frozenset({"dns"}),
    "_service_info_http":      frozenset({"http"}),
    "_service_info_https":     frozenset({"https"}),
    "_service_info_http_alt":    frozenset({"http"}),
    "_service_info_tls":     frozenset({"https", "unknown"}),
    "_service_info_mssql":    frozenset({"mssql"}),
    "_service_info_mysql":    frozenset({"mysql"}),
    "_service_info_rdp":    frozenset({"rdp"}),
    "_service_info_postgresql":    frozenset({"postgresql"}),
    "_service_info_vnc":    frozenset({"vnc"}),
    "_service_info_redis":    frozenset({"redis"}),
    "_service_info_elasticsearch":    frozenset({"http", "https"}),
    "_service_info_memcached":   frozenset({"memcached"}),
    "_service_info_mongodb":   frozenset({"mongodb"}),
    "_service_info_snmp":     frozenset({"snmp"}),
    "_service_info_smb":     frozenset({"smb"}),
    "_service_info_modbus":     frozenset({"modbus"}),
    "_service_info_wins":    frozenset({"wins", "nbns"}),
    "_service_info_rsync":   frozenset({"rsync"}),
    "_service_info_couchdb":    frozenset({"http", "https"}),
    "_service_info_influxdb":   frozenset({"http", "https"}),
    "_service_info_generic": frozenset({"unknown"}),
    "_service_info_mysql_creds": frozenset({"mysql"}),
    "_service_info_postgresql_creds": frozenset({"postgresql"}),
    "_service_info_http_basic_auth": frozenset({"http", "https"}),
    # OWASP full coverage probes
    "_web_test_ssrf_basic":            frozenset({"http", "https"}),
    "_web_test_account_enumeration":   frozenset({"http", "https"}),
    "_web_test_rate_limiting":         frozenset({"http", "https"}),
    "_web_test_idor_indicators":       frozenset({"http", "https"}),
    "_web_test_subresource_integrity": frozenset({"http", "https"}),
    "_web_test_mixed_content":         frozenset({"http", "https"}),
    "_web_test_js_library_versions":   frozenset({"http", "https"}),
    "_web_test_verbose_errors":        frozenset({"http", "https"}),
    "_web_test_java_servers":          frozenset({"http", "https"}),
    "_web_test_ognl_injection":        frozenset({"http", "https"}),
    "_web_test_java_deserialization":  frozenset({"http", "https"}),
    "_web_test_spring_actuator":       frozenset({"http", "https"}),
}

# =====================================================================
# Local worker threads per node
# =====================================================================

LOCAL_WORKERS_MIN = 1
LOCAL_WORKERS_MAX = 16
LOCAL_WORKERS_DEFAULT = 2

# =====================================================================
# Port lists
# =====================================================================

COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 445,
  502, 1433, 1521, 27017, 3306, 3389, 5432, 5900,
  8080, 8443, 9200, 11211
]

ALL_PORTS = list(range(1, 65536))

# =====================================================================
# Risk score computation
# =====================================================================

RISK_SEVERITY_WEIGHTS = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 2, "INFO": 0}
RISK_CONFIDENCE_MULTIPLIERS = {"certain": 1.0, "firm": 0.8, "tentative": 0.5}
RISK_SIGMOID_K = 0.02
RISK_CRED_PENALTY_PER = 15
RISK_CRED_PENALTY_CAP = 30

# =====================================================================
# Job archive
# =====================================================================

JOB_ARCHIVE_VERSION = 1
MAX_CONTINUOUS_PASSES = 100

# Scan phases in execution order (5 phases total)
PHASE_ORDER = ["port_scan", "fingerprint", "service_probes", "web_tests", "correlation"]
PHASE_MARKERS = {
  "fingerprint": "fingerprint_completed",
  "service_probes": "service_info_completed",
  "web_tests": "web_tests_completed",
  "correlation": "correlation_completed",
}

# Graybox scan phases in execution order
GRAYBOX_PHASE_ORDER = [
  "preflight", "authentication", "discovery", "graybox_probes",
  "weak_auth",
]
