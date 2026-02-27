"""
RedMesh constants and feature catalog definitions.
"""

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
      "_service_info_modbus"
    ]
  },
  {
    "id": "web_discovery",
    "label": "Discovery",
    "description": "Enumerate exposed files, admin panels, homepage secrets, tech fingerprinting, and VPN endpoints (OWASP WSTG-INFO).",
    "category": "web",
    "methods": ["_web_test_common", "_web_test_homepage", "_web_test_tech_fingerprint", "_web_test_vpn_endpoints"]
  },
  {
    "id": "web_hardening",
    "label": "Hardening audit",
    "description": "Audit cookie flags, security headers, CORS policy, redirect handling, and HTTP methods (OWASP WSTG-CONF).",
    "category": "web",
    "methods": ["_web_test_flags", "_web_test_security_headers", "_web_test_cors_misconfiguration", "_web_test_open_redirect", "_web_test_http_methods"]
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
    "description": "Non-destructive probes for path traversal, reflected XSS, and SQL injection (OWASP WSTG-INPV).",
    "category": "web",
    "methods": ["_web_test_path_traversal", "_web_test_xss", "_web_test_sql_injection"]
  },
  {
    "id": "active_auth",
    "label": "Credential testing",
    "description": "Test default/weak credentials on database and remote access services. May trigger account lockout.",
    "category": "service",
    "methods": ["_service_info_mysql_creds", "_service_info_postgresql_creds"]
  },
  {
    "id": "post_scan_correlation",
    "label": "Cross-service correlation",
    "description": "Post-scan analysis: honeypot detection, OS consistency, infrastructure leak aggregation.",
    "category": "correlation",
    "methods": ["_post_scan_correlate"]
  }
]

# Job status constants
JOB_STATUS_RUNNING = "RUNNING"
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

# =====================================================================
# Protocol fingerprinting and probe routing
# =====================================================================

# Fingerprint configuration
FINGERPRINT_TIMEOUT = 2        # seconds — passive banner grab timeout
FINGERPRINT_MAX_BANNER = 512   # bytes — max banner stored per port
FINGERPRINT_HTTP_TIMEOUT = 4   # seconds — active HTTP probe timeout (honeypots may be slow)
FINGERPRINT_NUDGE_TIMEOUT = 3  # seconds — generic \r\n nudge probe timeout

# Well-known TCP port → protocol (fallback when banner is unrecognized)
WELL_KNOWN_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 42: "wins",
    53: "dns", 80: "http", 81: "http", 110: "pop3", 143: "imap",
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
    "_service_info_tls":     frozenset({"https", "unknown", "wins"}),
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
    "_service_info_generic": frozenset({"unknown", "wins"}),
    "_service_info_mysql_creds": frozenset({"mysql"}),
    "_service_info_postgresql_creds": frozenset({"postgresql"}),
}

# =====================================================================
# Risk score computation
# =====================================================================

RISK_SEVERITY_WEIGHTS = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 10, "LOW": 2, "INFO": 0}
RISK_CONFIDENCE_MULTIPLIERS = {"certain": 1.0, "firm": 0.8, "tentative": 0.5}
RISK_SIGMOID_K = 0.02
RISK_CRED_PENALTY_PER = 15
RISK_CRED_PENALTY_CAP = 30