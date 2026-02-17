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
      "_service_info_80",
      "_service_info_443",
      "_service_info_8080",
      "_service_info_21",
      "_service_info_22",
      "_service_info_23",
      "_service_info_25",
      "_service_info_53",
      "_service_info_161",
      "_service_info_445",
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
      "_service_info_1433",
      "_service_info_3306",
      "_service_info_3389",
      "_service_info_5432",
      "_service_info_5900",
      "_service_info_6379",
      "_service_info_9200",
      "_service_info_11211",
      "_service_info_27017",
      "_service_info_502"
    ]
  },
  {
    "id": "web_test_common",
    "label": "Common exposure scan",
    "description": "Probe default admin panels, disclosed files, and common misconfigurations.",
    "category": "web",
    "methods": [
      "_web_test_common",
      "_web_test_homepage",
      "_web_test_flags",
      "_web_test_graphql_introspection",
      "_web_test_metadata_endpoints"
    ]
  },
  {
    "id": "web_test_security_headers",
    "label": "Security headers audit",
    "description": "Check HSTS, CSP, X-Frame-Options, and other critical response headers.",
    "category": "web",
    "methods": [
      "_web_test_security_headers",
      "_web_test_cors_misconfiguration",
      "_web_test_open_redirect",
      "_web_test_http_methods"
    ]
  },
  {
    "id": "web_test_vulnerability",
    "label": "Vulnerability probes",
    "description": "Non-destructive probes for common web vulnerabilities.",
    "category": "web",
    "methods": [
      "_web_test_path_traversal",
      "_web_test_xss",
      "_web_test_sql_injection",
      "_web_test_api_auth_bypass"
    ]
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
    161: "snmp", 443: "https", 445: "smb", 502: "modbus",
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
    "_service_info_21":      frozenset({"ftp"}),
    "_service_info_22":      frozenset({"ssh"}),
    "_service_info_23":      frozenset({"telnet"}),
    "_service_info_25":      frozenset({"smtp"}),
    "_service_info_53":      frozenset({"dns"}),
    "_service_info_80":      frozenset({"http"}),
    "_service_info_443":     frozenset({"https"}),
    "_service_info_8080":    frozenset({"http"}),
    "_service_info_tls":     frozenset({"https", "unknown", "wins"}),
    "_service_info_1433":    frozenset({"mssql"}),
    "_service_info_3306":    frozenset({"mysql"}),
    "_service_info_3389":    frozenset({"rdp"}),
    "_service_info_5432":    frozenset({"postgresql"}),
    "_service_info_5900":    frozenset({"vnc"}),
    "_service_info_6379":    frozenset({"redis"}),
    "_service_info_9200":    frozenset({"http", "https"}),
    "_service_info_11211":   frozenset({"memcached"}),
    "_service_info_27017":   frozenset({"mongodb"}),
    "_service_info_161":     frozenset({"snmp"}),
    "_service_info_445":     frozenset({"smb"}),
    "_service_info_502":     frozenset({"modbus"}),
    "_service_info_generic": frozenset({"unknown", "wins"}),
}