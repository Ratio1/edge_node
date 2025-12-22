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