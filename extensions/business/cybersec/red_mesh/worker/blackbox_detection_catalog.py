"""Native black-box non-CVE detection signature catalog.

These IDs count stable issue families that existing native probes can emit.
They are intentionally coarser than payloads and endpoints: one signature per
evidence-backed vulnerability family.
"""

BLACKBOX_DETECTION_CATALOG = (
  {"id": "exposed-admin-endpoint", "probe": "_web_test_common", "category": "discovery"},
  {"id": "exposed-server-status", "probe": "_web_test_common", "category": "discovery"},
  {"id": "exposed-env-config", "probe": "_web_test_homepage", "category": "discovery"},
  {"id": "homepage-secret-disclosure", "probe": "_web_test_homepage", "category": "discovery"},
  {"id": "server-header-disclosure", "probe": "_web_test_tech_fingerprint", "category": "discovery"},
  {"id": "technology-mismatch", "probe": "_web_test_tech_fingerprint", "category": "discovery"},
  {"id": "vpn-portal-exposure", "probe": "_web_test_vpn_endpoints", "category": "discovery"},
  {"id": "cms-version-disclosure", "probe": "_web_test_cms_fingerprint", "category": "discovery"},
  {"id": "cms-readme-exposure", "probe": "_web_test_cms_fingerprint", "category": "discovery"},
  {"id": "verbose-error-disclosure", "probe": "_web_test_verbose_errors", "category": "discovery"},
  {"id": "debug-toolbar-exposure", "probe": "_web_test_verbose_errors", "category": "discovery"},
  {"id": "java-server-version-disclosure", "probe": "_web_test_java_servers", "category": "discovery"},
  {"id": "tomcat-manager-exposure", "probe": "_web_test_java_servers", "category": "discovery"},
  {"id": "jboss-console-exposure", "probe": "_web_test_java_servers", "category": "discovery"},
  {"id": "weblogic-console-exposure", "probe": "_web_test_java_servers", "category": "discovery"},
  {"id": "directory-listing", "probe": "_web_test_flags", "category": "hardening"},
  {"id": "cookie-missing-secure", "probe": "_web_test_flags", "category": "hardening"},
  {"id": "cookie-missing-httponly", "probe": "_web_test_flags", "category": "hardening"},
  {"id": "cookie-missing-samesite", "probe": "_web_test_flags", "category": "hardening"},
  {"id": "missing-security-header", "probe": "_web_test_security_headers", "category": "hardening"},
  {"id": "weak-security-header", "probe": "_web_test_security_headers", "category": "hardening"},
  {"id": "insecure-cors", "probe": "_web_test_cors_misconfiguration", "category": "hardening"},
  {"id": "dangerous-http-method", "probe": "_web_test_http_methods", "category": "hardening"},
  {"id": "missing-csrf-token", "probe": "_web_test_csrf", "category": "hardening"},
  {"id": "graphql-introspection", "probe": "_web_test_graphql_introspection", "category": "api"},
  {"id": "cloud-metadata-exposure", "probe": "_web_test_metadata_endpoints", "category": "api"},
  {"id": "api-auth-bypass", "probe": "_web_test_api_auth_bypass", "category": "api"},
  {"id": "path-traversal", "probe": "_web_test_path_traversal", "category": "injection"},
  {"id": "reflected-xss", "probe": "_web_test_xss", "category": "injection"},
  {"id": "sql-injection", "probe": "_web_test_sql_injection", "category": "injection"},
  {"id": "server-side-template-injection", "probe": "_web_test_ssti", "category": "injection"},
  {"id": "shellshock", "probe": "_web_test_shellshock", "category": "injection"},
  {"id": "php-cgi-argument-injection", "probe": "_web_test_php_cgi", "category": "injection"},
  {"id": "ognl-injection", "probe": "_web_test_ognl_injection", "category": "injection"},
  {"id": "java-deserialization-endpoint", "probe": "_web_test_java_deserialization", "category": "injection"},
  {"id": "spring-actuator-exposure", "probe": "_web_test_spring_actuator", "category": "injection"},
  {"id": "open-redirect", "probe": "_web_test_open_redirect", "category": "injection"},
  {"id": "ssrf-indicator", "probe": "_web_test_ssrf_basic", "category": "injection"},
  {"id": "account-enumeration", "probe": "_web_test_account_enumeration", "category": "auth"},
  {"id": "missing-rate-limit", "probe": "_web_test_rate_limiting", "category": "auth"},
  {"id": "idor-indicator", "probe": "_web_test_idor_indicators", "category": "auth"},
  {"id": "missing-subresource-integrity", "probe": "_web_test_subresource_integrity", "category": "integrity"},
  {"id": "mixed-content", "probe": "_web_test_mixed_content", "category": "integrity"},
  {"id": "eol-js-library", "probe": "_web_test_js_library_versions", "category": "integrity"},
  {"id": "weak-mysql-credential", "probe": "_service_info_mysql_creds", "category": "service"},
  {"id": "weak-postgresql-credential", "probe": "_service_info_postgresql_creds", "category": "service"},
  {"id": "weak-http-basic-auth", "probe": "_service_info_http_basic_auth", "category": "service"},
  {"id": "unauthenticated-redis", "probe": "_service_info_redis", "category": "service"},
  {"id": "unauthenticated-memcached", "probe": "_service_info_memcached", "category": "service"},
  {"id": "unauthenticated-mongodb", "probe": "_service_info_mongodb", "category": "service"},
)


def blackbox_detection_ids() -> set[str]:
  """Return stable black-box non-CVE detector IDs."""
  return {entry["id"] for entry in BLACKBOX_DETECTION_CATALOG}
