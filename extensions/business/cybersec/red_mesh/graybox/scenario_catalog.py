"""Graybox scenario signature catalog.

The catalog defines stable, countable authenticated-testing scenarios. Probe
implementations may emit a subset on any given target depending on configured
endpoints, auth state, and safety gates.

Schema (per-entry dict):
  id:     stable scenario identifier (see docs/adr/2026-05-12-scenario-id-convention.md).
  family: owning probe area; for v1 OWASP API Top 10 use one of
          "api_access", "api_auth", "api_data", "api_config", "api_abuse";
          legacy families "access_control"/"misconfiguration"/"injection"/
          "business_logic" remain for OWASP Web Top 10 scenarios.
  title:  short human-facing title rendered in reports.
  owasp:  OWASP category tag, e.g. "A01:2021" (Web Top 10 2021) or
          "API1:2023" (API Top 10 2023).
  attack: optional list of MITRE ATT&CK technique IDs the finding maps to.
          Mandatory and non-empty for v1 OWASP API Top 10 scenarios
          (Subphase 1.2). Legacy PT-A* entries may omit this field.
"""

GRAYBOX_SCENARIO_CATALOG = (
  # Access control / IDOR / BOLA
  {"id": "PT-A01-01", "family": "access_control", "title": "IDOR/BOLA read bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-02", "family": "access_control", "title": "Function-level authorization bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-03", "family": "access_control", "title": "HTTP method authorization bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-04", "family": "access_control", "title": "Authenticated open redirect", "owasp": "A01:2021"},
  {"id": "PT-A01-05", "family": "access_control", "title": "Object ownership update bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-06", "family": "access_control", "title": "Object ownership delete bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-07", "family": "access_control", "title": "Horizontal tenant isolation failure", "owasp": "A01:2021"},
  {"id": "PT-A01-08", "family": "access_control", "title": "Vertical privilege escalation", "owasp": "A01:2021"},
  {"id": "PT-A01-09", "family": "access_control", "title": "Admin endpoint reachable by regular user", "owasp": "A01:2021"},
  {"id": "PT-A01-10", "family": "access_control", "title": "Query parameter role override", "owasp": "A01:2021"},
  {"id": "PT-A01-11", "family": "access_control", "title": "Path parameter role override", "owasp": "A01:2021"},
  {"id": "PT-A01-12", "family": "access_control", "title": "Hidden field authorization tampering", "owasp": "A01:2021"},
  {"id": "PT-A01-13", "family": "access_control", "title": "Alternate content-type authorization bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-14", "family": "access_control", "title": "Batch endpoint object authorization bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-15", "family": "access_control", "title": "Nested resource ownership bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-16", "family": "access_control", "title": "Collection filter tenant bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-17", "family": "access_control", "title": "Direct file download authorization bypass", "owasp": "A01:2021"},
  {"id": "PT-A01-18", "family": "access_control", "title": "Impersonation parameter accepted", "owasp": "A01:2021"},
  {"id": "PT-A01-19", "family": "access_control", "title": "Cross-account search result exposure", "owasp": "A01:2021"},
  {"id": "PT-A01-20", "family": "access_control", "title": "Unauthorized export endpoint access", "owasp": "A01:2021"},

  # Cryptographic/session/authentication configuration
  {"id": "PT-A02-01", "family": "misconfiguration", "title": "Debug/config endpoint disclosure", "owasp": "A05:2021"},
  {"id": "PT-A02-02", "family": "misconfiguration", "title": "Permissive CORS configuration", "owasp": "A05:2021"},
  {"id": "PT-A02-03", "family": "misconfiguration", "title": "Missing security headers", "owasp": "A05:2021"},
  {"id": "PT-A02-04", "family": "misconfiguration", "title": "Insecure session cookie attributes", "owasp": "A05:2021"},
  {"id": "PT-A02-05", "family": "misconfiguration", "title": "CSRF protection missing", "owasp": "A01:2021"},
  {"id": "PT-A02-06", "family": "misconfiguration", "title": "Weak session token quality", "owasp": "A07:2021"},
  {"id": "PT-A02-07", "family": "misconfiguration", "title": "Missing login rate limiting", "owasp": "A07:2021"},
  {"id": "PT-A02-08", "family": "misconfiguration", "title": "Session remains valid after logout", "owasp": "A07:2021"},
  {"id": "PT-A02-09", "family": "misconfiguration", "title": "Remember-me token lacks rotation", "owasp": "A07:2021"},
  {"id": "PT-A02-10", "family": "misconfiguration", "title": "Password change missing old password check", "owasp": "A07:2021"},
  {"id": "PT-A02-11", "family": "misconfiguration", "title": "Weak password accepted", "owasp": "A07:2021"},
  {"id": "PT-A02-12", "family": "misconfiguration", "title": "JWT weak algorithm accepted", "owasp": "A02:2021"},
  {"id": "PT-A02-13", "family": "misconfiguration", "title": "JWT claim tampering accepted", "owasp": "A07:2021"},
  {"id": "PT-A02-14", "family": "misconfiguration", "title": "Sensitive token in URL", "owasp": "A02:2021"},
  {"id": "PT-A02-15", "family": "misconfiguration", "title": "Long-lived session without idle timeout", "owasp": "A07:2021"},
  {"id": "PT-A02-16", "family": "misconfiguration", "title": "MFA challenge bypass indicator", "owasp": "A07:2021"},
  {"id": "PT-A02-17", "family": "misconfiguration", "title": "Account enumeration by response timing", "owasp": "A07:2021"},
  {"id": "PT-A02-18", "family": "misconfiguration", "title": "Password reset token not invalidated", "owasp": "A07:2021"},

  # Injection and input validation
  {"id": "PT-A03-01", "family": "injection", "title": "Authenticated form injection", "owasp": "A03:2021"},
  {"id": "PT-A03-02", "family": "injection", "title": "Stored XSS", "owasp": "A03:2021"},
  {"id": "PT-A03-03", "family": "injection", "title": "Authenticated path traversal", "owasp": "A03:2021"},
  {"id": "PT-A03-04", "family": "injection", "title": "Reflected XSS behind auth", "owasp": "A03:2021"},
  {"id": "PT-A03-05", "family": "injection", "title": "DOM XSS indicator", "owasp": "A03:2021"},
  {"id": "PT-A03-06", "family": "injection", "title": "Template injection indicator", "owasp": "A03:2021"},
  {"id": "PT-A03-07", "family": "injection", "title": "Command injection indicator", "owasp": "A03:2021"},
  {"id": "PT-A03-08", "family": "injection", "title": "NoSQL injection indicator", "owasp": "A03:2021"},
  {"id": "PT-A03-09", "family": "injection", "title": "LDAP injection indicator", "owasp": "A03:2021"},
  {"id": "PT-A03-10", "family": "injection", "title": "XXE-safe parser indicator", "owasp": "A05:2021"},
  {"id": "PT-A03-11", "family": "injection", "title": "CSV formula injection", "owasp": "A03:2021"},
  {"id": "PT-A03-12", "family": "injection", "title": "Header injection", "owasp": "A03:2021"},
  {"id": "PT-A03-13", "family": "injection", "title": "File name traversal on upload/download", "owasp": "A03:2021"},
  {"id": "PT-A03-14", "family": "injection", "title": "GraphQL argument injection", "owasp": "A03:2021"},
  {"id": "PT-A03-15", "family": "injection", "title": "JSON body type confusion", "owasp": "A03:2021"},
  {"id": "PT-A03-16", "family": "injection", "title": "XML payload parser issue", "owasp": "A05:2021"},
  {"id": "PT-A03-17", "family": "injection", "title": "Search query injection indicator", "owasp": "A03:2021"},
  {"id": "PT-A03-18", "family": "injection", "title": "Upload content sniffing bypass", "owasp": "A05:2021"},

  # Insecure design / mass assignment
  {"id": "PT-A04-01", "family": "access_control", "title": "Mass assignment privilege field", "owasp": "A04:2021"},
  {"id": "PT-A04-02", "family": "access_control", "title": "Mass assignment ownership field", "owasp": "A04:2021"},
  {"id": "PT-A04-03", "family": "access_control", "title": "Mass assignment price field", "owasp": "A04:2021"},
  {"id": "PT-A04-04", "family": "access_control", "title": "Client-side role trust", "owasp": "A04:2021"},
  {"id": "PT-A04-05", "family": "access_control", "title": "Client-side approval trust", "owasp": "A04:2021"},
  {"id": "PT-A04-06", "family": "access_control", "title": "Missing server-side invariant check", "owasp": "A04:2021"},
  {"id": "PT-A04-07", "family": "access_control", "title": "Business rule bypass through optional field", "owasp": "A04:2021"},
  {"id": "PT-A04-08", "family": "access_control", "title": "Unsafe default role on object creation", "owasp": "A04:2021"},

  # Login/injection compatibility and business logic
  {"id": "PT-A05-01", "family": "injection", "title": "Login form injection", "owasp": "A03:2021"},
  {"id": "PT-A06-01", "family": "business_logic", "title": "Workflow step skipping", "owasp": "A04:2021"},
  {"id": "PT-A06-02", "family": "business_logic", "title": "Business value validation bypass", "owasp": "A04:2021"},
  {"id": "PT-A06-03", "family": "business_logic", "title": "Invalid state transition accepted", "owasp": "A04:2021"},
  {"id": "PT-A06-04", "family": "business_logic", "title": "Negative amount accepted", "owasp": "A04:2021"},
  {"id": "PT-A06-05", "family": "business_logic", "title": "Quantity or limit bypass", "owasp": "A04:2021"},
  {"id": "PT-A06-06", "family": "business_logic", "title": "Coupon or discount replay", "owasp": "A04:2021"},
  {"id": "PT-A06-07", "family": "business_logic", "title": "Idempotency or replay failure", "owasp": "A04:2021"},
  {"id": "PT-A06-08", "family": "business_logic", "title": "Approval bypass", "owasp": "A04:2021"},
  {"id": "PT-A06-09", "family": "business_logic", "title": "Time-window bypass", "owasp": "A04:2021"},
  {"id": "PT-A06-10", "family": "business_logic", "title": "Multi-step action completed out of order", "owasp": "A04:2021"},

  # Existing weak-auth/API scenarios
  {"id": "PT-A07-01", "family": "business_logic", "title": "Weak credential simulation", "owasp": "A07:2021"},
  {"id": "PT-A07-02", "family": "misconfiguration", "title": "Password reset token predictability", "owasp": "A07:2021"},
  {"id": "PT-A07-03", "family": "misconfiguration", "title": "Session not rotated after login", "owasp": "A07:2021"},
  {"id": "PT-A07-04", "family": "misconfiguration", "title": "Account enumeration by response body", "owasp": "A07:2021"},
  # Legacy SSRF scenario kept under its original ID for backward compat.
  # Probe emits owasp="API7:2023"; catalog now matches.
  {"id": "PT-API7-01", "family": "injection", "title": "Authenticated SSRF",
   "owasp": "API7:2023", "attack": ["T1190"]},

  # ── OWASP API Top 10 2023 (v1 — Subphase 1.2) ──────────────────────────
  # ATT&CK mappings copied from the V1 Scenario Manifest in the plan
  # (`_todos/2026-05-12-graybox-api-top10-plan-detailed.md`, lines 90-115).
  # API10 (Unsafe Consumption) intentionally omitted — Phase 9 follow-up.

  # API1 — Broken Object Level Authorization
  {"id": "PT-OAPI1-01", "family": "api_access",
   "title": "API object-level authorization bypass (BOLA)",
   "owasp": "API1:2023", "attack": ["T1190", "T1078"]},

  # API2 — Broken Authentication
  {"id": "PT-OAPI2-01", "family": "api_auth",
   "title": "API JWT missing-signature accepted (alg=none)",
   "owasp": "API2:2023", "attack": ["T1078", "T1552"]},
  {"id": "PT-OAPI2-02", "family": "api_auth",
   "title": "API JWT signed with weak HMAC secret",
   "owasp": "API2:2023", "attack": ["T1212", "T1552"]},
  {"id": "PT-OAPI2-03", "family": "api_auth",
   "title": "API token not invalidated on logout",
   "owasp": "API2:2023", "attack": ["T1078"]},

  # API3 — Broken Object Property Level Authorization (BOPLA)
  {"id": "PT-OAPI3-01", "family": "api_data",
   "title": "API response leaks sensitive properties (excessive exposure)",
   "owasp": "API3:2023", "attack": ["T1552", "T1190"]},
  {"id": "PT-OAPI3-02", "family": "api_data",
   "title": "API accepts mass assignment of privileged properties",
   "owasp": "API3:2023", "attack": ["T1565", "T1078"]},

  # API4 — Unrestricted Resource Consumption
  {"id": "PT-OAPI4-01", "family": "api_abuse",
   "title": "API endpoint lacks pagination cap",
   "owasp": "API4:2023", "attack": ["T1499"]},
  {"id": "PT-OAPI4-02", "family": "api_abuse",
   "title": "API endpoint accepts oversized payload",
   "owasp": "API4:2023", "attack": ["T1499"]},
  {"id": "PT-OAPI4-03", "family": "api_abuse",
   "title": "API endpoint lacks rate limit",
   "owasp": "API4:2023", "attack": ["T1499"]},

  # API5 — Broken Function Level Authorization
  {"id": "PT-OAPI5-01", "family": "api_access",
   "title": "API function-level authorization bypass (regular as admin, read)",
   "owasp": "API5:2023", "attack": ["T1190", "T1078"]},
  {"id": "PT-OAPI5-02", "family": "api_access",
   "title": "API function-level authorization bypass (anonymous as user, read)",
   "owasp": "API5:2023", "attack": ["T1190"]},
  {"id": "PT-OAPI5-03", "family": "api_access",
   "title": "API method-override authorization bypass",
   "owasp": "API5:2023", "attack": ["T1190", "T1078"]},
  {"id": "PT-OAPI5-02-mut", "family": "api_access",
   "title": "API function-level authorization bypass (regular as admin, mutating)",
   "owasp": "API5:2023", "attack": ["T1190", "T1078", "T1565"]},

  # API6 — Unrestricted Access to Sensitive Business Flows
  {"id": "PT-OAPI6-01", "family": "api_abuse",
   "title": "API business flow lacks rate limit / abuse controls",
   "owasp": "API6:2023", "attack": ["T1499", "T1190"]},
  {"id": "PT-OAPI6-02", "family": "api_abuse",
   "title": "API business flow lacks uniqueness check",
   "owasp": "API6:2023", "attack": ["T1565", "T1190"]},

  # API8 — Security Misconfiguration
  {"id": "PT-OAPI8-01", "family": "api_config",
   "title": "API permissive CORS configuration",
   "owasp": "API8:2023", "attack": ["T1190"]},
  {"id": "PT-OAPI8-02", "family": "api_config",
   "title": "API response missing security headers",
   "owasp": "API8:2023", "attack": ["T1190"]},
  {"id": "PT-OAPI8-03", "family": "api_config",
   "title": "API debug endpoint exposed",
   "owasp": "API8:2023", "attack": ["T1552", "T1190"]},
  {"id": "PT-OAPI8-04", "family": "api_config",
   "title": "API verbose error response leaks internals",
   "owasp": "API8:2023", "attack": ["T1190"]},
  {"id": "PT-OAPI8-05", "family": "api_config",
   "title": "API advertises unexpected HTTP methods",
   "owasp": "API8:2023", "attack": ["T1190"]},

  # API9 — Improper Inventory Management
  {"id": "PT-OAPI9-01", "family": "api_config",
   "title": "API OpenAPI/Swagger specification publicly exposed",
   "owasp": "API9:2023", "attack": ["T1595", "T1190"]},
  {"id": "PT-OAPI9-02", "family": "api_config",
   "title": "API legacy version still live (version sprawl)",
   "owasp": "API9:2023", "attack": ["T1595", "T1190"]},
  {"id": "PT-OAPI9-03", "family": "api_config",
   "title": "API deprecated path still serving requests",
   "owasp": "API9:2023", "attack": ["T1190"]},
)


def graybox_scenario_ids() -> set[str]:
  """Return stable graybox scenario IDs."""
  return {entry["id"] for entry in GRAYBOX_SCENARIO_CATALOG}


def graybox_scenario(scenario_id: str) -> dict | None:
  """Return the catalog entry for ``scenario_id`` or None if missing."""
  for entry in GRAYBOX_SCENARIO_CATALOG:
    if entry["id"] == scenario_id:
      return entry
  return None


def attack_for_scenario(scenario_id: str) -> list[str]:
  """Return the ATT&CK technique IDs for ``scenario_id``.

  Returns an empty list when the scenario is unknown or the entry has no
  ``attack`` field set. Used by `ProbeBase.emit_vulnerable(..., attack=None)`
  as the default attack mapping so the catalog is the single source of
  truth (see Subphase 1.6).
  """
  entry = graybox_scenario(scenario_id)
  if entry is None:
    return []
  return list(entry.get("attack", []))
