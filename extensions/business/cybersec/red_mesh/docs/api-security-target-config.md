# `target_config.api_security` JSON shape

This is the operator-facing reference for the OWASP API Top 10 graybox scan
configuration. Pass it inside `target_config` on `launch_webapp_scan`.

Source of truth: `graybox/models/target_config.py` (Subphase 1.1 of the API
Top 10 plan). Scenario IDs live in `graybox/scenario_catalog.py` and the
ADR at `docs/adr/2026-05-12-scenario-id-convention.md`.

API10 ("Unsafe Consumption of APIs") is **deliberately not present** in v1
— it is scheduled for Phase 9 once a callback-receiver service exists.

## Top-level shape

```json
{
  "target_config": {
    "api_security": {
      "object_endpoints":   [ApiObjectEndpoint],
      "property_endpoints": [ApiPropertyEndpoint],
      "function_endpoints": [ApiFunctionEndpoint],
      "resource_endpoints": [ApiResourceEndpoint],
      "business_flows":     [ApiBusinessFlow],
      "token_endpoints":    ApiTokenEndpoint,
      "inventory_paths":    ApiInventoryPaths,
      "ssrf_body_fields":         ["url", "webhook", "callback", "image_url", "redirect_uri"],
      "sensitive_field_patterns": [],
      "tampering_fields":         ["is_admin", "is_superuser", "role", "verified", ...],
      "debug_path_candidates":    ["/debug", "/api/debug", "/api/_routes", ...]
    }
  }
}
```

## Endpoint sub-models

### `ApiObjectEndpoint` — drives **PT-OAPI1-01** (BOLA)

```json
{
  "path": "/api/records/{id}/",
  "test_ids": [1, 2],
  "owner_field": "owner",
  "id_param": "id",
  "tenant_field": ""
}
```

Only `path` is required. Set `tenant_field` for cross-tenant BOLA.

### `ApiPropertyEndpoint` — drives **PT-OAPI3-01** (excessive exposure) and **PT-OAPI3-02** (mass assignment, stateful)

```json
{
  "path": "/api/profile/{id}/",
  "method_read": "GET",
  "method_write": "PATCH",
  "test_id": 1,
  "id_param": "id"
}
```

### `ApiFunctionEndpoint` — drives **PT-OAPI5-01..04** (BFLA)

```json
{
  "path": "/api/admin/users/{uid}/promote/",
  "method": "POST",
  "privilege": "admin",
  "auth_required_marker": "",
  "revert_path": "/api/admin/users/{uid}/demote/",
  "revert_body": {"reason": "test"}
}
```

`revert_path` is **mandatory** when `method != "GET"` and you want
PT-OAPI5-03 / PT-OAPI5-04 to run with `allow_stateful_probes=true`.
Without it, the stateful probe emits `inconclusive`.

### `ApiResourceEndpoint` — drives **PT-OAPI4-01..03**

```json
{
  "path": "/api/records/list/",
  "limit_param": "limit",
  "baseline_limit": 10,
  "abuse_limit": 999999,
  "rate_limit_expected": false
}
```

Set `rate_limit_expected=true` only on endpoints that genuinely should be
rate-limited — otherwise PT-OAPI4-03 will produce noisy false positives.

### `ApiBusinessFlow` — drives **PT-OAPI6-01..02** (stateful)

```json
{
  "path": "/api/auth/signup/",
  "method": "POST",
  "flow_name": "signup",
  "body_template": {"username": "x", "email": "x@x"},
  "verify_path": "/api/users/?username=",
  "test_account": "abuse_canary",
  "captcha_marker": "",
  "mfa_marker": ""
}
```

Requires `allow_stateful_probes=true` and a tester-supplied non-privileged
`test_account`. Hard-capped at N=5 attempts per flow.

### `ApiTokenEndpoint` — drives **PT-OAPI2-01..03**

```json
{
  "token_path": "/api/token/",
  "protected_path": "/api/me/",
  "logout_path": "/api/auth/logout/",
  "weak_secret_candidates": ["secret", "changeme", "password", ...]
}
```

`logout_path` is required for **PT-OAPI2-03** (logout-doesn't-invalidate);
without it, only PT-OAPI2-01 and PT-OAPI2-02 fire.

### `ApiInventoryPaths` — drives **PT-OAPI9-01..03**

```json
{
  "openapi_candidates": ["/openapi.json", "/swagger.json", "/v3/api-docs", ...],
  "current_version": "/api/v2/",
  "version_sibling_candidates": ["/api/v1/", "/api/v0/", "/api/beta/", ...],
  "canonical_probe_path": "/api/v2/records/1/",
  "private_path_patterns": ["/internal/", "/admin/"],
  "deprecated_paths": ["/api/v1/legacy/"]
}
```

`canonical_probe_path` should be a known-existing endpoint under
`current_version`; PT-OAPI9-02 cross-checks each sibling version by hitting
the same path under it.

## Cross-cutting fields

- **`ssrf_body_fields`**: extends PT-API7-01 to scan JSON body fields by name.
- **`sensitive_field_patterns`**: appended to the built-in regex list used by
  PT-OAPI3-01.
- **`tampering_fields`**: property names PT-OAPI3-02 attempts to set via mass
  assignment.
- **`debug_path_candidates`**: paths PT-OAPI8-03 probes for debug exposure.

## Notes on auth + budget (forward references)

- **Bearer / API-key auth descriptors** (`api_security.auth`) land in
  Subphase 1.5. Secret values (`bearer_token`, `api_key`) are top-level
  launch parameters, **not** inside `target_config`.
- **`max_total_requests`** lands in Subphase 1.7 as a per-scan request
  budget cap.

## Minimal example

```json
{
  "target_url": "https://api.example.com",
  "official_username": "admin",
  "official_password": "...",
  "regular_username": "alice",
  "regular_password": "...",
  "target_config": {
    "api_security": {
      "object_endpoints": [
        {"path": "/api/records/{id}/", "test_ids": [42, 43],
         "tenant_field": "tenant_id"}
      ],
      "function_endpoints": [
        {"path": "/api/admin/export/", "method": "GET"}
      ],
      "token_endpoints": {
        "token_path": "/api/token/",
        "protected_path": "/api/me/",
        "logout_path": "/api/auth/logout/"
      },
      "inventory_paths": {
        "current_version": "/api/v2/",
        "canonical_probe_path": "/api/v2/health"
      }
    }
  },
  "allow_stateful_probes": false
}
```
