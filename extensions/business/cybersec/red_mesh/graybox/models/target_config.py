"""
Application-specific endpoint mapping for graybox probes.

Sectioned by probe category (E4). Each probe reads only its section.
Endpoint entries use typed dataclasses — typos in keys raise at
construction time, not at runtime deep inside a probe.

Passed to the worker via JobConfig.target_config (serialized dict).
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field, fields
from typing import Any


# Common CSRF field names across frameworks (C5)
COMMON_CSRF_FIELDS = [
  "csrfmiddlewaretoken",  # Django
  "csrf_token",           # Flask / WTForms
  "authenticity_token",   # Rails
  "_csrf",                # Spring Security
  "_token",               # Laravel
]


_SECRET_BODY_KEY_PARTS = (
  "password", "passwd", "pwd", "secret", "api_key", "apikey",
  "authorization", "cookie", "credential",
)
_SECRET_BODY_TOKEN_KEYS = {"token", "access_token", "refresh_token", "id_token"}
_SECRET_BODY_VALUE_MARKERS = (
  "bearer ", "basic ", "apikey=", "api_key=", "access_token=",
  "refresh_token=", "client_secret=", "-----begin ",
)
_SAFE_SECRET_BODY_PREFIX = "__redmesh_"
_ALLOWED_SECRET_REF_PREFIXES = (
  ("api_security", "token_endpoints", "token_request_body"),
)
_ALLOWED_SECRET_REF_LIST_FIELDS = {
  ("api_security", "function_endpoints"): {"revert_body"},
  ("api_security", "business_flows"): {"body_template", "revert_body"},
}


def _ensure_mapping(d, context: str) -> dict:
  if d is None:
    return {}
  if not isinstance(d, dict):
    raise TypeError(f"{context} must be an object")
  return d


def _checked_dict(cls, d, context: str = "") -> dict:
  context = context or cls.__name__
  d = _ensure_mapping(d, context)
  allowed = {f.name for f in fields(cls)}
  unknown = sorted((key for key in d.keys() if key not in allowed), key=str)
  if unknown:
    unknown_text = ", ".join(str(key) for key in unknown)
    raise ValueError(f"{context} has unknown field(s): {unknown_text}")
  return d


def _looks_like_secret_body_key(key) -> bool:
  normalized = str(key or "").strip().lower().replace("-", "_")
  if normalized in _SECRET_BODY_TOKEN_KEYS:
    return True
  if normalized.endswith("_token") or normalized.endswith("_api_key"):
    return True
  return any(part in normalized for part in _SECRET_BODY_KEY_PARTS)


def _looks_like_secret_body_value(value) -> bool:
  if not isinstance(value, str):
    return False
  normalized = value.strip().lower()
  if not normalized:
    return False
  if any(marker in normalized for marker in _SECRET_BODY_VALUE_MARKERS):
    return True
  # Compact JWT-looking strings are too easy to leak through examples.
  return normalized.startswith("eyj") and normalized.count(".") >= 2


def _is_typed_secret_ref(value) -> bool:
  if not isinstance(value, dict):
    return False
  return (
    set(value.keys()) == {"secret_ref"} and
    isinstance(value.get("secret_ref"), str) and
    bool(value.get("secret_ref").strip())
  )


def _is_safe_secret_body_placeholder(value) -> bool:
  return (
    isinstance(value, str) and
    value.startswith(_SAFE_SECRET_BODY_PREFIX) and
    value.endswith("__")
  )


def _is_allowed_secret_ref_path(path: tuple) -> bool:
  for prefix in _ALLOWED_SECRET_REF_PREFIXES:
    if path[:len(prefix)] == prefix:
      return True
  for list_prefix, allowed_fields in _ALLOWED_SECRET_REF_LIST_FIELDS.items():
    if len(path) < len(list_prefix) + 2:
      continue
    if path[:len(list_prefix)] != list_prefix:
      continue
    if not isinstance(path[len(list_prefix)], int):
      continue
    if path[len(list_prefix) + 1] in allowed_fields:
      return True
  return False


def iter_target_config_secret_refs(value, path: tuple = ()):
  """Yield ``(path, ref_name)`` for typed target-config secret refs."""
  if _is_typed_secret_ref(value):
    yield path, value["secret_ref"].strip()
    return
  if isinstance(value, dict):
    for key, item in value.items():
      yield from iter_target_config_secret_refs(item, path + (key,))
    return
  if isinstance(value, list):
    for idx, item in enumerate(value):
      yield from iter_target_config_secret_refs(item, path + (idx,))


def collect_target_config_secret_refs(value) -> list[str]:
  refs = []
  seen = set()
  for _path, ref in iter_target_config_secret_refs(value):
    if ref and ref not in seen:
      seen.add(ref)
      refs.append(ref)
  return refs


def validate_target_config_secret_ref_positions(value):
  for path, ref in iter_target_config_secret_refs(value):
    if not _is_allowed_secret_ref_path(path):
      path_text = ".".join(str(part) for part in path)
      raise ValueError(
        f"{path_text} uses secret_ref {ref!r} outside an approved request body"
      )


def resolve_target_config_secret_refs(value, secret_values: dict):
  """Return a copy with typed secret refs replaced by runtime values."""
  if _is_typed_secret_ref(value):
    ref = value["secret_ref"].strip()
    if ref not in (secret_values or {}):
      raise KeyError(ref)
    return secret_values[ref]
  if isinstance(value, dict):
    return {
      key: resolve_target_config_secret_refs(item, secret_values)
      for key, item in value.items()
    }
  if isinstance(value, list):
    return [
      resolve_target_config_secret_refs(item, secret_values)
      for item in value
    ]
  return value


def _reject_inline_secrets(value, context: str):
  """Reject raw secret material in request-body-like config payloads.

  Request bodies are persisted as part of JobConfig.target_config. They
  may contain non-secret test data, but credentials must move through an
  explicit secret reference so archives and reports remain publish-safe.
  """
  if _is_typed_secret_ref(value):
    return
  if isinstance(value, dict):
    for key, item in value.items():
      item_context = f"{context}.{key}"
      if _is_typed_secret_ref(item):
        continue
      if _looks_like_secret_body_key(key):
        if _is_safe_secret_body_placeholder(item):
          continue
        raise ValueError(
          f"{item_context} contains secret-looking data; use secret_ref"
        )
      if _looks_like_secret_body_value(item):
        raise ValueError(
          f"{item_context} contains secret-looking data; use secret_ref"
        )
      _reject_inline_secrets(item, item_context)
    return
  if isinstance(value, list):
    for idx, item in enumerate(value):
      _reject_inline_secrets(item, f"{context}[{idx}]")
    return
  if _looks_like_secret_body_value(value):
    raise ValueError(f"{context} contains secret-looking data; use secret_ref")


# ── Typed endpoint configs (E4) ──────────────────────────────────────────

@dataclass(frozen=True)
class IdorEndpoint:
  """Endpoint for IDOR/BOLA testing (PT-A01-01)."""
  path: str                                  # e.g. "/api/records/{id}/"
  test_ids: list[int] = field(default_factory=lambda: [1, 2])
  owner_field: str = "owner"
  id_param: str = "id"

  @classmethod
  def from_dict(cls, d: dict) -> IdorEndpoint:
    d = _checked_dict(cls, d)
    return cls(
      path=d["path"],
      test_ids=d.get("test_ids", [1, 2]),
      owner_field=d.get("owner_field", "owner"),
      id_param=d.get("id_param", "id"),
    )


@dataclass(frozen=True)
class AdminEndpoint:
  """Endpoint for privilege escalation testing (PT-A01-02)."""
  path: str                                  # e.g. "/api/admin/export-users/"
  method: str = "GET"
  content_markers: list[str] = field(default_factory=list)

  @classmethod
  def from_dict(cls, d: dict) -> AdminEndpoint:
    d = _checked_dict(cls, d)
    return cls(
      path=d["path"],
      method=d.get("method", "GET"),
      content_markers=d.get("content_markers", []),
    )


@dataclass(frozen=True)
class WorkflowEndpoint:
  """Endpoint for business logic testing (PT-A06-01)."""
  path: str                                  # e.g. "/api/records/{id}/force-pay/"
  method: str = "POST"
  expected_guard: str = ""

  @classmethod
  def from_dict(cls, d: dict) -> WorkflowEndpoint:
    d = _checked_dict(cls, d)
    return cls(
      path=d["path"],
      method=d.get("method", "POST"),
      expected_guard=d.get("expected_guard", ""),
    )


@dataclass(frozen=True)
class SsrfEndpoint:
  """Endpoint for SSRF testing (PT-API7-01)."""
  path: str                                  # e.g. "api/fetch/"
  param: str = "url"                         # query param that accepts a URL

  @classmethod
  def from_dict(cls, d: dict) -> SsrfEndpoint:
    d = _checked_dict(cls, d)
    return cls(path=d["path"], param=d.get("param", "url"))


# ── Probe-sectioned config (E4) ─────────────────────────────────────────

@dataclass(frozen=True)
class AccessControlConfig:
  """Config for access control probes (A01)."""
  idor_endpoints: list[IdorEndpoint] = field(default_factory=list)
  admin_endpoints: list[AdminEndpoint] = field(default_factory=list)

  @classmethod
  def from_dict(cls, d: dict) -> AccessControlConfig:
    d = _checked_dict(cls, d)
    return cls(
      idor_endpoints=[IdorEndpoint.from_dict(e) for e in d.get("idor_endpoints", [])],
      admin_endpoints=[AdminEndpoint.from_dict(e) for e in d.get("admin_endpoints", [])],
    )


@dataclass(frozen=True)
class JwtEndpoint:
  """Endpoint pair for JWT weak-algorithm testing (PT-A02-12)."""
  token_path: str = ""             # e.g. "/api/token/" — issues JWT
  protected_path: str = ""         # e.g. "/api/me/" — accepts Bearer JWT
  username: str = ""               # creds for token issuance
  password: str = ""

  @classmethod
  def from_dict(cls, d: dict) -> JwtEndpoint:
    d = _checked_dict(cls, d)
    return cls(
      token_path=d.get("token_path", ""),
      protected_path=d.get("protected_path", ""),
      username=d.get("username", ""),
      password=d.get("password", ""),
    )


@dataclass(frozen=True)
class MisconfigConfig:
  """Config for misconfiguration probes (A02)."""
  debug_paths: list[str] = field(default_factory=lambda: [
    "/debug/config/", "/.env", "/actuator/env", "/server-info",
    "/actuator", "/server-status",
  ])
  jwt_endpoints: JwtEndpoint = field(default_factory=JwtEndpoint)

  @classmethod
  def from_dict(cls, d: dict) -> MisconfigConfig:
    d = _checked_dict(cls, d)
    return cls(
      debug_paths=d.get("debug_paths", cls.__dataclass_fields__["debug_paths"].default_factory()),
      jwt_endpoints=JwtEndpoint.from_dict(d.get("jwt_endpoints", {})),
    )


@dataclass(frozen=True)
class ReflectiveEndpoint:
  """Endpoint that reflects a single query param into the response.

  Used by PT-A03-04 (XSS), PT-A03-06 (SSTI), PT-A03-07 (command),
  PT-A03-12 (header). The probe sends a category-specific payload via
  ``param`` and inspects the response body or headers.
  """
  path: str
  param: str = "msg"

  @classmethod
  def from_dict(cls, d: dict) -> ReflectiveEndpoint:
    d = _checked_dict(cls, d)
    return cls(path=d["path"], param=d.get("param", "msg"))


@dataclass(frozen=True)
class JsonLookupEndpoint:
  """Endpoint that takes a JSON body for PT-A03-15 type-confusion testing."""
  path: str
  field: str = "id"

  @classmethod
  def from_dict(cls, d: dict) -> JsonLookupEndpoint:
    d = _checked_dict(cls, d)
    return cls(path=d["path"], field=d.get("field", "id"))


@dataclass(frozen=True)
class InjectionConfig:
  """Config for injection probes (A03/A05/API7)."""
  ssrf_endpoints: list[SsrfEndpoint] = field(default_factory=list)
  xss_endpoints: list[ReflectiveEndpoint] = field(default_factory=list)
  ssti_endpoints: list[ReflectiveEndpoint] = field(default_factory=list)
  cmd_endpoints: list[ReflectiveEndpoint] = field(default_factory=list)
  header_endpoints: list[ReflectiveEndpoint] = field(default_factory=list)
  json_type_endpoints: list[JsonLookupEndpoint] = field(default_factory=list)

  @classmethod
  def from_dict(cls, d: dict) -> InjectionConfig:
    d = _checked_dict(cls, d)
    return cls(
      ssrf_endpoints=[SsrfEndpoint.from_dict(e) for e in d.get("ssrf_endpoints", [])],
      xss_endpoints=[ReflectiveEndpoint.from_dict(e) for e in d.get("xss_endpoints", [])],
      ssti_endpoints=[ReflectiveEndpoint.from_dict(e) for e in d.get("ssti_endpoints", [])],
      cmd_endpoints=[ReflectiveEndpoint.from_dict(e) for e in d.get("cmd_endpoints", [])],
      header_endpoints=[ReflectiveEndpoint.from_dict(e) for e in d.get("header_endpoints", [])],
      json_type_endpoints=[JsonLookupEndpoint.from_dict(e) for e in d.get("json_type_endpoints", [])],
    )


@dataclass(frozen=True)
class RecordEndpoint:
  """Endpoint for business logic validation testing (PT-A06-02)."""
  path: str                                  # e.g. "/records/{id}/"
  method: str = "POST"
  amount_field: str = "amount"               # field name for monetary amount
  status_field: str = "status"               # field name for status/state
  valid_transitions: dict[str, list[str]] = field(default_factory=dict)  # e.g. {"draft": ["submitted"]}

  @classmethod
  def from_dict(cls, d: dict) -> RecordEndpoint:
    d = _checked_dict(cls, d)
    return cls(
      path=d["path"],
      method=d.get("method", "POST"),
      amount_field=d.get("amount_field", "amount"),
      status_field=d.get("status_field", "status"),
      valid_transitions=d.get("valid_transitions", {}),
    )


@dataclass(frozen=True)
class BusinessLogicConfig:
  """Config for business logic probes (A06)."""
  workflow_endpoints: list[WorkflowEndpoint] = field(default_factory=list)
  record_endpoints: list[RecordEndpoint] = field(default_factory=list)

  @classmethod
  def from_dict(cls, d: dict) -> BusinessLogicConfig:
    d = _checked_dict(cls, d)
    return cls(
      workflow_endpoints=[WorkflowEndpoint.from_dict(e) for e in d.get("workflow_endpoints", [])],
      record_endpoints=[RecordEndpoint.from_dict(e) for e in d.get("record_endpoints", [])],
    )


@dataclass(frozen=True)
class DiscoveryConfig:
  """Config for route/form discovery."""
  scope_prefix: str = ""                  # e.g. "/api/" — only crawl under this path
  max_pages: int = 50                     # max pages to crawl
  max_depth: int = 3                      # max link-follow depth

  @classmethod
  def from_dict(cls, d: dict) -> DiscoveryConfig:
    d = _checked_dict(cls, d)
    return cls(
      scope_prefix=d.get("scope_prefix", ""),
      max_pages=d.get("max_pages", 50),
      max_depth=d.get("max_depth", 3),
    )


# ── OWASP API Top 10 2023 endpoint configs ──────────────────────────────
#
# Used by the five API probe families introduced in v1
# (`api_access`, `api_auth`, `api_data`, `api_config`, `api_abuse`).
# See `docs/adr/2026-05-12-scenario-id-convention.md` and the plan at
# `_todos/2026-05-12-graybox-api-top10-plan-detailed.md` (Subphase 1.1).
#
# `ApiOutboundEndpoint` is deliberately absent — API10 is deferred to
# Phase 9 (callback-receiver infrastructure required).

@dataclass(frozen=True)
class ApiObjectEndpoint:
  """API object endpoint for BOLA testing (PT-OAPI1-01).

  Probe iterates ``test_ids`` against ``path`` (a template containing
  ``{id_param}``), as `regular_session`, expects ownership mismatch.
  """
  path: str                                  # e.g. "/api/records/{id}/"
  test_ids: list[int] = field(default_factory=lambda: [1, 2])
  owner_field: str = "owner"
  id_param: str = "id"
  tenant_field: str = ""                    # optional, for cross-tenant BOLA
  expected_owner: str = ""                  # expected low-privilege owner value
  expected_tenant: str = ""                 # expected low-privilege tenant value

  @classmethod
  def from_dict(cls, d: dict) -> ApiObjectEndpoint:
    d = _checked_dict(cls, d)
    return cls(
      path=d["path"],
      test_ids=d.get("test_ids", [1, 2]),
      owner_field=d.get("owner_field", "owner"),
      id_param=d.get("id_param", "id"),
      tenant_field=d.get("tenant_field", ""),
      expected_owner=d.get("expected_owner", ""),
      expected_tenant=d.get("expected_tenant", ""),
    )


@dataclass(frozen=True)
class ApiPropertyEndpoint:
  """API property endpoint for BOPLA testing (PT-OAPI3-01 read, PT-OAPI3-02 write).

  Read probe scans the JSON response for sensitive field names. Write
  probe (stateful) attempts to set extra fields from ``tampering_fields``
  on the object identified by ``test_id`` and verifies via re-GET.
  """
  path: str                                  # e.g. "/api/profile/{id}/"
  method_read: str = "GET"
  method_write: str = "PATCH"
  test_id: int = 1                           # designated object for write test
  id_param: str = "id"

  @classmethod
  def from_dict(cls, d: dict) -> ApiPropertyEndpoint:
    d = _checked_dict(cls, d)
    return cls(
      path=d["path"],
      method_read=d.get("method_read", "GET"),
      method_write=d.get("method_write", "PATCH"),
      test_id=d.get("test_id", 1),
      id_param=d.get("id_param", "id"),
    )


@dataclass(frozen=True)
class ApiFunctionEndpoint:
  """API function endpoint for BFLA testing (PT-OAPI5-01..04).

  ``method == "GET"`` entries are tested read-only in Phase 2.3
  (PT-OAPI5-01 / PT-OAPI5-02). Non-GET entries require both
  ``allow_stateful_probes=True`` AND ``revert_path``/``revert_body``
  (Phase 3.4, PT-OAPI5-03 / PT-OAPI5-04, stateful contract).
  """
  path: str                                  # e.g. "/api/admin/users/{uid}/promote/"
  method: str = "GET"
  privilege: str = "admin"                  # "admin", "user", "anon"
  auth_required_marker: str = ""            # body substring expected on 401/403
  revert_path: str = ""                     # e.g. ".../demote/" — required for stateful
  revert_body: dict = field(default_factory=dict)
  allow_malformed_json_probe: bool = False  # opt-in for PT-OAPI8-04 malformed JSON POST

  @classmethod
  def from_dict(cls, d: dict) -> ApiFunctionEndpoint:
    d = _checked_dict(cls, d)
    _reject_inline_secrets(
      d.get("revert_body", {}),
      "ApiFunctionEndpoint.revert_body",
    )
    return cls(
      path=d["path"],
      method=d.get("method", "GET"),
      privilege=d.get("privilege", "admin"),
      auth_required_marker=d.get("auth_required_marker", ""),
      revert_path=d.get("revert_path", ""),
      revert_body=d.get("revert_body", {}),
      allow_malformed_json_probe=d.get("allow_malformed_json_probe", False),
    )


@dataclass(frozen=True)
class ApiResourceEndpoint:
  """API resource endpoint for bounded resource-consumption testing (PT-OAPI4-*).

  Bounded by construction — no stress testing. Total requests across the
  family stop at ``max_total_requests`` (per scan, see ApiSecurityConfig)
  or earlier if a 429 is observed.

  ``rate_limit_expected`` defaults to False — only set True when the
  endpoint is genuinely supposed to be rate-limited; otherwise the
  PT-OAPI4-03 (no-rate-limit) probe will produce noisy false positives.
  """
  path: str                                  # e.g. "/api/records/list/"
  limit_param: str = "limit"
  baseline_limit: int = 10
  abuse_limit: int = 999_999
  rate_limit_expected: bool = False
  allow_high_limit_probe: bool = False
  allow_oversized_payload_probe: bool = False
  oversized_payload_bytes: int = 65_536

  @classmethod
  def from_dict(cls, d: dict) -> ApiResourceEndpoint:
    d = _checked_dict(cls, d)
    return cls(
      path=d["path"],
      limit_param=d.get("limit_param", "limit"),
      baseline_limit=d.get("baseline_limit", 10),
      abuse_limit=d.get("abuse_limit", 999_999),
      rate_limit_expected=d.get("rate_limit_expected", False),
      allow_high_limit_probe=d.get("allow_high_limit_probe", False),
      allow_oversized_payload_probe=d.get("allow_oversized_payload_probe", False),
      oversized_payload_bytes=d.get("oversized_payload_bytes", 65_536),
    )


@dataclass(frozen=True)
class ApiBusinessFlow:
  """Sensitive business-flow endpoint for abuse testing (PT-OAPI6-*).

  All checks are stateful by definition — they create or replay data.
  ``test_account`` is a tester-supplied non-privileged identity used so
  the official user is never touched by abuse probes.
  """
  path: str                                  # e.g. "/api/auth/signup/"
  method: str = "POST"
  flow_name: str = "signup"                 # "signup", "password_reset", "purchase", etc.
  body_template: dict = field(default_factory=dict)
  verify_path: str = ""                     # endpoint to verify duplicate creation
  verify_method: str = "GET"
  revert_path: str = ""                     # cleanup endpoint required before mutation
  revert_method: str = "POST"
  revert_body: dict = field(default_factory=dict)
  test_account: str = ""                    # non-privileged identity used during abuse test
  allow_static_test_account_body: bool = False
  captcha_marker: str = ""                  # body substring indicating CAPTCHA challenge
  mfa_marker: str = ""                      # body substring indicating MFA challenge

  @classmethod
  def from_dict(cls, d: dict) -> ApiBusinessFlow:
    d = _checked_dict(cls, d)
    _reject_inline_secrets(
      d.get("body_template", {}),
      "ApiBusinessFlow.body_template",
    )
    _reject_inline_secrets(
      d.get("revert_body", {}),
      "ApiBusinessFlow.revert_body",
    )
    return cls(
      path=d["path"],
      method=d.get("method", "POST"),
      flow_name=d.get("flow_name", "signup"),
      body_template=d.get("body_template", {}),
      verify_path=d.get("verify_path", ""),
      verify_method=d.get("verify_method", "GET"),
      revert_path=d.get("revert_path", ""),
      revert_method=d.get("revert_method", "POST"),
      revert_body=d.get("revert_body", {}),
      test_account=d.get("test_account", ""),
      allow_static_test_account_body=d.get("allow_static_test_account_body", False),
      captcha_marker=d.get("captcha_marker", ""),
      mfa_marker=d.get("mfa_marker", ""),
    )


@dataclass(frozen=True)
class ApiTokenEndpoint:
  """Token endpoint for broken-auth testing (PT-OAPI2-01..03).

  ``token_path`` issues a JWT given credentials; ``protected_path`` accepts
  it. ``logout_path`` is required for PT-OAPI2-03 (logout-doesn't-invalidate,
  stateful — revert is re-authentication).

  ``weak_secret_candidates`` is an inline dictionary used by PT-OAPI2-02.
  Defaults are deliberately tiny — extend per engagement, or use a
  Phase 9 wordlist follow-up.
  """
  token_path: str = ""                       # e.g. "/api/token/"
  protected_path: str = ""                   # e.g. "/api/me/"
  logout_path: str = ""                      # e.g. "/api/auth/logout/" — required for PT-OAPI2-03
  token_request_method: str = "POST"
  token_request_body: dict = field(default_factory=dict)
  token_response_field: str = ""
  weak_secret_candidates: list[str] = field(default_factory=lambda: [
    "secret", "changeme", "password", "1234567890",
    "jwt", "key", "topsecret", "default",
  ])

  @classmethod
  def from_dict(cls, d: dict) -> ApiTokenEndpoint:
    d = _checked_dict(cls, d)
    _reject_inline_secrets(
      d.get("token_request_body", {}),
      "ApiTokenEndpoint.token_request_body",
    )
    defaults = cls.__dataclass_fields__["weak_secret_candidates"].default_factory()
    return cls(
      token_path=d.get("token_path", ""),
      protected_path=d.get("protected_path", ""),
      logout_path=d.get("logout_path", ""),
      token_request_method=d.get("token_request_method", "POST"),
      token_request_body=d.get("token_request_body", {}),
      token_response_field=d.get("token_response_field", ""),
      weak_secret_candidates=d.get("weak_secret_candidates", defaults),
    )


@dataclass(frozen=True)
class ApiInventoryPaths:
  """Inventory-related paths for API9 testing.

  ``openapi_candidates`` are probed by PT-OAPI9-01 looking for an exposed
  OpenAPI/Swagger document. ``current_version`` + sibling probing drives
  PT-OAPI9-02 (version sprawl); ``deprecated_paths`` drives PT-OAPI9-03.
  ``private_path_patterns`` is used as the substring/glob set indicating
  paths in the spec that shouldn't be publicly exposed.
  """
  openapi_candidates: list[str] = field(default_factory=lambda: [
    "/openapi.json", "/swagger.json", "/v3/api-docs",
    "/api/swagger.json", "/api-docs", "/swagger-ui.html",
  ])
  current_version: str = ""                  # e.g. "/api/v2/"
  version_sibling_candidates: list[str] = field(default_factory=lambda: [
    "/api/v1/", "/api/v0/", "/api/beta/", "/api/internal/", "/api/legacy/",
  ])
  canonical_probe_path: str = ""             # canonical endpoint under current_version used to verify a sibling responds
  private_path_patterns: list[str] = field(default_factory=list)
  deprecated_paths: list[str] = field(default_factory=list)

  @classmethod
  def from_dict(cls, d: dict) -> ApiInventoryPaths:
    d = _checked_dict(cls, d)
    fields_ = cls.__dataclass_fields__
    return cls(
      openapi_candidates=d.get(
        "openapi_candidates",
        fields_["openapi_candidates"].default_factory(),
      ),
      current_version=d.get("current_version", ""),
      version_sibling_candidates=d.get(
        "version_sibling_candidates",
        fields_["version_sibling_candidates"].default_factory(),
      ),
      canonical_probe_path=d.get("canonical_probe_path", ""),
      private_path_patterns=d.get("private_path_patterns", []),
      deprecated_paths=d.get("deprecated_paths", []),
    )


@dataclass(frozen=True)
class AuthDescriptor:
  """Non-secret auth configuration for graybox session establishment.

  Secret values (`bearer_token`, `api_key`, `bearer_refresh_token`) are
  **never** carried in this object or anywhere inside ``target_config``.
  They travel as top-level launch parameters and are stored in the R1FS
  secret payload — see Subphase 1.5 commit #8.

  Fields:
    auth_type: Selects the AuthStrategy at runtime. ``form`` is the
               default and keeps existing behaviour. ``bearer`` and
               ``api_key`` add API-native auth in Subphase 1.5.
    bearer_token_header_name: HTTP header used for Bearer tokens. Default
               ``Authorization``; rare APIs use ``X-Auth-Token`` etc.
    bearer_scheme: Scheme prefix for Bearer tokens. Default ``Bearer``;
               some APIs use ``Token`` or empty (raw token).
    bearer_refresh_url: Optional. If set, BearerAuth will POST here to
               refresh an expired token (Phase 9 OAuth2 will replace this
               with a proper grant flow).
    api_key_header_name: Header name for API-key auth, e.g. ``X-Api-Key``.
    api_key_query_param: Query-parameter name for API-key auth when
               ``api_key_location='query'``.
    api_key_location: ``header`` (default) or ``query``. Query is allowed
               for legacy APIs only; evidence scrubbers will redact the
               configured param name from URLs at the finding boundary.
    authenticated_probe_path: Path used by strategy preflight when
               ``auth_type != 'form'`` to verify the credentials work
               before any probe runs (e.g. ``/api/me``).
    authenticated_probe_method: HTTP method for authenticated validation.
               Defaults to GET because many APIs reject HEAD even when
               credentials are valid.
    api_logout_path: Optional explicit logout endpoint for API-native
               sessions. Form scans continue using ``logout_path``.
  """
  auth_type: str = "form"   # "form" | "bearer" | "api_key"
  bearer_token_header_name: str = "Authorization"
  bearer_scheme: str = "Bearer"
  bearer_refresh_url: str = ""
  api_key_header_name: str = "X-Api-Key"
  api_key_query_param: str = "api_key"
  api_key_location: str = "header"  # "header" | "query"
  authenticated_probe_path: str = ""
  authenticated_probe_method: str = "GET"
  api_logout_path: str = ""

  @classmethod
  def from_dict(cls, d: dict) -> AuthDescriptor:
    d = _checked_dict(cls, d)
    return cls(
      auth_type=d.get("auth_type", "form"),
      bearer_token_header_name=d.get("bearer_token_header_name", "Authorization"),
      bearer_scheme=d.get("bearer_scheme", "Bearer"),
      bearer_refresh_url=d.get("bearer_refresh_url", ""),
      api_key_header_name=d.get("api_key_header_name", "X-Api-Key"),
      api_key_query_param=d.get("api_key_query_param", "api_key"),
      api_key_location=d.get("api_key_location", "header"),
      authenticated_probe_path=d.get("authenticated_probe_path", ""),
      authenticated_probe_method=d.get("authenticated_probe_method", "GET"),
      api_logout_path=d.get("api_logout_path", ""),
    )


@dataclass(frozen=True)
class ApiSecurityConfig:
  """Aggregated config for the five OWASP API Top 10 graybox probe families.

  Probes draw from exactly the section they own:
    - api_access  → object_endpoints (BOLA), function_endpoints (BFLA)
    - api_auth    → token_endpoints (broken auth)
    - api_data    → property_endpoints (BOPLA read/write)
    - api_config  → inventory_paths, debug_path_candidates (misconfig/inventory)
    - api_abuse   → resource_endpoints, business_flows

  ``ssrf_body_fields`` extends the legacy PT-API7-01 SSRF probe (lives in
  injection.py, kept under its legacy ID) to scan JSON body fields by name.

  ``sensitive_field_patterns`` augments the built-in default patterns used
  by PT-OAPI3-01 (excessive property exposure). Entries are merged with,
  not replacing, the defaults.

  ``tampering_fields`` lists property names PT-OAPI3-02 will attempt to set
  via mass assignment.

  Auth descriptor (`auth`) and per-scan request budget
  (`max_total_requests`) land in Subphases 1.5 and 1.7 respectively;
  added here as future hooks would couple this subphase to those.
  """
  object_endpoints: list[ApiObjectEndpoint] = field(default_factory=list)
  property_endpoints: list[ApiPropertyEndpoint] = field(default_factory=list)
  function_endpoints: list[ApiFunctionEndpoint] = field(default_factory=list)
  resource_endpoints: list[ApiResourceEndpoint] = field(default_factory=list)
  business_flows: list[ApiBusinessFlow] = field(default_factory=list)
  token_endpoints: ApiTokenEndpoint = field(default_factory=ApiTokenEndpoint)
  inventory_paths: ApiInventoryPaths = field(default_factory=ApiInventoryPaths)
  auth: AuthDescriptor = field(default_factory=AuthDescriptor)

  ssrf_body_fields: list[str] = field(default_factory=lambda: [
    "url", "webhook", "callback", "image_url", "redirect_uri",
  ])
  sensitive_field_patterns: list[str] = field(default_factory=list)
  tampering_fields: list[str] = field(default_factory=lambda: [
    "is_admin", "is_superuser", "role", "verified", "email_verified",
    "tenant_id", "owner_id", "balance",
  ])
  debug_path_candidates: list[str] = field(default_factory=lambda: [
    "/debug", "/api/debug", "/api/_routes",
    "/actuator", "/actuator/env", "/q/dev", "/__debug__",
  ])
  # OWASP API Top 10 — Subphase 1.7. Per-scan request budget cap. Each
  # `ProbeBase.budget()` call decrements a shared `RequestBudget`; once
  # exhausted, probes emit `inconclusive` with reason `budget_exhausted`
  # rather than continuing to issue requests.
  max_total_requests: int = 1000

  @classmethod
  def from_dict(cls, d: dict) -> ApiSecurityConfig:
    d = _checked_dict(cls, d)
    fields_ = cls.__dataclass_fields__
    return cls(
      object_endpoints=[ApiObjectEndpoint.from_dict(e) for e in d.get("object_endpoints", [])],
      property_endpoints=[ApiPropertyEndpoint.from_dict(e) for e in d.get("property_endpoints", [])],
      function_endpoints=[ApiFunctionEndpoint.from_dict(e) for e in d.get("function_endpoints", [])],
      resource_endpoints=[ApiResourceEndpoint.from_dict(e) for e in d.get("resource_endpoints", [])],
      business_flows=[ApiBusinessFlow.from_dict(e) for e in d.get("business_flows", [])],
      token_endpoints=ApiTokenEndpoint.from_dict(d.get("token_endpoints", {})),
      inventory_paths=ApiInventoryPaths.from_dict(d.get("inventory_paths", {})),
      auth=AuthDescriptor.from_dict(d.get("auth", {})),
      ssrf_body_fields=d.get(
        "ssrf_body_fields",
        fields_["ssrf_body_fields"].default_factory(),
      ),
      sensitive_field_patterns=d.get("sensitive_field_patterns", []),
      tampering_fields=d.get(
        "tampering_fields",
        fields_["tampering_fields"].default_factory(),
      ),
      debug_path_candidates=d.get(
        "debug_path_candidates",
        fields_["debug_path_candidates"].default_factory(),
      ),
      max_total_requests=d.get("max_total_requests", 1000),
    )


# ── Main config ─────────────────────────────────────────────────────────

@dataclass(frozen=True)
class GrayboxTargetConfig:
  """
  Application-specific endpoint mapping for graybox probes.

  Sectioned by probe category. Each probe reads only its section,
  and adding a new probe's config doesn't bloat unrelated sections.
  Endpoint entries use typed dataclasses — typos in keys raise at
  construction time, not at runtime deep inside a probe.

  Passed to the worker via JobConfig.target_config (serialized dict).
  """
  # Per-probe sections (E4)
  access_control: AccessControlConfig = field(default_factory=AccessControlConfig)
  misconfig: MisconfigConfig = field(default_factory=MisconfigConfig)
  injection: InjectionConfig = field(default_factory=InjectionConfig)
  business_logic: BusinessLogicConfig = field(default_factory=BusinessLogicConfig)
  discovery: DiscoveryConfig = field(default_factory=DiscoveryConfig)
  api_security: ApiSecurityConfig = field(default_factory=ApiSecurityConfig)

  # Login endpoint configuration (shared across probes)
  login_path: str = "/auth/login/"
  logout_path: str = "/auth/logout/"
  password_reset_path: str = ""           # e.g. "/auth/password-reset/request/"
  password_reset_confirm_path: str = ""   # e.g. "/auth/password-reset/confirm/"
  username_field: str = "username"
  password_field: str = "password"
  csrf_field: str = ""                    # empty = auto-detect from COMMON_CSRF_FIELDS

  def to_dict(self) -> dict:
    return {k: v for k, v in asdict(self).items() if v is not None}

  @classmethod
  def from_dict(cls, d: dict) -> GrayboxTargetConfig:
    d = _checked_dict(cls, d)
    return cls(
      access_control=AccessControlConfig.from_dict(d.get("access_control", {})),
      misconfig=MisconfigConfig.from_dict(d.get("misconfig", {})),
      injection=InjectionConfig.from_dict(d.get("injection", {})),
      business_logic=BusinessLogicConfig.from_dict(d.get("business_logic", {})),
      discovery=DiscoveryConfig.from_dict(d.get("discovery", {})),
      api_security=ApiSecurityConfig.from_dict(d.get("api_security", {})),
      login_path=d.get("login_path", "/auth/login/"),
      logout_path=d.get("logout_path", "/auth/logout/"),
      password_reset_path=d.get("password_reset_path", ""),
      password_reset_confirm_path=d.get("password_reset_confirm_path", ""),
      username_field=d.get("username_field", "username"),
      password_field=d.get("password_field", "password"),
      csrf_field=d.get("csrf_field", ""),
    )
