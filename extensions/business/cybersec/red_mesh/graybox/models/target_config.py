"""
Application-specific endpoint mapping for graybox probes.

Sectioned by probe category (E4). Each probe reads only its section.
Endpoint entries use typed dataclasses — typos in keys raise at
construction time, not at runtime deep inside a probe.

Passed to the worker via JobConfig.target_config (serialized dict).
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any


# Common CSRF field names across frameworks (C5)
COMMON_CSRF_FIELDS = [
  "csrfmiddlewaretoken",  # Django
  "csrf_token",           # Flask / WTForms
  "authenticity_token",   # Rails
  "_csrf",                # Spring Security
  "_token",               # Laravel
]


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
    return cls(path=d["path"], param=d.get("param", "url"))


# ── Probe-sectioned config (E4) ─────────────────────────────────────────

@dataclass(frozen=True)
class AccessControlConfig:
  """Config for access control probes (A01)."""
  idor_endpoints: list[IdorEndpoint] = field(default_factory=list)
  admin_endpoints: list[AdminEndpoint] = field(default_factory=list)

  @classmethod
  def from_dict(cls, d: dict) -> AccessControlConfig:
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
    return cls(
      debug_paths=d.get("debug_paths", cls.__dataclass_fields__["debug_paths"].default_factory()),
      jwt_endpoints=JwtEndpoint.from_dict(d.get("jwt_endpoints", {})),
    )


@dataclass(frozen=True)
class InjectionConfig:
  """Config for injection probes (A03/A05/API7)."""
  ssrf_endpoints: list[SsrfEndpoint] = field(default_factory=list)

  @classmethod
  def from_dict(cls, d: dict) -> InjectionConfig:
    return cls(
      ssrf_endpoints=[SsrfEndpoint.from_dict(e) for e in d.get("ssrf_endpoints", [])],
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
    return cls(
      scope_prefix=d.get("scope_prefix", ""),
      max_pages=d.get("max_pages", 50),
      max_depth=d.get("max_depth", 3),
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
    return cls(
      access_control=AccessControlConfig.from_dict(d.get("access_control", {})),
      misconfig=MisconfigConfig.from_dict(d.get("misconfig", {})),
      injection=InjectionConfig.from_dict(d.get("injection", {})),
      business_logic=BusinessLogicConfig.from_dict(d.get("business_logic", {})),
      discovery=DiscoveryConfig.from_dict(d.get("discovery", {})),
      login_path=d.get("login_path", "/auth/login/"),
      logout_path=d.get("logout_path", "/auth/logout/"),
      password_reset_path=d.get("password_reset_path", ""),
      password_reset_confirm_path=d.get("password_reset_confirm_path", ""),
      username_field=d.get("username_field", "username"),
      password_field=d.get("password_field", "password"),
      csrf_field=d.get("csrf_field", ""),
    )
