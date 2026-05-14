from __future__ import annotations

from dataclasses import dataclass, field

from ..auth_credentials import Credentials


@dataclass(frozen=True)
class GrayboxCredential:
  username: str = ""
  password: str = ""
  bearer_token: str = ""
  bearer_refresh_token: str = ""
  api_key: str = ""
  principal: str = "official"

  @property
  def is_configured(self) -> bool:
    return bool(self.username or self.bearer_token or self.api_key)

  def to_credentials(self) -> Credentials:
    return Credentials(
      username=self.username,
      password=self.password,
      bearer_token=self.bearer_token,
      bearer_refresh_token=self.bearer_refresh_token,
      api_key=self.api_key,
      principal=self.principal,
    )

  def to_dict(self) -> dict:
    return {
      "username": self.username,
      "has_password": bool(self.password),
      "has_bearer_token": bool(self.bearer_token),
      "has_bearer_refresh_token": bool(self.bearer_refresh_token),
      "has_api_key": bool(self.api_key),
      "principal": self.principal,
    }


@dataclass(frozen=True)
class GrayboxCredentialSet:
  official: GrayboxCredential
  regular: GrayboxCredential | None = None
  weak_candidates: list[str] = field(default_factory=list)
  max_weak_attempts: int = 5

  @classmethod
  def from_job_config(cls, job_config) -> GrayboxCredentialSet:
    regular = None
    if (
      getattr(job_config, "regular_username", "")
      or getattr(job_config, "regular_bearer_token", "")
      or getattr(job_config, "regular_api_key", "")
    ):
      regular = GrayboxCredential(
        username=getattr(job_config, "regular_username", "") or "",
        password=getattr(job_config, "regular_password", "") or "",
        bearer_token=getattr(job_config, "regular_bearer_token", "") or "",
        bearer_refresh_token=getattr(job_config, "regular_bearer_refresh_token", "") or "",
        api_key=getattr(job_config, "regular_api_key", "") or "",
        principal="regular",
      )
    return cls(
      official=GrayboxCredential(
        username=getattr(job_config, "official_username", "") or "",
        password=getattr(job_config, "official_password", "") or "",
        bearer_token=getattr(job_config, "bearer_token", "") or "",
        bearer_refresh_token=getattr(job_config, "bearer_refresh_token", "") or "",
        api_key=getattr(job_config, "api_key", "") or "",
        principal="official",
      ),
      regular=regular,
      weak_candidates=list(getattr(job_config, "weak_candidates", None) or []),
      max_weak_attempts=int(getattr(job_config, "max_weak_attempts", 5) or 5),
    )

  @staticmethod
  def weak_auth_enabled(job_config) -> bool:
    """Pure predicate: does this job_config enable weak-auth probing?

    Single source of truth for the "weak-auth will run" decision.
    Used by both the worker phase gate and live-progress phase
    resolution so the UI never reports a scan done while weak-auth
    still has work to do.
    """
    creds = GrayboxCredentialSet.from_job_config(job_config)
    excluded = set(getattr(job_config, "excluded_features", None) or [])
    return bool(creds.weak_candidates) and "_graybox_weak_auth" not in excluded


@dataclass(frozen=True)
class DiscoveryResult:
  routes: list[str] = field(default_factory=list)
  forms: list[str] = field(default_factory=list)

  def to_tuple(self) -> tuple[list[str], list[str]]:
    return self.routes, self.forms


@dataclass(frozen=True)
class GrayboxProbeContext:
  target_url: str
  auth_manager: object
  target_config: object
  safety: object
  discovered_routes: list[str] = field(default_factory=list)
  discovered_forms: list[str] = field(default_factory=list)
  regular_username: str = ""
  allow_stateful: bool = False
  # OWASP API Top 10 — Subphase 1.7. Reference (not value) to a shared
  # mutable RequestBudget. The frozen dataclass owns the binding; the
  # budget object itself mutates as probes consume.
  request_budget: object = None
  allowed_scenario_ids: tuple[str, ...] | None = None
  rollback_journal: object = None
  job_id: str = ""
  worker_id: str = ""
  assignment_revision: int = 0

  def to_kwargs(self) -> dict:
    return {
      "target_url": self.target_url,
      "auth_manager": self.auth_manager,
      "target_config": self.target_config,
      "safety": self.safety,
      "discovered_routes": list(self.discovered_routes),
      "discovered_forms": list(self.discovered_forms),
      "regular_username": self.regular_username,
      "allow_stateful": self.allow_stateful,
      "request_budget": self.request_budget,
      "allowed_scenario_ids": self.allowed_scenario_ids,
      "rollback_journal": self.rollback_journal,
      "job_id": self.job_id,
      "worker_id": self.worker_id,
      "assignment_revision": self.assignment_revision,
    }


@dataclass(frozen=True)
class GrayboxAuthState:
  created_at: float = 0.0
  refresh_count: int = 0
  official_authenticated: bool = False
  regular_authenticated: bool = False
  auth_errors: tuple[str, ...] = ()

  @property
  def has_authenticated_session(self) -> bool:
    return self.official_authenticated


@dataclass(frozen=True)
class GrayboxProbeDefinition:
  key: str
  cls_path: str

  @classmethod
  def from_entry(cls, entry) -> "GrayboxProbeDefinition":
    if isinstance(entry, GrayboxProbeDefinition):
      return entry
    return cls(
      key=entry["key"],
      cls_path=entry["cls"],
    )


@dataclass(frozen=True)
class GrayboxProbeRunResult:
  findings: list[object] = field(default_factory=list)
  artifacts: list[object] = field(default_factory=list)
  outcome: str = "completed"

  @classmethod
  def from_value(cls, value, default_outcome: str = "completed") -> "GrayboxProbeRunResult":
    if isinstance(value, GrayboxProbeRunResult):
      return value
    return cls(
      findings=list(value or []),
      outcome=default_outcome,
    )
