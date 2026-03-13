from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class GrayboxCredential:
  username: str = ""
  password: str = ""

  @property
  def is_configured(self) -> bool:
    return bool(self.username)

  def to_dict(self) -> dict:
    return {
      "username": self.username,
      "password": self.password,
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
    if getattr(job_config, "regular_username", ""):
      regular = GrayboxCredential(
        username=getattr(job_config, "regular_username", "") or "",
        password=getattr(job_config, "regular_password", "") or "",
      )
    return cls(
      official=GrayboxCredential(
        username=getattr(job_config, "official_username", "") or "",
        password=getattr(job_config, "official_password", "") or "",
      ),
      regular=regular,
      weak_candidates=list(getattr(job_config, "weak_candidates", None) or []),
      max_weak_attempts=int(getattr(job_config, "max_weak_attempts", 5) or 5),
    )


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
  outcome: str = "completed"

  @classmethod
  def from_value(cls, value, default_outcome: str = "completed") -> "GrayboxProbeRunResult":
    if isinstance(value, GrayboxProbeRunResult):
      return value
    return cls(
      findings=list(value or []),
      outcome=default_outcome,
    )
