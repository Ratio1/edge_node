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
