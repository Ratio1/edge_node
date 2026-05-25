"""Reset selected CAR fixed-size app data volumes."""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from extensions.business.container_apps.fixed_volume import safe_path_component
from extensions.business.container_apps.sync.constants import (
  STAGE_VALIDATION,
  SYSTEM_VOLUME_NAME,
)

from .constants import (
  RESET_APPLY_RESTART_NOW,
  RESET_MODE_VOLUMES,
  RESET_SCHEMA_VERSION,
  STAGE_RESTART,
)


class ResetValidationError(ValueError):
  """Raised when a reset request cannot be planned safely."""

  def __init__(self, message: str, *, request_id: Optional[str] = None):
    super().__init__(message)
    self.stage = STAGE_VALIDATION
    self.request_id = request_id


@dataclass(frozen=True)
class ResetVolumePlan:
  logical_name: str
  safe_name: str
  host_root: Path
  owner_uid: Optional[int]
  owner_gid: Optional[int]
  mode: int


@dataclass(frozen=True)
class ResetRequestPlan:
  request_id: Optional[str]
  mode: str
  apply: str
  volumes: tuple[ResetVolumePlan, ...]

  def volume_names(self) -> list[str]:
    return [volume.logical_name for volume in self.volumes]


@dataclass(frozen=True)
class ResetApplyResult:
  request_id: Optional[str]
  volumes: tuple[str, ...]
  cleared_count: int
  restart_started: bool
  restart_error: Optional[str] = None

  def to_response(self) -> dict:
    status = "ok" if self.restart_started else "error"
    response = {
      "schema_version": RESET_SCHEMA_VERSION,
      "status": status,
      "mode": RESET_MODE_VOLUMES,
      "apply": RESET_APPLY_RESTART_NOW,
      "reset": {
        "status": "ok",
        "volumes": list(self.volumes),
        "cleared_count": self.cleared_count,
        "preserved": {
          "env_overrides": True,
        },
      },
      "restart": {
        "requested": True,
        "started": self.restart_started,
        "error": self.restart_error,
      },
    }
    if not self.restart_started:
      response["stage"] = STAGE_RESTART
      response["error"] = self.restart_error or "container restart failed"
    if self.request_id is not None:
      response["request_id"] = self.request_id
    return response


class ResetManager:
  """Validate and execute fixed-size volume reset requests."""

  def __init__(self, owner):
    self.owner = owner

  # ----- planning --------------------------------------------------------

  def plan_request(self, request_body: dict) -> ResetRequestPlan:
    if not isinstance(request_body, dict):
      raise ResetValidationError("request body must be a JSON object")

    request_id = self._request_id_from_body(request_body)
    if "request_id" in request_body and request_id is None:
      raise ResetValidationError("request_id must be a string")

    if request_body.get("schema_version") != RESET_SCHEMA_VERSION:
      raise ResetValidationError(
        f"schema_version must be {RESET_SCHEMA_VERSION}",
        request_id=request_id,
      )

    mode = request_body.get("mode")
    if mode != RESET_MODE_VOLUMES:
      raise ResetValidationError(
        f"mode must be {RESET_MODE_VOLUMES!r}",
        request_id=request_id,
      )

    apply_mode = request_body.get("apply", RESET_APPLY_RESTART_NOW)
    if apply_mode != RESET_APPLY_RESTART_NOW:
      raise ResetValidationError(
        f"apply must be {RESET_APPLY_RESTART_NOW!r}",
        request_id=request_id,
      )

    preserve = request_body.get("preserve", {})
    if preserve is None:
      preserve = {}
    if not isinstance(preserve, dict):
      raise ResetValidationError("preserve must be a JSON object", request_id=request_id)
    if preserve.get("env_overrides", True) is not True:
      raise ResetValidationError(
        "preserve.env_overrides is always true in v1",
        request_id=request_id,
      )

    configured = self._configured_fixed_size_volumes(request_id)
    requested = self._requested_volume_names(request_body, configured, request_id)
    volumes = tuple(
      self._resolve_volume(logical_name, configured[logical_name], request_id)
      for logical_name in requested
    )
    if not volumes:
      raise ResetValidationError(
        "no resettable fixed-size volumes selected",
        request_id=request_id,
      )

    return ResetRequestPlan(
      request_id=request_id,
      mode=mode,
      apply=apply_mode,
      volumes=volumes,
    )

  def _configured_fixed_size_volumes(self, request_id: Optional[str]) -> dict:
    cfg = getattr(self.owner, "cfg_fixed_size_volumes", None)
    if not isinstance(cfg, dict) or not cfg:
      raise ResetValidationError(
        "no FIXED_SIZE_VOLUMES are configured",
        request_id=request_id,
      )
    configured = {}
    for logical_name, volume_cfg in cfg.items():
      if not isinstance(logical_name, str) or not logical_name:
        continue
      if not isinstance(volume_cfg, dict):
        continue
      configured[logical_name] = volume_cfg
    if not configured:
      raise ResetValidationError(
        "no valid FIXED_SIZE_VOLUMES are configured",
        request_id=request_id,
      )
    return configured

  def _requested_volume_names(
    self,
    request_body: dict,
    configured: dict,
    request_id: Optional[str],
  ) -> list[str]:
    raw_volumes = request_body.get("volumes")
    if raw_volumes is None:
      return sorted(configured.keys())
    if not isinstance(raw_volumes, list):
      raise ResetValidationError("volumes must be a list", request_id=request_id)
    if not raw_volumes:
      raise ResetValidationError("volumes must not be empty", request_id=request_id)

    names = []
    seen = set()
    for raw_name in raw_volumes:
      if not isinstance(raw_name, str):
        raise ResetValidationError(
          "volume names must be strings",
          request_id=request_id,
        )
      if self._is_path_like(raw_name):
        raise ResetValidationError(
          f"volume name must be a logical FIXED_SIZE_VOLUMES key, not a path: {raw_name!r}",
          request_id=request_id,
        )
      if raw_name not in configured:
        raise ResetValidationError(
          f"unknown fixed-size volume: {raw_name}",
          request_id=request_id,
        )
      if raw_name not in seen:
        seen.add(raw_name)
        names.append(raw_name)
    return names

  @staticmethod
  def _is_path_like(name: str) -> bool:
    if not name or name in (".", ".."):
      return True
    if "/" in name or "\\" in name:
      return True
    return ".." in name

  def _resolve_volume(
    self,
    logical_name: str,
    volume_cfg: dict,
    request_id: Optional[str],
  ) -> ResetVolumePlan:
    safe_name = safe_path_component(logical_name)
    if safe_name in ("_", SYSTEM_VOLUME_NAME):
      raise ResetValidationError(
        f"unsafe fixed-size volume name: {logical_name!r}",
        request_id=request_id,
      )

    fixed_volume = self._active_fixed_volume(safe_name)
    if fixed_volume is None:
      raise ResetValidationError(
        f"fixed-size volume is not active: {logical_name}",
        request_id=request_id,
      )

    host_root = Path(fixed_volume.mount_path)
    self._validate_volume_root(host_root, safe_name, request_id)
    st = os.lstat(str(host_root))
    if not stat.S_ISDIR(st.st_mode):
      raise ResetValidationError(
        f"fixed-size volume root is not a directory: {logical_name}",
        request_id=request_id,
      )
    if stat.S_ISLNK(st.st_mode):
      raise ResetValidationError(
        f"fixed-size volume root is a symlink: {logical_name}",
        request_id=request_id,
      )

    return ResetVolumePlan(
      logical_name=logical_name,
      safe_name=safe_name,
      host_root=host_root,
      owner_uid=getattr(fixed_volume, "owner_uid", None),
      owner_gid=getattr(fixed_volume, "owner_gid", None),
      mode=stat.S_IMODE(st.st_mode),
    )

  def _active_fixed_volume(self, safe_name: str):
    for volume in getattr(self.owner, "_fixed_volumes", []) or []:
      if getattr(volume, "name", None) == safe_name:
        return volume
    return None

  def _validate_volume_root(
    self,
    host_root: Path,
    safe_name: str,
    request_id: Optional[str],
  ) -> None:
    mounts_root = (
      Path(self.owner.get_data_folder())
      / self.owner._get_instance_data_subfolder()
      / "fixed_volumes"
      / "mounts"
    )
    resolved_mounts = mounts_root.resolve()
    resolved_root = host_root.resolve()
    if resolved_root == resolved_mounts:
      raise ResetValidationError("refusing to reset fixed_volumes mount root", request_id=request_id)
    if resolved_root.name != safe_name:
      raise ResetValidationError(
        f"fixed-size volume root name mismatch for {safe_name}",
        request_id=request_id,
      )
    if not str(resolved_root).startswith(str(resolved_mounts) + os.sep):
      raise ResetValidationError(
        f"fixed-size volume root escapes CAR data directory: {safe_name}",
        request_id=request_id,
      )

  # ----- execution -------------------------------------------------------

  def reset_volumes(self, plan: ResetRequestPlan) -> int:
    cleared = 0
    for volume in plan.volumes:
      self._validate_volume_root(volume.host_root, volume.safe_name, plan.request_id)
      if not volume.host_root.is_dir() or volume.host_root.is_symlink():
        raise RuntimeError(f"reset target is no longer a real directory: {volume.logical_name}")
      cleared += self._clear_directory_contents(volume.host_root)
      self._restore_root_metadata(volume)
    return cleared

  def _clear_directory_contents(self, root: Path) -> int:
    cleared = 0
    for child in list(root.iterdir()):
      self._remove_entry_no_follow(child)
      cleared += 1
    return cleared

  def _remove_entry_no_follow(self, path: Path) -> None:
    st = os.lstat(str(path))
    if stat.S_ISDIR(st.st_mode):
      for child in list(path.iterdir()):
        self._remove_entry_no_follow(child)
      os.rmdir(str(path))
      return
    os.unlink(str(path))

  def _restore_root_metadata(self, volume: ResetVolumePlan) -> None:
    os.chmod(str(volume.host_root), volume.mode)
    if volume.owner_uid is not None or volume.owner_gid is not None:
      uid = volume.owner_uid if volume.owner_uid is not None else -1
      gid = volume.owner_gid if volume.owner_gid is not None else -1
      os.chown(str(volume.host_root), uid, gid)

  # ----- responses -------------------------------------------------------

  def validation_error_response(self, exc: ResetValidationError) -> dict:
    response = {
      "schema_version": RESET_SCHEMA_VERSION,
      "status": "error",
      "stage": exc.stage,
      "error": str(exc),
    }
    if exc.request_id is not None:
      response["request_id"] = exc.request_id
    return response

  @staticmethod
  def _request_id_from_body(request_body: Optional[dict]) -> Optional[str]:
    if not isinstance(request_body, dict):
      return None
    request_id = request_body.get("request_id")
    return request_id if isinstance(request_id, str) else None


__all__ = [
  "ResetApplyResult",
  "ResetManager",
  "ResetRequestPlan",
  "ResetValidationError",
  "ResetVolumePlan",
]
