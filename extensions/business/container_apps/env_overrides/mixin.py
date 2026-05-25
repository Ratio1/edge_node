"""Mixin: local env override request/response integration for CAR."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional

from extensions.business.container_apps.sync.constants import (
  STAGE_VALIDATION,
  SYSTEM_VOLUME_MOUNT,
)
from extensions.business.container_apps.sync.control_files import (
  JsonControlFile,
  JsonControlFileClaimError,
  JsonControlFileDecodeError,
  JsonControlFileObjectError,
  JsonControlFileReadError,
  JsonControlFileUnsafeError,
)
from extensions.business.container_apps.sync.manager import system_volume_host_root

from .constants import (
  ENV_OVERRIDES_INVALID_FILE,
  ENV_OVERRIDES_PROCESSING_FILE,
  ENV_OVERRIDES_REQUEST_FILE,
  ENV_OVERRIDES_RESPONSE_FILE,
  ENV_OVERRIDES_SCHEMA_VERSION,
  ENV_OVERRIDES_SUBDIR,
)
from .manager import EnvOverrideManager


def env_overrides_dir(owner) -> Path:
  """Host-side path of the env-overrides control-plane subdir."""
  return system_volume_host_root(owner) / ENV_OVERRIDES_SUBDIR


class _EnvOverridesMixin:
  """File-protocol bridge for local CAR env override patches."""

  # ----- config ----------------------------------------------------------

  def _env_overrides_cfg(self) -> dict:
    cfg = getattr(self, "cfg_env_overrides", None)
    return cfg if isinstance(cfg, dict) else {}

  def _env_overrides_enabled(self) -> bool:
    cfg = self._env_overrides_cfg()
    if "ENABLED" not in cfg:
      return True
    return bool(cfg.get("ENABLED"))

  def _env_overrides_control_available(self) -> bool:
    return (
      self._env_overrides_enabled()
      and not getattr(self, "_sync_unavailable", False)
      and not getattr(self, "_env_overrides_unavailable", False)
    )

  # ----- manager ---------------------------------------------------------

  def _ensure_env_overrides_manager(self) -> Optional[EnvOverrideManager]:
    if not self._env_overrides_enabled():
      return None
    manager = getattr(self, "_env_overrides_manager", None)
    if manager is None:
      manager = EnvOverrideManager(self)
      self._env_overrides_manager = manager
    return manager

  # ----- system-volume subdir ------------------------------------------

  def _configure_env_overrides_control_dir(self):
    """Create the app-writable /r1en_system/env-overrides directory."""
    self._env_overrides_unavailable = False
    if not self._env_overrides_enabled():
      return
    if getattr(self, "_sync_unavailable", False):
      self._env_overrides_unavailable = True
      return

    eod = env_overrides_dir(self)
    try:
      try:
        st = os.lstat(str(eod))
      except FileNotFoundError:
        st = None
      if st is not None and (
        stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
      ):
        os.unlink(str(eod))
      os.makedirs(str(eod), exist_ok=True)
      st = os.lstat(str(eod))
      if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"{eod} is not a real directory")
    except Exception as exc:
      self.P(
        f"[env-overrides] control directory unsafe/unavailable: {exc}. "
        f"ENV_OVERRIDES request files will not be advertised.",
        color="r",
      )
      self._env_overrides_unavailable = True
      return

    try:
      os.chown(str(eod), 0, 0)
      os.chmod(str(eod), 0o1777)
    except OSError as exc:
      self.P(
        f"[env-overrides] could not enforce root-owned {eod} mode 0o1777: {exc}. "
        f"ENV_OVERRIDES request files will not be advertised.",
        color="r",
      )
      self._env_overrides_unavailable = True
      return

  # ----- env-var injection ----------------------------------------------

  def _inject_env_overrides_env_vars(self):
    if not isinstance(getattr(self, "env", None), dict):
      return
    if not self._env_overrides_control_available():
      return
    control_dir = f"{SYSTEM_VOLUME_MOUNT}/{ENV_OVERRIDES_SUBDIR}"
    self.env["R1_ENV_OVERRIDES_DIR"] = control_dir
    self.env["R1_ENV_OVERRIDES_REQUEST_FILE"] = (
      f"{control_dir}/{ENV_OVERRIDES_REQUEST_FILE}"
    )
    self.env["R1_ENV_OVERRIDES_RESPONSE_FILE"] = (
      f"{control_dir}/{ENV_OVERRIDES_RESPONSE_FILE}"
    )

  def _apply_env_overrides_to_env(self):
    manager = self._ensure_env_overrides_manager()
    if manager is not None:
      manager.apply_to_env(self.env)

  # ----- recovery --------------------------------------------------------

  def _recover_env_overrides_processing(self):
    if not self._env_overrides_control_available():
      return
    control_file = self._request_env_overrides_control_file()
    proc = control_file.processing_path
    req = control_file.pending_path
    try:
      recovered = control_file.recover_stale_processing()
    except (OSError, JsonControlFileUnsafeError) as exc:
      self.P(f"[env-overrides] failed to recover orphan .processing: {exc}", color="r")
      return
    if recovered:
      self.P(
        f"[env-overrides] recovered orphan {proc.name} -> {req.name} for retry",
        color="y",
      )

  # ----- request processing ---------------------------------------------

  def _request_env_overrides_control_file(self) -> JsonControlFile:
    return JsonControlFile(
      env_overrides_dir(self),
      ENV_OVERRIDES_REQUEST_FILE,
      ENV_OVERRIDES_PROCESSING_FILE,
    )

  def _env_overrides_tick(self, current_time: float) -> bool:
    """Process one pending request.json. Returns True when restart_now was accepted."""
    if not self._env_overrides_control_available():
      return False

    manager = self._ensure_env_overrides_manager()
    if manager is None:
      return False

    control_file = self._request_env_overrides_control_file()
    try:
      claimed = control_file.claim_object()
    except JsonControlFileClaimError as exc:
      self.P(
        f"[env-overrides] could not rename request.json -> .processing: {exc}",
        color="r",
      )
      return False
    except JsonControlFileReadError as exc:
      self._fail_env_override_request(
        None,
        f"could not read .processing: {exc}",
        control_file.processing_path,
      )
      return False
    except JsonControlFileUnsafeError as exc:
      self._fail_env_override_request(None, str(exc), control_file.processing_path)
      return False
    except JsonControlFileDecodeError as exc:
      self._fail_env_override_request(
        None,
        f"malformed JSON: {exc}",
        control_file.processing_path,
        raw_body=exc.raw_body,
      )
      return False
    except JsonControlFileObjectError as exc:
      self._fail_env_override_request(
        None,
        str(exc),
        control_file.processing_path,
        raw_body=exc.raw_body,
      )
      return False

    if claimed is None:
      return False

    try:
      result = manager.apply_patch(claimed.body, raw_body=claimed.raw_body)
    except Exception as exc:
      self._fail_env_override_request(
        claimed.body,
        str(exc),
        claimed.processing_path,
        raw_body=claimed.raw_body,
      )
      return False

    try:
      control_file.write_json(ENV_OVERRIDES_RESPONSE_FILE, result.to_response())
    except Exception as exc:
      self.P(f"[env-overrides] failed to write response.json: {exc}", color="r")
      try:
        control_file.discard_processing()
      except OSError:
        pass
      return False

    try:
      control_file.discard_processing()
    except OSError as exc:
      self.P(
          f"[env-overrides] failed to delete .processing after success: {exc}",
          color="r",
        )

    return result.restart_requested

  def _fail_env_override_request(
    self,
    request_body: Optional[dict],
    error: str,
    processing_path: Optional[Path],
    raw_body: Optional[str] = None,
  ) -> None:
    failed_ts = self.time()
    node_id = getattr(self, "ee_id", None) or getattr(self, "node_id", None)
    request_id = None
    if isinstance(request_body, dict) and isinstance(request_body.get("request_id"), str):
      request_id = request_body.get("request_id")

    invalid_payload = {
      "request": request_body,
      "_error": {
        "stage": STAGE_VALIDATION,
        "error": error,
        "failed_timestamp": failed_ts,
        "node_id": node_id,
      },
    }
    if request_id is not None:
      invalid_payload["_error"]["request_id"] = request_id
    if raw_body is not None and request_body is None:
      invalid_payload["_error"]["raw_body"] = raw_body[:1024]

    response_payload = {
      "schema_version": ENV_OVERRIDES_SCHEMA_VERSION,
      "status": "error",
      "stage": STAGE_VALIDATION,
      "error": error,
      "failed_timestamp": failed_ts,
    }
    if request_id is not None:
      response_payload["request_id"] = request_id

    control_file = self._request_env_overrides_control_file()
    try:
      control_file.write_json(ENV_OVERRIDES_INVALID_FILE, invalid_payload)
    except Exception as exc:
      self.P(f"[env-overrides] failed to write request.json.invalid: {exc}", color="r")
    try:
      control_file.write_json(ENV_OVERRIDES_RESPONSE_FILE, response_payload)
    except Exception as exc:
      self.P(f"[env-overrides] failed to write response.json: {exc}", color="r")

    if processing_path is not None and os.path.lexists(str(processing_path)):
      try:
        control_file.discard_processing()
      except OSError as exc:
        self.P(
          f"[env-overrides] failed to delete .processing after error: {exc}",
          color="r",
        )
