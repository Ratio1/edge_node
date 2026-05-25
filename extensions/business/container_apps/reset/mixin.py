"""Mixin: reset request/response integration for CAR."""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Optional

from extensions.business.container_apps.sync.constants import (
  STAGE_RUNTIME_STOP,
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
  RESET_INVALID_FILE,
  RESET_PROCESSING_FILE,
  RESET_REQUEST_FILE,
  RESET_RESPONSE_FILE,
  RESET_SCHEMA_VERSION,
  RESET_SUBDIR,
  STAGE_RESTART,
  STAGE_VOLUME_RESET,
)
from .manager import ResetApplyResult, ResetManager, ResetRequestPlan, ResetValidationError


def reset_dir(owner) -> Path:
  """Host-side path of the reset control-plane subdir."""
  return system_volume_host_root(owner) / RESET_SUBDIR


class _ResetMixin:
  """File-protocol bridge for local CAR reset requests."""

  # ----- config ----------------------------------------------------------

  def _reset_cfg(self) -> dict:
    cfg = getattr(self, "cfg_reset", None)
    return cfg if isinstance(cfg, dict) else {}

  def _reset_enabled(self) -> bool:
    cfg = self._reset_cfg()
    if "ENABLED" not in cfg:
      return True
    return bool(cfg.get("ENABLED"))

  def _reset_control_available(self) -> bool:
    return (
      self._reset_enabled()
      and not getattr(self, "_sync_unavailable", False)
      and not getattr(self, "_reset_unavailable", False)
    )

  # ----- manager ---------------------------------------------------------

  def _ensure_reset_manager(self) -> Optional[ResetManager]:
    if not self._reset_enabled():
      return None
    manager = getattr(self, "_reset_manager", None)
    if manager is None:
      manager = ResetManager(self)
      self._reset_manager = manager
    return manager

  # ----- system-volume subdir ------------------------------------------

  def _configure_reset_control_dir(self):
    """Create the app-writable /r1en_system/reset directory."""
    self._reset_unavailable = False
    if not self._reset_enabled():
      return
    if getattr(self, "_sync_unavailable", False):
      self._reset_unavailable = True
      return

    root = reset_dir(self)
    try:
      try:
        st = os.lstat(str(root))
      except FileNotFoundError:
        st = None
      if st is not None and (
        stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode)
      ):
        os.unlink(str(root))
      os.makedirs(str(root), exist_ok=True)
      st = os.lstat(str(root))
      if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise RuntimeError(f"{root} is not a real directory")
    except Exception as exc:
      self.P(
        f"[reset] control directory unsafe/unavailable: {exc}. "
        f"RESET request files will not be advertised.",
        color="r",
      )
      self._reset_unavailable = True
      return

    try:
      os.chown(str(root), 0, 0)
      os.chmod(str(root), 0o1777)
    except OSError as exc:
      self.P(
        f"[reset] could not enforce root-owned {root} mode 0o1777: {exc}. "
        f"RESET request files will not be advertised.",
        color="r",
      )
      self._reset_unavailable = True

  # ----- env-var injection ----------------------------------------------

  def _inject_reset_env_vars(self):
    if not isinstance(getattr(self, "env", None), dict):
      return
    if not self._reset_control_available():
      return
    control_dir = f"{SYSTEM_VOLUME_MOUNT}/{RESET_SUBDIR}"
    self.env["R1_RESET_DIR"] = control_dir
    self.env["R1_RESET_REQUEST_FILE"] = f"{control_dir}/{RESET_REQUEST_FILE}"
    self.env["R1_RESET_RESPONSE_FILE"] = f"{control_dir}/{RESET_RESPONSE_FILE}"

  # ----- recovery --------------------------------------------------------

  def _recover_reset_processing(self):
    if not self._reset_control_available():
      return
    control_file = self._request_reset_control_file()
    proc = control_file.processing_path
    req = control_file.pending_path
    try:
      recovered = control_file.recover_stale_processing()
    except (OSError, JsonControlFileUnsafeError) as exc:
      self.P(f"[reset] failed to recover orphan .processing: {exc}", color="r")
      return
    if recovered:
      self.P(
        f"[reset] recovered orphan {proc.name} -> {req.name} for retry",
        color="y",
      )

  # ----- request processing ---------------------------------------------

  def _request_reset_control_file(self) -> JsonControlFile:
    return JsonControlFile(
      reset_dir(self),
      RESET_REQUEST_FILE,
      RESET_PROCESSING_FILE,
    )

  def _reset_tick(self, current_time: float) -> None:
    """Process one pending reset request inline. Never routes through _restart_container."""
    if not self._reset_control_available():
      return

    manager = self._ensure_reset_manager()
    if manager is None:
      return

    control_file = self._request_reset_control_file()
    try:
      claimed = control_file.claim_object()
    except JsonControlFileClaimError as exc:
      self.P(f"[reset] could not rename request.json -> .processing: {exc}", color="r")
      return
    except JsonControlFileReadError as exc:
      self._fail_reset_request(
        None, STAGE_VALIDATION,
        f"could not read .processing: {exc}", control_file.processing_path,
      )
      return
    except JsonControlFileUnsafeError as exc:
      self._fail_reset_request(None, STAGE_VALIDATION, str(exc), control_file.processing_path)
      return
    except JsonControlFileDecodeError as exc:
      self._fail_reset_request(
        None, STAGE_VALIDATION,
        f"malformed JSON: {exc}", control_file.processing_path,
        raw_body=exc.raw_body,
      )
      return
    except JsonControlFileObjectError as exc:
      self._fail_reset_request(
        None, STAGE_VALIDATION, str(exc), control_file.processing_path,
        raw_body=exc.raw_body,
      )
      return

    if claimed is None:
      return

    try:
      plan = manager.plan_request(claimed.body)
    except ResetValidationError as exc:
      self._fail_reset_request(
        claimed.body, exc.stage, str(exc), claimed.processing_path,
        raw_body=claimed.raw_body,
      )
      return

    stopped = self._stop_container_runtime_for_restart()
    if not stopped:
      self._fail_reset_request(
        claimed.body,
        STAGE_RUNTIME_STOP,
        "could not stop/remove container before reset",
        claimed.processing_path,
        plan=plan,
      )
      return

    reset_error = None
    cleared_count = 0
    try:
      cleared_count = manager.reset_volumes(plan)
    except Exception as exc:
      reset_error = str(exc)

    restart_started = self._reset_safe_start_container()
    if reset_error is not None:
      self._fail_reset_request(
        claimed.body,
        STAGE_VOLUME_RESET,
        reset_error,
        claimed.processing_path,
        plan=plan,
        restart_started=restart_started,
      )
      return

    restart_error = None if restart_started else "container restart failed after reset"
    response = ResetApplyResult(
      request_id=plan.request_id,
      volumes=tuple(plan.volume_names()),
      cleared_count=cleared_count,
      restart_started=restart_started,
      restart_error=restart_error,
    ).to_response()

    try:
      control_file.write_json(RESET_RESPONSE_FILE, response)
    except Exception as exc:
      self.P(f"[reset] failed to write response.json: {exc}", color="r")

    try:
      control_file.discard_processing()
    except OSError as exc:
      self.P(f"[reset] failed to delete .processing after reset: {exc}", color="r")

  def _reset_safe_start_container(self) -> bool:
    try:
      container = self.start_container()
    except Exception as exc:
      self.P(f"[reset] start_container after reset failed: {exc}", color="r")
      return False
    if not container:
      return False
    try:
      self._reset_runtime_state_post_start()
    except Exception as exc:
      self.P(f"[reset] runtime-state reset after reset failed: {exc}", color="r")
    return True

  def _fail_reset_request(
    self,
    request_body: Optional[dict],
    stage: str,
    error: str,
    processing_path: Optional[Path],
    raw_body: Optional[str] = None,
    plan: Optional[ResetRequestPlan] = None,
    restart_started: Optional[bool] = None,
  ) -> None:
    failed_ts = self.time()
    node_id = getattr(self, "ee_id", None) or getattr(self, "node_id", None)
    request_id = None
    if isinstance(request_body, dict) and isinstance(request_body.get("request_id"), str):
      request_id = request_body.get("request_id")

    invalid_payload = {
      "request": request_body,
      "_error": {
        "stage": stage,
        "error": error,
        "failed_timestamp": failed_ts,
        "node_id": node_id,
      },
    }
    if request_id is not None:
      invalid_payload["_error"]["request_id"] = request_id
    if raw_body is not None and request_body is None:
      invalid_payload["_error"]["raw_body"] = raw_body[:1024]

    reset_status = "skipped" if stage in (STAGE_VALIDATION, STAGE_RUNTIME_STOP) else "error"
    response_payload = {
      "schema_version": RESET_SCHEMA_VERSION,
      "status": "error",
      "stage": stage,
      "error": error,
      "failed_timestamp": failed_ts,
      "reset": {
        "status": reset_status,
        "volumes": plan.volume_names() if plan is not None else [],
        "preserved": {
          "env_overrides": True,
        },
      },
      "restart": {
        "requested": True,
        "started": bool(restart_started),
      },
    }
    if request_id is not None:
      response_payload["request_id"] = request_id
    if raw_body is not None and request_body is None:
      response_payload["raw_body_prefix"] = raw_body[:1024]

    control_file = self._request_reset_control_file()
    try:
      control_file.write_json(RESET_INVALID_FILE, invalid_payload)
    except Exception as exc:
      self.P(f"[reset] failed to write request.json.invalid: {exc}", color="r")
    try:
      control_file.write_json(RESET_RESPONSE_FILE, response_payload)
    except Exception as exc:
      self.P(f"[reset] failed to write response.json: {exc}", color="r")

    if processing_path is not None and os.path.lexists(str(processing_path)):
      try:
        control_file.discard_processing()
      except OSError as exc:
        self.P(f"[reset] failed to delete .processing after error: {exc}", color="r")
