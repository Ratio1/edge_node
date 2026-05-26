"""Host-private environment override state for Container App Runner."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from extensions.business.container_apps.sync.constants import STAGE_VALIDATION
from extensions.business.container_apps.sync.control_files import write_json_atomic

from .constants import (
  APPLY_NEXT_RESTART,
  APPLY_RESTART_NOW,
  APPLY_VALUES,
  ENV_NAME_PATTERN,
  ENV_OVERRIDES_MAX_BYTES,
  ENV_OVERRIDES_SCHEMA_VERSION,
  ENV_OVERRIDES_STATE_FILE,
  RESERVED_ENV_NAMES,
  RESERVED_ENV_PREFIXES,
)


@dataclass(frozen=True)
class EnvOverrideApplyResult:
  """Result of applying one override patch to host-private state."""

  request_id: Optional[str]
  apply: str
  set_keys: tuple[str, ...]
  removed_keys: tuple[str, ...]
  active_count: int

  @property
  def restart_requested(self) -> bool:
    return self.apply == APPLY_RESTART_NOW

  def to_response(self) -> dict:
    restart = {
      "requested": self.restart_requested,
      "scheduled": self.restart_requested,
      "deferred": not self.restart_requested,
    }
    if not self.restart_requested:
      restart["reason"] = APPLY_NEXT_RESTART

    response = {
      "schema_version": ENV_OVERRIDES_SCHEMA_VERSION,
      "status": "ok",
      "apply": self.apply,
      "restart": restart,
      "overrides": {
        "set": list(self.set_keys),
        "removed": list(self.removed_keys),
        "active_count": self.active_count,
      },
    }
    if self.request_id is not None:
      response["request_id"] = self.request_id
    return response


class EnvOverrideValidationError(ValueError):
  """Raised when an env override request cannot be applied."""

  def __init__(self, message: str, *, request_id: Optional[str] = None):
    super().__init__(message)
    self.stage = STAGE_VALIDATION
    self.request_id = request_id

  def to_response(self) -> dict:
    response = {
      "schema_version": ENV_OVERRIDES_SCHEMA_VERSION,
      "status": "error",
      "stage": self.stage,
      "error": str(self),
    }
    if self.request_id is not None:
      response["request_id"] = self.request_id
    return response


class EnvOverrideManager:
  """Validate, persist, and overlay CAR local environment overrides."""

  _name_re = re.compile(ENV_NAME_PATTERN)
  _request_keys = frozenset({
    "schema_version",
    "request_id",
    "apply",
    "set",
    "remove",
  })

  def __init__(self, owner):
    self.owner = owner

  # ----- storage ---------------------------------------------------------

  def _state_path(self) -> Path:
    return (
      Path(self.owner.get_data_folder())
      / self.owner._get_instance_data_subfolder()
      / "plugin_data"
      / ENV_OVERRIDES_STATE_FILE
    )

  def load_overrides(self) -> dict[str, str]:
    """Load persisted overrides, ignoring corrupt or malformed state."""
    loaded = None
    loader = getattr(self.owner, "diskapi_load_json_from_data", None)
    if callable(loader):
      try:
        loaded = loader(
          ENV_OVERRIDES_STATE_FILE,
          subfolder="plugin_data",
          verbose=False,
        )
      except TypeError:
        loaded = self._load_overrides_from_path()
      except Exception as exc:
        self._log(f"[env-overrides] could not load state via diskapi: {exc}", color="y")
        loaded = None
    else:
      loaded = self._load_overrides_from_path()

    if loaded is None:
      return {}
    if not isinstance(loaded, dict):
      self._log("[env-overrides] ignoring malformed non-object state", color="y")
      return {}

    normalized = {}
    for key, value in loaded.items():
      if (
        isinstance(key, str)
        and isinstance(value, str)
        and self._name_re.match(key)
        and key not in RESERVED_ENV_NAMES
        and not key.startswith(RESERVED_ENV_PREFIXES)
      ):
        normalized[key] = value
      else:
        self._log(
          f"[env-overrides] ignoring malformed state entry {key!r}", color="y"
        )
    return normalized

  def save_overrides(self, overrides: dict[str, str]) -> None:
    """Persist normalized override strings under plugin_data/."""
    saver = getattr(self.owner, "diskapi_save_json_to_data", None)
    if callable(saver):
      try:
        saver(
          overrides,
          ENV_OVERRIDES_STATE_FILE,
          subfolder="plugin_data",
          indent=True,
        )
      except TypeError:
        write_json_atomic(self._state_path(), overrides)
      return
    write_json_atomic(self._state_path(), overrides)

  def _load_overrides_from_path(self):
    path = self._state_path()
    try:
      with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)
    except FileNotFoundError:
      return None
    except Exception as exc:
      self._log(f"[env-overrides] could not load {path}: {exc}", color="y")
      return None

  # ----- public operations ----------------------------------------------

  def apply_patch(self, request_body: dict, *, raw_body: Optional[str] = None) -> EnvOverrideApplyResult:
    """Apply one v1 set/remove request to host-private override state."""
    self._validate_raw_size(raw_body)
    patch = self._parse_patch(request_body)

    overrides = self.load_overrides()
    for key, value in patch["set"].items():
      overrides[key] = value

    removed_keys = []
    for key in patch["remove"]:
      if key in overrides:
        removed_keys.append(key)
        overrides.pop(key, None)

    self._validate_state_size(overrides, patch["request_id"])
    self.save_overrides(overrides)

    return EnvOverrideApplyResult(
      request_id=patch["request_id"],
      apply=patch["apply"],
      set_keys=tuple(sorted(patch["set"].keys())),
      removed_keys=tuple(sorted(removed_keys)),
      active_count=len(overrides),
    )

  def apply_to_env(self, env: dict) -> dict:
    """Overlay persisted overrides onto a Docker env dict."""
    if not isinstance(env, dict):
      return env
    env.update(self.load_overrides())
    return env

  def error_response_from_exception(self, exc: Exception, request_body: Optional[dict] = None) -> dict:
    """Build a protocol error response without leaking full request content."""
    if isinstance(exc, EnvOverrideValidationError):
      return exc.to_response()
    request_id = self._request_id_from_body(request_body)
    response = {
      "schema_version": ENV_OVERRIDES_SCHEMA_VERSION,
      "status": "error",
      "stage": STAGE_VALIDATION,
      "error": str(exc),
    }
    if request_id is not None:
      response["request_id"] = request_id
    return response

  # ----- validation ------------------------------------------------------

  def _parse_patch(self, request_body: dict) -> dict:
    if not isinstance(request_body, dict):
      raise EnvOverrideValidationError("request body must be a JSON object")

    request_id = self._request_id_from_body(request_body)
    if "request_id" in request_body and request_id is None:
      raise EnvOverrideValidationError("request_id must be a string")

    self._reject_unknown_fields(request_body, self._request_keys, request_id)

    if request_body.get("schema_version") != ENV_OVERRIDES_SCHEMA_VERSION:
      raise EnvOverrideValidationError(
        f"schema_version must be {ENV_OVERRIDES_SCHEMA_VERSION}",
        request_id=request_id,
      )

    apply_mode = request_body.get("apply", APPLY_NEXT_RESTART)
    if apply_mode not in APPLY_VALUES:
      raise EnvOverrideValidationError(
        f"apply must be one of {sorted(APPLY_VALUES)}",
        request_id=request_id,
      )

    raw_set = request_body.get("set", {})
    raw_remove = request_body.get("remove", [])
    if not isinstance(raw_set, dict):
      raise EnvOverrideValidationError("set must be a JSON object", request_id=request_id)
    if not isinstance(raw_remove, list):
      raise EnvOverrideValidationError("remove must be a list", request_id=request_id)

    set_values = {}
    for key, value in raw_set.items():
      name = self._validate_env_name(key, request_id)
      set_values[name] = self._normalize_value(value, request_id)

    remove_names = []
    for raw_name in raw_remove:
      remove_names.append(self._validate_env_name(raw_name, request_id))

    overlap = sorted(set(set_values).intersection(remove_names))
    if overlap:
      raise EnvOverrideValidationError(
        f"keys cannot be both set and removed: {', '.join(overlap)}",
        request_id=request_id,
      )

    return {
      "request_id": request_id,
      "apply": apply_mode,
      "set": set_values,
      "remove": remove_names,
    }

  @staticmethod
  def _reject_unknown_fields(
    request_body: dict,
    allowed: frozenset[str],
    request_id: Optional[str],
  ) -> None:
    unknown = sorted(set(request_body).difference(allowed))
    if unknown:
      raise EnvOverrideValidationError(
        "unsupported request field(s): {}".format(", ".join(unknown)),
        request_id=request_id,
      )

  def _validate_raw_size(self, raw_body: Optional[str]) -> None:
    if raw_body is None:
      return
    size = len(raw_body.encode("utf-8"))
    if size > ENV_OVERRIDES_MAX_BYTES:
      raise EnvOverrideValidationError(
        f"request body exceeds {ENV_OVERRIDES_MAX_BYTES} bytes"
      )

  def _validate_state_size(self, overrides: dict[str, str], request_id: Optional[str]) -> None:
    serialized = json.dumps(overrides, separators=(",", ":"), sort_keys=True)
    size = len(serialized.encode("utf-8"))
    if size > ENV_OVERRIDES_MAX_BYTES:
      raise EnvOverrideValidationError(
        f"persisted env override state would exceed {ENV_OVERRIDES_MAX_BYTES} bytes",
        request_id=request_id,
      )

  def _validate_env_name(self, raw_name: Any, request_id: Optional[str]) -> str:
    if not isinstance(raw_name, str):
      raise EnvOverrideValidationError("environment variable names must be strings", request_id=request_id)
    if not self._name_re.match(raw_name):
      raise EnvOverrideValidationError(
        f"invalid environment variable name: {raw_name!r}",
        request_id=request_id,
      )
    if raw_name in RESERVED_ENV_NAMES or raw_name.startswith(RESERVED_ENV_PREFIXES):
      raise EnvOverrideValidationError(
        f"environment variable is reserved: {raw_name}",
        request_id=request_id,
      )
    return raw_name

  def _normalize_value(self, value: Any, request_id: Optional[str]) -> str:
    if value is None:
      raise EnvOverrideValidationError(
        "null values are not supported; use remove instead",
        request_id=request_id,
      )
    if isinstance(value, bool):
      return "true" if value else "false"
    if isinstance(value, str):
      return value
    if isinstance(value, int):
      return str(value)
    if isinstance(value, float):
      if not math.isfinite(value):
        raise EnvOverrideValidationError(
          "numbers must be finite",
          request_id=request_id,
        )
      return json.dumps(value, separators=(",", ":"), allow_nan=False)
    if isinstance(value, (list, dict)):
      return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
      )
    raise EnvOverrideValidationError(
      f"unsupported value type for env override: {type(value).__name__}",
      request_id=request_id,
    )

  @staticmethod
  def _request_id_from_body(request_body: Optional[dict]) -> Optional[str]:
    if not isinstance(request_body, dict):
      return None
    request_id = request_body.get("request_id")
    return request_id if isinstance(request_id, str) else None

  def _log(self, message: str, **kwargs) -> None:
    logger = getattr(self.owner, "P", None)
    if callable(logger):
      logger(message, **kwargs)


__all__ = [
  "EnvOverrideApplyResult",
  "EnvOverrideManager",
  "EnvOverrideValidationError",
]
