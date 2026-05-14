"""Helpers for CAR volume-sync JSON control files.

The sync data plane uses small JSON files in the always-mounted system
volume as a control protocol between the app and CAR. This module owns the
file mechanics: atomic JSON writes, pending-to-processing claims, stale
processing recovery, and processing cleanup. SyncManager keeps the domain
validation and response payload shapes.
"""

from __future__ import annotations

import errno
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


@dataclass(frozen=True)
class ClaimedJsonObject:
  """A JSON object claimed from a pending control file."""

  body: dict
  raw_body: str
  processing_path: Path


class JsonControlFileError(Exception):
  """Base class for control-file mechanics errors."""

  def __init__(
    self,
    message: str,
    *,
    raw_body: Optional[str] = None,
    processing_path: Optional[Path] = None,
  ) -> None:
    super().__init__(message)
    self.raw_body = raw_body
    self.processing_path = processing_path


class JsonControlFileClaimError(JsonControlFileError):
  """The pending file could not be renamed to its processing name."""


class JsonControlFileReadError(JsonControlFileError):
  """The processing file could not be read."""


class JsonControlFileDecodeError(JsonControlFileError):
  """The processing file was not valid JSON."""


class JsonControlFileObjectError(JsonControlFileError):
  """The processing file was JSON, but not a JSON object."""


class JsonControlFileUnsafeError(JsonControlFileError):
  """The processing file is not a regular no-follow-readable file."""


def _ensure_real_directory(path: Path, *, create: bool) -> bool:
  """Ensure ``path`` is a real directory, not a symlink.

  Returns False only when ``create`` is False and the path is absent.
  """
  path = Path(path)
  if create:
    try:
      path.mkdir(parents=True, exist_ok=True)
    except FileExistsError:
      pass
  try:
    st = os.lstat(str(path))
  except FileNotFoundError:
    if create:
      raise
    return False
  if stat.S_ISLNK(st.st_mode):
    raise JsonControlFileUnsafeError(
      f"refusing symlink control directory: {path}"
    )
  if not stat.S_ISDIR(st.st_mode):
    raise JsonControlFileUnsafeError(
      f"refusing non-directory control directory: {path}"
    )
  return True


def write_json_atomic(path: Path, payload: Any) -> None:
  """Write JSON to ``path`` atomically and make it app-readable.

  Creates the parent directory if missing. Uses a temporary file in the same
  directory so ``os.replace`` is atomic within the filesystem. The final file
  is chmod'd to 0o666 because CAR runs as root inside the edge node but the
  app inside the container often runs as a non-root user.
  """
  path = Path(path)
  _ensure_real_directory(path.parent, create=True)
  fd, tmp_name = tempfile.mkstemp(
    dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp"
  )
  try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
      json.dump(payload, handle, indent=2, sort_keys=True)
      handle.flush()
      os.fsync(handle.fileno())
    os.chmod(tmp_name, 0o666)
    os.replace(tmp_name, str(path))
  except Exception:
    try:
      os.unlink(tmp_name)
    except OSError:
      pass
    raise


class JsonControlFile:
  """File-mechanics helper for a single pending/processing JSON control file."""

  def __init__(self, root: Path, pending_name: str, processing_name: str):
    self.root = Path(root)
    self.pending_name = pending_name
    self.processing_name = processing_name

  @property
  def pending_path(self) -> Path:
    return self.root / self.pending_name

  @property
  def processing_path(self) -> Path:
    return self.root / self.processing_name

  def _root_is_safe(self) -> bool:
    return _ensure_real_directory(self.root, create=False)

  def has_pending(self) -> bool:
    if not self._root_is_safe():
      return False
    try:
      os.lstat(str(self.pending_path))
      return True
    except FileNotFoundError:
      return False

  @staticmethod
  def _read_text_no_follow(path: Path) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
      flags |= os.O_NOFOLLOW

    fd: Optional[int] = None
    try:
      fd = os.open(str(path), flags)
      st = os.fstat(fd)
      if not stat.S_ISREG(st.st_mode):
        raise JsonControlFileUnsafeError(
          f"refusing to read non-regular control file: {path.name}",
          processing_path=path,
        )
      with os.fdopen(fd, "r", encoding="utf-8") as handle:
        fd = None
        return handle.read()
    except OSError as exc:
      if getattr(exc, "errno", None) == errno.ELOOP:
        raise JsonControlFileUnsafeError(
          f"refusing to read symlink control file: {path.name}",
          processing_path=path,
        ) from exc
      raise
    finally:
      if fd is not None:
        try:
          os.close(fd)
        except OSError:
          pass

  def claim_processing(self) -> Optional[Path]:
    """Atomically rename pending -> processing, returning the processing path."""
    if not self.has_pending():
      return None
    try:
      os.replace(str(self.pending_path), str(self.processing_path))
    except OSError as exc:
      raise JsonControlFileClaimError(
        str(exc), processing_path=self.processing_path,
      ) from exc
    return self.processing_path

  def claim_object(self) -> Optional[ClaimedJsonObject]:
    """Claim a pending JSON object control file.

    Returns None when no pending file exists. Raises a JsonControlFileError
    subclass for mechanics, JSON decode, or JSON-shape failures. On decode or
    shape failure, the processing file remains in place so callers can write
    their own failure artifacts and then discard it.
    """
    processing_path = self.claim_processing()
    if processing_path is None:
      return None

    try:
      raw_body = self._read_text_no_follow(processing_path)
    except UnicodeDecodeError as exc:
      raise JsonControlFileDecodeError(
        f"invalid UTF-8 in {self.pending_name}: {exc}",
        processing_path=processing_path,
      ) from exc
    except OSError as exc:
      raise JsonControlFileReadError(
        str(exc), processing_path=processing_path,
      ) from exc

    try:
      body = json.loads(raw_body)
    except json.JSONDecodeError as exc:
      raise JsonControlFileDecodeError(
        str(exc), raw_body=raw_body, processing_path=processing_path,
      ) from exc

    if not isinstance(body, dict):
      raise JsonControlFileObjectError(
        f"{self.pending_name} must be a JSON object",
        raw_body=raw_body,
        processing_path=processing_path,
      )

    return ClaimedJsonObject(
      body=body,
      raw_body=raw_body,
      processing_path=processing_path,
    )

  def discard_processing(self) -> None:
    if os.path.lexists(str(self.processing_path)):
      os.unlink(str(self.processing_path))

  def recover_stale_processing(self) -> bool:
    """Rename orphan processing -> pending without overwriting a pending file."""
    if not self._root_is_safe():
      return False
    if not os.path.lexists(str(self.processing_path)):
      return False
    st = os.lstat(str(self.processing_path))
    if stat.S_ISLNK(st.st_mode):
      os.unlink(str(self.processing_path))
      return False
    if stat.S_ISREG(st.st_mode) and not os.path.lexists(str(self.pending_path)):
      os.replace(str(self.processing_path), str(self.pending_path))
      return True
    return False

  def write_json(self, file_name: str, payload: Any) -> None:
    write_json_atomic(self.root / file_name, payload)


__all__ = [
  "ClaimedJsonObject",
  "JsonControlFile",
  "JsonControlFileClaimError",
  "JsonControlFileDecodeError",
  "JsonControlFileError",
  "JsonControlFileObjectError",
  "JsonControlFileReadError",
  "JsonControlFileUnsafeError",
  "write_json_atomic",
]
