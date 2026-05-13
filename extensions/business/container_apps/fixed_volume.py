"""
Fixed-size, file-backed volume helper for the container_app_runner plugin.

Provides file-backed ext4 volumes mounted via loop devices that enforce a hard
ENOSPC limit when the volume is full. Each volume is a regular file formatted
as ext4, attached to a loop device, and mounted at a host directory that is
then bind-mounted into the container.

Adapted from the volume_isolation PoC.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional


def safe_path_component(raw, sanitize_fn=None):
  """Sanitize a single path component to prevent directory traversal.

  Applies an optional sanitize_fn (e.g. sanitize_name for cosmetic cleanup),
  then verifies via os.path.realpath that the result cannot escape a parent
  directory.  Returns '_' for any unsafe input.
  """
  if sanitize_fn is not None:
    s = sanitize_fn(str(raw))
  else:
    s = re.sub(r'[^\w.\-]', '_', str(raw))
  _parent = '/.__probe__'
  _expected = os.path.join(_parent, s)
  if not s or os.path.realpath(_expected) != _expected:
    return '_'
  return s


def _log(logger: Optional[Callable], level: str, message: str) -> None:
  """Route a log message through the provided logger or fall back to print."""
  if logger is not None:
    logger(f"[FixedVolume] [{level}] {message}")
  else:
    print(f"[FixedVolume] [{level}] {message}", flush=True)


def _is_path_mounted(mount_path) -> bool:
  """Return True iff `mount_path` is an exact mountpoint in /proc/mounts.

  The kernel writes each /proc/mounts line as:
    <device> <mountpoint> <fstype> <options> <dump> <pass>
  with whitespace/backslashes in the mountpoint escaped as octal sequences
  (`\\040` space, `\\011` tab, `\\012` newline, `\\134` backslash).

  Substring/`in` matching on the whole file is unsafe: a mount at
  `/a/b/data2` would make `/a/b/data` look mounted (prefix aliasing), so the
  caller might skip a real mount step and lose the isolation guarantee.
  This helper parses each line, unescapes the mountpoint, and compares
  exactly.
  """
  try:
    with open("/proc/mounts", "r", encoding="utf-8") as f:
      lines = f.readlines()
  except OSError:
    return False
  target = str(mount_path).rstrip("/")
  for line in lines:
    parts = line.split()
    if len(parts) < 2:
      continue
    mp = parts[1]
    mp = (mp.replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\"))
    if mp.rstrip("/") == target:
      return True
  return False


@dataclass
class FixedVolume:
  """Fixed-size file-backed volume specification.

  Parameters
  ----------
  name : str
      Logical volume name (e.g. "data").
  size : str
      Size string accepted by fallocate (e.g. "100M", "1G").
  root : pathlib.Path
      Root directory for this plugin's fixed_volumes/ artifacts.
  fs_type : str, optional
      Filesystem type to use for formatting.
  owner_uid : int, optional
      UID to chown the mount path to after mount.
  owner_gid : int, optional
      GID to chown the mount path to after mount.
  """

  name: str
  size: str
  root: Path
  fs_type: str = "ext4"
  owner_uid: Optional[int] = None
  owner_gid: Optional[int] = None

  def __post_init__(self):
    """Validate that the volume name cannot escape the root directory."""
    abs_root = str(self._abs_root)
    for derived in (self.img_path, self.mount_path, self.meta_path):
      resolved = str(derived.resolve())
      if not resolved.startswith(abs_root + os.sep):
        raise ValueError(
          f"Volume name {self.name!r} resolves outside root: {resolved!r}"
        )

  @property
  def _abs_root(self) -> Path:
    """Root resolved to an absolute path (required for losetup/mount commands)."""
    return self.root.resolve()

  @property
  def img_path(self) -> Path:
    """Path to the file-backed image."""
    return self._abs_root / "images" / f"{self.name}.img"

  @property
  def mount_path(self) -> Path:
    """Path to the mountpoint directory."""
    return self._abs_root / "mounts" / self.name

  @property
  def meta_path(self) -> Path:
    """Path to the metadata JSON file."""
    return self._abs_root / "meta" / f"{self.name}.json"


def _run(
  cmd: list[str],
  capture: bool = False,
  logger: Optional[Callable] = None,
) -> str:
  """Run a command with logging and optional output capture.

  Returns captured stdout when capture is True, otherwise empty string.
  Raises subprocess.CalledProcessError on non-zero exit.
  """
  cmd_str = shlex.join(cmd)
  _log(logger, "CMD", f"cmd={cmd_str} capture={capture}")

  result = subprocess.run(cmd, text=True, capture_output=True)
  _log(
    logger, "INFO",
    f"rc={result.returncode} stdout_len={len(result.stdout)} stderr_len={len(result.stderr)}",
  )
  if result.stdout:
    for line in result.stdout.strip().splitlines():
      _log(logger, "INFO", f"stdout: {line}")
  if result.stderr:
    for line in result.stderr.strip().splitlines():
      _log(logger, "WARN", f"stderr: {line}")
  if result.returncode != 0:
    raise subprocess.CalledProcessError(
      result.returncode, cmd, output=result.stdout, stderr=result.stderr
    )
  if capture:
    return result.stdout.strip()
  return ""


REQUIRED_TOOLS = ["fallocate", "mkfs.ext4", "losetup", "mount", "umount", "blkid"]


def _require_tools(logger: Optional[Callable] = None) -> None:
  """Ensure required host tools are installed.

  Raises RuntimeError if any tool is missing.
  """
  missing = [t for t in REQUIRED_TOOLS if shutil.which(t) is None]
  _log(logger, "INFO", f"Tool check required={REQUIRED_TOOLS} missing={missing}")
  if missing:
    raise RuntimeError(
      "Missing required tools for fixed-size volumes: "
      + ", ".join(missing)
      + ". Install util-linux + e2fsprogs."
    )


def _parse_size_to_bytes(size_str: str) -> int:
  """Parse a fallocate-style size string (e.g. '100M', '1G', '0.5G') to bytes.

  Supports K, M, G, T suffixes (case-insensitive) with fractional values.
  Plain integers are bytes.
  """
  s = size_str.strip().upper()
  multipliers = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
  if s and s[-1] in multipliers:
    return int(float(s[:-1]) * multipliers[s[-1]])
  return int(s)


def ensure_created(
  vol: FixedVolume,
  force_recreate: bool = False,
  logger: Optional[Callable] = None,
) -> None:
  """Create the image file and filesystem if needed.

  If the image already exists and force_recreate is False, checks for size
  mismatch between the config and the actual file. Logs a warning if they
  differ but does NOT resize -- the old image is used as-is.
  """
  _log(
    logger, "STEP",
    f"Ensuring volume image exists volume={vol.name} size={vol.size} "
    f"img_path={vol.img_path} force_recreate={force_recreate}",
  )

  vol.img_path.parent.mkdir(parents=True, exist_ok=True)
  vol.mount_path.mkdir(parents=True, exist_ok=True)
  vol.meta_path.parent.mkdir(parents=True, exist_ok=True)

  if force_recreate and vol.img_path.exists():
    _log(logger, "WARN", f"FORCE_RECREATE: removing existing image path={vol.img_path}")
    vol.img_path.unlink()

  if not vol.img_path.exists():
    _run(["fallocate", "-l", vol.size, str(vol.img_path)], logger=logger)
    _run(["mkfs.ext4", "-F", "-m", "0", str(vol.img_path)], logger=logger)
    return

  # Image exists -- check for size mismatch
  actual_bytes = vol.img_path.stat().st_size
  configured_bytes = _parse_size_to_bytes(vol.size)
  if actual_bytes != configured_bytes:
    _log(
      logger, "WARN",
      f"Size mismatch for volume '{vol.name}': "
      f"config={vol.size} ({configured_bytes} bytes) vs "
      f"actual={actual_bytes} bytes. "
      f"Refusing to resize. Use FORCE_RECREATE to destroy and recreate.",
    )

  _log(logger, "INFO", f"Image file already exists path={vol.img_path}")
  try:
    _run(["blkid", "-p", str(vol.img_path)], logger=logger)
  except subprocess.CalledProcessError:
    _log(logger, "WARN", f"No filesystem detected, formatting path={vol.img_path}")
    _run(["mkfs.ext4", "-F", "-m", "0", str(vol.img_path)], logger=logger)


def _ensure_loop_device_nodes(logger: Optional[Callable] = None) -> None:
  """Ensure enough /dev/loopN device nodes exist for losetup.

  On some container environments (e.g., Docker-in-Docker), only a limited set
  of loop device nodes exists (/dev/loop0-8), and they may all be in use by
  the host (e.g., snap packages). This creates additional device nodes so
  losetup can find a free one.
  """
  max_loop = 64
  created = 0
  for i in range(max_loop):
    dev_path = Path(f"/dev/loop{i}")
    if not dev_path.exists():
      try:
        os.mknod(str(dev_path), 0o660 | 0o60000, os.makedev(7, i))  # block device, major=7
        created += 1
      except (OSError, PermissionError):
        break
  if created > 0:
    _log(logger, "INFO", f"Created {created} loop device nodes (up to /dev/loop{max_loop - 1})")


def attach_loop(
  vol: FixedVolume,
  logger: Optional[Callable] = None,
) -> str:
  """Attach the image file to a loop device. Returns the device path."""
  _log(logger, "STEP", f"Attaching loop device img_path={vol.img_path}")
  _ensure_loop_device_nodes(logger=logger)
  existing = _run(["losetup", "-j", str(vol.img_path)], capture=True, logger=logger)
  if existing:
    loop_dev = existing.split(":")[0]
    _log(logger, "INFO", f"Existing loop device found loop_dev={loop_dev}")
    return loop_dev
  loop_dev = _run(
    ["losetup", "-f", "--show", str(vol.img_path)], capture=True, logger=logger
  )
  _log(logger, "INFO", f"Loop device attached loop_dev={loop_dev}")
  return loop_dev


def mount_volume(
  vol: FixedVolume,
  loop_dev: str,
  logger: Optional[Callable] = None,
) -> bool:
  """Mount a loop device at the volume mount path.

  Returns True if this is a fresh mount (first time for a new image),
  False if the mount already existed.
  """
  _log(
    logger, "STEP",
    f"Mounting loop_dev={loop_dev} mount_path={vol.mount_path} fs_type={vol.fs_type}",
  )
  if _is_path_mounted(vol.mount_path):
    _log(logger, "INFO", f"Mount already present mount_path={vol.mount_path}")
    return False

  _run(["mount", "-t", vol.fs_type, loop_dev, str(vol.mount_path)], logger=logger)

  if vol.owner_uid is not None and vol.owner_gid is not None:
    os.chown(vol.mount_path, vol.owner_uid, vol.owner_gid)
    _log(
      logger, "INFO",
      f"Adjusted ownership mount_path={vol.mount_path} uid={vol.owner_uid} gid={vol.owner_gid}",
    )

  return True


def _remove_lost_found(vol: FixedVolume, logger: Optional[Callable] = None) -> None:
  """Remove lost+found/ directory from a freshly formatted volume."""
  lost_found = vol.mount_path / "lost+found"
  if lost_found.is_dir():
    shutil.rmtree(lost_found)
    _log(logger, "INFO", f"Removed lost+found from {vol.mount_path}")


def write_meta(
  vol: FixedVolume,
  loop_dev: str,
  logger: Optional[Callable] = None,
) -> None:
  """Write metadata describing the provisioned volume."""
  data = {
    "volume_name": vol.name,
    "configured_size": vol.size,
    "fs_type": vol.fs_type,
    "img_path": str(vol.img_path),
    "mount_path": str(vol.mount_path),
    "loop_dev": loop_dev,
  }
  vol.meta_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
  _log(
    logger, "INFO",
    f"Wrote metadata meta_path={vol.meta_path} loop_dev={loop_dev} size={vol.size}",
  )


def provision(
  vol: FixedVolume,
  force_recreate: bool = False,
  logger: Optional[Callable] = None,
) -> FixedVolume:
  """Provision a volume: create image, attach loop, mount, write metadata.

  Idempotent -- reuses existing image/loop/mount when possible.
  On a fresh volume (new image), removes lost+found/ after mount.
  """
  _log(
    logger, "STEP",
    f"Provisioning volume={vol.name} size={vol.size} root={vol.root}",
  )
  is_new = not vol.img_path.exists() or force_recreate
  ensure_created(vol, force_recreate=force_recreate, logger=logger)
  loop_dev = attach_loop(vol, logger=logger)
  is_fresh_mount = mount_volume(vol, loop_dev, logger=logger)
  write_meta(vol, loop_dev, logger=logger)

  if is_new and is_fresh_mount:
    _remove_lost_found(vol, logger=logger)

  _log(
    logger, "INFO",
    f"Volume provisioned img_path={vol.img_path} mount_path={vol.mount_path} loop_dev={loop_dev}",
  )
  return vol


def cleanup(
  vol: FixedVolume,
  logger: Optional[Callable] = None,
) -> bool:
  """Unmount and detach the loop device for a volume.

  Graceful -- never raises. All errors are caught and logged as warnings.
  Returns False when unmount/detach could not be confirmed so callers can
  preserve cleanup handles and retry later.
  """
  _log(
    logger, "STEP",
    f"Cleaning up volume={vol.name} mount_path={vol.mount_path}",
  )
  result = True
  loop_dev = None
  if vol.meta_path.exists():
    try:
      meta = json.loads(vol.meta_path.read_text(encoding="utf-8"))
      loop_dev = meta.get("loop_dev")
      _log(logger, "INFO", f"Loaded metadata loop_dev={loop_dev}")
    except Exception as exc:
      result = False
      _log(logger, "WARN", f"Failed to read metadata error={exc}")

  if _is_path_mounted(vol.mount_path):
    try:
      _run(["umount", str(vol.mount_path)], logger=logger)
    except Exception as exc:
      result = False
      _log(logger, "WARN", f"Unmount failed mount_path={vol.mount_path} error={exc}")
  else:
    _log(logger, "INFO", f"Mount path is not mounted mount_path={vol.mount_path}")

  if loop_dev:
    try:
      _run(["losetup", "-d", loop_dev], logger=logger)
    except Exception as exc:
      result = False
      _log(logger, "WARN", f"Detach loop failed loop_dev={loop_dev} error={exc}")

  if _is_path_mounted(vol.mount_path):
    result = False
    _log(logger, "WARN", f"Mount path is still mounted mount_path={vol.mount_path}")

  _log(
    logger, "INFO",
    f"Cleanup complete mount_path={vol.mount_path} loop_dev={loop_dev} ok={result}",
  )
  return result


def docker_bind_spec(vol: FixedVolume, container_target: str) -> Dict[str, Dict[str, str]]:
  """Build docker-py bind mount specification for the volume.

  Returns a dict suitable for the docker-py `volumes` argument:
  {"/host/mount/path": {"bind": "/container/path", "mode": "rw"}}
  """
  spec = {str(vol.mount_path): {"bind": container_target, "mode": "rw"}}
  _log(None, "INFO", f"Bind spec host={vol.mount_path} container={container_target}")
  return spec


def cleanup_stale_mounts(
  root: Path,
  logger: Optional[Callable] = None,
) -> None:
  """Scan metadata files and clean up any stale mounts/loop devices.

  Called on startup to recover from prior crashes or edge node restarts.
  Checks /proc/mounts first to skip silently when nothing is mounted
  (reduces log noise after edge node container restart).
  """
  meta_dir = root / "meta"
  if not meta_dir.is_dir():
    return

  for meta_file in sorted(meta_dir.glob("*.json")):
    try:
      meta = json.loads(meta_file.read_text(encoding="utf-8"))
    except Exception as exc:
      _log(logger, "WARN", f"Failed to read stale metadata {meta_file}: {exc}")
      continue

    mount_path = meta.get("mount_path", "")
    loop_dev = meta.get("loop_dev", "")

    # Skip if nothing is mounted at this exact path (edge node restart case).
    # Exact match avoids false positives from sibling paths sharing a prefix.
    if not mount_path or not _is_path_mounted(mount_path):
      _log(logger, "INFO", f"No active mount for {meta_file.stem}, skipping stale cleanup")
      continue

    _log(logger, "WARN", f"Found stale mount for {meta_file.stem}, cleaning up...")

    try:
      _run(["umount", mount_path], logger=logger)
    except Exception as exc:
      _log(logger, "WARN", f"Stale umount failed path={mount_path}: {exc}")

    if loop_dev:
      try:
        _run(["losetup", "-d", loop_dev], logger=logger)
      except Exception as exc:
        _log(logger, "WARN", f"Stale losetup -d failed dev={loop_dev}: {exc}")
