"""Mixin: volume-sync provider/consumer integration for CAR.

Bridges :class:`SyncManager` into ``ContainerAppRunnerPlugin``'s lifecycle:

  * always-on: provisions the 10M ``/r1en_system`` system volume (a fixed-size
    loopback identical in machinery to ``FIXED_SIZE_VOLUMES``) and exports
    ``R1_*`` env vars to the container
  * provider role: per ``cfg_sync_poll_interval`` polls for a pending
    ``request.json``, then drives ``stop_container → publish_snapshot →
    start_container`` inline (must NOT route through ``_restart_container``,
    which calls ``_cleanup_fixed_size_volumes`` and unmounts the loopback
    before we can read from it)
  * consumer role: same cadence polls ChainStore for newer ``version``, then
    drives ``stop_container → apply_snapshot → start_container`` inline
  * consumer first-boot: blocks the very first ``start_container`` until a
    record is available (bounded by ``cfg_sync_initial_sync_timeout``)
  * recovery: any orphan ``request.json.processing`` left behind by a prior
    crash is renamed back to ``request.json`` on plugin init so the next
    provider tick retries cleanly

See ``docs/_todos/2026-05-03T17:37:43_car_volume_sync_provider_consumer.md``
for the full design and rationale.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from extensions.business.container_apps import fixed_volume
from extensions.business.container_apps.sync_manager import (
  CHAINSTORE_SYNC_HKEY,
  SYNC_INVALID_FILE,
  SYNC_LAST_APPLY_FILE,
  SYNC_PROCESSING_FILE,
  SYNC_REQUEST_FILE,
  SYSTEM_VOLUME_FS,
  SYSTEM_VOLUME_MOUNT,
  SYSTEM_VOLUME_NAME,
  SYSTEM_VOLUME_SIZE,
  SyncManager,
  VOLUME_SYNC_SUBDIR,
  history_received_dir,
  history_sent_dir,
  system_volume_host_root,
  volume_sync_dir,
)


class _SyncMixin:
  """
  Required attributes on the composing plugin:
    - self.P, self.time, self.cfg_*                  (BasePlugin)
    - self.get_data_folder, _get_instance_data_subfolder
    - self.volumes (dict, populated by CAR)
    - self._fixed_volumes (list, populated by _FixedSizeVolumesMixin)
    - self.env (dict, container env)
    - self.r1fs, self.chainstore_hset/hget/hsync     (BasePlugin API)
    - self.stop_container(), self.start_container()  (CAR lifecycle)
    - self.cfg_sync                                  (CAR config block)
    - self.ee_id                                     (BasePlugin identity)
  """

  # ----- system volume provisioning --------------------------------------

  def _configure_system_volume(self):
    """Provision the always-on /r1en_system fixed-size loopback.

    Idempotent across plugin restarts: ``fixed_volume.provision`` reuses an
    existing image/loop/mount when available. Adds the bind spec to
    ``self.volumes`` so ``start_container`` mounts ``/r1en_system`` at the
    correct host path. The ``volume-sync/`` subdir is created post-mount so
    SyncManager always has a place to write request/response files.
    """
    try:
      fixed_volume._require_tools(logger=self.P)
    except RuntimeError as exc:
      self.P(
        f"[sync] system volume unavailable: {exc}. "
        f"SYNC will be effectively disabled until tools are installed.",
        color="r",
      )
      return

    root = (
      Path(self.get_data_folder())
      / self._get_instance_data_subfolder()
      / "fixed_volumes"
    )

    # Recover any stale mounts from prior crashes (parity with
    # _configure_fixed_size_volumes).
    fixed_volume.cleanup_stale_mounts(root, logger=self.P)

    owner_uid, owner_gid = (None, None)
    resolver = getattr(self, "_resolve_image_owner", None)
    if callable(resolver):
      try:
        owner_uid, owner_gid = resolver()
      except Exception as exc:
        self.P(
          f"[sync] _resolve_image_owner failed (using root): {exc}", color="y"
        )

    vol = fixed_volume.FixedVolume(
      name=SYSTEM_VOLUME_NAME,
      size=SYSTEM_VOLUME_SIZE,
      root=root,
      fs_type=SYSTEM_VOLUME_FS,
      owner_uid=owner_uid,
      owner_gid=owner_gid,
    )
    fixed_volume.provision(vol, force_recreate=False, logger=self.P)

    # Track for shared cleanup (parity with FIXED_SIZE_VOLUMES).
    if not hasattr(self, "_fixed_volumes"):
      self._fixed_volumes = []
    self._fixed_volumes.append(vol)

    self.volumes.update(fixed_volume.docker_bind_spec(vol, SYSTEM_VOLUME_MOUNT))

    # Ensure volume-sync subdir exists before container start so the app
    # can drop a request.json on its first tick. Chmod 0o777 so non-root
    # apps inside the container can write here regardless of whether
    # _resolve_image_owner() returned a usable UID/GID. This is safe:
    # the system volume is per-CAR-instance and the app already owns the
    # rest of its container — there's no isolation gain in restricting
    # the control-plane subdir to root.
    vsd = volume_sync_dir(self)
    vsd.mkdir(parents=True, exist_ok=True)
    try:
      os.chmod(str(vsd), 0o777)
    except OSError as exc:
      self.P(
        f"[sync] could not chmod {vsd} to 0o777: {exc}", color="y"
      )
    # Also widen the mount root so writes that need to land at the
    # volume root (rare but possible for future control-plane features)
    # don't 13-EACCES against a root-owned filesystem.
    try:
      os.chmod(str(vol.mount_path), 0o777)
    except OSError as exc:
      self.P(
        f"[sync] could not chmod {vol.mount_path} to 0o777: {exc}", color="y"
      )
    self.P(
      f"[sync] system volume ready: {vol.mount_path} -> {SYSTEM_VOLUME_MOUNT} "
      f"(volume-sync at {vsd})",
      color="g",
    )

  # ----- env-var injection -----------------------------------------------

  def _inject_sync_env_vars(self):
    """Add the ``R1_*`` env vars to the container's environment.

    ``R1_SYSTEM_VOLUME`` / ``R1_VOLUME_SYNC_DIR`` / ``R1_SYNC_REQUEST_FILE``
    are always set so apps can write the request unconditionally; CAR just
    won't act on it without ``SYNC.ENABLED``. ``R1_SYNC_TYPE`` and
    ``R1_SYNC_KEY`` are only set when SYNC is enabled so apps that want to
    branch on role can.
    """
    if not isinstance(getattr(self, "env", None), dict):
      return
    self.env["R1_SYSTEM_VOLUME"] = SYSTEM_VOLUME_MOUNT
    self.env["R1_VOLUME_SYNC_DIR"] = f"{SYSTEM_VOLUME_MOUNT}/{VOLUME_SYNC_SUBDIR}"
    self.env["R1_SYNC_REQUEST_FILE"] = (
      f"{SYSTEM_VOLUME_MOUNT}/{VOLUME_SYNC_SUBDIR}/{SYNC_REQUEST_FILE}"
    )
    if self._sync_enabled():
      sync_type = self.cfg_sync.get("TYPE")
      sync_key = self.cfg_sync.get("KEY")
      if sync_type:
        self.env["R1_SYNC_TYPE"] = str(sync_type)
      if sync_key:
        self.env["R1_SYNC_KEY"] = str(sync_key)

  # ----- config helpers --------------------------------------------------

  def _sync_cfg(self) -> dict:
    cfg = getattr(self, "cfg_sync", None) or {}
    return cfg if isinstance(cfg, dict) else {}

  def _sync_enabled(self) -> bool:
    return bool(self._sync_cfg().get("ENABLED"))

  def _sync_role(self) -> Optional[str]:
    role = self._sync_cfg().get("TYPE")
    if role in ("provider", "consumer"):
      return role
    return None

  def _sync_poll_interval(self) -> float:
    raw = self._sync_cfg().get("POLL_INTERVAL", 10)
    try:
      return max(1.0, float(raw))
    except (TypeError, ValueError):
      return 10.0

  def _sync_initial_timeout(self) -> float:
    raw = self._sync_cfg().get("INITIAL_SYNC_TIMEOUT", 600)
    try:
      return max(0.0, float(raw))
    except (TypeError, ValueError):
      return 600.0

  # convenience for SyncManager (it reads owner.cfg_sync_key)
  @property
  def cfg_sync_key(self):
    return self._sync_cfg().get("KEY")

  @property
  def cfg_sync_type(self):
    return self._sync_cfg().get("TYPE")

  # ----- manager handle ---------------------------------------------------

  def _ensure_sync_manager(self) -> Optional[SyncManager]:
    """Lazy-init the SyncManager. Returns None if SYNC is not enabled."""
    if not self._sync_enabled():
      return None
    sm = getattr(self, "_sync_manager", None)
    if sm is None:
      sm = SyncManager(self)
      self._sync_manager = sm
    return sm

  # ----- recovery on plugin init -----------------------------------------

  def _recover_stale_processing(self):
    """Rename any orphan request.json.processing back to request.json.

    Called from the plugin's on_init so a crash mid-publish doesn't leave
    a request stuck. The next provider tick will then re-claim it.
    """
    vsd = volume_sync_dir(self)
    proc = vsd / SYNC_PROCESSING_FILE
    req = vsd / SYNC_REQUEST_FILE
    if proc.is_file() and not req.exists():
      try:
        os.replace(str(proc), str(req))
        self.P(
          f"[sync] recovered orphan {proc.name} -> {req.name} for retry",
          color="y",
        )
      except OSError as exc:
        self.P(
          f"[sync] failed to recover orphan .processing: {exc}", color="r"
        )

  # ----- provider tick ---------------------------------------------------

  def _sync_provider_tick(self, current_time: float) -> None:
    """If a pending request.json exists, run the full publish flow.

    Drives ``stop_container → publish_snapshot → start_container`` inline.
    Always returns ``None`` — must NOT use a StopReason because that would
    route through ``_restart_container``, which unmounts the system volume
    before we can read from it (see plan Step 1 verification).
    """
    sm = self._ensure_sync_manager()
    if sm is None or self._sync_role() != "provider":
      return
    if not self._sync_should_tick(current_time):
      return

    req = volume_sync_dir(self) / SYNC_REQUEST_FILE
    if not req.is_file():
      return

    self.P(
      f"[sync] provider tick: claiming {req.name} for publish", color="b"
    )
    claimed = sm.claim_request()
    if claimed is None:
      # claim_request already wrote .invalid + response.json
      return
    archive_paths, metadata = claimed

    try:
      self.stop_container()
    except Exception as exc:
      self.P(f"[sync] stop_container before publish failed: {exc}", color="r")

    try:
      sm.publish_snapshot(archive_paths, metadata)
    except Exception as exc:
      # SyncManager.publish_snapshot has internal try/except for every
      # stage, but we still wrap to guarantee we always restart the
      # container even if something truly unexpected escapes.
      self.P(f"[sync] publish_snapshot raised unexpectedly: {exc}", color="r")

    self._sync_safe_start_container()

  # ----- consumer tick ---------------------------------------------------

  def _sync_consumer_tick(self, current_time: float) -> None:
    """If a newer ChainStore record exists, fetch+extract+restart inline."""
    sm = self._ensure_sync_manager()
    if sm is None or self._sync_role() != "consumer":
      return
    if not self._sync_should_tick(current_time):
      return

    record = sm.fetch_latest()
    if not isinstance(record, dict):
      return
    new_version = record.get("version")
    if not isinstance(new_version, int):
      return

    latest_local = sm.latest_received()
    last_version = (latest_local or {}).get("version") if latest_local else None
    if isinstance(last_version, int) and new_version <= last_version:
      return  # already applied

    self.P(
      f"[sync] consumer tick: applying v{new_version} (cid={record.get('cid')})",
      color="b",
    )

    try:
      self.stop_container()
    except Exception as exc:
      self.P(f"[sync] stop_container before apply failed: {exc}", color="r")

    try:
      sm.apply_snapshot(record)
    except Exception as exc:
      self.P(f"[sync] apply_snapshot raised unexpectedly: {exc}", color="r")

    self._sync_safe_start_container()

  # ----- consumer first-boot block ---------------------------------------

  def _sync_initial_consumer_block(self) -> None:
    """Block the consumer's very first start_container until a record exists.

    Polls ChainStore every ``POLL_INTERVAL`` seconds, up to
    ``INITIAL_SYNC_TIMEOUT`` total (0 = wait forever). On timeout: log a
    warning and proceed with an empty system volume. If a record is
    available, applies it before returning so the container starts on a
    populated volume.
    """
    sm = self._ensure_sync_manager()
    if sm is None or self._sync_role() != "consumer":
      return
    # If we've already applied something locally, no need to block.
    if sm.latest_received() is not None:
      return

    deadline = self._sync_initial_timeout()
    poll = self._sync_poll_interval()
    start = self.time()
    forever = deadline == 0
    self.P(
      f"[sync] consumer first-boot: blocking until first snapshot lands "
      f"(timeout={'forever' if forever else f'{deadline:.0f}s'}, poll={poll:.0f}s)",
      color="y",
    )

    while True:
      record = sm.fetch_latest()
      if isinstance(record, dict) and isinstance(record.get("version"), int):
        sm.apply_snapshot(record)
        return
      elapsed = self.time() - start
      if not forever and elapsed >= deadline:
        self.P(
          f"[sync] consumer first-boot timed out after {elapsed:.0f}s — "
          f"starting with an empty system volume",
          color="r",
        )
        return
      # Use the BasePlugin sleep helper if available for hook-friendly
      # cooperative waiting; fall back to time.sleep otherwise.
      sleeper = getattr(self, "sleep", None)
      if callable(sleeper):
        sleeper(poll)
      else:  # pragma: no cover — non-plugin contexts
        import time as _time
        _time.sleep(poll)

  # ----- internal helpers ------------------------------------------------

  def _sync_should_tick(self, current_time: float) -> bool:
    last = getattr(self, "_last_sync_check", 0.0) or 0.0
    if current_time - last < self._sync_poll_interval():
      return False
    self._last_sync_check = current_time
    return True

  def _sync_safe_start_container(self) -> None:
    """Restart the container after a sync slice. Failures are logged, not
    raised, because the periodic loop will retry and ``_check_container_status``
    will pick up a still-stopped container on the next pass.
    """
    try:
      self.start_container()
    except Exception as exc:
      self.P(f"[sync] start_container after sync slice failed: {exc}", color="r")
