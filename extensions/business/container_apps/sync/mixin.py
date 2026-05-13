"""Mixin: volume-sync provider/consumer integration for CAR.

Bridges :class:`SyncManager` into ``ContainerAppRunnerPlugin``'s lifecycle:

  * always-on: provisions the 10M ``/r1en_system`` system volume (a fixed-size
    loopback identical in machinery to ``FIXED_SIZE_VOLUMES``) and exports
    ``R1_*`` env vars to the container
  * provider role: per ``cfg_sync_poll_interval`` polls for a pending
    ``request.json``, then drives runtime stop → publish_snapshot →
    start_container inline (must NOT route through ``_restart_container``,
    which calls ``_cleanup_fixed_size_volumes`` and unmounts the loopback
    before we can read from it)
  * consumer role: same cadence polls ChainStore for newer ``version``, then
    drives runtime stop → apply_snapshot → start_container inline.
    First boot starts on an empty volume; the next tick picks up whatever
    snapshot is in ChainStore. Apps that strictly require state at startup
    must implement their own poll-and-retry in their entrypoint.
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

from .control_files import JsonControlFile
from .constants import (
  SYNC_PROCESSING_FILE,
  SYNC_REQUEST_FILE,
  SYSTEM_VOLUME_FS,
  SYSTEM_VOLUME_MOUNT,
  SYSTEM_VOLUME_NAME,
  SYSTEM_VOLUME_SIZE,
  VOLUME_SYNC_SUBDIR,
)
from .manager import (
  CONSUMER_APPLY_OFFLINE_RESTART,
  CONSUMER_APPLY_ONLINE_NO_RESTART,
  CONSUMER_APPLY_ONLINE_RESTART,
  SyncManager,
  history_received_dir,
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
    - self._stop_container_runtime_for_restart(),
      self.start_container()  (CAR lifecycle)
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
      # Without the host tools we cannot provision /r1en_system, which means
      # there is no shared filesystem for the app to drop request.json into
      # and no host root for CAR to poll. Mark sync as unavailable so
      # _sync_enabled() returns False (skipping all provider/consumer ticks)
      # and _inject_sync_env_vars() refuses to advertise R1_SYSTEM_VOLUME
      # to the container — otherwise the app would write to a non-existent
      # in-container mount while CAR polled a host root that was never
      # provisioned. Codex review finding 5 on PR #399.
      self.P(
        f"[sync] system volume unavailable: {exc}. "
        f"SYNC will be disabled and R1_SYSTEM_VOLUME env vars will not be "
        f"exported until host tools are installed.",
        color="r",
      )
      self._sync_unavailable = True
      return

    root = (
      Path(self.get_data_folder())
      / self._get_instance_data_subfolder()
      / "fixed_volumes"
    )

    # NOTE: deliberately do NOT call fixed_volume.cleanup_stale_mounts here.
    # _FixedSizeVolumesMixin._configure_fixed_size_volumes() runs BEFORE us
    # in on_init / _restart_container and already scans meta/ for the whole
    # root. Calling it again from here would unmount any FIXED_SIZE_VOLUMES
    # entries that the previous step just provisioned (because their meta/
    # files exist) and then we'd never re-mount them — the data volume
    # would land empty in the container.

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
    try:
      fixed_volume.provision(vol, force_recreate=False, logger=self.P)
    except Exception as exc:
      # Tool presence alone is not enough: hosts can still lack usable loop
      # devices, mount privileges, or filesystem support. Container execution
      # should continue without advertising the sync volume in that case.
      self.P(
        f"[sync] system volume unavailable: could not provision "
        f"{SYSTEM_VOLUME_NAME}: {exc}. SYNC will be disabled and "
        f"R1_SYSTEM_VOLUME env vars will not be exported.",
        color="r",
      )
      self._sync_unavailable = True
      return

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
    os.makedirs(str(vsd), exist_ok=True)
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

    If ``_sync_unavailable`` was set during ``_configure_system_volume``
    (host tools missing), inject nothing — advertising a mount that was
    never provisioned would route the app's writes into a phantom path.
    """
    if not isinstance(getattr(self, "env", None), dict):
      return
    if getattr(self, "_sync_unavailable", False):
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
    if getattr(self, "_sync_unavailable", False):
      return False
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

  # ----- hsync interval (consumer only) ----------------------------------
  # Decoupled from POLL_INTERVAL: every consumer tick still does the cheap
  # chainstore_hget against the local replica, but the expensive network
  # hsync is gated by this interval. Provider does not call hsync.
  _HSYNC_POLL_INTERVAL_MIN = 300.0
  _HSYNC_POLL_INTERVAL_DEFAULT = 600.0

  def _hsync_poll_interval(self) -> float:
    """Seconds between chainstore_hsync refreshes on the consumer side.

    Min 300s, default 600s. Non-numeric values fall back to the default;
    values below the min are clamped up.

    .. note::
       DEBUG/DEVELOPMENT ONLY — to be removed. The HSYNC_POLL_INTERVAL
       config field exists temporarily so we can dial down the hsync
       network burn while ChainStore propagation is still being tuned on
       devnet. Once propagation is reliable, this should become a fixed
       internal default and the operator-tunable field should be deleted
       from the SYNC config block.
    """
    raw = self._sync_cfg().get("HSYNC_POLL_INTERVAL", self._HSYNC_POLL_INTERVAL_DEFAULT)
    try:
      v = float(raw)
    except (TypeError, ValueError):
      return self._HSYNC_POLL_INTERVAL_DEFAULT
    return max(self._HSYNC_POLL_INTERVAL_MIN, v)

  # convenience for SyncManager (it reads owner.cfg_sync_key)
  @property
  def cfg_sync_key(self):
    return self._sync_cfg().get("KEY")

  @property
  def cfg_sync_type(self):
    return self._sync_cfg().get("TYPE")

  @property
  def cfg_sync_hsync_poll_interval(self) -> float:
    """Mirror of ``_hsync_poll_interval()`` accessible by ``SyncManager``
    via ``owner.cfg_sync_hsync_poll_interval`` (same convention as
    ``cfg_sync_key`` / ``cfg_sync_type``).
    """
    return self._hsync_poll_interval()

  @property
  def cfg_sync_allow_online_provider_capture(self) -> bool:
    """Provider-local opt-in for Docker archive capture from live containers."""
    return bool(self._sync_cfg().get("ALLOW_ONLINE_PROVIDER_CAPTURE"))

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
    control_file = JsonControlFile(
      volume_sync_dir(self), SYNC_REQUEST_FILE, SYNC_PROCESSING_FILE
    )
    proc = control_file.processing_path
    req = control_file.pending_path
    try:
      recovered = control_file.recover_stale_processing()
    except OSError as exc:
      self.P(
        f"[sync] failed to recover orphan .processing: {exc}", color="r"
      )
      return
    if recovered:
      self.P(
        f"[sync] recovered orphan {proc.name} -> {req.name} for retry",
        color="y",
      )

  # ----- provider tick ---------------------------------------------------

  def _sync_provider_tick(self, current_time: float) -> None:
    """If a pending request.json exists, run the full publish flow.

    Drives runtime stop → publish_snapshot → start_container inline.
    Always returns ``None`` — must NOT use a StopReason because that would
    route through ``_restart_container``, which unmounts the system volume
    before we can read from it (see plan Step 1 verification).
    """
    sm = self._ensure_sync_manager()
    if sm is None or self._sync_role() != "provider":
      return
    if not self._sync_should_tick(current_time):
      return

    control_file = JsonControlFile(
      volume_sync_dir(self), SYNC_REQUEST_FILE, SYNC_PROCESSING_FILE
    )
    if not control_file.has_pending():
      return

    self.P(
      f"[sync] provider tick: claiming {control_file.pending_name} for publish",
      color="b",
    )
    claimed = sm.claim_request()
    if claimed is None:
      # claim_request already wrote .invalid + response.json
      return

    stopped_for_sync = claimed.runtime.provider_capture == "offline"
    if stopped_for_sync:
      self._stop_container_runtime_for_restart()

    try:
      sm.publish_snapshot(claimed)
    except Exception as exc:
      # SyncManager.publish_snapshot has internal try/except for every
      # stage, but we still wrap to guarantee we always restart the
      # container even if something truly unexpected escapes.
      self.P(f"[sync] publish_snapshot raised unexpectedly: {exc}", color="r")

    if stopped_for_sync:
      self._sync_safe_start_container()

  # ----- consumer tick ---------------------------------------------------

  def _sync_consumer_tick(self, current_time: float) -> None:
    """If the ChainStore record points at a different CID than what we last
    applied, fetch+extract+restart inline. Identity is the CID, not the
    version: the CID is content-addressed and uniquely identifies the
    bundle, while ``version`` is informational metadata only (kept for
    filename ordering + human-readable logs). Comparing CIDs eliminates
    a class of clock-skew failure modes (a provider's wonky timestamp
    can never make a consumer permanently ignore a corrected snapshot)
    and makes multi-provider sync sets coherent without ordering
    assumptions.
    """
    sm = self._ensure_sync_manager()
    if sm is None or self._sync_role() != "consumer":
      return
    if not self._sync_should_tick(current_time):
      return

    record = sm.fetch_latest()
    if not isinstance(record, dict):
      return
    record_cid = record.get("cid")
    if not record_cid:
      return

    latest_local = sm.latest_received()
    last_cid = (latest_local or {}).get("cid") if latest_local else None
    if last_cid and record_cid == last_cid:
      return  # same bundle as the last apply — nothing to do

    self.P(
      f"[sync] consumer tick: applying cid={record_cid} "
      f"(v{record.get('version')})",
      color="b",
    )

    apply_mode = self._sync_consumer_apply_mode(record)
    if apply_mode == CONSUMER_APPLY_OFFLINE_RESTART:
      self._stop_container_runtime_for_restart()

    applied = False
    try:
      applied = bool(sm.apply_snapshot(record))
    except Exception as exc:
      self.P(f"[sync] apply_snapshot raised unexpectedly: {exc}", color="r")

    if apply_mode == CONSUMER_APPLY_OFFLINE_RESTART:
      self._sync_safe_start_container()
    elif apply_mode == CONSUMER_APPLY_ONLINE_RESTART and applied:
      self._stop_container_runtime_for_restart()
      self._sync_safe_start_container()

  # ----- internal helpers ------------------------------------------------

  def _sync_consumer_apply_mode(self, record: Optional[dict] = None) -> str:
    """Return the consumer-local lifecycle policy for snapshot apply.

    Provider-published records may carry the requester's desired
    ``runtime.consumer_apply`` for audit/UI purposes, but lifecycle safety is
    decided by the consumer node. A provider must not be able to force a
    running consumer to hot-apply files without local operator opt-in.
    """
    mode = self._sync_cfg().get("CONSUMER_APPLY_MODE", CONSUMER_APPLY_OFFLINE_RESTART)
    allowed = {
      CONSUMER_APPLY_OFFLINE_RESTART,
      CONSUMER_APPLY_ONLINE_NO_RESTART,
      CONSUMER_APPLY_ONLINE_RESTART,
    }
    if mode not in allowed:
      self.P(
        f"[sync] unknown local CONSUMER_APPLY_MODE {mode!r}; using "
        f"{CONSUMER_APPLY_OFFLINE_RESTART!r}",
        color="y",
      )
      return CONSUMER_APPLY_OFFLINE_RESTART
    return mode

  def _sync_record_consumer_apply_mode(self, record: dict) -> str:
    """Backward-compatible wrapper for tests/older call sites."""
    return self._sync_consumer_apply_mode(record)

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

    Calls ``_reset_runtime_state_post_start`` after the start so that
    readiness gates, health-probe timers, log capture, and
    BUILD_AND_RUN_COMMANDS all re-engage against the freshly-started
    container — same contract ``_restart_container`` follows. Without this,
    tunnels stay marked ready, health checks are skipped, log streams are
    stale, and image-defined startup commands don't rerun.

    The reset is guarded by its own try/except so a failed reset does not
    roll back a successful start — the next periodic tick can re-evaluate
    readiness.
    """
    try:
      self.start_container()
    except Exception as exc:
      self.P(f"[sync] start_container after sync slice failed: {exc}", color="r")
      return
    try:
      self._reset_runtime_state_post_start()
    except Exception as exc:
      self.P(
        f"[sync] runtime-state reset after sync slice failed: {exc}", color="r"
      )
