"""Mixin: provision and teardown fallocate-backed fixed-size volumes."""
from pathlib import Path

from extensions.business.container_apps import fixed_volume
from extensions.business.container_apps.fixed_volume import safe_path_component


class _FixedSizeVolumesMixin:
  """
  Provision and cleanup fallocate-backed fixed-size volumes for a container plugin.

  Required on the composing plugin:
    - self.P(msg, color=...)               (BasePlugin)
    - self.get_data_folder()               (BasePlugin)
    - self._get_instance_data_subfolder()  (plugin)
    - self.cfg_fixed_size_volumes          (plugin config)
    - self.volumes                         (dict, initialized by the plugin)
    - self._fixed_volumes                  (list, initialized by the plugin)
    - self.docker_client                   (docker-py client)
    - self._get_full_image_ref()           (plugin)
  """

  def _resolve_image_owner(self):
    """
    Resolve the image's runtime USER to numeric (uid, gid) for volume chown,
    WITHOUT executing the user-supplied image.

    Returns:
      (None, None) when the image has no USER, runs as root, or uses a
      symbolic name (e.g. "appuser") that can't be resolved without running
      the image. Caller keeps the root-owned default in those cases.

      (uid, gid) for numeric USER directives: "1000", "1000:2000".

    Previously this ran a throwaway container from the target image to read
    /etc/passwd. That expanded the execution surface of volume provisioning
    to user-supplied images before the main runtime start path. We now
    inspect image metadata only. Users with symbolic-USER images and
    non-root ownership needs must set OWNER_UID/OWNER_GID explicitly in
    FIXED_SIZE_VOLUMES.
    """
    try:
      image_ref = self._get_full_image_ref()
      image = self.docker_client.images.get(image_ref)
      raw = (image.attrs.get("Config") or {}).get("User", "") or ""
    except Exception as exc:
      self.P(f"[FixedVolume] Could not inspect image for USER: {exc}", color='y')
      return (None, None)

    raw = raw.strip()
    if not raw or raw in ("root", "0", "0:0", "root:root") or raw.startswith("0:"):
      self.P(
        f"[FixedVolume] Image '{image_ref}' runs as root (USER='{raw}'); "
        "keeping root-owned mount"
      )
      return (None, None)

    user_part, sep, group_part = raw.partition(":")

    def _maybe_int(s):
      s = s.strip()
      if not s:
        return None
      try:
        return int(s)
      except ValueError:
        return None

    uid = _maybe_int(user_part)
    gid = _maybe_int(group_part) if group_part else None

    if uid is not None and (not group_part or gid is not None):
      # Fully numeric. Default gid to uid when only uid was given.
      if gid is None:
        gid = uid
      self.P(
        f"[FixedVolume] Image '{image_ref}' USER='{raw}' -> uid={uid} gid={gid}"
      )
      return (uid, gid)

    self.P(
      f"[FixedVolume] Image '{image_ref}' USER='{raw}' is symbolic and cannot "
      "be resolved without running the image. Volume will be root-owned. "
      "Set OWNER_UID/OWNER_GID in FIXED_SIZE_VOLUMES to override.",
      color='y',
    )
    return (None, None)

  def _configure_fixed_size_volumes(self):
    """
    Processes FIXED_SIZE_VOLUMES configuration to create file-backed,
    fixed-size volumes and mount them into the container via loop devices.

    FIXED_SIZE_VOLUMES format:
      {
        "vol_name": {
          "SIZE": "100M",
          "MOUNTING_POINT": "/container/path",
          "FS_TYPE": "ext4",        # optional
          "OWNER_UID": None,        # optional
          "OWNER_GID": None,        # optional
          "FORCE_RECREATE": False   # optional
        }
      }
    """
    if not hasattr(self, 'cfg_fixed_size_volumes') or not self.cfg_fixed_size_volumes:
      return

    if not isinstance(self.cfg_fixed_size_volumes, dict):
      self.P("FIXED_SIZE_VOLUMES must be a dictionary, skipping", color='r')
      return

    # Reject logical names that sanitize to the same backing name. Without
    # this check `"a/b"` and `"a?b"` would both normalize to `"a_b"` and
    # silently alias the same image/meta/mount paths, breaking isolation.
    from collections import defaultdict
    safe_to_logicals = defaultdict(list)
    for logical in self.cfg_fixed_size_volumes.keys():
      safe_to_logicals[safe_path_component(logical)].append(logical)
    collisions = {s: ls for s, ls in safe_to_logicals.items() if len(ls) > 1}
    if collisions:
      details = "; ".join(f"{s!r} <- {ls}" for s, ls in collisions.items())
      raise ValueError(
        f"FIXED_SIZE_VOLUMES: multiple logical names normalize to the same "
        f"sanitized name: {details}. Rename keys to use only [A-Za-z0-9._-]."
      )

    # Check required tools
    try:
      fixed_volume._require_tools(logger=self.P)
    except RuntimeError as exc:
      self.P(
        f"Fixed-size volumes unavailable: {exc}. "
        f"Container will start without fixed-size volumes.",
        color='r'
      )
      return

    # Build root path using existing per-plugin data directory
    root = Path(self.get_data_folder()) / self._get_instance_data_subfolder() / "fixed_volumes"

    # Recover from prior crashes
    fixed_volume.cleanup_stale_mounts(root, logger=self.P)

    # Detect orphaned volumes (in meta/ but not in config)
    meta_dir = root / "meta"
    if meta_dir.is_dir():
      existing_names = {f.stem for f in meta_dir.glob("*.json")}
      configured_names = {safe_path_component(k) for k in self.cfg_fixed_size_volumes.keys()}
      orphaned = existing_names - configured_names
      for name in orphaned:
        self.P(
          f"WARNING: Fixed-size volume '{name}' exists on disk but is not in config. "
          f"Orphaned volume data at {root}. Remove manually or re-add to config.",
          color='y'
        )

    provisioned = []
    try:
      for logical_name, vol_config in self.cfg_fixed_size_volumes.items():
        if not isinstance(vol_config, dict):
          self.P(f"FIXED_SIZE_VOLUMES['{logical_name}'] must be a dict, skipping", color='r')
          continue

        size = vol_config.get('SIZE')
        mounting_point = vol_config.get('MOUNTING_POINT')

        if not size:
          self.P(f"FIXED_SIZE_VOLUMES['{logical_name}'] missing 'SIZE' field, skipping", color='r')
          continue

        if not mounting_point:
          self.P(f"FIXED_SIZE_VOLUMES['{logical_name}'] missing 'MOUNTING_POINT' field, skipping", color='r')
          continue

        fs_type = vol_config.get('FS_TYPE', 'ext4')
        owner_uid = vol_config.get('OWNER_UID')
        owner_gid = vol_config.get('OWNER_GID')
        force_recreate = vol_config.get('FORCE_RECREATE', False)

        # Auto-detect UID/GID from the image's USER directive when the user
        # didn't override. This makes volumes writable for non-root images
        # (e.g. USER appuser) without needing explicit OWNER_UID/OWNER_GID
        # in every config. Images that run as root get (None, None) and keep
        # the historical root-owned behavior.
        # NOTE: mount_volume() re-chowns on every mount, so this also corrects
        # ownership on reused volumes (FORCE_RECREATE not required).
        if owner_uid is None and owner_gid is None:
          owner_uid, owner_gid = self._resolve_image_owner()

        safe_name = safe_path_component(logical_name)
        vol = fixed_volume.FixedVolume(
          name=safe_name,
          size=str(size),
          root=root,
          fs_type=fs_type,
          owner_uid=owner_uid,
          owner_gid=owner_gid,
        )

        self.P(f"  Provisioning fixed-size volume '{logical_name}' -> '{safe_name}' size={size} -> container '{mounting_point}'")
        fixed_volume.provision(vol, force_recreate=force_recreate, logger=self.P)
        provisioned.append(vol)

        bind_spec = fixed_volume.docker_bind_spec(vol, str(mounting_point))
        self.volumes.update(bind_spec)
        self._fixed_volumes.append(vol)

        self.P(f"  Fixed-size volume '{logical_name}' ready: {vol.mount_path} -> {mounting_point}", color='g')

    except Exception as exc:
      self.P(f"Error during fixed-size volume provisioning: {exc}", color='r')
      # Clean up already-provisioned volumes before re-raising
      for vol in provisioned:
        try:
          fixed_volume.cleanup(vol, logger=self.P)
        except Exception:
          pass
      raise
    return


  def _cleanup_fixed_size_volumes(self):
    """
    Unmount and detach loop devices for all provisioned fixed-size volumes.
    Called during container stop/close to free loop device resources.
    """
    if not hasattr(self, '_fixed_volumes') or not self._fixed_volumes:
      return True

    result = True
    remaining_volumes = []
    for vol in self._fixed_volumes:
      try:
        cleaned = fixed_volume.cleanup(vol, logger=self.P)
        if not cleaned:
          result = False
          remaining_volumes.append(vol)
      except Exception as exc:
        result = False
        remaining_volumes.append(vol)
        self.P(f"Failed to cleanup fixed volume '{vol.name}': {exc}", color='r')
    self._fixed_volumes = remaining_volumes
    return result
