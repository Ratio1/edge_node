"""Mixin: provision and teardown fallocate-backed fixed-size volumes."""


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
    Resolve the image's runtime USER to numeric (uid, gid) for volume chown.

    Returns (None, None) when the image has no USER directive or runs as
    root, so the caller can keep the root-owned default behavior.

    Supports:
      - numeric forms: "1000", "1000:1000", "1000:2000"
      - name forms: "appuser", "appuser:appgroup" — resolved via an ephemeral
        `getent passwd` (with a `cat /etc/passwd` fallback for images that
        don't ship `getent`, like distroless).
    """
    try:
      image_ref = self._get_full_image_ref()
      image = self.docker_client.images.get(image_ref)
      raw = (image.attrs.get("Config") or {}).get("User", "") or ""
    except Exception as exc:
      self.P(f"[FixedVolume] Could not inspect image for USER: {exc}", color='y')
      return (None, None)

    raw = raw.strip()
    if not raw or raw == "root" or raw == "0" or raw.startswith("0:"):
      self.P(
        f"[FixedVolume] Image '{image_ref}' runs as root (USER='{raw}'); "
        "keeping root-owned mount"
      )
      return (None, None)

    # Split user[:group]
    user_part, _, group_part = raw.partition(":")

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

    if uid is not None and (gid is not None or not group_part):
      # Fully numeric (or "<uid>" with no group part).
      # Default gid to uid when only uid was provided, matching typical
      # Docker USER conventions (appuser == appuser:appuser).
      if gid is None:
        gid = uid
      self.P(
        f"[FixedVolume] Image '{image_ref}' USER='{raw}' -> uid={uid} gid={gid}"
      )
      return (uid, gid)

    # Name-based (or partially named) form: need to look it up inside the image.
    username = user_part
    groupname = group_part if group_part and _maybe_int(group_part) is None else None
    numeric_gid = _maybe_int(group_part) if group_part else None

    passwd_line = self._lookup_passwd_in_image(image_ref, username)
    if not passwd_line:
      self.P(
        f"[FixedVolume] Could not resolve USER '{raw}' from image '{image_ref}'; "
        "falling back to root-owned mount",
        color='y',
      )
      return (None, None)

    # passwd format: name:x:uid:gid:gecos:home:shell
    parts = passwd_line.split(":")
    try:
      resolved_uid = int(parts[2])
      resolved_gid = int(parts[3])
    except (IndexError, ValueError):
      self.P(
        f"[FixedVolume] Unexpected passwd line for USER '{raw}' in image '{image_ref}': "
        f"{passwd_line!r}; falling back to root-owned mount",
        color='y',
      )
      return (None, None)

    # Group lookup is best-effort: if the USER directive had an explicit group
    # that wasn't numeric, resolve it too. Numeric group wins over passwd gid.
    if numeric_gid is not None:
      resolved_gid = numeric_gid
    elif groupname:
      group_line = self._lookup_group_in_image(image_ref, groupname)
      if group_line:
        gparts = group_line.split(":")
        try:
          resolved_gid = int(gparts[2])
        except (IndexError, ValueError):
          pass

    self.P(
      f"[FixedVolume] Image '{image_ref}' USER='{raw}' -> uid={resolved_uid} gid={resolved_gid}"
    )
    return (resolved_uid, resolved_gid)

  def _lookup_passwd_in_image(self, image_ref, username):
    """Run a throwaway container to look up a username in /etc/passwd."""
    # Prefer `getent passwd <user>` (Debian/Alpine/Ubuntu), fall back to
    # reading /etc/passwd directly (works for distroless images that ship
    # /etc/passwd but not getent).
    for cmd in (
      ["getent", "passwd", username],
      ["cat", "/etc/passwd"],
    ):
      out = self._run_throwaway(image_ref, cmd)
      if not out:
        continue
      for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
          continue
        if line.split(":", 1)[0] == username:
          return line
    return None

  def _lookup_group_in_image(self, image_ref, groupname):
    """Run a throwaway container to look up a group in /etc/group."""
    for cmd in (
      ["getent", "group", groupname],
      ["cat", "/etc/group"],
    ):
      out = self._run_throwaway(image_ref, cmd)
      if not out:
        continue
      for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
          continue
        if line.split(":", 1)[0] == groupname:
          return line
    return None

  def _run_throwaway(self, image_ref, command):
    """
    Run a one-shot throwaway container against `image_ref` with the given
    command, bypassing the image's ENTRYPOINT. Returns decoded stdout on
    success, empty string on any failure (caller handles fallback).
    """
    try:
      out = self.docker_client.containers.run(
        image_ref,
        command=command,
        entrypoint="",
        remove=True,
        stdout=True,
        stderr=False,
      )
      if isinstance(out, bytes):
        out = out.decode("utf-8", errors="replace")
      return out or ""
    except Exception:
      return ""

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

    from pathlib import Path
    try:
      from extensions.business.container_apps import fixed_volume
    except ImportError:
      from . import fixed_volume

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
      configured_names = set(self.cfg_fixed_size_volumes.keys())
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

        vol = fixed_volume.FixedVolume(
          name=logical_name,
          size=str(size),
          root=root,
          fs_type=fs_type,
          owner_uid=owner_uid,
          owner_gid=owner_gid,
        )

        self.P(f"  Provisioning fixed-size volume '{logical_name}' size={size} -> container '{mounting_point}'")
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
      return

    try:
      from extensions.business.container_apps import fixed_volume
    except ImportError:
      from . import fixed_volume

    for vol in self._fixed_volumes:
      try:
        fixed_volume.cleanup(vol, logger=self.P)
      except Exception as exc:
        self.P(f"Failed to cleanup fixed volume '{vol.name}': {exc}", color='r')
    self._fixed_volumes = []
    return
