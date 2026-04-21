"""Tests for fixed_volume.py module and _ContainerUtilsMixin integration."""

import json
import os
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

from extensions.business.container_apps.fixed_volume import (
  FixedVolume,
  _parse_size_to_bytes,
  _require_tools,
  _is_path_mounted,
  docker_bind_spec,
  ensure_created,
  attach_loop,
  mount_volume,
  cleanup,
  cleanup_stale_mounts,
  provision,
  _remove_lost_found,
)


# ---------------------------------------------------------------------------
# Unit tests for FixedVolume dataclass
# ---------------------------------------------------------------------------

class TestFixedVolumeDataclass(unittest.TestCase):

  def test_paths_computed_from_root_and_name(self):
    vol = FixedVolume(name="data", size="100M", root=Path("/tmp/fv"))
    self.assertEqual(vol.img_path, Path("/tmp/fv/images/data.img"))
    self.assertEqual(vol.mount_path, Path("/tmp/fv/mounts/data"))
    self.assertEqual(vol.meta_path, Path("/tmp/fv/meta/data.json"))

  def test_defaults(self):
    vol = FixedVolume(name="x", size="1G", root=Path("/r"))
    self.assertEqual(vol.fs_type, "ext4")
    self.assertIsNone(vol.owner_uid)
    self.assertIsNone(vol.owner_gid)


# ---------------------------------------------------------------------------
# Unit tests for _parse_size_to_bytes
# ---------------------------------------------------------------------------

class TestParseSizeToBytes(unittest.TestCase):

  def test_megabytes(self):
    self.assertEqual(_parse_size_to_bytes("100M"), 100 * 1024**2)

  def test_gigabytes(self):
    self.assertEqual(_parse_size_to_bytes("1G"), 1024**3)

  def test_kilobytes(self):
    self.assertEqual(_parse_size_to_bytes("512K"), 512 * 1024)

  def test_terabytes(self):
    self.assertEqual(_parse_size_to_bytes("2T"), 2 * 1024**4)

  def test_plain_bytes(self):
    self.assertEqual(_parse_size_to_bytes("1048576"), 1048576)

  def test_case_insensitive(self):
    self.assertEqual(_parse_size_to_bytes("100m"), 100 * 1024**2)


# ---------------------------------------------------------------------------
# Unit tests for docker_bind_spec
# ---------------------------------------------------------------------------

class TestDockerBindSpec(unittest.TestCase):

  def test_returns_correct_format(self):
    vol = FixedVolume(name="data", size="50M", root=Path("/r"))
    spec = docker_bind_spec(vol, "/app/data")
    expected = {str(vol.mount_path): {"bind": "/app/data", "mode": "rw"}}
    self.assertEqual(spec, expected)


# ---------------------------------------------------------------------------
# Unit tests for _require_tools
# ---------------------------------------------------------------------------

class TestRequireTools(unittest.TestCase):

  @patch("shutil.which", return_value="/usr/bin/tool")
  def test_all_tools_present(self, mock_which):
    _require_tools()  # should not raise

  @patch("shutil.which", side_effect=lambda t: None if t == "losetup" else "/usr/bin/x")
  def test_missing_tool_raises(self, mock_which):
    with self.assertRaises(RuntimeError) as ctx:
      _require_tools()
    self.assertIn("losetup", str(ctx.exception))


# ---------------------------------------------------------------------------
# Unit tests for ensure_created
# ---------------------------------------------------------------------------

class TestEnsureCreated(unittest.TestCase):

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_new_image_calls_fallocate_and_mkfs(self, mock_run):
    vol = FixedVolume(name="data", size="100M", root=Path("/tmp/test_fv"))
    with patch.object(Path, "exists", return_value=False), \
         patch.object(Path, "mkdir"):
      ensure_created(vol)

    cmds = [call[0][0] for call in mock_run.call_args_list]
    self.assertEqual(cmds[0][0], "fallocate")
    self.assertIn("-m", cmds[1])  # mkfs.ext4 -F -m 0
    self.assertEqual(cmds[1][0], "mkfs.ext4")

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_existing_image_skips_allocation(self, mock_run):
    vol = FixedVolume(name="data", size="100M", root=Path("/tmp/test_fv"))
    stat_result = MagicMock()
    stat_result.st_size = 100 * 1024**2  # matches config
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "stat", return_value=stat_result), \
         patch.object(Path, "mkdir"):
      ensure_created(vol)

    cmds = [call[0][0] for call in mock_run.call_args_list]
    # Should NOT call fallocate, only blkid
    self.assertTrue(all(c[0] != "fallocate" for c in cmds))

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_size_mismatch_logs_warning(self, mock_run):
    vol = FixedVolume(name="data", size="200M", root=Path("/tmp/test_fv"))
    stat_result = MagicMock()
    stat_result.st_size = 100 * 1024**2  # 100M != 200M
    logged = []
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "stat", return_value=stat_result), \
         patch.object(Path, "mkdir"):
      ensure_created(vol, logger=lambda m: logged.append(m))

    warning_msgs = [m for m in logged if "mismatch" in m.lower()]
    self.assertTrue(len(warning_msgs) > 0, "Expected size mismatch warning")


# ---------------------------------------------------------------------------
# Unit tests for attach_loop
# ---------------------------------------------------------------------------

class TestAttachLoop(unittest.TestCase):

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_reuses_existing_device(self, mock_run):
    mock_run.return_value = "/dev/loop5: ..."
    vol = FixedVolume(name="data", size="100M", root=Path("/r"))
    # First call is losetup -j, which returns existing device
    mock_run.side_effect = ["/dev/loop5: [...]"]
    result = attach_loop(vol)
    self.assertEqual(result, "/dev/loop5")

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_creates_new_device(self, mock_run):
    # First call: losetup -j returns empty; second: losetup -f returns new device
    mock_run.side_effect = ["", "/dev/loop7"]
    vol = FixedVolume(name="data", size="100M", root=Path("/r"))
    result = attach_loop(vol)
    self.assertEqual(result, "/dev/loop7")


# ---------------------------------------------------------------------------
# Unit tests for _is_path_mounted (exact /proc/mounts matching)
# ---------------------------------------------------------------------------

class TestIsPathMounted(unittest.TestCase):

  def _proc_mounts(self, data):
    return patch("builtins.open", mock_open(read_data=data))

  def test_exact_match_returns_true(self):
    data = "/dev/loop0 /r/mounts/data ext4 rw 0 0\n"
    with self._proc_mounts(data):
      self.assertTrue(_is_path_mounted("/r/mounts/data"))

  def test_prefix_sibling_does_not_alias(self):
    # Previously a substring check matched /r/mounts/data against
    # /r/mounts/data2 and made callers skip the real mount step.
    data = "/dev/loop0 /r/mounts/data2 ext4 rw 0 0\n"
    with self._proc_mounts(data):
      self.assertFalse(_is_path_mounted("/r/mounts/data"))

  def test_trailing_slash_normalized(self):
    data = "/dev/loop0 /r/mounts/data ext4 rw 0 0\n"
    with self._proc_mounts(data):
      self.assertTrue(_is_path_mounted("/r/mounts/data/"))

  def test_octal_escaped_space_in_mountpoint(self):
    # /proc/mounts encodes a space as \040.
    data = "/dev/loop0 /r/with\\040space ext4 rw 0 0\n"
    with self._proc_mounts(data):
      self.assertTrue(_is_path_mounted("/r/with space"))

  def test_malformed_lines_ignored(self):
    data = "garbage\n\n/dev/loop0 /r/mounts/data ext4 rw 0 0\n"
    with self._proc_mounts(data):
      self.assertTrue(_is_path_mounted("/r/mounts/data"))
      self.assertFalse(_is_path_mounted("/r/mounts/missing"))

  def test_returns_false_when_proc_mounts_unreadable(self):
    with patch("builtins.open", side_effect=OSError("permission denied")):
      self.assertFalse(_is_path_mounted("/anything"))


# ---------------------------------------------------------------------------
# Unit tests for mount_volume
# ---------------------------------------------------------------------------

class TestMountVolume(unittest.TestCase):

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_skips_already_mounted(self, mock_run):
    vol = FixedVolume(name="data", size="100M", root=Path("/r"))
    mount_data = f"/dev/loop0 {vol.mount_path} ext4 rw 0 0\n"
    with patch("builtins.open", mock_open(read_data=mount_data)):
      is_fresh = mount_volume(vol, "/dev/loop0")
    self.assertFalse(is_fresh)
    mock_run.assert_not_called()

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_does_not_alias_prefix_sibling_mount(self, mock_run):
    # /r/mounts/data2 is mounted; /r/mounts/data must NOT be treated as
    # already mounted, so mount_volume must still call `mount -t`.
    vol = FixedVolume(name="data", size="100M", root=Path("/r"))
    mount_data = "/dev/loop0 /r/mounts/data2 ext4 rw 0 0\n"
    with patch("builtins.open", mock_open(read_data=mount_data)):
      is_fresh = mount_volume(vol, "/dev/loop0")
    self.assertTrue(is_fresh)
    mock_run.assert_called()


# ---------------------------------------------------------------------------
# Unit tests for cleanup
# ---------------------------------------------------------------------------

class TestCleanup(unittest.TestCase):

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_handles_missing_metadata(self, mock_run):
    vol = FixedVolume(name="data", size="100M", root=Path("/nonexistent"))
    # Should not raise even if meta_path doesn't exist
    cleanup(vol)

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_handles_umount_failure(self, mock_run):
    vol = FixedVolume(name="data", size="100M", root=Path("/tmp/fv"))
    meta = {"loop_dev": "/dev/loop3"}
    mock_run.side_effect = [Exception("umount fail"), None]  # umount fails, losetup succeeds
    with patch.object(Path, "exists", return_value=True), \
         patch.object(Path, "read_text", return_value=json.dumps(meta)):
      cleanup(vol)  # should not raise


# ---------------------------------------------------------------------------
# Unit tests for cleanup_stale_mounts
# ---------------------------------------------------------------------------

class TestCleanupStaleMounts(unittest.TestCase):

  def test_no_op_when_meta_dir_missing(self):
    cleanup_stale_mounts(Path("/nonexistent"))  # should not raise

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_skips_when_not_in_proc_mounts(self, mock_run):
    """After edge node restart, nothing is mounted, so cleanup is a no-op."""
    root = Path("/tmp/fv")
    meta = {"mount_path": "/tmp/fv/mounts/data", "loop_dev": "/dev/loop3"}

    with patch.object(Path, "is_dir", return_value=True), \
         patch.object(Path, "glob", return_value=[Path("/tmp/fv/meta/data.json")]), \
         patch.object(Path, "read_text", return_value=json.dumps(meta)), \
         patch("builtins.open", mock_open(read_data="")):
      cleanup_stale_mounts(root)

    # _run should NOT be called since mount is not in /proc/mounts
    mock_run.assert_not_called()

  @patch("extensions.business.container_apps.fixed_volume._run")
  def test_prefix_sibling_does_not_trigger_cleanup(self, mock_run):
    """A sibling mount sharing a prefix must not cause cleanup of a different
    stale entry. Previously substring matching aliased /data onto /data2."""
    root = Path("/tmp/fv")
    # Meta says /tmp/fv/mounts/data is the recorded mount, but only
    # /tmp/fv/mounts/data2 is actually mounted.
    meta = {"mount_path": "/tmp/fv/mounts/data", "loop_dev": "/dev/loop3"}
    proc = "/dev/loop0 /tmp/fv/mounts/data2 ext4 rw 0 0\n"

    with patch.object(Path, "is_dir", return_value=True), \
         patch.object(Path, "glob", return_value=[Path("/tmp/fv/meta/data.json")]), \
         patch.object(Path, "read_text", return_value=json.dumps(meta)), \
         patch("builtins.open", mock_open(read_data=proc)):
      cleanup_stale_mounts(root)

    mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Unit tests for provision
# ---------------------------------------------------------------------------

class TestProvision(unittest.TestCase):

  @patch("extensions.business.container_apps.fixed_volume._remove_lost_found")
  @patch("extensions.business.container_apps.fixed_volume.write_meta")
  @patch("extensions.business.container_apps.fixed_volume.mount_volume", return_value=True)
  @patch("extensions.business.container_apps.fixed_volume.attach_loop", return_value="/dev/loop0")
  @patch("extensions.business.container_apps.fixed_volume.ensure_created")
  def test_full_flow_new_volume(self, mock_ensure, mock_attach, mock_mount, mock_meta, mock_lf):
    vol = FixedVolume(name="data", size="100M", root=Path("/r"))
    with patch.object(Path, "exists", return_value=False):
      result = provision(vol)
    self.assertIs(result, vol)
    mock_ensure.assert_called_once()
    mock_attach.assert_called_once()
    mock_mount.assert_called_once()
    mock_meta.assert_called_once()
    mock_lf.assert_called_once()  # lost+found removed on new volume

  @patch("extensions.business.container_apps.fixed_volume._remove_lost_found")
  @patch("extensions.business.container_apps.fixed_volume.write_meta")
  @patch("extensions.business.container_apps.fixed_volume.mount_volume", return_value=False)
  @patch("extensions.business.container_apps.fixed_volume.attach_loop", return_value="/dev/loop0")
  @patch("extensions.business.container_apps.fixed_volume.ensure_created")
  def test_remount_skips_lost_found(self, mock_ensure, mock_attach, mock_mount, mock_meta, mock_lf):
    vol = FixedVolume(name="data", size="100M", root=Path("/r"))
    with patch.object(Path, "exists", return_value=True):
      provision(vol)
    mock_lf.assert_not_called()  # NOT removed on re-mount


# ---------------------------------------------------------------------------
# Integration tests for _ContainerUtilsMixin methods
# ---------------------------------------------------------------------------

from extensions.business.container_apps.tests.support import make_container_app_runner


class TestConfigureFixedSizeVolumes(unittest.TestCase):

  def _make_plugin(self, **overrides):
    plugin = make_container_app_runner()
    plugin.cfg_fixed_size_volumes = overrides.get("cfg_fixed_size_volumes", {})
    plugin._fixed_volumes = []
    plugin.get_data_folder = lambda: "/tmp/test_data"
    plugin._get_instance_data_subfolder = lambda: "container_apps/test_plugin"
    return plugin

  def test_empty_config_is_noop(self):
    plugin = self._make_plugin(cfg_fixed_size_volumes={})
    plugin._configure_fixed_size_volumes()
    self.assertEqual(plugin._fixed_volumes, [])
    self.assertEqual(plugin.volumes, {})

  def test_missing_size_skips_entry(self):
    plugin = self._make_plugin(cfg_fixed_size_volumes={
      "data": {"MOUNTING_POINT": "/app/data"}
    })
    with patch("extensions.business.container_apps.fixed_volume._require_tools"), \
         patch("extensions.business.container_apps.fixed_volume.cleanup_stale_mounts"), \
         patch.object(Path, "is_dir", return_value=False):
      plugin._configure_fixed_size_volumes()
    self.assertEqual(plugin._fixed_volumes, [])
    warnings = [m for m in plugin.logged_messages if "SIZE" in m]
    self.assertTrue(len(warnings) > 0)

  def test_missing_mounting_point_skips_entry(self):
    plugin = self._make_plugin(cfg_fixed_size_volumes={
      "data": {"SIZE": "100M"}
    })
    with patch("extensions.business.container_apps.fixed_volume._require_tools"), \
         patch("extensions.business.container_apps.fixed_volume.cleanup_stale_mounts"), \
         patch.object(Path, "is_dir", return_value=False):
      plugin._configure_fixed_size_volumes()
    self.assertEqual(plugin._fixed_volumes, [])
    warnings = [m for m in plugin.logged_messages if "MOUNTING_POINT" in m]
    self.assertTrue(len(warnings) > 0)

  @patch("extensions.business.container_apps.fixed_volume.docker_bind_spec",
         return_value={"/host/mount": {"bind": "/app/data", "mode": "rw"}})
  @patch("extensions.business.container_apps.fixed_volume.provision")
  @patch("extensions.business.container_apps.fixed_volume.cleanup_stale_mounts")
  @patch("extensions.business.container_apps.fixed_volume._require_tools")
  def test_successful_provision_populates_volumes(self, mock_tools, mock_stale, mock_prov, mock_spec):
    plugin = self._make_plugin(cfg_fixed_size_volumes={
      "data": {"SIZE": "100M", "MOUNTING_POINT": "/app/data"}
    })
    with patch.object(Path, "is_dir", return_value=False):
      plugin._configure_fixed_size_volumes()

    self.assertEqual(len(plugin._fixed_volumes), 1)
    self.assertEqual(plugin._fixed_volumes[0].name, "data")
    self.assertIn("/host/mount", plugin.volumes)
    mock_prov.assert_called_once()

  @patch("extensions.business.container_apps.fixed_volume._require_tools",
         side_effect=RuntimeError("missing tools"))
  def test_missing_tools_returns_without_crash(self, mock_tools):
    plugin = self._make_plugin(cfg_fixed_size_volumes={
      "data": {"SIZE": "100M", "MOUNTING_POINT": "/app/data"}
    })
    plugin._configure_fixed_size_volumes()
    self.assertEqual(plugin._fixed_volumes, [])
    errors = [m for m in plugin.logged_messages if "unavailable" in m.lower()]
    self.assertTrue(len(errors) > 0)


class TestCleanupFixedSizeVolumes(unittest.TestCase):

  def test_noop_when_empty(self):
    plugin = make_container_app_runner()
    plugin._fixed_volumes = []
    plugin._cleanup_fixed_size_volumes()
    self.assertEqual(plugin._fixed_volumes, [])

  @patch("extensions.business.container_apps.fixed_volume.cleanup")
  def test_calls_cleanup_for_each_volume(self, mock_cleanup):
    plugin = make_container_app_runner()
    vol1 = FixedVolume(name="a", size="50M", root=Path("/r"))
    vol2 = FixedVolume(name="b", size="50M", root=Path("/r"))
    plugin._fixed_volumes = [vol1, vol2]
    plugin._cleanup_fixed_size_volumes()
    self.assertEqual(mock_cleanup.call_count, 2)
    self.assertEqual(plugin._fixed_volumes, [])

  @patch("extensions.business.container_apps.fixed_volume.cleanup",
         side_effect=[Exception("fail"), None])
  def test_continues_on_failure(self, mock_cleanup):
    plugin = make_container_app_runner()
    vol1 = FixedVolume(name="a", size="50M", root=Path("/r"))
    vol2 = FixedVolume(name="b", size="50M", root=Path("/r"))
    plugin._fixed_volumes = [vol1, vol2]
    plugin._cleanup_fixed_size_volumes()  # should not raise
    self.assertEqual(mock_cleanup.call_count, 2)
    self.assertEqual(plugin._fixed_volumes, [])


if __name__ == "__main__":
  unittest.main()
