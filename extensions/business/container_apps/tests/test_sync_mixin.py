"""Unit tests for ``_SyncMixin`` stand-alone methods.

Covers env-var injection, config helpers, stale .processing recovery, and
the provider/consumer ticks driven against a fake plugin that records
stop_container/start_container call ordering. The mixin's
_configure_system_volume() is intentionally NOT tested here because it
shells out to losetup/mount which require root + a real loopback environment;
that path is exercised by the e2e scenarios (volume_sync/02_mount_persistence_sanity
and the rest).
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from extensions.business.container_apps.sync import (
  SYSTEM_VOLUME_MOUNT,
  SYSTEM_VOLUME_NAME,
  SyncManager,
  _SyncMixin,
  history_received_dir,
  volume_sync_dir,
)
from extensions.business.container_apps.tests.test_sync_manager import (
  _FakeDockerArchiveContainer,
  _FakeChainStore,
  _FakeR1FS,
  _make_owner,
  _tar_bytes,
)


class _FakePlugin(_SyncMixin):
  """A minimal fake plugin that mixes in _SyncMixin and records lifecycle calls."""

  def __init__(self, owner_ns):
    self._delegate = owner_ns
    self.stop_calls = 0
    self.start_calls = 0
    self.runtime_stop_calls = 0
    self.fixed_volume_cleanup_calls = 0
    self.lifecycle_log: list[str] = []
    # Mirror SyncManager-required attributes onto self by attribute lookup.
    # We simply use __getattr__ to forward.

  def __getattr__(self, name):
    return getattr(self._delegate, name)

  # Plugin lifecycle stubs (logged + counted)
  def stop_container(self):
    self.stop_calls += 1
    self.lifecycle_log.append("stop")

  def _stop_container_runtime_for_restart(self):
    self.runtime_stop_calls += 1
    self.stop_container()

  def _cleanup_fixed_size_volumes(self):
    self.fixed_volume_cleanup_calls += 1

  def start_container(self):
    self.start_calls += 1
    self.lifecycle_log.append("start")

  def _reset_runtime_state_post_start(self):
    """Mirror the real plugin's helper so sync-tick tests can observe both
    the call order and the resulting state-marker resets.
    """
    self.lifecycle_log.append("reset")
    # Same resets the real container_app_runner._reset_runtime_state_post_start
    # performs. Log stream / build-and-run hooks are no-ops in this fake.
    self.container_start_time = self.time()
    self._app_ready = False
    self._health_probe_start = None
    self._tunnel_start_allowed = False
    self._commands_started = False

  # Mark-as-mutable env so the mixin's _inject_sync_env_vars can write.
  @property
  def env(self):
    return self._delegate.__dict__.setdefault("env", {})


def _make_plugin(tmpdir, *, role="provider", enabled=True, key="SYNC-KEY-1"):
  owner = _make_owner(tmpdir)
  owner.cfg_sync = {
    "ENABLED": enabled,
    "KEY": key,
    "TYPE": role,
    "POLL_INTERVAL": 1,
  }
  owner.cfg_sync_type = role
  owner.cfg_sync_key = key
  plugin = _FakePlugin(owner)
  # Make sure the volume-sync directory exists for tests that don't go through
  # _configure_system_volume.
  volume_sync_dir(plugin).mkdir(parents=True, exist_ok=True)
  return plugin, owner


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

class TestConfigHelpers(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)

  def tearDown(self):
    self._tmp.cleanup()

  def test_disabled(self):
    plugin, _ = _make_plugin(self.tmpdir, enabled=False)
    self.assertFalse(plugin._sync_enabled())
    self.assertIsNone(plugin._ensure_sync_manager())

  def test_enabled_provider(self):
    plugin, _ = _make_plugin(self.tmpdir, role="provider")
    self.assertTrue(plugin._sync_enabled())
    self.assertEqual(plugin._sync_role(), "provider")
    self.assertIsInstance(plugin._ensure_sync_manager(), SyncManager)
    # Lazy-init returns the same instance.
    self.assertIs(plugin._ensure_sync_manager(), plugin._sync_manager)

  def test_invalid_role(self):
    plugin, _ = _make_plugin(self.tmpdir, role="bogus")
    self.assertIsNone(plugin._sync_role())

  def test_poll_interval_floor(self):
    plugin, owner = _make_plugin(self.tmpdir)
    owner.cfg_sync["POLL_INTERVAL"] = 0
    self.assertEqual(plugin._sync_poll_interval(), 1.0)

  def test_poll_interval_invalid_falls_back(self):
    plugin, owner = _make_plugin(self.tmpdir)
    owner.cfg_sync["POLL_INTERVAL"] = "nope"
    self.assertEqual(plugin._sync_poll_interval(), 10.0)

  def test_hsync_poll_interval_default(self):
    """When SYNC.HSYNC_POLL_INTERVAL is unset, ``_hsync_poll_interval``
    returns the 60s default so consumers don't go to the network for fresh
    chain replicas more than once per default window.
    """
    plugin, owner = _make_plugin(self.tmpdir)
    # Make sure the field really is absent on the test fixture.
    owner.cfg_sync.pop("HSYNC_POLL_INTERVAL", None)
    self.assertEqual(plugin._hsync_poll_interval(), 60.0)
    # Same value surfaces via the SyncManager-facing property.
    self.assertEqual(plugin.cfg_sync_hsync_poll_interval, 60.0)

  def test_hsync_poll_interval_floor(self):
    """Values below the 10s minimum are clamped up — the floor protects
    the cluster from operators who set the knob aggressively low without
    realising the network cost."""
    plugin, owner = _make_plugin(self.tmpdir)
    owner.cfg_sync["HSYNC_POLL_INTERVAL"] = 1
    self.assertEqual(plugin._hsync_poll_interval(), 10.0)

  def test_hsync_poll_interval_invalid_falls_back(self):
    """Non-numeric values fall back to the default (not the floor) — same
    pattern as ``_sync_poll_interval`` so misconfiguration is forgiving
    but conservative."""
    plugin, owner = _make_plugin(self.tmpdir)
    owner.cfg_sync["HSYNC_POLL_INTERVAL"] = "nope"
    self.assertEqual(plugin._hsync_poll_interval(), 60.0)

  def test_online_provider_capture_string_false_is_false(self):
    plugin, owner = _make_plugin(self.tmpdir)
    owner.cfg_sync["ALLOW_ONLINE_PROVIDER_CAPTURE"] = "false"
    self.assertFalse(plugin.cfg_sync_allow_online_provider_capture)

  def test_online_provider_capture_string_true_is_true(self):
    plugin, owner = _make_plugin(self.tmpdir)
    owner.cfg_sync["ALLOW_ONLINE_PROVIDER_CAPTURE"] = "true"
    self.assertTrue(plugin.cfg_sync_allow_online_provider_capture)


# ---------------------------------------------------------------------------
# Env-var injection
# ---------------------------------------------------------------------------

class TestEnvInjection(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)

  def tearDown(self):
    self._tmp.cleanup()

  def test_always_on_keys_present(self):
    plugin, _ = _make_plugin(self.tmpdir, enabled=False)
    plugin._inject_sync_env_vars()
    self.assertEqual(plugin.env["R1_SYSTEM_VOLUME"], "/r1en_system")
    self.assertEqual(plugin.env["R1_VOLUME_SYNC_DIR"], "/r1en_system/volume-sync")
    self.assertEqual(
      plugin.env["R1_SYNC_REQUEST_FILE"], "/r1en_system/volume-sync/request.json"
    )
    # Role/key keys not set when SYNC disabled.
    self.assertNotIn("R1_SYNC_TYPE", plugin.env)
    self.assertNotIn("R1_SYNC_KEY", plugin.env)

  def test_role_and_key_set_when_enabled(self):
    plugin, _ = _make_plugin(self.tmpdir, role="consumer", key="abc-123")
    plugin._inject_sync_env_vars()
    self.assertEqual(plugin.env["R1_SYNC_TYPE"], "consumer")
    self.assertEqual(plugin.env["R1_SYNC_KEY"], "abc-123")

  def test_no_env_when_sync_unavailable(self):
    """If _configure_system_volume set _sync_unavailable (host tools missing),
    _inject_sync_env_vars must not advertise R1_SYSTEM_VOLUME or any other
    R1_* key — the mount doesn't exist on the host, so the app would write
    into a phantom path while CAR polled a host root that was never
    provisioned. Codex review finding 5 on PR #399."""
    plugin, _ = _make_plugin(self.tmpdir, role="provider", key="abc-123")
    plugin._sync_unavailable = True
    plugin._inject_sync_env_vars()
    for k in ("R1_SYSTEM_VOLUME", "R1_VOLUME_SYNC_DIR", "R1_SYNC_REQUEST_FILE",
              "R1_SYNC_TYPE", "R1_SYNC_KEY"):
      self.assertNotIn(k, plugin.env)

  def test_sync_disabled_when_unavailable(self):
    """_sync_enabled() must return False when _sync_unavailable is set, even
    with SYNC.ENABLED=True in config — provider/consumer ticks would
    otherwise poll a host root that doesn't exist."""
    plugin, _ = _make_plugin(self.tmpdir, role="provider", enabled=True)
    self.assertTrue(plugin._sync_enabled())  # baseline
    plugin._sync_unavailable = True
    self.assertFalse(plugin._sync_enabled())

  def test_successful_system_volume_config_clears_sync_unavailable(self):
    plugin, _ = _make_plugin(self.tmpdir, role="provider", enabled=True)
    plugin._sync_unavailable = True

    with patch(
      "extensions.business.container_apps.sync.mixin.fixed_volume._require_tools"
    ), patch(
      "extensions.business.container_apps.sync.mixin.fixed_volume.provision",
      side_effect=lambda vol, **_kwargs: vol,
    ):
      plugin._configure_system_volume()

    self.assertFalse(plugin._sync_unavailable)
    self.assertIn(SYSTEM_VOLUME_MOUNT, [spec["bind"] for spec in plugin.volumes.values()])
    self.assertEqual(os.stat(volume_sync_dir(plugin).parent).st_mode & 0o777, 0o755)
    self.assertEqual(os.stat(volume_sync_dir(plugin)).st_mode & 0o777, 0o777)
    self.assertEqual(os.stat(volume_sync_dir(plugin)).st_mode & 0o1000, 0o1000)

  def test_system_volume_config_recreates_symlinked_volume_sync_dir(self):
    plugin, _ = _make_plugin(self.tmpdir, role="provider", enabled=True)
    vsd = volume_sync_dir(plugin)
    vsd.rmdir()
    outside = self.tmpdir / "outside-control"
    outside.mkdir()
    os.symlink(str(outside), str(vsd))

    with patch(
      "extensions.business.container_apps.sync.mixin.fixed_volume._require_tools"
    ), patch(
      "extensions.business.container_apps.sync.mixin.fixed_volume.provision",
      side_effect=lambda vol, **_kwargs: vol,
    ):
      plugin._configure_system_volume()

    self.assertFalse(plugin._sync_unavailable)
    self.assertTrue(vsd.is_dir())
    self.assertFalse(vsd.is_symlink())
    self.assertEqual(os.stat(vsd.parent).st_mode & 0o777, 0o755)
    self.assertEqual(os.stat(vsd).st_mode & 0o1000, 0o1000)


# ---------------------------------------------------------------------------
# Stale .processing recovery
# ---------------------------------------------------------------------------

class TestRecoverStaleProcessing(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.plugin, self.owner = _make_plugin(self.tmpdir)
    self.vsd = volume_sync_dir(self.plugin)

  def tearDown(self):
    self._tmp.cleanup()

  def test_no_op_when_no_processing(self):
    self.plugin._recover_stale_processing()  # should not raise
    self.assertFalse((self.vsd / "request.json").exists())

  def test_renames_processing_back(self):
    (self.vsd / "request.json.processing").write_text('{"archive_paths":["/app/data/"]}')
    self.plugin._recover_stale_processing()
    self.assertFalse((self.vsd / "request.json.processing").exists())
    self.assertTrue((self.vsd / "request.json").is_file())

  def test_keeps_existing_request_intact(self):
    # If both exist (rare crash race), don't overwrite the in-flight request.
    (self.vsd / "request.json").write_text('{"archive_paths":["/app/data/"]}')
    (self.vsd / "request.json.processing").write_text('{"archive_paths":["/old/"]}')
    self.plugin._recover_stale_processing()
    # .processing untouched, request.json preserved.
    self.assertTrue((self.vsd / "request.json.processing").exists())
    self.assertEqual(
      json.loads((self.vsd / "request.json").read_text())["archive_paths"],
      ["/app/data/"],
    )


# ---------------------------------------------------------------------------
# Provider tick
# ---------------------------------------------------------------------------

class TestProviderTick(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    self.plugin, self.owner = _make_plugin(self.tmpdir, role="provider")
    self.vsd = volume_sync_dir(self.plugin)
    # Seed data volume
    (self.owner._fixed_root / "appdata" / "weights.bin").write_bytes(b"abc")

  def tearDown(self):
    self._tmp.cleanup()

  def _write_request(self, body):
    (self.vsd / "request.json").write_text(json.dumps(body))

  def test_no_request_no_action(self):
    self.plugin._sync_provider_tick(current_time=100.0)
    self.assertEqual(self.plugin.stop_calls, 0)
    self.assertEqual(self.plugin.start_calls, 0)

  def test_disabled_no_action(self):
    self.owner.cfg_sync["ENABLED"] = False
    self._write_request({"archive_paths": ["/app/data/"]})
    self.plugin._sync_provider_tick(current_time=100.0)
    self.assertEqual(self.plugin.stop_calls, 0)
    self.assertTrue((self.vsd / "request.json").exists())

  def test_consumer_role_no_provider_action(self):
    self.owner.cfg_sync["TYPE"] = "consumer"
    self._write_request({"archive_paths": ["/app/data/"]})
    self.plugin._sync_provider_tick(current_time=100.0)
    self.assertEqual(self.plugin.stop_calls, 0)

  def test_throttle_skips_within_poll_interval(self):
    self.owner.cfg_sync["POLL_INTERVAL"] = 100
    self._write_request({"archive_paths": ["/app/data/"]})
    self.plugin._last_sync_check = 90.0
    self.plugin._sync_provider_tick(current_time=100.0)  # only 10s since last
    self.assertEqual(self.plugin.stop_calls, 0)

  def test_full_provider_flow(self):
    self._write_request({"archive_paths": ["/app/data/"], "metadata": {"v": 1}})
    self.plugin._sync_provider_tick(current_time=1000.0)

    # stop -> work -> start in that order
    self.assertEqual(self.plugin.lifecycle_log, ["stop", "start", "reset"])
    # response.json + chainstore + history all produced
    response = json.loads((self.vsd / "response.json").read_text())
    self.assertEqual(response["status"], "ok")
    self.assertEqual(len(self.owner._cs.hset_calls), 1)

  def test_provider_sync_uses_runtime_stop_without_fixed_volume_cleanup(self):
    self._write_request({"archive_paths": ["/app/data/"]})

    self.plugin._sync_provider_tick(current_time=1000.0)

    self.assertEqual(self.plugin.runtime_stop_calls, 1)
    self.assertEqual(self.plugin.fixed_volume_cleanup_calls, 0)
    self.assertEqual(self.plugin.lifecycle_log, ["stop", "start", "reset"])

  def test_online_provider_capture_skips_runtime_stop(self):
    self.owner.cfg_sync["ALLOW_ONLINE_PROVIDER_CAPTURE"] = True
    self.plugin.container = _FakeDockerArchiveContainer({
      "/tmp/generated.txt": _tar_bytes("generated.txt", b"from-container"),
    })
    self._write_request({
      "archive_paths": ["/tmp/generated.txt"],
      "runtime": {"provider_capture": "online"},
    })

    self.plugin._sync_provider_tick(current_time=1000.0)

    self.assertEqual(self.plugin.runtime_stop_calls, 0)
    self.assertEqual(self.plugin.start_calls, 0)
    self.assertEqual(self.plugin.lifecycle_log, [])
    response = json.loads((self.vsd / "response.json").read_text())
    self.assertEqual(response["status"], "ok")

  def test_validation_failure_does_not_stop_container(self):
    # claim_request fails fast; no need to disturb the container.
    self._write_request({"archive_paths": ["/nope/"]})
    self.plugin._sync_provider_tick(current_time=1000.0)
    self.assertEqual(self.plugin.stop_calls, 0)
    self.assertEqual(self.plugin.start_calls, 0)
    invalid = json.loads((self.vsd / "request.json.invalid").read_text())
    self.assertEqual(invalid["_error"]["stage"], "validation")

  def test_publish_failure_still_restarts_container(self):
    self._write_request({"archive_paths": ["/app/data/"]})
    self.owner._r1fs.add_should_raise = RuntimeError("ipfs gone")
    self.plugin._sync_provider_tick(current_time=1000.0)
    # We did stop because claim succeeded; the failure was at r1fs stage.
    self.assertEqual(self.plugin.lifecycle_log, ["stop", "start", "reset"])
    response = json.loads((self.vsd / "response.json").read_text())
    self.assertEqual(response["stage"], "r1fs_upload")


# ---------------------------------------------------------------------------
# Consumer tick
# ---------------------------------------------------------------------------

class TestConsumerTick(unittest.TestCase):
  def setUp(self):
    self._tmp = tempfile.TemporaryDirectory()
    self.tmpdir = Path(self._tmp.name)
    # Set up provider+consumer plugins sharing one r1fs/chainstore.
    self.provider_plugin, self.provider_owner = _make_plugin(
      self.tmpdir / "p", role="provider"
    )
    self.consumer_plugin, self.consumer_owner = _make_plugin(
      self.tmpdir / "c", role="consumer"
    )
    # Share state by using the provider's r1fs/chainstore on the consumer.
    shared_r1fs = self.provider_owner._r1fs
    shared_cs = self.provider_owner._cs
    self.consumer_owner.r1fs = shared_r1fs
    self.consumer_owner._r1fs = shared_r1fs
    self.consumer_owner.chainstore_hset = shared_cs.hset
    self.consumer_owner.chainstore_hget = shared_cs.hget
    self.consumer_owner.chainstore_hsync = shared_cs.hsync
    self.consumer_owner._cs = shared_cs
    # Same SYNC.KEY across both
    self.consumer_owner.cfg_sync["KEY"] = "SYNC-KEY-1"
    self.consumer_owner.cfg_sync_key = "SYNC-KEY-1"

    (self.provider_owner._fixed_root / "appdata" / "weights.bin").write_bytes(b"data1")

  def tearDown(self):
    self._tmp.cleanup()

  def _publish(self, content=b"data1", runtime=None):
    (self.provider_owner._fixed_root / "appdata" / "weights.bin").write_bytes(content)
    p_vsd = volume_sync_dir(self.provider_plugin)
    p_vsd.mkdir(parents=True, exist_ok=True)
    request = {"archive_paths": ["/app/data/"]}
    if runtime is not None:
      request["runtime"] = runtime
    (p_vsd / "request.json").write_text(json.dumps(request))
    self.provider_plugin._last_sync_check = 0
    self.provider_plugin._sync_provider_tick(current_time=1000.0)

  def test_no_record_no_action(self):
    self.consumer_plugin._sync_consumer_tick(current_time=1000.0)
    self.assertEqual(self.consumer_plugin.stop_calls, 0)

  def test_full_consumer_flow(self):
    self._publish()
    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)
    self.assertEqual(self.consumer_plugin.lifecycle_log, ["stop", "start", "reset"])
    target = self.consumer_owner._fixed_root / "appdata" / "weights.bin"
    self.assertEqual(target.read_bytes(), b"data1")
    self.assertTrue((volume_sync_dir(self.consumer_plugin) / "last_apply.json").exists())

  def test_consumer_explicit_offline_restart_stops_applies_and_restarts(self):
    self._publish(runtime={"consumer_apply": "offline_restart"})

    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)

    self.assertEqual(self.consumer_plugin.runtime_stop_calls, 1)
    self.assertEqual(self.consumer_plugin.lifecycle_log, ["stop", "start", "reset"])
    target = self.consumer_owner._fixed_root / "appdata" / "weights.bin"
    self.assertEqual(target.read_bytes(), b"data1")

  def test_consumer_online_no_restart_applies_without_lifecycle_stop_start(self):
    self.consumer_owner.cfg_sync["CONSUMER_APPLY_MODE"] = "online_no_restart"
    self._publish(runtime={"consumer_apply": "online_no_restart"})

    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)

    self.assertEqual(self.consumer_plugin.runtime_stop_calls, 0)
    self.assertEqual(self.consumer_plugin.start_calls, 0)
    self.assertEqual(self.consumer_plugin.lifecycle_log, [])
    target = self.consumer_owner._fixed_root / "appdata" / "weights.bin"
    self.assertEqual(target.read_bytes(), b"data1")
    self.assertTrue((volume_sync_dir(self.consumer_plugin) / "last_apply.json").exists())

  def test_consumer_online_restart_applies_before_restart(self):
    self.consumer_owner.cfg_sync["CONSUMER_APPLY_MODE"] = "online_restart"
    target = self.consumer_owner._fixed_root / "appdata" / "weights.bin"
    target.write_bytes(b"old")
    self._publish(content=b"new", runtime={"consumer_apply": "online_restart"})

    orig_stop = self.consumer_plugin.stop_container

    def stop_after_apply():
      self.assertEqual(target.read_bytes(), b"new")
      orig_stop()

    self.consumer_plugin.stop_container = stop_after_apply
    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)

    self.assertEqual(self.consumer_plugin.runtime_stop_calls, 1)
    self.assertEqual(self.consumer_plugin.lifecycle_log, ["stop", "start", "reset"])

  def test_provider_record_cannot_force_consumer_online_apply(self):
    self._publish(runtime={"consumer_apply": "online_no_restart"})

    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)

    self.assertEqual(self.consumer_plugin.runtime_stop_calls, 1)
    self.assertEqual(self.consumer_plugin.lifecycle_log, ["stop", "start", "reset"])

  def test_consumer_resets_runtime_state_after_apply(self):
    """After a sync slice, per-restart runtime markers must be reset so
    readiness gates, health-probe timers, and BUILD_AND_RUN_COMMANDS re-engage
    against the freshly-started container. Otherwise tunnels stay marked
    ready, health checks are skipped, and image-defined startup commands
    don't rerun — the codex review's HIGH-severity finding 2 on PR #399.
    """
    # Seed the plugin with "previous container is running" markers.
    self.consumer_plugin.container_start_time = 999.0
    self.consumer_plugin._app_ready = True
    self.consumer_plugin._health_probe_start = 999.0
    self.consumer_plugin._tunnel_start_allowed = True
    self.consumer_plugin._commands_started = True

    self._publish()
    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)

    # Order: stop, start, then reset (reset MUST come after start so the
    # markers reflect the new container, not the prior one).
    self.assertEqual(
      self.consumer_plugin.lifecycle_log, ["stop", "start", "reset"]
    )
    # All readiness / probe / command-rerun markers reset. The fake's
    # ``time()`` is a monotonic counter that increments on each read, so
    # compare against the seeded sentinel (999.0) rather than chasing the
    # exact post-reset value.
    self.assertNotEqual(self.consumer_plugin.container_start_time, 999.0)
    self.assertIsNotNone(self.consumer_plugin.container_start_time)
    self.assertFalse(self.consumer_plugin._app_ready)
    self.assertIsNone(self.consumer_plugin._health_probe_start)
    self.assertFalse(self.consumer_plugin._tunnel_start_allowed)
    self.assertFalse(self.consumer_plugin._commands_started)

  def test_skips_when_record_cid_matches_last_apply(self):
    """The consumer's 'is this new?' check is by CID, not version. A second
    tick that sees the same ChainStore record (same cid) is a no-op even
    if version metadata changed."""
    self._publish()
    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)
    self.consumer_plugin.lifecycle_log.clear()
    self.consumer_plugin._last_sync_check = 0  # reset throttle
    # Tick again without a new publish — should be a no-op (same cid).
    self.consumer_plugin._sync_consumer_tick(current_time=3000.0)
    self.assertEqual(self.consumer_plugin.lifecycle_log, [])

  def test_applies_when_cid_differs_even_if_version_lower(self):
    """A consumer should apply any record whose cid differs from the last
    applied entry, regardless of version ordering. This guards against
    clock-skew failure modes where a provider's wonky timestamp could
    otherwise make a corrected snapshot look 'older'."""
    # First publish + apply (creates a baseline received entry).
    self._publish(content=b"initial")
    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)
    initial_received = self.consumer_plugin._sync_manager.latest_received()
    self.assertIsNotNone(initial_received)
    initial_version = initial_received["version"]

    # Hand-craft a chainstore record with a *lower* version but a fresh CID.
    # Under the old version-comparison logic this would be skipped; under
    # CID comparison it must be applied.
    spoofed_cid = "QmSPOOF_LOWER_VERSION_FRESH_CONTENT"
    fake_tar = self.consumer_owner._r1fs.added.get(initial_received["cid"], b"")
    self.consumer_owner._r1fs.added[spoofed_cid] = fake_tar
    self.consumer_owner._cs.store[("CHAINSTORE_SYNC", "SYNC-KEY-1")] = {
      "cid": spoofed_cid,
      "version": initial_version - 100,  # explicitly older
      "timestamp": 0.5,
      "node_id": "ee_other",
      "metadata": {"who": "wonky-clock"},
      "manifest": initial_received["manifest"],
    }

    self.consumer_plugin.lifecycle_log.clear()
    self.consumer_plugin._last_sync_check = 0
    self.consumer_plugin._sync_consumer_tick(current_time=3000.0)
    # The new (lower-versioned but different-cid) record was applied.
    self.assertEqual(self.consumer_plugin.lifecycle_log, ["stop", "start", "reset"])
    latest = self.consumer_plugin._sync_manager.latest_received()
    self.assertEqual(latest["cid"], spoofed_cid)

  def test_misalignment_skips_apply(self):
    # Store a record in chainstore that references a path consumer can't map.
    self.consumer_owner._cs.store[("CHAINSTORE_SYNC", "SYNC-KEY-1")] = {
      "cid": "QmFAKE_BAD",
      "version": 9999999999,
      "timestamp": 1.0,
      "node_id": "ee_other",
      "metadata": {},
      "manifest": {
        "schema_version": 1,
        "archive_paths": ["/app/data/", "/nope/"],
        "archive_format": "tar.gz",
        "encryption": "r1fs-default",
        "archive_size_bytes": 123,
      },
    }
    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)
    # We did stop — that's fine; we restart even on apply failure.
    self.assertEqual(self.consumer_plugin.lifecycle_log, ["stop", "start", "reset"])
    # No last_apply written
    self.assertFalse(
      (volume_sync_dir(self.consumer_plugin) / "last_apply.json").exists()
    )
    # No history advance
    self.assertEqual(
      len(list(history_received_dir(self.consumer_plugin).glob("*.json"))), 0
    )


if __name__ == "__main__":
  unittest.main()
