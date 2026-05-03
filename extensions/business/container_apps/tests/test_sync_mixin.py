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

from extensions.business.container_apps.mixins.sync_mixin import _SyncMixin
from extensions.business.container_apps.sync_manager import (
  SYSTEM_VOLUME_MOUNT,
  SYSTEM_VOLUME_NAME,
  SyncManager,
  history_received_dir,
  volume_sync_dir,
)
from extensions.business.container_apps.tests.test_sync_manager import (
  _FakeChainStore,
  _FakeR1FS,
  _make_owner,
)


class _FakePlugin(_SyncMixin):
  """A minimal fake plugin that mixes in _SyncMixin and records lifecycle calls."""

  def __init__(self, owner_ns):
    self._delegate = owner_ns
    self.stop_calls = 0
    self.start_calls = 0
    self.lifecycle_log: list[str] = []
    # Mirror SyncManager-required attributes onto self by attribute lookup.
    # We simply use __getattr__ to forward.

  def __getattr__(self, name):
    return getattr(self._delegate, name)

  # Plugin lifecycle stubs (logged + counted)
  def stop_container(self):
    self.stop_calls += 1
    self.lifecycle_log.append("stop")

  def start_container(self):
    self.start_calls += 1
    self.lifecycle_log.append("start")

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
    "INITIAL_SYNC_TIMEOUT": 0,  # let tests opt-in to short timeouts
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
    self.assertEqual(self.plugin.lifecycle_log, ["stop", "start"])
    # response.json + chainstore + history all produced
    response = json.loads((self.vsd / "response.json").read_text())
    self.assertEqual(response["status"], "ok")
    self.assertEqual(len(self.owner._cs.hset_calls), 1)

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
    self.assertEqual(self.plugin.lifecycle_log, ["stop", "start"])
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

  def _publish(self, content=b"data1"):
    (self.provider_owner._fixed_root / "appdata" / "weights.bin").write_bytes(content)
    p_vsd = volume_sync_dir(self.provider_plugin)
    p_vsd.mkdir(parents=True, exist_ok=True)
    (p_vsd / "request.json").write_text(json.dumps({"archive_paths": ["/app/data/"]}))
    self.provider_plugin._last_sync_check = 0
    self.provider_plugin._sync_provider_tick(current_time=1000.0)

  def test_no_record_no_action(self):
    self.consumer_plugin._sync_consumer_tick(current_time=1000.0)
    self.assertEqual(self.consumer_plugin.stop_calls, 0)

  def test_full_consumer_flow(self):
    self._publish()
    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)
    self.assertEqual(self.consumer_plugin.lifecycle_log, ["stop", "start"])
    target = self.consumer_owner._fixed_root / "appdata" / "weights.bin"
    self.assertEqual(target.read_bytes(), b"data1")
    self.assertTrue((volume_sync_dir(self.consumer_plugin) / "last_apply.json").exists())

  def test_skips_already_applied_version(self):
    self._publish()
    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)
    self.consumer_plugin.lifecycle_log.clear()
    self.consumer_plugin._last_sync_check = 0  # reset throttle
    # Tick again without a new publish — should be a no-op.
    self.consumer_plugin._sync_consumer_tick(current_time=3000.0)
    self.assertEqual(self.consumer_plugin.lifecycle_log, [])

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
        "archive_size_bytes": 123,
      },
    }
    self.consumer_plugin._sync_consumer_tick(current_time=2000.0)
    # We did stop — that's fine; we restart even on apply failure.
    self.assertEqual(self.consumer_plugin.lifecycle_log, ["stop", "start"])
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
