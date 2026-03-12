import json
import sys
import struct
import unittest
from unittest.mock import MagicMock, patch

from .conftest import DummyOwner, MANUAL_RUN, PentestLocalWorker, color_print, mock_plugin_modules


class TestPhase12LiveProgress(unittest.TestCase):
  """Phase 12: Live Worker Progress."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def test_worker_progress_model_roundtrip(self):
    """WorkerProgress.from_dict(wp.to_dict()) preserves all fields."""
    from extensions.business.cybersec.red_mesh.models import WorkerProgress
    wp = WorkerProgress(
      job_id="job-1",
      worker_addr="0xWorkerA",
      pass_nr=2,
      progress=45.5,
      phase="service_probes",
      ports_scanned=500,
      ports_total=1024,
      open_ports_found=[22, 80, 443],
      completed_tests=["fingerprint_completed", "service_info_completed"],
      updated_at=1700000000.0,
      live_metrics={"total_duration": 30.5},
    )
    d = wp.to_dict()
    wp2 = WorkerProgress.from_dict(d)
    self.assertEqual(wp2.job_id, "job-1")
    self.assertEqual(wp2.worker_addr, "0xWorkerA")
    self.assertEqual(wp2.pass_nr, 2)
    self.assertAlmostEqual(wp2.progress, 45.5)
    self.assertEqual(wp2.phase, "service_probes")
    self.assertEqual(wp2.ports_scanned, 500)
    self.assertEqual(wp2.ports_total, 1024)
    self.assertEqual(wp2.open_ports_found, [22, 80, 443])
    self.assertEqual(wp2.completed_tests, ["fingerprint_completed", "service_info_completed"])
    self.assertEqual(wp2.updated_at, 1700000000.0)
    self.assertEqual(wp2.live_metrics, {"total_duration": 30.5})

  def test_get_job_progress_filters_by_job(self):
    """get_job_progress returns only workers for the requested job."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"

    # Simulate two jobs' progress in the :live hset
    live_data = {
      "job-A:worker-1": {"job_id": "job-A", "progress": 50},
      "job-A:worker-2": {"job_id": "job-A", "progress": 75},
      "job-B:worker-3": {"job_id": "job-B", "progress": 30},
    }
    plugin.chainstore_hgetall.return_value = live_data
    plugin.chainstore_hget.return_value = {"job_status": "RUNNING"}

    result = Plugin.get_job_progress(plugin, job_id="job-A")
    self.assertEqual(result["job_id"], "job-A")
    self.assertEqual(result["status"], "RUNNING")
    self.assertEqual(len(result["workers"]), 2)
    self.assertIn("worker-1", result["workers"])
    self.assertIn("worker-2", result["workers"])
    self.assertNotIn("worker-3", result["workers"])

  def test_get_job_progress_empty(self):
    """get_job_progress for non-existent job returns empty workers dict."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.chainstore_hgetall.return_value = {}
    plugin.chainstore_hget.return_value = None

    result = Plugin.get_job_progress(plugin, job_id="nonexistent")
    self.assertEqual(result["job_id"], "nonexistent")
    self.assertIsNone(result["status"])
    self.assertEqual(result["workers"], {})

  def test_publish_live_progress(self):
    """_publish_live_progress writes stage-based progress to CStore :live hset."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"
    plugin._last_progress_publish = 0
    plugin.time.return_value = 100.0

    # Mock a local worker with state (port scan partial + fingerprint done)
    worker = MagicMock()
    worker.state = {
      "ports_scanned": list(range(100)),
      "open_ports": [22, 80],
      "completed_tests": ["fingerprint_completed"],
      "done": False,
    }
    worker.initial_ports = list(range(1, 513))

    plugin.scan_jobs = {"job-1": {"worker-thread-1": worker}}

    # Mock CStore lookup for pass_nr
    plugin.chainstore_hget.return_value = {"job_pass": 3}

    Plugin._publish_live_progress(plugin)

    # Verify hset was called with correct key pattern
    plugin.chainstore_hset.assert_called_once()
    call_args = plugin.chainstore_hset.call_args
    self.assertEqual(call_args.kwargs["hkey"], "test-instance:live")
    self.assertEqual(call_args.kwargs["key"], "job-1:node-A")
    progress_data = call_args.kwargs["value"]
    self.assertEqual(progress_data["job_id"], "job-1")
    self.assertEqual(progress_data["worker_addr"], "node-A")
    self.assertEqual(progress_data["pass_nr"], 3)
    self.assertEqual(progress_data["phase"], "service_probes")
    self.assertEqual(progress_data["ports_scanned"], 100)
    self.assertEqual(progress_data["ports_total"], 512)
    self.assertIn(22, progress_data["open_ports_found"])
    self.assertIn(80, progress_data["open_ports_found"])
    # Stage-based progress: service_probes = stage 3 (idx 2), so 2/5*100 = 40%
    self.assertEqual(progress_data["progress"], 40.0)
    # Single thread — no threads field
    self.assertNotIn("threads", progress_data)

  def test_publish_live_progress_missing_interval_uses_default(self):
    """Missing publish interval falls back to the default safely."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"
    plugin._last_progress_publish = 0
    plugin.time.return_value = 100.0
    plugin._progress_publish_interval = None
    plugin.cfg_progress_publish_interval = None
    plugin.CONFIG = {"PROGRESS_PUBLISH_INTERVAL": 30}

    worker = MagicMock()
    worker.state = {
      "ports_scanned": list(range(10)),
      "open_ports": [],
      "completed_tests": [],
      "done": False,
    }
    worker.initial_ports = list(range(1, 33))
    plugin.scan_jobs = {"job-1": {"worker-thread-1": worker}}
    plugin.chainstore_hget.return_value = {"job_pass": 1}

    Plugin._publish_live_progress(plugin)

    self.assertEqual(Plugin._get_progress_publish_interval(plugin), 30.0)
    plugin.chainstore_hset.assert_called_once()

  def test_publish_live_progress_invalid_interval_uses_default(self):
    """Malformed publish interval falls back to the default safely."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"
    plugin._last_progress_publish = 80
    plugin.time.return_value = 100.0
    plugin._progress_publish_interval = None
    plugin.cfg_progress_publish_interval = "invalid"
    plugin.CONFIG = {"PROGRESS_PUBLISH_INTERVAL": 30}

    worker = MagicMock()
    worker.state = {
      "ports_scanned": list(range(10)),
      "open_ports": [],
      "completed_tests": [],
      "done": False,
    }
    worker.initial_ports = list(range(1, 33))
    plugin.scan_jobs = {"job-1": {"worker-thread-1": worker}}
    plugin.chainstore_hget.return_value = {"job_pass": 1}

    Plugin._publish_live_progress(plugin)

    self.assertEqual(Plugin._get_progress_publish_interval(plugin), 30.0)
    plugin.chainstore_hset.assert_not_called()

  def test_publish_live_progress_zero_interval_uses_default(self):
    """Zero publish interval falls back to the default instead of tight-looping."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"
    plugin._last_progress_publish = 80
    plugin.time.return_value = 100.0
    plugin._progress_publish_interval = None
    plugin.cfg_progress_publish_interval = 0
    plugin.CONFIG = {"PROGRESS_PUBLISH_INTERVAL": 30}

    worker = MagicMock()
    worker.state = {
      "ports_scanned": list(range(10)),
      "open_ports": [],
      "completed_tests": [],
      "done": False,
    }
    worker.initial_ports = list(range(1, 33))
    plugin.scan_jobs = {"job-1": {"worker-thread-1": worker}}
    plugin.chainstore_hget.return_value = {"job_pass": 1}

    Plugin._publish_live_progress(plugin)

    self.assertEqual(Plugin._get_progress_publish_interval(plugin), 30.0)
    plugin.chainstore_hset.assert_not_called()

  def test_publish_live_progress_multi_thread_phase(self):
    """Phase is the earliest active phase; per-thread data is included."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"
    plugin._last_progress_publish = 0
    plugin.time.return_value = 100.0

    # Thread 1: fully done
    worker1 = MagicMock()
    worker1.state = {
      "ports_scanned": list(range(256)),
      "open_ports": [22],
      "completed_tests": ["fingerprint_completed", "service_info_completed", "web_tests_completed", "correlation_completed"],
      "done": True,
    }
    worker1.initial_ports = list(range(1, 257))

    # Thread 2: still on port scan (50 of 256 ports)
    worker2 = MagicMock()
    worker2.state = {
      "ports_scanned": list(range(50)),
      "open_ports": [],
      "completed_tests": [],
      "done": False,
    }
    worker2.initial_ports = list(range(257, 513))

    plugin.scan_jobs = {"job-1": {"t1": worker1, "t2": worker2}}
    plugin.chainstore_hget.return_value = {"job_pass": 1}

    Plugin._publish_live_progress(plugin)

    call_args = plugin.chainstore_hset.call_args
    progress_data = call_args.kwargs["value"]
    # Phase should be port_scan (earliest across threads), not done
    self.assertEqual(progress_data["phase"], "port_scan")
    # Stage-based: port_scan (idx 0) + sub-progress (306/512 * 20%) = ~12%
    self.assertGreater(progress_data["progress"], 10)
    self.assertLess(progress_data["progress"], 15)
    # Per-thread data should be present (2 threads)
    self.assertIn("threads", progress_data)
    self.assertEqual(progress_data["threads"]["t1"]["phase"], "done")
    self.assertEqual(progress_data["threads"]["t2"]["phase"], "port_scan")
    self.assertEqual(progress_data["threads"]["t2"]["ports_scanned"], 50)
    self.assertEqual(progress_data["threads"]["t2"]["ports_total"], 256)

  def test_clear_live_progress(self):
    """_clear_live_progress deletes progress keys for all workers."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"

    Plugin._clear_live_progress(plugin, "job-1", ["worker-A", "worker-B"])

    self.assertEqual(plugin.chainstore_hset.call_count, 2)
    calls = plugin.chainstore_hset.call_args_list
    keys_deleted = {c.kwargs["key"] for c in calls}
    self.assertEqual(keys_deleted, {"job-1:worker-A", "job-1:worker-B"})
    for c in calls:
      self.assertIsNone(c.kwargs["value"])



class TestPhase14Purge(unittest.TestCase):
  """Phase 14: Job Deletion & Purge."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _make_plugin(self):
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"
    return plugin

  def test_purge_finalized_collects_all_cids(self):
    """Finalized purge collects archive + config + aggregated_report + worker report CIDs."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    # CStore stub for a finalized job
    job_specs = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "job_cid": "cid-archive",
      "job_config_cid": "cid-config",
    }
    plugin.chainstore_hget.return_value = job_specs

    # Archive contains nested CIDs
    archive = {
      "passes": [
        {
          "aggregated_report_cid": "cid-agg-1",
          "worker_reports": {
            "worker-A": {"report_cid": "cid-wr-A"},
            "worker-B": {"report_cid": "cid-wr-B"},
          },
        },
      ],
    }
    plugin.r1fs.get_json.return_value = archive
    plugin.r1fs.delete_file.return_value = True
    plugin.chainstore_hgetall.return_value = {}

    # Normalize returns the specs as-is
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    # Verify all 5 CIDs were deleted
    deleted_cids = {c.args[0] for c in plugin.r1fs.delete_file.call_args_list}
    self.assertEqual(deleted_cids, {"cid-archive", "cid-config", "cid-agg-1", "cid-wr-A", "cid-wr-B"})
    self.assertEqual(result["cids_deleted"], 5)
    self.assertEqual(result["cids_total"], 5)

  def test_purge_finalized_no_pass_report_cids(self):
    """Finalized purge does NOT try to delete individual pass report CIDs (they are inside archive)."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "job_cid": "cid-archive",
      # No pass_reports key — finalized stubs don't have them
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin.r1fs.get_json.return_value = {"passes": []}
    plugin.r1fs.delete_file.return_value = True
    plugin.chainstore_hgetall.return_value = {}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    # Only archive CID should be deleted (no pass_reports, no config, no workers)
    deleted_cids = {c.args[0] for c in plugin.r1fs.delete_file.call_args_list}
    self.assertEqual(deleted_cids, {"cid-archive"})

  def test_purge_running_collects_all_cids(self):
    """Stopped (was running) purge collects config + worker CIDs + pass report CIDs + nested CIDs."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "STOPPED",
      "job_config_cid": "cid-config",
      "workers": {
        "node-A": {"finished": True, "canceled": True, "report_cid": "cid-wr-A"},
      },
      "pass_reports": [
        {"report_cid": "cid-pass-1"},
      ],
    }
    plugin.chainstore_hget.return_value = job_specs

    # Pass report contains nested CIDs
    pass_report = {
      "aggregated_report_cid": "cid-agg-1",
      "worker_reports": {
        "node-A": {"report_cid": "cid-pass-wr-A"},
      },
    }
    plugin.r1fs.get_json.return_value = pass_report
    plugin.r1fs.delete_file.return_value = True
    plugin.chainstore_hgetall.return_value = {}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    deleted_cids = {c.args[0] for c in plugin.r1fs.delete_file.call_args_list}
    self.assertEqual(deleted_cids, {"cid-config", "cid-wr-A", "cid-pass-1", "cid-agg-1", "cid-pass-wr-A"})

  def test_purge_r1fs_failure_keeps_cstore(self):
    """Partial R1FS failure leaves CStore intact and returns 'partial' status."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "job_cid": "cid-archive",
      "job_config_cid": "cid-config",
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin.r1fs.get_json.return_value = {"passes": []}

    # First CID deletes ok, second raises
    plugin.r1fs.delete_file.side_effect = [True, Exception("disk error")]

    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "partial")
    self.assertEqual(result["cids_deleted"], 1)
    self.assertEqual(result["cids_failed"], 1)
    self.assertEqual(result["cids_total"], 2)

    # CStore should NOT be tombstoned
    tombstone_calls = [
      c for c in plugin.chainstore_hset.call_args_list
      if c.kwargs.get("hkey") == "test-instance" and c.kwargs.get("value") is None
    ]
    self.assertEqual(len(tombstone_calls), 0)

  def test_purge_cleans_live_progress(self):
    """Purge deletes live progress keys for the job from :live hset."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "STOPPED",
      "workers": {"node-A": {"finished": True}},
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin.r1fs.delete_file.return_value = True

    # Live hset has keys for this job and another
    plugin.chainstore_hgetall.return_value = {
      "job-1:node-A": {"progress": 100},
      "job-1:node-B": {"progress": 50},
      "job-2:node-C": {"progress": 30},
    }
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    # Check that live progress keys for job-1 were deleted
    live_delete_calls = [
      c for c in plugin.chainstore_hset.call_args_list
      if c.kwargs.get("hkey") == "test-instance:live" and c.kwargs.get("value") is None
    ]
    deleted_keys = {c.kwargs["key"] for c in live_delete_calls}
    self.assertEqual(deleted_keys, {"job-1:node-A", "job-1:node-B"})
    # job-2 key should NOT be touched
    self.assertNotIn("job-2:node-C", deleted_keys)

  def test_purge_success_tombstones_cstore(self):
    """After all CIDs deleted, CStore key is tombstoned (set to None)."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "job_cid": "cid-archive",
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin.r1fs.get_json.return_value = {"passes": []}
    plugin.r1fs.delete_file.return_value = True
    plugin.chainstore_hgetall.return_value = {}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    # CStore tombstone: hset(hkey=instance_id, key=job_id, value=None)
    tombstone_calls = [
      c for c in plugin.chainstore_hset.call_args_list
      if c.kwargs.get("hkey") == "test-instance"
        and c.kwargs.get("key") == "job-1"
        and c.kwargs.get("value") is None
    ]
    self.assertEqual(len(tombstone_calls), 1)

  def test_stop_and_delete_delegates_to_purge(self):
    """stop_and_delete_job marks job stopped then delegates to purge_job."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()
    plugin.scan_jobs = {}

    job_specs = {
      "job_id": "job-1",
      "job_status": "RUNNING",
      "workers": {"node-A": {"finished": False}},
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    # Mock purge_job to verify delegation
    purge_result = {"status": "success", "job_id": "job-1", "cids_deleted": 3, "cids_total": 3}
    plugin.purge_job = MagicMock(return_value=purge_result)

    result = Plugin.stop_and_delete_job(plugin, "job-1")

    # Verify job was marked stopped before purge
    hset_calls = [
      c for c in plugin.chainstore_hset.call_args_list
      if c.kwargs.get("hkey") == "test-instance" and c.kwargs.get("key") == "job-1"
    ]
    self.assertEqual(len(hset_calls), 1)
    saved_specs = hset_calls[0].kwargs["value"]
    self.assertEqual(saved_specs["job_status"], "STOPPED")
    self.assertTrue(saved_specs["workers"]["node-A"]["finished"])
    self.assertTrue(saved_specs["workers"]["node-A"]["canceled"])

    # Verify purge was called
    plugin.purge_job.assert_called_once_with("job-1")
    self.assertEqual(result, purge_result)



class TestPhase15Listing(unittest.TestCase):
  """Phase 15: Listing Endpoint Optimization."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def test_list_finalized_returns_stub_fields(self):
    """Finalized jobs return exact CStoreJobFinalized fields."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"

    finalized_stub = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "target": "10.0.0.1",
      "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "task_name": "scan-1",
      "risk_score": 75,
      "run_mode": "SINGLEPASS",
      "duration": 120.5,
      "pass_count": 1,
      "launcher": "0xLauncher",
      "launcher_alias": "node1",
      "worker_count": 2,
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1700000000.0,
      "date_completed": 1700000120.0,
      "job_cid": "QmArchive123",
      "job_config_cid": "QmConfig456",
    }
    plugin.chainstore_hgetall.return_value = {"job-1": finalized_stub}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", finalized_stub))

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("job-1", result)
    entry = result["job-1"]

    # All CStoreJobFinalized fields present
    self.assertEqual(entry["job_id"], "job-1")
    self.assertEqual(entry["job_status"], "FINALIZED")
    self.assertEqual(entry["job_cid"], "QmArchive123")
    self.assertEqual(entry["job_config_cid"], "QmConfig456")
    self.assertEqual(entry["scan_type"], "webapp")
    self.assertEqual(entry["target_url"], "https://example.com/app")
    self.assertEqual(entry["target"], "10.0.0.1")
    self.assertEqual(entry["risk_score"], 75)
    self.assertEqual(entry["duration"], 120.5)
    self.assertEqual(entry["pass_count"], 1)
    self.assertEqual(entry["worker_count"], 2)

  def test_list_running_stripped(self):
    """Running jobs have listing fields but no heavy data."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"

    running_spec = {
      "job_id": "job-2",
      "job_status": "RUNNING",
      "target": "10.0.0.2",
      "scan_type": "webapp",
      "target_url": "https://example.com/live",
      "task_name": "scan-2",
      "risk_score": 0,
      "run_mode": "CONTINUOUS_MONITORING",
      "start_port": 1,
      "end_port": 65535,
      "date_created": 1700000000.0,
      "launcher": "0xLauncher",
      "launcher_alias": "node1",
      "job_pass": 3,
      "job_config_cid": "QmConfig789",
      "workers": {
        "addr-A": {"start_port": 1, "end_port": 32767, "finished": False, "report_cid": "QmBigReport1"},
        "addr-B": {"start_port": 32768, "end_port": 65535, "finished": False, "report_cid": "QmBigReport2"},
      },
      "timeline": [
        {"event": "created", "ts": 1700000000.0},
        {"event": "started", "ts": 1700000001.0},
      ],
      "pass_reports": [
        {"pass_nr": 1, "report_cid": "QmPass1"},
        {"pass_nr": 2, "report_cid": "QmPass2"},
      ],
      "redmesh_job_start_attestation": {"big": "blob"},
    }
    plugin.chainstore_hgetall.return_value = {"job-2": running_spec}
    plugin._normalize_job_record = MagicMock(return_value=("job-2", running_spec))

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("job-2", result)
    entry = result["job-2"]

    # Listing essentials present
    self.assertEqual(entry["job_id"], "job-2")
    self.assertEqual(entry["job_status"], "RUNNING")
    self.assertEqual(entry["target"], "10.0.0.2")
    self.assertEqual(entry["scan_type"], "webapp")
    self.assertEqual(entry["target_url"], "https://example.com/live")
    self.assertEqual(entry["task_name"], "scan-2")
    self.assertEqual(entry["run_mode"], "CONTINUOUS_MONITORING")
    self.assertEqual(entry["job_pass"], 3)
    self.assertEqual(entry["worker_count"], 2)
    self.assertEqual(entry["pass_count"], 2)

    # Heavy fields stripped
    self.assertNotIn("workers", entry)
    self.assertNotIn("timeline", entry)
    self.assertNotIn("pass_reports", entry)
    self.assertNotIn("redmesh_job_start_attestation", entry)
    self.assertNotIn("job_config_cid", entry)
    self.assertNotIn("report_cid", entry)



class TestPhase16ScanMetrics(unittest.TestCase):
  """Phase 16: Scan Metrics Collection."""

  def test_metrics_collector_empty_build(self):
    """build() with zero data returns ScanMetrics with defaults, no crash."""
    from extensions.business.cybersec.red_mesh.worker import MetricsCollector
    mc = MetricsCollector()
    result = mc.build()
    d = result.to_dict()
    self.assertEqual(d.get("total_duration", 0), 0)
    self.assertEqual(d.get("rate_limiting_detected", False), False)
    self.assertEqual(d.get("blocking_detected", False), False)
    # No crash, sparse output
    self.assertNotIn("connection_outcomes", d)
    self.assertNotIn("response_times", d)

  def test_metrics_collector_records_connections(self):
    """After recording outcomes, connection_outcomes has correct counts."""
    from extensions.business.cybersec.red_mesh.worker import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(100)
    mc.record_connection("connected", 0.05)
    mc.record_connection("connected", 0.03)
    mc.record_connection("timeout", 1.0)
    mc.record_connection("refused", 0.01)
    d = mc.build().to_dict()
    outcomes = d["connection_outcomes"]
    self.assertEqual(outcomes["connected"], 2)
    self.assertEqual(outcomes["timeout"], 1)
    self.assertEqual(outcomes["refused"], 1)
    self.assertEqual(outcomes["total"], 4)
    # Response times computed
    rt = d["response_times"]
    self.assertIn("mean", rt)
    self.assertIn("p95", rt)
    self.assertEqual(rt["count"], 4)

  def test_metrics_collector_records_probes(self):
    """After recording probes, probe_breakdown has entries."""
    from extensions.business.cybersec.red_mesh.worker import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(10)
    mc.record_probe("_service_info_http", "completed")
    mc.record_probe("_service_info_ssh", "completed")
    mc.record_probe("_web_test_xss", "skipped:no_http")
    d = mc.build().to_dict()
    self.assertEqual(d["probes_attempted"], 3)
    self.assertEqual(d["probes_completed"], 2)
    self.assertEqual(d["probes_skipped"], 1)
    self.assertEqual(d["probe_breakdown"]["_service_info_http"], "completed")
    self.assertEqual(d["probe_breakdown"]["_web_test_xss"], "skipped:no_http")

  def test_metrics_collector_phase_durations(self):
    """start/end phases produce positive durations."""
    import time
    from extensions.business.cybersec.red_mesh.worker import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(10)
    mc.phase_start("port_scan")
    time.sleep(0.01)
    mc.phase_end("port_scan")
    d = mc.build().to_dict()
    self.assertIn("phase_durations", d)
    self.assertGreater(d["phase_durations"]["port_scan"], 0)

  def test_metrics_collector_findings(self):
    """record_finding tracks severity distribution."""
    from extensions.business.cybersec.red_mesh.worker import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(10)
    mc.record_finding("HIGH")
    mc.record_finding("HIGH")
    mc.record_finding("MEDIUM")
    mc.record_finding("INFO")
    d = mc.build().to_dict()
    fd = d["finding_distribution"]
    self.assertEqual(fd["HIGH"], 2)
    self.assertEqual(fd["MEDIUM"], 1)
    self.assertEqual(fd["INFO"], 1)

  def test_metrics_collector_coverage(self):
    """Coverage tracks ports scanned vs in range."""
    from extensions.business.cybersec.red_mesh.worker import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(100)
    for i in range(50):
      mc.record_connection("connected" if i < 5 else "refused", 0.01)
    # Simulate finding 5 open ports with banner confirmation
    for i in range(5):
      mc.record_open_port(8000 + i, protocol="http" if i < 3 else "ssh", banner_confirmed=(i < 3))
    d = mc.build().to_dict()
    cov = d["coverage"]
    self.assertEqual(cov["ports_in_range"], 100)
    self.assertEqual(cov["ports_scanned"], 50)
    self.assertEqual(cov["coverage_pct"], 50.0)
    self.assertEqual(cov["open_ports_count"], 5)
    # Open port details
    self.assertEqual(len(d["open_port_details"]), 5)
    self.assertEqual(d["open_port_details"][0]["port"], 8000)
    self.assertEqual(d["open_port_details"][0]["protocol"], "http")
    self.assertTrue(d["open_port_details"][0]["banner_confirmed"])
    self.assertFalse(d["open_port_details"][3]["banner_confirmed"])
    # Banner confirmation
    self.assertEqual(d["banner_confirmation"]["confirmed"], 3)
    self.assertEqual(d["banner_confirmation"]["guessed"], 2)

  def test_scan_metrics_model_roundtrip(self):
    """ScanMetrics.from_dict(sm.to_dict()) preserves all fields."""
    from extensions.business.cybersec.red_mesh.models.shared import ScanMetrics
    sm = ScanMetrics(
      phase_durations={"port_scan": 10.5, "fingerprint": 3.2},
      total_duration=15.0,
      connection_outcomes={"connected": 50, "timeout": 5, "total": 55},
      response_times={"min": 0.01, "max": 1.0, "mean": 0.1, "median": 0.08, "stddev": 0.05, "p95": 0.5, "p99": 0.9, "count": 55},
      rate_limiting_detected=True,
      blocking_detected=False,
      coverage={"ports_in_range": 1000, "ports_scanned": 1000, "ports_skipped": 0, "coverage_pct": 100.0},
      probes_attempted=5,
      probes_completed=4,
      probes_skipped=1,
      probes_failed=0,
      probe_breakdown={"_service_info_http": "completed"},
      finding_distribution={"HIGH": 3, "MEDIUM": 2},
    )
    d = sm.to_dict()
    sm2 = ScanMetrics.from_dict(d)
    self.assertEqual(sm2.to_dict(), d)

  def test_scan_metrics_strip_none(self):
    """Empty/None fields stripped from serialization."""
    from extensions.business.cybersec.red_mesh.models.shared import ScanMetrics
    sm = ScanMetrics()
    d = sm.to_dict()
    self.assertNotIn("phase_durations", d)
    self.assertNotIn("connection_outcomes", d)
    self.assertNotIn("response_times", d)
    self.assertNotIn("slow_ports", d)
    self.assertNotIn("probe_breakdown", d)

  def test_merge_worker_metrics(self):
    """_merge_worker_metrics sums outcomes, coverage, findings; maxes duration; ORs flags."""
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    m1 = {
      "connection_outcomes": {"connected": 30, "timeout": 5, "total": 35},
      "coverage": {"ports_in_range": 500, "ports_scanned": 500, "ports_skipped": 0, "coverage_pct": 100.0, "open_ports_count": 3},
      "finding_distribution": {"HIGH": 2, "MEDIUM": 1},
      "service_distribution": {"http": 2, "ssh": 1},
      "probe_breakdown": {"_service_info_http": "completed", "_web_test_xss": "completed"},
      "phase_durations": {"port_scan": 30.0, "fingerprint": 10.0, "service_probes": 15.0},
      "response_times": {"min": 0.01, "max": 0.5, "mean": 0.05, "median": 0.04, "stddev": 0.03, "p95": 0.2, "p99": 0.4, "count": 500},
      "probes_attempted": 3, "probes_completed": 3, "probes_skipped": 0, "probes_failed": 0,
      "total_duration": 60.0,
      "rate_limiting_detected": False, "blocking_detected": False,
      "open_port_details": [
        {"port": 22, "protocol": "ssh", "banner_confirmed": True},
        {"port": 80, "protocol": "http", "banner_confirmed": True},
        {"port": 443, "protocol": "http", "banner_confirmed": False},
      ],
      "banner_confirmation": {"confirmed": 2, "guessed": 1},
    }
    m2 = {
      "connection_outcomes": {"connected": 20, "timeout": 10, "total": 30},
      "coverage": {"ports_in_range": 500, "ports_scanned": 400, "ports_skipped": 100, "coverage_pct": 80.0, "open_ports_count": 2},
      "finding_distribution": {"HIGH": 1, "LOW": 3},
      "service_distribution": {"http": 1, "mysql": 1},
      "probe_breakdown": {"_service_info_http": "completed", "_service_info_mysql": "completed", "_web_test_xss": "failed"},
      "phase_durations": {"port_scan": 45.0, "fingerprint": 8.0, "service_probes": 20.0},
      "response_times": {"min": 0.02, "max": 0.8, "mean": 0.08, "median": 0.06, "stddev": 0.05, "p95": 0.3, "p99": 0.7, "count": 400},
      "probes_attempted": 3, "probes_completed": 2, "probes_skipped": 1, "probes_failed": 0,
      "total_duration": 75.0,
      "rate_limiting_detected": True, "blocking_detected": False,
      "open_port_details": [
        {"port": 80, "protocol": "http", "banner_confirmed": True},  # duplicate port 80
        {"port": 3306, "protocol": "mysql", "banner_confirmed": True},
      ],
      "banner_confirmation": {"confirmed": 2, "guessed": 0},
    }
    merged = PentesterApi01Plugin._merge_worker_metrics([m1, m2])
    # Sums
    self.assertEqual(merged["connection_outcomes"]["connected"], 50)
    self.assertEqual(merged["connection_outcomes"]["timeout"], 15)
    self.assertEqual(merged["connection_outcomes"]["total"], 65)
    self.assertEqual(merged["coverage"]["ports_in_range"], 1000)
    self.assertEqual(merged["coverage"]["ports_scanned"], 900)
    self.assertEqual(merged["coverage"]["ports_skipped"], 100)
    self.assertEqual(merged["coverage"]["coverage_pct"], 90.0)
    self.assertEqual(merged["coverage"]["open_ports_count"], 5)
    self.assertEqual(merged["finding_distribution"]["HIGH"], 3)
    self.assertEqual(merged["finding_distribution"]["LOW"], 3)
    self.assertEqual(merged["finding_distribution"]["MEDIUM"], 1)
    self.assertEqual(merged["probes_attempted"], 6)
    self.assertEqual(merged["probes_completed"], 5)
    self.assertEqual(merged["probes_skipped"], 1)
    # Service distribution summed
    self.assertEqual(merged["service_distribution"]["http"], 3)
    self.assertEqual(merged["service_distribution"]["ssh"], 1)
    self.assertEqual(merged["service_distribution"]["mysql"], 1)
    # Probe breakdown: union, worst status wins
    self.assertEqual(merged["probe_breakdown"]["_service_info_http"], "completed")
    self.assertEqual(merged["probe_breakdown"]["_service_info_mysql"], "completed")
    self.assertEqual(merged["probe_breakdown"]["_web_test_xss"], "failed")  # failed > completed
    # Phase durations: max per phase (threads/nodes run in parallel)
    self.assertEqual(merged["phase_durations"]["port_scan"], 45.0)
    self.assertEqual(merged["phase_durations"]["fingerprint"], 10.0)
    self.assertEqual(merged["phase_durations"]["service_probes"], 20.0)
    # Response times: merged stats
    rt = merged["response_times"]
    self.assertEqual(rt["min"], 0.01)   # global min
    self.assertEqual(rt["max"], 0.8)    # global max
    self.assertEqual(rt["count"], 900)  # total count
    # Weighted mean: (0.05*500 + 0.08*400) / 900 ≈ 0.0633
    self.assertAlmostEqual(rt["mean"], 0.0633, places=3)
    self.assertEqual(rt["p95"], 0.3)    # max of per-thread p95
    self.assertEqual(rt["p99"], 0.7)    # max of per-thread p99
    # Max duration
    self.assertEqual(merged["total_duration"], 75.0)
    # OR flags
    self.assertTrue(merged["rate_limiting_detected"])
    self.assertFalse(merged["blocking_detected"])
    # Open port details: deduplicated by port, sorted
    opd = merged["open_port_details"]
    self.assertEqual(len(opd), 4)  # 22, 80, 443, 3306 (80 deduplicated)
    self.assertEqual(opd[0]["port"], 22)
    self.assertEqual(opd[1]["port"], 80)
    self.assertEqual(opd[2]["port"], 443)
    self.assertEqual(opd[3]["port"], 3306)
    # Banner confirmation: summed
    self.assertEqual(merged["banner_confirmation"]["confirmed"], 4)
    self.assertEqual(merged["banner_confirmation"]["guessed"], 1)


  def test_close_job_merges_thread_metrics(self):
    """16b: _close_job replaces generically-merged scan_metrics with properly summed metrics."""
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"

    # Two mock workers with different scan_metrics
    worker1 = MagicMock()
    worker1.get_status.return_value = {
      "open_ports": [80], "service_info": {}, "scan_metrics": {
        "connection_outcomes": {"connected": 10, "timeout": 2, "total": 12},
        "total_duration": 30.0,
        "probes_attempted": 2, "probes_completed": 2, "probes_skipped": 0, "probes_failed": 0,
        "rate_limiting_detected": False, "blocking_detected": False,
      }
    }
    worker2 = MagicMock()
    worker2.get_status.return_value = {
      "open_ports": [443], "service_info": {}, "scan_metrics": {
        "connection_outcomes": {"connected": 8, "timeout": 5, "total": 13},
        "total_duration": 45.0,
        "probes_attempted": 2, "probes_completed": 1, "probes_skipped": 1, "probes_failed": 0,
        "rate_limiting_detected": True, "blocking_detected": False,
      }
    }
    plugin.scan_jobs = {"job-1": {"t1": worker1, "t2": worker2}}

    # _get_aggregated_report with merge_objects_deep would do last-writer-wins on leaf ints
    # Simulate that by returning worker2's metrics (wrong — should be summed)
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80, 443], "service_info": {},
      "scan_metrics": {
        "connection_outcomes": {"connected": 8, "timeout": 5, "total": 13},
        "total_duration": 45.0,
      }
    })
    # Use real static method for merge
    plugin._merge_worker_metrics = PentesterApi01Plugin._merge_worker_metrics

    saved_reports = []
    def capture_add_json(data, show_logs=False):
      saved_reports.append(data)
      return "QmReport123"
    plugin.r1fs.add_json.side_effect = capture_add_json

    job_specs = {"job_id": "job-1", "target": "10.0.0.1", "workers": {}}
    plugin.chainstore_hget.return_value = job_specs
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))
    plugin._get_job_config = MagicMock(return_value={"redact_credentials": False})
    plugin._redact_report = MagicMock(side_effect=lambda r: r)

    PentesterApi01Plugin._close_job(plugin, "job-1")

    # The report saved to R1FS should have properly merged metrics
    self.assertEqual(len(saved_reports), 1)
    sm = saved_reports[0].get("scan_metrics")
    self.assertIsNotNone(sm)
    # Connection outcomes should be summed, not last-writer-wins
    self.assertEqual(sm["connection_outcomes"]["connected"], 18)
    self.assertEqual(sm["connection_outcomes"]["timeout"], 7)
    self.assertEqual(sm["connection_outcomes"]["total"], 25)
    # Max duration
    self.assertEqual(sm["total_duration"], 45.0)
    # Probes summed
    self.assertEqual(sm["probes_attempted"], 4)
    self.assertEqual(sm["probes_completed"], 3)
    # OR flags
    self.assertTrue(sm["rate_limiting_detected"])

  def test_finalize_pass_attaches_pass_metrics(self):
    """16c: _maybe_finalize_pass merges node metrics into PassReport.scan_metrics."""
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-launcher"
    plugin.cfg_llm_agent_api_enabled = False
    plugin.cfg_attestation_min_seconds_between_submits = 3600

    # Two workers, each with a report_cid
    workers = {
      "node-A": {"finished": True, "report_cid": "cid-report-A"},
      "node-B": {"finished": True, "report_cid": "cid-report-B"},
    }
    job_specs = {
      "job_id": "job-1",
      "job_status": "RUNNING",
      "target": "10.0.0.1",
      "run_mode": "SINGLEPASS",
      "launcher": "node-launcher",
      "workers": workers,
      "job_pass": 1,
      "pass_reports": [],
      "timeline": [{"event": "created", "ts": 1700000000.0}],
    }
    plugin.chainstore_hgetall.return_value = {"job-1": job_specs}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))
    plugin.time.return_value = 1700000120.0

    # Node reports with different metrics
    node_report_a = {
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "correlation_findings": [], "start_port": 1, "end_port": 32767,
      "ports_scanned": 32767,
      "scan_metrics": {
        "connection_outcomes": {"connected": 5, "timeout": 1, "total": 6},
        "total_duration": 50.0,
        "probes_attempted": 3, "probes_completed": 3, "probes_skipped": 0, "probes_failed": 0,
        "rate_limiting_detected": False, "blocking_detected": False,
      }
    }
    node_report_b = {
      "open_ports": [443], "service_info": {}, "web_tests_info": {},
      "correlation_findings": [], "start_port": 32768, "end_port": 65535,
      "ports_scanned": 32768,
      "scan_metrics": {
        "connection_outcomes": {"connected": 3, "timeout": 4, "total": 7},
        "total_duration": 65.0,
        "probes_attempted": 3, "probes_completed": 2, "probes_skipped": 0, "probes_failed": 1,
        "rate_limiting_detected": False, "blocking_detected": True,
      }
    }

    node_reports_by_addr = {"node-A": node_report_a, "node-B": node_report_b}
    plugin._collect_node_reports = MagicMock(return_value=node_reports_by_addr)
    # _get_aggregated_report would use merge_objects_deep (wrong for metrics)
    # Return a dict with last-writer-wins metrics to simulate the bug
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80, 443], "service_info": {}, "web_tests_info": {},
      "scan_metrics": node_report_b["scan_metrics"],  # wrong — just node B's
    })
    # Use real static method for merge
    plugin._merge_worker_metrics = PentesterApi01Plugin._merge_worker_metrics

    # Capture what gets saved as pass report
    saved_pass_reports = []
    def capture_add_json(data, show_logs=False):
      saved_pass_reports.append(data)
      return f"QmPassReport{len(saved_pass_reports)}"
    plugin.r1fs.add_json.side_effect = capture_add_json

    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 25, "breakdown": {}}, []))
    plugin._get_job_config = MagicMock(return_value={})
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._build_job_archive = MagicMock()
    plugin._clear_live_progress = MagicMock()
    plugin._emit_timeline_event = MagicMock()
    plugin._get_timeline_date = MagicMock(return_value=1700000000.0)
    plugin.Pd = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # Should have saved: aggregated_data (step 6) + pass_report (step 10)
    self.assertGreaterEqual(len(saved_pass_reports), 2)
    pass_report = saved_pass_reports[-1]  # Last one is the PassReport

    sm = pass_report.get("scan_metrics")
    self.assertIsNotNone(sm, "PassReport should have scan_metrics")
    # Connection outcomes summed across nodes
    self.assertEqual(sm["connection_outcomes"]["connected"], 8)
    self.assertEqual(sm["connection_outcomes"]["timeout"], 5)
    self.assertEqual(sm["connection_outcomes"]["total"], 13)
    # Max duration
    self.assertEqual(sm["total_duration"], 65.0)
    # Probes summed
    self.assertEqual(sm["probes_attempted"], 6)
    self.assertEqual(sm["probes_completed"], 5)
    self.assertEqual(sm["probes_failed"], 1)
    # OR flags
    self.assertFalse(sm["rate_limiting_detected"])
    self.assertTrue(sm["blocking_detected"])
