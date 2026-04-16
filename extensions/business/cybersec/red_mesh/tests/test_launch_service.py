import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.constants import (
  PORT_ORDER_SEQUENTIAL,
  ScanType,
)
from extensions.business.cybersec.red_mesh.services.launch import launch_local_jobs
from extensions.business.cybersec.red_mesh.services.scan_strategy import ScanStrategy


class DummyOwner:
  def __init__(self):
    self.cfg_port_order = PORT_ORDER_SEQUENTIAL
    self.cfg_excluded_features = []
    self.cfg_scan_min_rnd_delay = 0.0
    self.cfg_scan_max_rnd_delay = 0.0
    self.cfg_ics_safe_mode = True
    self.cfg_scanner_identity = "probe.redmesh.local"
    self.cfg_scanner_user_agent = ""
    self.cfg_nr_local_workers = 2
    self.messages = []

  def P(self, message, **_kwargs):
    self.messages.append(message)


class DummyNetworkWorker:
  def __init__(self, *, local_id_prefix, worker_target_ports, **kwargs):
    self.local_worker_id = f"worker-{local_id_prefix}"
    self.worker_target_ports = worker_target_ports
    self.kwargs = kwargs
    self.started = False

  def start(self):
    self.started = True


class DummyWebappWorker:
  def __init__(self, *, local_id, target_url, job_config, **kwargs):
    self.local_worker_id = local_id
    self.target_url = target_url
    self.job_config = job_config
    self.kwargs = kwargs
    self.started = False

  def start(self):
    self.started = True


class TestLaunchService(unittest.TestCase):

  def test_launch_local_jobs_uses_network_strategy_dispatch(self):
    owner = DummyOwner()
    strategy = ScanStrategy(
      scan_type=ScanType.NETWORK,
      worker_cls=DummyNetworkWorker,
      catalog_categories=("service",),
    )

    with patch("extensions.business.cybersec.red_mesh.services.launch.get_scan_strategy", return_value=strategy):
      local_jobs = launch_local_jobs(
        owner,
        job_id="job-1",
        target="10.0.0.10",
        launcher="0xlauncher",
        start_port=1,
        end_port=4,
        job_config={
          "scan_type": "network",
          "nr_local_workers": 2,
          "port_order": PORT_ORDER_SEQUENTIAL,
        },
      )

    self.assertEqual(len(local_jobs), 2)
    self.assertTrue(all(worker.started for worker in local_jobs.values()))
    self.assertEqual(
      sorted(len(worker.worker_target_ports) for worker in local_jobs.values()),
      [2, 2],
    )

  def test_launch_local_jobs_uses_webapp_strategy_dispatch(self):
    owner = DummyOwner()
    strategy = ScanStrategy(
      scan_type=ScanType.WEBAPP,
      worker_cls=DummyWebappWorker,
      catalog_categories=("graybox",),
    )

    with patch("extensions.business.cybersec.red_mesh.services.launch.get_scan_strategy", return_value=strategy):
      local_jobs = launch_local_jobs(
        owner,
        job_id="job-2",
        target="app.internal",
        launcher="0xlauncher",
        start_port=443,
        end_port=443,
        job_config={
          "scan_type": "webapp",
          "target": "app.internal",
          "start_port": 443,
          "end_port": 443,
          "exceptions": [],
          "distribution_strategy": "SLICE",
          "port_order": PORT_ORDER_SEQUENTIAL,
          "nr_local_workers": 1,
          "enabled_features": [],
          "excluded_features": [],
          "run_mode": "SINGLEPASS",
          "target_url": "https://example.com/app",
          "official_username": "admin",
          "official_password": "secret",
        },
      )

    self.assertEqual(list(local_jobs.keys()), ["1"])
    worker = local_jobs["1"]
    self.assertTrue(worker.started)
    self.assertEqual(worker.target_url, "https://example.com/app")
    self.assertEqual(worker.job_config.scan_type, "webapp")
