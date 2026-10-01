import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.constants import (
  PORT_ORDER_SEQUENTIAL,
  ScanType,
)
from extensions.business.cybersec.red_mesh.services.launch import launch_local_jobs
from extensions.business.cybersec.red_mesh.services.scan_strategy import ScanStrategy
from .test_tenant_execution_effects import context as _execution_context


def _bound_network_config(job_config, address="10.0.0.10"):
  """RM-108 phase 5: admission never yields an unbound config."""
  binding = _execution_context({"kind": "network", "address": address}).build_binding(
    "0xlauncher", ["node-1"]).to_dict()
  return {**job_config, "target": address, "execution_binding": binding}


def _bound_webapp_config(job_config, url="https://example.com/app"):
  binding = _execution_context(
    {"kind": "webapp", "url": url, "allowedPathPrefix": "/"}).build_binding(
    "0xlauncher", ["node-1"]).to_dict()
  return {**job_config, "execution_binding": binding}


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
    # RM-108 phase 5: a bound job_config now requires the owner to reauthorize the announced
    # assignment before local workers start; these dispatch/port-slicing tests are not about that
    # check, so it is a stub that always confirms the announced assignment.
    self._worker_assignment = {}

  def P(self, message, **_kwargs):
    self.messages.append(message)

  def _require_worker_execution(self, job_id, job_config, execution_identity=None):
    return self._worker_assignment


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
    owner._worker_assignment = {"start_port": 1, "end_port": 4, "target_ports": None}
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
        job_config=_bound_network_config({
          "scan_type": "network",
          "nr_local_workers": 2,
          "port_order": PORT_ORDER_SEQUENTIAL,
        }),
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
        job_config=_bound_webapp_config({
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
        }),
      )

    self.assertEqual(list(local_jobs.keys()), ["1"])
    worker = local_jobs["1"]
    self.assertTrue(worker.started)
    self.assertEqual(worker.target_url, "https://example.com/app")
    self.assertEqual(worker.job_config.scan_type, "webapp")

  def test_explicit_target_ports_override_contiguous_range(self):
    """Comparison mode supplies an explicit, non-contiguous port list."""
    owner = DummyOwner()
    owner._worker_assignment = {"start_port": 1, "end_port": 2, "target_ports": [22, 443, 8080]}
    strategy = ScanStrategy(
      scan_type=ScanType.NETWORK,
      worker_cls=DummyNetworkWorker,
      catalog_categories=("service",),
    )
    with patch("extensions.business.cybersec.red_mesh.services.launch.get_scan_strategy", return_value=strategy):
      local_jobs = launch_local_jobs(
        owner,
        job_id="job-cmp",
        target="10.0.0.10",
        launcher="0xlauncher",
        start_port=1,
        end_port=2,  # ignored when target_ports is provided
        job_config=_bound_network_config({
          "scan_type": "network",
          "nr_local_workers": 1,
          "port_order": PORT_ORDER_SEQUENTIAL,
        }),
        target_ports=[22, 443, 8080],
      )
    scanned = sorted(
      p for worker in local_jobs.values() for p in worker.worker_target_ports
    )
    self.assertEqual(scanned, [22, 443, 8080])

  def test_network_timeout_profile_reaches_each_local_worker(self):
    owner = DummyOwner()
    owner._worker_assignment = {"start_port": 80, "end_port": 81, "target_ports": None}
    strategy = ScanStrategy(
      scan_type=ScanType.NETWORK,
      worker_cls=DummyNetworkWorker,
      catalog_categories=("service",),
    )
    with patch("extensions.business.cybersec.red_mesh.services.launch.get_scan_strategy", return_value=strategy):
      local_jobs = launch_local_jobs(
        owner,
        job_id="job-thorough",
        target="10.0.0.10",
        launcher="0xlauncher",
        start_port=80,
        end_port=81,
        job_config=_bound_network_config({
          "scan_type": "network",
          "nr_local_workers": 2,
          "port_order": PORT_ORDER_SEQUENTIAL,
          "timeout_profile": "THOROUGH",
        }),
      )

    self.assertEqual(
      {worker.kwargs["timeout_profile"] for worker in local_jobs.values()},
      {"THOROUGH"},
    )

  def _launch_with_roe(self, roe):
    owner = DummyOwner()
    owner._worker_assignment = {"start_port": 22, "end_port": 23, "target_ports": None}
    strategy = ScanStrategy(
      scan_type=ScanType.NETWORK,
      worker_cls=DummyNetworkWorker,
      catalog_categories=("service",),
    )
    job_config = {"scan_type": "network", "nr_local_workers": 1}
    if roe is not None:
      job_config["roe"] = roe
    job_config = _bound_network_config(job_config)
    with patch("extensions.business.cybersec.red_mesh.services.launch.get_scan_strategy", return_value=strategy):
      local_jobs = launch_local_jobs(
        owner, job_id="job-roe", target="10.0.0.10", launcher="0xlauncher",
        start_port=22, end_port=23, job_config=job_config,
      )
    return {worker.kwargs["authenticated_action"] for worker in local_jobs.values()}

  def test_authenticated_action_follows_the_roe(self):
    # RM-103 item 5: off unless the job's RoE permit it.
    self.assertEqual(self._launch_with_roe(None), {False})
    self.assertEqual(self._launch_with_roe({"dos_allowed": True}), {False})
    self.assertEqual(self._launch_with_roe({"authenticated_action": True}), {True})
    self.assertEqual(self._launch_with_roe({"authenticated_action": "false"}), {False})
    # RM-095: the engagement snapshot's three-field RoE.
    self.assertEqual(self._launch_with_roe({"authenticated_action": True, "stateful_probes_allowed": False,
                                            "ics_safe_mode_required": True}), {True})


class TestComparisonTieredAssignment(unittest.TestCase):
  """Tiered mirror+slice port assignment for geographic comparison mode."""

  def test_slice_mirrors_common_ports_and_splits_the_chosen_range(self):
    """SLICE (default): only COMMON_PORTS are mirrored/compared; the operator's
    chosen range is split across nodes for coverage (not mirrored)."""
    from extensions.business.cybersec.red_mesh.constants import COMMON_PORTS
    from extensions.business.cybersec.red_mesh.services.launch_api import (
      build_comparison_workers,
      compute_comparison_port_tier,
    )
    # The comparison tier is exactly COMMON_PORTS — the chosen range is NOT in it.
    tier = set(compute_comparison_port_tier(1, 33))
    self.assertEqual(tier, {p for p in COMMON_PORTS if 1 <= p <= 65535})
    self.assertNotIn(1, tier)
    self.assertIn(443, tier)

    workers = build_comparison_workers(["0xA", "0xB", "0xC"], 1, 33)
    common = set(COMMON_PORTS)
    coverage_slices = []
    for w in workers.values():
      target = set(w["target_ports"])
      self.assertTrue(common.issubset(target))  # standard ports mirrored to all
      coverage_slices.append(target - common)
    # The chosen range (minus common ports already mirrored) is split disjointly
    # across nodes and together covers 1..33 — i.e. sliced, not mirrored.
    union = set().union(*coverage_slices) | common
    self.assertTrue(set(range(1, 34)).issubset(union))
    for i in range(len(coverage_slices)):
      for j in range(i + 1, len(coverage_slices)):
        self.assertTrue(coverage_slices[i].isdisjoint(coverage_slices[j]))
    # Not every node scans the same set (slicing actually happened).
    self.assertGreater(len({tuple(w["target_ports"]) for w in workers.values()}), 1)

  def test_large_range_mirrors_common_ports_and_slices_bulk(self):
    from extensions.business.cybersec.red_mesh.constants import COMMON_PORTS
    from extensions.business.cybersec.red_mesh.services.launch_api import (
      build_comparison_workers,
    )
    workers = build_comparison_workers(["0xA", "0xB", "0xC"], 1, 5000)
    common = set(COMMON_PORTS)
    union = set()
    coverage_slices = []
    for w in workers.values():
      target = set(w["target_ports"])
      self.assertTrue(common.issubset(target))  # comparison tier mirrored to all
      union |= target
      coverage_slices.append(target - common)
    # Coverage slices are disjoint and together cover the whole range.
    self.assertTrue(set(range(1, 5001)).issubset(union))
    for i in range(len(coverage_slices)):
      for j in range(i + 1, len(coverage_slices)):
        self.assertTrue(coverage_slices[i].isdisjoint(coverage_slices[j]))

  def test_full_mirror_gives_every_node_the_full_range(self):
    """MIRROR choice in comparison mode: every node scans the identical full
    range (plus standard ports), with no coverage split."""
    from extensions.business.cybersec.red_mesh.constants import COMMON_PORTS
    from extensions.business.cybersec.red_mesh.services.launch_api import (
      build_comparison_workers,
    )
    workers = build_comparison_workers(["0xA", "0xB", "0xC"], 1, 5000, full_mirror=True)
    expected = sorted(set(range(1, 5001)) | set(COMMON_PORTS))
    port_sets = [w["target_ports"] for w in workers.values()]
    for target in port_sets:
      self.assertEqual(target, expected)  # identical full set on every node
    # All nodes scan the same set (no disjoint coverage slices).
    self.assertEqual(len({tuple(t) for t in port_sets}), 1)


class TestWorkerAssignmentRevision(unittest.TestCase):
  """Every freshly built worker entry carries assignment_revision=1.

  Bound (tenant) jobs are refused by the worker's launch gate until the field is an int >= 1,
  so a launch that omits it only starts after the launcher's startup_timeout reannounce.
  """

  def test_network_mirror_and_slice_seed_revision_one(self):
    from extensions.business.cybersec.red_mesh.constants import DISTRIBUTION_MIRROR, DISTRIBUTION_SLICE
    from extensions.business.cybersec.red_mesh.services.launch_api import build_network_workers

    for strategy in (DISTRIBUTION_MIRROR, DISTRIBUTION_SLICE):
      workers, error = build_network_workers(DummyOwner(), ["0xA", "0xB"], 1, 100, strategy)
      self.assertIsNone(error)
      self.assertEqual({entry["assignment_revision"] for entry in workers.values()}, {1}, strategy)

  def test_comparison_workers_seed_revision_one(self):
    from extensions.business.cybersec.red_mesh.services.launch_api import build_comparison_workers

    for full_mirror in (False, True):
      workers = build_comparison_workers(["0xA", "0xB"], 1, 100, full_mirror=full_mirror)
      self.assertEqual({entry["assignment_revision"] for entry in workers.values()}, {1}, full_mirror)
