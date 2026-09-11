"""Explicit rollout records, configuration floor and provenance at the CStore boundary."""
from itertools import product
from unittest.mock import patch
import unittest

from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError

from . import test_tenant_asset_administration as fixtures


class TestTenantExecutionRollout(unittest.TestCase):
  setUp = fixtures.TestTenantAssetAdministration.setUp

  def record(self, stage="compatibility", enabled=False):
    self.store.put("execution_rollout", "instance-a", record={"stage": stage, "enabled": enabled})

  def read(self, stage="compatibility", enabled=False):
    return self.service.read_execution_rollout("instance-a", stage=stage, enabled=enabled)

  def test_compatibility_requires_explicit_known_storage_without_initialization_writes(self):
    before = len(self.owner.writes)
    with self.assertRaises(TenantStoreError):
      self.read()
    self.assertEqual(len(self.owner.writes), before)
    self.record()
    rollout = self.read()
    self.assertTrue(rollout.allows_new(bound=False, membership_key_present=False, selectors_omitted=True))
    self.assertFalse(rollout.allows_new(bound=True))
    with self.assertRaises(TenantStoreError):
      self.service.read_execution_rollout("other-instance", stage="compatibility", enabled=False)

  def test_complete_control_matrix_pins_the_restrictive_floor_and_new_admission_lanes(self):
    stages = ("compatibility", "draining", "tenant")
    for configured_stage, stored_stage, configured_enabled, stored_enabled in product(stages, stages, (False, True), (False, True)):
      with self.subTest(configured_stage=configured_stage, stored_stage=stored_stage,
                        configured_enabled=configured_enabled, stored_enabled=stored_enabled):
        self.record(stored_stage, stored_enabled)
        rollout = self.read(configured_stage, configured_enabled)
        self.assertEqual(rollout.stage, stages[max(stages.index(configured_stage), stages.index(stored_stage))])
        bound_allowed = configured_stage == stored_stage == "tenant" and configured_enabled and stored_enabled
        legacy_allowed = configured_stage == stored_stage == "compatibility" and not configured_enabled and not stored_enabled
        self.assertIs(rollout.allows_new(bound=True), bound_allowed)
        for presence, omitted in product((None, False, True, 0, "absent"), (False, True, 1, None)):
          self.assertIs(rollout.allows_new(bound=False, membership_key_present=presence, selectors_omitted=omitted),
            legacy_allowed and presence is False and omitted is True)
        for malformed_bound in (None, 0, 1, "false"):
          self.assertFalse(rollout.allows_new(bound=malformed_bound, membership_key_present=False, selectors_omitted=True))

  def test_draining_settles_current_work_but_blocks_new_admission_and_future_passes(self):
    self.record("draining", False)
    rollout = self.read("draining", False)
    for bound in (False, True):
      self.assertTrue(rollout.allows_existing(bound=bound, operation="current"))
      self.assertFalse(rollout.allows_existing(bound=bound, operation="new_pass"))
      self.assertFalse(rollout.allows_existing(bound=bound, operation="preflight"))
      self.assertFalse(rollout.allows_new(bound=bound, membership_key_present=False, selectors_omitted=True))
    self.record("compatibility", False)
    self.assertEqual(self.read("draining", False).stage, "draining")
    self.assertFalse(self.read("draining", False).allows_new(
      bound=False, membership_key_present=False, selectors_omitted=True))
    self.record("tenant", False)
    for configured_stage in ("compatibility", "draining", "tenant"):
      for bound in (False, True):
        self.assertFalse(self.read(configured_stage, False).allows_existing(bound=bound))
        self.assertFalse(self.read(configured_stage, False).allows_new(
          bound=bound, membership_key_present=False, selectors_omitted=True))

  def test_current_bound_work_requires_matching_tenant_controls_outside_draining(self):
    self.record("tenant", True)
    rollout = self.read("tenant", True)
    self.assertTrue(rollout.allows_existing(bound=True))
    self.assertTrue(rollout.allows_existing(bound=True, operation="new_pass"))
    self.assertFalse(rollout.allows_existing(bound=False))
    self.assertFalse(self.read("compatibility", True).allows_existing(bound=True))
    self.assertFalse(self.read("tenant", False).allows_existing(bound=True))
    self.record()
    self.assertTrue(self.read().allows_existing(bound=False))
    self.assertFalse(self.read().allows_existing(bound=True))
    for presence in (None, True, 0, "absent"):
      self.assertFalse(self.read().allows_existing(bound=False, operation="new_pass",
        membership_key_present=presence))
    self.assertTrue(self.read().allows_existing(bound=False, operation="new_pass", membership_key_present=False))

  def test_invalid_config_and_typed_storage_fail_closed_without_writes(self):
    self.record()
    before = len(self.owner.writes)
    for stage in (None, "", "Tenant", "unknown", [], False):
      with self.subTest(stage=stage), self.assertRaises(TenantStoreError):
        self.read(stage)
    for enabled in (None, 0, 1, "false", {}, []):
      with self.subTest(enabled=enabled), self.assertRaises(TenantStoreError):
        self.read(enabled=enabled)
    key = ('["redmesh","tenancy",1,"deployment"]', '["execution_rollout","deployment","instance-a"]')
    saved = self.owner.data[key]
    for changes in ({"stage": "unknown"}, {"stage": None}, {"enabled": 0}, {"enabled": "false"},
                    {"schemaVersion": True}, {"namespace": "foreign"}, {"ids": ["other"]},
                    {"unrecognized_control": True}):
      with self.subTest(changes=changes), self.assertRaises(TenantStoreError):
        self.owner.data[key] = {**saved, **changes}
        self.read()
    self.owner.data[key] = saved
    for missing in ("enabled", "stage"):
      with self.subTest(missing=missing), self.assertRaises(TenantStoreError):
        self.owner.data[key] = {name: value for name, value in saved.items() if name != missing}
        self.read()
    with patch.object(self.owner, "chainstore_hget", side_effect=RuntimeError("private failure")):
      with self.assertRaises(TenantStoreError):
        self.read()
    self.assertEqual(len(self.owner.writes), before)


class TestBoundEffectiveNetworkAssignments(unittest.TestCase):
  def test_bound_assignments_require_ports_remaining_after_exclusions(self):
    from .test_api import TestPhase1ConfigCID
    from .test_tenant_execution_effects import context
    from extensions.business.cybersec.red_mesh.services.launch_api import build_network_workers, launch_network_scan
    from extensions.business.cybersec.red_mesh.worker.pentest_worker import PentestLocalWorker
    admission = context({"kind": "network", "address": "192.0.2.1"})
    for comparison_mode in (False, True):
      for emptied in (True, False):
        with self.subTest(comparison_mode=comparison_mode, emptied=emptied):
          owner = TestPhase1ConfigCID._build_mock_plugin()
          TestPhase1ConfigCID._bind_launch_helpers(owner)
          assignments, error = build_network_workers(owner, ["node-1", "node-2"], 1, 4, "SLICE",
                                                     comparison_mode=comparison_mode)
          self.assertIsNone(error)
          first = assignments["node-1"]
          first_ports = first.get("target_ports") or list(range(first["start_port"], first["end_port"] + 1))
          exceptions = first_ports if emptied else first_ports[:-1]
          with patch("socket.socket", side_effect=AssertionError("No network")), \
               patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")):
            result = launch_network_scan(owner, execution_context=admission, authorized=True,
              start_port=1, end_port=4, exceptions=exceptions, comparison_mode=comparison_mode)
          if emptied:
            self.assertEqual(result.get("error"), "validation_error")
            self.assertEqual(result.get("message"), "Empty execution assignment")
            owner.r1fs.add_json.assert_not_called()
            owner.chainstore_hset.assert_not_called()
          else:
            self.assertNotIn("error", result)
            self.assertEqual(result["job_specs"]["execution_binding"]["participant_order"], ["node-1", "node-2"])
            for address, assigned in assignments.items():
              ports = assigned.get("target_ports") or list(range(assigned["start_port"], assigned["end_port"] + 1))
              worker = PentestLocalWorker(owner, target="192.0.2.1", job_id="fixture-job", initiator="launcher",
                local_id_prefix=address, worker_target_ports=ports, exceptions=exceptions)
              self.assertTrue(worker.initial_ports)

  def test_unbound_exclusion_behavior_is_unchanged(self):
    from .test_api import TestPhase1ConfigCID
    from extensions.business.cybersec.red_mesh.services.launch_api import launch_network_scan
    owner = TestPhase1ConfigCID._build_mock_plugin()
    TestPhase1ConfigCID._bind_launch_helpers(owner)
    owner.cfg_chainstore_peers = ["node-1", "node-2"]
    result = launch_network_scan(owner, target="192.0.2.1", authorized=True,
      start_port=1, end_port=4, exceptions=[1, 2])
    self.assertNotIn("error", result)
    self.assertNotIn("execution_binding", result["job_specs"])
    owner.r1fs.add_json.assert_called()
    owner.chainstore_hset.assert_called()
