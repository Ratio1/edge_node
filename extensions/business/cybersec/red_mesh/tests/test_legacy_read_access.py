"""Legacy compatibility is a fresh stored-account decision, never an omitted selector default."""
from copy import deepcopy
from itertools import product
from threading import Event, Thread
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.repositories.cstore import JobStateRepository
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied, TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from extensions.business.cybersec.red_mesh.tenancy.read_access import LegacyReadAccess
from .test_tenant_read_access import ReadStore
from .test_execution_binding_models import binding_payload
from . import test_api as api_fixtures


class TestLegacyReadAccess(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.owner = ReadStore()
    self.Plugin = api_fixtures.TestPhase3Archive()._get_plugin_class()
    self.owner.account("reader")
    self.accounts = CstoreAuthAccountReader(self.owner)
    self.tenants = CstoreTenantAdministrationStore(self.owner, "deployment")
    self.administration = TenantAdministrationService(self.accounts, self.tenants)
    self.owner.stage = "compatibility"
    self.owner.enabled = False
    self.tenants.put("execution_rollout", self.owner.cfg_instance_id,
                     record={"stage": "compatibility", "enabled": False})
    self.rollout_reads = 0
    self.normalizations = []
    self.actor = {"account_id": "reader"}
    self.owner.jobs["storage-alias"] = {"job_id": "job-1", "job_status": "RUNNING", "workers": {},
                                       "extension": {"items": ["preserved"]}}
    self.access = LegacyReadAccess(self.administration, JobStateRepository(self.owner),
                                  self.normalize, self.rollout)
    self.owner.reads.clear()
    self.writes_before = list(self.owner.writes)

  def normalize(self, key, record, *, migrate):
    self.normalizations.append((key, migrate))
    return self.Plugin._normalize_job_record(self.owner, key, record, migrate=migrate)

  def rollout(self):
    self.rollout_reads += 1
    return self.administration.read_execution_rollout(self.owner.cfg_instance_id,
      enabled=self.owner.enabled, stage=self.owner.stage)

  def read(self, operation="list", *, actor=None, permission="reports:view", job_id="job-1"):
    actor = self.actor if actor is None else actor
    if operation == "get":
      return self.access.get_job(actor, job_id, operation=permission)
    return self.access.list_jobs(actor, operation=permission)

  def assert_no_job_read(self):
    self.assertFalse(any(entry[1] == self.owner.cfg_instance_id for entry in self.owner.reads))
    self.assertEqual(self.owner.writes, self.writes_before)

  def test_fresh_identity_and_current_rollout_precede_one_captured_enumeration(self):
    for operation in ("get", "list"):
      with self.subTest(operation=operation):
        self.owner.reads.clear()
        self.rollout_reads = 0
        result = self.read(operation)
        job = result if operation == "get" else result["storage-alias"]
        self.assertEqual(job["job_id"], "job-1")
        self.assertEqual(job["launcher"], "storage-alias")
        self.assertEqual(self.owner.reads[0], ("get", "auth", "reader"))
        self.assertEqual(sum(item == ("get", "auth", "reader") for item in self.owner.reads), 1)
        self.assertEqual(self.rollout_reads, 1)
        self.assertEqual(self.owner.reads[-1], ("list", self.owner.cfg_instance_id))
        self.assertTrue(all(migrate is False for _, migrate in self.normalizations))
        self.assertEqual(self.owner.writes, self.writes_before)

  def test_point_lookup_is_logical_id_only_and_missing_ids_use_real_normalization(self):
    with self.assertRaises(AdministrationDenied) as caught:
      self.read("get", job_id="storage-alias")
    self.assertEqual(caught.exception.status_code, 404)
    self.owner.jobs["without-id"] = {"workers": {}}
    self.assertEqual(self.read("get", job_id="without-id")["job_id"], "without-id")
    self.assertEqual(set(self.read()), {"storage-alias", "without-id"})

  def test_explicit_empty_malformed_memberships_and_revocation_never_become_legacy(self):
    for membership in ([], None, {}, "legacy", [{"role": "tenant_user", "tenant_id": "unknown"}]):
      with self.subTest(membership=membership):
        self.owner.data[("auth", "reader")]["metadata"]["tenant_memberships"] = membership
        self.owner.reads.clear()
        self.rollout_reads = 0
        with self.assertRaises(AdministrationDenied):
          self.read()
        self.assertEqual(self.rollout_reads, 0)
        self.assert_no_job_read()
    self.owner.account("reader", active=False)
    self.owner.reads.clear()
    with self.assertRaises(AdministrationDenied):
      self.read()
    self.assert_no_job_read()

  def test_unknown_actor_and_spoofed_role_cannot_skip_stored_identity(self):
    for actor in ({}, {"account_id": "unknown", "role": "admin"}):
      with self.subTest(actor=actor):
        self.owner.reads.clear()
        with self.assertRaises(AdministrationDenied):
          self.read(actor=actor)
        self.assert_no_job_read()
    with self.assertRaises(AdministrationDenied):
      self.read(actor={"account_id": "reader", "role": "admin"}, permission="audit:view")
    self.assert_no_job_read()

  def test_reused_service_observes_both_configured_and_stored_rollout_changes(self):
    stages = ("compatibility", "draining", "tenant")
    for configured, stored, enabled, stored_enabled in product(stages, stages, (False, True), (False, True)):
      with self.subTest(configured=configured, stored=stored, enabled=enabled, stored_enabled=stored_enabled):
        self.owner.stage, self.owner.enabled = configured, enabled
        self.tenants.put("execution_rollout", self.owner.cfg_instance_id,
                         record={"stage": stored, "enabled": stored_enabled})
        self.writes_before = list(self.owner.writes)
        self.owner.reads.clear()
        if configured == stored == "compatibility" and enabled is False and stored_enabled is False:
          self.assertIn("storage-alias", self.read())
        else:
          with self.assertRaises(AdministrationDenied):
            self.read()
          self.assert_no_job_read()

  def test_missing_or_invalid_rollout_is_unavailable_before_jobs(self):
    hkey, key = self.tenants._location("execution_rollout", (self.owner.cfg_instance_id,))
    saved = self.owner.data[(hkey, key)]
    for value in (None, {}, {**saved, "namespace": "foreign"}):
      with self.subTest(value=value):
        self.owner.data[(hkey, key)] = value
        self.owner.reads.clear()
        with self.assertRaises(TenantStoreError):
          self.read()
        self.assert_no_job_read()

  def test_rollout_reader_errors_and_invalid_results_are_sanitized(self):
    for value in (None, {}, "compatibility"):
      with self.subTest(value=value):
        self.access.read_rollout = lambda: value
        with self.assertRaises(TenantStoreError) as caught:
          self.read()
        self.assertEqual(str(caught.exception), "Legacy read controls are unavailable")
        self.assert_no_job_read()
    def failing_reader():
      raise RuntimeError("private control details")
    self.access.read_rollout = failing_reader
    with self.assertRaises(TenantStoreError) as caught:
      self.read()
    self.assertNotIn("private", str(caught.exception))
    self.assert_no_job_read()

  def test_reused_service_rechecks_account_after_success(self):
    self.assertIn("storage-alias", self.read())
    self.owner.account("reader", active=False)
    self.owner.reads.clear()
    with self.assertRaises(AdministrationDenied):
      self.read()
    self.assert_no_job_read()

  def test_audit_requires_stored_legacy_admin_not_an_ordinary_reader(self):
    with self.assertRaises(AdministrationDenied) as caught:
      self.read(permission="audit:view")
    self.assertEqual(caught.exception.status_code, 403)
    self.assert_no_job_read()
    self.assertIn("storage-alias", self.read(actor={"account_id": "creator"}, permission="audit:view"))
    for permission in ("tasks:launch", "arbitrary", None):
      with self.subTest(permission=permission), self.assertRaises(AdministrationDenied):
        self.read(actor={"account_id": "creator"}, permission=permission)

  def test_bound_null_and_non_dict_rows_are_not_normalized_or_returned(self):
    self.owner.jobs.update(bound={"job_id": "bound", "execution_binding": binding_payload()},
                           null_binding={"job_id": "null_binding", "execution_binding": None},
                           malformed_binding={"job_id": "malformed_binding", "execution_binding": {}},
                           tombstone=None, malformed=[])
    self.assertEqual(set(self.read()), {"storage-alias"})
    self.assertEqual(self.normalizations, [("storage-alias", False)])
    for job_id in ("bound", "null_binding", "malformed_binding", "tombstone", "malformed", "missing"):
      with self.subTest(job_id=job_id), self.assertRaises(AdministrationDenied) as caught:
        self.read("get", job_id=job_id)
      self.assertEqual(caught.exception.status_code, 404)

  def test_duplicate_logical_ids_and_bound_alias_collisions_are_order_independent(self):
    original = self.owner.jobs["storage-alias"]
    for conflicting in (deepcopy(original), {"job_id": "job-1", "execution_binding": None},
                        {"job_id": "job-1", "execution_binding": binding_payload()}):
      for reverse in (False, True):
        for operation in ("get", "list"):
          with self.subTest(conflicting=conflicting, reverse=reverse, operation=operation):
            rows = [("storage-alias", deepcopy(original)), ("other-key", deepcopy(conflicting))]
            self.owner.enumeration = dict(reversed(rows) if reverse else rows)
            with self.assertRaises(TenantStoreError):
              self.read(operation)
    self.owner.enumeration = {"storage-alias": deepcopy(original),
                              "job-1": {"execution_binding": None}}
    with self.assertRaises(TenantStoreError):
      self.read()

  def test_returned_values_are_detached_in_both_directions(self):
    result = self.read("get")
    result["extension"]["items"].append("returned")
    self.assertEqual(self.owner.jobs["storage-alias"]["extension"]["items"], ["preserved"])
    result = self.read("get")
    self.owner.jobs["storage-alias"]["extension"]["items"].append("stored")
    self.assertEqual(result["extension"]["items"], ["preserved"])

  def test_copy_time_binding_appearance_is_filtered_without_normalization(self):
    copying, changed = Event(), Event()
    failures = []
    def writer():
      try:
        if not copying.wait(2):
          raise AssertionError("Copy did not start")
        self.owner.jobs["storage-alias"]["execution_binding"] = None
      except Exception as error:
        failures.append(error)
      finally:
        changed.set()
    def copying_job(value):
      copying.set()
      if not changed.wait(2):
        raise AssertionError("Writer did not finish")
      return deepcopy(value)
    thread = Thread(target=writer)
    thread.start()
    try:
      with patch("extensions.business.cybersec.red_mesh.tenancy.read_access.deepcopy", side_effect=copying_job):
        self.assertEqual(self.read(), {})
    finally:
      thread.join(timeout=3)
    self.assertFalse(thread.is_alive())
    self.assertEqual(failures, [])
    self.assertEqual(self.normalizations, [])

  def test_enumeration_failure_or_invalid_top_level_never_becomes_empty_success(self):
    for value in (None, [], 1):
      with self.subTest(value=value):
        self.owner.enumeration = value
        with self.assertRaises(TenantStoreError):
          self.read()
    self.owner.enumeration = {}
    self.assertEqual(self.read(), {})
    self.owner.fail_hkey = self.owner.cfg_instance_id
    with self.assertRaises(TenantStoreError) as caught:
      self.read()
    self.assertNotIn("private", str(caught.exception))

  def test_enumeration_capture_errors_are_sanitized(self):
    class BrokenEnumeration(dict):
      def items(self):
        yield "storage-alias", {"job_id": "job-1"}
        raise RuntimeError("private concurrent enumeration failure")
    self.owner.enumeration = BrokenEnumeration()
    with self.assertRaises(TenantStoreError) as caught:
      self.read()
    self.assertEqual(str(caught.exception), "Legacy job storage is unavailable")
    self.assertEqual(self.normalizations, [])

  def test_post_capture_enumeration_changes_do_not_change_returned_rows(self):
    original = self.access.normalize
    def changing_normalizer(key, record, *, migrate):
      self.owner.jobs.clear()
      self.owner.jobs["new"] = {"job_id": "new", "workers": {}}
      return original(key, record, migrate=migrate)
    self.access.normalize = changing_normalizer
    self.assertEqual(set(self.read()), {"storage-alias"})
    self.assertEqual(set(self.owner.jobs), {"new"})
    self.assertEqual(self.owner.writes, self.writes_before)

  def test_normalization_errors_or_invalid_identity_fail_closed_without_writes(self):
    for output in (("changed", {"job_id": "job-1"}), ("storage-alias", None),
                   ("storage-alias", {"job_id": ""}),
                   ("storage-alias", {"job_id": "job-1", "execution_binding": None})):
      with self.subTest(output=output):
        self.access.normalize = lambda key, record, *, migrate: output
        with self.assertRaises(TenantStoreError):
          self.read()
        self.assertEqual(self.owner.writes, self.writes_before)
    def failing_normalizer(key, record, *, migrate):
      record["extension"]["items"].append("normalizer mutation")
      raise RuntimeError("private normalization details")
    self.access.normalize = failing_normalizer
    with self.assertRaises(TenantStoreError) as caught:
      self.read()
    self.assertNotIn("private", str(caught.exception))
    self.assertEqual(self.owner.jobs["storage-alias"]["extension"]["items"], ["preserved"])
    self.assertEqual(self.owner.writes, self.writes_before)
