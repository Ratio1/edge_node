"""Current tenant readers through real policy/adapters and synthetic external storage."""
import copy
from threading import Event, Thread
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.repositories.cstore import JobStateRepository
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied, TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from extensions.business.cybersec.red_mesh.tenancy.read_access import TenantReadAccess
from .test_execution_binding_models import binding_payload
from .test_tenant_administration import FakeAdministrationStore


class ReadStore(FakeAdministrationStore):
  """Job storage deliberately returns shared references, unlike the administration fixture."""

  cfg_instance_id = "shared-jobs"

  def __init__(self):
    super().__init__()
    self.jobs = {}
    self.reads = []
    self.fail_hkey = None
    self.enumeration = self.jobs

  def chainstore_hget(self, *, hkey, key):
    self.reads.append(("get", hkey, key))
    if hkey == self.fail_hkey:
      raise RuntimeError("private storage payload")
    if hkey == self.cfg_instance_id:
      return self.jobs.get(key)
    return super().chainstore_hget(hkey=hkey, key=key)

  def chainstore_hgetall(self, *, hkey):
    self.reads.append(("list", hkey))
    if hkey == self.fail_hkey:
      raise RuntimeError("private storage payload")
    if hkey == self.cfg_instance_id:
      return self.enumeration
    return super().chainstore_hgetall(hkey=hkey)


class TestTenantReadAccess(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.store = ReadStore()
    self.accounts = CstoreAuthAccountReader(self.store)
    self.tenants = CstoreTenantAdministrationStore(self.store, "deployment")
    self.administration = TenantAdministrationService(self.accounts, self.tenants)
    self.request_id = str(uuid4())
    prepared = self.administration.prepare_tenant(
      {"account_id": "creator"}, self.request_id, "Example", "example", "initial")
    self.assertTrue(prepared["success"], prepared)
    self.tenant_id = prepared["data"]["tenantId"]
    self.store.grant("initial", self.tenant_id)
    activated = self.administration.activate_tenant({"account_id": "creator"}, self.request_id)
    self.assertTrue(activated["success"], activated)
    self.store.account("reader", memberships=[{"role": "tenant_user", "tenant_id": self.tenant_id}])
    self.actor = {"account_id": "reader"}
    self.binding = {**binding_payload(), "tenant_id": self.tenant_id}
    self.record = {"job_id": "job-1", "execution_binding": self.binding,
                   "job_status": "FINALIZED", "job_cid": "archive-ref",
                   "unknown_extension": {"items": ["preserved"]}}
    self.store.jobs["job-1"] = self.record
    self.access = TenantReadAccess(self.administration, JobStateRepository(self.store))
    self.store.reads.clear()
    self.writes_before = list(self.store.writes)

  def read(self, operation, *, actor=None, tenant_id=None, job_id="job-1"):
    actor = self.actor if actor is None else actor
    tenant_id = self.tenant_id if tenant_id is None else tenant_id
    if operation == "get":
      return self.access.get_job(actor, tenant_id, job_id)
    return self.access.list_jobs(actor, tenant_id)

  def assert_no_job_read(self):
    self.assertFalse(any(event[1] == self.store.cfg_instance_id for event in self.store.reads))
    self.assertEqual(self.store.writes, self.writes_before)

  def test_current_reader_authorizes_published_tenant_before_point_read_or_enumeration(self):
    for operation in ("get", "list"):
      with self.subTest(operation=operation):
        self.store.reads.clear()
        result = self.read(operation, actor={"account_id": " READER "})
        self.assertEqual(result, self.record if operation == "get" else {"job-1": self.record})
        self.assertEqual(self.store.reads[0], ("get", "auth", "reader"))
        self.assertEqual(sum(event == ("get", "auth", "reader") for event in self.store.reads), 1)
        for kind, ids in (("tenant", (self.tenant_id,)), ("receipt", ("creator", self.request_id)),
                          ("domain", ("example",))):
          hkey, key = self.tenants._location(kind, ids)
          self.assertIn(("get", hkey, key), self.store.reads[:-1])
        self.assertEqual(self.store.reads[-1], ("get", self.store.cfg_instance_id, "job-1")
                         if operation == "get" else ("list", self.store.cfg_instance_id))
        self.assertEqual(self.store.writes, self.writes_before)

  def test_audit_uses_named_permission_and_unknown_operations_never_read_jobs(self):
    for method in (lambda **kwargs: self.access.get_job(self.actor, self.tenant_id, "job-1", **kwargs),
                   lambda **kwargs: self.access.list_jobs(self.actor, self.tenant_id, **kwargs)):
      for operation in ("audit:view", "tasks:launch", None):
        self.store.reads.clear()
        with self.assertRaises(AdministrationDenied) as caught:
          method(operation=operation)
        self.assertEqual(caught.exception.status_code, 403)
        self.assert_no_job_read()
    self.store.account("reader", memberships=[{"role": "tenant_admin", "tenant_id": self.tenant_id}])
    self.assertEqual(self.access.get_job(self.actor, self.tenant_id, "job-1", operation="audit:view"), self.record)
    self.assertEqual(self.access.list_jobs(self.actor, self.tenant_id, operation="audit:view"), {"job-1": self.record})

  def test_all_saved_task_targets_are_read_without_launch_authority(self):
    targets = [{"kind": "network", "address": "192.0.2.10"},
               {"kind": "webapp", "url": "https://example.com/api", "allowedPathPrefix": "/api"},
               {"kind": "model", "adapter": "openai_compatible",
                "endpointUrl": "https://example.com/v1/chat/completions", "model": "Model"}]
    for target in targets:
      with self.subTest(kind=target["kind"]):
        self.binding.update(asset_target=target, asset_target_digest=canonical_digest(target))
        self.assertEqual(self.read("get"), self.record)
        self.assertEqual(self.read("list"), {"job-1": self.record})
    self.assertFalse(self.tenants.get("tenant", self.tenant_id)["allow_pentester"])
    self.assertIsNone(self.accounts.get_account(self.binding["actor_id"]))
    self.assertFalse(any('"asset"' in str(event) or '"tenant_node"' in str(event) for event in self.store.reads))
    self.assertEqual(self.store.writes, self.writes_before)

  def test_reader_is_independent_of_original_launcher_state_and_current_compute_assignments(self):
    self.store.account(self.binding["actor_id"], active=False, memberships=[])
    for role in ("tenant_user", "tenant_admin", "tenant_pentester", "super_pentester", "super_tenant_admin"):
      with self.subTest(role=role):
        scope = None if role == "super_tenant_admin" else self.tenant_id
        self.store.account("reader", memberships=[{"role": role, "tenant_id": scope}])
        self.assertEqual(self.read("get"), self.record)
        self.assertEqual(self.read("list"), {"job-1": self.record})
    self.assertEqual(self.store.writes, self.writes_before)

  def test_each_operation_rechecks_revoked_reader_even_if_launcher_remains_authorized(self):
    self.store.account(self.binding["actor_id"], memberships=[{"role": "tenant_admin", "tenant_id": self.tenant_id}])
    for operation in ("get", "list"):
      for changes in ({"memberships": []}, {"memberships": [], "active": False},
                      {"memberships": [{"role": "tenant_user", "tenant_id": "foreign"}]}):
        with self.subTest(operation=operation, changes=changes):
          self.store.account("reader", memberships=[{"role": "tenant_user", "tenant_id": self.tenant_id}])
          self.read(operation)
          self.store.account("reader", **changes)
          self.store.reads.clear()
          with self.assertRaises(AdministrationDenied) as raised:
            self.read(operation, actor={**self.actor, "role": "super_tenant_admin", "tenant_id": self.tenant_id})
          self.assertEqual((raised.exception.status_code, raised.exception.error), (404, "not_found"))
          self.assert_no_job_read()

  def test_malformed_actor_or_stored_principal_never_reaches_jobs(self):
    resolved = self.accounts.get_account("reader")
    for operation in ("get", "list"):
      for actor in ({}, {"account_id": "missing"}, {"account_id": []}, {"account_id": "bad id"},
                    "reader", resolved, self.record):
        with self.subTest(operation=operation, actor=actor):
          self.store.reads.clear()
          with self.assertRaises(AdministrationDenied) as raised:
            self.read(operation, actor=actor)
          self.assertEqual(raised.exception.status_code, 404)
          self.assert_no_job_read()
      for memberships in (None, {}, [{"role": "tenant_user", "tenant_id": None}], [{"role": "owner", "tenant_id": self.tenant_id}]):
        with self.subTest(operation=operation, memberships=memberships):
          self.store.data[("auth", "reader")]["metadata"]["tenant_memberships"] = memberships
          self.store.reads.clear()
          with self.assertRaises(AdministrationDenied) as raised:
            self.read(operation)
          self.assertEqual(raised.exception.status_code, 404)
          self.assert_no_job_read()
      self.store.account("reader", memberships=[{"role": "tenant_user", "tenant_id": self.tenant_id}])

  def test_identity_unavailable_is_sanitized_before_job_reads(self):
    self.store.fail_hkey = "auth"
    for operation in ("get", "list"):
      with self.subTest(operation=operation):
        self.store.reads.clear()
        with self.assertRaises(AdministrationDenied) as raised:
          self.read(operation)
        self.assertEqual((raised.exception.status_code, raised.exception.error), (503, "unavailable"))
        self.assertNotIn("private", str(raised.exception))
        self.assert_no_job_read()

  def test_unknown_foreign_and_unpublished_tenants_deny_before_jobs(self):
    self.store.account("initial-pending")
    pending = self.administration.prepare_tenant({"account_id": "creator"}, str(uuid4()), "Pending", "pending",
                                                 "initial-pending")
    pending_id = pending["data"]["tenantId"]
    self.writes_before = list(self.store.writes)
    for operation in ("get", "list"):
      for tenant_id in ("foreign", "missing", pending_id, "", []):
        with self.subTest(operation=operation, tenant_id=tenant_id):
          # RM-083: one tenant per account, so the reader is made a member of the tenant it probes.
          if tenant_id in ("missing", pending_id):
            self.store.account("reader", memberships=[{"role": "tenant_user", "tenant_id": tenant_id}])
          self.store.reads.clear()
          with self.assertRaises(AdministrationDenied) as raised:
            self.read(operation, tenant_id=tenant_id)
          self.assertEqual((raised.exception.status_code, raised.exception.error), (404, "not_found"))
          self.assert_no_job_read()

  def test_corrupt_publication_and_tenant_storage_failures_precede_job_reads(self):
    domain_key = self.tenants._location("domain", ("example",))
    del self.store.data[domain_key]
    for operation in ("get", "list"):
      with self.subTest(operation=operation):
        self.store.reads.clear()
        with self.assertRaises(TenantStoreError) as raised:
          self.read(operation)
        self.assertNotIn("private", str(raised.exception))
        self.assert_no_job_read()
    self.store.fail_hkey = domain_key[0]
    for operation in ("get", "list"):
      self.store.reads.clear()
      with self.assertRaises(TenantStoreError):
        self.read(operation)
      self.assert_no_job_read()

  def test_missing_unattributed_and_foreign_rows_share_not_found_or_omission(self):
    values = [None, {}, [], "private malformed row", {"job_id": "job-1"}]
    values += [{"job_id": "job-1", "execution_binding": binding} for binding in (
      None, {}, [], "private binding", {"namespace": "deployment"},
      {**self.binding, "namespace": "foreign", "schema_version": "corrupt"},
      {**self.binding, "tenant_id": "tn_" + str(uuid4()), "schema_version": "corrupt"})]
    for value in values:
      with self.subTest(value=value):
        self.store.jobs["job-1"] = value
        with self.assertRaises(AdministrationDenied) as raised:
          self.read("get")
        self.assertEqual((raised.exception.status_code, raised.exception.error), (404, "not_found"))
        self.assertEqual(self.read("list"), {})
    with self.assertRaises(AdministrationDenied) as raised:
      self.read("get", job_id="absent")
    self.assertEqual((raised.exception.status_code, raised.exception.error), (404, "not_found"))

  def test_local_binding_corruption_fails_closed_for_point_and_list(self):
    values = [{"namespace": "deployment", "tenant_id": self.tenant_id}]
    values += [{**self.binding, field: value} for field, value in (
      ("schema_version", True), ("asset_target_digest", "0" * 64), ("participant_order", []),
      ("actor_id", " SPOOF "), ("asset_id", "invalid"), ("extra", "private value"))]
    for value in values:
      for operation in ("get", "list"):
        with self.subTest(operation=operation, binding=value):
          self.store.jobs["job-1"] = {**self.record, "execution_binding": value}
          with self.assertRaises(TenantStoreError) as raised:
            self.read(operation)
          self.assertNotIn("private", str(raised.exception))

  def test_repository_key_must_match_local_stored_job_id(self):
    for value in (None, "different-job", [], 1):
      for operation in ("get", "list"):
        with self.subTest(operation=operation, job_id=value):
          self.store.jobs["job-1"] = {**self.record, "job_id": value}
          with self.assertRaises(TenantStoreError):
            self.read(operation)

  def test_foreign_corruption_does_not_poison_matching_list(self):
    self.store.jobs.update({"foreign-tenant": {"execution_binding": {"namespace": "deployment", "tenant_id": "foreign"}},
                            "foreign-namespace": {"execution_binding": {"namespace": "other", "tenant_id": self.tenant_id}},
                            "unattributed": {"private": "not a tenant row"}})
    self.assertEqual(self.read("list"), {"job-1": self.record})

  def test_surfaced_repository_errors_are_sanitized(self):
    self.store.fail_hkey = self.store.cfg_instance_id
    for operation in ("get", "list"):
      with self.subTest(operation=operation):
        with self.assertRaises(TenantStoreError) as raised:
          self.read(operation)
        self.assertNotIn("private", str(raised.exception))
        self.assertIsNone(raised.exception.__cause__)
        self.assertTrue(raised.exception.__suppress_context__)

  def test_malformed_enumeration_is_unavailable_not_empty_success(self):
    for enumeration in (None, [], (), "private", 0, False):
      with self.subTest(enumeration=enumeration):
        self.store.enumeration = enumeration
        with self.assertRaises(TenantStoreError) as raised:
          self.read("list")
        self.assertNotIn("private", str(raised.exception))

  def test_empty_valid_enumeration_is_a_successful_empty_list(self):
    self.store.jobs.clear()
    self.assertEqual(self.read("list"), {})

  def test_enumeration_capture_failure_is_sanitized(self):
    class UnavailableEnumeration(dict):
      def items(self):
        raise RuntimeError("private enumeration failure")

    self.store.enumeration = UnavailableEnumeration(self.store.jobs)
    with self.assertRaises(TenantStoreError) as raised:
      self.read("list")
    self.assertNotIn("private", str(raised.exception))
    self.assertIsNone(raised.exception.__cause__)
    self.assertTrue(raised.exception.__suppress_context__)

  def test_get_and_list_snapshots_are_detached_in_both_directions(self):
    original = copy.deepcopy(self.record)
    for operation in ("get", "list"):
      with self.subTest(operation=operation):
        self.store.jobs["job-1"] = copy.deepcopy(original)
        result = self.read(operation)
        returned = result if operation == "get" else result["job-1"]
        returned["execution_binding"]["participant_order"].append("injected")
        returned["unknown_extension"]["items"].clear()
        self.assertEqual(self.store.jobs["job-1"], original)
        snapshot = self.read(operation)
        self.store.jobs["job-1"]["execution_binding"]["participant_order"].clear()
        self.store.jobs["job-1"]["unknown_extension"]["items"].append("later mutation")
        self.assertEqual(snapshot, original if operation == "get" else {"job-1": original})
    self.assertEqual(self.store.writes, self.writes_before)

  def test_concurrent_copy_validates_the_returned_snapshot_not_the_borrowed_record(self):
    original = copy.deepcopy(self.record)
    for operation in ("get", "list"):
      for field, value, foreign in (("tenant_id", "tn_" + str(uuid4()), True),
                                    ("namespace", "other-deployment", True),
                                    ("asset_target_digest", "0" * 64, False),
                                    ("job_id", "different-job", False)):
        with self.subTest(operation=operation, field=field):
          self.store.jobs["job-1"] = copy.deepcopy(original)
          copying, changed = Event(), Event()
          failures = []

          def writer():
            try:
              if not copying.wait(timeout=3):
                raise AssertionError("Snapshot copy did not begin")
              stored = self.store.jobs["job-1"]
              if field == "job_id":
                stored[field] = value
              else:
                stored["execution_binding"][field] = value
            except Exception as error:
              failures.append(error)
            finally:
              changed.set()

          def copy_after_change(record):
            copying.set()
            if not changed.wait(timeout=3):
              raise AssertionError("Concurrent mutation did not complete")
            return copy.deepcopy(record)

          thread = Thread(target=writer, daemon=True)
          thread.start()
          try:
            with patch("extensions.business.cybersec.red_mesh.tenancy.read_access.deepcopy",
                       side_effect=copy_after_change):
              if not foreign:
                with self.assertRaises(TenantStoreError):
                  self.read(operation)
              elif operation == "get":
                with self.assertRaises(AdministrationDenied) as raised:
                  self.read(operation)
                self.assertEqual((raised.exception.status_code, raised.exception.error), (404, "not_found"))
              else:
                self.assertEqual(self.read(operation), {})
          finally:
            copying.set()
            thread.join(timeout=3)
          self.assertFalse(thread.is_alive())
          self.assertTrue(changed.is_set())
          self.assertEqual(failures, [])

  def test_two_serving_nodes_share_authorized_view_and_independently_reauthorize(self):
    other = ReadStore()
    other.data = self.store.data
    other.jobs = self.store.jobs
    other.enumeration = other.jobs
    other.ee_addr = "unassigned-serving-node"
    administration = TenantAdministrationService(CstoreAuthAccountReader(other),
                                                 CstoreTenantAdministrationStore(other, "deployment"))
    access = TenantReadAccess(administration, JobStateRepository(other))
    self.assertEqual(access.get_job(self.actor, self.tenant_id, "job-1"), self.read("get"))
    self.assertEqual(access.list_jobs(self.actor, self.tenant_id), self.read("list"))
    self.store.account("reader", memberships=[])
    other.reads.clear()
    for call in (lambda: access.get_job(self.actor, self.tenant_id, "job-1"),
                 lambda: access.list_jobs(self.actor, self.tenant_id)):
      with self.assertRaises(AdministrationDenied):
        call()
    self.assertFalse(any(event[1] == other.cfg_instance_id for event in other.reads))

  def test_concurrent_enumeration_addition_and_removal_do_not_escape_or_leak(self):
    original = copy.deepcopy(self.record)
    expected = {"job-1": original, "job-2": {**copy.deepcopy(original), "job_id": "job-2"}}
    for mutation in ("addition", "removal"):
      with self.subTest(mutation=mutation):
        self.store.jobs.clear()
        self.store.jobs.update(copy.deepcopy(expected))
        copying, changed = Event(), Event()
        failures = []

        def writer():
          try:
            if not copying.wait(timeout=3):
              raise AssertionError("Snapshot copy did not begin")
            if mutation == "addition":
              self.store.jobs["foreign-new"] = {
                "job_id": "foreign-new",
                "execution_binding": {"namespace": "deployment", "tenant_id": "foreign"},
                "private": "foreign content",
              }
            else:
              del self.store.jobs["job-2"]
          except Exception as error:
            failures.append(error)
          finally:
            changed.set()

        def copy_after_change(record):
          copying.set()
          if not changed.wait(timeout=3):
            raise AssertionError("Concurrent mutation did not complete")
          return copy.deepcopy(record)

        thread = Thread(target=writer, daemon=True)
        thread.start()
        try:
          with patch("extensions.business.cybersec.red_mesh.tenancy.read_access.deepcopy",
                     side_effect=copy_after_change):
            self.assertEqual(self.read("list"), expected)
        finally:
          copying.set()
          thread.join(timeout=3)
        self.assertFalse(thread.is_alive())
        self.assertTrue(changed.is_set())
        self.assertEqual(failures, [])
        self.assertEqual(self.store.writes, self.writes_before)
