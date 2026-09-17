"""RM-026 I1b B9: admission for the three destructive controls.

`purge_job`, `stop_and_delete_job` and `purge_all_redmesh_data` delete R1FS artifacts and tombstone
CStore records. Two of the three shipped as GET, all three took no requester, and
`purge_all_redmesh_data` was gated only by a `confirm=true` boolean in the request body -- which
proves intent, not authority.

The owner's decision (2026-09-14) is **Super-Tenant Admins only, for now**. That is a tenant-scoped
role, so unlike every earlier slice in this series these endpoints do NOT admit the legacy half:
a legacy account, however privileged, is refused. RM-078 is what made the granted half expressible;
before it, `jobs:purge` could not be held by anyone.

The scoping consequence is the safety property worth stating: `purge_all_redmesh_data` admitted
through the tenant seam enumerates *that tenant's* jobs, not every job on the node.
"""
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import uuid4

SECRET = "mock-only-b9-canary"


class PurgeAdmissionCase(unittest.TestCase):
  def setUp(self):
    from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
    from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import (
      CstoreTenantAdministrationStore)
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import (
      CstoreAuthAccountReader)
    from .test_api import TestPhase1ConfigCID
    from .test_execution_binding_models import binding_payload
    from .test_tenant_read_access import ReadStore

    TestPhase1ConfigCID._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.Plugin = PentesterApi01Plugin
    self.store = ReadStore()
    self.tenants = CstoreTenantAdministrationStore(self.store, "deployment")
    administration = TenantAdministrationService(CstoreAuthAccountReader(self.store), self.tenants)
    request_id = str(uuid4())
    prepared = administration.prepare_tenant(
      {"account_id": "creator"}, request_id, "Example", "example", "initial")
    self.tenant_id = prepared["data"]["tenantId"]
    self.store.grant("initial", self.tenant_id)
    administration.activate_tenant({"account_id": "creator"}, request_id)
    self.store.jobs["job-1"] = {
      "job_id": "job-1", "job_status": "FINALIZED", "job_cid": "archive-ref",
      "execution_binding": {**binding_payload(), "tenant_id": self.tenant_id}}
    self.actor = {"account_id": "reader"}
    self.owner = SimpleNamespace(
      cfg_instance_id=self.store.cfg_instance_id, cfg_tenancy_namespace="deployment",
      cfg_tenant_execution_enabled=False, cfg_tenant_execution_stage="compatibility",
      chainstore_hget=self.store.chainstore_hget, chainstore_hgetall=self.store.chainstore_hgetall,
      chainstore_hset=self.store.chainstore_hset, P=lambda *a, **k: None)
    self.owner._normalize_job_record = (
      lambda key, record, **kwargs: PentesterApi01Plugin._normalize_job_record(
        self.owner, key, record, **kwargs))

  def as_role(self, role):
    scope = None if role == "super_tenant_admin" else self.tenant_id  # RM-083: STA is full-portfolio
    self.store.account("reader", memberships=[{"role": role, "tenant_id": scope}])

  def as_legacy_admin(self):
    self.store.account("reader", role="admin")

  def no_purge(self):
    """Canaries bound in the plugin's own namespace, where the endpoints read them.

    `patch.multiple` as a context manager yields {} when every target is given explicitly, so the
    mocks are built here and handed back by name -- an earlier version asserted on the yielded
    mapping and would have raised KeyError rather than checked anything.
    """
    import contextlib
    import sys
    module = sys.modules[self.Plugin.__module__]
    for name in ("purge_job", "stop_and_delete_job", "purge_all_jobs"):
      assert hasattr(module, name), "the plugin no longer imports %s; the canary is vacuous" % name
    canaries = {name: Mock(side_effect=RuntimeError(SECRET))
                for name in ("purge_job", "stop_and_delete_job", "purge_all_jobs")}

    @contextlib.contextmanager
    def _patched():
      with patch.multiple(module, **canaries):
        yield canaries

    return _patched()

  def call(self, name):
    if name == "purge_all_redmesh_data":
      return self.Plugin.purge_all_redmesh_data(
        self.owner, confirm=True, request_actor=self.actor, tenant_id=self.tenant_id)
    return getattr(self.Plugin, name)(
      self.owner, "job-1", request_actor=self.actor, tenant_id=self.tenant_id)


NAMES = ("purge_job", "stop_and_delete_job", "purge_all_redmesh_data")


class TestPurgeAdmission(PurgeAdmissionCase):
  def test_a_super_tenant_admin_reaches_the_purge(self):
    self.as_role("super_tenant_admin")
    for name in NAMES:
      with self.subTest(name=name):
        with self.no_purge():
          result = self.call(name)
        # Admission passed, so the canary raised inside the effect.
        self.assertNotEqual(result.get("status_code"), 403, result)
        self.assertNotIn(SECRET, repr(result))

  def test_every_other_tenant_role_is_refused(self):
    for role in ("super_pentester", "tenant_admin", "tenant_pentester", "tenant_user"):
      for name in NAMES:
        with self.subTest(role=role, name=name):
          self.as_role(role)
          with self.no_purge() as canaries:
            result = self.call(name)
          self.assertEqual(result.get("status_code"), 403, result)
          for canary in canaries.values():
            canary.assert_not_called()

  def test_a_legacy_admin_is_a_platform_super_tenant_admin_and_is_admitted(self):
    """`cstore_identity._parse_memberships:118` maps an account with `role == "admin"` and no
    explicit memberships key to `TenantMembership("super_tenant_admin", None)` -- a platform-scoped
    Super-Tenant Admin, which `resolve_tenant_roles` matches for every tenant.

    So under this identity model a legacy admin *is* a Super-Tenant Admin, and the owner's
    "Super-Tenant Admins only" admits them. This is asserted rather than assumed because the
    opposite was stated to the owner earlier in this task and was wrong: the deferral that blocked
    B9 was about tenant-scoped *effect authority* not being expressible, not about legacy admins
    being a different role.
    """
    self.as_legacy_admin()
    for name in NAMES:
      with self.subTest(name=name):
        with self.no_purge():
          result = self.call(name)
        self.assertNotEqual(result.get("status_code"), 403, result)
        self.assertNotIn(SECRET, repr(result))

  def test_a_legacy_non_admin_is_refused(self):
    """The fallback is keyed to `role == "admin"` exactly; nothing else inherits platform scope."""
    for role in ("user", "pentester", "viewer"):
      with self.subTest(role=role):
        self.store.account("reader", role=role)
        with self.no_purge() as canaries:
          result = self.call("purge_job")
        self.assertEqual(result.get("success"), False, result)
        self.assertIn(result.get("status_code"), (403, 404), result)
        for canary in canaries.values():
          canary.assert_not_called()

  def test_an_omitted_tenant_is_refused_without_consulting_the_store(self):
    """A null tenant_id routes to LegacyReadAccess everywhere else in this series. That seam happens
    to refuse `jobs:purge` today, so this guard is belt-and-braces -- which is exactly why the
    assertion has to be about what the guard *uniquely* does, or it passes with the guard deleted.

    What it uniquely does is refuse before any store access: the decision does not depend on
    LegacyReadAccess's operation allowlist staying closed in a later change.
    """
    self.as_legacy_admin()  # the account the legacy seam would otherwise resolve
    for name in NAMES:
      with self.subTest(name=name):
        self.store.reads.clear()
        with self.no_purge() as canaries:
          if name == "purge_all_redmesh_data":
            result = self.Plugin.purge_all_redmesh_data(
              self.owner, confirm=True, request_actor=self.actor)
          else:
            result = getattr(self.Plugin, name)(self.owner, "job-1", request_actor=self.actor)
        self.assertEqual(result, {"success": False, "error": "forbidden", "status_code": 403},
                         result)
        self.assertEqual(list(self.store.reads), [],
                         "the refusal consulted the store before deciding: %r" % (self.store.reads,))
        for canary in canaries.values():
          canary.assert_not_called()

  def test_confirmation_is_still_required_and_is_not_authority(self):
    self.as_role("super_tenant_admin")
    with self.no_purge() as canaries:
      result = self.Plugin.purge_all_redmesh_data(
        self.owner, confirm=False, request_actor=self.actor, tenant_id=self.tenant_id)
    self.assertEqual(result.get("status"), "error", result)
    canaries["purge_all_jobs"].assert_not_called()

  def test_an_unadmitted_caller_cannot_use_confirmation_as_a_probe(self):
    """A denial must not reveal whether confirmation would have been accepted."""
    self.as_role("tenant_user")
    with self.no_purge() as canaries:
      result = self.Plugin.purge_all_redmesh_data(
        self.owner, confirm=False, request_actor=self.actor, tenant_id=self.tenant_id)
    self.assertEqual(result.get("status_code"), 403, result)
    canaries["purge_all_jobs"].assert_not_called()


class TestPurgeScope(PurgeAdmissionCase):
  def test_purge_all_enumerates_only_the_admitted_tenant(self):
    """The safety property the tenant seam buys: a Super-Tenant Admin purging "everything" purges
    their own tenant's jobs, not every job on the node."""
    import sys
    from .test_execution_binding_models import binding_payload
    self.as_role("super_tenant_admin")
    self.store.jobs["foreign-job"] = {
      "job_id": "foreign-job", "job_status": "FINALIZED",
      "execution_binding": {**binding_payload(), "tenant_id": "tn_someone_else"}}
    module = sys.modules[self.Plugin.__module__]
    seen = {}
    with patch.object(module, "purge_all_jobs",
                      Mock(side_effect=lambda _owner, **kwargs: seen.update(kwargs) or {"ok": True})):
      self.Plugin.purge_all_redmesh_data(
        self.owner, confirm=True, request_actor=self.actor, tenant_id=self.tenant_id)
    self.assertIn("checked_jobs", seen, seen)
    self.assertEqual(set(seen["checked_jobs"]), {"job-1"},
                     "purge_all reached a job outside the admitted tenant: %r" % (seen,))




class TestPerItemOutcomes(unittest.TestCase):
  """B9 step 2, from the owner's decision (2026-09-14): a mixed batch reports the partial rather
  than denying wholly, and the per-item outcome must be explicit and attributable, never an
  aggregate count.

  What shipped reported `jobs_succeeded` / `jobs_failed` counters plus an `errors` list. Failures
  were attributable; successes were not -- a purged job's id appeared nowhere, so an operator
  reading a partial result could not tell *which* jobs were gone. After an irreversible delete that
  is the only question that matters.
  """

  def setUp(self):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.services import control
    self.control = control

  def _owner(self, jobs):
    from unittest.mock import MagicMock
    owner = MagicMock()
    owner.cfg_instance_id = "test-instance"
    owner.ee_addr = "node-a"
    owner.P = lambda *a, **k: None
    owner._log_audit_event = lambda *a, **k: None
    owner.chainstore_hgetall.side_effect = lambda *, hkey: {}
    owner._normalize_job_record.side_effect = lambda key, record, **kw: (key, record)
    return owner

  def _run(self, jobs, purge_results):
    owner = self._owner(jobs)
    calls = []

    def _purge(_owner, job_id, **_kwargs):
      calls.append(job_id)
      return purge_results[job_id]

    with patch.object(self.control, "purge_job", _purge), \
         patch.object(self.control, "stop_and_delete_job", _purge):
      return self.control.purge_all_jobs(owner, checked_jobs=jobs), calls

  def test_every_job_appears_in_the_outcomes_with_its_own_verdict(self):
    jobs = {
      "gone": {"job_id": "gone", "job_status": "FINALIZED", "launcher": "node-a"},
      "kept": {"job_id": "kept", "job_status": "FINALIZED", "launcher": "node-a"},
    }
    result, _calls = self._run(jobs, {
      "gone": {"status": "success", "cids_deleted": 3, "cids_failed": 0},
      "kept": {"status": "partial", "cids_deleted": 1, "cids_failed": 2,
               "message": "r1fs delete failed"},
    })
    outcomes = {row["job_id"]: row for row in result["outcomes"]}
    self.assertEqual(set(outcomes), {"gone", "kept"}, result)
    self.assertEqual(outcomes["gone"]["outcome"], "purged")
    self.assertEqual(outcomes["gone"]["cids_deleted"], 3)
    self.assertEqual(outcomes["kept"]["outcome"], "retained")
    self.assertEqual(outcomes["kept"]["cids_failed"], 2)
    self.assertIn("r1fs delete failed", outcomes["kept"]["message"])
    self.assertEqual(result["status"], "partial")

  def test_a_force_purged_job_is_named_as_such_rather_than_counted(self):
    """Force-purge tombstones a record the current schema cannot parse, with best-effort artifact
    cleanup. An operator must be able to tell those apart from clean purges by id."""
    jobs = {"legacy": {"job_id": "legacy", "job_status": "FINALIZED", "launcher": "node-a"}}
    result, _calls = self._run(jobs, {"legacy": {"status": "unexpected"}})
    outcomes = {row["job_id"]: row for row in result["outcomes"]}
    self.assertEqual(outcomes["legacy"]["outcome"], "force_purged", result)

  def test_a_foreign_launcher_job_is_reported_as_refused_and_never_touched(self):
    jobs = {"theirs": {"job_id": "theirs", "job_status": "FINALIZED", "launcher": "node-b"}}
    result, calls = self._run(jobs, {})
    outcomes = {row["job_id"]: row for row in result["outcomes"]}
    self.assertEqual(outcomes["theirs"]["outcome"], "refused", result)
    self.assertEqual(calls, [], "a foreign-launcher job was purged")

  def test_the_outcomes_account_for_every_job_and_agree_with_the_counters(self):
    """The counters stay for compatibility, so they must not be able to drift from the list."""
    jobs = {name: {"job_id": name, "job_status": "FINALIZED", "launcher": "node-a"}
            for name in ("a", "b", "c")}
    result, _calls = self._run(jobs, {
      "a": {"status": "success", "cids_deleted": 1},
      "b": {"status": "partial", "cids_failed": 1, "message": "kept"},
      "c": {"status": "success", "cids_deleted": 2},
    })
    self.assertEqual(len(result["outcomes"]), result["jobs_total"])
    purged = [row for row in result["outcomes"] if row["outcome"] == "purged"]
    self.assertEqual(len(purged), result["jobs_succeeded"])


class TestSweepsStayInsideTheAdmittedTenant(unittest.TestCase):
  """The per-job loop was scoped by `checked_jobs`; the sweeps after it were not.

  Every sweep exempted only `failed_job_ids`, which can only contain ids from the *admitted*
  enumeration. Another tenant's rows are never enumerated, therefore never marked failed, therefore
  always deleted -- including its job records and its R1FS submission artifacts, reported as
  `status: "success"` with the victims absent from `outcomes`. Found by review, reproduced against
  the real function, and pinned here.
  """

  def setUp(self):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.services import control
    self.control = control

  def _run(self, checked_jobs):
    from unittest.mock import MagicMock
    self.tombstoned = []
    hashes = {
      "test-instance": {"job-a": {"job_id": "job-a"}, "job-b": {"job_id": "job-b"}},
      "test-instance:live": {"job-b:w1": {"job_id": "job-b"}, "job-a:w1": {"job_id": "job-a"}},
      "test-instance:triage": {"job-b:f1": {"job_id": "job-b"}},
      "test-instance:triage:audit": {"job-b:f1": [{"job_id": "job-b"}]},
    }
    owner = MagicMock()
    owner.cfg_instance_id = "test-instance"
    owner.ee_addr = "node-a"
    owner.P = lambda *a, **k: None
    owner._log_audit_event = lambda *a, **k: None
    owner.chainstore_hgetall.side_effect = lambda *, hkey: hashes.get(hkey, {})

    def _hset(*, hkey, key, value, **_kw):
      if value is None:
        self.tombstoned.append((hkey, key))

    owner.chainstore_hset.side_effect = _hset
    owner._normalize_job_record.side_effect = lambda k, r, **kw: (k, r)
    admitted = {"job-a": {"job_id": "job-a", "job_status": "FINALIZED", "launcher": "node-a"}}
    with patch.object(self.control, "purge_job",
                      Mock(return_value={"status": "success", "cids_deleted": 1})), \
         patch.object(self.control, "stop_and_delete_job",
                      Mock(return_value={"status": "success"})):
      return self.control.purge_all_jobs(
        owner, checked_jobs=admitted if checked_jobs else None)

  def test_another_tenants_rows_are_never_swept(self):
    self._run(checked_jobs=True)
    stray = [row for row in self.tombstoned if "job-b" in str(row)]
    self.assertEqual(stray, [], "a tenant-scoped purge deleted another tenant's rows: %r" % (stray,))

  def test_the_admitted_tenants_own_rows_are_still_swept(self):
    """The scoping must not turn the sweep into a no-op -- that would pass the test above for the
    wrong reason."""
    self._run(checked_jobs=True)
    self.assertIn(("test-instance:live", "job-a:w1"), self.tombstoned, self.tombstoned)
    self.assertIn(("test-instance", "job-a"), self.tombstoned, self.tombstoned)

  def test_an_internal_whole_node_purge_still_sweeps_everything(self):
    """`checked_jobs=None` is the legacy internal path and keeps its whole-node behaviour."""
    self._run(checked_jobs=False)
    self.assertTrue([row for row in self.tombstoned if "job-b" in str(row)],
                    "the whole-node purge stopped sweeping: %r" % (self.tombstoned,))


class TestTheLedgerIsLiveOnThePurgePath(unittest.TestCase):
  """The three destructive services accepted a `ledger` and never used it, while the docstring
  claimed it marked the point past which deletion is irreversible. Two consequences the ledger
  exists to prevent: a raise after R1FS deletion reported `unavailable` 503 -- "nothing happened"
  with artifacts already gone -- and contract 4's re-admission before the irreversible step never
  ran on the most destructive path in the system."""

  def setUp(self):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.services import control
    from extensions.business.cybersec.red_mesh.tenancy.effects import EffectLedger, EffectState
    self.control = control
    self.EffectLedger = EffectLedger
    self.EffectState = EffectState

  def _owner(self, delete_ok=True):
    from unittest.mock import MagicMock
    owner = MagicMock()
    owner.cfg_instance_id = "test-instance"
    owner.ee_addr = "node-a"
    owner.P = lambda *a, **k: None
    owner._log_audit_event = lambda *a, **k: None
    owner.chainstore_hgetall.side_effect = lambda *, hkey: {}
    owner._normalize_job_record.side_effect = lambda k, r, **kw: (k, r)
    owner.r1fs.delete_file.return_value = delete_ok
    return owner

  def _job(self):
    return {"job_id": "job-1", "job_status": "FINALIZED", "launcher": "node-a",
            "job_cid": "cid-archive", "workers": {}}

  def test_the_requester_is_revalidated_before_the_first_deletion(self):
    checkpoints = []
    ledger = self.EffectLedger(on_checkpoint=lambda: checkpoints.append(1))
    self.control.purge_job(self._owner(), "job-1", checked_job=self._job(), ledger=ledger)
    self.assertEqual(len(checkpoints), 1, "no re-admission ran before the irreversible delete")

  def test_a_deleted_artifact_is_recorded_so_a_later_raise_cannot_claim_nothing_happened(self):
    ledger = self.EffectLedger()
    self.control.purge_job(self._owner(), "job-1", checked_job=self._job(), ledger=ledger)
    self.assertIs(ledger.state, self.EffectState.DELIVERED,
                  "an irreversible R1FS delete left the ledger at %r" % (ledger.state,))

  def test_nothing_is_recorded_when_no_artifact_was_deleted(self):
    """The ledger must stay NONE when the purge deleted nothing, or every failure would falsely
    claim an effect landed."""
    ledger = self.EffectLedger()
    owner = self._owner(delete_ok=False)
    self.control.purge_job(owner, "job-1", checked_job=self._job(), ledger=ledger)
    self.assertIs(ledger.state, self.EffectState.NONE)


class TestPurgeErrorsCarryNoExceptionProse(unittest.TestCase):
  """Contract 7. These endpoints became externally reachable as POST in B9, and every failure branch
  published `f"{type(exc).__name__}: {exc}"` -- the exception text can carry storage paths, CIDs and
  backend internals. The class name is a typed diagnostic and is kept; the text is not."""

  def setUp(self):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.services import control
    self.control = control

  def test_a_storage_failure_publishes_the_class_not_the_message(self):
    from unittest.mock import MagicMock
    owner = MagicMock()
    owner.cfg_instance_id = "test-instance"
    owner.ee_addr = "node-a"
    owner.P = lambda *a, **k: None
    owner._log_audit_event = lambda *a, **k: None
    owner.chainstore_hgetall.side_effect = lambda *, hkey: {}
    owner._normalize_job_record.side_effect = lambda k, r, **kw: (k, r)
    owner.chainstore_hset.side_effect = RuntimeError(SECRET)
    result = self.control.purge_all_jobs(owner, checked_jobs={
      "job-1": {"job_id": "job-1", "job_status": "FINALIZED", "launcher": "node-a"}})
    published = repr(result)
    self.assertNotIn(SECRET, published, published)
    self.assertIn("RuntimeError", published,
                  "the typed diagnostic was stripped along with the prose: %s" % published)


if __name__ == "__main__":
  unittest.main()
