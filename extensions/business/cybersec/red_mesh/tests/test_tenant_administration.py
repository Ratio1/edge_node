"""Administration protocol through real identity/storage adapters and synthetic external state."""
import copy
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService, TenantStoreError
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_tenant import CstoreTenantReader


class FakeAdministrationStore:
  def __init__(self):
    self.data = {}
    self.writes = []
    self.fail_write = None
    self.fail_after_write = False
    self.noop = False
    # RM-084 P6: there is no account-role `admin` any more, so the platform creator says what it is
    # -- a full-portfolio Super-Tenant Admin -- as a stored membership row.
    self.account("creator", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.account("initial")

  def account(self, name, *, memberships=None, generation=None, active=True, state=None):
    """A v1 account record, as the Navigator writes it (tenancy/account_record.py).

    `generation` is a UUID v4 because the record rule says so: a test that used a readable label here
    wrote a record the parser refuses, which showed up as every caller becoming "no such account".

    Rewriting an existing account keeps its generation unless one is given, as the Navigator does for
    a membership edit: a new generation is a new incarnation, which is its own test (`account_changed`).
    """
    at = "2026-01-01T00:00:00.000Z"
    existing = self.data.get(("auth", name))
    if generation is None:
      generation = existing["generation"] if isinstance(existing, dict) and "generation" in existing else str(uuid4())
    resolved_state = state if state is not None else ("active" if active else "deleting")
    self.data[("auth", name)] = {
      "schemaVersion": 1,
      "accountId": name,
      "state": resolved_state,
      "generation": generation,
      "password": {"algo": "argon2id", "v": 19, "m": 65536, "t": 3, "p": 1, "len": 32,
                   "salt": "c2FsdHNhbHRzYWx0c2FsdA==",
                   "hash": "aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g="},
      "memberships": list(memberships) if memberships is not None else [],
      "createdAt": at, "createdBy": "@bootstrap",
      "updatedAt": at, "updatedBy": "@bootstrap",
      "passwordChangedAt": at,
    }
    if resolved_state != "active":
      self.data[("auth", name)].update(stateChangedAt=at, stateChangedBy="creator")

  def grant(self, name, tenant_id, role="tenant_admin"):
    # Idempotent, as the Navigator's writer is: a v1 record refuses a duplicate row outright.
    rows = self.data[("auth", name)]["memberships"]
    row = {"role": role, "tenant_id": tenant_id}
    if row not in rows:
      rows.append(row)

  def chainstore_hget(self, *, hkey, key):
    return copy.deepcopy(self.data.get((hkey, key)))

  def chainstore_hgetall(self, *, hkey):
    return {key: copy.deepcopy(value) for (bucket, key), value in self.data.items() if bucket == hkey}

  def chainstore_hset(self, *, hkey, key, value, **kwargs):
    self.writes.append((hkey, key))
    failed = len(self.writes) == self.fail_write
    if not self.noop and (not failed or self.fail_after_write):
      self.data[(hkey, key)] = copy.deepcopy(value)
    if failed:
      raise RuntimeError("private storage failure")
    return True


class TestTenantAdministration(unittest.TestCase):
  def setUp(self):
    self.env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    self.env.start()
    self.addCleanup(self.env.stop)
    self.store = FakeAdministrationStore()
    self.repo = CstoreTenantAdministrationStore(self.store, "test-deployment")
    self.service = TenantAdministrationService(CstoreAuthAccountReader(self.store), self.repo)
    self.actor = {"account_id": "creator"}
    self.request = str(uuid4())

  def prepare(self, **changes):
    values = dict(request_id=self.request, display_name=" Example ", domain_id="example", initial_admin_id=" INITIAL ")
    values.update(changes)
    return self.service.prepare_tenant(self.actor, **values)

  def create(self):
    prepared = self.prepare()
    self.assertTrue(prepared["success"], prepared)
    self.store.grant("initial", prepared["data"]["tenantId"])
    result = self.service.activate_tenant(self.actor, self.request)
    self.assertTrue(result["success"], result)
    return result["data"]

  def test_prepare_publish_and_scoped_read_are_persistent(self):
    prepared = self.prepare()["data"]
    tenant_id = prepared["tenantId"]
    self.assertEqual(prepared["state"], "pending")
    self.assertEqual(len(tenant_id), 39)
    self.assertIsNone(CstoreTenantReader(self.store, "test-deployment").get_tenant_policy(tenant_id))
    self.assertEqual(self.service.list_tenants(self.actor)["data"], [])
    self.assertEqual(self.service.activate_tenant(self.actor, self.request)["status_code"], 409)
    self.store.grant("initial", tenant_id)
    activated = self.service.activate_tenant(self.actor, self.request)["data"]
    self.assertEqual(activated["tenantId"], tenant_id)
    self.assertEqual(activated["displayName"], "Example")
    self.assertFalse(activated["allowPentester"])
    self.assertEqual((activated["memberCount"], activated["adminCount"], activated["assetCount"]), (1, 1, 0))
    self.assertTrue(activated["canUpdateAllowPentester"])
    self.assertEqual(self.service.get_tenant({"account_id": "initial"}, tenant_id)["data"],
                     {**activated, "canUpdateAllowPentester": False,
                      "assignableMemberRoles": ["tenant_admin", "tenant_user"]})
    self.assertTrue(CstoreTenantReader(self.store, "test-deployment").get_tenant_policy(tenant_id).active)

  def test_matching_pending_retry_resumes_but_changed_intent_never_writes(self):
    first = self.prepare()["data"]
    self.assertEqual(self.prepare()["data"], first)
    for changes in ({"display_name": "Changed"}, {"domain_id": "changed"}, {"initial_admin_id": "creator"}):
      before = len(self.store.writes)
      self.assertEqual(self.prepare(**changes)["status_code"], 409)
      self.assertEqual(len(self.store.writes), before)

  def test_allow_pentester_desired_state_is_persistent_and_attributed(self):
    tenant_id = self.create()["tenantId"]
    before = self.repo.get("tenant", tenant_id)
    before["retention_policy"] = {"future_extension": "preserve"}
    self.repo.put("tenant", tenant_id, record=before)
    result = self.service.update_tenant_allow_pentester(self.actor, tenant_id, True)
    self.assertTrue(result["success"], result)
    self.assertTrue(result["data"]["allowPentester"])
    self.assertTrue(result["data"]["canUpdateAllowPentester"])
    self.assertEqual(result["data"]["allowPentesterChangedBy"], "creator")
    self.assertTrue(result["data"]["allowPentesterChangedAt"])
    self.assertEqual(self.service.get_tenant(self.actor, tenant_id)["data"], result["data"])
    self.assertTrue(CstoreTenantReader(self.store, "test-deployment").get_tenant_policy(tenant_id).allow_pentester)
    stored = self.repo.get("tenant", tenant_id)
    for field, value in before.items():
      if field != "allow_pentester":
        self.assertEqual(stored[field], value, field)
    self.assertFalse(self.service.update_tenant_allow_pentester(self.actor, tenant_id, False)["data"]["allowPentester"])

  def test_allow_pentester_same_value_reauthorizes_without_rewriting_attribution(self):
    tenant_id = self.create()["tenantId"]
    before = len(self.store.writes)
    unchanged = self.service.update_tenant_allow_pentester(self.actor, tenant_id, False)
    self.assertTrue(unchanged["success"])
    self.assertNotIn("allowPentesterChangedBy", unchanged["data"])
    self.assertEqual(len(self.store.writes), before)
    changed = self.service.update_tenant_allow_pentester(self.actor, tenant_id, True)
    self.store.account("second", memberships=[{"role": "super_pentester", "tenant_id": tenant_id}])
    before = len(self.store.writes)
    retried = self.service.update_tenant_allow_pentester({"account_id": "second"}, tenant_id, True)
    self.assertEqual(retried["data"], {**changed["data"], "canUpdateNodeFailurePolicy": False,
                                     "canManageMembers": False, "assignableMemberRoles": []})
    self.assertEqual(len(self.store.writes), before)
    self.store.account("second", memberships=[])
    self.assertEqual(self.service.update_tenant_allow_pentester(
      {"account_id": "second", "role": "super_tenant_admin"}, tenant_id, True)["status_code"], 404)
    self.assertEqual(len(self.store.writes), before)

  def test_allow_pentester_uses_only_current_in_scope_platform_roles(self):
    tenant_id = self.create()["tenantId"]
    for role, scope, status in (("super_tenant_admin", None, 200),
                                ("super_pentester", tenant_id, 200),
                                ("super_pentester", None, 200),
                                ("super_tenant_admin", "foreign", 404),
                                ("super_pentester", "foreign", 404),
                                ("tenant_admin", tenant_id, 403),
                                ("tenant_pentester", tenant_id, 403),
                                ("tenant_user", tenant_id, 403)):
      with self.subTest(role=role, scope=scope):
        self.store.account("operator", memberships=[{"role": role, "tenant_id": scope}])
        actor = {"account_id": "operator", "role": "super_tenant_admin", "tenant_id": tenant_id}
        before = len(self.store.writes)
        result = self.service.update_tenant_allow_pentester(actor, tenant_id, True)
        self.assertEqual(result["status_code"], status)
        read = self.service.get_tenant(actor, tenant_id)
        if status == 404:
          self.assertEqual(read["status_code"], 404)
        else:
          self.assertIs(read["data"]["canUpdateAllowPentester"], status == 200)
        if status != 200:
          self.assertEqual(len(self.store.writes), before)
    self.store.account("operator", memberships=[{"role": "super_pentester", "tenant_id": tenant_id}], active=False)
    self.assertEqual(self.service.update_tenant_allow_pentester(
      {"account_id": "operator"}, tenant_id, True)["status_code"], 404)

  def test_allow_pentester_unconfirmed_writes_can_be_retried_without_false_success(self):
    tenant_id = self.create()["tenantId"]
    for noop, fail_after in ((True, False), (False, False), (False, True)):
      with self.subTest(noop=noop, fail_after=fail_after):
        self.store.noop = False
        self.store.fail_write = None
        self.service.update_tenant_allow_pentester(self.actor, tenant_id, False)
        self.store.noop = noop
        self.store.fail_write = None if noop else len(self.store.writes) + 1
        self.store.fail_after_write = fail_after
        result = self.service.update_tenant_allow_pentester(self.actor, tenant_id, True)
        self.assertEqual(result, {"success": False, "status": "error", "status_code": 503, "error": "unavailable"})
        self.store.noop = False
        self.store.fail_write = None
        self.assertTrue(self.service.update_tenant_allow_pentester(self.actor, tenant_id, True)["success"])

  def test_allow_pentester_corrupt_latest_change_metadata_denies_reads_and_writes(self):
    tenant_id = self.create()["tenantId"]
    original = self.repo.get("tenant", tenant_id)
    for metadata in ({"allow_pentester_changed_by": "creator"},
                     {"allow_pentester_changed_at": "2026-09-10T00:00:00+00:00"},
                     {"allow_pentester_changed_by": {}, "allow_pentester_changed_at": "private-value"},
                     {"allow_pentester_changed_by": " Creator ", "allow_pentester_changed_at": "2026-09-10"},
                     {"allow_pentester_changed_by": "creator", "allow_pentester_changed_at": "not-a-time"}):
      with self.subTest(metadata=metadata):
        self.repo.put("tenant", tenant_id, record={**original, **metadata})
        before = len(self.store.writes)
        self.assertEqual(self.service.get_tenant(self.actor, tenant_id)["status_code"], 503)
        self.assertEqual(self.service.update_tenant_allow_pentester(self.actor, tenant_id, True)["status_code"], 503)
        self.assertEqual(len(self.store.writes), before)

  def test_allow_pentester_requires_published_tenant_and_readable_identity(self):
    prepared = self.prepare()["data"]
    before = len(self.store.writes)
    for tenant_id in (prepared["tenantId"], "missing"):
      self.assertEqual(self.service.update_tenant_allow_pentester(self.actor, tenant_id, True)["status_code"], 404)
    self.assertEqual(len(self.store.writes), before)
    self.store.grant("initial", prepared["tenantId"])
    self.service.activate_tenant(self.actor, self.request)
    before = len(self.store.writes)
    with patch.object(self.store, "chainstore_hget", side_effect=RuntimeError("private")):
      self.assertEqual(self.service.update_tenant_allow_pentester(self.actor, prepared["tenantId"], True),
                       {"success": False, "status": "error", "status_code": 503, "error": "unavailable"})
    self.assertEqual(len(self.store.writes), before)
    # Loss of a publication binding may not be repaired by a policy write.
    del self.store.data[self.repo._location("domain", ("example",))]
    self.assertEqual(self.service.update_tenant_allow_pentester(self.actor, prepared["tenantId"], True)["status_code"], 503)
    self.assertEqual(len(self.store.writes), before)

  def test_allow_pentester_response_failure_is_unconfirmed_not_rollback(self):
    tenant_id = self.create()["tenantId"]
    with patch.object(self.store, "chainstore_hgetall", side_effect=RuntimeError("private")):
      result = self.service.update_tenant_allow_pentester(self.actor, tenant_id, True)
    self.assertEqual(result, {"success": False, "status": "error", "status_code": 503, "error": "unavailable"})
    before = len(self.store.writes)
    observed = self.service.get_tenant(self.actor, tenant_id)["data"]
    self.assertTrue(observed["allowPentester"])
    self.assertEqual(self.service.update_tenant_allow_pentester(self.actor, tenant_id, True)["data"], observed)
    self.assertEqual(len(self.store.writes), before)

  def test_allow_pentester_view_depends_on_shared_facts_not_serving_node(self):
    tenant_id = self.create()["tenantId"]
    other_node = FakeAdministrationStore()
    other_node.data = self.store.data
    other_node.ee_addr = "serving-node-outside-tenant"
    other_service = TenantAdministrationService(CstoreAuthAccountReader(other_node),
                                               CstoreTenantAdministrationStore(other_node, "test-deployment"))
    changed = self.service.update_tenant_allow_pentester(self.actor, tenant_id, True)
    self.assertEqual(other_service.get_tenant(self.actor, tenant_id)["data"], changed["data"])
    self.store.account("creator", memberships=[])
    self.assertEqual(other_service.get_tenant(self.actor, tenant_id)["status_code"], 404)
    self.assertEqual(other_service.update_tenant_allow_pentester(self.actor, tenant_id, True)["status_code"], 404)

  def test_completed_retry_does_not_require_or_restore_initial_admin(self):
    tenant = self.create()
    self.store.account("initial", generation=str(uuid4()), memberships=[])
    row = self.repo.get("tenant", tenant["tenantId"])
    row["allow_pentester"] = True
    self.repo.put("tenant", tenant["tenantId"], record=row)
    before = len(self.store.writes)
    self.assertEqual(self.prepare()["data"]["state"], "active")
    self.assertTrue(self.service.activate_tenant(self.actor, self.request)["data"]["allowPentester"])
    self.assertEqual(len(self.store.writes), before)
    self.assertEqual(self.store.data[("auth", "initial")]["memberships"], [])

  def test_pending_retry_rechecks_admin_incarnation_and_creator_authority(self):
    self.prepare()
    self.store.account("initial", generation=str(uuid4()))
    before = len(self.store.writes)
    self.assertEqual(self.prepare()["status_code"], 409)
    self.assertEqual(self.service.activate_tenant(self.actor, self.request)["status_code"], 409)
    self.store.account("creator", memberships=[])
    self.assertEqual(self.prepare()["status_code"], 403)
    self.assertEqual(len(self.store.writes), before)

  def test_initial_admin_must_hold_no_scope_but_a_retry_keeps_its_own_membership(self):
    # RM-083. First preparation refuses an initial admin that already belongs somewhere; a retry after
    # the Navigator wrote this tenant's admin membership must still resume.
    for memberships in ([{"role": "tenant_user", "tenant_id": "tn_995918e9-0000-4000-8000-000000000008"}],
                        [{"role": "super_pentester", "tenant_id": None}], None):
      with self.subTest(memberships=memberships):
        self.setUpStore()
        if memberships is None:
          self.store.account("initial", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
        else:
          self.store.account("initial", memberships=memberships)
        denied = self.prepare()
        self.assertEqual((denied["status_code"], denied["error"]), (409, "scope_conflict"))
        self.assertEqual(self.store.writes, [])
    self.setUpStore()
    prepared = self.prepare()["data"]
    self.store.grant("initial", prepared["tenantId"])
    self.assertEqual(self.prepare()["data"], prepared)
    self.store.grant("initial", "tn_995918e9-0000-4000-8000-000000000008", "tenant_user")
    self.assertEqual(self.prepare()["status_code"], 404)  # a two-tenant account is denied as a whole
    self.store.account("initial", memberships=[{"role": "tenant_user", "tenant_id": prepared["tenantId"]}])
    denied = self.prepare()
    self.assertEqual((denied["status_code"], denied["error"]), (409, "scope_conflict"))
    self.store.account("initial", memberships=[{"role": "tenant_admin", "tenant_id": prepared["tenantId"]}])
    self.assertTrue(self.service.activate_tenant(self.actor, self.request)["success"])

  def test_creation_is_not_granted_by_scoped_platform_or_browser_roles(self):
    # RM-083: a tenant-scoped Super-Tenant Admin is not a valid account at all, so it is unknown (404).
    for memberships, status in (([], 403), ([{"role": "super_tenant_admin", "tenant_id": "allowed"}], 404),
                                ([{"role": "super_pentester", "tenant_id": None}], 403)):
      self.store.account("creator", memberships=memberships)
      self.actor["role"] = "super_tenant_admin"
      self.assertEqual(self.prepare()["status_code"], status)
      self.assertEqual(self.store.writes, [])

  def test_invalid_payload_and_missing_admin_deny_before_writes(self):
    for changes in ({"request_id": "short"}, {"display_name": " "}, {"display_name": "x" * 121},
                    {"domain_id": "UPPER"}, {"domain_id": "-bad"}, {"domain_id": "a" * 64},
                    {"initial_admin_id": "missing"}, {"initial_admin_id": {"account_id": "initial"}}):
      self.assertIn(self.prepare(**changes)["status_code"], (400, 404))
      self.assertEqual(self.store.writes, [])

  def test_another_creator_cannot_activate_receipt_or_reuse_reserved_domain(self):
    self.prepare()
    self.store.account("other", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    other = {"account_id": "other"}
    before = len(self.store.writes)
    self.assertEqual(self.service.activate_tenant(other, self.request)["status_code"], 404)
    self.assertEqual(self.service.prepare_tenant(other, self.request, "Example", "example", "initial")["status_code"], 409)
    self.assertEqual(len(self.store.writes), before)

  def test_each_observable_failed_write_is_unavailable_and_retryable(self):
    for write in (1, 2, 3, 4):
      for after in (False, True):
        with self.subTest(write=write, after=after):
          self.setUpStore()
          self.store.fail_write, self.store.fail_after_write = write, after
          result = self.prepare()
          if write == 4:
            self.store.grant("initial", result["data"]["tenantId"])
            result = self.service.activate_tenant(self.actor, self.request)
          self.assertEqual(result["status_code"], 503, result)
          self.assertNotIn("private", json.dumps(result))
          self.store.fail_write = None
          prepared = self.prepare()["data"]
          if prepared["state"] == "pending":
            self.store.grant("initial", prepared["tenantId"])
          self.assertTrue(self.service.activate_tenant(self.actor, self.request)["success"])

  def setUpStore(self):
    self.store = FakeAdministrationStore()
    self.repo = CstoreTenantAdministrationStore(self.store, "test-deployment")
    self.service = TenantAdministrationService(CstoreAuthAccountReader(self.store), self.repo)

  def test_successful_noop_write_is_not_publication(self):
    self.store.noop = True
    self.assertEqual(self.prepare()["status_code"], 503)
    self.assertEqual(self.service.list_tenants(self.actor)["data"], [])

  def test_member_permissions_counts_and_last_observed_admin(self):
    tenant = self.create()
    tenant_id = tenant["tenantId"]
    self.store.account("reader", memberships=[{"role": "tenant_user", "tenant_id": tenant_id}])
    self.store.account("foreign", memberships=[{"role": "tenant_admin", "tenant_id": "tn_995918e9-0000-4000-8000-000000000008"}])
    self.store.account("disabled", active=False, memberships=[{"role": "tenant_admin", "tenant_id": tenant_id}])
    # RM-084 P7: an archived admin is listed but is not cover for the last active one.
    self.store.account("paused", state="deactivated", memberships=[{"role": "tenant_admin", "tenant_id": tenant_id}])
    reader, foreign = {"account_id": "reader"}, {"account_id": "foreign"}
    self.assertEqual(self.service.list_tenants(foreign)["data"], [])
    self.assertEqual(self.service.get_tenant(foreign, tenant_id)["status_code"], 404)
    self.assertEqual(self.service.get_tenant_members(reader, tenant_id)["status_code"], 403)
    members = self.service.get_tenant_members({"account_id": "initial"}, tenant_id)["data"]
    self.assertEqual(members, [{"accountId": "initial", "displayName": "initial", "role": "tenant_admin",
                                "state": "active"},
                               {"accountId": "paused", "displayName": "paused", "role": "tenant_admin",
                                "state": "deactivated"},
                               {"accountId": "reader", "displayName": "reader", "role": "tenant_user",
                                "state": "active"}])
    detail = self.service.get_tenant(reader, tenant_id)["data"]
    self.assertEqual((detail["memberCount"], detail["adminCount"]), (2, 1))
    sole = self.service.authorize_tenant_membership(self.actor, tenant_id, "initial", "tenant_admin", True)
    # RM-083: the more specific last_tenant_admin wins over last_membership for a sole admin's only row.
    self.assertEqual((sole["status_code"], sole["error"]), (409, "last_tenant_admin"))
    self.assertEqual(self.service.authorize_tenant_membership(self.actor, tenant_id, "initial", "tenant_user")["status_code"], 409)
    self.assertEqual(self.service.authorize_tenant_membership(self.actor, tenant_id, "reader", "super_tenant_admin")["status_code"], 400)
    self.assertEqual(self.service.authorize_tenant_membership(reader, tenant_id, "reader", "tenant_admin")["status_code"], 403)
    approval = self.service.authorize_tenant_membership({"account_id": "initial"}, tenant_id, "reader", "tenant_admin")["data"]
    self.assertEqual(approval, {"accountId": "reader", "tenantId": tenant_id, "role": "tenant_admin", "remove": False,
                                "accountGeneration": self.store.data[("auth", "reader")]["generation"]})

  def test_domain_lookup_requires_creator_and_sees_pending_reservation(self):
    self.assertEqual(self.service.check_tenant_domain(self.actor, "example")["data"], {"available": True})
    self.prepare()
    self.assertEqual(self.service.check_tenant_domain(self.actor, "example")["data"], {"available": False})
    self.assertEqual(self.service.check_tenant_domain({"account_id": "initial"}, "example")["status_code"], 403)

  def test_concurrent_service_instances_share_one_creation_reservation(self):
    from concurrent.futures import ThreadPoolExecutor

    def prepare(_):
      service = TenantAdministrationService(CstoreAuthAccountReader(self.store), self.repo)
      return service.prepare_tenant(self.actor, self.request, "Example", "example", "initial")

    with ThreadPoolExecutor(max_workers=8) as executor:
      results = list(executor.map(prepare, range(16)))
    self.assertTrue(all(result["success"] for result in results))
    self.assertEqual(len({result["data"]["tenantId"] for result in results}), 1)
    self.assertEqual(len(self.store.writes), 3)

  def test_deleted_or_inactive_initial_admin_cannot_publish_pending_tenant(self):
    prepared = self.prepare()["data"]
    for state in (None, "deleting"):
      if state is None:
        del self.store.data[("auth", "initial")]
      else:
        self.store.account("initial", active=False)
        self.store.grant("initial", prepared["tenantId"])
      before = len(self.store.writes)
      self.assertEqual(self.service.activate_tenant(self.actor, self.request)["status_code"], 404)
      self.assertEqual(len(self.store.writes), before)
      self.assertEqual(self.service.list_tenants(self.actor)["data"], [])

  def test_read_authority_is_rechecked_and_two_tenant_counts_are_scoped(self):
    first = self.create()
    self.request = str(uuid4())
    self.store.account("initial-2")
    second = self.prepare(domain_id="second", display_name="Second", initial_admin_id="initial-2")["data"]
    self.store.grant("initial-2", second["tenantId"])
    self.assertTrue(self.service.activate_tenant(self.actor, self.request)["success"])
    self.store.account("scoped", memberships=[{"role": "super_pentester", "tenant_id": first["tenantId"]}])
    self.store.account("second-only", memberships=[{"role": "tenant_user", "tenant_id": second["tenantId"]}])
    visible = self.service.list_tenants({"account_id": "scoped"})["data"]
    self.assertEqual([(row["tenantId"], row["memberCount"]) for row in visible], [(first["tenantId"], 1)])
    self.store.account("scoped", memberships=[])
    self.assertEqual(self.service.get_tenant({"account_id": "scoped"}, first["tenantId"])["status_code"], 404)
    self.assertEqual(self.service.list_tenants({"account_id": "scoped"})["data"], [])

  def test_second_active_admin_allows_observed_admin_removal_without_backend_account_write(self):
    tenant = self.create()
    self.store.account("second")
    self.store.grant("second", tenant["tenantId"])
    before = copy.deepcopy(self.store.data)
    self.assertTrue(self.service.authorize_tenant_membership(
      self.actor, tenant["tenantId"], "initial", "tenant_user")["success"])
    self.store.grant("initial", tenant["tenantId"], "tenant_user")
    self.assertTrue(self.service.authorize_tenant_membership(
      self.actor, tenant["tenantId"], "initial", "tenant_admin", True)["success"])
    self.store.data = copy.deepcopy(before)
    # RM-083: the admin row is the account's only one, so removing it would leave no scope.
    last = self.service.authorize_tenant_membership(self.actor, tenant["tenantId"], "initial", "tenant_admin", True)
    self.assertEqual((last["status_code"], last["error"]), (409, "last_membership"))
    self.assertEqual(self.store.data, before)

  def test_root_tenant_admin_membership_is_not_a_peer_admin_to_remove(self):
    # RM-082. A peer tenant admin removing the founder's admin role is the takeover the password
    # rule refuses; the founder may step down and a Super-Tenant Admin may remove it.
    tenant_id = self.create()["tenantId"]
    self.store.account("peer")
    self.store.grant("peer", tenant_id)
    peer = {"account_id": "peer"}
    for role, remove in (("tenant_admin", True), ("tenant_user", False)):
      with self.subTest(role=role, remove=remove):
        denied = self.service.authorize_tenant_membership(peer, tenant_id, "initial", role, remove)
        self.assertEqual((denied["status_code"], denied["error"]), (403, "root_tenant_admin"))
    self.assertTrue(self.service.authorize_tenant_membership(peer, tenant_id, "peer", "tenant_user")["success"])
    self.assertTrue(self.service.authorize_tenant_membership(
      {"account_id": "initial"}, tenant_id, "initial", "tenant_user")["success"])
    self.assertTrue(self.service.authorize_tenant_membership(self.actor, tenant_id, "initial", "tenant_user")["success"])
    # The founder's removal is still refused for a peer before the last-membership rule is reached.
    denied = self.service.authorize_tenant_membership(peer, tenant_id, "initial", "tenant_admin", True)
    self.assertEqual((denied["status_code"], denied["error"]), (403, "root_tenant_admin"))
    for actor in (peer, {"account_id": "initial"}, self.actor):
      target = actor["account_id"] if actor is not self.actor else "initial"
      with self.subTest(actor=actor["account_id"], target=target):
        last = self.service.authorize_tenant_membership(actor, tenant_id, target, "tenant_admin", True)
        self.assertEqual((last["status_code"], last["error"]), (409, "last_membership"))

  def test_tenant_admin_edits_only_existing_members_and_never_the_pentester_role(self):
    # RM-083. Attaching an outside account would make it resettable by this tenant's admins, and the
    # pentester role is the platform's to grant, remove or overwrite.
    tenant_id = self.create()["tenantId"]
    admin = {"account_id": "initial"}
    self.store.account("outsider")
    self.store.account("member", memberships=[{"role": "tenant_user", "tenant_id": tenant_id}])
    self.store.account("tester", memberships=[{"role": "tenant_pentester", "tenant_id": tenant_id}])
    self.store.account("elsewhere", memberships=[{"role": "tenant_user", "tenant_id": "tn_995918e9-0000-4000-8000-000000000008"}])
    for target in ("outsider", "elsewhere"):
      with self.subTest(target=target):
        denied = self.service.authorize_tenant_membership(admin, tenant_id, target, "tenant_user")
        self.assertEqual((denied["status_code"], denied["error"]), (403, "not_a_member"))
    for target, role, remove in (("member", "tenant_pentester", False), ("tester", "tenant_user", False),
                                 ("tester", "tenant_pentester", True), ("tester", "tenant_admin", False)):
      with self.subTest(target=target, role=role, remove=remove):
        denied = self.service.authorize_tenant_membership(admin, tenant_id, target, role, remove)
        self.assertEqual((denied["status_code"], denied["error"]), (403, "pentester_role_reserved"))
    self.assertTrue(self.service.authorize_tenant_membership(admin, tenant_id, "member", "tenant_admin")["success"])
    last = self.service.authorize_tenant_membership(admin, tenant_id, "member", "tenant_user", True)
    self.assertEqual((last["status_code"], last["error"]), (409, "last_membership"))
    for target, role, remove in (("outsider", "tenant_user", False), ("member", "tenant_pentester", False),
                                 ("tester", "tenant_user", False)):
      with self.subTest(platform=target, role=role):
        self.assertTrue(self.service.authorize_tenant_membership(self.actor, tenant_id, target, role, remove)["success"])
    last = self.service.authorize_tenant_membership(self.actor, tenant_id, "tester", "tenant_pentester", True)
    self.assertEqual((last["status_code"], last["error"]), (409, "last_membership"))

  def test_membership_writes_never_give_an_account_a_second_scope(self):
    # RM-083 (owner): an account is platform-scoped or belongs to exactly one tenant.
    tenant_id = self.create()["tenantId"]
    self.store.account("elsewhere", memberships=[{"role": "tenant_user", "tenant_id": "tn_995918e9-0000-4000-8000-000000000008"}])
    self.store.account("pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.store.account("allowlisted", memberships=[{"role": "super_pentester", "tenant_id": tenant_id}])
    self.store.account("legacy", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    before = copy.deepcopy(self.store.data)
    for target in ("elsewhere", "pentester", "allowlisted", "legacy", "creator"):
      with self.subTest(target=target):
        denied = self.service.authorize_tenant_membership(self.actor, tenant_id, target, "tenant_user")
        self.assertEqual((denied["status_code"], denied["error"]), (409, "scope_conflict"))
    self.assertEqual(self.store.data, before)

  def test_account_creation_is_approved_with_its_one_membership(self):
    tenant_id = self.create()["tenantId"]
    admin = {"account_id": "initial"}
    self.store.account("reader", memberships=[{"role": "tenant_user", "tenant_id": tenant_id}])
    self.store.account("taken", memberships=[{"role": "tenant_user", "tenant_id": "tn_995918e9-0000-4000-8000-000000000008"}])
    before = copy.deepcopy(self.store.data)
    self.assertEqual(self.service.authorize_tenant_account_creation(admin, tenant_id, " New ", "tenant_user")["data"],
                     {"accountId": "new", "tenantId": tenant_id, "role": "tenant_user"})
    self.assertTrue(self.service.authorize_tenant_account_creation(admin, tenant_id, "new", "tenant_admin")["success"])
    for actor, account_id, role, expected in (
        (admin, "new", "tenant_pentester", (403, "pentester_role_reserved")),
        (admin, "new", "super_tenant_admin", (400, "invalid_membership")),
        (admin, "taken", "tenant_user", (409, "account_exists")),
        ({"account_id": "reader"}, "new", "tenant_user", (403, "forbidden")),
        ({"account_id": "taken"}, "new", "tenant_user", (404, "not_found"))):
      with self.subTest(actor=actor["account_id"], account_id=account_id, role=role):
        denied = self.service.authorize_tenant_account_creation(actor, tenant_id, account_id, role)
        self.assertEqual((denied["status_code"], denied.get("error")), expected)
    self.assertTrue(self.service.authorize_tenant_account_creation(self.actor, tenant_id, "new", "tenant_pentester")["success"])
    self.assertEqual(self.store.data, before)

  def test_detail_projects_member_administration_capability(self):
    tenant_id = self.create()["tenantId"]
    self.store.account("reader", memberships=[{"role": "tenant_user", "tenant_id": tenant_id}])
    expected = {"creator": (True, ["tenant_admin", "tenant_pentester", "tenant_user"]),
                "initial": (True, ["tenant_admin", "tenant_user"]), "reader": (False, [])}
    for account_id, (can_manage, roles) in expected.items():
      with self.subTest(account_id=account_id):
        detail = self.service.get_tenant({"account_id": account_id}, tenant_id)["data"]
        self.assertEqual((detail["canManageMembers"], detail["assignableMemberRoles"]), (can_manage, roles))

  def test_tenant_without_recorded_founder_keeps_peer_membership_edits(self):
    tenant_id = self.create()["tenantId"]
    stored = self.repo.get("tenant", tenant_id)
    self.repo.put("tenant", tenant_id, record={k: v for k, v in stored.items() if k != "root_admin_id"})
    self.store.account("peer")
    self.store.grant("peer", tenant_id)
    self.assertTrue(self.service.authorize_tenant_membership(
      {"account_id": "peer"}, tenant_id, "initial", "tenant_user")["success"])
    self.store.grant("initial", tenant_id, "tenant_user")
    self.assertTrue(self.service.authorize_tenant_membership(
      {"account_id": "peer"}, tenant_id, "initial", "tenant_admin", True)["success"])

  def test_corrupt_receipt_and_tenant_bindings_fail_without_writes(self):
    prepared = self.prepare()["data"]
    original = copy.deepcopy(self.store.data)
    for kind, ids, change in (("receipt", ("creator", self.request), {"tenant_id": "tn_bad"}),
                              ("receipt", ("creator", self.request), {"initial_admin_id": None}),
                              ("tenant", (prepared["tenantId"],), {"request_id": str(uuid4())}),
                              ("tenant", (prepared["tenantId"],), {"active": 1})):
      self.store.data = copy.deepcopy(original)
      hkey = '["redmesh","tenancy",1,"test-deployment"]'
      key = json.dumps([kind, "test-deployment", *ids], separators=(",", ":"))
      self.store.data[(hkey, key)].update(change)
      before = len(self.store.writes)
      self.assertEqual(self.prepare()["status_code"], 503)
      self.assertEqual(len(self.store.writes), before)

  def test_published_reads_and_membership_approval_require_publication_bindings(self):
    tenant_id = self.create()["tenantId"]
    original = copy.deepcopy(self.store.data)
    hkey = '["redmesh","tenancy",1,"test-deployment"]'
    tenant_key = json.dumps(["tenant", "test-deployment", tenant_id], separators=(",", ":"))
    domain_key = '["domain","test-deployment","example"]'
    receipt_key = json.dumps(["receipt", "test-deployment", "creator", self.request], separators=(",", ":"))
    for key, change in ((tenant_key, {"request_id": str(uuid4())}), (tenant_key, {"actor_id": "someone"}),
                        (receipt_key, {"tenant_id": "tn_" + str(uuid4())}),
                        (domain_key, {"tenant_id": "tn_" + str(uuid4())}), (domain_key, None),
                        (receipt_key, None)):
      with self.subTest(key=key, change=change):
        self.store.data = copy.deepcopy(original)
        if change is None:
          del self.store.data[(hkey, key)]
        else:
          self.store.data[(hkey, key)].update(change)
        before = len(self.store.writes)
        for result in (self.service.get_tenant(self.actor, tenant_id), self.service.list_tenants(self.actor),
                       self.service.get_tenant_members(self.actor, tenant_id),
                       self.service.authorize_tenant_membership(self.actor, tenant_id, "initial", "tenant_admin")):
          self.assertEqual(result["status_code"], 503, result)
        self.assertEqual(len(self.store.writes), before)


class TestAdministrationPluginBoundary(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def test_allow_pentester_request_model_preserves_json_types_before_authorization(self):
    import inspect
    from pydantic import create_model

    store = FakeAdministrationStore()
    plugin = object.__new__(self.Plugin)
    plugin.cfg_tenant_administration_enabled, plugin.cfg_tenancy_namespace = True, "deployment"
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(plugin, name, getattr(store, name))
    # The core's FastAPI template copies these real signature fields into a Pydantic model.
    fields = {param.name: (param.annotation, param.default) for param in
              inspect.signature(plugin.update_tenant_allow_pentester).parameters.values()}
    RequestModel = create_model("AllowPentesterRequest", **fields)
    actor = {"account_id": "creator"}
    request_id = str(uuid4())
    with patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"}):
      tenant_id = plugin.prepare_tenant(actor, request_id, "Tenant", "tenant", "initial")["data"]["tenantId"]
      store.grant("initial", tenant_id)
      plugin.activate_tenant(actor, request_id)
      for value in (True, False, 0, 1, "true", "false", None, [], {}):
        with self.subTest(value=value):
          payload = RequestModel.model_validate_json(json.dumps({
            "actor": actor, "tenant_id": tenant_id, "allow_pentester": value}))
          before = len(store.writes)
          result = plugin.update_tenant_allow_pentester(**payload.model_dump())
          self.assertEqual(result["status_code"], 200 if type(value) is bool else 400)
          if type(value) is not bool:
            self.assertEqual(len(store.writes), before)
      missing = RequestModel.model_validate_json(json.dumps({"actor": actor, "tenant_id": tenant_id}))
      self.assertEqual(plugin.update_tenant_allow_pentester(**missing.model_dump())["status_code"], 400)

  def test_disabled_or_invalid_config_denies_every_administration_method_before_store_access(self):
    from unittest.mock import MagicMock
    methods = ("prepare_tenant", "activate_tenant", "list_tenants", "get_tenant", "get_tenant_members",
               "check_tenant_domain", "authorize_tenant_membership", "authorize_tenant_account_creation",
               "authorize_account_state_change",
               "update_tenant_allow_pentester",
               "get_tenant_nodes", "set_tenant_node_assignment", "list_tenant_assets",
               "get_tenant_asset", "create_tenant_asset", "update_tenant_asset")
    self.assertTrue(all(getattr(self.Plugin, name).__http_method__ == "post" for name in methods))
    for enabled, namespace in ((False, "deployment"), ("true", "deployment"), (True, None), (True, " ")):
      for name in methods:
        with self.subTest(enabled=enabled, namespace=namespace, method=name):
          plugin = object.__new__(self.Plugin)
          plugin.cfg_tenant_administration_enabled, plugin.cfg_tenancy_namespace = enabled, namespace
          plugin.chainstore_hget = MagicMock(side_effect=AssertionError("No storage access"))
          plugin.chainstore_hset = MagicMock(side_effect=AssertionError("No storage write"))
          result = getattr(plugin, name)(actor={"account_id": "creator"})
          self.assertEqual(result["status_code"], 503)
          self.assertFalse(result["success"])
          plugin.chainstore_hget.assert_not_called()
          plugin.chainstore_hset.assert_not_called()

  def test_enabled_real_plugin_creation_and_read_use_server_configuration(self):
    store = FakeAdministrationStore()
    plugin = object.__new__(self.Plugin)
    plugin.cfg_tenant_administration_enabled, plugin.cfg_tenancy_namespace = True, "deployment"
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(plugin, name, getattr(store, name))
    actor = {"account_id": "creator", "namespace": "browser-ignored"}
    request = str(uuid4())
    with patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"}):
      prepared = plugin.prepare_tenant(actor, request, "Tenant", "tenant", "initial")
      self.assertTrue(prepared["success"], prepared)
      tenant_id = prepared["data"]["tenantId"]
      store.grant("initial", tenant_id)
      self.assertTrue(plugin.activate_tenant(actor, request)["success"])
      self.assertEqual(plugin.list_tenants(actor)["data"][0]["tenantId"], tenant_id)
      self.assertEqual(plugin.get_tenant(actor, tenant_id)["data"]["tenantId"], tenant_id)
      self.assertEqual(plugin.get_tenant_members(actor, tenant_id)["data"][0]["accountId"], "initial")
      self.assertFalse(plugin.check_tenant_domain(actor, "tenant")["data"]["available"])
      self.assertEqual(plugin.authorize_tenant_membership(actor, tenant_id, "initial", "tenant_admin")["data"]["accountId"], "initial")
      state = plugin.authorize_account_state_change(actor, "initial", "deactivated", tenant_id)
      self.assertEqual((state["status_code"], state["error"]), (409, "last_tenant_admin"))
    self.assertTrue(all(json.loads(hkey)[3] == "deployment" for hkey, _ in store.writes))


def test_auth_hkey_is_read_from_the_plugin_instance_env_before_the_process_env(monkeypatch):
  """RM-026 MVP: the hkey is a pipeline-level value, so the plugin reads its own instance ENV first
  and falls back to os.environ. Note what this does NOT claim: deeploy's injector
  (deeploy_mixin._ensure_runner_cstore_auth_env) targets CONTAINERIZED_APPS_SIGNATURES only, so a
  deeploy-launched PENTESTER_API_01 gets no hkey unless its instance config carries
  ENV.R1EN_CSTORE_AUTH_HKEY or the host env sets it. Instance ENV wins over the host env."""
  from types import SimpleNamespace
  from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import (
    AUTH_HKEY_ENV, CstoreAuthAccountReader)
  monkeypatch.delenv(AUTH_HKEY_ENV, raising=False)
  owner = SimpleNamespace(cfg_env={AUTH_HKEY_ENV: " pipeline-hkey "}, chainstore_hget=lambda **k: None)
  assert CstoreAuthAccountReader(owner)._hkey() == "pipeline-hkey"
  monkeypatch.setenv(AUTH_HKEY_ENV, "process-hkey")
  assert CstoreAuthAccountReader(owner)._hkey() == "pipeline-hkey"
  owner.cfg_env = None
  assert CstoreAuthAccountReader(owner)._hkey() == "process-hkey"

class TestTenantRootAdministrator(TestTenantAdministration):
  """RM-026 MVP: the founder is recorded so a tenant admin cannot reset the founder's credential and
  take the tenant over. Optional by design: tenants created before the field existed do not carry it,
  and absence must read as "unknown", never as "anyone"."""

  def test_a_created_tenant_records_its_root_administrator(self):
    activated = self.create()
    self.assertEqual(activated["rootAdminId"], "initial")
    detail = self.service.get_tenant(self.actor, activated["tenantId"])["data"]
    self.assertEqual(detail["rootAdminId"], "initial")

  ENVELOPE = ("schemaVersion", "namespace", "kind", "ids")

  def stored_tenant(self, tenant_id):
    """The tenant's own fields: `get` returns them wrapped, and putting the wrapper back double-wraps."""
    stored = self.repo.get("tenant", tenant_id)
    return {key: value for key, value in stored.items() if key not in self.ENVELOPE}

  def test_a_tenant_without_the_field_reads_as_unknown_rather_than_failing(self):
    activated = self.create()
    tenant_id = activated["tenantId"]
    stored = self.stored_tenant(tenant_id)
    self.repo.put("tenant", tenant_id, record={k: v for k, v in stored.items() if k != "root_admin_id"})
    detail = self.service.get_tenant(self.actor, tenant_id)
    self.assertTrue(detail["success"], detail)
    self.assertIsNone(detail["data"]["rootAdminId"])

  def test_a_malformed_root_administrator_fails_closed(self):
    """Pinned on the validator itself. Going through the store would pass for the wrong reason: the
    receipt binding rejects any changed value, so it would stay green with the validation deleted."""
    activated = self.create()
    tenant = self.stored_tenant(activated["tenantId"])
    for malformed in ("  Mixed Case  ", "", "   ", 7, {}):
      with self.subTest(root_admin_id=malformed):
        with self.assertRaises(TenantStoreError):
          self.service._validate_tenant({**tenant, "root_admin_id": malformed})
    # The recorded canonical value still validates.
    self.service._validate_tenant(tenant)
