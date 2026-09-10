"""Administration protocol through real identity/storage adapters and synthetic external state."""
import copy
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
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
    self.account("creator", role="admin")
    self.account("initial")

  def account(self, name, *, role="user", memberships=None, generation="generation-1", active=True):
    metadata = {"navigatorAccountGeneration": generation, "navigatorAccountState": "active" if active else "deleting"}
    if memberships is not None:
      metadata["tenant_memberships"] = memberships
    self.data[("auth", name)] = {"role": role, "metadata": metadata, "createdAt": "2026-01-01"}

  def grant(self, name, tenant_id, role="tenant_admin"):
    self.data[("auth", name)]["metadata"].setdefault("tenant_memberships", []).append(
      {"role": role, "tenant_id": tenant_id})

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
                     {**activated, "canUpdateAllowPentester": False})
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
    self.assertEqual(retried["data"], changed["data"])
    self.assertEqual(len(self.store.writes), before)
    self.store.account("second", role="admin", memberships=[])
    self.assertEqual(self.service.update_tenant_allow_pentester(
      {"account_id": "second", "role": "super_tenant_admin"}, tenant_id, True)["status_code"], 404)
    self.assertEqual(len(self.store.writes), before)

  def test_allow_pentester_uses_only_current_in_scope_platform_roles(self):
    tenant_id = self.create()["tenantId"]
    for role, scope, status in (("super_tenant_admin", tenant_id, 200),
                                ("super_pentester", tenant_id, 200),
                                ("super_pentester", None, 200),
                                ("super_tenant_admin", "foreign", 404),
                                ("super_pentester", "foreign", 404),
                                ("tenant_admin", tenant_id, 403),
                                ("tenant_pentester", tenant_id, 403),
                                ("tenant_user", tenant_id, 403)):
      with self.subTest(role=role, scope=scope):
        self.store.account("operator", role="admin", memberships=[{"role": role, "tenant_id": scope}])
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
    self.store.account("creator", role="admin", memberships=[])
    self.assertEqual(other_service.get_tenant(self.actor, tenant_id)["status_code"], 404)
    self.assertEqual(other_service.update_tenant_allow_pentester(self.actor, tenant_id, True)["status_code"], 404)

  def test_completed_retry_does_not_require_or_restore_initial_admin(self):
    tenant = self.create()
    self.store.account("initial", generation="replacement", memberships=[])
    row = self.repo.get("tenant", tenant["tenantId"])
    row["allow_pentester"] = True
    self.repo.put("tenant", tenant["tenantId"], record=row)
    before = len(self.store.writes)
    self.assertEqual(self.prepare()["data"]["state"], "active")
    self.assertTrue(self.service.activate_tenant(self.actor, self.request)["data"]["allowPentester"])
    self.assertEqual(len(self.store.writes), before)
    self.assertEqual(self.store.data[("auth", "initial")]["metadata"]["tenant_memberships"], [])

  def test_pending_retry_rechecks_admin_incarnation_and_creator_authority(self):
    self.prepare()
    self.store.account("initial", generation="replacement")
    before = len(self.store.writes)
    self.assertEqual(self.prepare()["status_code"], 409)
    self.assertEqual(self.service.activate_tenant(self.actor, self.request)["status_code"], 409)
    self.store.account("creator", memberships=[])
    self.assertEqual(self.prepare()["status_code"], 403)
    self.assertEqual(len(self.store.writes), before)

  def test_creation_is_not_granted_by_scoped_platform_or_browser_roles(self):
    for memberships in ([], [{"role": "super_tenant_admin", "tenant_id": "allowed"}],
                        [{"role": "super_pentester", "tenant_id": None}]):
      self.store.account("creator", memberships=memberships)
      self.actor["role"] = "super_tenant_admin"
      self.assertEqual(self.prepare()["status_code"], 403)
      self.assertEqual(self.store.writes, [])

  def test_invalid_payload_and_missing_admin_deny_before_writes(self):
    for changes in ({"request_id": "short"}, {"display_name": " "}, {"display_name": "x" * 121},
                    {"domain_id": "UPPER"}, {"domain_id": "-bad"}, {"domain_id": "a" * 64},
                    {"initial_admin_id": "missing"}, {"initial_admin_id": {"account_id": "initial"}}):
      self.assertIn(self.prepare(**changes)["status_code"], (400, 404))
      self.assertEqual(self.store.writes, [])

  def test_another_creator_cannot_activate_receipt_or_reuse_reserved_domain(self):
    self.prepare()
    self.store.account("other", role="admin")
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
    self.store.account("foreign", memberships=[{"role": "tenant_admin", "tenant_id": "other"}])
    self.store.account("disabled", active=False, memberships=[{"role": "tenant_admin", "tenant_id": tenant_id}])
    reader, foreign = {"account_id": "reader"}, {"account_id": "foreign"}
    self.assertEqual(self.service.list_tenants(foreign)["data"], [])
    self.assertEqual(self.service.get_tenant(foreign, tenant_id)["status_code"], 404)
    self.assertEqual(self.service.get_tenant_members(reader, tenant_id)["status_code"], 403)
    members = self.service.get_tenant_members({"account_id": "initial"}, tenant_id)["data"]
    self.assertEqual(members, [{"accountId": "initial", "displayName": "initial", "role": "tenant_admin"},
                               {"accountId": "reader", "displayName": "reader", "role": "tenant_user"}])
    self.assertEqual(self.service.get_tenant(reader, tenant_id)["data"]["memberCount"], 2)
    self.assertEqual(self.service.authorize_tenant_membership(self.actor, tenant_id, "initial", "tenant_admin", True)["status_code"], 409)
    self.assertEqual(self.service.authorize_tenant_membership(self.actor, tenant_id, "initial", "tenant_user")["status_code"], 409)
    self.assertEqual(self.service.authorize_tenant_membership(self.actor, tenant_id, "reader", "super_tenant_admin")["status_code"], 400)
    self.assertEqual(self.service.authorize_tenant_membership(reader, tenant_id, "reader", "tenant_admin")["status_code"], 403)
    approval = self.service.authorize_tenant_membership({"account_id": "initial"}, tenant_id, "reader", "tenant_admin")["data"]
    self.assertEqual(approval, {"accountId": "reader", "accountGeneration": "generation-1", "tenantId": tenant_id,
                                "role": "tenant_admin", "remove": False})

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
    second = self.prepare(domain_id="second", display_name="Second")["data"]
    self.store.grant("initial", second["tenantId"])
    self.assertTrue(self.service.activate_tenant(self.actor, self.request)["success"])
    self.store.account("scoped", memberships=[{"role": "super_tenant_admin", "tenant_id": first["tenantId"]}])
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
      self.actor, tenant["tenantId"], "initial", "tenant_admin", True)["success"])
    self.assertEqual(self.store.data, before)

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
               "check_tenant_domain", "authorize_tenant_membership", "update_tenant_allow_pentester")
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
    self.assertTrue(all(json.loads(hkey)[3] == "deployment" for hkey, _ in store.writes))
