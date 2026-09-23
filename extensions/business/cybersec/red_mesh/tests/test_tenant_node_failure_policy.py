"""Node-failure settings through real administration/storage and external-state fakes."""
import unittest
import json
from unittest.mock import patch

from . import test_tenant_administration as fixtures


class TestTenantNodeFailurePolicy(unittest.TestCase):
  setUp = fixtures.TestTenantAdministration.setUp
  prepare = fixtures.TestTenantAdministration.prepare
  create = fixtures.TestTenantAdministration.create

  def test_changed_policy_is_persistent_preserves_publication_and_replays(self):
    tenant_id = self.create()["tenantId"]
    before = self.repo.get("tenant", tenant_id)
    before["future_extension"] = {"preserve": True}
    self.repo.put("tenant", tenant_id, record=before)
    result = self.service.update_tenant_node_failure_policy(self.actor, tenant_id, "continue")
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"]["nodeFailurePolicy"], "continue")
    self.assertTrue(result["data"]["canUpdateNodeFailurePolicy"])
    self.assertEqual(result["data"]["nodeFailurePolicyChangedBy"], "creator")
    after = self.repo.get("tenant", tenant_id)
    self.assertEqual({key: after[key] for key in before if key != "node_failure_policy"},
                     {key: value for key, value in before.items() if key != "node_failure_policy"})
    self.assertEqual(self.service.activate_tenant(self.actor, self.request)["data"], result["data"])

  def test_legacy_default_and_noop_never_write_or_replace_attribution(self):
    tenant_id = self.create()["tenantId"]
    tenant = self.repo.get("tenant", tenant_id)
    tenant.pop("node_failure_policy")
    self.repo.put("tenant", tenant_id, record=tenant)
    before = len(self.store.writes)
    result = self.service.update_tenant_node_failure_policy(self.actor, tenant_id, "stop")
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"]["nodeFailurePolicy"], "stop")
    self.assertNotIn("nodeFailurePolicyChangedBy", result["data"])
    self.assertEqual(len(self.store.writes), before)
    first = self.service.update_tenant_node_failure_policy(self.actor, tenant_id, "continue")
    before = len(self.store.writes)
    repeated = self.service.update_tenant_node_failure_policy({"account_id": "initial"}, tenant_id, "continue")
    self.assertEqual(repeated["data"], {**first["data"], "canUpdateAllowPentester": False,
                                        "assignableMemberRoles": ["tenant_admin", "tenant_user"]})
    self.assertEqual(len(self.store.writes), before)
    self.store.data[("auth", "initial")]["memberships"] = []
    self.assertEqual(self.service.update_tenant_node_failure_policy(
      {"account_id": "initial"}, tenant_id, "continue")["status_code"], 404)
    self.assertEqual(len(self.store.writes), before)

  def test_exact_enum_and_current_role_scope(self):
    tenant_id = self.create()["tenantId"]
    for value in (None, True, False, 1, [], {}, "STOP", " stop", "continue ", ""):
      with self.subTest(value=value):
        before = len(self.store.writes)
        self.assertEqual(self.service.update_tenant_node_failure_policy(
          self.actor, tenant_id, value)["status_code"], 400)
        self.assertEqual(len(self.store.writes), before)
    cases = [("super_tenant_admin", None, 200), ("tenant_admin", tenant_id, 200),
             ("super_pentester", tenant_id, 403), ("tenant_pentester", tenant_id, 403),
             ("tenant_user", tenant_id, 403), ("super_tenant_admin", "foreign", 404),
             ("tenant_admin", "foreign", 404)]
    for role, scope, status in cases:
      with self.subTest(role=role, scope=scope):
        self.store.account("operator", memberships=[{"role": role, "tenant_id": scope}])
        actor = {"account_id": "operator", "role": "super_tenant_admin"}
        before = len(self.store.writes)
        result = self.service.update_tenant_node_failure_policy(actor, tenant_id, "stop")
        self.assertEqual(result["status_code"], status)
        self.assertEqual(len(self.store.writes), before)
        if status != 404:
          detail = self.service.get_tenant(actor, tenant_id)["data"]
          self.assertEqual(detail["canUpdateNodeFailurePolicy"], status == 200)
    # RM-083: a mixed-scope account is denied as a whole, never partially admitted.
    self.store.account("operator", memberships=[{"role": "tenant_user", "tenant_id": tenant_id},
                                               {"role": "super_tenant_admin", "tenant_id": None}])
    self.assertEqual(self.service.update_tenant_node_failure_policy(
      {"account_id": "operator"}, tenant_id, "continue")["status_code"], 404)

  def test_corrupt_policy_or_attribution_is_unavailable_without_repair(self):
    tenant_id = self.create()["tenantId"]
    # Physical fixture keys independently pin the public namespace/key contract.
    key = (json.dumps(["redmesh", "tenancy", 1, "test-deployment"], separators=(",", ":")),
           json.dumps(["tenant", "test-deployment", tenant_id], separators=(",", ":")))
    valid = self.repo.get("tenant", tenant_id)
    corruptions = [{"node_failure_policy": value} for value in (None, True, 1, [], {}, "STOP", " stop")]
    corruptions += [{"node_failure_policy_changed_by": "creator"},
                    {"node_failure_policy_changed_at": "2026-09-11T00:00:00+00:00"}]
    for actor, timestamp in ((" CREATOR ", "2026-09-11T00:00:00+00:00"),
                             ([], "2026-09-11T00:00:00+00:00"),
                             ("creator", "2026-09-11T00:00:00"),
                             ("creator", "2026-09-11T00:00:00+01:00"),
                             ("creator", None), ("creator", "broken")):
      corruptions.append({"node_failure_policy_changed_by": actor, "node_failure_policy_changed_at": timestamp})
    for corruption in corruptions:
      with self.subTest(corruption=corruption):
        self.store.data[key] = {**valid, **corruption}
        before = len(self.store.writes)
        self.assertEqual(self.service.get_tenant(self.actor, tenant_id)["status_code"], 503)
        self.assertEqual(self.service.update_tenant_node_failure_policy(
          self.actor, tenant_id, "stop")["status_code"], 503)
        self.assertEqual(self.service.activate_tenant(self.actor, self.request)["status_code"], 503)
        self.assertEqual(len(self.store.writes), before)

  def test_unconfirmed_write_retry_and_response_failure_do_not_claim_rollback(self):
    tenant_id = self.create()["tenantId"]
    for after_write in (False, True):
      with self.subTest(after_write=after_write):
        self.store.fail_write = None
        self.service.update_tenant_node_failure_policy(self.actor, tenant_id, "stop")
        self.store.fail_write = len(self.store.writes) + 1
        self.store.fail_after_write = after_write
        result = self.service.update_tenant_node_failure_policy(self.actor, tenant_id, "continue")
        self.assertEqual(result["status_code"], 503)
        self.assertNotIn("private", str(result))
        self.assertEqual(self.repo.get("tenant", tenant_id)["node_failure_policy"],
                         "continue" if after_write else "stop")
        self.store.fail_write = None
        result = self.service.update_tenant_node_failure_policy(self.actor, tenant_id, "continue")
        self.assertTrue(result["success"], result)
    from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
    with patch.object(self.repo, "count_assets", side_effect=TenantStoreError("private response failure")):
      result = self.service.update_tenant_node_failure_policy(self.actor, tenant_id, "stop")
    self.assertEqual(result["status_code"], 503)
    self.assertEqual(self.repo.get("tenant", tenant_id)["node_failure_policy"], "stop")
