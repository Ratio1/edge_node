"""Public plugin request transport through real tenant authorization and persistence."""
import inspect
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from pydantic import create_model

from .conftest import mock_plugin_modules
from .test_tenant_administration import FakeAdministrationStore


class TestNodeFailurePolicyTransport(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.store = FakeAdministrationStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "policy-transport"
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.store, name))
    self.creator = {"account_id": "creator"}
    request = str(uuid4())
    prepared = self.plugin.prepare_tenant(self.creator, request, "Tenant", "tenant", "initial")
    self.assertTrue(prepared["success"], prepared)
    self.tenant_id = prepared["data"]["tenantId"]
    self.store.grant("initial", self.tenant_id)
    self.assertTrue(self.plugin.activate_tenant(self.creator, request)["success"])

  def test_tenant_admin_can_change_only_the_new_setting_through_json_transport(self):
    method = self.plugin.update_tenant_node_failure_policy
    self.assertEqual(method.__http_method__, "post")
    # Match the native FastAPI template's signature-derived request model.
    fields = {p.name: (p.annotation, p.default) for p in inspect.signature(method).parameters.values()}
    request_model = create_model("NodeFailurePolicyRequest", **fields)
    request = request_model.model_validate_json(json.dumps({
      "actor": {"account_id": "initial"}, "tenant_id": self.tenant_id,
      "node_failure_policy": "continue",
    }))
    result = method(**request.model_dump())
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"]["nodeFailurePolicy"], "continue")
    self.assertIs(result["data"]["canUpdateNodeFailurePolicy"], True)
    self.assertIs(result["data"]["canUpdateAllowPentester"], False)
    self.assertEqual(result["data"]["nodeFailurePolicyChangedBy"], "initial")
    self.assertEqual(self.plugin.get_tenant({"account_id": "initial"}, self.tenant_id)["data"],
                     result["data"])
    self.assertEqual(self.plugin.update_tenant_allow_pentester(
      {"account_id": "initial"}, self.tenant_id, True)["status_code"], 403)

  def test_json_types_are_not_coerced_to_a_valid_policy(self):
    method = self.plugin.update_tenant_node_failure_policy
    fields = {p.name: (p.annotation, p.default) for p in inspect.signature(method).parameters.values()}
    request_model = create_model("InvalidNodeFailurePolicyRequest", **fields)
    for value in (None, True, False, 0, 1, [], {}, ["stop"], "STOP", " continue ", ""):
      with self.subTest(value=value):
        request = request_model.model_validate_json(json.dumps({
          "actor": self.creator, "tenant_id": self.tenant_id, "node_failure_policy": value,
        }))
        before = len(self.store.writes)
        self.assertEqual(method(**request.model_dump())["status_code"], 400)
        self.assertEqual(len(self.store.writes), before)
    request = request_model.model_validate_json(json.dumps({
      "actor": self.creator, "tenant_id": self.tenant_id,
    }))
    self.assertEqual(method(**request.model_dump())["status_code"], 400)

  def test_missing_namespace_never_accesses_storage(self):
    def forbidden_storage(**kwargs):
      raise AssertionError("An unbound namespace must not access storage")
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, forbidden_storage)
    for namespace in (None, " "):
      with self.subTest(namespace=namespace):
        self.plugin.cfg_tenancy_namespace = namespace
        result = self.plugin.update_tenant_node_failure_policy(
          actor=self.creator, tenant_id=self.tenant_id, node_failure_policy="continue")
        self.assertEqual(result["status_code"], 503)
        self.assertIs(result["success"], False)


if __name__ == "__main__":
  unittest.main()
