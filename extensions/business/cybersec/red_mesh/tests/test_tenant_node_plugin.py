"""Assignment APIs through the real plugin, identity and administration adapters."""
import inspect
import json
import unittest
from unittest.mock import PropertyMock, patch
from uuid import uuid4

from pydantic import create_model

from .test_tenant_administration import FakeAdministrationStore


class TestTenantNodePlugin(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    environment = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    environment.start()
    self.addCleanup(environment.stop)
    self.storage = FakeAdministrationStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenant_administration_enabled = True
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.cfg_chainstore_peers = ["Node-A", "Node-B"]
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.storage, name))
    self.actor = {"account_id": "creator"}
    self.tenant = self.create_tenant("one")

  def create_tenant(self, domain):
    request = str(uuid4())
    # RM-083: an account belongs to one tenant, so each further tenant gets its own initial admin.
    admin = "initial" if domain == "one" else f"initial-{domain}"
    if admin != "initial":
      self.storage.account(admin)
    result = self.plugin.prepare_tenant(self.actor, request, domain, domain, admin)
    self.assertTrue(result["success"], result)
    tenant = result["data"]["tenantId"]
    self.storage.grant(admin, tenant)
    self.assertTrue(self.plugin.activate_tenant(self.actor, request)["success"])
    return tenant

  def request_model(self):
    # The core template copies these exact endpoint annotations/defaults into Pydantic.
    fields = {parameter.name: (parameter.annotation, parameter.default)
              for parameter in inspect.signature(self.plugin.set_tenant_node_assignment).parameters.values()}
    return create_model("TenantNodeAssignmentRequest", **fields)

  def test_json_mutation_is_visible_through_the_tenant_read_endpoint(self):
    request = self.request_model().model_validate_json(json.dumps({
      "actor": self.actor, "tenant_id": self.tenant, "node_address": "Node-A", "active": True,
    }))
    result = self.plugin.set_tenant_node_assignment(**request.model_dump())
    self.assertEqual(result, {"success": True, "status_code": 200, "data": {
      "tenantId": self.tenant, "nodeAddress": "Node-A", "active": True,
    }})
    self.assertEqual(self.plugin.get_tenant_nodes({"account_id": "initial"}, self.tenant)["data"], {
      "tenantId": self.tenant, "nodes": [{"nodeAddress": "Node-A"}], "canManageAssignments": False,
    })

  def test_generated_json_model_does_not_coerce_assignment_input(self):
    model = self.request_model()
    self.plugin.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)
    values = (True, False, 0, 1, 0.0, 1.0, "true", "false", "1", "yes", None, [], {})
    for value in values:
      with self.subTest(active=value):
        request = model.model_validate_json(json.dumps({
          "actor": self.actor, "tenant_id": self.tenant, "node_address": "Node-A", "active": value,
        }))
        before = len(self.storage.writes)
        result = self.plugin.set_tenant_node_assignment(**request.model_dump())
        self.assertEqual(result["status_code"], 200 if type(value) is bool else 400, result)
        if type(value) is not bool:
          self.assertEqual(len(self.storage.writes), before)
    for address in (None, 17, True, [], {}, "", " Node-A", "Node\ufeffA", "a" * 257):
      with self.subTest(address=address):
        request = model.model_validate_json(json.dumps({
          "actor": self.actor, "tenant_id": self.tenant, "node_address": address, "active": True,
        }))
        before = len(self.storage.writes)
        self.assertEqual(self.plugin.set_tenant_node_assignment(**request.model_dump())["status_code"], 400)
        self.assertEqual(len(self.storage.writes), before)
    for missing in ("active", "node_address"):
      body = {"actor": self.actor, "tenant_id": self.tenant, "node_address": "Node-A", "active": True}
      del body[missing]
      request = model.model_validate_json(json.dumps(body))
      self.assertEqual(self.plugin.set_tenant_node_assignment(**request.model_dump())["status_code"], 400)

  def test_plugin_rechecks_stored_roles_and_scope_before_configuration_access(self):
    foreign = self.create_tenant("two")
    # RM-083: a tenant-scoped Super-Tenant Admin is not a valid account; only full-portfolio is.
    self.storage.account("platform", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.assertTrue(self.plugin.set_tenant_node_assignment({"account_id": "platform"}, self.tenant, "Node-A", True)["success"])
    self.storage.account("scoped", memberships=[{"role": "super_tenant_admin", "tenant_id": self.tenant}])
    denied = [({"account_id": "scoped"}, self.tenant, 404), ({"account_id": "scoped"}, foreign, 404)]
    for role in ("super_pentester", "tenant_admin", "tenant_pentester", "tenant_user"):
      self.storage.account(role, memberships=[{"role": role, "tenant_id": self.tenant}])
      denied.append(({"account_id": role, "role": "super_tenant_admin",
                      "tenant_memberships": [{"role": "super_tenant_admin", "tenant_id": None}]},
                     self.tenant, 403))
    self.storage.account("mixed", memberships=[{"role": "tenant_user", "tenant_id": self.tenant},
                                              {"role": "super_tenant_admin", "tenant_id": None}])
    denied.append(({"account_id": "mixed"}, self.tenant, 404))
    with patch.object(self.Plugin, "cfg_chainstore_peers", new_callable=PropertyMock,
                      create=True, side_effect=RuntimeError("private configuration")) as config:
      for actor, tenant, status in denied:
        with self.subTest(actor=actor["account_id"], tenant=tenant):
          before = len(self.storage.writes)
          for active in (True, False):
            result = self.plugin.set_tenant_node_assignment(actor, tenant, "Node-A", active)
            self.assertEqual(result["status_code"], status, result)
          self.assertEqual(len(self.storage.writes), before)
          config.assert_not_called()
      self.storage.account("platform", memberships=[])
      platform = {"account_id": "platform"}
      self.assertEqual(self.plugin.set_tenant_node_assignment(platform, self.tenant, "Node-A", True)["status_code"], 404)
      self.assertEqual(self.plugin.get_tenant_nodes(platform, self.tenant)["status_code"], 404)
      config.assert_not_called()

  def test_reads_and_removal_do_not_evaluate_plugin_peer_property(self):
    self.plugin.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True)
    with patch.object(self.Plugin, "cfg_chainstore_peers", new_callable=PropertyMock,
                      create=True, side_effect=RuntimeError("private configuration")) as config:
      self.assertTrue(self.plugin.get_tenant_nodes(self.actor, self.tenant)["success"])
      self.assertTrue(self.plugin.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", False)["success"])
      self.assertTrue(self.plugin.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", False)["success"])
      config.assert_not_called()
      self.assertEqual(self.plugin.set_tenant_node_assignment(self.actor, self.tenant, "Node-A", True), {
        "success": False, "status": "error", "status_code": 503, "error": "unavailable",
      })
      config.assert_called_once()
