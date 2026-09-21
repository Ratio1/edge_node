"""A bound job exports to its own tenant, or nowhere (RM-081 Phase 3b)."""
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.services.config import (
  TENANT_INTEGRATION_NOT_CONFIGURED, tenant_export_binding)
from extensions.business.cybersec.red_mesh.services.soc_export_policy import (
  required_soc_launch_error)
from extensions.business.cybersec.red_mesh.tenancy.execution import context_tenant_id
from .test_execution_binding_models import binding_payload


# Reuse the canonical fixture rather than hand-rolling a binding: it carries the real
# canonical_digest, so this file stays correct if the binding shape changes.
BINDING = binding_payload()
TENANT = BINDING["tenant_id"]


class Owner:
  def __init__(self, blocks=None, records=None):
    self.config_data = dict(blocks or {})
    self._records = dict(records or {})

  def _get_tenant_integration_config(self, tenant_id, integration_id):
    return self._records.get((tenant_id, integration_id))


def record(config=None):
  return {"config": dict(config or {"ENABLED": True})}


class FakeContext:
  def __init__(self, facts):
    self._facts = facts

  def to_dict(self):
    return dict(self._facts)


class TestExportBinding(unittest.TestCase):
  def test_an_unbound_job_is_legacy_and_uses_the_node(self):
    self.assertEqual(tenant_export_binding(Owner(), {"job_id": "j"}, "misp"), (None, None))

  def test_a_bound_job_whose_tenant_configured_the_integration_resolves_it(self):
    owner = Owner(records={(TENANT, "misp"): record()})
    self.assertEqual(
      tenant_export_binding(owner, {"execution_binding": BINDING}, "misp"), (TENANT, None))

  def test_a_bound_job_whose_tenant_has_no_record_exports_nowhere(self):
    owner = Owner({"MISP_EXPORT": {"ENABLED": True, "MISP_URL": "https://node.example"}})
    self.assertEqual(tenant_export_binding(owner, {"execution_binding": BINDING}, "misp"),
                     (TENANT, TENANT_INTEGRATION_NOT_CONFIGURED))

  def test_configuring_one_integration_does_not_configure_another(self):
    owner = Owner(records={(TENANT, "misp"): record()})
    self.assertEqual(tenant_export_binding(owner, {"execution_binding": BINDING}, "taxii"),
                     (TENANT, TENANT_INTEGRATION_NOT_CONFIGURED))

  def test_another_tenants_record_is_not_this_tenants(self):
    owner = Owner(records={(binding_payload()["tenant_id"], "misp"): record()})
    self.assertEqual(tenant_export_binding(owner, {"execution_binding": BINDING}, "misp"),
                     (TENANT, TENANT_INTEGRATION_NOT_CONFIGURED))

  def test_a_malformed_binding_is_refused_rather_than_treated_as_legacy(self):
    for binding in ({"execution_binding": None}, {"execution_binding": {"tenant_id": "tn_a"}},
                    {"execution_binding": "text"}, {"execution_binding": {**BINDING, "tenant_id": ""}}):
      self.assertEqual(tenant_export_binding(Owner(), binding, "misp")[1],
                       TENANT_INTEGRATION_NOT_CONFIGURED, binding)


class TestLaunchContextTenant(unittest.TestCase):
  def test_no_context_is_a_legacy_launch(self):
    self.assertIsNone(context_tenant_id(None))

  def test_a_context_yields_its_tenant(self):
    self.assertEqual(context_tenant_id(FakeContext({"tenant_id": "tn_a"})), "tn_a")

  def test_a_context_that_cannot_be_read_never_raises_at_the_gate(self):
    class Broken:
      def to_dict(self):
        raise RuntimeError("unreadable")
    self.assertIsNone(context_tenant_id(Broken()))
    self.assertIsNone(context_tenant_id(FakeContext({"tenant_id": "  "})))


class TestRequiredSocLaunchGate(unittest.TestCase):
  def setUp(self):
    # Without the signing secret every readiness check reports missing_hmac_secret, which would
    # mask the destination differences these tests are about.
    env = patch.dict("os.environ", {"REDMESH_EVENT_HMAC_SECRET": "secret"})
    env.start()
    self.addCleanup(env.stop)

  def node(self, **wazuh):
    return {"EVENT_EXPORT": {"ENABLED": True},
            "WAZUH_EXPORT": {"ENABLED": True, "MODE": "http",
                             "HTTP_URL": "https://node-soc.example", "TOKEN": "node", **wazuh}}

  def test_nothing_required_gates_nothing(self):
    owner = Owner(self.node(IS_REQUIRED=False))
    self.assertIsNone(required_soc_launch_error(owner))
    self.assertIsNone(required_soc_launch_error(owner, "tn_a"))

  def test_a_legacy_launch_still_gates_on_the_node(self):
    ready = Owner(self.node(IS_REQUIRED=True))
    self.assertIsNone(required_soc_launch_error(ready))
    unready = Owner(self.node(IS_REQUIRED=True, HTTP_URL="", TOKEN=""))
    self.assertEqual(required_soc_launch_error(unready)["error"], "soc_export_required_unavailable")

  def test_a_bound_launch_is_refused_when_its_tenant_configured_nothing(self):
    # The node's SOC is healthy and required. That must not admit a tenant that has configured
    # nothing: passing here would mean launching on another party's readiness.
    owner = Owner(self.node(IS_REQUIRED=True))
    error = required_soc_launch_error(owner, "tn_a")
    self.assertEqual(error["error_class"], TENANT_INTEGRATION_NOT_CONFIGURED)
    self.assertTrue(error["required"])

  def test_a_bound_launch_passes_on_its_own_ready_destination(self):
    owner = Owner(self.node(IS_REQUIRED=True), {
      ("tn_a", "wazuh"): record({"ENABLED": True, "MODE": "http",
                                 "HTTP_URL": "https://a-soc.example", "TOKEN": "a"})})
    self.assertIsNone(required_soc_launch_error(owner, "tn_a"))

  def test_a_tenant_whose_own_destination_is_unready_is_refused(self):
    owner = Owner(self.node(IS_REQUIRED=True), {
      ("tn_a", "wazuh"): record({"ENABLED": True, "MODE": "http", "HTTP_URL": "", "TOKEN": ""})})
    self.assertEqual(required_soc_launch_error(owner, "tn_a")["error"],
                     "soc_export_required_unavailable")

  def test_a_tenant_cannot_opt_out_of_a_deployment_requirement(self):
    # IS_REQUIRED is ORed across node and tenant: opting in is allowed, opting out is not.
    owner = Owner(self.node(IS_REQUIRED=True), {
      ("tn_a", "wazuh"): record({"ENABLED": True, "IS_REQUIRED": False, "MODE": "http",
                                 "HTTP_URL": "", "TOKEN": ""})})
    self.assertIsNotNone(required_soc_launch_error(owner, "tn_a"))

  def test_a_tenant_may_opt_in_when_the_deployment_does_not_require_it(self):
    owner = Owner(self.node(IS_REQUIRED=False), {
      ("tn_a", "wazuh"): record({"ENABLED": True, "IS_REQUIRED": True, "MODE": "http",
                                 "HTTP_URL": "", "TOKEN": ""})})
    self.assertIsNotNone(required_soc_launch_error(owner, "tn_a"))
    self.assertIsNone(required_soc_launch_error(owner))


if __name__ == "__main__":
  unittest.main()
