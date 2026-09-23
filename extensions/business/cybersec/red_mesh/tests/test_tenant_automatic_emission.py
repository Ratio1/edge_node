"""Automatic SOC emission at finalization resolves the job's tenant (RM-081 Phase 4)."""
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.services import event_hooks
from extensions.business.cybersec.red_mesh.services.config import (
  TENANT_INTEGRATION_NOT_CONFIGURED)
from .test_execution_binding_models import binding_payload


class Owner:
  cfg_instance_id = "pdev5"

  def __init__(self, blocks=None, records=None):
    self.config_data = dict(blocks or {})
    self._records = dict(records or {})
    self.status_writes = []

  def _get_tenant_integration_config(self, tenant_id, integration_id):
    return self._records.get((tenant_id, integration_id))

  def chainstore_hget(self, *, hkey, key):
    return None

  def chainstore_hset(self, *, hkey, key, value, **kwargs):
    self.status_writes.append(hkey)
    return True


NODE = {"EVENT_EXPORT": {"ENABLED": True},
        "WAZUH_EXPORT": {"ENABLED": True, "MODE": "http", "HTTP_URL": "https://node.example",
                         "TOKEN": "node"}}
EVENT = {"event_id": "ev-1", "dedupe_key": "dk-1"}


class TestAutomaticEmissionTenant(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"REDMESH_EVENT_HMAC_SECRET": "secret"})
    env.start()
    self.addCleanup(env.stop)
    self.binding = binding_payload()
    self.tenant = self.binding["tenant_id"]

  def emit(self, owner, job_specs):
    # The delivery transport itself is not under test here; which tenant reaches it is.
    with patch.object(event_hooks, "deliver_redmesh_event") as deliver:
      deliver.return_value = {"status": "sent", "integration_id": "wazuh",
                              "event_id": EVENT["event_id"], "dedupe_key": EVENT["dedupe_key"]}
      result = event_hooks.emit_redmesh_event(owner, job_specs, dict(EVENT))
    return result, deliver

  def test_a_bound_job_delivers_to_its_own_tenant(self):
    owner = Owner(NODE, {(self.tenant, "wazuh"): {"config": {"ENABLED": True}}})
    job_specs = {"job_id": "job-1", "execution_binding": self.binding}
    result, deliver = self.emit(owner, job_specs)
    self.assertEqual(result["status"], "sent")
    self.assertEqual(deliver.call_args.kwargs["tenant_id"], self.tenant)

  def test_a_bound_job_whose_tenant_configured_nothing_never_delivers(self):
    owner = Owner(NODE)
    job_specs = {"job_id": "job-1", "execution_binding": self.binding}
    result, deliver = self.emit(owner, job_specs)
    self.assertEqual(result["status"], "skipped")
    self.assertEqual(result["error"], TENANT_INTEGRATION_NOT_CONFIGURED)
    deliver.assert_not_called()

  def test_an_unconfigured_tenant_is_configuration_state_not_a_delivery_failure(self):
    # Recording it as a failure would accrue a failure signature and eventually a cooldown for
    # something that never attempted to send.
    owner = Owner(NODE)
    job_specs = {"job_id": "job-1", "execution_binding": self.binding}
    self.emit(owner, job_specs)
    status = job_specs["soc_event_status"]
    self.assertEqual(status["integration_status"], "not_configured")
    self.assertIsNone(status.get("last_failure_signature"))

  def test_a_legacy_unbound_job_still_delivers_on_the_node(self):
    owner = Owner(NODE)
    result, deliver = self.emit(owner, {"job_id": "job-1"})
    self.assertEqual(result["status"], "sent")
    self.assertIsNone(deliver.call_args.kwargs["tenant_id"])

  def test_two_tenants_reach_two_destinations(self):
    other = binding_payload()
    owner = Owner(NODE, {
      (self.tenant, "wazuh"): {"config": {"ENABLED": True, "HTTP_URL": "https://a.example"}},
      (other["tenant_id"], "wazuh"): {"config": {"ENABLED": True, "HTTP_URL": "https://b.example"}}})
    _, first = self.emit(owner, {"job_id": "j1", "execution_binding": self.binding})
    _, second = self.emit(owner, {"job_id": "j2", "execution_binding": other})
    self.assertEqual(first.call_args.kwargs["tenant_id"], self.tenant)
    self.assertEqual(second.call_args.kwargs["tenant_id"], other["tenant_id"])

  def test_a_tenant_that_disabled_wazuh_is_skipped_not_sent_on_the_nodes(self):
    owner = Owner(NODE, {(self.tenant, "wazuh"): {"config": {"ENABLED": False}}})
    result, deliver = self.emit(owner, {"job_id": "j", "execution_binding": self.binding})
    self.assertEqual(result["status"], "skipped")
    self.assertEqual(result["error"], "wazuh_disabled")
    deliver.assert_not_called()


if __name__ == "__main__":
  unittest.main()
