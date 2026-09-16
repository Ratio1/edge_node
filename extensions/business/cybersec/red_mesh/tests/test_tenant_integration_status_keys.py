"""Per-tenant integration status and history keys (RM-081 Phase 2).

The point of these tests is what does NOT move: existing deployment history keeps its key, and the
three node-level ids keep reporting the node's record even under a tenant-scoped call.
"""
import unittest

from extensions.business.cybersec.red_mesh.services import integration_status, soc_export_policy
from extensions.business.cybersec.red_mesh.tenancy.integrations import (
  NODE_LEVEL_INTEGRATION_IDS, TENANT_INTEGRATION_IDS, status_tenant)


class FakeOwner:
  cfg_instance_id = "pdev5"

  def __init__(self):
    self.hsets = {}

  def chainstore_hget(self, *, hkey, key):
    return self.hsets.get(hkey, {}).get(key)

  def chainstore_hset(self, *, hkey, key, value, **kwargs):
    self.hsets.setdefault(hkey, {})[key] = value
    return True


class TestStatusTenantSplit(unittest.TestCase):
  def test_only_the_four_tenant_ids_scope(self):
    for integration_id in TENANT_INTEGRATION_IDS:
      self.assertEqual(status_tenant(integration_id, "tn_a"), "tn_a")
    for integration_id in NODE_LEVEL_INTEGRATION_IDS:
      self.assertIsNone(status_tenant(integration_id, "tn_a"))

  def test_an_unscoped_call_is_unscoped_for_every_id(self):
    for integration_id in (*TENANT_INTEGRATION_IDS, *NODE_LEVEL_INTEGRATION_IDS):
      self.assertIsNone(status_tenant(integration_id, None))


class TestStatusHkey(unittest.TestCase):
  def test_the_node_key_is_byte_for_byte_what_it_was(self):
    owner = FakeOwner()
    self.assertEqual(integration_status._status_hkey(owner), "pdev5:integrations")
    self.assertEqual(soc_export_policy._status_hkey(owner), "pdev5:integrations")

  def test_both_modules_agree_on_the_tenant_key(self):
    owner = FakeOwner()
    self.assertEqual(integration_status._status_hkey(owner, "tn_a"),
                     soc_export_policy._status_hkey(owner, "tn_a"))
    self.assertEqual(integration_status._status_hkey(owner, "tn_a"), "pdev5:integrations:tn_a")

  def test_a_tenant_that_could_forge_a_key_is_refused(self):
    owner = FakeOwner()
    for bad in ("", "   ", "tn_a:integrations", ":", 7, b"tn_a"):
      for module in (integration_status, soc_export_policy):
        with self.assertRaises(ValueError, msg=(module.__name__, bad)):
          module._status_hkey(owner, bad)


class TestRecordedHistoryIsolation(unittest.TestCase):
  def setUp(self):
    self.owner = FakeOwner()

  def test_two_tenants_never_see_each_other_or_the_node(self):
    integration_status.record_integration_status(
      self.owner, "wazuh", outcome="success", event_id="node-event")
    integration_status.record_integration_status(
      self.owner, "wazuh", outcome="success", event_id="a-event", tenant_id="tn_a")
    integration_status.record_integration_status(
      self.owner, "wazuh", outcome="failure", error_class="connect_failed", tenant_id="tn_b")

    node = integration_status._load_status_record(self.owner, "wazuh")
    first = integration_status._load_status_record(self.owner, "wazuh", "tn_a")
    second = integration_status._load_status_record(self.owner, "wazuh", "tn_b")
    self.assertEqual(node["last_event_id"], "node-event")
    self.assertEqual(first["last_event_id"], "a-event")
    self.assertNotIn("last_event_id", second)
    self.assertEqual(second["last_error_class"], "connect_failed")
    self.assertIsNone(first["last_error_class"])
    self.assertEqual(set(self.owner.hsets),
                     {"pdev5:integrations", "pdev5:integrations:tn_a", "pdev5:integrations:tn_b"})

  def test_a_node_level_id_writes_to_the_node_key_even_under_a_tenant(self):
    for integration_id in NODE_LEVEL_INTEGRATION_IDS:
      integration_status.record_integration_status(
        self.owner, integration_id, outcome="success", event_id="e", tenant_id="tn_a")
    self.assertEqual(set(self.owner.hsets), {"pdev5:integrations"})
    self.assertEqual(set(self.owner.hsets["pdev5:integrations"]),
                     set(NODE_LEVEL_INTEGRATION_IDS))
    for integration_id in NODE_LEVEL_INTEGRATION_IDS:
      self.assertEqual(
        integration_status._load_status_record(self.owner, integration_id, "tn_a"),
        integration_status._load_status_record(self.owner, integration_id))

  def test_existing_deployment_history_is_still_read_by_an_unscoped_call(self):
    self.owner.hsets["pdev5:integrations"] = {"wazuh": {"last_event_id": "pre-existing"}}
    self.assertEqual(
      integration_status._load_status_record(self.owner, "wazuh")["last_event_id"], "pre-existing")
    self.assertEqual(
      soc_export_policy.load_integration_status_record(self.owner, "wazuh")["last_event_id"],
      "pre-existing")
    # A tenant starts empty rather than inheriting the node's history.
    self.assertEqual(integration_status._load_status_record(self.owner, "wazuh", "tn_a"), {})

  def test_cooldown_is_read_from_the_tenant_that_earned_it(self):
    # "timeout" is a triggering class; SOC_DELIVERY_COOLDOWN_ERROR is the code the cooldown is
    # reported under, not one that causes it.
    self.assertIn("timeout", soc_export_policy.SOC_COOLDOWN_ERROR_CLASSES)
    for _ in range(2):
      integration_status.record_integration_status(
        self.owner, "wazuh", outcome="failure",
        error_class="timeout", tenant_id="tn_a")
    self.assertIsNotNone(soc_export_policy.current_integration_cooldown(
      self.owner, "wazuh", "tn_a"))
    self.assertIsNone(soc_export_policy.current_integration_cooldown(self.owner, "wazuh", "tn_b"))
    self.assertIsNone(soc_export_policy.current_integration_cooldown(self.owner, "wazuh"))

  def test_the_aggregate_history_view_scopes_with_its_caller(self):
    integration_status.record_integration_status(
      self.owner, "wazuh", outcome="success", event_id="a-event", tenant_id="tn_a")
    scoped = integration_status.get_integration_status(self.owner, "tn_a")["integrations"]
    unscoped = integration_status.get_integration_status(self.owner)["integrations"]
    self.assertEqual(scoped["wazuh"].get("last_event_id"), "a-event")
    self.assertIsNone(unscoped["wazuh"].get("last_event_id"))
    # Criterion 4: the node-level three read identically either way.
    for integration_id in NODE_LEVEL_INTEGRATION_IDS:
      self.assertEqual(scoped[integration_id], unscoped[integration_id])


if __name__ == "__main__":
  unittest.main()
