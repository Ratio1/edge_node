"""Exercise Native resource admission through the payment and placement helpers."""
import unittest

from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs, make_plugin_entry
from extensions.business.deeploy.tests.test_stack_resources import _FakeBlockchain


class NativeResourceTests(unittest.TestCase):
  def setUp(self):
    self.plugin = make_deeploy_plugin()
    self.plugin.bc = _FakeBlockchain(job_type=16)

  def inputs(self, resources, reservation=None):
    row = make_plugin_entry("CONTAINER_APP_RUNNER", CONTAINER_RESOURCES=resources)
    if reservation:
      row["FIXED_SIZE_VOLUMES"] = {"cache": {"SIZE": reservation, "MOUNTING_POINT": "/cache"}}
    return make_inputs(job_id=7, job_app_type="native", node_res_req={"cpu": 3, "memory": "10g"}, plugins=[row])

  def accept(self, inputs):
    return self.plugin.deeploy_check_payment_and_job_owner(inputs, "0xowner", is_create=True)

  def test_individual_paid_caps_and_native_storage_floor(self):
    values = {"cpu": 2.5, "memory": "512m", "storage": "1g", "ports": {"main": 8080}}
    inputs = self.inputs(values, "1g")
    self.assertTrue(self.accept(inputs))
    self.assertEqual(self.plugin._aggregate_container_resources(inputs)["storage"], "1024m")
    self.assertEqual(inputs.plugins[0]["CONTAINER_RESOURCES"], values)
    del inputs.plugins[0]["CONTAINER_RESOURCES"]["storage"]
    self.assertEqual(self.plugin._aggregate_container_resources(inputs)["storage"], "1024m")
    inputs.plugins[0]["CONTAINER_RESOURCES"]["storage"] = "0g"
    with self.assertRaisesRegex(ValueError, "Volume Storage"):
      self.accept(inputs)

  def test_new_native_caps_must_be_finite_positive_and_within_worker(self):
    for key, value in (("cpu", float("nan")), ("cpu", "Infinity"), ("cpu", -1), ("cpu", 0),
                       ("cpu", True), ("cpu", 3.01), ("memory", "bad"), ("memory", "0g"),
                       ("memory", "-1g"), ("memory", "11g"), ("storage", "malformed")):
      with self.subTest(key=key, value=value), self.assertRaises(ValueError):
        self.accept(self.inputs({"cpu": 3, "memory": "10g", key: value}))

  def test_existing_full_tier_per_container_is_supported(self):
    inputs = self.inputs({"cpu": 3, "memory": "10g", "storage": "0g"})
    inputs.plugins.append(make_plugin_entry("WORKER_APP_RUNNER", CONTAINER_RESOURCES={"cpu": 3, "memory": "10g"}))
    inputs.plugins.append(make_plugin_entry("IN_PROCESS"))
    self.assertTrue(self.accept(inputs))
