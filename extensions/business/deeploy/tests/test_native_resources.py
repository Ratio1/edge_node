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

  def test_legacy_create_recovers_the_paid_worker_request_when_absent(self):
    inputs = self.inputs({"cpu": 3, "memory": "10g"})
    del inputs["node_res_req"]
    self.assertTrue(self.accept(inputs))  # N-ENTRY has 10 GiB available to one container.
    inputs.plugins[0]["CONTAINER_RESOURCES"]["memory"] = "11g"
    with self.assertRaisesRegex(ValueError, "worker tier"):
      self.accept(inputs)
    inputs["node_res_req"] = {"cpu": 3}  # Omitting just RAM inherits the same ceiling.
    with self.assertRaisesRegex(ValueError, "worker tier"):
      self.accept(inputs)
    inputs["node_res_req"] = "invalid"
    with self.assertRaisesRegex(ValueError, "must be a dictionary"):
      self.accept(inputs)

  def test_existing_full_tier_per_container_is_supported(self):
    inputs = self.inputs({"cpu": 3, "memory": "10g", "storage": "0g"})
    inputs.plugins.append(make_plugin_entry("WORKER_APP_RUNNER", CONTAINER_RESOURCES={"cpu": 3, "memory": "10g"}))
    inputs.plugins.append(make_plugin_entry("IN_PROCESS"))
    self.assertTrue(self.accept(inputs))

  def test_legacy_volume_definition_uses_bytes_and_optional_allocation_uses_mib(self):
    from extensions.business.container_apps.fixed_volume import _parse_size_to_bytes
    from extensions.business.deeploy.container_allocations import allocated_resources
    for saved_size in ("16777216", 16777216, "16M"):
      with self.subTest(saved_size=saved_size):
        inputs = self.inputs({"cpu": 1, "memory": "512m"}, saved_size)
        row = inputs.plugins[0]
        self.assertTrue(self.accept(inputs))
        self.assertEqual(_parse_size_to_bytes(str(saved_size)), 16 * 1024 ** 2)  # Runtime image size.
        self.assertEqual(allocated_resources(row, native=True).storage, 16 * 1024 ** 2)
        self.assertEqual(self.plugin._aggregate_container_resources(inputs)["storage"], "16m")
        row["CONTAINER_RESOURCES"]["storage"] = 16  # The bare budget retains its historical MiB unit.
        self.assertTrue(self.accept(inputs))
        self.assertEqual(allocated_resources(row, native=True).storage, 16 * 1024 ** 2)
        self.assertEqual(row["FIXED_SIZE_VOLUMES"]["cache"]["SIZE"], saved_size)

  def test_native_placement_counts_docker_units_and_fractional_limits(self):
    inputs = self.inputs({"cpu": "0.125", "memory": "0.5GB", "storage": "512KB"})
    self.assertTrue(self.accept(inputs))
    self.assertEqual(self.plugin._aggregate_container_resources(inputs),
                     {"cpu": 0.125, "memory": "512m", "storage": "0.5m"})
