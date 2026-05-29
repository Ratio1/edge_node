import unittest

from extensions.business.deeploy.deeploy_const import (
  DEEPLOY_ERRORS,
  DEEPLOY_RESOURCES,
  JOB_APP_TYPES,
  JOB_APP_TYPES_ALL,
)
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs, make_plugin_entry


class _FakeBlockchain:
  def __init__(self, job_type=1):
    self.job_type = job_type

  def get_evm_network(self):
    return "testnet"

  def get_job_details(self, job_id):
    return {
      "id": job_id,
      "escrowOwner": "0xowner",
      "startTimestamp": None,
      "jobType": self.job_type,
    }


class DeeployStackResourceTests(unittest.TestCase):

  def test_stack_is_allowed_job_app_type(self):
    self.assertIn(JOB_APP_TYPES.STACK, JOB_APP_TYPES_ALL)

  def test_aggregate_container_resources_includes_container_and_fixed_storage(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          CONTAINER_RESOURCES={"cpu": 0.5, "memory": "512m", "storage": "4g"},
          FIXED_SIZE_VOLUMES={"data": {"SIZE": "1G", "MOUNTING_POINT": "/data"}},
        ),
        make_plugin_entry(
          "WORKER_APP_RUNNER",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "1g", "storage": "8g"},
        ),
      ]
    )

    resources = plugin._aggregate_container_resources(inputs)

    self.assertEqual(resources[DEEPLOY_RESOURCES.CPU], 1.5)
    self.assertEqual(resources[DEEPLOY_RESOURCES.MEMORY], "1536m")
    self.assertEqual(resources[DEEPLOY_RESOURCES.STORAGE], "13312m")

  def test_stack_resources_may_fit_under_paid_tier(self):
    plugin = make_deeploy_plugin()
    plugin.bc = _FakeBlockchain(job_type=1)  # ENTRY: 1 CPU, 2GB RAM, 8GB storage
    inputs = make_inputs(
      job_id=123,
      job_app_type=JOB_APP_TYPES.STACK,
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          CONTAINER_RESOURCES={"cpu": 0.5, "memory": "512m", "storage": "2g"},
        ),
        make_plugin_entry(
          "WORKER_APP_RUNNER",
          CONTAINER_RESOURCES={"cpu": 0.25, "memory": "512m", "storage": "2g"},
        ),
      ],
    )

    self.assertTrue(plugin.deeploy_check_payment_and_job_owner(inputs, "0xowner", is_create=True))

  def test_stack_resources_reject_when_over_paid_tier(self):
    plugin = make_deeploy_plugin()
    plugin.bc = _FakeBlockchain(job_type=54)  # LITE: 0.5 CPU, 1GB RAM, 4GB storage
    inputs = make_inputs(
      job_id=123,
      job_app_type=JOB_APP_TYPES.STACK,
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          CONTAINER_RESOURCES={"cpu": 0.5, "memory": "512m", "storage": "2g"},
        ),
        make_plugin_entry(
          "WORKER_APP_RUNNER",
          CONTAINER_RESOURCES={"cpu": 0.5, "memory": "512m", "storage": "2g"},
        ),
      ],
    )

    with self.assertRaisesRegex(ValueError, DEEPLOY_ERRORS.JOB_RESOURCES3):
      plugin.deeploy_check_payment_and_job_owner(inputs, "0xowner", is_create=True)


if __name__ == "__main__":
  unittest.main()
