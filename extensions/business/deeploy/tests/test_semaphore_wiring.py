import unittest

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, JOB_APP_TYPES
from extensions.business.deeploy.tests.support import make_deeploy_plugin


class DeeploySemaphoreWiringTests(unittest.TestCase):

  def test_autowire_native_container_semaphore_sets_provider_and_consumer_keys(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1"}
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1"}
        ],
      },
    ]

    wired = plugin._autowire_native_container_semaphore("job-001", plugins, JOB_APP_TYPES.NATIVE)

    native_instance = wired[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    car_instance = wired[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    # Without plugin_name, falls back to sanitize_name(app_id__instance_id)
    self.assertEqual(native_instance["SEMAPHORE"], "job-001__native-1")
    self.assertEqual(car_instance["SEMAPHORED_KEYS"], ["job-001__native-1"])

  def test_autowire_prefers_plugin_name_over_instance_id(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "my-agent",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1"}
        ],
      },
    ]

    wired = plugin._autowire_native_container_semaphore("job-001", plugins, JOB_APP_TYPES.NATIVE)

    native_instance = wired[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    car_instance = wired[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    # With plugin_name, uses app_id__plugin_name (no sanitize_name)
    self.assertEqual(native_instance["SEMAPHORE"], "job-001__my-agent")
    self.assertEqual(car_instance["SEMAPHORED_KEYS"], ["job-001__my-agent"])

  def test_autowire_skips_when_explicit_shmem_dynamic_env_exists(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1"}
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
            "DYNAMIC_ENV": {
              "API_HOST": [{"type": "shmem", "path": ["provider", "CONTAINER_IP"]}]
            },
          }
        ],
      },
    ]

    wired = plugin._autowire_native_container_semaphore("job-001", plugins, JOB_APP_TYPES.NATIVE)

    native_instance = wired[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    car_instance = wired[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    self.assertNotIn("SEMAPHORE", native_instance)
    self.assertNotIn("SEMAPHORED_KEYS", car_instance)

  def test_autowire_skips_when_manual_semaphore_config_already_present(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            "SEMAPHORE": "manual-key",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1"}
        ],
      },
    ]

    wired = plugin._autowire_native_container_semaphore("job-001", plugins, JOB_APP_TYPES.NATIVE)

    native_instance = wired[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    car_instance = wired[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    self.assertEqual(native_instance["SEMAPHORE"], "manual-key")
    self.assertNotIn("SEMAPHORED_KEYS", car_instance)


if __name__ == "__main__":
  unittest.main()
