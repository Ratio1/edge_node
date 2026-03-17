import unittest

from extensions.business.deeploy.tests.support import make_deeploy_plugin


class DeeployDynamicEnvResolutionTests(unittest.TestCase):

  def test_has_shmem_dynamic_env_detects_explicit_shmem_entries(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
            "DYNAMIC_ENV": {
              "API_URL": [
                {"type": "static", "value": "http://"},
                {"type": "shmem", "path": ["provider", "CONTAINER_IP"]},
              ]
            },
          }
        ],
      }
    ]

    self.assertTrue(plugin._has_shmem_dynamic_env(plugins))

  def test_resolve_shmem_references_rewrites_paths_and_sets_semaphores(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"type": "shmem", "path": ["provider-ui-name", "CONTAINER_IP"]}
              ]
            },
          }
        ],
      },
    ]
    name_to_instance = {
      "provider-ui-name": {"instance_id": "native-1", "signature": "A_SIMPLE_PLUGIN"}
    }

    resolved = plugin._resolve_shmem_references(plugins, name_to_instance, "app-123")

    provider_instance = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    consumer_instance = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    sem_key = "app-123__native-1"

    self.assertEqual(
      consumer_instance["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      [sem_key, "CONTAINER_IP"],
    )
    self.assertEqual(provider_instance["SEMAPHORE"], sem_key)
    self.assertEqual(consumer_instance["SEMAPHORED_KEYS"], [sem_key])


if __name__ == "__main__":
  unittest.main()
