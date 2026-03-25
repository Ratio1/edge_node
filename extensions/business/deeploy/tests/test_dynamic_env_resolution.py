import unittest

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs, make_plugin_entry


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

  def test_resolve_shmem_in_plugins_rewrites_paths_and_sets_semaphores(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "my-native",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "my-frontend",
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"type": "shmem", "path": ["my-native", "CONTAINER_IP"]}
              ]
            },
          }
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-123")

    provider_instance = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    consumer_instance = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    # Key is app_id__plugin_name (not sanitized, not using instance_id)
    self.assertEqual(provider_instance["SEMAPHORE"], "app-123__my-native")
    self.assertEqual(
      consumer_instance["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      ["app-123__my-native", "CONTAINER_IP"],
    )
    self.assertEqual(consumer_instance["SEMAPHORED_KEYS"], ["app-123__my-native"])

  def test_resolve_shmem_in_plugins_rejects_unknown_provider(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"type": "shmem", "path": ["nonexistent", "PORT"]}
              ]
            },
          }
        ],
      },
    ]

    with self.assertRaisesRegex(ValueError, "unknown plugin 'nonexistent'"):
      plugin._resolve_shmem_in_plugins(plugins, "app-1")

  def test_resolve_shmem_in_plugins_rejects_duplicate_names(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1", DEEPLOY_KEYS.PLUGIN_NAME: "dup"},
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-2", DEEPLOY_KEYS.PLUGIN_NAME: "dup"},
        ],
      },
    ]

    with self.assertRaisesRegex(ValueError, "Duplicate plugin_name"):
      plugin._resolve_shmem_in_plugins(plugins, "app-1")

  def test_resolve_shmem_in_plugins_noop_without_plugin_names(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1", "PORT": 3000}
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-1")

    instance = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertNotIn("SEMAPHORE", instance)

  def test_resolve_shmem_in_plugins_sets_semaphore_on_all_named_instances(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "n1", DEEPLOY_KEYS.PLUGIN_NAME: "alpha"},
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "c1", DEEPLOY_KEYS.PLUGIN_NAME: "beta"},
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "job-1")

    self.assertEqual(resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]["SEMAPHORE"], "job-1__alpha")
    self.assertEqual(resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]["SEMAPHORE"], "job-1__beta")


if __name__ == "__main__":
  unittest.main()
