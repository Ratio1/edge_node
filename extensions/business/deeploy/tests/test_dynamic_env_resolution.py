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

  def test_translate_dynamic_env_ui_keeps_explicit_dynamic_env_precedence(self):
    plugin = make_deeploy_plugin()
    translated = plugin._translate_dynamic_env_ui_in_instance_payload({
      "DYNAMIC_ENV": {
        "API_HOST": [{"type": "host_ip"}]
      },
      "DYNAMIC_ENV_UI": {
        "API_HOST": [{"source": "container_ip", "provider": "backend"}]
      },
    })

    self.assertEqual(translated["DYNAMIC_ENV"], {
      "API_HOST": [{"type": "host_ip"}]
    })
    self.assertNotIn("DYNAMIC_ENV_UI", translated)

  def test_translate_dynamic_env_ui_rejects_missing_container_provider(self):
    plugin = make_deeploy_plugin()

    with self.assertRaisesRegex(ValueError, "requires a provider"):
      plugin._compile_dynamic_env_ui({
        "API_HOST": [{"source": "container_ip"}]
      })

  def test_compile_dynamic_env_ui_supports_plugin_value(self):
    plugin = make_deeploy_plugin()

    compiled = plugin._compile_dynamic_env_ui({
      "UPSTREAM_PORT": [
        {"source": "plugin_value", "provider": "native-agent", "key": "PORT"}
      ]
    })

    self.assertEqual(compiled, {
      "UPSTREAM_PORT": [
        {"type": "shmem", "path": ["native-agent", "PORT"]}
      ]
    })

  def test_compile_dynamic_env_ui_rejects_plugin_value_without_provider(self):
    plugin = make_deeploy_plugin()

    with self.assertRaisesRegex(ValueError, "plugin_value requires a provider"):
      plugin._compile_dynamic_env_ui({
        "UPSTREAM_PORT": [{"source": "plugin_value", "key": "PORT"}]
      })

  def test_compile_dynamic_env_ui_rejects_plugin_value_without_key(self):
    plugin = make_deeploy_plugin()

    with self.assertRaisesRegex(ValueError, "plugin_value requires a key"):
      plugin._compile_dynamic_env_ui({
        "UPSTREAM_PORT": [{"source": "plugin_value", "provider": "native-agent"}]
      })


if __name__ == "__main__":
  unittest.main()
