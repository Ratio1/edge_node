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

  def test_resolve_shmem_in_plugins_rejects_malformed_shmem_path(self):
    plugin = make_deeploy_plugin()
    malformed_paths = [
      ["provider"],
      ["provider", "PORT", "extra"],
      ["provider", ""],
      ["", "PORT"],
      [123, "PORT"],
    ]

    for path in malformed_paths:
      plugins = [
        {
          plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
          plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
            {
              plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
              DEEPLOY_KEYS.PLUGIN_NAME: "provider",
            }
          ],
        },
        {
          plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
          plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
            {
              plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
              DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
              "DYNAMIC_ENV": {
                "API_HOST": [
                  {"type": "shmem", "path": path}
                ]
              },
            }
          ],
        },
      ]

      with self.assertRaisesRegex(ValueError, "DYNAMIC_ENV shmem path"):
        plugin._resolve_shmem_in_plugins(plugins, "app-1")

  def test_resolve_shmem_in_plugins_rejects_source_shmem_entries(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "provider",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"source": "shmem", "path": ["provider", "PORT"]},
              ]
            },
          }
        ],
      },
    ]

    with self.assertRaisesRegex(ValueError, "source='shmem'"):
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

  def test_resolve_shmem_in_plugins_rejects_invalid_plugin_name(self):
    plugin = make_deeploy_plugin()
    for bad_name in ["my plugin", "plugin/foo", "plugin.bar", "plugin@1"]:
      plugins = [
        {
          plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "SOME_PLUGIN",
          plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
            {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "p-1", "plugin_name": bad_name}
          ],
        },
      ]
      with self.assertRaisesRegex(ValueError, "Invalid plugin_name"):
        plugin._resolve_shmem_in_plugins(plugins, "app-1")

  def test_resolve_shmem_in_plugins_accepts_duplicate_stale_named_semaphore_with_plugin_name_consumer(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "SOME_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "p-1",
            "plugin_name": "alpha",
            "SEMAPHORE": "old-app__shared-provider",
          },
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "p-2",
            "plugin_name": "beta",
            "SEMAPHORE": "old-app__shared-provider",
          },
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "consumer-1",
            "plugin_name": "frontend",
            "DYNAMIC_ENV": {
              "API_PORT": [
                {"type": "shmem", "path": ["alpha", "PORT"]},
              ]
            },
          }
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-1")
    alpha = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    beta = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][1]
    consumer = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    self.assertEqual(alpha["SEMAPHORE"], "app-1__alpha")
    self.assertEqual(beta["SEMAPHORE"], "app-1__beta")
    self.assertEqual(
      consumer["DYNAMIC_ENV"]["API_PORT"][0]["path"],
      ["app-1__alpha", "PORT"],
    )
    self.assertEqual(consumer["SEMAPHORED_KEYS"], ["app-1__alpha"])

  def test_resolve_shmem_in_plugins_rejects_plugin_name_explicit_semaphore_ambiguity(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "named-provider",
            DEEPLOY_KEYS.PLUGIN_NAME: "shared",
          },
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "explicit-provider",
            "SEMAPHORE": "shared",
          },
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "consumer-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
            "DYNAMIC_ENV": {
              "API_PORT": [
                {"type": "shmem", "path": ["shared", "PORT"]},
              ]
            },
          }
        ],
      },
    ]

    with self.assertRaisesRegex(ValueError, "ambiguous semaphore key 'shared'"):
      plugin._resolve_shmem_in_plugins(plugins, "app-1")

  def test_resolve_shmem_in_plugins_accepts_explicit_semaphore_reference(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "NATIVE_APP",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            "SEMAPHORE": "app-1__legacy-api",
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
                {"type": "shmem", "path": ["app-1__legacy-api", "CONTAINER_IP"]}
              ]
            },
          }
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-1")

    producer = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    consumer = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(producer["SEMAPHORE"], "app-1__legacy-api")
    self.assertEqual(
      consumer["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      ["app-1__legacy-api", "CONTAINER_IP"],
    )
    self.assertEqual(consumer["SEMAPHORED_KEYS"], ["app-1__legacy-api"])

  def test_resolve_shmem_in_plugins_rejects_duplicate_explicit_semaphore_providers(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "NATIVE_APP",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            "SEMAPHORE": "shared",
          },
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-2",
            "SEMAPHORE": "shared",
          },
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
            "DYNAMIC_ENV": {
              "API_PORT": [
                {"type": "shmem", "path": ["shared", "PORT"]}
              ]
            },
          }
        ],
      },
    ]

    with self.assertRaisesRegex(ValueError, "Duplicate semaphore key"):
      plugin._resolve_shmem_in_plugins(plugins, "app-1")

  def test_validate_plugin_runtime_keys_rejects_duplicate_explicit_semaphore_without_shmem(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "NATIVE_APP",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            "SEMAPHORE": "shared",
          },
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-2",
            "SEMAPHORE": "shared",
          },
        ],
      },
    ]

    with self.assertRaisesRegex(ValueError, "Duplicate semaphore key"):
      plugin._validate_plugin_runtime_keys(plugins)

  def test_resolve_shmem_in_plugins_recomputes_named_semaphore(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "SOME_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "api-service",
            "SEMAPHORE": "stale-app-id__api-service",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "consumer",
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"type": "shmem", "path": ["api-service", "CONTAINER_IP"]}
              ]
            },
          }
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-1")
    producer = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    consumer = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    self.assertEqual(producer["SEMAPHORE"], "app-1__api-service")
    self.assertEqual(
      consumer["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      ["app-1__api-service", "CONTAINER_IP"],
    )
    self.assertEqual(consumer["SEMAPHORED_KEYS"], ["app-1__api-service"])

  def test_resolve_shmem_in_plugins_clears_stale_semaphored_keys(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "native-api",
            "SEMAPHORED_KEYS": ["obsolete-key"],
            "SEMAPHORE": "app-1__old-name",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "consumer-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
            "SEMAPHORED_KEYS": ["obsolete-key"],
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"type": "shmem", "path": ["app-1__native-api", "CONTAINER_IP"]},
              ]
            },
          }
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-1")
    producer = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    consumer = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    self.assertEqual(producer["SEMAPHORE"], "app-1__native-api")
    self.assertEqual(producer.get("SEMAPHORED_KEYS", []), [])
    self.assertEqual(consumer["SEMAPHORED_KEYS"], ["app-1__native-api"])

  def test_resolve_shmem_in_plugins_rewrites_stale_alias_to_current_provider_key(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "native-api",
            "SEMAPHORE": "old-runtime-key",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "consumer-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"type": "shmem", "path": ["old-runtime-key", "CONTAINER_IP"]},
              ]
            },
          }
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-1")
    producer = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    consumer = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    self.assertEqual(producer["SEMAPHORE"], "app-1__native-api")
    self.assertEqual(
      consumer["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      ["app-1__native-api", "CONTAINER_IP"],
    )
    self.assertEqual(consumer["SEMAPHORED_KEYS"], ["app-1__native-api"])

  def test_resolve_shmem_in_plugins_rewrites_stale_app_alias_to_current_provider_key(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "native-api",
            "SEMAPHORE": "old-app__native-api",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "consumer-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"type": "shmem", "path": ["old-app__native-api", "CONTAINER_IP"]},
              ]
            },
          }
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-1")
    consumer = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    self.assertEqual(
      consumer["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      ["app-1__native-api", "CONTAINER_IP"],
    )
    self.assertEqual(consumer["SEMAPHORED_KEYS"], ["app-1__native-api"])

  def test_resolve_shmem_in_plugins_rejects_ambiguous_duplicate_stale_alias_consumer(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "A_SIMPLE_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "alpha",
            "SEMAPHORE": "old-app__shared-api",
          },
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-2",
            DEEPLOY_KEYS.PLUGIN_NAME: "beta",
            "SEMAPHORE": "old-app__shared-api",
          },
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "consumer-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "frontend",
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"type": "shmem", "path": ["old-app__shared-api", "CONTAINER_IP"]},
              ]
            },
          }
        ],
      },
    ]

    with self.assertRaisesRegex(ValueError, "ambiguous semaphore key 'old-app__shared-api'"):
      plugin._resolve_shmem_in_plugins(plugins, "app-1")

  def test_resolve_shmem_in_plugins_rejects_cross_app_provider_key(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "SOME_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "api-service",
            "SEMAPHORE": "app-1__api-service",
          }
        ],
      },
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "car-1",
            DEEPLOY_KEYS.PLUGIN_NAME: "consumer",
            "DYNAMIC_ENV": {
              "API_HOST": [
                {"type": "shmem", "path": ["other-app__api-service", "CONTAINER_IP"]}
              ]
            },
          }
        ],
      },
    ]

    with self.assertRaisesRegex(ValueError, "unknown plugin 'other-app__api-service'"):
      plugin._resolve_shmem_in_plugins(plugins, "app-1")

  def test_resolve_shmem_in_plugins_stale_reference_without_names(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "NATIVE_APP",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "native-1",
            "SEMAPHORE": "app-1__legacy-api",
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
                {"type": "shmem", "path": ["app-1__legacy-api", "CONTAINER_IP"]}
              ]
            },
          }
        ],
      },
    ]

    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-1")
    consumer = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(
      consumer["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      ["app-1__legacy-api", "CONTAINER_IP"],
    )
    self.assertEqual(consumer["SEMAPHORED_KEYS"], ["app-1__legacy-api"])

  def test_resolve_shmem_in_plugins_keeps_matching_semaphore(self):
    plugin = make_deeploy_plugin()
    plugins = [
      {
        plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "SOME_PLUGIN",
        plugin.ct.CONFIG_PLUGIN.K_INSTANCES: [
          {plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "p-1", "plugin_name": "alpha", "SEMAPHORE": "app-1__alpha"}
        ],
      },
    ]
    resolved = plugin._resolve_shmem_in_plugins(plugins, "app-1")
    instance = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["SEMAPHORE"], "app-1__alpha")

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
