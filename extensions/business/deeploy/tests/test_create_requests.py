import unittest

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs, make_plugin_entry


class DeeployCreateRequestPreparationTests(unittest.TestCase):

  def test_prepare_single_plugin_instance_uses_signature_and_app_params(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugin_signature="CONTAINER_APP_RUNNER",
      app_params={"IMAGE": "repo/app:latest", "PORT": 3000},
    )

    prepared = plugin.deeploy_prepare_single_plugin_instance(inputs)

    self.assertEqual(prepared[plugin.ct.CONFIG_PLUGIN.K_SIGNATURE], "CONTAINER_APP_RUNNER")
    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertTrue(instance[plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID].startswith("CONTAINER_APP_"))
    self.assertEqual(instance["IMAGE"], "repo/app:latest")
    self.assertEqual(instance["PORT"], 3000)

  def test_prepare_plugins_groups_instances_by_signature_and_tracks_names(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="frontend", PORT=3000),
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="worker", PORT=3001),
        make_plugin_entry("A_SIMPLE_PLUGIN", plugin_name="native", PROCESS_DELAY=5),
      ]
    )

    prepared_plugins, name_to_instance = plugin.deeploy_prepare_plugins(inputs)

    self.assertEqual(len(prepared_plugins), 2)
    grouped = {
      item[plugin.ct.CONFIG_PLUGIN.K_SIGNATURE]: item[plugin.ct.CONFIG_PLUGIN.K_INSTANCES]
      for item in prepared_plugins
    }
    self.assertEqual(len(grouped["CONTAINER_APP_RUNNER"]), 2)
    self.assertEqual(grouped["CONTAINER_APP_RUNNER"][0]["PORT"], 3000)
    self.assertEqual(grouped["CONTAINER_APP_RUNNER"][1]["PORT"], 3001)
    self.assertEqual(name_to_instance["frontend"]["signature"], "CONTAINER_APP_RUNNER")
    self.assertEqual(name_to_instance["worker"]["signature"], "CONTAINER_APP_RUNNER")
    self.assertEqual(name_to_instance["native"]["signature"], "A_SIMPLE_PLUGIN")

  def test_prepare_plugins_regenerates_duplicate_instance_ids(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("CONTAINER_APP_RUNNER", instance_id="dup", PORT=3000),
        make_plugin_entry("CONTAINER_APP_RUNNER", instance_id="dup", PORT=3001),
      ]
    )

    prepared_plugins, _ = plugin.deeploy_prepare_plugins(inputs)

    instances = prepared_plugins[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES]
    self.assertEqual(instances[0][plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID], "dup")
    self.assertNotEqual(instances[1][plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID], "dup")

  def test_prepare_single_plugin_instance_preserves_exposed_ports(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugin_signature="CONTAINER_APP_RUNNER",
      app_params={
        "IMAGE": "repo/app:latest",
        "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
        "EXPOSED_PORTS": {
          "3000": {"is_main_port": True},
          "3001": {"tunnel": {"enabled": True, "engine": "cloudflare", "token": "cf-token"}},
        },
      },
    )

    prepared = plugin.deeploy_prepare_single_plugin_instance(inputs)

    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertTrue(instance["EXPOSED_PORTS"]["3000"]["is_main_port"])
    self.assertEqual(instance["EXPOSED_PORTS"]["3001"]["tunnel"]["token"], "cf-token")

  def test_validate_plugins_array_accepts_container_runner_with_exposed_ports(self):
    plugin = make_deeploy_plugin()
    plugins = [
      make_plugin_entry(
        "CONTAINER_APP_RUNNER",
        IMAGE="repo/app:latest",
        CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
        EXPOSED_PORTS={
          "3000": {"is_main_port": True},
        },
      )
    ]

    self.assertTrue(plugin._validate_plugins_array(plugins))

  def test_validate_plugins_array_rejects_non_dict_exposed_ports(self):
    plugin = make_deeploy_plugin()
    plugins = [
      make_plugin_entry(
        "CONTAINER_APP_RUNNER",
        IMAGE="repo/app:latest",
        CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
        EXPOSED_PORTS=["3000"],
      )
    ]

    with self.assertRaisesRegex(ValueError, "EXPOSED_PORTS"):
      plugin._validate_plugins_array(plugins)

  def test_prepare_single_plugin_instance_translates_dynamic_env_ui(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugin_signature="CONTAINER_APP_RUNNER",
      app_params={
        "IMAGE": "repo/app:latest",
        "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
        "DYNAMIC_ENV_UI": {
          "API_URL": [
            {"source": "static", "value": "http://"},
            {"source": "container_ip", "provider": "backend"},
            {"source": "static", "value": ":3000"},
          ]
        },
      },
    )

    prepared = plugin.deeploy_prepare_single_plugin_instance(inputs)

    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertNotIn("DYNAMIC_ENV_UI", instance)
    self.assertEqual(instance["DYNAMIC_ENV"]["API_URL"], [
      {"type": "static", "value": "http://"},
      {"type": "shmem", "path": ["backend", "CONTAINER_IP"]},
      {"type": "static", "value": ":3000"},
    ])


if __name__ == "__main__":
  unittest.main()
