import unittest
from collections import defaultdict

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

  def test_prepare_plugins_groups_instances_by_signature(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="frontend", PORT=3000),
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="worker", PORT=3001),
        make_plugin_entry("A_SIMPLE_PLUGIN", plugin_name="native", PROCESS_DELAY=5),
      ]
    )

    prepared_plugins = plugin.deeploy_prepare_plugins(inputs)

    self.assertEqual(len(prepared_plugins), 2)
    grouped = {
      item[plugin.ct.CONFIG_PLUGIN.K_SIGNATURE]: item[plugin.ct.CONFIG_PLUGIN.K_INSTANCES]
      for item in prepared_plugins
    }
    self.assertEqual(len(grouped["CONTAINER_APP_RUNNER"]), 2)
    self.assertEqual(grouped["CONTAINER_APP_RUNNER"][0]["PORT"], 3000)
    self.assertEqual(grouped["CONTAINER_APP_RUNNER"][1]["PORT"], 3001)

  def test_prepare_plugins_preserves_plugin_name_in_instance(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="frontend", PORT=3000),
      ]
    )

    prepared_plugins = plugin.deeploy_prepare_plugins(inputs)

    instance = prepared_plugins[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance[DEEPLOY_KEYS.PLUGIN_NAME], "frontend")

  def test_prepare_plugins_regenerates_duplicate_instance_ids(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("CONTAINER_APP_RUNNER", instance_id="dup", PORT=3000),
        make_plugin_entry("CONTAINER_APP_RUNNER", instance_id="dup", PORT=3001),
      ]
    )

    prepared_plugins = plugin.deeploy_prepare_plugins(inputs)

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

  def test_prepare_plugins_resolves_shmem_with_app_id(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("A_SIMPLE_PLUGIN", plugin_name="native-api", PROCESS_DELAY=5),
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="frontend",
          IMAGE="repo/app:latest",
          DYNAMIC_ENV={
            "API_HOST": [{"type": "shmem", "path": ["native-api", "CONTAINER_IP"]}]
          },
        ),
      ]
    )

    prepared = plugin.deeploy_prepare_plugins(inputs, app_id="app-123")

    native_instance = prepared[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    car_instance = prepared[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    # Semaphore key uses app_id__plugin_name (not sanitized)
    self.assertEqual(native_instance["SEMAPHORE"], "app-123__native-api")
    # Shmem path rewritten from plugin name to semaphore key
    self.assertEqual(
      car_instance["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      ["app-123__native-api", "CONTAINER_IP"],
    )
    # Consumer gets SEMAPHORED_KEYS
    self.assertEqual(car_instance["SEMAPHORED_KEYS"], ["app-123__native-api"])

  def test_prepare_plugins_rejects_duplicate_plugin_names(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="backend", PORT=3000),
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="backend", PORT=3001),
      ]
    )

    with self.assertRaisesRegex(ValueError, "Duplicate plugin_name"):
      plugin.deeploy_prepare_plugins(inputs, app_id="app-1")

  def test_prepare_plugins_rejects_duplicate_explicit_semaphore_without_shmem(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("A_SIMPLE_PLUGIN", instance_id="native-1", SEMAPHORE="shared"),
        make_plugin_entry("A_SIMPLE_PLUGIN", instance_id="native-2", SEMAPHORE="shared"),
      ]
    )

    with self.assertRaisesRegex(ValueError, "Duplicate semaphore key"):
      plugin.deeploy_prepare_plugins(inputs)

  def test_prepare_plugins_rejects_invalid_semaphore_shape(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("A_SIMPLE_PLUGIN", instance_id="native-1", SEMAPHORE=123),
      ]
    )

    with self.assertRaisesRegex(ValueError, "SEMAPHORE"):
      plugin.deeploy_prepare_plugins(inputs)

  def test_prepare_plugins_rejects_invalid_semaphored_keys_shape(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          instance_id="container-1",
          SEMAPHORED_KEYS=["valid-key", ""],
        ),
      ]
    )

    with self.assertRaisesRegex(ValueError, "SEMAPHORED_KEYS"):
      plugin.deeploy_prepare_plugins(inputs)

  def test_prepare_plugins_rejects_shmem_referencing_unknown_plugin(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="frontend",
          IMAGE="repo/app:latest",
          DYNAMIC_ENV={
            "API_HOST": [{"type": "shmem", "path": ["nonexistent", "PORT"]}]
          },
        ),
      ]
    )

    with self.assertRaisesRegex(ValueError, "unknown plugin 'nonexistent'"):
      plugin.deeploy_prepare_plugins(inputs, app_id="app-1")

  def test_prepare_plugins_rejects_malformed_dynamic_env_entries(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="frontend",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "256m"},
          DYNAMIC_ENV={
            "API_URL": {"type": "shmem", "path": ["provider", "PORT"]},
          },
        ),
      ]
    )

    with self.assertRaisesRegex(ValueError, "DYNAMIC_ENV entries for 'API_URL' must be a list"):
      plugin.deeploy_prepare_plugins(inputs, app_id="app-1")

  def test_prepare_plugins_without_app_id_skips_resolution(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="frontend", PORT=3000),
      ]
    )

    prepared = plugin.deeploy_prepare_plugins(inputs)

    instance = prepared[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertNotIn("SEMAPHORE", instance)

  def test_create_pipeline_on_nodes_without_chainstore_response_returns_empty_keys(self):
    plugin = make_deeploy_plugin()
    plugin.time = lambda: 1_000.0
    plugin.defaultdict = defaultdict
    called = {"start": 0, "reset": 0}
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: called.__setitem__("reset", called["reset"] + 1)

    def start_pipeline(**kwargs):
      called["start"] += 1
      return {
        "NAME": kwargs["name"],
        "APP_ALIAS": kwargs["app_alias"],
        "PLUGINS": kwargs["plugins"],
        "DEEPLOY_SPECS": kwargs["deeploy_specs"],
      }

    plugin.cmdapi_start_pipeline_by_params = start_pipeline
    inputs = make_inputs(
      app_alias="native-app",
      job_id=11,
      pipeline_input_type="void",
      pipeline_input_uri="",
      chainstore_response=False,
      plugins=[
        make_plugin_entry("A_SIMPLE_PLUGIN", plugin_name="native-api", PROCESS_DELAY=5),
      ],
    )

    response_keys, saved_pipeline = plugin._DeeployMixin__create_pipeline_on_nodes(
      ["node-1"],
      inputs,
      "native-app_abc123",
      "native-app",
      "void",
      "owner",
      job_app_type="native",
      dct_deeploy_specs={"job_id": 11},
    )

    self.assertEqual(response_keys, {})
    self.assertEqual(called["start"], 1)
    self.assertEqual(called["reset"], 0)
    self.assertEqual(saved_pipeline["NAME"], "native-app_abc123")

  def test_create_pipeline_on_nodes_recovers_duplicate_stale_named_semaphores_with_autowire(self):
    plugin = make_deeploy_plugin()
    plugin.time = lambda: 1_000.0
    plugin.defaultdict = defaultdict
    called = {"start": 0, "reset": 0}
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: called.__setitem__("reset", called["reset"] + 1)

    def start_pipeline(**kwargs):
      called["start"] += 1
      return {
        "PLUGINS": kwargs["plugins"],
        "DEEPLOY_SPECS": kwargs["deeploy_specs"],
      }

    plugin.cmdapi_start_pipeline_by_params = start_pipeline
    inputs = make_inputs(
      app_alias="native-app",
      job_id=11,
      pipeline_input_type="void",
      pipeline_input_uri="",
      chainstore_response=True,
      plugins=[
        make_plugin_entry(
          "A_SIMPLE_PLUGIN",
          instance_id="native-1",
          plugin_name="alpha",
          SEMAPHORE="old-app__shared-api",
          PROCESS_DELAY=5,
        ),
        make_plugin_entry(
          "A_SIMPLE_PLUGIN",
          instance_id="native-2",
          plugin_name="beta",
          SEMAPHORE="old-app__shared-api",
          PROCESS_DELAY=5,
        ),
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          instance_id="car-1",
          plugin_name="frontend",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "256m"},
        ),
      ],
    )

    response_keys, saved_pipeline = plugin._DeeployMixin__create_pipeline_on_nodes(
      ["node-1"],
      inputs,
      "native-app_abc123",
      "native-app",
      "void",
      "owner",
      job_app_type="native",
      dct_deeploy_specs={"job_id": 11},
    )

    native_instances = saved_pipeline["PLUGINS"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES]
    container_instance = saved_pipeline["PLUGINS"][1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(native_instances[0]["SEMAPHORE"], "native-app_abc123__alpha")
    self.assertEqual(native_instances[1]["SEMAPHORE"], "native-app_abc123__beta")
    self.assertEqual(
      container_instance["SEMAPHORED_KEYS"],
      ["native-app_abc123__alpha", "native-app_abc123__beta"],
    )
    self.assertEqual(called["start"], 1)
    self.assertEqual(called["reset"], 1)
    self.assertEqual(len(response_keys["node-1"]), 3)
    self.assertEqual(
      saved_pipeline["DEEPLOY_SPECS"][DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS],
      response_keys,
    )

  def test_create_pipeline_on_nodes_rejects_duplicate_final_autowire_semaphores(self):
    plugin = make_deeploy_plugin()
    plugin.time = lambda: 1_000.0
    plugin.defaultdict = defaultdict
    called = {"start": 0, "reset": 0}
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: called.__setitem__("reset", called["reset"] + 1)
    plugin.cmdapi_start_pipeline_by_params = lambda **kwargs: called.__setitem__("start", called["start"] + 1)

    inputs = make_inputs(
      app_alias="native-app",
      job_id=11,
      pipeline_input_type="void",
      pipeline_input_uri="",
      chainstore_response=False,
      plugins=[
        make_plugin_entry("A_SIMPLE_PLUGIN", instance_id="native/a", PROCESS_DELAY=5),
        make_plugin_entry("A_SIMPLE_PLUGIN", instance_id="native a", PROCESS_DELAY=5),
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          instance_id="car-1",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "256m"},
        ),
      ],
    )

    with self.assertRaisesRegex(ValueError, "Duplicate final semaphore key"):
      plugin._DeeployMixin__create_pipeline_on_nodes(
        ["node-1"],
        inputs,
        "native-app_abc123",
        "native-app",
        "void",
        "owner",
        job_app_type="native",
        dct_deeploy_specs={"job_id": 11},
      )

    self.assertEqual(called["start"], 0)
    self.assertEqual(called["reset"], 0)

  def test_create_pipeline_on_nodes_strips_stale_chainstore_response_key_when_disabled(self):
    plugin = make_deeploy_plugin()
    plugin.time = lambda: 1_000.0
    plugin.defaultdict = defaultdict
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: None

    def start_pipeline(**kwargs):
      return {
        "PLUGINS": kwargs["plugins"],
        "DEEPLOY_SPECS": kwargs["deeploy_specs"],
      }

    plugin.cmdapi_start_pipeline_by_params = start_pipeline
    response_key_field = plugin.ct.BIZ_PLUGIN_DATA.CHAINSTORE_RESPONSE_KEY
    inputs = make_inputs(
      app_alias="native-app",
      job_id=11,
      pipeline_input_type="void",
      pipeline_input_uri="",
      chainstore_response=False,
      plugins=[
        make_plugin_entry(
          "A_SIMPLE_PLUGIN",
          plugin_name="native-api",
          PROCESS_DELAY=5,
          **{response_key_field: "stale-response-key"},
        ),
      ],
    )

    response_keys, saved_pipeline = plugin._DeeployMixin__create_pipeline_on_nodes(
      ["node-1"],
      inputs,
      "native-app_abc123",
      "native-app",
      "void",
      "owner",
      job_app_type="native",
      dct_deeploy_specs={"job_id": 11, DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS: {"node-1": ["old-key"]}},
    )

    instance = saved_pipeline["PLUGINS"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(response_keys, {})
    self.assertNotIn(response_key_field, instance)
    self.assertNotIn(DEEPLOY_KEYS.CHAINSTORE_RESPONSE_KEYS, saved_pipeline["DEEPLOY_SPECS"])


if __name__ == "__main__":
  unittest.main()
