import unittest
from collections import defaultdict

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, JOB_APP_TYPES
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

  def test_prepare_single_plugin_instance_accepts_top_level_per_node_config(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugin_signature="CONTAINER_APP_RUNNER",
      app_params={"IMAGE": "repo/app:latest", "PORT": 3000},
      perNodeConfig={
        "byIndex": {
          "0": {"ENV": {"NODE_ID": "1"}},
        },
      },
    )

    prepared = plugin.deeploy_prepare_single_plugin_instance(inputs)

    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertNotIn("perNodeConfig", instance)
    self.assertEqual(instance["PER_NODE_CONFIG"], {
      "byIndex": {
        "0": {"ENV": {"NODE_ID": "1"}},
      },
    })

  def test_prepare_plugins_rejects_top_level_per_node_config_with_plugins_array(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      perNodeConfig={"0xai_node_a": {"ENV": {"NODE_ID": "1"}}},
      plugins=[
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="frontend", PORT=3000),
      ],
    )

    with self.assertRaisesRegex(ValueError, "Top-level perNodeConfig"):
      plugin.deeploy_prepare_plugins(inputs)

  def test_legacy_plugin_normalization_moves_top_level_per_node_config_into_plugin(self):
    plugin = make_deeploy_plugin()
    request = {
      DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
      DEEPLOY_KEYS.APP_PARAMS: {"IMAGE": "repo/app:latest"},
      "perNodeConfig": {
        "byIndex": {
          "0": {"ENV": {"NODE_ID": "1"}},
        },
      },
    }

    normalized = plugin._normalize_plugins_input(request)

    self.assertNotIn("perNodeConfig", normalized)
    self.assertEqual(len(normalized[DEEPLOY_KEYS.PLUGINS]), 1)
    instance = normalized[DEEPLOY_KEYS.PLUGINS][0]
    self.assertEqual(instance["PER_NODE_CONFIG"], {
      "byIndex": {
        "0": {"ENV": {"NODE_ID": "1"}},
      },
    })

  def test_per_node_config_rejects_malformed_structured_sections(self):
    plugin = make_deeploy_plugin()

    with self.assertRaisesRegex(ValueError, "default must be a dictionary"):
      plugin._normalize_per_node_config({"default": []})
    with self.assertRaisesRegex(ValueError, "byIndex must be a dictionary"):
      plugin._normalize_per_node_config({"byIndex": ""})
    with self.assertRaisesRegex(ValueError, "duplicate aliases"):
      plugin._normalize_per_node_config({"byIndex": {}, "BY_INDEX": {}})

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

  def test_per_node_config_materializes_container_and_worker_configs(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="db",
          IMAGE="repo/db:latest",
          ENV={"CLUSTER": "crdb"},
          perNodeConfig={
            "default": {"ENV": {"ROLE": "replica"}},
            "byIndex": {
              "0": {"ENV": {"NODE_ID": "1"}},
            },
            "byNode": {
              "0xai_node_b": {
                "ENV": {"NODE_ID": "2"},
                "CONTAINER_START_COMMAND": ["start-node-2"],
              },
            },
          },
        ),
        make_plugin_entry(
          "WORKER_APP_RUNNER",
          plugin_name="worker",
          IMAGE="node:22",
          VCS_DATA={
            "REPO_OWNER": "ratio1",
            "REPO_NAME": "demo",
            "BRANCH": "main",
          },
          PER_NODE_CONFIG={
            "byNode": {
              "node_b": {
                "VCS_DATA": {"BRANCH": "develop"},
                "ENV": {"WORKER_NODE": "node-b"},
              },
            },
          },
        ),
      ]
    )

    prepared = plugin.deeploy_prepare_plugins(inputs)
    node_a_plugins = plugin._materialize_plugins_for_node(prepared, "0xai_node_a", 0)
    node_b_plugins = plugin._materialize_plugins_for_node(prepared, "0xai_node_b", 1)

    node_a_car = node_a_plugins[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    node_b_car = node_b_plugins[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    node_b_worker = node_b_plugins[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]

    self.assertEqual(node_a_car["ENV"], {
      "CLUSTER": "crdb",
      "ROLE": "replica",
      "NODE_ID": "1",
    })
    self.assertEqual(node_b_car["ENV"], {
      "CLUSTER": "crdb",
      "ROLE": "replica",
      "NODE_ID": "2",
    })
    self.assertEqual(node_b_car["CONTAINER_START_COMMAND"], ["start-node-2"])
    self.assertEqual(node_b_worker["VCS_DATA"]["REPO_OWNER"], "ratio1")
    self.assertEqual(node_b_worker["VCS_DATA"]["REPO_NAME"], "demo")
    self.assertEqual(node_b_worker["VCS_DATA"]["BRANCH"], "develop")
    self.assertEqual(node_b_worker["ENV"], {"WORKER_NODE": "node-b"})
    self.assertNotIn("perNodeConfig", node_b_car)
    self.assertNotIn("PER_NODE_CONFIG", node_b_worker)

  def test_per_node_config_accepts_direct_node_address_map(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="db",
          IMAGE="repo/db:latest",
          ENV={"CLUSTER": "crdb"},
          perNodeConfig={
            "0xai_node_a": {"ENV": {"NODE_ID": "1"}},
            "0xai_node_b": {"ENV": {"NODE_ID": "2"}},
          },
        ),
      ]
    )

    prepared = plugin.deeploy_prepare_plugins(inputs)
    node_b_plugins = plugin._materialize_plugins_for_node(prepared, "0xai_node_b", 1)

    instance = node_b_plugins[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["ENV"], {"CLUSTER": "crdb", "NODE_ID": "2"})
    self.assertNotIn("perNodeConfig", instance)

  def test_per_node_config_dynamic_env_resolves_after_materialization(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("A_SIMPLE_PLUGIN", plugin_name="native-api", PROCESS_DELAY=5),
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="frontend",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          perNodeConfig={
            "0xai_node_a": {
              "DYNAMIC_ENV": {
                "API_HOST": [{"type": "shmem", "path": ["native-api", "CONTAINER_IP"]}]
              }
            }
          },
        ),
      ]
    )

    prepared = plugin.deeploy_prepare_plugins(inputs)
    materialized = plugin._materialize_plugins_for_node(prepared, "0xai_node_a", 0)
    resolved = plugin._resolve_shmem_in_plugins(materialized, "app-123")

    native_instance = resolved[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    car_instance = resolved[1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(native_instance["SEMAPHORE"], "app-123__native-api")
    self.assertEqual(
      car_instance["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      ["app-123__native-api", "CONTAINER_IP"],
    )

  def test_per_node_config_rejects_resource_preflight_overrides(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="db",
          IMAGE="repo/db:latest",
          perNodeConfig={
            "0xai_node_a": {
              "container_resources": {"cpu": 4},
            }
          },
        ),
      ]
    )

    prepared = plugin.deeploy_prepare_plugins(inputs)
    with self.assertRaisesRegex(ValueError, "container_resources"):
      plugin._materialize_plugins_for_node(prepared, "0xai_node_a", 0)

  def test_per_node_config_rejects_image_override(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="db",
          IMAGE="repo/db:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          perNodeConfig={
            "0xai_node_a": {
              "IMAGE": "postgres:latest",
            }
          },
        ),
      ]
    )

    prepared = plugin.deeploy_prepare_plugins(inputs)
    with self.assertRaisesRegex(ValueError, "IMAGE"):
      plugin._materialize_plugins_for_node(prepared, "0xai_node_a", 0)

  def test_per_node_config_rejects_unmatched_selectors(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="db",
          IMAGE="repo/db:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          perNodeConfig={
            "byIndex": {"2": {"ENV": {"NODE_ID": "3"}}},
            "byNode": {"0xai_missing": {"ENV": {"NODE_ID": "missing"}}},
          },
        ),
      ]
    )

    prepared = plugin.deeploy_prepare_plugins(inputs)
    with self.assertRaisesRegex(ValueError, "outside target nodes"):
      plugin._validate_per_node_config_selectors(prepared, ["0xai_node_a", "0xai_node_b"])

  def test_per_node_config_rejects_mixed_structured_and_direct_node_keys(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="db",
          IMAGE="repo/db:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          perNodeConfig={
            "default": {"ENV": {"ROLE": "replica"}},
            "0xai_node_a": {"ENV": {"NODE_ID": "1"}},
          },
        ),
      ]
    )

    prepared = plugin.deeploy_prepare_plugins(inputs)
    with self.assertRaisesRegex(ValueError, "cannot mix structured keys"):
      plugin._validate_per_node_config_selectors(prepared, ["0xai_node_a"])

  def test_create_dispatch_sends_full_per_node_config_to_runners(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1000
    plugin._validate_dependency_tree = lambda inputs: True
    plugin._ensure_runner_cstore_auth_env = lambda app_id, prepared_plugins: prepared_plugins
    plugin._ensure_deeploy_specs_job_config = lambda specs, pipeline_params=None: specs
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: True
    sent = []

    def capture_start(**kwargs):
      sent.append(kwargs)
      return {"ok": True, "plugins": kwargs["plugins"]}

    plugin.cmdapi_start_pipeline_by_params = capture_start
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="db",
          IMAGE="repo/db:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          ENV={"CLUSTER": "crdb"},
          perNodeConfig={
            "default": {"ENV": {"ROLE": "replica"}},
            "byIndex": {"0": {"ENV": {"NODE_ID": "1"}}},
            "byNode": {"0xai_node_b": {"ENV": {"NODE_ID": "2"}}},
          },
        ),
      ],
      chainstore_response=False,
      pipeline_input_uri=None,
      pipeline_params={},
      job_id=901,
      project_id=None,
      project_name=None,
      job_tags=[],
      spare_nodes=[],
      allow_replication_in_the_wild=False,
    )

    plugin._DeeployMixin__create_pipeline_on_nodes(
      nodes=["0xai_node_a", "0xai_node_b"],
      inputs=inputs,
      app_id="per-node-app",
      app_alias="Per Node App",
      app_type="DeeployTestbedStream",
      owner="owner",
      job_app_type=JOB_APP_TYPES.GENERIC,
    )

    self.assertEqual(len(sent), 2)
    first_instance = sent[0]["plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    second_instance = sent[1]["plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(first_instance["ENV"], {"CLUSTER": "crdb"})
    self.assertEqual(second_instance["ENV"], {"CLUSTER": "crdb"})
    self.assertIn("PER_NODE_CONFIG", first_instance)
    self.assertIn("PER_NODE_CONFIG", second_instance)
    self.assertEqual(first_instance["PER_NODE_CONFIG"], second_instance["PER_NODE_CONFIG"])
    self.assertEqual(first_instance["PER_NODE_TARGET_NODES"], ["0xai_node_a", "0xai_node_b"])
    self.assertEqual(second_instance["PER_NODE_TARGET_NODES"], ["0xai_node_a", "0xai_node_b"])

  def test_create_redeploy_uses_persisted_target_order_for_by_index(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1000
    plugin._validate_dependency_tree = lambda inputs: True
    plugin._ensure_runner_cstore_auth_env = lambda app_id, prepared_plugins: prepared_plugins
    plugin._ensure_deeploy_specs_job_config = lambda specs, pipeline_params=None: specs
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: True
    sent = []

    def capture_start(**kwargs):
      sent.append(kwargs)
      return {"ok": True, "plugins": kwargs["plugins"]}

    plugin.cmdapi_start_pipeline_by_params = capture_start
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="db",
          IMAGE="repo/db:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          ENV={"CLUSTER": "crdb"},
          perNodeConfig={
            "byIndex": {
              "0": {"ENV": {"NODE_ID": "1"}},
              "1": {"ENV": {"NODE_ID": "2"}},
            },
          },
        ),
      ],
      chainstore_response=False,
      pipeline_input_uri=None,
      pipeline_params={},
      job_id=902,
      project_id=None,
      project_name=None,
      job_tags=[],
      spare_nodes=[],
      allow_replication_in_the_wild=False,
    )

    plugin._DeeployMixin__create_pipeline_on_nodes(
      nodes=["0xai_node_b", "0xai_node_a"],
      inputs=inputs,
      app_id="per-node-app",
      app_alias="Per Node App",
      app_type="DeeployTestbedStream",
      owner="owner",
      job_app_type=JOB_APP_TYPES.GENERIC,
      dct_deeploy_specs={
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["0xai_node_a", "0xai_node_b"],
      },
    )

    by_node = {
      call["node_address"]: call["plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
      for call in sent
    }
    self.assertEqual(by_node["0xai_node_a"]["ENV"], {"CLUSTER": "crdb"})
    self.assertEqual(by_node["0xai_node_b"]["ENV"], {"CLUSTER": "crdb"})
    self.assertEqual(
      by_node["0xai_node_a"]["PER_NODE_CONFIG"]["byIndex"],
      by_node["0xai_node_b"]["PER_NODE_CONFIG"]["byIndex"],
    )

  def test_create_partial_redeploy_sends_full_per_node_target_order(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1000
    plugin._validate_dependency_tree = lambda inputs: True
    plugin._ensure_runner_cstore_auth_env = lambda app_id, prepared_plugins: prepared_plugins
    plugin._ensure_deeploy_specs_job_config = lambda specs, pipeline_params=None: specs
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: True
    sent = []

    def capture_start(**kwargs):
      sent.append(kwargs)
      return {"ok": True, "plugins": kwargs["plugins"]}

    plugin.cmdapi_start_pipeline_by_params = capture_start
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="db",
          IMAGE="repo/db:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          ENV={"CLUSTER": "crdb"},
          perNodeConfig={
            "byIndex": {
              "1": {"ENV": {"NODE_ID": "2"}},
            },
          },
        ),
      ],
      chainstore_response=False,
      pipeline_input_uri=None,
      pipeline_params={},
      job_id=903,
      project_id=None,
      project_name=None,
      job_tags=[],
      spare_nodes=[],
      allow_replication_in_the_wild=False,
    )

    plugin._DeeployMixin__create_pipeline_on_nodes(
      nodes=["0xai_node_b"],
      inputs=inputs,
      app_id="per-node-app",
      app_alias="Per Node App",
      app_type="DeeployTestbedStream",
      owner="owner",
      job_app_type=JOB_APP_TYPES.GENERIC,
      dct_deeploy_specs={
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["0xai_node_a", "0xai_node_b"],
      },
    )

    instance = sent[0]["plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["ENV"], {"CLUSTER": "crdb"})
    self.assertEqual(instance["CHAINSTORE_PEERS"], ["0xai_node_b"])
    self.assertEqual(instance["PER_NODE_TARGET_NODES"], ["0xai_node_a", "0xai_node_b"])
    self.assertEqual(
      sent[0]["deeploy_specs"][DEEPLOY_KEYS.CURRENT_TARGET_NODES],
      ["0xai_node_a", "0xai_node_b"],
    )
    self.assertEqual(instance["PER_NODE_CONFIG"]["byIndex"], {"1": {"ENV": {"NODE_ID": "2"}}})

  def test_create_dispatch_resolves_shmem_inside_per_node_config(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1000
    plugin._validate_dependency_tree = lambda inputs: True
    plugin._ensure_runner_cstore_auth_env = lambda app_id, prepared_plugins: prepared_plugins
    plugin._ensure_deeploy_specs_job_config = lambda specs, pipeline_params=None: specs
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: True
    sent = []

    def capture_start(**kwargs):
      sent.append(kwargs)
      return {"ok": True, "plugins": kwargs["plugins"]}

    plugin.cmdapi_start_pipeline_by_params = capture_start
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("A_SIMPLE_PLUGIN", plugin_name="native-api", PROCESS_DELAY=5),
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="frontend",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          perNodeConfig={
            "0xai_node_a": {
              "DYNAMIC_ENV": {
                "API_HOST": [{"type": "shmem", "path": ["native-api", "CONTAINER_IP"]}]
              }
            }
          },
        ),
      ],
      chainstore_response=False,
      pipeline_input_uri=None,
      pipeline_params={},
      job_id=904,
      project_id=None,
      project_name=None,
      job_tags=[],
      spare_nodes=[],
      allow_replication_in_the_wild=False,
    )

    plugin._DeeployMixin__create_pipeline_on_nodes(
      nodes=["0xai_node_a"],
      inputs=inputs,
      app_id="per-node-app",
      app_alias="Per Node App",
      app_type="DeeployTestbedStream",
      owner="owner",
      job_app_type=JOB_APP_TYPES.NATIVE,
    )

    native_instance = sent[0]["plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    car_instance = sent[0]["plugins"][1][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(native_instance["SEMAPHORE"], "per-node-app__native-api")
    self.assertEqual(car_instance["SEMAPHORED_KEYS"], ["per-node-app__native-api"])
    self.assertEqual(
      car_instance["PER_NODE_CONFIG"]["0xai_node_a"]["DYNAMIC_ENV"]["API_HOST"][0]["path"],
      ["per-node-app__native-api", "CONTAINER_IP"],
    )


if __name__ == "__main__":
  unittest.main()
