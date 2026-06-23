import unittest
from collections import defaultdict

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_PLUGIN_DATA, JOB_APP_TYPES
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs, make_plugin_entry


class DeeployUpdateRequestPreparationTests(unittest.TestCase):

  def test_prepare_single_plugin_instance_update_uses_plugin_config_and_strips_signature_fields(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-1",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "signature": "IGNORED",
        "IMAGE": "repo/app:latest",
        "PORT": 3000,
      },
    )

    self.assertEqual(prepared[plugin.ct.CONFIG_PLUGIN.K_SIGNATURE], "CONTAINER_APP_RUNNER")
    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance[plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID], "instance-1")
    self.assertEqual(instance["IMAGE"], "repo/app:latest")
    self.assertEqual(instance["PORT"], 3000)
    self.assertNotIn(DEEPLOY_KEYS.PLUGIN_SIGNATURE, instance)
    self.assertNotIn("signature", instance)

  def test_prepare_single_plugin_instance_update_falls_back_to_instance_conf(self):
    plugin = make_deeploy_plugin()
    fallback_instance = {
      plugin.ct.CONFIG_PLUGIN.K_SIGNATURE: "CONTAINER_APP_RUNNER",
      "instance_conf": {
        plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "old-instance",
        "IMAGE": "repo/old:1.0",
        "PORT": 3002,
      },
    }

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-2",
      fallback_instance=fallback_instance,
    )

    self.assertEqual(prepared[plugin.ct.CONFIG_PLUGIN.K_SIGNATURE], "CONTAINER_APP_RUNNER")
    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance[plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID], "instance-2")
    self.assertEqual(instance["IMAGE"], "repo/old:1.0")
    self.assertEqual(instance["PORT"], 3002)

  def test_extract_plugin_request_conf_removes_update_metadata_fields(self):
    plugin = make_deeploy_plugin()
    result = plugin._extract_plugin_request_conf(
      plugin_entry={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "instance-1",
        "instance_id": "instance-1",
        plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "instance-1",
        "CHAINSTORE_RESPONSE_KEY": "resp-key",
        "CHAINSTORE_PEERS": ["peer-a"],
        "IMAGE": "repo/app:latest",
        "PORT": 3000,
      },
      instance_id_key=plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID,
      chainstore_response_key="CHAINSTORE_RESPONSE_KEY",
      chainstore_peers_key="CHAINSTORE_PEERS",
    )

    self.assertEqual(result, {
      "IMAGE": "repo/app:latest",
      "PORT": 3000,
    })

  def test_prepare_single_plugin_instance_update_preserves_exposed_ports(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-3",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "IMAGE": "repo/app:latest",
        "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
        "EXPOSED_PORTS": {
          "3005": {"is_main_port": True},
          "3006": {"tunnel": {"enabled": True, "engine": "cloudflare", "token": "upd-token"}},
        },
      },
    )

    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertTrue(instance["EXPOSED_PORTS"]["3005"]["is_main_port"])
    self.assertEqual(instance["EXPOSED_PORTS"]["3006"]["tunnel"]["token"], "upd-token")

  def test_extract_plugin_request_conf_keeps_exposed_ports(self):
    plugin = make_deeploy_plugin()
    result = plugin._extract_plugin_request_conf(
      plugin_entry={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_KEYS.PLUGIN_INSTANCE_ID: "instance-1",
        "instance_id": "instance-1",
        plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "instance-1",
        "CHAINSTORE_RESPONSE_KEY": "resp-key",
        "CHAINSTORE_PEERS": ["peer-a"],
        "IMAGE": "repo/app:latest",
        "EXPOSED_PORTS": {
          "3000": {"is_main_port": True},
        },
      },
      instance_id_key=plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID,
      chainstore_response_key="CHAINSTORE_RESPONSE_KEY",
      chainstore_peers_key="CHAINSTORE_PEERS",
    )

    self.assertEqual(result, {
      "IMAGE": "repo/app:latest",
      "EXPOSED_PORTS": {
        "3000": {"is_main_port": True},
      },
    })

  def test_prepare_single_plugin_instance_update_preserves_dynamic_env(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-4",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "IMAGE": "repo/app:latest",
        "DYNAMIC_ENV": {
          "API_HOST": [
            {"type": "host_ip"},
            {"type": "static", "value": ":3000"},
          ]
        },
      },
    )

    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["DYNAMIC_ENV"]["API_HOST"], [
      {"type": "host_ip"},
      {"type": "static", "value": ":3000"},
    ])

  def test_prepare_single_plugin_instance_update_preserves_shmem_dynamic_env(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-5",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "IMAGE": "repo/app:latest",
        "DYNAMIC_ENV": {
          "UPSTREAM_PORT": [
            {"type": "shmem", "path": ["native-agent", "PORT"]},
          ]
        },
      },
    )

    instance = prepared[plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["DYNAMIC_ENV"]["UPSTREAM_PORT"], [
      {"type": "shmem", "path": ["native-agent", "PORT"]},
    ])

  def test_prepare_single_plugin_instance_update_materializes_per_node_config(self):
    plugin = make_deeploy_plugin()

    prepared = plugin.deeploy_prepare_single_plugin_instance_update(
      inputs=make_inputs(),
      instance_id="instance-6",
      plugin_config={
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "WORKER_APP_RUNNER",
        "IMAGE": "node:22",
        "VCS_DATA": {
          "REPO_OWNER": "ratio1",
          "REPO_NAME": "demo",
          "BRANCH": "main",
        },
        "perNodeConfig": {
          "0xai_node_b": {
            "VCS_DATA": {"BRANCH": "develop"},
            "ENV": {"WORKER_NODE": "node-b"},
          },
        },
      },
    )

    materialized = plugin._materialize_plugins_for_node([prepared], "0xai_node_b", 1)

    instance = materialized[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["VCS_DATA"]["REPO_OWNER"], "ratio1")
    self.assertEqual(instance["VCS_DATA"]["REPO_NAME"], "demo")
    self.assertEqual(instance["VCS_DATA"]["BRANCH"], "develop")
    self.assertEqual(instance["ENV"], {"WORKER_NODE": "node-b"})
    self.assertNotIn("perNodeConfig", instance)

  def test_per_node_config_update_uses_persisted_target_node_order(self):
    plugin = make_deeploy_plugin()

    ordered = plugin._ordered_nodes_for_per_node_config(
      nodes=["0xai_node_b", "0xai_node_a"],
      dct_deeploy_specs={DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["0xai_node_a", "0xai_node_b"]},
    )

    self.assertEqual(ordered, ["0xai_node_a", "0xai_node_b"])

  def test_update_pipeline_reuses_requested_instance_config_for_duplicate_node_instances(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 123.0
    plugin._ensure_deeploy_specs_job_config = lambda specs, pipeline_params=None: specs
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: None
    captures = []

    def start_pipeline(**kwargs):
      captures.append({
        "node": kwargs["node_address"],
        "plugins": kwargs["plugins"],
      })
      return {"node": kwargs["node_address"], "plugins": kwargs["plugins"]}

    plugin.cmdapi_start_pipeline_by_params = start_pipeline
    nodes = ["0xai_node_a", "0xai_node_b"]
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          instance_id="shared-instance",
          plugin_name="shared-service",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          ENV={"BASE": "1"},
          perNodeConfig={
            "byIndex": {
              "0": {"ENV": {"NODE_INDEX": "0"}},
              "1": {"ENV": {"NODE_INDEX": "1"}},
            },
            "byNode": {
              "0xai_node_b": {"ENV": {"NODE_NAME": "node-b"}},
            },
          },
        ),
      ],
      pipeline_input_uri="",
      chainstore_response=False,
      job_tags=[],
      spare_nodes=[],
      allow_replication_in_the_wild=False,
    )
    discovered_plugin_instances = [
      {
        DEEPLOY_PLUGIN_DATA.NODE: node,
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "shared-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "signature": "CONTAINER_APP_RUNNER",
          "instance_conf": {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "shared-instance",
            "plugin_name": "shared-service",
            "IMAGE": "repo/old:latest",
          },
        },
      }
      for node in nodes
    ]

    plugin._DeeployMixin__update_pipeline_on_nodes(
      nodes=nodes,
      inputs=inputs,
      app_id="app-1",
      app_alias="App 1",
      app_type="Void",
      owner="owner",
      discovered_plugin_instances=discovered_plugin_instances,
      dct_deeploy_specs={DEEPLOY_KEYS.CURRENT_TARGET_NODES: nodes},
      job_app_type=JOB_APP_TYPES.SERVICE,
    )

    self.assertEqual(len(captures), 2)
    by_node = {
      capture["node"]: capture["plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
      for capture in captures
    }
    self.assertEqual(by_node["0xai_node_a"]["ENV"], {"BASE": "1"})
    self.assertEqual(by_node["0xai_node_b"]["ENV"], {"BASE": "1"})
    self.assertIn("PER_NODE_CONFIG", by_node["0xai_node_a"])
    self.assertIn("PER_NODE_CONFIG", by_node["0xai_node_b"])
    self.assertEqual(
      by_node["0xai_node_a"]["PER_NODE_CONFIG"],
      by_node["0xai_node_b"]["PER_NODE_CONFIG"],
    )
    self.assertEqual(by_node["0xai_node_a"]["PER_NODE_TARGET_NODES"], nodes)
    self.assertEqual(by_node["0xai_node_b"]["PER_NODE_TARGET_NODES"], nodes)

  def test_update_partial_operation_uses_full_per_node_target_order(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1000
    plugin._ensure_deeploy_specs_job_config = lambda specs, pipeline_params=None: specs
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: True
    captures = []

    def start_pipeline(**kwargs):
      captures.append({
        "node": kwargs["node_address"],
        "plugins": kwargs["plugins"],
      })
      return {"node": kwargs["node_address"], "plugins": kwargs["plugins"]}

    plugin.cmdapi_start_pipeline_by_params = start_pipeline
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          instance_id="shared-instance",
          plugin_name="shared-service",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "128m"},
          ENV={"BASE": "1"},
          perNodeConfig={
            "byIndex": {
              "1": {"ENV": {"NODE_INDEX": "1"}},
            },
          },
        ),
      ],
      pipeline_input_uri="",
      chainstore_response=False,
      job_tags=[],
      spare_nodes=[],
      allow_replication_in_the_wild=False,
    )
    discovered_plugin_instances = [
      {
        DEEPLOY_PLUGIN_DATA.NODE: "0xai_node_b",
        DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "shared-instance",
        DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {
          "signature": "CONTAINER_APP_RUNNER",
          "instance_conf": {
            plugin.ct.CONFIG_INSTANCE.K_INSTANCE_ID: "shared-instance",
            "plugin_name": "shared-service",
            "IMAGE": "repo/old:latest",
          },
        },
      }
    ]

    plugin._DeeployMixin__update_pipeline_on_nodes(
      nodes=["0xai_node_b"],
      inputs=inputs,
      app_id="app-1",
      app_alias="App 1",
      app_type="Void",
      owner="owner",
      discovered_plugin_instances=discovered_plugin_instances,
      dct_deeploy_specs={DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["0xai_node_a", "0xai_node_b"]},
      job_app_type=JOB_APP_TYPES.SERVICE,
    )

    instance = captures[0]["plugins"][0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["ENV"], {"BASE": "1"})
    self.assertEqual(instance["CHAINSTORE_PEERS"], ["0xai_node_a", "0xai_node_b"])
    self.assertEqual(instance["PER_NODE_TARGET_NODES"], ["0xai_node_a", "0xai_node_b"])
    self.assertEqual(instance["PER_NODE_CONFIG"]["byIndex"], {"1": {"ENV": {"NODE_INDEX": "1"}}})

  def test_scale_up_prepare_refreshes_full_per_node_target_order(self):
    plugin = make_deeploy_plugin()
    plugin.defaultdict = defaultdict
    plugin.time = lambda: 1000
    base_pipeline = {
      "app_id": "app-1",
      "pipeline_type": "Void",
      "url": "",
      "pipeline_params": {},
      "deeploy_specs": {
        DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["0xai_node_a", "0xai_node_b"],
        DEEPLOY_KEYS.JOB_APP_TYPE: JOB_APP_TYPES.SERVICE,
      },
      "plugins": [
        {
          "SIGNATURE": "CONTAINER_APP_RUNNER",
          "INSTANCES": [
            {
              "INSTANCE_ID": "stale-instance",
              "plugin_name": "db",
              "IMAGE": "repo/db:latest",
              "CONTAINER_RESOURCES": {"cpu": 1, "memory": "128m"},
              "PER_NODE_TARGET_NODES": ["stale-node"],
              "PER_NODE_CONFIG": {
                "byIndex": {
                  "2": {"ENV": {"NODE_ID": "3"}},
                },
              },
            }
          ],
        }
      ],
    }
    running_apps_for_job = {
      "0xai_node_a": {
        "app-1": {
          "plugins": {
            "CONTAINER_APP_RUNNER": [
              {
                "instance": "existing-instance-a",
                "instance_conf": {"CHAINSTORE_RESPONSE_KEY": "resp-a"},
              }
            ],
          },
        },
      },
      "0xai_node_b": {
        "app-1": {
          "plugins": {
            "CONTAINER_APP_RUNNER": [
              {
                "instance": "existing-instance-b",
                "instance_conf": {"CHAINSTORE_RESPONSE_KEY": "resp-b"},
              }
            ],
          },
        },
      },
    }

    create_pipelines, update_pipelines, _response_keys = plugin.prepare_create_update_pipelines(
      base_pipeline=base_pipeline,
      new_nodes=["0xai_node_c"],
      update_nodes=["0xai_node_a", "0xai_node_b"],
      running_apps_for_job=running_apps_for_job,
    )

    expected_nodes = ["0xai_node_a", "0xai_node_b", "0xai_node_c"]
    created = create_pipelines["0xai_node_c"]["plugins"][0]["INSTANCES"][0]
    updated = update_pipelines["0xai_node_b"]["plugins"][0]["INSTANCES"][0]
    self.assertEqual(created["CHAINSTORE_PEERS"], expected_nodes)
    self.assertEqual(created["PER_NODE_TARGET_NODES"], expected_nodes)
    self.assertEqual(updated["CHAINSTORE_PEERS"], expected_nodes)
    self.assertEqual(updated["PER_NODE_TARGET_NODES"], expected_nodes)


if __name__ == "__main__":
  unittest.main()
