import unittest

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs


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


if __name__ == "__main__":
  unittest.main()
