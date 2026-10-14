import copy
import hashlib
import unittest
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, unquote, urlsplit

from extensions.business.container_apps.cockroachdb_readiness import is_cockroachdb_service, probe_cockroachdb_readiness
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs, make_plugin_entry
from extensions.business.deeploy.tests.test_deployment_operations import Coordinator


class CockroachRecoveryTests(unittest.TestCase):
  def test_service_recognition_includes_exact_previous_configs_and_fails_closed(self):
    for image in ("ghcr.io/ratio1/r1db:stable", "ghcr.io/ratio1/r1db@sha256:abc",
                  "ghcr.io/ratio1/deeploy-cockroachdb-service:main"):
      self.assertTrue(is_cockroachdb_service(image, {}))
    self.assertTrue(is_cockroachdb_service(None, {"CRDB_NODE_COUNT": "3"}))
    self.assertTrue(is_cockroachdb_service(None, {"CRDB_HOSTNAMES": "roach1,roach2,roach3"}))
    self.assertFalse(is_cockroachdb_service("ghcr.io/ratio1/r1db-lookalike:stable", {}))
    self.assertFalse(is_cockroachdb_service("postgres:16", {}))

  def test_partial_certificate_rollout_stops_every_node_before_restoring_exact_configs(self):
    plugin = Coordinator()
    operation = plugin.operation("update")
    operation["previous_nodes"] = ["A", "B", "C"]
    operation["previous_instances"]["C"] = [("RUNNER", "worker")]
    plugin.plan["previous_configs"]["C"] = copy.deepcopy(plugin.plan["previous_configs"]["A"])
    for node, pipeline in plugin.plan["previous_configs"].items():
      instance = pipeline["PLUGINS"][0]["INSTANCES"][0]
      instance.update(
        FIXED_SIZE_VOLUMES={"cockroach_data": {"MOUNTING_POINT": "/cockroach/cockroach-data"}},
        ENV={"CRDB_NODE_ID": str(ord(node) - ord("A") + 1), "CRDB_CA_CRT": "__R1_DAUTH_SECRET__",
             "CF_TUNNEL_TOKEN": "__R1_DAUTH_SECRET__"},
      )
      pipeline["pipeline_params"] = {"deeploy_cockroachdb": {"clientTunnel": {"url": "original-client.test:26257"}}}
    previous = copy.deepcopy(plugin.plan["previous_configs"])
    plugin._save_operation(operation)
    plugin._advance_deployment_operation(operation)
    for node in operation["previous_nodes"]:
      plugin.report(operation, node, "stopped", attempt="retire")
    plugin._advance_deployment_operation(operation)
    plugin.report(operation, "A", "ready")
    plugin.report(operation, "B", "ready")
    plugin.report(operation, "C", "failed")
    plugin._advance_deployment_operation(operation)
    for node in ("A", "B"):
      plugin.report(operation, node, "stopped", sequence=2)
    plugin._advance_deployment_operation(operation)
    self.assertFalse(any(config["DEEPLOY_OPERATION"]["attempt"] == "restore" for _, config in plugin.commands))
    self.assertIsNone(operation["outcome"])
    plugin.report(operation, "C", "stopped", sequence=2)
    plugin._advance_deployment_operation(operation)
    plugin._advance_deployment_operation(operation)
    restored = {node: config for node, config in plugin.commands if config["DEEPLOY_OPERATION"]["attempt"] == "restore"}
    self.assertEqual(set(restored), set(previous))
    for node, config in restored.items():
      config.pop("DEEPLOY_OPERATION")
      self.assertEqual(config, previous[node])
    for node in ("A", "B"):
      plugin.report(operation, node, "ready", attempt="restore")
    plugin._advance_deployment_operation(operation)
    self.assertIsNone(operation["outcome"])
    plugin.report(operation, "C", "ready", attempt="restore")
    plugin._advance_deployment_operation(operation)
    plugin._advance_deployment_operation(operation)
    self.assertEqual((operation["outcome"], operation["recovery"]), ("failed", "completed"))

  def test_sql_probe_is_scoped_to_node_expected_certificate_and_secret_environment(self):
    container = Mock()
    container.exec_run.return_value = SimpleNamespace(exit_code=0)
    env = {
      "CRDB_NODE_ID": "3", "CRDB_DATABASE": "appdb", "CRDB_USER": "app_user",
      "CRDB_PASSWORD": "special:@/?# password", "CRDB_CA_CRT": "ca\n\n",
      "CRDB_NODE_CRT": "node\n", "CRDB_CERTS_DIR": "/custom/certs",
    }
    self.assertTrue(probe_cockroachdb_readiness(container, env))
    args, kwargs = container.exec_run.call_args
    self.assertNotIn(env["CRDB_PASSWORD"], str(args))
    self.assertTrue(kwargs["stdout"])
    self.assertTrue(kwargs["stderr"])
    self.assertEqual(args[0][:4], ["timeout", "--signal=TERM", "--kill-after=1s", "8s"])
    probe_env = kwargs["environment"]
    url = urlsplit(probe_env["COCKROACH_URL"])
    self.assertEqual((url.hostname, url.port, url.path), ("roach3", 26257, "/appdb"))
    self.assertEqual(unquote(url.password), env["CRDB_PASSWORD"])
    self.assertEqual(parse_qs(url.query)["sslmode"], ["verify-full"])
    self.assertEqual(parse_qs(url.query)["sslrootcert"], ["/custom/certs/ca.crt"])
    self.assertEqual(probe_env["R1_CA_SHA256"], hashlib.sha256(b"ca\n").hexdigest())
    self.assertEqual(probe_env["R1_NODE_SHA256"], hashlib.sha256(b"node\n").hexdigest())
    container.exec_run.return_value.exit_code = 1
    self.assertFalse(probe_cockroachdb_readiness(container, env))
    container.exec_run.side_effect = RuntimeError("potentially sensitive Docker exception")
    self.assertFalse(probe_cockroachdb_readiness(container, env))

  def test_missing_certificate_or_credentials_never_executes_a_weaker_probe(self):
    env = {
      "CRDB_NODE_ID": "1", "CRDB_DATABASE": "appdb", "CRDB_USER": "app_user",
      "CRDB_PASSWORD": "password", "CRDB_CA_CRT": "ca", "CRDB_NODE_CRT": "node",
    }
    for key in env:
      incomplete = {name: value for name, value in env.items() if name != key}
      container = Mock()
      self.assertFalse(probe_cockroachdb_readiness(container, incomplete))
      container.exec_run.assert_not_called()

  def test_regeneration_creates_new_ca_without_mutating_previous_certificates_or_storage(self):
    plugin = make_deeploy_plugin()
    nodes = ["A", "B", "C"]
    allocation = {"clientTunnel": {"url": "original-client.test:26257"}}
    inputs = make_inputs(
      plugins=[make_plugin_entry(
        "CONTAINER_APP_RUNNER", instance_id="database", IMAGE="ghcr.io/ratio1/r1db:stable",
        ENV={"CRDB_DATABASE": "appdb", "CRDB_USER": "app_user", "CRDB_PASSWORD": "password"},
        FIXED_SIZE_VOLUMES={"cockroach_data": {"SIZE": "8G", "MOUNTING_POINT": "/cockroach/cockroach-data"}},
        PER_NODE_CONFIG={"byNode": {
          node: {"ENV": {"CRDB_NODE_ID": str(index + 1), "CF_TUNNEL_TOKEN": "token-" + node}}
          for index, node in enumerate(nodes)
        }},
      )],
      pipeline_params={"deeploy_cockroachdb": allocation},
    )
    plugin._prepare_cockroachdb_secure_config(inputs, nodes)
    previous = copy.deepcopy(inputs)
    inputs["cockroachdb_certificate_regeneration_id"] = "11111111-1111-4111-8111-111111111111"
    inputs["chainstore_response"] = False
    operation_id, intent, applied = plugin._prepare_cockroachdb_regeneration_lifecycle(inputs, {})
    self.assertFalse(applied)
    plugin._prepare_cockroachdb_secure_config(inputs, nodes)
    new_instance = inputs["plugins"][0]
    old_instance = previous["plugins"][0]
    self.assertEqual(new_instance["FIXED_SIZE_VOLUMES"], old_instance["FIXED_SIZE_VOLUMES"])
    self.assertEqual(inputs["pipeline_params"]["deeploy_cockroachdb"]["clientTunnel"], allocation["clientTunnel"])
    for node in nodes:
      old = old_instance["PER_NODE_CONFIG"]["byNode"][node]["ENV"]
      new = new_instance["PER_NODE_CONFIG"]["byNode"][node]["ENV"]
      for key in ("CRDB_CA_CRT", "CRDB_NODE_CRT", "CRDB_NODE_KEY"):
        self.assertNotEqual(old[key], new[key])
      for key in ("CRDB_NODE_ID", "CF_TUNNEL_TOKEN"):
        self.assertEqual(old[key], new[key])
    lifecycle = inputs["pipeline_params"]["deeploy_cockroachdb"]
    self.assertEqual(lifecycle["certificateGenerationId"], operation_id)
    self.assertEqual(lifecycle["certificateRegenerationIntentSha256"], intent)

  def test_certificate_intent_ignores_delivery_fields_but_detects_service_changes(self):
    plugin = make_deeploy_plugin()
    original = {"plugins": [{"ENV": {"CRDB_USER": "app_user"}}]}
    expected = plugin._cockroachdb_regeneration_intent_hash(original)
    retry = {**original, "request_id": "retry", "expected_revision": 3, "chainstore_response": False}
    self.assertEqual(plugin._cockroachdb_regeneration_intent_hash(retry), expected)
    changed = copy.deepcopy(retry)
    changed["plugins"][0]["ENV"]["CRDB_USER"] = "different_user"
    self.assertNotEqual(plugin._cockroachdb_regeneration_intent_hash(changed), expected)
