import unittest
import copy
from collections import defaultdict
import ipaddress
import sys
import types

from cryptography import x509


for _mod_name in ("torch", "torch.nn", "torch.nn.functional"):
  sys.modules.setdefault(_mod_name, types.ModuleType(_mod_name))

from naeural_core.main.net_mon import NetMonCt

from extensions.business.deeploy.deeploy_const import (
  DEEPLOY_DYNAMIC_ENV_KEYS,
  DEEPLOY_DYNAMIC_ENV_TYPES,
  DEEPLOY_KEYS,
  DEEPLOY_PLUGIN_DATA,
  JOB_APP_TYPES,
)
from extensions.business.deeploy.tests.support import make_deeploy_plugin, make_inputs, make_plugin_entry


class _KeyErrorOnMissingAttrInputs(dict):
  def __getattr__(self, item):
    try:
      return self[item]
    except KeyError:
      raise KeyError(item)


class DeeployCreateRequestPreparationTests(unittest.TestCase):

  def _make_cockroachdb_secure_inputs(self, client_url="tcp.ratio1.link:30472"):
    return make_inputs(
      pipeline_params={
        "deeploy_cockroachdb": {
          "version": 1,
          "service": "cockroachdb",
          "status": "allocated",
          "nodeOrder": ["0xai_node_a", "0xai_node_b", "0xai_node_c"],
          "clientTunnel": {"url": client_url},
          "internalTunnels": [],
        },
      },
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="cockroachdb",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          ENV={
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "app_user",
            "CRDB_PASSWORD": "secret-password",
          },
          PER_NODE_CONFIG={
            "byNode": {
              "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1", "CF_TUNNEL_TOKEN": "token-a"}},
              "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2", "CF_TUNNEL_TOKEN": "token-b"}},
              "0xai_node_c": {"ENV": {"CRDB_NODE_ID": "3", "CF_TUNNEL_TOKEN": "token-c"}},
            },
          },
        ),
      ],
    )

  def test_cockroachdb_client_hostname_parser_accepts_tunnel_endpoint_forms(self):
    plugin = make_deeploy_plugin()

    self.assertEqual(
      plugin._cockroachdb_client_hostname("tcp.ratio1.link:30472"),
      "tcp.ratio1.link",
    )
    self.assertEqual(
      plugin._cockroachdb_client_hostname("tcp://db.example.test:26257"),
      "db.example.test",
    )
    self.assertEqual(plugin._cockroachdb_client_hostname("127.0.0.2:26257"), "127.0.0.2")

    for invalid in (
      "",
      "tcp://user:password@db.example.test:26257",
      "tcp://*.example.test:26257",
      "tcp://db.example.test:26257/path",
      "tcp://db.example.test:26257?query=value",
      "tcp://db.example.test:not-a-port",
      "tcp://db.example.test:70000",
    ):
      with self.subTest(invalid=invalid):
        with self.assertRaisesRegex(ValueError, "client tunnel"):
          plugin._cockroachdb_client_hostname(invalid)

  def test_managed_service_kind_resolves_explicit_legacy_and_persisted_cockroachdb(self):
    plugin = make_deeploy_plugin()
    cockroach_plugin = make_plugin_entry(
      "CONTAINER_APP_RUNNER",
      plugin_name="cockroachdb",
      IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
    )

    self.assertEqual(
      plugin._resolve_deeploy_service_kind(
        inputs=make_inputs(service_kind="cockroachdb", plugins=[cockroach_plugin]),
      ),
      "cockroachdb",
    )
    self.assertEqual(
      plugin._resolve_deeploy_service_kind(inputs=make_inputs(plugins=[cockroach_plugin])),
      "cockroachdb",
    )
    self.assertEqual(
      plugin._resolve_deeploy_service_kind(
        inputs=make_inputs(plugins=[cockroach_plugin]),
        deeploy_specs={DEEPLOY_KEYS.SERVICE_KIND: "cockroachdb"},
      ),
      "cockroachdb",
    )

  def test_managed_service_kind_recognizes_exact_r1_meshdb_and_legacy_repositories(self):
    plugin = make_deeploy_plugin()
    digest = "sha256:" + ("a" * 64)
    accepted = (
      "ghcr.io/ratio1/r1-meshdb:v1.0.0",
      f"ghcr.io/ratio1/r1-meshdb@{digest}",
      f"ghcr.io/ratio1/r1-meshdb:v1.0.0@{digest}",
      "ghcr.io/ratio1/deeploy-cockroachdb-service:main",
      f"ghcr.io/ratio1/deeploy-cockroachdb-service@{digest}",
      f"ghcr.io/ratio1/deeploy-cockroachdb-service:main@{digest}",
    )
    rejected = (
      "ghcr.io/example/r1-meshdb:latest",
      "ghcr.io/ratio1/r1-meshdb-helper:latest",
      "ghcr.io/ratio1/deeploy-cockroachdb-service2:main",
    )

    for image in accepted:
      with self.subTest(image=image):
        self.assertTrue(plugin._is_cockroachdb_plugin_instance({"IMAGE": image}))
    for image in rejected:
      with self.subTest(image=image):
        self.assertFalse(plugin._is_cockroachdb_plugin_instance({"IMAGE": image}))
        misleading = {
          "IMAGE": image,
          "plugin_name": "cockroachdb",
          "ENV": {"CRDB_NODE_COUNT": "3"},
        }
        self.assertFalse(plugin._is_cockroachdb_plugin_instance(misleading))

    candidate = make_plugin_entry("CONTAINER_APP_RUNNER", IMAGE=accepted[1])
    self.assertEqual(
      plugin._resolve_deeploy_service_kind(
        inputs=make_inputs(service_kind="cockroachdb", plugins=[candidate]),
      ),
      "cockroachdb",
    )

    near_match = make_plugin_entry(
      "CONTAINER_APP_RUNNER",
      plugin_name="cockroachdb",
      IMAGE=rejected[1],
      ENV={"CRDB_NODE_COUNT": "3"},
    )
    with self.assertRaisesRegex(ValueError, "service kind.*does not match"):
      plugin._resolve_deeploy_service_kind(
        inputs=make_inputs(service_kind="cockroachdb", plugins=[near_match]),
      )

  def test_managed_service_kind_rejects_unsupported_or_conflicting_identity(self):
    plugin = make_deeploy_plugin()
    postgres_plugin = make_plugin_entry(
      "CONTAINER_APP_RUNNER",
      plugin_name="postgres",
      IMAGE="postgres:17",
    )

    with self.assertRaisesRegex(ValueError, "Unsupported Deeploy service kind"):
      plugin._resolve_deeploy_service_kind(
        inputs=make_inputs(service_kind="postgresql", plugins=[postgres_plugin]),
      )
    with self.assertRaisesRegex(ValueError, "service kind.*does not match"):
      plugin._resolve_deeploy_service_kind(
        inputs=make_inputs(service_kind="cockroachdb", plugins=[postgres_plugin]),
      )
    with self.assertRaisesRegex(ValueError, "service kind.*does not match"):
      plugin._resolve_deeploy_service_kind(
        inputs=make_inputs(plugins=[postgres_plugin]),
        deeploy_specs={DEEPLOY_KEYS.SERVICE_KIND: "cockroachdb"},
      )

  def test_managed_service_kind_is_absent_for_ordinary_services(self):
    plugin = make_deeploy_plugin()
    postgres_plugin = make_plugin_entry(
      "CONTAINER_APP_RUNNER",
      plugin_name="postgres",
      IMAGE="postgres:17",
    )

    self.assertIsNone(
      plugin._resolve_deeploy_service_kind(inputs=make_inputs(plugins=[postgres_plugin]))
    )

  def test_managed_service_secure_config_matches_legacy_cockroachdb_hook(self):
    plugin = make_deeploy_plugin()
    nodes = ["0xai_node_a", "0xai_node_b", "0xai_node_c"]
    cert_bundle = plugin._generate_cockroachdb_cert_bundle(nodes, "tcp.ratio1.link")
    direct_inputs = self._make_cockroachdb_secure_inputs()
    generic_inputs = copy.deepcopy(direct_inputs)
    plugin._generate_cockroachdb_cert_bundle = (
      lambda target_nodes, client_hostname=None: copy.deepcopy(cert_bundle)
    )

    plugin._prepare_cockroachdb_secure_config(direct_inputs, nodes)
    service_kind = plugin._resolve_deeploy_service_kind(inputs=generic_inputs)
    plugin._prepare_managed_service_secure_config(service_kind, generic_inputs, nodes)

    self.assertEqual(generic_inputs, direct_inputs)

  def test_generated_cockroachdb_node_certificates_include_client_hostname(self):
    plugin = make_deeploy_plugin()

    bundle = plugin._generate_cockroachdb_cert_bundle(
      ["0xai_node_a", "0xai_node_b"],
      client_hostname="tcp.ratio1.link",
    )

    for node in ("0xai_node_a", "0xai_node_b"):
      cert = x509.load_pem_x509_certificate(bundle[node]["CRDB_NODE_CRT"].encode("ascii"))
      san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
      self.assertIn("tcp.ratio1.link", san.get_values_for_type(x509.DNSName))
      self.assertIn("roach1", san.get_values_for_type(x509.DNSName))
      self.assertIn("roach2", san.get_values_for_type(x509.DNSName))
      self.assertIn("localhost", san.get_values_for_type(x509.DNSName))

    ip_bundle = plugin._generate_cockroachdb_cert_bundle(
      ["0xai_node_a", "0xai_node_b"],
      client_hostname="127.0.0.2",
    )
    ip_cert = x509.load_pem_x509_certificate(ip_bundle["0xai_node_a"]["CRDB_NODE_CRT"].encode("ascii"))
    ip_san = ip_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    self.assertIn(ipaddress.ip_address("127.0.0.2"), ip_san.get_values_for_type(x509.IPAddress))

  def test_cockroachdb_secure_config_reuses_hostname_bound_bundle_and_forces_one_generation(self):
    plugin = make_deeploy_plugin()
    inputs = self._make_cockroachdb_secure_inputs()
    nodes = ["0xai_node_a", "0xai_node_b", "0xai_node_c"]

    plugin._prepare_cockroachdb_secure_config(inputs, nodes)
    allocation = inputs[DEEPLOY_KEYS.PIPELINE_PARAMS]["deeploy_cockroachdb"]
    first_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"][nodes[0]]["ENV"]["CRDB_NODE_KEY"]
    self.assertEqual(allocation["certificateHostname"], "tcp.ratio1.link")

    plugin._prepare_cockroachdb_secure_config(inputs, nodes)
    reused_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"][nodes[0]]["ENV"]["CRDB_NODE_KEY"]
    self.assertEqual(reused_key, first_key)

    inputs["cockroachdb_certificate_regeneration_id"] = "11111111-1111-4111-8111-111111111111"
    plugin._prepare_cockroachdb_secure_config(inputs, nodes)
    regenerated_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"][nodes[0]]["ENV"]["CRDB_NODE_KEY"]
    self.assertNotEqual(regenerated_key, first_key)
    self.assertEqual(
      allocation["certificateGenerationId"],
      "11111111-1111-4111-8111-111111111111",
    )

    plugin._prepare_cockroachdb_secure_config(inputs, nodes)
    replay_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"][nodes[0]]["ENV"]["CRDB_NODE_KEY"]
    self.assertEqual(replay_key, regenerated_key)

    inputs.pop("cockroachdb_certificate_regeneration_id")
    allocation["clientTunnel"]["url"] = "replacement.example.test:26257"
    plugin._prepare_cockroachdb_secure_config(inputs, nodes)
    self.assertNotIn("certificateGenerationId", allocation)
    self.assertNotIn("certificateRegenerationIntentSha256", allocation)

  def test_cockroachdb_secure_config_regenerates_when_managed_hostname_changes(self):
    plugin = make_deeploy_plugin()
    inputs = self._make_cockroachdb_secure_inputs("old.example.test:26257")
    nodes = ["0xai_node_a", "0xai_node_b", "0xai_node_c"]

    plugin._prepare_cockroachdb_secure_config(inputs, nodes)
    first_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"][nodes[0]]["ENV"]["CRDB_NODE_KEY"]
    allocation = inputs[DEEPLOY_KEYS.PIPELINE_PARAMS]["deeploy_cockroachdb"]
    allocation["clientTunnel"]["url"] = "new.example.test:26257"

    plugin._prepare_cockroachdb_secure_config(inputs, nodes)

    second_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"][nodes[0]]["ENV"]["CRDB_NODE_KEY"]
    self.assertNotEqual(second_key, first_key)
    self.assertEqual(allocation["certificateHostname"], "new.example.test")

  def test_cockroachdb_regeneration_ignores_request_supplied_lifecycle_metadata(self):
    plugin = make_deeploy_plugin()
    inputs = self._make_cockroachdb_secure_inputs()
    nodes = ["0xai_node_a", "0xai_node_b", "0xai_node_c"]
    plugin._prepare_cockroachdb_secure_config(inputs, nodes)
    original_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"][nodes[0]]["ENV"][
      "CRDB_NODE_KEY"
    ]
    allocation = inputs[DEEPLOY_KEYS.PIPELINE_PARAMS]["deeploy_cockroachdb"]
    persisted_allocation = copy.deepcopy(allocation)
    persisted_allocation["certificateGenerationId"] = "11111111-1111-4111-8111-111111111111"
    persisted_allocation["certificateRegenerationIntentSha256"] = "old-intent"
    new_id = "22222222-2222-4222-8222-222222222222"
    allocation["certificateGenerationId"] = new_id
    allocation["certificateRegenerationIntentSha256"] = "caller-controlled"
    inputs["cockroachdb_certificate_regeneration_id"] = new_id
    inputs[DEEPLOY_KEYS.CHAINSTORE_RESPONSE] = True

    plugin._prepare_cockroachdb_regeneration_lifecycle(
      inputs,
      {
        DEEPLOY_KEYS.JOB_CONFIG: {
          DEEPLOY_KEYS.PIPELINE_PARAMS: {"deeploy_cockroachdb": persisted_allocation},
        },
      },
    )
    self.assertEqual(
      allocation["certificateGenerationId"],
      "11111111-1111-4111-8111-111111111111",
    )

    plugin._prepare_cockroachdb_secure_config(inputs, nodes)

    regenerated_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"][nodes[0]]["ENV"][
      "CRDB_NODE_KEY"
    ]
    self.assertNotEqual(regenerated_key, original_key)
    self.assertEqual(allocation["certificateGenerationId"], new_id)

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

  def test_plugins_array_normalization_moves_single_top_level_per_node_config_into_plugin(self):
    plugin = make_deeploy_plugin()
    request = {
      DEEPLOY_KEYS.PLUGINS: [
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="cockroachdb",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
        ),
      ],
      "PER_NODE_CONFIG": {
        "byNode": {
          "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1"}},
          "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2"}},
        },
      },
    }

    normalized = plugin._normalize_plugins_input(request)

    self.assertNotIn("PER_NODE_CONFIG", normalized)
    self.assertEqual(
      normalized[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"],
      {
        "byNode": {
          "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1"}},
          "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2"}},
        },
      },
    )

  def test_plugins_array_normalization_rejects_ambiguous_top_level_per_node_config(self):
    plugin = make_deeploy_plugin()
    request = {
      DEEPLOY_KEYS.PLUGINS: [
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="db"),
        make_plugin_entry("WORKER_APP_RUNNER", plugin_name="worker"),
      ],
      "PER_NODE_CONFIG": {
        "byIndex": {
          "0": {"ENV": {"NODE_ID": "1"}},
        },
      },
    }

    with self.assertRaisesRegex(ValueError, "exactly one plugin"):
      plugin._normalize_plugins_input(request)

  def test_top_level_per_node_config_rejects_duplicate_spellings(self):
    plugin = make_deeploy_plugin()
    request = {
      DEEPLOY_KEYS.PLUGINS: [
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="db"),
      ],
      "perNodeConfig": {
        "byIndex": {
          "0": {"ENV": {"NODE_ID": "camel"}},
        },
      },
      "PER_NODE_CONFIG": {
        "byIndex": {
          "0": {"ENV": {"NODE_ID": "upper"}},
        },
      },
    }

    with self.assertRaisesRegex(ValueError, "Only one top-level perNodeConfig"):
      plugin._normalize_plugins_input(request)

  def test_normalized_plugins_input_sync_removes_stale_top_level_per_node_config(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="cockroachdb",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
        ),
      ],
      PER_NODE_CONFIG={
        "byIndex": {
          "0": {"ENV": {"CRDB_NODE_ID": "1"}},
        },
      },
    )
    normalized = plugin._normalize_plugins_input(plugin.deepcopy(inputs))

    plugin._sync_normalized_plugins_input(inputs, normalized)
    prepared = plugin.deeploy_prepare_plugins(inputs)

    self.assertNotIn("PER_NODE_CONFIG", inputs)
    instance = prepared[0][plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    self.assertEqual(instance["PER_NODE_CONFIG"]["byIndex"], {
      "0": {"ENV": {"CRDB_NODE_ID": "1"}},
    })

  def test_get_request_per_node_config_tolerates_keyerror_missing_attributes(self):
    plugin = make_deeploy_plugin()
    inputs = _KeyErrorOnMissingAttrInputs({
      DEEPLOY_KEYS.PLUGINS: [
        make_plugin_entry("CONTAINER_APP_RUNNER", plugin_name="db"),
      ],
    })

    self.assertEqual(plugin._get_request_per_node_config(inputs), (None, None))

  def test_per_node_config_rejects_malformed_structured_sections(self):
    plugin = make_deeploy_plugin()

    with self.assertRaisesRegex(ValueError, "default must be a dictionary"):
      plugin._normalize_per_node_config({"default": []})
    with self.assertRaisesRegex(ValueError, "byIndex must be a dictionary"):
      plugin._normalize_per_node_config({"byIndex": ""})
    with self.assertRaisesRegex(ValueError, "duplicate aliases"):
      plugin._normalize_per_node_config({"byIndex": {}, "BY_INDEX": {}})

  def test_per_node_config_canonicalizes_overlay_keys_and_rejects_collisions(self):
    plugin = make_deeploy_plugin()

    _default, by_index, _by_node = plugin._normalize_per_node_config({
      "byIndex": {"0": {"ai_engine": "llama_cpp_medium"}},
    })
    self.assertEqual(by_index[0], {"AI_ENGINE": "llama_cpp_medium"})

    with self.assertRaisesRegex(ValueError, "duplicate normalized key 'AI_ENGINE'"):
      plugin._normalize_per_node_config({
        "byIndex": {
          "0": {
            "AI_ENGINE": "llama_cpp_small",
            "ai_engine": "llama_cpp_medium",
          },
        },
      })

  def test_per_node_config_rejects_one_shot_commands(self):
    plugin = make_deeploy_plugin()

    for command_key in ("INSTANCE_COMMAND", "INSTANCE_COMMAND_LAST"):
      with self.subTest(command_key=command_key), self.assertRaisesRegex(
        ValueError, "system-managed"
      ):
        plugin._normalize_per_node_config({
          "byIndex": {"0": {command_key.lower(): {"COMMAND": "RESTART"}}},
        })

  def test_per_node_config_rejects_duplicate_normalized_selectors(self):
    plugin = make_deeploy_plugin()

    with self.assertRaisesRegex(ValueError, "duplicate normalized index 1"):
      plugin._normalize_per_node_config({
        "byIndex": {
          "01": {"ENV": {"NODE_ID": "first"}},
          "1": {"ENV": {"NODE_ID": "second"}},
        },
      })
    with self.assertRaisesRegex(ValueError, "duplicate node selector '1'"):
      plugin._normalize_per_node_config({
        "byNode": {
          1: {"ENV": {"NODE_ID": "first"}},
          "1": {"ENV": {"NODE_ID": "second"}},
        },
      })

  def test_per_node_config_rejects_normalized_nested_alias(self):
    plugin = make_deeploy_plugin()

    with self.assertRaisesRegex(ValueError, "Nested .* overlays"):
      plugin._normalize_per_node_config({
        "byIndex": {"0": {"PerNodeConfig": {}}},
      })

  def test_log_redaction_masks_per_node_config_and_token_keys(self):
    plugin = make_deeploy_plugin()

    redacted = plugin._redact_per_node_config_for_log({
      DEEPLOY_KEYS.PLUGINS: [{
        "EXPOSED_PORTS": {
          "26257": {
            "token": "cf-token",
            "apiKey": "api-key",
            "privateKey": "private-key",
            "protocol": "tcp",
          },
        },
        "ENV": {
          "R1EN_CSTORE_AUTH_BOOTSTRAP_ADMIN_PWD": "admin-pwd",
        },
        "PER_NODE_CONFIG": {
          "byNode": {
            "0xai_node_a": {
              "ENV": {
                "CF_TUNNEL_TOKEN": "node-token",
              },
            },
          },
        },
      }],
    })

    serialized = str(redacted)
    self.assertNotIn("cf-token", serialized)
    self.assertNotIn("api-key", serialized)
    self.assertNotIn("private-key", serialized)
    self.assertNotIn("admin-pwd", serialized)
    self.assertNotIn("node-token", serialized)
    self.assertIn("'token': '***'", serialized)
    self.assertIn("'apiKey': '***'", serialized)
    self.assertIn("'privateKey': '***'", serialized)
    self.assertIn("'R1EN_CSTORE_AUTH_BOOTSTRAP_ADMIN_PWD': '***'", serialized)
    self.assertIn("'PER_NODE_CONFIG': '***'", serialized)

  def test_cockroachdb_secure_config_generates_node_certs_and_redacts_them(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="cockroachdb",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          ENV={
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "app_user",
            "CRDB_PASSWORD": "secret-password",
          },
          PER_NODE_CONFIG={
            "byNode": {
              "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1", "CF_TUNNEL_TOKEN": "token-a"}},
              "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2", "CF_TUNNEL_TOKEN": "token-b"}},
              "0xai_node_c": {"ENV": {"CRDB_NODE_ID": "3", "CF_TUNNEL_TOKEN": "token-c"}},
            },
          },
        ),
      ],
    )

    plugin._prepare_cockroachdb_secure_config(inputs, ["0xai_node_a", "0xai_node_b", "0xai_node_c"])

    instance = inputs[DEEPLOY_KEYS.PLUGINS][0]
    self.assertEqual(instance["ENV"]["CRDB_SECURE"], "true")
    by_node = instance["PER_NODE_CONFIG"]["byNode"]
    node_a_env = by_node["0xai_node_a"]["ENV"]
    node_b_env = by_node["0xai_node_b"]["ENV"]
    for env in (node_a_env, node_b_env):
      self.assertIn("-----BEGIN CERTIFICATE-----", env["CRDB_CA_CRT"])
      self.assertIn("-----BEGIN CERTIFICATE-----", env["CRDB_NODE_CRT"])
      self.assertIn("-----BEGIN RSA PRIVATE KEY-----", env["CRDB_NODE_KEY"])
      self.assertNotIn("CRDB_CA_KEY", env)
    self.assertIn("CRDB_CLIENT_ROOT_CRT", node_a_env)
    self.assertIn("CRDB_CLIENT_ROOT_KEY", node_a_env)
    self.assertNotIn("CRDB_CLIENT_ROOT_CRT", node_b_env)
    self.assertNotIn("CRDB_CLIENT_ROOT_KEY", node_b_env)
    self.assertEqual(node_a_env["CF_TUNNEL_TOKEN"], "token-a")

    redacted = plugin._redact_per_node_config_for_log(inputs)
    serialized = str(redacted)
    self.assertNotIn("secret-password", serialized)
    self.assertNotIn("BEGIN RSA PRIVATE KEY", serialized)
    self.assertIn("'PER_NODE_CONFIG': '***'", serialized)

  def test_cockroachdb_secure_config_accepts_camelcase_per_node_config(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="cockroachdb",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          ENV={
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "app_user",
            "CRDB_PASSWORD": "secret-password",
          },
          perNodeConfig={
            "byNode": {
              "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1", "CF_TUNNEL_TOKEN": "token-a"}},
              "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2", "CF_TUNNEL_TOKEN": "token-b"}},
              "0xai_node_c": {"ENV": {"CRDB_NODE_ID": "3", "CF_TUNNEL_TOKEN": "token-c"}},
            },
          },
        ),
      ],
    )

    plugin._prepare_cockroachdb_secure_config(inputs, ["0xai_node_a", "0xai_node_b", "0xai_node_c"])

    instance = inputs[DEEPLOY_KEYS.PLUGINS][0]
    self.assertNotIn("perNodeConfig", instance)
    by_node = instance["PER_NODE_CONFIG"]["byNode"]
    self.assertEqual(by_node["0xai_node_a"]["ENV"]["CF_TUNNEL_TOKEN"], "token-a")
    self.assertEqual(by_node["0xai_node_b"]["ENV"]["CRDB_NODE_ID"], "2")
    self.assertIn("CRDB_NODE_KEY", by_node["0xai_node_a"]["ENV"])

  def test_cockroachdb_secure_config_reuses_existing_bundle_for_same_nodes(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          ENV={
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "app_user",
            "CRDB_PASSWORD": "secret-password",
          },
          PER_NODE_CONFIG={
            "byNode": {
              "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1", "CF_TUNNEL_TOKEN": "token-a"}},
              "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2", "CF_TUNNEL_TOKEN": "token-b"}},
              "0xai_node_c": {"ENV": {"CRDB_NODE_ID": "3", "CF_TUNNEL_TOKEN": "token-c"}},
            },
          },
        ),
      ],
    )

    plugin._prepare_cockroachdb_secure_config(inputs, ["0xai_node_a", "0xai_node_b", "0xai_node_c"])
    node_a_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"]["0xai_node_a"]["ENV"]["CRDB_NODE_KEY"]

    plugin._prepare_cockroachdb_secure_config(inputs, ["0xai_node_a", "0xai_node_b", "0xai_node_c"])

    reused_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"]["0xai_node_a"]["ENV"]["CRDB_NODE_KEY"]
    self.assertEqual(node_a_key, reused_key)

  def test_cockroachdb_secure_config_regenerates_for_scale_up(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          ENV={
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "app_user",
            "CRDB_PASSWORD": "secret-password",
          },
          PER_NODE_CONFIG={
            "byNode": {
              "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1", "CF_TUNNEL_TOKEN": "token-a"}},
              "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2", "CF_TUNNEL_TOKEN": "token-b"}},
              "0xai_node_c": {"ENV": {"CRDB_NODE_ID": "3", "CF_TUNNEL_TOKEN": "token-c"}},
            },
          },
        ),
      ],
    )

    plugin._prepare_cockroachdb_secure_config(inputs, ["0xai_node_a", "0xai_node_b", "0xai_node_c"])
    first_key = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"]["0xai_node_a"]["ENV"]["CRDB_NODE_KEY"]
    inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"]["0xai_node_d"] = {
      "ENV": {"CRDB_NODE_ID": "4", "CF_TUNNEL_TOKEN": "token-d"}
    }

    plugin._prepare_cockroachdb_secure_config(
      inputs,
      ["0xai_node_a", "0xai_node_b", "0xai_node_c", "0xai_node_d"],
    )

    by_node = inputs[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"]["byNode"]
    self.assertNotEqual(first_key, by_node["0xai_node_a"]["ENV"]["CRDB_NODE_KEY"])
    self.assertIn("CRDB_NODE_KEY", by_node["0xai_node_d"]["ENV"])
    self.assertEqual(by_node["0xai_node_d"]["ENV"]["CF_TUNNEL_TOKEN"], "token-d")

  def test_cockroachdb_pipeline_secure_config_regenerates_for_legacy_scale_up(self):
    plugin = make_deeploy_plugin()
    pipeline = {
      NetMonCt.PLUGINS: [{
        "SIGNATURE": "CONTAINER_APP_RUNNER",
        "INSTANCES": [{
          "IMAGE": "ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          "ENV": {
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "app_user",
            "CRDB_PASSWORD": "secret-password",
            "CRDB_NODE_COUNT": "3",
            "CRDB_HOSTNAMES": "roach1.example,roach2.example,roach3.example",
          },
          "PER_NODE_CONFIG": {
            "byNode": {
              "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1", "CF_TUNNEL_TOKEN": "token-a"}},
              "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2", "CF_TUNNEL_TOKEN": "token-b"}},
              "0xai_node_c": {"ENV": {"CRDB_NODE_ID": "3", "CF_TUNNEL_TOKEN": "token-c"}},
            },
          },
        }],
      }],
    }

    plugin._prepare_cockroachdb_secure_config_for_pipeline(
      pipeline,
      ["0xai_node_a", "0xai_node_b", "0xai_node_c"],
    )
    first_key = pipeline[NetMonCt.PLUGINS][0]["INSTANCES"][0]["PER_NODE_CONFIG"]["byNode"]["0xai_node_a"]["ENV"]["CRDB_NODE_KEY"]
    pipeline[NetMonCt.PLUGINS][0]["INSTANCES"][0]["PER_NODE_CONFIG"]["byNode"]["0xai_node_d"] = {
      "ENV": {"CRDB_NODE_ID": "4", "CF_TUNNEL_TOKEN": "token-d"}
    }

    with self.assertRaisesRegex(ValueError, "CRDB_HOSTNAMES"):
      plugin._prepare_cockroachdb_secure_config_for_pipeline(
        pipeline,
        ["0xai_node_a", "0xai_node_b", "0xai_node_c", "0xai_node_d"],
      )

    pipeline[NetMonCt.PLUGINS][0]["INSTANCES"][0]["ENV"]["CRDB_HOSTNAMES"] = (
      "roach1.example,roach2.example,roach3.example,roach4.example"
    )
    plugin._prepare_cockroachdb_secure_config_for_pipeline(
      pipeline,
      ["0xai_node_a", "0xai_node_b", "0xai_node_c", "0xai_node_d"],
    )

    instance = pipeline[NetMonCt.PLUGINS][0]["INSTANCES"][0]
    by_node = instance["PER_NODE_CONFIG"]["byNode"]
    self.assertEqual(instance["ENV"]["CRDB_SECURE"], "true")
    self.assertEqual(instance["ENV"]["CRDB_NODE_COUNT"], "4")
    self.assertEqual(
      instance["ENV"]["CRDB_HOSTNAMES"],
      "roach1.example,roach2.example,roach3.example,roach4.example",
    )
    self.assertNotEqual(first_key, by_node["0xai_node_a"]["ENV"]["CRDB_NODE_KEY"])
    self.assertIn("CRDB_NODE_KEY", by_node["0xai_node_d"]["ENV"])
    self.assertEqual(by_node["0xai_node_d"]["ENV"]["CF_TUNNEL_TOKEN"], "token-d")

  def test_cockroachdb_secure_config_rejects_reserved_or_unsafe_identifiers(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          ENV={
            "CRDB_DATABASE": "app-db",
            "CRDB_USER": "root",
            "CRDB_PASSWORD": "secret-password",
          },
        ),
      ],
    )

    with self.assertRaisesRegex(ValueError, "SQL identifier"):
      plugin._prepare_cockroachdb_secure_config(inputs, ["0xai_node_a", "0xai_node_b", "0xai_node_c"])

    inputs[DEEPLOY_KEYS.PLUGINS][0]["ENV"]["CRDB_DATABASE"] = "appdb"
    for reserved_user in ("root", "ROOT", "admin", "AdMiN", "node", "public"):
      with self.subTest(reserved_user=reserved_user):
        inputs[DEEPLOY_KEYS.PLUGINS][0]["ENV"]["CRDB_USER"] = reserved_user
        with self.assertRaisesRegex(ValueError, "reserved"):
          plugin._prepare_cockroachdb_secure_config(
            inputs,
            ["0xai_node_a", "0xai_node_b", "0xai_node_c"],
          )

  def test_legacy_pipeline_rejects_reserved_user_before_certificate_generation(self):
    plugin = make_deeploy_plugin()
    generation_calls = []
    plugin._generate_cockroachdb_cert_bundle = (
      lambda *args, **kwargs: generation_calls.append((args, kwargs))
    )
    pipeline = {
      NetMonCt.PLUGINS: [{
        "SIGNATURE": "CONTAINER_APP_RUNNER",
        "INSTANCES": [{
          "IMAGE": "ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          "ENV": {
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "admin",
            "CRDB_PASSWORD": "secret-password",
          },
        }],
      }],
    }

    with self.assertRaisesRegex(ValueError, "reserved"):
      plugin._prepare_cockroachdb_secure_config_for_pipeline(
        pipeline,
        ["0xai_node_a", "0xai_node_b", "0xai_node_c"],
      )

    self.assertEqual(generation_calls, [])

  def test_deeploy_status_payload_keeps_cockroachdb_config_unredacted(self):
    payload = {
      DEEPLOY_KEYS.PIPELINE: {
        NetMonCt.PLUGINS.upper(): [{
          "SIGNATURE": "CONTAINER_APP_RUNNER",
          "INSTANCES": [{
            "ENV": {
              "CRDB_PASSWORD": "secret-password",
              "CRDB_NODE_KEY": "-----BEGIN RSA PRIVATE KEY-----private",
            },
            "EXPOSED_PORTS": [{
              "token": "client-facing-token",
            }],
            "PER_NODE_CONFIG": {
              "byNode": {
                "0xai_node_a": {
                  "ENV": {
                    "CF_TUNNEL_TOKEN": "internal-token",
                    "CRDB_CLIENT_ROOT_KEY": "-----BEGIN RSA PRIVATE KEY-----root",
                  },
                },
              },
            },
          }],
        }],
      },
    }

    serialized = str(payload)
    self.assertIn("secret-password", serialized)
    self.assertIn("client-facing-token", serialized)
    self.assertIn("internal-token", serialized)
    self.assertIn("BEGIN RSA PRIVATE KEY", serialized)
    instance = payload[DEEPLOY_KEYS.PIPELINE][NetMonCt.PLUGINS.upper()][0]["INSTANCES"][0]
    self.assertIsInstance(instance["PER_NODE_CONFIG"], dict)
    self.assertEqual(
      instance["PER_NODE_CONFIG"]["byNode"]["0xai_node_a"]["ENV"]["CF_TUNNEL_TOKEN"],
      "internal-token",
    )
    self.assertEqual(
      instance["PER_NODE_CONFIG"]["byNode"]["0xai_node_a"]["ENV"]["CRDB_CLIENT_ROOT_KEY"],
      "-----BEGIN RSA PRIVATE KEY-----root",
    )
    self.assertEqual(instance["ENV"]["CRDB_PASSWORD"], "secret-password")
    self.assertEqual(instance["ENV"]["CRDB_NODE_KEY"], "-----BEGIN RSA PRIVATE KEY-----private")
    self.assertEqual(instance["EXPOSED_PORTS"][0]["token"], "client-facing-token")

  def test_cockroachdb_target_change_policy_blocks_scale_down_reorder_and_replacement(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          ENV={
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "app_user",
            "CRDB_PASSWORD": "secret-password",
          },
        ),
      ],
    )

    self.assertTrue(plugin._validate_cockroachdb_target_change([], ["0xai_a", "0xai_b", "0xai_c"], inputs))
    self.assertTrue(
      plugin._validate_cockroachdb_target_change(
        ["0xai_a", "0xai_b"],
        ["0xai_a", "0xai_b", "0xai_c"],
        inputs,
      )
    )
    with self.assertRaisesRegex(ValueError, "must append"):
      plugin._validate_cockroachdb_target_change(
        ["0xai_a", "0xai_b"],
        ["0xai_replacement", "0xai_b", "0xai_c"],
        inputs,
      )
    with self.assertRaisesRegex(ValueError, "must append"):
      plugin._validate_cockroachdb_target_change(
        ["0xai_a", "0xai_b"],
        ["0xai_b", "0xai_a", "0xai_c"],
        inputs,
      )
    with self.assertRaisesRegex(ValueError, "at least 3"):
      plugin._validate_cockroachdb_target_change([], ["0xai_a", "0xai_b"], inputs)
    with self.assertRaisesRegex(ValueError, "at least 3"):
      plugin._validate_cockroachdb_target_change([], ["0xai_a"], inputs)
    with self.assertRaisesRegex(ValueError, "distinct addresses"):
      plugin._validate_cockroachdb_target_change([], ["0xai_a", "0xai_a", "0xai_a"], inputs)
    with self.assertRaisesRegex(ValueError, "scale-down"):
      plugin._validate_cockroachdb_target_change(
        ["0xai_a", "0xai_b", "0xai_c", "0xai_d"],
        ["0xai_a", "0xai_b", "0xai_c"],
        inputs,
      )
    with self.assertRaisesRegex(ValueError, "reordering"):
      plugin._validate_cockroachdb_target_change(
        ["0xai_a", "0xai_b", "0xai_c"],
        ["0xai_b", "0xai_a", "0xai_c"],
        inputs,
      )
    with self.assertRaisesRegex(ValueError, "replacement or reordering"):
      plugin._validate_cockroachdb_target_change(
        ["0xai_a", "0xai_b", "0xai_c"],
        ["0xai_a", "0xai_b", "0xai_replacement"],
        inputs,
      )

  def test_cockroachdb_secure_config_rejects_fewer_than_three_nodes(self):
    plugin = make_deeploy_plugin()
    certificate_generation_calls = []
    plugin._generate_cockroachdb_cert_bundle = (
      lambda *args, **kwargs: certificate_generation_calls.append((args, kwargs))
    )
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          IMAGE="ghcr.io/ratio1/deeploy-cockroachdb-service:main",
          ENV={
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "app_user",
            "CRDB_PASSWORD": "secret-password",
          },
          PER_NODE_CONFIG={
            "byNode": {
              "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1", "CF_TUNNEL_TOKEN": "token-a"}},
              "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2", "CF_TUNNEL_TOKEN": "token-b"}},
            },
          },
        ),
      ],
    )

    with self.assertRaisesRegex(ValueError, "at least 3"):
      plugin._prepare_cockroachdb_secure_config(inputs, ["0xai_node_a", "0xai_node_b"])
    self.assertEqual(certificate_generation_calls, [])
    with self.assertRaisesRegex(ValueError, "distinct addresses"):
      plugin._prepare_cockroachdb_secure_config(
        inputs,
        ["0xai_node_a", "0xai_node_a", "0xai_node_a"],
      )
    self.assertEqual(certificate_generation_calls, [])

    pipeline = {
      NetMonCt.PLUGINS: [{
        "SIGNATURE": "CONTAINER_APP_RUNNER",
        "INSTANCES": [copy.deepcopy(inputs[DEEPLOY_KEYS.PLUGINS][0])],
      }],
    }
    with self.assertRaisesRegex(ValueError, "at least 3"):
      plugin._prepare_cockroachdb_secure_config_for_pipeline(
        pipeline,
        ["0xai_node_a", "0xai_node_b"],
      )
    self.assertEqual(certificate_generation_calls, [])
    with self.assertRaisesRegex(ValueError, "distinct addresses"):
      plugin._prepare_cockroachdb_secure_config_for_pipeline(
        pipeline,
        ["0xai_node_a", "0xai_node_a", "0xai_node_a"],
      )
    self.assertEqual(certificate_generation_calls, [])

  def test_running_pipeline_context_uses_persisted_target_order_over_discovery_order(self):
    plugin = make_deeploy_plugin()
    plugin._discover_plugin_instances = lambda **kwargs: [
      {DEEPLOY_PLUGIN_DATA.NODE: "0xai_node_b"},
      {DEEPLOY_PLUGIN_DATA.NODE: "0xai_node_a"},
    ]
    plugin._prepare_updated_deeploy_specs = lambda **kwargs: {
      DEEPLOY_KEYS.CURRENT_TARGET_NODES: ["0xai_node_a", "0xai_node_b"],
    }

    context = plugin._gather_running_pipeline_context(owner="0xowner", job_id=1)

    self.assertEqual(context["discovered_nodes"], ["0xai_node_b", "0xai_node_a"])
    self.assertEqual(context["nodes"], ["0xai_node_a", "0xai_node_b"])

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

  def test_prepare_plugins_rejects_backend_source_shmem_shape(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry("A_SIMPLE_PLUGIN", plugin_name="provider", PROCESS_DELAY=5),
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="frontend",
          IMAGE="repo/app:latest",
          DYNAMIC_ENV={
            "API_HOST": [
              {
                DEEPLOY_DYNAMIC_ENV_KEYS.SOURCE: DEEPLOY_DYNAMIC_ENV_TYPES.SHMEM,
                DEEPLOY_DYNAMIC_ENV_KEYS.PATH: ["provider", "PORT"],
              }
            ]
          },
        ),
      ]
    )

    with self.assertRaisesRegex(ValueError, "source='shmem'"):
      plugin.deeploy_prepare_plugins(inputs, app_id="app-1")

  def test_normalize_plugins_input_moves_legacy_top_level_per_node_config_to_generated_plugin(self):
    plugin = make_deeploy_plugin()
    request = {
      DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
      DEEPLOY_KEYS.APP_PARAMS: {"IMAGE": "repo/app:latest"},
      "perNodeConfig": {"node-1": {"ENV": {"REGION": "eu"}}},
    }

    normalized = plugin._normalize_plugins_input(request)

    self.assertEqual(normalized[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"], {"node-1": {"ENV": {"REGION": "eu"}}})
    self.assertNotIn("perNodeConfig", normalized)
    self.assertNotIn("perNodeConfig", normalized[DEEPLOY_KEYS.APP_PARAMS])

  def test_normalize_plugins_input_moves_single_explicit_plugin_top_level_per_node_config(self):
    plugin = make_deeploy_plugin()
    request = {
      DEEPLOY_KEYS.PLUGINS: [
        make_plugin_entry("CONTAINER_APP_RUNNER", IMAGE="repo/app:latest"),
      ],
      "PER_NODE_CONFIG": {"node-1": {"ENV": {"REGION": "eu"}}},
    }

    normalized = plugin._normalize_plugins_input(request)

    self.assertNotIn("PER_NODE_CONFIG", normalized)
    self.assertEqual(
      normalized[DEEPLOY_KEYS.PLUGINS][0]["PER_NODE_CONFIG"],
      {"node-1": {"ENV": {"REGION": "eu"}}},
    )

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

  def test_prepare_plugins_rejects_unknown_dynamic_env_backend_type(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="frontend",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "256m"},
          DYNAMIC_ENV={
            "API_URL": [
              {"type": "container_ip", "provider": "api"}
            ],
          },
        ),
      ]
    )

    with self.assertRaisesRegex(ValueError, "unsupported type 'container_ip'"):
      plugin.deeploy_prepare_plugins(inputs, app_id="app-1")

  def test_prepare_plugins_rejects_ui_only_plugin_value_dynamic_env_type(self):
    plugin = make_deeploy_plugin()
    inputs = make_inputs(
      plugins=[
        make_plugin_entry(
          "CONTAINER_APP_RUNNER",
          plugin_name="frontend",
          IMAGE="repo/app:latest",
          CONTAINER_RESOURCES={"cpu": 1, "memory": "256m"},
          DYNAMIC_ENV={
            "API_URL": [
              {"type": "plugin_value", "provider": "api", "key": "PORT"}
            ],
          },
        ),
      ]
    )

    with self.assertRaisesRegex(ValueError, "unsupported type 'plugin_value'"):
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
