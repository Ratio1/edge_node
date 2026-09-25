import copy
import unittest

from extensions.business.deeploy.tests.support import make_deeploy_plugin
from extensions.business.deeploy.tests import test_update_requests as update_tests
from extensions.business.deeploy.tests.test_secret_staging import _SecretStagingPlugin
from extensions.business.deeploy.deeploy_const import DEEPLOY_PLUGIN_DATA
from extensions.business.deeploy.deeploy_mixin import DEEPLOY_DAUTH_SECRET_PLACEHOLDER as HIDDEN
from extensions.business.deeploy.deeploy_mixin import _DeeployMixin
from extensions.business.deeploy.selected_secrets import compile_request_selections


def pipeline(instance):
  return {"NAME": "app-123", "PLUGINS": [{
    "SIGNATURE": "CONTAINER_APP_RUNNER",
    "INSTANCES": [{"INSTANCE_ID": "current-instance", **copy.deepcopy(instance)}],
  }]}


def instance(payload):
  return payload["PLUGINS"][0]["INSTANCES"][0]


class SelectedSecretTests(unittest.TestCase):
  def setUp(self):
    self.plugin = make_deeploy_plugin()

  def test_compile_exact_request_namespace_and_extract_scalar_leaves(self):
    request = {"plugins": [{
      "plugin_signature": "CONTAINER_APP_RUNNER",
      "ENV": {"CUSTOM_VALUE": "ordinary-looking-secret", "PUBLIC": "visible", "EMPTY": ""},
      "DYNAMIC_ENV": {"URL": [
        {"type": "static", "value": "secret-prefix"},
        {"type": "host_ip"},
        {"type": "shmem", "path": ["provider", "PORT"]},
        {"type": "static", "value": ""},
      ]},
      "PER_NODE_CONFIG": {
        "byNode": {"node-a": {"ENV": {"KEY": "node-secret"}}},
        "byIndex": {"0": {"DYNAMIC_ENV": {"KEY": [{"type": "static", "value": "index-secret"}]}}},
      },
    }], "secret_paths": [
      ["plugins", 0, "ENV", "CUSTOM_VALUE"],
      ["plugins", 0, "ENV", "EMPTY"],
      ["plugins", 0, "DYNAMIC_ENV", "URL"],
      ["plugins", 0, "PER_NODE_CONFIG", "byNode", "node-a", "ENV", "KEY"],
      ["plugins", 0, "PER_NODE_CONFIG", "byIndex", "0", "DYNAMIC_ENV", "KEY"],
    ]}
    normalized = copy.deepcopy(request)
    compile_request_selections(request, normalized)
    self.assertNotIn("SECRET_PATHS", request["plugins"][0])
    expected = [path[2:] for path in request["secret_paths"]]
    self.assertEqual(normalized["plugins"][0]["SECRET_PATHS"], expected)
    redacted, secrets = self.plugin._extract_and_redact_deeploy_dauth_secrets(pipeline(normalized["plugins"][0]))
    config, bundle = instance(redacted), instance(secrets)
    self.assertEqual(config["ENV"], {"CUSTOM_VALUE": HIDDEN, "PUBLIC": "visible", "EMPTY": HIDDEN})
    self.assertEqual(bundle["ENV"], {"CUSTOM_VALUE": "ordinary-looking-secret", "EMPTY": ""})
    self.assertEqual(bundle["DYNAMIC_ENV"]["URL"], [{"value": "secret-prefix"}, None, None, {"value": ""}])
    self.assertEqual(config["DYNAMIC_ENV"]["URL"][2], {"type": "shmem", "path": ["provider", "PORT"]})
    self.assertEqual(config["PER_NODE_CONFIG"]["byNode"]["node-a"]["ENV"]["KEY"], HIDDEN)
    self.assertEqual(config["SECRET_PATHS"], expected)

  def test_reject_malformed_missing_and_arbitrary_paths(self):
    base = {"plugins": [{"ENV": {"KEY": "secret"}, "IMAGE": "repo/app", "DYNAMIC_ENV": {"URL": [{"type": "static", "value": "secret"}]}}]}
    cases = [None, "ENV.KEY", {}, [None], [[]], [["plugins", True, "ENV", "KEY"]],
      [["plugins", -1, "ENV", "KEY"]], [["plugins", "0", "ENV", "KEY"]],
      [["plugins", 1, "ENV", "KEY"]], [["PLUGINS", 0, "ENV", "KEY"]],
      [["plugins", 0, "IMAGE"]], [["plugins", 0, "ENV", "MISSING"]],
      [["plugins", 0, "DYNAMIC_ENV", "URL", 0, "value"]],
      [["plugins", 0, "DYNAMIC_ENV", "URL", "type"]],
      [["pipeline_params", "ENV", "KEY"]]]
    for selectors in cases:
      with self.subTest(selectors=selectors):
        request = {**copy.deepcopy(base), "secret_paths": selectors}
        with self.assertRaises(ValueError):
          compile_request_selections(request, copy.deepcopy(request))

  def test_reject_wrong_selected_value_shapes_without_echoing_values(self):
    for value in (None, {}, [], {"CUSTOM_VALUE": "do-not-echo"}):
      request = {"plugins": [{"ENV": {"KEY": value}}], "secret_paths": [["plugins", 0, "ENV", "KEY"]]}
      with self.assertRaises(ValueError) as exc:
        compile_request_selections(request, copy.deepcopy(request))
      self.assertNotIn("do-not-echo", str(exc.exception))
    for parts in ([], "do-not-echo", [{}], [{"type": "static"}], [{"type": "static", "value": 42}], [{"type": "static", "value": False}], [{"type": "static", "value": {"secret": "do-not-echo"}}]):
      request = {"plugins": [{"DYNAMIC_ENV": {"KEY": parts}}], "secret_paths": [["plugins", 0, "DYNAMIC_ENV", "KEY"]]}
      with self.assertRaises(ValueError) as exc:
        compile_request_selections(request, copy.deepcopy(request))
      self.assertNotIn("do-not-echo", str(exc.exception))

  def test_injected_metadata_rejected_even_without_selectors(self):
    for request in (
      {"plugins": [{"SECRET_PATHS": [["IMAGE"]]}]},
      {"plugins": [{"secret_paths": []}]},
      {"plugins": [{"PER_NODE_CONFIG": {"byNode": {"node-a": {"SECRET_PATHS": []}}}}]},
      {"plugins": [{}], "pipeline_params": {"PLUGINS": [{"INSTANCES": [{"SECRET_PATHS": []}]}]}},
      {"plugins": [{}], "SECRET_PATHS": []},
    ):
      with self.subTest(request=request), self.assertRaisesRegex(ValueError, "server-owned"):
        compile_request_selections(request, copy.deepcopy(request))

  def test_omission_preserves_metadata_and_explicit_deselection_requires_plaintext(self):
    prior, secrets = self.plugin._extract_and_redact_deeploy_dauth_secrets(pipeline({
      "ENV": {"CUSTOM_VALUE": "secret", "CF_TUNNEL_TOKEN": "mandatory"},
      "SECRET_PATHS": [["ENV", "CUSTOM_VALUE"]],
    }))
    current = copy.deepcopy(prior)
    instance(current).pop("SECRET_PATHS")
    configs, bundle = self.plugin._redact_pipeline_configs_and_build_secret_bundle(
      7, {"node": current}, {"job_secrets": secrets}, prior_pipeline=prior,
    )
    self.assertEqual(instance(configs["node"])["SECRET_PATHS"], [["ENV", "CUSTOM_VALUE"]])
    self.assertEqual(instance(bundle["job_secrets"])["ENV"]["CUSTOM_VALUE"], "secret")
    instance(current)["SECRET_PATHS"] = []
    with self.assertRaisesRegex(ValueError, "replacement plaintext"):
      self.plugin._redact_pipeline_configs_and_build_secret_bundle(7, {"node": current}, {"job_secrets": secrets}, prior_pipeline=prior)
    instance(current)["ENV"]["CUSTOM_VALUE"] = "now-public"
    configs, bundle = self.plugin._redact_pipeline_configs_and_build_secret_bundle(7, {"node": current}, {"job_secrets": secrets}, prior_pipeline=prior)
    self.assertEqual(instance(configs["node"])["ENV"]["CUSTOM_VALUE"], "now-public")
    self.assertEqual(instance(bundle["job_secrets"])["ENV"], {"CF_TUNNEL_TOKEN": "mandatory"})

  def test_dynamic_structure_changes_require_fresh_values(self):
    prior, secrets = self.plugin._extract_and_redact_deeploy_dauth_secrets(pipeline({
      "DYNAMIC_ENV": {"URL": [{"type": "static", "value": "first"}, {"type": "host_ip"}, {"type": "static", "value": "last"}]},
      "SECRET_PATHS": [["DYNAMIC_ENV", "URL"]],
    }))
    def build(current):
      return self.plugin._redact_pipeline_configs_and_build_secret_bundle(7, {"node": current}, {"job_secrets": secrets}, prior_pipeline=prior)
    _, bundle = build(copy.deepcopy(prior))
    self.assertEqual(instance(bundle["job_secrets"])["DYNAMIC_ENV"]["URL"][0]["value"], "first")
    for change in (
      lambda parts: parts.insert(0, {"type": "host_ip"}),
      lambda parts: parts.__setitem__(slice(None), [parts[0], parts[2], parts[1]]),
      lambda parts: parts[1].update(type="shmem", path=["provider", "PORT"]),
      lambda parts: parts[0].update(source="different"),
    ):
      current = copy.deepcopy(prior)
      parts = instance(current)["DYNAMIC_ENV"]["URL"]
      change(parts)
      with self.assertRaisesRegex(ValueError, "Unresolved dAuth"):
        build(current)
      for part in parts:
        if part.get("type") == "static":
          part["value"] = "fresh"
      build(current)

  def test_logs_mask_innocent_keys_and_invalid_selectors(self):
    request = {"plugins": [{"ENV": {"CUSTOM_VALUE": "env-secret"}, "DYNAMIC_ENV": {"CUSTOM_VALUE": [{"type": "static", "value": "dynamic-secret"}]}}], "secret_paths": "invalid"}
    logged = str(self.plugin._redact_per_node_config_for_log(request))
    self.assertNotIn("env-secret", logged)
    self.assertNotIn("dynamic-secret", logged)
    self.assertIn("CUSTOM_VALUE", logged)

  def test_empty_selected_value_survives_bundle_and_r1fs_staging(self):
    plugin = _SecretStagingPlugin()
    configs, bundle = plugin._redact_pipeline_configs_and_build_secret_bundle(7, {"node": pipeline({"ENV": {"CUSTOM_VALUE": ""}, "SECRET_PATHS": [["ENV", "CUSTOM_VALUE"]]})}, None)
    state = plugin.stage_job_pipeline_and_secrets(configs["node"], 7, bundle)
    r1fs_payload = next(event[1] for event in plugin.events if event[0] == "r1fs_add")
    self.assertEqual(instance(r1fs_payload)["ENV"]["CUSTOM_VALUE"], HIDDEN)
    self.assertEqual(instance(r1fs_payload)["SECRET_PATHS"], [["ENV", "CUSTOM_VALUE"]])
    self.assertEqual(instance(bundle["job_secrets"])["ENV"]["CUSTOM_VALUE"], "")
    self.assertIsNotNone(state)

  def test_r1fs_preserves_dynamic_reference_and_selection_path_order(self):
    source = pipeline({
      "SECRET_PATHS": [["ENV", "Z"], ["PER_NODE_CONFIG", "byNode", "node", "DYNAMIC_ENV", "URL"]],
      "DYNAMIC_ENV": {"URL": [{"type": "shmem", "path": ["z-provider", "A_KEY"]}]},
    })
    sorted_pipeline = _SecretStagingPlugin()._recursively_sort_pipeline_data(source)
    self.assertEqual(instance(sorted_pipeline), instance(source))

  def test_per_node_materialization_projects_and_prunes_metadata(self):
    source = pipeline({
      "ENV": {"BASE": "base", "OVERRIDE": "base-secret"},
      "PER_NODE_CONFIG": {
        "default": {"ENV": {"DEFAULT": "default-secret"}},
        "byIndex": {"0": {"ENV": {"INDEX": "index-secret"}}},
        "byNode": {
          "node-a": {"ENV": {"NODE": "node-secret", "OVERRIDE": "public-override"}},
          "node-b": {"ENV": {"NODE": "different-secret"}},
        },
      },
      "SECRET_PATHS": [
        ["ENV", "BASE"], ["ENV", "OVERRIDE"],
        ["PER_NODE_CONFIG", "default", "ENV", "DEFAULT"],
        ["PER_NODE_CONFIG", "byIndex", "0", "ENV", "INDEX"],
        ["PER_NODE_CONFIG", "byNode", "node-a", "ENV", "NODE"],
        ["PER_NODE_CONFIG", "byNode", "node-b", "ENV", "NODE"],
      ],
    })
    materialized = self.plugin._materialize_plugins_for_node(source["PLUGINS"], "node-a", 0)
    config = materialized[0]["INSTANCES"][0]
    self.assertNotIn("PER_NODE_CONFIG", config)
    self.assertCountEqual(config["SECRET_PATHS"], [["ENV", key] for key in ("BASE", "DEFAULT", "INDEX", "NODE")])
    redacted, secrets = self.plugin._extract_and_redact_deeploy_dauth_secrets(materialized)
    self.assertEqual(redacted[0]["INSTANCES"][0]["ENV"]["OVERRIDE"], "public-override")
    self.assertEqual(secrets[0]["INSTANCES"][0]["ENV"]["NODE"], "node-secret")
    self.assertIn("PER_NODE_CONFIG", instance(source))

  def test_scale_up_preserves_dynamic_and_per_node_selection_with_new_identity(self):
    plugin = self.plugin
    plugin.time = lambda: 1000
    source, secrets = plugin._extract_and_redact_deeploy_dauth_secrets(pipeline({
      "IMAGE": "repo/app", "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
      "DYNAMIC_ENV": {"URL": [{"type": "static", "value": "dynamic-secret"}, {"type": "host_ip"}]},
      "PER_NODE_CONFIG": {"byIndex": {"0": {"ENV": {"CUSTOM_VALUE": "node-secret"}}}},
      "SECRET_PATHS": [["DYNAMIC_ENV", "URL"], ["PER_NODE_CONFIG", "byIndex", "0", "ENV", "CUSTOM_VALUE"]],
    }))
    base = {"app_id": "app-123", "pipeline_type": "void", "plugins": source["PLUGINS"], "deeploy_specs": {"job_id": 7, "job_app_type": "generic", "current_target_nodes": ["old-node"]}}
    plugin.get_job_base_pipeline_from_r1fs = lambda *args, **kwargs: copy.deepcopy(base)
    plugin._load_dauth_job_secret_bundle = lambda job_id: {"job_secrets": secrets}
    captured = {}
    def stage(pipeline, job_id, secret_bundle):
      captured.update(pipeline=pipeline, bundle=secret_bundle)
      return {}
    plugin.stage_job_pipeline_and_secrets = stage
    plugin._reset_chainstore_response_keys = lambda *args, **kwargs: None
    plugin._start_create_update_pipelines = lambda **kwargs: captured.update(dispatch=kwargs)
    plugin.scale_up_job(["new-node"], [], 7, "owner", {}, wait_for_responses=False)
    self.assertEqual(instance(captured["pipeline"])["SECRET_PATHS"], instance(source)["SECRET_PATHS"])
    self.assertNotEqual(instance(captured["pipeline"])["INSTANCE_ID"], "current-instance")
    self.assertEqual(instance(captured["bundle"]["job_secrets"])["DYNAMIC_ENV"]["URL"][0]["value"], "dynamic-secret")
    self.assertNotIn("dynamic-secret", str(captured["dispatch"]))
    self.assertNotIn("node-secret", str(captured["dispatch"]))

  def test_recovery_rebuilds_metadata_and_scalar_bundle(self):
    source, secrets = self.plugin._extract_and_redact_deeploy_dauth_secrets(pipeline({
      "ENV": {"CUSTOM_VALUE": "secret"}, "SECRET_PATHS": [["ENV", "CUSTOM_VALUE"]],
    }))
    self.plugin.NestedDotDict = update_tests.make_inputs
    recovered = self.plugin._pipeline_plugins_to_reconcile_request(source)
    prepared = self.plugin.deeploy_prepare_plugins(update_tests.make_inputs(plugins=recovered))
    restored = {"PLUGINS": prepared}
    configs, bundle = self.plugin._redact_pipeline_configs_and_build_secret_bundle(7, {"node": restored}, {"job_secrets": secrets}, prior_pipeline=source)
    self.assertEqual(instance(configs["node"])["SECRET_PATHS"], [["ENV", "CUSTOM_VALUE"]])
    self.assertEqual(instance(bundle["job_secrets"])["ENV"]["CUSTOM_VALUE"], "secret")


class SelectedSecretRequestTests(unittest.TestCase):
  def make_fixture(self):
    entry = {
      "plugin_signature": "CONTAINER_APP_RUNNER", "instance_id": "current-instance",
      "IMAGE": "repo/app:1.0", "CONTAINER_RESOURCES": {"cpu": 1, "memory": "256m"},
      "ENV": {"CUSTOM_VALUE": "selected-plaintext", "PUBLIC": "visible"},
    }
    discovered = [{
      DEEPLOY_PLUGIN_DATA.INSTANCE_ID: "current-instance",
      DEEPLOY_PLUGIN_DATA.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
      DEEPLOY_PLUGIN_DATA.NODE: "node-1",
      DEEPLOY_PLUGIN_DATA.PLUGIN_INSTANCE: {"instance_conf": copy.deepcopy(entry)},
    }]
    fixture = update_tests.DeeployUpdateRequestPreparationTests()
    plugin, called = fixture._make_process_update_plugin(discovered)
    request = {
      "app_id": "app-123", "app_alias": "app", "job_id": 11, "job_app_type": "generic",
      "pipeline_input_type": "void", "chainstore_response": False,
      "target_nodes": ["node-1"], "target_nodes_count": 1,
      "return_request": True, "plugins": [entry],
      "secret_paths": [["plugins", 0, "ENV", "CUSTOM_VALUE"]],
    }
    return plugin, called, request

  def test_create_and_update_stage_selected_values_before_dispatch(self):
    for create in (True, False):
      with self.subTest(create=create):
        plugin, called, request = self.make_fixture()
        response = plugin._process_pipeline_request(request, is_create=create)
        self.assertEqual(response["status"], "success", response)
        self.assertEqual(called["stage"], 1)
        self.assertEqual(instance(called["staged_pipeline"])["ENV"]["CUSTOM_VALUE"], HIDDEN)
        self.assertEqual(instance(called["staged_secret_bundle"]["job_secrets"])["ENV"]["CUSTOM_VALUE"], "selected-plaintext")
        returned = response["request"]["plugins"][0]
        self.assertEqual(returned["ENV"], {"CUSTOM_VALUE": HIDDEN, "PUBLIC": "visible"})
        configs = called["deploy_kwargs"]["prepared_pipeline_configs"]
        self.assertNotIn("selected-plaintext", str(configs))

  def test_invalid_or_injected_selections_fail_before_stage_delete_or_dispatch(self):
    for create in (True, False):
      for change in (
        lambda req: req.update(secret_paths=[["plugins", 0, "IMAGE"]]),
        lambda req: req["plugins"][0].update(SECRET_PATHS=[["ENV", "PUBLIC"]]),
      ):
        plugin, called, request = self.make_fixture()
        change(request)
        response = plugin._process_pipeline_request(request, is_create=create)
        self.assertEqual(response["status"], "failed")
        self.assertEqual((called["stage"], called["delete"], called["deploy"]), (0, 0, 0))
        self.assertNotIn("selected-plaintext", response["error"])

  def test_old_client_update_preserves_metadata_and_hidden_value(self):
    plugin, called, request = self.make_fixture()
    prior, secrets = plugin._extract_and_redact_deeploy_dauth_secrets(pipeline({
      **request["plugins"][0], "SECRET_PATHS": [["ENV", "CUSTOM_VALUE"]],
    }))
    plugin._load_dauth_job_secret_bundle = lambda job_id: {"job_secrets": secrets}
    plugin.get_job_pipeline_from_cstore = lambda *args, **kwargs: copy.deepcopy(prior)
    request.pop("secret_paths")
    request["plugins"][0]["ENV"]["CUSTOM_VALUE"] = HIDDEN
    response = plugin._process_pipeline_request(request, is_create=False)
    self.assertEqual(response["status"], "success", response)
    self.assertEqual(instance(called["staged_pipeline"])["SECRET_PATHS"], [["ENV", "CUSTOM_VALUE"]])
    self.assertEqual(instance(called["staged_secret_bundle"]["job_secrets"])["ENV"]["CUSTOM_VALUE"], "selected-plaintext")

  def test_explicit_deselection_of_hidden_value_fails_before_delete(self):
    plugin, called, request = self.make_fixture()
    prior, secrets = plugin._extract_and_redact_deeploy_dauth_secrets(pipeline({
      **request["plugins"][0], "SECRET_PATHS": [["ENV", "CUSTOM_VALUE"]],
    }))
    plugin._load_dauth_job_secret_bundle = lambda job_id: {"job_secrets": secrets}
    plugin.get_job_pipeline_from_cstore = lambda *args, **kwargs: copy.deepcopy(prior)
    request["secret_paths"] = []
    request["plugins"][0]["ENV"]["CUSTOM_VALUE"] = HIDDEN
    response = plugin._process_pipeline_request(request, is_create=False)
    self.assertIn("replacement plaintext", response["error"])
    self.assertEqual((called["stage"], called["delete"], called["deploy"]), (0, 0, 0))

  def test_missing_bundle_does_not_discard_persisted_selection(self):
    plugin, called, request = self.make_fixture()
    prior, _ = plugin._extract_and_redact_deeploy_dauth_secrets(pipeline({
      **request["plugins"][0], "SECRET_PATHS": [["ENV", "CUSTOM_VALUE"]],
    }))
    plugin.get_job_pipeline_from_cstore = lambda *args, **kwargs: copy.deepcopy(prior)
    request.pop("secret_paths")
    response = plugin._process_pipeline_request(request, is_create=False)
    self.assertEqual(response["status"], "success", response)
    self.assertEqual(instance(called["staged_pipeline"])["ENV"]["CUSTOM_VALUE"], HIDDEN)
    self.assertEqual(response["request"]["plugins"][0]["ENV"]["CUSTOM_VALUE"], HIDDEN)

  def test_response_redaction_uses_inferred_identity_for_old_client(self):
    plugin, _, request = self.make_fixture()
    normalized = copy.deepcopy(request["plugins"])
    persisted = pipeline({**normalized[0], "SECRET_PATHS": [["ENV", "CUSTOM_VALUE"]]})
    request.pop("secret_paths")
    request["plugins"][0].pop("instance_id")
    response = plugin._redact_deeploy_dauth_secrets_for_response(request, pipeline=persisted, normalized_plugins=normalized)
    self.assertEqual(response["plugins"][0]["ENV"]["CUSTOM_VALUE"], HIDDEN)
    self.assertEqual(request["plugins"][0]["ENV"]["CUSTOM_VALUE"], "selected-plaintext")

  def test_old_client_aliases_and_legacy_responses_do_not_leak_inherited_secrets(self):
    for form in ("plugin-alias", "top-alias", "top-canonical", "legacy-top", "legacy-params"):
      with self.subTest(form=form):
        plugin, called, request = self.make_fixture()
        plugin._normalize_plugins_input = _DeeployMixin._normalize_plugins_input.__get__(plugin)
        overlay = {"byNode": {"node-1": {"ENV": {"CUSTOM_VALUE": "alias-selected-plaintext"}}}}
        selectors = [["PER_NODE_CONFIG", "byNode", "node-1", "ENV", "CUSTOM_VALUE"]]
        prior, secrets = plugin._extract_and_redact_deeploy_dauth_secrets(pipeline({
          **request["plugins"][0], "PER_NODE_CONFIG": overlay, "SECRET_PATHS": selectors,
        }))
        plugin._load_dauth_job_secret_bundle = lambda job_id: {"job_secrets": secrets}
        plugin.get_job_pipeline_from_cstore = lambda *args, **kwargs: copy.deepcopy(prior)
        request.pop("secret_paths")
        if form == "plugin-alias":
          request["plugins"][0]["perNodeConfig"] = overlay
        elif form in ("top-alias", "top-canonical"):
          request["perNodeConfig" if form == "top-alias" else "PER_NODE_CONFIG"] = overlay
        else:
          entry = request.pop("plugins")[0]
          request["plugin_signature"] = entry.pop("plugin_signature")
          request["instance_id"] = entry.pop("instance_id")
          request["app_params"] = entry
          if form == "legacy-top":
            request["perNodeConfig"] = overlay
          else:
            entry["perNodeConfig"] = overlay
        response = plugin._process_pipeline_request(request, is_create=False)
        self.assertEqual(response["status"], "success", response)
        self.assertNotIn("alias-selected-plaintext", str(response))
        self.assertNotIn("alias-selected-plaintext", str(called["staged_pipeline"]))
        self.assertNotIn("app_params", response["request"])
        returned = response["request"]
        if form == "plugin-alias":
          returned_overlay = returned["plugins"][0]["perNodeConfig"]
          self.assertNotIn("PER_NODE_CONFIG", returned["plugins"][0])
        elif form == "legacy-params":
          self.assertNotIn("plugins", returned)
          continue
        else:
          returned_overlay = returned["PER_NODE_CONFIG" if form == "top-canonical" else "perNodeConfig"]
        self.assertEqual(returned_overlay["byNode"]["node-1"]["ENV"]["CUSTOM_VALUE"], HIDDEN)

  def test_overlay_section_aliases_cannot_discard_inherited_selection(self):
    leaf = {"CUSTOM_VALUE": "section-alias-secret"}
    cases = [
      (["byNode", "node-1", "ENV", "CUSTOM_VALUE"],
       {"byNode": {"node-1": {"ENV": leaf}}},
       {"BY_NODE": {"node-1": {"env": leaf}}}),
      (["byNode", "node-1", "ENV", "CUSTOM_VALUE"],
       {"byNode": {"node-1": {"ENV": leaf}}},
       {"node-1": {"env": leaf}}),
      (["byIndex", "0", "ENV", "CUSTOM_VALUE"],
       {"byIndex": {"0": {"ENV": leaf}}},
       {"BY_INDEX": {"00": {"env": leaf}}}),
      (["default", "ENV", "CUSTOM_VALUE"],
       {"default": {"ENV": leaf}},
       {"DEFAULT": {"env": leaf}}),
    ]
    def hidden_values(value):
      if isinstance(value, dict):
        return {key: hidden_values(item) for key, item in value.items()}
      return HIDDEN if value == "section-alias-secret" else value
    for path, canonical, aliased in cases:
      with self.subTest(path=path):
        plugin, called, request = self.make_fixture()
        prior, secrets = plugin._extract_and_redact_deeploy_dauth_secrets(pipeline({
          **request["plugins"][0], "PER_NODE_CONFIG": canonical,
          "SECRET_PATHS": [["PER_NODE_CONFIG"] + path],
        }))
        plugin._load_dauth_job_secret_bundle = lambda job_id: {"job_secrets": secrets}
        plugin.get_job_pipeline_from_cstore = lambda *args, **kwargs: copy.deepcopy(prior)
        request.pop("secret_paths")
        request["plugins"][0]["PER_NODE_CONFIG"] = copy.deepcopy(aliased)
        response = plugin._process_pipeline_request(request, is_create=False)
        self.assertEqual(response["status"], "success", response)
        self.assertNotIn("section-alias-secret", str(called["staged_pipeline"]))
        self.assertEqual(response["request"]["plugins"][0]["PER_NODE_CONFIG"], hidden_values(aliased))
        # Explicit removal through an alias must still require real plaintext.
        plugin, called, _ = self.make_fixture()
        plugin._load_dauth_job_secret_bundle = lambda job_id: {"job_secrets": secrets}
        plugin.get_job_pipeline_from_cstore = lambda *args, **kwargs: copy.deepcopy(prior)
        request["secret_paths"] = []
        request["plugins"][0]["PER_NODE_CONFIG"] = hidden_values(aliased)
        response = plugin._process_pipeline_request(request, is_create=False)
        self.assertIn("replacement plaintext", response["error"])
        self.assertEqual((called["stage"], called["delete"], called["deploy"]), (0, 0, 0))

  def test_managed_update_preserves_custom_and_mandatory_secret_paths(self):
    fixture = update_tests.DeeployUpdateRequestPreparationTests()
    nodes, discovered, entry = fixture._make_four_replica_cockroach_update_fixture(make_deeploy_plugin())
    plugin, called = fixture._make_process_update_plugin(discovered, nodes=nodes, deeploy_specs={"job_id": 11, "job_app_type": "service", "current_target_nodes": nodes})
    entry["ENV"]["CUSTOM_VALUE"] = "managed-custom-secret"
    request = {
      "app_id": "cockroachdb_422ce92", "app_alias": "cockroachdb", "job_id": 11,
      "job_app_type": "service", "service_kind": "cockroachdb",
      "pipeline_input_type": "void", "chainstore_response": False,
      "target_nodes": nodes, "target_nodes_count": len(nodes), "plugins": [entry],
      "secret_paths": [["plugins", 0, "ENV", "CUSTOM_VALUE"]],
    }
    response = plugin._process_pipeline_request(request, is_create=False)
    self.assertEqual(response["status"], "success", response)
    self.assertEqual(instance(called["staged_pipeline"])["ENV"]["CUSTOM_VALUE"], HIDDEN)
    env = instance(called["staged_secret_bundle"]["job_secrets"])["ENV"]
    self.assertEqual(env["CUSTOM_VALUE"], "managed-custom-secret")
    self.assertIn("CRDB_PASSWORD", env)


if __name__ == "__main__":
  unittest.main()
