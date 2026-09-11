"""Preset asset behavior through real plugin signatures, identity and CStore adapters."""
from collections import Counter
from copy import deepcopy
import inspect
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from pydantic import ValidationError, create_model

from .test_tenant_administration import FakeAdministrationStore


class TestTenantAssetPlugin(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    environment = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    environment.start()
    self.addCleanup(environment.stop)
    self.storage = FakeAdministrationStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenant_administration_enabled = True
    self.plugin.cfg_tenancy_namespace = "deployment"
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.storage, name))
    self.actor = {"account_id": "creator"}
    request = str(uuid4())
    prepared = self.plugin.prepare_tenant(self.actor, request, "Example", "example", "initial")
    self.assertTrue(prepared["success"], prepared)
    self.tenant = prepared["data"]["tenantId"]
    self.storage.grant("initial", self.tenant)
    self.assertTrue(self.plugin.activate_tenant(self.actor, request)["success"])

  def call_json(self, method, **body):
    endpoint = getattr(self.plugin, method)
    # Exercise the same endpoint annotations/defaults copied by the core transport.
    fields = {parameter.name: (parameter.annotation, parameter.default)
              for parameter in inspect.signature(endpoint).parameters.values()}
    model = create_model("TenantAssetRequest", **fields)
    request = model.model_validate_json(json.dumps(body))
    return endpoint(**request.model_dump())

  def test_created_preset_is_visible_through_authorized_inventory(self):
    request = str(uuid4())
    created = self.call_json("create_tenant_asset", actor=self.actor, tenant_id=self.tenant,
                             request_id=request, display_name=" Network ",
                             target={"kind": "network", "address": "192.0.2.10"})
    self.assertTrue(created["success"], created)
    asset = created["data"]
    self.assertEqual(asset["assetId"], "as_" + request)
    self.assertEqual(asset["displayName"], "Network")
    self.assertEqual(asset["target"], {"kind": "network", "address": "192.0.2.10"})
    self.assertIs(asset["active"], True)
    listed = self.call_json("list_tenant_assets", actor={"account_id": "initial"},
                            tenant_id=self.tenant)
    self.assertEqual(listed["data"], {"tenantId": self.tenant, "assets": [asset],
                                     "canCreateAssets": False, "canUpdateAssets": False})

  def create_asset(self, **changes):
    body = {"actor": self.actor, "tenant_id": self.tenant, "request_id": str(uuid4()),
            "display_name": "Network", "target": {"kind": "network", "address": "192.0.2.10"}}
    body.update(changes)
    return self.call_json("create_tenant_asset", **body)

  def update_body(self, asset, **changes):
    body = {"actor": self.actor, "tenant_id": self.tenant, "asset_id": asset["assetId"],
            "expected_version": asset["version"], "display_name": asset["displayName"],
            "target": asset["target"], "active": asset["active"]}
    body.update(changes)
    return body

  def test_crud_and_replay_never_contact_the_saved_network_target(self):
    request_id = str(uuid4())
    with patch("socket.getaddrinfo", side_effect=AssertionError("CRUD must not resolve targets")) as dns, \
         patch("requests.sessions.Session.request", side_effect=AssertionError("CRUD must not probe targets")) as http:
      created = self.create_asset(request_id=request_id)
      self.assertTrue(created["success"], created)
      asset = created["data"]
      changed = self.call_json("update_tenant_asset", **self.update_body(
        asset, display_name="Retired network", active=False))
      self.assertTrue(changed["success"], changed)
      self.assertIs(changed["data"]["active"], False)
      before = len(self.storage.writes)
      replayed = self.create_asset(request_id=request_id)
      self.assertEqual(replayed["data"], changed["data"])
      self.assertEqual(len(self.storage.writes), before)
      detail = self.call_json("get_tenant_asset", actor=self.actor, tenant_id=self.tenant,
                              asset_id=asset["assetId"])
      self.assertEqual(detail["data"], {"asset": changed["data"], "canUpdateAssets": True,
                                       "canLaunchJobs": False})
      inventory = self.call_json("list_tenant_assets", actor=self.actor, tenant_id=self.tenant)
      self.assertEqual(inventory["data"]["assets"], [changed["data"]])
      dns.assert_not_called()
      http.assert_not_called()

  def test_capability_reports_literal_tenant_execution_flag_without_stored_reads(self):
    self.plugin.config_data = {"TENANT_EXECUTION_ENABLED": True}
    self.plugin.cfg_tenant_administration_enabled = False
    self.plugin.cfg_tenancy_namespace = ""
    self.plugin.cfg_tenant_execution_stage = "compatibility"
    with patch.object(self.plugin, "chainstore_hget", side_effect=AssertionError("No stored capability reads")), \
         patch.object(self.plugin, "chainstore_hgetall", side_effect=AssertionError("No capability enumeration")), \
         patch.object(self.plugin, "chainstore_hset", side_effect=AssertionError("No capability writes")):
      baseline = self.plugin.get_capability_status()
      self.assertIs(baseline["tenant_execution_enabled"], False)
      for value in (None, False, "false", "true", 0, 1, 0.0, 1.0, [], {}, True):
        with self.subTest(value=value):
          self.plugin.cfg_tenant_execution_enabled = value
          status = self.plugin.get_capability_status()
          self.assertIs(status["tenant_execution_enabled"], value is True)
          self.assertEqual(status, {**baseline, "tenant_execution_enabled": value is True})

  def test_launch_hint_resolves_stored_facts_once_without_node_rollout_or_asset_changes(self):
    asset = self.create_asset()["data"]
    self.storage.account("operator", memberships=[{"role": "tenant_pentester", "tenant_id": self.tenant}])
    self.assertTrue(self.plugin.update_tenant_allow_pentester(self.actor, self.tenant, True)["success"])
    actor = {"account_id": "operator"}
    before = deepcopy(self.storage.data)
    writes = len(self.storage.writes)
    self.plugin.cfg_tenant_execution_stage = "compatibility"
    for enabled, peers in ((False, []), (True, ["Node-A"])):
      with self.subTest(enabled=enabled, peers=peers):
        self.plugin.cfg_tenant_execution_enabled = enabled
        self.plugin.cfg_chainstore_peers = peers
        with patch.object(self.plugin, "chainstore_hget", wraps=self.plugin.chainstore_hget) as reads, \
             patch.object(self.plugin, "chainstore_hgetall", side_effect=AssertionError("No node enumeration")):
          result = self.call_json("get_tenant_asset", actor=actor, tenant_id=self.tenant,
                                  asset_id=asset["assetId"])
          self.assertEqual(result["data"], {"asset": asset, "canUpdateAssets": False, "canLaunchJobs": True})
          calls = [call.kwargs for call in reads.call_args_list]
          self.assertEqual([call for call in calls if call["hkey"] == "auth"],
                           [{"hkey": "auth", "key": "operator"}])
          self.assertEqual(Counter(json.loads(call["key"])[0] for call in calls if call["hkey"] != "auth"),
                           {"tenant": 1, "receipt": 1, "domain": 1, "asset": 1})
        self.assertIs(self.plugin.get_capability_status()["tenant_execution_enabled"], enabled)
        self.assertEqual(self.storage.data, before)
        self.assertEqual(len(self.storage.writes), writes)

  def test_bare_hex_numeric_host_is_not_silently_retargeted(self):
    before = len(self.storage.writes)
    result = self.create_asset(target={"kind": "webapp", "url": "https://0x/api", "allowedPathPrefix": "/api"})
    self.assertEqual(result["status_code"], 400, result)
    self.assertEqual(len(self.storage.writes), before)

  def test_generated_update_model_preserves_types_and_missing_required_state(self):
    asset = self.create_asset()["data"]
    invalid = {
      "active": (None, 0, 1, 0.0, 1.0, "false", "true", "yes", [], {}),
      "expected_version": (None, True, 1, [], {}, "", "a" * 63, "A" * 64),
      "display_name": (None, True, 1, [], {}, "", "\nNetwork", "Network\ufeff"),
      "target": (None, True, 1, [], "192.0.2.10", {},
                 {"kind": "network", "address": "192.0.2.10", "headers": {"X-Key": "forbidden"}}),
    }
    for field, values in invalid.items():
      for value in values:
        with self.subTest(field=field, value=value):
          before = len(self.storage.writes)
          result = self.call_json("update_tenant_asset", **self.update_body(asset, **{field: value}))
          self.assertEqual(result["status_code"], 400, result)
          self.assertEqual(len(self.storage.writes), before)
      with self.subTest(missing=field):
        body = self.update_body(asset)
        del body[field]
        before = len(self.storage.writes)
        result = self.call_json("update_tenant_asset", **body)
        self.assertEqual(result["status_code"], 400, result)
        self.assertEqual(len(self.storage.writes), before)

  def test_asset_mutations_use_stored_scoped_roles_not_actor_claims(self):
    asset = self.create_asset()["data"]
    for role in ("super_tenant_admin", "super_pentester", "tenant_admin", "tenant_pentester", "tenant_user"):
      with self.subTest(role=role):
        self.storage.account("operator", memberships=[{"role": role, "tenant_id": self.tenant}])
        actor = {"account_id": "operator", "role": "super_tenant_admin",
                 "tenant_memberships": [{"role": "super_tenant_admin", "tenant_id": None}]}
        allowed = role in ("super_tenant_admin", "super_pentester")
        before = len(self.storage.writes)
        created = self.create_asset(actor=actor)
        self.assertEqual(created["status_code"], 200 if allowed else 403, created)
        updated = self.call_json("update_tenant_asset", **self.update_body(
          asset, actor=actor, display_name=role))
        self.assertEqual(updated["status_code"], 200 if allowed else 403, updated)
        if allowed:
          asset = updated["data"]
          self.assertEqual(asset["changedBy"], "operator")
        else:
          self.assertEqual(len(self.storage.writes), before)
        listed = self.call_json("list_tenant_assets", actor=actor, tenant_id=self.tenant)
        self.assertIs(listed["data"]["canCreateAssets"], allowed)
        self.assertIs(listed["data"]["canUpdateAssets"], allowed)
        self.assertEqual(self.create_asset(actor=actor, tenant_id="foreign")["status_code"], 404)
        if role == "super_pentester":
          # Asset powers must never imply node-assignment authority.
          result = self.call_json("set_tenant_node_assignment", actor=actor,
                                  tenant_id=self.tenant, node_address="Node-A", active=True)
          self.assertEqual(result["status_code"], 403, result)
    self.storage.account("operator", memberships=[])
    before = len(self.storage.writes)
    for method, body in (
      ("get_tenant_asset", {"asset_id": asset["assetId"]}),
      ("list_tenant_assets", {}),
    ):
      result = self.call_json(method, actor=actor, tenant_id=self.tenant, **body)
      self.assertEqual(result["status_code"], 404, result)
    self.assertEqual(self.create_asset(actor=actor)["status_code"], 404)
    self.assertEqual(self.call_json("update_tenant_asset", **self.update_body(
      asset, actor=actor, active=False))["status_code"], 404)
    self.assertEqual(len(self.storage.writes), before)

  def test_generated_creation_model_does_not_repair_invalid_intent(self):
    invalid = {
      "request_id": (None, True, 1, [], {}, "", "A0000000-0000-4000-8000-000000000000"),
      "display_name": (None, True, 1, [], {}, "", "Network\n", "\ufeffNetwork"),
      "target": (None, True, 1, [], {}, "192.0.2.10",
                 {"kind": "network", "address": 3221225994},
                 {"kind": "network", "address": "192.0.2.10", "ports": [443]}),
    }
    for field, values in invalid.items():
      for value in values:
        with self.subTest(field=field, value=value):
          before = len(self.storage.writes)
          result = self.create_asset(**{field: value})
          self.assertEqual(result["status_code"], 400, result)
          self.assertEqual(len(self.storage.writes), before)
    for missing in invalid:
      with self.subTest(missing=missing):
        body = {"actor": self.actor, "tenant_id": self.tenant, "request_id": str(uuid4()),
                "display_name": "Network", "target": {"kind": "network", "address": "192.0.2.10"}}
        del body[missing]
        before = len(self.storage.writes)
        self.assertEqual(self.call_json("create_tenant_asset", **body)["status_code"], 400)
        self.assertEqual(len(self.storage.writes), before)

  def test_json_parser_rejects_unpaired_surrogates_before_service_dispatch(self):
    before = len(self.storage.writes)
    with self.assertRaises(ValidationError) as error:
      self.create_asset(display_name="\ud800")
    self.assertEqual(error.exception.errors()[0]["type"], "json_invalid")
    self.assertEqual(len(self.storage.writes), before)

  def test_url_presets_round_trip_without_provider_or_dns_calls(self):
    targets = (
      ({"kind": "webapp", "url": "HTTPS://EXAMPLE.TEST:443/api/%75sers", "allowedPathPrefix": "/api/"},
       {"kind": "webapp", "url": "https://example.test/api/%75sers", "allowedPathPrefix": "/api"}),
      ({"kind": "model", "adapter": "openai_compatible", "endpointUrl": "HTTPS://EXAMPLE.TEST:443/v1/chat/completions",
        "model": " Model-A "},
       {"kind": "model", "adapter": "openai_compatible", "endpointUrl": "https://example.test/v1/chat/completions",
        "model": "Model-A"}),
    )
    with patch("socket.getaddrinfo", side_effect=AssertionError("CRUD must not resolve targets")) as dns, \
         patch("requests.sessions.Session.request", side_effect=AssertionError("CRUD must not probe targets")) as http:
      for target, expected in targets:
        with self.subTest(kind=target["kind"]):
          created = self.create_asset(target=target)
          self.assertTrue(created["success"], created)
          asset = created["data"]
          self.assertEqual(asset["target"], expected)
          self.assertRegex(asset["targetDigest"], r"^[a-f0-9]{64}$")
          self.assertRegex(asset["version"], r"^[a-f0-9]{64}$")
          updated = self.call_json("update_tenant_asset", **self.update_body(asset, active=False))
          self.assertTrue(updated["success"], updated)
          self.assertEqual(updated["data"]["target"], expected)
          self.assertEqual(updated["data"]["targetDigest"], asset["targetDigest"])
          self.assertNotEqual(updated["data"]["version"], asset["version"])
          detail = self.call_json("get_tenant_asset", actor=self.actor, tenant_id=self.tenant,
                                  asset_id=asset["assetId"])
          self.assertEqual(detail["data"]["asset"], updated["data"])
      dns.assert_not_called()
      http.assert_not_called()

  def test_ambiguous_authorities_paths_and_out_of_prefix_urls_deny_without_writes(self):
    urls = (
      "https://@example.test/api", "https://user:password@example.test/api",
      "https://127.1/api", "https://0X/api", "https://0x7f000001/api", "https://0177.0.0.1/api",
      "https://example.test:/api", "https://example.test:0/api", "https://example.test:0443/api",
      "https://example.test:65536/api", "https://example.test./api", "httpſ://example.test/api",
      "https://example.test/api?", "https://example.test/api#", "https://example.test/api-other",
      "https://example.test/api/../outside", "https://example.test/api/%2e%2e/outside",
      "https://example.test/api/%FF", "https://example.test/api/%C0%AF", "https://example.test/api/%ED%A0%80",
      "https://example.test/api/%253foutside", "https://example.test/api/%255coutside",
      "https://example.test/api//users", "https://example.test/api/%",
    )
    with patch("socket.getaddrinfo", side_effect=AssertionError("Invalid targets must not resolve")) as dns, \
         patch("requests.sessions.Session.request", side_effect=AssertionError("Invalid targets must not probe")) as http:
      for url in urls:
        with self.subTest(url=url):
          before = len(self.storage.writes)
          result = self.create_asset(target={"kind": "webapp", "url": url, "allowedPathPrefix": "/api"})
          self.assertEqual(result["status_code"], 400, result)
          self.assertEqual(len(self.storage.writes), before)
      dns.assert_not_called()
      http.assert_not_called()
