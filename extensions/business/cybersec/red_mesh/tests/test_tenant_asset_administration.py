"""Preset asset behavior through real identity, policy and verified CStore boundaries."""
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from .test_tenant_administration import FakeAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError


def asset_location(tenant_id, asset_id):
  return ('["redmesh","tenancy",1,"deployment"]',
          json.dumps(["asset", "deployment", tenant_id, asset_id], separators=(",", ":")))


class TestTenantAssetAdministration(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.owner = FakeAdministrationStore()
    self.store = CstoreTenantAdministrationStore(self.owner, "deployment")
    self.service = TenantAdministrationService(CstoreAuthAccountReader(self.owner), self.store)
    self.actor = {"account_id": "creator"}
    request = str(uuid4())
    self.tenant = self.service.prepare_tenant(self.actor, request, "Tenant", "tenant", "initial")["data"]["tenantId"]
    self.owner.grant("initial", self.tenant)
    self.assertTrue(self.service.activate_tenant(self.actor, request)["success"])
    self.request = str(uuid4())
    self.target = {"kind": "network", "address": "192.0.2.10"}

  def create(self, **changes):
    fields = {"actor": self.actor, "tenant_id": self.tenant, "request_id": self.request,
              "display_name": " Asset ", "target": self.target}
    return self.service.create_tenant_asset(**{**fields, **changes})

  def test_created_network_asset_roundtrips_as_projected_authorized_inventory(self):
    result = self.create()
    self.assertTrue(result["success"], result)
    asset = result["data"]
    self.assertEqual(asset["assetId"], "as_" + self.request)
    self.assertEqual(asset["tenantId"], self.tenant)
    self.assertEqual(asset["displayName"], "Asset")
    self.assertEqual(asset["target"], self.target)
    self.assertTrue(asset["active"])
    self.assertEqual(asset["createdBy"], "creator")
    self.assertEqual(asset["changedBy"], "creator")
    self.assertRegex(asset["version"], r"^[a-f0-9]{64}$")
    self.assertRegex(asset["targetDigest"], r"^[a-f0-9]{64}$")
    self.assertEqual(asset["targetDigest"], "b1224a722dc62b2bdc9b43b977f3fcdbc7680551e0979abe3b0522734dca3f6d")
    self.assertEqual(self.service.get_tenant_asset(self.actor, self.tenant, asset["assetId"])["data"],
                     {"asset": asset, "canUpdateAssets": True, "canLaunchJobs": True})
    self.assertEqual(self.service.list_tenant_assets(self.actor, self.tenant)["data"],
                     {"tenantId": self.tenant, "assets": [asset], "canCreateAssets": True, "canUpdateAssets": True})
    self.assertEqual(self.service.get_tenant_asset({"account_id": "initial"}, self.tenant, asset["assetId"])["data"],
                     {"asset": asset, "canUpdateAssets": False, "canLaunchJobs": False})

  def test_launch_hint_uses_stored_role_scope_and_allow_pentester_policy(self):
    asset = self.create()["data"]
    cases = (
      ((("super_tenant_admin", None),), True, True),
      ((("super_tenant_admin", None), ("super_pentester", None)), True, True),
      ((("super_pentester", None),), True, True),
      ((("super_pentester", self.tenant),), True, True),
      ((("tenant_pentester", self.tenant),), False, True),
      ((("tenant_admin", self.tenant),), False, False),
      ((("tenant_user", self.tenant),), False, False),
      ((("tenant_admin", self.tenant), ("tenant_pentester", self.tenant)), False, True),
      ((("super_pentester", "tn_87654321-4321-4321-8321-cba987654321"), ("super_pentester", self.tenant)), True, True),
    )
    for allow_pentester in (False, True):
      self.assertTrue(self.service.update_tenant_allow_pentester(
        self.actor, self.tenant, allow_pentester)["success"])
      for memberships, disabled, enabled in cases:
        with self.subTest(memberships=memberships, allow_pentester=allow_pentester):
          self.owner.account("operator", memberships=[
            {"role": role, "tenant_id": scope} for role, scope in memberships])
          actor = {"account_id": "operator", "role": "super_tenant_admin",
                   "tenant_memberships": [{"role": "super_tenant_admin", "tenant_id": None}]}
          before = len(self.owner.writes)
          result = self.service.get_tenant_asset(actor, self.tenant, asset["assetId"])
          self.assertTrue(result["success"], result)
          self.assertIs(result["data"]["canLaunchJobs"], enabled if allow_pentester else disabled)
          self.assertEqual(result["data"]["asset"], asset)
          self.assertEqual(len(self.owner.writes), before)

  def test_launch_hint_never_exposes_foreign_missing_or_unpublished_assets(self):
    asset = self.create()["data"]
    self.owner.account("operator", memberships=[{"role": "tenant_pentester", "tenant_id": "foreign"}])
    result = self.service.get_tenant_asset({"account_id": "operator"}, self.tenant, asset["assetId"])
    self.assertEqual(result["status_code"], 404, result)
    self.assertNotIn("data", result)
    foreign_request = str(uuid4())
    self.owner.account("initial-foreign")
    foreign = self.service.prepare_tenant(self.actor, foreign_request, "Foreign", "foreign",
                                          "initial-foreign")["data"]["tenantId"]
    result = self.service.get_tenant_asset(self.actor, foreign, asset["assetId"])
    self.assertEqual(result["status_code"], 404, result)
    self.assertNotIn("data", result)
    self.owner.grant("initial-foreign", foreign)
    self.assertTrue(self.service.activate_tenant(self.actor, foreign_request)["success"])
    for tenant_id, asset_id in ((foreign, asset["assetId"]), (self.tenant, "as_" + str(uuid4()))):
      with self.subTest(tenant_id=tenant_id, asset_id=asset_id):
        result = self.service.get_tenant_asset(self.actor, tenant_id, asset_id)
        self.assertEqual(result["status_code"], 404, result)
        self.assertNotIn("data", result)
    tenant = self.store.get("tenant", self.tenant)
    with patch.dict(self.owner.data):
      self.store.put("tenant", self.tenant, record={**tenant, "active": False})
      result = self.service.get_tenant_asset(self.actor, self.tenant, asset["assetId"])
      self.assertEqual(result["status_code"], 404, result)
      self.assertNotIn("data", result)
    with patch.dict(self.owner.data):
      del self.owner.data[self.store._location("receipt", (tenant["actor_id"], tenant["request_id"]))]
      result = self.service.get_tenant_asset(self.actor, self.tenant, asset["assetId"])
      self.assertEqual(result["status_code"], 503, result)
      self.assertNotIn("data", result)

  def test_create_replay_does_not_write_and_changed_intent_conflicts(self):
    original = self.create()["data"]
    before = len(self.owner.writes)
    self.assertEqual(self.create()["data"], original)
    self.assertEqual(len(self.owner.writes), before)
    for changes in ({"display_name": "Other"}, {"target": {**self.target, "address": "192.0.2.11"}}):
      with self.subTest(changes=changes):
        self.assertEqual(self.create(**changes)["status_code"], 409)
        self.assertEqual(len(self.owner.writes), before)

  def test_updates_are_version_guarded_but_retries_do_not_restore_prior_state(self):
    original = self.create()["data"]
    def update(**changes):
      fields = {"actor": self.actor, "tenant_id": self.tenant, "asset_id": original["assetId"],
                "expected_version": original["version"], "display_name": "Renamed",
                "target": {**self.target, "address": "192.0.2.20"}, "active": False}
      return self.service.update_tenant_asset(**{**fields, **changes})
    changed = update()["data"]
    self.assertFalse(changed["active"])
    self.assertEqual(changed["createdAt"], original["createdAt"])
    self.assertNotEqual(changed["version"], original["version"])
    self.assertNotEqual(changed["targetDigest"], original["targetDigest"])
    before = len(self.owner.writes)
    self.assertEqual(update()["data"], changed)  # stale version is harmless for an exact no-op
    self.assertEqual(self.create()["data"], changed)  # original creation intent never restores it
    self.assertEqual(update(active=True)["status_code"], 409)
    self.assertEqual(len(self.owner.writes), before)
    self.assertTrue(update(active=True, expected_version=changed["version"])["data"]["active"])

  def test_a_network_asset_records_a_canonical_authorized_port_scope(self):
    """The scope sits beside the target, never in it: the target digest is the
    asset's identity and the execution binding re-checks it."""
    plain = self.create(request_id=str(uuid4()))["data"]
    self.assertNotIn("authorizedPorts", plain)
    result = self.create(authorized_ports=" 8080, 1-1024,1000-1030 ,22 ")
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"]["authorizedPorts"], "1-1030,8080")
    self.assertEqual(result["data"]["target"], self.target)
    self.assertEqual(result["data"]["targetDigest"], plain["targetDigest"])

  def test_an_invalid_or_misplaced_port_scope_is_refused(self):
    for scope in ("0-10", "1-65536", "20-10", "http", "1,,2", 80, ",".join(str(p) for p in range(1, 200, 2))):
      with self.subTest(scope=scope):
        self.assertEqual(self.create(request_id=str(uuid4()), authorized_ports=scope)["status_code"], 400)
    webapp = {"kind": "webapp", "url": "https://example.com/api", "allowedPathPrefix": "/api"}
    self.assertEqual(self.create(target=webapp, authorized_ports="443")["status_code"], 400)

  def test_an_update_that_omits_the_scope_preserves_it_and_null_clears_it(self):
    original = self.create(authorized_ports="1-1024")["data"]
    def update(version, **changes):
      fields = {"actor": self.actor, "tenant_id": self.tenant, "asset_id": original["assetId"],
                "expected_version": version, "display_name": "Asset",
                "target": self.target, "active": True}
      return self.service.update_tenant_asset(**{**fields, **changes})
    before = len(self.owner.writes)
    self.assertEqual(update(original["version"])["data"], original)  # omitted: an exact no-op
    self.assertEqual(len(self.owner.writes), before)
    widened = update(original["version"], authorized_ports="1-1024,8080")["data"]
    self.assertEqual(widened["authorizedPorts"], "1-1024,8080")
    self.assertNotEqual(widened["version"], original["version"])
    self.assertEqual(widened["targetDigest"], original["targetDigest"])
    cleared = update(widened["version"], authorized_ports=None)["data"]
    self.assertNotIn("authorizedPorts", cleared)

  def test_web_assets_canonicalize_authority_preserve_path_and_require_explicit_scope(self):
    for url, prefix, expected in (("HTTP://EXAMPLE.COM:80/api/item", "/api/", "http://example.com/api/item"),
                                  ("https://[2001:0DB8::1]:443/api", "/api", "https://[2001:db8::1]/api"),
                                  ("https://xn--bcher-kva.example/api/%7Eme", "/api", "https://xn--bcher-kva.example/api/%7Eme"),
                                  ("https://example.com", "/", "https://example.com/")):
      with self.subTest(url=url):
        result = self.create(request_id=str(uuid4()), target={"kind": "webapp", "url": url, "allowedPathPrefix": prefix})
        self.assertTrue(result["success"], result)
        self.assertEqual(result["data"]["target"], {"kind": "webapp", "url": expected,
                                                  "allowedPathPrefix": prefix.rstrip("/") or "/"})
    result = self.create(target={"kind": "webapp", "url": "https://example.com/api-other", "allowedPathPrefix": "/api"})
    self.assertEqual(result["status_code"], 400)

  def test_model_asset_retains_full_endpoint_and_case_without_dns_or_provider_requests(self):
    with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS during CRUD")), \
         patch("requests.sessions.Session.request", side_effect=AssertionError("No target calls during CRUD")):
      target = {"kind": "model", "adapter": "openai_compatible",
                "endpointUrl": "https://EXAMPLE.COM:443/custom/chat/completions", "model": " Case-Sensitive "}
      result = self.create(target=target)
      self.assertTrue(result["success"], result)
      self.assertEqual(result["data"]["target"], {**target, "endpointUrl": "https://example.com/custom/chat/completions", "model": "Case-Sensitive"})
      for endpoint in ("http://example.com/chat/completions", "https://example.com/v1",
                       "https://example.com/chat/completions/", "https://example.com/chat%2Fcompletions"):
        with self.subTest(endpoint=endpoint):
          self.assertEqual(self.create(request_id=str(uuid4()), target={**target, "endpointUrl": endpoint})["status_code"], 400)

  def test_counts_share_full_validation_even_for_inactive_assets(self):
    asset = self.create()["data"]
    self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], asset["version"],
                                     asset["displayName"], asset["target"], False)
    self.create(request_id=str(uuid4()))
    self.assertEqual(self.store.count_assets(self.tenant), 1)
    self.assertEqual(self.service.get_tenant(self.actor, self.tenant)["data"]["assetCount"], 1)
    key = json.dumps(["asset", "deployment", self.tenant, asset["assetId"]], separators=(",", ":"))
    self.owner.data[('["redmesh","tenancy",1,"deployment"]', key)]["target"] = {"kind": "network"}
    with self.assertRaises(TenantStoreError):
      self.store.count_assets(self.tenant)
    self.assertEqual(self.service.list_tenant_assets(self.actor, self.tenant)["status_code"], 503)

  def test_raw_non_ascii_authority_and_scheme_are_not_repaired_into_valid_urls(self):
    for url in ("https://\u212a.example/api", "http\u017f://example.com/api"):
      with self.subTest(url=url):
        self.assertEqual(self.create(target={"kind": "webapp", "url": url, "allowedPathPrefix": "/"})["status_code"], 400)

  def test_url_grammar_rejects_ambiguous_authorities_and_every_decoding_stage(self):
    bad_authorities = ("@host", "user@host", "user:password@host", "host:", "host:0", "host:080", "host:65536",
                       "127.1", "0x7f000001", "0x", "0X", "example.0x", "127.00.0.1", "256.0.0.1",
                       "example.123", "example.0xabc", "host.", "under_score", "höst", "-host", "host-",
                       "a" * 64 + ".example", "[::1%zone]", "[::1", "::1", "[::1]:", "[::1]:00")
    bad_paths = ("/a?", "/a#", "/a//b", "/a/./b", "/a/../b", "/a/%", "/a/%GG", "/a/%FF", "/a/%C0%AF",
                 "/a/%ED%A0%80", "/a/%25252541", "/a/%2E%2e/b", "/a/%252e%252e/b", "/a/%2F/b",
                 "/a/%20", "/a/%00", "/a/%C2%85", "/a/%EF%BB%BF", "/a/%3F", "/a/%23", "/a/%5C",
                 "/a\u2003", "/a\\b", "/a\ud800")
    before = len(self.owner.writes)
    with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")), \
         patch("requests.sessions.Session.request", side_effect=AssertionError("No HTTP")):
      for url in ["https://" + host + "/api" for host in bad_authorities] + ["https://host" + path for path in bad_paths]:
        with self.subTest(url=url):
          self.assertEqual(self.create(target={"kind": "webapp", "url": url, "allowedPathPrefix": "/"})["status_code"], 400)
      for prefix in (None, [], "", "api", "//api", "/api//", "/api/.", "/api/..", "/%61pi", "/api?", "/api#", "/api\\", "/api\u00a0"):
        with self.subTest(prefix=prefix):
          self.assertEqual(self.create(target={"kind": "webapp", "url": "https://host/api", "allowedPathPrefix": prefix})["status_code"], 400)
    self.assertEqual(len(self.owner.writes), before)

  def test_valid_encodings_boundaries_and_names_preserve_canonical_values(self):
    for path in ("/api/%7Eme", "/api/%257Eme", "/api/%25257Eme", "/api/%E2%82%AC"):
      with self.subTest(path=path):
        result = self.create(request_id=str(uuid4()), target={"kind": "webapp", "url": "https://host" + path, "allowedPathPrefix": "/api"})
        self.assertTrue(result["success"], result)
        self.assertEqual(result["data"]["target"]["url"], "https://host" + path)
    name = "\U0001f600" * 120
    asset = self.create(display_name="\u2003" + name + "\u2003")["data"]
    self.assertEqual(asset["displayName"], name)
    for value in ("", " ", name + "x", "\tAsset", "Asset\n", "\ufeffAsset", "Asset\x7f", "Asset\x85", "Asset\ud800", [], 1):
      with self.subTest(name=value):
        self.assertEqual(self.create(display_name=value)["status_code"], 400)
    target = {"kind": "model", "adapter": "openai_compatible", "endpointUrl": "https://host/chat/completions", "model": "\U0001f600" * 200}
    self.assertTrue(self.create(request_id=str(uuid4()), target=target)["success"])
    for value in ("x" * 201, "\tModel", "Model\n", "\ufeffModel", "Model\ud800", None):
      with self.subTest(model=value):
        self.assertEqual(self.create(target={**target, "model": value})["status_code"], 400)
    url = "https://host/" + "a" * (2048 - len("https://host/"))
    self.assertTrue(self.create(request_id=str(uuid4()), target={"kind": "webapp", "url": url, "allowedPathPrefix": "/"})["success"])
    self.assertEqual(self.create(target={"kind": "webapp", "url": url + "a", "allowedPathPrefix": "/"})["status_code"], 400)

  def test_network_target_accepts_a_canonical_hostname(self):
    target = {"kind": "network", "address": "scanme.nmap.org"}
    result = self.create(request_id=str(uuid4()), target=target)
    self.assertTrue(result["success"])
    self.assertEqual(result["data"]["target"], target)

  def test_noncanonical_and_secret_bearing_targets_are_rejected_before_writes(self):
    for target in (None, [], "192.0.2.10", {}, {"kind": "network", "address": 1},
                   {"kind": "network", "address": "192.0.2.0/24"}, {"kind": "network", "address": "::1"},
                   {"kind": "network", "address": "Example.com"}, {"kind": "network", "address": "http://example.com"},
                   {"kind": "network", "address": "example.com:80"}, {"kind": "network", "address": "example.com/"},
                   {"kind": "network", "address": "example.com."}, {"kind": "network", "address": "a..b"},
                   {"kind": "network", "address": "127.1"}, {"kind": "network", "address": "010.0.0.1"},
                   {"kind": "network", "address": "user@example.com"}, {"kind": "network", "address": "b\u00fccher.de"},
                   {"kind": "network", "address": ""}, {**self.target, "port": 443},
                   {**self.target, "credential_ref": "secret"}, {**self.target, "headers": {}},
                   {"kind": "api", "url": "https://host"}):
      with self.subTest(target=target):
        before = len(self.owner.writes)
        self.assertEqual(self.create(target=target)["status_code"], 400)
        self.assertEqual(len(self.owner.writes), before)

  def test_malformed_asset_selectors_are_bad_requests_after_scope_authorization(self):
    for asset_id in (None, {}, "", "as_bad", "as_" + str(uuid4()).upper()):
      with self.subTest(asset_id=asset_id):
        self.assertEqual(self.service.get_tenant_asset(self.actor, self.tenant, asset_id)["status_code"], 400)
        self.assertEqual(self.service.update_tenant_asset(self.actor, self.tenant, asset_id, "a" * 64, "Asset", self.target, True)["status_code"], 400)

  def test_every_asset_boundary_rejects_corrupt_records_including_inactive_rows(self):
    asset = self.create()["data"]
    row = self.store.get("asset", self.tenant, asset["assetId"])
    location = asset_location(self.tenant, asset["assetId"])
    for changes in ({"schemaVersion": True}, {"namespace": "foreign"}, {"kind": "tenant"},
                    {"ids": [self.tenant, "other"]}, {"tenant_id": "other"}, {"asset_id": "other"},
                    {"request_id": str(uuid4())}, {"display_name": " untrimmed "}, {"target": {}},
                    {"target_digest": "0" * 64}, {"create_intent_digest": "A" * 64}, {"active": 1},
                    {"created_by": " Creator "}, {"changed_by": {}}, {"created_at": "not-a-time"},
                    {"changed_at": "2026-09-11T12:00:00+01:00"}, {"changed_at": None},
                    {"active": False, "changed_by": ""}, {"future": float("nan")}):
      with self.subTest(changes=changes):
        bad = {**row, **changes}
        self.owner.data[location] = bad
        before = len(self.owner.writes)
        for read in (lambda: self.store.get("asset", self.tenant, asset["assetId"]),
                     lambda: self.store.list_assets(self.tenant), lambda: self.store.count_assets(self.tenant)):
          with self.assertRaises(TenantStoreError):
            read()
        with self.assertRaises(TenantStoreError):
          self.store.put("asset", self.tenant, asset["assetId"], record=bad)
        detail = self.service.get_tenant_asset(self.actor, self.tenant, asset["assetId"])
        self.assertEqual(detail["status_code"], 503)
        self.assertNotIn("data", detail)
        self.assertEqual(self.create()["status_code"], 503)
        self.assertEqual(self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], asset["version"], "Asset", self.target, False)["status_code"], 503)
        self.assertEqual(len(self.owner.writes), before)
    for bad in ("broken-json", b"\xff", [], {}, {"schemaVersion": 1, "namespace": "deployment",
                "tenant_id": self.tenant, "asset_id": asset["assetId"], "active": True}):
      with self.subTest(raw=bad):
        self.owner.data[location] = bad
        self.assertEqual(self.service.get_tenant_asset(self.actor, self.tenant, asset["assetId"])["status_code"], 503)
        self.assertEqual(self.create()["status_code"], 503)

  def test_foreign_corruption_is_filtered_but_local_noncanonical_fields_are_not_repaired(self):
    asset = self.create()["data"]
    hkey, _ = asset_location(self.tenant, asset["assetId"])
    for field in (["asset", "deployment", "foreign", None], ["asset", "foreign", self.tenant, None]):
      self.owner.data[hkey, json.dumps(field)] = "private malformed record"
    self.assertEqual(self.service.list_tenant_assets(self.actor, self.tenant)["data"]["assets"], [asset])
    self.assertEqual(self.store.count_assets(self.tenant), 1)
    for ids in ([self.tenant], [self.tenant, None], [self.tenant, asset["assetId"], "extra"]):
      key = json.dumps(["asset", "deployment", *ids], separators=(",", ":"))
      self.owner.data[hkey, key] = {"kind": "asset", "schemaVersion": 1, "namespace": "deployment", "ids": ids}
      with self.assertRaises(TenantStoreError):
        self.store.list_assets(self.tenant)
      del self.owner.data[hkey, key]
    noncanonical = (hkey, json.dumps(["asset", "deployment", self.tenant, asset["assetId"]]))
    self.owner.data[noncanonical] = "corrupt"
    self.assertEqual(self.service.list_tenant_assets(self.actor, self.tenant)["status_code"], 503)
    self.assertTrue(self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], asset["version"], "Asset", self.target, False)["success"])
    self.assertEqual(self.owner.data[noncanonical], "corrupt")
    self.assertEqual(self.service.list_tenant_assets(self.actor, self.tenant)["status_code"], 503)

  def test_full_record_version_preserves_future_fields_and_immutable_creation_metadata(self):
    original = self.create()["data"]
    row = self.store.get("asset", self.tenant, original["assetId"])
    extended = {**row, "future_field": {"value": "retained"}}
    self.store.put("asset", self.tenant, original["assetId"], record=extended)
    current = self.service.get_tenant_asset(self.actor, self.tenant, original["assetId"])["data"]["asset"]
    self.assertNotIn("future_field", current)
    self.assertNotEqual(current["version"], original["version"])
    self.assertEqual(self.service.update_tenant_asset(self.actor, self.tenant, original["assetId"], original["version"], "Renamed", self.target, True)["status_code"], 409)
    result = self.service.update_tenant_asset(self.actor, self.tenant, original["assetId"], current["version"], "Renamed", self.target, False)
    self.assertTrue(result["success"], result)
    changed = self.store.get("asset", self.tenant, original["assetId"])
    for name in ("future_field", "created_by", "created_at", "create_intent_digest", "request_id", "target_digest"):
      self.assertEqual(changed[name], extended[name])
    self.assertEqual(self.create()["data"], result["data"])
    with patch("extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration.MAX_ENUMERATED_RECORDS", 0):
      self.assertEqual(self.service.list_tenant_assets(self.actor, self.tenant)["status_code"], 503)

  def test_kind_is_immutable_and_mutation_types_remain_strict_on_noop(self):
    asset = self.create()["data"]
    before = len(self.owner.writes)
    web = {"kind": "webapp", "url": "https://host/", "allowedPathPrefix": "/"}
    self.assertEqual(self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], asset["version"], "Asset", web, True)["status_code"], 400)
    for version, active in [(asset["version"], value) for value in (1, 0, "true", None, [], {})] + [(value, True) for value in (None, "A" * 64, [], "short")]:
      with self.subTest(version=version, active=active):
        self.assertEqual(self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], version, "Asset", self.target, active)["status_code"], 400)
    self.assertEqual(len(self.owner.writes), before)

  def test_uncertain_create_and_update_writes_reconcile_without_rollback_or_history_reset(self):
    for after in (False, True):
      with self.subTest(after=after):
        request_id = str(uuid4())
        self.owner.fail_write = len(self.owner.writes) + 1
        self.owner.fail_after_write = after
        self.assertEqual(self.create(request_id=request_id)["status_code"], 503)
        before = len(self.owner.writes)
        self.owner.fail_write = None
        asset = self.create(request_id=request_id)["data"]
        self.assertEqual(len(self.owner.writes), before if after else before + 1)
        self.owner.fail_write = len(self.owner.writes) + 1
        self.assertEqual(self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], asset["version"], "Asset", self.target, False)["status_code"], 503)
        before = len(self.owner.writes)
        self.owner.fail_write = None
        changed = self.service.update_tenant_asset(self.actor, self.tenant, asset["assetId"], asset["version"], "Asset", self.target, False)
        self.assertTrue(changed["success"], changed)
        self.assertEqual(len(self.owner.writes), before if after else before + 1)
        self.assertEqual(self.create(request_id=request_id)["data"], changed["data"])
    self.owner.noop = True
    self.assertEqual(self.create()["status_code"], 503)
    self.owner.noop = False
    for acknowledgement in (False, None, 1):
      with self.subTest(acknowledgement=acknowledgement), patch.object(self.owner, "chainstore_hset", return_value=acknowledgement):
        self.assertEqual(self.create()["status_code"], 503)
