"""RM-095 phase 2, RM-107: engagements through the real administration service, identity and CStore store."""
from datetime import datetime, timezone
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from .test_tenant_administration import FakeAdministrationStore
from .contract_fixture import CONTRACT_SHA256, contract_terms
from extensions.business.cybersec.red_mesh.tenancy.administration import TenantAdministrationService
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_identity import CstoreAuthAccountReader

SHA_ROE, SHA_AUTH = "1" * 64, "2" * 64
NETWORK = {"kind": "network", "address": "192.0.2.10"}
WEBAPP = {"kind": "webapp", "url": "https://app.example.com/", "allowedPathPrefix": "/"}
MODEL = {"kind": "model", "adapter": "openai_compatible",
         "endpointUrl": "https://llm.example.com/v1/chat/completions", "model": "m"}


def network(**extra):
  return {"display_name": "Edge gateway", "target": NETWORK, "authorized_ports": "22,443", **extra}


def doc(sha256, ref, uploaded_by="creator", mime="application/pdf", kind="agreement", title=None, comment=""):
  """A verified document reference, as `resolve_engagement_document` returns one."""
  return {"store": "r1fs", "ref": ref, "kind": kind, "title": title or ref.upper(), "comment": comment,
          "sha256": sha256, "filename": ref + ".pdf", "mime": mime,
          "size_bytes": 2048, "uploaded_at": "2026-09-28T09:00:00Z", "uploaded_by": uploaded_by}


class TestTenantEngagements(unittest.TestCase):
  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.owner = FakeAdministrationStore()
    self.store = CstoreTenantAdministrationStore(self.owner, "deployment")
    self.service = TenantAdministrationService(CstoreAuthAccountReader(self.owner), self.store)
    self.actor = {"account_id": "creator"}
    self.tenant = self.new_tenant("tenant", contract=True)
    self.request = str(uuid4())

  def new_tenant(self, domain, contract):
    request, admin = str(uuid4()), "initial" if domain == "tenant" else "initial-" + domain
    self.owner.account(admin)
    prepared = self.service.prepare_tenant(self.actor, request, domain.title(), domain, admin, **contract_terms())
    self.assertTrue(prepared["success"], prepared)
    tenant = prepared["data"]["tenantId"]
    self.owner.grant(admin, tenant)
    self.assertTrue(self.service.activate_tenant(self.actor, request)["success"])
    if not contract:
      # A tenant created before contracts were required: its record and receipt carry no terms.
      for row in self.owner.data.values():
        if isinstance(row, dict) and row.get("tenant_id") == tenant:
          row.pop("legal", None), row.pop("contract", None)
    return tenant

  def fields(self, **changes):
    fields = {
      "actor": self.actor, "tenant_id": self.tenant, "request_id": self.request,
      "display_name": " Q4 external ", "allowed_run_modes": ["single_pass", "continuous"],
      "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-10-31T00:00:00+00:00",
      "roe": {"authenticated_action": True}, "context": {"client_name": "Example", "asset_exposure": "external"},
      "assets": [network(authorized_tests=["service_info_common", "active_auth"]),
                 {"display_name": "Customer portal", "target": WEBAPP, "authorized_tests": ["graybox"]},
                 {"display_name": "Support bot", "target": MODEL, "authorized_tests": ["prompt_injection_v1"]}],
      "documents": [doc(SHA_ROE, "roe", title="Rules of engagement"),
                    doc(SHA_AUTH, "auth", kind="third_party_consent", title="Hosting consent",
                        comment="provider ticket 42")],
    }
    fields.update(changes)
    return fields

  def create(self, **changes):
    return self.service.create_engagement(**self.fields(**changes))

  @staticmethod
  def view(result):
    """The engagement DTO without the per-call `replayed` flag."""
    return {key: value for key, value in result["data"].items() if key != "replayed"}

  def refused(self, result, status, error):
    self.assertFalse(result["success"], result)
    self.assertEqual((result["status_code"], result["error"]), (status, error))

  def test_created_engagement_defines_its_assets_scope_and_hash(self):
    result = self.create()
    self.assertTrue(result["success"], result)
    engagement = result["data"]
    self.assertEqual(engagement["engagementId"], "en_" + self.request)
    self.assertEqual(engagement["displayName"], "Q4 external")
    self.assertEqual(engagement["validUntil"], "2026-10-31T00:00:00Z")
    self.assertEqual(engagement["contractSha256"], CONTRACT_SHA256)
    self.assertEqual(engagement["roe"], {"authenticated_action": True, "stateful_probes_allowed": False,
                                         "ics_safe_mode_required": True})
    self.assertEqual(engagement["anchor"], {"status": "pending"})
    self.assertRegex(engagement["engagementHash"], r"^[a-f0-9]{64}$")
    network_asset, webapp, model = engagement["assets"]
    self.assertEqual({key: network_asset[key] for key in ("engagementAssetId", "displayName", "kind", "target")},
                     {"engagementAssetId": "ea_1", "displayName": "Edge gateway", "kind": "network",
                      "target": NETWORK})
    self.assertRegex(network_asset["targetDigest"], r"^[a-f0-9]{64}$")
    self.assertEqual(network_asset["authorizedPorts"], "22,443")
    self.assertEqual(network_asset["authorizedScanModes"], ["connect"])
    self.assertEqual(network_asset["authorizedTests"], ["active_auth", "service_info_common"])
    self.assertEqual((webapp["engagementAssetId"], webapp["kind"]), ("ea_2", "webapp"))
    self.assertNotIn("authorizedPorts", webapp)
    self.assertEqual((model["engagementAssetId"], model["kind"], model["target"], model["authorizedTests"]),
                     ("ea_3", "model", MODEL, ["prompt_injection_v1"]))
    self.assertNotIn("authorizedScanModes", model)
    self.assertEqual(engagement["allowedRunModes"], ["continuous", "single_pass"])
    self.assertEqual([(item["documentId"], item["kind"], item["title"], item["comment"], item["sha256"])
                      for item in engagement["documents"]],
                     [("ed_1", "agreement", "Rules of engagement", "", SHA_ROE),
                      ("ed_2", "third_party_consent", "Hosting consent", "provider ticket 42", SHA_AUTH)])
    for gone in ("kind", "roeDocument", "authorizationDocument"):
      self.assertNotIn(gone, engagement)

  def test_the_dto_never_carries_a_document_or_contract_reference(self):
    engagement = self.create()["data"]
    listed = self.service.list_engagements({"account_id": "initial"}, self.tenant)["data"]["engagements"]
    for view in (engagement, listed[0]):
      text = json.dumps(view)
      self.assertNotIn('"ref"', text)
      self.assertNotIn('"store"', text)
      self.assertNotIn("r1fs", text)

  def test_documents_are_optional(self):
    result = self.create(documents=[])
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"]["documents"], [])

  def test_a_tenant_without_a_contract_creates_no_engagement(self):
    legacy = self.new_tenant("legacy", contract=False)
    writes = len(self.owner.writes)
    self.refused(self.create(tenant_id=legacy, assets=[network(authorized_tests=["active_auth"])]),
                 400, "contract_required")
    self.refused(self.service.authorize_engagement_create(self.actor, legacy), 400, "contract_required")
    self.assertEqual(len(self.owner.writes), writes)

  def test_ports_and_scan_modes_are_normalized(self):
    assets = [network(authorized_ports="80, 443", authorized_scan_modes=["syn", "connect"],
                      authorized_tests=["service_info_common"])]
    engagement = self.create(assets=assets)["data"]
    self.assertEqual(engagement["assets"][0]["authorizedPorts"], "80,443")
    self.assertEqual(engagement["assets"][0]["authorizedScanModes"], ["connect", "syn"])

  def test_scan_mode_order_does_not_change_the_request(self):
    assets = lambda modes: [network(authorized_scan_modes=modes, authorized_tests=["active_auth"])]
    first = self.view(self.create(assets=assets(["syn", "connect"])))
    self.assertEqual(self.view(self.create(assets=assets(["connect", "syn"]))), first)
    self.refused(self.create(request_id=str(uuid4()), assets=assets([["connect"]])), 400, "engagement_asset_invalid")

  def test_a_network_asset_needs_a_port_scope(self):
    bare = {"display_name": "Bare", "target": NETWORK, "authorized_tests": ["service_info_common"]}
    self.refused(self.create(assets=[bare]), 400, "ports_required")
    for blank in (None, "", "   "):
      with self.subTest(ports=blank):
        self.refused(self.create(request_id=str(uuid4()), assets=[dict(bare, authorized_ports=blank)]),
                     400, "ports_required")
    self.assertTrue(self.create(assets=[dict(bare, authorized_ports="443")])["success"])

  def test_asset_refusals(self):
    portal = {"display_name": "Portal", "target": WEBAPP, "authorized_tests": ["graybox"]}
    cases = [
      ([dict(network(), authorized_tests=["active_auth"], asset_id="as_" + str(uuid4()))], "engagement_asset_invalid"),
      ([{"display_name": "Bot", "target": MODEL, "authorized_tests": []}], "tests_invalid"),
      ([{"display_name": "Bot", "target": MODEL, "authorized_tests": ["graybox"]}], "tests_invalid"),
      ([{"display_name": "Bot", "target": MODEL, "authorized_ports": "443",
         "authorized_tests": ["cbrn_safety_v1"]}], "engagement_asset_invalid"),
      ([dict(portal, authorized_tests=["service_info_common"])], "tests_invalid"),
      ([network(authorized_tests=["graybox"])], "tests_invalid"),
      ([network(authorized_tests=["nope"])], "tests_invalid"),
      ([dict(portal, authorized_ports="80")], "engagement_asset_invalid"),
      ([dict(portal, authorized_scan_modes=["connect"])], "engagement_asset_invalid"),
      ([network(authorized_scan_modes=["udp"], authorized_tests=["active_auth"])], "engagement_asset_invalid"),
      ([network(authorized_scan_modes=[], authorized_tests=["active_auth"])], "engagement_asset_invalid"),
      ([network(authorized_tests=["active_auth"])] * 2, "engagement_asset_invalid"),
      ([network(authorized_tests=["active_auth"], display_name="")], "engagement_asset_invalid"),
      ([network(authorized_tests=["active_auth"], target={"kind": "network", "address": "bad host"})],
       "asset_target_invalid"),
      ([dict(portal, target={"kind": "webapp", "url": "ftp://x", "allowedPathPrefix": "/"})], "asset_target_invalid"),
      ([], "engagement_asset_invalid"),
    ]
    for assets, error in cases:
      with self.subTest(error=error, assets=assets):
        self.refused(self.create(request_id=str(uuid4()), assets=assets), 400, error)

  def test_request_value_refusals(self):
    cases = [
      ({"allowed_run_modes": ["forever"]}, "run_modes_invalid"), ({"allowed_run_modes": []}, "run_modes_invalid"),
      ({"allowed_run_modes": None}, "run_modes_invalid"), ({"display_name": ""}, "invalid_request"),
      ({"valid_until": "2026-09-01T00:00:00Z"}, "window_invalid"), ({"valid_from": "tomorrow"}, "window_invalid"),
      ({"roe": {"dos_allowed": True}}, "roe_invalid"), ({"roe": {"authenticated_action": "yes"}}, "roe_invalid"),
      ({"context": {"client_name": None}}, "context_invalid"),
      ({"documents": [doc(SHA_ROE, "roe", uploaded_by="someone")]}, "document_invalid"),
      ({"documents": [{"ref": "auth"}]}, "document_invalid"),
      ({"documents": [doc(SHA_ROE, "roe", kind="roe")]}, "document_invalid"),
      ({"documents": [doc(SHA_ROE, "roe", title=" ")]}, "document_invalid"),
      ({"documents": [doc(SHA_ROE, "roe"), doc(SHA_ROE, "roe-again")]}, "document_invalid"),
      ({"documents": [doc("%064x" % index, "d%d" % index) for index in range(21)]}, "document_invalid"),
      ({"documents": "roe"}, "document_invalid"),
      ({"supersedes": "en_nope"}, "supersedes_invalid"),
      ({"supersedes": "en_" + str(uuid4())}, "supersedes_invalid"),
      ({"request_id": "not-a-uuid"}, "invalid_request"),
    ]
    for changes, error in cases:
      with self.subTest(error=error, changes=changes):
        self.refused(self.create(**{"request_id": str(uuid4()), **changes}), 400, error)

  def test_replay_returns_the_record_without_a_write(self):
    first = self.create()
    self.assertIs(first["data"]["replayed"], False)
    first = self.view(first)
    writes = len(self.owner.writes)
    replayed = self.create()
    self.assertIs(replayed["data"]["replayed"], True)
    self.assertEqual(self.view(replayed), first)
    # A re-upload of the same bytes has a new reference but is the same creation.
    documents = self.fields()["documents"]
    self.assertEqual(self.view(self.create(documents=[doc(SHA_ROE, "roe-again", title="Rules of engagement"),
                                                      documents[1]])), first)
    self.assertEqual(len(self.owner.writes), writes)
    self.refused(self.create(display_name="Other"), 409, "conflict")
    self.refused(self.create(documents=[doc("3" * 64, "roe", title="Rules of engagement"), documents[1]]),
                 409, "conflict")
    self.refused(self.create(documents=[doc(SHA_ROE, "roe", title="SOW"), documents[1]]), 409, "conflict")
    self.refused(self.create(allowed_run_modes=["continuous"]), 409, "conflict")
    self.refused(self.create(assets=list(reversed(self.fields()["assets"]))), 409, "conflict")

  def test_roles(self):
    self.owner.account("platform-pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.owner.account("scoped-pentester", memberships=[{"role": "super_pentester", "tenant_id": self.tenant}])
    self.owner.account("pentester", memberships=[{"role": "tenant_pentester", "tenant_id": self.tenant}])
    self.owner.account("viewer", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    other = self.new_tenant("other", contract=True)
    self.owner.account("elsewhere", memberships=[{"role": "super_pentester", "tenant_id": other}])
    # Owner, 2026-09-28: only a Super-Tenant Admin manages engagements; a Super-Pentester reads
    # their documents (Q5) but neither creates nor revokes.
    for account in ("platform-pentester", "scoped-pentester", "pentester", "viewer", "initial"):
      docs = [doc(SHA_ROE, "roe", account), doc(SHA_AUTH, "auth", account)]
      self.refused(self.create(actor={"account_id": account}, request_id=str(uuid4()), documents=docs),
                   403, "forbidden")
    self.refused(self.create(actor={"account_id": "elsewhere"}, request_id=str(uuid4())), 404, "not_found")
    engagement = self.create()["data"]["engagementId"]
    for account in ("platform-pentester", "scoped-pentester", "pentester", "viewer"):
      self.refused(self.service.revoke_engagement({"account_id": account}, self.tenant, engagement, "x"),
                   403, "forbidden")
    for account in ("pentester", "viewer"):
      self.refused(self.service.engagement_document_ref({"account_id": account}, self.tenant, engagement, "ed_1"),
                   403, "forbidden")
      self.assertTrue(self.service.get_engagement({"account_id": account}, self.tenant, engagement)["success"])
    self.refused(self.service.get_engagement({"account_id": "elsewhere"}, self.tenant, engagement), 404, "not_found")
    self.assertTrue(self.service.engagement_document_ref({"account_id": "platform-pentester"}, self.tenant, engagement, "ed_1")["success"])
    viewer = self.service.get_engagement({"account_id": "viewer"}, self.tenant, engagement)["data"]
    self.assertEqual((viewer["canRevokeEngagements"], viewer["canDownloadDocuments"]), (False, False))
    listed = self.service.list_engagements({"account_id": "platform-pentester"}, self.tenant)["data"]
    self.assertEqual((listed["canCreateEngagements"], listed["canRevokeEngagements"]), (False, False))
    listed = self.service.list_engagements(self.actor, self.tenant)["data"]
    self.assertEqual((listed["canCreateEngagements"], listed["canRevokeEngagements"]), (True, True))

  def test_document_ref_is_authorized_before_the_lookup(self):
    self.owner.account("viewer", memberships=[{"role": "tenant_user", "tenant_id": self.tenant}])
    missing = "en_" + str(uuid4())
    self.refused(self.service.engagement_document_ref({"account_id": "viewer"}, self.tenant, missing, "ed_1"),
                 403, "forbidden")
    self.refused(self.service.engagement_document_ref(self.actor, self.tenant, missing, "ed_1"), 404, "not_found")
    engagement = self.create()["data"]["engagementId"]
    for bad in ("contract", "roe", "ed_0", "ed_01", 2):
      self.refused(self.service.engagement_document_ref(self.actor, self.tenant, engagement, bad),
                   400, "invalid_request")
    self.refused(self.service.engagement_document_ref(self.actor, self.tenant, engagement, "ed_3"), 404, "not_found")
    ref = self.service.engagement_document_ref(self.actor, self.tenant, engagement, "ed_2")["data"]
    self.assertEqual((ref["store"], ref["ref"], ref["sha256"]), ("r1fs", "auth", SHA_AUTH))

  def test_supersedes_links_without_revoking(self):
    first = self.create()["data"]["engagementId"]
    second = self.create(request_id=str(uuid4()), supersedes=first)["data"]
    self.assertEqual(second["supersedes"], first)
    self.assertTrue(self.service.get_engagement(self.actor, self.tenant, first)["data"]["engagement"]["active"])
    self.refused(self.create(request_id=first[3:], supersedes=first), 409, "conflict")

  def test_revoke_is_final_and_idempotent(self):
    engagement = self.create()["data"]
    self.refused(self.service.revoke_engagement(self.actor, self.tenant, engagement["engagementId"], " "),
                 400, "invalid_request")
    revoked = self.service.revoke_engagement(self.actor, self.tenant, engagement["engagementId"], " Scope withdrawn ")
    self.assertTrue(revoked["success"], revoked)
    self.assertFalse(revoked["data"]["active"])
    self.assertEqual((revoked["data"]["revokedBy"], revoked["data"]["revokeReason"]), ("creator", "Scope withdrawn"))
    self.assertEqual(revoked["data"]["engagementHash"], engagement["engagementHash"])
    self.assertIs(revoked["data"]["replayed"], False)
    writes = len(self.owner.writes)
    again = self.service.revoke_engagement(self.actor, self.tenant, engagement["engagementId"], "again")
    self.assertIs(again["data"]["replayed"], True)
    self.assertEqual(self.view(again), self.view(revoked))
    self.assertEqual(len(self.owner.writes), writes)
    self.refused(self.service.revoke_engagement(self.actor, self.tenant, "en_" + str(uuid4()), "x"), 404, "not_found")

  def test_list_is_newest_first_and_filters_on_active(self):
    with patch("extensions.business.cybersec.red_mesh.tenancy.administration.datetime") as clock:
      ids = []
      for day in (1, 3, 2):
        clock.now.return_value = datetime(2026, 9, day, tzinfo=timezone.utc)
        ids.append(self.create(request_id=str(uuid4()))["data"]["engagementId"])
      self.service.revoke_engagement(self.actor, self.tenant, ids[0], "done")
    listed = self.service.list_engagements(self.actor, self.tenant)["data"]["engagements"]
    self.assertEqual([row["engagementId"] for row in listed], [ids[1], ids[2], ids[0]])
    active = self.service.list_engagements(self.actor, self.tenant, active=True)["data"]["engagements"]
    self.assertEqual([row["engagementId"] for row in active], [ids[1], ids[2]])
    self.refused(self.service.list_engagements(self.actor, self.tenant, active="yes"), 400, "invalid_request")


class TestEngagementTargetGrammar(unittest.TestCase):
  """RM-107: an engagement asset's target is the only scan-target write gate (`normalize_target`).

  Ported from the retired tenant asset suites: the strict grammar, canonical forms, the refusal of
  secret-bearing or ambiguous targets, and no DNS, HTTP or write on any refusal.
  """
  setUp = TestTenantEngagements.setUp
  new_tenant = TestTenantEngagements.new_tenant
  fields = TestTenantEngagements.fields
  _TESTS = {"network": ["service_info_common"], "webapp": ["graybox"], "model": ["prompt_injection_v1"]}

  def create(self, target, display_name="Asset"):
    kind = target.get("kind") if isinstance(target, dict) else None
    asset = {"display_name": display_name, "target": target, "authorized_tests": self._TESTS.get(kind, ["graybox"]),
             **({"authorized_ports": "443"} if kind == "network" else {})}
    return self.service.create_engagement(**self.fields(request_id=str(uuid4()), assets=[asset], documents=[]))

  def created_target(self, target):
    result = self.create(target)
    self.assertTrue(result["success"], result)
    return result["data"]["assets"][0]["target"]

  def refused(self, target, error="asset_target_invalid", display_name="Asset"):
    before = len(self.owner.writes)
    result = self.create(target, display_name)
    self.assertEqual((result.get("status_code"), result.get("error")), (400, error), result)
    self.assertEqual(len(self.owner.writes), before)

  def test_web_targets_canonicalize_authority_preserve_path_and_require_explicit_scope(self):
    for url, prefix, expected in (("HTTP://EXAMPLE.COM:80/api/item", "/api/", "http://example.com/api/item"),
                                  ("https://[2001:0DB8::1]:443/api", "/api", "https://[2001:db8::1]/api"),
                                  ("https://xn--bcher-kva.example/api/%7Eme", "/api", "https://xn--bcher-kva.example/api/%7Eme"),
                                  ("https://example.com", "/", "https://example.com/")):
      with self.subTest(url=url):
        self.assertEqual(self.created_target({"kind": "webapp", "url": url, "allowedPathPrefix": prefix}),
                         {"kind": "webapp", "url": expected, "allowedPathPrefix": prefix.rstrip("/") or "/"})
    self.refused({"kind": "webapp", "url": "https://example.com/api-other", "allowedPathPrefix": "/api"})

  def test_model_target_retains_full_endpoint_and_case_without_dns_or_provider_requests(self):
    with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS during create")), \
         patch("requests.sessions.Session.request", side_effect=AssertionError("No target calls during create")):
      target = {"kind": "model", "adapter": "openai_compatible",
                "endpointUrl": "https://EXAMPLE.COM:443/custom/chat/completions", "model": " Case-Sensitive "}
      self.assertEqual(self.created_target(target),
                       {**target, "endpointUrl": "https://example.com/custom/chat/completions", "model": "Case-Sensitive"})
      for endpoint in ("http://example.com/chat/completions", "https://example.com/v1",
                       "https://example.com/chat/completions/", "https://example.com/chat%2Fcompletions"):
        with self.subTest(endpoint=endpoint):
          self.refused({**target, "endpointUrl": endpoint})

  def test_raw_non_ascii_authority_and_scheme_are_not_repaired_into_valid_urls(self):
    for url in ("https://\u212a.example/api", "http\u017f://example.com/api", "https://0x/api"):
      with self.subTest(url=url):
        self.refused({"kind": "webapp", "url": url, "allowedPathPrefix": "/"})

  def test_url_grammar_rejects_ambiguous_authorities_and_every_decoding_stage(self):
    bad_authorities = ("@host", "user@host", "user:password@host", "host:", "host:0", "host:080", "host:65536",
                       "127.1", "0x7f000001", "0x", "0X", "example.0x", "127.00.0.1", "256.0.0.1",
                       "example.123", "example.0xabc", "host.", "under_score", "h\u00f6st", "-host", "host-",
                       "a" * 64 + ".example", "[::1%zone]", "[::1", "::1", "[::1]:", "[::1]:00")
    bad_paths = ("/a?", "/a#", "/a//b", "/a/./b", "/a/../b", "/a/%", "/a/%GG", "/a/%FF", "/a/%C0%AF",
                 "/a/%ED%A0%80", "/a/%25252541", "/a/%2E%2e/b", "/a/%252e%252e/b", "/a/%2F/b",
                 "/a/%20", "/a/%00", "/a/%C2%85", "/a/%EF%BB%BF", "/a/%3F", "/a/%23", "/a/%5C",
                 "/a\u2003", "/a\\b", "/a\ud800")
    with patch("socket.getaddrinfo", side_effect=AssertionError("No DNS")), \
         patch("requests.sessions.Session.request", side_effect=AssertionError("No HTTP")):
      for url in ["https://" + host + "/api" for host in bad_authorities] + ["https://host" + path for path in bad_paths]:
        with self.subTest(url=url):
          self.refused({"kind": "webapp", "url": url, "allowedPathPrefix": "/"})
      for prefix in (None, [], "", "api", "//api", "/api//", "/api/.", "/api/..", "/%61pi", "/api?", "/api#",
                     "/api\\", "/api\u00a0"):
        with self.subTest(prefix=prefix):
          self.refused({"kind": "webapp", "url": "https://host/api", "allowedPathPrefix": prefix})

  def test_valid_encodings_boundaries_and_names_preserve_canonical_values(self):
    for path in ("/api/%7Eme", "/api/%257Eme", "/api/%25257Eme", "/api/%E2%82%AC"):
      with self.subTest(path=path):
        self.assertEqual(self.created_target({"kind": "webapp", "url": "https://host" + path,
                                              "allowedPathPrefix": "/api"})["url"], "https://host" + path)
    name = "\U0001f600" * 200
    result = self.create({"kind": "network", "address": "192.0.2.10"}, display_name="\u2003" + name + "\u2003")
    self.assertEqual(result["data"]["assets"][0]["displayName"], name)
    for value in ("", " ", name + "x", "\tAsset", "Asset\n", "\ufeffAsset", "Asset\x7f", "Asset\x85", "Asset\ud800",
                  [], 1):
      with self.subTest(name=value):
        self.refused({"kind": "network", "address": "192.0.2.10"}, "engagement_asset_invalid", display_name=value)
    target = {"kind": "model", "adapter": "openai_compatible", "endpointUrl": "https://host/chat/completions",
              "model": "\U0001f600" * 200}
    self.created_target(target)
    for value in ("x" * 201, "\tModel", "Model\n", "\ufeffModel", "Model\ud800", None):
      with self.subTest(model=value):
        self.refused({**target, "model": value})
    url = "https://host/" + "a" * (2048 - len("https://host/"))
    self.created_target({"kind": "webapp", "url": url, "allowedPathPrefix": "/"})
    self.refused({"kind": "webapp", "url": url + "a", "allowedPathPrefix": "/"})

  def test_port_scope_is_merged_canonical_and_bounded(self):
    # Ported from the retired tenant asset suite with the target grammar.
    network = {"kind": "network", "address": "192.0.2.10"}

    def create(ports):
      asset = {"display_name": "Edge", "target": network, "authorized_ports": ports,
               "authorized_tests": ["service_info_common"]}
      return self.service.create_engagement(**self.fields(request_id=str(uuid4()), assets=[asset], documents=[]))
    created = create(" 8080, 1-1024,1000-1030 ,22 ")
    self.assertEqual(created["data"]["assets"][0]["authorizedPorts"], "1-1030,8080")
    for ports in ("0-10", "1-65536", "20-10", "http", "1,,2", 80, ",".join(str(port * 2) for port in range(1, 66))):
      with self.subTest(ports=ports):
        before = len(self.owner.writes)
        result = create(ports)
        self.assertEqual((result.get("status_code"), result.get("error")), (400, "engagement_asset_invalid"), result)
        self.assertEqual(len(self.owner.writes), before)

  def test_network_target_accepts_a_canonical_hostname(self):
    target = {"kind": "network", "address": "scanme.nmap.org"}
    self.assertEqual(self.created_target(target), target)

  def test_noncanonical_and_secret_bearing_targets_are_rejected_before_writes(self):
    network = {"kind": "network", "address": "192.0.2.10"}
    for target in (None, [], "192.0.2.10", {}, {"kind": "network", "address": 1},
                   {"kind": "network", "address": "192.0.2.0/24"}, {"kind": "network", "address": "::1"},
                   {"kind": "network", "address": "Example.com"}, {"kind": "network", "address": "http://example.com"},
                   {"kind": "network", "address": "example.com:80"}, {"kind": "network", "address": "example.com/"},
                   {"kind": "network", "address": "example.com."}, {"kind": "network", "address": "a..b"},
                   {"kind": "network", "address": "127.1"}, {"kind": "network", "address": "010.0.0.1"},
                   {"kind": "network", "address": "user@example.com"}, {"kind": "network", "address": "b\u00fccher.de"},
                   {"kind": "network", "address": ""}, {**network, "port": 443},
                   {**network, "credential_ref": "secret"}, {**network, "headers": {}},
                   {"kind": "webapp", "url": "https://0177.0.0.1/api", "allowedPathPrefix": "/"},
                   {"kind": "webapp", "url": "https://example.test:0443/api", "allowedPathPrefix": "/"},
                   {"kind": "webapp", "url": "https://host/api/%253foutside", "allowedPathPrefix": "/api"},
                   {"kind": "webapp", "url": "https://host/api/%255coutside", "allowedPathPrefix": "/api"},
                   {"kind": "webapp", "url": "https://host/api/%2e%2e/x", "allowedPathPrefix": "/api"},
                   {"kind": "api", "url": "https://host"}):
      with self.subTest(target=target):
        self.refused(target)


if __name__ == "__main__":
  unittest.main()
