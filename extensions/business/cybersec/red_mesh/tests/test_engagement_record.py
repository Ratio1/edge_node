"""RM-095 phase 2, RM-107: engagement values, the hashed shape and the stored-record validator."""
import copy
import json
import unittest

from extensions.business.cybersec.red_mesh.constants import FEATURE_CATALOG
from extensions.business.cybersec.red_mesh.services.scan_strategy import SCAN_STRATEGIES
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import CstoreTenantAdministrationStore
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.engagements import (
  EngagementInvalid, engagement_hash, feature_ids_for_kind, normalize_context, normalize_document_labels,
  normalize_engagement_assets, normalize_instant, normalize_roe, normalize_run_modes, normalize_window,
  validate_engagement)
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from .test_tenant_administration import FakeAdministrationStore

TENANT = "tenant-1"
REQUEST = "5b8f7c1e-2a1d-4d4b-9b1e-0c8f6a4d2e10"
ENGAGEMENT = "en_" + REQUEST
NETWORK_TARGET = {"kind": "network", "address": "192.0.2.10"}
WEBAPP_TARGET = {"kind": "webapp", "url": "https://app.example.com/login", "allowedPathPrefix": "/"}
MODEL_TARGET = {"kind": "model", "adapter": "openai_compatible",
                "endpointUrl": "https://llm.example.com/v1/chat/completions", "model": "example-model"}
SHA_A, SHA_B, SHA_C = "a" * 64, "b" * 64, "c" * 64


def doc_ref(sha256=SHA_A, ref="doc-1", **extra):
  return {"store": "fake", "ref": ref, "sha256": sha256, "filename": "roe.pdf",
          "mime": "application/pdf", "size_bytes": 1024, "uploaded_at": "2026-09-28T09:00:00Z",
          "uploaded_by": "creator", **extra}


def document(index, sha256, kind="agreement", title="Rules of engagement", comment="", **extra):
  return {"document_id": "ed_%d" % index, "kind": kind, "title": title, "comment": comment,
          **doc_ref(sha256, "doc-%d" % index), **extra}


def record(**changes):
  row = {
    "tenant_id": TENANT, "engagement_id": ENGAGEMENT, "request_id": REQUEST,
    "display_name": "Q4 external test", "allowed_run_modes": ["single_pass"],
    "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-10-31T00:00:00Z",
    "contract_sha256": SHA_C,
    "documents": [document(1, SHA_A),
                  document(2, SHA_B, "third_party_consent", "Hosting consent", "AWS case 123")],
    "roe": normalize_roe({}), "context": normalize_context({"client_name": "Example"}),
    "assets": [
      {"engagement_asset_id": "ea_1", "display_name": "Edge gateway", "kind": "network",
       "target": NETWORK_TARGET, "target_digest": canonical_digest(NETWORK_TARGET),
       "authorized_ports": "22,443", "authorized_scan_modes": ["connect"],
       "authorized_tests": ["service_info_common"]},
      {"engagement_asset_id": "ea_2", "display_name": "Customer portal", "kind": "webapp",
       "target": WEBAPP_TARGET, "target_digest": canonical_digest(WEBAPP_TARGET),
       "authorized_tests": ["graybox"]},
    ],
    "active": True, "created_by": "creator", "created_at": "2026-09-28T10:00:00+00:00",
    "create_intent_digest": "f" * 64,
  }
  row.update(changes)
  row["engagement_hash"] = engagement_hash(row)
  return row


class TestEngagementValues(unittest.TestCase):
  def test_feature_ids_follow_the_scan_strategy_categories(self):
    for kind, strategy in (("network", SCAN_STRATEGIES["network"]), ("webapp", SCAN_STRATEGIES["webapp"])):
      self.assertEqual(feature_ids_for_kind(kind), tuple(
        item["id"] for item in FEATURE_CATALOG if item["category"] in strategy.catalog_categories))
    self.assertIn("service_info_common", feature_ids_for_kind("network"))
    self.assertEqual(feature_ids_for_kind("webapp"), ("graybox",))
    # A model asset's tests are the Model Testing question sets.
    self.assertEqual(feature_ids_for_kind("model"), ("cbrn_safety_v1", "prompt_injection_v1"))

  def test_roe_is_the_three_enforced_flags_with_safe_defaults(self):
    self.assertEqual(normalize_roe(None), {"authenticated_action": False, "stateful_probes_allowed": False,
                                           "ics_safe_mode_required": True})
    self.assertTrue(normalize_roe({"authenticated_action": True})["authenticated_action"])
    for bad in ({"authenticated_action": "false"}, {"dos_allowed": False}, ["x"], {"ics_safe_mode_required": 0}):
      with self.assertRaises(EngagementInvalid) as caught:
        normalize_roe(bad)
      self.assertEqual(caught.exception.code, "roe_invalid")

  def test_context_is_strict_and_never_coerces(self):
    empty = normalize_context({})
    self.assertEqual(empty, normalize_context(None))
    self.assertEqual(empty["methodology"], "PTES + OWASP WSTG + CVSS v3.1")
    self.assertIsNone(empty["point_of_contact"])
    full = normalize_context({"client_name": " Example ", "asset_exposure": "internal",
                              "point_of_contact": {"name": "Ana", "email": "ana@example.com"}})
    self.assertEqual(full["client_name"], "Example")
    self.assertEqual(full["point_of_contact"], {"name": "Ana", "email": "ana@example.com", "phone": "", "role": ""})
    for bad in ({"client_name": None}, {"client_name": 5}, {"unknown": "x"}, {"asset_exposure": "moon"},
                {"client_name": "x" * 501}, {"point_of_contact": {"pager": "1"}}, "text"):
      with self.assertRaises(EngagementInvalid) as caught:
        normalize_context(bad)
      self.assertEqual(caught.exception.code, "context_invalid")

  def test_window_has_one_canonical_form(self):
    self.assertEqual(normalize_instant("2026-10-01T00:00:00Z"), "2026-10-01T00:00:00Z")
    self.assertEqual(normalize_instant("2026-10-01T00:00:00.123+00:00"), "2026-10-01T00:00:00Z")
    for bad in ("2026-10-01", "2026-10-01T00:00:00+02:00", "2026-10-01T00:00:00", 5, "2026-13-01T00:00:00Z"):
      with self.assertRaises(EngagementInvalid):
        normalize_instant(bad)
    with self.assertRaises(EngagementInvalid):
      normalize_window("2026-10-02T00:00:00Z", "2026-10-01T00:00:00Z")
    with self.assertRaises(EngagementInvalid):
      normalize_window("2026-10-01T00:00:00Z", "2026-10-01T00:00:00+00:00")

  def test_run_modes_are_a_sorted_non_empty_subset(self):
    self.assertEqual(normalize_run_modes(["single_pass", "continuous"]), ["continuous", "single_pass"])
    self.assertEqual(normalize_run_modes(["single_pass"]), ["single_pass"])
    for bad in ([], None, "continuous", ["continuous", "continuous"], ["SINGLEPASS"], ["point-in-time"]):
      with self.assertRaises(EngagementInvalid) as caught:
        normalize_run_modes(bad)
      self.assertEqual(caught.exception.code, "run_modes_invalid")

  def test_document_labels_are_a_kind_a_title_and_a_bounded_comment(self):
    self.assertEqual(normalize_document_labels("agreement", " RoE v2 ", " signed \n"),
                     {"kind": "agreement", "title": "RoE v2", "comment": "signed"})
    self.assertEqual(normalize_document_labels("other", "Scope email", "")["comment"], "")
    for args in (("roe", "RoE", ""), ("agreement", "", ""), ("agreement", "x" * 201, ""),
                 ("agreement", "RoE", "x" * 2001), ("agreement", "RoE", None), ("agreement", None, ""),
                 ("agreement", "RoE", "bell\x07"), ("agreement", "RoE", "c1\x85"), ("agreement", "RoE", "\ufeffbom")):
      with self.assertRaises(EngagementInvalid) as caught:
        normalize_document_labels(*args)
      self.assertEqual(caught.exception.code, "document_invalid")


class TestEngagementAssets(unittest.TestCase):
  """RM-107: the engagement defines its targets; ids are positional, the kind is the target's."""

  def test_assets_are_numbered_in_the_order_given_with_their_target_and_digest(self):
    assets = normalize_engagement_assets([
      {"display_name": " Edge gateway ", "target": NETWORK_TARGET, "authorized_ports": "443, 22",
       "authorized_tests": ["service_info_common"]},
      {"display_name": "Portal", "target": WEBAPP_TARGET, "authorized_tests": ["graybox"]},
      {"display_name": "Support bot", "target": MODEL_TARGET, "authorized_tests": ["prompt_injection_v1"]},
    ])
    self.assertEqual(assets[0], {
      "engagement_asset_id": "ea_1", "display_name": "Edge gateway", "kind": "network",
      "target": NETWORK_TARGET, "target_digest": canonical_digest(NETWORK_TARGET),
      "authorized_ports": "22,443", "authorized_scan_modes": ["connect"],
      "authorized_tests": ["service_info_common"]})
    self.assertEqual([(entry["engagement_asset_id"], entry["kind"]) for entry in assets],
                     [("ea_1", "network"), ("ea_2", "webapp"), ("ea_3", "model")])
    self.assertEqual(assets[2]["authorized_tests"], ["prompt_injection_v1"])
    self.assertNotIn("authorized_ports", assets[2])

  def test_ten_or_more_assets_keep_their_numeric_order(self):
    many = [{"display_name": "Host %d" % index, "target": {"kind": "network", "address": "192.0.2.%d" % index},
             "authorized_ports": "443", "authorized_tests": ["service_info_common"]} for index in range(1, 12)]
    assets = normalize_engagement_assets(many)
    self.assertEqual([entry["engagement_asset_id"] for entry in assets], ["ea_%d" % n for n in range(1, 12)])
    validate_engagement(record(assets=assets), (TENANT, ENGAGEMENT))

  def test_refusals(self):
    network = {"display_name": "Edge", "target": NETWORK_TARGET, "authorized_ports": "443",
               "authorized_tests": ["service_info_common"]}
    cases = {
      "engagement_asset_invalid": ([], None, [network, dict(network, display_name="Same host")],
                                   [dict(network, asset_id="as_x")], [dict(network, display_name="")],
                                   [dict(network, display_name="x" * 201)],
                                   [{"display_name": "Portal", "target": WEBAPP_TARGET, "authorized_ports": "80",
                                     "authorized_tests": ["graybox"]}],
                                   [dict(network, authorized_scan_modes=["udp"])],
                                   [dict(network, authorized_ports="0-70000")]),
      "asset_target_invalid": ([dict(network, target={"kind": "network", "address": "not a host!"})],
                               [dict(network, target={"kind": "printer"})], [dict(network, target=None)]),
      "ports_required": ([{key: value for key, value in network.items() if key != "authorized_ports"}],),
      "tests_invalid": ([dict(network, authorized_tests=[])], [dict(network, authorized_tests=["graybox"])],
                        [{"display_name": "Bot", "target": MODEL_TARGET, "authorized_tests": ["graybox"]}]),
    }
    for code, values in cases.items():
      for value in values:
        with self.subTest(code=code, value=value), self.assertRaises(EngagementInvalid) as caught:
          normalize_engagement_assets(value)
        self.assertEqual(caught.exception.code, code)


class TestEngagementHash(unittest.TestCase):
  def test_same_inputs_same_hash(self):
    self.assertEqual(record()["engagement_hash"], record()["engagement_hash"])
    self.assertRegex(record()["engagement_hash"], r"^[a-f0-9]{64}$")

  def test_every_hashed_input_changes_the_hash(self):
    base = record()["engagement_hash"]
    changes = {
      "tenant_id": "tenant-2", "engagement_id": "en_" + "1" * 8 + "-1111-4111-8111-" + "1" * 12,
      "display_name": "Other", "allowed_run_modes": ["continuous", "single_pass"],
      "valid_until": "2026-11-30T00:00:00Z", "contract_sha256": "9" * 64,
      "documents": record()["documents"][:1],
      "supersedes": "en_" + "2" * 8 + "-2222-4222-8222-" + "2" * 12,
      "roe": normalize_roe({"authenticated_action": True}),
      "context": normalize_context({"client_name": "Other"}),
      "assets": record()["assets"][:1],
    }
    for field, value in changes.items():
      with self.subTest(field=field):
        self.assertNotEqual(record(**{field: value})["engagement_hash"], base)
    for field, value in (("authorized_scan_modes", ["connect", "syn"]), ("display_name", "Edge 2"),
                         ("target", {"kind": "network", "address": "192.0.2.11"})):
      with self.subTest(asset=field):
        scoped = copy.deepcopy(record()["assets"])
        scoped[0][field] = value
        self.assertNotEqual(record(assets=scoped)["engagement_hash"], base)
    for label, value in (("kind", "other"), ("sha256", SHA_C), ("title", "SOW"), ("comment", "annex 2")):
      with self.subTest(document=label):
        documents = copy.deepcopy(record()["documents"])
        documents[0][label] = value
        self.assertNotEqual(record(documents=documents)["engagement_hash"], base)

  def test_document_references_and_bookkeeping_do_not_enter_the_hash(self):
    base = record()["engagement_hash"]
    moved = copy.deepcopy(record()["documents"])
    moved[0].update(ref="doc-99", uploaded_at="2026-09-29T00:00:00Z", filename="other.pdf")
    self.assertEqual(record(documents=moved)["engagement_hash"], base)
    # The same documents in another order are the same engagement (ids follow the new order).
    swapped = [dict(item, document_id="ed_%d" % (index + 1))
               for index, item in enumerate(reversed(record()["documents"]))]
    self.assertEqual(record(documents=swapped)["engagement_hash"], base)
    self.assertEqual(record(created_at="2026-09-29T00:00:00+00:00", created_by="other")["engagement_hash"], base)


class TestEngagementValidator(unittest.TestCase):
  def test_a_created_and_a_revoked_record_are_valid(self):
    validate_engagement(record(), (TENANT, ENGAGEMENT))
    validate_engagement(record(active=False, revoked_by="creator", revoked_at="2026-10-02T00:00:00+00:00",
                               revoke_reason="Scope withdrawn"), (TENANT, ENGAGEMENT))

  def test_an_engagement_without_documents_is_valid(self):
    validate_engagement(record(documents=[]), (TENANT, ENGAGEMENT))

  def test_unknown_fields_are_kept(self):
    validate_engagement({**record(), "signature": {"future": True}}, (TENANT, ENGAGEMENT))

  def test_a_later_catalog_context_or_document_change_does_not_make_a_record_unreadable(self):
    # Immutable and hashed: live-code vocabularies are checked at creation, not on every read.
    retired = record()
    retired["assets"][0]["authorized_tests"] = ["retired_feature"]
    retired["context"] = {**retired["context"], "added_later": ""}
    retired["documents"][0] = {**retired["documents"][0], "signature": "0x1"}
    retired["engagement_hash"] = engagement_hash(retired)
    validate_engagement(retired, (TENANT, ENGAGEMENT))

  def test_tampered_records_are_refused(self):
    unsorted = record()
    unsorted["assets"] = list(reversed(unsorted["assets"]))
    unsorted["engagement_hash"] = engagement_hash(unsorted)
    wrong_digest = record()
    wrong_digest["assets"][0]["target_digest"] = "d" * 64
    wrong_kind = record()
    wrong_kind["assets"][1]["kind"] = "network"
    no_name = record()
    del no_name["assets"][0]["display_name"]
    same_target = record()
    same_target["assets"][1] = {**same_target["assets"][0], "engagement_asset_id": "ea_2"}
    phase_one = record()
    phase_one["assets"][0] = {"asset_id": "as_0a7e3c52-9d0e-4f6f-8a3c-5f2d1b9e7c41",
                              **{key: value for key, value in phase_one["assets"][0].items()
                                 if key not in ("engagement_asset_id", "display_name", "target")}}
    webapp_ports = record()
    webapp_ports["assets"][1]["authorized_ports"] = "80"
    network_without_ports = record()
    network_without_ports["assets"][0]["authorized_ports"] = None
    unsorted_tests = record()
    unsorted_tests["assets"][0]["authorized_tests"] = ["z_test", "a_test"]
    cases = {
      "hash": {**record(), "engagement_hash": "0" * 64},
      "ids": record(engagement_id="en_" + "3" * 8 + "-3333-4333-8333-" + "3" * 12),
      "assets out of order": unsorted, "target digest": wrong_digest, "kind not the target's": wrong_kind,
      "asset without a name": no_name, "same target twice": same_target, "tenant asset reference": phase_one,
      "revoke fields on an active record": record(revoked_by="creator"),
      "revoked without reason": record(active=False, revoked_by="creator", revoked_at="2026-10-02T00:00:00+00:00"),
      "window not canonical": record(valid_from="2026-10-01T00:00:00+00:00"),
      "self supersedes": record(supersedes=ENGAGEMENT),
      "contract ref instead of hash": record(contract_sha256={"ref": "doc-1"}),
      "no contract": record(contract_sha256=None),
      "run modes unsorted": record(allowed_run_modes=["single_pass", "continuous"]),
      "no run mode": record(allowed_run_modes=[]),
      "document ids out of order": record(documents=[document(2, SHA_A)]),
      "document kind": record(documents=[document(1, SHA_A, kind="roe")]),
      "document without title": record(documents=[document(1, SHA_A, title="")]),
      "same file twice": record(documents=[document(1, SHA_A), document(2, SHA_A, title="Again")]),
      "21 documents": record(documents=[document(index + 1, "%064x" % index) for index in range(21)]),
      "v1 kind": {**record(), "engagement_kind": "continuous"},
      "v1 documents": {**record(), "roe_document": doc_ref(), "authorization_document": doc_ref(SHA_B)},
      "webapp ports": webapp_ports, "network without ports": network_without_ports,
      "tests unsorted": unsorted_tests,
      "context not an object": record(context="Example"),
    }
    for name, row in cases.items():
      with self.subTest(name), self.assertRaises((ValueError, TypeError, KeyError)):
        validate_engagement(row, (TENANT, ENGAGEMENT))


class TestEngagementStoreKind(unittest.TestCase):
  def setUp(self):
    self.owner = FakeAdministrationStore()
    self.store = CstoreTenantAdministrationStore(self.owner, "deployment")

  def test_round_trip_and_listing(self):
    self.store.put("engagement", TENANT, ENGAGEMENT, record=record())
    stored = self.store.get("engagement", TENANT, ENGAGEMENT)
    self.assertEqual(stored["engagement_hash"], record()["engagement_hash"])
    self.assertEqual([row["engagement_id"] for row in self.store.list_engagements(TENANT)], [ENGAGEMENT])
    self.assertEqual(self.store.list_engagements("tenant-2"), [])

  def test_a_corrupt_stored_record_is_a_store_error(self):
    with self.assertRaises(TenantStoreError):
      self.store.put("engagement", TENANT, ENGAGEMENT, record={**record(), "engagement_hash": "0" * 64})
    hkey = '["redmesh","tenancy",1,"deployment"]'
    key = json.dumps(["engagement", "deployment", TENANT, ENGAGEMENT], separators=(",", ":"))
    self.owner.data[(hkey, key)] = {**record(), "schemaVersion": 1, "namespace": "deployment",
                                                 "kind": "engagement", "ids": [TENANT, ENGAGEMENT], "roe": {}}
    with self.assertRaises(TenantStoreError):
      self.store.get("engagement", TENANT, ENGAGEMENT)


if __name__ == "__main__":
  unittest.main()
