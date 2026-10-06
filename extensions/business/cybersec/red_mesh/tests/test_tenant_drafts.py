"""RM-109 phase 2: tenant drafts through the real plugin endpoints, administration service and adapters."""
import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import (
  CstoreTenantAdministrationStore,
)
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from .contract_fixture import CONTRACT_PDF, CONTRACT_SHA256, FakeDocumentStore, contract_b64
from .test_tenant_administration import FakeAdministrationStore

TENANCY_HKEY = '["redmesh","tenancy",1,"deployment"]'
PNG = b"\x89PNG\r\n\x1a\nnot a contract"
SCHEDULE_PDF = b"%PDF-1.7\n%fixture data handling schedule\n%%EOF\n"
LEGAL = {"name": "Example Holdings SRL", "registration_id": "RO12345678",
         "signer_name": "Ana Pop", "signer_role": "Director"}
KINDS = ("contract", "framework_agreement", "data_handling")


def ok(case, result):
  case.assertTrue(result.get("success"), result)
  case.assertEqual(result["status_code"], 200, result)
  return result["data"]


def refused(case, result, status_code, error):
  case.assertFalse(result.get("success"), result)
  case.assertEqual((result["status_code"], result["error"]), (status_code, error), result)


class _DraftCase(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    env = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    env.start()
    self.addCleanup(env.stop)
    self.store = FakeAdministrationStore()
    self.store.account("other-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.store.account("pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    # Not a valid account record (a Super-Tenant Admin is always full-portfolio): the caller is unknown.
    self.store.account("scoped-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": "tn_" + str(uuid4())}])
    self.documents = FakeDocumentStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.P = lambda *args, **kwargs: None
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.store, name))
    self.plugin._document_store = lambda: self.documents
    self.events = []
    self.plugin._log_audit_event = lambda event, details: self.events.append((event, details))
    self.repo = CstoreTenantAdministrationStore(self.store, "deployment")
    self.actor = {"account_id": "creator"}

  # -- helpers ----------------------------------------------------------------------------------

  def create(self, display_name="Acme", compliance_types=("nis2",), request_id=None):
    request_id = request_id or str(uuid4())
    return ok(self, self.plugin.create_tenant_draft(self.actor, request_id, display_name, list(compliance_types)))

  def update(self, draft_id, changes, actor=None):
    return self.plugin.update_tenant_draft(actor or self.actor, draft_id, changes)

  def upload(self, draft_id, kind="contract", raw=CONTRACT_PDF, filename="signed.pdf", actor=None):
    return self.plugin.upload_tenant_draft_document(actor or self.actor, draft_id, kind, filename,
                                                    base64.b64encode(raw).decode("ascii"))

  def stored(self, draft_id):
    return self.repo.get("tenant_draft", draft_id)

  def complete_fields(self, draft_id):
    return ok(self, self.update(draft_id, {"display_name": "Acme SRL", "domain_id": "acme",
                                           "initial_admin_id": "Acme.Admin", "legal": dict(LEGAL)}))

  def set_activation(self, draft_id):
    row = self.stored(draft_id)
    row["activation"] = {"actor_id": "creator", "request_id": str(uuid4()),
                         "started_at": "2026-10-07T00:00:00+00:00"}
    self.repo.put("tenant_draft", draft_id, record=row)


class TestDraftRecord(_DraftCase):
  def test_a_partial_draft_is_saved_and_read_back(self):
    request_id = str(uuid4())
    draft = self.create(" Acme ", ["nis2", "cra"], request_id=request_id)
    self.assertEqual(draft["draft_id"], "td_" + request_id)
    self.assertEqual(draft["display_name"], "Acme")
    self.assertEqual(draft["compliance_types"], ["cra", "nis2"])
    self.assertEqual((draft["domain_id"], draft["initial_admin_id"]), ("", ""))
    self.assertEqual(draft["legal"], {key: "" for key in LEGAL})
    self.assertEqual(draft["items"]["contract"], {
      "state": "missing", "document": None, "covers": [], "effective_from": None,
      "effective_until": None, "basis": "Contractual obligation", "covered_by": None})
    self.assertEqual(draft["items"]["framework_agreement"]["covers"], ["framework_agreement"])
    self.assertEqual(draft["items"]["data_handling"]["covers"], ["data_handling"])
    self.assertEqual(draft["applicability"], {"framework_agreement": {"decision": "unknown", "reason": None},
                                              "data_handling": {"decision": "unknown", "reason": None}})
    self.assertIsNone(draft["activation"])
    self.assertIsNone(draft["last_release"])
    self.assertEqual((draft["created_by"], draft["updated_by"]), ("creator", "creator"))
    self.assertFalse(draft["completeness"]["complete"])
    self.assertNotIn("schemaVersion", draft)
    self.assertNotIn("namespace", draft)
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft["draft_id"])), draft)

    changed = ok(self, self.update(draft["draft_id"], {
      "domain_id": "acme", "legal": {"name": " Acme SRL "},
      "items": {"framework_agreement": {"effective_from": "2026-11-01", "effective_until": None}},
      "applicability": {"data_handling": {"decision": "not_required", "reason": "No personal data"}}}))
    self.assertEqual(changed["domain_id"], "acme")
    self.assertEqual(changed["legal"], {"name": "Acme SRL", "registration_id": "", "signer_name": "",
                                        "signer_role": ""})
    self.assertEqual(changed["items"]["framework_agreement"]["effective_from"], "2026-11-01")
    self.assertEqual(changed["applicability"]["data_handling"],
                     {"decision": "not_required", "reason": "No personal data"})
    self.assertEqual(changed["display_name"], "Acme")
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft["draft_id"])), changed)
    # Another full-portfolio Super-Tenant Admin may continue the draft.
    other = ok(self, self.update(draft["draft_id"], {"initial_admin_id": " Acme.Admin "},
                                 actor={"account_id": "other-sta"}))
    self.assertEqual((other["initial_admin_id"], other["updated_by"]), ("acme.admin", "other-sta"))
    self.assertEqual(other["created_by"], "creator")

  def test_a_create_replay_answers_the_existing_draft(self):
    request_id = str(uuid4())
    first = self.create("Acme", request_id=request_id)
    writes = len(self.store.writes)
    again = ok(self, self.plugin.create_tenant_draft(self.actor, request_id, "Other", ["cra"]))
    self.assertEqual(again, first)
    self.assertEqual(len(self.store.writes), writes)

  def test_an_empty_draft_is_allowed(self):
    draft = self.create("", ())
    self.assertEqual((draft["display_name"], draft["compliance_types"]), ("", []))

  def test_the_list_counts_done_items(self):
    first = self.create("First")
    second = self.create("Second", ["ai_act"])
    ok(self, self.upload(second["draft_id"]))
    ok(self, self.update(second["draft_id"], {"items": {"contract": {"covers": ["data_handling"]}}}))
    rows = ok(self, self.plugin.list_tenant_drafts(self.actor))
    by_id = {row["draft_id"]: row for row in rows}
    self.assertEqual(set(by_id), {first["draft_id"], second["draft_id"]})
    self.assertEqual(set(by_id[first["draft_id"]]), {"draft_id", "display_name", "compliance_types", "created_at",
                                                     "updated_at", "items_done", "items_total", "activation"})
    self.assertEqual((by_id[first["draft_id"]]["items_done"], by_id[first["draft_id"]]["items_total"]), (0, 3))
    # The signed contract and the data handling item it covers.
    self.assertEqual(by_id[second["draft_id"]]["items_done"], 2)
    self.assertEqual(by_id[second["draft_id"]]["compliance_types"], ["ai_act"])

  def test_a_draft_id_is_never_a_tenant_and_tenants_are_never_drafts(self):
    draft = self.create()
    self.assertEqual(self.plugin.get_tenant(self.actor, draft["draft_id"])["status_code"], 404)
    self.assertEqual(ok(self, self.plugin.list_tenants(self.actor)), [])


class TestDraftRoles(_DraftCase):
  def test_every_operation_refuses_anyone_but_a_full_portfolio_super_tenant_admin(self):
    draft = self.create()
    ok(self, self.upload(draft["draft_id"]))
    draft_id = draft["draft_id"]
    calls = {
      "create": lambda actor: self.plugin.create_tenant_draft(actor, str(uuid4()), "X", ["nis2"]),
      "update": lambda actor: self.plugin.update_tenant_draft(actor, draft_id, {"display_name": "Y"}),
      "get": lambda actor: self.plugin.get_tenant_draft(actor, draft_id),
      "list": lambda actor: self.plugin.list_tenant_drafts(actor),
      "delete": lambda actor: self.plugin.delete_tenant_draft(actor, draft_id),
      "upload": lambda actor: self.plugin.upload_tenant_draft_document(
        actor, draft_id, "data_handling", "s.pdf", contract_b64(SCHEDULE_PDF)),
      "download": lambda actor: self.plugin.download_tenant_draft_document(actor, draft_id, "contract"),
    }
    data, puts, deleted = copy.deepcopy(self.store.data), len(self.documents.puts), list(self.documents.deleted)
    actors = {"tenant account": {"account_id": "initial"}, "super pentester": {"account_id": "pentester"},
              "tenant-scoped STA": {"account_id": "scoped-sta"}, "unknown": {"account_id": "nobody"},
              "no actor": None}
    for label, actor in actors.items():
      for name, call in calls.items():
        with self.subTest(actor=label, operation=name):
          result = call(actor)
          self.assertFalse(result["success"], result)
          if label in ("tenant account", "super pentester"):
            self.assertEqual((result["status_code"], result["error"]), (403, "forbidden"))
          else:
            self.assertEqual(result["status_code"], 404)
          self.assertNotIn("data", result)
    self.assertEqual(self.store.data, data)
    self.assertEqual((len(self.documents.puts), self.documents.deleted), (puts, deleted))
    self.assertEqual(self.events, [])

  def test_no_namespace_means_unavailable_before_any_storage_access(self):
    self.plugin.cfg_tenancy_namespace = None
    for name in ("create_tenant_draft", "update_tenant_draft", "get_tenant_draft", "list_tenant_drafts",
                 "delete_tenant_draft", "upload_tenant_draft_document", "download_tenant_draft_document"):
      with self.subTest(name):
        self.assertEqual(getattr(self.Plugin, name).__http_method__, "post")
        self.assertEqual(getattr(self.plugin, name)(actor=self.actor)["status_code"], 503)
    self.assertEqual(self.store.writes, [])
    self.assertEqual(self.documents.puts, [])


class TestDraftValidation(_DraftCase):
  def assert_refused_without_writes(self, call, status_code, error):
    writes, puts = len(self.store.writes), len(self.documents.puts)
    refused(self, call(), status_code, error)
    self.assertEqual((len(self.store.writes), len(self.documents.puts)), (writes, puts))

  def test_create_refuses_malformed_input(self):
    for request_id in ("", "not-a-uuid", str(uuid4()).upper(), None, 7):
      with self.subTest(request_id=request_id):
        self.assert_refused_without_writes(
          lambda: self.plugin.create_tenant_draft(self.actor, request_id, "Acme", ["nis2"]), 400, "invalid_request")
    for display_name, types in (("x" * 121, ["nis2"]), (7, ["nis2"]), ("A\x00B", ["nis2"]),
                                ("Acme", ["gdpr"]), ("Acme", "nis2"), ("Acme", ["nis2", "nis2"]), ("Acme", None)):
      with self.subTest(display_name=display_name, types=types):
        self.assert_refused_without_writes(
          lambda: self.plugin.create_tenant_draft(self.actor, str(uuid4()), display_name, types),
          400, "invalid_request")

  def test_draft_ids_are_checked_before_any_read(self):
    for draft_id in ("", "tn_" + str(uuid4()), "td_not-a-uuid", "td_" + str(uuid4()).upper(), None, 7):
      for call in (lambda: self.plugin.get_tenant_draft(self.actor, draft_id),
                   lambda: self.update(draft_id, {"display_name": "X"}),
                   lambda: self.plugin.delete_tenant_draft(self.actor, draft_id),
                   lambda: self.upload(draft_id),
                   lambda: self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract")):
        with self.subTest(draft_id=draft_id):
          self.assert_refused_without_writes(call, 400, "invalid_request")

  def test_an_absent_draft_is_not_found(self):
    draft_id = "td_" + str(uuid4())
    for call in (lambda: self.plugin.get_tenant_draft(self.actor, draft_id),
                 lambda: self.update(draft_id, {"display_name": "X"}),
                 lambda: self.plugin.delete_tenant_draft(self.actor, draft_id),
                 lambda: self.upload(draft_id),
                 lambda: self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract")):
      with self.subTest(call=call):
        self.assert_refused_without_writes(call, 404, "not_found")

  def test_update_refuses_malformed_changes(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF))
    cases = {
      "not a dict": None,
      "unknown key": {"tenant_id": "tn_x"},
      "long name": {"display_name": "x" * 121},
      "bad admin": {"initial_admin_id": "A"},
      "legal key": {"legal": {"vat": "1"}},
      "legal long": {"legal": {"name": "x" * 201}},
      "legal type": {"legal": "Acme"},
      "compliance type": {"compliance_types": ["gdpr"]},
      "item kind": {"items": {"scope_of_work": {"state": "missing"}}},
      "item field": {"items": {"contract": {"document": None}}},
      "item state": {"items": {"contract": {"state": "done"}}},
      "set signed": {"items": {"framework_agreement": {"state": "signed"}}},
      "awaiting with a file": {"items": {"data_handling": {"state": "awaiting_signature"}}},
      "covers unknown": {"items": {"contract": {"covers": ["gdpr_dpa"]}}},
      "contract covers itself": {"items": {"contract": {"covers": ["contract"]}}},
      "own record dropped": {"items": {"framework_agreement": {"covers": ["data_handling"]}}},
      "schedule covers agreement": {"items": {"data_handling": {"covers": ["data_handling", "framework_agreement"]}}},
      "covers duplicate": {"items": {"contract": {"covers": ["data_handling", "data_handling"]}}},
      "covers not a list": {"items": {"contract": {"covers": "data_handling"}}},
      "bad date": {"items": {"contract": {"effective_from": "2026-13-01"}}},
      "datetime": {"items": {"contract": {"effective_until": "2026-11-01T00:00:00"}}},
      "record key contract": {"applicability": {"contract": {"decision": "required", "reason": None}}},
      "record key engagement": {"applicability": {"scope_of_work": {"decision": "required", "reason": None}}},
      "decision": {"applicability": {"data_handling": {"decision": "maybe", "reason": None}}},
      "not required without reason": {"applicability": {"data_handling": {"decision": "not_required", "reason": None}}},
      "not required blank reason": {"applicability": {"data_handling": {"decision": "not_required", "reason": " "}}},
      "reason long": {"applicability": {"data_handling": {"decision": "required", "reason": "x" * 501}}},
      "applicability shape": {"applicability": {"data_handling": "required"}},
    }
    for label, changes in cases.items():
      with self.subTest(label):
        self.assert_refused_without_writes(lambda: self.update(draft_id, changes), 400, "invalid_request")
    self.assert_refused_without_writes(lambda: self.update(draft_id, {"domain_id": "Not A Slug"}), 400, "invalid_domain")

  def test_update_accepts_emptiness_and_engagement_records_in_covers(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.update(draft_id, {"display_name": "Acme", "domain_id": "acme"}))
    draft = ok(self, self.update(draft_id, {
      "display_name": "", "domain_id": "", "compliance_types": [],
      "items": {"contract": {"covers": ["rules_of_engagement", "data_handling", "scope_of_work"]},
                "framework_agreement": {"covers": ["framework_agreement", "data_handling"]}}}))
    self.assertEqual((draft["display_name"], draft["domain_id"], draft["compliance_types"]), ("", "", []))
    # Stored in the vocabulary's order, whatever order they were sent in.
    self.assertEqual(draft["items"]["contract"]["covers"], ["data_handling", "scope_of_work", "rules_of_engagement"])

  def test_awaiting_signature_and_missing_transitions(self):
    draft_id = self.create()["draft_id"]
    draft = ok(self, self.update(draft_id, {"items": {"framework_agreement": {"state": "awaiting_signature"}}}))
    self.assertEqual(draft["items"]["framework_agreement"]["state"], "awaiting_signature")
    draft = ok(self, self.update(draft_id, {"items": {"framework_agreement": {"state": "missing"}}}))
    self.assertEqual(draft["items"]["framework_agreement"]["state"], "missing")

  def test_an_unchanged_update_does_not_write(self):
    draft_id = self.create()["draft_id"]
    writes = len(self.store.writes)
    ok(self, self.update(draft_id, {"display_name": "Acme"}))
    ok(self, self.update(draft_id, {}))
    self.assertEqual(len(self.store.writes), writes)


class TestDraftCompleteness(_DraftCase):
  def completeness(self, draft_id):
    return ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))["completeness"]

  def test_a_new_draft_lists_every_gap(self):
    draft = self.create("", ())
    self.assertEqual(draft["completeness"], {"complete": False, "missing": [
      "field:display_name", "field:domain_id", "field:initial_admin_id", "field:legal.name",
      "field:legal.registration_id", "field:legal.signer_name", "field:legal.signer_role",
      "field:compliance_types", "item:contract", "record:framework_agreement", "record:data_handling"]})

  def test_unknown_and_required_records_are_gaps_until_covered_or_not_required(self):
    draft_id = self.create()["draft_id"]
    self.complete_fields(draft_id)
    ok(self, self.upload(draft_id))
    self.assertEqual(self.completeness(draft_id)["missing"], ["record:framework_agreement", "record:data_handling"])
    ok(self, self.update(draft_id, {"applicability": {"framework_agreement": {"decision": "required", "reason": None}}}))
    self.assertEqual(self.completeness(draft_id)["missing"], ["record:framework_agreement", "record:data_handling"])
    ok(self, self.update(draft_id, {"applicability": {
      "framework_agreement": {"decision": "not_required", "reason": "Combined in the contract"},
      "data_handling": {"decision": "not_required", "reason": "No data leaves the client"}}}))
    self.assertEqual(self.completeness(draft_id), {"complete": True, "missing": []})

  def test_a_covered_record_is_never_a_gap_whatever_its_decision(self):
    draft_id = self.create()["draft_id"]
    self.complete_fields(draft_id)
    ok(self, self.update(draft_id, {
      "items": {"contract": {"covers": ["framework_agreement", "data_handling"]}},
      "applicability": {"framework_agreement": {"decision": "required", "reason": None}}}))
    # Coverage counts only while the covering item is signed.
    self.assertEqual(self.completeness(draft_id)["missing"],
                     ["item:contract", "record:framework_agreement", "record:data_handling"])
    draft = ok(self, self.upload(draft_id))
    self.assertEqual(draft["completeness"], {"complete": True, "missing": []})
    self.assertEqual(draft["items"]["framework_agreement"]["covered_by"], "contract")
    self.assertEqual(draft["items"]["data_handling"]["covered_by"], "contract")
    self.assertIsNone(draft["items"]["contract"]["covered_by"])

  def test_a_signed_agreement_covers_its_schedule_but_an_awaiting_one_does_not(self):
    draft_id = self.create()["draft_id"]
    self.complete_fields(draft_id)
    ok(self, self.upload(draft_id))
    ok(self, self.update(draft_id, {"items": {"framework_agreement": {
      "state": "awaiting_signature", "covers": ["framework_agreement", "data_handling"]}}}))
    self.assertEqual(self.completeness(draft_id)["missing"], ["record:framework_agreement", "record:data_handling"])
    draft = ok(self, self.upload(draft_id, "framework_agreement"))
    self.assertEqual(draft["completeness"], {"complete": True, "missing": []})
    self.assertEqual(draft["items"]["data_handling"]["covered_by"], "framework_agreement")
    self.assertIsNone(draft["items"]["framework_agreement"]["covered_by"])

  def test_engagement_level_records_never_block_a_tenant_draft(self):
    draft_id = self.create()["draft_id"]
    self.complete_fields(draft_id)
    ok(self, self.upload(draft_id))
    draft = ok(self, self.update(draft_id, {
      "items": {"contract": {"covers": ["scope_of_work", "rules_of_engagement"]}},
      "applicability": {"framework_agreement": {"decision": "not_required", "reason": "None"},
                        "data_handling": {"decision": "not_required", "reason": "None"}}}))
    self.assertEqual(draft["completeness"], {"complete": True, "missing": []})
    ok(self, self.update(draft_id, {"items": {"contract": {"covers": []}}}))
    self.assertTrue(self.completeness(draft_id)["complete"])

  def test_the_contract_item_is_always_required(self):
    draft_id = self.create()["draft_id"]
    self.complete_fields(draft_id)
    ok(self, self.update(draft_id, {"applicability": {
      "framework_agreement": {"decision": "not_required", "reason": "x"},
      "data_handling": {"decision": "not_required", "reason": "y"}}}))
    self.assertEqual(self.completeness(draft_id)["missing"], ["item:contract"])


class TestDraftDocuments(_DraftCase):
  def test_an_upload_signs_the_item_with_a_draft_envelope(self):
    draft_id = self.create()["draft_id"]
    draft = ok(self, self.upload(draft_id, filename="Signed Contract.pdf"))
    item = draft["items"]["contract"]
    self.assertEqual(item["state"], "signed")
    self.assertEqual(item["document"], {
      "store": "fake", "ref": "doc-1", "filename": "Signed_Contract.pdf", "mime": "application/pdf",
      "uploaded_at": item["document"]["uploaded_at"], "uploaded_by": "creator", "sha256": CONTRACT_SHA256,
      "size_bytes": len(CONTRACT_PDF)})
    envelope = self.documents.puts[0]
    self.assertEqual((envelope["kind"], envelope["schema_version"], envelope["document_kind"], envelope["draft_id"]),
                     ("redmesh_tenant_contract", "1.1", "contract", draft_id))
    self.assertEqual(envelope["uploaded_by"], "creator")
    self.assertEqual(self.stored(draft_id)["items"]["contract"]["document"], item["document"])
    # Another Super-Tenant Admin's upload into the same draft is accepted.
    other = ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF, actor={"account_id": "other-sta"}))
    self.assertEqual(other["items"]["data_handling"]["document"]["uploaded_by"], "other-sta")
    self.assertEqual(self.documents.puts[1]["document_kind"], "data_handling")

  def test_an_upload_from_any_state_replaces_and_deletes_the_previous_file_after_the_write(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.update(draft_id, {"items": {"contract": {"state": "awaiting_signature",
                                                           "covers": ["data_handling"],
                                                           "effective_from": "2026-11-01"}}}))
    first = ok(self, self.upload(draft_id))["items"]["contract"]["document"]["ref"]
    seen = []
    delete = self.documents.delete

    def observed_delete(ref):
      seen.append((ref, self.stored(draft_id)["items"]["contract"]["document"]["ref"]))
      delete(ref)
    self.documents.delete = observed_delete
    item = ok(self, self.upload(draft_id, raw=b"%PDF-1.7\n%second copy\n%%EOF\n"))["items"]["contract"]
    self.assertEqual(item["document"]["ref"], "doc-2")
    self.assertEqual((item["covers"], item["effective_from"]), (["data_handling"], "2026-11-01"))
    self.assertEqual(seen, [(first, "doc-2")])
    self.assertNotIn(first, self.documents.envelopes)

  def test_a_wrong_file_is_refused_with_the_slot_code(self):
    draft_id = self.create()["draft_id"]
    for kind, code in (("contract", "contract_invalid"), ("framework_agreement", "document_invalid"),
                       ("data_handling", "document_invalid")):
      for raw in (PNG, b""):
        with self.subTest(kind=kind, raw=raw):
          refused(self, self.upload(draft_id, kind, raw), 400, code)
      refused(self, self.plugin.upload_tenant_draft_document(self.actor, draft_id, kind, "c.pdf", "not base64!"),
              400, code)
    self.assertEqual(self.documents.puts, [])
    self.assertEqual(self.stored(draft_id)["items"]["contract"]["state"], "missing")

  def test_an_unknown_slot_is_invalid(self):
    draft_id = self.create()["draft_id"]
    for kind in ("scope_of_work", "", None, "Contract"):
      with self.subTest(kind=kind):
        refused(self, self.upload(draft_id, kind), 400, "invalid_request")
        refused(self, self.plugin.download_tenant_draft_document(self.actor, draft_id, kind), 400, "invalid_request")
    self.assertEqual(self.documents.puts, [])

  def test_a_store_failure_is_unavailable(self):
    draft_id = self.create()["draft_id"]
    self.documents.fail = True
    refused(self, self.upload(draft_id), 503, "unavailable")
    self.assertEqual(self.stored(draft_id)["items"]["contract"]["state"], "missing")

  def test_download_returns_the_verified_file(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF, filename="schedule.pdf"))
    data = ok(self, self.plugin.download_tenant_draft_document(self.actor, draft_id, "data_handling"))
    self.assertEqual(data, {"filename": "schedule.pdf", "mime": "application/pdf",
                            "content_b64": base64.b64encode(SCHEDULE_PDF).decode("ascii"),
                            "sha256": hashlib.sha256(SCHEDULE_PDF).hexdigest()})
    refused(self, self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract"), 404, "not_found")

  def test_setting_an_item_missing_deletes_its_file(self):
    draft_id = self.create()["draft_id"]
    ref = ok(self, self.upload(draft_id))["items"]["contract"]["document"]["ref"]
    draft = ok(self, self.update(draft_id, {"items": {"contract": {"state": "missing"}}}))
    self.assertEqual((draft["items"]["contract"]["state"], draft["items"]["contract"]["document"]), ("missing", None))
    self.assertEqual(self.documents.deleted, [ref])
    self.assertIsNone(self.stored(draft_id)["items"]["contract"]["document"])

  def test_delete_removes_every_file_then_the_record(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF))
    present = []
    delete = self.documents.delete

    def observed_delete(ref):
      present.append(self.stored(draft_id) is not None)
      delete(ref)
    self.documents.delete = observed_delete
    data = ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))
    self.assertEqual(data, {"draft_id": draft_id, "files_deleted": 2})
    self.assertEqual(present, [True, True])
    self.assertEqual(sorted(self.documents.deleted), ["doc-1", "doc-2"])
    self.assertIsNone(self.stored(draft_id))
    refused(self, self.plugin.get_tenant_draft(self.actor, draft_id), 404, "not_found")
    self.assertEqual(self.events, [("tenant_draft_deleted", {"draft_id": draft_id, "actor": "creator",
                                                             "files_deleted": 2})])

  def test_a_failed_file_delete_keeps_the_record_for_a_retry(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    self.documents.fail_delete = {"doc-1"}
    refused(self, self.plugin.delete_tenant_draft(self.actor, draft_id), 503, "unavailable")
    self.assertIsNotNone(self.stored(draft_id))
    self.assertEqual(self.events, [])
    self.documents.fail_delete = set()
    self.assertEqual(ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))["files_deleted"], 1)


class TestDraftLockAndMissingFiles(_DraftCase):
  def test_a_draft_being_activated_is_locked(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    self.set_activation(draft_id)
    writes, puts = len(self.store.writes), len(self.documents.puts)
    for call in (lambda: self.update(draft_id, {"display_name": "X"}),
                 lambda: self.update(draft_id, {"items": {"contract": {"state": "missing"}}}),
                 lambda: self.plugin.delete_tenant_draft(self.actor, draft_id),
                 lambda: self.upload(draft_id, "data_handling", SCHEDULE_PDF)):
      refused(self, call(), 409, "draft_locked")
    self.assertEqual((len(self.store.writes), len(self.documents.puts)), (writes, puts))
    self.assertEqual(self.documents.deleted, [])
    draft = ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))
    self.assertEqual(draft["activation"]["actor_id"], "creator")
    self.assertTrue(ok(self, self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract")))
    rows = ok(self, self.plugin.list_tenant_drafts(self.actor))
    self.assertEqual(rows[0]["activation"]["actor_id"], "creator")

  def test_an_unreadable_file_never_changes_the_row(self):
    # R1FS answers a timeout as no file: a read failure must not be persisted as `missing`.
    draft_id = self.create()["draft_id"]
    self.complete_fields(draft_id)
    ok(self, self.upload(draft_id))
    signed = self.stored(draft_id)["items"]["contract"]
    reads = []
    self.documents.get = lambda ref: reads.append(ref)
    draft = ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))
    self.assertEqual((draft["items"]["contract"]["state"], draft["items"]["contract"]["document"]),
                     ("signed", signed["document"]))
    ok(self, self.update(draft_id, {"display_name": "Acme Renamed"}))
    ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF))
    ok(self, self.plugin.create_tenant_draft(self.actor, draft_id[3:], "Replay", ["nis2"]))
    self.assertEqual(self.stored(draft_id)["items"]["contract"], signed)
    self.assertNotIn("item:contract", ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))
                     ["completeness"]["missing"])
    # No answer reads the store; only a download does.
    self.assertEqual(reads, [])
    refused(self, self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract"), 404, "not_found")
    self.assertEqual(reads, ["doc-1"])
    self.assertEqual(self.stored(draft_id)["items"]["contract"], signed)

  def test_answers_do_not_need_the_document_store(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    self.documents.fail = True
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))["items"]["contract"]["state"],
                     "signed")
    ok(self, self.update(draft_id, {"display_name": "Acme Renamed"}))
    refused(self, self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract"), 503, "unavailable")

  def test_a_stored_document_that_is_not_a_pdf_fails_closed(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    key = json.dumps(["tenant_draft", "deployment", draft_id], separators=(",", ":"))
    self.store.data[(TENANCY_HKEY, key)]["items"]["contract"]["document"]["mime"] = "image/png"
    refused(self, self.plugin.get_tenant_draft(self.actor, draft_id), 503, "unavailable")

  def test_a_gone_file_is_not_found_on_download_and_skipped_on_delete(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF))
    self.documents.envelopes.pop("doc-1")
    refused(self, self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract"), 404, "not_found")
    self.assertEqual(self.stored(draft_id)["items"]["contract"]["state"], "signed")
    # A gone file whose delete is not confirmed is skipped, not a failure.
    self.documents.fail_delete = {"doc-1"}
    data = ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))
    self.assertEqual(data["files_deleted"], 1)
    self.assertEqual(self.documents.deleted, ["doc-2"])
    self.assertIsNone(self.stored(draft_id))

  def test_a_failed_delete_of_an_unreferenced_file_is_logged_with_its_slot_and_ref(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    logged = []
    self.plugin.P = lambda message, **kwargs: logged.append((message, kwargs.get("color")))
    self.documents.fail_delete = {"doc-1"}
    item = ok(self, self.upload(draft_id, raw=b"%PDF-1.7\n%second copy\n%%EOF\n"))["items"]["contract"]
    self.assertEqual(item["document"]["ref"], "doc-2")
    self.assertEqual(len(logged), 1)
    message, color = logged[0]
    self.assertEqual(color, "r")
    for part in (draft_id, "contract", "doc-1"):
      self.assertIn(part, message)
    # The rollback of an upload whose write is refused logs the same way.
    logged.clear()
    self.set_activation(draft_id)
    self.documents.fail_delete = {"doc-3"}
    attach = self.plugin._call_tenant_administration
    self.plugin._call_tenant_administration = lambda operation, actor, **kwargs: (
      {"success": True, "status_code": 200, "data": {"accountId": "creator"}}
      if operation == "authorize_tenant_draft_upload" else attach(operation, actor, **kwargs))
    refused(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF), 409, "draft_locked")
    self.assertEqual(len(logged), 1)
    for part in (draft_id, "data_handling", "doc-3"):
      self.assertIn(part, logged[0][0])


class _ActivationCase(_DraftCase):
  def setUp(self):
    super().setUp()
    self.store.account("acme.admin")

  def ready(self, combined=False, uploader=None):
    """A complete draft: the contract, plus the agreement and the schedule unless `combined`."""
    draft_id = self.create(compliance_types=("nis2", "cra"))["draft_id"]
    self.complete_fields(draft_id)
    ok(self, self.upload(draft_id, actor=uploader))
    if combined:
      ok(self, self.update(draft_id, {"items": {"contract": {
        "covers": ["framework_agreement", "data_handling", "scope_of_work"]}}}))
    else:
      ok(self, self.update(draft_id, {"items": {"framework_agreement": {"effective_from": "2026-11-01"}}}))
      ok(self, self.upload(draft_id, "framework_agreement", b"%PDF-1.7\n%agreement\n%%EOF\n", actor=uploader))
      ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF, actor=uploader))
    return draft_id

  def activate(self, draft_id, request_id, actor=None):
    # Every creation argument the caller sends is ignored on the draft path.
    return self.plugin.prepare_tenant(actor or self.actor, request_id, "Ignored", "ignored", "nobody",
                                      legal_name="Ignored", registration_id="X", signer_name="Y",
                                      signer_role="Z", contract_ref="doc-ignored", draft_id=draft_id)

  def rows(self, kind):
    return [value for (hkey, key), value in self.store.data.items()
            if hkey == TENANCY_HKEY and value is not None and json.loads(key)[0] == kind]

  def finish(self, draft_id, request_id):
    """The Navigator side after `prepare_tenant`: membership, `activate_tenant`."""
    tenant_id = self.rows("receipt")[-1]["tenant_id"]
    self.store.grant("acme.admin", tenant_id)
    ok(self, self.plugin.activate_tenant(self.actor, request_id))
    return tenant_id


class TestDraftActivation(_ActivationCase):
  def test_the_tenant_is_created_from_the_draft_alone(self):
    draft_id, request_id = self.ready(), str(uuid4())
    draft = ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))
    prepared = ok(self, self.activate(draft_id, request_id))
    self.assertEqual((prepared["state"], prepared["initialAdminId"]), ("pending", "acme.admin"))
    marker = self.stored(draft_id)["activation"]
    self.assertEqual((marker["actor_id"], marker["request_id"]), ("creator", request_id))
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))["activation"]["tenant_state"],
                     "pending")
    receipt, = self.rows("receipt")
    self.assertEqual(receipt["draft_id"], draft_id)
    tenant, = self.rows("tenant")
    self.assertNotIn("draft_id", tenant)
    self.assertEqual((tenant["display_name"], tenant["domain_id"], tenant["legal"]), ("Acme SRL", "acme", LEGAL))
    self.assertEqual(tenant["compliance_types"], ["cra", "nis2"])
    for kind in KINDS:
      self.assertEqual(receipt[kind], draft["items"][kind]["document"])
      self.assertEqual(tenant[kind], draft["items"][kind]["document"])
    self.assertEqual(tenant["governance"], {
      "coverage": {"framework_agreement": "framework_agreement", "data_handling": "data_handling"},
      "applicability": draft["applicability"],
      "effective": {"contract": {"effective_from": None, "effective_until": None},
                    "framework_agreement": {"effective_from": "2026-11-01", "effective_until": None},
                    "data_handling": {"effective_from": None, "effective_until": None}}})
    self.assertIsNone(self.repo.get("domain", "ignored"))
    tenant_id = self.finish(draft_id, request_id)
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))["activation"]["tenant_state"],
                     "active")
    contract = ok(self, self.plugin.get_tenant_contract(self.actor, tenant_id))
    self.assertEqual(contract["compliance_types"], ["cra", "nis2"])
    self.assertEqual(contract["framework_agreement"], draft["items"]["framework_agreement"]["document"])
    downloaded = ok(self, self.plugin.download_tenant_document(self.actor, tenant_id, "data_handling"))
    self.assertEqual(downloaded["sha256"], hashlib.sha256(SCHEDULE_PDF).hexdigest())
    refused(self, self.plugin.download_tenant_document(self.actor, tenant_id, "other"), 400, "invalid_request")
    refused(self, self.plugin.download_tenant_document({"account_id": "acme.admin"}, tenant_id, "contract"),
            403, "forbidden")
    # Close: the record goes, the files are the tenant's.
    closed = ok(self, self.plugin.close_tenant_draft({"account_id": "other-sta"}, draft_id))
    self.assertEqual(closed, {"draft_id": draft_id, "tenant_id": tenant_id})
    self.assertIsNone(self.stored(draft_id))
    self.assertEqual(self.documents.deleted, [])
    refused(self, self.plugin.close_tenant_draft(self.actor, draft_id), 404, "not_found")

  def test_a_combined_contract_leaves_the_other_slots_empty(self):
    draft_id, request_id = self.ready(combined=True), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    tenant, = self.rows("tenant")
    self.assertEqual((tenant["framework_agreement"], tenant["data_handling"]), (None, None))
    self.assertEqual(tenant["governance"]["coverage"], {"framework_agreement": "contract",
                                                        "data_handling": "contract", "scope_of_work": "contract"})
    refused(self, self.plugin.download_tenant_document(self.actor, tenant_id, "framework_agreement"),
            404, "not_found")
    self.assertTrue(ok(self, self.plugin.download_tenant_document(self.actor, tenant_id, "contract")))

  def test_an_incomplete_draft_is_refused_with_its_gaps_and_writes_nothing(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.update(draft_id, {"domain_id": "acme"}))
    writes = len(self.store.writes)
    result = self.activate(draft_id, str(uuid4()))
    refused(self, result, 409, "draft_incomplete")
    self.assertEqual(result["missing"][:2], ["field:initial_admin_id", "field:legal.name"])
    self.assertIn("record:framework_agreement", result["missing"])
    self.assertEqual(len(self.store.writes), writes)
    self.assertIsNone(self.stored(draft_id)["activation"])

  def test_a_replay_is_the_same_creation(self):
    draft_id, request_id = self.ready(), str(uuid4())
    first = ok(self, self.activate(draft_id, request_id))
    self.assertEqual(ok(self, self.activate(draft_id, request_id)), first)
    self.finish(draft_id, request_id)
    again = ok(self, self.activate(draft_id, request_id))
    self.assertEqual((again["tenantId"], again["state"]), (first["tenantId"], "active"))
    self.assertEqual(len(self.rows("tenant")), 1)

  def test_another_activation_is_refused_while_the_marker_is_held(self):
    draft_id, request_id = self.ready(), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    marker = self.stored(draft_id)["activation"]
    for actor, request in (({"account_id": "other-sta"}, request_id), ({"account_id": "other-sta"}, str(uuid4())),
                           (self.actor, str(uuid4()))):
      with self.subTest(actor=actor, request=request):
        writes = len(self.store.writes)
        result = self.activate(draft_id, request, actor=actor)
        refused(self, result, 409, "activation_in_progress")
        self.assertEqual(result["holder"], {"actor_id": "creator", "started_at": marker["started_at"]})
        self.assertEqual(len(self.store.writes), writes)

  def test_a_super_tenant_admin_other_than_the_uploader_activates_and_a_lost_role_replays(self):
    draft_id, request_id = self.ready(uploader={"account_id": "other-sta"}), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    self.store.account("other-sta", memberships=[])
    self.assertEqual(self.activate(draft_id, request_id)["status_code"], 200)

  def test_a_first_activation_refuses_an_uploader_without_the_role(self):
    draft_id = self.ready(uploader={"account_id": "other-sta"})
    self.store.account("other-sta", memberships=[])
    writes = len(self.store.writes)
    refused(self, self.activate(draft_id, str(uuid4())), 400, "contract_invalid")
    self.assertEqual(len(self.store.writes), writes)

  def test_a_ref_from_another_draft_or_slot_is_refused(self):
    other_id = self.ready()
    other = self.stored(other_id)
    draft_id = self.ready()
    row = self.stored(draft_id)
    cases = {
      "contract of another draft": ("contract", other["items"]["contract"]["document"], "contract_invalid"),
      "schedule of another draft": ("data_handling", other["items"]["data_handling"]["document"], "document_invalid"),
      "this draft's contract in the agreement slot": (
        "framework_agreement", row["items"]["contract"]["document"], "document_invalid"),
    }
    for label, (kind, document, code) in cases.items():
      with self.subTest(label):
        changed = copy.deepcopy(row)
        changed["items"][kind]["document"] = document
        self.repo.put("tenant_draft", draft_id, record=changed)
        writes = len(self.store.writes)
        refused(self, self.activate(draft_id, str(uuid4())), 400, code)
        self.assertEqual(len(self.store.writes), writes)

  def test_a_ref_changed_after_resolution_is_draft_changed(self):
    draft_id = self.ready()
    resolved = {kind: item["document"] for kind, item in self.stored(draft_id)["items"].items()}
    ok(self, self.upload(draft_id, "data_handling", b"%PDF-1.7\n%new schedule\n%%EOF\n"))
    writes = len(self.store.writes)
    result = self.plugin._call_tenant_administration("prepare_tenant", self.actor, request_id=str(uuid4()),
                                                     draft_id=draft_id, draft_documents=resolved)
    refused(self, result, 409, "draft_changed")
    self.assertEqual(len(self.store.writes), writes)

  def test_a_file_bound_to_a_tenant_is_in_use_for_a_draft(self):
    draft_id = self.ready()
    row = self.stored(draft_id)
    # Another creation receipt already binds this draft's contract file (same CID); the scan reads
    # raw rows, so even one the validator would refuse counts.
    self.store.data[(TENANCY_HKEY, '["receipt","deployment","creator","x"]')] = {
      "contract": row["items"]["contract"]["document"]}
    refused(self, self.activate(draft_id, str(uuid4())), 409, "contract_in_use")

  def test_a_draft_id_is_never_a_tenant_id(self):
    from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
    draft_id, request_id = self.ready(), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    self.finish(draft_id, request_id)
    calls = {
      "nodes": lambda: self.plugin.get_tenant_nodes(self.actor, draft_id),
      "node assignment": lambda: self.plugin.set_tenant_node_assignment(self.actor, draft_id, "0xai_node", True),
      "membership": lambda: self.plugin.authorize_tenant_membership(self.actor, draft_id, "acme.admin", "tenant_user"),
      "engagements": lambda: self.plugin.list_engagements(self.actor, draft_id),
      "engagement create": lambda: self.plugin.create_engagement(self.actor, draft_id, str(uuid4())),
      "tenant": lambda: self.plugin.get_tenant(self.actor, draft_id),
      "tenant document": lambda: self.plugin.download_tenant_document(self.actor, draft_id, "contract"),
    }
    for label, call in calls.items():
      with self.subTest(label):
        refused(self, call(), 404, "not_found")
    service = self.plugin._execution_service()
    with self.assertRaises(AdministrationDenied) as denied:
      service.resolve_execution_admission(self.actor, draft_id, "en_" + str(uuid4()), "ea_1")
    self.assertEqual((denied.exception.status_code, denied.exception.error), (404, "not_found"))


class TestDraftRelease(_ActivationCase):
  def test_a_crash_after_the_marker_leaves_no_receipt_and_a_retry_recovers(self):
    draft_id, request_id = self.ready(), str(uuid4())
    # The marker write is the first of this preparation, the receipt the second.
    self.store.fail_write = len(self.store.writes) + 2
    refused(self, self.activate(draft_id, request_id), 503, "unavailable")
    self.store.fail_write = None
    self.assertEqual(self.stored(draft_id)["activation"]["request_id"], request_id)
    self.assertEqual(self.rows("receipt"), [])
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))["activation"]["tenant_state"], "none")
    prepared = ok(self, self.activate(draft_id, request_id))
    self.assertEqual(self.rows("receipt")[0]["tenant_id"], prepared["tenantId"])

  def test_a_crash_after_the_marker_is_released_without_touching_the_files(self):
    draft_id, request_id = self.ready(), str(uuid4())
    self.store.fail_write = len(self.store.writes) + 2
    refused(self, self.activate(draft_id, request_id), 503, "unavailable")
    self.store.fail_write = None
    before = self.stored(draft_id)["items"]
    released = ok(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id))["released"]
    self.assertEqual((released["request_id"], released["tenant_id"], released["initial_admin_id"]),
                     (request_id, None, None))
    self.assertEqual(self.stored(draft_id)["items"], before)
    self.assertIsNone(self.stored(draft_id)["activation"])
    self.assertEqual(ok(self, self.activate(draft_id, str(uuid4())))["state"], "pending")

  def test_release_removes_the_pending_tenant_keeps_the_files_and_frees_them(self):
    draft_id, request_id = self.ready(), str(uuid4())
    prepared = ok(self, self.activate(draft_id, request_id))
    self.store.grant("acme.admin", prepared["tenantId"])
    result = ok(self, self.plugin.release_tenant_draft_activation({"account_id": "other-sta"}, draft_id))
    released = result["released"]
    self.assertEqual(set(result), {"draft_id", "released"})
    self.assertEqual({key: released[key] for key in ("actor_id", "request_id", "tenant_id", "initial_admin_id")},
                     {"actor_id": "other-sta", "request_id": request_id, "tenant_id": prepared["tenantId"],
                      "initial_admin_id": "acme.admin"})
    self.assertEqual((self.rows("tenant"), self.rows("receipt")), ([], []))
    self.assertIsNone(self.repo.get("domain", "acme"))
    self.assertEqual(self.documents.deleted, [])
    row = self.stored(draft_id)
    self.assertIsNone(row["activation"])
    self.assertEqual(row["last_release"], released)
    self.assertTrue(all(item["state"] == "signed" for item in row["items"].values()))
    self.assertEqual(self.events, [("tenant_draft_activation_released",
                                    {"draft_id": draft_id, "actor": "other-sta", "rows_deleted": 3})])
    # A retry answers the release again, without a second event.
    self.assertEqual(ok(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id))["released"], released)
    self.assertEqual(len(self.events), 1)
    # The Navigator removes the membership; a fresh activation then uses the same files.
    self.store.account("acme.admin", memberships=[])
    fresh = str(uuid4())
    prepared = ok(self, self.activate(draft_id, fresh))
    self.assertIsNone(self.stored(draft_id)["last_release"])
    self.finish(draft_id, fresh)
    self.assertEqual(len(self.rows("tenant")), 1)

  def test_release_is_refused_once_active_and_close_needs_an_active_tenant(self):
    draft_id, request_id = self.ready(), str(uuid4())
    refused(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id), 409, "not_activating")
    refused(self, self.plugin.close_tenant_draft(self.actor, draft_id), 409, "activation_not_complete")
    ok(self, self.activate(draft_id, request_id))
    refused(self, self.plugin.close_tenant_draft(self.actor, draft_id), 409, "activation_not_complete")
    self.finish(draft_id, request_id)
    writes = len(self.store.writes)
    refused(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id), 409, "tenant_active")
    self.assertEqual(len(self.store.writes), writes)
    refused(self, self.plugin.delete_tenant_draft(self.actor, draft_id), 409, "draft_locked")
    ok(self, self.plugin.close_tenant_draft({"account_id": "other-sta"}, draft_id))

  def test_release_after_the_tenant_was_deleted_removes_no_row_and_empties_the_items(self):
    draft_id, request_id = self.ready(), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    # What `delete_tenant` leaves: no receipt, no tenant row, the domain still reserved.
    self.repo.delete("receipt", "creator", request_id)
    self.repo.delete("tenant", tenant_id)
    domain = self.repo.get("domain", "acme")
    released = ok(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id))["released"]
    self.assertEqual((released["tenant_id"], released["initial_admin_id"]), (None, None))
    self.assertEqual(self.repo.get("domain", "acme"), domain)
    row = self.stored(draft_id)
    self.assertTrue(all(item["state"] == "missing" and item["document"] is None for item in row["items"].values()))
    self.assertEqual(self.events[-1][1]["rows_deleted"], 0)
    self.assertEqual(ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))["files_deleted"], 0)

  def test_a_release_resumed_after_its_receipt_went_keeps_the_ids_and_the_files(self):
    draft_id, request_id = self.ready(), str(uuid4())
    prepared = ok(self, self.activate(draft_id, request_id))
    # Stop after the receipt delete, before the marker is cleared.
    service_store = self.plugin._execution_service().store
    real_put = type(service_store).put

    def put(store, kind, *ids, record):
      if kind == "tenant_draft" and record.get("activation") is None and record.get("last_release"):
        raise TenantStoreError("crash")
      return real_put(store, kind, *ids, record=record)
    with patch.object(type(service_store), "put", put):
      refused(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id), 503, "unavailable")
    self.assertEqual(self.rows("receipt"), [])
    released = ok(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id))["released"]
    self.assertEqual(released["tenant_id"], prepared["tenantId"])
    self.assertTrue(all(item["state"] == "signed" for item in self.stored(draft_id)["items"].values()))

  def test_tenant_delete_lists_every_tenant_document(self):
    for combined, count in ((False, 3), (True, 1)):
      with self.subTest(combined=combined):
        draft_id, request_id = self.ready(combined=combined), str(uuid4())
        ok(self, self.activate(draft_id, request_id))
        tenant_id = self.finish(draft_id, request_id)
        ok(self, self.plugin.close_tenant_draft(self.actor, draft_id))
        self.store.account("acme.admin", memberships=[])
        begun = ok(self, self.plugin._call_tenant_administration("begin_tenant_delete", self.actor, tenant_id=tenant_id))
        tenant = self.repo.get("tenant", tenant_id)
        expected = sorted(tenant[kind]["ref"] for kind in KINDS if tenant[kind] is not None)
        self.assertEqual(len(expected), count)
        self.assertEqual([ref["ref"] for ref in begun["documentRefs"]], expected)
        # The next draft needs another domain.
        self.repo.delete("tenant", tenant_id)
        self.repo.delete("receipt", "creator", request_id)
        self.repo.delete("domain", "acme")


class TestDraftStoreKind(unittest.TestCase):
  def setUp(self):
    self.owner = FakeAdministrationStore()
    self.repo = CstoreTenantAdministrationStore(self.owner, "deployment")

  def test_a_malformed_draft_row_is_not_readable(self):
    draft_id = "td_" + str(uuid4())
    key = json.dumps(["tenant_draft", "deployment", draft_id], separators=(",", ":"))
    base = {"schemaVersion": 1, "namespace": "deployment", "kind": "tenant_draft", "ids": [draft_id]}
    for row in ({**base}, {**base, "draft_id": "td_other"}):
      with self.subTest(row=row):
        self.owner.data[(TENANCY_HKEY, key)] = row
        with self.assertRaises(TenantStoreError):
          self.repo.get("tenant_draft", draft_id)
        with self.assertRaises(TenantStoreError):
          self.repo.list_tenant_drafts()
    with self.assertRaises(TenantStoreError):
      self.repo.put("tenant_draft", draft_id, record={"draft_id": draft_id})


if __name__ == "__main__":
  unittest.main()
