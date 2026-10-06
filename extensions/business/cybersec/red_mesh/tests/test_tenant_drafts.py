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

  def test_a_gone_file_reads_as_missing_and_delete_skips_it(self):
    draft_id = self.create()["draft_id"]
    self.complete_fields(draft_id)
    ok(self, self.upload(draft_id))
    ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF))
    self.documents.envelopes.pop("doc-1")
    draft = ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))
    self.assertEqual((draft["items"]["contract"]["state"], draft["items"]["contract"]["document"]), ("missing", None))
    self.assertEqual(draft["items"]["data_handling"]["state"], "signed")
    self.assertIn("item:contract", draft["completeness"]["missing"])
    refused(self, self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract"), 404, "not_found")
    # The stored row is corrected on the next write.
    self.assertEqual(self.stored(draft_id)["items"]["contract"]["state"], "signed")
    ok(self, self.update(draft_id, {"display_name": "Acme Renamed"}))
    self.assertEqual((self.stored(draft_id)["items"]["contract"]["state"],
                      self.stored(draft_id)["items"]["contract"]["document"]), ("missing", None))
    # A gone file whose delete is not confirmed is skipped, not a failure.
    self.documents.envelopes.pop("doc-2")
    self.documents.fail_delete = {"doc-2"}
    data = ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))
    self.assertEqual(data["files_deleted"], 0)
    self.assertIsNone(self.stored(draft_id))

  def test_an_unreadable_document_store_is_unavailable_not_missing(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    self.documents.fail = True
    refused(self, self.plugin.get_tenant_draft(self.actor, draft_id), 503, "unavailable")


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
