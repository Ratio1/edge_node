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
from .contract_fixture import CONTRACT_PDF, CONTRACT_SHA256, FakeDocumentStore, contract_b64, legal_dto
from .test_tenant_administration import FakeAdministrationStore

TENANCY_HKEY = '["redmesh","tenancy",1,"deployment"]'
PNG = b"\x89PNG\r\n\x1a\nnot a contract"
SCHEDULE_PDF = b"%PDF-1.7\n%fixture data handling schedule\n%%EOF\n"
GENERATED_PDF = b"%PDF-1.7\n%fixture generated tenant pack\n%%EOF\n"
LEGAL = {"name": "Example Holdings SRL", "registration_id": "RO12345678",
         "signer_name": "Ana Pop", "signer_role": "Director"}
PARTY = {"address": "Str. Exemplu 1, Cluj-Napoca", "vat_id": "RO12345678", "contact_name": "Ion Pop",
         "contact_email": "ion.pop@example.com", "contact_phone": "+40 700 000 000"}
KINDS = ("contract", "framework_agreement", "data_handling")
GENERATED_AT = "2026-10-07T10:00:00Z"
# The baseline as the Navigator sends it: canonical JSON of what the pack was rendered from.
SNAPSHOT = json.dumps({"generated_at": GENERATED_AT, "legal": LEGAL, "profile": {"legal_name": "RedMesh SRL"}},
                      sort_keys=True, separators=(",", ":"))
GENERATED_KEYS = {"store", "ref", "filename", "mime", "uploaded_at", "uploaded_by", "sha256", "size_bytes",
                  "snapshot_sha256", "generated_at", "generated_by"}


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

  def generate(self, draft_id, raw=GENERATED_PDF, snapshot=SNAPSHOT, generated_at=GENERATED_AT, actor=None,
               filename="generated.pdf", document_kind="contract", engagement_draft_id=None):
    """RM-110 `store_generated_document`: the rendered pack and its baseline, for a tenant draft's
    `contract` slot or (with `engagement_draft_id`) an engagement draft's pack."""
    return self.plugin.store_generated_document(actor or self.actor, draft_id=draft_id,
                                                engagement_draft_id=engagement_draft_id, document_kind=document_kind,
                                                filename=filename, content_b64=base64.b64encode(raw).decode("ascii"),
                                                snapshot=snapshot, generated_at=generated_at)

  def stored(self, draft_id):
    return self.repo.get("tenant_draft", draft_id)

  def complete_fields(self, draft_id):
    return ok(self, self.update(draft_id, {"display_name": "Acme SRL", "domain_id": "acme",
                                           "initial_admin_id": "Acme.Admin", "legal": dict(LEGAL),
                                           "items": {"contract": {"effective_from": "2026-11-01"}}}))

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
    # RM-110: the party block carries the optional customer fields too, all empty at creation.
    self.assertEqual(draft["legal"], legal_dto({key: "" for key in LEGAL}))
    # The collapsed checklist (RM-109 phase 4): the tenant agreement pack in the `contract` slot covers
    # both tenant records, applicability is `required` for both; the other two slots stay in the record.
    self.assertEqual(draft["items"]["contract"], {
      "state": "missing", "document": None, "covers": ["framework_agreement", "data_handling"],
      "effective_from": None, "effective_until": None, "generated": None, "basis": "Contractual obligation",
      "covered_by": None})
    self.assertEqual(draft["items"]["framework_agreement"]["covers"], ["framework_agreement"])
    self.assertEqual(draft["items"]["data_handling"]["covers"], ["data_handling"])
    self.assertEqual(draft["applicability"], {"framework_agreement": {"decision": "required", "reason": None},
                                              "data_handling": {"decision": "required", "reason": None}})
    self.assertIsNone(draft["activation"])
    self.assertIsNone(draft["last_release"])
    self.assertEqual((draft["created_by"], draft["updated_by"]), ("creator", "creator"))
    self.assertFalse(draft["completeness"]["complete"])
    self.assertNotIn("schemaVersion", draft)
    self.assertNotIn("namespace", draft)
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft["draft_id"])), draft)

    changed = ok(self, self.update(draft["draft_id"], {
      "domain_id": "acme", "legal": {"name": " Acme SRL "},
      "items": {"framework_agreement": {"effective_from": "2026-11-01", "effective_until": None}}}))
    self.assertEqual(changed["domain_id"], "acme")
    self.assertEqual(changed["legal"], legal_dto({"name": "Acme SRL", "registration_id": "", "signer_name": "",
                                                  "signer_role": ""}))
    self.assertEqual(changed["items"]["framework_agreement"]["effective_from"], "2026-11-01")
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
    # The hidden slots never count, signed or not.
    ok(self, self.upload(second["draft_id"], "data_handling", SCHEDULE_PDF))
    rows = ok(self, self.plugin.list_tenant_drafts(self.actor))
    by_id = {row["draft_id"]: row for row in rows}
    self.assertEqual(set(by_id), {first["draft_id"], second["draft_id"]})
    self.assertEqual(set(by_id[first["draft_id"]]), {"draft_id", "display_name", "compliance_types", "created_at",
                                                     "updated_at", "items_done", "items_total", "nodes",
                                                     "activation"})
    # One shown item since the two-pack shape; done once the pack is signed.
    self.assertEqual((by_id[first["draft_id"]]["items_done"], by_id[first["draft_id"]]["items_total"]), (0, 1))
    self.assertEqual((by_id[second["draft_id"]]["items_done"], by_id[second["draft_id"]]["items_total"]), (1, 1))
    self.assertEqual(by_id[second["draft_id"]]["compliance_types"], ["ai_act"])

  def test_a_draft_id_is_never_a_tenant_and_tenants_are_never_drafts(self):
    draft = self.create()
    self.assertEqual(self.plugin.get_tenant(self.actor, draft["draft_id"])["status_code"], 404)
    self.assertEqual(ok(self, self.plugin.list_tenants(self.actor)), [])

  def test_a_row_written_before_the_generated_slot_reads_back_as_never_generated(self):
    # RM-109 phases 2-3 wrote items without the key; such a row is current, not old.
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    key = json.dumps(["tenant_draft", "deployment", draft_id], separators=(",", ":"))
    for item in self.store.data[(TENANCY_HKEY, key)]["items"].values():
      del item["generated"]
    draft = ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))
    self.assertEqual({kind: item["generated"] for kind, item in draft["items"].items()},
                     {kind: None for kind in KINDS})
    self.assertEqual(draft["items"]["contract"]["state"], "signed")
    self.assertEqual(len(ok(self, self.plugin.list_tenant_drafts(self.actor))), 1)
    # The next write stores the key.
    ok(self, self.update(draft_id, {"display_name": "Renamed"}))
    self.assertEqual(self.stored(draft_id)["items"]["contract"]["generated"], None)
    self.assertIn("generated", self.store.data[(TENANCY_HKEY, key)]["items"]["contract"])


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
      "generate": lambda actor: self.plugin.store_generated_document(
        actor, draft_id=draft_id, document_kind="contract", filename="g.pdf", content_b64=contract_b64(GENERATED_PDF),
        snapshot=SNAPSHOT, generated_at=GENERATED_AT),
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
                 "delete_tenant_draft", "upload_tenant_draft_document", "download_tenant_draft_document",
                 "store_generated_document"):
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
                   lambda: self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract"),
                   lambda: self.generate(draft_id)):
        with self.subTest(draft_id=draft_id):
          self.assert_refused_without_writes(call, 400, "invalid_request")

  def test_an_absent_draft_is_not_found(self):
    draft_id = "td_" + str(uuid4())
    for call in (lambda: self.plugin.get_tenant_draft(self.actor, draft_id),
                 lambda: self.update(draft_id, {"display_name": "X"}),
                 lambda: self.plugin.delete_tenant_draft(self.actor, draft_id),
                 lambda: self.upload(draft_id),
                 lambda: self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract"),
                 lambda: self.generate(draft_id)):
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
      "party long": {"legal": {"address": "x" * 201}},
      "party type": {"legal": {"contact_email": 7}},
      "compliance type": {"compliance_types": ["gdpr"]},
      "item kind": {"items": {"scope_of_work": {"state": "missing"}}},
      "item field": {"items": {"contract": {"document": None}}},
      "item state": {"items": {"contract": {"state": "done"}}},
      "set signed": {"items": {"framework_agreement": {"state": "signed"}}},
      "awaiting with a file": {"items": {"data_handling": {"state": "awaiting_signature"}}},
      "bad date": {"items": {"contract": {"effective_from": "2026-13-01"}}},
      "datetime": {"items": {"contract": {"effective_until": "2026-11-01T00:00:00"}}},
    }
    for label, changes in cases.items():
      with self.subTest(label):
        self.assert_refused_without_writes(lambda: self.update(draft_id, changes), 400, "invalid_request")
    self.assert_refused_without_writes(lambda: self.update(draft_id, {"domain_id": "Not A Slug"}), 400, "invalid_domain")

  def test_covers_and_applicability_are_fixed_by_the_pack(self):
    # Owner, 2026-10-07: never edited, so not change keys at all, whatever the value.
    draft_id = self.create()["draft_id"]
    before = self.stored(draft_id)
    for label, changes in {
      "contract covers": {"items": {"contract": {"covers": ["framework_agreement", "data_handling"]}}},
      "covers dropped": {"items": {"contract": {"covers": []}}},
      "agreement covers": {"items": {"framework_agreement": {"covers": ["framework_agreement", "data_handling"]}}},
      "applicability required": {"applicability": {"data_handling": {"decision": "required", "reason": None}}},
      "applicability not required": {"applicability": {"data_handling": {"decision": "not_required", "reason": "x"}}},
      "applicability shape": {"applicability": {"data_handling": "required"}},
    }.items():
      with self.subTest(label):
        self.assert_refused_without_writes(lambda: self.update(draft_id, changes), 400, "invalid_request")
    after = self.stored(draft_id)
    self.assertEqual(after, before)
    self.assertEqual(after["items"]["contract"]["covers"], ["framework_agreement", "data_handling"])
    self.assertEqual(after["applicability"], {"framework_agreement": {"decision": "required", "reason": None},
                                              "data_handling": {"decision": "required", "reason": None}})

  def test_update_accepts_emptiness(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.update(draft_id, {"display_name": "Acme", "domain_id": "acme"}))
    draft = ok(self, self.update(draft_id, {"display_name": "", "domain_id": "", "compliance_types": []}))
    self.assertEqual((draft["display_name"], draft["domain_id"], draft["compliance_types"]), ("", "", []))

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
    # Rule 3 (collapsed checklist): the two tenant records sit in the contract's fixed covers, so
    # the signed pack decides them and no `record:` gap is listed. RM-112: the admin is optional.
    self.assertEqual(draft["completeness"], {"complete": False, "missing": [
      "field:display_name", "field:domain_id", "field:legal.name",
      "field:legal.registration_id", "field:legal.signer_name", "field:legal.signer_role",
      "field:compliance_types", "field:contract.effective_from", "item:contract"]})

  def test_the_signed_pack_alone_decides_the_records_and_engagement_records_never_block(self):
    draft_id = self.create()["draft_id"]
    self.complete_fields(draft_id)
    # With the fields filled, the pack is the only gap: no `record:` entry, tenant or engagement level.
    self.assertEqual(self.completeness(draft_id)["missing"], ["item:contract"])
    ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF))
    self.assertEqual(self.completeness(draft_id)["missing"], ["item:contract"])
    draft = ok(self, self.upload(draft_id))
    self.assertEqual(draft["completeness"], {"complete": True, "missing": []})
    self.assertEqual(draft["items"]["framework_agreement"]["covered_by"], "contract")
    self.assertEqual(draft["items"]["data_handling"]["covered_by"], "contract")
    self.assertIsNone(draft["items"]["contract"]["covered_by"])

  def test_missing_and_awaiting_signature_keep_the_generated_block(self):
    # Nothing generates yet (RM-110); the block is written into the record directly.
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    row = self.stored(draft_id)
    generated = {**row["items"]["contract"]["document"], "ref": "doc-generated", "sha256": "b" * 64,
                 "snapshot_sha256": "c" * 64, "generated_at": "2026-10-07T00:00:00Z", "generated_by": "creator"}
    row["items"]["contract"]["generated"] = generated
    self.repo.put("tenant_draft", draft_id, record=row)
    draft = ok(self, self.update(draft_id, {"items": {"contract": {"state": "missing"}}}))
    self.assertEqual((draft["items"]["contract"]["state"], draft["items"]["contract"]["generated"]),
                     ("missing", generated))
    self.assertEqual(self.documents.deleted, ["doc-1"])
    draft = ok(self, self.update(draft_id, {"items": {"contract": {"state": "awaiting_signature"}}}))
    self.assertEqual((draft["items"]["contract"]["state"], draft["items"]["contract"]["generated"]),
                     ("awaiting_signature", generated))
    # A malformed block is refused by the store.
    row = self.stored(draft_id)
    row["items"]["contract"]["generated"] = {**generated, "snapshot_sha256": "nope"}
    with self.assertRaises(TenantStoreError):
      self.repo.put("tenant_draft", draft_id, record=row)
    # Delete removes the generated file too.
    self.assertEqual(ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))["files_deleted"], 1)
    self.assertEqual(self.documents.deleted, ["doc-1", "doc-generated"])
    self.assertIsNone(self.stored(draft_id))


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
    self.assertEqual((item["state"], item["effective_from"]), ("signed", "2026-11-01"))
    self.assertEqual(seen, [(first, "doc-2")])
    self.assertNotIn(first, self.documents.envelopes)

  def test_the_generated_bytes_are_not_a_signed_copy(self):
    # Nothing generates yet (RM-110); the block is written into the record directly.
    draft_id = self.create()["draft_id"]
    row = self.stored(draft_id)
    row["items"]["contract"]["generated"] = {
      "store": "fake", "ref": "doc-generated", "filename": "generated.pdf", "mime": "application/pdf",
      "size_bytes": len(SCHEDULE_PDF), "sha256": hashlib.sha256(SCHEDULE_PDF).hexdigest(),
      "uploaded_at": "2026-10-07T00:00:00Z", "uploaded_by": "creator", "snapshot_sha256": "c" * 64,
      "generated_at": "2026-10-07T00:00:00Z", "generated_by": "creator"}
    self.repo.put("tenant_draft", draft_id, record=row)
    writes = len(self.store.writes)
    refused(self, self.upload(draft_id, raw=SCHEDULE_PDF), 409, "same_as_generated")
    self.assertEqual(len(self.store.writes), writes)
    # The refused upload's file is discarded; the draft is unchanged.
    self.assertEqual(self.documents.deleted, ["doc-1"])
    self.assertEqual(self.stored(draft_id), row)
    # Other bytes are a signed copy; another slot is not compared with this one's baseline.
    self.assertEqual(ok(self, self.upload(draft_id))["items"]["contract"]["state"], "signed")
    self.assertEqual(ok(self, self.upload(draft_id, "data_handling", SCHEDULE_PDF))["items"]["data_handling"]["state"],
                     "signed")

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
    # RM-112: a draft with a signed document is kept, so the file here is the unsigned pack.
    draft_id = self.create()["draft_id"]
    ok(self, self.generate(draft_id))
    present = []
    delete = self.documents.delete

    def observed_delete(ref):
      present.append(self.stored(draft_id) is not None)
      delete(ref)
    self.documents.delete = observed_delete
    data = ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))
    self.assertEqual(data, {"draft_id": draft_id, "files_deleted": 1, "engagement_drafts_deleted": 0})
    self.assertEqual(present, [True])
    self.assertEqual(self.documents.deleted, ["doc-1"])
    self.assertIsNone(self.stored(draft_id))
    refused(self, self.plugin.get_tenant_draft(self.actor, draft_id), 404, "not_found")
    self.assertEqual(self.events, [("tenant_draft_deleted", {"draft_id": draft_id, "actor": "creator",
                                                             "files_deleted": 1, "engagement_drafts_deleted": 0})])

  def test_a_failed_file_delete_keeps_the_record_for_a_retry(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.generate(draft_id))
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
                 lambda: self.upload(draft_id, "data_handling", SCHEDULE_PDF),
                 lambda: self.generate(draft_id)):
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
    # A gone file whose delete is not confirmed is skipped, not a failure. RM-112: a signed draft is
    # kept, so the delete runs on an unsigned one whose pack file is gone.
    draft_id = self.create()["draft_id"]
    ok(self, self.generate(draft_id))
    self.documents.envelopes.pop("doc-3")
    self.documents.fail_delete = {"doc-3"}
    data = ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))
    self.assertEqual(data["files_deleted"], 0)
    self.assertEqual(self.documents.deleted, [])
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


class TestGeneratedDocuments(_DraftCase):
  """RM-110 `store_generated_document` on the tenant draft's `contract` slot."""

  def test_generation_hashes_the_bytes_and_the_snapshot_and_stores_both_in_one_envelope(self):
    draft_id = self.create()["draft_id"]
    draft = ok(self, self.generate(draft_id, filename="Tenant Pack.pdf", actor={"account_id": "other-sta"}))
    item = draft["items"]["contract"]
    self.assertEqual((item["state"], item["document"]), ("generated", None))
    generated = item["generated"]
    self.assertEqual(set(generated), GENERATED_KEYS)
    # Hashed here, never taken from the caller.
    self.assertEqual(generated["sha256"], hashlib.sha256(GENERATED_PDF).hexdigest())
    self.assertEqual(generated["snapshot_sha256"], hashlib.sha256(SNAPSHOT.encode("utf-8")).hexdigest())
    self.assertEqual((generated["store"], generated["ref"], generated["filename"], generated["mime"],
                      generated["size_bytes"]), ("fake", "doc-1", "Tenant_Pack.pdf", "application/pdf", len(GENERATED_PDF)))
    self.assertEqual((generated["uploaded_by"], generated["generated_by"], generated["generated_at"]),
                     ("other-sta", "other-sta", GENERATED_AT))
    self.assertTrue(generated["uploaded_at"])
    self.assertEqual(draft["updated_by"], "other-sta")
    # One envelope: the draft envelope with the generated role, the snapshot next to the bytes.
    envelope, = self.documents.puts
    self.assertEqual((envelope["kind"], envelope["schema_version"], envelope["document_kind"], envelope["draft_id"],
                      envelope["role"]), ("redmesh_tenant_contract", "1.1", "contract", draft_id, "generated"))
    self.assertNotIn("engagement_draft_id", envelope)
    self.assertEqual((envelope["snapshot"], envelope["sha256"], envelope["uploaded_by"]),
                     (SNAPSHOT, generated["sha256"], "other-sta"))
    self.assertEqual(base64.b64decode(envelope["content_b64"]), GENERATED_PDF)
    self.assertEqual(self.documents.get("doc-1")["snapshot"], SNAPSHOT)
    self.assertEqual(self.stored(draft_id)["items"]["contract"]["generated"], generated)
    # Not a signed copy: completeness and the list still wait for one, and the signed download is empty.
    self.assertIn("item:contract", draft["completeness"]["missing"])
    self.assertEqual(ok(self, self.plugin.list_tenant_drafts(self.actor))[0]["items_done"], 0)
    refused(self, self.plugin.download_tenant_draft_document(self.actor, draft_id, "contract"), 404, "not_found")
    self.assertEqual(self.events, [])

  def test_generation_transitions_and_replaces_the_previous_generated_file_after_the_write(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.update(draft_id, {"items": {"contract": {"state": "awaiting_signature"}}}))
    self.assertEqual(ok(self, self.generate(draft_id))["items"]["contract"]["state"], "generated")
    seen = []
    delete = self.documents.delete

    def observed_delete(ref):
      seen.append((ref, self.stored(draft_id)["items"]["contract"]["generated"]["ref"]))
      delete(ref)
    self.documents.delete = observed_delete
    second = ok(self, self.generate(draft_id, raw=SCHEDULE_PDF, snapshot=json.dumps({"v": 2})))["items"]["contract"]
    self.assertEqual((second["state"], second["generated"]["ref"]), ("generated", "doc-2"))
    self.assertEqual(second["generated"]["snapshot_sha256"], hashlib.sha256(b'{"v": 2}').hexdigest())
    self.assertEqual(seen, [("doc-1", "doc-2")])
    self.assertNotIn("doc-1", self.documents.envelopes)
    # An update may set the item missing or awaiting_signature, both keep the block; `generated` is
    # never set by an update.
    draft = ok(self, self.update(draft_id, {"items": {"contract": {"state": "missing"}}}))
    self.assertEqual((draft["items"]["contract"]["state"], draft["items"]["contract"]["generated"]),
                     ("missing", second["generated"]))
    draft = ok(self, self.update(draft_id, {"items": {"contract": {"state": "awaiting_signature"}}}))
    self.assertEqual(draft["items"]["contract"]["state"], "awaiting_signature")
    refused(self, self.update(draft_id, {"items": {"contract": {"state": "generated"}}}), 400, "invalid_request")
    # The generated bytes are not a signed copy; other bytes are, and the block survives the upload.
    refused(self, self.upload(draft_id, raw=SCHEDULE_PDF), 409, "same_as_generated")
    signed = ok(self, self.upload(draft_id))["items"]["contract"]
    self.assertEqual((signed["state"], signed["document"]["ref"], signed["generated"]),
                     ("signed", "doc-4", second["generated"]))
    # Signed: generation is refused before anything is stored; the row is unchanged.
    row, writes, puts = self.stored(draft_id), len(self.store.writes), len(self.documents.puts)
    refused(self, self.generate(draft_id), 409, "already_signed")
    self.assertEqual((len(self.store.writes), len(self.documents.puts)), (writes, puts))
    self.assertEqual(self.stored(draft_id), row)
    self.assertEqual(self.documents.deleted, ["doc-1", "doc-3"])
    # The stored shape is checked: a `generated` item without its block is not readable.
    row["items"]["contract"].update(state="generated", document=None, generated=None)
    with self.assertRaises(TenantStoreError):
      self.repo.put("tenant_draft", draft_id, record=row)

  def test_generation_refuses_malformed_input_before_any_store_write(self):
    draft_id = self.create()["draft_id"]
    child = ok(self, self.plugin.create_engagement_draft(self.actor, draft_id, str(uuid4()), "Pack"))["engagement_draft_id"]
    cases = {
      "no id": dict(draft_id=None),
      "both ids": dict(engagement_draft_id=child),
      "another slot": dict(document_kind="data_handling"),
      "the pack slot on a tenant draft": dict(document_kind="engagement_pack"),
      "the contract slot on an engagement draft": dict(draft_id=None, engagement_draft_id=child, document_kind="contract"),
      "snapshot type": dict(snapshot={"a": 1}),
      "snapshot empty": dict(snapshot=""),
      "snapshot not json": dict(snapshot="{nope"),
      "snapshot not an object": dict(snapshot="[1]"),
      "snapshot too large": dict(snapshot=json.dumps({"x": "a" * (64 * 1024)})),
      "generated_at type": dict(generated_at=None),
      "generated_at date only": dict(generated_at="2026-10-07"),
      "generated_at not utc": dict(generated_at="2026-10-07T10:00:00+02:00"),
      "generated_at impossible": dict(generated_at="2026-13-07T10:00:00Z"),
    }
    for label, changes in cases.items():
      with self.subTest(label):
        refused(self, self.generate(**{"draft_id": draft_id, **changes}), 400, "invalid_request")
    for raw in (PNG, b""):
      with self.subTest(raw=raw):
        refused(self, self.generate(draft_id, raw=raw), 400, "contract_invalid")
    refused(self, self.plugin.store_generated_document(self.actor, draft_id=draft_id, document_kind="contract",
                                                       filename="g.pdf", content_b64="not base64!", snapshot=SNAPSHOT,
                                                       generated_at=GENERATED_AT), 400, "contract_invalid")
    self.assertEqual(self.documents.puts, [])
    self.assertEqual(self.stored(draft_id)["items"]["contract"]["state"], "missing")
    # `+00:00` and fractional seconds are UTC instants too.
    self.assertTrue(ok(self, self.generate(draft_id, generated_at="2026-10-07T10:00:00.250+00:00")))
    # An absent engagement draft, as every engagement draft operation.
    refused(self, self.generate(None, engagement_draft_id="ted_" + str(uuid4()), document_kind="engagement_pack"),
            404, "not_found")
    self.documents.fail = True
    refused(self, self.generate(draft_id), 503, "unavailable")

  def test_a_refused_attach_discards_the_stored_file(self):
    # The marker set between the authorization and the locked write: the file goes, the row is kept.
    draft_id = self.create()["draft_id"]
    self.set_activation(draft_id)
    attach = self.plugin._call_tenant_administration
    self.plugin._call_tenant_administration = lambda operation, actor, **kwargs: (
      {"success": True, "status_code": 200, "data": {"accountId": "creator"}}
      if operation == "authorize_generated_document" else attach(operation, actor, **kwargs))
    refused(self, self.generate(draft_id), 409, "draft_locked")
    self.assertEqual((len(self.documents.puts), self.documents.deleted), (1, ["doc-1"]))
    self.assertIsNone(self.stored(draft_id)["items"]["contract"]["generated"])


class _ActivationCase(_DraftCase):
  def setUp(self):
    super().setUp()
    self.store.account("acme.admin")

  def ready(self, combined=False, uploader=None):
    """A complete draft: the contract (which covers both tenant records: `combined` leaves it at
    that, the collapsed shape), plus the agreement and the schedule otherwise."""
    draft_id = self.create(compliance_types=("nis2", "cra"))["draft_id"]
    self.complete_fields(draft_id)
    ok(self, self.upload(draft_id, actor=uploader))
    if not combined:
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
    # The whole party block is copied, the optional fields empty here (RM-110).
    self.assertEqual((tenant["display_name"], tenant["domain_id"], tenant["legal"]),
                     ("Acme SRL", "acme", legal_dto(LEGAL)))
    self.assertEqual(tenant["compliance_types"], ["cra", "nis2"])
    for kind in KINDS:
      self.assertEqual(receipt[kind], draft["items"][kind]["document"])
      self.assertEqual(tenant[kind], draft["items"][kind]["document"])
    self.assertEqual(tenant["governance"], {
      "coverage": {"framework_agreement": "framework_agreement", "data_handling": "data_handling"},
      "applicability": draft["applicability"],
      "effective": {"contract": {"effective_from": "2026-11-01", "effective_until": None},
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
                                                        "data_handling": "contract"})
    refused(self, self.plugin.download_tenant_document(self.actor, tenant_id, "framework_agreement"),
            404, "not_found")
    self.assertTrue(ok(self, self.plugin.download_tenant_document(self.actor, tenant_id, "contract")))

  def test_an_incomplete_draft_is_refused_with_its_gaps_and_writes_nothing(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.update(draft_id, {"domain_id": "acme"}))
    writes = len(self.store.writes)
    result = self.activate(draft_id, str(uuid4()))
    refused(self, result, 409, "draft_incomplete")
    self.assertEqual(result["missing"][:2], ["field:legal.name", "field:legal.registration_id"])
    self.assertIn("item:contract", result["missing"])
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

  def delete_tenant(self, tenant_id):
    """The real `delete_tenant`: members removed first, no jobs (an empty job hash)."""
    self.plugin.cfg_instance_id = "jobs"
    self.store.account("acme.admin", memberships=[])
    return self.plugin.delete_tenant(self.actor, tenant_id)

  def assert_released_after_the_tenant_delete(self, draft_id):
    domain = self.repo.get("domain", "acme")
    self.assertIsNotNone(domain)
    released = ok(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id))["released"]
    self.assertEqual((released["tenant_id"], released["initial_admin_id"]), (None, None))
    self.assertEqual(self.repo.get("domain", "acme"), domain)
    row = self.stored(draft_id)
    self.assertIsNone(row["activation"])
    self.assertTrue(all(item["state"] == "missing" and item["document"] is None for item in row["items"].values()))
    self.assertEqual(self.events[-1], ("tenant_draft_activation_released",
                                       {"draft_id": draft_id, "actor": "creator", "rows_deleted": 0}))
    self.assertEqual(ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))["files_deleted"], 0)

  def test_release_after_the_tenant_was_deleted_removes_no_row_and_empties_the_items(self):
    draft_id, request_id = self.ready(), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    files = sorted(item["document"]["ref"] for item in self.stored(draft_id)["items"].values())
    deleted = ok(self, self.delete_tenant(tenant_id))
    self.assertEqual(deleted["documents"], 3)
    self.assertEqual(sorted(self.documents.deleted), files)
    self.assertEqual((self.rows("tenant"), self.rows("receipt")), ([], []))
    self.assert_released_after_the_tenant_delete(draft_id)

  def test_release_after_a_tenant_delete_that_stopped_before_the_tenant_row(self):
    draft_id, request_id = self.ready(), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    real_delete = CstoreTenantAdministrationStore.delete

    def delete(store, kind, *ids):
      if kind == "tenant":
        raise TenantStoreError("crash between the receipt and the tenant row")
      return real_delete(store, kind, *ids)
    with patch.object(CstoreTenantAdministrationStore, "delete", delete):
      refused(self, self.delete_tenant(tenant_id), 503, "unavailable")
    self.assertEqual(self.rows("receipt"), [])
    self.assertIn("deleting", self.repo.raw_record("tenant", tenant_id))
    self.assert_released_after_the_tenant_delete(draft_id)
    # The tenant delete is still finished by calling it again.
    self.assertTrue(ok(self, self.delete_tenant(tenant_id))["deleted"])

  def test_a_tenant_being_deleted_refuses_release(self):
    draft_id, request_id = self.ready(), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    self.store.account("acme.admin", memberships=[])
    ok(self, self.plugin._call_tenant_administration("begin_tenant_delete", self.actor, tenant_id=tenant_id,
                                                     mark=True))
    writes = len(self.store.writes)
    refused(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id), 409, "tenant_deleting")
    self.assertEqual(len(self.store.writes), writes)

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
    self.assertIsNone(self.stored(draft_id)["activation"])
    self.assertTrue(all(item["state"] == "signed" for item in self.stored(draft_id)["items"].values()))
    # The crashed call emitted nothing; the call that clears the marker emits the one event, with
    # only its own deletes counted.
    self.assertEqual(self.events, [("tenant_draft_activation_released",
                                    {"draft_id": draft_id, "actor": "creator", "rows_deleted": 0})])
    # A further call answers the release again and emits nothing.
    self.assertEqual(ok(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id))["released"], released)
    self.assertEqual(len(self.events), 1)

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


class TestPartyBlockAndBaseline(_ActivationCase):
  """RM-110: the party-block fields and the generated baseline at activation."""

  def key(self, kind, *ids):
    return TENANCY_HKEY, json.dumps([kind, "deployment", *ids], separators=(",", ":"))

  def test_the_party_fields_are_saved_bound_at_activation_and_read_from_the_tenant(self):
    draft_id, request_id = self.ready(combined=True), str(uuid4())
    draft = ok(self, self.update(draft_id, {"legal": {**PARTY, "contact_phone": " +40 700 000 000 "}}))
    self.assertEqual(draft["legal"], {**LEGAL, **PARTY})
    # Optional: emptiness is allowed and never a completeness gap.
    draft = ok(self, self.update(draft_id, {"legal": {"vat_id": ""}}))
    self.assertEqual((draft["legal"]["vat_id"], draft["completeness"]["complete"]), ("", True))
    ok(self, self.update(draft_id, {"legal": {"vat_id": PARTY["vat_id"]}}))
    ok(self, self.activate(draft_id, request_id))
    receipt, = self.rows("receipt")
    tenant, = self.rows("tenant")
    self.assertEqual((receipt["legal"], tenant["legal"]), ({**LEGAL, **PARTY}, {**LEGAL, **PARTY}))
    tenant_id = self.finish(draft_id, request_id)
    self.assertEqual(ok(self, self.plugin.get_tenant_contract(self.actor, tenant_id))["legal"], {**LEGAL, **PARTY})
    # Bound as the four fields: a tenant whose party block differs from its receipt's fails closed.
    self.store.data[self.key("tenant", tenant_id)]["legal"]["contact_email"] = "other@example.com"
    self.assertEqual(self.plugin.get_tenant_contract(self.actor, tenant_id)["status_code"], 503)
    self.assertEqual(self.plugin.get_tenant(self.actor, tenant_id)["status_code"], 503)

  def test_a_legacy_four_key_legal_block_reads_back_with_empty_party_fields(self):
    draft_id = self.create()["draft_id"]
    self.store.data[self.key("tenant_draft", draft_id)]["legal"] = dict(LEGAL)
    draft = ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))
    self.assertEqual(draft["legal"], legal_dto(LEGAL))
    self.assertNotIn("field:legal.name", draft["completeness"]["missing"])
    # The read did not write; the next write stores the completed block.
    self.assertEqual(self.store.data[self.key("tenant_draft", draft_id)]["legal"], LEGAL)
    ok(self, self.update(draft_id, {"display_name": "Renamed"}))
    self.assertEqual(self.store.data[self.key("tenant_draft", draft_id)]["legal"], legal_dto(LEGAL))

  def test_the_generated_baseline_becomes_the_tenants_contract_generated_and_is_deleted_with_it(self):
    draft_id, request_id = self.create()["draft_id"], str(uuid4())
    self.complete_fields(draft_id)
    generated = ok(self, self.generate(draft_id))["items"]["contract"]["generated"]
    ok(self, self.upload(draft_id))
    ok(self, self.activate(draft_id, request_id))
    receipt, = self.rows("receipt")
    tenant, = self.rows("tenant")
    self.assertEqual((receipt["contract_generated"], tenant["contract_generated"]), (generated, generated))
    # A replay carries the same baseline.
    self.assertEqual(ok(self, self.activate(draft_id, request_id))["tenantId"], tenant["tenant_id"])
    tenant_id = self.finish(draft_id, request_id)
    contract = ok(self, self.plugin.get_tenant_contract(self.actor, tenant_id))
    self.assertEqual((contract["contract_generated"], contract["contract"]["sha256"]), (generated, CONTRACT_SHA256))
    # The envelope behind its ref carries the bytes and the snapshot for the baseline readers.
    envelope = self.documents.get(generated["ref"])
    self.assertEqual((envelope["role"], envelope["snapshot"], base64.b64decode(envelope["content_b64"])),
                     ("generated", SNAPSHOT, GENERATED_PDF))
    # A tenant document for delete, next to the signed contract.
    ok(self, self.plugin.close_tenant_draft(self.actor, draft_id))
    self.store.account("acme.admin", memberships=[])
    self.plugin.cfg_instance_id = "jobs"
    begun = ok(self, self.plugin._call_tenant_administration("begin_tenant_delete", self.actor, tenant_id=tenant_id))
    self.assertEqual(sorted(ref["ref"] for ref in begun["documentRefs"]), sorted([generated["ref"], tenant["contract"]["ref"]]))
    deleted = ok(self, self.plugin.delete_tenant(self.actor, tenant_id))
    self.assertEqual(deleted["documents"], 2)
    self.assertEqual(sorted(self.documents.deleted), sorted([generated["ref"], tenant["contract"]["ref"]]))

  def test_the_generated_pack_is_verified_at_activation_like_the_signed_documents(self):
    draft_id = self.create()["draft_id"]
    self.complete_fields(draft_id)
    generated = ok(self, self.generate(draft_id))["items"]["contract"]["generated"]
    ok(self, self.upload(draft_id))
    row = self.stored(draft_id)
    resolved = {**{kind: item["document"] for kind, item in row["items"].items()},
                "contract_generated": {key: generated[key] for key in row["items"]["contract"]["document"]}}
    # The generated ref changed between resolution and the locked step.
    ok(self, self.update(draft_id, {"items": {"contract": {"state": "missing"}}}))
    ok(self, self.generate(draft_id, raw=SCHEDULE_PDF))
    ok(self, self.upload(draft_id))
    writes = len(self.store.writes)
    result = self.plugin._call_tenant_administration("prepare_tenant", self.actor, request_id=str(uuid4()),
                                                     draft_id=draft_id, draft_documents=resolved)
    refused(self, result, 409, "draft_changed")
    self.assertEqual(len(self.store.writes), writes)
    # A tampered generated file, or one bound to another draft, does not verify: the contract slot's code.
    ref = self.stored(draft_id)["items"]["contract"]["generated"]["ref"]
    original = self.documents.envelopes[ref]["content_b64"]
    self.documents.envelopes[ref]["content_b64"] = base64.b64encode(PNG).decode("ascii")
    refused(self, self.activate(draft_id, str(uuid4())), 400, "contract_invalid")
    self.documents.envelopes[ref]["content_b64"] = original
    self.documents.envelopes[ref]["draft_id"] = "td_" + str(uuid4())
    refused(self, self.activate(draft_id, str(uuid4())), 400, "contract_invalid")
    self.documents.envelopes[ref]["draft_id"] = draft_id
    self.assertEqual(len(self.store.writes), writes)
    self.assertEqual(self.rows("receipt"), [])
    # Intact: the activation goes through.
    self.assertTrue(ok(self, self.activate(draft_id, str(uuid4()))))

  def test_release_after_the_tenant_was_deleted_drops_the_generated_baseline_too(self):
    # The tenant delete removed `contract_generated.ref`, the draft's generated file: the block goes
    # with the signed copy, and a fresh generation replaces nothing.
    draft_id, request_id = self.create()["draft_id"], str(uuid4())
    self.complete_fields(draft_id)
    generated = ok(self, self.generate(draft_id))["items"]["contract"]["generated"]
    ok(self, self.upload(draft_id))
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    self.plugin.cfg_instance_id = "jobs"
    self.store.account("acme.admin", memberships=[])
    self.assertEqual(ok(self, self.plugin.delete_tenant(self.actor, tenant_id))["documents"], 2)
    self.assertNotIn(generated["ref"], self.documents.envelopes)
    ok(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id))
    item = self.stored(draft_id)["items"]["contract"]
    self.assertEqual((item["state"], item["document"], item["generated"]), ("missing", None, None))
    deleted = list(self.documents.deleted)
    again = ok(self, self.generate(draft_id, raw=SCHEDULE_PDF))["items"]["contract"]
    self.assertEqual((again["state"], again["generated"]["ref"]), ("generated", "doc-3"))
    self.assertEqual(self.documents.deleted, deleted)

  def test_contract_generated_is_optional_on_receipt_and_tenant_and_bound_when_present(self):
    draft_id, request_id = self.ready(combined=True), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    receipt_key, tenant_key = self.key("receipt", "creator", request_id), self.key("tenant", tenant_id)
    # Never generated: no key on either row, null in the answer (so pre-RM-110 rows read the same).
    self.assertNotIn("contract_generated", self.store.data[receipt_key])
    self.assertNotIn("contract_generated", self.store.data[tenant_key])
    self.assertIsNone(ok(self, self.plugin.get_tenant_contract(self.actor, tenant_id))["contract_generated"])
    block = {"store": "fake", "ref": "doc-generated", "filename": "generated.pdf", "mime": "application/pdf",
             "size_bytes": len(GENERATED_PDF), "sha256": hashlib.sha256(GENERATED_PDF).hexdigest(),
             "uploaded_at": "2026-10-07T00:00:00Z", "uploaded_by": "creator", "snapshot_sha256": "c" * 64,
             "generated_at": GENERATED_AT, "generated_by": "creator"}
    original = copy.deepcopy(self.store.data)
    cases = {
      "extra on the tenant": (None, block),
      "missing on the tenant": (block, None),
      "different on the tenant": (block, {**block, "sha256": "f" * 64}),
      "malformed": ({**block, "snapshot_sha256": "nope"}, {**block, "snapshot_sha256": "nope"}),
      "null": (None, None),
    }
    for label, (on_receipt, on_tenant) in cases.items():
      with self.subTest(label):
        self.store.data = copy.deepcopy(original)
        if label == "null" or on_receipt is not None:
          self.store.data[receipt_key]["contract_generated"] = on_receipt
        if label == "null" or on_tenant is not None:
          self.store.data[tenant_key]["contract_generated"] = on_tenant
        writes = len(self.store.writes)
        self.assertEqual(self.plugin.get_tenant(self.actor, tenant_id)["status_code"], 503)
        self.assertEqual(self.plugin.get_tenant_contract(self.actor, tenant_id)["status_code"], 503)
        self.assertEqual(len(self.store.writes), writes)
    # On both and well formed: bound, read, and one of the tenant's documents.
    self.store.data = copy.deepcopy(original)
    for key in (receipt_key, tenant_key):
      self.store.data[key]["contract_generated"] = block
    self.assertEqual(ok(self, self.plugin.get_tenant_contract(self.actor, tenant_id))["contract_generated"], block)
    self.assertTrue(ok(self, self.plugin.get_tenant(self.actor, tenant_id)))


class TestRefusalShape(unittest.TestCase):
  def test_refusal_details_never_override_the_fixed_keys(self):
    from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied, _endpoint

    @_endpoint
    def refuse():
      raise AdministrationDenied(409, "draft_incomplete", missing=["item:contract"], success=True, status="ok")
    self.assertEqual(refuse(), {"success": False, "status": "error", "status_code": 409,
                                "error": "draft_incomplete", "missing": ["item:contract"]})
    # `status_code` and `error` are the refusal's own arguments; a detail cannot carry them.
    with self.assertRaises(TypeError):
      AdministrationDenied(409, "draft_incomplete", status_code=200)


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

  def test_the_raw_scan_fails_closed_on_a_row_it_cannot_decode(self):
    self.owner.data[(TENANCY_HKEY, '["receipt","deployment","creator","r1"]')] = {"contract": {"ref": "doc-1"}}
    self.assertEqual(self.repo.raw_rows("receipt"), [{"contract": {"ref": "doc-1"}}])
    self.owner.data[(TENANCY_HKEY, '["receipt","deployment","creator","r2"]')] = "{not json"
    with self.assertRaises(TenantStoreError):
      self.repo.raw_rows("receipt")
    # Other kinds are not decoded.
    self.assertEqual(self.repo.raw_rows("tenant"), [])


if __name__ == "__main__":
  unittest.main()
