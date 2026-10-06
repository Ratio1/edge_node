"""RM-109 phase 4: engagement drafts inside the tenant draft, through the real plugin endpoints."""
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
from extensions.business.cybersec.red_mesh.tenancy.engagements import ROE_DEFAULTS
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from .contract_fixture import envelope
from .test_tenant_drafts import GENERATED_AT, PNG, SCHEDULE_PDF, SNAPSHOT, TENANCY_HKEY, _ActivationCase, ok, refused

PACK_PDF = b"%PDF-1.7\n%fixture signed engagement pack\n%%EOF\n"
GENERATED_PDF = b"%PDF-1.7\n%fixture generated engagement pack\n%%EOF\n"
NETWORK = {"display_name": "Edge gateway", "target": {"kind": "network", "address": "192.0.2.10"},
           "authorized_ports": "22,443", "authorized_tests": ["service_info_common"]}
WEBAPP = {"display_name": "Portal", "target": {"kind": "webapp", "url": "https://app.example.com/", "allowedPathPrefix": "/"},
          "authorized_tests": ["graybox"]}
COMPLETE = {"display_name": " Q4 external ", "allowed_run_modes": ["single_pass"],
            "valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-10-31T00:00:00+00:00",
            "roe": {"authenticated_action": True}, "context": {"client_name": "Example"}, "assets": [NETWORK]}
LIST_KEYS = {"engagement_draft_id", "parent", "display_name", "assets_count", "document_state", "created_at",
             "updated_at"}
SNAPSHOT_SHA256 = hashlib.sha256(SNAPSHOT.encode("utf-8")).hexdigest()


class _EngagementDraftCase(_ActivationCase):
  def child(self, parent, display_name="Pack", request_id=None, actor=None):
    request_id = request_id or str(uuid4())
    return ok(self, self.plugin.create_engagement_draft(actor or self.actor, parent, request_id, display_name))

  def update_child(self, engagement_draft_id, changes, actor=None):
    return self.plugin.update_engagement_draft(actor or self.actor, engagement_draft_id, changes)

  def upload_pack(self, engagement_draft_id, raw=PACK_PDF, filename="pack.pdf", actor=None):
    return self.plugin.upload_engagement_draft_document(actor or self.actor, engagement_draft_id, filename,
                                                        base64.b64encode(raw).decode("ascii"))

  def stored_child(self, engagement_draft_id):
    return self.repo.get("engagement_draft", engagement_draft_id)

  def fill(self, engagement_draft_id, **changes):
    return ok(self, self.update_child(engagement_draft_id, {**COMPLETE, **changes}))

  def active_tenant(self):
    """A tenant activated from a draft; the draft is not closed. Returns (draft_id, tenant_id)."""
    draft_id, request_id = self.ready(), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    return draft_id, self.finish(draft_id, request_id)

  def generate_pack(self, engagement_draft_id, raw=GENERATED_PDF, actor=None, snapshot=SNAPSHOT):
    """RM-110 `store_generated_document` on the pack slot; answers the `generated` block."""
    draft = ok(self, self.generate(None, raw=raw, snapshot=snapshot, actor=actor, document_kind="engagement_pack",
                                   engagement_draft_id=engagement_draft_id))
    return draft["document"]["generated"]

  def write_generated(self, engagement_draft_id, raw=GENERATED_PDF, uploaded_by="creator", ref="doc-generated"):
    """A generated block written directly, for an uploader the endpoint could not have recorded."""
    self.documents.envelopes[ref] = envelope(uploaded_by, raw, schema_version="1.1", document_kind="engagement_pack",
                                             engagement_draft_id=engagement_draft_id, role="generated",
                                             filename="generated.pdf", snapshot={"x": 1})
    block = {"store": "fake", "ref": ref, "filename": "generated.pdf", "mime": "application/pdf",
             "size_bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
             "uploaded_at": "2026-09-27T12:00:00Z", "uploaded_by": uploaded_by,
             "snapshot_sha256": SNAPSHOT_SHA256, "generated_at": "2026-10-07T00:00:00Z", "generated_by": uploaded_by}
    row = self.stored_child(engagement_draft_id)
    row["document"]["generated"] = block
    self.repo.put("engagement_draft", engagement_draft_id, record=row)
    return block

  def engagement_rows(self):
    return [value for (hkey, key), value in self.store.data.items()
            if hkey == TENANCY_HKEY and value is not None and json.loads(key)[0] == "engagement"]


class TestEngagementDraftRecord(_EngagementDraftCase):
  def test_a_child_is_created_inside_a_tenant_draft_and_read_back(self):
    parent, request_id = self.create()["draft_id"], str(uuid4())
    draft = self.child(parent, " Pack ", request_id=request_id)
    self.assertEqual(draft["engagement_draft_id"], "ted_" + request_id)
    self.assertEqual(draft["parent"], {"draft_id": parent})
    self.assertEqual(draft["display_name"], "Pack")
    self.assertEqual((draft["allowed_run_modes"], draft["valid_from"], draft["valid_until"], draft["assets"]),
                     ([], "", "", []))
    self.assertEqual(draft["roe"], ROE_DEFAULTS)
    self.assertIsInstance(draft["context"], dict)
    self.assertEqual(draft["document"], {"state": "missing", "document": None, "generated": None})
    self.assertEqual((draft["created_by"], draft["updated_by"]), ("creator", "creator"))
    self.assertEqual(draft["completeness"], {
      "complete": False,
      "missing": ["field:allowed_run_modes", "field:valid_from", "field:valid_until", "field:assets",
                  "item:engagement_pack"],
      "reasons": {"allowed_run_modes": "run_modes_invalid", "valid_from": "window_invalid",
                  "valid_until": "window_invalid", "assets": "engagement_asset_invalid"}})
    self.assertNotIn("schemaVersion", draft)
    self.assertEqual(ok(self, self.plugin.get_engagement_draft(self.actor, draft["engagement_draft_id"])), draft)
    # A replay answers the existing draft without a write, whatever else it sends.
    writes = len(self.store.writes)
    again = ok(self, self.plugin.create_engagement_draft(self.actor, "tn_" + str(uuid4()), request_id, "Other"))
    self.assertEqual(again, draft)
    self.assertEqual(len(self.store.writes), writes)

  def test_a_child_is_created_inside_an_active_tenant_and_listed_there(self):
    _, tenant_id = self.active_tenant()
    draft = self.child(tenant_id)
    self.assertEqual(draft["parent"], {"tenant_id": tenant_id})
    rows = ok(self, self.plugin.list_engagement_drafts(self.actor, tenant_id))
    self.assertEqual([row["engagement_draft_id"] for row in rows], [draft["engagement_draft_id"]])
    self.assertEqual(set(rows[0]), LIST_KEYS)
    self.assertEqual((rows[0]["parent"], rows[0]["assets_count"], rows[0]["document_state"]),
                     ({"tenant_id": tenant_id}, 0, "missing"))

  def test_the_parent_must_be_an_existing_tenant_draft_or_a_live_tenant(self):
    pending_draft, pending_request = self.ready(), str(uuid4())
    pending = ok(self, self.activate(pending_draft, pending_request))["tenantId"]
    for label, parent in (("absent draft", "td_" + str(uuid4())), ("absent tenant", "tn_" + str(uuid4())),
                          ("pending tenant", pending)):
      with self.subTest(label):
        writes = len(self.store.writes)
        refused(self, self.plugin.create_engagement_draft(self.actor, parent, str(uuid4()), "Pack"), 404, "not_found")
        self.assertEqual(len(self.store.writes), writes)
    for parent in ("", None, 7, "ted_" + str(uuid4()), "acme", "TN_" + str(uuid4())):
      with self.subTest(parent=parent):
        refused(self, self.plugin.create_engagement_draft(self.actor, parent, str(uuid4()), "Pack"), 400, "invalid_request")
        refused(self, self.plugin.list_engagement_drafts(self.actor, parent), 400, "invalid_request")
    parent = self.create()["draft_id"]
    refused(self, self.plugin.create_engagement_draft(self.actor, parent, "not-a-uuid", "Pack"), 400, "invalid_request")
    refused(self, self.plugin.create_engagement_draft(self.actor, parent, str(uuid4()), "x" * 121), 400, "invalid_request")
    # A parent that does not exist has no children.
    self.assertEqual(ok(self, self.plugin.list_engagement_drafts(self.actor, "td_" + str(uuid4()))), [])

  def test_update_checks_every_field_with_the_engagement_normalizers(self):
    engagement_draft_id = self.child(self.create()["draft_id"])["engagement_draft_id"]
    self.fill(engagement_draft_id)
    cases = {
      "not a dict": (None, "invalid_request"),
      "unknown key": ({"tenant_id": "tn_x"}, "invalid_request"),
      "name type": ({"display_name": 7}, "invalid_request"),
      "name long": ({"display_name": "x" * 121}, "invalid_request"),
      "run mode": ({"allowed_run_modes": ["forever"]}, "run_modes_invalid"),
      "run modes type": ({"allowed_run_modes": "single_pass"}, "run_modes_invalid"),
      "instant": ({"valid_from": "tomorrow"}, "window_invalid"),
      "instant type": ({"valid_until": None}, "window_invalid"),
      "window order": ({"valid_until": "2026-09-01T00:00:00Z"}, "window_invalid"),
      "roe flag": ({"roe": {"dos_allowed": True}}, "roe_invalid"),
      "roe type": ({"roe": {"authenticated_action": "yes"}}, "roe_invalid"),
      "context": ({"context": {"client_name": None}}, "context_invalid"),
      "asset ports": ({"assets": [{key: value for key, value in NETWORK.items() if key != "authorized_ports"}]},
                      "ports_required"),
      "asset tests": ({"assets": [{**NETWORK, "authorized_tests": ["graybox"]}]}, "tests_invalid"),
      "asset target": ({"assets": [{**NETWORK, "target": {"kind": "network", "address": "bad host"}}]},
                       "asset_target_invalid"),
      "asset twice": ({"assets": [NETWORK, NETWORK]}, "engagement_asset_invalid"),
      "stored asset echoed back": ({"assets": [{**NETWORK, "engagement_asset_id": "ea_1"}]}, "engagement_asset_invalid"),
      "document shape": ({"document": {"document": None}}, "invalid_request"),
      "document signed": ({"document": {"state": "signed"}}, "invalid_request"),
      "document state": ({"document": {"state": "done"}}, "invalid_request"),
    }
    before = self.stored_child(engagement_draft_id)
    for label, (changes, code) in cases.items():
      with self.subTest(label):
        writes = len(self.store.writes)
        refused(self, self.update_child(engagement_draft_id, changes), 400, code)
        self.assertEqual(len(self.store.writes), writes)
    self.assertEqual(self.stored_child(engagement_draft_id), before)

  def test_update_accepts_emptiness_and_stores_normalized_values(self):
    engagement_draft_id = self.child(self.create()["draft_id"])["engagement_draft_id"]
    draft = self.fill(engagement_draft_id)
    self.assertEqual((draft["display_name"], draft["valid_until"]), ("Q4 external", "2026-10-31T00:00:00Z"))
    self.assertEqual(draft["roe"], {**ROE_DEFAULTS, "authenticated_action": True})
    self.assertEqual(draft["context"]["client_name"], "Example")
    asset = draft["assets"][0]
    self.assertEqual((asset["engagement_asset_id"], asset["kind"], asset["authorized_ports"], asset["authorized_scan_modes"]),
                     ("ea_1", "network", "22,443", ["connect"]))
    self.assertEqual(draft["completeness"], {"complete": False, "missing": ["item:engagement_pack"], "reasons": {}})
    # Continuous without single pass is a format the normalizer accepts; completeness names it.
    draft = ok(self, self.update_child(engagement_draft_id, {"allowed_run_modes": ["continuous"]}))
    self.assertEqual(draft["completeness"]["missing"], ["field:allowed_run_modes", "item:engagement_pack"])
    self.assertEqual(draft["completeness"]["reasons"], {"allowed_run_modes": "run_modes_invalid"})
    emptied = ok(self, self.update_child(engagement_draft_id, {
      "display_name": "", "allowed_run_modes": [], "valid_from": "", "valid_until": "", "roe": None, "context": None,
      "assets": []}, actor={"account_id": "other-sta"}))
    self.assertEqual((emptied["display_name"], emptied["allowed_run_modes"], emptied["valid_from"], emptied["assets"]),
                     ("", [], "", []))
    self.assertEqual(emptied["roe"], ROE_DEFAULTS)
    self.assertEqual((emptied["updated_by"], emptied["created_by"]), ("other-sta", "creator"))
    self.assertEqual(emptied["completeness"]["reasons"]["display_name"], "invalid_request")
    writes = len(self.store.writes)
    ok(self, self.update_child(engagement_draft_id, {"display_name": ""}))
    ok(self, self.update_child(engagement_draft_id, {}))
    self.assertEqual(len(self.store.writes), writes)

  def test_the_list_is_newest_first_and_filtered_on_the_parent(self):
    parent, other = self.create("One")["draft_id"], self.create("Two")["draft_id"]
    with patch("extensions.business.cybersec.red_mesh.tenancy.administration.datetime") as clock:
      from datetime import datetime, timezone
      ids = []
      for day in (1, 3, 2):
        clock.now.return_value = datetime(2026, 10, day, tzinfo=timezone.utc)
        ids.append(self.child(parent, "Pack %d" % day)["engagement_draft_id"])
      clock.now.return_value = datetime(2026, 10, 9, tzinfo=timezone.utc)
      elsewhere = self.child(other)["engagement_draft_id"]
    self.fill(ids[0], assets=[NETWORK, WEBAPP])
    ok(self, self.upload_pack(ids[0]))
    rows = ok(self, self.plugin.list_engagement_drafts(self.actor, parent))
    self.assertEqual([row["engagement_draft_id"] for row in rows], [ids[1], ids[2], ids[0]])
    self.assertEqual((rows[2]["assets_count"], rows[2]["document_state"], rows[2]["display_name"]),
                     (2, "signed", "Q4 external"))
    self.assertEqual([row["engagement_draft_id"] for row in ok(self, self.plugin.list_engagement_drafts(self.actor, other))],
                     [elsewhere])

  def test_ids_are_checked_before_any_read_and_an_absent_draft_is_not_found(self):
    def calls(engagement_draft_id):
      return (lambda: self.plugin.get_engagement_draft(self.actor, engagement_draft_id),
              lambda: self.update_child(engagement_draft_id, {"display_name": "X"}),
              lambda: self.plugin.delete_engagement_draft(self.actor, engagement_draft_id),
              lambda: self.upload_pack(engagement_draft_id),
              lambda: self.plugin.download_engagement_draft_document(self.actor, engagement_draft_id),
              lambda: self.plugin.activate_engagement_draft(self.actor, engagement_draft_id),
              lambda: self.generate(None, engagement_draft_id=engagement_draft_id, document_kind="engagement_pack"))
    for engagement_draft_id in ("", "td_" + str(uuid4()), "tn_" + str(uuid4()), "ted_not-a-uuid",
                                "ted_" + str(uuid4()).upper(), None, 7):
      for call in calls(engagement_draft_id):
        with self.subTest(engagement_draft_id=engagement_draft_id):
          refused(self, call(), 400, "invalid_request")
    for call in calls("ted_" + str(uuid4())):
      with self.subTest(call=call):
        refused(self, call(), 404, "not_found")
    self.assertEqual(self.store.writes, [])
    self.assertEqual(self.documents.puts, [])


class TestEngagementDraftRoles(_EngagementDraftCase):
  def test_every_operation_refuses_anyone_but_a_full_portfolio_super_tenant_admin(self):
    parent = self.create()["draft_id"]
    engagement_draft_id = self.child(parent)["engagement_draft_id"]
    ok(self, self.upload_pack(engagement_draft_id))
    calls = {
      "create": lambda actor: self.plugin.create_engagement_draft(actor, parent, str(uuid4()), "X"),
      "update": lambda actor: self.plugin.update_engagement_draft(actor, engagement_draft_id, {"display_name": "Y"}),
      "get": lambda actor: self.plugin.get_engagement_draft(actor, engagement_draft_id),
      "list": lambda actor: self.plugin.list_engagement_drafts(actor, parent),
      "delete": lambda actor: self.plugin.delete_engagement_draft(actor, engagement_draft_id),
      "upload": lambda actor: self.plugin.upload_engagement_draft_document(
        actor, engagement_draft_id, "s.pdf", base64.b64encode(SCHEDULE_PDF).decode("ascii")),
      "download": lambda actor: self.plugin.download_engagement_draft_document(actor, engagement_draft_id),
      "activate": lambda actor: self.plugin.activate_engagement_draft(actor, engagement_draft_id),
      "generate": lambda actor: self.plugin.store_generated_document(
        actor, engagement_draft_id=engagement_draft_id, document_kind="engagement_pack", filename="g.pdf",
        content_b64=base64.b64encode(GENERATED_PDF).decode("ascii"), snapshot=SNAPSHOT, generated_at=GENERATED_AT),
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
    for name in ("create_engagement_draft", "update_engagement_draft", "get_engagement_draft",
                 "list_engagement_drafts", "delete_engagement_draft", "upload_engagement_draft_document",
                 "download_engagement_draft_document", "activate_engagement_draft"):
      with self.subTest(name):
        self.assertEqual(getattr(self.Plugin, name).__http_method__, "post")
        self.assertEqual(getattr(self.plugin, name)(actor=self.actor)["status_code"], 503)
    self.assertEqual(self.store.writes, [])


class TestEngagementDraftLock(_EngagementDraftCase):
  def test_every_write_is_locked_while_the_parent_is_being_activated(self):
    parent = self.create()["draft_id"]
    engagement_draft_id = self.child(parent)["engagement_draft_id"]
    self.fill(engagement_draft_id)
    ok(self, self.upload_pack(engagement_draft_id))
    self.set_activation(parent)
    writes, puts = len(self.store.writes), len(self.documents.puts)
    for label, call in {
      "create": lambda: self.plugin.create_engagement_draft(self.actor, parent, str(uuid4()), "X"),
      "update": lambda: self.update_child(engagement_draft_id, {"display_name": "X"}),
      "state": lambda: self.update_child(engagement_draft_id, {"document": {"state": "missing"}}),
      "upload": lambda: self.upload_pack(engagement_draft_id, SCHEDULE_PDF),
      "delete": lambda: self.plugin.delete_engagement_draft(self.actor, engagement_draft_id),
      "generate": lambda: self.generate(None, engagement_draft_id=engagement_draft_id, document_kind="engagement_pack"),
    }.items():
      with self.subTest(label):
        refused(self, call(), 409, "draft_locked")
    self.assertEqual((len(self.store.writes), len(self.documents.puts)), (writes, puts))
    self.assertEqual(self.documents.deleted, [])
    # Reads stay open; activation is refused for the parent still being a draft, marker or not.
    self.assertEqual(ok(self, self.plugin.get_engagement_draft(self.actor, engagement_draft_id))["document"]["state"], "signed")
    self.assertEqual(len(ok(self, self.plugin.list_engagement_drafts(self.actor, parent))), 1)
    self.assertTrue(ok(self, self.plugin.download_engagement_draft_document(self.actor, engagement_draft_id)))
    refused(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id), 409, "parent_not_active")


class TestEngagementDraftDocuments(_EngagementDraftCase):
  def test_an_upload_signs_the_pack_with_the_pack_envelope(self):
    engagement_draft_id = self.child(self.create()["draft_id"])["engagement_draft_id"]
    draft = ok(self, self.upload_pack(engagement_draft_id, filename="Signed Pack.pdf"))
    slot = draft["document"]
    self.assertEqual(slot["state"], "signed")
    self.assertEqual(slot["document"], {
      "store": "fake", "ref": "doc-1", "filename": "Signed_Pack.pdf", "mime": "application/pdf",
      "uploaded_at": slot["document"]["uploaded_at"], "uploaded_by": "creator",
      "sha256": hashlib.sha256(PACK_PDF).hexdigest(), "size_bytes": len(PACK_PDF)})
    self.assertIsNone(slot["generated"])
    stored = self.documents.puts[0]
    self.assertEqual((stored["kind"], stored["schema_version"], stored["document_kind"], stored["engagement_draft_id"]),
                     ("redmesh_tenant_contract", "1.1", "engagement_pack", engagement_draft_id))
    self.assertNotIn("draft_id", stored)
    self.assertNotIn("tenant_id", stored)
    self.assertEqual(self.stored_child(engagement_draft_id)["document"]["document"], slot["document"])
    # A replacement from another Super-Tenant Admin, from any state; the old file goes after the write.
    seen = []
    delete = self.documents.delete

    def observed_delete(ref):
      seen.append((ref, self.stored_child(engagement_draft_id)["document"]["document"]["ref"]))
      delete(ref)
    self.documents.delete = observed_delete
    again = ok(self, self.upload_pack(engagement_draft_id, SCHEDULE_PDF, actor={"account_id": "other-sta"}))
    self.assertEqual((again["document"]["document"]["ref"], again["document"]["document"]["uploaded_by"]),
                     ("doc-2", "other-sta"))
    self.assertEqual(seen, [("doc-1", "doc-2")])
    downloaded = ok(self, self.plugin.download_engagement_draft_document(self.actor, engagement_draft_id))
    self.assertEqual(downloaded, {"filename": "pack.pdf", "mime": "application/pdf",
                                  "content_b64": base64.b64encode(SCHEDULE_PDF).decode("ascii"),
                                  "sha256": hashlib.sha256(SCHEDULE_PDF).hexdigest()})

  def test_a_wrong_file_is_document_invalid_and_an_empty_slot_is_not_found(self):
    engagement_draft_id = self.child(self.create()["draft_id"])["engagement_draft_id"]
    for raw in (PNG, b""):
      with self.subTest(raw=raw):
        refused(self, self.upload_pack(engagement_draft_id, raw), 400, "document_invalid")
    refused(self, self.plugin.upload_engagement_draft_document(self.actor, engagement_draft_id, "p.pdf", "not base64!"),
            400, "document_invalid")
    self.assertEqual(self.documents.puts, [])
    refused(self, self.plugin.download_engagement_draft_document(self.actor, engagement_draft_id), 404, "not_found")
    self.documents.fail = True
    refused(self, self.upload_pack(engagement_draft_id), 503, "unavailable")
    self.assertEqual(self.stored_child(engagement_draft_id)["document"]["state"], "missing")

  def test_generation_stores_the_pack_with_its_snapshot_in_the_pack_envelope(self):
    parent = self.create()["draft_id"]
    engagement_draft_id = self.child(parent)["engagement_draft_id"]
    draft = ok(self, self.generate(None, raw=GENERATED_PDF, engagement_draft_id=engagement_draft_id,
                                   document_kind="engagement_pack", actor={"account_id": "other-sta"}))
    slot = draft["document"]
    self.assertEqual((slot["state"], slot["document"]), ("generated", None))
    generated = slot["generated"]
    self.assertEqual((generated["sha256"], generated["snapshot_sha256"], generated["uploaded_by"], generated["generated_by"],
                      generated["generated_at"]),
                     (hashlib.sha256(GENERATED_PDF).hexdigest(), SNAPSHOT_SHA256, "other-sta", "other-sta", GENERATED_AT))
    stored, = self.documents.puts
    self.assertEqual((stored["kind"], stored["schema_version"], stored["document_kind"], stored["engagement_draft_id"],
                      stored["role"], stored["snapshot"]),
                     ("redmesh_tenant_contract", "1.1", "engagement_pack", engagement_draft_id, "generated", SNAPSHOT))
    self.assertNotIn("draft_id", stored)
    self.assertNotIn("tenant_id", stored)
    self.assertEqual(self.stored_child(engagement_draft_id)["document"]["generated"], generated)
    # Not signed: the list says so, completeness still waits, the signed download is empty.
    self.assertEqual(ok(self, self.plugin.list_engagement_drafts(self.actor, parent))[0]["document_state"], "generated")
    self.assertIn("item:engagement_pack", draft["completeness"]["missing"])
    refused(self, self.plugin.download_engagement_draft_document(self.actor, engagement_draft_id), 404, "not_found")
    for raw in (PNG, b""):
      with self.subTest(raw=raw):
        refused(self, self.generate(None, raw=raw, engagement_draft_id=engagement_draft_id,
                                    document_kind="engagement_pack"), 400, "document_invalid")

  def test_the_generated_bytes_are_not_a_signed_copy(self):
    engagement_draft_id = self.child(self.create()["draft_id"])["engagement_draft_id"]
    generated = self.generate_pack(engagement_draft_id)
    writes = len(self.store.writes)
    refused(self, self.upload_pack(engagement_draft_id, GENERATED_PDF), 409, "same_as_generated")
    self.assertEqual(len(self.store.writes), writes)
    # The refused upload's file is discarded; the draft is unchanged.
    self.assertEqual(self.documents.deleted, ["doc-2"])
    self.assertEqual(self.stored_child(engagement_draft_id)["document"],
                     {"state": "generated", "document": None, "generated": generated})
    # Other bytes are a signed copy, and the block survives the upload.
    self.assertEqual(ok(self, self.upload_pack(engagement_draft_id))["document"]["generated"], generated)

  def test_state_transitions_as_a_tenant_item_and_missing_keeps_generated(self):
    engagement_draft_id = self.child(self.create()["draft_id"])["engagement_draft_id"]
    generated = self.generate_pack(engagement_draft_id)
    draft = ok(self, self.update_child(engagement_draft_id, {"document": {"state": "awaiting_signature"}}))
    self.assertEqual((draft["document"]["state"], draft["document"]["generated"]), ("awaiting_signature", generated))
    ok(self, self.upload_pack(engagement_draft_id))
    refused(self, self.update_child(engagement_draft_id, {"document": {"state": "awaiting_signature"}}), 400, "invalid_request")
    draft = ok(self, self.update_child(engagement_draft_id, {"document": {"state": "missing"}}))
    self.assertEqual(draft["document"], {"state": "missing", "document": None, "generated": generated})
    self.assertEqual(self.documents.deleted, ["doc-2"])
    self.assertIn("doc-1", self.documents.envelopes)
    # `generated` is set by generation alone, from missing here; the previous generated file goes
    # after the write. Once signed, generation is refused.
    refused(self, self.update_child(engagement_draft_id, {"document": {"state": "generated"}}), 400, "invalid_request")
    again = self.generate_pack(engagement_draft_id, raw=SCHEDULE_PDF)
    self.assertEqual((again["ref"], self.documents.deleted), ("doc-3", ["doc-2", "doc-1"]))
    self.assertEqual(self.stored_child(engagement_draft_id)["document"]["state"], "generated")
    ok(self, self.upload_pack(engagement_draft_id))
    puts = len(self.documents.puts)
    refused(self, self.generate(None, engagement_draft_id=engagement_draft_id, document_kind="engagement_pack"),
            409, "already_signed")
    self.assertEqual(len(self.documents.puts), puts)
    self.assertEqual(self.stored_child(engagement_draft_id)["document"]["generated"], again)

  def test_delete_removes_both_files_then_the_record(self):
    engagement_draft_id = self.child(self.create()["draft_id"])["engagement_draft_id"]
    self.generate_pack(engagement_draft_id)
    ok(self, self.upload_pack(engagement_draft_id))
    present = []
    delete = self.documents.delete

    def observed_delete(ref):
      present.append(self.stored_child(engagement_draft_id) is not None)
      delete(ref)
    self.documents.delete = observed_delete
    data = ok(self, self.plugin.delete_engagement_draft(self.actor, engagement_draft_id))
    self.assertEqual(data, {"engagement_draft_id": engagement_draft_id, "files_deleted": 2})
    self.assertEqual(present, [True, True])
    self.assertEqual(sorted(self.documents.deleted), ["doc-1", "doc-2"])
    self.assertIsNone(self.stored_child(engagement_draft_id))
    self.assertEqual(self.events, [("engagement_draft_deleted", {
      "engagement_draft_id": engagement_draft_id, "actor": "creator", "files_deleted": 2})])

  def test_a_failed_file_delete_keeps_the_record_and_a_late_upload_is_a_conflict(self):
    engagement_draft_id = self.child(self.create()["draft_id"])["engagement_draft_id"]
    ok(self, self.upload_pack(engagement_draft_id))
    self.documents.fail_delete = {"doc-1"}
    refused(self, self.plugin.delete_engagement_draft(self.actor, engagement_draft_id), 503, "unavailable")
    self.assertIsNotNone(self.stored_child(engagement_draft_id))
    self.documents.fail_delete = set()
    service = self.plugin._execution_service()
    refused(self, service.finish_engagement_draft_delete(self.actor, engagement_draft_id, []), 409, "conflict")
    self.assertEqual(ok(self, self.plugin.delete_engagement_draft(self.actor, engagement_draft_id))["files_deleted"], 1)


class TestEngagementDraftActivation(_EngagementDraftCase):
  def ready_child(self, parent, generated=True, uploader=None):
    engagement_draft_id = self.child(parent)["engagement_draft_id"]
    self.fill(engagement_draft_id)
    if generated:
      self.generate_pack(engagement_draft_id, actor=uploader)
    ok(self, self.upload_pack(engagement_draft_id, actor=uploader))
    return engagement_draft_id

  def test_the_parent_must_be_a_tenant(self):
    parent = self.create()["draft_id"]
    engagement_draft_id = self.ready_child(parent)
    writes = len(self.store.writes)
    refused(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id), 409, "parent_not_active")
    self.assertEqual(len(self.store.writes), writes)
    self.assertIsNotNone(self.stored_child(engagement_draft_id))

  def test_an_incomplete_draft_is_refused_with_its_gaps_and_writes_nothing(self):
    _, tenant_id = self.active_tenant()
    engagement_draft_id = self.child(tenant_id, "")["engagement_draft_id"]
    writes = len(self.store.writes)
    result = self.plugin.activate_engagement_draft(self.actor, engagement_draft_id)
    refused(self, result, 409, "draft_incomplete")
    self.assertEqual(result["missing"], ["field:display_name", "field:allowed_run_modes", "field:valid_from",
                                         "field:valid_until", "field:assets", "item:engagement_pack"])
    self.assertEqual(result["reasons"]["display_name"], "invalid_request")
    self.fill(engagement_draft_id, allowed_run_modes=["continuous"])
    result = self.plugin.activate_engagement_draft(self.actor, engagement_draft_id)
    refused(self, result, 409, "draft_incomplete")
    self.assertEqual((result["missing"], result["reasons"]),
                     (["field:allowed_run_modes", "item:engagement_pack"], {"allowed_run_modes": "run_modes_invalid"}))
    # The one write is the fill; neither refusal wrote.
    self.assertEqual(len(self.store.writes) - writes, 1)
    self.assertEqual(self.engagement_rows(), [])

  def test_the_engagement_is_created_from_the_draft_with_both_packs(self):
    _, tenant_id = self.active_tenant()
    engagement_draft_id = self.ready_child(tenant_id)
    row = self.stored_child(engagement_draft_id)
    signed, generated = row["document"]["document"], row["document"]["generated"]
    self.events.clear()
    result = ok(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id))
    engagement_id = "en_" + engagement_draft_id[4:]
    self.assertEqual(result, {"engagementId": engagement_id, "replayed": False})
    self.assertIsNone(self.stored_child(engagement_draft_id))
    self.assertEqual(self.documents.deleted, [])
    engagement, = self.engagement_rows()
    self.assertEqual((engagement["tenant_id"], engagement["engagement_id"], engagement["request_id"]),
                     (tenant_id, engagement_id, engagement_draft_id[4:]))
    self.assertEqual((engagement["display_name"], engagement["allowed_run_modes"], engagement["valid_until"]),
                     ("Q4 external", ["single_pass"], "2026-10-31T00:00:00Z"))
    self.assertEqual(engagement["assets"], row["assets"])
    self.assertEqual((engagement["roe"], engagement["context"]), (row["roe"], row["context"]))
    self.assertEqual(engagement["documents"], [
      {"document_id": "ed_1", **signed, "kind": "agreement", "title": "Engagement pack",
       "comment": "baseline sha256 " + generated["sha256"]},
      {"document_id": "ed_2", **{key: generated[key] for key in signed}, "kind": "other",
       "title": "Generated engagement pack (unsigned)", "comment": "snapshot sha256 " + SNAPSHOT_SHA256}])
    self.assertEqual(self.events, [("engagement_created", {
      "tenant_id": tenant_id, "engagement_id": engagement_id, "engagement_hash": engagement["engagement_hash"],
      "actor": "creator"})])
    # Read as any engagement, with both packs downloadable through the engagement document path.
    view = ok(self, self.plugin.get_engagement(self.actor, tenant_id, engagement_id))["engagement"]
    self.assertEqual([(item["documentId"], item["kind"], item["title"]) for item in view["documents"]],
                     [("ed_1", "agreement", "Engagement pack"), ("ed_2", "other", "Generated engagement pack (unsigned)")])
    for document_id, raw in (("ed_1", PACK_PDF), ("ed_2", GENERATED_PDF)):
      downloaded = ok(self, self.plugin.download_engagement_document(self.actor, tenant_id, engagement_id, document_id))
      self.assertEqual(downloaded["sha256"], hashlib.sha256(raw).hexdigest())
      self.assertEqual(base64.b64decode(downloaded["content_b64"]), raw)
    # The baseline readers (RM-111, RM-068) find the snapshot in the second document's envelope.
    baseline = self.documents.get(engagement["documents"][1]["ref"])
    self.assertEqual((baseline["role"], baseline["snapshot"], baseline["engagement_draft_id"]),
                     ("generated", SNAPSHOT, engagement_draft_id))
    self.assertEqual(hashlib.sha256(baseline["snapshot"].encode("utf-8")).hexdigest(), SNAPSHOT_SHA256)
    self.assertEqual([item["engagement_draft_id"] for item in ok(self, self.plugin.list_engagement_drafts(self.actor, tenant_id))], [])

  def test_without_a_generated_pack_the_signed_pack_is_the_only_document(self):
    _, tenant_id = self.active_tenant()
    engagement_draft_id = self.ready_child(tenant_id, generated=False)
    ok(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id))
    engagement, = self.engagement_rows()
    self.assertEqual([(item["document_id"], item["kind"], item["comment"]) for item in engagement["documents"]],
                     [("ed_1", "agreement", "")])

  def test_a_crash_after_create_engagement_is_finished_by_the_next_call_whoever_makes_it(self):
    _, tenant_id = self.active_tenant()
    engagement_draft_id = self.ready_child(tenant_id)
    self.events.clear()
    real_delete = CstoreTenantAdministrationStore.delete

    def delete(store, kind, *ids):
      if kind == "engagement_draft":
        raise TenantStoreError("crash between the engagement write and the row delete")
      return real_delete(store, kind, *ids)
    with patch.object(CstoreTenantAdministrationStore, "delete", delete):
      refused(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id), 503, "unavailable")
    self.assertEqual(len(self.engagement_rows()), 1)
    self.assertIsNotNone(self.stored_child(engagement_draft_id))
    self.assertEqual(self.events, [])
    writes = len(self.store.writes)
    result = ok(self, self.plugin.activate_engagement_draft({"account_id": "other-sta"}, engagement_draft_id))
    self.assertEqual(result, {"engagementId": "en_" + engagement_draft_id[4:], "replayed": True})
    self.assertIsNone(self.stored_child(engagement_draft_id))
    self.assertEqual(len(self.engagement_rows()), 1)
    # The replay only removed the row: one tombstone, no event.
    self.assertEqual(len(self.store.writes), writes + 1)
    self.assertEqual(self.events, [])
    refused(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id), 404, "not_found")

  def test_a_pack_uploader_must_hold_the_platform_role(self):
    _, tenant_id = self.active_tenant()
    engagement_draft_id = self.ready_child(tenant_id, uploader={"account_id": "other-sta"})
    self.store.account("other-sta", memberships=[])
    writes = len(self.store.writes)
    refused(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id), 400, "document_invalid")
    self.assertEqual(len(self.store.writes), writes)
    self.assertEqual(self.engagement_rows(), [])
    # The generated pack's uploader too.
    other = self.ready_child(tenant_id, generated=False)
    self.write_generated(other, uploaded_by="nobody", ref="doc-generated-2")
    refused(self, self.plugin.activate_engagement_draft(self.actor, other), 400, "document_invalid")
    # Another Super-Tenant Admin than the uploaders activates.
    self.store.account("other-sta", memberships=[{"role": "super_tenant_admin", "tenant_id": None}])
    self.assertTrue(ok(self, self.plugin.activate_engagement_draft({"account_id": "other-sta"}, engagement_draft_id)))

  def test_a_signed_pack_bound_to_an_engagement_is_in_use(self):
    _, tenant_id = self.active_tenant()
    engagement_draft_id = self.ready_child(tenant_id)
    ref = self.stored_child(engagement_draft_id)["document"]["document"]["ref"]
    # Any engagement row naming the file counts, raw and under any tenant.
    self.store.data[(TENANCY_HKEY, '["engagement","deployment","tn_x","en_x"]')] = {"documents": [{"ref": ref}]}
    writes = len(self.store.writes)
    refused(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id), 409, "contract_in_use")
    self.assertEqual(len(self.store.writes), writes)

  def test_a_pack_that_does_not_verify_or_moved_is_refused(self):
    _, tenant_id = self.active_tenant()
    engagement_draft_id = self.ready_child(tenant_id)
    row = self.stored_child(engagement_draft_id)
    resolved = {"signed": row["document"]["document"], "generated": {key: row["document"]["generated"][key]
                                                                      for key in row["document"]["document"]}}
    # A ref changed between resolution and the locked step.
    ok(self, self.upload_pack(engagement_draft_id, SCHEDULE_PDF))
    writes = len(self.store.writes)
    result = self.plugin._call_tenant_administration("activate_engagement_draft", self.actor,
                                                     engagement_draft_id=engagement_draft_id, documents=resolved)
    refused(self, result, 409, "draft_changed")
    self.assertEqual(len(self.store.writes), writes)
    # A pack whose envelope names another draft, or whose bytes changed, does not verify.
    ref = self.stored_child(engagement_draft_id)["document"]["document"]["ref"]
    self.documents.envelopes[ref]["engagement_draft_id"] = "ted_" + str(uuid4())
    refused(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id), 400, "document_invalid")
    self.documents.envelopes[ref]["engagement_draft_id"] = engagement_draft_id
    generated_ref = self.stored_child(engagement_draft_id)["document"]["generated"]["ref"]
    self.documents.envelopes[generated_ref]["content_b64"] = base64.b64encode(PNG).decode("ascii")
    refused(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id), 400, "document_invalid")
    self.assertEqual(self.engagement_rows(), [])


class TestTenantDraftCascade(_EngagementDraftCase):
  def test_delete_tenant_draft_removes_the_children_their_files_then_its_own(self):
    parent = self.create()["draft_id"]
    ok(self, self.upload(parent))
    first, second = (self.child(parent)["engagement_draft_id"] for _ in range(2))
    self.generate_pack(first)
    ok(self, self.upload_pack(first))
    ok(self, self.upload_pack(second, SCHEDULE_PDF))
    order = []
    delete = self.documents.delete

    def observed_delete(ref):
      order.append((ref, self.stored(parent) is not None, self.stored_child(first) is not None))
      delete(ref)
    self.documents.delete = observed_delete
    data = ok(self, self.plugin.delete_tenant_draft(self.actor, parent))
    self.assertEqual(data, {"draft_id": parent, "files_deleted": 4, "engagement_drafts_deleted": 2})
    # Children's files (the parent row still there; the signed pack, then the generated one), their
    # rows, then the parent's own file and row.
    self.assertEqual(order[:3], [("doc-3", True, True), ("doc-2", True, True), ("doc-4", True, False)])
    self.assertEqual(order[3][:2], ("doc-1", True))
    self.assertEqual(sorted(self.documents.deleted), ["doc-1", "doc-2", "doc-3", "doc-4"])
    for engagement_draft_id in (first, second):
      self.assertIsNone(self.stored_child(engagement_draft_id))
    self.assertIsNone(self.stored(parent))
    self.assertEqual(self.events[-1], ("tenant_draft_deleted", {
      "draft_id": parent, "actor": "creator", "files_deleted": 4, "engagement_drafts_deleted": 2}))

  def test_a_child_created_meanwhile_is_a_conflict_and_a_failed_child_file_keeps_everything(self):
    parent = self.create()["draft_id"]
    engagement_draft_id = self.child(parent)["engagement_draft_id"]
    ok(self, self.upload_pack(engagement_draft_id))
    service = self.plugin._execution_service()
    refused(self, service.finish_tenant_draft_delete(self.actor, parent, []), 409, "conflict")
    self.documents.fail_delete = {"doc-1"}
    refused(self, self.plugin.delete_tenant_draft(self.actor, parent), 503, "unavailable")
    self.assertIsNotNone(self.stored(parent))
    self.assertIsNotNone(self.stored_child(engagement_draft_id))
    self.documents.fail_delete = set()
    self.assertEqual(ok(self, self.plugin.delete_tenant_draft(self.actor, parent))["engagement_drafts_deleted"], 1)

  def test_a_child_deleted_meanwhile_does_not_stop_the_cascade(self):
    parent = self.create()["draft_id"]
    ok(self, self.upload(parent))
    engagement_draft_id = self.child(parent)["engagement_draft_id"]
    ok(self, self.upload_pack(engagement_draft_id))
    call = self.plugin._call_tenant_administration

    def racing(operation, actor, **kwargs):
      if operation == "finish_engagement_draft_delete":
        # Another call removed the child between the file deletes and its row delete.
        self.repo.delete("engagement_draft", kwargs["engagement_draft_id"])
      return call(operation, actor, **kwargs)
    self.plugin._call_tenant_administration = racing
    data = ok(self, self.plugin.delete_tenant_draft(self.actor, parent))
    self.assertEqual(data, {"draft_id": parent, "files_deleted": 2, "engagement_drafts_deleted": 1})
    self.assertIsNone(self.stored(parent))
    self.assertIsNone(self.stored_child(engagement_draft_id))

  def test_close_re_homes_the_children_and_a_crash_between_the_two_is_finished_by_the_next_call(self):
    draft_id, request_id = self.ready(), str(uuid4())
    children = [self.child(draft_id, "Pack %d" % index)["engagement_draft_id"] for index in range(2)]
    ok(self, self.activate(draft_id, request_id))
    tenant_id = self.finish(draft_id, request_id)
    real_delete = CstoreTenantAdministrationStore.delete

    def delete(store, kind, *ids):
      if kind == "tenant_draft":
        raise TenantStoreError("crash between the re-home and the row delete")
      return real_delete(store, kind, *ids)
    with patch.object(CstoreTenantAdministrationStore, "delete", delete):
      refused(self, self.plugin.close_tenant_draft(self.actor, draft_id), 503, "unavailable")
    for engagement_draft_id in children:
      self.assertEqual(self.stored_child(engagement_draft_id)["parent"], {"tenant_id": tenant_id})
    self.assertIsNotNone(self.stored(draft_id))
    closed = ok(self, self.plugin.close_tenant_draft({"account_id": "other-sta"}, draft_id))
    self.assertEqual(closed, {"draft_id": draft_id, "tenant_id": tenant_id})
    self.assertIsNone(self.stored(draft_id))
    self.assertEqual(self.documents.deleted, [])
    listed = ok(self, self.plugin.list_engagement_drafts(self.actor, tenant_id))
    self.assertEqual({row["engagement_draft_id"] for row in listed}, set(children))
    self.assertTrue(all(row["parent"] == {"tenant_id": tenant_id} for row in listed))
    self.assertEqual(ok(self, self.plugin.list_engagement_drafts(self.actor, draft_id)), [])
    # The Navigator then activates the signed children under the tenant.
    self.fill(children[0])
    ok(self, self.upload_pack(children[0]))
    activated = ok(self, self.plugin.activate_engagement_draft(self.actor, children[0]))
    self.assertEqual(activated["engagementId"], "en_" + children[0][4:])
    self.assertEqual(self.engagement_rows()[0]["tenant_id"], tenant_id)
    self.assertEqual([row["engagement_draft_id"] for row in ok(self, self.plugin.list_engagement_drafts(self.actor, tenant_id))],
                     [children[1]])

  def test_a_tenant_deleted_with_children_leaves_them_behind(self):
    draft_id, tenant_id = self.active_tenant()
    ok(self, self.plugin.close_tenant_draft(self.actor, draft_id))
    engagement_draft_id = self.child(tenant_id)["engagement_draft_id"]
    self.plugin.cfg_instance_id = "jobs"
    self.store.account("acme.admin", memberships=[])
    self.assertTrue(ok(self, self.plugin.delete_tenant(self.actor, tenant_id))["deleted"])
    # No cascade from `delete_tenant` (accepted): the row stays for data maintenance, and activation
    # finds no tenant.
    self.assertIsNotNone(self.stored_child(engagement_draft_id))
    self.fill(engagement_draft_id)
    ok(self, self.upload_pack(engagement_draft_id))
    refused(self, self.plugin.activate_engagement_draft(self.actor, engagement_draft_id), 404, "not_found")


class TestEngagementDraftIdsNeverResolve(_EngagementDraftCase):
  def test_an_engagement_draft_id_is_neither_a_tenant_nor_an_engagement_id(self):
    from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
    _, tenant_id = self.active_tenant()
    engagement_draft_id = self.child(tenant_id)["engagement_draft_id"]
    calls = {
      "tenant": lambda: self.plugin.get_tenant(self.actor, engagement_draft_id),
      "nodes": lambda: self.plugin.get_tenant_nodes(self.actor, engagement_draft_id),
      "membership": lambda: self.plugin.authorize_tenant_membership(self.actor, engagement_draft_id, "acme.admin", "tenant_user"),
      "engagements": lambda: self.plugin.list_engagements(self.actor, engagement_draft_id),
      "engagement create": lambda: self.plugin.create_engagement(self.actor, engagement_draft_id, str(uuid4())),
      "tenant document": lambda: self.plugin.download_tenant_document(self.actor, engagement_draft_id, "contract"),
      "engagement": lambda: self.plugin.get_engagement(self.actor, tenant_id, engagement_draft_id),
      "revoke": lambda: self.plugin.revoke_engagement(self.actor, tenant_id, engagement_draft_id, "x"),
      "engagement document": lambda: self.plugin.download_engagement_document(self.actor, tenant_id, engagement_draft_id, "ed_1"),
      "tenant draft": lambda: self.plugin.get_tenant_draft(self.actor, engagement_draft_id),
    }
    for label, call in calls.items():
      with self.subTest(label):
        result = call()
        self.assertEqual(result["status_code"], 404 if label != "tenant draft" else 400, result)
    service = self.plugin._execution_service()
    with self.assertRaises(AdministrationDenied) as denied:
      service.resolve_execution_admission(self.actor, tenant_id, engagement_draft_id, "ea_1")
    self.assertEqual((denied.exception.status_code, denied.exception.error), (404, "not_found"))
    self.assertEqual(service.engagement_end_reason(tenant_id, engagement_draft_id), "engagement_not_found")


if __name__ == "__main__":
  unittest.main()
