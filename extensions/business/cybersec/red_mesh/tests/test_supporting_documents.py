"""RM-261 phase 1: supporting documents. Files added to an engagement draft (hashed at activation) and
`supporting_document` rows on live engagements, contracts and contract drafts (outside every hash).
Real plugin endpoints, administration service and CStore adapter."""
import base64
import hashlib
import json
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy import administration
from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import (
  CstoreTenantAdministrationStore,
)
from extensions.business.cybersec.red_mesh.tenancy.engagements import engagement_hash
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError

from .asset_fixture import pick
from .test_amendment_activation import _AmendmentCase
from .test_engagement_drafts import COMPLETE, NOTES_PDF, PACK_PDF, SCHEDULE_PDF
from .test_tenant_contracts import SHARED_C
from .test_tenant_drafts import ok, refused

PNG_A = b"\x89PNG\r\n\x1a\n" + b"\x00" * 16
PNG_B = b"\x89PNG\r\n\x1a\n" + b"\x01" * 16
PNG_C = b"\x89PNG\r\n\x1a\n" + b"\x02" * 16
SUPPORTING_KEYS = {"documentId", "ownerId", "kind", "title", "sha256", "uploadedAt", "addedAfterSigning", "withdrawn"}


def b64(raw):
  return base64.b64encode(raw).decode("ascii")


class _SupportingCase(_AmendmentCase):
  def add_to_draft(self, draft_id, raw=PNG_A, kind="other", title="Insurance", actor=None):
    return self.plugin.upload_engagement_draft_added_document(actor or self.actor, draft_id, "cert.png", b64(raw),
                                                              kind, title, "")

  def signed_draft(self, tenant_id, added=()):
    """A complete draft of `tenant_id` with the `added` files uploaded into it, then its pack signed."""
    draft_id = ok(self, self.plugin.create_engagement_draft(self.actor, tenant_id, str(uuid4()), "Added"))["engagement_draft_id"]
    self.fill(draft_id)
    for raw in added:
      ok(self, self.add_to_draft(draft_id, raw))
    ok(self, self.upload_pack(draft_id))
    return draft_id

  def add(self, tenant_id, owner_id, raw=PNG_A, request_id=None, title="Scope letter", kind="other", actor=None):
    return self.plugin.add_supporting_document(actor or self.actor, tenant_id, owner_id, request_id or str(uuid4()),
                                               "letter.png", b64(raw), kind, title, "from the client")

  def withdraw(self, tenant_id, owner_id, document_id, reason="Superseded", actor=None):
    return self.plugin.withdraw_supporting_document(actor or self.actor, tenant_id, owner_id, document_id, reason)

  def listed(self, tenant_id, owner_id, actor=None):
    return self.plugin.list_supporting_documents(actor or self.actor, tenant_id, owner_id)

  def download(self, tenant_id, owner_id, document_id, actor=None):
    return self.plugin.download_supporting_document(actor or self.actor, tenant_id, owner_id, document_id)

  def swap(self, ref, raw=PNG_B):
    """Another valid envelope under the same ref: the file changed after it was added."""
    self.documents.envelopes[ref] = {**self.documents.envelopes[ref], "content_b64": b64(raw),
                                     "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}

  def member(self, tenant_id, name="member", role="tenant_admin"):
    self.store.account(name)
    self.store.grant(name, tenant_id, role)
    return {"account_id": name}


class TestDraftAdditions(_SupportingCase):
  def test_an_added_document_is_bound_at_activation_hashed_and_downloads_as_a_png(self):
    tenant_id, _ = self.scenario()
    draft_id = self.signed_draft(tenant_id, [PNG_A])
    entry, = self.stored_child(draft_id)["carried_documents"]
    self.assertEqual((entry["document_id"], entry["added"], entry["kind"], entry["mime"]), ("ad_1", True, "other", "image/png"))
    ok(self, self.plugin.activate_engagement_draft(self.actor, draft_id))
    row = self.repo.get("engagement", tenant_id, "en_" + draft_id[4:])
    self.assertEqual([(doc["document_id"], doc["kind"]) for doc in row["documents"]], [("ed_1", "agreement"), ("ed_2", "other")])
    self.assertNotIn("added", row["documents"][1])
    self.assertEqual(row["engagement_hash"], engagement_hash(row))
    self.assertNotEqual(engagement_hash({**row, "documents": row["documents"][:1]}), row["engagement_hash"])
    got = ok(self, self.plugin.download_engagement_document(self.actor, tenant_id, row["engagement_id"], "ed_2"))
    self.assertEqual((got["mime"], base64.b64decode(got["content_b64"])), ("image/png", PNG_A))

  def test_an_added_file_changed_after_the_upload_is_draft_changed_on_both_activation_paths(self):
    tenant_id, old_id = self.scenario()
    direct = self.signed_draft(tenant_id, [PNG_A])
    self.swap(self.stored_child(direct)["carried_documents"][0]["ref"])
    refused(self, self.plugin.activate_engagement_draft(self.actor, direct), 409, "draft_changed")
    second = self.ready_contract(tenant_id, [SHARED_C])
    copy_id = self.copy(tenant_id, old_id, second, sign=False)
    ref = ok(self, self.add_to_draft(copy_id))["carried_documents"][0]["ref"]
    ok(self, self.upload_pack(copy_id))
    original = dict(self.documents.envelopes[ref])
    self.swap(ref)
    refused(self, self.activate_contract(tenant_id, second), 409, "draft_changed")
    # The file back as it was: the amendment binds it.
    self.documents.envelopes[ref] = original
    ok(self, self.activate_contract(tenant_id, second))
    bound = self.repo.get("engagement", tenant_id, "en_" + copy_id[4:])["documents"]
    self.assertEqual([doc["ref"] for doc in bound][-1], ref)

  def test_an_uploader_who_is_not_a_platform_super_tenant_admin_is_refused_at_activation(self):
    tenant_id, _ = self.scenario()
    draft_id = self.signed_draft(tenant_id, [PNG_A])
    row = self.stored_child(draft_id)
    ref = row["carried_documents"][0]["ref"]
    row["carried_documents"][0]["uploaded_by"] = "pentester"
    self.repo.put("engagement_draft", draft_id, record=row)
    self.documents.envelopes[ref]["uploaded_by"] = "pentester"
    refused(self, self.plugin.activate_engagement_draft(self.actor, draft_id), 400, "document_invalid")

  def test_the_limit_counts_the_packs_the_carried_and_the_added_documents(self):
    tenant_id, old_id = self.old_engagement_tenant()
    draft_id = self.plugin.create_engagement_draft(self.actor, tenant_id, str(uuid4()), "R", supersedes=old_id)
    draft_id = ok(self, draft_id)["engagement_draft_id"]
    puts = len(self.documents.puts)
    # Two carried documents and two packs fill a limit of four; five leaves room for one.
    with patch.object(administration, "MAX_ENGAGEMENT_DOCUMENTS", 4):
      refused(self, self.add_to_draft(draft_id), 400, "document_invalid")
    with patch.object(administration, "MAX_ENGAGEMENT_DOCUMENTS", 5):
      ok(self, self.add_to_draft(draft_id))
      refused(self, self.add_to_draft(draft_id, PNG_B), 400, "document_invalid")
    # Only the one accepted file is kept.
    self.assertEqual(len(self.documents.deleted), len(self.documents.puts) - puts - 1)

  def test_a_draft_of_a_tenant_draft_and_a_signed_pack_take_no_added_document(self):
    child = self.child(self.create()["draft_id"])["engagement_draft_id"]
    tenant_id, _ = self.scenario()
    signed = self.signed_draft(tenant_id)
    puts = len(self.documents.puts)
    refused(self, self.add_to_draft(child), 409, "parent_not_active")
    refused(self, self.add_to_draft(signed), 409, "already_signed")
    self.assertEqual(len(self.documents.puts), puts)

  def old_engagement_tenant(self):
    """A tenant with one engagement holding a signed agreement, a consent and an other document."""
    tenant_id, _ = self.scenario()
    refs = [ok(self, self.plugin.upload_engagement_document(
              self.actor, tenant_id, "doc.pdf", b64(raw), kind, title, ""))["ref"]
            for raw, kind, title in ((PACK_PDF, "agreement", "Signed"), (SCHEDULE_PDF, "third_party_consent", "Consent"),
                                     (NOTES_PDF, "other", "Notes"))]
    old_id = ok(self, self.plugin.create_engagement(
      self.actor, tenant_id, str(uuid4()), "Old", COMPLETE["valid_from"], COMPLETE["valid_until"],
      COMPLETE["context"], [pick(self.asset_in(tenant_id))], refs))["engagementId"]
    return tenant_id, old_id

  def test_removing_an_added_entry_or_deleting_the_draft_deletes_its_file_and_never_a_carried_one(self):
    tenant_id, old_id = self.old_engagement_tenant()
    carried = [doc["ref"] for doc in self.repo.get("engagement", tenant_id, old_id)["documents"][1:]]
    draft_id = ok(self, self.plugin.create_engagement_draft(
      self.actor, tenant_id, str(uuid4()), "R", supersedes=old_id))["engagement_draft_id"]
    first = ok(self, self.add_to_draft(draft_id))["carried_documents"][-1]
    self.assertEqual(first["document_id"], "ad_1")
    ok(self, self.update_child(draft_id, {"carried_documents": ["ed_2", "ed_3"]}))
    self.assertEqual(self.documents.deleted, [first["ref"]])
    second = ok(self, self.add_to_draft(draft_id, PNG_B))["carried_documents"][-1]
    ok(self, self.plugin.delete_engagement_draft(self.actor, draft_id))
    self.assertEqual(self.documents.deleted, [first["ref"], second["ref"]])
    self.assertTrue(all(ref in self.documents.envelopes for ref in carried))


class TestSupportingRows(_SupportingCase):
  def test_a_document_added_to_a_live_engagement_leaves_its_hash_and_lists_and_downloads(self):
    tenant_id, engagement_id = self.scenario()
    before = self.repo.get("engagement", tenant_id, engagement_id)
    self.events.clear()
    document = ok(self, self.add(tenant_id, engagement_id))["document"]
    self.assertEqual(self.repo.get("engagement", tenant_id, engagement_id), before)
    self.assertEqual((document["ownerId"], document["kind"], document["uploadedBy"], document["withdrawn"]),
                     (engagement_id, "other", "creator", None))
    self.assertEqual(document["sha256"], hashlib.sha256(PNG_A).hexdigest())
    self.assertEqual([event for event, _ in self.events], ["supporting_document_added"])
    listed = ok(self, self.listed(tenant_id, engagement_id))
    self.assertEqual((listed["documents"], listed["can_manage"]), ([document], True))
    self.assertNotIn("ref", json.dumps(listed))
    got = ok(self, self.download(tenant_id, engagement_id, document["documentId"]))
    self.assertEqual(base64.b64decode(got["content_b64"]), PNG_A)
    # A changed file is not served.
    self.swap(self.rows("supporting_document")[0]["ref"])
    refused(self, self.download(tenant_id, engagement_id, document["documentId"]), 409, "document_integrity")

  def test_a_repeated_add_returns_the_stored_row_and_writes_one_row_one_file_one_audit(self):
    tenant_id, engagement_id = self.scenario()
    request_id = str(uuid4())
    first = ok(self, self.add(tenant_id, engagement_id, request_id=request_id))
    self.events.clear()
    puts = len(self.documents.puts)
    again = ok(self, self.add(tenant_id, engagement_id, PNG_B, request_id=request_id))
    self.assertEqual((again["document"], again["replayed"], first["replayed"]), (first["document"], True, False))
    self.assertEqual((len(self.rows("supporting_document")), len(self.documents.puts), self.events), (1, puts, []))

  def test_a_failed_row_write_discards_the_stored_file(self):
    tenant_id, engagement_id = self.scenario()
    with self.crash("supporting_document", lambda ids, record: True):
      self.assertEqual(self.add(tenant_id, engagement_id)["status_code"], 503)
    self.assertEqual((self.rows("supporting_document"), self.documents.deleted), ([], ["doc-%d" % len(self.documents.puts)]))

  def test_withdrawing_twice_writes_one_audit_and_the_withdrawn_file_stays_listed_and_downloadable(self):
    tenant_id, engagement_id = self.scenario()
    document_id = ok(self, self.add(tenant_id, engagement_id))["document"]["documentId"]
    refused(self, self.withdraw(tenant_id, engagement_id, document_id, ""), 400, "invalid_request")
    refused(self, self.withdraw(tenant_id, engagement_id, "sd_" + str(uuid4())), 404, "not_found")
    self.events.clear()
    first = ok(self, self.withdraw(tenant_id, engagement_id, document_id, "Lapsed"))
    again = ok(self, self.withdraw(tenant_id, engagement_id, document_id, "Another reason"))
    self.assertEqual((first["replayed"], again["replayed"], again["document"]), (False, True, first["document"]))
    self.assertEqual(first["document"]["withdrawn"]["reason"], "Lapsed")
    self.assertEqual([event for event, _ in self.events], ["supporting_document_withdrawn"])
    self.assertEqual(ok(self, self.listed(tenant_id, engagement_id))["documents"], [first["document"]])
    self.assertEqual(base64.b64decode(ok(self, self.download(tenant_id, engagement_id, document_id))["content_b64"]), PNG_A)

  def test_an_owner_holds_twenty_documents_withdrawn_ones_included(self):
    tenant_id, engagement_id = self.scenario()
    for number in range(20):
      first = ok(self, self.add(tenant_id, engagement_id, PNG_A + bytes([number])))["document"]
    ok(self, self.withdraw(tenant_id, engagement_id, first["documentId"]))
    puts = len(self.documents.puts)
    refused(self, self.add(tenant_id, engagement_id, PNG_C), 409, "document_limit")
    self.assertEqual(len(self.documents.deleted), len(self.documents.puts) - puts)

  def test_only_a_super_tenant_admin_adds_or_withdraws_and_a_contract_is_read_by_one_alone(self):
    tenant_id, engagement_id = self.scenario()
    document_id = ok(self, self.add(tenant_id, engagement_id))["document"]["documentId"]
    contract_doc = ok(self, self.add(tenant_id, "c_1", PNG_B))["document"]["documentId"]
    member, pentester = self.member(tenant_id), {"account_id": "pentester"}
    for actor in (member, pentester):
      for owner, doc in ((engagement_id, document_id), ("c_1", contract_doc)):
        self.assertEqual(self.add(tenant_id, owner, actor=actor)["status_code"], 403)
        self.assertEqual(self.withdraw(tenant_id, owner, doc, actor=actor)["status_code"], 403)
    # A contract's list and download are the Super-Tenant Admin's alone.
    for actor in (member, pentester):
      self.assertEqual(self.listed(tenant_id, "c_1", actor=actor)["status_code"], 403)
      self.assertEqual(self.download(tenant_id, "c_1", contract_doc, actor=actor)["status_code"], 403)
    # An engagement's: a member sees the id, kind, title, hash and time and no reference or uploader;
    # a Super Pentester also downloads and sees the file facts, but not the uploader.
    seen = ok(self, self.listed(tenant_id, engagement_id, actor=member))
    self.assertEqual((set(seen["documents"][0]), seen["can_manage"]), (SUPPORTING_KEYS, False))
    self.assertEqual(self.download(tenant_id, engagement_id, document_id, actor=member)["status_code"], 403)
    read = ok(self, self.listed(tenant_id, engagement_id, actor=pentester))["documents"][0]
    self.assertEqual(set(read) - SUPPORTING_KEYS, {"comment", "filename", "mime", "sizeBytes"})
    self.assertTrue(ok(self, self.download(tenant_id, engagement_id, document_id, actor=pentester))["content_b64"])
    self.assertEqual(self.listed(tenant_id, engagement_id, actor={"account_id": "nobody"})["status_code"], 404)

  def test_a_contract_draft_takes_documents_and_its_delete_removes_them_and_their_files(self):
    tenant_id, _ = self.scenario()
    contract_id = self.contract_draft(tenant_id)["data"]["contract_id"]
    ok(self, self.add(tenant_id, contract_id))
    ref = self.rows("supporting_document")[0]["ref"]
    ok(self, self.plugin.delete_tenant_contract_draft(self.actor, tenant_id, contract_id))
    self.assertEqual((self.rows("supporting_document"), self.documents.deleted), ([], [ref]))
    refused(self, self.add(tenant_id, "c_9"), 404, "not_found")

  def test_deleting_the_tenant_removes_the_rows_and_their_files(self):
    tenant_id, engagement_id = self.scenario()
    ok(self, self.add(tenant_id, engagement_id))
    ok(self, self.add(tenant_id, "c_1", PNG_B))
    refs = {row["ref"] for row in self.rows("supporting_document")}
    ok(self, self.plugin.delete_tenant(self.actor, tenant_id))
    self.assertEqual(self.rows("supporting_document"), [])
    self.assertLessEqual(refs, set(self.documents.deleted))

  def test_a_replacement_and_an_amendment_copy_carry_the_live_documents_and_not_the_withdrawn(self):
    tenant_id, engagement_id = self.scenario()
    live = ok(self, self.add(tenant_id, engagement_id, title="Live"))["document"]["documentId"]
    gone = ok(self, self.add(tenant_id, engagement_id, PNG_B, title="Gone"))["document"]["documentId"]
    ok(self, self.withdraw(tenant_id, engagement_id, gone))
    draft = ok(self, self.plugin.create_engagement_draft(self.actor, tenant_id, str(uuid4()), "R", supersedes=engagement_id))
    entry, = draft["carried_documents"]
    self.assertEqual((entry["document_id"], entry["title"], "added" in entry), ("ed_1", "Live", False))
    self.fill(draft["engagement_draft_id"])
    ok(self, self.upload_pack(draft["engagement_draft_id"]))
    ok(self, self.plugin.activate_engagement_draft(self.actor, draft["engagement_draft_id"]))
    new = self.repo.get("engagement", tenant_id, "en_" + draft["engagement_draft_id"][4:])
    self.assertEqual([doc["title"] for doc in new["documents"]], ["Engagement pack", "Live"])
    # An amendment copy is a replacement draft: removable before signing, the live row and its file stay.
    other_id = ok(self, self.engagement(tenant_id))["engagementId"]
    ok(self, self.add(tenant_id, other_id, PNG_C, title="Kept"))
    second = self.ready_contract(tenant_id, [SHARED_C])
    copy_id = self.copy(tenant_id, other_id, second, sign=False)
    self.assertEqual([doc["title"] for doc in self.stored_child(copy_id)["carried_documents"]], ["Kept"])
    ok(self, self.update_child(copy_id, {"carried_documents": []}))
    self.assertEqual(self.documents.deleted, [])
    self.assertEqual(self.download(tenant_id, other_id, self.rows("supporting_document")[-1]["document_id"])["success"], True)


  def test_a_row_write_that_lands_and_then_fails_keeps_its_file_and_the_row_downloads(self):
    tenant_id, engagement_id = self.scenario()
    real = CstoreTenantAdministrationStore.put

    def lands_then_fails(store, kind, *ids, record=None):
      real(store, kind, *ids, record=record)
      raise TenantStoreError("lost answer")
    with patch.object(CstoreTenantAdministrationStore, "put", lands_then_fails):
      self.assertEqual(self.add(tenant_id, engagement_id)["status_code"], 503)
    row, = self.rows("supporting_document")
    self.assertEqual(self.documents.deleted, [])
    self.assertEqual(base64.b64decode(ok(self, self.download(tenant_id, engagement_id, row["document_id"]))["content_b64"]), PNG_A)

  def test_withdrawing_again_answers_the_stored_row_whatever_reason_it_sends(self):
    tenant_id, engagement_id = self.scenario()
    document_id = ok(self, self.add(tenant_id, engagement_id))["document"]["documentId"]
    first = ok(self, self.withdraw(tenant_id, engagement_id, document_id, "Lapsed"))
    again = ok(self, self.withdraw(tenant_id, engagement_id, document_id, ""))
    self.assertEqual((again["replayed"], again["document"]), (True, first["document"]))

  def test_a_contract_draft_document_is_listed_and_downloaded_as_the_contract_after_activation(self):
    tenant_id, engagement_id = self.scenario()
    second = self.ready_contract(tenant_id, [SHARED_C])
    self.copy(tenant_id, engagement_id, second)
    document_id = ok(self, self.add(tenant_id, second, PNG_B))["document"]["documentId"]
    ok(self, self.activate_contract(tenant_id, second))
    self.assertEqual([doc["documentId"] for doc in ok(self, self.listed(tenant_id, second))["documents"]], [document_id])
    self.assertEqual(base64.b64decode(ok(self, self.download(tenant_id, second, document_id))["content_b64"]), PNG_B)

  def test_a_carried_supporting_document_withdrawn_since_refuses_direct_activation_until_removed(self):
    tenant_id, engagement_id = self.scenario()
    kept = ok(self, self.add(tenant_id, engagement_id, title="Kept"))["document"]["documentId"]
    draft_id = ok(self, self.plugin.create_engagement_draft(self.actor, tenant_id, str(uuid4()), "R",
                                                            supersedes=engagement_id))["engagement_draft_id"]
    # A document added after the draft exists is not in the snapshot.
    ok(self, self.add(tenant_id, engagement_id, PNG_C, title="Later"))
    self.assertEqual([doc["title"] for doc in self.stored_child(draft_id)["carried_documents"]], ["Kept"])
    self.fill(draft_id)
    ok(self, self.upload_pack(draft_id))
    ok(self, self.withdraw(tenant_id, engagement_id, kept))
    refused(self, self.plugin.activate_engagement_draft(self.actor, draft_id), 409, "carried_withdrawn")
    # Removal is before signing (RM-248): the pack is dropped, the entry removed, the pack signed again.
    ok(self, self.update_child(draft_id, {"document": {"state": "missing"}}))
    ok(self, self.update_child(draft_id, {"carried_documents": []}))
    ok(self, self.upload_pack(draft_id))
    ok(self, self.plugin.activate_engagement_draft(self.actor, draft_id))

  def test_a_carried_supporting_document_withdrawn_since_refuses_an_amendment_until_removed(self):
    tenant_id, engagement_id = self.scenario()
    kept = ok(self, self.add(tenant_id, engagement_id, title="Kept"))["document"]["documentId"]
    second = self.ready_contract(tenant_id, [SHARED_C])
    copy_id = self.copy(tenant_id, engagement_id, second)
    ok(self, self.withdraw(tenant_id, engagement_id, kept))
    refused(self, self.activate_contract(tenant_id, second), 409, "carried_withdrawn")
    ok(self, self.update_child(copy_id, {"document": {"state": "missing"}}))
    ok(self, self.update_child(copy_id, {"carried_documents": []}))
    ok(self, self.upload_pack(copy_id))
    ok(self, self.activate_contract(tenant_id, second))

  def test_a_replacement_whose_carried_documents_exceed_the_limit_is_document_limit(self):
    tenant_id, engagement_id = self.scenario()
    ok(self, self.add(tenant_id, engagement_id))
    with patch.object(administration, "MAX_ENGAGEMENT_DOCUMENTS", 2):
      refused(self, self.plugin.create_engagement_draft(self.actor, tenant_id, str(uuid4()), "R", supersedes=engagement_id),
              409, "document_limit")

  def test_a_non_super_tenant_admin_cannot_upload_an_added_document(self):
    tenant_id, _ = self.scenario()
    draft_id = ok(self, self.plugin.create_engagement_draft(self.actor, tenant_id, str(uuid4()), "D"))["engagement_draft_id"]
    puts = len(self.documents.puts)
    self.assertEqual(self.add_to_draft(draft_id, actor=self.member(tenant_id))["status_code"], 403)
    self.assertEqual(len(self.documents.puts), puts)

  def test_an_added_upload_is_refused_while_the_parent_tenant_is_not_active(self):
    tenant_id, _ = self.scenario()
    draft_id = ok(self, self.plugin.create_engagement_draft(self.actor, tenant_id, str(uuid4()), "D"))["engagement_draft_id"]
    self.repo.put("tenant", tenant_id, record={**self.repo.get("tenant", tenant_id), "active": False})
    puts = len(self.documents.puts)
    refused(self, self.add_to_draft(draft_id), 409, "parent_not_active")
    self.assertEqual(len(self.documents.puts), puts)

  def test_an_added_draft_write_that_lands_and_then_fails_keeps_its_file(self):
    tenant_id, _ = self.scenario()
    draft_id = ok(self, self.plugin.create_engagement_draft(self.actor, tenant_id, str(uuid4()), "D"))["engagement_draft_id"]
    real = CstoreTenantAdministrationStore.put

    def lands_then_fails(store, kind, *ids, record=None):
      real(store, kind, *ids, record=record)
      raise TenantStoreError("lost answer")
    with patch.object(CstoreTenantAdministrationStore, "put", lands_then_fails):
      self.assertEqual(self.add_to_draft(draft_id)["status_code"], 503)
    entry, = self.stored_child(draft_id)["carried_documents"]
    self.assertEqual((self.documents.deleted, entry["ref"] in self.documents.envelopes), ([], True))

  def test_an_id_is_not_served_under_another_tenant_owner_or_to_a_member_of_another_tenant(self):
    tenant_a, engagement_a = self.scenario()
    tenant_b, engagement_b = self.scenario()
    other_a = ok(self, self.engagement(tenant_a))["engagementId"]
    document_id = ok(self, self.add(tenant_a, engagement_a))["document"]["documentId"]
    for call in (lambda: self.add(tenant_b, engagement_a), lambda: self.listed(tenant_b, engagement_a),
                 lambda: self.download(tenant_b, engagement_a, document_id),
                 lambda: self.download(tenant_a, other_a, document_id), lambda: self.withdraw(tenant_a, other_a, document_id)):
      self.assertEqual(call()["status_code"], 404)
    stranger = self.member(tenant_b, "stranger")
    for call in (lambda: self.listed(tenant_a, engagement_a, actor=stranger),
                 lambda: self.download(tenant_a, engagement_a, document_id, actor=stranger)):
      self.assertIn(call()["status_code"], (403, 404))


class TestSupportingRecords(_SupportingCase):
  def test_the_validator_keeps_unknown_fields_and_refuses_what_the_operations_could_not_write(self):
    tenant_id, engagement_id = self.scenario()
    ok(self, self.add(tenant_id, engagement_id))
    row = self.rows("supporting_document")[0]
    ids = (tenant_id, engagement_id, row["document_id"])
    self.repo.put("supporting_document", *ids, record={**row, "future_field": 1})
    self.assertEqual(self.repo.get("supporting_document", *ids)["future_field"], 1)
    for label, change in {"agreement kind": {"document_kind": "agreement"}, "id mismatch": {"owner_id": "c_1"},
                          "bad withdrawal": {"withdrawn": {"reason": "x"}}, "no hash": {"sha256": "abc"},
                          "bad size": {"size_bytes": 0}}.items():
      with self.subTest(label), self.assertRaises(TenantStoreError):
        self.repo.put("supporting_document", *ids, record={**row, **change})
    with self.assertRaises(TenantStoreError):
      self.repo.get("supporting_note", *ids)

  def test_a_draft_row_written_before_added_documents_reads_and_a_mismatched_added_marker_does_not(self):
    tenant_id, _ = self.scenario()
    self.assertNotIn("carried_documents", self.stored_child(self.signed_draft(tenant_id)))
    draft_id = self.signed_draft(tenant_id, [PNG_A])
    row = self.stored_child(draft_id)
    entry = row["carried_documents"][0]
    for label, change in {"added without an ad id": {"document_id": "ed_1"}, "an ad id not added": {"added": None},
                          "added false": {"added": False}}.items():
      carried = [{key: value for key, value in {**entry, **change}.items() if value is not None}]
      with self.subTest(label), self.assertRaises(TenantStoreError):
        self.repo.put("engagement_draft", draft_id, record={**row, "carried_documents": carried})
