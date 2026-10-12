"""RM-133 step 2: several contracts per tenant. A further contract is a contract draft on the active
tenant, numbered `c_<n>`, generated, signed and activated in one locked call that assigns its nodes
and writes it onto the tenant row; engagements pick a contract; the launch gate, the node union, the
in-use scan and the delete path cover the set. Real plugin endpoints, service and adapters."""
import base64
from datetime import datetime, timezone
import hashlib
import json
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from extensions.business.cybersec.red_mesh.services.tenant_contract import (
  ContractRefused, resolve_contract, resolve_draft_document, resolve_engagement_pack, resolve_tenant_contract_document)
from .asset_fixture import pick
from .contract_fixture import FakeDocumentStore, envelope
from .test_engagement_drafts import COMPLETE
from .test_tenant_draft_setup import OWN_NODE, _SetupCase
from .test_tenant_drafts import GENERATED_AT, TENANCY_HKEY, ok, refused, snapshot_of

SIGNED_2 = b"%PDF-1.7\n%fixture signed second contract\n%%EOF\n"
GENERATED_2 = b"%PDF-1.7\n%fixture generated second contract\n%%EOF\n"
SIGNED_3 = b"%PDF-1.7\n%fixture signed third contract\n%%EOF\n"
GENERATED_3 = b"%PDF-1.7\n%fixture generated third contract\n%%EOF\n"
SHARED_A = {"node_address": "Node-A", "mode": "shared"}
PRIVATE_B = {"node_address": "Node-B", "mode": "private"}
SHARED_C = {"node_address": "Node-C", "mode": "shared"}
DRAFT_KEYS = {"tenant_id", "contract_id", "request_id", "state", "document", "generated", "effective_from",
              "effective_until", "nodes", "supersedes", "created_by", "created_at", "updated_by", "updated_at"}
ENTRY_KEYS = {"contractId", "state", "sha256", "effectiveFrom", "effectiveUntil", "nodes", "generatedSha256",
              "supersedes", "supersededBy"}


class _ContractSetCase(_SetupCase):
  def contract_draft(self, tenant_id, request_id=None, actor=None):
    return self.plugin.create_tenant_contract_draft(actor or self.actor, tenant_id, request_id or str(uuid4()))

  def update_contract(self, tenant_id, contract_id, changes, actor=None):
    return self.plugin.update_tenant_contract_draft(actor or self.actor, tenant_id, contract_id, changes)

  def generate_contract(self, tenant_id, contract_id, raw=GENERATED_2, snapshot=None, actor=None, ids=None):
    """`ids`: the id form sent instead of this contract draft's (a wrong or a doubled one)."""
    plan = self.stored_contract(tenant_id, contract_id)["nodes"] if snapshot is None else None
    return self.plugin.store_generated_document(
      actor or self.actor, document_kind="contract", filename="generated.pdf",
      content_b64=base64.b64encode(raw).decode("ascii"), snapshot=snapshot_of(plan) if snapshot is None else snapshot,
      generated_at=GENERATED_AT, **({"tenant_id": tenant_id, "contract_id": contract_id} if ids is None else ids))

  def upload_contract(self, tenant_id, contract_id, raw=SIGNED_2, actor=None):
    return self.plugin.upload_tenant_contract_document(actor or self.actor, tenant_id, contract_id, "signed.pdf",
                                                       base64.b64encode(raw).decode("ascii"))

  def ready_contract(self, tenant_id, nodes, signed=SIGNED_2, generated=GENERATED_2, effective_from="2027-01-01"):
    """A contract draft with its dates, plan, generated pack and signed copy: ready to activate."""
    contract_id = ok(self, self.contract_draft(tenant_id))["contract_id"]
    ok(self, self.update_contract(tenant_id, contract_id, {"effective_from": effective_from, "nodes": nodes}))
    ok(self, self.generate_contract(tenant_id, contract_id, raw=generated))
    ok(self, self.upload_contract(tenant_id, contract_id, raw=signed))
    return contract_id

  def activate_contract(self, tenant_id, contract_id, actor=None):
    return self.plugin.activate_tenant_contract(actor or self.actor, tenant_id, contract_id)

  def stored_contract(self, tenant_id, contract_id):
    return self.repo.get("tenant_contract_draft", tenant_id, contract_id)

  def tenant_row(self, tenant_id):
    return self.repo.get("tenant", tenant_id)

  def node_rows(self, tenant_id):
    return sorted((row["node_address"], row["mode"], row["active"]) for row in self.repo.list_node_assignments(tenant_id))

  def engagement(self, tenant_id, request_id=None, actor=None, **extra):
    asset = self.asset_in(tenant_id)
    return self.plugin.create_engagement(actor or self.actor, tenant_id, request_id or str(uuid4()),
                                         COMPLETE["display_name"], COMPLETE["valid_from"], COMPLETE["valid_until"],
                                         COMPLETE["context"], [pick(asset)], **extra)

  def second_contract_tenant(self, nodes=(SHARED_A,)):
    """An active, contract-fixed tenant with `c_2` activated for `nodes`: (tenant_id, c_2)."""
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    contract_id = self.ready_contract(tenant_id, list(nodes))
    ok(self, self.activate_contract(tenant_id, contract_id))
    return tenant_id, contract_id


class TestNumbering(_ContractSetCase):
  def test_ids_are_allocated_from_the_tenant_counter_and_never_reused(self):
    _, tenant_id = self.tenant("acme", fixed=True)
    first = ok(self, self.contract_draft(tenant_id))
    self.assertEqual((first["contract_id"], first["state"], first["nodes"], first["supersedes"]), ("c_2", "missing", [], None))
    self.assertEqual(set(first) - {"completeness"}, DRAFT_KEYS)
    self.assertEqual(first["completeness"]["missing"], ["field:effective_from", "field:nodes", "item:contract"])
    second = ok(self, self.contract_draft(tenant_id))
    self.assertEqual(second["contract_id"], "c_3")
    self.assertEqual(self.tenant_row(tenant_id)["next_contract_no"], 4)
    # The counter is on the tenant row before the draft row: the first write of a create is the tenant's.
    ok(self, self.plugin.delete_tenant_contract_draft(self.actor, tenant_id, "c_2"))
    self.assertIsNone(self.stored_contract(tenant_id, "c_2"))
    self.assertEqual(ok(self, self.contract_draft(tenant_id))["contract_id"], "c_4")
    rows = ok(self, self.plugin.list_tenant_contract_drafts(self.actor, tenant_id))
    self.assertEqual([row["contract_id"] for row in rows], ["c_3", "c_4"])
    self.assertEqual(set(rows[0]), {"contract_id", "state", "effective_from", "effective_until", "nodes_count",
                                    "supersedes", "created_at", "updated_at"})

  def test_a_create_replayed_with_the_same_request_id_answers_the_existing_draft(self):
    _, tenant_id = self.tenant("acme", fixed=True)
    request_id = str(uuid4())
    first = ok(self, self.contract_draft(tenant_id, request_id))
    writes = len(self.store.writes)
    again = ok(self, self.contract_draft(tenant_id, request_id))
    self.assertEqual(again, first)
    self.assertEqual(len(self.store.writes), writes)
    self.assertEqual(self.tenant_row(tenant_id)["next_contract_no"], 3)

  def test_a_tenant_without_a_contract_takes_no_contract_draft(self):
    _, tenant_id = self.tenant("acme", fixed=True)
    for (hkey, key), value in self.store.data.items():
      if hkey == TENANCY_HKEY and isinstance(value, dict) and value.get("tenant_id") == tenant_id:
        value.pop("contract", None), value.pop("legal", None), value.pop("contract_generated", None)
    refused(self, self.contract_draft(tenant_id), 400, "contract_required")
    self.assertEqual(ok(self, self.plugin.get_tenant(self.actor, tenant_id))["contracts"], [])

  def test_a_malformed_stored_row_fails_the_read_closed(self):
    _, tenant_id = self.tenant("acme", fixed=True)
    ok(self, self.contract_draft(tenant_id))
    key = json.dumps(["tenant_contract_draft", "deployment", tenant_id, "c_2"], separators=(",", ":"))
    good = self.store.data[(TENANCY_HKEY, key)]
    for label, change in {"unknown key": {"extra": 1}, "first id": {"contract_id": "c_1"},
                          "bad state": {"state": "done"}, "bad supersedes": {"supersedes": "c_2"},
                          "bad nodes": {"nodes": [{"node_address": "Node-A"}]},
                          "bad request": {"request_id": "x"}}.items():
      with self.subTest(label):
        self.store.data[(TENANCY_HKEY, key)] = {**good, **change}
        with self.assertRaises(TenantStoreError):
          self.repo.get("tenant_contract_draft", tenant_id, "c_2")
    self.store.data[(TENANCY_HKEY, key)] = good
    self.assertIsNotNone(self.repo.get("tenant_contract_draft", tenant_id, "c_2"))

  def test_only_a_full_portfolio_super_tenant_admin_on_an_active_tenant(self):
    _, tenant_id = self.tenant("acme", fixed=True)
    self.store.grant("acme.admin", tenant_id)
    contract_id = ok(self, self.contract_draft(tenant_id))["contract_id"]
    calls = {
      "create": lambda actor: self.contract_draft(tenant_id, actor=actor),
      "list": lambda actor: self.plugin.list_tenant_contract_drafts(actor, tenant_id),
      "get": lambda actor: self.plugin.get_tenant_contract_draft(actor, tenant_id, contract_id),
      "update": lambda actor: self.update_contract(tenant_id, contract_id, {"effective_from": "2027-01-01"}, actor=actor),
      "upload": lambda actor: self.upload_contract(tenant_id, contract_id, actor=actor),
      "generate": lambda actor: self.generate_contract(tenant_id, contract_id, actor=actor),
      "delete": lambda actor: self.plugin.delete_tenant_contract_draft(actor, tenant_id, contract_id),
      "activate": lambda actor: self.activate_contract(tenant_id, contract_id, actor=actor),
      "contract read": lambda actor: self.plugin.get_tenant_contract(actor, tenant_id, contract_id),
    }
    for label, call in calls.items():
      with self.subTest(label):
        refused(self, call({"account_id": "acme.admin"}), 403, "forbidden")
        refused(self, call({"account_id": "scoped-sta"}), 404, "not_found")
    # A draft id is never a tenant id.
    refused(self, self.plugin.get_tenant_contract_draft(self.actor, "td_" + str(uuid4()), contract_id), 404, "not_found")


class TestLifecycle(_ContractSetCase):
  def test_the_contract_is_generated_signed_and_activated_onto_the_tenant(self):
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    contract_id = ok(self, self.contract_draft(tenant_id))["contract_id"]
    draft = ok(self, self.update_contract(tenant_id, contract_id,
                                          {"effective_from": "2027-01-01", "effective_until": "2027-12-31",
                                           "nodes": [PRIVATE_B, SHARED_A]}))
    self.assertEqual(draft["nodes"], [SHARED_A, PRIVATE_B])
    self.assertEqual(draft["completeness"]["missing"], ["item:contract"])
    # Generation binds the plan; the envelope names the tenant and the contract id in the contract slot.
    generated = ok(self, self.generate_contract(tenant_id, contract_id))
    self.assertEqual((generated["state"], generated["generated"]["nodes"]), ("generated", [SHARED_A, PRIVATE_B]))
    stored = self.documents.envelopes[generated["generated"]["ref"]]
    self.assertEqual((stored["schema_version"], stored["document_kind"], stored["tenant_id"], stored["contract_id"],
                      stored["role"]), ("1.1", "contract", tenant_id, contract_id, "generated"))
    self.assertNotIn("draft_id", stored)
    signed = ok(self, self.upload_contract(tenant_id, contract_id))
    self.assertEqual((signed["state"], signed["document"]["sha256"]), ("signed", hashlib.sha256(SIGNED_2).hexdigest()))
    self.assertEqual(signed["completeness"], {"complete": True, "missing": []})
    stored = self.documents.envelopes[signed["document"]["ref"]]
    self.assertEqual((stored["document_kind"], stored["tenant_id"], stored["contract_id"]), ("contract", tenant_id, contract_id))
    self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", True)])
    activated = ok(self, self.activate_contract(tenant_id, contract_id))
    self.assertEqual(activated, {"tenantId": tenant_id, "contractId": contract_id, "replayed": False})
    self.assertEqual(self.events[-1][0], "tenant_contract_activated")
    # The block on the tenant row, the draft row gone, the private node assigned, the shared one kept.
    tenant = self.tenant_row(tenant_id)
    block = tenant["contracts"][contract_id]
    self.assertEqual(set(block), {"contract", "contract_generated", "effective_from", "effective_until", "nodes",
                                  "activated_by", "activated_at", "supersedes", "superseded_by"})
    self.assertEqual((block["contract"], block["contract_generated"]["nodes"], block["effective_from"],
                      block["effective_until"], block["nodes"], block["activated_by"], block["supersedes"], block["superseded_by"]),
                     (signed["document"], [SHARED_A, PRIVATE_B], "2027-01-01", "2027-12-31", [SHARED_A, PRIVATE_B],
                      "creator", None, None))
    self.assertIsNone(self.stored_contract(tenant_id, contract_id))
    self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", True), ("Node-B", "private", True)])
    # `c_1` is untouched: its fields, its receipt binding and every existing reader.
    self.assertEqual(tenant["contract"]["sha256"], ok(self, self.plugin.get_tenant_contract(self.actor, tenant_id))["contract"]["sha256"])
    # A replay answers without writing; a draft row left behind by a crash goes with it.
    writes = len(self.store.writes)
    self.assertEqual(ok(self, self.activate_contract(tenant_id, contract_id))["replayed"], True)
    self.assertEqual(len(self.store.writes), writes)
    self.repo.put("tenant_contract_draft", tenant_id, contract_id, record={key: draft[key] for key in DRAFT_KEYS})
    self.assertEqual(ok(self, self.activate_contract(tenant_id, contract_id))["replayed"], True)
    self.assertIsNone(self.stored_contract(tenant_id, contract_id))

  def test_the_tenant_lists_its_contracts_to_every_member_without_file_names(self):
    tenant_id, contract_id = self.second_contract_tenant(nodes=[SHARED_A, PRIVATE_B])
    self.store.grant("acme.admin", tenant_id)
    for actor in (self.actor, {"account_id": "acme.admin"}):
      with self.subTest(actor=actor["account_id"]):
        contracts = ok(self, self.plugin.get_tenant(actor, tenant_id))["contracts"]
        self.assertEqual([entry["contractId"] for entry in contracts], ["c_1", contract_id])
        for entry in contracts:
          self.assertEqual(set(entry), ENTRY_KEYS)
          self.assertEqual(entry["state"], "active")
        self.assertEqual(contracts[0]["nodes"], [{"nodeAddress": "Node-A", "mode": "shared"}])
        self.assertEqual(contracts[0]["effectiveFrom"], "2026-11-01")
        self.assertEqual(contracts[1]["nodes"], [{"nodeAddress": "Node-A", "mode": "shared"}, {"nodeAddress": "Node-B", "mode": "private"}])
        self.assertEqual((contracts[1]["effectiveFrom"], contracts[1]["sha256"]),
                         ("2027-01-01", hashlib.sha256(SIGNED_2).hexdigest()))
        self.assertEqual((contracts[1]["supersedes"], contracts[1]["supersededBy"]), (None, None))
    # The file name and the download stay on the platform-only per-contract read.
    record = ok(self, self.plugin.get_tenant_contract(self.actor, tenant_id, contract_id))
    self.assertEqual((record["contract"]["filename"], record["contract_id"], record["nodes"], record["framework_agreement"]),
                     ("signed.pdf", contract_id, [SHARED_A, PRIVATE_B], None))
    downloaded = ok(self, self.plugin.download_tenant_contract(self.actor, tenant_id, contract_id))
    self.assertEqual(base64.b64decode(downloaded["content_b64"]), SIGNED_2)
    self.assertEqual(ok(self, self.plugin.download_tenant_document(self.actor, tenant_id, "contract", contract_id))["sha256"],
                     hashlib.sha256(SIGNED_2).hexdigest())
    refused(self, self.plugin.get_tenant_contract({"account_id": "acme.admin"}, tenant_id, contract_id), 403, "forbidden")
    refused(self, self.plugin.get_tenant_contract(self.actor, tenant_id, "c_9"), 404, "not_found")
    refused(self, self.plugin.get_tenant_contract(self.actor, tenant_id, "nine"), 400, "invalid_request")

  def test_activation_refusals_write_nothing(self):
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    contract_id = ok(self, self.contract_draft(tenant_id))["contract_id"]
    writes = len(self.store.writes)
    result = self.activate_contract(tenant_id, contract_id)
    refused(self, result, 409, "draft_incomplete")
    self.assertEqual(result["missing"], ["field:effective_from", "field:nodes", "item:contract"])
    ok(self, self.update_contract(tenant_id, contract_id, {"effective_from": "2027-01-01", "nodes": [SHARED_C]}))
    ok(self, self.upload_contract(tenant_id, contract_id))
    # Signed without a generated pack: stale.
    result = self.activate_contract(tenant_id, contract_id)
    refused(self, result, 409, "draft_incomplete")
    self.assertEqual(result["missing"], ["item:contract_stale"])
    ok(self, self.update_contract(tenant_id, contract_id, {"state": "missing"}))
    ok(self, self.generate_contract(tenant_id, contract_id))
    ok(self, self.upload_contract(tenant_id, contract_id))
    # A file that moved or no longer verifies.
    row = self.stored_contract(tenant_id, contract_id)
    self.documents.envelopes[row["document"]["ref"]]["contract_id"] = "c_9"
    refused(self, self.activate_contract(tenant_id, contract_id), 400, "contract_invalid")
    self.documents.envelopes[row["document"]["ref"]]["contract_id"] = contract_id
    # An uploader without the platform role.
    self.store.account("demoted")
    self.documents.envelopes[row["document"]["ref"]]["uploaded_by"] = "demoted"
    row["document"]["uploaded_by"] = "demoted"
    self.repo.put("tenant_contract_draft", tenant_id, contract_id, record=row)
    refused(self, self.activate_contract(tenant_id, contract_id), 400, "contract_invalid")
    self.assertNotIn("contracts", self.tenant_row(tenant_id))
    self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", True)])
    self.assertIsNotNone(self.stored_contract(tenant_id, contract_id))

  def test_a_signed_draft_locks_its_plan_and_keeps_its_files_on_delete(self):
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    contract_id = self.ready_contract(tenant_id, [SHARED_C])
    refused(self, self.update_contract(tenant_id, contract_id, {"nodes": [SHARED_A]}), 409, "nodes_locked")
    refused(self, self.generate_contract(tenant_id, contract_id), 409, "already_signed")
    refused(self, self.plugin.delete_tenant_contract_draft(self.actor, tenant_id, contract_id), 409, "draft_has_signed_documents")
    ok(self, self.update_contract(tenant_id, contract_id, {"state": "missing"}))
    refs = [self.documents.puts[-1]["sha256"]]
    deleted = ok(self, self.plugin.delete_tenant_contract_draft(self.actor, tenant_id, contract_id))
    self.assertEqual(deleted, {"contract_id": contract_id, "files_deleted": 1})
    self.assertIsNone(self.stored_contract(tenant_id, contract_id))
    self.assertEqual(self.events[-1][0], "tenant_contract_draft_deleted")
    del refs

  def test_the_id_forms_of_generation_are_exclusive_and_the_plan_is_bound(self):
    draft_id, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    contract_id = ok(self, self.contract_draft(tenant_id))["contract_id"]
    ok(self, self.update_contract(tenant_id, contract_id, {"nodes": [SHARED_C]}))
    refused(self, self.generate_contract(tenant_id, contract_id,
                                         ids={"draft_id": draft_id, "tenant_id": tenant_id, "contract_id": contract_id}),
            400, "invalid_request")
    refused(self, self.generate_contract(tenant_id, contract_id, snapshot=snapshot_of([SHARED_A])), 409, "draft_changed")
    refused(self, self.generate_contract(tenant_id, contract_id, ids={"tenant_id": tenant_id, "contract_id": "c_9"}), 404, "not_found")
    self.assertIsNone(self.stored_contract(tenant_id, contract_id)["generated"])


class TestNodesAcrossTheSet(_ContractSetCase):
  def test_a_shared_node_is_accepted_in_the_same_mode_and_refused_in_another(self):
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    second = self.ready_contract(tenant_id, [SHARED_A, PRIVATE_B])
    ok(self, self.activate_contract(tenant_id, second))
    self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", True), ("Node-B", "private", True)])
    nodes = ok(self, self.plugin.get_tenant_nodes(self.actor, tenant_id))
    self.assertEqual((nodes["nodesFixed"], nodes["canManageAssignments"]), (True, False))
    # The other mode is refused at the plan write already (the node has a live assignment)...
    third = ok(self, self.contract_draft(tenant_id))["contract_id"]
    private_a = {"node_address": "Node-A", "mode": "private"}
    refused(self, self.update_contract(tenant_id, third, {"nodes": [private_a]}), 409, "node_shared_assigned")
    # ...and at activation, naming the node, when the plan was written before the assignment existed.
    third = self.ready_contract(tenant_id, [SHARED_C], signed=SIGNED_3, generated=GENERATED_3)
    row = self.stored_contract(tenant_id, third)
    row["nodes"] = [private_a]
    row["generated"]["nodes"] = [private_a]
    self.repo.put("tenant_contract_draft", tenant_id, third, record=row)
    tenant_before = self.tenant_row(tenant_id)
    result = self.activate_contract(tenant_id, third)
    refused(self, result, 409, "contract_nodes_unavailable")
    self.assertEqual(result["nodes"], [{"nodeAddress": "Node-A", "error": "node_shared_assigned"}])
    self.assertEqual(self.tenant_row(tenant_id), tenant_before)
    self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", True), ("Node-B", "private", True)])
    self.assertIsNotNone(self.stored_contract(tenant_id, third))
    # Another tenant's node is refused as before, naming it.
    _, other = self.tenant("other", nodes=[SHARED_C], fixed=True)
    self.assertEqual(self.node_rows(other), [("Node-C", "shared", True)])
    row = self.stored_contract(tenant_id, third)
    row["nodes"] = [{"node_address": "Node-C", "mode": "private"}]
    row["generated"]["nodes"] = row["nodes"]
    self.repo.put("tenant_contract_draft", tenant_id, third, record=row)
    result = self.activate_contract(tenant_id, third)
    refused(self, result, 409, "contract_nodes_unavailable")
    self.assertEqual(result["nodes"], [{"nodeAddress": "Node-C", "error": "node_shared_assigned"}])

  def test_a_tenant_whose_first_contract_lists_no_nodes_becomes_fixed_with_the_second(self):
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A])
    ok(self, self.assign(tenant_id, "Node-C"))
    self.assertEqual(ok(self, self.plugin.get_tenant_nodes(self.actor, tenant_id))["nodesFixed"], False)
    second = self.ready_contract(tenant_id, [SHARED_A])
    ok(self, self.activate_contract(tenant_id, second))
    self.assertEqual(ok(self, self.plugin.get_tenant_nodes(self.actor, tenant_id))["nodesFixed"], True)
    refused(self, self.plugin.set_tenant_node_assignment(self.actor, tenant_id, "Node-C", False), 409, "nodes_fixed_by_contract")
    # An assignment the tenant already holds is still answered.
    self.assertEqual(ok(self, self.assign(tenant_id, "Node-A"))["state"], "assigned")

  def test_a_private_plan_holds_the_node_from_the_plan_write_until_the_draft_goes(self):
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    _, other = self.tenant("other", nodes=[SHARED_C])
    contract_id = ok(self, self.contract_draft(tenant_id))["contract_id"]
    ok(self, self.update_contract(tenant_id, contract_id, {"nodes": [PRIVATE_B]}))
    result = self.assign(other, "Node-B")
    refused(self, result, 409, "node_planned_private")
    self.assertEqual(result["holder"], {"tenant_id": tenant_id, "contract_id": contract_id})
    # A tenant draft cannot plan it either.
    draft_id = self.create()["draft_id"]
    refused(self, self.plan(draft_id, [PRIVATE_B]), 409, "node_planned_private")
    ok(self, self.plugin.delete_tenant_contract_draft(self.actor, tenant_id, contract_id))
    self.assertEqual(ok(self, self.assign(other, "Node-B"))["state"], "assigned")


class TestInUseAndDelete(_ContractSetCase):
  def test_a_further_contracts_files_are_in_use_everywhere(self):
    tenant_id, contract_id = self.second_contract_tenant()
    block = self.tenant_row(tenant_id)["contracts"][contract_id]
    # Another contract draft pointed at the same signed copy, by its row: refused at activation.
    third = self.ready_contract(tenant_id, [SHARED_A], signed=SIGNED_3, generated=GENERATED_3)
    row = self.stored_contract(tenant_id, third)
    row["document"] = dict(block["contract"])
    self.repo.put("tenant_contract_draft", tenant_id, third, record=row)
    self.documents.envelopes[block["contract"]["ref"]]["contract_id"] = third
    refused(self, self.activate_contract(tenant_id, third), 409, "contract_in_use")
    # A one-step creation bound to it (service level: the resolver would refuse the envelope first).
    service = self.plugin._execution_service()
    self.store.account("initial-2")
    result = service.prepare_tenant(self.actor, str(uuid4()), "Other", "other", "initial-2",
                                    legal={"name": "Other SRL", "registration_id": "RO2", "signer_name": "A", "signer_role": "B"},
                                    contract=dict(block["contract"]))
    refused(self, result, 409, "contract_in_use")
    # And a contract draft's own files, before activation, hold their refs too.
    fourth = self.ready_contract(tenant_id, [SHARED_A], signed=b"%PDF-1.7\n%four\n%%EOF\n", generated=b"%PDF-1.7\n%gen four\n%%EOF\n")
    held = self.stored_contract(tenant_id, fourth)["document"]
    result = service.prepare_tenant(self.actor, str(uuid4()), "Other", "other", "initial-2",
                                    legal={"name": "Other SRL", "registration_id": "RO2", "signer_name": "A", "signer_role": "B"},
                                    contract=dict(held))
    refused(self, result, 409, "contract_in_use")

  def test_tenant_delete_lists_and_removes_every_contract_file_and_draft(self):
    tenant_id, contract_id = self.second_contract_tenant()
    block = self.tenant_row(tenant_id)["contracts"][contract_id]
    third = self.ready_contract(tenant_id, [SHARED_A], signed=SIGNED_3, generated=GENERATED_3)
    draft = self.stored_contract(tenant_id, third)
    service = self.plugin._execution_service()
    begun = ok(self, service.begin_tenant_delete(self.actor, tenant_id, mark=True))
    refs = {entry["ref"] for entry in begun["documentRefs"]}
    for expected in (block["contract"]["ref"], block["contract_generated"]["ref"], draft["document"]["ref"], draft["generated"]["ref"]):
      self.assertIn(expected, refs)
    ok(self, service.record_tenant_documents_deleted(self.actor, tenant_id, sorted(refs)))
    finished = ok(self, service.finish_tenant_delete(self.actor, tenant_id))
    self.assertEqual(finished["contractDrafts"], 1)
    self.assertIsNone(self.repo.get("tenant_contract_draft", tenant_id, third))
    self.assertIsNone(self.repo.get("tenant", tenant_id))


class TestEngagementsPickAContract(_ContractSetCase):
  def test_an_engagement_binds_to_the_picked_contract_and_replays(self):
    tenant_id, contract_id = self.second_contract_tenant()
    tenant = self.tenant_row(tenant_id)
    first = ok(self, self.engagement(tenant_id))
    self.assertEqual(first["contractSha256"], tenant["contract"]["sha256"])
    request_id = str(uuid4())
    second = ok(self, self.engagement(tenant_id, request_id, contract_id=contract_id))
    self.assertEqual(second["contractSha256"], tenant["contracts"][contract_id]["contract"]["sha256"])
    self.assertNotIn("contractId", second)
    # Replays: the intent carries the pick only when it was sent.
    self.assertEqual(ok(self, self.engagement(tenant_id, request_id, contract_id=contract_id))["replayed"], True)
    refused(self, self.engagement(tenant_id, request_id), 409, "conflict")
    pre_upgrade = str(uuid4())
    ok(self, self.engagement(tenant_id, pre_upgrade))
    self.assertEqual(ok(self, self.engagement(tenant_id, pre_upgrade))["replayed"], True)
    for label, bad in {"unknown": "c_9", "malformed": "two", "first id spelled": "c_01"}.items():
      with self.subTest(label):
        refused(self, self.engagement(tenant_id, contract_id=bad), 400, "contract_unknown")
    # `c_1` spelled out is the default.
    self.assertEqual(ok(self, self.engagement(tenant_id, contract_id="c_1"))["contractSha256"], tenant["contract"]["sha256"])
    # The launch gate accepts both contracts of the set.
    service = self.plugin._execution_service()
    self.store.grant("acme.admin", tenant_id)
    for engagement in (first, second):
      with self.subTest(engagement["engagementId"]):
        service.resolve_execution_admission(self.actor, tenant_id, engagement["engagementId"], "ea_1")
    # A sha256 outside the set is a damaged record.
    row = self.repo.get("engagement", tenant_id, second["engagementId"])
    self.store.data[(TENANCY_HKEY, json.dumps(["engagement", "deployment", tenant_id, second["engagementId"]], separators=(",", ":")))] = \
      {**row, "contract_sha256": "f" * 64}
    with self.assertRaises(TenantStoreError):
      service.resolve_execution_admission(self.actor, tenant_id, second["engagementId"], "ea_1")

  def test_an_engagement_draft_stores_the_pick_and_activation_binds_it(self):
    tenant_id, contract_id = self.second_contract_tenant()
    child = self.child(tenant_id)["engagement_draft_id"]
    self.assertIsNone(self.stored_child(child).get("contract_id"))
    self.assertIsNone(ok(self, self.plugin.get_engagement_draft(self.actor, child))["contract_id"])
    refused(self, self.update_child(child, {"contract_id": "c_9"}), 400, "contract_unknown")
    refused(self, self.update_child(child, {"contract_id": "nine"}), 400, "contract_unknown")
    picked = ok(self, self.update_child(child, {"contract_id": contract_id}))
    self.assertEqual(picked["contract_id"], contract_id)
    self.assertEqual(self.stored_child(child)["contract_id"], contract_id)
    self.assertIsNone(ok(self, self.update_child(child, {"contract_id": ""}))["contract_id"])
    ok(self, self.update_child(child, {"contract_id": contract_id}))
    # Under a tenant draft there is one contract: no pick.
    draft_id = self.create()["draft_id"]
    under_draft = self.child(draft_id)["engagement_draft_id"]
    refused(self, self.update_child(under_draft, {"contract_id": "c_2"}), 400, "contract_unknown")
    self.fill(child)
    ok(self, self.upload_pack(child))
    activated = ok(self, self.plugin.activate_engagement_draft(self.actor, child))
    engagement = ok(self, self.plugin.get_engagement(self.actor, tenant_id, activated["engagementId"]))["engagement"]
    self.assertEqual(engagement["contractSha256"], self.tenant_row(tenant_id)["contracts"][contract_id]["contract"]["sha256"])
    # A row written before the pick existed reads as no pick.
    other = self.child(tenant_id)["engagement_draft_id"]
    key = json.dumps(["engagement_draft", "deployment", other], separators=(",", ":"))
    del self.store.data[(TENANCY_HKEY, key)]["contract_id"]
    self.assertIsNone(ok(self, self.plugin.get_engagement_draft(self.actor, other))["contract_id"])
    self.store.data[(TENANCY_HKEY, key)]["contract_id"] = "nine"
    refused(self, self.plugin.get_engagement_draft(self.actor, other), 503, "unavailable")


class TestRevisions(_ContractSetCase):
  """RM-133 step 3: a contract draft created with `supersedes` is a revision, prefilled from the
  contract it replaces; activation links both ways; the replaced contract stays in force for its
  own engagements and takes no new one."""

  def revision(self, tenant_id, supersedes, signed=SIGNED_3, generated=GENERATED_3, nodes=None):
    draft = ok(self, self.plugin.create_tenant_contract_draft(self.actor, tenant_id, str(uuid4()), supersedes=supersedes))
    if nodes is not None:
      ok(self, self.update_contract(tenant_id, draft["contract_id"], {"nodes": nodes}))
    ok(self, self.generate_contract(tenant_id, draft["contract_id"], raw=generated))
    ok(self, self.upload_contract(tenant_id, draft["contract_id"], raw=signed))
    return draft

  def test_a_revision_is_prefilled_from_the_contract_it_replaces(self):
    tenant_id, second = self.second_contract_tenant(nodes=[SHARED_A, PRIVATE_B])
    draft = ok(self, self.plugin.create_tenant_contract_draft(self.actor, tenant_id, str(uuid4()), supersedes="c_1"))
    self.assertEqual((draft["contract_id"], draft["supersedes"], draft["nodes"], draft["state"]), ("c_3", "c_1", [SHARED_A], "missing"))
    self.assertEqual(draft["effective_from"], datetime.now(timezone.utc).date().isoformat())
    self.assertIsNone(draft["effective_until"])
    other = ok(self, self.plugin.create_tenant_contract_draft(self.actor, tenant_id, str(uuid4()), supersedes=second))
    self.assertEqual((other["supersedes"], other["nodes"]), (second, [SHARED_A, PRIVATE_B]))
    rows = ok(self, self.plugin.list_tenant_contract_drafts(self.actor, tenant_id))
    self.assertEqual([(row["contract_id"], row["supersedes"]) for row in rows], [("c_3", "c_1"), ("c_4", second)])
    refused(self, self.plugin.create_tenant_contract_draft(self.actor, tenant_id, str(uuid4()), supersedes="c_9"), 400, "contract_unknown")
    refused(self, self.plugin.create_tenant_contract_draft(self.actor, tenant_id, str(uuid4()), supersedes="nine"), 400, "contract_unknown")
    # A plain further contract (no `supersedes`) starts empty, as before.
    plain = ok(self, self.plugin.create_tenant_contract_draft(self.actor, tenant_id, str(uuid4()), supersedes=""))
    self.assertEqual((plain["supersedes"], plain["nodes"], plain["effective_from"]), (None, [], None))

  def test_activation_links_both_contracts_and_the_old_one_keeps_its_engagements(self):
    tenant_id, second = self.second_contract_tenant(nodes=[SHARED_A])
    old = ok(self, self.engagement(tenant_id))
    picked = ok(self, self.engagement(tenant_id, contract_id=second))
    revision = self.revision(tenant_id, "c_1")
    ok(self, self.activate_contract(tenant_id, revision["contract_id"]))
    tenant = self.tenant_row(tenant_id)
    self.assertEqual(tenant["contract_superseded_by"], revision["contract_id"])
    self.assertEqual(tenant["contracts"][revision["contract_id"]]["supersedes"], "c_1")
    self.assertIsNone(tenant["contracts"][revision["contract_id"]]["superseded_by"])
    contracts = ok(self, self.plugin.get_tenant(self.actor, tenant_id))["contracts"]
    self.assertEqual([(entry["contractId"], entry["supersedes"], entry["supersededBy"]) for entry in contracts],
                     [("c_1", None, revision["contract_id"]), (second, None, None), (revision["contract_id"], "c_1", None)])
    self.assertEqual(ok(self, self.plugin.get_tenant_contract(self.actor, tenant_id))["superseded_by"], revision["contract_id"])
    # The old engagements still launch under the replaced contract; a new one on it is refused.
    service = self.plugin._execution_service()
    for engagement in (old, picked):
      service.resolve_execution_admission(self.actor, tenant_id, engagement["engagementId"], "ea_1")
    refused(self, self.engagement(tenant_id), 409, "contract_superseded")
    refused(self, self.engagement(tenant_id, contract_id="c_1"), 409, "contract_superseded")
    self.assertEqual(ok(self, self.engagement(tenant_id, contract_id=revision["contract_id"]))["contractSha256"],
                     tenant["contracts"][revision["contract_id"]]["contract"]["sha256"])
    # Nothing is released: the union still holds c_1's node.
    self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", True)])
    refused(self, self.plugin.set_tenant_node_assignment(self.actor, tenant_id, "Node-A", False), 409, "nodes_fixed_by_contract")
    # A further contract (`c_2`) can be revised too: the block carries the link.
    again = self.revision(tenant_id, second, signed=b"%PDF-1.7\n%five\n%%EOF\n", generated=b"%PDF-1.7\n%gen five\n%%EOF\n")
    ok(self, self.activate_contract(tenant_id, again["contract_id"]))
    tenant = self.tenant_row(tenant_id)
    self.assertEqual(tenant["contracts"][second]["superseded_by"], again["contract_id"])
    refused(self, self.engagement(tenant_id, contract_id=second), 409, "contract_superseded")

  def test_a_contract_is_replaced_once_and_a_revision_of_a_replaced_one_is_refused(self):
    tenant_id, _ = self.second_contract_tenant()
    first = self.revision(tenant_id, "c_1")
    rival = self.revision(tenant_id, "c_1", signed=b"%PDF-1.7\n%rival\n%%EOF\n", generated=b"%PDF-1.7\n%gen rival\n%%EOF\n")
    ok(self, self.activate_contract(tenant_id, first["contract_id"]))
    tenant_before = self.tenant_row(tenant_id)
    refused(self, self.activate_contract(tenant_id, rival["contract_id"]), 409, "contract_superseded")
    self.assertEqual(self.tenant_row(tenant_id), tenant_before)
    self.assertIsNotNone(self.stored_contract(tenant_id, rival["contract_id"]))
    refused(self, self.plugin.create_tenant_contract_draft(self.actor, tenant_id, str(uuid4()), supersedes="c_1"), 409, "contract_superseded")

  def test_an_engagement_draft_on_a_replaced_contract_stays_editable_and_is_re_pointed(self):
    tenant_id, second = self.second_contract_tenant()
    child = self.child(tenant_id)["engagement_draft_id"]
    ok(self, self.update_child(child, {"contract_id": "c_1"}))
    revision = self.revision(tenant_id, "c_1")
    ok(self, self.activate_contract(tenant_id, revision["contract_id"]))
    # Other fields still save; activation on the replaced contract is refused; a re-pick activates.
    self.fill(child)
    ok(self, self.upload_pack(child))
    refused(self, self.plugin.activate_engagement_draft(self.actor, child), 409, "contract_superseded")
    self.assertIsNotNone(self.stored_child(child))
    ok(self, self.update_child(child, {"contract_id": revision["contract_id"]}))
    activated = ok(self, self.plugin.activate_engagement_draft(self.actor, child))
    engagement = ok(self, self.plugin.get_engagement(self.actor, tenant_id, activated["engagementId"]))["engagement"]
    self.assertEqual(engagement["contractSha256"], self.tenant_row(tenant_id)["contracts"][revision["contract_id"]]["contract"]["sha256"])
    # A re-pick onto the replaced contract is refused on the write.
    other = self.child(tenant_id)["engagement_draft_id"]
    refused(self, self.update_child(other, {"contract_id": "c_1"}), 409, "contract_superseded")


class TestEnvelopeBinding(_ContractSetCase):
  def test_a_contract_drafts_file_passes_no_other_resolver_and_the_reverse(self):
    tenant_id = "tn_" + str(uuid4())
    documents = FakeDocumentStore()
    documents.envelopes["c2"] = envelope(schema_version="1.1", document_kind="contract", tenant_id=tenant_id, contract_id="c_2")
    documents.envelopes["one"] = envelope()
    documents.envelopes["draft"] = envelope(schema_version="1.1", document_kind="contract", draft_id="td_" + str(uuid4()))
    documents.envelopes["pack"] = envelope(schema_version="1.1", document_kind="engagement_pack", engagement_draft_id="ted_" + str(uuid4()))
    self.assertEqual(resolve_tenant_contract_document(documents, "c2", tenant_id=tenant_id, contract_id="c_2")["sha256"],
                     documents.envelopes["c2"]["sha256"])
    for label, call in {
      "one-step": lambda: resolve_contract(documents, "c2"),
      "draft": lambda: resolve_draft_document(documents, "c2", draft_id="td_" + str(uuid4()), document_kind="contract"),
      "pack": lambda: resolve_engagement_pack(documents, "c2", engagement_draft_id="ted_" + str(uuid4())),
      "other tenant": lambda: resolve_tenant_contract_document(documents, "c2", tenant_id="tn_" + str(uuid4()), contract_id="c_2"),
      "other id": lambda: resolve_tenant_contract_document(documents, "c2", tenant_id=tenant_id, contract_id="c_3"),
      "a one-step file": lambda: resolve_tenant_contract_document(documents, "one", tenant_id=tenant_id, contract_id="c_2"),
      "a draft file": lambda: resolve_tenant_contract_document(documents, "draft", tenant_id=tenant_id, contract_id="c_2"),
      "an engagement pack": lambda: resolve_tenant_contract_document(documents, "pack", tenant_id=tenant_id, contract_id="c_2"),
    }.items():
      with self.subTest(label):
        with self.assertRaises(ContractRefused) as refusal:
          call()
        self.assertEqual(refusal.exception.status_code, 400)
    self.assertEqual(resolve_contract(documents, "one")["ref"], "one")
