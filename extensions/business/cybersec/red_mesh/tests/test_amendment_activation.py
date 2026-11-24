"""RM-249 phase 1b: an amendment's activation moves the tenant's engagements. The amendment note; a
replacement draft picks the pending amendment and goes live only through its activation; the guard
(`engagements_to_move`) and the writes in order (tenant row, nodes, copies, release), finished by a
repeated call and audited at least once; `copy_failed`. Real plugin endpoints, service and adapters."""
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import (
  CstoreTenantAdministrationStore,
)
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError

from .asset_fixture import pick
from .test_engagement_drafts import COMPLETE, PACK_PDF
from .test_tenant_contracts import PRIVATE_B, SHARED_A, SHARED_C, _ContractSetCase
from .test_tenant_drafts import ok, refused, snapshot_of

NOTE = "Continues c_1; Node-A is dropped."


class _AmendmentCase(_ContractSetCase):
  def setUp(self):
    super().setUp()
    # One service for every call, so its clock stays inside the engagement window and its job reader is ours.
    self.service = self.admission_service()
    self.plugin._execution_service = lambda: self.service
    self.busy = set()
    self.service.tenant_node_jobs_reader = lambda tenant_id, node_address: node_address in self.busy
    self.count = 0

  def scenario(self, nodes=(SHARED_A,), fixed=True):
    """A tenant with one live engagement on `c_1`: (tenant_id, engagement id)."""
    self.count += 1
    _, tenant_id = self.tenant("acme%d" % self.count, nodes=list(nodes), fixed=fixed)
    return tenant_id, ok(self, self.engagement(tenant_id))["engagementId"]

  def copy(self, tenant_id, old_id, contract_id, sign=True, raw=PACK_PDF):
    """A replacement draft of `old_id` that picks the amendment draft `contract_id`."""
    draft_id = ok(self, self.plugin.create_engagement_draft(
      self.actor, tenant_id, str(uuid4()), "Copy", supersedes=old_id))["engagement_draft_id"]
    ok(self, self.update_child(draft_id, {"contract_id": contract_id}))
    self.fill(draft_id)
    if sign:
      ok(self, self.upload_pack(draft_id, raw=raw))
    return draft_id

  def crash(self, kind, when, delete=False):
    """Every write (or delete) of `kind` for which `when(ids, record)` holds raises a store failure."""
    name = "delete" if delete else "put"
    real = getattr(CstoreTenantAdministrationStore, name)

    def wrapped(store, row_kind, *ids, record=None):
      if row_kind == kind and when(ids, record):
        raise TenantStoreError("crash")
      return real(store, row_kind, *ids, **({} if delete else {"record": record}))
    return patch.object(CstoreTenantAdministrationStore, name, wrapped)

  def live_ids(self, tenant_id):
    return sorted(row["engagement_id"] for row in self.repo.list_engagements(tenant_id) if row["active"])


class TestAmendmentNote(_AmendmentCase):
  def test_the_note_is_printed_in_the_pack_locked_with_the_signed_copy_and_optional_in_old_rows(self):
    tenant_id, old_id = self.scenario()
    ok(self, self.plugin.revoke_engagement(self.actor, tenant_id, old_id, "ended"))
    contract_id = ok(self, self.contract_draft(tenant_id))["contract_id"]
    refused(self, self.update_contract(tenant_id, contract_id, {"note": "x" * 2001}), 400, "invalid_request")
    for bad in ("a\u2028b", "a\u2029b", "a\ud800b", "a\u202eb", "a\rb"):
      refused(self, self.update_contract(tenant_id, contract_id, {"note": bad}), 400, "invalid_request")
    ok(self, self.update_contract(tenant_id, contract_id, {"effective_from": "2027-01-01", "note": NOTE}))
    plan = self.stored_contract(tenant_id, contract_id)["nodes"]
    # The pack prints the note: a snapshot of another note is not of this draft.
    refused(self, self.generate_contract(tenant_id, contract_id, snapshot=snapshot_of(plan)), 409, "draft_changed")
    generated = ok(self, self.generate_contract(tenant_id, contract_id, snapshot=snapshot_of(plan, note=NOTE)))
    self.assertEqual(generated["generated"]["note"], NOTE)
    # A note change makes the pack stale until it is generated again.
    stale = ok(self, self.update_contract(tenant_id, contract_id, {"note": "Another note"}))
    self.assertEqual(stale["completeness"]["missing"], ["item:contract", "item:contract_stale"])
    ok(self, self.update_contract(tenant_id, contract_id, {"note": NOTE}))
    ok(self, self.upload_contract(tenant_id, contract_id))
    refused(self, self.update_contract(tenant_id, contract_id, {"note": None}), 409, "note_locked")
    ok(self, self.activate_contract(tenant_id, contract_id))
    self.assertEqual(self.tenant_row(tenant_id)["contracts"][contract_id]["note"], NOTE)
    # Rows written before the note have none and still read.
    tenant = self.tenant_row(tenant_id)
    old_block = {key: value for key, value in tenant["contracts"][contract_id].items() if key != "note"}
    self.repo.put("tenant", tenant_id, record={**tenant, "contracts": {contract_id: old_block}})
    self.assertEqual(ok(self, self.plugin.get_tenant(self.actor, tenant_id))["contracts"][1]["contractId"], contract_id)
    draft = self.contract_draft(tenant_id)
    row = {key: value for key, value in ok(self, draft).items() if key not in ("completeness", "note")}
    self.repo.put("tenant_contract_draft", tenant_id, row["contract_id"], record=row)
    self.assertIsNone(ok(self, self.plugin.get_tenant_contract_draft(self.actor, tenant_id, row["contract_id"]))["note"])


class TestPlannedNodes(_AmendmentCase):
  def test_a_planned_node_still_draining_is_refused_at_save_and_at_activation(self):
    tenant_id, _ = self.scenario()
    self.repo.put("tenant_node", tenant_id, "Node-B", record={
      "tenant_id": tenant_id, "node_address": "Node-B", "active": True, "mode": "private", "draining": True,
      "changed_by": "creator", "changed_at": "2026-11-01T00:00:00+00:00"})
    self.busy.add("Node-B")
    contract_id = ok(self, self.contract_draft(tenant_id))["contract_id"]
    result = self.update_contract(tenant_id, contract_id, {"nodes": [PRIVATE_B]})
    refused(self, result, 409, "node_draining")
    self.assertEqual(result["nodeAddress"], "Node-B")
    ready = self.ready_contract(tenant_id, [SHARED_C], signed=b"%PDF-1.7\n%another\n%%EOF\n", generated=b"%PDF-1.7\n%gen\n%%EOF\n")
    self.repo.put("tenant_contract_draft", tenant_id, ready, record={
      **self.stored_contract(tenant_id, ready), "nodes": [PRIVATE_B],
      "generated": {**self.stored_contract(tenant_id, ready)["generated"], "nodes": [PRIVATE_B]}})
    refused(self, self.activate_contract(tenant_id, ready), 409, "node_draining")


class TestGuard(_AmendmentCase):
  def test_every_live_engagement_needs_one_signed_copy_and_a_revoked_one_needs_none(self):
    tenant_id, active = self.scenario()
    suspended = ok(self, self.engagement(tenant_id))["engagementId"]
    ok(self, self.plugin.suspend_engagement(self.actor, tenant_id, suspended, "pause"))
    scheduled = ok(self, self.plugin.create_engagement(
      self.actor, tenant_id, str(uuid4()), "Later", "2026-11-01T00:00:00Z", "2026-11-30T00:00:00Z",
      COMPLETE["context"], [pick(self.asset_in(tenant_id))]))["engagementId"]
    revoked = ok(self, self.engagement(tenant_id))["engagementId"]
    ok(self, self.plugin.revoke_engagement(self.actor, tenant_id, revoked, "done"))
    second = self.ready_contract(tenant_id, [SHARED_C])
    self.copy(tenant_id, active, second, sign=False)
    self.copy(tenant_id, suspended, second, sign=False)
    self.copy(tenant_id, suspended, second, sign=False)
    writes = len(self.store.writes)
    result = self.activate_contract(tenant_id, second)
    refused(self, result, 409, "engagements_to_move")
    self.assertEqual(sorted((entry["engagementId"], entry["reason"]) for entry in result["engagements"]),
                     sorted([(active, "copy_unsigned"), (suspended, "two_copies"), (scheduled, "no_copy")]))
    self.assertEqual(len(self.store.writes), writes)


  def test_a_copy_refused_by_the_preflight_is_named_with_its_code(self):
    tenant_id, old_id = self.scenario()
    second = self.ready_contract(tenant_id, [SHARED_C])
    copy_id = self.copy(tenant_id, old_id, second)
    with patch.object(self.service, "_replaceable", side_effect=AdministrationDenied(409, "engagement_superseded")):
      result = self.activate_contract(tenant_id, second)
    refused(self, result, 409, "engagement_superseded")
    self.assertEqual((result["engagementDraftId"], result["reason"]), (copy_id, "engagement_superseded"))


class TestMovesAndCrashes(_AmendmentCase):
  def test_activation_moves_a_copy_releases_one_node_and_drains_the_one_with_a_job(self):
    tenant_id, old_id = self.scenario(nodes=(SHARED_A, PRIVATE_B))
    second = self.ready_contract(tenant_id, [SHARED_C])
    copy_id = self.copy(tenant_id, old_id, second)
    new_id = "en_" + copy_id[4:]
    self.busy.add("Node-A")
    self.events.clear()
    self.assertEqual(ok(self, self.activate_contract(tenant_id, second)),
                     {"tenantId": tenant_id, "contractId": second, "replayed": False})
    old, new = self.repo.get("engagement", tenant_id, old_id), self.repo.get("engagement", tenant_id, new_id)
    self.assertEqual((old["active"], old["superseded_by"], old["revoke_reason"]), (False, new_id, "Replaced by " + new_id))
    self.assertEqual(new["contract_sha256"], self.tenant_row(tenant_id)["contracts"][second]["contract"]["sha256"])
    self.assertEqual((self.stored_child(copy_id), self.stored_contract(tenant_id, second)), (None, None))
    states = {node["nodeAddress"]: node["state"] for node in ok(self, self.plugin.get_tenant_nodes(self.actor, tenant_id))["nodes"]}
    self.assertEqual(states, {"Node-A": "draining", "Node-C": "assigned"})
    self.assertEqual([event for event, _ in self.events], [
      "tenant_contract_activated", "engagement_created", "engagement_revoked", "node_draining", "node_released"])

  def test_a_crash_after_any_write_is_finished_by_repeating_the_call_and_audited(self):
    crashes = {
      "after the tenant row": lambda old: ("tenant_node", lambda ids, record: True, False),
      "after the nodes": lambda old: ("engagement", lambda ids, record: True, False),
      "after a copy's engagement row": lambda old: ("engagement", lambda ids, record: ids[-1] == old, False),
      "after the copies": lambda old: ("tenant_node", lambda ids, record: record["active"] is False, False),
      "after the release": lambda old: ("tenant_contract_draft", lambda ids, record: True, True),
    }
    for label, crash in crashes.items():
      with self.subTest(label):
        # A node-less `c_1` with a hand-assigned node: only the amendment defines the new nodes.
        tenant_id, old_id = self.scenario(fixed=False)
        second = self.ready_contract(tenant_id, [SHARED_C])
        new_id = "en_" + self.copy(tenant_id, old_id, second)[4:]
        kind, when, delete = crash(old_id)
        with self.crash(kind, when, delete):
          refused(self, self.activate_contract(tenant_id, second), 503, "unavailable")
        if label in ("after the tenant row", "after the nodes"):
          with self.assertRaises(AdministrationDenied) as denied:
            self.service.resolve_execution_admission(self.actor, tenant_id, old_id, "ea_1")
          self.assertEqual(denied.exception.error, "contract_archived")
        self.events.clear()
        self.assertIs(ok(self, self.activate_contract(tenant_id, second))["replayed"], False)
        self.assertEqual([event for event, _ in self.events], [
          "tenant_contract_activated", "engagement_created", "engagement_revoked", "node_released"])
        self.assertEqual(self.live_ids(tenant_id), [new_id])
        self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", False), ("Node-C", "shared", True)])
        self.assertIsNone(self.stored_contract(tenant_id, second))

  def test_a_copy_that_fails_on_the_repeated_call_keeps_the_activation_open_until_resigned_or_revoked(self):
    for label in ("re-signed", "old engagement revoked"):
      with self.subTest(label):
        tenant_id, old_id = self.scenario()
        second = self.ready_contract(tenant_id, [SHARED_C])
        copy_id = self.copy(tenant_id, old_id, second)
        with self.crash("tenant_node", lambda ids, record: True):
          refused(self, self.activate_contract(tenant_id, second), 503, "unavailable")
        # The draft row is left: the copy still cannot go live on its own.
        refused(self, self.plugin.activate_engagement_draft(self.actor, copy_id), 409, "contract_not_active")
        ok(self, self.update_child(copy_id, {"document": {"state": "missing"}}))
        result = self.activate_contract(tenant_id, second)
        refused(self, result, 409, "copy_failed")
        self.assertEqual((result["engagementDraftId"], result["reason"]), (copy_id, "draft_incomplete"))
        self.assertIsNotNone(self.stored_contract(tenant_id, second))
        if label == "re-signed":
          ok(self, self.upload_pack(copy_id))
        else:
          ok(self, self.plugin.revoke_engagement(self.actor, tenant_id, old_id, "no replacement"))
        ok(self, self.activate_contract(tenant_id, second))
        self.assertIsNone(self.stored_contract(tenant_id, second))
        self.assertEqual(self.live_ids(tenant_id), [] if label == "old engagement revoked" else ["en_" + copy_id[4:]])


class TestPendingPick(_AmendmentCase):
  def test_only_a_replacement_picks_a_pending_amendment_and_a_named_draft_keeps_its_signed_copy(self):
    tenant_id, old_id = self.scenario()
    unsigned = ok(self, self.contract_draft(tenant_id))["contract_id"]
    plain = self.child(tenant_id)["engagement_draft_id"]
    refused(self, self.update_child(plain, {"contract_id": unsigned}), 409, "contract_not_active")
    copy_id = self.copy(tenant_id, old_id, unsigned)
    refused(self, self.plugin.activate_engagement_draft(self.actor, copy_id), 409, "contract_not_active")
    refused(self, self.plugin.delete_tenant_contract_draft(self.actor, tenant_id, unsigned), 409, "contract_draft_in_use")
    second = self.ready_contract(tenant_id, [SHARED_C])
    self.copy(tenant_id, old_id, second, sign=False)
    refused(self, self.upload_contract(tenant_id, second, raw=b"%PDF-1.7\n%other\n%%EOF\n"), 409, "contract_draft_in_use")
    refused(self, self.update_contract(tenant_id, second, {"state": "missing"}), 409, "contract_draft_in_use")
    self.assertEqual(self.stored_contract(tenant_id, second)["state"], "signed")

  def test_a_pending_pick_needs_a_draft_that_amends_the_contract_in_force(self):
    tenant_id, old_id = self.scenario()
    pending = ok(self, self.contract_draft(tenant_id))["contract_id"]
    row = self.stored_contract(tenant_id, pending)
    for supersedes, status, code in ((None, 400, "contract_unknown"), ("c_9", 409, "contract_superseded")):
      self.repo.put("tenant_contract_draft", tenant_id, pending, record={**row, "supersedes": supersedes})
      draft_id = ok(self, self.plugin.create_engagement_draft(
        self.actor, tenant_id, str(uuid4()), "Copy", supersedes=old_id))["engagement_draft_id"]
      refused(self, self.update_child(draft_id, {"contract_id": pending}), status, code)
    self.repo.put("tenant_contract_draft", tenant_id, pending, record=row)
    ok(self, self.update_child(draft_id, {"contract_id": pending}))


class TestIncompleteActivation(_AmendmentCase):
  """The tenant row holds the block and the draft row is left: only the activation touches the draft."""

  def incomplete(self, copy=False):
    """A tenant whose `c_2` crashed after step 1 (the tenant row): (tenant_id, old engagement, c_2, copy)."""
    tenant_id, old_id = self.scenario()
    if not copy:
      ok(self, self.plugin.revoke_engagement(self.actor, tenant_id, old_id, "ended"))
    second = self.ready_contract(tenant_id, [SHARED_C])
    copy_id = self.copy(tenant_id, old_id, second) if copy else None
    with self.crash("tenant_node", lambda ids, record: True):
      refused(self, self.activate_contract(tenant_id, second), 503, "unavailable")
    return tenant_id, old_id, second, copy_id

  def test_every_draft_write_and_delete_is_refused_and_the_in_force_file_stays(self):
    tenant_id, _, second, _ = self.incomplete()
    ref = self.tenant_row(tenant_id)["contracts"][second]["contract"]["ref"]
    for label, call in {
      "update": lambda: self.update_contract(tenant_id, second, {"effective_until": "2028-01-01"}),
      "upload": lambda: self.upload_contract(tenant_id, second, raw=b"%PDF-1.7\n%other\n%%EOF\n"),
      "generate": lambda: self.generate_contract(tenant_id, second),
      "delete": lambda: self.plugin.delete_tenant_contract_draft(self.actor, tenant_id, second),
      "finish delete": lambda: self.service.finish_tenant_contract_draft_delete(self.actor, tenant_id, second, [ref]),
    }.items():
      with self.subTest(label):
        refused(self, call(), 409, "activation_incomplete")
    self.assertIn(ref, self.documents.envelopes)
    # A further amendment waits for the unfinished one.
    refused(self, self.contract_draft(tenant_id, supersedes="c_2"), 409, "activation_incomplete")

  def test_the_resume_of_a_contract_no_longer_in_force_writes_nothing_and_the_finish_deletes_the_row(self):
    tenant_id, _, second, _ = self.incomplete()
    tenant = self.tenant_row(tenant_id)
    block = tenant["contracts"][second]
    third = {**block, "supersedes": second, "contract": {**block["contract"], "sha256": "0" * 64}}
    self.repo.put("tenant", tenant_id, record={
      **tenant, "contracts": {second: {**block, "superseded_by": "c_3"}, "c_3": third}})
    self.events.clear()
    ok(self, self.activate_contract(tenant_id, second))
    self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", True)])
    self.assertEqual([event for event, _ in self.events], ["tenant_contract_activated"])
    self.assertIsNone(self.stored_contract(tenant_id, second))

  def test_the_resume_reads_no_file_of_the_contract_draft_but_still_resolves_the_copy_packs(self):
    tenant_id, _, second, _ = self.incomplete()
    row = self.stored_contract(tenant_id, second)
    for ref in (row["document"]["ref"], row["generated"]["ref"]):
      self.documents.envelopes.pop(ref)
    ok(self, self.activate_contract(tenant_id, second))
    self.assertIsNone(self.stored_contract(tenant_id, second))

  def test_a_copy_pack_is_still_resolved_on_the_resume(self):
    tenant_id, old_id, second, copy_id = self.incomplete(copy=True)
    pack = self.stored_child(copy_id)["document"]["document"]["ref"]
    self.documents.envelopes.pop(pack)
    result = self.activate_contract(tenant_id, second)
    refused(self, result, 409, "copy_failed")
    self.assertEqual(result["engagementDraftId"], copy_id)

  def test_a_planned_node_is_held_against_another_tenants_private_assignment_until_assigned(self):
    tenant_id, _, second, _ = self.incomplete()
    _, other = self.tenant("other", nodes=[SHARED_A])
    refused(self, self.assign(other, "Node-C", "private"), 409, "node_planned_private")
    ok(self, self.activate_contract(tenant_id, second))
    refused(self, self.assign(other, "Node-C", "private"), 409, "node_shared_assigned")

  def test_no_pick_resolves_to_the_contract_in_force_and_refuses_while_its_draft_is_left(self):
    tenant_id, _, second, _ = self.incomplete()
    refused(self, self.engagement(tenant_id), 409, "contract_not_active")
    refused(self, self.engagement(tenant_id, contract_id=second), 409, "contract_not_active")
    plain = self.child(tenant_id)["engagement_draft_id"]
    refused(self, self.update_child(plain, {"contract_id": None}), 409, "contract_not_active")
    self.fill(plain)
    ok(self, self.upload_pack(plain))
    refused(self, self.plugin.activate_engagement_draft(self.actor, plain), 409, "contract_not_active")

  def test_the_finish_waits_for_the_copies_and_the_preflight_of_a_moved_copy_writes_nothing(self):
    tenant_id, old_id, second, copy_id = self.incomplete(copy=True)
    refused(self, self.service.finish_tenant_contract_activation(self.actor, tenant_id, second), 409, "conflict")
    self.assertIsNotNone(self.stored_contract(tenant_id, second))
    with self.crash("engagement", lambda ids, record: ids[-1] == old_id):
      refused(self, self.activate_contract(tenant_id, second), 503, "unavailable")
    writes = len(self.store.writes)
    self.assertIsNone(self.service._activate_draft(self.actor, copy_id, None, True, amendment=True, preflight=True))
    self.assertEqual((len(self.store.writes), self.stored_child(copy_id) is not None), (writes, True))


class TestSignedCopiesBindTheirContract(_AmendmentCase):
  def test_a_signed_pack_keeps_its_pick_and_a_signed_copy_keeps_the_nodes_and_note_of_its_amendment(self):
    tenant_id, old_id = self.scenario()
    unsigned = ok(self, self.contract_draft(tenant_id))["contract_id"]
    copy_id = self.copy(tenant_id, old_id, unsigned)
    refused(self, self.update_child(copy_id, {"contract_id": None}), 409, "already_signed")
    refused(self, self.update_contract(tenant_id, unsigned, {"nodes": [SHARED_C, PRIVATE_B]}), 409, "contract_draft_in_use")
    refused(self, self.update_contract(tenant_id, unsigned, {"note": NOTE}), 409, "contract_draft_in_use")
    ok(self, self.update_contract(tenant_id, unsigned, {"effective_from": "2027-02-01"}))
    ok(self, self.update_child(copy_id, {"contract_id": unsigned}))
    # Dropping the pack in the same update frees the pick.
    ok(self, self.update_child(copy_id, {"document": {"state": "missing"}, "contract_id": None}))
    ok(self, self.update_contract(tenant_id, unsigned, {"note": NOTE}))
    # No pick means `c_1`: the console's explicit `c_1` on a signed pick-less draft is no change.
    plain = self.child(tenant_id)["engagement_draft_id"]
    self.fill(plain)
    ok(self, self.upload_pack(plain))
    ok(self, self.update_child(plain, {"contract_id": "c_1"}))


class TestActivationAuthorization(_AmendmentCase):
  def test_activation_with_copies_needs_the_platform_role_and_revoke_and_the_pick_stays_in_its_tenant(self):
    from extensions.business.cybersec.red_mesh.tenancy import policy
    tenant_id, old_id = self.scenario()
    self.store.grant("acme.admin", tenant_id)
    second = self.ready_contract(tenant_id, [SHARED_C])
    copy_id = self.copy(tenant_id, old_id, second)
    writes = len(self.store.writes)
    refused(self, self.activate_contract(tenant_id, second, actor={"account_id": "acme.admin"}), 403, "forbidden")
    without = policy._ROLE_OPERATIONS["super_tenant_admin"] - {"engagements:revoke"}
    with patch.dict(policy._ROLE_OPERATIONS, {"super_tenant_admin": without}):
      result = self.activate_contract(tenant_id, second)
    refused(self, result, 403, "forbidden")
    self.assertEqual((len(self.store.writes), self.live_ids(tenant_id)), (writes, [old_id]))
    # Another tenant's draft cannot pick this tenant's pending amendment.
    _, other = self.tenant("other", nodes=[SHARED_A])
    foreign = self.child(other)["engagement_draft_id"]
    refused(self, self.update_child(foreign, {"contract_id": second}), 400, "contract_unknown")
    ok(self, self.activate_contract(tenant_id, second))
    self.assertEqual(self.live_ids(tenant_id), ["en_" + copy_id[4:]])
