"""RM-127: the nodes are part of the tenant contract. They are planned before it is generated, the
generated pack is bound to them, a signed contract locks them, activation assigns them all or
refuses, and after activation they stay fixed. Real plugin endpoints, service and adapters."""
import json
from uuid import uuid4

from .contract_fixture import install_contract
from .test_tenant_draft_setup import _SetupCase
from .test_tenant_drafts import SCHEDULE_PDF, ok, refused, snapshot_of

SHARED_A = {"node_address": "Node-A", "mode": "shared"}
PRIVATE_B = {"node_address": "Node-B", "mode": "private"}
PLAN = [SHARED_A, PRIVATE_B]


class _ContractNodesCase(_SetupCase):
  def missing(self, draft_id):
    return ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))["completeness"]["missing"]

  def generate_for(self, draft_id, plan=None, **kwargs):
    plan = self.stored(draft_id)["nodes"] if plan is None else plan
    return self.generate(draft_id, snapshot=snapshot_of(plan), **kwargs)

  def node_rows(self, tenant_id):
    return sorted((row["node_address"], row["mode"], row["active"])
                  for row in self.repo.list_node_assignments(tenant_id))

  def prepared(self, plan=PLAN, domain_id="acme"):
    """A ready draft for `plan`, prepared: (draft_id, request_id, tenant_id), the tenant inactive."""
    draft_id = self.ready_without_admin(display_name=domain_id, domain_id=domain_id, nodes=plan)
    request_id = str(uuid4())
    tenant_id = ok(self, self.activate(draft_id, request_id))["tenantId"]
    return draft_id, request_id, tenant_id


class TestNodesBeforeTheContract(_ContractNodesCase):
  def test_a_draft_without_nodes_lists_the_gap_and_cannot_generate(self):
    draft_id = self.create()["draft_id"]
    self.assertIn("field:nodes", self.missing(draft_id))
    writes, puts = len(self.store.writes), len(self.documents.puts)
    result = self.generate_for(draft_id, plan=[])
    refused(self, result, 409, "draft_incomplete")
    self.assertEqual(result["missing"], ["field:nodes"])
    self.assertEqual((len(self.store.writes), len(self.documents.puts)), (writes, puts))
    ok(self, self.plan(draft_id, PLAN))
    self.assertNotIn("field:nodes", self.missing(draft_id))

  def test_the_generated_block_records_the_plan_the_snapshot_printed(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.plan(draft_id, [PRIVATE_B, SHARED_A]))
    generated = ok(self, self.generate_for(draft_id))["items"]["contract"]["generated"]
    # The draft's shape and order (sorted by address); names and IPs stay in the snapshot.
    self.assertEqual(generated["nodes"], PLAN)
    self.assertEqual(self.stored(draft_id)["items"]["contract"]["generated"]["nodes"], PLAN)
    self.assertNotIn("item:contract_stale", self.missing(draft_id))

  def test_a_snapshot_of_other_nodes_is_refused_before_anything_is_stored(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.plan(draft_id, PLAN))
    puts = len(self.documents.puts)
    for label, plan in {"missing": [], "fewer": [SHARED_A], "other mode": [SHARED_A, {**PRIVATE_B, "mode": "shared"}],
                        "other order": [PRIVATE_B, SHARED_A]}.items():
      with self.subTest(label):
        refused(self, self.generate_for(draft_id, plan=plan), 409, "draft_changed")
    for label, nodes in {"null": None, "not a list": "Node-A", "no address": [{"mode": "shared"}],
                         "bad mode": [{"nodeAddress": "Node-A", "mode": "exclusive"}], "not an object": ["Node-A"]}.items():
      with self.subTest(label):
        refused(self, self.generate(draft_id, snapshot=json.dumps({"nodes": nodes})), 400, "invalid_request")
    self.assertEqual(len(self.documents.puts), puts)
    self.assertIsNone(self.stored(draft_id)["items"]["contract"]["generated"])

  def test_a_plan_changed_between_authorize_and_attach_is_refused_and_the_file_discarded(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.plan(draft_id, PLAN))
    call = self.plugin._call_tenant_administration

    def replan_before_attach(operation, actor, **kwargs):
      if operation == "attach_generated_document":
        ok(self, self.plan(draft_id, [SHARED_A]))
      return call(operation, actor, **kwargs)
    self.plugin._call_tenant_administration = replan_before_attach
    refused(self, self.generate_for(draft_id), 409, "draft_changed")
    self.assertEqual((len(self.documents.puts), self.documents.deleted), (1, ["doc-1"]))
    self.assertIsNone(self.stored(draft_id)["items"]["contract"]["generated"])

  def test_an_engagement_pack_is_generated_without_nodes(self):
    draft_id = self.create()["draft_id"]
    child = self.child(draft_id)["engagement_draft_id"]
    generated = self.generate_pack(child, snapshot='{"v":1}')
    self.assertNotIn("nodes", generated)


class TestStaleAndLocked(_ContractNodesCase):
  def test_a_plan_changed_after_generation_makes_the_contract_stale_until_regenerated(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.plan(draft_id, PLAN))
    ok(self, self.generate_for(draft_id))
    ok(self, self.plan(draft_id, [SHARED_A]))
    self.assertIn("item:contract_stale", self.missing(draft_id))
    # In any state: awaiting signature too.
    ok(self, self.update(draft_id, {"items": {"contract": {"state": "awaiting_signature"}}}))
    self.assertIn("item:contract_stale", self.missing(draft_id))
    ok(self, self.generate_for(draft_id, raw=SCHEDULE_PDF))
    self.assertNotIn("item:contract_stale", self.missing(draft_id))

  def test_a_signed_copy_without_a_generated_pack_or_from_before_rm127_is_stale(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.plan(draft_id, PLAN))
    ok(self, self.upload(draft_id))
    self.assertIn("item:contract_stale", self.missing(draft_id))
    # A block written before RM-127 has no `nodes`: it printed none.
    ok(self, self.update(draft_id, {"items": {"contract": {"state": "missing"}}}))
    generated = ok(self, self.generate_for(draft_id))["items"]["contract"]["generated"]
    row = self.stored(draft_id)
    row["items"]["contract"]["generated"] = {key: value for key, value in generated.items() if key != "nodes"}
    self.repo.put("tenant_draft", draft_id, record=row)
    self.assertIn("item:contract_stale", self.missing(draft_id))

  def test_a_signed_contract_locks_the_plan(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.plan(draft_id, PLAN))
    ok(self, self.generate_for(draft_id))
    ok(self, self.upload(draft_id))
    writes = len(self.store.writes)
    refused(self, self.plan(draft_id, [SHARED_A]), 409, "nodes_locked")
    # Dropping the copy in the same update does not unlock it.
    refused(self, self.update(draft_id, {"nodes": [SHARED_A], "items": {"contract": {"state": "missing"}}}),
            409, "nodes_locked")
    self.assertEqual(len(self.store.writes), writes)
    # The same plan, and other fields, still save.
    ok(self, self.plan(draft_id, list(PLAN)))
    ok(self, self.update(draft_id, {"display_name": "Renamed"}))
    # Dropped first, the plan changes and the contract is stale.
    ok(self, self.update(draft_id, {"items": {"contract": {"state": "missing"}}}))
    ok(self, self.plan(draft_id, [SHARED_A]))
    self.assertIn("item:contract_stale", self.missing(draft_id))


class TestActivationAssignsTheContractNodes(_ContractNodesCase):
  def test_activation_assigns_every_node_and_fixes_them(self):
    _, request_id, tenant_id = self.prepared()
    self.assertEqual(self.node_rows(tenant_id), [])
    ok(self, self.plugin.activate_tenant(self.actor, request_id))
    self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", True), ("Node-B", "private", True)])
    view = ok(self, self.plugin.get_tenant_nodes(self.actor, tenant_id))
    self.assertEqual([(node["nodeAddress"], node["mode"]) for node in view["nodes"]],
                     [("Node-A", "shared"), ("Node-B", "private")])
    self.assertEqual((view["canManageAssignments"], view["nodesFixed"]), (False, True))
    # A replay of the active tenant writes nothing more.
    writes = len(self.store.writes)
    ok(self, self.plugin.activate_tenant(self.actor, request_id))
    self.assertEqual(len(self.store.writes), writes)

  def test_a_taken_or_ineligible_node_refuses_activation_and_writes_nothing(self):
    _, other = self.tenant("other")
    ok(self, self.assign(other, "Node-A", "private"))
    _, request_id, tenant_id = self.prepared()
    self.plugin.cfg_chainstore_peers = ["Node-A", "Node-C"]
    writes = len(self.store.writes)
    result = self.plugin.activate_tenant(self.actor, request_id)
    refused(self, result, 409, "contract_nodes_unavailable")
    self.assertEqual(result["nodes"], [{"nodeAddress": "Node-A", "error": "node_private_assigned"},
                                       {"nodeAddress": "Node-B", "error": "ineligible_node"}])
    self.assertEqual(len(self.store.writes), writes)
    self.assertEqual(self.node_rows(tenant_id), [])
    self.assertFalse(self.repo.get("tenant", tenant_id)["active"])

  def test_an_unreadable_peer_list_is_unavailable(self):
    _, request_id, tenant_id = self.prepared()
    self.plugin.cfg_chainstore_peers = None
    refused(self, self.plugin.activate_tenant(self.actor, request_id), 503, "unavailable")
    self.assertEqual(self.node_rows(tenant_id), [])

  def test_the_drafts_own_private_plan_does_not_block_its_activation(self):
    # Node-B is held privately by the draft being activated; no other tenant may take it meanwhile.
    _, other = self.tenant("other")
    _, request_id, tenant_id = self.prepared()
    refused(self, self.assign(other, "Node-B"), 409, "node_planned_private")
    ok(self, self.plugin.activate_tenant(self.actor, request_id))
    self.assertIn(("Node-B", "private", True), self.node_rows(tenant_id))

  def test_a_replay_after_a_crash_between_rows_fills_the_gaps(self):
    _, request_id, tenant_id = self.prepared()
    service = self.plugin._execution_service()
    service._assign_node(service._actor(self.actor), tenant_id, "Node-A", "shared", None)
    self.assertFalse(self.repo.get("tenant", tenant_id)["active"])
    ok(self, self.plugin.activate_tenant(self.actor, request_id))
    self.assertEqual(self.node_rows(tenant_id), [("Node-A", "shared", True), ("Node-B", "private", True)])

  def test_a_release_drops_the_rows_of_a_stopped_activation(self):
    draft_id, _, tenant_id = self.prepared()
    service = self.plugin._execution_service()
    service._assign_node(service._actor(self.actor), tenant_id, "Node-A", "shared", None)
    released = ok(self, self.plugin._call_tenant_administration("release_tenant_draft_activation", self.actor,
                                                                draft_id=draft_id))
    self.assertEqual(released["rows_deleted"], 4)
    self.assertEqual(self.node_rows(tenant_id), [])
    self.assertIsNone(self.repo.get("tenant", tenant_id))
    # The draft can be prepared again; the signed copy still locks the plan until it is dropped.
    refused(self, self.plan(draft_id, [SHARED_A]), 409, "nodes_locked")


class TestNodesFixedAfterActivation(_ContractNodesCase):
  def test_assign_and_release_are_refused_and_a_held_assignment_is_answered(self):
    _, tenant_id = self.tenant("acme", nodes=PLAN, fixed=True)
    writes = len(self.store.writes)
    refused(self, self.assign(tenant_id, "Node-C"), 409, "nodes_fixed_by_contract")
    refused(self, self.assign(tenant_id, "Node-A", "private"), 409, "nodes_fixed_by_contract")
    refused(self, self.plugin.set_tenant_node_assignment(self.actor, tenant_id, "Node-A", False), 409,
            "nodes_fixed_by_contract")
    # Asking for what the tenant already holds is answered (the console's activation retry did).
    self.assertEqual(ok(self, self.assign(tenant_id, "Node-A"))["state"], "assigned")
    self.assertEqual(ok(self, self.assign(tenant_id, "Node-B", "private"))["mode"], "private")
    self.assertEqual(len(self.store.writes), writes)

  def test_a_one_step_tenant_still_edits_its_nodes(self):
    self.store.account("initial")
    request_id = str(uuid4())
    prepared = ok(self, self.plugin.prepare_tenant(self.actor, request_id, "one", "one", "initial",
                                                   **install_contract(self.plugin, ref="doc-one")))
    self.store.grant("initial", prepared["tenantId"])
    ok(self, self.plugin.activate_tenant(self.actor, request_id))
    tenant_id = prepared["tenantId"]
    ok(self, self.assign(tenant_id, "Node-A"))
    ok(self, self.plugin.set_tenant_node_assignment(self.actor, tenant_id, "Node-A", False))
    view = ok(self, self.plugin.get_tenant_nodes(self.actor, tenant_id))
    self.assertEqual((view["canManageAssignments"], view["nodesFixed"]), (True, False))
