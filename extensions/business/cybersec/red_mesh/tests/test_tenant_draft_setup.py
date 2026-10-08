"""RM-112 phase 2: a tenant activated without an admin, the draft node plan and its private hold,
draft delete refused once signed, and the tenant row's node count. Real plugin endpoints, service
and adapters."""
import json
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.identity import AccountView
from .test_engagement_drafts import _EngagementDraftCase
from .test_tenant_drafts import LEGAL, TENANCY_HKEY, ok, refused


class _SetupCase(_EngagementDraftCase):
  def setUp(self):
    super().setUp()
    self.plugin.cfg_chainstore_peers = ["Node-A", "Node-B", "Node-C"]
    # An empty job hash: a release finds no running job.
    self.plugin.cfg_instance_id = "jobs"

  def ready_without_admin(self, display_name="Acme SRL", domain_id="acme", compliance_types=("nis2",)):
    draft_id = self.create(compliance_types=compliance_types)["draft_id"]
    ok(self, self.update(draft_id, {"display_name": display_name, "domain_id": domain_id, "legal": dict(LEGAL),
                                    "items": {"contract": {"effective_from": "2026-11-01"}}}))
    ok(self, self.upload(draft_id))
    return draft_id

  def tenant(self, domain_id, nodes=None):
    """An active tenant from a draft without an admin; the draft stays (not closed)."""
    draft_id = self.ready_without_admin(display_name=domain_id, domain_id=domain_id)
    if nodes is not None:
      ok(self, self.update(draft_id, {"nodes": nodes}))
    request_id = str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    tenant_id = ok(self, self.plugin.activate_tenant(self.actor, request_id))["tenantId"]
    return draft_id, tenant_id

  def assign(self, tenant_id, node_address, mode="shared"):
    return self.plugin.set_tenant_node_assignment(self.actor, tenant_id, node_address, True, mode)

  def plan(self, draft_id, nodes):
    return self.update(draft_id, {"nodes": nodes})


class TestActivationWithoutAdmin(_SetupCase):
  def test_completeness_no_longer_asks_for_an_admin(self):
    draft = self.create("", ())
    self.assertEqual(draft["completeness"]["missing"], [
      "field:display_name", "field:domain_id", "field:legal.name", "field:legal.registration_id",
      "field:legal.signer_name", "field:legal.signer_role", "field:compliance_types", "field:contract.effective_from",
      "item:contract"])

  def test_activation_needs_the_contract_start_date_but_not_an_end_date(self):
    """Decision 24: the term is printed in the pack; no end date means an indefinite term."""
    draft_id = self.ready_without_admin()
    ok(self, self.update(draft_id, {"items": {"contract": {"effective_from": None, "effective_until": None}}}))
    result = self.activate(draft_id, str(uuid4()))
    refused(self, result, 409, "draft_incomplete")
    self.assertEqual(result["missing"], ["field:contract.effective_from"])
    ok(self, self.update(draft_id, {"items": {"contract": {"effective_from": "2026-11-01"}}}))
    self.assertEqual(ok(self, self.activate(draft_id, str(uuid4())))["state"], "pending")

  def test_a_draft_created_without_compliance_types_cannot_activate_until_one_is_set(self):
    draft_id = self.ready_without_admin(compliance_types=())
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))["compliance_types"], [])
    result = self.activate(draft_id, str(uuid4()))
    refused(self, result, 409, "draft_incomplete")
    self.assertEqual(result["missing"], ["field:compliance_types"])
    ok(self, self.update(draft_id, {"compliance_types": ["cra"]}))
    self.assertEqual(ok(self, self.activate(draft_id, str(uuid4())))["state"], "pending")

  def test_activation_without_an_admin_touches_no_account_and_records_no_founder(self):
    draft_id, request_id = self.ready_without_admin(), str(uuid4())
    accounts = {key: value for key, value in self.store.data.items() if key[0] == "auth"}
    prepared = ok(self, self.activate(draft_id, request_id))
    self.assertEqual((prepared["state"], prepared["initialAdminId"], prepared["initialAdminGeneration"]),
                     ("pending", None, None))
    receipt, = self.rows("receipt")
    self.assertEqual((receipt["initial_admin_id"], receipt["initial_admin_generation"]), (None, None))
    detail = ok(self, self.plugin.activate_tenant(self.actor, request_id))
    self.assertEqual((detail["tenantId"], detail["rootAdminId"], detail["adminCount"]),
                     (prepared["tenantId"], None, 0))
    tenant, = self.rows("tenant")
    self.assertIsNone(tenant["root_admin_id"])
    self.assertEqual({key: value for key, value in self.store.data.items() if key[0] == "auth"}, accounts)
    # The tenant reads back valid everywhere: list, detail, close.
    row, = ok(self, self.plugin.list_tenants(self.actor))
    self.assertEqual(row["rootAdminId"], None)
    ok(self, self.plugin.get_tenant(self.actor, prepared["tenantId"]))
    ok(self, self.plugin.close_tenant_draft(self.actor, draft_id))

  def test_a_replay_without_an_admin_is_the_same_creation(self):
    draft_id, request_id = self.ready_without_admin(), str(uuid4())
    first = ok(self, self.activate(draft_id, request_id))
    self.assertEqual(ok(self, self.activate(draft_id, request_id)), first)
    ok(self, self.plugin.activate_tenant(self.actor, request_id))
    again = ok(self, self.activate(draft_id, request_id))
    self.assertEqual((again["tenantId"], again["state"], again["initialAdminId"]), (first["tenantId"], "active", None))
    self.assertEqual(ok(self, self.plugin.activate_tenant(self.actor, request_id))["tenantId"], first["tenantId"])
    self.assertEqual(len(self.rows("tenant")), 1)

  def test_an_admin_set_after_the_marker_is_a_request_conflict(self):
    # The marker locks the draft, so only a direct row edit can change it; the receipt fixes the admin.
    draft_id, request_id = self.ready_without_admin(), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    row = self.stored(draft_id)
    row["initial_admin_id"] = "acme.admin"
    self.repo.put("tenant_draft", draft_id, record=row)
    refused(self, self.activate(draft_id, request_id), 409, "request_conflict")

  def test_activation_with_an_admin_still_needs_the_membership(self):
    draft_id, request_id = self.ready_without_admin(), str(uuid4())
    ok(self, self.update(draft_id, {"initial_admin_id": "acme.admin"}))
    prepared = ok(self, self.activate(draft_id, request_id))
    self.assertEqual(prepared["initialAdminId"], "acme.admin")
    self.assertTrue(prepared["initialAdminGeneration"])
    refused(self, self.plugin.activate_tenant(self.actor, request_id), 409, "initial_admin_required")
    self.store.grant("acme.admin", prepared["tenantId"])
    self.assertEqual(ok(self, self.plugin.activate_tenant(self.actor, request_id))["rootAdminId"], "acme.admin")

  def test_release_of_a_stuck_activation_without_an_admin(self):
    draft_id, request_id = self.ready_without_admin(), str(uuid4())
    prepared = ok(self, self.activate(draft_id, request_id))
    released = ok(self, self.plugin.release_tenant_draft_activation(self.actor, draft_id))["released"]
    self.assertEqual((released["request_id"], released["tenant_id"], released["initial_admin_id"]),
                     (request_id, prepared["tenantId"], None))
    self.assertEqual((self.rows("tenant"), self.rows("receipt")), ([], []))
    self.assertIsNone(self.stored(draft_id)["activation"])
    self.assertEqual(ok(self, self.activate(draft_id, str(uuid4())))["state"], "pending")

  def test_the_one_step_creation_still_requires_an_admin(self):
    from .contract_fixture import contract_terms
    service = self.plugin._execution_service()
    refused(self, service.prepare_tenant(self.actor, str(uuid4()), "Acme", "acme", None, **contract_terms()),
            400, "invalid_request")

  def test_a_receipt_with_one_admin_field_only_is_corrupt(self):
    draft_id, request_id = self.ready_without_admin(), str(uuid4())
    ok(self, self.activate(draft_id, request_id))
    key = json.dumps(["receipt", "deployment", "creator", request_id], separators=(",", ":"))
    for field, value in (("initial_admin_id", "acme.admin"), ("initial_admin_generation", "gen")):
      with self.subTest(field=field):
        stored = self.store.data[(TENANCY_HKEY, key)]
        self.store.data[(TENANCY_HKEY, key)] = {**stored, field: value}
        refused(self, self.activate(draft_id, request_id), 503, "unavailable")
        self.store.data[(TENANCY_HKEY, key)] = stored
    stored = self.store.data[(TENANCY_HKEY, key)]
    self.store.data[(TENANCY_HKEY, key)] = {k: v for k, v in stored.items() if k != "initial_admin_generation"}
    refused(self, self.activate(draft_id, request_id), 503, "unavailable")


class TestDraftNodePlan(_SetupCase):
  def test_the_plan_is_saved_sorted_and_validated(self):
    draft_id = self.create()["draft_id"]
    self.assertEqual(self.stored(draft_id)["nodes"], [])
    draft = ok(self, self.plan(draft_id, [{"node_address": "Node-B", "mode": "shared"},
                                          {"node_address": "Node-A", "mode": "private"}]))
    self.assertEqual(draft["nodes"], [{"node_address": "Node-A", "mode": "private"},
                                      {"node_address": "Node-B", "mode": "shared"}])
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))["nodes"], draft["nodes"])
    row, = ok(self, self.plugin.list_tenant_drafts(self.actor))
    self.assertEqual(row["nodes"], draft["nodes"])
    for label, nodes in {
      "not a list": {"node_address": "Node-A", "mode": "shared"},
      "bad address": [{"node_address": "bad address", "mode": "shared"}],
      "bad mode": [{"node_address": "Node-A", "mode": "exclusive"}],
      "no mode": [{"node_address": "Node-A"}],
      "extra key": [{"node_address": "Node-A", "mode": "shared", "x": 1}],
      "duplicate": [{"node_address": "Node-A", "mode": "shared"}, {"node_address": "Node-A", "mode": "private"}],
    }.items():
      with self.subTest(label):
        writes = len(self.store.writes)
        refused(self, self.plan(draft_id, nodes), 400, "invalid_request")
        self.assertEqual(len(self.store.writes), writes)
    self.assertEqual(ok(self, self.plan(draft_id, []))["nodes"], [])

  def test_a_row_written_before_the_plan_existed_reads_back_with_no_nodes(self):
    draft_id = self.create()["draft_id"]
    key = json.dumps(["tenant_draft", "deployment", draft_id], separators=(",", ":"))
    del self.store.data[(TENANCY_HKEY, key)]["nodes"]
    self.assertEqual(ok(self, self.plugin.get_tenant_draft(self.actor, draft_id))["nodes"], [])
    self.assertEqual(len(ok(self, self.plugin.list_tenant_drafts(self.actor))), 1)
    # A malformed plan is not readable.
    self.store.data[(TENANCY_HKEY, key)]["nodes"] = [{"node_address": "Node-A", "mode": "exclusive"}]
    refused(self, self.plugin.get_tenant_draft(self.actor, draft_id), 503, "unavailable")

  def test_a_private_plan_blocks_another_tenants_assignment_and_names_the_draft(self):
    _, tenant_id = self.tenant("other")
    draft_id = self.create("Holder")["draft_id"]
    ok(self, self.plan(draft_id, [{"node_address": "Node-A", "mode": "private"},
                                  {"node_address": "Node-B", "mode": "shared"}]))
    for mode in ("shared", "private"):
      with self.subTest(mode=mode):
        writes = len(self.store.writes)
        result = self.assign(tenant_id, "Node-A", mode)
        refused(self, result, 409, "node_planned_private")
        self.assertEqual(result["holder"], {"draft_id": draft_id, "display_name": "Holder"})
        self.assertEqual(len(self.store.writes), writes)
    # A shared plan reserves nothing.
    ok(self, self.assign(tenant_id, "Node-B", "private"))

  def test_a_caller_without_the_full_portfolio_sees_reserved_without_the_draft(self):
    _, tenant_id = self.tenant("other")
    draft_id = self.create("Holder")["draft_id"]
    ok(self, self.plan(draft_id, [{"node_address": "Node-A", "mode": "private"}]))
    service = self.plugin._execution_service()
    scoped = AccountView("scoped", True)
    with self.assertRaises(AdministrationDenied) as denied:
      service._assign_node(scoped, tenant_id, "Node-A", "shared", None)
    self.assertEqual((denied.exception.status_code, denied.exception.error, denied.exception.details),
                     (409, "node_planned_private", {}))

  def test_a_node_held_by_one_draft_cannot_be_planned_by_another(self):
    holder = self.create("Holder")["draft_id"]
    other = self.create("Other")["draft_id"]
    ok(self, self.plan(holder, [{"node_address": "Node-A", "mode": "private"}]))
    for mode in ("shared", "private"):
      with self.subTest(mode=mode):
        result = self.plan(other, [{"node_address": "Node-A", "mode": mode}])
        refused(self, result, 409, "node_planned_private")
        self.assertEqual(result["holder"], {"draft_id": holder, "display_name": "Holder"})
        self.assertEqual(self.stored(other)["nodes"], [])
    # The holder keeps editing its own draft, plan included.
    ok(self, self.update(holder, {"display_name": "Renamed"}))
    ok(self, self.plan(holder, [{"node_address": "Node-A", "mode": "private"},
                                {"node_address": "Node-B", "mode": "private"}]))
    # Dropping the plan lifts the hold.
    ok(self, self.plan(holder, []))
    ok(self, self.plan(other, [{"node_address": "Node-A", "mode": "private"}]))

  def test_a_private_plan_is_refused_while_the_node_has_a_live_assignment(self):
    _, tenant_id = self.tenant("other")
    ok(self, self.assign(tenant_id, "Node-A", "shared"))
    ok(self, self.assign(tenant_id, "Node-B", "private"))
    draft_id = self.create()["draft_id"]
    refused(self, self.plan(draft_id, [{"node_address": "Node-A", "mode": "private"}]), 409, "node_shared_assigned")
    refused(self, self.plan(draft_id, [{"node_address": "Node-B", "mode": "private"}]), 409, "node_private_assigned")
    # A shared plan of an assigned node is accepted: activation skips it if it is still taken.
    ok(self, self.plan(draft_id, [{"node_address": "Node-A", "mode": "shared"},
                                  {"node_address": "Node-B", "mode": "shared"}]))
    # Released, the node can be held.
    ok(self, self.plugin.set_tenant_node_assignment(self.actor, tenant_id, "Node-A", False))
    ok(self, self.plan(draft_id, [{"node_address": "Node-A", "mode": "private"}]))

  def test_activation_assigns_its_own_private_plan_and_close_lifts_the_hold(self):
    _, other_tenant = self.tenant("other")
    draft_id, tenant_id = self.tenant("acme", nodes=[{"node_address": "Node-A", "mode": "private"}])
    refused(self, self.assign(other_tenant, "Node-A"), 409, "node_planned_private")
    # The tenant whose receipt names the holding draft assigns it, retries included.
    for _ in range(2):
      self.assertEqual(ok(self, self.assign(tenant_id, "Node-A", "private"))["mode"], "private")
    ok(self, self.plugin.close_tenant_draft(self.actor, draft_id))
    # No hold left: the refusal is the live private assignment's.
    refused(self, self.assign(other_tenant, "Node-A"), 409, "node_private_assigned")
    ok(self, self.plugin.set_tenant_node_assignment(self.actor, tenant_id, "Node-A", False))
    ok(self, self.assign(other_tenant, "Node-A"))

  def test_delete_lifts_the_hold(self):
    _, tenant_id = self.tenant("other")
    draft_id = self.create()["draft_id"]
    ok(self, self.plan(draft_id, [{"node_address": "Node-A", "mode": "private"}]))
    refused(self, self.assign(tenant_id, "Node-A"), 409, "node_planned_private")
    ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))
    ok(self, self.assign(tenant_id, "Node-A"))


class TestDraftDeleteWithSignedDocuments(_SetupCase):
  def test_a_signed_agreement_pack_refuses_the_delete(self):
    draft_id = self.create()["draft_id"]
    ok(self, self.upload(draft_id))
    writes = len(self.store.writes)
    refused(self, self.plugin.delete_tenant_draft(self.actor, draft_id), 409, "draft_has_signed_documents")
    self.assertEqual((len(self.store.writes), self.documents.deleted), (writes, []))
    self.assertIsNotNone(self.stored(draft_id))
    # Dropping the signed copy makes it deletable again.
    ok(self, self.update(draft_id, {"items": {"contract": {"state": "missing"}}}))
    ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))
    self.assertIsNone(self.stored(draft_id))

  def test_a_signed_engagement_pack_refuses_the_delete(self):
    draft_id = self.create()["draft_id"]
    engagement_draft_id = self.child(draft_id)["engagement_draft_id"]
    self.generate_pack(engagement_draft_id)
    ok(self, self.upload_pack(engagement_draft_id))
    refused(self, self.plugin.delete_tenant_draft(self.actor, draft_id), 409, "draft_has_signed_documents")
    self.assertEqual(self.documents.deleted, [])
    self.assertIsNotNone(self.stored_child(engagement_draft_id))
    ok(self, self.update_child(engagement_draft_id, {"document": {"state": "missing"}}))
    self.assertEqual(ok(self, self.plugin.delete_tenant_draft(self.actor, draft_id))["engagement_drafts_deleted"], 1)


class TestTenantNodeCount(_SetupCase):
  def test_the_row_counts_live_assignments(self):
    _, tenant_id = self.tenant("acme")
    self.assertEqual(ok(self, self.plugin.list_tenants(self.actor))[0]["nodeCount"], 0)
    ok(self, self.assign(tenant_id, "Node-A"))
    ok(self, self.assign(tenant_id, "Node-B", "private"))
    ok(self, self.plugin.set_tenant_node_assignment(self.actor, tenant_id, "Node-B", False))
    row, = ok(self, self.plugin.list_tenants(self.actor))
    self.assertEqual(row["nodeCount"], 1)
    self.assertEqual(ok(self, self.plugin.get_tenant(self.actor, tenant_id))["nodeCount"], 1)
