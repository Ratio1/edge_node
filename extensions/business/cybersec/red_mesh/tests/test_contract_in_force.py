"""RM-249 phase 1a: one contract in force per tenant. The highest-numbered contract nobody replaced is
in force; every other contract is archived and authorizes nothing (launch, a new pass, the running job's
end-stop), while the running pass itself is never refused. Real plugin endpoints, service and adapters."""
import copy
from uuid import uuid4

from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied

from .test_tenant_contracts import PRIVATE_B, SHARED_A, _ContractSetCase
from .test_tenant_drafts import ok, refused


class TestContractInForce(_ContractSetCase):
  def replaced_with_a_live_first_engagement(self):
    """`c_1` carries an admitted engagement, then `c_2` replaces it: (tenant_id, e1, binding of e1, e2 on c_2)."""
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    self.store.grant("acme.admin", tenant_id)
    first = ok(self, self.engagement(tenant_id))
    self.service = self.admission_service()
    admission = self.service.resolve_execution_admission(self.actor, tenant_id, first["engagementId"], "ea_1")
    self.before = admission.to_dict()["engagement"]
    binding = admission.build_binding("coordinator", ["Node-A"])
    ok(self, self.activate_contract(tenant_id, self.ready_contract(tenant_id, [SHARED_A, PRIVATE_B])))
    return tenant_id, first, binding, ok(self, self.engagement(tenant_id, contract_id="c_2"))

  def test_an_engagement_on_a_replaced_contract_cannot_launch_or_start_a_pass_and_its_job_stops(self):
    tenant_id, first, binding, second = self.replaced_with_a_live_first_engagement()
    with self.assertRaises(AdministrationDenied) as denied:
      self.service.resolve_execution_admission(self.actor, tenant_id, first["engagementId"], "ea_1")
    self.assertEqual((denied.exception.status_code, denied.exception.error), (409, "contract_archived"))
    with self.assertRaises(AdministrationDenied) as denied:
      self.service.reauthorize_execution(binding, new_pass=True)
    self.assertEqual((denied.exception.status_code, denied.exception.error), (409, "contract_archived"))
    for end_reason in (self.service.engagement_end_reason, self.service.execution_basis_end_reason):
      self.assertEqual(end_reason(tenant_id, first["engagementId"]), "contract_archived")
      self.assertIsNone(end_reason(tenant_id, second["engagementId"]))
    # The running pass is never refused: finalization, analysis and events reauthorize without `new_pass`.
    self.service.reauthorize_execution(binding)
    self.assertIs(ok(self, self.plugin.get_engagement(self.actor, tenant_id, first["engagementId"]))["engagement"]["contractArchived"], True)
    # RM-255: the job's authorization block cites the engagement's own contract, not `c_1`.
    after = self.service.resolve_execution_admission(self.actor, tenant_id, second["engagementId"], "ea_1").to_dict()["engagement"]
    signed = self.repo.get("tenant", tenant_id)["contracts"]["c_2"]["contract"]
    self.assertEqual(after["authorization"]["document_sha256"], after["contract_sha256"])
    self.assertEqual({key: after["authorization"]["document_" + key] for key in ("filename", "size_bytes")},
                     {key: signed[key] for key in ("filename", "size_bytes")})
    # A job admitted before the amendment keeps its stored `c_1` snapshot.
    self.assertEqual(self.before["authorization"]["document_sha256"], self.repo.get("tenant", tenant_id)["contract"]["sha256"])
    self.assertNotEqual(self.before["authorization"]["document_sha256"], after["contract_sha256"])

  def test_the_older_of_two_contracts_added_side_by_side_is_archived(self):
    """Rows written before the deploy: `c_2` and `c_3` both nobody replaced. `c_3`, the higher, is in force."""
    tenant_id, second = self.second_contract_tenant()
    on_second = ok(self, self.engagement(tenant_id, contract_id=second))
    tenant = self.tenant_row(tenant_id)
    block = copy.deepcopy(tenant["contracts"][second])
    block["contract"]["sha256"] = "e" * 64
    block["contract_generated"]["sha256"] = "d" * 64
    block["supersedes"] = None
    self.repo.put("tenant", tenant_id, record={**tenant, "contracts": {**tenant["contracts"], "c_3": block}})
    contracts = ok(self, self.plugin.get_tenant(self.actor, tenant_id))["contracts"]
    self.assertEqual([(entry["contractId"], entry["state"], entry["supersededBy"]) for entry in contracts],
                     [("c_1", "archived", second), (second, "archived", None), ("c_3", "active", None)])
    self.assertIs(ok(self, self.plugin.get_engagement(self.actor, tenant_id, on_second["engagementId"]))["engagement"]["contractArchived"], True)
    refused(self, self.engagement(tenant_id, contract_id=second), 409, "contract_superseded")
    self.assertEqual(ok(self, self.engagement(tenant_id, contract_id="c_3"))["contractSha256"], "e" * 64)
    child = self.child(tenant_id)["engagement_draft_id"]
    refused(self, self.update_child(child, {"contract_id": second}), 409, "contract_superseded")
    ok(self, self.update_child(child, {"contract_id": "c_3"}))

  def test_a_pick_is_part_of_the_intent_on_a_tenant_with_only_the_first_contract(self):
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    request_id = str(uuid4())
    ok(self, self.engagement(tenant_id, request_id))
    self.assertIs(ok(self, self.engagement(tenant_id, request_id))["replayed"], True)
    refused(self, self.engagement(tenant_id, request_id, contract_id="c_1"), 409, "conflict")

  def test_a_node_only_the_archived_contract_lists_reads_retired_and_is_released_by_hand(self):
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    ok(self, self.activate_contract(tenant_id, self.ready_contract(tenant_id, [PRIVATE_B])))
    # A tenant amended before the deploy still holds the dropped node: the rule reads it retired.
    self.repo.put("tenant_node", tenant_id, "Node-A", record={
      "tenant_id": tenant_id, "node_address": "Node-A", "active": True, "mode": "shared", "draining": False,
      "changed_by": "creator", "changed_at": "2026-11-01T00:00:00+00:00"})
    nodes = {node["nodeAddress"]: node for node in ok(self, self.plugin.get_tenant_nodes(self.actor, tenant_id))["nodes"]}
    self.assertEqual((nodes["Node-A"]["state"], nodes["Node-B"]["state"]), ("retired", "assigned"))
    ok(self, self.plugin.set_tenant_node_assignment(self.actor, tenant_id, "Node-A", False))
    self.assertEqual([node["nodeAddress"] for node in ok(self, self.plugin.get_tenant_nodes(self.actor, tenant_id))["nodes"]], ["Node-B"])

  def test_a_retired_node_is_not_a_held_node_in_the_drift_read(self):
    """RM-213: Node-A (retired) and Node-B (assigned) are both off the peer list; only Node-B is held."""
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    ok(self, self.activate_contract(tenant_id, self.ready_contract(tenant_id, [PRIVATE_B])))
    self.repo.put("tenant_node", tenant_id, "Node-A", record={
      "tenant_id": tenant_id, "node_address": "Node-A", "active": True, "mode": "shared", "draining": False,
      "changed_by": "creator", "changed_at": "2026-11-01T00:00:00+00:00"})
    self.plugin.cfg_chainstore_peers = ["Node-C"]
    held = ok(self, self.plugin.list_deployment_nodes(self.actor))["notInDeployment"]
    self.assertEqual(held, [{"nodeAddress": "Node-B", "alias": None,
                             "tenants": [{"tenantId": tenant_id, "state": "assigned"}]}])

  def test_activating_a_draft_with_no_supersedes_on_a_tenant_with_a_contract_is_refused(self):
    _, tenant_id = self.tenant("acme", nodes=[SHARED_A], fixed=True)
    contract_id = self.ready_contract(tenant_id, [PRIVATE_B])
    self.repo.put("tenant_contract_draft", tenant_id, contract_id, record={**self.stored_contract(tenant_id, contract_id), "supersedes": None})
    refused(self, self.activate_contract(tenant_id, contract_id), 400, "supersedes_required")
