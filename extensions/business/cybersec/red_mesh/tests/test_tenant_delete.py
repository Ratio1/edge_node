"""RM-107: `delete_tenant` through the real plugin endpoint, administration service and CStore adapters."""
import base64
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from .test_tenant_administration import FakeAdministrationStore
from .contract_fixture import install_contract

PDF = b"%PDF-1.7\n%fixture engagement agreement\n%%EOF\n"
TENANCY_HKEY = '["redmesh","tenancy",1,"deployment"]'


class TestTenantDelete(unittest.TestCase):
  @classmethod
  def setUpClass(cls):
    from .conftest import mock_plugin_modules
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    cls.Plugin = PentesterApi01Plugin

  def setUp(self):
    environment = patch.dict("os.environ", {"R1EN_CSTORE_AUTH_HKEY": "auth"})
    environment.start()
    self.addCleanup(environment.stop)
    self.storage = FakeAdministrationStore()
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.cfg_instance_id = "jobs"
    self.plugin.P = lambda *args, **kwargs: None
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.storage, name))
    self.events = []
    self.plugin._log_audit_event = lambda event, details: self.events.append((event, details))
    self.actor = {"account_id": "creator"}
    self.request = str(uuid4())
    prepared = self.plugin.prepare_tenant(self.actor, self.request, "Example", "example", "initial",
                                          **install_contract(self.plugin))
    self.assertTrue(prepared["success"], prepared)
    self.tenant = prepared["data"]["tenantId"]
    self.storage.grant("initial", self.tenant)
    self.assertTrue(self.plugin.activate_tenant(self.actor, self.request)["success"])
    self.documents = self.plugin._document_store()
    self.plugin.configured_peers_reader = None
    refs = [self.upload("Rules of engagement"), self.upload("Scope email", kind="other", raw=PDF + b"2")]
    created = self.plugin.create_engagement(
      self.actor, self.tenant, str(uuid4()), "Q4", ["single_pass"], "2026-10-01T00:00:00Z",
      "2027-10-01T00:00:00Z", {}, {"client_name": "Example"},
      [{"display_name": "Edge", "target": {"kind": "network", "address": "192.0.2.10"},
        "authorized_ports": "443", "authorized_tests": ["service_info_common"]}], refs)
    self.assertTrue(created["success"], created)
    self.engagement_refs = refs
    self.events.clear()

  def upload(self, title, kind="agreement", raw=PDF):
    uploaded = self.plugin.upload_engagement_document(self.actor, self.tenant, "doc.pdf",
                                                      base64.b64encode(raw).decode("ascii"), kind, title)
    self.assertTrue(uploaded["success"], uploaded)
    return uploaded["data"]["ref"]

  def remove_members(self):
    self.storage.account("initial", memberships=[])

  def put_job(self, job_id, tenant_id):
    self.storage.data[("jobs", job_id)] = {"job_id": job_id, "execution_binding": {
      "namespace": "deployment", "tenant_id": tenant_id}}

  def tenancy_rows(self):
    rows = {}
    for (hkey, key), value in self.storage.data.items():
      if hkey == TENANCY_HKEY and value is not None:
        rows.setdefault(json.loads(key)[0], []).append(value)
    return rows

  def refused(self, result, status, error):
    self.assertFalse(result["success"], result)
    self.assertEqual((result["status_code"], result["error"]), (status, error))

  def test_a_tenant_with_members_is_refused_and_left_untouched(self):
    writes = len(self.storage.writes)
    self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 409, "tenant_has_members")
    self.assertEqual(len(self.storage.writes), writes)
    self.assertEqual(self.documents.deleted, [])

  def test_delete_removes_records_and_documents_keeps_the_domain_and_is_audited(self):
    self.remove_members()
    self.put_job("other-job", "tn_" + str(uuid4()))
    result = self.plugin.delete_tenant(self.actor, self.tenant)
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"], {"tenantId": self.tenant, "deleted": True, "engagements": 1,
                                      "integrations": 0, "nodeAssignments": 0, "documents": 3})
    self.assertEqual(sorted(self.documents.deleted), sorted(["doc-fixture", *self.engagement_refs]))
    rows = self.tenancy_rows()
    for kind in ("tenant", "receipt", "engagement", "asset"):
      self.assertNotIn(kind, rows)
    self.assertEqual(len(rows["domain"]), 1)
    self.refused(self.plugin.get_tenant(self.actor, self.tenant), 404, "not_found")
    self.assertEqual(self.plugin.list_tenants(self.actor)["data"], [])
    self.assertEqual(self.plugin.check_tenant_domain(self.actor, "example")["data"], {"available": False})
    # A retried creation finds no receipt and the domain still taken: the tenant cannot come back.
    self.refused(self.plugin.prepare_tenant(self.actor, self.request, "Example", "example", "initial",
                                            **install_contract(self.plugin)), 409, "domain_conflict")
    self.assertEqual(self.events, [("tenant_deleted", {
      "tenant_id": self.tenant, "actor": "creator", "engagements": 1, "integrations": 0,
      "nodeAssignments": 0, "documents": 3})])
    self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 404, "not_found")

  def test_a_tenant_with_jobs_is_refused_before_anything_changes(self):
    self.remove_members()
    self.put_job("job-1", self.tenant)
    self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 409, "tenant_has_jobs")
    self.assertTrue(self.plugin.get_tenant(self.actor, self.tenant)["success"])
    self.assertEqual(self.documents.deleted, [])
    self.storage.data[("jobs", "job-1")] = None  # purged
    self.assertTrue(self.plugin.delete_tenant(self.actor, self.tenant)["success"])

  def test_a_job_written_after_the_mark_gives_the_tenant_back(self):
    self.remove_members()
    answers = iter([[], ["late-job"]])
    with patch.object(self.Plugin, "_tenant_job_ids", lambda plugin, tenant_id: next(answers)):
      self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 409, "tenant_has_jobs")
    self.assertTrue(self.plugin.get_tenant(self.actor, self.tenant)["success"])
    self.assertNotIn("deleting", self.tenancy_rows()["tenant"][0])
    self.assertEqual(self.documents.deleted, [])

  def test_a_failed_give_back_is_finished_by_a_retry(self):
    self.remove_members()
    answers = iter([[], ["late-job"]])
    real = self.Plugin._call_tenant_administration

    def abort_fails(plugin, operation, *args, **kwargs):
      if operation == "abort_tenant_delete":
        return {"success": False, "status": "error", "status_code": 503, "error": "unavailable"}
      return real(plugin, operation, *args, **kwargs)
    with patch.object(self.Plugin, "_tenant_job_ids", lambda plugin, tenant_id: next(answers)), \
         patch.object(self.Plugin, "_call_tenant_administration", abort_fails):
      self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 503, "unavailable")
    self.assertIn("deleting", self.tenancy_rows()["tenant"][0])
    # The job is still there: the retry refuses at the first check and gives the tenant back.
    self.put_job("late-job", self.tenant)
    self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 409, "tenant_has_jobs")
    self.assertNotIn("deleting", self.tenancy_rows()["tenant"][0])
    self.assertTrue(self.plugin.get_tenant(self.actor, self.tenant)["success"])
    self.assertEqual(self.documents.deleted, [])

  def test_unreadable_jobs_are_unavailable_not_none(self):
    self.remove_members()
    self.storage.data[("jobs", "broken")] = "not a record"
    with patch.object(self.Plugin, "_get_job_state_repository", side_effect=RuntimeError("down")):
      self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 503, "unavailable")
    self.assertTrue(self.plugin.get_tenant(self.actor, self.tenant)["success"])

  def test_a_failed_document_delete_is_finished_by_a_retry(self):
    self.remove_members()
    self.documents.fail_delete = {self.engagement_refs[1]}
    self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 503, "unavailable")
    # Marked: inactive to everything else, records kept so the retry still finds every document.
    self.refused(self.plugin.get_tenant(self.actor, self.tenant), 404, "not_found")
    self.assertIn("engagement", self.tenancy_rows())
    self.refused(self.plugin.activate_tenant(self.actor, self.request), 409, "tenant_deleting")
    first = list(self.documents.deleted)
    self.documents.fail_delete = set()
    self.assertTrue(self.plugin.delete_tenant(self.actor, self.tenant)["success"])
    self.assertNotIn(self.engagement_refs[1], first)
    # Every document is deleted, none twice.
    self.assertEqual(sorted(self.documents.deleted), sorted(["doc-fixture", *self.engagement_refs]))
    self.assertEqual(self.documents.deleted[:len(first)], first)
    self.assertEqual(self.events[-1][1]["documents"], 3)

  def test_a_record_delete_that_stopped_after_the_receipt_is_finished_by_a_retry(self):
    from extensions.business.cybersec.red_mesh.tenancy.adapters.cstore_administration import (
      CstoreTenantAdministrationStore)
    from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
    self.remove_members()
    original = CstoreTenantAdministrationStore.delete

    def failing(store, kind, *ids):
      if kind == "tenant":
        raise TenantStoreError("write not verified")
      return original(store, kind, *ids)
    with patch.object(CstoreTenantAdministrationStore, "delete", failing):
      self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 503, "unavailable")
    rows = self.tenancy_rows()
    self.assertNotIn("receipt", rows)
    self.assertIn("deleting", rows["tenant"][0])
    result = self.plugin.delete_tenant(self.actor, self.tenant)
    self.assertTrue(result["success"], result)
    self.assertNotIn("tenant", self.tenancy_rows())

  def test_a_document_deleted_but_not_recorded_does_not_block_the_retry(self):
    self.remove_members()
    # An earlier attempt deleted this file and stopped before recording it: the backend no longer
    # confirms a delete for it, and it reads as absent.
    gone = self.engagement_refs[0]
    self.documents.envelopes.pop(gone)
    self.documents.fail_delete = {gone}
    result = self.plugin.delete_tenant(self.actor, self.tenant)
    self.assertTrue(result["success"], result)
    self.assertEqual(result["data"]["documents"], 3)
  def test_a_document_the_backend_still_holds_stops_the_delete(self):
    self.remove_members()
    self.documents.fail_delete = {"doc-fixture"}
    self.refused(self.plugin.delete_tenant(self.actor, self.tenant), 503, "unavailable")
    self.assertIn("doc-fixture", self.documents.envelopes)
    self.assertIn("tenant", self.tenancy_rows())

  def test_only_a_super_tenant_admin_deletes(self):
    self.storage.account("platform-pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.refused(self.plugin.delete_tenant({"account_id": "platform-pentester"}, self.tenant), 403, "forbidden")
    self.refused(self.plugin.delete_tenant({"account_id": "initial"}, self.tenant), 403, "forbidden")
    self.refused(self.plugin.delete_tenant({"account_id": "stranger"}, self.tenant), 404, "not_found")
    self.refused(self.plugin.delete_tenant(self.actor, "tn_" + str(uuid4())), 404, "not_found")
    self.assertTrue(self.plugin.get_tenant(self.actor, self.tenant)["success"])

  def test_a_tenant_created_before_contracts_and_a_v1_engagement_row_are_deleted(self):
    self.remove_members()
    for (hkey, key), row in list(self.storage.data.items()):
      if hkey == TENANCY_HKEY and isinstance(row, dict) and row.get("tenant_id") == self.tenant:
        if row.get("kind") in ("tenant", "receipt"):
          row.pop("legal", None), row.pop("contract", None)
        if row.get("kind") == "engagement":
          # An RM-095 record: the v2 validator refuses it, the delete still clears it and its files.
          row.pop("documents"), row.update(roe_document={"store": "fake", "ref": "doc-roe-v1"})
    self.documents.envelopes["doc-roe-v1"] = {"kind": "redmesh_engagement_document"}
    result = self.plugin.delete_tenant(self.actor, self.tenant)
    self.assertTrue(result["success"], result)
    self.assertEqual(sorted(self.documents.deleted), ["doc-roe-v1"])
    self.assertNotIn("tenant", self.tenancy_rows())


if __name__ == "__main__":
  unittest.main()
