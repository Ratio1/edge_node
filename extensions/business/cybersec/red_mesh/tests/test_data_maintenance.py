"""RM-108 (temporary): backup export, old-format cleanup and restore through the plugin endpoints."""
import base64
import copy
import hashlib
import json
import unittest
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.services import data_maintenance
from .contract_fixture import install_contract
from .test_execution_binding_models import binding_payload
from .test_tenant_administration import FakeAdministrationStore

TENANCY = '["redmesh","tenancy",1,"deployment"]'
JOBS = "jobs"


def binding_v1_payload():
  """Schema 1 (RM-084): a tenant asset row. No longer built or read outside this tool."""
  value = {key: item for key, item in binding_payload().items()
           if key not in ("engagement_id", "engagement_asset_id", "engagement_hash")}
  return {**value, "schema_version": 1, "asset_id": "as_" + str(uuid4())}


def cid(number):
  return "Qm" + str(number).rjust(44, "1").replace("0", "A")


CONFIG, ARCHIVE, REPORT, SECRET, BUNDLE, SHARED, EVIDENCE = (cid(n) for n in range(1, 8))


def job(job_id, binding, **extra):
  return {"job_id": job_id, "job_status": "FINALIZED", "run_mode": "SINGLEPASS", "launcher": "node-a",
          "target": "192.0.2.10", "start_port": 20, "end_port": 25, "date_created": 1,
          "job_config_cid": CONFIG, "job_cid": ARCHIVE, **({"execution_binding": binding}
                                                           if binding is not None else {}), **extra}


class Files:
  """R1FS as the artifact repository sees it, plus what the raw `ipfs` calls would return."""

  def __init__(self):
    self.json = {
      CONFIG: {"target": "192.0.2.10", "secret_ref": SECRET},
      ARCHIVE: {"job_id": "old1", "passes": [{"pass_nr": 1, "aggregated_report_cid": SHARED,
                                                "worker_reports": {"node-a": {"report_cid": REPORT}}}]},
    }
    self.deleted = []
    self.refuse = set()

  def get_json(self, reference, **kwargs):
    return copy.deepcopy(self.json.get(reference))

  def delete(self, reference, **kwargs):
    if reference in self.refuse:
      return False
    self.deleted.append(reference)
    return True


class TestDataMaintenance(unittest.TestCase):
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
    self.storage.account("pentester", memberships=[{"role": "super_pentester", "tenant_id": None}])
    self.plugin = object.__new__(self.Plugin)
    self.plugin.cfg_tenancy_namespace = "deployment"
    self.plugin.cfg_instance_id = JOBS
    self.plugin.P = lambda *args, **kwargs: None
    for name in ("chainstore_hget", "chainstore_hgetall", "chainstore_hset"):
      setattr(self.plugin, name, getattr(self.storage, name))
    self.events = []
    self.plugin._log_audit_event = lambda event, details: self.events.append((event, details))
    self.actor = {"account_id": "creator"}
    request = str(uuid4())
    prepared = self.plugin.prepare_tenant(self.actor, request, "Example", "example", "initial",
                                          **install_contract(self.plugin))
    self.assertTrue(prepared["success"], prepared)
    self.tenant = prepared["data"]["tenantId"]
    self.storage.grant("initial", self.tenant)
    self.assertTrue(self.plugin.activate_tenant(self.actor, request)["success"])
    self.files = Files()
    self.plugin._get_artifact_repository = lambda: self.files
    # What `ipfs pin ls` would say: unknown unless a test says so.
    self.pins = {}
    pins = patch.object(data_maintenance, "pinned_locally", side_effect=lambda item, home: self.pins.get(item))
    pins.start()
    self.addCleanup(pins.stop)
    self.current = binding_payload()
    self.current["tenant_id"] = self.tenant
    self.put(JOBS, "new1", job("new1", self.current, job_config_cid=cid(20), job_cid=cid(21),
                                stix_export={"artifact_cid": SHARED}))
    self.files.json[cid(20)] = {"target": "192.0.2.10"}
    self.files.json[cid(21)] = {"job_id": "new1", "passes": []}
    self.put(JOBS, "old1", job("old1", binding_v1_payload(), opencti_export={"artifact_cid": BUNDLE}))
    self.put(f"{JOBS}:live", "old1:node-a", {"job_id": "old1"})
    self.put(f"{JOBS}:model_test_raw_evidence", "old1", {"artifact_cid": EVIDENCE})
    self.events.clear()

  def put(self, hkey, field, value):
    self.storage.data[(hkey, field)] = copy.deepcopy(value)

  def scan(self):
    rows, cursor = [], {"hkey_index": 0, "offset": 0}
    while cursor:
      page = self.plugin.export_redmesh_records(self.actor, cursor["hkey_index"], cursor["offset"], 2)
      self.assertTrue(page["success"], page)
      rows += page["data"]["rows"]
      cursor = page["data"]["next"]
    return {(row["hkey"], row["field"]): row for row in rows}

  def target(self, row):
    return {"hkey": row["hkey"], "field": row["field"], "expected_sha256": row["sha256"]}

  def clean(self, *rows):
    done = self.plugin.cleanup_redmesh_old_data(self.actor, True, [self.target(row) for row in rows])
    self.assertTrue(done["success"], done)
    return done["data"]["outcomes"]

  # -- authorization ----------------------------------------------------------------------------

  def test_only_a_full_portfolio_super_tenant_admin_calls_any_of_the_five(self):
    calls = (
      lambda actor: self.plugin.export_redmesh_records(actor, 0, 0, 10),
      lambda actor: self.plugin.export_redmesh_file(actor, JOBS, "old1", CONFIG),
      lambda actor: self.plugin.cleanup_redmesh_old_data(actor, True, []),
      lambda actor: self.plugin.restore_redmesh_file(actor, CONFIG, "a.bin", "", ""),
      lambda actor: self.plugin.restore_redmesh_records(actor, []),
    )
    before = copy.deepcopy(self.storage.data)
    for actor in ({"account_id": "pentester"}, {"account_id": "initial"}, {"account_id": "nobody"}, None):
      for call in calls:
        result = call(actor)
        self.assertFalse(result["success"])
        self.assertIn(result["status_code"], (401, 403, 404))
    self.assertEqual(self.storage.data, before)
    self.assertEqual(self.files.deleted, [])

  # -- export -----------------------------------------------------------------------------------

  def test_export_pages_through_every_registered_hkey_and_classifies_rows(self):
    rows = self.scan()
    self.assertEqual(rows[(JOBS, "new1")]["class"], "current")
    self.assertEqual((rows[(JOBS, "old1")]["class"], rows[(JOBS, "old1")]["reason"]),
                     ("old", "binding_schema_1"))
    self.assertEqual(rows[(f"{JOBS}:live", "old1:node-a")]["reason"], "old_job")
    self.assertEqual(rows[("auth", "creator")]["class"], "current")
    tenancy = [row for (hkey, _), row in rows.items() if hkey == TENANCY]
    self.assertEqual({row["class"] for row in tenancy}, {"current"})
    self.assertEqual({json.loads(row["field"])[0] for row in tenancy}, {"tenant", "receipt", "domain"})
    # Every page is audited, with where it read and nothing of what it read.
    exported = [details for event, details in self.events if event == "data_exported"]
    self.assertGreater(len(exported), 5)
    self.assertEqual(exported[0], {"actor": "creator", "hkey_index": 0, "offset": 0, "status_code": 200})

  def test_the_registry_names_every_hkey_the_plugin_builds(self):
    import pathlib
    import re
    root = pathlib.Path(data_maintenance.__file__).resolve().parents[1]
    built = set()
    for path in root.rglob("*.py"):
      if "tests" in path.parts or path.name == "data_maintenance.py":
        continue
      text = path.read_text(encoding="utf-8")
      built.update(re.findall(r"""cfg_instance_id[^"'\n]*\}((?::[a-z_]+)+)[:"']""", text))
    self.assertTrue(built)
    hkeys = self.plugin.export_redmesh_records(self.actor, 0, 0, 1)["data"]["hkeys"]
    names = {item["hkey"] for item in hkeys}
    self.assertEqual({JOBS + suffix for suffix in built} - names, set())
    self.assertLessEqual({JOBS, TENANCY, "auth", f"{JOBS}:integrations:{self.tenant}"}, names)
    self.assertEqual([item["hkey"] for item in hkeys if item["account"]], ["auth"])

  def test_a_job_lists_the_files_its_record_config_and_archive_name(self):
    row = self.scan()[(JOBS, "old1")]
    self.assertEqual({item["cid"] for item in row["cids"]}, {CONFIG, ARCHIVE, REPORT, SECRET, BUNDLE, SHARED})
    self.assertTrue(row["files_complete"])
    self.assertEqual(self.scan()[(f"{JOBS}:model_test_raw_evidence", "old1")]["cids"],
                     [{"cid": EVIDENCE, "role": "artifact_cid", "withheld": False}])

  def test_an_unreadable_archive_marks_the_row_and_blocks_its_cleanup(self):
    del self.files.json[ARCHIVE]
    row = self.scan()[(JOBS, "old1")]
    self.assertFalse(row["files_complete"])
    self.assertEqual(self.clean(row)[0]["outcome"], "files_unknown")
    self.assertIsNotNone(self.storage.data[(JOBS, "old1")])
    self.assertEqual(self.files.deleted, [])

  def test_old_formats_of_every_kind_are_named(self):
    asset = json.dumps(["asset", "deployment", self.tenant, "as_1"], separators=(",", ":"))
    engagement = json.dumps(["engagement", "deployment", self.tenant, "en_1"], separators=(",", ":"))
    gone = json.dumps(["tenant_node", "deployment", "tn_" + str(uuid4()), "node"], separators=(",", ":"))
    self.put(TENANCY, asset, {"kind": "asset"})
    self.put(TENANCY, engagement, {"kind": "engagement", "engagement_kind": "point-in-time",
                                   "roe_document": {"ref": cid(30)}})
    self.put(TENANCY, gone, {"kind": "tenant_node"})
    self.put(TENANCY, "not json", {"x": 1})
    self.put(JOBS, "unbound", job("unbound", None))
    self.put(JOBS, "moved", job("other", self.current))
    self.put(JOBS, "text", "a string")
    self.put(JOBS, "dead", None)
    self.put(f"{JOBS}:triage", "missing:f1", {"state": "open"})
    self.put(f"{JOBS}:triage:audit", "new1:f1", {"not": "a list"})
    self.put(f"{JOBS}:integrations", "wazuh", {"last_success_at": "2026-09-01T00:00:00Z",
                                                "last_artifact_cid": SECRET})
    self.put(f"{JOBS}:integrations", "retired", {"last_success_at": "2026-09-01T00:00:00Z"})
    self.put(f"{JOBS}:integrations", "stix", "text")
    rows = self.scan()
    found = {key: (row["class"], row["reason"]) for key, row in rows.items()}
    self.assertEqual(found[(TENANCY, asset)], ("old", "asset_row"))
    self.assertEqual(found[(TENANCY, engagement)], ("old", "engagement_v1"))
    self.assertEqual(rows[(TENANCY, engagement)]["cids"], [{"cid": cid(30), "role": "roe_document.ref", "withheld": False}])
    self.assertEqual(found[(TENANCY, gone)], ("old", "unrecognized"))
    self.assertEqual(found[(TENANCY, "not json")], ("old", "unrecognized"))
    self.assertEqual(found[(JOBS, "unbound")], ("old", "unbound_job"))
    self.assertEqual(found[(JOBS, "moved")], ("old", "legacy_job_key"))
    self.assertEqual(found[(JOBS, "text")], ("old", "unrecognized"))
    self.assertEqual(found[(JOBS, "dead")], ("tombstone", ""))
    self.assertEqual(found[(f"{JOBS}:triage", "missing:f1")], ("orphan", "job_gone"))
    self.assertEqual(found[(f"{JOBS}:triage:audit", "new1:f1")], ("old", "unrecognized"))
    self.assertEqual(found[(f"{JOBS}:integrations", "wazuh")], ("current", ""))
    self.assertEqual(found[(f"{JOBS}:integrations", "retired")], ("old", "unrecognized"))
    self.assertEqual(found[(f"{JOBS}:integrations", "stix")], ("old", "unrecognized"))
    # A status row remembers a file without owning it: the old job's file still goes.
    self.assertEqual(self.clean(rows[(JOBS, "old1")])[0]["files_kept"], 1)
    self.assertIn(SECRET, self.files.deleted)

  def test_a_tenant_without_a_contract_is_old_and_so_are_its_rows(self):
    tenant = json.dumps(["tenant", "deployment", self.tenant], separators=(",", ":"))
    row = self.storage.data[(TENANCY, tenant)]
    del row["contract"], row["legal"]
    self.put(f"{JOBS}:integrations:{self.tenant}", "wazuh", {"last_success_at": "2026-09-01T00:00:00Z"})
    rows = self.scan()
    self.assertEqual((rows[(TENANCY, tenant)]["class"], rows[(TENANCY, tenant)]["reason"]),
                     ("old", "tenant_without_contract"))
    self.assertEqual((rows[(f"{JOBS}:integrations:{self.tenant}", "wazuh")]["class"],
                      rows[(f"{JOBS}:integrations:{self.tenant}", "wazuh")]["reason"]), ("old", "old_tenant"))
    self.assertEqual(rows[(JOBS, "new1")]["class"], "current")

  def draft_row(self):
    """RM-109. A tenant draft with a signed contract file, written through the real endpoint."""
    created = self.plugin.create_tenant_draft(self.actor, str(uuid4()), "Draft", ["nis2"])
    self.assertTrue(created["success"], created)
    draft_id = created["data"]["draft_id"]
    field = json.dumps(["tenant_draft", "deployment", draft_id], separators=(",", ":"))
    row = self.storage.data[(TENANCY, field)]
    row["items"]["contract"].update(state="signed", document={
      "store": "r1fs", "ref": cid(40), "filename": "contract.pdf", "mime": "application/pdf",
      "uploaded_at": "2026-10-07T00:00:00Z", "uploaded_by": "creator", "sha256": "a" * 64, "size_bytes": 10})
    self.events.clear()
    return field

  def test_a_tenant_draft_is_current_its_files_are_listed_and_cleanup_keeps_it(self):
    # A draft has no tenant: it must never read as an orphan of the tenant its id is not.
    field = self.draft_row()
    rows = self.scan()
    row = rows[(TENANCY, field)]
    self.assertEqual((row["class"], row["reason"]), ("current", ""))
    self.assertEqual(row["cids"], [{"cid": cid(40), "role": "items.contract.document.ref", "withheld": False}])
    self.assertTrue(row["files_complete"])
    self.assertEqual(self.clean(row)[0]["outcome"], "not_old")
    self.assertIsNotNone(self.storage.data[(TENANCY, field)])
    self.assertEqual(self.files.deleted, [])
    # Still current once every tenant is gone.
    tenant = json.dumps(["tenant", "deployment", self.tenant], separators=(",", ":"))
    del self.storage.data[(TENANCY, tenant)]["contract"]
    self.assertEqual(self.scan()[(TENANCY, field)]["class"], "current")

  def test_a_malformed_tenant_draft_is_old_not_orphan(self):
    field = self.draft_row()
    self.storage.data[(TENANCY, field)]["items"]["contract"]["state"] = "done"
    row = self.scan()[(TENANCY, field)]
    self.assertEqual((row["class"], row["reason"]), ("old", "unrecognized"))
    self.assertEqual(row["cids"], [{"cid": cid(40), "role": "items.contract.document.ref", "withheld": False}])

  def test_a_file_is_served_only_for_a_row_that_references_it(self):
    with patch.object(data_maintenance, "read_stored_file", return_value={"cid": CONFIG}) as read:
      self.assertTrue(self.plugin.export_redmesh_file(self.actor, JOBS, "old1", CONFIG)["success"])
      refused = self.plugin.export_redmesh_file(self.actor, JOBS, "new1", CONFIG)
      self.assertEqual((refused["status_code"], refused["error"]), (404, "file_not_in_inventory"))
      self.assertEqual(self.plugin.export_redmesh_file(self.actor, "other", "x", CONFIG)["status_code"], 400)
      self.assertEqual(read.call_count, 1)

  def test_bad_paging_is_refused(self):
    for arguments in ((-1, 0, 10), (0, -1, 10), (0, 0, 0), (0, 0, 51), (99, 0, 10), ("0", 0, 10), (True, 0, 10)):
      result = self.plugin.export_redmesh_records(self.actor, *arguments)
      self.assertEqual((result["status_code"], result["error"]), (400, "invalid_request"), arguments)

  # -- cleanup ----------------------------------------------------------------------------------

  def test_cleanup_deletes_each_old_row_with_its_files_and_keeps_a_shared_file(self):
    rows = self.scan()
    targets = [rows[(JOBS, "old1")], rows[(f"{JOBS}:live", "old1:node-a")],
               rows[(f"{JOBS}:model_test_raw_evidence", "old1")]]
    outcomes = self.clean(*targets)
    self.assertEqual(outcomes[0], {"hkey": JOBS, "field": "old1", "outcome": "deleted",
                                   "files_deleted": 5, "files_kept": 1, "files_unverified": 0})
    self.assertEqual([item["outcome"] for item in outcomes], ["deleted"] * 3)
    self.assertEqual(sorted(self.files.deleted), sorted([CONFIG, ARCHIVE, REPORT, SECRET, BUNDLE, EVIDENCE]))
    for key in ((JOBS, "old1"), (f"{JOBS}:live", "old1:node-a"), (f"{JOBS}:model_test_raw_evidence", "old1")):
      self.assertIsNone(self.storage.data[key])
    self.assertIsNotNone(self.storage.data[(JOBS, "new1")])
    self.assertEqual(self.events[-1], ("old_data_deleted", {"actor": "creator", "targets": 3, "status_code": 200,
                                                             "outcomes": {"deleted": 3}}))
    after = self.scan()
    self.assertEqual({row["class"] for row in after.values()}, {"current", "tombstone"})

  def test_a_job_row_is_deleted_alone_and_its_other_rows_keep_their_own_hash_check(self):
    rows = self.scan()
    self.clean(rows[(JOBS, "old1")])
    self.assertIsNotNone(self.storage.data[(f"{JOBS}:live", "old1:node-a")])
    # Changed after the scan: refused, so the backup never misses the newer value.
    self.storage.data[(f"{JOBS}:live", "old1:node-a")]["progress"] = 50
    self.assertEqual(self.clean(rows[(f"{JOBS}:live", "old1:node-a")])[0]["outcome"], "changed")
    fresh = self.scan()[(f"{JOBS}:live", "old1:node-a")]
    self.assertEqual((fresh["class"], fresh["reason"]), ("orphan", "job_gone"))
    self.assertEqual(self.clean(fresh)[0]["outcome"], "deleted")

  def test_the_rows_of_a_running_old_job_are_never_deleted(self):
    self.put(JOBS, "busy", job("busy", binding_v1_payload(), job_status="RUNNING"))
    self.put(f"{JOBS}:triage", "busy:f1", {"state": "open"})
    rows = self.scan()
    self.assertEqual(rows[(f"{JOBS}:triage", "busy:f1")]["reason"], "old_job")
    outcomes = self.clean(rows[(JOBS, "busy")], rows[(f"{JOBS}:triage", "busy:f1")])
    self.assertEqual([item["outcome"] for item in outcomes], ["running", "running"])
    self.assertIsNotNone(self.storage.data[(f"{JOBS}:triage", "busy:f1")])

  def test_nothing_with_files_is_deleted_while_a_current_row_cannot_be_read_in_full(self):
    del self.files.json[cid(21)]
    rows = self.scan()
    self.assertFalse(rows[(JOBS, "new1")]["files_complete"])
    self.assertEqual(self.clean(rows[(JOBS, "old1")])[0]["outcome"], "files_unknown")
    self.assertEqual(self.files.deleted, [])
    asset = json.dumps(["asset", "deployment", self.tenant, "as_1"], separators=(",", ":"))
    self.put(TENANCY, asset, {"kind": "asset"})
    self.assertEqual(self.clean(self.scan()[(TENANCY, asset)])[0]["outcome"], "deleted")

  def test_a_config_with_inline_credentials_is_withheld_from_the_backup(self):
    self.files.json[CONFIG]["official_password"] = "not-for-export"
    self.files.json[cid(40)] = {"third": 1}
    self.put(JOBS, "old1", {**self.storage.data[(JOBS, "old1")],
                             "authorization": {"third_party_auth_cids": [cid(40), "not a cid"]}})
    row = self.scan()[(JOBS, "old1")]
    listed = {item["cid"]: item for item in row["cids"]}
    self.assertTrue(listed[CONFIG]["withheld"])
    self.assertFalse(listed[ARCHIVE]["withheld"])
    self.assertEqual(listed[cid(40)]["role"], "authorization.third_party_auth_cids[0]")
    with patch.object(data_maintenance, "read_stored_file") as read:
      refused = self.plugin.export_redmesh_file(self.actor, JOBS, "old1", CONFIG)
      self.assertEqual((refused["status_code"], refused["error"]), (409, "file_withheld"))
      read.assert_not_called()
    # Withheld from the backup, still deleted with its job.
    self.assertEqual(self.clean(row)[0]["outcome"], "deleted")
    self.assertIn(CONFIG, self.files.deleted)

  def test_credential_files_under_the_built_in_key_are_withheld(self):
    fallback, safe, evidence = cid(41), cid(42), cid(43)
    self.files.json[CONFIG].update(secret_store_unsafe_fallback=True, secret_ref=fallback)
    self.files.json[ARCHIVE]["job_config"] = {"model_provider_secret_ref": safe,
                                              "model_provider_secret_store_unsafe_fallback": False}
    self.put(f"{JOBS}:model_test_raw_evidence", "old1", {"artifact_cid": evidence, "unsafe_key_fallback": True})
    rows = self.scan()
    listed = {item["cid"]: item["withheld"] for item in rows[(JOBS, "old1")]["cids"]}
    self.assertEqual((listed[fallback], listed[safe], listed[CONFIG]), (True, False, False))
    self.assertEqual(rows[(f"{JOBS}:model_test_raw_evidence", "old1")]["cids"],
                     [{"cid": evidence, "role": "artifact_cid", "withheld": True}])

  def test_an_archive_embedding_a_config_with_inline_credentials_is_withheld(self):
    self.files.json[ARCHIVE]["job_config"] = {"regular_password": "not-for-export", "official_password": ""}
    listed = {item["cid"]: item["withheld"] for item in self.scan()[(JOBS, "old1")]["cids"]}
    self.assertEqual((listed[ARCHIVE], listed[CONFIG]), (True, False))

  def test_a_current_config_with_blank_credential_fields_is_exported(self):
    self.files.json[cid(20)].update(official_password="", bearer_token="", weak_candidates=[],
                                    secret_store_unsafe_fallback=False, secret_ref=cid(44))
    listed = {item["cid"]: item["withheld"] for item in self.scan()[(JOBS, "new1")]["cids"]}
    self.assertEqual((listed[cid(20)], listed[cid(44)]), (False, False))

  def test_a_file_two_old_rows_share_is_deleted_once(self):
    self.put(JOBS, "old2", job("old2", binding_v1_payload(), job_config_cid=cid(50), job_cid=cid(51),
                                opencti_export={"artifact_cid": BUNDLE}))
    self.files.json[cid(50)] = {"target": "192.0.2.10"}
    self.files.json[cid(51)] = {"job_id": "old2", "passes": []}
    rows = self.scan()
    outcomes = self.clean(rows[(JOBS, "old1")], rows[(JOBS, "old2")])
    self.assertEqual([item["outcome"] for item in outcomes], ["deleted", "deleted"])
    self.assertEqual(self.files.deleted.count(BUNDLE), 1)

  def test_a_failed_delete_stops_before_the_files_that_list_the_others(self):
    self.files.refuse = {BUNDLE}
    row = self.scan()[(JOBS, "old1")]
    self.assertEqual(self.clean(row)[0]["outcome"], "partial")
    # The config and the archive were not touched: the row still lists all its files.
    self.assertNotIn(CONFIG, self.files.deleted)
    self.assertNotIn(ARCHIVE, self.files.deleted)
    self.assertTrue(self.scan()[(JOBS, "old1")]["files_complete"])

  def test_a_file_gone_from_this_node_is_counted_unverified_and_a_failed_one_stops_the_row(self):
    self.files.refuse = {BUNDLE}
    self.pins[BUNDLE] = False
    outcome = self.clean(self.scan()[(JOBS, "old1")])[0]
    self.assertEqual((outcome["outcome"], outcome["files_unverified"]), ("deleted", 1))
    self.assertEqual(self.events[-1][1]["outcomes"], {"deleted": 1})
    # Still pinned here after a failed delete: a real failure.
    self.pins[BUNDLE] = True
    self.put(JOBS, "old1", job("old1", binding_v1_payload(), opencti_export={"artifact_cid": BUNDLE},
                               job_config_cid=None, job_cid=None))
    self.assertEqual(self.clean(self.scan()[(JOBS, "old1")])[0]["outcome"], "partial")
    # `ipfs` could not tell: a failure too.
    self.pins[BUNDLE] = None
    self.assertEqual(self.clean(self.scan()[(JOBS, "old1")])[0]["outcome"], "partial")

  def test_a_container_gone_from_this_node_does_not_lock_the_row(self):
    # A restored old job whose archive was withheld: the archive is gone, the row can be cleaned.
    del self.files.json[ARCHIVE]
    self.pins[ARCHIVE] = False
    row = self.scan()[(JOBS, "old1")]
    self.assertTrue(row["files_complete"])
    self.assertNotIn(ARCHIVE, {item["cid"] for item in row["cids"]})
    self.assertEqual(self.clean(row)[0]["outcome"], "deleted")
    self.assertNotIn(ARCHIVE, self.files.deleted)

  def test_a_gone_file_is_answered_410(self):
    self.pins[CONFIG] = False
    with patch.object(data_maintenance, "read_stored_file",
                      side_effect=data_maintenance.MaintenanceError(503, "file_unavailable")):
      answer = self.plugin.export_redmesh_file(self.actor, JOBS, "old1", CONFIG)
    self.assertEqual((answer["status_code"], answer["error"]), (410, "file_gone"))

  def test_audit_details_from_the_caller_are_bounded(self):
    self.plugin.export_redmesh_file({"account_id": "x" * 500}, JOBS, "old1", {"not": "a cid"})
    self.plugin.export_redmesh_records(self.actor, 0, "y" * 500, 10)
    self.assertEqual(self.events[0][1], {"actor": "x" * 128, "cid": None, "status_code": 404})
    self.assertEqual(self.events[1][1]["offset"], "y" * 128)

  def test_the_files_of_a_running_old_job_are_kept(self):
    self.put(JOBS, "busy", job("busy", binding_v1_payload(), job_status="RUNNING", job_config_cid=cid(52),
                               job_cid=None, opencti_export={"artifact_cid": BUNDLE}))
    self.files.json[cid(52)] = {"target": "192.0.2.10"}
    outcome = self.clean(self.scan()[(JOBS, "old1")])[0]
    self.assertEqual(outcome["outcome"], "deleted")
    self.assertNotIn(BUNDLE, self.files.deleted)

  def test_a_refused_call_is_audited_with_the_account_it_claimed(self):
    self.plugin.export_redmesh_records({"account_id": "pentester"}, 0, 0, 10)
    self.assertEqual(self.events, [("data_exported", {"actor": "pentester", "hkey_index": 0, "offset": 0,
                                                      "status_code": 403})])

  def test_file_exports_and_restores_are_audited_by_cid(self):
    with patch.object(data_maintenance, "read_stored_file", return_value={"cid": CONFIG}):
      self.plugin.export_redmesh_file(self.actor, JOBS, "old1", CONFIG)
    self.plugin.restore_redmesh_file(self.actor, "--bad", "a.bin", "", "")
    self.assertEqual(self.events, [
      ("data_file_exported", {"actor": "creator", "cid": CONFIG, "status_code": 200}),
      ("data_file_restored", {"actor": "creator", "cid": "--bad", "status_code": 400})])

  def test_cleanup_refuses_what_changed_runs_or_is_current(self):
    rows = self.scan()
    self.put(JOBS, "busy", job("busy", binding_v1_payload(), job_status="RUNNING"))
    busy = self.scan()[(JOBS, "busy")]
    stale = dict(rows[(JOBS, "old1")])
    self.storage.data[(JOBS, "old1")]["job_status"] = "STOPPED"
    outcomes = self.clean(stale, busy, rows[(JOBS, "new1")], rows[("auth", "creator")],
                          {"hkey": JOBS, "field": "never", "sha256": "0" * 64})
    self.assertEqual([item["outcome"] for item in outcomes],
                     ["changed", "running", "not_old", "refused", "absent"])
    self.assertEqual(self.files.deleted, [])
    self.assertIsNotNone(self.storage.data[("auth", "creator")])

  def test_a_failed_file_delete_keeps_the_row(self):
    self.files.refuse = {REPORT}
    outcome = self.clean(self.scan()[(JOBS, "old1")])[0]
    self.assertEqual(outcome["outcome"], "partial")
    self.assertIsNotNone(self.storage.data[(JOBS, "old1")])
    self.files.refuse = set()
    self.assertEqual(self.clean(self.scan()[(JOBS, "old1")])[0]["outcome"], "deleted")

  def test_cleanup_needs_confirm_and_a_bounded_list(self):
    row = self.target(self.scan()[(JOBS, "old1")])
    for confirm, targets in ((False, [row]), ("true", [row]), (True, []), (True, [row, row]),
                             (True, [{**row, "extra": 1}]), (True, [row] * 101), (True, None)):
      result = self.plugin.cleanup_redmesh_old_data(self.actor, confirm, targets)
      self.assertEqual((result["status_code"], result["error"]), (400, "invalid_request"))
    self.assertIsNotNone(self.storage.data[(JOBS, "old1")])

  # -- restore ----------------------------------------------------------------------------------

  def test_restore_writes_back_what_is_gone_and_never_overwrites(self):
    rows = self.scan()
    saved = [{"hkey": key[0], "field": key[1], "value": rows[key]["value"]}
             for key in ((JOBS, "old1"), (JOBS, "new1"), ("auth", "creator"))]
    self.clean(rows[(JOBS, "old1")])
    self.storage.data[(JOBS, "new1")]["job_status"] = "STOPPED"
    self.events.clear()
    done = self.plugin.restore_redmesh_records(self.actor, saved + [
      {"hkey": "elsewhere", "field": "x", "value": {"a": 1}},
      {"hkey": f"{JOBS}:integrations:tn_{uuid4()}", "field": "wazuh", "value": {"schema_version": "1.0.0"}}])
    self.assertTrue(done["success"], done)
    self.assertEqual([item["outcome"] for item in done["data"]["outcomes"]],
                     ["written", "conflict", "refused", "refused", "written"])
    self.assertEqual(self.storage.data[(JOBS, "old1")], rows[(JOBS, "old1")]["value"])
    self.assertEqual(self.storage.data[(JOBS, "new1")]["job_status"], "STOPPED")
    self.assertEqual(self.events[0], ("data_restored", {"actor": "creator", "rows": 5, "status_code": 200,
                                                        "outcomes": {"written": 2, "conflict": 1, "refused": 2}}))
    again = self.plugin.restore_redmesh_records(self.actor, saved[:1])
    self.assertEqual(again["data"]["outcomes"][0]["outcome"], "same")


class TestStoredFiles(unittest.TestCase):
  """The raw `ipfs` calls, with the binary replaced by a recorder."""

  def setUp(self):
    self.calls = []
    self.answers = {}
    patcher = patch.object(data_maintenance, "_ipfs", side_effect=self.ipfs)
    patcher.start()
    self.addCleanup(patcher.stop)

  def ipfs(self, arguments, ipfs_home, *, cwd=None, timeout=None):
    self.calls.append(list(arguments))
    if arguments[0] == "get":
      with open(f"{cwd}/file", "wb") as handle:
        handle.write(b"stored bytes")
      return ""
    return self.answers[arguments[0] if "--only-hash" not in arguments else "hash"]

  def test_read_returns_the_stored_bytes_and_name(self):
    self.answers["ls"] = f"{cid(9)} 12 abc123.bin\n"
    found = data_maintenance.read_stored_file(CONFIG, "/repo")
    self.assertEqual(found, {"cid": CONFIG, "filename": "abc123.bin",
                             "content_b64": base64.b64encode(b"stored bytes").decode(),
                             "sha256": hashlib.sha256(b"stored bytes").hexdigest(), "size_bytes": 12})
    self.assertEqual(self.calls[1], ["get", "-o", "file", "--", f"{CONFIG}/abc123.bin"])

  def test_read_refuses_bad_input_strange_listings_and_large_files(self):
    for bad in ("-o/etc/passwd", "../x", "", None, "Qmshort", CONFIG + "/x", CONFIG + "\n"):
      with self.assertRaises(data_maintenance.MaintenanceError) as raised:
        data_maintenance.read_stored_file(bad, "/repo")
      self.assertEqual(raised.exception.code, "invalid_request")
    self.assertEqual(self.calls, [])
    for listing, code in ((f"{cid(9)} 12 ../evil\n", "file_unavailable"),
                          (f"{cid(9)} 12 a.bin\n{cid(9)} 12 b.bin\n", "file_unavailable"),
                          ("", "file_unavailable"),
                          (f"{cid(9)} {51 * 1024 * 1024} a.bin\n", "file_too_large")):
      self.answers["ls"] = listing
      with self.assertRaises(data_maintenance.MaintenanceError) as raised:
        data_maintenance.read_stored_file(CONFIG, "/repo")
      self.assertEqual(raised.exception.code, code)
    self.assertNotIn("get", [call[0] for call in self.calls])

  def write(self, **changes):
    data = b"stored bytes"
    arguments = {"cid": CONFIG, "filename": "abc123.bin",
                 "content_b64": base64.b64encode(data).decode(),
                 "sha256": hashlib.sha256(data).hexdigest(), **changes}
    return data_maintenance.write_stored_file(ipfs_home="/repo", **arguments)

  def test_write_adds_the_file_only_when_the_cid_is_the_same(self):
    self.answers.update(hash=f"{cid(9)}\n{CONFIG}\n", add=f"{cid(9)}\n{CONFIG}\n")
    self.assertEqual(self.write(), {"cid": CONFIG, "outcome": "written"})
    self.assertEqual(self.calls[-1], ["add", "-q", "-w", "--", "abc123.bin"])
    self.calls.clear()
    self.answers["hash"] = f"{cid(9)}\n{cid(8)}\n"
    with self.assertRaises(data_maintenance.MaintenanceError) as raised:
      self.write()
    self.assertEqual(raised.exception.code, "cid_mismatch")
    self.assertEqual(len(self.calls), 1)

  def test_write_refuses_bad_names_bad_bytes_and_a_wrong_hash(self):
    for changes, code in (({"filename": "../a.bin"}, "invalid_request"), ({"filename": ".hidden"}, "invalid_request"),
                          ({"filename": "-rf"}, "invalid_request"), ({"filename": "a/b"}, "invalid_request"),
                          ({"cid": "--help"}, "invalid_request"), ({"content_b64": "not base64!"}, "invalid_request"),
                          ({"sha256": "0" * 64}, "hash_mismatch"), ({"sha256": None}, "invalid_request")):
      with self.assertRaises(data_maintenance.MaintenanceError) as raised:
        self.write(**changes)
      self.assertEqual(raised.exception.code, code, changes)
    self.assertEqual(self.calls, [])


class TestPinnedLocally(unittest.TestCase):
  """`ipfs pin ls` answers: pinned, definitely not pinned, or anything else (unknown)."""

  def answer(self, returncode, stdout=b"", stderr=b""):
    done = type("Done", (), {"returncode": returncode, "stdout": stdout, "stderr": stderr})()
    with patch.object(data_maintenance.subprocess, "run", return_value=done) as run:
      found = data_maintenance.pinned_locally(CONFIG, "/repo")
    return found, run

  def test_the_three_answers(self):
    found, run = self.answer(0, stdout=f"{CONFIG} recursive\n".encode())
    self.assertIs(found, True)
    self.assertEqual(run.call_args.args[0], ["ipfs", "pin", "ls", "--type=recursive", "--", CONFIG])
    self.assertEqual(run.call_args.kwargs["env"]["IPFS_PATH"], "/repo")
    self.assertIs(self.answer(1, stderr=f"Error: path '/ipfs/{CONFIG}' is not pinned".encode())[0], False)
    self.assertIsNone(self.answer(1, stderr=b"Error: no IPFS repo found")[0])
    self.assertIsNone(self.answer(0, stdout=b"")[0])
    self.assertIsNone(data_maintenance.pinned_locally("--help", "/repo"))


if __name__ == "__main__":
  unittest.main()
