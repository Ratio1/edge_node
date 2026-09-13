"""Tenant artifact integrity using producer serializers and synthetic JSON storage."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.models import JobArchive, JobConfig, PassReport
from extensions.business.cybersec.red_mesh.models.reports import AggregatedScanData, NodeReport
from extensions.business.cybersec.red_mesh.model_testing.artifacts import ModelTestArchive, ModelTestWorkerResult
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from extensions.business.cybersec.red_mesh.tenancy.job_artifacts import (
  MAX_ARTIFACT_FETCHES, MAX_ARTIFACT_REFERENCES, TenantJobArtifacts, checked_job_snapshot,
)
from .test_execution_binding_models import binding_payload


def pass_payload(pass_nr=1, aggregate="aggregate", workers=None):
  return PassReport(pass_nr=pass_nr, date_started=1, date_completed=2, duration=1,
    aggregated_report_cid=aggregate, worker_reports={} if workers is None else workers,
    llm_analysis="Inline assessment", quick_summary="Inline summary").to_dict()


class JsonStore:
  def __init__(self, rows):
    self.rows = rows
    self.reads = []
    self.failure = None

  def read(self, cid):
    self.reads.append(cid)
    if cid == self.failure:
      raise RuntimeError("private storage detail")
    return self.rows.get(cid)


def fixture(kind="network", archived=False):
  binding = {**binding_payload(), "participant_order": ["node-a"]}
  if kind == "webapp":
    binding["asset_target"] = {"kind": "webapp", "url": "https://example.com/api", "allowedPathPrefix": "/api"}
  elif kind == "model":
    binding["asset_target"] = {"kind": "model", "adapter": "openai_compatible",
      "endpointUrl": "https://example.com/v1/chat/completions", "model": "Model"}
  binding["asset_target_digest"] = canonical_digest(binding["asset_target"])
  job = {"job_id": "job-1", "execution_binding": binding, "job_status": "RUNNING",
    "job_config_cid": "config", "workers": {"node-a": {"report_cid": "worker"}},
    "pass_reports": [{"pass_nr": 1, "report_cid": "pass"}]}
  config = JobConfig.from_dict({"execution_binding": binding, "target": "192.0.2.10",
    "start_port": 1, "end_port": 100, "scan_type": kind}).to_dict()
  worker = NodeReport(job_id="job-1", target="192.0.2.10", initiator="actor", start_port=1,
    end_port=100, open_ports=[443], service_info={}, web_tests_info={}, completed_tests=[]).to_dict()
  aggregate = AggregatedScanData(open_ports=[443], service_info={}, web_tests_info={}, completed_tests=[]).to_dict()
  if kind == "webapp":
    worker.update(scan_type="webapp", target_url="https://example.com/api", graybox_results={"findings": ["kept"]})
    aggregate.update(scan_type="webapp", graybox_results={"findings": ["kept"]})
  report = pass_payload(workers={"node-a": {"report_cid": "worker"}})
  if kind == "model":
    job.update(job_type="model_test", scan_type="model_test", pass_reports=[])
    config = {"job_id": "job-1", "job_type": "model_test", "execution_binding": binding}
    worker = ModelTestWorkerResult(job_id="job-1", worker_addr="node-a", status="complete",
      model_test_results={"cases": []}, model_test_summary={"overall_status": "complete"}).to_dict()
    archive = ModelTestArchive.from_dict({"job_id": "job-1", "job_config": config,
      "ui_aggregate": {"worker_result_cid": "worker"},
      "model_test_node_selection": {"selected_execution_node": "node-a"}}).to_dict()
  else:
    archive = JobArchive(job_id="job-1", job_config=config, timeline=[], passes=[report],
      ui_aggregate={}, duration=1, date_created=1, date_completed=2).to_dict()
  if archived:
    job.update(job_cid="archive", job_status="FINALIZED")
    job.pop("workers")
    job.pop("pass_reports")
  return job, JsonStore({"config": config, "archive": archive, "pass": report,
                        "worker": worker, "aggregate": aggregate})


class TestTenantJobArtifacts(unittest.TestCase):
  def test_checked_snapshot_rejects_invalid_or_unbound_values(self):
    job, _ = fixture()
    values = [None, {}, [], "job", {**job, "execution_binding": None},
              {**job, "execution_binding": {}}, {**job, "job_id": None}, {**job, "job_id": ""}]
    for value in values:
      with self.subTest(value=value):
        with self.assertRaises(TenantStoreError):
          checked_job_snapshot(value)
    with self.assertRaises(TenantStoreError):
      checked_job_snapshot(job, "foreign")

  def test_checked_snapshot_detaches_nested_values_and_validates_copied_identity(self):
    job, _ = fixture()
    original = deepcopy(job)
    result = checked_job_snapshot(job, "job-1")
    result["execution_binding"]["participant_order"].clear()
    self.assertEqual(job, original)
    result = checked_job_snapshot(job)
    job["workers"]["node-a"].clear()
    self.assertEqual(result, original)
    def mutate_then_copy(value):
      value["job_id"] = "foreign"
      return deepcopy(value)
    with patch("extensions.business.cybersec.red_mesh.tenancy.job_artifacts.deepcopy", side_effect=mutate_then_copy):
      with self.assertRaises(TenantStoreError):
        checked_job_snapshot(original, "job-1")

  def test_running_scan_and_graybox_payloads_follow_only_typed_edges(self):
    for kind in ("network", "webapp"):
      for cid in ("pass", "aggregate", "worker"):
        with self.subTest(kind=kind, cid=cid):
          job, store = fixture(kind)
          result = TenantJobArtifacts(job, store.read).report(cid)
          self.assertEqual(result, store.rows[cid])
          self.assertEqual(set(store.reads), {"pass", cid})
          self.assertNotIn("config", store.reads)

  def test_archived_payloads_validate_archive_before_following_inline_pass_edges(self):
    for kind in ("network", "webapp", "model"):
      job, store = fixture(kind, archived=True)
      artifacts = TenantJobArtifacts(job, store.read)
      self.assertEqual(artifacts.archive(), store.rows["archive"])
      self.assertEqual(artifacts.report("worker"), store.rows["worker"])
      self.assertEqual(store.reads, ["archive", "worker"])
      self.assertNotIn("config", store.reads)

  def test_archive_is_none_only_when_no_archive_is_referenced(self):
    job, store = fixture()
    self.assertIsNone(TenantJobArtifacts(job, store.read).archive())
    self.assertEqual(store.reads, [])
    for value in (None, [], "private", {}, {"job_id": "job-1"}):
      with self.subTest(value=value):
        job, store = fixture(archived=True)
        store.rows["archive"] = value
        with self.assertRaises(TenantStoreError):
          TenantJobArtifacts(job, store.read).archive()
        self.assertEqual(store.reads, ["archive"])

  def test_raw_archive_job_and_config_binding_are_checked_before_descendants(self):
    for mutation in ("job_id", "missing_config", "null_binding", "foreign_binding", "model_config_job"):
      with self.subTest(mutation=mutation):
        job, store = fixture("model" if mutation == "model_config_job" else "network", archived=True)
        archive = store.rows["archive"]
        if mutation == "job_id":
          archive["job_id"] = "foreign"
        elif mutation == "missing_config":
          archive.pop("job_config")
        elif mutation == "null_binding":
          archive["job_config"]["execution_binding"] = None
        elif mutation == "foreign_binding":
          archive["job_config"]["execution_binding"] = {**job["execution_binding"], "actor_id": "other"}
        else:
          archive["job_config"]["job_id"] = "foreign"
        with self.assertRaises(TenantStoreError):
          TenantJobArtifacts(job, store.read).report("worker")
        self.assertEqual(store.reads, ["archive"])

  def test_unsupported_archive_and_model_worker_versions_fail_before_publication(self):
    for kind in ("network", "model"):
      for version in (True, 2, "1", None):
        with self.subTest(kind=kind, version=version):
          job, store = fixture(kind, archived=True)
          store.rows["archive"]["archive_version"] = version
          with self.assertRaises(TenantStoreError):
            TenantJobArtifacts(job, store.read).report("worker")
          self.assertEqual(store.reads, ["archive"])
    for cid in ("archive", "worker"):
      with self.subTest(cid=cid):
        job, store = fixture("model", archived=True)
        store.rows[cid]["schema_version"] = "unknown"
        with self.assertRaises(TenantStoreError):
          TenantJobArtifacts(job, store.read).report("worker")
        if cid == "archive":
          self.assertEqual(store.reads, ["archive"])

  def test_restricted_inline_pass_envelope_cannot_publish_or_authorize_descendants(self):
    job, store = fixture(archived=True)
    store.rows["archive"]["passes"][0]["kind"] = "redmesh_model_test_raw_evidence"
    with self.assertRaises(TenantStoreError):
      TenantJobArtifacts(job, store.read).report("worker")
    self.assertEqual(store.reads, ["archive"])

  def test_real_finalizers_produce_archives_accepted_without_requiring_scan_config_job_id(self):
    from .test_tenant_execution_archive import TestTenantExecutionArchive
    source = TestTenantExecutionArchive()
    for kind in ("network", "model"):
      with self.subTest(kind=kind):
        plugin, specs, _, _, _, persisted = source.ready(kind)
        source.finalize(kind, plugin, specs)
        stub = source.Plugin._get_job_state_repository(plugin).get_job(specs["job_id"])
        store = JsonStore(persisted)
        self.assertEqual(TenantJobArtifacts(stub, store.read).archive(), persisted[stub["job_cid"]])
        self.assertEqual(store.reads, [stub["job_cid"]])

  def test_generic_report_never_downloads_archive_config_or_unassociated_references(self):
    for archived in (False, True):
      for cid in ("config", "archive", "secret", "raw", "authorization", "rulebook", "export", "unknown"):
        with self.subTest(archived=archived, cid=cid):
          job, store = fixture(archived=archived)
          job.update(secret_ref="secret", model_test_raw_evidence={"artifact_cid": "raw"},
            authorization={"document_cid": "authorization"}, rulebook_assessments={"artifact_cid": "rulebook"},
            timeline=[{"report_cid": "unknown"}], stix_export={"artifact_cid": "export"})
          store.rows["pass"]["findings"] = [{"report_cid": "unknown"}]
          with self.assertRaises(AdministrationDenied) as raised:
            TenantJobArtifacts(job, store.read).report(cid)
          self.assertEqual((raised.exception.status_code, raised.exception.error), (404, "not_found"))
          self.assertNotIn(cid, store.reads)

  def test_mismatched_pass_and_worker_identity_fail_unavailable(self):
    for cid, field, value in (("pass", "pass_nr", 2), ("pass", "pass_nr", True),
                              ("worker", "job_id", "foreign"), ("worker", "job_id", None)):
      with self.subTest(cid=cid, field=field):
        job, store = fixture()
        store.rows[cid][field] = value
        with self.assertRaises(TenantStoreError):
          TenantJobArtifacts(job, store.read).report(cid)
        if cid == "pass":
          self.assertEqual(store.reads, ["pass"])

  def test_model_worker_identity_comes_from_binding_without_selected_node_fallback(self):
    for archived in (False, True):
      job, store = fixture("model", archived)
      store.rows["worker"]["worker_addr"] = "foreign-worker"
      job["model_test_node_selection"] = {"selected_execution_node": "foreign-worker"}
      with self.assertRaises(TenantStoreError):
        TenantJobArtifacts(job, store.read).report("worker")
    job, store = fixture("model")
    job["execution_binding"]["participant_order"].append("node-b")
    with self.assertRaises(TenantStoreError):
      TenantJobArtifacts(job, store.read)
    self.assertEqual(store.reads, [])

  def test_malformed_and_restricted_payloads_never_publish(self):
    for cid in ("pass", "aggregate", "worker"):
      for value in (None, [], "private", {}, {"kind": "redmesh_model_test_raw_evidence", "job_id": "job-1"}):
        with self.subTest(cid=cid, value=value):
          job, store = fixture()
          store.rows[cid] = value
          with self.assertRaises(TenantStoreError) as raised:
            TenantJobArtifacts(job, store.read).report(cid)
          self.assertNotIn("private", str(raised.exception))

  def test_storage_errors_are_sanitized_and_no_fallback_runs(self):
    job, store = fixture()
    store.failure = "pass"
    with self.assertRaises(TenantStoreError) as raised:
      TenantJobArtifacts(job, store.read).report("worker")
    self.assertEqual(store.reads, ["pass"])
    self.assertNotIn("private", str(raised.exception))
    self.assertIsNone(raised.exception.__cause__)

  def test_compatible_duplicate_references_are_memoized_and_results_are_detached(self):
    job, store = fixture()
    job["pass_reports"].append(deepcopy(job["pass_reports"][0]))
    artifacts = TenantJobArtifacts(job, store.read)
    first = artifacts.report("worker")
    expected = deepcopy(first)
    first["open_ports"].clear()
    store.rows["worker"]["job_id"] = "later-foreign"
    job["pass_reports"].clear()
    self.assertEqual(artifacts.report("worker"), expected)
    self.assertEqual(store.reads, ["pass", "worker"])

  def test_conflicting_kind_identity_and_cycles_fail_before_conflicting_fetch(self):
    for mutation in ("pass_identity", "pass_cycle", "leaf_kind", "config_alias", "archive_cycle"):
      with self.subTest(mutation=mutation):
        job, store = fixture(archived=mutation == "archive_cycle")
        report = store.rows["archive"]["passes"][0] if mutation == "archive_cycle" else store.rows["pass"]
        if mutation == "pass_identity":
          job["pass_reports"].append({"pass_nr": 2, "report_cid": "pass"})
        elif mutation == "pass_cycle":
          report["aggregated_report_cid"] = "pass"
        elif mutation == "leaf_kind":
          report["aggregated_report_cid"] = "worker"
        elif mutation == "config_alias":
          report["aggregated_report_cid"] = "config"
        else:
          report["aggregated_report_cid"] = "archive"
        with self.assertRaises(TenantStoreError):
          TenantJobArtifacts(job, store.read).report("worker")
        self.assertNotIn("worker", store.reads)
        self.assertNotIn("config", store.reads)

  def test_fetch_limit_is_exact_and_checked_before_storage(self):
    self.assertEqual(MAX_ARTIFACT_FETCHES, 128)
    for count in (128, 129):
      with self.subTest(count=count):
        job, store = fixture()
        job["workers"] = {}
        job["pass_reports"] = [{"pass_nr": n, "report_cid": f"p-{n}"} for n in range(1, count + 1)]
        store.rows = {f"p-{n}": pass_payload(n, aggregate="") for n in range(1, count + 1)}
        artifacts = TenantJobArtifacts(job, store.read)
        if count == 128:
          self.assertEqual(artifacts.report("p-1"), store.rows["p-1"])
        else:
          with self.assertRaises(TenantStoreError):
            artifacts.report("p-1")
        self.assertEqual(len(store.reads), 128)

  def test_reference_limit_counts_empty_entries_before_traversal(self):
    self.assertEqual(MAX_ARTIFACT_REFERENCES, 10000)
    for count in (10000, 10001):
      with self.subTest(count=count):
        job, store = fixture()
        job["pass_reports"] = []
        job["workers"] = {f"node-{n}": {} for n in range(count)}
        if count == 10000:
          with self.assertRaises(AdministrationDenied):
            TenantJobArtifacts(job, store.read).report("unknown")
        else:
          with self.assertRaises(TenantStoreError):
            TenantJobArtifacts(job, store.read).report("unknown")
        self.assertEqual(store.reads, [])

  def test_reference_limit_accumulates_parent_entries_and_single_aggregate_edges(self):
    for workers in ({}, {"node-a": {}}):
      with self.subTest(workers=workers):
        job, store = fixture()
        job["workers"] = {}
        job["pass_reports"] = [{"pass_nr": 1, "report_cid": "pass"}] * 9999
        store.rows["pass"]["worker_reports"] = workers
        artifacts = TenantJobArtifacts(job, store.read)
        if workers:
          with self.assertRaises(TenantStoreError):
            artifacts.report("aggregate")
          self.assertEqual(store.reads, ["pass"])
        else:
          artifacts.report("aggregate")
          self.assertEqual(store.reads, ["pass", "aggregate"])

  def test_running_analysis_uses_inline_pass_data_and_honors_selectors(self):
    job, store = fixture()
    job["pass_reports"].append({"pass_nr": 2, "report_cid": "p2"})
    store.rows["p2"] = pass_payload(2, aggregate="")
    artifacts = TenantJobArtifacts(job, store.read)
    latest = artifacts.analysis_pass()
    self.assertEqual(latest, {"pass": store.rows["p2"], "report_cid": "p2", "total_passes": 2, "archived": False})
    self.assertEqual(artifacts.analysis_pass(cid="pass")["pass"]["pass_nr"], 1)
    self.assertEqual(artifacts.analysis_pass(pass_nr=1, cid="pass")["pass"]["pass_nr"], 1)
    for kwargs in ({"cid": "worker"}, {"cid": "aggregate"}, {"pass_nr": 1, "cid": "p2"},
                   {"pass_nr": 99}, {"pass_nr": True}, {"pass_nr": 1.0}):
      with self.subTest(kwargs=kwargs):
        with self.assertRaises(AdministrationDenied):
          artifacts.analysis_pass(**kwargs)
    self.assertEqual(set(store.reads), {"pass", "p2"})

  def test_archived_analysis_does_not_recover_pruned_pass_or_aggregate_cid_selectors(self):
    job, store = fixture(archived=True)
    artifacts = TenantJobArtifacts(job, store.read)
    self.assertEqual(artifacts.analysis_pass(pass_nr=1), {"pass": store.rows["archive"]["passes"][0],
      "report_cid": "aggregate", "total_passes": 1, "archived": True})
    for cid in ("pass", "aggregate", "archive"):
      with self.assertRaises(AdministrationDenied):
        artifacts.analysis_pass(cid=cid)
    self.assertEqual(store.reads, ["archive"])

  def test_no_history_has_generic_not_found_and_no_inline_text_is_still_pass_context(self):
    job, store = fixture()
    store.rows["pass"].pop("llm_analysis")
    self.assertNotIn("llm_analysis", TenantJobArtifacts(job, store.read).analysis_pass()["pass"])
    job["pass_reports"] = []
    with self.assertRaises(AdministrationDenied) as raised:
      TenantJobArtifacts(job, store.read).analysis_pass()
    self.assertEqual((raised.exception.status_code, raised.exception.error), (404, "not_found"))

  def test_malformed_structural_collections_are_not_recovered_as_empty(self):
    for parent, field in (("job", "pass_reports"), ("job", "workers"),
                          ("pass", "worker_reports"), ("archive", "passes")):
      for value in (None, "private", 1):
        with self.subTest(parent=parent, field=field, value=value):
          job, store = fixture(archived=parent == "archive")
          (job if parent == "job" else store.rows[parent])[field] = value
          with self.assertRaises(TenantStoreError):
            TenantJobArtifacts(job, store.read).report("worker")
