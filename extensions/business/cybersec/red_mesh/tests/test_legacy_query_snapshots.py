"""Explicit legacy snapshots reuse checked projections, never global recovery."""
from copy import deepcopy
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.models import JobArchive
from extensions.business.cybersec.red_mesh.models.reports import AggregatedScanData, NodeReport
from extensions.business.cybersec.red_mesh.model_testing.artifacts import ModelTestArchive, ModelTestWorkerResult
from extensions.business.cybersec.red_mesh.services import query, triage
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.job_artifacts import TenantJobArtifacts, checked_job_snapshot
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from .test_execution_binding_models import binding_payload
from .test_tenant_job_artifacts import fixture as bound_artifact_fixture, pass_payload
from .test_tenant_query_snapshots import QueryStore


MODE = {"snapshot_mode": "legacy_unbound"}


def legacy_fixture(kind="network", archived=False):
  job = {"job_id": "job-1", "job_status": "RUNNING", "target": "192.0.2.10",
         "scan_type": kind, "job_pass": 1, "job_config_cid": "config",
         "workers": {"node-a": {"report_cid": "worker", "assignment_revision": 1}},
         "pass_reports": [{"pass_nr": 1, "report_cid": "pass"}]}
  config = {"target": job["target"], "scan_type": kind, "start_port": 1, "end_port": 100}
  report = pass_payload(workers={"node-a": {"report_cid": "worker"}})
  report["findings"] = [{"finding_id": "finding-1", "title": "Issue"}]
  worker = NodeReport(job_id="job-1", target=job["target"], initiator="launcher", start_port=1,
    end_port=100, open_ports=[443], service_info={}, web_tests_info={}, completed_tests=[]).to_dict()
  aggregate = AggregatedScanData(open_ports=[443], service_info={}, web_tests_info={}, completed_tests=[]).to_dict()
  if kind == "webapp":
    job.update(target="example.com", target_url="https://example.com/api")
    worker.update(scan_type="webapp", graybox_results={"findings": ["preserved"]})
  if kind == "model_test":
    job.update(job_type=kind, pass_reports=[], model_test_node_selection={"selected_execution_node": "node-a"})
    config = {"job_id": "job-1", "job_type": kind}
    worker = ModelTestWorkerResult(job_id="job-1", worker_addr="node-a", status="complete",
      model_test_results={"cases": []}, model_test_summary={"overall_status": "complete"}).to_dict()
    archive = ModelTestArchive.from_dict({"job_id": "job-1", "job_config": config,
      "ui_aggregate": {"worker_result_cid": "worker"},
      "model_test_node_selection": {"selected_execution_node": "node-a"}}).to_dict()
  else:
    archive = JobArchive(job_id="job-1", job_config=config, passes=[report], timeline=[],
      ui_aggregate={}, duration=1, date_created=1, date_completed=2).to_dict()
  if archived:
    job.update(job_status="FINALIZED", job_cid="archive")
    job.pop("workers")
    job.pop("pass_reports")
  owner = QueryStore()
  owner.artifacts.update(config=config, archive=archive, worker=worker, aggregate=aggregate)
  owner.artifacts["pass"] = report
  return job, owner


class TestLegacyQuerySnapshots(unittest.TestCase):
  def optional_methods(self):
    return [(method, ("job-1",), "checked_job") for method in (
      query.get_job_data, query.get_job_progress, query.get_job_archive, query.get_job_analysis,
      triage.get_job_triage, triage.get_job_archive_with_triage)] + [
      (query.list_network_jobs, (), "checked_jobs"), (query.list_local_jobs, (), "checked_jobs")]

  def test_explicit_mode_and_snapshot_matrix_denies_before_fallback(self):
    for method, args, keyword in self.optional_methods():
      for mode in ("legacy_unbound", "unknown", None, [], True):
        for supplied in (False, True):
          with self.subTest(method=method.__name__, mode=mode, supplied=supplied):
            owner = QueryStore()
            kwargs = {"snapshot_mode": mode, **({keyword: None} if supplied else {})}
            with self.assertRaises(TenantStoreError):
              method(owner, *args, **kwargs)
            self.assertEqual(owner.reads, [])

  def test_unknown_mode_denies_even_valid_snapshots_and_empty_lists(self):
    job, owner = legacy_fixture()
    for method, args, keyword in self.optional_methods():
      value = {} if keyword == "checked_jobs" else job
      with self.subTest(method=method.__name__), self.assertRaises(TenantStoreError):
        method(owner, *args, **{keyword: value}, snapshot_mode="unknown")
    with self.assertRaises(TenantStoreError):
      query.get_job_status(owner, "job-1", checked_job=job, snapshot_mode="unknown")
    self.assertEqual(owner.reads, [])

  def test_legacy_snapshot_requires_complete_binding_absence(self):
    job, owner = legacy_fixture()
    for binding in (None, {}, binding_payload()):
      value = {**job, "execution_binding": binding}
      for method, args, keyword in self.optional_methods():
        supplied = {"job-1": value} if keyword == "checked_jobs" else value
        with self.subTest(binding=binding, method=method.__name__), self.assertRaises(TenantStoreError):
          method(owner, *args, **{keyword: supplied}, **MODE)
      with self.assertRaises(TenantStoreError):
        TenantJobArtifacts(value, owner.get_json, **MODE)
    self.assertEqual(owner.reads, [])

  def test_snapshot_and_artifact_modes_stay_explicit_and_required(self):
    job, owner = legacy_fixture()
    for mode in ("tenant_bound", "unknown", None, []):
      with self.subTest(mode=mode):
        with self.assertRaises(TenantStoreError):
          checked_job_snapshot(job, snapshot_mode=mode)
        with self.assertRaises(TenantStoreError):
          TenantJobArtifacts(job, owner.get_json, snapshot_mode=mode)
    for value in (None, {}, [], {**job, "job_id": ""}, {**job, "job_id": "foreign"}):
      with self.subTest(value=value), self.assertRaises(TenantStoreError):
        checked_job_snapshot(value, "job-1", **MODE)
    for value in (None, {}, []):
      with self.subTest(value=value), self.assertRaises(TenantStoreError):
        TenantJobArtifacts(value, owner.get_json, **MODE)
    with self.assertRaises(TypeError):
      checked_job_snapshot(**MODE)
    with self.assertRaises(TypeError):
      TenantJobArtifacts(read_json=owner.get_json, **MODE)

  def test_copied_snapshot_is_validated_and_detached_in_both_directions(self):
    job, _ = legacy_fixture()
    original = deepcopy(job)
    copied = checked_job_snapshot(job, "job-1", **MODE)
    copied["workers"].clear()
    self.assertEqual(job, original)
    copied = checked_job_snapshot(job, **MODE)
    job["workers"].clear()
    self.assertEqual(copied, original)
    for change in ({"execution_binding": None}, {"job_id": "foreign"}):
      def mutate_then_copy(value):
        value.update(change)
        return deepcopy(value)
      with self.subTest(change=change), patch(
          "extensions.business.cybersec.red_mesh.tenancy.job_artifacts.deepcopy", side_effect=mutate_then_copy):
        with self.assertRaises(TenantStoreError):
          checked_job_snapshot(deepcopy(original), "job-1", **MODE)

  def test_running_data_and_status_use_only_captured_worker_points(self):
    job, owner = legacy_fixture()
    job["pass_reports"] = [{"pass_nr": n} for n in range(1, 8)]
    owner.points[("jobs:live", "job-1:node-a")] = {
      "job_id": "job-1", "worker_addr": "node-a", "progress": 37,
      "pass_nr": 1, "assignment_revision_seen": 1}
    result = query.get_job_data(owner, "job-1", checked_job=job, **MODE)
    self.assertEqual(owner.reads, [("jobs:live", "job-1:node-a")])
    self.assertEqual(result["job"]["workers_reconciled"]["node-a"]["progress"], 37)
    self.assertEqual(len(result["job"]["pass_reports"]), 5)
    self.assertEqual(len(job["pass_reports"]), 7)
    result["job"]["workers"].clear()
    self.assertIn("node-a", job["workers"])
    status = query.get_job_status(owner, "job-1", checked_job=job, **MODE)
    self.assertEqual(status["status"], "network_tracked")
    self.assertNotIn("execution_binding", status)
    self.assertNotIn("execution_binding", status["job"])

  def test_progress_identity_and_storage_errors_are_sanitized(self):
    for value in ({"job_id": "foreign", "worker_addr": "node-a"},
                  {"job_id": "job-1", "worker_addr": "foreign"}, [], RuntimeError("private detail")):
      job, owner = legacy_fixture()
      owner.points[("jobs:live", "job-1:node-a")] = value
      with self.subTest(value=value), self.assertRaises(TenantStoreError) as caught:
        query.get_job_progress(owner, "job-1", checked_job=job, **MODE)
      self.assertNotIn("private", str(caught.exception))
      self.assertEqual(owner.reads, [("jobs:live", "job-1:node-a")])
    for workers in (None, [], {"": {}}, {1: {}}, {"node-a": None}):
      job, owner = legacy_fixture()
      with self.subTest(workers=workers), self.assertRaises(TenantStoreError):
        query.get_job_progress(owner, "job-1", checked_job={**job, "workers": workers}, **MODE)
      self.assertEqual(owner.reads, [])

  def test_lists_preserve_alias_keys_but_local_membership_uses_logical_id(self):
    job, owner = legacy_fixture()
    def unexpected_normalization(*args):
      raise AssertionError("Checked legacy rows were already normalized by admission")
    owner._normalize_job_record = unexpected_normalization
    owner.scan_jobs = {"job-1": object(), "foreign": object()}
    jobs = {"old-launcher-key": job}
    listing = query.list_network_jobs(owner, checked_jobs=jobs, **MODE)
    self.assertEqual(set(listing), {"old-launcher-key"})
    self.assertEqual(listing["old-launcher-key"]["job_id"], "job-1")
    self.assertNotIn("execution_binding", listing["old-launcher-key"])
    local = query.list_local_jobs(owner, checked_jobs=jobs, **MODE)
    self.assertEqual(set(local), {"old-launcher-key"})
    self.assertEqual(local["old-launcher-key"]["job_id"], "job-1")
    self.assertEqual(owner.reads, [("jobs:live", "job-1:node-a")])
    self.assertEqual(query.list_network_jobs(owner, checked_jobs={}, **MODE), {})
    self.assertEqual(query.list_local_jobs(owner, checked_jobs={}, **MODE), {})

  def test_invalid_checked_lists_fail_not_partial(self):
    job, owner = legacy_fixture()
    for value in (None, [], {"alias": None}, {"": job}, {1: job},
                  {"alias": {**job, "workers": None}}, {"alias": {**job, "pass_reports": {}}}):
      for method in (query.list_network_jobs, query.list_local_jobs):
        with self.subTest(value=value, method=method.__name__), self.assertRaises(TenantStoreError):
          method(owner, checked_jobs=value, **MODE)
    self.assertEqual(owner.reads, [])

  def test_archived_data_and_model_listing_preserve_safe_stub_without_fetch(self):
    job, owner = legacy_fixture("model_test", archived=True)
    job["model_test_summary"] = {"overall_status": "failed", "error_message": "private error"}
    result = query.get_job_data(owner, "job-1", checked_job=job, **MODE)
    self.assertEqual(result["job"]["job_cid"], "archive")
    self.assertNotIn("private", str(result))
    listing = query.list_network_jobs(owner, checked_jobs={"alias": job}, **MODE)
    self.assertEqual(listing["alias"]["model_test_node_selection"]["selected_execution_node"], "node-a")
    self.assertNotIn("private", str(listing))
    self.assertEqual(owner.reads, [])

  def test_partial_legacy_archive_config_and_point_triage_are_preserved(self):
    for config in ({}, {"target": "192.0.2.10"}):
      job, owner = legacy_fixture(archived=True)
      owner.artifacts["archive"]["job_config"] = config
      state = {"job_id": "job-1", "finding_id": "finding-1", "status": "accepted_risk", "note": "reviewed"}
      owner.points[("jobs:triage", "job-1:finding-1")] = state
      with self.subTest(config=config):
        result = query.get_job_archive(owner, "job-1", checked_job=job, **MODE)
        self.assertEqual(result["archive"]["passes"][0]["findings"][0]["triage"]["note"], "reviewed")
        self.assertNotIn("execution_binding", result)
        self.assertEqual(owner.reads, [("artifact", "archive"), ("jobs:triage", "job-1:finding-1")])
        result["triage"]["finding-1"]["note"] = "modified"
        self.assertEqual(state["note"], "reviewed")
        specific = triage.get_job_triage(owner, "job-1", "finding-1", checked_job=job, **MODE)
        self.assertTrue(specific["found"])
        self.assertNotIn("audit", specific)
        self.assertNotIn("execution_binding", specific)

  def test_partial_model_archive_config_is_legacy_compatible_but_present_identity_is_exact(self):
    for config in ({}, {"target": "Provider / Model"}):
      job, owner = legacy_fixture("model_test", archived=True)
      owner.artifacts["archive"]["job_config"] = config
      with self.subTest(config=config):
        result = query.get_job_archive(owner, "job-1", checked_job=job, **MODE)
        self.assertEqual(result["archive"]["job_id"], "job-1")
        self.assertEqual(result["triage"], {})
        self.assertNotIn("execution_binding", result)
        self.assertEqual(owner.reads, [("artifact", "archive")])
    for identity in (None, "", "foreign"):
      job, owner = legacy_fixture("model_test", archived=True)
      owner.artifacts["archive"]["job_config"] = {"job_id": identity}
      with self.subTest(identity=identity), self.assertRaises(TenantStoreError):
        query.get_job_archive(owner, "job-1", checked_job=job, **MODE)
      self.assertEqual(owner.reads, [("artifact", "archive")])
    bound_job, store = bound_artifact_fixture("model", archived=True)
    store.rows["archive"]["job_config"].pop("job_id")
    with self.assertRaises(TenantStoreError):
      TenantJobArtifacts(bound_job, store.read).archive()
    self.assertEqual(store.reads, ["archive"])

  def test_bad_archive_parent_stops_before_descendants_and_triage(self):
    changes = ({"job_id": "foreign"}, {"job_config": None},
               {"job_config": {"execution_binding": None}},
               {"job_config": {"execution_binding": binding_payload()}}, {"execution_binding": None})
    for change in changes:
      job, owner = legacy_fixture(archived=True)
      owner.artifacts["archive"].update(change)
      with self.subTest(change=change), self.assertRaises(TenantStoreError):
        query.get_job_archive(owner, "job-1", checked_job=job, **MODE)
      self.assertEqual(owner.reads, [("artifact", "archive")])

  def test_analysis_uses_associated_running_pass_or_archived_inline_pass(self):
    for archived in (False, True):
      job, owner = legacy_fixture(archived=archived)
      kwargs = {"pass_nr": 1} if archived else {"cid": "pass"}
      with self.subTest(archived=archived):
        result = query.get_job_analysis(owner, "job-1", checked_job=job, **kwargs, **MODE)
        self.assertEqual(result["analysis"], "Inline assessment")
        self.assertEqual(result["report_cid"], "aggregate" if archived else "pass")
        self.assertNotIn("execution_binding", result)
        self.assertEqual(owner.reads, [("artifact", "archive" if archived else "pass")])
        with self.assertRaises(AdministrationDenied):
          query.get_job_analysis(owner, "job-1", cid="orphan", checked_job=job, **MODE)
        self.assertNotIn(("artifact", "orphan"), owner.reads)

  def test_reports_follow_real_typed_producers_only_for_the_checked_job(self):
    for kind in ("network", "webapp", "model_test"):
      for archived in (False, True):
        for cid in (("worker",) if kind == "model_test" else ("worker", "aggregate")):
          job, owner = legacy_fixture(kind, archived)
          with self.subTest(kind=kind, archived=archived, cid=cid):
            result = TenantJobArtifacts(job, owner.get_json, **MODE).report(cid)
            self.assertEqual(result, owner.artifacts[cid])
            result["job_id"] = "changed"
            self.assertNotEqual(owner.artifacts[cid].get("job_id"), "changed")
            self.assertNotIn(("artifact", "config"), owner.reads)

  def test_generic_report_never_accepts_archive_config_or_unassociated_cids(self):
    for archived in (False, True):
      job, owner = legacy_fixture(archived=archived)
      for cid in ("archive", "config", "orphan", "formal-review", "raw-evidence"):
        with self.subTest(archived=archived, cid=cid), self.assertRaises(AdministrationDenied):
          TenantJobArtifacts(job, owner.get_json, **MODE).report(cid)
        if cid != "archive" or not archived:
          self.assertNotIn(("artifact", cid), owner.reads)

  def test_missing_archive_unknown_finding_and_storage_failure_do_not_recover(self):
    job, owner = legacy_fixture()
    result = query.get_job_archive(owner, "job-1", checked_job=job, **MODE)
    self.assertEqual(result, {"job_id": "job-1", "error": "not_available"})
    with self.assertRaises(AdministrationDenied):
      triage.get_job_triage(owner, "job-1", checked_job=job, **MODE)
    self.assertEqual(owner.reads, [])
    job["job_cid"] = "archive"
    with self.assertRaises(AdministrationDenied):
      triage.get_job_triage(owner, "job-1", "unknown", checked_job=job, **MODE)
    self.assertEqual(owner.reads, [("artifact", "archive")])
    for value in (None, RuntimeError("private storage failure")):
      owner.artifacts["archive"] = value
      with self.subTest(value=value), self.assertRaises(TenantStoreError) as caught:
        query.get_job_archive(owner, "job-1", checked_job=job, **MODE)
      self.assertNotIn("private", str(caught.exception))

  def test_model_progress_remains_sanitized_and_detached(self):
    job, owner = legacy_fixture("model_test")
    job["model_test_summary"] = {"overall_status": "failed", "error_message": "private summary"}
    owner.points[("jobs:live", "job-1:node-a")] = {
      "job_id": "job-1", "worker_addr": "node-a", "progress": 20,
      "pass_nr": 1, "assignment_revision_seen": 1, "error_message": "private worker"}
    result = query.get_job_progress(owner, "job-1", checked_job=job, **MODE)
    self.assertEqual(result["job_type"], "model_test")
    self.assertEqual(set(result["workers"]), {"node-a"})
    self.assertNotIn("private", str(result))
    self.assertNotIn("execution_binding", result)
    result["model_test_node_selection"]["selected_execution_node"] = "changed"
    self.assertEqual(job["model_test_node_selection"]["selected_execution_node"], "node-a")

  def test_present_artifact_binding_and_foreign_worker_identity_are_unavailable(self):
    for change in ({"execution_binding": None}, {"execution_binding": binding_payload()},
                   {"job_id": "foreign"}, {"kind": "redmesh_model_test_raw_evidence"}):
      job, owner = legacy_fixture()
      owner.artifacts["worker"].update(change)
      with self.subTest(change=change), self.assertRaises(TenantStoreError):
        TenantJobArtifacts(job, owner.get_json, **MODE).report("worker")

  def test_model_worker_identity_comes_from_snapshot_not_launcher(self):
    for archived in (False, True):
      job, owner = legacy_fixture("model_test", archived)
      job["launcher"] = "wrong-node"
      if not archived:
        job.pop("model_test_node_selection")
      with self.subTest(archived=archived):
        result = TenantJobArtifacts(job, owner.get_json, **MODE).report("worker")
        self.assertEqual(result["worker_addr"], "node-a")
        owner.artifacts["worker"]["worker_addr"] = "wrong-node"
        with self.assertRaises(TenantStoreError):
          TenantJobArtifacts(job, owner.get_json, **MODE).report("worker")

  def test_missing_conflicting_or_ambiguous_model_identity_denies_worker_edge(self):
    variants = ({"model_test_node_selection": {}},
                {"model_test_node_selection": {"selected_execution_node": ""}},
                {"workers": {"node-b": {}}},
                {"workers": {"node-a": {}, "node-b": {}}})
    for change in variants:
      job, owner = legacy_fixture("model_test", archived=True)
      job.update(change)
      with self.subTest(change=change), self.assertRaises(TenantStoreError):
        TenantJobArtifacts(job, owner.get_json, **MODE).report("worker")

  def test_model_archive_without_worker_edge_needs_no_invented_worker(self):
    job, owner = legacy_fixture("model_test", archived=True)
    job.pop("model_test_node_selection")
    owner.artifacts["archive"]["ui_aggregate"].pop("worker_result_cid")
    result = query.get_job_archive(owner, "job-1", checked_job=job, **MODE)
    self.assertEqual(result["archive"]["job_id"], "job-1")
    self.assertEqual(result["triage"], {})
    self.assertEqual(owner.reads, [("artifact", "archive")])

  def test_reference_and_fetch_limits_still_fail_without_partial_results(self):
    job, owner = legacy_fixture()
    job["pass_reports"] = [{"pass_nr": 1, "report_cid": "pass"}] * 10001
    with self.assertRaises(TenantStoreError):
      TenantJobArtifacts(job, owner.get_json, **MODE)
    self.assertEqual(owner.reads, [])
    job["pass_reports"] = [{"pass_nr": n, "report_cid": f"pass-{n}"} for n in range(1, 130)]
    owner.artifacts.update({f"pass-{n}": pass_payload(n, aggregate="") for n in range(1, 130)})
    with self.assertRaises(TenantStoreError):
      TenantJobArtifacts(job, owner.get_json, **MODE).report("worker")
    self.assertEqual(len(owner.reads), 128)

  def test_duplicate_compatible_edges_are_memoized_and_conflicts_fail(self):
    job, owner = legacy_fixture()
    artifacts = TenantJobArtifacts(job, owner.get_json, **MODE)
    self.assertEqual(artifacts.report("worker"), artifacts.report("worker"))
    self.assertEqual(owner.reads, [("artifact", "pass"), ("artifact", "worker")])
    owner.artifacts["pass"]["aggregated_report_cid"] = "worker"
    with self.assertRaises(TenantStoreError):
      TenantJobArtifacts(job, owner.get_json, **MODE).report("worker")
