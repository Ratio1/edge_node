"""Checked snapshot projections must never recover through global or local state."""
from copy import deepcopy
from collections import deque
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.services import query
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from .test_execution_binding_models import binding_payload


class QueryStore:
  cfg_instance_id = "jobs"

  def __init__(self):
    self.points = {}
    self.artifacts = {}
    self.reads = []
    self.r1fs = self
    self.scan_jobs = {}
    self.model_test_jobs = {}

  def chainstore_hget(self, *, hkey, key):
    self.reads.append((hkey, key))
    result = self.points.get((hkey, key))
    if isinstance(result, Exception):
      raise result
    return result

  def chainstore_hgetall(self, **kwargs):
    raise AssertionError("Global enumeration is forbidden")

  def _get_job_from_cstore(self, job_id):
    raise AssertionError("Checked job must not be re-read")

  def _get_job_status(self, job_id):
    raise AssertionError("Local status recovery is forbidden")

  def _normalize_job_record(self, job_key, job_spec):
    return job_key, dict(job_spec)

  def get_json(self, cid):
    self.reads.append(("artifact", cid))
    result = self.artifacts.get(cid)
    if isinstance(result, Exception):
      raise result
    return result

  def time(self):
    return 100.0


def checked_job():
  return {"job_id": "job-1", "execution_binding": binding_payload(), "job_status": "RUNNING",
          "target": "192.0.2.10", "job_pass": 1,
          "workers": {"node-a": {"assignment_revision": 1}}, "pass_reports": []}


def archive_for(job):
  return {"job_id": job["job_id"], "job_config": {"execution_binding": deepcopy(job["execution_binding"]),
          "target": job["target"]}, "passes": [{"pass_nr": 1, "llm_analysis": "analysis",
          "aggregated_report_cid": "aggregate", "findings": [{"finding_id": "finding-1"}]}]}


class TestTenantQuerySnapshots(unittest.TestCase):
  def setUp(self):
    self.owner = QueryStore()
    self.job = checked_job()

  def test_checked_archive_and_analysis_absence_have_typed_not_found(self):
    archive = query.get_job_archive(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(archive["status_code"], 404)
    self.assertEqual(archive["error"], "not_found")
    self.job["pass_reports"] = [{"pass_nr": 1, "report_cid": "pass"}]
    self.owner.artifacts["pass"] = {"pass_nr": 1}
    analysis = query.get_job_analysis(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(analysis["status_code"], 404)
    self.assertEqual(analysis["error"], "not_found")

  def test_audit_filters_the_copied_value_and_captures_membership_before_iteration(self):
    owned = {"job_id": "job-1", "event": "owned"}
    self.owner._audit_log = deque([owned, {"job_id": "foreign", "event": "private"}])
    copying = deepcopy
    def mutate_during_copy(value):
      if value is owned:
        value["job_id"] = "foreign"
        self.owner._audit_log.clear()
        self.owner._audit_log.append({"job_id": "job-1", "event": "new"})
      return copying(value)
    with patch("extensions.business.cybersec.red_mesh.services.query.deepcopy", side_effect=mutate_during_copy):
      self.assertEqual(query.get_job_audit(self.owner, checked_jobs={"job-1": self.job}), {"audit_log": [], "total": 0})
    self.assertEqual(self.owner.reads, [])

  def test_audit_results_are_detached_and_capture_failures_are_sanitized(self):
    self.owner._audit_log = [{"job_id": "job-1", "details": {"items": [1]}}]
    result = query.get_job_audit(self.owner, checked_jobs={"job-1": self.job})
    result["audit_log"][0]["details"]["items"].append(2)
    self.assertEqual(self.owner._audit_log[0]["details"]["items"], [1])
    class BrokenLog(list):
      def __iter__(self):
        raise RuntimeError("private audit details")
    for malformed in (None, {}, "invalid", BrokenLog()):
      self.owner._audit_log = malformed
      with self.assertRaises(TenantStoreError) as caught:
        query.get_job_audit(self.owner, checked_jobs={"job-1": self.job})
      self.assertEqual(str(caught.exception), "Tenant audit is unavailable")

  def test_report_no_pin_mode_is_used_for_the_authorized_leaf_and_ancestors(self):
    self.job["pass_reports"] = [{"pass_nr": 1, "report_cid": "pass"}]
    self.owner.artifacts.update({"pass": {"pass_nr": 1, "worker_reports": {"node-a": {"report_cid": "worker"}}},
                                 "worker": {"job_id": "job-1", "open_ports": [443]}})
    reads = []
    def get_json(cid, *, pin):
      reads.append((cid, pin))
      return self.owner.artifacts[cid]
    self.owner.get_json = get_json
    result = query.get_job_report(self.owner, "job-1", "worker", checked_job=self.job)
    self.assertEqual(result["execution_binding"], self.job["execution_binding"])
    self.assertEqual(result["report"]["open_ports"], [443])
    self.assertEqual(reads, [("pass", False), ("worker", False)])

  def test_data_uses_checked_copy_and_only_assigned_progress_keys(self):
    self.job["pass_reports"] = [{"pass_nr": n} for n in range(7)]
    self.owner.points[("jobs:live", "job-1:node-a")] = {
      "job_id": "job-1", "worker_addr": "node-a", "progress": 37,
      "pass_nr": 1, "assignment_revision_seen": 1}
    result = query.get_job_data(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(self.owner.reads, [("jobs:live", "job-1:node-a")])
    self.assertEqual(result["job"]["execution_binding"], self.job["execution_binding"])
    self.assertEqual(result["job"]["workers_reconciled"]["node-a"]["progress"], 37)
    self.assertEqual(len(result["job"]["pass_reports"]), 5)
    self.assertEqual(len(self.job["pass_reports"]), 7)
    result["job"]["execution_binding"]["participant_order"].append("injected")
    self.assertNotIn("injected", self.job["execution_binding"]["participant_order"])

  def test_explicit_invalid_snapshots_never_select_legacy_paths(self):
    for value in (None, {}, [], {**self.job, "job_id": "other"},
                  {**self.job, "execution_binding": None}):
      for method in (query.get_job_data, query.get_job_progress, query.get_job_archive, query.get_job_analysis):
        with self.subTest(value=value, method=method.__name__):
          with self.assertRaises(TenantStoreError):
            method(self.owner, "job-1", checked_job=value)
          self.assertEqual(self.owner.reads, [])

  def test_progress_is_bound_and_rejects_foreign_job_or_worker_payloads(self):
    for field in ("job_id", "worker_addr"):
      with self.subTest(field=field):
        self.owner.points[("jobs:live", "job-1:node-a")] = {
          "job_id": "job-1", "worker_addr": "node-a", field: "foreign"}
        with self.assertRaises(TenantStoreError):
          query.get_job_progress(self.owner, "job-1", checked_job=self.job)
    self.owner.points.clear()
    result = query.get_job_progress(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(result["execution_binding"], self.job["execution_binding"])
    self.assertEqual(set(result["workers"]), {"node-a"})
    self.assertEqual(result["workers"]["node-a"]["worker_state"], "unseen")

  def test_progress_storage_failure_is_sanitized(self):
    self.owner.points[("jobs:live", "job-1:node-a")] = RuntimeError("private payload")
    with self.assertRaises(TenantStoreError) as caught:
      query.get_job_progress(self.owner, "job-1", checked_job=self.job)
    self.assertNotIn("private", str(caught.exception))

  def test_stale_pass_or_revision_is_not_folded_into_progress(self):
    for field, value, reason in (("pass_nr", 99, "pass_mismatch"),
                                 ("assignment_revision_seen", 99, "revision_mismatch")):
      with self.subTest(field=field):
        self.owner.points[("jobs:live", "job-1:node-a")] = {
          "job_id": "job-1", "worker_addr": "node-a", "progress": 90, field: value}
        result = query.get_job_progress(self.owner, "job-1", checked_job=self.job)
        self.assertEqual(result["workers"]["node-a"]["ignored_live_reason"], reason)
        self.assertNotEqual(result["workers"]["node-a"].get("progress"), 90)

  def test_invalid_or_unassigned_workers_deny_without_global_recovery(self):
    for workers in (None, [], {"foreign-node": {}}, {"node-a": None}):
      with self.subTest(workers=workers):
        job = {**self.job, "workers": workers}
        with self.assertRaises(TenantStoreError):
          query.get_job_progress(self.owner, "job-1", checked_job=job)
        self.assertEqual(self.owner.reads, [])

  def test_archived_data_does_not_fetch_artifacts_or_live_progress(self):
    self.job["job_cid"] = "archive"
    result = query.get_job_data(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(result["job"], self.job)
    self.assertEqual(self.owner.reads, [])

  def test_list_preserves_binding_and_empty_checked_list_is_valid(self):
    self.assertEqual(query.list_network_jobs(self.owner, checked_jobs={}), {})
    result = query.list_network_jobs(self.owner, checked_jobs={"job-1": self.job})
    self.assertEqual(result["job-1"]["execution_binding"], self.job["execution_binding"])
    self.assertEqual(self.owner.reads, [])
    for value in (None, [], {"other": self.job}, {"job-1": {}}):
      with self.subTest(value=value), self.assertRaises(TenantStoreError):
        query.list_network_jobs(self.owner, checked_jobs=value)

  def test_malformed_listing_projection_is_unavailable_not_partial(self):
    for field, value in (("workers", []), ("workers", None), ("pass_reports", {}), ("pass_reports", None)):
      with self.subTest(field=field, value=value), self.assertRaises(TenantStoreError):
        query.list_network_jobs(self.owner, checked_jobs={"job-1": {**self.job, field: value}})

  def test_status_and_local_listing_do_not_use_local_worker_content(self):
    self.owner.scan_jobs = {"job-1": object(), "foreign": object()}
    result = query.get_job_status(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(result["job_id"], "job-1")
    self.assertEqual(result["execution_binding"], self.job["execution_binding"])
    local = query.list_local_jobs(self.owner, checked_jobs={"job-1": self.job})
    self.assertEqual(set(local), {"job-1"})
    self.assertEqual(local["job-1"]["execution_binding"], self.job["execution_binding"])

  def test_archive_and_analysis_are_bound_and_never_use_orphan_cids(self):
    self.job["job_cid"] = "archive"
    self.owner.artifacts["archive"] = archive_for(self.job)
    archive = query.get_job_archive(self.owner, "job-1", summary_only=True, checked_job=self.job)
    self.assertEqual(archive["execution_binding"], self.job["execution_binding"])
    self.assertEqual(archive["archive"]["passes"][0]["findings_count"], 1)
    analysis = query.get_job_analysis(self.owner, "job-1", pass_nr=1, checked_job=self.job)
    self.assertEqual(analysis["analysis"], "analysis")
    self.assertEqual(analysis["report_cid"], "aggregate")
    self.assertEqual(analysis["execution_binding"], self.job["execution_binding"])
    with self.assertRaises(AdministrationDenied):
      query.get_job_analysis(self.owner, "job-1", cid="orphan", checked_job=self.job)
    self.assertNotIn(("artifact", "orphan"), self.owner.reads)

  def test_running_analysis_uses_associated_pass_and_inline_text(self):
    self.job["pass_reports"] = [{"pass_nr": 2, "report_cid": "pass-2"}]
    self.owner.artifacts["pass-2"] = {"pass_nr": 2, "llm_analysis": "inline"}
    result = query.get_job_analysis(self.owner, "job-1", cid="pass-2", checked_job=self.job)
    self.assertEqual(result["analysis"], "inline")
    self.assertEqual(result["pass_nr"], 2)
    self.assertEqual(result["report_cid"], "pass-2")
