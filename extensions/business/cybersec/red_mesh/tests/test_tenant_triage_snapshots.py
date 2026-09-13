"""Archive identity precedes serializers, finding-state reads and publication."""
from copy import deepcopy
import unittest

from extensions.business.cybersec.red_mesh.services import triage
from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from .test_tenant_query_snapshots import QueryStore, archive_for, checked_job


class TestTenantTriageSnapshots(unittest.TestCase):
  def setUp(self):
    self.owner = QueryStore()
    self.job = checked_job()
    self.job["job_cid"] = "archive"
    self.archive = archive_for(self.job)
    self.owner.artifacts["archive"] = self.archive
    self.state = {"job_id": "job-1", "finding_id": "finding-1", "status": "open",
                  "note": "reviewed", "actor": "reviewer", "updated_at": 1}
    self.owner.points[("jobs:triage", "job-1:finding-1")] = self.state

  def test_archive_uses_point_state_and_preserves_detached_binding(self):
    result = triage.get_job_archive_with_triage(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(self.owner.reads, [("artifact", "archive"), ("jobs:triage", "job-1:finding-1")])
    self.assertEqual(result["archive"]["passes"][0]["findings"][0]["triage"], self.state)
    self.assertEqual(result["execution_binding"], self.job["execution_binding"])
    result["triage"]["finding-1"]["note"] = "changed"
    self.assertEqual(self.state["note"], "reviewed")

  def test_finding_specific_read_never_includes_or_reads_audit(self):
    result = triage.get_job_triage(self.owner, "job-1", "finding-1", checked_job=self.job)
    self.assertTrue(result["found"])
    self.assertNotIn("audit", result)
    self.assertEqual(result["triage"], self.state)
    self.assertEqual(self.owner.reads, [("artifact", "archive"), ("jobs:triage", "job-1:finding-1")])

  def test_unknown_finding_denies_before_state_read(self):
    with self.assertRaises(AdministrationDenied) as caught:
      triage.get_job_triage(self.owner, "job-1", "foreign", checked_job=self.job)
    self.assertEqual(caught.exception.status_code, 404)
    self.assertEqual(self.owner.reads, [("artifact", "archive")])

  def test_raw_archive_identity_failure_precedes_triage(self):
    variants = [{**self.archive, "job_id": "foreign"},
                {**self.archive, "job_config": {}},
                {**self.archive, "job_config": {"execution_binding": None}}]
    foreign = deepcopy(self.archive)
    foreign["job_config"]["execution_binding"]["namespace"] = "foreign"
    variants.append(foreign)
    for value in variants:
      with self.subTest(value=value):
        self.owner.reads.clear()
        self.owner.artifacts["archive"] = value
        with self.assertRaises(TenantStoreError):
          triage.get_job_archive_with_triage(self.owner, "job-1", checked_job=self.job)
        self.assertEqual(self.owner.reads, [("artifact", "archive")])

  def test_invalid_snapshot_never_reads_any_store(self):
    for value in (None, {}, {**self.job, "job_id": "foreign"}):
      for method in (triage.get_job_triage, triage.get_job_archive_with_triage):
        with self.subTest(value=value, method=method.__name__), self.assertRaises(TenantStoreError):
          method(self.owner, "job-1", checked_job=value)
    self.assertEqual(self.owner.reads, [])

  def test_state_identity_or_storage_failure_is_not_empty_success(self):
    for value in ({**self.state, "job_id": "foreign"}, {**self.state, "finding_id": "foreign"},
                  [], {}, RuntimeError("private payload")):
      with self.subTest(value=value):
        self.owner.points[("jobs:triage", "job-1:finding-1")] = value
        with self.assertRaises(TenantStoreError) as caught:
          triage.get_job_triage(self.owner, "job-1", checked_job=self.job)
        self.assertNotIn("private", str(caught.exception))
    self.owner.points.clear()
    result = triage.get_job_triage(self.owner, "job-1", "finding-1", checked_job=self.job)
    self.assertFalse(result["found"])
    self.assertIsNone(result["triage"])

  def test_finding_budget_rejects_before_point_reads(self):
    self.archive["passes"][0]["findings"] = [{"finding_id": str(n)} for n in range(10001)]
    with self.assertRaises(TenantStoreError):
      triage.get_job_triage(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(self.owner.reads, [("artifact", "archive")])

  def test_exact_finding_budget_succeeds_and_duplicates_read_state_once(self):
    self.archive["passes"][0]["findings"] = [{"finding_id": "finding-1"} for _ in range(10000)]
    result = triage.get_job_triage(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(result["triage"], {"finding-1": self.state})
    self.assertEqual(self.owner.reads, [("artifact", "archive"), ("jobs:triage", "job-1:finding-1")])

  def test_missing_archive_and_broken_reference_are_distinct(self):
    self.job.pop("job_cid")
    result = triage.get_job_archive_with_triage(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(result["error"], "not_available")
    self.assertEqual(self.owner.reads, [])
    self.job["job_cid"] = "missing"
    with self.assertRaises(TenantStoreError):
      triage.get_job_archive_with_triage(self.owner, "job-1", checked_job=self.job)

  def test_model_archive_is_sanitized_and_never_reads_triage(self):
    target = {"kind": "model", "adapter": "openai_compatible",
              "endpointUrl": "https://example.com/v1/chat/completions", "model": "Model"}
    self.job["execution_binding"].update(asset_target=target, asset_target_digest=canonical_digest(target),
                                         participant_order=["node-a"])
    self.job.update(job_type="model_test", scan_type="model_test")
    self.archive = archive_for(self.job)
    self.archive.update(job_type="model_test", model_test_summary={"error_message": "private error"})
    self.archive["job_config"].update(job_id="job-1", job_type="model_test")
    self.owner.artifacts["archive"] = self.archive
    result = triage.get_job_archive_with_triage(self.owner, "job-1", checked_job=self.job)
    self.assertEqual(result["triage"], {})
    self.assertNotIn("private error", str(result))
    self.assertEqual(self.owner.reads, [("artifact", "archive")])
