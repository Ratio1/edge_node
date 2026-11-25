"""RM-060 Phase F: a job purge deletes the graybox evidence blobs its worker reports point at."""
import unittest
from copy import deepcopy

from extensions.business.cybersec.red_mesh.services import control
from .test_triage_purge import _PurgeOwner, _PurgeRepo
from .test_triage_store import TENANT_A, TENANT_B


def _worker_report(*evidence_cids):
  return {"graybox_results": {"8000": {"_p": {"findings": [
    {"status": "vulnerable", "evidence_artifacts": [{"raw_evidence_cid": cid} for cid in evidence_cids]},
  ]}}}}


class _Repo(_PurgeRepo):
  def __init__(self, owner):
    super().__init__(owner)

  def delete(self, cid, **kwargs):
    self.owner.deleted.append(cid)
    return True


class _Owner(_PurgeOwner):
  def __init__(self):
    super().__init__()
    self.deleted = []

  def _get_artifact_repository(self):
    return _Repo(self)

  def add_graybox_job(self, job_id, tenant, report_cid, report):
    record = self.add_job(job_id, tenant=tenant)
    self.archives[f"arch-{job_id}"]["passes"][0]["worker_reports"] = {"node-a": {"report_cid": report_cid}}
    self.archives[report_cid] = report
    record["workers"] = {"node-a": {"report_cid": report_cid, "finished": True}}
    return record


class TestPurgeDeletesEvidence(unittest.TestCase):
  def setUp(self):
    self.owner = _Owner()

  def test_purge_job_deletes_evidence_cids(self):
    self.owner.add_graybox_job("job-1", TENANT_A, "rep-1", _worker_report("ev-1", "ev-2"))
    result = control.purge_job(self.owner, "job-1", checked_job=deepcopy(self.owner.hashes["inst"]["job-1"]))
    self.assertEqual(result["status"], "success", result)
    self.assertIn("ev-1", self.owner.deleted)
    self.assertIn("ev-2", self.owner.deleted)

  def test_purge_job_keeps_evidence_cid_referenced_by_another_job(self):
    self.owner.add_graybox_job("job-1", TENANT_A, "rep-1", _worker_report("ev-1", "ev-shared"))
    self.owner.add_graybox_job("job-b", TENANT_B, "rep-b", _worker_report("ev-shared"))
    control.purge_job(self.owner, "job-1", checked_job=deepcopy(self.owner.hashes["inst"]["job-1"]))
    self.assertIn("ev-1", self.owner.deleted)
    self.assertNotIn("ev-shared", self.owner.deleted)

  def test_unreadable_other_report_keeps_evidence(self):
    self.owner.add_graybox_job("job-1", TENANT_A, "rep-1", _worker_report("ev-shared"))
    self.owner.add_graybox_job("job-b", TENANT_B, "rep-b", _worker_report("ev-shared"))
    del self.owner.archives["rep-b"]  # job-b's report cannot be read: sharing is unknown
    control.purge_job(self.owner, "job-1", checked_job=deepcopy(self.owner.hashes["inst"]["job-1"]))
    self.assertNotIn("ev-shared", self.owner.deleted)

  def test_force_purge_deletes_evidence_cids(self):
    record = self.owner.add_graybox_job("job-1", TENANT_A, "rep-1", _worker_report("ev-1"))
    control._force_purge_job(self.owner, "job-1", record, [])
    self.assertIn("ev-1", self.owner.deleted)
