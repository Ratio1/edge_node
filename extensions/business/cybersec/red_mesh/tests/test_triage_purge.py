"""Step 4a S4: a job purge keeps host triage and deletes legacy rows; a whole purge also deletes host triage."""
import json
import unittest
from copy import deepcopy

from extensions.business.cybersec.red_mesh.models import FindingTriageAuditEntry, FindingTriageState
from extensions.business.cybersec.red_mesh.repositories.cstore import JobStateRepository
from extensions.business.cybersec.red_mesh.services import control, triage
from .test_triage_store import TENANT_A, TENANT_B
from .test_triage_write import HOST, _Owner, _Repo, write


class _PurgeRepo(_Repo):
  def get_job_config(self, job):
    return {}

  def delete(self, cid, **kwargs):
    return True


class _PurgeOwner(_Owner):
  cfg_tenancy_namespace = "deployment"

  def _get_artifact_repository(self):
    return _PurgeRepo(self)

  def _normalize_job_record(self, key, record):
    return key, dict(record)


def tenancy_field(tenant):
  return json.dumps(["tenant", "deployment", tenant], separators=(",", ":"))


class TestTriageSurvivesPurge(unittest.TestCase):
  def setUp(self):
    self.owner = _PurgeOwner()
    for job_id, tenant in (("job-1", TENANT_A), ("job-b", TENANT_B)):
      self.owner.add_job(job_id, tenant=tenant)
    self.repo = JobStateRepository(self.owner)
    for tenant in (TENANT_A, TENANT_B):
      self.repo.put_host_triage(FindingTriageState(job_id="job-1", finding_id="f1", status="remediated",
                                                   tenant_id=tenant, host=HOST))
      self.repo.append_host_triage_audit(FindingTriageAuditEntry(
        job_id="job-1", finding_id="f1", status="remediated", tenant_id=tenant, host=HOST))
    # what an older release left: job-keyed rows
    self.owner.hashes["inst:triage"] = {"job-1:f1": {"job_id": "job-1", "finding_id": "f1", "status": "open"},
                                        "job-9:f1": {"job_id": "job-9", "finding_id": "f1", "status": "open"}}
    self.owner.hashes["inst:triage:audit"] = {"job-1:f1": [{"status": "open"}]}

  def host_rows(self, tenant):
    return {k: v for k, v in self.owner.hashes.get(f"inst:triage:t:{tenant}", {}).items()}

  def test_purging_a_job_keeps_host_records_and_deletes_its_legacy_rows(self):
    result = control.purge_job(self.owner, "job-1", checked_job=deepcopy(self.owner.hashes["inst"]["job-1"]))
    self.assertEqual(result["status"], "success", result)
    self.assertNotIn("job-1", self.owner.hashes["inst"])
    self.assertEqual(set(self.host_rows(TENANT_A)), {f"{HOST}\x1ff1"})
    self.assertEqual(len(self.owner.hashes[f"inst:triage:audit:{TENANT_A}"]), 1)
    self.assertEqual(set(self.owner.hashes["inst:triage"]), {"job-9:f1"})
    self.assertEqual(self.owner.hashes["inst:triage:audit"], {})

  def test_a_later_job_of_the_host_reads_the_record_after_the_purge(self):
    control.purge_job(self.owner, "job-1", checked_job=deepcopy(self.owner.hashes["inst"]["job-1"]))
    rerun = self.owner.add_job("job-2")
    self.assertEqual(self.repo.list_triage_for_record(rerun)["f1"]["status"], "remediated")

  def test_a_whole_node_purge_deletes_every_tenants_host_triage_and_audit(self):
    # tenant B has no job record any more: only the tenancy store still names it
    del self.owner.hashes["inst"]["job-b"]
    self.owner.hashes[json.dumps(["redmesh", "tenancy", 1, "deployment"], separators=(",", ":"))] = {
      tenancy_field(TENANT_B): {"kind": "tenant"}}
    result = control.purge_all_jobs(self.owner)
    self.assertEqual(result["status"], "success", result)
    for tenant in (TENANT_A, TENANT_B):
      self.assertEqual(self.host_rows(tenant), {})
      self.assertEqual(self.owner.hashes[f"inst:triage:audit:{tenant}"], {})

  def test_a_tenant_scoped_purge_touches_only_that_tenants_host_triage(self):
    jobs = {"job-1": deepcopy(self.owner.hashes["inst"]["job-1"])}
    result = control.purge_all_jobs(self.owner, checked_jobs=jobs, snapshot_mode="tenant_bound")
    self.assertEqual(result["status"], "success", result)
    self.assertEqual(self.host_rows(TENANT_A), {})
    self.assertEqual(set(self.host_rows(TENANT_B)), {f"{HOST}\x1ff1"})
    self.assertEqual(len(self.owner.hashes[f"inst:triage:audit:{TENANT_B}"]), 1)

  def test_a_failed_job_keeps_host_triage_for_the_retry(self):
    self.owner.add_job("job-f", launcher="node-z")  # not this node's: purge refuses it
    result = control.purge_all_jobs(self.owner)
    self.assertNotEqual(result["status"], "success")
    self.assertEqual(set(self.host_rows(TENANT_A)), {f"{HOST}\x1ff1"})
    self.assertEqual(set(self.host_rows(TENANT_B)), {f"{HOST}\x1ff1"})

  def _interrupted_audit(self, tenant, job_id="job-1"):
    """A triage change of `tenant`'s f1 whose state is confirmed but whose audit append is refused."""
    real = self.owner.chainstore_hset
    audit_hkey = f"inst:triage:audit:{tenant}"
    self.owner.chainstore_hset = lambda **kw: False if kw["hkey"] == audit_hkey else real(**kw)
    result, _ = write(self.owner, job_id=job_id, ids="f1", status="false_positive", note="old note")
    self.assertEqual([r["outcome"] for r in result["results"]], ["write_failed"])
    self.owner.chainstore_hset = real

  def test_a_whole_purge_drops_unfinished_triage_changes_so_none_comes_back(self):
    self._interrupted_audit(TENANT_A)
    self.assertEqual(control.purge_all_jobs(self.owner)["status"], "success")
    self.assertEqual(self.owner.hashes[f"inst:triage:audit:{TENANT_A}"], {})
    self.owner.add_job("job-2")
    write(self.owner, job_id="job-2", ids="f1", status="remediated", note="new")
    audit = triage._job_repo(self.owner).get_host_triage_audit(TENANT_A, HOST, "f1")
    self.assertEqual([(e["job_id"], e["note"]) for e in audit], [("job-2", "new")])

  def test_a_tenant_scoped_purge_keeps_the_other_tenants_unfinished_changes(self):
    self._interrupted_audit(TENANT_A)
    self._interrupted_audit(TENANT_B, job_id="job-b")
    jobs = {"job-1": deepcopy(self.owner.hashes["inst"]["job-1"])}
    self.assertEqual(control.purge_all_jobs(self.owner, checked_jobs=jobs, snapshot_mode="tenant_bound")["status"],
                     "success")
    self.assertEqual([key[0] for key in self.owner._triage_unfinished_writes], [TENANT_B])

  def test_a_tenant_purge_with_no_jobs_left_still_deletes_its_host_triage(self):
    # the last job went in a single-job purge, which keeps host triage; the tenant-wide purge now sees no job
    result = control.purge_all_jobs(self.owner, checked_jobs={}, snapshot_mode="tenant_bound", tenant_id=TENANT_A)
    self.assertEqual(result["status"], "success", result)
    self.assertEqual(self.host_rows(TENANT_A), {})
    self.assertEqual(self.owner.hashes[f"inst:triage:audit:{TENANT_A}"], {})
    self.assertEqual(set(self.host_rows(TENANT_B)), {f"{HOST}\x1ff1"})

  def test_a_refused_triage_delete_reports_partial_and_keeps_the_unfinished_change(self):
    self._interrupted_audit(TENANT_A)
    real = self.owner.chainstore_hset
    host_hkeys = {f"inst:triage:t:{TENANT_A}", f"inst:triage:audit:{TENANT_A}"}
    self.owner.chainstore_hset = lambda **kw: False if kw["hkey"] in host_hkeys else real(**kw)
    result = control.purge_all_jobs(self.owner)
    self.assertEqual(result["status"], "partial", result)
    self.assertIn(f"inst:triage:t:{TENANT_A}", [e["scope"] for e in result["errors"]])
    self.assertEqual(set(self.host_rows(TENANT_A)), {f"{HOST}\x1ff1"})
    self.assertEqual([key[0] for key in self.owner._triage_unfinished_writes], [TENANT_A])
    self.assertEqual(self.host_rows(TENANT_B), {})  # the other tenant's sweep still ran


if __name__ == "__main__":
  unittest.main()
