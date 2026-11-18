"""Step 4a S2: the record-level reader every internal consumer uses (rulebook, framework evidence, archive)."""
import unittest

from extensions.business.cybersec.red_mesh.models import FindingTriageState
from extensions.business.cybersec.red_mesh.repositories.cstore import JobStateRepository
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from .test_execution_binding_models import binding_payload
from .test_triage_store import TENANT_A, TENANT_B, _Store


def record(tenant=TENANT_A, target=None):
  binding = binding_payload()
  binding["tenant_id"] = tenant
  if target:
    binding.update(asset_target=target, asset_target_digest=canonical_digest(target))
  return {"job_id": "j", "execution_binding": binding}


def state(tenant, host="192.0.2.10", finding="f1", job="writer"):
  return FindingTriageState(job_id=job, finding_id=finding, status="false_positive", tenant_id=tenant, host=host)


class TestListTriageForRecord(unittest.TestCase):
  def setUp(self):
    self.owner = _Store()
    self.repo = JobStateRepository(self.owner)

  def test_a_record_of_the_host_is_read_by_every_job_of_that_tenant_and_host(self):
    self.repo.put_host_triage(state(TENANT_A, job="first-run"))
    for job in (record(), {**record(), "job_id": "rerun"}):
      self.assertEqual(self.repo.list_triage_for_record(job)["f1"]["job_id"], "first-run")

  def test_other_tenant_other_host_and_unbound_records_read_nothing(self):
    self.repo.put_host_triage(state(TENANT_A))
    self.assertEqual(self.repo.list_triage_for_record(record(TENANT_B)), {})
    other_host = {"kind": "network", "address": "192.0.2.77"}
    self.assertEqual(self.repo.list_triage_for_record(record(target=other_host)), {})
    model = {"kind": "model", "adapter": "openai_compatible",
             "endpointUrl": "https://api.example.com/v1/chat/completions", "model": "m"}
    for bad in (record(target=model), {"job_id": "j"}, {"job_id": "j", "execution_binding": {}}, None):
      self.assertEqual(self.repo.list_triage_for_record(bad), {})

  def test_legacy_job_keyed_rows_are_ignored(self):
    self.owner.hashes["inst:triage"] = {"j:f1": {"job_id": "j", "finding_id": "f1", "status": "false_positive"}}
    self.assertEqual(self.repo.list_triage_for_record(record()), {})


if __name__ == "__main__":
  unittest.main()
