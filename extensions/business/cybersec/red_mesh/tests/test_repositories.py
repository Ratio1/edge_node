import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.models import CStoreJobRunning, JobArchive, JobConfig, PassReport, WorkerProgress
from extensions.business.cybersec.red_mesh.repositories import ArtifactRepository, JobStateRepository


class TestJobStateRepository(unittest.TestCase):

  def _make_owner(self):
    owner = MagicMock()
    owner.cfg_instance_id = "test-instance"
    return owner

  def test_job_state_repository_reads_and_writes_jobs(self):
    owner = self._make_owner()
    repo = JobStateRepository(owner)

    repo.get_job("job-1")
    owner.chainstore_hget.assert_called_once_with(hkey="test-instance", key="job-1")

    repo.put_job("job-1", {"job_id": "job-1"})
    owner.chainstore_hset.assert_called_once_with(hkey="test-instance", key="job-1", value={"job_id": "job-1"})

  def test_job_state_repository_uses_live_namespace(self):
    owner = self._make_owner()
    repo = JobStateRepository(owner)

    repo.list_live_progress()
    owner.chainstore_hgetall.assert_called_once_with(hkey="test-instance:live")

    repo.delete_live_progress("job-1:node-A")
    owner.chainstore_hset.assert_called_once_with(hkey="test-instance:live", key="job-1:node-A", value=None)

  def test_job_state_repository_supports_typed_running_jobs(self):
    owner = self._make_owner()
    owner.chainstore_hget.return_value = {
      "job_id": "job-1",
      "job_status": "RUNNING",
      "job_pass": 1,
      "run_mode": "SINGLEPASS",
      "launcher": "node-a",
      "launcher_alias": "node-a",
      "target": "example.com",
      "task_name": "Test",
      "start_port": 1,
      "end_port": 10,
      "date_created": 1.0,
      "job_config_cid": "QmConfig",
      "workers": {},
      "timeline": [],
      "pass_reports": [],
    }
    repo = JobStateRepository(owner)

    running = repo.get_running_job("job-1")

    self.assertIsInstance(running, CStoreJobRunning)
    persisted = repo.put_running_job(running)
    self.assertEqual(persisted["job_id"], "job-1")
    self.assertEqual(persisted["scan_type"], "network")

  def test_job_state_repository_supports_typed_live_progress(self):
    owner = self._make_owner()
    repo = JobStateRepository(owner)
    progress = WorkerProgress(
      job_id="job-1",
      worker_addr="node-a",
      pass_nr=1,
      progress=25.0,
      phase="port_scan",
      scan_type="network",
      phase_index=1,
      total_phases=5,
      ports_scanned=10,
      ports_total=40,
      open_ports_found=[22],
      completed_tests=["probe"],
      updated_at=1.0,
    )

    persisted = repo.put_live_progress_model(progress)

    self.assertEqual(persisted["job_id"], "job-1")
    owner.chainstore_hset.assert_called_once()

  def test_job_state_repository_put_job_coerces_running_job_shape(self):
    owner = self._make_owner()
    repo = JobStateRepository(owner)

    payload = repo.put_job("job-1", {
      "job_id": "job-1",
      "job_status": "RUNNING",
      "job_pass": 1,
      "run_mode": "SINGLEPASS",
      "launcher": "node-a",
      "launcher_alias": "node-a",
      "target": "example.com",
      "scan_type": "webapp",
      "target_url": "https://example.com/app",
      "task_name": "Test",
      "start_port": 443,
      "end_port": 443,
      "date_created": 1.0,
      "job_config_cid": "QmConfig",
      "workers": {},
      "timeline": [],
      "pass_reports": [],
    })

    self.assertEqual(payload["scan_type"], "webapp")
    self.assertEqual(payload["target_url"], "https://example.com/app")

  def test_job_state_repository_supports_finding_triage(self):
    owner = self._make_owner()
    owner.chainstore_hget.side_effect = [
      {"job_id": "job-1", "finding_id": "f-1", "status": "accepted_risk", "note": "known issue"},
      [{"job_id": "job-1", "finding_id": "f-1", "status": "accepted_risk", "timestamp": 10.0}],
    ]
    owner.chainstore_hgetall.side_effect = [
      {"job-1:f-1": {"job_id": "job-1", "finding_id": "f-1", "status": "accepted_risk"}},
      {"job-1:f-1": [{"job_id": "job-1", "finding_id": "f-1", "status": "accepted_risk", "timestamp": 10.0}]},
    ]
    repo = JobStateRepository(owner)

    triage = repo.get_finding_triage_model("job-1", "f-1")
    audit = repo.get_finding_triage_audit("job-1", "f-1")
    repo.delete_job_triage("job-1")

    self.assertEqual(triage.status, "accepted_risk")
    self.assertEqual(audit[0]["finding_id"], "f-1")
    self.assertEqual(owner.chainstore_hset.call_count, 2)


class TestArtifactRepository(unittest.TestCase):

  def _make_owner(self):
    owner = MagicMock()
    owner.r1fs = MagicMock()
    return owner

  def test_artifact_repository_reads_and_writes_json(self):
    owner = self._make_owner()
    repo = ArtifactRepository(owner)

    repo.get_json("QmCID")
    owner.r1fs.get_json.assert_called_once_with("QmCID")

    repo.put_json({"job_id": "job-1"}, show_logs=False)
    owner.r1fs.add_json.assert_called_once_with({"job_id": "job-1"}, show_logs=False)

  def test_artifact_repository_passes_secret_for_protected_json(self):
    owner = self._make_owner()
    repo = ArtifactRepository(owner)

    repo.get_json("QmCID", secret="node-secret-key")
    owner.r1fs.get_json.assert_called_once_with("QmCID", secret="node-secret-key")

    repo.put_json({"job_id": "job-1"}, show_logs=False, secret="node-secret-key")
    owner.r1fs.add_json.assert_called_once_with(
      {"job_id": "job-1"},
      show_logs=False,
      secret="node-secret-key",
    )

  def test_artifact_repository_job_config_helper(self):
    owner = self._make_owner()
    repo = ArtifactRepository(owner)

    repo.get_job_config({"job_config_cid": "QmConfig"})
    owner.r1fs.get_json.assert_called_once_with("QmConfig")

  def test_artifact_repository_delete_is_guarded_on_empty_cid(self):
    owner = self._make_owner()
    repo = ArtifactRepository(owner)

    self.assertFalse(repo.delete(""))
    owner.r1fs.delete_file.assert_not_called()

  def test_artifact_repository_supports_typed_models(self):
    owner = self._make_owner()
    repo = ArtifactRepository(owner)
    owner.r1fs.get_json.return_value = {
      "target": "example.com",
      "start_port": 1,
      "end_port": 10,
      "exceptions": [],
      "distribution_strategy": "SLICE",
      "port_order": "SEQUENTIAL",
      "nr_local_workers": 2,
      "enabled_features": [],
      "excluded_features": [],
      "run_mode": "SINGLEPASS",
    }

    job_config = repo.get_job_config_model({"job_config_cid": "QmConfig"})

    self.assertIsInstance(job_config, JobConfig)

    pass_report = PassReport(
      pass_nr=1,
      date_started=1.0,
      date_completed=2.0,
      duration=1.0,
      aggregated_report_cid="QmAgg",
      worker_reports={},
    )
    repo.put_pass_report(pass_report)

    archive = JobArchive(
      job_id="job-1",
      job_config=job_config.to_dict(),
      timeline=[],
      passes=[],
      ui_aggregate={"total_open_ports": [], "total_services": 0, "total_findings": 0},
      duration=1.0,
      date_created=1.0,
      date_completed=2.0,
    )
    repo.put_archive(archive)

    self.assertEqual(owner.r1fs.add_json.call_count, 2)
