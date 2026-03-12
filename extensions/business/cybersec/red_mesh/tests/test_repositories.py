import unittest
from unittest.mock import MagicMock

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

