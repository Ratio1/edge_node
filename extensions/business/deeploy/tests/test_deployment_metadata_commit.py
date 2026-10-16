"""Restart repair for versioned canonical metadata, independently of workloads."""
import copy
import unittest
from types import SimpleNamespace

from extensions.business.deeploy.deeploy_job_mixin import (
  _DeeployJobMixin, DEEPLOY_JOBS_CSTORE_HKEY, DAUTH_JOB_SECRETS_CSTORE_HKEY,
)


class Metadata(_DeeployJobMixin):
  def __init__(self, storage=None):
    self.storage = storage if storage is not None else {}
    self.deepcopy = copy.deepcopy
    self.bc = SimpleNamespace(
      address="oracle", get_dauth_oracles=lambda: (["oracle", "replica"], []),
      sign=lambda record, **kwargs: record.update(EE_SIGN="signed", EE_SENDER="oracle"),
    )
    self.fail_pointer = False
    self.deleted = []
    self._recursively_sort_pipeline_data = lambda value: value
    self._save_pipeline_to_r1fs = lambda pipeline: "cid-restored"
    self._delete_pipeline_cid_from_r1fs = self.deleted.append

  def chainstore_hget(self, hkey, key):
    return copy.deepcopy(self.storage.get((hkey, key)))

  def chainstore_hgetall(self, hkey):
    return {key: value for (namespace, key), value in self.storage.items() if namespace == hkey}

  def chainstore_hset(self, hkey, key, value, **kwargs):
    if self.fail_pointer and hkey == DEEPLOY_JOBS_CSTORE_HKEY:
      return False
    self.storage[hkey, key] = copy.deepcopy(value)
    return True


class DeploymentMetadataCommitTests(unittest.TestCase):
  def test_partial_secret_commit_is_repaired_after_restart_without_old_generation_write(self):
    previous = dict(job_id="7", revision=5, pipeline_cid="cid-previous", deleted=False)
    plugin = Metadata({(DEEPLOY_JOBS_CSTORE_HKEY, "7"): previous})
    operation = dict(job_id=7, target_revision=6, operation_id="recover", coordinator="oracle")
    pipeline = {"NAME": "app", "DEEPLOY_SPECS": {"revision": 4}, "PLUGINS": []}
    bundle = {"job_id": "7", "revision": "recover:restore", "job_secrets": {"token": "old-value"}}
    plugin.fail_pointer = True
    with self.assertRaisesRegex(RuntimeError, "metadata publication"):
      plugin.commit_deployment_revision(operation, pipeline, bundle)
    self.assertEqual(plugin.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"], previous)
    staged = plugin.storage[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"]
    self.assertEqual(staged["deployment_revision"], 6)
    self.assertEqual(plugin.deleted, [])

    restarted = Metadata(plugin.storage)
    restarted.commit_deployment_revision(operation, pipeline, bundle)
    pointer = restarted.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"]
    self.assertEqual(pointer["revision"], 6)
    self.assertEqual(pointer["pipeline_cid"], "cid-restored")
    self.assertEqual(restarted.storage[DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"], staged)
    self.assertEqual(restarted.deleted, ["cid-previous"])
    self.assertEqual(pipeline["DEEPLOY_SPECS"]["revision"], 4)
    restarted.commit_deployment_revision(operation, pipeline, bundle)
    self.assertEqual(restarted.deleted, ["cid-previous"])

  def test_deleted_pointer_is_not_listed_or_loaded_and_higher_revision_can_replace_it(self):
    plugin = Metadata({(DEEPLOY_JOBS_CSTORE_HKEY, "7"): {
      "revision": 8, "deleted": True, "pipeline_cid": None,
    }})
    self.assertIsNone(plugin._get_pipeline_from_cstore(7))
    self.assertEqual(plugin.list_all_deployed_jobs_from_cstore(), {})
    plugin.commit_deployment_revision(
      dict(job_id=7, target_revision=9, operation_id="new", coordinator="oracle"),
      {"NAME": "new-app", "DEEPLOY_SPECS": {"revision": 9}}, {"job_secrets": {}},
    )
    self.assertEqual(plugin.list_all_deployed_jobs_from_cstore(), {"7": "cid-restored"})
    self.assertEqual(plugin.storage[DEEPLOY_JOBS_CSTORE_HKEY, "7"]["revision"], 9)


if __name__ == "__main__":
  unittest.main()
