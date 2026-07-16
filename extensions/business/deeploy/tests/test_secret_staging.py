import copy
import unittest

from extensions.business.deeploy.deeploy_job_mixin import (
  DAUTH_JOB_SECRETS_CSTORE_HKEY,
  DEEPLOY_JOBS_CSTORE_HKEY,
  _DeeployJobMixin,
)
from extensions.business.deeploy.deeploy_mixin import (
  DEEPLOY_DAUTH_SECRET_PLACEHOLDER,
  _DeeployMixin,
)


class _BCStub:
  def get_dauth_oracles(self):
    return ["dauth-a", "dauth-b"], ["a", "b"]


class _R1FSStub:
  def __init__(self, events):
    self.events = events
    self.next_cid = "staged-cid"

  def add_json(self, payload, **kwargs):
    self.events.append(("r1fs_add", copy.deepcopy(payload), kwargs))
    return self.next_cid

  def calculate_json_cid(self, payload, **kwargs):
    return self.next_cid

  def delete_file(self, cid, **kwargs):
    self.events.append(("r1fs_delete", cid, kwargs))


class _SecretStagingPlugin(_DeeployMixin, _DeeployJobMixin):
  def __init__(self):
    self.events = []
    self.bc = _BCStub()
    self.r1fs = _R1FSStub(self.events)
    self.store = {
      (DEEPLOY_JOBS_CSTORE_HKEY, "7"): "prior-cid",
      (DAUTH_JOB_SECRETS_CSTORE_HKEY, "7"): {
        "job_id": "7",
        "job_secrets": {
          "PLUGINS": [{
            "INSTANCES": [{
              "ENV": {
                "CF_TUNNEL_TOKEN": "prior-token",
                "CRDB_PASSWORD": "removed-password",
              },
            }],
          }],
        },
      },
    }
    self.deepcopy = copy.deepcopy
    self.cfg_deeploy_verbose = 0

  def chainstore_hget(self, hkey, key):
    return copy.deepcopy(self.store.get((hkey, str(key))))

  def chainstore_hset(self, hkey, key, value, **kwargs):
    self.events.append(("hset", hkey, str(key), copy.deepcopy(value), kwargs))
    self.store[(hkey, str(key))] = copy.deepcopy(value)
    return True

  def _get_pipeline_from_cstore(self, job_id):
    return self.chainstore_hget(DEEPLOY_JOBS_CSTORE_HKEY, str(job_id))

  def _redact_per_node_config_for_log(self, payload):
    return "redacted"

  def json_dumps(self, payload, **kwargs):
    return str(payload)

  def Pd(self, *args, **kwargs):
    return


def _pipeline(token=DEEPLOY_DAUTH_SECRET_PLACEHOLDER):
  return {
    "NAME": "app",
    "TYPE": "void",
    "PLUGINS": [{
      "SIGNATURE": "CONTAINER_APP_RUNNER",
      "INSTANCES": [{
        "INSTANCE_ID": "car",
        "ENV": {"CF_TUNNEL_TOKEN": token},
      }],
    }],
  }


class DeeploySecretBundleTests(unittest.TestCase):
  def setUp(self):
    self.plugin = _SecretStagingPlugin()

  def test_reconstruction_uses_new_value_before_prior_same_path(self):
    pipeline = _pipeline()
    new_secrets = {
      "PLUGINS": [{"INSTANCES": [{"ENV": {"CF_TUNNEL_TOKEN": "new-token"}}]}],
    }

    bundle = self.plugin._build_complete_dauth_job_secret_bundle(
      7,
      pipeline,
      new_secrets,
      self.plugin._load_dauth_job_secret_bundle(7),
    )

    env = bundle["job_secrets"]["PLUGINS"][0]["INSTANCES"][0]["ENV"]
    self.assertEqual(env, {"CF_TUNNEL_TOKEN": "new-token"})

  def test_reconstruction_reuses_prior_same_path_and_omits_removed_paths(self):
    bundle = self.plugin._build_complete_dauth_job_secret_bundle(
      7,
      _pipeline(),
      {},
      self.plugin._load_dauth_job_secret_bundle(7),
    )

    env = bundle["job_secrets"]["PLUGINS"][0]["INSTANCES"][0]["ENV"]
    self.assertEqual(env, {"CF_TUNNEL_TOKEN": "prior-token"})
    self.assertNotIn("CRDB_PASSWORD", env)

  def test_reconstruction_rejects_unresolved_placeholder(self):
    with self.assertRaisesRegex(ValueError, "PLUGINS/0/INSTANCES/0/ENV/CF_TUNNEL_TOKEN"):
      self.plugin._build_complete_dauth_job_secret_bundle(8, _pipeline(), {}, None)

  def test_reconstruction_rejects_unknown_placeholder_without_same_path_value(self):
    pipeline = _pipeline()
    pipeline["PLUGINS"][0]["INSTANCES"][0]["FUTURE_SECRET"] = (
      DEEPLOY_DAUTH_SECRET_PLACEHOLDER
    )

    with self.assertRaisesRegex(ValueError, "FUTURE_SECRET"):
      self.plugin._build_complete_dauth_job_secret_bundle(
        7,
        pipeline,
        {},
        self.plugin._load_dauth_job_secret_bundle(7),
      )


class DeeploySecretStagingTests(unittest.TestCase):
  def setUp(self):
    self.plugin = _SecretStagingPlugin()
    self.bundle = {"job_id": "7", "job_secrets": {"PLUGINS": []}}

  def test_stage_writes_complete_bundle_before_publishing_pipeline_pointer(self):
    state = self.plugin.stage_job_pipeline_and_secrets(_pipeline(), 7, self.bundle)

    self.assertEqual(state["prior_cid"], "prior-cid")
    self.assertEqual([event[0] for event in self.plugin.events[:3]], ["r1fs_add", "hset", "hset"])
    secret_write = self.plugin.events[1]
    pipeline_write = self.plugin.events[2]
    self.assertEqual(pipeline_write[1], DEEPLOY_JOBS_CSTORE_HKEY)
    self.assertEqual(pipeline_write[4]["extra_peers"], ["dauth-a", "dauth-b"])
    self.assertTrue(pipeline_write[4]["include_default_peers"])
    self.assertTrue(pipeline_write[4]["include_configured_peers"])
    self.assertEqual(secret_write[1], DAUTH_JOB_SECRETS_CSTORE_HKEY)
    self.assertEqual(secret_write[3]["pipeline_cid"], "staged-cid")
    self.assertFalse(secret_write[4]["include_default_peers"])
    self.assertFalse(secret_write[4]["include_configured_peers"])

  def test_commit_deletes_prior_cid_only_while_stage_is_current(self):
    state = self.plugin.stage_job_pipeline_and_secrets(_pipeline(), 7, self.bundle)
    self.assertTrue(self.plugin.commit_staged_job_pipeline_and_secrets(state))
    self.assertIn(("r1fs_delete", "prior-cid", {
      "show_logs": False,
      "raise_on_error": False,
    }), self.plugin.events)

  def test_rollback_restores_prior_pointer_and_bundle_then_deletes_stage(self):
    prior_bundle = copy.deepcopy(self.plugin.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")])
    state = self.plugin.stage_job_pipeline_and_secrets(_pipeline(), 7, self.bundle)

    self.assertTrue(self.plugin.rollback_staged_job_pipeline_and_secrets(state))
    self.assertEqual(self.plugin.store[(DEEPLOY_JOBS_CSTORE_HKEY, "7")], "prior-cid")
    self.assertEqual(self.plugin.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")], prior_bundle)
    self.assertEqual(self.plugin.events[-1][0:2], ("r1fs_delete", "staged-cid"))

  def test_rollback_does_not_overwrite_newer_concurrent_stage(self):
    state = self.plugin.stage_job_pipeline_and_secrets(_pipeline(), 7, self.bundle)
    newer_bundle = {"job_id": "7", "job_secrets": {"newer": True}}
    self.plugin.store[(DEEPLOY_JOBS_CSTORE_HKEY, "7")] = "newer-cid"
    self.plugin.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")] = newer_bundle
    event_count = len(self.plugin.events)

    self.assertFalse(self.plugin.rollback_staged_job_pipeline_and_secrets(state))
    self.assertEqual(self.plugin.store[(DEEPLOY_JOBS_CSTORE_HKEY, "7")], "newer-cid")
    self.assertEqual(self.plugin.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")], newer_bundle)
    self.assertEqual(len(self.plugin.events), event_count)

  def test_rollback_does_not_overwrite_newer_bundle_with_same_cid(self):
    state = self.plugin.stage_job_pipeline_and_secrets(_pipeline(), 7, self.bundle)
    newer_bundle = {"job_id": "7", "job_secrets": {"newer": True}}
    self.plugin.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")] = newer_bundle

    self.assertFalse(self.plugin.rollback_staged_job_pipeline_and_secrets(state))
    self.assertEqual(self.plugin.store[(DEEPLOY_JOBS_CSTORE_HKEY, "7")], "staged-cid")
    self.assertEqual(self.plugin.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")], newer_bundle)
    self.assertNotEqual(self.plugin.events[-1][0:2], ("r1fs_delete", "staged-cid"))

  def test_commit_requires_staged_bundle_to_still_be_current(self):
    state = self.plugin.stage_job_pipeline_and_secrets(_pipeline(), 7, self.bundle)
    self.plugin.store[(DAUTH_JOB_SECRETS_CSTORE_HKEY, "7")] = {
      "job_id": "7",
      "job_secrets": {"newer": True},
    }

    self.assertFalse(self.plugin.commit_staged_job_pipeline_and_secrets(state))
    self.assertNotIn(("r1fs_delete", "prior-cid", {
      "show_logs": False,
      "raise_on_error": False,
    }), self.plugin.events)


if __name__ == "__main__":
  unittest.main()
