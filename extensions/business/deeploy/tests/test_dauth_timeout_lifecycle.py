import copy
import sys
import types
import unittest
from unittest.mock import patch

from extensions.business.dauth.dauth_mixin import _DauthMixin
from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_STATUS
from extensions.business.deeploy.tests.test_secret_staging import (
  _SecretStagingPlugin,
  _pipeline,
)


class _BasePluginStub:
  CONFIG = {"VALIDATION_RULES": {}}

  @staticmethod
  def endpoint(*_args, **_kwargs):
    return lambda func: func


_supervisor_module = types.ModuleType(
  "naeural_core.business.default.web_app.supervisor_fast_api_web_app"
)
_supervisor_module.SupervisorFastApiWebApp = _BasePluginStub
sys.modules.setdefault(_supervisor_module.__name__, _supervisor_module)

from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin


class _LifecyclePlugin(_SecretStagingPlugin):
  def __init__(self):
    super().__init__()
    self._DeeployManagerApiPlugin__pending_deploy_requests = {}
    self.worker_configs = {}

  def _get_response(self, result):
    return result

  def _release_managed_update_action(self, _claim_key):
    return


class _Oracle(_DauthMixin):
  def __init__(self):
    self.store = {}
    self.const = types.SimpleNamespace(
      BASE_CT=types.SimpleNamespace(
        dAuth=types.SimpleNamespace(DAUTH_NONCE="nonce")
      )
    )
    self.bc = types.SimpleNamespace(
      maybe_add_prefix=lambda address: address,
      encrypt_str=lambda str_data, str_recipient: f"encrypted-for-{str_recipient}",
    )

  def chainstore_hget(self, hkey, key):
    return copy.deepcopy(self.store.get((hkey, str(key))))

  def _verify_signed_dauth_body(self, _body):
    return "node-a", "eth-node-a"

  def _validate_dauth_secret_request_nonce(self, _body):
    return "nonce"

  def json_dumps(self, payload):
    return str(payload)


class DeeployDauthTimeoutLifecycleTests(unittest.TestCase):
  def test_partial_create_dispatch_keeps_staged_metadata(self):
    plugin = _LifecyclePlugin()
    state = plugin.stage_job_pipeline_and_secrets(
      _pipeline(), 116, {"job_id": "116", "job_secrets": {"PLUGINS": []}}
    )
    state["retain_on_failed_dispatch"] = True

    def dispatch(_plugin, node, config):
      if node == "node-b":
        raise RuntimeError("command unavailable")
      plugin.worker_configs[node] = copy.deepcopy(config)

    with patch("extensions.business.deeploy.deeploy_mixin.dispatch_pipeline_config", dispatch):
      with self.assertRaisesRegex(RuntimeError, "command unavailable"):
        plugin._DeeployMixin__create_pipeline_on_nodes(
          nodes=["node-a", "node-b"],
          inputs={},
          app_id="app",
          app_alias="app",
          app_type="void",
          owner="owner",
          prepared_deploy_plan={"enable_chainstore_response": False},
          prepared_pipeline_configs={"node-a": _pipeline(), "node-b": _pipeline()},
          dispatch_state=state,
        )

    self.assertTrue(state["dispatch_attempted"])
    self.assertIn("node-a", plugin.worker_configs)
    self.assertTrue(plugin.settle_failed_staged_job_pipeline_and_secrets(
      state, "dispatch error"
    ))
    self.assertEqual(plugin._get_pipeline_from_cstore(116), state["staged_cid"])

  def test_pre_dispatch_create_failure_removes_staged_metadata(self):
    plugin = _LifecyclePlugin()
    state = plugin.stage_job_pipeline_and_secrets(
      _pipeline(), 116, {"job_id": "116", "job_secrets": {"PLUGINS": []}}
    )
    state["retain_on_failed_dispatch"] = True

    self.assertTrue(plugin.settle_failed_staged_job_pipeline_and_secrets(
      state, "validation error"
    ))
    self.assertIsNone(plugin._get_pipeline_from_cstore(116))
    self.assertIsNone(plugin._load_dauth_job_secret_bundle(116))
    self.assertNotIn("dispatch_uncertain", state)
    self.assertIn("staged-cid", [event[1] for event in plugin.events if event[0] == "r1fs_delete"])

  def test_failed_dispatched_create_reports_uncertainty(self):
    plugin = _LifecyclePlugin()
    state = plugin.stage_job_pipeline_and_secrets(
      _pipeline(), 116, {"job_id": "116", "job_secrets": {"PLUGINS": []}}
    )
    state["retain_on_failed_dispatch"] = True
    state["dispatch_attempted"] = True
    pending = {
      "kind": "pipeline",
      "staging": state,
      "confirm": {},
      "base_result": {},
    }

    response = DeeployManagerApiPlugin.finalize_pending_request_pipeline(
      plugin, pending, {}, DEEPLOY_STATUS.FAIL
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.FAIL)
    self.assertTrue(response["dispatch_uncertain"])
    self.assertEqual(plugin._get_pipeline_from_cstore(116), state["staged_cid"])

  def test_unmarked_stage_without_prior_cid_rolls_back(self):
    plugin = _LifecyclePlugin()
    state = plugin.stage_job_pipeline_and_secrets(
      _pipeline(), 116, {"job_id": "116", "job_secrets": {"PLUGINS": []}}
    )
    pending = {
      "kind": "pipeline",
      "staging": state,
      "confirm": {},
      "base_result": {},
    }

    response = DeeployManagerApiPlugin.finalize_pending_request_pipeline(
      plugin, pending, {}, DEEPLOY_STATUS.FAIL
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.FAIL)
    self.assertIsNone(plugin._get_pipeline_from_cstore(116))
    self.assertIsNone(plugin._load_dauth_job_secret_bundle(116))

  def test_timed_out_create_keeps_secrets_for_dispatched_worker(self):
    plugin = _LifecyclePlugin()
    job_id = 116
    pipeline = _pipeline()
    pipeline["NAME"] = "r1db_test"
    pipeline["DEEPLOY_SPECS"] = {"current_target_nodes": ["node-a", "node-b"]}
    state = plugin.stage_job_pipeline_and_secrets(
      pipeline,
      job_id,
      {"job_id": str(job_id), "job_secrets": {"PLUGINS": []}},
    )
    state["retain_on_failed_dispatch"] = True
    plugin.worker_configs["node-a"] = copy.deepcopy(pipeline)
    pending_id = "pending-create"
    pending = {
      "kind": "pipeline",
      "staging": state,
      "response_keys": {"node-a": ["a"], "node-b": ["b"]},
      "dct_status": {"a": {"node": "node-a", "status": "ready"}},
      "start_time": 0,
      "timeout": 10,
      "base_result": {DEEPLOY_KEYS.APP_ID: pipeline["NAME"]},
    }
    plugin._DeeployManagerApiPlugin__pending_deploy_requests[pending_id] = pending

    response = DeeployManagerApiPlugin.maybe_mark_timed_out_request(
      plugin, pending_id, pending, now=11
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.TIMEOUT)
    self.assertTrue(response["dispatch_uncertain"])
    self.assertIn("node-a", plugin.worker_configs)
    self.assertEqual(
      plugin._load_dauth_job_secret_bundle(job_id)["pipeline_cid"],
      state["staged_cid"],
    )
    self.assertEqual(plugin._get_pipeline_from_cstore(job_id), state["staged_cid"])

    oracle = _Oracle()
    oracle.r1fs = types.SimpleNamespace(get_json=lambda cid, **_kwargs: (
      copy.deepcopy(pipeline) if cid == state["staged_cid"] else None
    ))
    with self.assertRaisesRegex(ValueError, "not running job"):
      oracle.process_dauth_get_secret_request({"job_id": job_id})

    oracle.store = copy.deepcopy(plugin.store)
    secrets_response = oracle.process_dauth_get_secret_request({"job_id": job_id})
    self.assertEqual(secrets_response["status"], "success")
    self.assertEqual(secrets_response["encrypted_secret_bundle"], "encrypted-for-node-a")

  def test_failed_update_restores_prior_bundle_and_cid(self):
    plugin = _LifecyclePlugin()
    state = plugin.stage_job_pipeline_and_secrets(
      _pipeline(), 7, {"job_id": "7", "job_secrets": {"PLUGINS": []}}
    )
    pending = {
      "kind": "pipeline",
      "staging": state,
      "confirm": {},
      "base_result": {},
    }

    response = DeeployManagerApiPlugin.finalize_pending_request_pipeline(
      plugin, pending, {"a": {"node": "node-a", "status": "ready"}}, DEEPLOY_STATUS.FAIL
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], DEEPLOY_STATUS.FAIL)
    self.assertEqual(plugin._get_pipeline_from_cstore(7), state["prior_cid"])
    self.assertEqual(
      plugin._load_dauth_job_secret_bundle(7), state["prior_bundle"]
    )
    self.assertIn("staged-cid", [event[1] for event in plugin.events if event[0] == "r1fs_delete"])


if __name__ == "__main__":
  unittest.main()
