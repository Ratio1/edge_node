from extensions.business.deeploy.tests.support import submit_deployment, capture_deployment_admission
import copy
import sys
import threading
import types
import unittest
from collections import defaultdict
from types import SimpleNamespace
from unittest.mock import Mock

from naeural_core import constants as ct

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS, DEEPLOY_STATUS
from extensions.business.deeploy.deeploy_mixin import (
  DEEPLOY_DAUTH_JOB_SECRETS_HKEY,
  DEEPLOY_DAUTH_SECRET_PLACEHOLDER,
  _DeeployMixin,
)


class _BasePluginStub:
  CONFIG = {"VALIDATION_RULES": {}}

  @staticmethod
  def endpoint(*_args, **_kwargs):
    def decorator(func):
      return func
    return decorator


_supervisor_module = types.ModuleType(
  "naeural_core.business.default.web_app.supervisor_fast_api_web_app"
)
_supervisor_module.SupervisorFastApiWebApp = _BasePluginStub
sys.modules[
  "naeural_core.business.default.web_app.supervisor_fast_api_web_app"
] = _supervisor_module

from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin


class _InputsStub(dict):
  def __getattr__(self, item):
    try:
      return self[item]
    except KeyError:
      raise KeyError(item)


class _BCStub:
  def __init__(self):
    self.submitted = []

  def node_addr_to_eth_addr(self, node):
    return f"eth_{node}"

  def submit_node_update(self, job_id, nodes):
    self.submitted.append((job_id, list(nodes)))


class _ProcessRequestStub(DeeployManagerApiPlugin):
  def __init__(self):
    self._create_job_claim_lock = threading.Lock()
    self._active_create_job_ids = set()
    capture_deployment_admission(self, {})

  def _DeeployManagerApiPlugin__ensure_eth_balance(self):
    return True

  def _get_response(self, dct_data):
    return dct_data

  def P(self, *args, **kwargs):
    return

  def Pd(self, *args, **kwargs):
    return

  def time(self):
    return 1_000.0

  def trace_info(self):
    return ""

  def json_dumps(self, obj, **kwargs):
    return str(obj)

  def deeploy_verify_and_get_inputs(self, request, request_type=None, **_kwargs):
    return "sender", _InputsStub(copy.deepcopy(request))

  def deeploy_get_auth_result(self, inputs):
    return {
      DEEPLOY_KEYS.ESCROW_OWNER: "owner",
      DEEPLOY_KEYS.SENDER_ESCROW: "escrow",
    }

  def deeploy_check_payment_and_job_owner(self, inputs, owner, is_create=False, debug=False):
    return True

  def _check_nodes_availability(self, inputs, skip_resource_check=False):
    return list(inputs[DEEPLOY_KEYS.TARGET_NODES])

  def _ensure_deeploy_specs_job_config(self, specs, pipeline_params=None):
    return specs

  def _queue_pipeline_persistence(self, persistence_state):
    self.queued_persistence = persistence_state
    return True

  def chainstore_hget(self, hkey, key):
    return getattr(self, "canonical_record", None)

  def chainstore_hset(self, hkey, key, value):
    if not hasattr(self, "chainstore_writes"):
      self.chainstore_writes = []
    self.chainstore_writes.append({
      "hkey": hkey,
      "key": key,
      "value": copy.deepcopy(value),
    })
    return True

  def cmdapi_build_pipeline_config(self, **kwargs):
    config = {
      "NAME": kwargs["name"],
      "TYPE": kwargs["stream_type"],
    }
    if kwargs.get("url") is not None:
      config["URL"] = kwargs["url"]
    if kwargs.get("plugins") is not None:
      config["PLUGINS"] = copy.deepcopy(kwargs["plugins"])
    ignored = {"name", "stream_type", "url", "plugins"}
    config.update({
      key.upper(): copy.deepcopy(value)
      for key, value in kwargs.items()
      if key not in ignored
    })
    return config

  def _load_dauth_job_secret_bundle(self, job_id):
    return None

  def _get_pipeline_from_cstore(self, job_id):
    return getattr(self, "existing_pipeline_cid", None)

  def stage_job_pipeline_and_secrets(self, pipeline, job_id, secret_bundle):
    self.chainstore_hset(
      hkey=DEEPLOY_DAUTH_JOB_SECRETS_HKEY,
      key=str(job_id),
      value=secret_bundle,
    )
    return {"job_id": str(job_id), "pipeline": copy.deepcopy(pipeline)}

  def commit_staged_job_pipeline_and_secrets(self, state):
    return True

  def rollback_staged_job_pipeline_and_secrets(self, state):
    return True


class DeeployProcessRequestTests(unittest.TestCase):

  def test_status_auth_expiry_is_401_without_reclassifying_selector_errors(self):
    plugin = _ProcessRequestStub()
    plugin.deeploy_get_auth_result = lambda inputs: _DeeployMixin.deeploy_get_auth_result(plugin, inputs)
    plugin.deeploy_verify_and_get_inputs = lambda request, **kwargs: ("sender", _InputsStub({
      **request, "wallet_escrow": "escrow", "wallet_escrow_owner": "owner",
    }))
    plugin.time_to_str = lambda timestamp: str(timestamp)
    plugin.time = lambda: 100_000
    request = dict(nonce=hex(100_000_000), EE_ETH_SENDER="sender", EE_ETH_SIGN="signature")
    for nonce in (hex(1_000_000), "invalid", hex(100_001_000)):
      with self.subTest(nonce=nonce):
        result = plugin.get_deployment_status({**request, "nonce": nonce, "job_id": 7})
        self.assertEqual(result["status_code"], 401)
        self.assertEqual(result["error"]["code"], "AUTHENTICATION_FAILED")
    # Valid authorization with missing selectors stays a request error.
    result = plugin.get_deployment_status(request)
    self.assertEqual(result["status_code"], 400)
    self.assertEqual(result["error"]["code"], "INVALID_REQUEST")
    plugin._repair_deployment_records = Mock(side_effect=RuntimeError("storage unavailable"))
    self.assertEqual(plugin.get_deployment_status({**request, "job_id": 7})["status_code"], 503)
    plugin.deeploy_verify_and_get_inputs = Mock(side_effect=ValueError("Invalid signature"))
    self.assertEqual(plugin.get_deployment_status({**request, "job_id": 7})["status_code"], 401)
    # Shared nonce validation remains unchanged for other endpoint callers.
    with self.assertRaisesRegex(ValueError, "Nonce is expired"):
      plugin.deeploy_get_nonce(hex(1_000_000))

  def test_failed_create_retry_reuses_paid_job_only_after_confirmed_cleanup(self):
    completed = dict(job_id=97, owner="owner", kind="create", phase="completed",
                     outcome="failed", recovery="completed", target_revision=1,
                     request_id="previous-request")
    cases = [
      ("cleaned", [completed], "owner", True),
      ("no-history", [], "owner", False),
      ("blocked", [dict(completed, recovery="blocked")], "owner", False),
      ("still-stopping", [dict(completed, phase="stopping_failed_rollout")], "owner", False),
      ("other-job", [dict(completed, job_id=98)], "owner", False),
      ("other-owner", [dict(completed, owner="someone-else")], "owner", False),
      ("changed-paid-owner", [completed], "someone-else", False),
      ("newer-success", [completed, dict(completed, target_revision=2, outcome="succeeded")], "owner", False),
    ]
    for name, records, paid_owner, allowed in cases:
      with self.subTest(name=name):
        plugin = _ProcessRequestStub()
        plugin.ct = ct
        plugin.deepcopy = copy.deepcopy
        plugin.uuid = lambda size=7: "retry-id"[:size]
        plugin.cfg_deeploy_verbose = 0
        plugin._operation_records = lambda: {str(i): record for i, record in enumerate(records)}
        plugin.bc = SimpleNamespace(get_evm_network=lambda: "mainnet", get_job_details=lambda **kwargs: {
          "escrowOwner": paid_owner, "startTimestamp": 1, "jobType": 1,
        })
        # Use the real payment/ownership validator, not the fixture's override.
        plugin.deeploy_check_payment_and_job_owner = (
          DeeployManagerApiPlugin.deeploy_check_payment_and_job_owner.__get__(plugin)
        )
        nodes = Mock(side_effect=ValueError("Reached node selection after payment validation"))
        plugin._check_nodes_availability = nodes
        response = submit_deployment(plugin, {
          "job_id": 97, "app_alias": "native", "job_app_type": "native",
          "pipeline_input_type": "void", "pipeline_input_uri": None, "pipeline_params": {},
          "target_nodes": ["node"], "plugins": [{"plugin_signature": "CUSTOM_EXEC_01", "CODE": ""}],
        })
        self.assertEqual(nodes.called, allowed, response)
        self.assertEqual(response["status_code"], 400 if name != "still-stopping" else 409)
        if allowed:
          self.assertIn("Reached node selection", response["error"]["message"])

  def test_create_pipeline_accepts_ui_cockroach_single_plugin_top_level_per_node_config(self):
    plugin = _ProcessRequestStub()
    plugin.ct = ct
    plugin.bc = _BCStub()
    plugin.deepcopy = copy.deepcopy
    plugin.defaultdict = defaultdict
    plugin.sanitize_name = lambda value: str(value).replace("/", "_").replace(" ", "_")
    plugin.uuid = lambda size=7: "abc1234"[:size]
    plugin.cfg_deeploy_verbose = 0
    plugin.queued_persistence = None
    plugin.chainstore_writes = []
    captured = {}

    def check_and_deploy_pipelines(**kwargs):
      captured.update(kwargs)
      return {}, DEEPLOY_STATUS.COMMAND_DELIVERED, {}, {
        "CONFIG_STREAMS": [{"NAME": kwargs["app_id"]}],
      }

    plugin.check_and_deploy_pipelines = check_and_deploy_pipelines
    capture_deployment_admission(plugin, captured)
    request = {
      DEEPLOY_KEYS.APP_ALIAS: "cockroachdb",
      DEEPLOY_KEYS.TARGET_NODES: ["0xai_node_a", "0xai_node_b", "0xai_node_c"],
      DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
      DEEPLOY_KEYS.PIPELINE_INPUT_URI: None,
      DEEPLOY_KEYS.PIPELINE_PARAMS: {
        "deeploy_cockroachdb": {
          "version": 1,
          "service": "cockroachdb",
        },
      },
      DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
      DEEPLOY_KEYS.JOB_APP_TYPE: "service",
      DEEPLOY_KEYS.JOB_ID: 97,
      DEEPLOY_KEYS.RETURN_REQUEST: True,
      DEEPLOY_KEYS.PLUGINS: [{
        DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
        "IMAGE": "ghcr.io/ratio1/deeploy-cockroachdb-service:main",
        "CONTAINER_RESOURCES": {"cpu": 1, "memory": "2g", "storage": "8g"},
        "ENV": {
          "CRDB_DATABASE": "appdb",
          "CRDB_USER": "appuser",
          "CRDB_PASSWORD": "secret-password",
          "CRDB_MAX_OFFSET": "500ms",
        },
      }],
      "PER_NODE_CONFIG": {
        "byNode": {
          "0xai_node_a": {"ENV": {"CRDB_NODE_ID": "1", "CF_TUNNEL_TOKEN": "token-a"}},
          "0xai_node_b": {"ENV": {"CRDB_NODE_ID": "2", "CF_TUNNEL_TOKEN": "token-b"}},
          "0xai_node_c": {"ENV": {"CRDB_NODE_ID": "3", "CF_TUNNEL_TOKEN": "token-c"}},
        },
      },
    }

    invalid_request = copy.deepcopy(request)
    invalid_request[DEEPLOY_KEYS.TARGET_NODES] = ["0xai_node_a", "0xai_node_b"]
    invalid_res = submit_deployment(plugin, invalid_request, is_create=True)
    self.assertEqual(invalid_res[DEEPLOY_KEYS.STATUS], "error")
    self.assertIn("at least 3 target nodes", invalid_res[DEEPLOY_KEYS.ERROR]["message"])
    self.assertEqual(captured, {})
    self.assertEqual(plugin.bc.submitted, [])

    duplicate_request = copy.deepcopy(request)
    duplicate_request[DEEPLOY_KEYS.TARGET_NODES] = ["0xai_node_a", "0xai_node_a", "0xai_node_a"]
    duplicate_res = submit_deployment(plugin, duplicate_request, is_create=True)
    self.assertEqual(duplicate_res[DEEPLOY_KEYS.STATUS], "error")
    self.assertIn("distinct addresses", duplicate_res[DEEPLOY_KEYS.ERROR]["message"])
    self.assertEqual(captured, {})
    self.assertEqual(plugin.bc.submitted, [])

    plugin._claim_create_job(97)
    overlapping_result = submit_deployment(plugin, request, is_create=True)
    self.assertEqual(overlapping_result[DEEPLOY_KEYS.STATUS], "error")
    self.assertEqual(overlapping_result["status_code"], 400)
    self.assertIn("already in progress", overlapping_result[DEEPLOY_KEYS.ERROR]["message"])
    self.assertEqual(captured, {})
    self.assertEqual(plugin.chainstore_writes, [])
    plugin._release_create_job("97")

    res = submit_deployment(plugin, request, is_create=True)

    self.assertEqual(res[DEEPLOY_KEYS.STATUS], "accepted")
    self.assertEqual(plugin.bc.submitted, [])
    deployed_inputs = captured["inputs"]
    self.assertNotIn("PER_NODE_CONFIG", deployed_inputs)
    deployed_plugin = deployed_inputs[DEEPLOY_KEYS.PLUGINS][0]
    prepared_plugin = (
      captured["prepared_create_deploy_plan"]["node_plugins_by_addr"]["0xai_node_a"][0]
      [plugin.ct.CONFIG_PLUGIN.K_INSTANCES][0]
    )
    self.assertEqual(
      deployed_plugin["PER_NODE_CONFIG"]["byNode"]["0xai_node_b"]["ENV"]["CRDB_NODE_ID"],
      "2",
    )
    self.assertEqual(
      prepared_plugin["PER_NODE_CONFIG"]["byNode"]["0xai_node_b"]["ENV"]["CRDB_NODE_ID"],
      "2",
    )
    self.assertEqual(plugin.bc.submitted, [])
    self.assertNotIn("request", res)
    self.assertNotIn("token-a", str(res))
    self.assertNotIn("token-b", str(res))
    self.assertEqual(plugin.chainstore_writes, [])
    stored = str(captured["bundle"])
    self.assertIn("token-a", stored)
    self.assertIn("token-b", stored)
    self.assertNotIn(DEEPLOY_DAUTH_SECRET_PLACEHOLDER, stored)
    self.assertEqual(
      prepared_plugin["PER_NODE_CONFIG"]["byNode"]["0xai_node_a"]["ENV"]["CF_TUNNEL_TOKEN"],
      DEEPLOY_DAUTH_SECRET_PLACEHOLDER,
    )

    plugin.existing_pipeline_cid = "retained-first-attempt-cid"
    captured.clear()
    prior_writes = len(plugin.chainstore_writes)
    retry_result = submit_deployment(plugin, request, is_create=True)
    self.assertEqual(retry_result[DEEPLOY_KEYS.STATUS], "error")
    self.assertEqual(retry_result["status_code"], 400)
    self.assertIn("may still", retry_result[DEEPLOY_KEYS.ERROR]["message"])
    self.assertEqual(captured, {})
    self.assertEqual(len(plugin.chainstore_writes), prior_writes)

    plugin.existing_pipeline_cid = None
    def failed_admission(**kwargs):
      raise RuntimeError("replication unavailable")
    plugin._admit_prepared_deployment = failed_admission
    failed_result = submit_deployment(plugin, request, is_create=True)
    self.assertEqual(failed_result[DEEPLOY_KEYS.STATUS], "error")
    self.assertEqual(failed_result["status_code"], 503)
    self.assertTrue(failed_result["error"]["retryable"])
    self.assertIn("same request_id", failed_result["error"]["message"])
    self.assertEqual(plugin.bc.submitted, [])

  def test_create_rejects_reserved_cockroachdb_user_before_payment_or_node_lookup(self):
    plugin = _ProcessRequestStub()
    plugin.ct = ct
    plugin.bc = _BCStub()
    plugin.deepcopy = copy.deepcopy
    plugin.sanitize_name = lambda value: str(value).replace("/", "_").replace(" ", "_")
    plugin.uuid = lambda size=7: "abc1234"[:size]
    plugin.cfg_deeploy_verbose = 0
    plugin.queued_persistence = None
    phase_calls = []
    plugin.deeploy_check_payment_and_job_owner = (
      lambda *args, **kwargs: phase_calls.append("payment") or True
    )
    plugin._check_nodes_availability = (
      lambda inputs, **kwargs: phase_calls.append("nodes")
      or list(inputs[DEEPLOY_KEYS.TARGET_NODES])
    )
    plugin.check_and_deploy_pipelines = (
      lambda **kwargs: phase_calls.append("deploy")
      or ({}, DEEPLOY_STATUS.COMMAND_DELIVERED, {}, {})
    )

    response = submit_deployment(plugin,
      {
        DEEPLOY_KEYS.APP_ALIAS: "cockroachdb",
        DEEPLOY_KEYS.TARGET_NODES: ["0xai_node_a", "0xai_node_b", "0xai_node_c"],
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.PIPELINE_INPUT_URI: None,
        DEEPLOY_KEYS.PIPELINE_PARAMS: {},
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.JOB_APP_TYPE: "service",
        DEEPLOY_KEYS.JOB_ID: 97,
        DEEPLOY_KEYS.RETURN_REQUEST: False,
        DEEPLOY_KEYS.PLUGINS: [{
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          "IMAGE": "ghcr.io/ratio1/r1db@sha256:" + ("a" * 64),
          "CONTAINER_RESOURCES": {"cpu": 1, "memory": "2g", "storage": "8g"},
          "ENV": {
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "AdMiN",
            "CRDB_PASSWORD": "secret-password",
          },
        }],
      },
      is_create=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "error")
    self.assertIn("reserved", response[DEEPLOY_KEYS.ERROR]["message"])
    self.assertEqual(phase_calls, [])
    self.assertEqual(plugin.bc.submitted, [])

  def test_create_rejects_per_node_cockroachdb_credentials_before_payment_or_node_lookup(self):
    plugin = _ProcessRequestStub()
    plugin.ct = ct
    plugin.bc = _BCStub()
    plugin.deepcopy = copy.deepcopy
    plugin.sanitize_name = lambda value: str(value).replace("/", "_").replace(" ", "_")
    plugin.uuid = lambda size=7: "abc1234"[:size]
    plugin.cfg_deeploy_verbose = 0
    plugin.queued_persistence = None
    phase_calls = []
    plugin.deeploy_check_payment_and_job_owner = (
      lambda *args, **kwargs: phase_calls.append("payment") or True
    )
    plugin._check_nodes_availability = (
      lambda inputs, **kwargs: phase_calls.append("nodes")
      or list(inputs[DEEPLOY_KEYS.TARGET_NODES])
    )
    plugin.check_and_deploy_pipelines = (
      lambda **kwargs: phase_calls.append("deploy")
      or ({}, DEEPLOY_STATUS.COMMAND_DELIVERED, {}, {})
    )

    response = submit_deployment(plugin,
      {
        DEEPLOY_KEYS.APP_ALIAS: "cockroachdb",
        DEEPLOY_KEYS.TARGET_NODES: ["0xai_node_a", "0xai_node_b", "0xai_node_c"],
        DEEPLOY_KEYS.PIPELINE_INPUT_TYPE: "void",
        DEEPLOY_KEYS.PIPELINE_INPUT_URI: None,
        DEEPLOY_KEYS.PIPELINE_PARAMS: {},
        DEEPLOY_KEYS.CHAINSTORE_RESPONSE: False,
        DEEPLOY_KEYS.JOB_APP_TYPE: "service",
        DEEPLOY_KEYS.JOB_ID: 97,
        DEEPLOY_KEYS.RETURN_REQUEST: False,
        DEEPLOY_KEYS.PLUGINS: [{
          DEEPLOY_KEYS.PLUGIN_SIGNATURE: "CONTAINER_APP_RUNNER",
          "IMAGE": "ghcr.io/ratio1/r1db@sha256:" + ("a" * 64),
          "CONTAINER_RESOURCES": {"cpu": 1, "memory": "2g", "storage": "8g"},
          "ENV": {
            "CRDB_DATABASE": "appdb",
            "CRDB_USER": "app_user",
            "CRDB_PASSWORD": "secret-password",
          },
          "PER_NODE_CONFIG": {
            "byNode": {
              "0xai_node_b": {"ENV": {"CRDB_USER": "root"}},
            },
          },
        }],
      },
      is_create=True,
    )

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "error")
    self.assertIn("per-node ENV", response[DEEPLOY_KEYS.ERROR]["message"])
    self.assertEqual(phase_calls, [])
    self.assertEqual(plugin.bc.submitted, [])

  def test_error_handler_redacts_secret_request_values(self):
    plugin = _ProcessRequestStub()
    plugin.deepcopy = copy.deepcopy
    plugin.cfg_deeploy_verbose = 0
    request = {
      DEEPLOY_KEYS.PLUGINS: [{
        "EXPOSED_PORTS": {
          "26257": {
            "token": "cf-token",
            "protocol": "tcp",
          },
        },
        "PER_NODE_CONFIG": {
          "byNode": {
            "0xai_node_a": {"ENV": {"CF_TUNNEL_TOKEN": "node-token"}},
          },
        },
      }],
    }

    res = plugin._DeeployManagerApiPlugin__handle_error(ValueError("boom"), request)

    serialized = str(res)
    self.assertNotIn("cf-token", serialized)
    self.assertNotIn("node-token", serialized)
    self.assertIn("'token': '***'", serialized)
    self.assertIn("'PER_NODE_CONFIG': '***'", serialized)


if __name__ == "__main__":
  unittest.main()
