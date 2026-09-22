import json
import sys
import types
import unittest
from types import SimpleNamespace

from ratio1.const.base import dAuth

from extensions.business.dauth.dauth_mixin import (
  DAUTH_SECRET_REVEAL_ACTION,
  DAUTH_VIEW_SECRETS_PERMISSION,
)
from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS
from extensions.business.deeploy.tests.support import InputsStub, make_deeploy_plugin


_supervisor_module = types.ModuleType("naeural_core.business.default.web_app.supervisor_fast_api_web_app")


class _BasePluginStub:
  CONFIG = {"VALIDATION_RULES": {}}

  @classmethod
  def endpoint(cls, **kwargs):  # pylint: disable=unused-argument
    def decorator(fn):
      return fn
    return decorator


_supervisor_module.SupervisorFastApiWebApp = _BasePluginStub
sys.modules.setdefault(
  "naeural_core.business.default.web_app.supervisor_fast_api_web_app",
  _supervisor_module,
)

from extensions.business.deeploy.deeploy_manager_api import DeeployManagerApiPlugin


REQUEST_TIME = 1_700_000_000
REQUEST_NONCE = hex(REQUEST_TIME * 1000)


class _RevealBC:
  def __init__(self, sender="0xOwner", permissions=0):
    self.sender = sender
    self.permissions = permissions
    self.signed = None

  def get_user_escrow_details(self, address):
    return {
      "isActive": True,
      "escrowOwner": "0xOwner",
      "permissions": self.permissions,
    }

  def get_job_details(self, job_id):  # pylint: disable=unused-argument
    return {"escrowOwner": "0xOwner"}

  @staticmethod
  def get_evm_network():
    return "devnet"

  @staticmethod
  def get_network_data(network):  # pylint: disable=unused-argument
    return {dAuth.EvmNetData.DAUTH_URL_KEY: "https://devnet-dauth.ratio1.ai/get_auth_data"}

  def sign(self, body):
    body["EE_SENDER"] = "deeploy-oracle"
    body["EE_ETH_SENDER"] = "0xOracle"
    body["EE_SIGN"] = "relay-signature"
    self.signed = body

  @staticmethod
  def verify(result, return_full_info=False):  # pylint: disable=unused-argument
    return SimpleNamespace(valid=True, sender="dauth-oracle")

  @staticmethod
  def node_address_to_eth_address(address):  # pylint: disable=unused-argument
    return "0xDauth"

  @staticmethod
  def is_dauth_oracle(node_address_eth=None):  # pylint: disable=unused-argument
    return True

  @staticmethod
  def decrypt_str(encrypted_bundle, signer):  # pylint: disable=unused-argument
    return json.dumps({
      "job_id": "7",
      "pipeline_cid": "cid-7",
      "job_secrets": {"PLUGINS": [{"INSTANCES": [{"ENV": {"TOKEN": "secret"}}]}]},
    })


class _Response:
  status_code = 200

  def __init__(self, plugin):
    self.plugin = plugin

  def json(self):
    return {
      "result": {
        "status": "success",
        "job_id": "7",
        "nonce": self.plugin.bc.signed["nonce"],
        "encrypted_secret_bundle": "encrypted",
      },
    }


class _Requests:
  def __init__(self, plugin):
    self.plugin = plugin
    self.calls = []

  def post(self, url, json=None, timeout=None):
    self.calls.append((url, json, timeout))
    return _Response(self.plugin)


def make_reveal_plugin(sender="0xOwner", permissions=0):
  plugin = make_deeploy_plugin()
  plugin.bc = _RevealBC(sender=sender, permissions=permissions)
  plugin.time = lambda: REQUEST_TIME
  plugin._get_pipeline_from_cstore = lambda job_id: "cid-7"
  plugin.get_pipeline_from_r1fs = lambda *args, **kwargs: {
    "OWNER": "0xOwner",
    "PLUGINS": [{"INSTANCES": [{"ENV": {"TOKEN": "__R1_DAUTH_SECRET__"}}]}],
  }
  plugin.requests = _Requests(plugin)
  return plugin


def reveal_inputs(sender="0xOwner"):
  return InputsStub({
    "action": DAUTH_SECRET_REVEAL_ACTION,
    DEEPLOY_KEYS.JOB_ID: "7",
    DEEPLOY_KEYS.NONCE: REQUEST_NONCE,
    "EE_ETH_SENDER": sender,
  })


def reveal_auth(sender="0xOwner"):
  return {
    DEEPLOY_KEYS.SENDER: sender,
    DEEPLOY_KEYS.ESCROW_OWNER: "0xOwner",
  }


class DeeploySecretRevealTests(unittest.TestCase):

  def test_owner_can_reveal_without_delegate_permission(self):
    plugin = make_reveal_plugin()

    result = plugin._validate_job_secret_reveal_access(
      reveal_inputs(),
      reveal_auth(),
    )

    self.assertEqual(result[0:2], ("7", "cid-7"))
    self.assertEqual(result[2]["OWNER"], "0xOwner")

  def test_delegate_with_view_secrets_permission_can_reveal(self):
    plugin = make_reveal_plugin(
      sender="0xDelegate",
      permissions=DAUTH_VIEW_SECRETS_PERMISSION,
    )

    result = plugin._validate_job_secret_reveal_access(
      reveal_inputs("0xDelegate"),
      reveal_auth("0xDelegate"),
    )

    self.assertEqual(result[0:2], ("7", "cid-7"))

  def test_delegate_without_view_secrets_permission_is_rejected(self):
    plugin = make_reveal_plugin(sender="0xDelegate", permissions=1 << 0)

    with self.assertRaisesRegex(ValueError, "lacks view-secrets permission"):
      plugin._validate_job_secret_reveal_access(
        reveal_inputs("0xDelegate"),
        reveal_auth("0xDelegate"),
      )

  def test_relay_uses_job_only_public_contract_and_validates_internal_generation(self):
    plugin = make_reveal_plugin()
    wallet_request = {
      "action": DAUTH_SECRET_REVEAL_ACTION,
      "job_id": "7",
      "nonce": REQUEST_NONCE,
      "EE_ETH_SENDER": "0xOwner",
      "EE_ETH_SIGN": "wallet-signature",
    }

    secrets = plugin._request_dauth_job_secret_reveal(
      wallet_request=wallet_request,
      job_id="7",
      pipeline_cid="cid-7",
    )

    self.assertEqual(secrets["PLUGINS"][0]["INSTANCES"][0]["ENV"]["TOKEN"], "secret")
    url, payload, timeout = plugin.requests.calls[0]
    self.assertEqual(url, "https://devnet-dauth.ratio1.ai/reveal_job_secrets")
    self.assertEqual(timeout, (10, 60))
    self.assertNotIn("pipeline_cid", payload["body"]["wallet_request"])

  def test_relay_rejects_bundle_for_another_internal_generation(self):
    plugin = make_reveal_plugin()

    with self.assertRaisesRegex(ValueError, "pipeline generation is stale"):
      plugin._request_dauth_job_secret_reveal(
        wallet_request={"job_id": "7"},
        job_id="7",
        pipeline_cid="cid-new",
      )

  def test_relay_rejects_pipeline_changed_during_request(self):
    plugin = make_reveal_plugin()
    reads = iter(["cid-7", "cid-new"])
    plugin._get_pipeline_from_cstore = lambda job_id: next(reads)

    with self.assertRaisesRegex(ValueError, "changed while revealing"):
      pipeline_cid = plugin._get_pipeline_from_cstore("7")
      plugin._request_dauth_job_secret_reveal(
        wallet_request={"job_id": "7"},
        job_id="7",
        pipeline_cid=pipeline_cid,
      )

  def test_resolve_replaces_only_exact_placeholder_paths(self):
    plugin = make_reveal_plugin()
    pipeline = {
      "PLUGINS": [{
        "INSTANCES": [{
          "ENV": {
            "TOKEN": "__R1_DAUTH_SECRET__",
            "PUBLIC": "visible",
          },
        }],
      }],
    }
    secrets = {
      "PLUGINS": [{
        "INSTANCES": [{
          "ENV": {
            "TOKEN": "secret",
            "PUBLIC": "ignored-secret-copy",
            "EXTRA": "ignored",
          },
        }],
      }],
    }

    resolved = plugin._resolve_dauth_job_secrets_for_reveal(pipeline, secrets)

    self.assertEqual(resolved["PLUGINS"][0]["INSTANCES"][0]["ENV"]["TOKEN"], "secret")
    self.assertEqual(resolved["PLUGINS"][0]["INSTANCES"][0]["ENV"]["PUBLIC"], "visible")
    self.assertNotIn("EXTRA", resolved["PLUGINS"][0]["INSTANCES"][0]["ENV"])
    self.assertEqual(pipeline["PLUGINS"][0]["INSTANCES"][0]["ENV"]["TOKEN"], "__R1_DAUTH_SECRET__")

  def test_resolve_fails_when_placeholder_value_is_missing(self):
    plugin = make_reveal_plugin()
    pipeline = {
      "PLUGINS": [{"INSTANCES": [{"ENV": {"TOKEN": "__R1_DAUTH_SECRET__"}}]}],
    }

    with self.assertRaisesRegex(ValueError, "PLUGINS/0/INSTANCES/0/ENV/TOKEN"):
      plugin._resolve_dauth_job_secrets_for_reveal(pipeline, {})

  def test_api_returns_resolved_pipeline_without_internal_cid(self):
    plugin = DeeployManagerApiPlugin.__new__(DeeployManagerApiPlugin)
    inputs = reveal_inputs()
    plugin.deeploy_verify_and_get_inputs = lambda request, **kwargs: ("0xOwner", inputs)
    plugin.deeploy_get_auth_result = lambda request_inputs: reveal_auth()
    pipeline = {
      "PLUGINS": [{"INSTANCES": [{"ENV": {"TOKEN": "__R1_DAUTH_SECRET__"}}]}],
    }
    plugin._validate_job_secret_reveal_access = lambda **kwargs: ("7", "cid-7", pipeline)
    plugin._request_dauth_job_secret_reveal = lambda **kwargs: {"PLUGINS": []}
    plugin._resolve_dauth_job_secrets_for_reveal = lambda **kwargs: {"PLUGINS": [{"resolved": True}]}
    plugin._get_pipeline_from_cstore = lambda job_id: "cid-7"
    plugin._get_response = lambda result: result

    response = plugin.reveal_job_secrets({"job_id": "7"})

    self.assertEqual(response[DEEPLOY_KEYS.STATUS], "success")
    self.assertEqual(response[DEEPLOY_KEYS.JOB_ID], "7")
    self.assertEqual(response[DEEPLOY_KEYS.PIPELINE], {"PLUGINS": [{"resolved": True}]})
    self.assertNotIn("job_secrets", response)
    self.assertNotIn(DEEPLOY_KEYS.PIPELINE_CID, response)


if __name__ == "__main__":
  unittest.main()
