import unittest

from eth_account import Account
from eth_account.messages import encode_defunct

from ratio1.bc.base import BaseBlockEngine

from extensions.business.deeploy.deeploy_const import DEEPLOY_REQUEST_TYPES
from extensions.business.deeploy.tests.support import make_deeploy_plugin


class _V3BcStub:

  def __init__(self):
    self.verify_calls = []

  def compact_canonical_json(self, value):
    return BaseBlockEngine.compact_canonical_json(None, value)

  def eth_verify_text_signature(
    self,
    text,
    signature,
    message_prefix="",
    no_hash=False,
    expected_signer=None,
    **kwargs,
  ):
    self.verify_calls.append({
      "text": text,
      "signature": signature,
      "message_prefix": message_prefix,
      "no_hash": no_hash,
      "expected_signer": expected_signer,
    })
    recovered = Account.recover_message(
      encode_defunct(primitive=text.encode("utf-8")),
      signature=signature,
    )
    return recovered


class DeeployV3WrapperTests(unittest.TestCase):

  def setUp(self):
    self.plugin = make_deeploy_plugin()
    self.plugin.bc = _V3BcStub()

  def test_wrapper_message_and_hash_match_typescript_contract(self):
    payload = {
      "nonce": "0xabc",
      "app_alias": "münchen_api",
      "target_nodes": ["0xai_node_a", "0xai_node_b"],
      "target_nodes_count": 0,
      "plugins": [
        {
          "plugin_signature": "WORKER_APP_RUNNER",
          "plugin_name": "api",
          "ENV": {"GREETING": "bună ziua"},
          "DYNAMIC_ENV": {
            "API_URL": [
              {"type": "static", "value": "https://"},
              {"type": "shmem", "path": ["web", "HOST_PORT"]},
            ],
          },
        },
        {
          "plugin_signature": "EDGE_NODE_API_TEST",
          "plugin_name": "probe",
        },
      ],
      "pipeline_params": {
        "labels": {"city": "Iași"},
      },
    }

    payload_hash = self.plugin._deeploy_payload_hash_v3(payload)
    message = self.plugin._deeploy_wrapper_message(
      request_type=DEEPLOY_REQUEST_TYPES.CREATE_PIPELINE,
      payload=payload,
      payload_hash=payload_hash,
    )

    self.assertEqual(payload_hash, "12169fe2f1a33373ba651d14318eb18d3239c0148a0d601de9f4ce3be9d2dded")
    self.assertEqual(
      message,
      """Please sign this Deeploy request:

Request type: create pipeline
Plugins: 2
Nodes: 2
Hash: 12169fe2f1a33373ba651d14318eb18d3239c0148a0d601de9f4ce3be9d2dded""",
    )

  def test_scale_up_wrapper_omits_plugins_line(self):
    payload = {
      "job_id": 42,
      "app_id": "api_1234567",
      "target_nodes": ["0xai_new_node"],
      "target_nodes_count": 0,
      "nonce": "0xdef",
    }

    payload_hash = self.plugin._deeploy_payload_hash_v3(payload)
    message = self.plugin._deeploy_wrapper_message(
      request_type=DEEPLOY_REQUEST_TYPES.SCALE_UP_JOB_WORKERS,
      payload=payload,
      payload_hash=payload_hash,
    )

    self.assertEqual(payload_hash, "1911187f82db8b14c607ffa1d15660deab623f184b07f622d55920615e2b9dcb")
    self.assertNotIn("Plugins:", message)
    self.assertEqual(
      message,
      """Please sign this Deeploy request:

Request type: scale up workers
Nodes: 1
Hash: 1911187f82db8b14c607ffa1d15660deab623f184b07f622d55920615e2b9dcb""",
    )

  def test_v3_signature_verification_recovers_sender(self):
    private_key = "0x" + "1" * 64
    sender = Account.from_key(private_key).address
    payload = {
      "nonce": "0xabc",
      "app_alias": "münchen_api",
      "target_nodes": ["0xai_node_a", "0xai_node_b"],
      "target_nodes_count": 0,
      "plugins": [{"plugin_signature": "EDGE_NODE_API_TEST"}],
      "pipeline_params": {"labels": {"city": "Iași"}},
    }
    payload_hash = self.plugin._deeploy_payload_hash_v3(payload)
    message = self.plugin._deeploy_wrapper_message(
      request_type=DEEPLOY_REQUEST_TYPES.CREATE_PIPELINE,
      payload=payload,
      payload_hash=payload_hash,
    )
    signature = Account.sign_message(
      encode_defunct(primitive=message.encode("utf-8")),
      private_key=private_key,
    ).signature.hex()
    if not signature.startswith("0x"):
      signature = "0x" + signature

    signed_payload = {
      **payload,
      "EE_HASH": payload_hash,
      "EE_ETH_SIGN": signature,
      "EE_ETH_SENDER": sender,
    }

    recovered = self.plugin._DeeployMixin__verify_signature_v3(
      signed_payload,
      request_type=DEEPLOY_REQUEST_TYPES.CREATE_PIPELINE,
    )

    self.assertEqual(recovered.lower(), sender.lower())
    self.assertEqual(self.plugin.bc.verify_calls[0]["expected_signer"].lower(), sender.lower())
    self.assertTrue(self.plugin.bc.verify_calls[0]["no_hash"])

  def test_v3_signature_verification_rejects_tampered_payload(self):
    payload = {
      "job_id": 42,
      "app_id": "api_1234567",
      "target_nodes": ["0xai_new_node"],
      "target_nodes_count": 0,
      "nonce": "0xdef",
      "EE_HASH": "0" * 64,
      "EE_ETH_SIGN": "0x" + "11" * 65,
      "EE_ETH_SENDER": "0x" + "22" * 20,
    }

    with self.assertRaisesRegex(ValueError, "Invalid Deeploy v3 request hash"):
      self.plugin._DeeployMixin__verify_signature_v3(
        payload,
        request_type=DEEPLOY_REQUEST_TYPES.SCALE_UP_JOB_WORKERS,
      )


if __name__ == "__main__":
  unittest.main()
