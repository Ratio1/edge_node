import unittest

from extensions.business.deeploy.deeploy_const import DEEPLOY_KEYS
from extensions.business.deeploy.tests.support import InputsStub, make_deeploy_plugin
from naeural_core.constants import BASE_CT


class _BCStub:
  """
  Minimal blockchain adapter for Deeploy v3 verifier tests.
  """
  def __init__(self, expected_text=None, signer="0x1234567890123456789012345678901234567890"):
    self.expected_text = expected_text
    self.signer = signer
    self.verified_texts = []

  def is_valid_eth_address(self, address):
    """
    Accept any non-empty 0x address for focused verifier tests.
    """
    return isinstance(address, str) and address.startswith("0x")

  def get_user_escrow_details(self, sender):
    """
    Return an active escrow so request validation can complete.
    """
    return {
      "isActive": True,
      "escrowAddress": "0xEscrow",
      "escrowOwner": "0xOwner",
    }

  def eth_verify_text_signature(
    self,
    text,
    signature,
    no_hash=False,
    message_prefix="",
    raise_if_error=False,
    expected_signer=None,
  ):
    """
    Capture the exact text passed to signature verification.
    """
    self.verified_texts.append({
      "text": text,
      "signature": signature,
      "no_hash": no_hash,
      "message_prefix": message_prefix,
      "expected_signer": expected_signer,
    })
    if self.expected_text is not None and text != self.expected_text:
      return None
    return expected_signer or self.signer


class DeeployV3WrapperSignatureTests(unittest.TestCase):

  def test_payload_hash_and_wrapper_match_dapp_create_fixture(self):
    plugin = make_deeploy_plugin()
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

    payload_hash = plugin._deeploy_payload_hash(payload)
    self.assertEqual(payload_hash, "12169fe2f1a33373ba651d14318eb18d3239c0148a0d601de9f4ce3be9d2dded")
    self.assertEqual(
      plugin._deeploy_wrapper_message(
        request_type="create pipeline",
        payload=payload,
        hash_value=payload_hash,
      ),
      "Please sign this Deeploy request:\n"
      "\n"
      "Request type: create pipeline\n"
      "Plugins: 2\n"
      "Nodes: 2\n"
      "Request hash: 12169fe2f1a33373ba651d14318eb18d3239c0148a0d601de9f4ce3be9d2dded",
    )

  def test_payload_hash_and_wrapper_match_dapp_scale_up_fixture(self):
    plugin = make_deeploy_plugin()
    payload = {
      "job_id": 42,
      "app_id": "api_1234567",
      "target_nodes": ["0xai_new_node"],
      "target_nodes_count": 0,
      "nonce": "0xdef",
    }

    payload_hash = plugin._deeploy_payload_hash(payload)
    self.assertEqual(payload_hash, "1911187f82db8b14c607ffa1d15660deab623f184b07f622d55920615e2b9dcb")
    self.assertEqual(
      plugin._deeploy_wrapper_message(
        request_type="scale up workers",
        payload=payload,
        hash_value=payload_hash,
      ),
      "Please sign this Deeploy request:\n"
      "\n"
      "Request type: scale up workers\n"
      "Nodes: 1\n"
      "Request hash: 1911187f82db8b14c607ffa1d15660deab623f184b07f622d55920615e2b9dcb",
    )

  def test_verify_and_get_inputs_uses_v3_wrapper_when_hash_is_present(self):
    plugin = make_deeploy_plugin()
    payload = {
      "nonce": "0xabc",
      "target_nodes": ["0xai_node_a"],
      "target_nodes_count": 0,
      "plugins": [{"plugin_signature": "WORKER_APP_RUNNER"}],
      BASE_CT.BCctbase.ETH_SENDER: "0x1234567890123456789012345678901234567890",
      BASE_CT.BCctbase.ETH_SIGN: "0xsignature",
    }
    payload[BASE_CT.BCctbase.HASH] = plugin._deeploy_payload_hash(payload)
    expected_message = plugin._deeploy_wrapper_message(
      request_type="create pipeline",
      payload=payload,
      hash_value=payload[BASE_CT.BCctbase.HASH],
    )
    plugin.NestedDotDict = InputsStub
    plugin.bc = _BCStub(expected_text=expected_message)

    sender, inputs = plugin.deeploy_verify_and_get_inputs(payload, request_type="create pipeline")

    self.assertEqual(sender, "0x1234567890123456789012345678901234567890")
    self.assertEqual(inputs[DEEPLOY_KEYS.PLUGINS], [{"plugin_signature": "WORKER_APP_RUNNER"}])
    self.assertEqual(plugin.bc.verified_texts, [{
      "text": expected_message,
      "signature": "0xsignature",
      "no_hash": True,
      "message_prefix": "",
      "expected_signer": "0x1234567890123456789012345678901234567890",
    }])

  def test_v3_verification_rejects_tampered_payload_hash(self):
    plugin = make_deeploy_plugin()
    payload = {
      "nonce": "0xabc",
      "app_alias": "original",
      "target_nodes_count": 1,
      BASE_CT.BCctbase.ETH_SENDER: "0x1234567890123456789012345678901234567890",
      BASE_CT.BCctbase.ETH_SIGN: "0xsignature",
    }
    payload[BASE_CT.BCctbase.HASH] = plugin._deeploy_payload_hash(payload)
    payload["app_alias"] = "tampered"
    plugin.NestedDotDict = InputsStub
    plugin.bc = _BCStub()

    with self.assertRaisesRegex(ValueError, "Invalid payload hash"):
      plugin.deeploy_verify_and_get_inputs(payload, request_type="create pipeline")


if __name__ == "__main__":
  unittest.main()
