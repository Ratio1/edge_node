import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class _FakeBasePlugin:
  CONFIG = {
    "VALIDATION_RULES": {},
    "AI_ENGINE": "llama_cpp_small",
  }
  STATUS_PENDING = "pending"

  @staticmethod
  def endpoint(method="get", require_token=False, streaming_type=None, chunk_size=1024 * 1024):  # pylint: disable=unused-argument
    def decorator(func):
      return func
    return decorator

  @staticmethod
  def balanced_endpoint(func):
    return func

  def Pd(self, *args, **kwargs):  # pylint: disable=unused-argument
    return None

  def P(self, *args, **kwargs):  # pylint: disable=unused-argument
    return None

  @staticmethod
  def shorten_str(value):
    return str(value)


class _FakeLlmCT:
  REQUEST_ID = "REQUEST_ID"
  REQUEST_TYPE = "REQUEST_TYPE"
  MESSAGES = "MESSAGES"
  TEMPERATURE = "TEMPERATURE"
  TOP_P = "TOP_P"
  MAX_TOKENS = "MAX_TOKENS"
  RESPONSE_FORMAT = "RESPONSE_FORMAT"
  ADDITIONAL = "ADDITIONAL"
  TEXT = "text"
  FULL_OUTPUT = "FULL_OUTPUT"


def _load_plugin_class():
  source_path = ROOT / "extensions" / "business" / "edge_inference_api" / "llm_inference_api.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.business.edge_inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin\n",
    "",
  )
  source = source.replace(
    "from extensions.serving.mixins_llm.llm_utils import LlmCT\n",
    "",
  )
  namespace = {
    "BasePlugin": _FakeBasePlugin,
    "LlmCT": _FakeLlmCT,
    "__name__": "loaded_llm_inference_api",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["LLMInferenceApiPlugin"]


LLMInferenceApiPlugin = _load_plugin_class()


class LLMInferenceApiPluginTests(unittest.TestCase):
  def test_payload_uses_llm_serving_uppercase_contract(self):
    plugin = LLMInferenceApiPlugin()

    payload = plugin.compute_payload_kwargs_from_predict_params(
      request_id="req-1",
      request_data={
        "parameters": {
          "messages": [{"role": "user", "content": "hello"}],
          "temperature": 0.1,
          "max_tokens": 64,
          "top_p": 0.9,
          "repeat_penalty": 1.1,
          "response_format": {"type": "json_object"},
          "seed": 123,
          "frequency_penalty": 0.2,
        }
      },
    )

    self.assertIn("JEEVES_CONTENT", payload)
    self.assertEqual(payload["JEEVES_CONTENT"]["REQUEST_ID"], "req-1")
    self.assertEqual(payload["JEEVES_CONTENT"]["REQUEST_TYPE"], "LLM")
    self.assertEqual(payload["JEEVES_CONTENT"]["MESSAGES"][0]["content"], "hello")
    self.assertEqual(payload["JEEVES_CONTENT"]["MAX_TOKENS"], 64)
    self.assertEqual(payload["JEEVES_CONTENT"]["RESPONSE_FORMAT"], {"type": "json_object"})
    self.assertEqual(payload["JEEVES_CONTENT"]["REPETITION_PENALTY"], 1.1)
    self.assertEqual(payload["JEEVES_CONTENT"]["SEED"], 123)
    self.assertEqual(payload["JEEVES_CONTENT"]["FREQUENCY_PENALTY"], 0.2)
    self.assertNotIn("REPEAT_PENALTY", payload["JEEVES_CONTENT"])

  def test_filter_valid_inference_accepts_lowercase_request_id(self):
    plugin = LLMInferenceApiPlugin()
    plugin._requests = {"req-2": {"status": "pending"}}  # pylint: disable=protected-access
    inference = {
      "request_id": "req-2",
      "text": "{}",
      "IS_VALID": True,
    }

    self.assertTrue(plugin.filter_valid_inference(inference))
    self.assertEqual(inference["REQUEST_ID"], "req-2")

  def test_filter_valid_inference_accepts_nested_additional_request_id(self):
    plugin = LLMInferenceApiPlugin()
    plugin._requests = {"req-3": {"status": "pending"}}  # pylint: disable=protected-access
    inference = {
      "ADDITIONAL": {"REQUEST_ID": "req-3"},
      "text": "{}",
      "IS_VALID": True,
    }

    self.assertTrue(plugin.filter_valid_inference(inference))
    self.assertEqual(inference["REQUEST_ID"], "req-3")

  def test_filter_valid_inference_maps_missing_id_to_single_pending_request(self):
    plugin = LLMInferenceApiPlugin()
    plugin._requests = {"req-4": {"status": "pending"}}  # pylint: disable=protected-access
    inference = {
      "text": "{}",
      "IS_VALID": True,
    }

    self.assertTrue(plugin.filter_valid_inference(inference))
    self.assertEqual(inference["REQUEST_ID"], "req-4")

  def test_filter_valid_inference_rejects_missing_id_when_ambiguous(self):
    plugin = LLMInferenceApiPlugin()
    plugin._requests = {  # pylint: disable=protected-access
      "req-5": {"status": "pending"},
      "req-6": {"status": "pending"},
    }
    inference = {
      "text": "{}",
      "IS_VALID": True,
    }

    self.assertFalse(plugin.filter_valid_inference(inference))
    self.assertNotIn("REQUEST_ID", inference)

  def test_filter_valid_inference_maps_unknown_id_to_single_pending_request(self):
    plugin = LLMInferenceApiPlugin()
    plugin._requests = {"req-7": {"status": "pending"}}  # pylint: disable=protected-access
    inference = {
      "REQUEST_ID": "stale-or-backend-id",
      "text": "{}",
      "IS_VALID": True,
    }

    self.assertTrue(plugin.filter_valid_inference(inference))
    self.assertEqual(inference["REQUEST_ID"], "req-7")

  def test_filter_valid_inference_accepts_invalid_text_with_single_pending_request(self):
    plugin = LLMInferenceApiPlugin()
    plugin._requests = {"req-8": {"status": "pending"}}  # pylint: disable=protected-access
    inference = {
      "text": "{\"ok\": true}",
      "IS_VALID": False,
    }

    self.assertTrue(plugin.filter_valid_inference(inference))
    self.assertEqual(inference["REQUEST_ID"], "req-8")


if __name__ == "__main__":
  unittest.main()
