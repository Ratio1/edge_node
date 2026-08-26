import unittest
from inspect import signature
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class _FakeBasePlugin:
  CONFIG = {
    "VALIDATION_RULES": {},
    "AI_ENGINE": "llama_cpp_small",
  }
  STATUS_PENDING = "pending"
  STATUS_COMPLETED = "completed"

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

  def predict(self, authorization=None, **kwargs):
    return {"authorization": authorization, **kwargs}

  def predict_async(self, authorization=None, request_id=None, **kwargs):
    return {"authorization": authorization, "request_id": request_id, **kwargs}

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
  @staticmethod
  def _make_plugin(**overrides):
    plugin = LLMInferenceApiPlugin()
    plugin.cfg_ai_engine = overrides.get("AI_ENGINE", "llama_cpp_small")
    plugin.cfg_served_models = overrides.get("SERVED_MODELS", [])
    plugin.cfg_startup_ai_engine_params = overrides.get("STARTUP_AI_ENGINE_PARAMS", {})
    return plugin

  def test_model_capability_uses_explicit_aliases_and_effective_ai_config(self):
    plugin = self._make_plugin(
      AI_ENGINE="llama_cpp_medium",
      SERVED_MODELS=["friendly-model-b"],
      STARTUP_AI_ENGINE_PARAMS={"MODEL_NAME": "org/model-b"},
    )

    capabilities = plugin._get_balancing_capabilities()  # pylint: disable=protected-access

    self.assertEqual(
      capabilities["models"],
      ["friendly-model-b", "llama_cpp_medium", "org/model-b"],
    )

  def test_model_matching_requires_requested_model_locally_and_remotely(self):
    plugin = self._make_plugin(SERVED_MODELS=["model-a"])
    request_data = {"parameters": {"model": "model-b"}}

    self.assertFalse(plugin._can_execute_request(request_data))  # pylint: disable=protected-access
    self.assertFalse(  # pylint: disable=protected-access
      plugin._capacity_record_can_execute_request(
        {"capabilities": {"models": ["model-a"]}},
        request_data,
      )
    )
    self.assertTrue(  # pylint: disable=protected-access
      plugin._capacity_record_can_execute_request(
        {"capabilities": {"models": ["model-b"]}},
        request_data,
      )
    )

  def test_unspecified_model_preserves_local_first_compatibility(self):
    plugin = self._make_plugin(SERVED_MODELS=["model-a"])

    self.assertTrue(plugin._can_execute_request({"parameters": {}}))  # pylint: disable=protected-access
    self.assertTrue(  # pylint: disable=protected-access
      plugin._capacity_record_can_execute_request({}, {"parameters": {}})
    )

  def test_legacy_positional_endpoint_calls_preserve_parameter_order(self):
    plugin = self._make_plugin()
    messages = [{"role": "user", "content": "hello"}]

    for endpoint_name in (
      "predict",
      "predict_async",
      "create_chat_completion",
      "create_chat_completion_async",
    ):
      with self.subTest(endpoint=endpoint_name):
        result = getattr(plugin, endpoint_name)(messages, 0.2, 128)
        self.assertEqual(result["messages"], messages)
        self.assertEqual(result["temperature"], 0.2)
        self.assertEqual(result["max_tokens"], 128)
        self.assertIsNone(result["model"])

    keyword_model = plugin.predict(messages, 0.2, 128, model="model-b")
    self.assertEqual(keyword_model["model"], "model-b")

    self.assertEqual(
      list(signature(plugin.check_predict_params).parameters)[:3],
      ["messages", "temperature", "max_tokens"],
    )
    processed = plugin.process_predict_params(messages, 0.2, 128)
    self.assertEqual(processed["temperature"], 0.2)
    self.assertEqual(processed["max_tokens"], 128)
    self.assertNotIn("model", processed)

  def test_payload_uses_llm_serving_uppercase_contract(self):
    plugin = self._make_plugin()

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
          "model": "llama_cpp_small",
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
    self.assertNotIn("MODEL", payload["JEEVES_CONTENT"])
    self.assertNotIn("REPEAT_PENALTY", payload["JEEVES_CONTENT"])
    self.assertEqual(payload["JEEVES_CONTENT"]["TARGET_MODEL_KEY"], "llama_cpp_small")

  def test_compute_payload_kwargs_without_model_has_no_target_key(self):
    plugin = LLMInferenceApiPlugin()
    payload = plugin.compute_payload_kwargs_from_predict_params(
      request_id="req-nm",
      request_data={
        "parameters": {
          "messages": [{"role": "user", "content": "hello"}],
          "max_tokens": 16,
        }
      },
    )
    self.assertNotIn("TARGET_MODEL_KEY", payload["JEEVES_CONTENT"])

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

  def test_filter_valid_inference_fails_single_pending_on_invalid_empty_output(self):
    plugin = LLMInferenceApiPlugin()
    plugin._requests = {"req-9": {"status": "pending"}}  # pylint: disable=protected-access
    failed = {}
    logged = []
    plugin.P = lambda *args, **kwargs: logged.append((args, kwargs))
    plugin._fail_request = lambda request_id, error_message: failed.update({  # pylint: disable=protected-access
      "request_id": request_id,
      "error_message": error_message,
    }) or True
    inference = {
      "REQUEST_ID": "req-9",
      "text": "",
      "raw_model_output": "SENTINEL_MODEL_CONTENT_MUST_NOT_BE_LOGGED",
      "IS_VALID": False,
    }

    self.assertFalse(plugin.filter_valid_inference(inference))
    self.assertEqual(failed["request_id"], "req-9")
    self.assertEqual(failed["error_message"], "Local LLM returned an invalid empty response.")
    self.assertIn("Rejected invalid LLM inference without text output.", repr(logged))
    self.assertNotIn("SENTINEL_MODEL_CONTENT_MUST_NOT_BE_LOGGED", repr(logged))

  def test_filter_valid_inference_ignores_request_id_less_empty_placeholder(self):
    plugin = LLMInferenceApiPlugin()
    plugin._requests = {"req-live": {"status": "pending"}}  # pylint: disable=protected-access
    plugin._fail_request = lambda *_args, **_kwargs: self.fail("placeholder must not fail pending request")
    inference = {
      "text": "",
      "IS_VALID": False,
    }

    self.assertFalse(plugin.filter_valid_inference(inference))
    self.assertEqual(plugin._requests["req-live"]["status"], "pending")  # pylint: disable=protected-access

  def test_filter_valid_inference_ignores_all_empty_full_output_placeholders(self):
    for placeholder in ({}, [], "", "irrelevant-placeholder"):
      with self.subTest(placeholder=placeholder):
        plugin = LLMInferenceApiPlugin()
        plugin._requests = {"req-live": {"status": "pending"}}  # pylint: disable=protected-access
        plugin._fail_request = lambda *_args, **_kwargs: self.fail("placeholder must not fail pending request")
        inference = {
          "text": "",
          "FULL_OUTPUT": placeholder,
          "IS_VALID": False,
        }

        self.assertFalse(plugin.filter_valid_inference(inference))
        self.assertEqual(plugin._requests["req-live"]["status"], "pending")  # pylint: disable=protected-access

  def test_filter_valid_inference_ignores_whitespace_only_content(self):
    for inference in (
      {"text": "   ", "IS_VALID": False},
      {
        "text": "",
        "FULL_OUTPUT": {"choices": [{"message": {"content": "\n\t"}}]},
        "IS_VALID": False,
      },
    ):
      with self.subTest(inference=inference):
        plugin = LLMInferenceApiPlugin()
        plugin._requests = {"req-live": {"status": "pending"}}  # pylint: disable=protected-access
        plugin._fail_request = lambda *_args, **_kwargs: self.fail("placeholder must not fail pending request")

        self.assertFalse(plugin.filter_valid_inference(inference))
        self.assertEqual(plugin._requests["req-live"]["status"], "pending")  # pylint: disable=protected-access

  def test_handle_inference_preserves_requested_model_when_backend_omits_model_name(self):
    plugin = self._make_plugin()
    plugin._requests = {  # pylint: disable=protected-access
      "req-9": {
        "status": plugin.STATUS_PENDING,
        "parameters": {"model": "public-model-alias"},
        "metadata": {},
      },
    }
    plugin._metrics = {"requests_completed": 0}  # pylint: disable=protected-access
    plugin.time = lambda: 10.0
    plugin._decrement_active_requests = lambda: None  # pylint: disable=protected-access
    plugin._annotate_result_with_node_roles = lambda result_payload, request_data: result_payload  # pylint: disable=protected-access

    plugin.handle_single_inference(
      {
        "REQUEST_ID": "req-9",
        "text": "done",
        "FULL_OUTPUT": None,
      },
      model_name=None,
    )

    self.assertEqual(plugin._requests["req-9"]["result"]["MODEL_NAME"], "public-model-alias")


if __name__ == "__main__":
  unittest.main()
