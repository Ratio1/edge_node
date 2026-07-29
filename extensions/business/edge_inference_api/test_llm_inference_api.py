import inspect
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

  def health(self):
    return {"status": "ok"}

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
  SEED = "SEED"


def _load_plugin_module():
  source_path = ROOT / "extensions" / "business" / "edge_inference_api" / "llm_inference_api.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.business.edge_inference_api import base_inference_api as base_inference_api_module\n",
    "",
  )
  source = source.replace(
    "from extensions.business.edge_inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin\n",
    "",
  )
  source = source.replace(
    "from extensions.serving.mixins_llm import llm_utils as llm_utils_module\n",
    "",
  )
  source = source.replace(
    "from extensions.serving.mixins_llm.llm_utils import LlmCT\n",
    "",
  )
  namespace = {
    "BasePlugin": _FakeBasePlugin,
    "LlmCT": _FakeLlmCT,
    "base_inference_api_module": type("BaseInferenceApiModule", (), {
      "__file__": str(ROOT / "extensions/business/edge_inference_api/base_inference_api.py"),
    }),
    "llm_utils_module": type("LlmUtilsModule", (), {
      "__file__": str(ROOT / "extensions/serving/mixins_llm/llm_utils.py"),
    }),
    "__file__": str(source_path),
    "__name__": "loaded_llm_inference_api",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace


LOADED_PLUGIN_MODULE = _load_plugin_module()
LLMInferenceApiPlugin = LOADED_PLUGIN_MODULE["LLMInferenceApiPlugin"]


class LLMInferenceApiPluginTests(unittest.TestCase):
  def test_health_reports_actual_serving_manager_readiness(self):
    plugin = LLMInferenceApiPlugin()
    plugin.get_serving_processes = lambda: ["expected-server"]
    plugin.global_shmem = {"serving_manager": type("Manager", (), {"is_avail": lambda _self, name: name == "expected-server"})()}
    self.assertIs(plugin.health()["serving_ready"], True)
    self.assertIs(plugin.health()["benchmark_mode_enabled"], False)
    self.assertIsNone(plugin.health()["runtime_fingerprint"])
    self.assertIsNone(plugin.health()["worker_code_identity"])
    plugin.cfg_benchmark_mode_enabled = True
    self.assertIs(plugin.health()["benchmark_mode_enabled"], True)
    plugin.global_shmem = {}
    self.assertIs(plugin.health()["serving_ready"], False)

  def test_health_keeps_null_identity_keys_for_inprocess_generic_worker(self):
    server = type("GenericServer", (), {"inprocess": True})()
    manager = type("Manager", (), {
      "is_avail": lambda _self, _name: True,
      "_get_server": lambda _self, _name: server,
    })()
    plugin = LLMInferenceApiPlugin()
    plugin.get_serving_processes = lambda: ["generic-llama-server"]
    plugin.global_shmem = {"serving_manager": manager}

    health = plugin.health()

    self.assertIs(health["serving_ready"], True)
    self.assertIsNone(health["runtime_fingerprint"])
    self.assertIsNone(health["worker_code_identity"])

  def test_benchmark_mode_is_an_explicit_default_off_endpoint_parameter(self):
    for method_name in ("predict", "predict_async", "create_chat_completion", "create_chat_completion_async"):
      parameter = inspect.signature(getattr(LLMInferenceApiPlugin, method_name)).parameters["benchmark_mode"]
      self.assertIs(parameter.default, False)

  def test_benchmark_mode_reaches_uppercase_worker_payload(self):
    plugin = LLMInferenceApiPlugin()
    plugin.cfg_benchmark_mode_enabled = True
    parameters = plugin.process_predict_params(
      messages=[{"role": "user", "content": "x"}], temperature=0.0, max_tokens=1,
      benchmark_mode=True,
    )
    payload = plugin.compute_payload_kwargs_from_predict_params(
      "req-benchmark", {"parameters": parameters},
    )
    self.assertIs(payload["JEEVES_CONTENT"]["BENCHMARK_MODE"], True)

  def test_benchmark_mode_requires_instance_enablement(self):
    plugin = LLMInferenceApiPlugin()
    plugin.check_generation_params = lambda **_kwargs: None
    plugin.cfg_benchmark_mode_enabled = False
    error = plugin.check_predict_params(
      messages=[{"role": "user", "content": "x"}], temperature=0.0, max_tokens=1,
      benchmark_mode=True,
    )
    self.assertEqual(error, "`benchmark_mode` is disabled on this instance.")
    parameters = plugin.process_predict_params(
      messages=[{"role": "user", "content": "x"}], temperature=0.0, max_tokens=1,
      benchmark_mode=True,
    )
    self.assertIs(parameters["benchmark_mode"], False)

    plugin.cfg_benchmark_mode_enabled = True
    self.assertIsNone(plugin.check_predict_params(
      messages=[{"role": "user", "content": "x"}], temperature=0.0, max_tokens=1,
      benchmark_mode=True, seed=42,
    ))

  def test_benchmark_mode_requires_integer_seed(self):
    plugin = LLMInferenceApiPlugin()
    plugin.check_generation_params = lambda **_kwargs: None
    plugin.cfg_benchmark_mode_enabled = True
    self.assertEqual(
      plugin.check_predict_params(
        messages=[{"role": "user", "content": "x"}],
        temperature=0.1,
        max_tokens=512,
        benchmark_mode=True,
        seed=None,
      ),
      "`seed` must be an integer in benchmark mode.",
    )
    self.assertIsNone(plugin.check_predict_params(
      messages=[{"role": "user", "content": "x"}],
      temperature=0.1,
      max_tokens=512,
      benchmark_mode=True,
      seed=42,
    ))

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

  def test_generic_serving_envelope_keeps_existing_completion_response_shape(self):
    plugin = LLMInferenceApiPlugin()
    plugin.time = lambda: 1234.5
    plugin._annotate_result_with_node_roles = lambda **_kwargs: None
    inference = {
      "REQUEST_ID": "req-generic",
      "text": "MATCH (n) RETURN n LIMIT 1",
      "FULL_OUTPUT": {
        "choices": [{
          "message": {"content": "MATCH (n) RETURN n LIMIT 1"},
          "finish_reason": "stop",
        }],
        "usage": {"completion_tokens": 9},
      },
      "IS_VALID": True,
    }

    response = plugin.build_completion_response(
      request_id="req-generic",
      model_name="edgeguard-base-qwen3-4b",
      inference=inference,
      request_data={"metadata": {"route": "base"}},
    )

    self.assertEqual(response["REQUEST_ID"], "req-generic")
    self.assertEqual(response["MODEL_NAME"], "edgeguard-base-qwen3-4b")
    self.assertEqual(response["TEXT_RESPONSE"], "MATCH (n) RETURN n LIMIT 1")
    self.assertEqual(response["object"], "chat.completion")
    self.assertEqual(response["id"], "req-generic")
    self.assertEqual(response["model"], "edgeguard-base-qwen3-4b")
    self.assertEqual(response["metadata"], {"route": "base"})
    self.assertEqual(response["choices"], inference["FULL_OUTPUT"]["choices"])
    self.assertEqual(response["usage"], {"completion_tokens": 9})

  def test_filter_valid_inference_fails_single_pending_on_invalid_empty_output(self):
    plugin = LLMInferenceApiPlugin()
    plugin._requests = {"req-9": {"status": "pending"}}  # pylint: disable=protected-access
    failed = {}
    plugin._fail_request = lambda request_id, error_message: failed.update({  # pylint: disable=protected-access
      "request_id": request_id,
      "error_message": error_message,
    }) or True
    inference = {
      "REQUEST_ID": "req-9",
      "text": "",
      "IS_VALID": False,
    }

    self.assertFalse(plugin.filter_valid_inference(inference))
    self.assertEqual(failed["request_id"], "req-9")
    self.assertEqual(failed["error_message"], "Local LLM returned an invalid empty response.")

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

if __name__ == "__main__":
  unittest.main()
