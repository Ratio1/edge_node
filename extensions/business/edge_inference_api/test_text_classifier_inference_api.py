import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]


class _FakeBasePlugin:
  CONFIG = {"VALIDATION_RULES": {}}

  def __init__(self, **kwargs):
    self.cfg_min_text_length = kwargs.get("MIN_TEXT_LENGTH", 1)
    self.cfg_ai_engine = kwargs.get("AI_ENGINE", "text_classifier")
    self.cfg_startup_ai_engine_params = kwargs.get("STARTUP_AI_ENGINE_PARAMS", {})
    self.log = SimpleNamespace()
    self._requests = {}
    self.debug_logs = []

  @staticmethod
  def endpoint(method="get", require_token=False, streaming_type=None, chunk_size=1024 * 1024):  # pylint: disable=unused-argument
    def decorator(func):
      return func
    return decorator

  @staticmethod
  def balanced_endpoint(func):
    func.__balanced_endpoint__ = True
    return func

  def _get_payload_field(self, data, key, default=None):
    if not isinstance(data, dict):
      return default
    if key in data:
      return data[key]
    key_upper = key.upper()
    if key_upper in data:
      return data[key_upper]
    return default

  def _iter_struct_payloads(self, data):
    if isinstance(data, list):
      return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
      return [item for item in data.values() if isinstance(item, dict)]
    return []

  def _extract_request_id_from_payload(self, payload, key_candidates=None):
    keys = key_candidates or ["request_id", "REQUEST_ID"]
    for key in keys:
      value = self._get_payload_field(payload, key)
      if value is not None:
        return value
    return None

  def _build_owned_payloads_by_request_id(self, data, key_candidates=None):
    owned_payloads = {}
    for payload in self._iter_struct_payloads(data):
      request_id = self._extract_request_id_from_payload(payload, key_candidates)
      if request_id is None or request_id not in self._requests:
        continue
      owned_payloads.setdefault(request_id, payload)
    return owned_payloads

  def Pd(self, message):
    self.debug_logs.append(message)


def _load_plugin_class():
  source_path = ROOT / "extensions" / "business" / "edge_inference_api" / "text_classifier_inference_api.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.business.edge_inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin\n",
    "",
  )
  namespace = {
    "BasePlugin": _FakeBasePlugin,
    "__name__": "loaded_text_classifier_inference_api",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["TextClassifierInferenceApiPlugin"]


TextClassifierInferenceApiPlugin = _load_plugin_class()


class TextClassifierInferenceApiPluginTests(unittest.TestCase):
  def test_compute_payload_kwargs_wraps_text_in_struct_payload(self):
    plugin = TextClassifierInferenceApiPlugin(
      AI_ENGINE="text_classifier",
      STARTUP_AI_ENGINE_PARAMS={
        "MODEL_INSTANCE_ID": "privacy-filter",
        "MODEL_NAME": "openai/privacy-filter",
      },
    )

    payload_kwargs = plugin.compute_payload_kwargs_from_predict_params(
      request_id="rf_1234",
      request_data={
        "parameters": {
          "text": "Email body to classify",
          "metadata": {"source": "local"},
          "request_type": "classification",
        },
        "created_at": 123.0,
        "metadata": {},
      },
    )

    self.assertEqual(payload_kwargs["request_id"], "rf_1234")
    self.assertEqual(
      payload_kwargs["STRUCT_DATA"],
      {
        "text": "Email body to classify",
        "request_id": "rf_1234",
        "metadata": {"source": "local"},
        "__SERVING_TARGET__": {
          "INFERENCE_REQUEST": True,
          "AI_ENGINE": "text_classifier",
          "MODEL_INSTANCE_ID": "privacy-filter",
          "MODEL_NAME": "openai/privacy-filter",
        },
      },
    )
    self.assertEqual(payload_kwargs["metadata"], {"source": "local"})
    self.assertEqual(payload_kwargs["type"], "classification")
    self.assertEqual(payload_kwargs["submitted_at"], 123.0)

  def test_build_result_from_inference_preserves_classifier_output(self):
    plugin = TextClassifierInferenceApiPlugin()

    result_payload = plugin._build_result_from_inference(  # pylint: disable=protected-access
      request_id="654129af5c33",
      inference={
        "REQUEST_ID": "654129af5c33",
        "TEXT": "example text",
        "result": [{"label": "safe", "score": 0.97}],
        "MODEL_NAME": "openai/privacy-filter",
        "PIPELINE_TASK": "token-classification",
      },
      metadata={},
      request_data={"metadata": {}, "parameters": {"text": "example text"}},
    )

    self.assertEqual(result_payload["status"], "completed")
    self.assertEqual(result_payload["request_id"], "654129af5c33")
    self.assertEqual(result_payload["text"], "example text")
    self.assertEqual(
      result_payload["classification"],
      [{"label": "safe", "score": 0.97}],
    )
    self.assertEqual(result_payload["model_name"], "openai/privacy-filter")
    self.assertEqual(result_payload["pipeline_task"], "token-classification")

  def test_build_result_from_inference_preserves_runtime_model_metadata(self):
    plugin = TextClassifierInferenceApiPlugin()

    result_payload = plugin._build_result_from_inference(  # pylint: disable=protected-access
      request_id="req-onnx",
      inference={
        "REQUEST_ID": "req-onnx",
        "TEXT": "example text",
        "result": {"prediction": "safe"},
        "MODEL": {"key": "generic_text_classifier", "version": "2026.05.09"},
        "MODEL_VERSION": "2026.05.09",
        "HF_RUNTIME": "onnx_fp32",
        "RUNTIME": "onnxruntime",
      },
      metadata={},
      request_data={"metadata": {}, "parameters": {"text": "example text"}},
    )

    self.assertEqual(result_payload["classification"], {"prediction": "safe"})
    self.assertEqual(
      result_payload["model"],
      {"key": "generic_text_classifier", "version": "2026.05.09"},
    )
    self.assertEqual(result_payload["model_version"], "2026.05.09")
    self.assertEqual(result_payload["hf_runtime"], "onnx_fp32")
    self.assertEqual(result_payload["runtime"], "onnxruntime")

  def test_handle_inferences_falls_back_to_payload_request_id(self):
    plugin = TextClassifierInferenceApiPlugin()
    plugin._requests = {"req-1": {"status": "pending"}}  # pylint: disable=protected-access
    handled = []

    def handle_inference_for_request(request_id, inference, metadata):
      handled.append((request_id, inference, metadata))

    plugin.handle_inference_for_request = handle_inference_for_request

    plugin.handle_inferences(
      inferences=[{"result": [{"label": "safe", "score": 0.97}]}],
      data=[{"request_id": "req-1", "metadata": {"source": "test"}}],
    )

    self.assertEqual(
      handled,
      [
        (
          "req-1",
          {"result": [{"label": "safe", "score": 0.97}]},
          {"source": "test"},
        )
      ],
    )
    self.assertEqual(plugin.debug_logs, [])

  def test_handle_inferences_prefers_inference_request_id_over_payload_fallback(self):
    plugin = TextClassifierInferenceApiPlugin()
    plugin._requests = {  # pylint: disable=protected-access
      "payload-req": {"status": "pending"},
      "inference-req": {"status": "pending"},
    }
    handled = []

    def handle_inference_for_request(request_id, inference, metadata):
      handled.append((request_id, metadata))

    plugin.handle_inference_for_request = handle_inference_for_request

    plugin.handle_inferences(
      inferences=[{"REQUEST_ID": "inference-req", "result": "ok"}],
      data=[{"request_id": "payload-req", "metadata": {"source": "payload"}}],
    )

    self.assertEqual(handled, [("inference-req", {})])

  def test_handle_inferences_skips_payloads_without_request_id(self):
    plugin = TextClassifierInferenceApiPlugin()
    handled = []
    plugin.handle_inference_for_request = lambda **kwargs: handled.append(kwargs)

    plugin.handle_inferences(
      inferences=[{"result": [{"label": "warmup"}]}],
      data=[{"metadata": {"source": "startup"}}],
    )

    self.assertEqual(handled, [])
    self.assertEqual(
      plugin.debug_logs,
      ["No request_id found in inference at index 0, skipping."],
    )


if __name__ == "__main__":
  unittest.main()
