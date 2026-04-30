import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[3]


class _FakeBasePlugin:
  CONFIG = {"VALIDATION_RULES": {}}

  def __init__(self, **kwargs):
    self.cfg_min_struct_data_fields = kwargs.get("MIN_STRUCT_DATA_FIELDS", 1)
    self.log = SimpleNamespace()

  @staticmethod
  def endpoint(method="get", require_token=False, streaming_type=None, chunk_size=1024 * 1024):  # pylint: disable=unused-argument
    def decorator(func):
      return func
    return decorator

  @staticmethod
  def balanced_endpoint(func):
    func.__balanced_endpoint__ = True
    return func


def _load_plugin_class():
  source_path = ROOT / "extensions" / "business" / "edge_inference_api" / "sd_inference_api.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.business.edge_inference_api.base_inference_api import BaseInferenceApiPlugin as BasePlugin\n",
    "",
  )
  namespace = {
    "BasePlugin": _FakeBasePlugin,
    "__name__": "loaded_sd_inference_api",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["SdInferenceApiPlugin"]


SdInferenceApiPlugin = _load_plugin_class()


class SdInferenceApiPluginTests(unittest.TestCase):
  def test_compute_payload_kwargs_preserves_structured_sample(self):
    plugin = SdInferenceApiPlugin()

    payload_kwargs = plugin.compute_payload_kwargs_from_predict_params(
      request_id="rf_1234",
      request_data={
        "parameters": {
          "struct_data": {
            "SepalLengthCm": 5.1,
            "SepalWidthCm": 3.5,
            "PetalLengthCm": 1.4,
            "PetalWidthCm": 0.2,
          },
          "metadata": {"source": "local"},
          "request_type": "prediction",
        },
        "created_at": 123.0,
        "metadata": {},
      },
    )

    self.assertEqual(payload_kwargs["request_id"], "rf_1234")
    self.assertEqual(
      payload_kwargs["STRUCT_DATA"],
      {
        "SepalLengthCm": 5.1,
        "SepalWidthCm": 3.5,
        "PetalLengthCm": 1.4,
        "PetalWidthCm": 0.2,
        "request_id": "rf_1234",
        "metadata": {"source": "local"},
      },
    )
    self.assertEqual(payload_kwargs["metadata"], {"source": "local"})
    self.assertEqual(payload_kwargs["type"], "prediction")
    self.assertEqual(payload_kwargs["submitted_at"], 123.0)

  def test_build_result_from_raw_structured_inference_uses_payload_as_prediction(self):
    plugin = SdInferenceApiPlugin()

    result_payload = plugin._build_result_from_inference(  # pylint: disable=protected-access
      request_id="654129af5c33",
      inference={
        "Species": "iris-setosa",
        "processed_at": 1776385217.3100915,
      },
      metadata={},
      request_data={"metadata": {}},
    )

    self.assertEqual(result_payload["status"], "completed")
    self.assertEqual(result_payload["request_id"], "654129af5c33")
    self.assertEqual(
      result_payload["prediction"],
      {
        "Species": "iris-setosa",
      },
    )
    self.assertEqual(result_payload["processed_at"], 1776385217.3100915)


if __name__ == "__main__":
  unittest.main()
