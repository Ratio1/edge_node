import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class _FakeTextClassifierInferenceApiPlugin:
  CONFIG = {
    "AI_ENGINE": "text_classifier",
    "API_TITLE": "Text Classifier Inference API",
    "API_SUMMARY": "Local text classification API for paired clients.",
  }


def _load_plugin_class():
  source_path = ROOT / "extensions" / "business" / "edge_inference_api" / "privacy_filter_inference_api.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.business.edge_inference_api.text_classifier_inference_api import (\n"
    "  _CONFIG as BASE_TEXT_CLASSIFIER_CONFIG,\n"
    "  TextClassifierInferenceApiPlugin,\n"
    ")\n",
    "",
  )
  namespace = {
    "BASE_TEXT_CLASSIFIER_CONFIG": _FakeTextClassifierInferenceApiPlugin.CONFIG,
    "TextClassifierInferenceApiPlugin": _FakeTextClassifierInferenceApiPlugin,
    "__name__": "loaded_privacy_filter_inference_api",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["PrivacyFilterInferenceApiPlugin"]


PrivacyFilterInferenceApiPlugin = _load_plugin_class()


class PrivacyFilterInferenceApiPluginTests(unittest.TestCase):
  def test_config_uses_dedicated_engine(self):
    self.assertEqual(PrivacyFilterInferenceApiPlugin.CONFIG["AI_ENGINE"], "privacy_filter")
    self.assertEqual(PrivacyFilterInferenceApiPlugin.CONFIG["API_TITLE"], "Privacy Filter Inference API")

  def test_build_result_from_inference_uses_findings_key(self):
    plugin = PrivacyFilterInferenceApiPlugin()

    result_payload = plugin._build_result_from_inference(  # pylint: disable=protected-access
      request_id="654129af5c33",
      inference={
        "REQUEST_ID": "654129af5c33",
        "TEXT": "example text",
        "result": [{"entity_group": "private_email", "word": "alice@example.com", "score": 0.97}],
        "REDACTED_TEXT": "[PRIVATE_EMAIL]",
        "CENSORED_TEXT": "*****************",
        "DETECTED_ENTITY_GROUPS": ["private_email"],
        "FINDINGS_COUNT": 1,
        "MODEL_NAME": "openai/privacy-filter",
        "PIPELINE_TASK": "token-classification",
        "MODEL": {"model_key": "privacy_filter", "model_version": "2026.05.09"},
        "MODEL_VERSION": "2026.05.09",
        "MODEL_REVISION": "rev-privacy",
        "HF_RUNTIME": "pt",
        "RUNTIME": "transformers",
      },
      metadata={},
      request_data={"metadata": {}, "parameters": {"text": "example text"}},
    )

    self.assertEqual(result_payload["status"], "completed")
    self.assertEqual(result_payload["request_id"], "654129af5c33")
    self.assertEqual(result_payload["text"], "example text")
    self.assertEqual(
      result_payload["findings"],
      [{"entity_group": "private_email", "word": "alice@example.com", "score": 0.97}],
    )
    self.assertEqual(result_payload["redacted_text"], "[PRIVATE_EMAIL]")
    self.assertEqual(result_payload["censored_text"], "*****************")
    self.assertEqual(result_payload["detected_entity_groups"], ["private_email"])
    self.assertEqual(result_payload["findings_count"], 1)
    self.assertEqual(result_payload["model_name"], "openai/privacy-filter")
    self.assertEqual(result_payload["pipeline_task"], "token-classification")
    self.assertEqual(
      result_payload["model"],
      {"model_key": "privacy_filter", "model_version": "2026.05.09"},
    )
    self.assertEqual(result_payload["model_version"], "2026.05.09")
    self.assertEqual(result_payload["model_revision"], "rev-privacy")
    self.assertEqual(result_payload["hf_runtime"], "pt")
    self.assertEqual(result_payload["runtime"], "transformers")


if __name__ == "__main__":
  unittest.main()
