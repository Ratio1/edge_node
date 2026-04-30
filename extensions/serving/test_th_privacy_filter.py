import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class _FakeThTextClassifier:
  CONFIG = {
    "MODEL_NAME": None,
    "PIPELINE_TASK": None,
    "TRUST_REMOTE_CODE": True,
    "EXPECTED_AI_ENGINES": None,
    "MAX_LENGTH": 512,
    "INFERENCE_KWARGS": {},
  }

  def __init__(self, **kwargs):
    self.cfg_picked_input = kwargs.get("PICKED_INPUT", getattr(self, "CONFIG", {}).get("PICKED_INPUT", "STRUCT_DATA"))
    self.cfg_text_keys = kwargs.get("TEXT_KEYS", getattr(self, "CONFIG", {}).get("TEXT_KEYS", ["text", "email_text", "content", "request", "body"]))
    self.cfg_request_id_keys = kwargs.get("REQUEST_ID_KEYS", getattr(self, "CONFIG", {}).get("REQUEST_ID_KEYS", ["request_id", "REQUEST_ID"]))
    self.cfg_expected_ai_engines = kwargs.get("EXPECTED_AI_ENGINES", getattr(self, "CONFIG", {}).get("EXPECTED_AI_ENGINES"))
    self.cfg_model_instance_id = kwargs.get("MODEL_INSTANCE_ID", getattr(self, "CONFIG", {}).get("MODEL_INSTANCE_ID"))
    self.cfg_model_name = kwargs.get("MODEL_NAME", getattr(self, "CONFIG", {}).get("MODEL_NAME"))
    self.logged_messages = []

  def P(self, *args, **kwargs):
    self.logged_messages.append((args, kwargs))
    return

  def get_model_name(self):
    return self.cfg_model_name

  def get_tokenizer_name(self):
    return self.cfg_model_name

  def get_pipeline_task(self):
    return getattr(self, "CONFIG", {}).get("PIPELINE_TASK")

  def get_additional_metadata(self):
    return {
      "MODEL_NAME": self.get_model_name(),
      "TOKENIZER_NAME": self.get_tokenizer_name(),
      "PIPELINE_TASK": self.get_pipeline_task(),
    }

  def get_tokenizer_name(self):
    return self.cfg_model_name

  def get_pipeline_task(self):
    return getattr(self, "CONFIG", {}).get("PIPELINE_TASK")

  def get_additional_metadata(self):
    return {
      "MODEL_NAME": self.get_model_name(),
      "TOKENIZER_NAME": self.get_tokenizer_name(),
      "PIPELINE_TASK": self.get_pipeline_task(),
    }

  def _extract_serving_target(self, struct_payload):
    if not isinstance(struct_payload, dict):
      return None
    target = struct_payload.get("__SERVING_TARGET__")
    return target if isinstance(target, dict) else None

  def get_expected_ai_engines(self):
    expected = self.cfg_expected_ai_engines
    if expected is None:
      return []
    if isinstance(expected, str):
      return [expected.lower()]
    return [item.lower() for item in expected]

  def _payload_matches_current_serving(self, struct_payload):
    target = self._extract_serving_target(struct_payload)
    if not isinstance(target, dict):
      return False
    if target.get("INFERENCE_REQUEST") is not True:
      return False
    expected_ai_engines = self.get_expected_ai_engines()
    if expected_ai_engines:
      ai_engine = target.get("AI_ENGINE")
      if not isinstance(ai_engine, str) or ai_engine.lower() not in expected_ai_engines:
        return False
    target_instance_id = target.get("MODEL_INSTANCE_ID")
    if target_instance_id is not None and self.cfg_model_instance_id is not None:
      if str(target_instance_id) != str(self.cfg_model_instance_id):
        return False
    target_model_name = target.get("MODEL_NAME")
    if target_model_name is not None and self.cfg_model_name is not None:
      if str(target_model_name) != str(self.cfg_model_name):
        return False
    return True


def _load_plugin_class():
  source_path = ROOT / "extensions" / "serving" / "default_inference" / "nlp" / "th_privacy_filter.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.serving.default_inference.nlp.th_hf_model_base import (\n"
    "  _CONFIG as BASE_HF_MODEL_CONFIG,\n"
    "  ThHfModelBase,\n"
    ")\n",
    "",
  )
  namespace = {
    "BASE_HF_MODEL_CONFIG": _FakeThTextClassifier.CONFIG,
    "ThHfModelBase": _FakeThTextClassifier,
    "__name__": "loaded_th_privacy_filter",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["ThPrivacyFilter"]


ThPrivacyFilter = _load_plugin_class()


class ThPrivacyFilterTests(unittest.TestCase):
  def test_config_pins_privacy_filter_defaults(self):
    self.assertEqual(ThPrivacyFilter.CONFIG["MODEL_NAME"], "openai/privacy-filter")
    self.assertEqual(ThPrivacyFilter.CONFIG["PIPELINE_TASK"], "token-classification")
    self.assertFalse(ThPrivacyFilter.CONFIG["TRUST_REMOTE_CODE"])
    self.assertIsNone(ThPrivacyFilter.CONFIG["MAX_LENGTH"])
    self.assertEqual(
      ThPrivacyFilter.CONFIG["INFERENCE_KWARGS"]["aggregation_strategy"],
      "simple",
    )

  def test_post_process_emits_redaction_friendly_fields(self):
    plugin = ThPrivacyFilter()

    decoded = plugin.post_process({
      "payloads": [{
        "request_id": "req-a",
        "text": "Alice alice@example.com",
        "struct_payload": {
          "__SERVING_TARGET__": {
            "INFERENCE_REQUEST": True,
            "AI_ENGINE": "privacy_filter",
            "MODEL_NAME": "openai/privacy-filter",
          },
        },
      }],
      "outputs": [
        {
          "entity_group": "private_person",
          "score": 0.99,
          "word": "Alice",
          "start": 0,
          "end": 5,
        },
        {
          "entity_group": "private_email",
          "score": 0.98,
          "word": "alice@example.com",
          "start": 6,
          "end": 23,
        },
      ],
    })

    self.assertEqual(decoded[0]["REQUEST_ID"], "req-a")
    self.assertEqual(len(decoded[0]["result"]), 2)
    self.assertEqual(
      decoded[0]["DETECTED_ENTITY_GROUPS"],
      ["private_person", "private_email"],
    )
    self.assertEqual(
      decoded[0]["REDACTED_TEXT"],
      "[PRIVATE_PERSON] [PRIVATE_EMAIL]",
    )
    self.assertEqual(
      decoded[0]["CENSORED_TEXT"],
      "**** ****",
    )
    self.assertEqual(decoded[0]["FINDINGS_COUNT"], 2)
    self.assertEqual(decoded[0]["MODEL_NAME"], "openai/privacy-filter")
    self.assertEqual(decoded[0]["TOKENIZER_NAME"], "openai/privacy-filter")
    self.assertEqual(decoded[0]["PIPELINE_TASK"], "token-classification")
    self.assertEqual(
      decoded[0]["SERVING_TARGET"],
      {
        "INFERENCE_REQUEST": True,
        "AI_ENGINE": "privacy_filter",
        "MODEL_NAME": "openai/privacy-filter",
      },
    )

  def test_prepare_payloads_filters_foreign_requests(self):
    plugin = ThPrivacyFilter(MODEL_NAME="openai/privacy-filter")

    prepared = plugin._prepare_payloads({
      "DATA": [
        {"STRUCT_DATA": {
          "text": "Alice",
          "request_id": "req-a",
          "__SERVING_TARGET__": {
            "INFERENCE_REQUEST": True,
            "AI_ENGINE": "privacy_filter",
            "MODEL_NAME": "openai/privacy-filter",
          },
        }},
        {"STRUCT_DATA": {
          "text": "Bob",
          "request_id": "req-b",
          "__SERVING_TARGET__": {
            "INFERENCE_REQUEST": True,
            "AI_ENGINE": "text_classifier",
          },
        }},
      ]
    })

    self.assertEqual(len(prepared), 2)
    self.assertEqual(prepared[0]["request_id"], "req-a")
    self.assertFalse(prepared[0]["ignored"])
    self.assertTrue(prepared[1]["ignored"])

  def test_post_process_preserves_cardinality_for_ignored_payloads(self):
    plugin = ThPrivacyFilter(MODEL_NAME="openai/privacy-filter")

    decoded = plugin.post_process({
      "payloads": [
        {"ignored": True},
        {
          "ignored": False,
          "request_id": "req-a",
          "text": "Alice alice@example.com",
          "struct_payload": {
            "__SERVING_TARGET__": {
              "INFERENCE_REQUEST": True,
              "AI_ENGINE": "privacy_filter",
              "MODEL_NAME": "openai/privacy-filter",
            },
          },
        },
      ],
      "outputs": [
        {
          "entity_group": "private_email",
          "score": 0.98,
          "word": "alice@example.com",
          "start": 6,
          "end": 23,
        },
      ],
    })

    self.assertEqual(decoded[0], [])
    self.assertEqual(decoded[1]["REQUEST_ID"], "req-a")


if __name__ == "__main__":
  unittest.main()
