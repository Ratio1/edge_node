import types
import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class _FakeHfModelBase:
  CONFIG = {"VALIDATION_RULES": {}, "EXPECTED_AI_ENGINES": None}

  def __init__(self, **kwargs):
    self.cfg_picked_input = kwargs.get("PICKED_INPUT", getattr(self, "CONFIG", {}).get("PICKED_INPUT", "STRUCT_DATA"))
    self.cfg_model_name = kwargs.get("MODEL_NAME", getattr(self, "CONFIG", {}).get("MODEL_NAME"))
    self.cfg_tokenizer_name = kwargs.get("TOKENIZER_NAME", getattr(self, "CONFIG", {}).get("TOKENIZER_NAME"))
    self.cfg_pipeline_task = kwargs.get("PIPELINE_TASK", getattr(self, "CONFIG", {}).get("PIPELINE_TASK"))
    self.cfg_text_keys = kwargs.get("TEXT_KEYS", getattr(self, "CONFIG", {}).get("TEXT_KEYS", ["text", "email_text", "content"]))
    self.cfg_request_id_keys = kwargs.get("REQUEST_ID_KEYS", getattr(self, "CONFIG", {}).get("REQUEST_ID_KEYS", ["request_id", "REQUEST_ID"]))
    self.cfg_max_length = kwargs.get("MAX_LENGTH", getattr(self, "CONFIG", {}).get("MAX_LENGTH", 512))
    self.cfg_hf_token = kwargs.get("HF_TOKEN", getattr(self, "CONFIG", {}).get("HF_TOKEN"))
    self.cfg_device = kwargs.get("DEVICE", getattr(self, "CONFIG", {}).get("DEVICE"))
    self.cfg_trust_remote_code = kwargs.get("TRUST_REMOTE_CODE", getattr(self, "CONFIG", {}).get("TRUST_REMOTE_CODE", True))
    self.cfg_expected_ai_engines = kwargs.get("EXPECTED_AI_ENGINES", getattr(self, "CONFIG", {}).get("EXPECTED_AI_ENGINES"))
    self.cfg_pipeline_kwargs = kwargs.get("PIPELINE_KWARGS", getattr(self, "CONFIG", {}).get("PIPELINE_KWARGS", {}))
    self.cfg_inference_kwargs = kwargs.get("INFERENCE_KWARGS", getattr(self, "CONFIG", {}).get("INFERENCE_KWARGS", {}))
    self.cfg_model_instance_id = kwargs.get("MODEL_INSTANCE_ID", getattr(self, "CONFIG", {}).get("MODEL_INSTANCE_ID"))
    self.os_environ = {}
    self.log = types.SimpleNamespace(get_models_folder=lambda: "/tmp/models")
    self.logged_messages = []
    self.classifier = None

  def P(self, *args, **kwargs):
    self.logged_messages.append((args, kwargs))
    return

  @property
  def hf_token(self):
    return self.cfg_hf_token or self.os_environ.get("EE_HF_TOKEN")

  def get_model_name(self):
    return self.cfg_model_name

  def get_tokenizer_name(self):
    return self.cfg_tokenizer_name or self.get_model_name()

  def get_pipeline_task(self):
    return self.cfg_pipeline_task

  def _resolve_pipeline_device(self):
    return -1

  def build_pipeline_kwargs(self):
    return dict(self.cfg_pipeline_kwargs or {})

  def get_additional_metadata(self):
    pipeline_task = getattr(self.classifier, "task", None) if self.classifier is not None else None
    return {
      "MODEL_NAME": self.get_model_name(),
      "TOKENIZER_NAME": self.get_tokenizer_name(),
      "PIPELINE_TASK": pipeline_task or self.get_pipeline_task(),
    }

  def get_expected_ai_engines(self):
    expected = self.cfg_expected_ai_engines
    if expected is None:
      return []
    if isinstance(expected, str):
      return [expected.lower()]
    return [item.lower() for item in expected]

  def _extract_serving_target(self, struct_payload):
    if not isinstance(struct_payload, dict):
      return None
    target = struct_payload.get("__SERVING_TARGET__")
    return target if isinstance(target, dict) else None

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
    if target_model_name is not None and self.get_model_name() is not None:
      if str(target_model_name) != str(self.get_model_name()):
        return False
    return True

  def startup(self):
    model_name = self.get_model_name()
    if not model_name:
      raise ValueError(f"{self.__class__.__name__} serving requires MODEL_NAME.")
    self.classifier = _PIPELINE_FACTORY(
      task=self.get_pipeline_task() or None,
      model=model_name,
      tokenizer=self.get_tokenizer_name(),
      cache_dir=self.log.get_models_folder(),
      token=self.hf_token,
      trust_remote_code=bool(self.cfg_trust_remote_code),
      device=self._resolve_pipeline_device(),
      **self.build_pipeline_kwargs(),
    )
    return


class _FakePipeline:
  def __init__(self, task=None):
    self.task = task
    self.calls = []

  def __call__(self, texts, **kwargs):
    self.calls.append((texts, kwargs))
    return [{"label": "ok", "score": 0.9} for _ in texts]


class _FallbackPipeline(_FakePipeline):
  def __call__(self, texts, **kwargs):
    self.calls.append((texts, kwargs))
    if isinstance(texts, list):
      raise AttributeError("'CustomBatchPipeline' object has no attribute 'framework'")
    return {"label": "ok", "score": 0.9}


class _PipelineFactory:
  def __init__(self):
    self.calls = []
    self.instance = _FakePipeline(task="text-classification")

  def __call__(self, *args, **kwargs):
    self.calls.append((args, kwargs))
    return self.instance


def _load_plugin_and_factory():
  factory = _PipelineFactory()
  source_path = ROOT / "extensions" / "serving" / "default_inference" / "nlp" / "th_text_classifier.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.serving.default_inference.nlp.th_hf_model_base import (\n"
    "  _CONFIG as BASE_HF_MODEL_CONFIG,\n"
    "  ThHfModelBase,\n"
    ")\n",
    "",
  )
  namespace = {
    "BASE_HF_MODEL_CONFIG": _FakeHfModelBase.CONFIG,
    "ThHfModelBase": _FakeHfModelBase,
    "__name__": "loaded_th_text_classifier",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["ThTextClassifier"], factory


ThTextClassifier, _PIPELINE_FACTORY = _load_plugin_and_factory()


class ThTextClassifierTests(unittest.TestCase):
  def test_startup_loads_transformers_pipeline_from_model_id(self):
    plugin = ThTextClassifier(MODEL_NAME="org/generic-text-classifier")

    plugin.startup()

    self.assertIs(plugin.classifier, _PIPELINE_FACTORY.instance)
    _args, kwargs = _PIPELINE_FACTORY.calls[-1]
    self.assertEqual(kwargs["model"], "org/generic-text-classifier")
    self.assertEqual(kwargs["tokenizer"], "org/generic-text-classifier")
    self.assertTrue(kwargs["trust_remote_code"])
    self.assertEqual(kwargs["device"], -1)

  def test_extract_text_and_request_id_from_struct_payload(self):
    plugin = ThTextClassifier(TEXT_KEYS=["email_text", "body"])

    text, struct_payload = plugin._extract_text({  # pylint: disable=protected-access
      "STRUCT_DATA": {
        "request_id": "req-1",
        "email_text": "  suspicious email body  ",
      }
    })
    request_id = plugin._extract_request_id(  # pylint: disable=protected-access
      payload={"STRUCT_DATA": struct_payload},
      struct_payload=struct_payload,
    )

    self.assertEqual(text, "suspicious email body")
    self.assertEqual(request_id, "req-1")

  def test_predict_uses_pipeline_with_inference_kwargs(self):
    plugin = ThTextClassifier(
      MODEL_NAME="org/generic-text-classifier",
      INFERENCE_KWARGS={"batch_size": 4},
    )
    plugin.startup()
    prepared = [{"text": "hello", "request_id": "req-1"}]

    predictions = plugin.predict(prepared)

    texts, kwargs = plugin.classifier.calls[-1]
    self.assertEqual(texts, ["hello"])
    self.assertEqual(kwargs["truncation"], True)
    self.assertEqual(kwargs["max_length"], 512)
    self.assertEqual(kwargs["batch_size"], 4)
    self.assertEqual(predictions["outputs"][0]["label"], "ok")

  def test_predict_falls_back_to_sequential_for_broken_custom_batch_pipeline(self):
    plugin = ThTextClassifier(MODEL_NAME="org/generic-text-classifier")
    plugin.classifier = _FallbackPipeline(task="text-classification")
    prepared = [
      {"text": "hello", "request_id": "req-1", "ignored": False},
      {"text": "world", "request_id": "req-2", "ignored": False},
    ]

    predictions = plugin.predict(prepared)

    self.assertEqual(len(predictions["outputs"]), 2)
    self.assertEqual(predictions["outputs"][0]["label"], "ok")
    self.assertEqual(predictions["outputs"][1]["label"], "ok")
    self.assertEqual(plugin.classifier.calls[0][0], ["hello", "world"])
    self.assertEqual(plugin.classifier.calls[1][0], "hello")
    self.assertEqual(plugin.classifier.calls[2][0], "world")

  def test_default_decode_outputs_normalizes_single_output(self):
    plugin = ThTextClassifier(MODEL_NAME="generic-model")
    payloads = [{
      "request_id": "req-a",
      "text": "mail a",
      "struct_payload": {
        "__SERVING_TARGET__": {
          "INFERENCE_REQUEST": True,
          "AI_ENGINE": "text_classifier",
        },
      },
    }]

    decoded = plugin._default_decode_outputs(  # pylint: disable=protected-access
      outputs={"label": "ok", "score": 0.5},
      payloads=payloads,
    )

    self.assertEqual(decoded[0]["REQUEST_ID"], "req-a")
    self.assertEqual(decoded[0]["result"]["label"], "ok")
    self.assertEqual(decoded[0]["MODEL_NAME"], "generic-model")
    self.assertEqual(decoded[0]["TOKENIZER_NAME"], "generic-model")
    self.assertEqual(
      decoded[0]["SERVING_TARGET"],
      {
        "INFERENCE_REQUEST": True,
        "AI_ENGINE": "text_classifier",
      },
    )

  def test_default_decode_outputs_keeps_single_token_classification_span_list(self):
    plugin = ThTextClassifier(MODEL_NAME="openai/privacy-filter")
    payloads = [{"request_id": "req-a", "text": "mail a"}]

    decoded = plugin._default_decode_outputs(  # pylint: disable=protected-access
      outputs=[
        {"entity_group": "private_person", "word": "Alice", "score": 0.99},
        {"entity_group": "private_email", "word": "alice@example.com", "score": 0.98},
      ],
      payloads=payloads,
    )

    self.assertEqual(decoded[0]["REQUEST_ID"], "req-a")
    self.assertEqual(len(decoded[0]["result"]), 2)
    self.assertEqual(decoded[0]["result"][0]["entity_group"], "private_person")
    self.assertEqual(decoded[0]["MODEL_NAME"], "openai/privacy-filter")

  def test_prepare_payloads_skips_invalid_payload_and_logs(self):
    plugin = ThTextClassifier(MODEL_NAME="generic-model", TEXT_KEYS=["body"])

    prepared = plugin._prepare_payloads({  # pylint: disable=protected-access
      "DATA": [
        {"STRUCT_DATA": {
          "body": "hello",
          "request_id": "req-a",
          "__SERVING_TARGET__": {
            "INFERENCE_REQUEST": True,
            "AI_ENGINE": "text_classifier",
          },
        }},
        {"STRUCT_DATA": {
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
    self.assertTrue(plugin.logged_messages)

  def test_prepare_payloads_ignores_other_serving_targets_without_logging(self):
    plugin = ThTextClassifier(MODEL_NAME="generic-model", TEXT_KEYS=["body"])

    prepared = plugin._prepare_payloads({  # pylint: disable=protected-access
      "DATA": [
        {"STRUCT_DATA": {
          "body": "hello",
          "request_id": "req-a",
          "__SERVING_TARGET__": {
            "INFERENCE_REQUEST": True,
            "AI_ENGINE": "privacy_filter",
          },
        }},
        {"STRUCT_DATA": {
          "body": "start-of-shift",
        }},
      ]
    })

    self.assertEqual(len(prepared), 2)
    self.assertTrue(all(item.get("ignored") for item in prepared))
    self.assertEqual(plugin.logged_messages, [])

  def test_default_decode_outputs_preserves_cardinality_for_ignored_payloads(self):
    plugin = ThTextClassifier(MODEL_NAME="generic-model")

    decoded = plugin._default_decode_outputs(  # pylint: disable=protected-access
      outputs={"label": "ok", "score": 0.5},
      payloads=[
        {"ignored": True},
        {
          "ignored": False,
          "request_id": "req-a",
          "text": "mail a",
          "struct_payload": {
            "__SERVING_TARGET__": {
              "INFERENCE_REQUEST": True,
              "AI_ENGINE": "text_classifier",
            },
          },
        },
      ],
    )

    self.assertEqual(decoded[0], [])
    self.assertEqual(decoded[1]["REQUEST_ID"], "req-a")

  def test_normalize_outputs_rejects_mismatched_batch_size(self):
    plugin = ThTextClassifier(MODEL_NAME="generic-model")

    with self.assertRaises(ValueError):
      plugin._normalize_outputs({"label": "ok"}, 2)  # pylint: disable=protected-access


if __name__ == "__main__":
  unittest.main()
