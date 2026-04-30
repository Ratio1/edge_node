import types
import unittest

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class _FakeBaseServingProcess:
  CONFIG = {"VALIDATION_RULES": {}}

  def __init__(self, **kwargs):
    self.cfg_model_name = kwargs.get("MODEL_NAME")
    self.cfg_tokenizer_name = kwargs.get("TOKENIZER_NAME")
    self.cfg_pipeline_task = kwargs.get("PIPELINE_TASK")
    self.cfg_max_length = kwargs.get("MAX_LENGTH", 512)
    self.cfg_model_weights_size = kwargs.get("MODEL_WEIGHTS_SIZE")
    self.cfg_hf_token = kwargs.get("HF_TOKEN")
    self.cfg_device = kwargs.get("DEVICE")
    self.cfg_trust_remote_code = kwargs.get("TRUST_REMOTE_CODE", True)
    self.cfg_expected_ai_engines = kwargs.get("EXPECTED_AI_ENGINES")
    self.cfg_pipeline_kwargs = kwargs.get("PIPELINE_KWARGS", {})
    self.cfg_inference_kwargs = kwargs.get("INFERENCE_KWARGS", {})
    self.cfg_warmup_enabled = kwargs.get("WARMUP_ENABLED", True)
    self.cfg_warmup_text = kwargs.get("WARMUP_TEXT", "Warmup request.")
    self.cfg_warmup_inference_kwargs = kwargs.get("WARMUP_INFERENCE_KWARGS", {})
    self.cfg_model_instance_id = kwargs.get("MODEL_INSTANCE_ID")
    self.os_environ = {}
    self.logged_messages = []
    self._model_load_config_calls = []
    self._fake_time = 0.0
    self.log = types.SimpleNamespace(
      get_models_folder=lambda: "/tmp/models",
      get_model_load_config=self._fake_log_get_model_load_config,
    )

  def _fake_log_get_model_load_config(self, **kwargs):
    self._model_load_config_calls.append(kwargs)
    weights_size = kwargs.get("weights_size")
    quantization_params = None
    model_params = {
      "cache_dir": kwargs.get("cache_dir"),
      "token": kwargs.get("token"),
      "low_cpu_mem_usage": True,
      "torch_dtype": "auto",
      "device_map": kwargs.get("device_map"),
    }
    if weights_size == 4:
      quantization_params = {
        "load_in_4bit": True,
        "load_in_8bit": False,
        "bnb_4bit_quant_type": "nf4",
      }
    elif weights_size == 8:
      quantization_params = {
        "load_in_8bit": True,
        "load_in_4bit": False,
        "llm_int8_threshold": 6.0,
      }
    return model_params, quantization_params

  def P(self, *args, **kwargs):
    self.logged_messages.append((args, kwargs))
    return

  def time(self):
    self._fake_time += 1.0
    return self._fake_time


class _FakeBitsAndBytesConfig:
  def __init__(self, **kwargs):
    self.kwargs = kwargs


class _FakePipeline:
  def __init__(self, task=None):
    self.task = task
    self.inference_calls = []

  def __call__(self, text, **kwargs):
    self.inference_calls.append((text, kwargs))
    return {"ok": True}


class _PipelineFactory:
  def __init__(self):
    self.calls = []
    self.instance = _FakePipeline()

  def __call__(self, *args, **kwargs):
    self.calls.append((args, kwargs))
    self.instance.task = kwargs.get("task")
    return self.instance


class _FakeTorch:
  bfloat16 = "bfloat16"

  class cuda:
    @staticmethod
    def is_available():
      return True


def _load_base_class():
  factory = _PipelineFactory()
  source_path = ROOT / "extensions" / "serving" / "default_inference" / "nlp" / "th_hf_model_base.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace("import torch as th\n\n", "")
  source = source.replace(
    "from transformers import BitsAndBytesConfig, pipeline as hf_pipeline\n\n",
    "",
  )
  source = source.replace(
    "from naeural_core.serving.base.base_serving_process import ModelServingProcess as BaseServingProcess\n\n",
    "",
  )
  namespace = {
    "th": _FakeTorch,
    "BitsAndBytesConfig": _FakeBitsAndBytesConfig,
    "hf_pipeline": factory,
    "BaseServingProcess": _FakeBaseServingProcess,
    "__name__": "loaded_th_hf_model_base",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["ThHfModelBase"], factory


ThHfModelBase, _PIPELINE_FACTORY = _load_base_class()


class _ConcreteHfModel(ThHfModelBase):
  pass


class ThHfModelBaseTests(unittest.TestCase):
  def test_hf_serving_raises_default_wait_time_above_generic_base(self):
    self.assertEqual(_ConcreteHfModel.CONFIG["MAX_WAIT_TIME"], 60)

  def test_startup_runs_default_warmup(self):
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      PIPELINE_TASK="text-classification",
    )

    plugin.startup()

    self.assertEqual(_PIPELINE_FACTORY.instance.inference_calls[-1][0], "Warmup request.")
    self.assertEqual(
      _PIPELINE_FACTORY.instance.inference_calls[-1][1]["max_length"],
      512,
    )
    self.assertEqual(
      _PIPELINE_FACTORY.instance.inference_calls[-1][1]["truncation"],
      True,
    )

  def test_startup_adds_4bit_quantization_config(self):
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      MODEL_WEIGHTS_SIZE=4,
      PIPELINE_TASK="text-classification",
    )

    plugin.startup()

    _args, kwargs = _PIPELINE_FACTORY.calls[-1]
    self.assertEqual(kwargs["tokenizer"], "test/model")
    self.assertEqual(kwargs["device"], 0)
    self.assertEqual(kwargs["model_kwargs"]["cache_dir"], "/tmp/models")
    self.assertEqual(kwargs["model_kwargs"]["dtype"], "auto")
    self.assertNotIn("torch_dtype", kwargs["model_kwargs"])
    self.assertIsInstance(kwargs["model_kwargs"]["quantization_config"], _FakeBitsAndBytesConfig)
    self.assertEqual(
      kwargs["model_kwargs"]["quantization_config"].kwargs["load_in_4bit"],
      True,
    )

  def test_startup_adds_8bit_quantization_config(self):
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      MODEL_WEIGHTS_SIZE=8,
      PIPELINE_TASK="text-classification",
    )

    plugin.startup()

    _args, kwargs = _PIPELINE_FACTORY.calls[-1]
    self.assertEqual(
      kwargs["model_kwargs"]["quantization_config"].kwargs["load_in_8bit"],
      True,
    )
    self.assertEqual(
      kwargs["model_kwargs"]["quantization_config"].kwargs["llm_int8_threshold"],
      6.0,
    )

  def test_cpu_device_forces_cpu_device_map(self):
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      DEVICE="cpu",
      PIPELINE_TASK="text-classification",
    )

    plugin.startup()

    _args, kwargs = _PIPELINE_FACTORY.calls[-1]
    self.assertEqual(kwargs["device"], -1)
    self.assertEqual(plugin._model_load_config_calls[-1]["device_map"], "cpu")
    self.assertEqual(kwargs["model_kwargs"]["device_map"], "cpu")

  def test_startup_can_disable_warmup(self):
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      PIPELINE_TASK="text-classification",
      WARMUP_ENABLED=False,
    )

    before_calls = len(_PIPELINE_FACTORY.instance.inference_calls)
    plugin.startup()
    after_calls = len(_PIPELINE_FACTORY.instance.inference_calls)

    self.assertEqual(after_calls, before_calls)


if __name__ == "__main__":
  unittest.main()
