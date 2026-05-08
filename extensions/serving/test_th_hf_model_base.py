import types
import unittest

from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]


class _FakeBaseServingProcess:
  CONFIG = {"VALIDATION_RULES": {}}

  def __init__(self, **kwargs):
    self.cfg_model_name = kwargs.get("MODEL_NAME")
    self.cfg_tokenizer_name = kwargs.get("TOKENIZER_NAME")
    self.cfg_pipeline_task = kwargs.get("PIPELINE_TASK")
    self.cfg_model_revision = kwargs.get("MODEL_REVISION")
    self.cfg_hf_runtime = kwargs.get("HF_RUNTIME", "auto")
    self.cfg_hf_artifact_manifest = kwargs.get("HF_ARTIFACT_MANIFEST", "artifact_manifest.json")
    self.cfg_hf_onnx_runtime_key = kwargs.get("HF_ONNX_RUNTIME_KEY", "onnx_fp32")
    self.cfg_hf_onnx_allow_patterns = kwargs.get("HF_ONNX_ALLOW_PATTERNS")
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
    self.framework = "pt"
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


class _FakeEncodedValue:
  def __init__(self, value):
    self.value = value
    self.dtype = None

  def astype(self, dtype):
    self.dtype = dtype
    return self


class _FakeTokenizer:
  def __init__(self):
    self.calls = []

  def __call__(self, text, **kwargs):
    self.calls.append((text, kwargs))
    return {
      "input_ids": _FakeEncodedValue([1, 2, 3]),
      "attention_mask": _FakeEncodedValue([1, 1, 1]),
    }


class _FakeOrtSession:
  def __init__(self):
    self.calls = []

  def run(self, output_names, inputs):
    self.calls.append((output_names, inputs))
    return [[0.25, 0.75]]


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
  return namespace["ThHfModelBase"], namespace["HfOnnxArtifactPipeline"], factory


ThHfModelBase, HfOnnxArtifactPipeline, _PIPELINE_FACTORY = _load_base_class()


class _ConcreteHfModel(ThHfModelBase):
  pass


class ThHfModelBaseTests(unittest.TestCase):
  def setUp(self):
    _PIPELINE_FACTORY.calls = []
    _PIPELINE_FACTORY.instance.inference_calls = []
    return

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

  def test_forced_pt_runtime_passes_model_revision_to_transformers_pipeline(self):
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      MODEL_REVISION="rev-123",
      HF_RUNTIME="pt",
      PIPELINE_TASK="text-classification",
      WARMUP_ENABLED=False,
    )

    plugin.startup()

    _args, kwargs = _PIPELINE_FACTORY.calls[-1]
    self.assertEqual(kwargs["revision"], "rev-123")
    self.assertEqual(plugin.hf_runtime, "pt")

  def test_auto_runtime_uses_onnx_artifact_on_cpu_only(self):
    manifest = {
      "model_key": "generic_text_classifier",
      "model_version": "2026.05.09",
      "pipeline_task": "text-classification",
      "runtimes": {
        "onnx_fp32": {
          "runtime": "onnxruntime",
          "entrypoint": "onnxruntime.InferenceSession",
          "files": [
            "model.onnx",
            "tokenizer.json",
            "contract.py",
            "schema.json",
            "model.safetensors",
          ],
        }
      },
    }
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      DEVICE="cpu",
      PIPELINE_TASK="text-classification",
      WARMUP_ENABLED=False,
    )
    download_calls = []
    plugin._load_hf_artifact_manifest = lambda: manifest  # pylint: disable=protected-access

    def fake_download(runtime_key, runtime_config, allow_patterns):
      download_calls.append((runtime_key, runtime_config, allow_patterns))
      return "/tmp/models/test-model"

    plugin._download_hf_runtime_snapshot = fake_download  # pylint: disable=protected-access
    plugin._build_hf_onnx_artifact_pipeline = (  # pylint: disable=protected-access
      lambda model_dir, runtime_key, runtime_config, manifest: _FakePipeline(task="text-classification")
    )

    plugin.startup()

    self.assertEqual(plugin.hf_runtime, "onnx_fp32")
    self.assertEqual(len(_PIPELINE_FACTORY.calls), 0)
    self.assertEqual(download_calls[0][0], "onnx_fp32")
    self.assertIn("model.onnx", download_calls[0][2])
    self.assertNotIn("model.safetensors", download_calls[0][2])

  def test_auto_runtime_keeps_transformers_pipeline_when_gpu_available(self):
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      PIPELINE_TASK="text-classification",
      WARMUP_ENABLED=False,
    )
    plugin._load_hf_artifact_manifest = lambda: {  # pylint: disable=protected-access
      "runtimes": {
        "onnx_fp32": {
          "runtime": "onnxruntime",
          "entrypoint": "onnxruntime.InferenceSession",
          "files": ["model.onnx"],
        }
      },
    }

    plugin.startup()

    self.assertEqual(plugin.device, 0)
    self.assertEqual(plugin.hf_runtime, "pt")
    self.assertEqual(len(_PIPELINE_FACTORY.calls), 1)

  def test_forced_onnx_runtime_uses_manifest_runtime_without_hardcoded_key(self):
    manifest = {
      "runtimes": {
        "cpu_artifact": {
          "runtime": "onnxruntime",
          "entrypoint": "onnxruntime.InferenceSession",
          "files": ["model.onnx", "schema.json", "contract.py"],
        }
      },
    }
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      DEVICE="cpu",
      HF_RUNTIME="onnx",
      PIPELINE_TASK="text-classification",
      WARMUP_ENABLED=False,
    )
    plugin._load_hf_artifact_manifest = lambda: manifest  # pylint: disable=protected-access
    plugin._download_hf_runtime_snapshot = (  # pylint: disable=protected-access
      lambda runtime_key, runtime_config, allow_patterns: "/tmp/models/test-model"
    )
    plugin._build_hf_onnx_artifact_pipeline = (  # pylint: disable=protected-access
      lambda model_dir, runtime_key, runtime_config, manifest: _FakePipeline(task="text-classification")
    )

    plugin.startup()

    self.assertEqual(plugin.hf_runtime, "cpu_artifact")
    self.assertEqual(len(_PIPELINE_FACTORY.calls), 0)

  def test_onnx_artifact_pipeline_uses_hf_contract_decoder(self):
    plugin = _ConcreteHfModel(
      MODEL_NAME="test/model",
      DEVICE="cpu",
      PIPELINE_TASK="text-classification",
      WARMUP_ENABLED=False,
    )
    fake_tokenizer = _FakeTokenizer()
    fake_session = _FakeOrtSession()
    created_sessions = []
    plugin._load_hf_onnx_tokenizer = lambda model_dir, runtime_config: fake_tokenizer  # pylint: disable=protected-access

    def fake_create_session(model_path, providers):
      created_sessions.append((model_path, providers))
      return fake_session

    plugin._create_hf_onnx_session = fake_create_session  # pylint: disable=protected-access

    with TemporaryDirectory() as tmpdir:
      model_dir = Path(tmpdir)
      (model_dir / "model.onnx").write_text("fake", encoding="utf-8")
      (model_dir / "schema.json").write_text(
        (
          '{"inputs":[{"name":"input_ids","dtype":"int64"},'
          '{"name":"attention_mask","dtype":"int64"}],'
          '"outputs":[{"name":"scores"}],'
          '"models":{"onnx_fp32":{"path":"model.onnx"}}}'
        ),
        encoding="utf-8",
      )
      (model_dir / "contract.py").write_text(
        (
          "def decode_generic_outputs(outputs, schema, **kwargs):\n"
          "  return {\n"
          "    'contract': 'hf',\n"
          "    'outputs': outputs,\n"
          "    'repo_id': kwargs.get('repo_id'),\n"
          "    'runtime': kwargs.get('runtime_key'),\n"
          "  }\n"
        ),
        encoding="utf-8",
      )
      manifest = {
        "pipeline_task": "text-classification",
        "runtimes": {
          "onnx_fp32": {
            "runtime": "onnxruntime",
            "files": ["model.onnx", "schema.json", "contract.py"],
          }
        },
      }

      pipeline = plugin._build_hf_onnx_artifact_pipeline(  # pylint: disable=protected-access
        model_dir=str(model_dir),
        runtime_key="onnx_fp32",
        runtime_config=manifest["runtimes"]["onnx_fp32"],
        manifest=manifest,
      )
      result = pipeline("hello world")
      batched_single_result = pipeline(["hello world"])

    self.assertIsInstance(pipeline, HfOnnxArtifactPipeline)
    self.assertEqual(result["contract"], "hf")
    self.assertEqual(batched_single_result["contract"], "hf")
    self.assertEqual(result["outputs"], {"scores": [0.25, 0.75]})
    self.assertEqual(result["repo_id"], "test/model")
    self.assertEqual(result["runtime"], "onnx_fp32")
    self.assertEqual(Path(created_sessions[0][0]).name, "model.onnx")
    output_names, inputs = fake_session.calls[-1]
    self.assertEqual(output_names, ["scores"])
    self.assertEqual(inputs["input_ids"].dtype, "int64")
    self.assertEqual(fake_tokenizer.calls[-1][1]["return_tensors"], "np")


if __name__ == "__main__":
  unittest.main()
