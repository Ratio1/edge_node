import json
import tempfile
import types
import unittest
from pathlib import Path

from extensions.serving.ai_engines.stable import AI_ENGINES


ROOT = Path(__file__).resolve().parents[2]


class _FakeBaseServingProcess:
  CONFIG = {
    "DEFAULT_DEVICE": "cpu",
    "DEFAULT_MAX_TOKENS": 2048,
    "VALIDATION_RULES": {},
  }

  def __init__(self):
    self.cache_dir = "/tmp/edge-node-test-cache"
    self.log = types.SimpleNamespace(gpu_info=lambda: [])
    self.messages = []
    self.cfg_generation_seed = 123

  def P(self, message, *_args, **_kwargs):
    self.messages.append(str(message))

  def json_dumps(self, value, **kwargs):
    return json.dumps(value, **kwargs)

  def safe_load_model(self, load_model_method, model_id, model_str_id=None):
    self.safe_load_model_args = {
      "model_id": model_id,
      "model_str_id": model_str_id,
    }
    return load_model_method()


class _FakeLlama:
  calls = []

  def __init__(self, **kwargs):
    self.kwargs = kwargs
    self.__class__.calls.append(("local", kwargs))

  @classmethod
  def from_pretrained(cls, **kwargs):
    cls.calls.append(("remote", kwargs))
    return types.SimpleNamespace(kwargs=kwargs)


class _FakeLlamaCppLib:
  @staticmethod
  def llama_supports_gpu_offload():
    return False


def _load_cybersec_qwen_class():
  source_path = (
    ROOT / "extensions" / "serving" / "default_inference" / "nlp" /
    "llama_cpp_cybersec_qwen_4b.py"
  )
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.serving.default_inference.nlp.llama_cpp_base import LlamaCppBaseServingProcess as BaseServingProcess\n",
    "",
  )
  namespace = {
    "BaseServingProcess": _FakeBaseServingProcess,
    "__name__": "loaded_llama_cpp_cybersec_qwen_4b",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return types.SimpleNamespace(
    cls=namespace["LlamaCppCybersecQwen4B"],
    config=namespace["_CONFIG"],
  )


def _load_llama_cpp_base_class():
  source_path = ROOT / "extensions" / "serving" / "default_inference" / "nlp" / "llama_cpp_base.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.serving.base.base_llm_serving import BaseLlmServing as BaseServingProcess\n",
    "",
  )
  source = source.replace(
    "from llama_cpp import Llama, llama_cpp as llama_cpp_lib\n",
    "",
  )
  source = source.replace(
    "from extensions.serving.mixins_llm.llm_utils import LlmCT\n",
    "",
  )
  namespace = {
    "BaseServingProcess": _FakeBaseServingProcess,
    "Llama": _FakeLlama,
    "llama_cpp_lib": _FakeLlamaCppLib,
    "LlmCT": types.SimpleNamespace(ROLE_KEY="role", DATA_KEY="content"),
    "__name__": "loaded_llama_cpp_base",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["LlamaCppBaseServingProcess"]


def _make_llama_cpp_process(**overrides):
  _FakeLlama.calls = []
  process = _load_llama_cpp_base_class()()
  defaults = {
    "cfg_model_path": None,
    "cfg_model_name": "org/repo",
    "cfg_model_filename": "model.gguf",
    "cfg_model_n_ctx": 1024,
    "cfg_chat_format": None,
    "cfg_draft_model": None,
    "cfg_n_gpu_layers": 0,
    "cfg_n_threads": 4,
  }
  defaults.update(overrides)
  for key, value in defaults.items():
    setattr(process, key, value)
  return process


class CyberSecQwenEngineTests(unittest.TestCase):
  def test_dedicated_ai_engine_mapping(self):
    self.assertEqual(
      AI_ENGINES["cybersec_qwen_4b"]["SERVING_PROCESS"],
      "llama_cpp_cybersec_qwen_4b",
    )
    self.assertNotIn("llama_cpp", AI_ENGINES)

  def test_serving_config_is_cpu_bounded_q4_model(self):
    loaded = _load_cybersec_qwen_class()
    config = loaded.config

    self.assertIs(loaded.cls.CONFIG, config)
    self.assertEqual(config["DEFAULT_DEVICE"], "cpu")
    self.assertEqual(config["N_GPU_LAYERS"], 0)
    self.assertEqual(config["N_THREADS"], 4)
    self.assertEqual(config["MODEL_N_CTX"], 4096)
    self.assertEqual(config["DEFAULT_MAX_TOKENS"], 1024)
    self.assertEqual(config["MODEL_INSTANCE_ID"], "cybersecqwen-4b")
    self.assertEqual(config["MODEL_NAME"], "mradermacher/CyberSecQwen-4B-GGUF")
    self.assertEqual(config["MODEL_FILENAME"], "CyberSecQwen-4B.Q4_K_M.gguf")

  def test_llama_cpp_base_can_load_mounted_model_file(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      model_path = Path(tmpdir) / "CyberSecQwen-4B.Q4_K_M.gguf"
      model_path.write_bytes(b"gguf")
      process = _make_llama_cpp_process(cfg_model_path=str(model_path))

      loaded = process._load_model()

    self.assertIsNone(loaded)
    self.assertEqual(len(_FakeLlama.calls), 1)
    call_type, kwargs = _FakeLlama.calls[0]
    self.assertEqual(call_type, "local")
    self.assertEqual(kwargs["model_path"], str(model_path))
    self.assertEqual(kwargs["n_threads"], 4)
    self.assertEqual(process.safe_load_model_args["model_id"], model_path.name)
    self.assertEqual(process.safe_load_model_args["model_str_id"], model_path.name)
    self.assertEqual(process.get_model_name(), model_path.name)
    self.assertFalse(any(str(model_path.parent) in message for message in process.messages))

  def test_llama_cpp_base_blank_model_path_uses_repo_loading(self):
    process = _make_llama_cpp_process(cfg_model_path="  ")

    process._load_model()

    self.assertEqual(len(_FakeLlama.calls), 1)
    call_type, kwargs = _FakeLlama.calls[0]
    self.assertEqual(call_type, "remote")
    self.assertEqual(kwargs["repo_id"], "org/repo")
    self.assertEqual(kwargs["filename"], "model.gguf")
    self.assertEqual(kwargs["cache_dir"], "/tmp/edge-node-test-cache")
    self.assertEqual(process.safe_load_model_args["model_id"], "org/repo")
    self.assertEqual(process.safe_load_model_args["model_str_id"], "org/repo/model.gguf")

  def test_llama_cpp_base_missing_model_path_error_is_sanitized(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      model_path = Path(tmpdir) / "missing.gguf"
      process = _make_llama_cpp_process(cfg_model_path=str(model_path))

      with self.assertRaises(FileNotFoundError) as raised:
        process._load_model()

    self.assertIn("missing.gguf", str(raised.exception))
    self.assertNotIn(tmpdir, str(raised.exception))


if __name__ == "__main__":
  unittest.main()
