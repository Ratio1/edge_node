import json
import sys
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
    self.hf_token = None
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

  @staticmethod
  def _post_process(preds_batch):
    return [
      {
        "IS_VALID": True,
        "text": text,
        "FULL_OUTPUT": full_output,
        **additional,
      }
      for text, full_output, additional in zip(
        preds_batch["text"],
        preds_batch["FULL_OUTPUT"],
        preds_batch["ADDITIONAL"],
      )
    ]


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
    "LlmCT": types.SimpleNamespace(
      ROLE_KEY="role",
      DATA_KEY="content",
      PRMP="prompt",
      TEXT="text",
      ADDITIONAL="ADDITIONAL",
      FULL_OUTPUT="FULL_OUTPUT",
    ),
    "__name__": "loaded_llama_cpp_base",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["LlamaCppBaseServingProcess"]


def _load_ai_engine_utils():
  source_path = ROOT / "naeural_core" / "naeural_core" / "serving" / "ai_engines" / "utils.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace("from naeural_core.serving.ai_engines import AI_ENGINES\n", "")
  namespace = {
    "AI_ENGINES": AI_ENGINES,
    "__name__": "loaded_ai_engine_utils",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return types.SimpleNamespace(
    get_serving_process_given_ai_engine=namespace["get_serving_process_given_ai_engine"],
    get_ai_engine_given_serving_process=namespace["get_ai_engine_given_serving_process"],
  )


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
    self.assertEqual(
      AI_ENGINES["edgeguard_qwen_4b"]["SERVING_PROCESS"],
      "llama_cpp_edgeguard_qwen_4b",
    )
    self.assertNotIn("llama_cpp", AI_ENGINES)

  def test_edgeguard_model_instance_id_keeps_dual_workers_distinct(self):
    utils = _load_ai_engine_utils()

    self.assertEqual(
      utils.get_serving_process_given_ai_engine("edgeguard_qwen_4b"),
      "llama_cpp_edgeguard_qwen_4b",
    )
    self.assertEqual(
      utils.get_serving_process_given_ai_engine(("edgeguard_qwen_4b", "edgeguard-base-qwen3-4b")),
      ("llama_cpp_edgeguard_qwen_4b", "edgeguard-base-qwen3-4b"),
    )
    self.assertEqual(
      utils.get_ai_engine_given_serving_process(
        ("llama_cpp_edgeguard_qwen_4b", "edgeguard-base-qwen3-4b"),
      ),
      ("edgeguard_qwen_4b", "edgeguard-base-qwen3-4b"),
    )

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
    downloaded_path = "/tmp/edge-node-test-cache/model.gguf"
    fake_hf_module = types.SimpleNamespace(
      HfApi=lambda token=None: types.SimpleNamespace(list_repo_files=lambda repo_id, token=None: ["model.gguf"]),
      hf_hub_download=lambda **_kwargs: downloaded_path,
    )
    previous_hf_module = sys.modules.get("huggingface_hub")
    sys.modules["huggingface_hub"] = fake_hf_module

    try:
      process._load_model()
    finally:
      if previous_hf_module is None:
        sys.modules.pop("huggingface_hub", None)
      else:
        sys.modules["huggingface_hub"] = previous_hf_module

    self.assertEqual(len(_FakeLlama.calls), 1)
    call_type, kwargs = _FakeLlama.calls[0]
    self.assertEqual(call_type, "local")
    self.assertEqual(kwargs["model_path"], downloaded_path)
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

  def test_llama_cpp_context_overflow_returns_structured_failure_without_retry(self):
    process = _make_llama_cpp_process()
    process._tps = []
    process.time = lambda: 1.0
    process.maybe_process_text = lambda text, _method: text
    process.check_condition = lambda _text, _condition: True
    process.model = types.SimpleNamespace()
    calls = []

    def overflow(**_kwargs):
      calls.append(True)
      raise ValueError("Requested tokens (17893) exceed context window of 4096")

    process.model.create_chat_completion = overflow
    result = process._predict([
      [{"max_tokens": 1600}],
      [[{"role": "user", "content": "large packet"}]],
      [{"REQUEST_ID": "req-context"}],
      [None],
      [None],
      [0],
      1,
    ])

    self.assertEqual(len(calls), 1)
    self.assertEqual(result["text"], [""])
    self.assertEqual(
      result["FULL_OUTPUT"][0]["error"]["code"],
      "context_window_exceeded",
    )
    self.assertEqual(result["FULL_OUTPUT"][0]["error"]["requested_tokens"], 17893)
    self.assertEqual(result["FULL_OUTPUT"][0]["error"]["context_window"], 4096)
    processed = process._post_process(result)
    self.assertFalse(processed[0]["IS_VALID"])
    self.assertEqual(processed[0]["ERROR_CODE"], "context_window_exceeded")
    self.assertEqual(processed[0]["ERROR"], "Model context window exceeded.")

  def test_llama_cpp_generation_logs_only_content_free_diagnostics(self):
    process = _make_llama_cpp_process()
    process._tps = []
    process.time = lambda: 1.0
    process.maybe_process_text = lambda text, _method: text
    process.check_condition = lambda _text, _condition: True
    partial_output = "partial-secret-model-output"
    process.model = types.SimpleNamespace(
      create_chat_completion=lambda **_kwargs: {
        "choices": [{
          "message": {"content": partial_output},
          "finish_reason": "length",
        }],
        "usage": {"completion_tokens": 512},
      },
    )

    result = process._predict([
      [{"max_tokens": 512}],
      [[{"role": "user", "content": "bounded prompt"}]],
      [{"REQUEST_ID": "req-length"}],
      [None],
      [None],
      [0],
      1,
    ])

    self.assertEqual(result["text"], [partial_output])
    self.assertFalse(any(partial_output in message for message in process.messages))
    self.assertTrue(any("text_chars=" in message for message in process.messages))

    base_source = (
      ROOT / "extensions" / "serving" / "base" / "base_llm_serving.py"
    ).read_text(encoding="utf-8")
    self.assertNotIn("shorten_str(text_lst)", base_source)
    self.assertIn("text_chars=", base_source)


if __name__ == "__main__":
  unittest.main()
