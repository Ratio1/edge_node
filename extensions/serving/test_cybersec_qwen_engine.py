import hashlib
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
    self.metadata = {"general.file_type": 15, "general.quantization_version": 2}
    self.__class__.calls.append(("local", kwargs))

  @classmethod
  def from_pretrained(cls, **kwargs):
    cls.calls.append(("remote", kwargs))
    return types.SimpleNamespace(kwargs=kwargs)


class _FakeLlamaCppLib:
  _lib = types.SimpleNamespace(_name=__file__)

  @staticmethod
  def llama_supports_gpu_offload():
    return False

  @staticmethod
  def llama_print_system_info():
    return b"fake-llama-build"


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
      REQUEST_ID="REQUEST_ID",
      MESSAGES="MESSAGES",
      TEMPERATURE="TEMPERATURE",
      TOP_P="TOP_P",
      MAX_TOKENS="MAX_TOKENS",
      CONTEXT="CONTEXT",
      VALID_CONDITION="VALID_CONDITION",
      PROCESS_METHOD="PROCESS_METHOD",
      RESPONSE_FORMAT="RESPONSE_FORMAT",
      BENCHMARK_MODE="BENCHMARK_MODE",
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
    "cfg_model_revision": None,
    "cfg_model_n_ctx": 1024,
    "cfg_chat_format": None,
    "cfg_draft_model": None,
    "cfg_n_gpu_layers": 0,
    "cfg_n_threads": 4,
    "cfg_default_temperature": 0.7,
    "cfg_default_top_p": 1.0,
    "cfg_default_max_tokens": 128,
    "cfg_repetition_penalty": 1.0,
    "cfg_default_response_format": None,
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
    fingerprint = process.get_runtime_fingerprint()
    self.assertEqual(fingerprint["gguf_sha256"], hashlib.sha256(b"gguf").hexdigest())
    self.assertEqual(fingerprint["model_revision"], f"artifact-sha256:{fingerprint['gguf_sha256']}")
    self.assertEqual(fingerprint["quantization"]["general.file_type"], 15)
    self.assertEqual(fingerprint["llama_cpp"]["build_sha256"], hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    self.assertRegex(fingerprint["llama_cpp"]["system_info_sha256"], r"^[0-9a-f]{64}$")
    self.assertRegex(fingerprint["load_configuration"]["draft_model_config_sha256"], r"^[0-9a-f]{64}$")
    self.assertRegex(fingerprint["fingerprint_sha256"], r"^[0-9a-f]{64}$")
    self.assertNotIn(str(model_path), json.dumps(fingerprint))

  def test_llama_cpp_base_blank_model_path_uses_repo_loading(self):
    process = _make_llama_cpp_process(cfg_model_path="  ")
    with tempfile.TemporaryDirectory() as tmpdir:
      downloaded_path = str(Path(tmpdir) / "snapshots" / ("a" * 40) / "model.gguf")
      Path(downloaded_path).parent.mkdir(parents=True)
      Path(downloaded_path).write_bytes(b"gguf")
      fake_hf_module = types.SimpleNamespace(
        HfApi=lambda token=None: types.SimpleNamespace(
          list_repo_files=lambda repo_id, revision=None, token=None: ["model.gguf"],
        ),
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

      self.assertEqual(process.get_runtime_fingerprint()["model_revision"], "a" * 40)

    self.assertEqual(len(_FakeLlama.calls), 1)
    call_type, kwargs = _FakeLlama.calls[0]
    self.assertEqual(call_type, "local")
    self.assertEqual(kwargs["model_path"], downloaded_path)
    self.assertEqual(process.safe_load_model_args["model_id"], "org/repo")
    self.assertEqual(process.safe_load_model_args["model_str_id"], "org/repo/model.gguf")

  def test_llama_cpp_base_applies_requested_revision_but_records_loaded_snapshot(self):
    process = _make_llama_cpp_process(cfg_model_revision="requested-tag")
    calls = []
    with tempfile.TemporaryDirectory() as tmpdir:
      snapshot = "b" * 40
      downloaded_path = str(Path(tmpdir) / "snapshots" / snapshot / "model.gguf")
      Path(downloaded_path).parent.mkdir(parents=True)
      Path(downloaded_path).write_bytes(b"gguf")
      fake_hf_module = types.SimpleNamespace(
        HfApi=lambda token=None: types.SimpleNamespace(
          list_repo_files=lambda **kwargs: calls.append(("list", kwargs)) or ["model.gguf"],
        ),
        hf_hub_download=lambda **kwargs: calls.append(("download", kwargs)) or downloaded_path,
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
    self.assertEqual(process.get_runtime_fingerprint()["model_revision"], snapshot)
    self.assertEqual(process.get_runtime_fingerprint()["load_configuration"]["requested_model_revision"], "requested-tag")
    self.assertTrue(all(kwargs["revision"] == "requested-tag" for _name, kwargs in calls))

  def test_llama_cpp_base_missing_model_path_error_is_sanitized(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      model_path = Path(tmpdir) / "missing.gguf"
      process = _make_llama_cpp_process(cfg_model_path=str(model_path))

      with self.assertRaises(FileNotFoundError) as raised:
        process._load_model()

    self.assertIn("missing.gguf", str(raised.exception))
    self.assertNotIn(tmpdir, str(raised.exception))

  def test_llama_cpp_base_preserves_explicit_zero_temperature(self):
    process = _make_llama_cpp_process()
    process.cfg_default_temperature = 0.7
    process.cfg_default_top_p = 0.9
    process.cfg_default_max_tokens = 1024
    process.cfg_repetition_penalty = 1.0
    process.check_relevant_input = lambda _input: True
    process.maybe_add_context_to_messages = lambda messages, context: messages
    process.get_default_response_format = lambda: {"type": "text"}
    process.process_predict_kwargs = lambda kwargs: kwargs

    preprocessed = process._pre_process({
      "DATA": [{
        "JEEVES_CONTENT": {
          "MESSAGES": [{"role": "user", "content": "Explain"}],
          "TEMPERATURE": 0.0,
        },
      }],
    })

    self.assertEqual(preprocessed[0][0]["temperature"], 0.0)

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

  def test_llama_cpp_benchmark_mode_resets_once_calls_once_and_omits_retry_hints(self):
    process = _make_llama_cpp_process()
    process.cfg_default_temperature = 0.7
    process.cfg_default_top_p = 0.9
    process.cfg_default_max_tokens = 128
    process.cfg_repetition_penalty = 1.0
    process.check_relevant_input = lambda _input: True
    process.maybe_add_context_to_messages = lambda messages, context: messages
    process.get_default_response_format = lambda: None
    process.process_predict_kwargs = lambda kwargs: kwargs
    process._tps = []
    process.time = lambda: 1.0
    process.maybe_process_text = lambda text, _method: text
    process.check_condition = lambda _text, _condition: False
    reset_calls = []
    completion_calls = []
    process.model = types.SimpleNamespace(
      reset=lambda: reset_calls.append(True),
      create_chat_completion=lambda **kwargs: (
        completion_calls.append(kwargs) or {
          "choices": [{"message": {"content": ""}, "finish_reason": "stop"}],
          "usage": {"completion_tokens": 0},
        }
      ),
    )

    preprocessed = process._pre_process({
      "DATA": [{"JEEVES_CONTENT": {
        "MESSAGES": [{"role": "user", "content": "fixture"}],
        "BENCHMARK_MODE": True,
        "VALID_CONDITION": "must-not-run",
        "PROCESS_METHOD": "must-not-run",
      }}],
    })
    result = process._predict(preprocessed)

    self.assertEqual(preprocessed[3], [None])
    self.assertEqual(preprocessed[4], [None])
    self.assertEqual(len(reset_calls), 1)
    self.assertEqual(len(completion_calls), 1)
    telemetry = result["FULL_OUTPUT"][0]["EDGEGUARD_BENCHMARK_TELEMETRY"]
    self.assertEqual(telemetry["reset_succeeded"], True)
    self.assertEqual(telemetry["attempt_count"], 1)
    self.assertRegex(telemetry["generation_config_sha256"], r"^[0-9a-f]{64}$")
    self.assertEqual(
      telemetry["generation_config_sha256"],
      process.benchmark_generation_config_sha256(completion_calls[0]),
    )

  def test_llama_cpp_benchmark_mode_missing_reset_makes_zero_completion_calls(self):
    process = _make_llama_cpp_process()
    process._tps = []
    process.time = lambda: 1.0
    process.maybe_process_text = lambda text, _method: text
    process.check_condition = lambda _text, _condition: True
    completion_calls = []
    process.model = types.SimpleNamespace(
      create_chat_completion=lambda **_kwargs: completion_calls.append(True),
    )
    result = process._predict([
      [{"max_tokens": 128}],
      [[{"role": "user", "content": "fixture"}]],
      [{"REQUEST_ID": "req", "BENCHMARK_MODE": True}],
      [None],
      [None],
      [0],
      1,
    ])

    self.assertEqual(completion_calls, [])
    self.assertEqual(result["FULL_OUTPUT"][0]["error"]["code"], "benchmark_reset_unavailable")
    telemetry = result["FULL_OUTPUT"][0]["EDGEGUARD_BENCHMARK_TELEMETRY"]
    self.assertEqual(telemetry["reset_succeeded"], False)
    self.assertEqual(telemetry["attempt_count"], 0)
    self.assertRegex(telemetry["generation_config_sha256"], r"^[0-9a-f]{64}$")

  def test_llama_cpp_benchmark_mode_terminal_outcomes_each_call_once(self):
    outcomes = {
      "success": lambda: {
        "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        "usage": {"completion_tokens": 1},
      },
      "empty": lambda: {
        "choices": [{"message": {"content": ""}, "finish_reason": "stop"}],
        "usage": {"completion_tokens": 0},
      },
      "provider_error": lambda: {"error": {"code": "provider_error"}},
      "context_error": lambda: (_ for _ in ()).throw(
        ValueError("Requested tokens (3301) exceed context window of 4096")
      ),
    }
    for label, outcome in outcomes.items():
      with self.subTest(label=label):
        process = _make_llama_cpp_process()
        process._tps = []
        process.time = lambda: 1.0
        process.maybe_process_text = lambda text, _method: text
        process.check_condition = lambda _text, _condition: False
        reset_calls = []
        completion_calls = []

        def complete(**_kwargs):
          completion_calls.append(True)
          return outcome()

        process.model = types.SimpleNamespace(
          reset=lambda: reset_calls.append(True),
          create_chat_completion=complete,
        )
        result = process._predict([
          [{"max_tokens": 128}],
          [[{"role": "user", "content": "fixture"}]],
          [{"REQUEST_ID": "req", "BENCHMARK_MODE": True}],
          [None],
          [None],
          [0],
          1,
        ])

        self.assertEqual(len(reset_calls), 1)
        self.assertEqual(len(completion_calls), 1)
        telemetry = result["FULL_OUTPUT"][0]["EDGEGUARD_BENCHMARK_TELEMETRY"]
        self.assertEqual(telemetry["reset_succeeded"], True)
        self.assertEqual(telemetry["attempt_count"], 1)
        self.assertRegex(telemetry["generation_config_sha256"], r"^[0-9a-f]{64}$")

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
