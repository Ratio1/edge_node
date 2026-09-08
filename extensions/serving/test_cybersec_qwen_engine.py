import ast
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from extensions.serving.ai_engines.stable import AI_ENGINES


ROOT = Path(__file__).resolve().parents[2]
PROFILE_DIR = ROOT / "extensions" / "serving" / "default_inference" / "nlp"


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


def _load_llama_cpp_base_class():
  source_path = PROFILE_DIR / "llama_cpp_base.py"
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
      PRMP="prompt",
      TEXT="text",
      ADDITIONAL="ADDITIONAL",
      FULL_OUTPUT="FULL_OUTPUT",
    ),
    "__file__": str(source_path),
    "__name__": "loaded_llama_cpp_base",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["LlamaCppBaseServingProcess"]


class _FakeLlmServing:
  ct = types.SimpleNamespace(
    PAYLOAD_DATA=types.SimpleNamespace(EE_PAYLOAD_PATH="EE_PAYLOAD_PATH"),
    SIGNATURE="SIGNATURE",
    JeevesCt=types.SimpleNamespace(JEEVES_CONTENT="JEEVES_CONTENT"),
  )

  def __init__(self, server_name):
    self.server_name = server_name
    self.messages = []

  def P(self, message, *_args, **_kwargs):
    self.messages.append(str(message))

  @staticmethod
  def shorten_str(value):
    return str(value)

  @staticmethod
  def get_relevant_signatures():
    return {"LLM_INFERENCE_API"}

  @staticmethod
  def check_supported_request_type(message_data):
    return True


def _load_llm_serving_relevance_gate():
  """Compile only `BaseLlmServing.check_relevant_input`, avoiding the torch import chain."""
  source_path = ROOT / "extensions" / "serving" / "base" / "base_llm_serving.py"
  source = source_path.read_text(encoding="utf-8")
  module = ast.parse(source)
  class_node = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "BaseLlmServing")
  method = next(node for node in class_node.body if isinstance(node, ast.FunctionDef) and node.name == "check_relevant_input")
  method_source = ast.get_source_segment(source, method)
  method_source = "\n".join(line[2:] if line.startswith("  ") else line for line in method_source.splitlines())
  namespace = {}
  exec(compile(method_source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["check_relevant_input"]


def _load_profile(filename, class_name):
  source_path = PROFILE_DIR / filename
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from extensions.serving.default_inference.nlp.llama_cpp_base import "
    "LlamaCppBaseServingProcess as BaseServingProcess\n",
    "",
  )
  namespace = {
    "BaseServingProcess": _FakeBaseServingProcess,
    "__file__": str(source_path),
    "__name__": f"loaded_{source_path.stem}",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return types.SimpleNamespace(
    cls=namespace[class_name],
    config=namespace["_CONFIG"],
    source=source_path.read_text(encoding="utf-8"),
  )


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


def _load_plugins_manager_mixin():
  source_path = ROOT / "ratio1_sdk" / "ratio1" / "plugins_manager_mixin.py"
  source = source_path.read_text(encoding="utf-8")
  source = source.replace(
    "from .code_cheker.base import BaseCodeChecker\n",
    "class BaseCodeChecker:\n  pass\n",
  )
  namespace = {
    "__file__": str(source_path),
    "__name__": "loaded_plugins_manager_mixin",
  }
  exec(compile(source, str(source_path), "exec"), namespace)  # noqa: S102
  return namespace["_PluginsManagerMixin"]


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
    "cfg_generation_seed": 123,
  }
  defaults.update(overrides)
  for key, value in defaults.items():
    setattr(process, key, value)
  return process


class CyberSecQwenEngineTests(unittest.TestCase):
  PROFILES = {
    "base_qwen3_4b": (
      "llama_cpp_base_qwen3_4b.py",
      "LlamaCppBaseQwen34B",
      "MaziyarPanahi/Qwen3-4B-Instruct-2507-GGUF",
      "Qwen3-4B-Instruct-2507.Q4_K_M.gguf",
      "edgeguard-base-qwen3-4b",
    ),
    "cybersec_qwen_4b": (
      "llama_cpp_cybersec_qwen_4b.py",
      "LlamaCppCybersecQwen4B",
      "mradermacher/CyberSecQwen-4B-GGUF",
      "CyberSecQwen-4B.Q4_K_M.gguf",
      "cybersecqwen-4b",
    ),
  }

  def test_public_and_generic_ai_engine_mappings(self):
    expected = {
      "base_qwen3_4b": "llama_cpp_base_qwen3_4b",
      "cybersec_qwen_4b": "llama_cpp_cybersec_qwen_4b",
      "llama_cpp_gguf": "llama_cpp_gguf",
    }
    for engine, serving_process in expected.items():
      with self.subTest(engine=engine):
        self.assertEqual(AI_ENGINES[engine]["SERVING_PROCESS"], serving_process)
    self.assertNotIn("edgeguard_qwen_4b", AI_ENGINES)
    self.assertNotIn("edgeguard_cybersec_qwen_4b", AI_ENGINES)

  def test_ai_engine_aliases_round_trip_with_instance_ids(self):
    utils = _load_ai_engine_utils()
    instances = {
      "base_qwen3_4b": "edgeguard-base-qwen3-4b",
      "llama_cpp_gguf": "private-model-a",
      "cybersec_qwen_4b": "edgeguard-cybersec-qwen-4b",
    }
    for engine, instance_id in instances.items():
      with self.subTest(engine=engine):
        serving_process = AI_ENGINES[engine]["SERVING_PROCESS"]
        self.assertEqual(
          utils.get_serving_process_given_ai_engine((engine, instance_id)),
          (serving_process, instance_id),
        )
        self.assertEqual(
          utils.get_ai_engine_given_serving_process((serving_process, instance_id)),
          (engine, instance_id),
        )

  def test_profiles_keep_model_identity_and_cpu_bounds(self):
    for engine, profile_args in self.PROFILES.items():
      filename, class_name, model_name, model_filename, instance_id = profile_args
      with self.subTest(engine=engine):
        loaded = _load_profile(filename, class_name)
        config = loaded.config
        self.assertIs(loaded.cls.CONFIG, config)
        self.assertEqual(config["DEFAULT_DEVICE"], "cpu")
        self.assertEqual(config["N_GPU_LAYERS"], 0)
        self.assertEqual(config["N_THREADS"], 4)
        self.assertEqual(config["MODEL_N_CTX"], 4096)
        self.assertEqual(config["MODEL_NAME"], model_name)
        self.assertEqual(config["MODEL_FILENAME"], model_filename)
        self.assertEqual(config["MODEL_INSTANCE_ID"], instance_id)
        self.assertNotIn("MODEL_API_KEY", config)

  def test_generic_gguf_profile_carries_no_model_identity(self):
    loaded = _load_profile("llama_cpp_gguf.py", "LlamaCppGguf")
    config = loaded.config
    self.assertIs(loaded.cls.CONFIG, config)
    self.assertEqual(config["DEFAULT_DEVICE"], "cpu")
    self.assertEqual(config["N_GPU_LAYERS"], 0)
    for key in ("MODEL_NAME", "MODEL_FILENAME", "MODEL_PATH", "MODEL_REVISION", "MODEL_INSTANCE_ID"):
      with self.subTest(key=key):
        self.assertIsNone(config.get(key))
    self.assertNotIn("MODEL_API_KEY", config)
    self.assertNotIn("ratio1/", loaded.source)

  def test_llm_serving_relevance_gate_matches_own_server_name(self):
    check_relevant_input = _load_llm_serving_relevance_gate()
    serving = _FakeLlmServing(server_name="LLAMA_CPP_GGUF_PRIVATE-MODEL-A")

    def request(content):
      return {"SIGNATURE": "LLM_INFERENCE_API", "JEEVES_CONTENT": content}

    self.assertTrue(check_relevant_input(serving, request({"TARGET_SERVING_NAME": "llama_cpp_gguf_private-model-a"})))
    self.assertFalse(check_relevant_input(serving, request({"TARGET_SERVING_NAME": "LLAMA_CPP_CYBERSEC_QWEN_4B"})))
    self.assertTrue(check_relevant_input(serving, request({"MESSAGES": []})))
    self.assertTrue(check_relevant_input(serving, request({"TARGET_SERVING_NAME": ""})))

  def test_profiles_are_configuration_only_generic_subclasses(self):
    for filename, class_name in (
      ("llama_cpp_base_qwen3_4b.py", "LlamaCppBaseQwen34B"),
      ("llama_cpp_gguf.py", "LlamaCppGguf"),
      ("llama_cpp_cybersec_qwen_4b.py", "LlamaCppCybersecQwen4B"),
    ):
      with self.subTest(filename=filename):
        source = (PROFILE_DIR / filename).read_text(encoding="utf-8")
        self.assertIn("nlp.llama_cpp_base import LlamaCppBaseServingProcess", source)
        self.assertNotIn("llama_cpp_edgeguard_base", source)
        self.assertNotIn("MODEL_API_KEY", source)
        self.assertNotIn("MODEL_REVISION", source)
        self.assertNotIn("EXPECTED_MODEL_SHA256", source)
        self.assertNotIn("WORKER_MODULE_SHA256", source)
        module = ast.parse(source)
        profile_class = next(
          node for node in module.body
          if isinstance(node, ast.ClassDef) and node.name == class_name
        )
        self.assertTrue(all(isinstance(node, (ast.Assign, ast.AnnAssign)) for node in profile_class.body))

  def test_edgeguard_specific_serving_modules_are_removed(self):
    self.assertFalse((PROFILE_DIR / "llama_cpp_edgeguard_base.py").exists())
    self.assertFalse((PROFILE_DIR / "llama_cpp_edgeguard_cybersec_qwen_4b.py").exists())
    self.assertFalse((PROFILE_DIR / "llama_cpp_edgeguard_qwen_4b.py").exists())

  def test_production_plugin_loader_resolves_base_qwen3_profile_class(self):
    module_name = (
      "extensions.serving.default_inference.nlp.llama_cpp_base_qwen3_4b"
    )
    base_module_name = "extensions.serving.default_inference.nlp.llama_cpp_base"
    fake_base_module = types.ModuleType(base_module_name)
    fake_base_module.LlamaCppBaseServingProcess = _FakeBaseServingProcess
    loader_class = _load_plugins_manager_mixin()
    loader = object.__new__(loader_class)
    loader.P = lambda *_args, **_kwargs: None
    loader._get_plugin_by_name = lambda *_args, **_kwargs: module_name

    try:
      with patch.dict(sys.modules, {base_module_name: fake_base_module}):
        module, class_name, class_def, config = loader._get_module_name_and_class(
          locations=["extensions.serving.default_inference.nlp"],
          name="llama_cpp_base_qwen3_4b",
        )
    finally:
      sys.modules.pop(module_name, None)

    self.assertEqual(module.__name__, module_name)
    self.assertEqual(class_name, "LlamaCppBaseQwen34B")
    self.assertIs(class_def.CONFIG, module._CONFIG)
    self.assertEqual(config["MODEL_INSTANCE_ID"], "edgeguard-base-qwen3-4b")

  def test_generic_llama_cpp_loads_all_public_profile_paths(self):
    for engine, profile_args in self.PROFILES.items():
      filename, class_name, model_name, model_filename, _instance_id = profile_args
      loaded = _load_profile(filename, class_name)
      with self.subTest(engine=engine), tempfile.TemporaryDirectory() as tmpdir:
        model_path = Path(tmpdir) / model_filename
        model_path.write_bytes(b"gguf")
        process = _make_llama_cpp_process(
          cfg_model_path=str(model_path),
          cfg_model_name=model_name,
          cfg_model_filename=model_filename,
        )

        self.assertIsNone(process._load_model())
        self.assertEqual(len(_FakeLlama.calls), 1)
        call_type, kwargs = _FakeLlama.calls[0]
        self.assertEqual(call_type, "local")
        self.assertEqual(kwargs["model_path"], str(model_path))
        self.assertEqual(kwargs["n_threads"], loaded.config["N_THREADS"])
        self.assertEqual(process.safe_load_model_args["model_id"], model_filename)
        self.assertEqual(process.safe_load_model_args["model_str_id"], model_filename)
        self.assertEqual(process.get_model_name(), model_filename)
        self.assertFalse(any(str(model_path.parent) in message for message in process.messages))

  def test_generic_llama_cpp_remote_loading_forwards_token_and_revision(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      downloaded = Path(tmpdir) / "model.gguf"
      downloaded.write_bytes(b"gguf")
      calls = []
      process = _make_llama_cpp_process(
        cfg_model_path="  ",
        cfg_model_revision="revision-123",
      )
      process.hf_token = "private-test-token"
      process._download_hf_model = lambda model_id, filename, revision: calls.append(
        (model_id, filename, revision, process.hf_token)
      ) or str(downloaded)

      process._load_model()

    self.assertEqual(calls, [("org/repo", "model.gguf", "revision-123", "private-test-token")])
    self.assertEqual(len(_FakeLlama.calls), 1)
    call_type, kwargs = _FakeLlama.calls[0]
    self.assertEqual(call_type, "local")
    self.assertEqual(kwargs["model_path"], str(downloaded))
    self.assertEqual(process.safe_load_model_args["model_id"], "org/repo")
    self.assertEqual(process.safe_load_model_args["model_str_id"], "org/repo/model.gguf")
    self.assertFalse(any("private-test-token" in message for message in process.messages))

  def test_generic_llama_cpp_missing_model_path_error_is_sanitized(self):
    with tempfile.TemporaryDirectory() as tmpdir:
      model_path = Path(tmpdir) / "missing.gguf"
      process = _make_llama_cpp_process(cfg_model_path=str(model_path))

      with self.assertRaises(FileNotFoundError) as raised:
        process._load_model()

    self.assertIn("missing.gguf", str(raised.exception))
    self.assertNotIn(tmpdir, str(raised.exception))

  def test_generic_llama_cpp_uses_origin_zero_temperature_fallback_and_omits_seed(self):
    process = _make_llama_cpp_process()
    process.check_relevant_input = lambda _input: True
    process.maybe_add_context_to_messages = lambda messages, context: messages
    process.get_default_response_format = lambda: {"type": "text"}
    process.process_predict_kwargs = lambda kwargs: kwargs

    preprocessed = process._pre_process({
      "DATA": [{
        "JEEVES_CONTENT": {
          "MESSAGES": [{"role": "user", "content": "Explain"}],
          "TEMPERATURE": 0.0,
          "SEED": 42,
        },
      }],
    })

    self.assertEqual(preprocessed[0][0]["temperature"], 0.7)
    self.assertNotIn("seed", preprocessed[0][0])
    self.assertEqual(preprocessed[2], [{"REQUEST_ID": None}])

  def test_generic_llama_cpp_retries_invalid_output_and_logs_raw_text(self):
    process = _make_llama_cpp_process()
    process._tps = []
    process.time = lambda: 1.0
    process.maybe_process_text = lambda text, _method: text
    process.check_condition = lambda text, _condition: text == "second-output"
    outputs = iter(["first-output", "second-output"])
    completion_calls = []

    def complete(**_kwargs):
      completion_calls.append(True)
      text = next(outputs)
      return {
        "choices": [{"message": {"content": text}, "finish_reason": "stop"}],
        "usage": {"completion_tokens": 1},
      }

    process.model = types.SimpleNamespace(create_chat_completion=complete)
    result = process._predict([
      [{"max_tokens": 8}],
      [[{"role": "user", "content": "fixture"}]],
      [{"REQUEST_ID": "req-generic"}],
      ["must-pass"],
      [None],
      [0],
      1,
    ])

    self.assertEqual(len(completion_calls), 2)
    self.assertEqual(result["text"], ["second-output"])
    self.assertTrue(any("first-output" in message for message in process.messages))
    self.assertTrue(any("second-output" in message for message in process.messages))


if __name__ == "__main__":
  unittest.main()
