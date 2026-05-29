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
    self.assertEqual(config["MODEL_N_CTX"], 4096)
    self.assertEqual(config["DEFAULT_MAX_TOKENS"], 1024)
    self.assertEqual(config["MODEL_INSTANCE_ID"], "cybersecqwen-4b")
    self.assertEqual(config["MODEL_NAME"], "mradermacher/CyberSecQwen-4B-GGUF")
    self.assertEqual(config["MODEL_FILENAME"], "CyberSecQwen-4B.Q4_K_M.gguf")


if __name__ == "__main__":
  unittest.main()
