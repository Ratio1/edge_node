import importlib.util
import unittest
from pathlib import Path
from unittest.mock import MagicMock


def _load_config_module():
  path = Path(__file__).resolve().parents[1] / "services" / "config.py"
  spec = importlib.util.spec_from_file_location("redmesh_config_under_test", path)
  module = importlib.util.module_from_spec(spec)
  spec.loader.exec_module(module)
  return module


_config = _load_config_module()


class LlmAgentConfigTests(unittest.TestCase):
  def test_default_model_provenance_is_local_cybersecqwen(self):
    owner = MagicMock()
    owner.cfg_llm_agent = None
    owner.CONFIG = {}

    config = _config.get_llm_agent_config(owner)

    self.assertEqual(config["MODEL"], "CyberSecQwen-4B.Q4_K_M.gguf")

  def test_model_override_is_preserved(self):
    owner = MagicMock()
    owner.cfg_llm_agent = {
      "ENABLED": True,
      "MODEL": "custom-local-model",
    }

    config = _config.get_llm_agent_config(owner)

    self.assertEqual(config["MODEL"], "custom-local-model")

  def test_local_llm_model_alias_is_preserved(self):
    owner = MagicMock()
    owner.cfg_llm_agent = {
      "ENABLED": True,
      "LOCAL_LLM_MODEL": "alias-local-model",
    }

    config = _config.get_llm_agent_config(owner)

    self.assertEqual(config["MODEL"], "alias-local-model")


if __name__ == "__main__":
  unittest.main()
