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
    self.assertEqual(config["PROVIDER"], "local")
    self.assertEqual(config["PROMPT_PROFILE"], "auto")
    self.assertEqual(config["LOCAL_PROMPT_PROFILE"], "local_cybersecqwen_quota_v1")
    self.assertEqual(config["REMOTE_PROMPT_PROFILE"], "remote_rich_v1")
    self.assertEqual(config["STRUCTURED_MAX_FINDINGS"], 6)
    self.assertEqual(config["STRUCTURED_MAX_TOKENS"], 2048)

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

  def test_prompt_profile_and_provider_overrides_are_preserved(self):
    owner = MagicMock()
    owner.cfg_llm_agent = {
      "ENABLED": True,
      "PROVIDER": "deepseek",
      "MODEL": "deepseek-chat",
      "PROMPT_PROFILE": "remote_rich_v1",
      "STRUCTURED_MAX_FINDINGS": 12,
      "STRUCTURED_MAX_TOKENS": 3072,
      "STRUCTURED_TEMPERATURE": "0.25",
    }

    config = _config.get_llm_agent_config(owner)

    self.assertEqual(config["PROVIDER"], "deepseek")
    self.assertEqual(config["MODEL"], "deepseek-chat")
    self.assertEqual(config["PROMPT_PROFILE"], "remote_rich_v1")
    self.assertEqual(config["STRUCTURED_MAX_FINDINGS"], 12)
    self.assertEqual(config["STRUCTURED_MAX_TOKENS"], 3072)
    self.assertEqual(config["STRUCTURED_TEMPERATURE"], 0.25)


if __name__ == "__main__":
  unittest.main()
