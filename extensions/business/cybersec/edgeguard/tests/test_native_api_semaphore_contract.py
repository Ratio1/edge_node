import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[5]


class EdgeGuardNativeApiSemaphoreContractTests(unittest.TestCase):

  def _read(self, relative_path):
    return (ROOT / relative_path).read_text()

  def test_edgeguard_native_emitters_preserve_legacy_aliases_on_top_of_fastapi_defaults(self):
    for relative_path, class_name in [
      ("extensions/business/cybersec/edgeguard/edgeguard_api.py", "EdgeguardApiPlugin"),
    ]:
      source = self._read(relative_path)
      self.assertIn(f"super({class_name}, self)._setup_semaphore_env()", source, relative_path)
      self.assertIn("self.semaphore_set_env('HOST', localhost_ip)", source, relative_path)
      self.assertIn("self.semaphore_set_env('API_HOST', localhost_ip)", source, relative_path)
      self.assertIn("self.semaphore_set_env('PORT', str(port))", source, relative_path)
      self.assertIn("self.semaphore_set_env('URL', 'http://{}:{}'.format(localhost_ip, port))", source, relative_path)
      self.assertIn("self.semaphore_set_env('API_PORT', str(port))", source, relative_path)
      self.assertIn("self.semaphore_set_env('API_URL', 'http://{}:{}'.format(localhost_ip, port))", source, relative_path)

  def test_edgeguard_playground_uses_one_semaphored_api_pipeline(self):
    source = self._read("extensions/business/cybersec/edgeguard/edgeguard_playground.md")

    self.assertIn('"SEMAPHORE": "edgeguard_api"', source)
    self.assertIn('"SIGNATURE": "LLM_INFERENCE_API"', source)
    self.assertIn('"SIGNATURE": "EDGEGUARD_API"', source)
    self.assertIn('"edgeguard_llm_finetuned"', source)
    self.assertIn('"edgeguard_llm_base"', source)
    self.assertIn('"edgeguard_llm_cybersec"', source)
    self.assertNotIn('"SIGNATURE": "EDGEGUARD_LLM_AGENT_API"', source)

  def test_edgeguard_playground_documents_pinned_hub_workers_without_model_paths(self):
    source = self._read("extensions/business/cybersec/edgeguard/edgeguard_playground.md")

    self.assertIn('"NAME": "edgeguard_playground_api"', source)
    self.assertIn('"AI_ENGINE": "edgeguard_qwen_4b"', source)
    self.assertIn('"AI_ENGINE": "base_qwen3_4b"', source)
    self.assertIn('"AI_ENGINE": "cybersec_qwen_4b"', source)
    self.assertIn('"MODEL_NAME": "mradermacher/CyberSecQwen-4B-GGUF"', source)
    self.assertIn('"MODEL_FILENAME": "CyberSecQwen-4B.Q4_K_M.gguf"', source)
    self.assertIn('"MODEL_REVISION": "4b369711d408b9fde0efcca155409c072b19a1f6"', source)
    self.assertIn("EE_HF_TOKEN", source)
    self.assertIn("reads the Hub\ntoken from the process environment", source)
    self.assertNotIn('"MODEL_PATH"', source)
    self.assertNotIn('"PORT": 509', source)
    self.assertNotIn("edgeguard_cybersec_qwen_4b", source)


if __name__ == "__main__":
  unittest.main()
