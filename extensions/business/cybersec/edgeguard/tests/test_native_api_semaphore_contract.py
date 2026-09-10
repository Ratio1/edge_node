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
    self.assertIn('"edgeguard_llm_private"', source)
    self.assertIn('"edgeguard_llm_base"', source)
    self.assertIn('"edgeguard_llm_cybersec"', source)
    self.assertNotIn('"SIGNATURE": "EDGEGUARD_LLM_AGENT_API"', source)

  def test_edgeguard_playground_documents_hub_workers_with_deployment_placeholders(self):
    source = self._read("extensions/business/cybersec/edgeguard/edgeguard_playground.md")

    self.assertIn('"NAME": "edgeguard_playground_api"', source)
    self.assertIn('"AI_ENGINE": "llama_cpp_gguf"', source)
    self.assertIn('"AI_ENGINE": "base_qwen3_4b"', source)
    self.assertIn('"AI_ENGINE": "cybersec_qwen_4b"', source)
    self.assertIn('"SERVED_MODELS": ["<public-model-key>"]', source)
    self.assertIn('"MODEL_INSTANCE_ID": "private-model"', source)
    self.assertIn('"MODEL_NAME": "<hub-org>/<private-gguf-repo>"', source)
    self.assertIn('"MODEL_REVISION": "<pinned-commit-sha>"', source)
    self.assertIn('"EDGEGUARD_DEFAULT_MODEL": "<public-model-key>"', source)
    self.assertIn('"MODEL_NAME": "mradermacher/CyberSecQwen-4B-GGUF"', source)
    self.assertIn('"MODEL_REVISION": "4b369711d408b9fde0efcca155409c072b19a1f6"', source)
    self.assertIn("EE_HF_TOKEN", source)
    self.assertNotIn('"MODEL_PATH"', source)
    self.assertNotIn('"PORT": 509', source)
    self.assertNotIn("MODEL_API_KEY", source)
    self.assertNotIn("edgeguard_qwen_4b", source)
    self.assertNotIn("finetuned", source.lower().replace("fine-tuned", ""))
    self.assertNotIn("ratio1/", source)


if __name__ == "__main__":
  unittest.main()
