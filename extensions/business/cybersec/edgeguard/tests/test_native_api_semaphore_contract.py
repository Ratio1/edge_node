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

  def test_edgeguard_playground_uses_api_semaphore_for_ui_base_url(self):
    source = self._read("extensions/business/cybersec/edgeguard/edgeguard_playground.md")

    self.assertIn('"SEMAPHORE": "edgeguard_api"', source)
    self.assertIn('"SEMAPHORED_KEYS": ["edgeguard_api"]', source)
    self.assertIn('"DYNAMIC_ENV": {', source)
    self.assertIn('"EDGEGUARD_API_BASE_URL": [', source)
    self.assertIn('"type": "shmem"', source)
    self.assertIn('"path": ["edgeguard_api", "API_URL"]', source)
    self.assertNotIn('"EDGEGUARD_API_BASE_URL": "http://127.0.0.1:5055"', source)
    self.assertNotIn('"SIGNATURE": "EDGEGUARD_LLM_AGENT_API"', source)
    self.assertNotIn("EDGEGUARD_LLM_AGENT_PORT", source)

  def test_edgeguard_playground_documents_generic_local_path_workers(self):
    source = self._read("extensions/business/cybersec/edgeguard/edgeguard_playground.md")

    self.assertIn('"NAME": "edgeguard_llm_finetuned_api"', source)
    self.assertIn('"AI_ENGINE": "edgeguard_qwen_4b"', source)
    self.assertIn("snapshots/369066092b5eef41c9093474ff7142cc530a853f/", source)
    self.assertIn('"NAME": "edgeguard_llm_base_api"', source)
    self.assertIn('"AI_ENGINE": "base_qwen_4b"', source)
    self.assertIn('"MODEL_PATH": "/edge_node/_local_cache/egm030-qwen3-base/', source)
    self.assertIn('"NAME": "edgeguard_llm_cybersec_api"', source)
    self.assertIn('"AI_ENGINE": "cybersec_qwen_4b"', source)
    self.assertIn('"PORT": 5092', source)
    self.assertIn('"MODEL_NAME": "mradermacher/CyberSecQwen-4B-GGUF"', source)
    self.assertIn('"MODEL_FILENAME": "CyberSecQwen-4B.Q4_K_M.gguf"', source)
    self.assertIn('"MODEL_INSTANCE_ID": "edgeguard-cybersec-qwen-4b"', source)
    self.assertIn("snapshots/4b369711d408b9fde0efcca155409c072b19a1f6/", source)
    self.assertIn('"EDGEGUARD_LLM_CYBERSEC_URLS": "http://127.0.0.1:5092"', source)
    self.assertIn("`MODEL_PATH` is the artifact-source setting", source)
    self.assertNotIn("MODEL_REVISION", source)
    self.assertNotIn("edgeguard_cybersec_qwen_4b", source)


if __name__ == "__main__":
  unittest.main()
