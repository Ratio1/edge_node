import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[4]


class NativeApiSemaphoreContractTests(unittest.TestCase):

  def _read(self, relative_path):
    return (ROOT / relative_path).read_text()

  def test_pentester_preserves_legacy_aliases_on_top_of_fastapi_defaults(self):
    source = self._read("extensions/business/cybersec/red_mesh/pentester_api_01.py")
    self.assertIn("super(PentesterApi01Plugin, self)._setup_semaphore_env()", source)
    self.assertIn("self.semaphore_set_env('HOST', localhost_ip)", source)
    self.assertIn("self.semaphore_set_env('API_HOST', localhost_ip)", source)
    self.assertIn("self.semaphore_set_env('PORT', str(port))", source)
    self.assertIn("self.semaphore_set_env('URL', 'http://{}:{}'.format(localhost_ip, port))", source)

  def test_base_inference_keeps_api_host_alias_on_top_of_fastapi_defaults(self):
    source = self._read("extensions/business/edge_inference_api/base_inference_api.py")
    self.assertIn("super(BaseInferenceApiPlugin, self)._setup_semaphore_env()", source)
    self.assertIn("self.semaphore_set_env('API_HOST', localhost_ip)", source)

  def test_other_native_emitters_preserve_legacy_aliases_on_top_of_fastapi_defaults(self):
    for relative_path, class_name in [
      ("extensions/business/cybersec/red_mesh/redmesh_llm_agent_api.py", "RedMeshLlmAgentApiPlugin"),
      ("extensions/business/cybersec/red_mesh/edgeguard_llm_agent_api.py", "EdgeguardLlmAgentApiPlugin"),
      ("extensions/business/cybersec/red_mesh/edgeguard_api.py", "EdgeguardApiPlugin"),
      ("plugins/business/cerviguard/local_serving_api.py", "LocalServingApiPlugin"),
    ]:
      source = self._read(relative_path)
      self.assertIn(f"super({class_name}, self)._setup_semaphore_env()", source, relative_path)
      self.assertIn("self.semaphore_set_env('HOST', localhost_ip)", source, relative_path)
      self.assertIn("self.semaphore_set_env('API_HOST', localhost_ip)", source, relative_path)
      self.assertIn("self.semaphore_set_env('PORT', str(port))", source, relative_path)
      self.assertIn("self.semaphore_set_env('URL', 'http://{}:{}'.format(localhost_ip, port))", source, relative_path)
      self.assertIn("self.semaphore_set_env('API_PORT', str(port))", source, relative_path)
      self.assertIn("self.semaphore_set_env('API_URL', 'http://{}:{}'.format(localhost_ip, port))", source, relative_path)

  def test_redmesh_llm_agent_consumer_prefers_api_ip(self):
    source = self._read("extensions/business/cybersec/red_mesh/mixins/llm_agent_mixin.py")
    self.assertIn("env.get('API_IP') or env.get('API_HOST') or env.get('HOST')", source)
    self.assertIn("env.get('PORT') or env.get('API_PORT')", source)

  def test_edgeguard_playground_uses_api_semaphore_for_ui_base_url(self):
    source = self._read("extensions/business/cybersec/red_mesh/edgeguard_playground.md")

    self.assertIn('"SEMAPHORE": "edgeguard_api"', source)
    self.assertIn('"SEMAPHORED_KEYS": ["edgeguard_api"]', source)
    self.assertIn('"DYNAMIC_ENV": {', source)
    self.assertIn('"EDGEGUARD_API_BASE_URL": [', source)
    self.assertIn('"type": "shmem"', source)
    self.assertIn('"path": ["edgeguard_api", "API_URL"]', source)
    self.assertNotIn('"EDGEGUARD_API_BASE_URL": "http://127.0.0.1:5055"', source)


if __name__ == "__main__":
  unittest.main()
