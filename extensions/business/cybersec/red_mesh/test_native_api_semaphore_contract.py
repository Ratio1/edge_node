import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[4]


class NativeApiSemaphoreContractTests(unittest.TestCase):

  def _read(self, relative_path):
    return (ROOT / relative_path).read_text()

  def test_native_emitters_use_api_ip_only_when_not_preserving_legacy_aliases(self):
    for relative_path in [
      "extensions/business/cybersec/red_mesh/redmesh_llm_agent_api.py",
      "plugins/business/cerviguard/local_serving_api.py",
    ]:
      source = self._read(relative_path)
      self.assertIn("self.semaphore_set_env('API_IP'", source, relative_path)
      self.assertIn("self.semaphore_set_env('API_PORT'", source, relative_path)
      self.assertIn("self.semaphore_set_env('API_URL'", source, relative_path)
      self.assertNotIn("self.semaphore_set_env('API_HOST'", source, relative_path)

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

  def test_redmesh_llm_agent_consumer_prefers_api_ip(self):
    source = self._read("extensions/business/cybersec/red_mesh/redmesh_llm_agent_mixin.py")
    self.assertIn("env.get('API_IP') or env.get('API_HOST') or env.get('HOST')", source)
    self.assertIn("env.get('PORT') or env.get('API_PORT')", source)


if __name__ == "__main__":
  unittest.main()
