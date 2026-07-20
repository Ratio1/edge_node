import unittest
from pathlib import Path

from .conftest import mock_plugin_modules


class TestApiOperationRemoval(unittest.TestCase):

  def test_operation_surface_is_absent_and_supported_endpoints_remain(self):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh import services
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    redmesh_root = Path(__file__).resolve().parents[1]
    self.assertFalse((redmesh_root / "services" / "api_operations.py").exists())
    self.assertNotIn("API_OPERATIONS", PentesterApi01Plugin.CONFIG)

    for name in (
      "DEFAULT_API_OPERATIONS_CONFIG",
      "get_api_operations_config",
      "create_analyze_job_operation",
      "get_api_operation_status",
      "cancel_api_operation",
      "get_api_operation_result",
      "maybe_start_api_operation_worker",
    ):
      self.assertFalse(hasattr(services, name), name)
      self.assertFalse(hasattr(PentesterApi01Plugin, name), name)

    self.assertTrue(callable(PentesterApi01Plugin.analyze_job))
    self.assertTrue(callable(PentesterApi01Plugin.preflight_model_test_provider))
