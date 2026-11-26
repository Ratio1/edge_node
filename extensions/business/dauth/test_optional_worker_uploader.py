"""Exercise stock worker configuration with and without local MinIO credentials."""

import json
import os
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from naeural_core.config.config_manager import ConfigManager
from naeural_core.main.orchestrator_mixins import managers_init
from ratio1.logging.base_logger import BaseLogger


class TestOptionalWorkerUploader(unittest.TestCase):
  """Run the default config through the real startup methods offline."""

  def test_stock_worker_can_start_without_minio_while_mqtt_remains_required(self):
    """Keep the optional uploader out of startup only when its credentials are absent.

    Exercises the strict configuration load and manager startup with a
    broker-provided environment and no external service connections.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Examples
    --------
    >>> TestOptionalWorkerUploader().test_stock_worker_can_start_without_minio_while_mqtt_remains_required()
    """
    # Load the stock application configuration from this Edge checkout.
    path = Path(__file__).resolve().parents[3] / ".config_app.json"
    # These are the relevant values that a dAuth reply supplies during test boot.
    mqtt = {name: "worker-fixture" for name in (
      "EE_MQTT_HOST", "EE_MQTT", "EE_MQTT_PORT", "EE_MQTT_USER", "EE_MQTT_SUBTOPIC", "EE_MQTT_CERT",
    )}
    # A node with local MinIO credentials must still start the configured uploader.
    minio = {name: "local-fixture" for name in (
      "EE_MINIO_ACCESS_KEY", "EE_MINIO_UPLOAD_BUCKET", "EE_MINIO_ENDPOINT", "EE_MINIO_SECRET_KEY", "EE_MINIO_SECURE",
    )}

    for available in (False, True):
      with self.subTest(local_uploader=available):
        # Stage fresh config and a logger that uses the real environment resolver.
        manager = ConfigManager.__new__(ConfigManager)
        manager._fn_app_config = "config_app.txt"
        manager.log = SimpleNamespace(load_data_json=lambda **_kwargs: json.loads(path.read_text()),
                                      replace_secrets=BaseLogger.replace_secrets)
        manager.P = Mock()
        manager.shmem = {}
        manager.load_streams_configurations = Mock()
        # Construct only the worker filesystem stage and intercept external plugin initialization.
        worker = SimpleNamespace(_config_manager=manager, log=manager.log, P=Mock(), DEBUG=False, _app_shmem={})
        with patch.dict(os.environ, dict(mqtt, **(minio if available else {})), clear=True):
          # Run the normal app loader before its filesystem manager initializer.
          manager.load()
          with patch.object(managers_init, "FileSystemManager") as filesystem:
            managers_init._ManagersInitMixin._initialize_file_system_manager(worker)
            self.assertIn("config_communication", manager.shmem)
            self.assertIn("file_system_manager", worker._app_shmem)
            self.assertEqual(filesystem.return_value.create_file_system.called, available)

    # The uploader exception must not relax validation for MQTT.
    with patch.dict(os.environ, {key: value for key, value in mqtt.items() if key != "EE_MQTT"}, clear=True):
      with self.assertRaisesRegex(ValueError, r"EE_MQTT"):
        manager.load()

    # A node may restart with the same uploader cached before the optional setting existed.
    legacy_config = json.loads(path.read_text())
    legacy_config["FILE_UPLOAD"].pop("OPTIONAL")
    manager.log.load_data_json = lambda **_kwargs: legacy_config
    with patch.dict(os.environ, mqtt, clear=True):
      manager.load()
      self.assertIs(manager.cfg_app_file_upload["ENABLED"], False)
