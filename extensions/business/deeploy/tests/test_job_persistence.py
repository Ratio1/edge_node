import unittest
# The writer and rolling-upgrade reader share the process-wide holder.
from unittest.mock import patch

from ratio1.bc.base import BaseBlockEngine

from extensions.business.deeploy.deeploy_job_mixin import _DeeployJobMixin


class _R1FSStub:
  def __init__(self):
    self.add_json_calls = []
    self.calculate_json_cid_calls = []
    self.get_json_calls = []

  def add_json(self, *args, **kwargs):
    self.add_json_calls.append((args, kwargs))
    return "cid"

  def calculate_json_cid(self, *args, **kwargs):
    self.calculate_json_cid_calls.append((args, kwargs))
    return "cid"

  def get_json(self, *args, **kwargs):
    self.get_json_calls.append((args, kwargs))
    return {"pipeline": "ok"}


class _JobPersistencePlugin(_DeeployJobMixin):
  def __init__(self):
    self.r1fs = _R1FSStub()
    self.messages = []

  def Pd(self, message, *args, **kwargs):
    self.messages.append(str(message))

  def json_dumps(self, obj, **kwargs):
    return str(obj)

  def _redact_per_node_config_for_log(self, value):
    return "***redacted***"

  def _get_pipeline_from_cstore(self, job_id):
    return "cid"


class DeeployJobPersistenceTests(unittest.TestCase):

  def test_save_pipeline_to_r1fs_suppresses_raw_r1fs_logs(self):
    """Save a deployment configuration without logging its raw contents.

    Verify that the SDK selects the random nonce, that writing protected
    copies requires the enabled setting, and that the pipeline summary
    logs a redaction in place of the configured value.

    Parameters
    ----------
    None

    Returns
    -------
    None

    Examples
    --------
    >>> DeeployJobPersistenceTests().test_save_pipeline_to_r1fs_suppresses_raw_r1fs_logs()
    """
    plugin = _JobPersistencePlugin()

    cid = plugin._save_pipeline_to_r1fs({
      "plugins": [{
        "ENV": {
          "CRDB_PASSWORD": "secret",
        },
      }],
    })

    self.assertEqual(cid, "cid")
    self.assertEqual(plugin.r1fs.add_json_calls[0][1]["show_logs"], False)
    # Random ciphertext has no deterministic CID to predict.
    self.assertEqual(plugin.r1fs.calculate_json_cid_calls, [])
    # Default-off writes use the public passphrase with the SDK's random nonce.
    self.assertIsNone(plugin.r1fs.add_json_calls[0][1].get("nonce"))
    # No protected write occurs unless the switch is enabled.
    self.assertIsNone(plugin.r1fs.add_json_calls[0][1].get("secret"))
    serialized_logs = "\n".join(plugin.messages)
    self.assertNotIn("secret", serialized_logs)
    self.assertIn("***redacted***", serialized_logs)

  def test_pipeline_r1fs_reads_suppress_raw_r1fs_logs_by_default(self):
    plugin = _JobPersistencePlugin()

    pipeline = plugin.get_job_pipeline_from_cstore(123)

    self.assertEqual(pipeline, {"pipeline": "ok"})
    self.assertEqual(plugin.r1fs.get_json_calls[0][1]["show_logs"], False)

  def test_enabled_writer_requires_local_secret_and_uses_random_nonce(self):
    """Fail closed on missing provisioning and use random nonces once provisioned.

    Returns
    -------
    None

    Examples
    --------
    >>> self.test_enabled_writer_requires_local_secret_and_uses_random_nonce()
    """
    # Use a synthetic process-local key and exercise both provisioning states.
    plugin = _JobPersistencePlugin()
    with patch("extensions.business.deeploy.r1fs_documents.ORACLE_R1FS_WRITES", True):
      with patch.object(BaseBlockEngine, "oracle_secret", return_value=None):
        # No protected copy can be written before the holder has a secret.
        self.assertIsNone(plugin._save_pipeline_to_r1fs({"pipeline": "fake"}))
        # Missing custody cannot silently fall back to the public passphrase.
        self.assertEqual(plugin.r1fs.add_json_calls, [])
      with patch.object(BaseBlockEngine, "oracle_secret", return_value="synthetic-shared"):
        # A provisioned oracle writes using the SDK's default random nonce.
        self.assertEqual(plugin._save_pipeline_to_r1fs({"pipeline": "fake"}), "cid")
        # The request passes the provisioned secret and no fixed nonce.
        self.assertEqual(plugin.r1fs.add_json_calls[0][1]["secret"], "synthetic-shared")
        # Omitting nonce requests secure randomness from the actual SDK.
        self.assertIsNone(plugin.r1fs.add_json_calls[0][1].get("nonce"))
        # Secret values are absent from application log messages.
        self.assertNotIn("synthetic-shared", "\n".join(plugin.messages))

  def test_compatibility_reader_delegates_once_during_default_off_release(self):
    """Read newer ciphertext with local legacy fallback before writes are enabled.

    Returns
    -------
    None

    Examples
    --------
    >>> self.test_compatibility_reader_delegates_once_during_default_off_release()
    """
    # Exercise the canonical job-copy reader with the local custody holder.
    plugin = _JobPersistencePlugin()
    with patch.object(BaseBlockEngine, "oracle_secret", return_value="synthetic-shared"):
      # The SDK fetches once and handles decryption locally.
      self.assertEqual(plugin.get_pipeline_from_r1fs("cid"), {"pipeline": "ok"})
    # The fetch cannot repeat for another key.
    self.assertEqual(len(plugin.r1fs.get_json_calls), 1)
    # Both candidate passphrases were given to the same SDK read.
    self.assertEqual(plugin.r1fs.get_json_calls[0][1]["secret"], "synthetic-shared")
    # None asks the SDK to try its historical default when the first key fails.
    self.assertEqual(plugin.r1fs.get_json_calls[0][1]["fallback_secrets"], (None,))


if __name__ == "__main__":
  unittest.main()
