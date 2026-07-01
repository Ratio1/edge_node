import unittest

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
    self.assertEqual(plugin.r1fs.calculate_json_cid_calls[0][1]["show_logs"], False)
    serialized_logs = "\n".join(plugin.messages)
    self.assertNotIn("secret", serialized_logs)
    self.assertIn("***redacted***", serialized_logs)

  def test_pipeline_r1fs_reads_suppress_raw_r1fs_logs_by_default(self):
    plugin = _JobPersistencePlugin()

    pipeline = plugin.get_job_pipeline_from_cstore(123)

    self.assertEqual(pipeline, {"pipeline": "ok"})
    self.assertEqual(plugin.r1fs.get_json_calls[0][1]["show_logs"], False)


if __name__ == "__main__":
  unittest.main()
