import unittest
from pathlib import Path


class SensitivePlatformLogTests(unittest.TestCase):
  def test_platform_logs_do_not_render_secret_bearing_values_or_commands(self):
    root = Path(__file__).resolve().parents[1]
    runner_source = (root / "container_app_runner.py").read_text(encoding="utf-8")
    utils_source = (root / "container_utils.py").read_text(encoding="utf-8")

    self.assertNotIn("self.json_dumps(self.env)", runner_source)
    self.assertNotIn("' '.join(command)", runner_source)
    self.assertNotIn("Running container exec command: {shell_cmd}", runner_source)
    self.assertNotIn("Start command: {self._start_command", runner_source)
    self.assertNotIn("{sanitized_key} = {value}", utils_source)
    self.assertNotIn("{variable_name} = {variable_value}", utils_source)


if __name__ == "__main__":
  unittest.main()
