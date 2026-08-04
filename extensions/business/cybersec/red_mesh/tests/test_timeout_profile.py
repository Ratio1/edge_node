import re
import unittest
from pathlib import Path

from extensions.business.cybersec.red_mesh.constants import (
  TIMEOUT_PROFILE_STANDARD,
  TIMEOUT_PROFILE_THOROUGH,
  resolve_target_response_timeout,
)
from extensions.business.cybersec.red_mesh.models.archive import JobConfig
from extensions.business.cybersec.red_mesh.services.launch_api import (
  normalize_network_timeout_profile,
)


def _minimal_job_config(**overrides):
  values = {
    "target": "10.0.0.10",
    "start_port": 1,
    "end_port": 443,
    "exceptions": [],
    "distribution_strategy": "SLICE",
    "port_order": "SEQUENTIAL",
    "nr_local_workers": 1,
    "enabled_features": [],
    "excluded_features": [],
    "run_mode": "SINGLEPASS",
  }
  values.update(overrides)
  return values


class TestTimeoutProfileContract(unittest.TestCase):
  def test_standard_preserves_every_supported_wait(self):
    for wait in (0.3, 2, 3, 4, 5):
      self.assertEqual(resolve_target_response_timeout(TIMEOUT_PROFILE_STANDARD, wait), wait)

  def test_thorough_uses_exact_capped_mapping(self):
    self.assertEqual(
      [resolve_target_response_timeout(TIMEOUT_PROFILE_THOROUGH, wait) for wait in (0.3, 2, 3, 4, 5)],
      [0.9, 6.0, 9.0, 12.0, 15.0],
    )

  def test_launch_normalization_defaults_and_rejects_invalid_values(self):
    self.assertEqual(normalize_network_timeout_profile(None), (TIMEOUT_PROFILE_STANDARD, None))
    self.assertEqual(normalize_network_timeout_profile("thorough"), (TIMEOUT_PROFILE_THOROUGH, None))
    value, error = normalize_network_timeout_profile("patient")
    self.assertIsNone(value)
    self.assertEqual(error["error"], "validation_error")
    self.assertIn("STANDARD or THOROUGH", error["message"])

  def test_job_config_roundtrip_and_legacy_default(self):
    thorough = JobConfig(**_minimal_job_config(timeout_profile=TIMEOUT_PROFILE_THOROUGH))
    self.assertEqual(JobConfig.from_dict(thorough.to_dict()).timeout_profile, TIMEOUT_PROFILE_THOROUGH)
    self.assertEqual(JobConfig.from_dict(_minimal_job_config()).timeout_profile, TIMEOUT_PROFILE_STANDARD)


class TestTimeoutProfileCallSiteAudit(unittest.TestCase):
  """Keep ordinary network waits profiled and explicit exclusions unchanged."""

  def test_network_worker_waits_use_resolver_except_timing_probe(self):
    root = Path(__file__).resolve().parents[1]
    sources = [root / "worker" / "pentest_worker.py"]
    sources.extend(sorted((root / "worker" / "service").glob("*.py")))
    sources.extend(sorted((root / "worker" / "web").glob("*.py")))

    ordinary_literal = re.compile(r"(?<!_target_timeout\()\b(?:auth_)?timeout\s*=\s*(?:0\.3|2|3|4|5)\b")
    socket_literal = re.compile(r"\.settimeout\((?:0\.3|2|3|4|5)\)")
    unresolved = []
    resolver_uses = 0
    for source in sources:
      text = source.read_text(encoding="utf-8")
      resolver_uses += text.count("_target_timeout(")
      for line_nr, line in enumerate(text.splitlines(), start=1):
        if ordinary_literal.search(line) or socket_literal.search(line):
          unresolved.append((source.relative_to(root).as_posix(), line_nr, line.strip()))

    self.assertGreaterEqual(resolver_uses, 150)
    self.assertEqual(len(unresolved), 1)
    path, _line_nr, line = unresolved[0]
    self.assertEqual(path, "worker/web/injection.py")
    self.assertIn("requests.get(url_sleep, timeout=5", line)

  def test_dune_and_timing_thresholds_remain_unprofiled(self):
    root = Path(__file__).resolve().parents[1]
    worker_text = (root / "worker" / "pentest_worker.py").read_text(encoding="utf-8")
    injection_text = (root / "worker" / "web" / "injection.py").read_text(encoding="utf-8")
    self.assertIn("time.sleep(delay)", worker_text)
    self.assertIn("requests.get(url_sleep, timeout=5", injection_text)
    self.assertIn("if elapsed >= 2.0:", injection_text)


if __name__ == "__main__":
  unittest.main()
