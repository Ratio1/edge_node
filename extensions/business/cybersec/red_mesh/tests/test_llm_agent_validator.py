"""Phase 2 of PR 388 remediation — probe-output validator.

_validate_probe_result classifies probe dicts as valid, coerce-able
(missing severity → UNKNOWN, non-list findings → coerced empty), or
quarantined (non-dict). Quarantined entries are surfaced in the
_malformed_probe_results block of the shaped LLM payload so the
model can deprioritize them instead of treating garbage as signal.
"""

import unittest
from unittest.mock import MagicMock

from extensions.business.cybersec.red_mesh.mixins.redmesh_llm_agent import (
  _RedMeshLlmAgentMixin,
)
from extensions.business.cybersec.red_mesh.tests.fixtures.multi_probe_report import (
  build_aggregated_report,
)


class _Host(_RedMeshLlmAgentMixin):
  def __init__(self):
    super().__init__()
    self.P = MagicMock()
    self.Pd = MagicMock()


class TestValidateProbeResult(unittest.TestCase):

  def test_non_dict_is_quarantined(self):
    host = _Host()
    self.assertEqual(
      host._validate_probe_result("_service_info_x", "not a dict"),
      (None, "non_dict"),
    )
    self.assertEqual(
      host._validate_probe_result("_service_info_x", None),
      (None, "non_dict"),
    )
    self.assertEqual(
      host._validate_probe_result("_service_info_x", 42),
      (None, "non_dict"),
    )

  def test_non_list_findings_coerced_with_reason(self):
    host = _Host()
    clean, reason = host._validate_probe_result(
      "_service_info_x", {"banner": "ok", "findings": "oops"},
    )
    self.assertEqual(reason, "findings_not_list")
    self.assertEqual(clean["findings"], [])
    self.assertEqual(clean["banner"], "ok")

  def test_missing_severity_defaults_to_unknown(self):
    host = _Host()
    clean, reason = host._validate_probe_result("_probe", {
      "findings": [{"title": "no severity here"}],
    })
    self.assertIsNone(reason)
    self.assertEqual(clean["findings"][0]["severity"], "UNKNOWN")

  def test_invalid_severity_coerced_to_unknown(self):
    host = _Host()
    clean, _ = host._validate_probe_result("_probe", {
      "findings": [{"title": "bad", "severity": "EXTREME_OMGWTFBBQ"}],
    })
    self.assertEqual(clean["findings"][0]["severity"], "UNKNOWN")

  def test_valid_severity_preserved(self):
    host = _Host()
    clean, _ = host._validate_probe_result("_probe", {
      "findings": [
        {"title": "crit", "severity": "CRITICAL"},
        {"title": "hi", "severity": "high"},  # lowercase normalized
      ],
    })
    self.assertEqual(clean["findings"][0]["severity"], "CRITICAL")
    self.assertEqual(clean["findings"][1]["severity"], "HIGH")

  def test_non_dict_finding_dropped_silently(self):
    """Individual malformed findings inside an otherwise-valid probe
    dict are dropped without raising — the probe's other findings
    still make it through.
    """
    host = _Host()
    clean, reason = host._validate_probe_result("_probe", {
      "findings": [
        "not a dict",
        {"title": "good", "severity": "HIGH"},
        42,
      ],
    })
    self.assertIsNone(reason)
    self.assertEqual(len(clean["findings"]), 1)
    self.assertEqual(clean["findings"][0]["title"], "good")


class TestMalformedProbeQuarantine(unittest.TestCase):

  def test_quarantine_surfaces_in_payload(self):
    """Port 9999 has a malformed _service_info_generic. After
    payload shaping the entry appears in _malformed_probe_results
    but NOT in top_findings.
    """
    host = _Host()
    report = build_aggregated_report()
    payload = host._build_llm_analysis_payload(
      "job-quar", report,
      {"target": "x", "scan_type": "network"},
      "security_assessment",
    )
    self.assertIn("_malformed_probe_results", payload)
    malformed = payload["_malformed_probe_results"]
    self.assertTrue(any(
      m["method"] == "_service_info_generic" and m["port"] == 9999
      for m in malformed
    ))
    # "oops_not_a_list" must not be iterated as char-findings.
    for f in payload["top_findings"]:
      self.assertNotIn("oops", (f.get("title") or ""))


if __name__ == '__main__':
  unittest.main()
