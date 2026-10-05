"""The flat walk names each probe as the report should print it (RM-118).

PDF group headers printed method names such as `_web_test_csrf`. Each probe
registers a `display_name`; the flat walk stamps it so the report can use it.
"""

import unittest

from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin


class _Host(_RiskScoringMixin):
  pass


def _walk(section, probe, finding):
  return _Host()._compute_risk_and_findings({
    "target": "app.test", "port_protocols": {"80": "http"},
    section: {"80": {probe: {"findings": [finding]}}},
  })[1]


class TestProbeDisplayName(unittest.TestCase):

  def _finding(self):
    return {"title": "POST form at / missing CSRF token", "severity": "MEDIUM", "confidence": "firm",
            "affected_assets": [{"host": "app.test", "port": 80, "url": "/", "parameter": "/a", "method": "POST"}]}

  def test_a_registered_probe_gets_its_display_name(self):
    [item] = _walk("web_tests_info", "_web_test_csrf", self._finding())
    self.assertEqual(item["probe"], "_web_test_csrf")
    self.assertEqual(item["probe_display_name"], "CSRF token presence")

  def test_an_unregistered_probe_keeps_only_its_id(self):
    [item] = _walk("web_tests_info", "_not_a_registered_probe", self._finding())
    self.assertNotIn("probe_display_name", item)

  def test_the_name_moves_neither_identity_nor_signature(self):
    [named] = _walk("web_tests_info", "_web_test_csrf", self._finding())
    from extensions.business.cybersec.red_mesh.models.finding_identity import content_hash, dedup_key
    bare = {k: v for k, v in named.items() if k != "probe_display_name"}
    self.assertEqual(dedup_key(named), dedup_key(bare))
    self.assertEqual(content_hash(named), content_hash(bare))


if __name__ == "__main__":
  unittest.main()
