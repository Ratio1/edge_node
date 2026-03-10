"""Tests for GrayboxFinding model."""

import json
import unittest

from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding


class TestGrayboxFinding(unittest.TestCase):

  def _make_finding(self, **overrides):
    defaults = dict(
      scenario_id="PT-A01-01",
      title="IDOR on /api/records/",
      status="vulnerable",
      severity="HIGH",
      owasp="A01:2021",
      cwe=["CWE-639", "CWE-862"],
      attack=["T1078"],
      evidence=["endpoint=/api/records/2/", "status=200"],
      replay_steps=["Login as user A", "GET /api/records/2/"],
      remediation="Enforce object-level authorization.",
    )
    defaults.update(overrides)
    return GrayboxFinding(**defaults)

  def test_to_dict_roundtrip(self):
    """to_dict() produces a JSON-safe dict."""
    f = self._make_finding()
    d = f.to_dict()
    self.assertIsInstance(d, dict)
    # JSON serializable
    serialized = json.dumps(d)
    self.assertIsInstance(json.loads(serialized), dict)
    # All fields present
    self.assertEqual(d["scenario_id"], "PT-A01-01")
    self.assertEqual(d["title"], "IDOR on /api/records/")
    self.assertEqual(d["status"], "vulnerable")
    self.assertEqual(d["severity"], "HIGH")
    self.assertEqual(d["owasp"], "A01:2021")
    self.assertEqual(d["cwe"], ["CWE-639", "CWE-862"])
    self.assertEqual(d["attack"], ["T1078"])

  def test_to_flat_finding_vulnerable(self):
    """Vulnerable status -> confidence=certain, severity preserved."""
    f = self._make_finding(status="vulnerable", severity="HIGH")
    flat = f.to_flat_finding(port=443, protocol="https", probe_name="access_control")
    self.assertEqual(flat["confidence"], "certain")
    self.assertEqual(flat["severity"], "HIGH")
    self.assertEqual(flat["probe_type"], "graybox")
    self.assertEqual(flat["port"], 443)
    self.assertEqual(flat["protocol"], "https")
    self.assertEqual(flat["probe"], "access_control")
    self.assertEqual(flat["category"], "graybox")
    self.assertIn("finding_id", flat)

  def test_to_flat_finding_not_vulnerable(self):
    """not_vulnerable status -> severity overridden to INFO."""
    f = self._make_finding(status="not_vulnerable", severity="HIGH")
    flat = f.to_flat_finding(port=443, protocol="https", probe_name="access_control")
    self.assertEqual(flat["severity"], "INFO")
    self.assertEqual(flat["confidence"], "firm")
    self.assertEqual(flat["status"], "not_vulnerable")

  def test_to_flat_finding_inconclusive(self):
    """inconclusive status -> confidence=tentative."""
    f = self._make_finding(status="inconclusive", severity="MEDIUM")
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="injection")
    self.assertEqual(flat["confidence"], "tentative")
    self.assertEqual(flat["severity"], "MEDIUM")

  def test_evidence_joined(self):
    """Evidence list is joined with '; ' in flat finding."""
    f = self._make_finding(evidence=["endpoint=/api/foo", "status=200"])
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="test")
    self.assertEqual(flat["evidence"], "endpoint=/api/foo; status=200")

  def test_cwe_joined(self):
    """CWE list is joined with ', ' in flat finding."""
    f = self._make_finding(cwe=["CWE-639", "CWE-862"])
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="test")
    self.assertEqual(flat["cwe_id"], "CWE-639, CWE-862")

  def test_finding_id_deterministic(self):
    """Same inputs produce the same finding_id."""
    f = self._make_finding()
    flat1 = f.to_flat_finding(port=443, protocol="https", probe_name="ac")
    flat2 = f.to_flat_finding(port=443, protocol="https", probe_name="ac")
    self.assertEqual(flat1["finding_id"], flat2["finding_id"])

  def test_replay_steps_preserved(self):
    """Replay steps round-trip to flat finding."""
    steps = ["Login as user A", "GET /api/records/2/"]
    f = self._make_finding(replay_steps=steps)
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="test")
    self.assertEqual(flat["replay_steps"], steps)

  def test_default_factory_lists(self):
    """All list fields default to [] (not None)."""
    f = GrayboxFinding(
      scenario_id="PT-X", title="T", status="vulnerable",
      severity="LOW", owasp="A01:2021",
    )
    self.assertEqual(f.cwe, [])
    self.assertEqual(f.attack, [])
    self.assertEqual(f.evidence, [])
    self.assertEqual(f.replay_steps, [])

  def test_attack_ids_in_flat(self):
    """attack_ids field in flat finding contains MITRE IDs."""
    f = self._make_finding(attack=["T1078", "T1110"])
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="test")
    self.assertEqual(flat["attack_ids"], ["T1078", "T1110"])

  def test_description_format(self):
    """Description includes scenario_id and title."""
    f = self._make_finding(scenario_id="PT-A03-01", title="SQL Injection")
    flat = f.to_flat_finding(port=80, protocol="http", probe_name="inj")
    self.assertEqual(flat["description"], "Scenario PT-A03-01: SQL Injection")

  def test_error_field(self):
    """error field is None by default, can be set."""
    f = self._make_finding()
    self.assertIsNone(f.error)
    f2 = self._make_finding(error="Connection refused")
    self.assertEqual(f2.error, "Connection refused")

  def test_frozen(self):
    """Finding is immutable."""
    f = self._make_finding()
    with self.assertRaises(AttributeError):
      f.title = "Changed"


if __name__ == '__main__':
  unittest.main()
