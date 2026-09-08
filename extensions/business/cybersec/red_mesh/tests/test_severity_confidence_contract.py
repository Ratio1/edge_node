"""RM-062 B4: severity is declared vs effective, confidence is never silently invented.

Two losses, both silent:

  * `not_vulnerable` overwrites the probe's declared severity with INFO and the
    original is gone. "We checked for a CRITICAL issue and it was absent" and
    "we checked for an INFO-level nicety and it was absent" become the same
    record, so the coverage evidence cannot say how much a passing check was
    worth.
  * An unrecognised confidence falls through `RISK_CONFIDENCE_MULTIPLIERS.get(
    value, 0.5)` to 0.5 — the same weight as `tentative`. A probe's typo scores
    as a real half-confidence finding, the stored value stays the typo, and
    nothing anywhere says the value was not understood.
"""

import unittest

from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.models.finding_schema import (
  normalize_confidence,
  validate_flat_finding,
)


def _flat(**overrides):
  payload = {
    "scenario_id": "PT-A01-01", "title": "t", "status": "vulnerable",
    "severity": "HIGH", "owasp": "A01:2021", "url": "https://app.test/x",
  }
  payload.update(overrides)
  return GrayboxFinding(**payload).to_flat_finding(
    port=443, protocol="https", probe_name="_graybox_access_control",
  )


class TestSeverityKeepsWhatTheProbeDeclared(unittest.TestCase):

  def test_a_clean_check_records_what_it_was_checking_for(self):
    flat = _flat(status="not_vulnerable", severity="CRITICAL")
    self.assertEqual(flat["severity"], "INFO")
    self.assertEqual(flat["declared_severity"], "CRITICAL")

  def test_two_clean_checks_of_different_weight_stay_distinguishable(self):
    critical = _flat(status="not_vulnerable", severity="CRITICAL")
    low = _flat(status="not_vulnerable", severity="LOW")
    self.assertEqual(critical["severity"], low["severity"])
    self.assertNotEqual(critical["declared_severity"], low["declared_severity"])

  def test_a_real_finding_declares_and_takes_effect_at_the_same_level(self):
    flat = _flat(status="vulnerable", severity="HIGH")
    self.assertEqual(flat["severity"], "HIGH")
    self.assertEqual(flat["declared_severity"], "HIGH")

  def test_the_effective_severity_is_what_gets_counted(self):
    # The override exists so a passing check does not inflate finding_counts;
    # preserving the declared value must not undo that.
    self.assertEqual(_flat(status="not_vulnerable", severity="CRITICAL")["severity"], "INFO")


class TestConfidenceIsNeverSilentlyInvented(unittest.TestCase):

  def test_a_known_value_passes_through(self):
    for value in ("certain", "firm", "tentative"):
      self.assertEqual(normalize_confidence(value), (value, True))

  def test_case_and_padding_are_tolerated(self):
    self.assertEqual(normalize_confidence("  Certain "), ("certain", True))

  def test_an_unknown_value_is_reported_as_unrecognised(self):
    """The number it lands on matters less than the fact that it is flagged.

    Defaulting to 0.5 is defensible; doing it invisibly is not, because the
    stored finding then says "probably" while the score says "tentative".
    """
    value, recognised = normalize_confidence("probably")
    self.assertEqual(value, "tentative")
    self.assertFalse(recognised)

  def test_an_empty_value_is_unrecognised_too(self):
    self.assertFalse(normalize_confidence("")[1])
    self.assertFalse(normalize_confidence(None)[1])

  def test_the_flat_finding_stores_the_normalised_value(self):
    flat = _flat()
    self.assertIn(flat["confidence"], ("certain", "firm", "tentative"))
    self.assertEqual(validate_flat_finding(flat), [])


class TestTheRiskWalkAgreesWithWhatIsStored(unittest.TestCase):

  def _score(self, confidence):
    from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

    class MockHost(_RiskScoringMixin):
      pass

    risk, flat = MockHost()._compute_risk_and_findings({
      "target": "app.test",
      "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": {"findings": [{
        "title": "t", "severity": "HIGH", "confidence": confidence,
      }]}}},
    })
    return risk["breakdown"]["findings_score"], flat[0]

  def test_an_unrecognised_confidence_is_normalised_in_the_stored_finding(self):
    """It scored as `tentative` while the finding said `probably`, so the number
    and the record disagreed and neither said why."""
    _score, flat = self._score("probably")
    self.assertEqual(flat["confidence"], "tentative")
    self.assertEqual(flat["declared_confidence"], "probably")

  def test_the_score_matches_the_stored_confidence(self):
    unknown_score, _flat = self._score("probably")
    tentative_score, _flat2 = self._score("tentative")
    self.assertEqual(unknown_score, tentative_score)

  def test_a_recognised_confidence_records_no_declared_override(self):
    _score, flat = self._score("certain")
    self.assertEqual(flat["confidence"], "certain")
    self.assertNotIn("declared_confidence", flat)


if __name__ == "__main__":
  unittest.main()
