"""RM-062 B5: coverage results are not findings.

A graybox scenario that ran and found nothing (`not_vulnerable`) or could not
decide (`inconclusive`) is evidence about *coverage* — how much was tested. Both
were emitted into the same flat list as real vulnerabilities and counted there,
so `total_findings` answered "how many scenarios ran" rather than "how many
findings exist".

Measured on a four-scenario fixture with one real vulnerability:
`total_findings` reported 4, and `finding_counts` reported **HIGH: 2** — because
only `not_vulnerable` is downgraded to INFO, so an `inconclusive` scenario kept
its declared HIGH severity, counted as a HIGH finding, and contributed to the
risk score. A scan that concluded nothing scored as one that found something.

The entries stay in the archive — coverage is evidence and a PTES report needs
it — but they are counted as coverage, not as findings.
"""

import unittest

from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin


class _Host(_RiskScoringMixin):
  pass


def _graybox_report(statuses):
  probes = {"findings": [
    GrayboxFinding(
      scenario_id=f"PT-A0{index}-01", title=f"scenario {index}", status=status,
      severity="HIGH", owasp="A01:2021", url=f"https://app.test/{index}",
    ).to_dict()
    for index, status in enumerate(statuses)
  ]}
  return {
    "target": "app.test",
    "port_protocols": {"443": "https"},
    "graybox_results": {"443": {"_graybox_access_control": probes}},
  }


class TestCountsMeanFindings(unittest.TestCase):

  def test_only_a_real_vulnerability_counts_as_a_finding(self):
    risk, flat = _Host()._compute_risk_and_findings(
      _graybox_report(["vulnerable", "not_vulnerable", "not_vulnerable", "inconclusive"])
    )
    self.assertEqual(risk["breakdown"]["finding_counts"]["HIGH"], 1)
    self.assertEqual(sum(risk["breakdown"]["finding_counts"].values()), 1)

  def test_an_inconclusive_scenario_is_not_a_high_finding(self):
    """The sharpest form: `inconclusive` kept its declared severity, so a
    scenario that concluded nothing counted as a HIGH vulnerability."""
    risk, _flat = _Host()._compute_risk_and_findings(_graybox_report(["inconclusive"]))
    self.assertEqual(risk["breakdown"]["finding_counts"]["HIGH"], 0)

  def test_coverage_is_reported_rather_than_discarded(self):
    risk, _flat = _Host()._compute_risk_and_findings(
      _graybox_report(["vulnerable", "not_vulnerable", "not_vulnerable", "inconclusive"])
    )
    coverage = risk["breakdown"]["coverage_counts"]
    self.assertEqual(coverage["not_vulnerable"], 2)
    self.assertEqual(coverage["inconclusive"], 1)

  def test_the_entries_stay_in_the_archive(self):
    """Coverage is evidence — a PTES "strength of test" section needs it. It is
    counted differently, not thrown away."""
    _risk, flat = _Host()._compute_risk_and_findings(
      _graybox_report(["vulnerable", "not_vulnerable", "inconclusive"])
    )
    self.assertEqual(len(flat), 3)

  def test_coverage_does_not_contribute_to_the_risk_score(self):
    only_coverage = _Host()._compute_risk_and_findings(
      _graybox_report(["not_vulnerable", "inconclusive"])
    )[0]
    self.assertEqual(only_coverage["breakdown"]["findings_score"], 0.0)

  def test_a_scan_that_found_nothing_scores_below_one_that_found_something(self):
    nothing = _Host()._compute_risk_and_findings(
      _graybox_report(["not_vulnerable", "inconclusive"])
    )[0]["score"]
    something = _Host()._compute_risk_and_findings(
      _graybox_report(["vulnerable"])
    )[0]["score"]
    self.assertLess(nothing, something)


class TestBlackboxFindingsAreUnaffected(unittest.TestCase):
  """Blackbox probes emit no `status` at all, so every entry is a finding."""

  def _blackbox(self, findings):
    return _Host()._compute_risk_and_findings({
      "target": "app.test",
      "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": {"findings": findings}}},
    })

  def test_a_statusless_finding_still_counts(self):
    risk, flat = self._blackbox([
      {"title": "Weak TLS", "severity": "MEDIUM", "confidence": "certain"},
    ])
    self.assertEqual(risk["breakdown"]["finding_counts"]["MEDIUM"], 1)
    self.assertEqual(len(flat), 1)

  def test_no_coverage_counts_are_invented_for_blackbox(self):
    risk, _flat = self._blackbox([
      {"title": "Weak TLS", "severity": "MEDIUM", "confidence": "certain"},
    ])
    self.assertEqual(
      sum(risk["breakdown"]["coverage_counts"].values()), 0,
    )


if __name__ == "__main__":
  unittest.main()
