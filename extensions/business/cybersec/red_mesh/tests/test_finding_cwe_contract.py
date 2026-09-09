"""RM-062 B6: carry `cwe` as a list of ints, end to end.

The graybox producer emitted `cwe_id: "CWE-639, CWE-862"` — a joined display
string — and no `cwe` list at all. The consumer parsed with `int()` after
stripping a single `CWE-` prefix, so a multi-CWE finding produced `"639, CWE-862"`,
failed to parse, and normalised to **nothing**: the finding reached the report,
the SIEM export and the LLM input with no weakness classification whatsoever.

Single-CWE findings parsed fine, which is why this survived — and NVD lists two
or three CWEs for a large share of real entries.
"""

import unittest

from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding


def _flat(cwe):
  return GrayboxFinding(
    scenario_id="PT-A01-01", title="IDOR", status="vulnerable",
    severity="HIGH", owasp="A01:2021", cwe=cwe,
    url="https://app.test/api/records/99",
  ).to_flat_finding(port=443, protocol="https", probe_name="_graybox_access_control")


class TestMultiCweSurvivesFlattening(unittest.TestCase):

  def test_every_cwe_reaches_the_typed_list(self):
    self.assertEqual(_flat(["CWE-639", "CWE-862"])["cwe"], [639, 862])

  def test_a_single_cwe_still_works(self):
    self.assertEqual(_flat(["CWE-639"])["cwe"], [639])

  def test_the_display_string_is_unchanged(self):
    # `cwe_id` stays the human-readable joined form every renderer already reads.
    self.assertEqual(_flat(["CWE-639", "CWE-862"])["cwe_id"], "CWE-639, CWE-862")

  def test_a_bare_number_is_accepted(self):
    self.assertEqual(_flat(["639"])["cwe"], [639])

  def test_junk_is_dropped_rather_than_poisoning_the_list(self):
    self.assertEqual(_flat(["CWE-639", "not-a-cwe", ""])["cwe"], [639])

  def test_no_cwe_yields_an_empty_list_not_a_missing_key(self):
    self.assertEqual(_flat([])["cwe"], [])


class TestTheConsumerParsesTheJoinedForm(unittest.TestCase):
  """The blackbox normaliser is the other half: it reads `cwe_id` when no typed
  list is present, and it could only ever parse a single value."""

  def _normalized(self, finding):
    from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin

    class MockHost(_RiskScoringMixin):
      pass

    _risk, flat = MockHost()._compute_risk_and_findings({
      "target": "app.test",
      "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": {"findings": [finding]}}},
    })
    return flat[0]

  def test_a_joined_cwe_id_normalises_to_every_value(self):
    flat = self._normalized({
      "title": "t", "severity": "HIGH", "confidence": "certain",
      "cwe_id": "CWE-639, CWE-862",
    })
    self.assertEqual(flat["cwe"], [639, 862])

  def test_a_single_cwe_id_is_unchanged(self):
    flat = self._normalized({
      "title": "t", "severity": "HIGH", "confidence": "certain",
      "cwe_id": "CWE-326",
    })
    self.assertEqual(flat["cwe"], [326])

  def test_the_display_string_names_every_cwe_not_just_the_first(self):
    flat = self._normalized({
      "title": "t", "severity": "HIGH", "confidence": "certain",
      "cwe": [639, 862, 285],
    })
    self.assertEqual(flat["cwe_id"], "CWE-639, CWE-862, CWE-285")

  def test_an_explicit_typed_list_wins_over_the_display_string(self):
    flat = self._normalized({
      "title": "t", "severity": "HIGH", "confidence": "certain",
      "cwe": [79], "cwe_id": "CWE-639, CWE-862",
    })
    self.assertEqual(flat["cwe"], [79])


if __name__ == "__main__":
  unittest.main()
