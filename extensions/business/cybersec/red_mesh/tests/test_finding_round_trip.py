"""RM-062 Phase 5: prove the contract end to end.

The phase asks for two things the earlier phases each only half-demonstrate:

  * a finding round-trips probe → archive → aggregate → report with its location
    and identity intact;
  * N distinct endpoints yield N deduplicated findings, and coverage results do
    not inflate the count.

Both were true of *pieces* — the identity tests use hand-built dicts, the
coverage tests read the risk breakdown — but neither followed one finding
through the real serialisation boundaries. That gap is how the branch shipped a
`_local_node_address` that returned an IP, four green fixtures over broken
behaviour, and an `evidence_items` key nothing produced: every layer was tested
against its own idea of the shape.
"""

import unittest

from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin
from extensions.business.cybersec.red_mesh.models.finding_schema import (
  validate_flat_finding,
)
from extensions.business.cybersec.red_mesh.models.reports import AggregatedScanData


class _Host(_RiskScoringMixin):
  pass


def _graybox_finding(index, status="vulnerable"):
  return GrayboxFinding(
    scenario_id="PT-A01-01",
    title="IDOR on a records endpoint",
    status=status,
    severity="HIGH",
    owasp="A01:2021",
    cwe=["CWE-639", "CWE-862"],
    evidence=[f"endpoint=https://app.test/api/records/{index}"],
    url=f"https://app.test/api/records/{index}",
    parameter="id",
    method="GET",
  )


def _aggregate(findings):
  """The shape `services/finalization.py` round-trips through R1FS."""
  return AggregatedScanData.from_dict({
    "open_ports": [443],
    "service_info": {},
    "web_tests_info": {},
    "completed_tests": ["graybox"],
    "target": "app.test",
    "scan_type": "graybox",
    "port_protocols": {"443": "https"},
    "graybox_results": {"443": {"_graybox_access_control": {
      "findings": [f.to_dict() for f in findings],
    }}},
  })


class TestOneFindingSurvivesTheWholePipeline(unittest.TestCase):

  def _flatten(self, findings):
    # to_dict → AggregatedScanData → to_dict is the real archive round trip.
    archived = _aggregate(findings).to_dict()
    _risk, flat = _Host()._compute_risk_and_findings(archived)
    return flat

  def test_the_location_survives_the_archive_round_trip(self):
    flat = self._flatten([_graybox_finding(99)])[0]
    asset = flat["affected_assets"][0]
    self.assertEqual(asset["url"], "https://app.test/api/records/99")
    self.assertEqual(asset["parameter"], "id")
    self.assertEqual(asset["method"], "GET")
    self.assertEqual(asset["host"], "app.test")

  def test_the_identity_survives_the_archive_round_trip(self):
    direct = _graybox_finding(99).to_flat_finding(
      port=443, protocol="https", probe_name="_graybox_access_control",
    )
    archived = self._flatten([_graybox_finding(99)])[0]
    self.assertEqual(archived["finding_id"], direct["finding_id"])
    self.assertEqual(archived["finding_id"], direct["finding_id"])

  def test_the_flat_finding_validates_against_the_contract(self):
    for flat in self._flatten([_graybox_finding(99), _graybox_finding(100)]):
      self.assertEqual(validate_flat_finding(flat), [], flat)

  def test_the_classification_survives_as_a_typed_list(self):
    flat = self._flatten([_graybox_finding(99)])[0]
    self.assertEqual(flat["cwe"], [639, 862])

  def test_the_graybox_results_are_not_dropped_by_the_archive_model(self):
    # The regression RM-060 fixed: `AggregatedScanData` had no field for them,
    # so the authenticated half of a scan vanished on the way to R1FS.
    archived = _aggregate([_graybox_finding(99)]).to_dict()
    self.assertIn("graybox_results", archived)
    self.assertEqual(archived["target"], "app.test")
    self.assertEqual(archived["scan_type"], "graybox")


class TestNEndpointsYieldNFindings(unittest.TestCase):

  def _flatten(self, findings):
    archived = _aggregate(findings).to_dict()
    return _Host()._compute_risk_and_findings(archived)

  def test_twelve_endpoints_are_twelve_findings(self):
    """The defect that made this necessary: identity carried no location, so one
    scenario on twelve endpoints deduplicated to a single finding."""
    findings = [_graybox_finding(index) for index in range(12)]
    _risk, flat = self._flatten(findings)
    self.assertEqual(len({f["finding_id"] for f in flat}), 12)

  def test_the_same_endpoint_twice_is_one_finding(self):
    _risk, flat = self._flatten([_graybox_finding(99), _graybox_finding(99)])
    self.assertEqual(len({f["finding_id"] for f in flat}), 1)

  def test_coverage_results_do_not_inflate_the_finding_count(self):
    findings = [_graybox_finding(0)] + [
      _graybox_finding(index, status="not_vulnerable") for index in range(1, 10)
    ]
    risk, flat = self._flatten(findings)
    self.assertEqual(sum(risk["breakdown"]["finding_counts"].values()), 1)
    self.assertEqual(risk["breakdown"]["coverage_counts"]["not_vulnerable"], 9)
    # Every entry is still archived — coverage is evidence, not noise.
    self.assertEqual(len(flat), 10)

  def test_a_scan_of_only_coverage_reports_no_findings(self):
    findings = [_graybox_finding(i, status="not_vulnerable") for i in range(5)]
    risk, _flat = self._flatten(findings)
    self.assertEqual(sum(risk["breakdown"]["finding_counts"].values()), 0)
    self.assertEqual(risk["breakdown"]["findings_score"], 0.0)


if __name__ == "__main__":
  unittest.main()
