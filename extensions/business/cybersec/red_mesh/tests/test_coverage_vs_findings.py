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


class TestEveryCounterAgreesWithEveryOther(unittest.TestCase):
  """The risk breakdown was pinned; the three consumer surfaces were not.

  An independent mutation run showed `is_coverage_result -> return False`, and
  reverting each of the three consumer-side count fixes, all left the full suite
  green. The predicate the whole of B5 rests on was mutant-tolerant: the tests
  named the UI and LLM defect in a docstring and asserted only on
  `risk["breakdown"]`.

  What that missed, measured on 1 vulnerable + 9 not_vulnerable + 1
  inconclusive: `total_findings: 1` above a severity chart summing to 11, with
  the inconclusive scenario ranked into the customer-facing top-findings list as
  a HIGH.
  """

  def _findings(self):
    findings = [{
      "title": "real", "severity": "HIGH", "confidence": "certain",
      "status": "vulnerable", "finding_id": "a" * 16,
    }]
    findings += [{
      "title": f"clean {i}", "severity": "INFO", "confidence": "firm",
      "status": "not_vulnerable", "finding_id": f"b{i:015d}",
    } for i in range(9)]
    findings.append({
      "title": "undecided", "severity": "HIGH", "confidence": "tentative",
      "status": "inconclusive", "finding_id": "c" * 16,
    })
    return findings

  def _aggregate(self):
    """The real `_compute_ui_aggregate`, not a reimplementation of its filter.

    The first version of these two tests recomputed the predicate in the test
    body and asserted on that — which passes whatever the production code does,
    the exact tautology this whole review round was about.
    """
    from extensions.business.cybersec.red_mesh.mixins.report import _ReportMixin

    class MockHost(_ReportMixin):
      # `_count_services` lives on a sibling mixin; the real plugin composes
      # both. Stubbed rather than reimplemented — this test is about counting
      # findings, and inventing a service count here would only be noise.
      _count_services = staticmethod(lambda *_args, **_kwargs: 0)

    passes = [{"findings": self._findings()}]
    agg = {"open_ports": [443], "service_info": {}, "port_protocols": {"443": "https"}}
    return MockHost()._compute_ui_aggregate(passes, agg)

  def test_the_ui_aggregate_does_not_contradict_itself(self):
    ui = self._aggregate()
    self.assertEqual(ui.total_findings, 1)
    self.assertEqual(
      sum((ui.findings_count or {}).values()), ui.total_findings,
      "the header says one number and the severity chart says another, in the "
      "same object the PDF and the frontend read",
    )

  def test_the_top_findings_list_excludes_a_scenario_that_concluded_nothing(self):
    titles = [f.get("title") for f in (self._aggregate().top_findings or [])]
    self.assertEqual(titles, ["real"])

  def test_the_llm_scan_summary_is_internally_consistent(self):
    from extensions.business.cybersec.red_mesh.llm_input_builder import build_llm_input

    payload = build_llm_input(
      findings=self._findings(), aggregated_report={"target": "app.test"},
    )
    summary = payload.scan_summary
    self.assertEqual(summary["total_findings"], 1)
    self.assertEqual(summary["included_findings"], 1)
    self.assertEqual(summary["truncated_findings"], 0)
    self.assertEqual(
      summary["included_findings"] + summary["truncated_findings"],
      summary["total_findings"],
      "the model is told one total and handed a different number",
    )

  def test_the_llm_agent_summary_counts_findings_not_scenarios(self):
    from extensions.business.cybersec.red_mesh.mixins.redmesh_llm_agent import (
      _RedMeshLlmAgentMixin,
    )

    class MockHost(_RedMeshLlmAgentMixin):
      pass

    summary = MockHost()._build_llm_findings_summary(
      {"findings": self._findings()},
    )
    self.assertEqual(summary["total_findings"], 1)
    self.assertEqual(summary["by_severity"], {"HIGH": 1})


class TestTheEgressCanTellThemApart(unittest.TestCase):
  """Coverage results leave the platform through the same event path.

  `services/finalization.py` emits `redmesh.finding.created` for every entry in
  the flat list, and the payload carried no `status` — so a SIEM could not
  distinguish a scenario that concluded nothing from a vulnerability. Because
  `inconclusive` keeps its *declared* severity, one arrived as a HIGH
  `finding.created` while the platform's own counts said there were no HIGH
  findings: two of our own surfaces disagreeing in front of the customer.
  """

  def _payload(self, finding):
    from extensions.business.cybersec.red_mesh.services.event_builder import (
      build_finding_event,
    )
    event = build_finding_event(
      job_specs={"job_id": "job-1", "target": "app.test"},
      finding=finding,
      event_action="created",
      hmac_secret="test-secret",
    )
    return (event or {}).get("finding") or {}

  def test_a_coverage_result_says_so(self):
    payload = self._payload({
      "finding_id": "c" * 16, "title": "undecided", "severity": "HIGH",
      "confidence": "tentative", "status": "inconclusive",
    })
    self.assertEqual(payload.get("status"), "inconclusive")
    self.assertTrue(payload.get("is_coverage_result"))

  def test_a_real_finding_is_not_marked_as_coverage(self):
    payload = self._payload({
      "finding_id": "a" * 16, "title": "real", "severity": "HIGH",
      "confidence": "certain", "status": "vulnerable",
    })
    self.assertFalse(payload.get("is_coverage_result"))

  def test_a_statusless_blackbox_finding_is_not_marked_as_coverage(self):
    payload = self._payload({
      "finding_id": "d" * 16, "title": "Weak TLS", "severity": "MEDIUM",
      "confidence": "certain",
    })
    self.assertFalse(payload.get("is_coverage_result"))


if __name__ == "__main__":
  unittest.main()
