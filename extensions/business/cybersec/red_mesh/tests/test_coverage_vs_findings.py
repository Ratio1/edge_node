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


class TestDedupDoesNotResurrectCoverage(unittest.TestCase):
  """Coverage is excluded on the first pass and re-included on the second.

  The scoring walk skips `not_vulnerable` / `inconclusive`, but the entries
  still go into the flat list — and the post-dedup recalculation loop rebuilds
  `findings_score` and `finding_counts` by iterating that list with no such
  skip. So the whole of B5 held only for as long as nothing deduplicated.

  Measured on one real HIGH plus one `inconclusive` HIGH: adding a *duplicate*
  of the real finding — which changes nothing about what was concluded — took
  `finding_counts["HIGH"]` from 1 to 2 and the findings score from 25.0 to
  37.5. The inconclusive scenario came back as a HIGH vulnerability.
  """

  def _report(self, items):
    return {
      "target": "app.test",
      "port_protocols": {"443": "https"},
      "graybox_results": {"443": {"_graybox_access_control": {"findings": items}}},
    }

  def _vulnerable(self):
    return GrayboxFinding(
      scenario_id="PT-A01-01", title="IDOR", status="vulnerable",
      severity="HIGH", owasp="A01:2021", url="https://app.test/x",
    ).to_dict()

  def _inconclusive(self):
    return GrayboxFinding(
      scenario_id="PT-A02-01", title="undecided", status="inconclusive",
      severity="HIGH", owasp="A02:2021", url="https://app.test/y",
    ).to_dict()

  def test_a_duplicate_does_not_promote_an_inconclusive_scenario_to_a_finding(self):
    risk, _flat = _Host()._compute_risk_and_findings(
      self._report([self._vulnerable(), dict(self._vulnerable()), self._inconclusive()])
    )
    self.assertEqual(risk["breakdown"]["finding_counts"]["HIGH"], 1)

  def test_deduplicating_does_not_change_what_was_concluded(self):
    """The sharpest form: dedup removes a redundant record, so every count it
    touches must be unchanged by whether the redundant record was there."""
    without = _Host()._compute_risk_and_findings(
      self._report([self._vulnerable(), self._inconclusive()])
    )[0]["breakdown"]
    with_dup = _Host()._compute_risk_and_findings(
      self._report([self._vulnerable(), dict(self._vulnerable()), self._inconclusive()])
    )[0]["breakdown"]
    self.assertEqual(with_dup["finding_counts"], without["finding_counts"])
    self.assertEqual(with_dup["findings_score"], without["findings_score"])
    self.assertEqual(with_dup["coverage_counts"], without["coverage_counts"])


class TestDedupDoesNotDeleteDistinctFindings(unittest.TestCase):
  """Dedup must key on content until locations are populated.

  Keying dedup on `dedup_key` reads as the obvious improvement — identity, not
  content — and it silently deleted findings. `grep -rn affected_assets worker/`
  returns **zero hits**: no blackbox probe sets a location, so every blackbox
  finding falls to `dedup_key`'s last-resort branch, whose discriminator is the
  lowercased *title*. Any probe emitting N findings in a loop under a constant
  title then collapses to one.

  Measured on the real SRI loop in `worker/web/hardening.py`, which appends up
  to five findings all titled "External script loaded without SRI": five
  distinct findings, five distinct content hashes, **one** survivor. Four
  unsafe CDN scripts vanished from the report, the archive and `finding_counts`.

  RM-061 owns populating url/parameter on blackbox findings. Until it lands, the
  content hash is the only key that separates these, so dedup stays on it — and
  this test is what says so, because reverting the one line responsible passed
  the entire 2311-test suite when it was written.
  """

  def _sri_findings(self, count=5):
    from extensions.business.cybersec.red_mesh.findings import (
      Finding, Severity, probe_result,
    )
    findings = [
      Finding(
        severity=Severity.MEDIUM,
        title="External script loaded without SRI",
        description=f"Script from cdn-{n}.example/s.js has no integrity attribute.",
        evidence=f'<script src="cdn-{n}.example/s.js" ...> without integrity=',
        owasp_id="A08:2021", cwe_id="CWE-829", confidence="certain",
      )
      for n in "abcde"[:count]
    ]
    return probe_result(findings=findings, probe_id="_web_test_hardening")

  def _flatten(self, probe):
    return _Host()._compute_risk_and_findings({
      "target": "app.test", "port_protocols": {"443": "https"},
      "web_tests_info": {"443": {"_web_test_hardening": probe}},
    })

  def test_five_scripts_without_sri_are_five_findings(self):
    _risk, flat = self._flatten(self._sri_findings())
    self.assertEqual(
      len(flat), 5,
      "findings differing only in which script they name were deduplicated "
      "away, so the report lost evidence the probe actually gathered",
    )

  def test_the_severity_counts_agree_with_what_survived(self):
    risk, flat = self._flatten(self._sri_findings())
    self.assertEqual(risk["breakdown"]["finding_counts"]["MEDIUM"], len(flat))

  def test_a_genuine_duplicate_still_deduplicates(self):
    """The control: dedup still has to do its job."""
    probe = self._sri_findings(count=1)
    probe = dict(probe, findings=probe["findings"] + [dict(probe["findings"][0])])
    _risk, flat = self._flatten(probe)
    self.assertEqual(len(flat), 1)


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


class TestEverySurvivingFindingHasItsOwnId(unittest.TestCase):
  """`finding_id` is the primary key, and three findings shared one.

  `finding_id` derives from `dedup_key`, dedup runs on `finding_signature`, and
  no blackbox probe sets a location — so findings that differ in content survive
  dedup and land with the *same* id. On `origin/develop` this could not happen:
  `finding_id` was `signature[:16]`, which is content-derived and therefore
  distinct per finding.

  Measured on the SRI loop: three survivors, one unique `finding_id`. It is the
  triage key (`services/triage.py`), the CStore key, the `finding_timeline`
  identity, the `uuid5` seed for STIX, the MISP object id and the SIEM event
  fingerprint — so triaging one SRI finding would stamp all of them, and
  `finding_timeline` would report three passes inside one pass.
  """

  def _sri(self, count=3):
    from extensions.business.cybersec.red_mesh.findings import (
      Finding, Severity, probe_result,
    )
    return probe_result(
      findings=[
        Finding(
          severity=Severity.MEDIUM, title="External script loaded without SRI",
          description=f"Script from cdn-{n}.example/s.js has no integrity attribute.",
          evidence=f'<script src="cdn-{n}.example/s.js">',
          owasp_id="A08:2021", cwe_id="CWE-829", confidence="certain",
        )
        for n in "abcde"[:count]
      ],
      probe_id="_web_test_hardening",
    )

  def _flat(self, count=3):
    return _Host()._compute_risk_and_findings({
      "target": "app.test", "port_protocols": {"443": "https"},
      "web_tests_info": {"443": {"_web_test_hardening": self._sri(count)}},
    })[1]

  def test_no_two_surviving_findings_share_an_id(self):
    flat = self._flat()
    self.assertEqual(
      len({f["finding_id"] for f in flat}), len(flat),
      "distinct findings shipped under one primary key, so triage, the "
      "finding timeline and every export would conflate them",
    )

  def test_the_id_does_not_depend_on_the_order_the_probe_emitted(self):
    """Disambiguation must derive from the finding, not from its position.

    Asserting only that two identical runs agree is too weak: a positional
    discriminator satisfies it, and that mutant survived. A probe that emits the
    same findings in a different order — or finds one more of them next pass —
    must not re-key the ones that did not change, or continuous monitoring
    reports churn that never happened.
    """
    def by_script(findings):
      return {f["description"].split()[2]: f["finding_id"] for f in findings}

    def flatten(probe):
      return _Host()._compute_risk_and_findings({
        "target": "app.test", "port_protocols": {"443": "https"},
        "web_tests_info": {"443": {"_web_test_hardening": probe}},
      })[1]

    forward = self._sri(3)
    backward = dict(forward, findings=list(reversed(forward["findings"])))
    self.assertEqual(by_script(flatten(forward)), by_script(flatten(backward)))

  def test_a_finding_with_a_unique_identity_keeps_its_dedup_key_as_its_id(self):
    flat = self._flat(count=1)
    self.assertEqual(flat[0]["finding_id"], flat[0]["dedup_key"])


class TestCveDedupRespectsTheCoverageBoundary(unittest.TestCase):
  """The CVE-title fallback is the one dedup loop that ignores B5's distinction.

  It walks the whole flat list — coverage entries included — and ranks on
  confidence alone, unlike `finding_rank` fifteen lines above it, which ranks
  severity first. So a `not_vulnerable` INFO record naming a CVE can evict, or
  be evicted by, a real vulnerability naming the same CVE.

  Measured: a `not_vulnerable` scenario and a CRITICAL finding both mentioning
  CVE-2024-1234 left **one** survivor and `coverage_counts` of zero — the
  coverage record deleted from the archive, contradicting this module's own
  "the entry is still archived, a PTES report needs the coverage evidence".
  """

  def _report(self, items):
    return {
      "target": "app.test", "port_protocols": {"443": "https"},
      "graybox_results": {"443": {"_graybox_components": {"findings": items}}},
    }

  def _entry(self, scenario, title, status, severity, confidence, path):
    entry = GrayboxFinding(
      scenario_id=scenario, title=title, status=status, severity=severity,
      owasp="A06:2021", url=f"https://app.test/{path}",
    ).to_dict()
    entry["confidence"] = confidence
    return entry

  def _both(self):
    return [
      self._entry("PT-A06-01", "CVE-2024-1234 RCE in component", "vulnerable",
                  "CRITICAL", "firm", "a"),
      self._entry("PT-A06-02", "CVE-2024-1234 patch verified absent",
                  "not_vulnerable", "INFO", "certain", "b"),
    ]

  def test_a_coverage_record_is_not_deduplicated_against_a_finding(self):
    _risk, flat = _Host()._compute_risk_and_findings(self._report(self._both()))
    self.assertEqual(len(flat), 2)

  def test_the_real_vulnerability_survives(self):
    risk, _flat = _Host()._compute_risk_and_findings(self._report(self._both()))
    self.assertEqual(risk["breakdown"]["finding_counts"]["CRITICAL"], 1)

  def test_the_coverage_evidence_survives(self):
    risk, _flat = _Host()._compute_risk_and_findings(self._report(self._both()))
    self.assertEqual(risk["breakdown"]["coverage_counts"]["not_vulnerable"], 1)


class TestTheIdDistinguishesTheAssetNotJustTheContent(unittest.TestCase):
  """The same weakness on two ports is two findings, and shared one id.

  Identity is stamped at probe time, before the walk knows which port the
  finding belongs to, so a `Finding` emitted for 443 and an identical one for
  8443 carry the same `dedup_key` *and* the same `content_hash`. The
  disambiguation added for the SRI case keyed only on content, so it could not
  separate them either.

  `finding_id` is what triage and the STIX `uuid5` seed resolve on, so the two
  assets collided: remediating the 8443 service would mark the 443 one done.
  """

  def _two_ports(self):
    from extensions.business.cybersec.red_mesh.findings import (
      Finding, Severity, probe_result,
    )

    def probe():
      return probe_result(
        findings=[Finding(
          severity=Severity.HIGH, title="Weak TLS", description="d",
          confidence="certain",
        )],
        probe_id="_service_info_ssl",
      )

    return _Host()._compute_risk_and_findings({
      "target": "app.test", "port_protocols": {"443": "https", "8443": "https"},
      "service_info": {
        "443": {"_service_info_ssl": probe()},
        "8443": {"_service_info_ssl": probe()},
      },
    })[1]

  def test_the_same_weakness_on_two_ports_gets_two_ids(self):
    flat = self._two_ports()
    self.assertEqual(len(flat), 2)
    self.assertEqual(
      len({f["finding_id"] for f in flat}), 2,
      "two services on two ports shipped under one primary key, so triaging "
      "one would resolve the other",
    )

  def test_the_ids_still_do_not_depend_on_scan_order(self):
    self.assertEqual(
      {f["port"]: f["finding_id"] for f in self._two_ports()},
      {f["port"]: f["finding_id"] for f in self._two_ports()},
    )


class TestTheContentHashSeesAllTheContent(unittest.TestCase):
  """Dedup keys on the content hash, and the content hash was blind.

  `models/finding_identity._CONTENT_FIELDS` names nine fields; the payload
  `Finding._identity_payload` supplies carries seven of them and omits
  `confidence`, `status`, `evidence`, `remediation`, `cvss_score` and
  `cvss_vector`. So two findings differing only in one of those hash the same,
  and content-keyed dedup deletes one — the exact failure the revert to
  content-keying exists to prevent, reached through the payload instead of the
  key choice.

  Measured: two findings differing only in `evidence` left one survivor. Same
  for `remediation`, and for a CVSS 9.8 against a 4.3.
  """

  def _survivors(self, **difference):
    from extensions.business.cybersec.red_mesh.findings import (
      Finding, Severity, probe_result,
    )
    base = dict(
      severity=Severity.HIGH, title="Weak configuration", description="d",
      confidence="certain",
    )
    probe = probe_result(
      findings=[Finding(**base), Finding(**base, **difference)],
      probe_id="_service_info_http",
    )
    return _Host()._compute_risk_and_findings({
      "target": "app.test", "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": probe}},
    })[1]

  def test_different_evidence_is_different_content(self):
    self.assertEqual(len(self._survivors(evidence="payload=X")), 2)

  def test_different_remediation_is_different_content(self):
    self.assertEqual(len(self._survivors(remediation="Rotate the key")), 2)

  def test_a_different_cvss_score_is_different_content(self):
    self.assertEqual(len(self._survivors(cvss_score=9.8)), 2)

  def test_an_identical_finding_still_deduplicates(self):
    """The control — widening the payload must not disable dedup."""
    self.assertEqual(len(self._survivors()), 1)


class TestCveDedupKeepsTheWorstFinding(unittest.TestCase):
  """The CVE fallback ranked on confidence alone and lost the severe finding.

  `finding_rank`, fifteen lines above it, ranks severity first and confidence
  second. The CVE-title loop compares only `CONFIDENCE_RANK`, so a LOW banner
  observation marked `certain` evicted a CRITICAL RCE marked `tentative` — both
  naming CVE-2024-1234. The report then carried one LOW where the scan had
  found a critical remote code execution.
  """

  def _survivors(self):
    findings = [
      {"title": "CVE-2024-1234: RCE in component", "severity": "CRITICAL",
       "confidence": "tentative", "description": "exploitable"},
      {"title": "CVE-2024-1234 banner observed", "severity": "LOW",
       "confidence": "certain", "description": "version string only"},
    ]
    return _Host()._compute_risk_and_findings({
      "target": "app.test", "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": {"findings": findings}}},
    })

  def test_the_critical_finding_is_the_one_that_survives(self):
    _risk, flat = self._survivors()
    self.assertEqual([f["severity"] for f in flat], ["CRITICAL"])

  def test_the_counts_report_the_critical(self):
    risk, _flat = self._survivors()
    self.assertEqual(risk["breakdown"]["finding_counts"]["CRITICAL"], 1)
    self.assertEqual(risk["breakdown"]["finding_counts"]["LOW"], 0)


class TestScoringIsOneWalk(unittest.TestCase):
  """Phase 3: score once, after dedup, over `flat_findings`.

  Three copies of the scoring loop coexisted — two producing walks and a
  post-dedup recount — and their drift caused the round-1 coverage bug. The
  recount is the correct one, so it becomes the only one. The cases below are
  the observable differences the collapse fixes, plus the crashes the
  incremental walks carried.
  """

  def _blackbox(self, finding):
    return _Host()._compute_risk_and_findings({
      "target": "app.test", "port_protocols": {"443": "https"},
      "service_info": {"443": {"_service_info_http": {"findings": [finding]}}},
    })

  def test_a_none_severity_does_not_crash_the_scan(self):
    """`finding.get("severity", "INFO").upper()` raises on an explicit None —
    the default only covers an *absent* key — and the exception killed the
    whole risk computation, not one finding."""
    risk, flat = self._blackbox(
      {"title": "t", "severity": None, "confidence": "certain"},
    )
    self.assertEqual(len(flat), 1)
    violations = risk["breakdown"]["schema_violations"]
    self.assertTrue(any("severity" in error for error in violations["errors"]))

  def test_a_none_confidence_does_not_crash_the_scan(self):
    _risk, flat = self._blackbox(
      {"title": "t", "severity": "MEDIUM", "confidence": None},
    )
    self.assertEqual(len(flat), 1)
    self.assertEqual(flat[0]["confidence"], "tentative")

  def test_a_padded_confidence_scores_as_its_trimmed_value(self):
    """The incremental walk read the raw string (` certain ` -> 0.5, the
    unknown-value multiplier); the recount read the normalised one (1.0). The
    two disagreed whenever dedup did not run. The normalised read is correct."""
    risk, _flat = self._blackbox(
      {"title": "t", "severity": "HIGH", "confidence": " certain "},
    )
    self.assertEqual(risk["breakdown"]["findings_score"], 25.0)

  def test_an_explicit_empty_asset_list_is_preserved(self):
    """`affected_assets: []` is a statement — "no location recorded" — and the
    falsy-check synthesis replaced it with an invented `{host, port}`. Only a
    truly absent key gets the synthetic asset."""
    _risk, flat = self._blackbox({
      "title": "t", "severity": "LOW", "confidence": "firm",
      "affected_assets": [],
    })
    self.assertEqual(flat[0]["affected_assets"], [])

  def test_an_absent_asset_list_still_gets_the_synthetic_host(self):
    _risk, flat = self._blackbox(
      {"title": "t", "severity": "LOW", "confidence": "firm"},
    )
    self.assertEqual(
      flat[0]["affected_assets"], [{"host": "app.test", "port": 443}],
    )

  def test_a_coverage_record_is_not_stamped_with_generic_remediation(self):
    """A scenario that concluded nothing has nothing to remediate; the default
    remediation text made coverage records read like findings in the PDF."""
    _risk, flat = self._blackbox({
      "title": "t", "severity": "INFO", "confidence": "firm",
      "status": "not_vulnerable",
    })
    self.assertNotIn("remediation_structured", flat[0])

  def test_graybox_coverage_keeps_its_deliberate_empty_assets(self):
    """The graybox producer emits `affected_assets: []` on purpose when a probe
    recorded no location; routing coverage through the shared normalisation
    must not overwrite that with a synthetic asset."""
    entry = GrayboxFinding(
      scenario_id="PT-A05-02", title="checked", status="not_vulnerable",
      severity="INFO", owasp="A05:2021",
    ).to_dict()
    _risk, flat = _Host()._compute_risk_and_findings({
      "target": "app.test", "port_protocols": {"443": "https"},
      "graybox_results": {"443": {"_graybox_misconfig": {"findings": [entry]}}},
    })
    self.assertEqual(len(flat), 1)
    self.assertEqual(flat[0]["affected_assets"], [])
