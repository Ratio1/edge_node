"""RM-169 step 4a item K: a closed finding, CVE or not, leaves the score, top findings and LLM input."""
import json
import unittest

from extensions.business.cybersec.red_mesh.cve_view import drop_closed
from extensions.business.cybersec.red_mesh.llm_input_builder import build_llm_input
from extensions.business.cybersec.red_mesh.mixins.redmesh_llm_agent import _RedMeshLlmAgentMixin
from extensions.business.cybersec.red_mesh.services.triage import _merge_triage_into_archive_dict
from .test_cve_view import _Host

NOW = 1_000.0
WEB = {"title": "Missing CSP header", "severity": "HIGH", "confidence": "firm", "probe": "_web_test_headers",
       "category": "web", "evidence": "no csp"}
OTHER = {"title": "Open admin panel", "severity": "MEDIUM", "confidence": "firm", "probe": "_web_test_admin",
         "category": "web", "evidence": "/admin"}


def compute(triage=None):
  report = {"target": "t", "port_protocols": {"80": "http"},
            "service_info": {"80": {"_service_info_http": {"findings": [dict(WEB), dict(OTHER)]}}}}
  risk, flat = _Host()._compute_risk_and_findings(report, triage)
  return risk, flat


class _Llm(_RedMeshLlmAgentMixin):
  def _extract_report_findings(self, report):
    return report["findings"]


class TestClosedNonCveFindings(unittest.TestCase):
  def setUp(self):
    self.base, flat = compute()
    self.web = next(f for f in flat if f["title"] == WEB["title"])["finding_id"]
    self.other = next(f for f in flat if f["title"] == OTHER["title"])["finding_id"]
    self.flat = flat

  def test_a_false_positive_webapp_finding_leaves_the_rerun_score(self):
    risk, _ = compute({self.web: {"status": "false_positive"}})
    self.assertLess(risk["score"], self.base["score"])
    self.assertEqual(risk["breakdown"]["finding_counts"]["HIGH"], 0)
    self.assertEqual(risk["breakdown"]["finding_counts"]["MEDIUM"], 1)

  def test_remediated_and_live_accepted_risk_leave_too(self):
    for record in ({"status": "remediated"}, {"status": "accepted_risk", "review_at": 9e12}):
      risk, _ = compute({self.web: record})
      self.assertEqual(risk["breakdown"]["finding_counts"]["HIGH"], 0, record)

  def test_expired_accepted_risk_counts_again(self):
    risk, _ = compute({self.web: {"status": "accepted_risk", "review_at": 1.0}})
    self.assertEqual(risk, self.base)

  def test_the_stored_flat_list_keeps_the_closed_finding(self):
    _, flat = compute({self.web: {"status": "false_positive"}})
    self.assertEqual(flat, self.flat)

  def test_empty_map_output_is_byte_identical(self):
    dump = lambda r: json.dumps(r, sort_keys=True, default=str)
    self.assertEqual(dump(compute({})), dump(compute(None)))
    self.assertEqual(dump(compute({})), dump(compute({"unrelated": {"status": "false_positive"}})))
    findings = [dict(WEB, finding_id="a"), dict(OTHER, finding_id="b")]
    self.assertEqual(drop_closed(findings, {}), findings)
    self.assertEqual(drop_closed(findings, None), findings)

  def test_llm_top_findings_drop_a_closed_webapp_finding(self):
    findings = [dict(WEB, finding_id="a", finding_signature="s1"), dict(OTHER, finding_id="b", finding_signature="s2")]
    compact, _ = _Llm()._build_llm_top_findings({"findings": findings}, "security_assessment",
                                                {"a": {"status": "false_positive"}})
    self.assertEqual(len(compact), 1)
    self.assertIn(OTHER["title"], compact[0]["title"])
    both, _ = _Llm()._build_llm_top_findings(
      {"findings": findings}, "security_assessment", {"a": {"status": "accepted_risk", "review_at": 1.0}})
    self.assertEqual(len(both), 2)
    none, _ = _Llm()._build_llm_top_findings({"findings": findings}, "security_assessment", {})
    self.assertEqual(len(none), 2)

  def test_llm_input_builder_drops_a_closed_webapp_finding(self):
    findings = [dict(WEB, finding_id="a", triage={"status": "false_positive"}), dict(OTHER, finding_id="b")]
    out = build_llm_input(findings=findings, aggregated_report={})
    self.assertEqual([f["title"] for f in out.findings], [OTHER["title"]])
    open_both = [dict(WEB, finding_id="a"), dict(OTHER, finding_id="b")]
    self.assertEqual(len(build_llm_input(findings=open_both, aggregated_report={}).findings), 2)


class TestCoverageRowsAreNotClosable(unittest.TestCase):
  def test_drop_closed_keeps_a_triaged_coverage_row(self):
    coverage = {"finding_id": "cov", "status": "not_vulnerable", "severity": "INFO", "title": "scenario ran"}
    other = dict(OTHER, finding_id="b")
    kept = drop_closed([coverage, other], {"cov": {"status": "false_positive"}, "b": {"status": "false_positive"}})
    self.assertEqual(kept, [coverage])

  def test_coverage_counts_ignore_the_triage_map(self):
    from .test_cve_view import _Host as Host
    coverage = {"finding_id": "cov", "status": "not_vulnerable", "severity": "INFO", "confidence": "firm",
                "title": "scenario ran", "probe": "p", "category": "x", "finding_signature": "sc"}
    report = {"target": "t", "port_protocols": {"80": "http"},
              "service_info": {"80": {"_service_info_http": {"findings": [dict(coverage)]}}}}
    base = Host()._compute_risk_and_findings(report)[0]["breakdown"]["coverage_counts"]
    flat = Host()._compute_risk_and_findings(report)[1]
    cid = next(f for f in flat if f.get("status") == "not_vulnerable")["finding_id"]
    triaged = Host()._compute_risk_and_findings(report, {cid: {"status": "false_positive"}})[0]["breakdown"]["coverage_counts"]
    self.assertEqual(sum(base.values()), 1)
    self.assertEqual(triaged, base)


class TestTopFindingsReadRefilter(unittest.TestCase):
  def archive(self):
    top = [dict(WEB, finding_id="a"), dict(OTHER, finding_id="b")]
    return {"passes": [{"findings": list(top)}], "ui_aggregate": {"top_findings": top, "latest_risk_score": 42}}

  def test_a_finding_closed_after_the_build_leaves_top_findings_only(self):
    merged = _merge_triage_into_archive_dict(self.archive(), {"a": {"status": "false_positive"}})
    ui = merged["ui_aggregate"]
    self.assertEqual([f["finding_id"] for f in ui["top_findings"]], ["b"])
    self.assertEqual(ui["latest_risk_score"], 42)  # stored score not recomputed on read
    self.assertEqual(len(merged["passes"][0]["findings"]), 2)  # exports keep it

  def test_expired_accepted_risk_stays_and_empty_map_changes_nothing(self):
    expired = _merge_triage_into_archive_dict(self.archive(), {"a": {"status": "accepted_risk", "review_at": 1.0}})
    self.assertEqual(len(expired["ui_aggregate"]["top_findings"]), 2)
    self.assertEqual(_merge_triage_into_archive_dict(self.archive(), {}), self.archive())


if __name__ == "__main__":
  unittest.main()
