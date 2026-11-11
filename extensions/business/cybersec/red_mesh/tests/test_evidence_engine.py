"""RM-120 phase 5: the shared evidence engine classifies a pass's findings per signal kind."""
import unittest

from extensions.business.cybersec.red_mesh.services import evidence_engine as engine
from extensions.business.cybersec.red_mesh.services import rulebook_assessment


def _finding(fid, severity, title, **more):
  return {"finding_id": fid, "severity": severity, "title": title, "status": "vulnerable", **more}


class TestEvidenceEngine(unittest.TestCase):
  def test_the_rulebook_still_reaches_the_moved_helpers(self):
    for name in ("_is_actionable_finding", "_severity", "_triage_status", "_matches_keywords",
                 "_ACCESS_KEYWORDS", "_CRYPTO_KEYWORDS", "_GAP_SEVERITIES"):
      self.assertIs(getattr(rulebook_assessment, name), getattr(engine, name), name)

  def test_actionable_excludes_not_vulnerable_and_triage_closed(self):
    findings = [_finding("a", "HIGH", "Auth bypass"), _finding("b", "HIGH", "Weak TLS", status="not_vulnerable"),
                _finding("c", "HIGH", "Default password"), {"severity": "HIGH"}]
    kept = engine.actionable_findings(findings, {"c": {"status": "false_positive"}})
    self.assertEqual([f["finding_id"] for f in kept], ["a"])

  def test_finding_kinds_match_by_keywords_and_rank_by_severity(self):
    findings = [_finding("a", "HIGH", "Authentication bypass on login", cwe_id="CWE-306"),
                _finding("b", "LOW", "TLS certificate expires soon", category="tls"),
                _finding("c", "MEDIUM", "Outdated server banner")]
    self.assertEqual(engine.classify("vulnerability_management", findings),
                     {"status": "gap", "gap": 2, "review": 1, "severities": {"HIGH": 1}})
    self.assertEqual(engine.classify("auth_access_findings", findings),
                     {"status": "gap", "gap": 1, "review": 0, "severities": {"HIGH": 1}})
    self.assertEqual(engine.classify("crypto_transport_findings", findings),
                     {"status": "needs_review", "gap": 0, "review": 1, "severities": {}})
    self.assertEqual(engine.classify("auth_access_findings", [findings[2]])["status"], "supported")
    self.assertEqual(engine.classify("vulnerability_management", [_finding("x", "CRITICAL", "RCE")])["severities"],
                     {"CRITICAL": 1})

  def test_assessment_and_soc_kinds_read_metadata_not_findings(self):
    self.assertEqual(engine.classify("assessment_performed", [])["status"], "supported")
    self.assertEqual(engine.classify("soc_incident_evidence", [], {"soc_event_status": {"last_status": "sent"}})["status"],
                     "supported")
    self.assertEqual(engine.classify("soc_incident_evidence", [], {"detection_correlation": {"status": "pending"}})["status"],
                     "needs_review")
    self.assertEqual(engine.classify("soc_incident_evidence", [], {})["status"], "needs_review")
    self.assertEqual(engine.soc_outcome({"status": "queued"}, None), "present")
    self.assertEqual(engine.soc_outcome(None, None), "absent")
    self.assertEqual(engine.classify("something_else", [_finding("a", "HIGH", "x")])["status"], "not_observable")


if __name__ == "__main__":
  unittest.main()
