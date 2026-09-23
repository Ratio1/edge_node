"""RM-090: KEV/EPSS stated as evaluated only when they were.

`DynamicReferenceCache` is constructed only in tests, so every production
finding carries `kev: False`, `epss_score: None` and an empty
`cvss_data_freshness`. The LLM input presented `kev: False` as a fact, and the
pass report gave the renderer no way to tell "not listed in KEV" from "KEV was
never consulted" — job 6d342bab's §3.1.3 claimed NVD/KEV/EPSS data it never had.
"""

import unittest

from extensions.business.cybersec.red_mesh.llm_input_builder import _sanitize_finding
from extensions.business.cybersec.red_mesh.mixins.risk import _RiskScoringMixin


class _Host(_RiskScoringMixin):
  pass


_CVE = {"title": "CVE-2018-15599: Username enumeration", "severity": "MEDIUM",
        "cve": ["CVE-2018-15599"], "kev": False, "epss_score": None}


class TestKevIsNotAFactWhenNeverEvaluated(unittest.TestCase):

  def test_unevaluated_kev_reaches_the_model_as_unknown(self):
    out = _sanitize_finding({**_CVE, "cvss_data_freshness": ""})
    self.assertIsNone(out["kev"])
    self.assertFalse(out["kev_evaluated"])

  def test_evaluated_kev_is_passed_through(self):
    out = _sanitize_finding({**_CVE, "kev": True, "cvss_data_freshness": "2026-09-23T08:00:00Z"})
    self.assertTrue(out["kev"])
    self.assertTrue(out["kev_evaluated"])


class TestThePassReportSaysWhetherReferencesRan(unittest.TestCase):

  def _breakdown(self, reference_data):
    risk, _flat = _Host()._compute_risk_and_findings({
      "target": "app.test",
      "port_protocols": {"22": "ssh"},
      "service_info": {"22": {"_service_info_ssh": {"findings": [dict(_CVE)]}}},
      "reference_data": reference_data,
    })
    return risk["breakdown"]

  def test_no_reference_data_means_not_enabled(self):
    self.assertIs(self._breakdown({})["reference_data_enabled"], False)

  def test_reference_data_means_enabled(self):
    self.assertIs(self._breakdown({"kev_catalog_date": "2026-09-22"})["reference_data_enabled"], True)

  def test_the_flag_survives_the_archived_breakdown_model(self):
    # `RiskBreakdown` is a whitelist: a field it does not declare is dropped
    # silently on the way to the archive, and the renderer would never see it.
    from extensions.business.cybersec.red_mesh.models.shared import RiskBreakdown
    archived = RiskBreakdown.from_dict(self._breakdown({})).to_dict()
    self.assertIs(archived["reference_data_enabled"], False)


if __name__ == "__main__":
  unittest.main()
