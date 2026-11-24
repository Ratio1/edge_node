"""RM-169 step 2c-iii: the archive read carries a computed `cve_view` per pass; it is never stored."""

import copy
import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.services import query


def finding(n, build_id="b1", **kw):
  return {"finding_id": "id%d" % n, "cve": ["CVE-2030-%d" % n], "port": 80, "confidence": "firm", "kev": True,
          "vulndb_build_id": build_id, "description": "apache 1.5 is vulnerable to CVE-2030-%d. x" % n,
          "evidence": "Detected version: 1.5, affected: <2", **kw}


def archive(*passes):
  return {"job_id": "j", "passes": [{"pass_nr": i + 1, "findings": list(p)} for i, p in enumerate(passes)]}


class ArchiveCveViewTests(unittest.TestCase):
  def read(self, stored, **kw):
    with patch.object(query, "get_job_archive_with_triage", return_value={"job_id": "j", "archive": stored}):
      return query.get_job_archive(object(), "j", **kw)

  def test_generated_passes_carry_the_view_and_static_passes_do_not(self):
    stored = archive([finding(1), finding(2, kev=False, cvss_score=5.0),
                      finding(3, confidence="tentative", confidence_reason="banner_unverified")],
                     [finding(1, build_id=None)], [])
    before = copy.deepcopy(stored)
    passes = self.read(stored)["archive"]["passes"]
    view = passes[0]["cve_view"]
    self.assertEqual(view["services"][0]["listed"], ["id1"])
    self.assertEqual(view["services"][0]["rollup"]["member_finding_ids"], ["id2"])
    self.assertEqual(view["counts"], {"raw": 3, "listed": 1, "rolled_up": 1, "possible": 0, "folded": 1, "closed": 0, "dropped": 0})
    self.assertEqual(len(passes[0]["findings"]), 3)  # `findings[]` keeps every CVE finding, folded ones too
    self.assertEqual(view["services"][0]["folded"]["member_finding_ids"], ["id3"])
    self.assertNotIn("cve_view", passes[1])
    self.assertNotIn("cve_view", passes[2])
    self.assertEqual(stored, before)  # the stored archive dict is untouched

  def test_dropped_comes_from_the_stored_breakdown_and_counts_equal_it(self):
    findings = [finding(1), finding(2, kev=False, cvss_score=5.0)]
    counts = {"raw": 5, "listed": 1, "rolled_up": 1, "possible": 0, "folded": 0, "closed": 0, "dropped": 3}
    stored = archive(findings, findings)
    stored["passes"][0]["risk_breakdown"] = {"cve_view_counts": counts}
    passes = self.read(stored)["archive"]["passes"]
    self.assertEqual(passes[0]["cve_view"]["counts"], counts)
    c = passes[0]["cve_view"]["counts"]
    self.assertEqual(c["listed"] + c["rolled_up"] + c["possible"] + c["folded"] + c["closed"] + c["dropped"], c["raw"])
    self.assertEqual(passes[1]["cve_view"]["counts"]["dropped"], 0)  # no stored counts

  def test_pagination_keeps_the_view_and_summary_does_not_need_it(self):
    stored = archive([finding(1)], [finding(2)])
    page = self.read(stored, pass_offset=1)["archive"]
    self.assertEqual([p["pass_nr"] for p in page["passes"]], [2])
    self.assertIn("cve_view", page["passes"][0])
    summary = self.read(stored, summary_only=True)["archive"]["passes"]
    self.assertNotIn("cve_view", summary[0])

  def test_a_model_test_archive_is_returned_as_is(self):
    stored = {"job_type": "model_test", "passes": [{"findings": [finding(1)]}]}
    self.assertNotIn("cve_view", self.read(stored)["archive"]["passes"][0])


if __name__ == "__main__":
  unittest.main()
