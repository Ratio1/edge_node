"""RM-169 step 2c-ii-a: `build_cve_view` listing, rollup, possible rows and conservation."""

import tempfile
import unittest

from extensions.business.cybersec.red_mesh import cve_db
from extensions.business.cybersec.red_mesh.findings import _finding_to_jsonable
from extensions.business.cybersec.red_mesh.cve_view import build_cve_view
from extensions.business.cybersec.red_mesh.vulndb.reader import load_vulndb

from .test_vulndb_findings import CVE, build

NET = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def fnd(n, *, confidence="firm", kev=False, score=9.8, vector=NET, version="3.1", constraint="<2.0", reason="nvd_range",
        port=80, product="apache", ver="1.5", epss=0.1, build_id="b1", cvss=None):
  cve = "CVE-2030-%04d" % n
  return {
    "finding_id": "id%04d" % n, "cve": [cve], "port": port, "confidence": confidence, "confidence_reason": reason,
    "kev": kev, "cvss_score": score, "cvss_version": version, "cvss_source": "nvd", "epss_score": epss,
    "vulndb_build_id": build_id,
    "cvss": [{"version": version, "vector": vector, "score": score, "source": "nvd"}] if cvss is None else cvss,
    "evidence": "Detected version: %s, affected: %s" % (ver, constraint),
    "description": "%s %s is vulnerable to %s. x" % (product, ver, cve),
  }


def conserved(test, view):
  c = view["counts"]
  test.assertEqual(c["listed"] + c["rolled_up"] + c["possible"] + c["closed"] + c["dropped"], c["raw"])


class CveViewTests(unittest.TestCase):
  def one(self, findings, **kw):
    view = build_cve_view(findings, **kw)
    conserved(self, view)
    return view, view["services"][0]

  def test_only_generated_cve_findings_make_a_view(self):
    static = fnd(1, build_id=None)
    self.assertIsNone(build_cve_view([static, {"title": "no cve", "finding_id": "x"}]))
    view, service = self.one([static, fnd(2, kev=True)])
    self.assertEqual((view["counts"]["raw"], service["listed"]), (1, ["id0002"]))

  def test_listing_cut(self):
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    findings = [
      fnd(1, kev=True, score=5.0, vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L"),  # KEV
      fnd(2),                                                           # AV:N PR:N 9.x
      fnd(3, vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),   # PR:L
      fnd(4, vector="AV:N/AC:L/Au:N/C:C/I:C/A:C", version="2.0", score=10.0),  # v2.0 never counts
      fnd(5, vector=v4, version="4.0", score=9.3),
      fnd(6, score=8.9),
    ]
    view, service = self.one(findings)
    self.assertEqual(set(service["listed"]), {"id0001", "id0002", "id0005"})
    self.assertEqual(service["listed"][0], "id0001")  # KEV first
    self.assertEqual(sorted(service["rollup"]["member_finding_ids"]), ["id0003", "id0004", "id0006"])
    self.assertEqual(view["counts"], {"raw": 6, "listed": 3, "rolled_up": 3, "possible": 0, "closed": 0, "dropped": 0})

  def test_v2_entry_with_network_text_never_lists(self):
    entry = [{"version": "2.0", "vector": "AV:N/PR:N/AV:N/PR:N", "score": 10.0, "source": "nvd"}]
    view, service = self.one([fnd(1, cvss=entry, score=5.0)])
    self.assertEqual(service["listed"], [])
    self.assertEqual(service["rollup"]["max_cvss"]["version"], "3.1")

  def test_order_epss_then_cve_id_and_missing_score_last(self):
    findings = [fnd(3, epss=0.5), fnd(2, epss=0.5), fnd(1, epss=0.9), fnd(4, score=None, cvss=[
      {"version": "3.1", "vector": NET, "score": 9.5, "source": "cna"}])]
    _, service = self.one(findings)
    self.assertEqual(service["listed"], ["id0001", "id0002", "id0003", "id0004"])

  def test_no_score_gives_an_empty_max_cvss(self):
    _, service = self.one([fnd(1, score=None, cvss=[], version="")])
    self.assertEqual(service["rollup"]["max_cvss"], {"score": None, "version": None, "source": None})

  def test_review_at_equal_to_now_is_reopened(self):
    view, service = self.one([fnd(1)], triage={"id0001": {"status": "accepted_risk", "review_at": 1000}}, now=1000)
    self.assertEqual((view["counts"]["closed"], service["listed"]), (0, ["id0001"]))

  def test_possible_reasons_and_input_order(self):
    findings = [fnd(1, confidence="tentative", reason="nvd_exact"), fnd(2, confidence="tentative", reason="banner_only"),
                fnd(3, confidence="tentative", reason="banner_only", kev=True), fnd(4, score=5.0), fnd(5, score=4.0),
                fnd(6, port=None), fnd(7, port=8080), fnd(8, port=443, product="nginx", ver="1.0")]
    view, service = self.one(findings)
    self.assertEqual(service["possible"]["reasons"], {"banner_only": 2, "nvd_exact": 1})
    self.assertEqual([s["port"] for s in view["services"]], [80, 443, 8080, None])
    self.assertEqual(view, build_cve_view(list(reversed(findings))))
    self.assertEqual(build_cve_view(findings[:5])["services"][0]["version"], "1.5")

  def test_the_cut_reads_the_cvss_entry_not_the_label(self):
    other = [{"version": "3.1", "vector": NET, "score": 9.8, "source": "cna"}]
    _, service = self.one([fnd(1, score=7.5, cvss=other)])  # label 7.5, the CNA entry makes the cut
    self.assertEqual(service["listed"], ["id0001"])

  def test_at_most_ten_listed_overflow_goes_to_the_rollup(self):
    findings = [fnd(n, score=9.0 + n / 100) for n in range(1, 14)]
    _, service = self.one(findings)
    self.assertEqual(len(service["listed"]), 10)
    self.assertEqual(service["listed"][0], "id0013")  # highest score first
    self.assertEqual(sorted(service["rollup"]["member_finding_ids"]), ["id0001", "id0002", "id0003"])

  def test_rollup_fix_version_and_totals(self):
    findings = [
      fnd(1, score=5.0, constraint=">=1.0,<1.9"), fnd(2, score=6.0, constraint="<1.10", kev=True),
      fnd(3, score=4.0, constraint="<=1.8,<1.2"),
    ]
    _, service = self.one(findings)
    rollup = service["rollup"]
    self.assertEqual((rollup["fix_version"], rollup["cve_count"], rollup["kev_count"]), ("1.9", 2, 0))  # `<1.10` is the listed KEV member's
    self.assertEqual(rollup["max_cvss"], {"score": 5.0, "version": "3.1", "source": "nvd"})
    self.assertEqual(service["listed"], ["id0002"])
    self.assertEqual(rollup["member_finding_ids"], ["id0001", "id0003"])

  def test_no_fixed_version_when_a_member_has_no_upper_bound(self):
    _, service = self.one([fnd(n, score=5.0, constraint=c) for n, c in ((1, "<1.9"), (2, "<=1.8"), (3, "==1.5"))])
    self.assertIsNone(service["rollup"]["fix_version"])
    self.assertEqual(service["rollup"]["cve_count"], 3)

  def test_services_are_split_by_port_and_product(self):
    view, _ = self.one([fnd(1, port=80), fnd(2, port=443), fnd(3, port=80, product="nginx")])
    self.assertEqual({(s["port"], s["product"]) for s in view["services"]},
                     {(80, "apache"), (443, "apache"), (80, "nginx")})
    self.assertEqual({s["version"] for s in view["services"]}, {"1.5"})

  def test_possible_section_caps_on_a_weblogic_sized_version(self):
    # 186 exact-only rows give tentative findings on one version, 8 of them in KEV.
    findings = [fnd(n, confidence="tentative", reason="nvd_exact", kev=n <= 8, score=float(n % 10), product="weblogic")
                for n in range(1, 187)]
    findings.append(fnd(500, product="weblogic", kev=True))
    view, service = self.one(findings)
    possible = service["possible"]
    self.assertEqual((possible["count"], possible["reasons"], len(possible["top"])), (186, {"nvd_exact": 186}, 3))
    self.assertEqual(len(possible["member_finding_ids"]), 186)
    self.assertEqual(len(service["possible_kev"]), 8)
    self.assertTrue(set(service["possible_kev"]) <= set(possible["member_finding_ids"]))
    self.assertTrue(all(t["cve_id"] in ("CVE-2030-%04d" % n for n in range(1, 9)) for t in possible["top"]))  # KEV first
    self.assertEqual(view["counts"], {"raw": 187, "listed": 1, "rolled_up": 0, "possible": 186, "closed": 0, "dropped": 0})
    self.assertIsNone(service["rollup"])

  def test_closed_and_dropped_are_counted_once(self):
    findings = [fnd(1, kev=True), fnd(2), fnd(3, confidence="tentative"), fnd(4), fnd(5), fnd(6)]
    triage = {"id0001": "false_positive", "id0003": {"status": "remediated"},
              "id0004": {"status": "accepted_risk", "review_at": 2000}, "id0005": {"status": "accepted_risk", "review_at": 500},
              "id0006": "open"}
    view, service = self.one(findings, triage=triage, now=1000, not_applicable=[{"cve_id": "a"}, {"cve_id": "b"}])
    self.assertEqual(view["counts"], {"raw": 8, "listed": 3, "rolled_up": 0, "possible": 0, "closed": 3, "dropped": 2})
    self.assertEqual(sorted(service["listed"]), ["id0002", "id0005", "id0006"])
    self.assertNotIn("id0001", service["listed"])
    self.assertIsNone(service["possible"])

  def test_the_evidence_and_description_format_is_pinned(self):
    """The view reads the matched constraint and the product from the text `check_cves` writes."""
    static = cve_db.check_cves("openssh", "4.0")
    self.assertTrue(static)
    with tempfile.TemporaryDirectory() as tmp:
      reader, keys = load_vulndb("generated", *build(tmp))
      self.assertIsNone(keys["vulndb_load_error"])
      cve_db.set_vulndb_reader(reader)
      self.addCleanup(cve_db.set_vulndb_reader, None)
      generated = cve_db.check_cves("openssh", "4.0")
    for source, found in (("static", static), ("generated", generated)):
      for f in found:
        with self.subTest(source=source, cve=f.cve[0]):
          self.assertRegex(f.evidence, r"^Detected version: 4\.0, affected: \S+$")
          self.assertTrue(f.description.startswith("openssh 4.0 is vulnerable to CVE-"))
    flat = [dict(_finding_to_jsonable(f), confidence="firm", cvss_score=5.0, cvss=[]) for f in generated]
    service = build_cve_view(flat)["services"][0]
    self.assertEqual((service["product"], service["version"]), ("openssh", "4.0"))
    self.assertEqual(service["rollup"]["fix_version"], "9.8")  # the matched `<9.8` row of the tiny database
    self.assertEqual(CVE, generated[0].cve[0])


if __name__ == "__main__":
  unittest.main()
