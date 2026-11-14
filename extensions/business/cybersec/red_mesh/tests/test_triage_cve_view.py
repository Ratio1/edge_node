"""Step 4a S5: the host triage map in `cve_view`, the risk walk and the archive merge."""
import unittest
from copy import deepcopy

from extensions.business.cybersec.red_mesh.cve_view import apply_triage, build_cve_view, effective_status
from extensions.business.cybersec.red_mesh.services.triage import _merge_triage_into_archive_dict
from .test_cve_view import _Host, conserved, fnd, raw

NOW = 1_000.0


def compute(findings, triage=None):
  report = {"target": "t", "port_protocols": {"80": "http"},
            "service_info": {"80": {"_service_info_http": {"findings": findings}}}}
  risk, flat = _Host()._compute_risk_and_findings(report, triage)
  return risk["breakdown"], flat


class TestEffectiveStatus(unittest.TestCase):
  def test_accepted_risk_reads_reopened_after_review_at_and_the_stored_record_is_untouched(self):
    record = {"status": "accepted_risk", "review_at": 500.0}
    self.assertEqual(effective_status(record, NOW), "reopened")
    self.assertEqual(effective_status(record, 400.0), "accepted_risk")
    self.assertEqual(record, {"status": "accepted_risk", "review_at": 500.0})
    self.assertEqual(effective_status({"status": "false_positive"}, NOW), "false_positive")
    self.assertEqual(effective_status("remediated", NOW), "remediated")

  def test_an_expired_accepted_risk_member_is_back_in_the_view(self):
    findings = [fnd(1), fnd(2)]
    live = {"id0001": {"status": "accepted_risk", "review_at": 5_000.0}}
    expired = {"id0001": {"status": "accepted_risk", "review_at": 500.0}}
    self.assertEqual(build_cve_view(findings, triage=live, now=NOW)["counts"]["closed"], 1)
    view = build_cve_view(findings, triage=expired, now=NOW)
    self.assertEqual(view["counts"]["closed"], 0)
    conserved(self, view)


class TestApplyTriage(unittest.TestCase):
  def test_the_record_is_embedded_on_a_copy_and_a_confirmed_possible_finding_is_certain(self):
    possible, firm = fnd(1, confidence="tentative", reason="banner_only"), fnd(2)
    triage = {"id0001": {"status": "open", "confirmed": True, "confirmed_by": "analyst"},
              "id0002": {"status": "open", "confirmed": True, "confirmed_by": "analyst"}}
    before = deepcopy([possible, firm])
    out = apply_triage([possible, firm, {"finding_id": "other"}], triage)
    self.assertEqual([possible, firm], before)
    self.assertEqual((out[0]["confidence"], out[0]["confidence_reason"], out[0]["verified_by"]),
                     ("certain", "triage_confirmed", "analyst"))
    self.assertEqual(out[0]["triage"], triage["id0001"])
    self.assertEqual((out[1]["confidence"], out[1]["confidence_reason"]), ("firm", "nvd_range"))  # only tentative
    self.assertNotIn("triage", out[2])

  def test_an_unconfirmed_record_does_not_raise_confidence(self):
    out = apply_triage([fnd(1, confidence="tentative")], {"id0001": {"status": "open"}})
    self.assertEqual(out[0]["confidence"], "tentative")


class TestRiskWalkWithHostTriage(unittest.TestCase):
  def test_confirm_moves_a_possible_finding_into_the_score_on_the_rerun(self):
    findings = [raw(1, "CRITICAL", confidence="tentative", reason="banner_only", kev=True)]
    before, _ = compute(findings)
    self.assertEqual((before["findings_score"], before["possible_cves"]), (0.0, 1))
    after, flat = compute(findings, {"id0001": {"status": "open", "confirmed": True, "confirmed_by": "a"}})
    self.assertGreater(after["findings_score"], 0)
    self.assertEqual((after["finding_counts"]["CRITICAL"], after["cve_view_counts"]["possible"]), (1, 0))
    self.assertEqual((flat[0]["confidence"], flat[0]["confidence_reason"], flat[0]["verified_by"]),
                     ("certain", "triage_confirmed", "a"))

  def test_a_closed_member_leaves_the_score_and_every_finding_carries_its_triage(self):
    findings = [raw(1, "CRITICAL", kev=True), raw(2, "HIGH")]
    base, _ = compute(findings)
    closed, flat = compute(findings, {"id0002": {"status": "false_positive", "actor": "a"}})
    self.assertLess(closed["findings_score"], base["findings_score"])
    self.assertEqual(closed["cve_view_counts"]["closed"], 1)
    by_id = {f["finding_id"]: f for f in flat}
    self.assertEqual(by_id["id0002"]["triage"]["status"], "false_positive")  # exports keep a closed CVE, with triage
    self.assertNotIn("triage", by_id["id0001"])

  def test_closed_findings_in_the_flat_list_leave_a_later_view_without_the_map(self):
    # What `with_cve_views`, `filter_listed` and the LLM input see: the embedded record alone closes the member.
    _, flat = compute([raw(1, "CRITICAL", kev=True), raw(2, "HIGH", kev=True)],
                      {"id0002": {"status": "remediated"}})
    view = build_cve_view(flat)
    self.assertEqual((view["counts"]["closed"], view["services"][0]["listed"]), (1, ["id0001"]))
    conserved(self, view)


class TestArchiveMerge(unittest.TestCase):
  def archive(self):
    return {"passes": [{"findings": [fnd(1, confidence="tentative"), fnd(2)]}],
            "ui_aggregate": {"top_findings": [fnd(2)]}}

  def test_merge_embeds_triage_and_reads_a_confirmed_finding_certain_without_rewriting_the_input(self):
    archive = self.archive()
    before = deepcopy(archive)
    merged = _merge_triage_into_archive_dict(archive, {
      "id0001": {"status": "open", "confirmed": True, "confirmed_by": "a"}, "id0002": {"status": "remediated"}})
    self.assertEqual(archive, before)
    first, second = merged["passes"][0]["findings"]
    self.assertEqual((first["confidence"], first["triage"]["status"]), ("certain", "open"))
    self.assertEqual(second["triage"]["status"], "remediated")
    self.assertEqual(merged["ui_aggregate"]["top_findings"][0]["triage"]["status"], "remediated")
    # the view built from the merged archive closes the remediated member and lists the confirmed one
    view = build_cve_view(merged["passes"][0]["findings"])
    self.assertEqual(view["counts"]["closed"], 1)


class TestFinalizationReadsHostTriage(unittest.TestCase):
  def run_finalization(self, records):
    from extensions.business.cybersec.red_mesh.services.finalization import maybe_finalize_pass
    from .test_tenant_execution_finalization import FinalizationOwner, execution_binding

    class Owner(FinalizationOwner):
      def chainstore_hgetall(self, hkey):
        if hkey.startswith("deployment:triage:t:"):
          return deepcopy(records.get(hkey, {}))
        return super().chainstore_hgetall(hkey)

    owner = Owner()
    seen = []
    real = owner._compute_risk_and_findings

    def spy(aggregated, triage=None):
      seen.append(triage)
      return real(aggregated, triage)
    owner._compute_risk_and_findings = spy
    maybe_finalize_pass(owner)
    return seen, execution_binding()["tenant_id"]

  def test_the_pass_is_scored_with_the_hosts_triage_of_its_own_tenant_only(self):
    from .test_tenant_execution_finalization import execution_binding
    tenant = execution_binding()["tenant_id"]
    record = {"job_id": "older", "finding_id": "f1", "status": "false_positive", "tenant_id": tenant,
              "host": "192.0.2.10"}
    seen, _ = self.run_finalization({f"deployment:triage:t:{tenant}": {"192.0.2.10\x1ff1": record},
                                     "deployment:triage:t:tn_other": {"192.0.2.10\x1ff2": record}})
    self.assertEqual(seen, [{"f1": record}])

  def test_without_triage_the_compute_is_called_as_before(self):
    seen, _ = self.run_finalization({})
    self.assertEqual(seen, [None])


if __name__ == "__main__":
  unittest.main()
