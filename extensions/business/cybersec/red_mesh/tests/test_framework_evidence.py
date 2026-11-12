"""RM-120 phase 5: evidence suggestions for the framework self-assessment through the real endpoint.

A tenant's finalized scans reach the suggester only through the tenant read seam; suggestions name
jobs and passes, never a finding title or a target; they change no score; `job:` evidence refs on
a draft must name a scan the tenant owns and has finalized.
"""
import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import patch
from uuid import uuid4

from extensions.business.cybersec.red_mesh.references.framework_packs import controls_for_level, load_framework_pack, list_framework_pack_ids
from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
from extensions.business.cybersec.red_mesh.services import evidence_engine, framework_evidence
from extensions.business.cybersec.red_mesh.tenancy import compliance

from .test_execution_binding_models import binding_payload
from .test_framework_assessment import PACK, FrameworkAssessmentFixture


class TestControlSignalMap(unittest.TestCase):
  def test_every_mapped_control_exists_and_every_kind_is_known(self):
    for pack_id, mapping in framework_evidence.CONTROL_SIGNALS.items():
      self.assertIn(pack_id, list_framework_pack_ids())
      pack = load_framework_pack(pack_id)
      known = {c["ref_id"] for c in pack["controls"]}
      self.assertEqual(set(mapping) - known, set(), pack_id)
      self.assertEqual(set(mapping.values()) - set(evidence_engine.SIGNAL_KINDS), set(), pack_id)

  def test_the_basic_level_has_a_mapped_control_for_the_main_signals(self):
    pack = load_framework_pack(PACK)
    basic = framework_evidence.mapped_controls(PACK, pack, "basic")
    for kind in ("vulnerability_management", "auth_access_findings", "assessment_performed", "soc_incident_evidence"):
      self.assertIn(kind, basic.values(), kind)
    self.assertNotIn("PR.DS-02.2", basic)  # Essential only
    self.assertIn("PR.DS-02.2", framework_evidence.mapped_controls(PACK, pack, "essential"))

  def test_job_refs_and_their_ownership_check(self):
    patch_body = {"scores": {"PR.AA-01.1": {"evidence_refs": [{"ref": "job:j-1:1", "review_state": "linked"},
                                                              {"ref": "contract", "review_state": "linked"},
                                                              {"ref": "job:j-2:3", "review_state": "linked"}]},
                             "GV.OC-03.1": {"evidence_refs": "nonsense"}}}
    refs = framework_evidence.job_refs(patch_body)
    self.assertEqual(refs, [("job:j-1:1", "j-1"), ("job:j-2:3", "j-2")])
    jobs = {"j-1": {"job_status": "FINALIZED"}, "j-2": {"job_status": "RUNNING"}}
    self.assertEqual(framework_evidence.invalid_job_refs(refs, jobs), ["job:j-2:3"])
    self.assertEqual(framework_evidence.invalid_job_refs(refs, {}), ["job:j-1:1", "job:j-2:3"])
    self.assertEqual(framework_evidence.job_refs({"assurance_level": "basic"}), [])
    # One grammar object: a job ref the validator accepts is one the ownership check sees.
    self.assertIs(framework_evidence._JOB_REF, compliance.JOB_REF)
    self.assertIsNotNone(compliance._EVIDENCE_REF.match("job:j-1:12"))
    self.assertIsNone(compliance._EVIDENCE_REF.match("job:j 1:12"))


class TestFrameworkEvidenceSuggestions(FrameworkAssessmentFixture):
  def setUp(self):
    super().setUp()
    framework_evidence.reset_cache()
    self.archives = {}
    self.plugin.r1fs = SimpleNamespace(get_json=lambda cid, *args, **kwargs: deepcopy(self.archives.get(cid)))
    self.revision = self.ok(self.save({"assurance_level": "basic",
                                       "level_provenance": {"kind": "declared"}}, 1))["assessmentRevision"]
    self.events.clear()

  # -- fixtures ---------------------------------------------------------------------------------

  def job(self, job_id, *, tenant=None, finalized=True, findings=None, completed=1770000300.0, soc=None):
    binding = {**binding_payload(), "tenant_id": tenant or self.tenant}
    record = {"job_id": job_id, "launcher": "operator", "workers": {}, "scan_type": "webapp",
              "job_status": "FINALIZED" if finalized else "RUNNING", "target": "https://app.example.test",
              "date_created": completed - 300, "date_completed": completed if finalized else None,
              "execution_binding": binding}
    if finalized:
      record["job_cid"] = f"archive-{job_id}"
      archive = {"job_id": job_id, "job_config": {"target": "https://app.example.test", "execution_binding": deepcopy(binding)},
                 "passes": [{"pass_nr": 2, "date_completed": completed, "findings": findings or []}]}
      if soc is not None:
        archive["soc_event_status"] = soc
      self.archives[f"archive-{job_id}"] = archive
    else:
      record["pass_reports"] = []
    self.storage.data[(self.plugin.cfg_instance_id, job_id)] = record
    return record

  def triage(self, job_id, finding_id, status):
    hkey = JobStateRepository(self.plugin)._triage_hkey
    self.storage.data[(hkey, f"{job_id}:{finding_id}")] = {"status": status}

  def suggest(self, actor=None):
    return self.plugin.suggest_framework_assessment_evidence(actor or self.admin, self.tenant, PACK)

  HIGH_AUTH = {"finding_id": "f-auth", "severity": "HIGH", "title": "Authentication bypass on app.example.test",
               "description": "token=supersecret leaks", "cwe_id": "CWE-306", "status": "vulnerable"}
  LOW_TLS = {"finding_id": "f-tls", "severity": "LOW", "title": "TLS certificate expires soon", "category": "tls",
             "status": "vulnerable"}

  # -- suggestions ------------------------------------------------------------------------------

  def test_a_finalized_scan_suggests_on_mapped_controls_and_changes_nothing(self):
    self.job("job-1", findings=[self.HIGH_AUTH, self.LOW_TLS], soc={"last_status": "sent"})
    before, writes = self.stored_row(), len(self.storage.writes)
    data = self.ok(self.suggest())
    self.assertEqual((data["packId"], data["assuranceLevel"], data["jobsAvailable"], data["jobsConsidered"]),
                     (PACK, "basic", 1, 1))
    auth = data["suggestions"]["PR.AA-01.1"]
    self.assertEqual(auth, [{"ref": "job:job-1:2", "signal_kind": "auth_access_findings", "status": "gap",
                             "summary": "1 unresolved medium-or-higher finding(s) in pass 2 match this control.",
                             "job_id": "job-1", "pass_nr": 2, "completed_at": "2026-02-02T02:45:00Z",
                             "counts": {"gap": 1, "review": 0}}])
    self.assertEqual(data["suggestions"]["ID.RA-01.1"][0]["counts"], {"gap": 1, "review": 1})
    self.assertEqual(data["suggestions"]["ID.RA-05.1"][0]["status"], "supported")
    self.assertEqual(data["suggestions"]["DE.AE-03.1"][0]["status"], "supported")
    self.assertNotIn("PR.DS-02.2", data["suggestions"])  # not counted at Basic
    self.assertIn({"control_id": "PR.AA-01.1", "ref": "job:job-1:2", "job_id": "job-1", "pass_nr": 2,
                   "severities": {"HIGH": 1}}, data["overriding"])
    # Nothing a tenant browser must not see: no finding title, no target, no CID.
    text = str(data)
    for secret in ("supersecret", "app.example.test", "archive-job-1", "Authentication bypass"):
      self.assertNotIn(secret, text)
    self.assertEqual((self.stored_row(), len(self.storage.writes)), (before, writes))
    self.assertEqual(self.events, [])

  def test_triage_closed_findings_and_unfinalized_jobs_do_not_count(self):
    self.job("job-1", findings=[self.HIGH_AUTH])
    self.triage("job-1", "f-auth", "false_positive")
    self.job("job-2", finalized=False, findings=[self.HIGH_AUTH])
    data = self.ok(self.suggest())
    self.assertEqual((data["jobsAvailable"], data["jobsConsidered"]), (1, 1))
    self.assertEqual(data["suggestions"]["PR.AA-01.1"][0]["status"], "supported")
    self.assertEqual(data["overriding"], [])

  def test_bounded_to_the_twenty_most_recent_finalized_jobs_and_three_per_control(self):
    for index in range(25):
      self.job(f"job-{index:02d}", findings=[self.HIGH_AUTH], completed=1770000000.0 + index * 60)
    self.job("foreign", tenant="tn_" + str(uuid4()), findings=[self.HIGH_AUTH], completed=1770009999.0)
    data = self.ok(self.suggest())
    self.assertEqual((data["jobsAvailable"], data["jobsConsidered"], data["jobsSkipped"]), (25, 20, 0))
    refs = [item["ref"] for item in data["suggestions"]["PR.AA-01.1"]]
    self.assertEqual(refs, ["job:job-24:2", "job:job-23:2", "job:job-22:2"])
    self.assertNotIn("foreign", str(data))

  def test_cached_per_draft_revision_until_the_draft_changes(self):
    self.job("job-1", findings=[self.HIGH_AUTH])
    calls = []
    real = framework_evidence._resolve_scan_context

    def counting(owner, job_id, pass_nr=None, **kwargs):
      calls.append(job_id)
      return real(owner, job_id, pass_nr, **kwargs)

    with patch.object(framework_evidence, "_resolve_scan_context", counting):
      first = self.ok(self.suggest())
      second = self.ok(self.suggest(self.viewer))
      self.assertEqual(calls, ["job-1"])
      self.assertEqual(first["suggestions"], second["suggestions"])
      self.ok(self.save({"sectoral_requirements": "sector energie"}, self.revision))
      self.ok(self.suggest())
      self.assertEqual(calls, ["job-1", "job-1"])

  def test_without_a_level_the_answer_is_empty_and_reads_no_job(self):
    self.ok(self.save({"assurance_level": None}, self.revision))
    self.job("job-1", findings=[self.HIGH_AUTH])
    with patch.object(framework_evidence, "_resolve_scan_context", side_effect=AssertionError("read")):
      data = self.ok(self.suggest())
    self.assertEqual((data["reason"], data["suggestions"], data["overriding"]), ("level_missing", {}, []))

  def test_roles_follow_the_assessment_view_and_refusals_are_audited(self):
    self.job("job-1", findings=[self.HIGH_AUTH])
    self.assertTrue(self.suggest(self.viewer)["success"])
    self.refused(self.suggest(self.pentester), 403, "forbidden")
    self.refused(self.suggest(self.stranger), 404, "not_found")
    self.assertEqual([(event, details["operation"], details["status_code"]) for event, details in self.events],
                     [("framework_assessment_refused", "suggest", 403), ("framework_assessment_refused", "suggest", 404)])

  # -- job refs on a draft ----------------------------------------------------------------------

  def test_a_job_ref_must_name_an_owned_finalized_scan(self):
    self.job("job-1", findings=[self.HIGH_AUTH])
    self.job("job-2", finalized=False)
    self.job("other", tenant="tn_" + str(uuid4()))
    link = lambda *refs: {"scores": {"PR.AA-01.1": {"documentation": 3, "implementation": 3, "excluded": False,
                                                    "justification": {"documentation": "a", "implementation": "b"},
                                                    "evidence_refs": [{"ref": ref, "review_state": "linked"} for ref in refs]}}}
    data = self.ok(self.save(link("job:job-1:2", "contract"), self.revision))
    self.assertEqual([r["ref"] for r in data["scores"]["PR.AA-01.1"]["evidence_refs"]], ["job:job-1:2", "contract"])
    revision = data["assessmentRevision"]
    for bad in ("job:job-2:1", "job:other:1", "job:missing:1"):
      result = self.save(link("job:job-1:2", bad), revision)
      self.refused(result, 400, "assessment_invalid")
      self.assertEqual(result["errors"], [{"code": "evidence_ref_invalid", "ids": [bad]}])
    self.assertEqual(self.ok(self.get())["assessmentRevision"], revision)  # nothing was written
    # A viewer is refused on authority before any job is read, whatever the payload says.
    self.refused(self.save(link("job:missing:1"), revision, actor=self.viewer), 403, "forbidden")
    self.assertEqual([details["operation"] for event, details in self.events if event == "framework_assessment_refused"],
                     ["save"] * 4)


if __name__ == "__main__":
  unittest.main()
