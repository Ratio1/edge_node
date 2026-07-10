import json
import sys
import time
import types
import unittest
from unittest.mock import MagicMock


def _install_pymisp_stub():
  if "pymisp" in sys.modules:
    return
  pymisp_stub = types.ModuleType("pymisp")
  pymisp_stub.MISPEvent = MagicMock
  pymisp_stub.MISPObject = MagicMock
  pymisp_stub.MISPAttribute = MagicMock
  pymisp_stub.PyMISP = MagicMock
  sys.modules["pymisp"] = pymisp_stub


_install_pymisp_stub()

from extensions.business.cybersec.red_mesh.services.control import purge_job
from extensions.business.cybersec.red_mesh.services.rulebook_assessment import (
  DEFAULT_RULEBOOK_PROFILE_ID,
  build_rulebook_assessment,
  ensure_rulebook_assessment,
  generate_rulebook_assessment,
  get_rulebook_assessment_status,
  get_rulebook_review,
  update_rulebook_review,
)


def _sample_findings():
  return [
    {
      "finding_id": "finding-auth-1",
      "severity": "HIGH",
      "title": "Authentication bypass on app.example.test",
      "description": "The endpoint leaks token=supersecret for 10.0.0.4.",
      "evidence": {"raw_response": "password=supersecret", "credential_ref": "secret://graybox"},
      "remediation": "Require authentication and validate sessions.",
      "cwe_id": "CWE-306",
      "owasp_id": "A01:2021",
      "probe": "_web_test_auth_bypass",
      "category": "auth",
      "status": "vulnerable",
    },
    {
      "finding_id": "finding-crypto-1",
      "severity": "LOW",
      "title": "TLS certificate expires soon on app.example.test",
      "description": "Certificate metadata needs review.",
      "cwe_id": "CWE-295",
      "probe": "_tls_certificate_check",
      "category": "tls",
      "status": "vulnerable",
    },
  ]


def _sample_pass_report():
  return {
    "pass_nr": 3,
    "date_started": 1770000000.0,
    "date_completed": 1770000300.0,
    "aggregated_report_cid": "agg-cid",
    "risk_score": 75,
    "quick_summary": "Issues were observed on app.example.test.",
    "findings": _sample_findings(),
  }


def _sample_archive():
  return {
    "job_id": "job-1",
    "job_config": {
      "target": "https://app.example.test/login",
      "target_url": "https://app.example.test/login",
      "scan_type": "webapp",
      "task_name": "Application scan",
      "start_port": 443,
      "end_port": 443,
      "secret_ref": "secret://graybox",
    },
    "passes": [_sample_pass_report()],
    "ui_aggregate": {},
    "duration": 300.0,
    "date_created": 1770000000.0,
    "date_completed": 1770000300.0,
    "soc_event_status": {"last_status": "sent"},
  }


def _sample_job_specs(**overrides):
  payload = {
    "job_id": "job-1",
    "job_status": "FINALIZED",
    "scan_type": "webapp",
    "target": "https://app.example.test/login",
    "target_url": "https://app.example.test/login",
    "job_cid": "archive-cid",
    "job_config_cid": "config-cid",
    "date_created": 1770000000.0,
    "date_completed": 1770000300.0,
    "run_mode": "SINGLEPASS",
    "launcher": "operator",
    "start_port": 443,
    "end_port": 443,
  }
  payload.update(overrides)
  return payload


class _FakeArtifactRepo:
  def __init__(self, owner, archive=None, aggregated=None):
    self.owner = owner
    self.archive = archive or _sample_archive()
    self.aggregated = aggregated or {"open_ports": [443]}
    self.deleted = []

  def get_archive(self, job_specs):
    return self.archive

  def get_json(self, cid):
    if cid == "archive-cid":
      return self.archive
    if cid == "agg-cid":
      return self.aggregated
    if cid == "config-cid":
      return self.archive.get("job_config", {})
    return self.owner.artifacts.get(cid)

  def get_job_config(self, job_specs):
    return self.archive.get("job_config", {})

  def get_pass_report(self, report_cid):
    return self.owner.artifacts.get(report_cid)

  def put_json(self, payload, *, show_logs=False):
    return self.owner.r1fs.add_json(payload, show_logs=show_logs)

  def delete(self, cid, *, show_logs=False, raise_on_error=False):
    self.deleted.append(cid)
    return True


class _Owner:
  cfg_instance_id = "tenant-a"

  def __init__(self, job_specs=None, archive=None):
    self.job_specs = job_specs or _sample_job_specs()
    self.archive = archive or _sample_archive()
    self.artifacts = {}
    self.records = {}
    self.messages = []
    self.audit_events = []
    self.artifact_repo = _FakeArtifactRepo(self, archive=self.archive)
    self.r1fs = MagicMock()
    self.r1fs.add_json.side_effect = self._add_json

  def _add_json(self, payload, show_logs=False):
    cid = f"QmRulebook{len(self.artifacts) + 1}"
    self.artifacts[cid] = payload
    return cid

  def P(self, msg, **kwargs):
    self.messages.append(msg)

  def time(self):
    return 1770000400.0

  def _get_job_from_cstore(self, job_id):
    return self.job_specs if job_id == "job-1" else None

  def _get_artifact_repository(self):
    return self.artifact_repo

  def _write_job_record(self, job_id, updated, context=""):
    self.job_specs = updated
    self.records[(self.cfg_instance_id, job_id)] = updated
    return updated

  def _normalize_job_record(self, job_id, raw):
    return job_id, raw

  def _log_audit_event(self, event_type, payload):
    self.audit_events.append((event_type, payload))

  def chainstore_hget(self, hkey, key):
    return self.records.get((hkey, key))

  def chainstore_hset(self, hkey, key, value):
    self.records[(hkey, key)] = value
    return True

  def chainstore_hgetall(self, hkey):
    return {
      key: value
      for (row_hkey, key), value in self.records.items()
      if row_hkey == hkey and value is not None
    }


class TestRulebookAssessment(unittest.TestCase):

  def test_generate_persists_artifact_metadata_and_redacts_sensitive_values(self):
    owner = _Owner()

    result = generate_rulebook_assessment(owner, "job-1")

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["artifact_cid"], "QmRulebook1")
    self.assertEqual(
      owner.job_specs["rulebook_assessments"][DEFAULT_RULEBOOK_PROFILE_ID]["artifact_cid"],
      "QmRulebook1",
    )
    meta = owner.job_specs["rulebook_assessments"][DEFAULT_RULEBOOK_PROFILE_ID]
    self.assertTrue(meta["auto_enabled"])
    self.assertEqual(meta["run_state"], "succeeded")
    self.assertEqual(meta["latest_pass_nr"], 3)
    self.assertEqual(meta["history"], [])
    assessment = owner.artifacts["QmRulebook1"]
    self.assertEqual(assessment["schema"], "redmesh.rulebook_assessment.v1")
    self.assertEqual(assessment["profile"]["profile_id"], DEFAULT_RULEBOOK_PROFILE_ID)
    self.assertGreater(assessment["status_counts"]["gap"], 0)

    serialized = json.dumps(assessment, sort_keys=True).lower()
    self.assertNotIn("app.example.test", serialized)
    self.assertNotIn("10.0.0.4", serialized)
    self.assertNotIn("supersecret", serialized)
    self.assertNotIn("credential_ref", serialized)
    self.assertNotIn("secret://graybox", serialized)
    self.assertNotIn("non_compliant", serialized)
    self.assertNotIn("compliant", serialized)
    self.assertIn("target:", serialized)

    status = get_rulebook_assessment_status(owner, "job-1")
    self.assertTrue(status["found"])
    self.assertTrue(status["generated"])
    self.assertEqual(status["artifact_cid"], "QmRulebook1")
    self.assertEqual(status["run_state"], "succeeded")

  def test_ensure_is_idempotent_for_existing_same_pass_and_force_regenerates(self):
    owner = _Owner()

    first = ensure_rulebook_assessment(owner, "job-1")
    second = ensure_rulebook_assessment(owner, "job-1")
    forced = generate_rulebook_assessment(owner, "job-1", force=True)

    self.assertEqual(first["artifact_cid"], "QmRulebook1")
    self.assertEqual(second["artifact_cid"], "QmRulebook1")
    self.assertTrue(second["cached"])
    self.assertEqual(forced["artifact_cid"], "QmRulebook2")
    self.assertEqual(owner.r1fs.add_json.call_count, 2)

    meta = owner.job_specs["rulebook_assessments"][DEFAULT_RULEBOOK_PROFILE_ID]
    self.assertEqual(meta["artifact_cid"], "QmRulebook2")
    self.assertEqual(meta["history"][0]["artifact_cid"], "QmRulebook1")

  def test_running_job_with_completed_pass_report_is_eligible(self):
    owner = _Owner(job_specs=_sample_job_specs(
      job_status="RUNNING",
      job_cid="",
      pass_reports=[{"pass_nr": 3, "report_cid": "pass-cid", "risk_score": 75}],
    ))
    owner.artifacts["pass-cid"] = _sample_pass_report()

    result = build_rulebook_assessment(owner, "job-1")

    self.assertEqual(result["status"], "ok")
    self.assertEqual(result["pass_nr"], 3)
    self.assertEqual(result["assessment"]["scan_context"]["job_status"], "RUNNING")

  def test_artifact_write_failure_persists_failed_status_without_generated_flag(self):
    owner = _Owner()
    owner.r1fs.add_json.side_effect = None
    owner.r1fs.add_json.return_value = None

    result = generate_rulebook_assessment(owner, "job-1")

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "artifact_write_failed")
    meta = owner.job_specs["rulebook_assessments"][DEFAULT_RULEBOOK_PROFILE_ID]
    self.assertEqual(meta["run_state"], "failed")
    self.assertTrue(meta["auto_enabled"])
    self.assertNotIn("artifact_cid", meta)
    status = get_rulebook_assessment_status(owner, "job-1")
    self.assertFalse(status["generated"])
    self.assertEqual(status["run_state"], "failed")
    self.assertEqual(status["last_error"]["error"], "artifact_write_failed")

  def test_reviewer_answer_cannot_hide_automated_gap_but_can_support_manual_check(self):
    owner = _Owner()

    review = update_rulebook_review(
      owner,
      "job-1",
      answers={
        "nis2.access.access_controls_reviewed": {"value": "yes", "note": "Reviewed."},
        "nis2.bcm.business_continuity": {"value": "yes", "note": "Plan exists."},
      },
      reviewer="alice",
      review_state="reviewed",
    )
    self.assertEqual(review["status"], "ok")
    self.assertEqual(review["audit"][-1]["changed_question_ids"], [
      "nis2.access.access_controls_reviewed",
      "nis2.bcm.business_continuity",
    ])

    result = build_rulebook_assessment(owner, "job-1")
    checks = {check["check_id"]: check for check in result["assessment"]["checks"]}

    self.assertEqual(checks["NIS2-21-ACCESS-001"]["automated_status"], "gap")
    self.assertEqual(checks["NIS2-21-ACCESS-001"]["status"], "gap")
    self.assertEqual(checks["NIS2-21-ACCESS-001"]["source"], "mixed")
    self.assertEqual(checks["NIS2-21-BCM-001"]["automated_status"], "not_observable")
    self.assertEqual(checks["NIS2-21-BCM-001"]["status"], "supported")
    self.assertEqual(checks["NIS2-21-BCM-001"]["source"], "reviewer")

    review_payload = get_rulebook_review(owner, "job-1")
    self.assertTrue(review_payload["found"])
    self.assertEqual(review_payload["review"]["review_state"], "reviewed")

  def test_invalid_review_answer_is_rejected(self):
    owner = _Owner()

    result = update_rulebook_review(
      owner,
      "job-1",
      answers={"nis2.unknown": {"value": "yes"}},
    )

    self.assertEqual(result["status"], "error")
    self.assertEqual(result["error"], "invalid_review_answer")

  def test_ineligible_jobs_fail_cleanly(self):
    model_owner = _Owner(job_specs=_sample_job_specs(job_type="model_test", scan_type="model_test"))
    running_owner = _Owner(job_specs=_sample_job_specs(job_status="RUNNING", job_cid=""))
    missing_pass_owner = _Owner(archive={**_sample_archive(), "passes": []})

    self.assertEqual(
      build_rulebook_assessment(model_owner, "job-1")["error"],
      "model_test_not_supported",
    )
    self.assertEqual(
      build_rulebook_assessment(running_owner, "job-1")["error"],
      "no_completed_passes",
    )
    self.assertEqual(
      update_rulebook_review(running_owner, "job-1", answers={})["error"],
      "job_not_finalized",
    )
    self.assertEqual(
      build_rulebook_assessment(missing_pass_owner, "job-1")["error"],
      "no_completed_passes",
    )

  def test_purge_removes_rulebook_artifact_and_review_rows(self):
    owner = _Owner(job_specs=_sample_job_specs(
      job_cid="",
      rulebook_assessments={
        DEFAULT_RULEBOOK_PROFILE_ID: {
          "artifact_cid": "QmRulebookAssessment",
          "history": [{"artifact_cid": "QmRulebookAssessmentOld"}],
        },
      },
    ))
    owner.records[(owner.cfg_instance_id, "job-1")] = owner.job_specs
    review_key = f"job-1:{DEFAULT_RULEBOOK_PROFILE_ID}"
    owner.records[(f"{owner.cfg_instance_id}:rulebook_review", review_key)] = {"job_id": "job-1"}
    owner.records[(f"{owner.cfg_instance_id}:rulebook_review:audit", review_key)] = [{"job_id": "job-1"}]

    result = purge_job(owner, "job-1")

    self.assertEqual(result["status"], "success")
    self.assertIn("QmRulebookAssessment", owner.artifact_repo.deleted)
    self.assertIn("QmRulebookAssessmentOld", owner.artifact_repo.deleted)
    self.assertIsNone(owner.records[(f"{owner.cfg_instance_id}:rulebook_review", review_key)])
    self.assertIsNone(owner.records[(f"{owner.cfg_instance_id}:rulebook_review:audit", review_key)])


if __name__ == "__main__":
  unittest.main()
