import json
import sys
import time
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
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
from extensions.business.cybersec.red_mesh.models import (
  RULEBOOK_ASSESSMENT_SCHEMA_VERSION,
  RULEBOOK_SUBMISSION_CONTRACT_VERSION,
  RulebookPendingSubmission,
  RulebookSubmissionReference,
  RulebookSubmissionRegistry,
)
from extensions.business.cybersec.red_mesh.repositories import JobStateRepository
from extensions.business.cybersec.red_mesh.services.rulebook_assessment import (
  DEFAULT_RULEBOOK_PROFILE_ID,
  build_rulebook_assessment,
  ensure_rulebook_assessment,
  generate_rulebook_assessment,
  get_rulebook_assessment_status,
  get_rulebook_review,
  reopen_rulebook_review,
  save_rulebook_review_draft,
  submit_rulebook_review,
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


def _complete_review_answers():
  return {
    "nis2.risk.risk_treatment_reviewed": {"value": "yes"},
    "nis2.incident.incident_process": {"value": "yes"},
    "nis2.bcm.business_continuity": {"value": "yes"},
    "nis2.supply.supplier_risk_reviewed": {"value": "yes"},
    "nis2.access.access_controls_reviewed": {"value": "yes"},
    "nis2.crypto.crypto_policy_reviewed": {"value": "yes"},
    "nis2.effectiveness.assessment_reviewed": {"value": "yes"},
    "nis2.reporting.reporting_process": {"value": "yes"},
  }


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
    self.owner.artifacts.pop(cid, None)
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
    self.assertEqual(assessment["schema_version"], "1.1.0")
    self.assertEqual(assessment["artifact_kind"], "generated_assessment")
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

  def test_persisted_generated_assessment_excludes_mutable_draft_review(self):
    owner = _Owner()
    update_rulebook_review(
      owner,
      "job-1",
      answers={"nis2.bcm.business_continuity": {"value": "yes", "note": "private draft comment"}},
      reviewer="draft-reviewer",
      review_state="draft",
    )

    preview = generate_rulebook_assessment(owner, "job-1", persist=False)
    persisted = generate_rulebook_assessment(owner, "job-1", persist=True)

    self.assertEqual(
      preview["assessment"]["checks"][2]["review_answer"]["note"],
      "private draft comment",
    )
    artifact = owner.artifacts[persisted["artifact_cid"]]
    self.assertEqual(artifact["review_state"], {"review_state": "draft", "answers": {}})
    serialized = json.dumps(artifact, sort_keys=True)
    self.assertNotIn("private draft comment", serialized)
    self.assertNotIn("draft-reviewer", serialized)

  def test_submission_models_and_registry_round_trip(self):
    reference = RulebookSubmissionReference(
      revision=1,
      cid="QmSubmission1",
      submitted_at=1770000400.0,
      actor="alice",
      pass_nr=3,
      profile_id=DEFAULT_RULEBOOK_PROFILE_ID,
      profile_version="1.0.0",
      schema_version=RULEBOOK_ASSESSMENT_SCHEMA_VERSION,
      review_revision=2,
      idempotency_key="submission-1",
      fingerprint="a" * 64,
    )
    pending = RulebookPendingSubmission(
      target_revision=2,
      expected_review_revision=3,
      expected_pass_nr=3,
      expected_profile_version="1.0.0",
      actor="alice",
      idempotency_key="submission-2",
      fingerprint="b" * 64,
    )
    registry = RulebookSubmissionRegistry(
      submissions=[reference],
      pending=pending,
    )

    payload = registry.to_dict()
    restored = RulebookSubmissionRegistry.from_dict(payload).to_dict()

    self.assertEqual(restored["contract_version"], RULEBOOK_SUBMISSION_CONTRACT_VERSION)
    self.assertEqual(restored["latest_revision"], 1)
    self.assertEqual(restored["submissions"][0]["cid"], "QmSubmission1")
    self.assertEqual(restored["pending"]["target_revision"], 2)

  def test_submission_registry_uses_dedicated_cstore_hash(self):
    owner = _Owner()
    repo = JobStateRepository(owner)
    registry = RulebookSubmissionRegistry(submissions=[])

    stored = repo.put_rulebook_submission_registry("job-1", DEFAULT_RULEBOOK_PROFILE_ID, registry)
    loaded = repo.get_rulebook_submission_registry_model("job-1", DEFAULT_RULEBOOK_PROFILE_ID)

    key = f"job-1:{DEFAULT_RULEBOOK_PROFILE_ID}"
    self.assertEqual(
      owner.records[(f"{owner.cfg_instance_id}:rulebook_review:submissions", key)],
      stored,
    )
    self.assertEqual(loaded.to_dict(), stored)

  def test_save_draft_is_revisioned_and_never_writes_r1fs(self):
    owner = _Owner()

    saved = save_rulebook_review_draft(
      owner,
      "job-1",
      answers={"nis2.bcm.business_continuity": {"value": "yes", "note": "Plan reviewed."}},
      actor="alice",
      expected_review_revision=0,
    )
    stale = save_rulebook_review_draft(
      owner,
      "job-1",
      answers={},
      actor="alice",
      expected_review_revision=0,
    )

    self.assertEqual(saved["status"], "ok")
    self.assertEqual(saved["review"]["review_revision"], 1)
    self.assertEqual(saved["effective_review_state"], "draft")
    self.assertEqual(stale["error"], "review_revision_conflict")
    self.assertEqual(owner.r1fs.add_json.call_count, 0)

  def test_submit_persists_complete_snapshot_and_replays_idempotently(self):
    owner = _Owner()
    saved = save_rulebook_review_draft(
      owner,
      "job-1",
      answers=_complete_review_answers(),
      actor="alice",
      expected_review_revision=0,
    )

    submitted = submit_rulebook_review(
      owner,
      "job-1",
      expected_review_revision=saved["review_revision"],
      expected_pass_nr=3,
      expected_profile_version="1.0.0",
      idempotency_key="submission-1",
      actor="alice",
    )
    replay = submit_rulebook_review(
      owner,
      "job-1",
      expected_review_revision=saved["review_revision"],
      expected_pass_nr=3,
      expected_profile_version="1.0.0",
      idempotency_key="submission-1",
      actor="alice",
    )
    conflict = submit_rulebook_review(
      owner,
      "job-1",
      expected_review_revision=saved["review_revision"],
      expected_pass_nr=3,
      expected_profile_version="1.0.0",
      idempotency_key="submission-1",
      actor="mallory",
    )

    self.assertEqual(submitted["effective_review_state"], "submitted")
    self.assertEqual(submitted["submission"]["revision"], 1)
    self.assertEqual(replay["submission"]["cid"], submitted["submission"]["cid"])
    self.assertTrue(replay["idempotent_replay"])
    self.assertEqual(conflict["error"], "submission_idempotency_conflict")
    self.assertEqual(owner.r1fs.add_json.call_count, 1)
    snapshot = owner.artifacts[submitted["submission"]["cid"]]
    self.assertEqual(snapshot["schema_version"], "1.1.0")
    self.assertEqual(snapshot["artifact_kind"], "review_submission")
    self.assertEqual(snapshot["submission"]["revision"], 1)
    self.assertEqual(snapshot["review_state"]["review_state"], "submitted")

  def test_submission_requires_complete_answers_and_comments(self):
    owner = _Owner()
    answers = _complete_review_answers()
    answers["nis2.reporting.reporting_process"] = {"value": "unknown", "note": ""}
    saved = save_rulebook_review_draft(
      owner,
      "job-1",
      answers=answers,
      actor="alice",
      expected_review_revision=0,
    )

    result = submit_rulebook_review(
      owner,
      "job-1",
      expected_review_revision=saved["review_revision"],
      expected_pass_nr=3,
      expected_profile_version="1.0.0",
      idempotency_key="submission-comments",
      actor="alice",
    )

    self.assertEqual(result["error"], "submission_comments_required")
    self.assertEqual(
      result["comment_required_question_ids"],
      ["nis2.reporting.reporting_process"],
    )
    self.assertEqual(owner.r1fs.add_json.call_count, 0)

  def test_r1fs_failure_keeps_draft_and_same_key_retry_recovers(self):
    owner = _Owner()
    saved = save_rulebook_review_draft(
      owner,
      "job-1",
      answers=_complete_review_answers(),
      actor="alice",
      expected_review_revision=0,
    )
    owner.r1fs.add_json.side_effect = None
    owner.r1fs.add_json.return_value = None

    failed = submit_rulebook_review(
      owner,
      "job-1",
      expected_review_revision=saved["review_revision"],
      expected_pass_nr=3,
      expected_profile_version="1.0.0",
      idempotency_key="submission-retry",
      actor="alice",
    )
    visible = get_rulebook_review(owner, "job-1")
    owner.r1fs.add_json.side_effect = owner._add_json
    recovered = submit_rulebook_review(
      owner,
      "job-1",
      expected_review_revision=saved["review_revision"],
      expected_pass_nr=3,
      expected_profile_version="1.0.0",
      idempotency_key="submission-retry",
      actor="alice",
    )

    self.assertEqual(failed["error"], "submission_persist_failed")
    self.assertEqual(visible["effective_review_state"], "draft")
    self.assertEqual(visible["submission_operation_state"], "failed")
    self.assertEqual(recovered["effective_review_state"], "submitted")
    self.assertEqual(recovered["submission"]["revision"], 1)

  def test_partial_final_registry_write_recovers_without_second_r1fs_write(self):
    owner = _Owner()
    saved = save_rulebook_review_draft(
      owner,
      "job-1",
      answers=_complete_review_answers(),
      actor="alice",
      expected_review_revision=0,
    )
    original_hset = owner.chainstore_hset
    failed_once = {"value": False}

    def fail_final_registry_write(hkey, key, value):
      if (
        hkey.endswith(":rulebook_review:submissions")
        and isinstance(value, dict)
        and value.get("submissions")
        and not value.get("pending")
        and not failed_once["value"]
      ):
        failed_once["value"] = True
        raise RuntimeError("simulated final registry failure")
      return original_hset(hkey, key, value)

    owner.chainstore_hset = fail_final_registry_write
    failed = submit_rulebook_review(
      owner,
      "job-1",
      expected_review_revision=saved["review_revision"],
      expected_pass_nr=3,
      expected_profile_version="1.0.0",
      idempotency_key="submission-partial",
      actor="alice",
    )
    owner.chainstore_hset = original_hset
    recovered = submit_rulebook_review(
      owner,
      "job-1",
      expected_review_revision=saved["review_revision"],
      expected_pass_nr=3,
      expected_profile_version="1.0.0",
      idempotency_key="submission-partial",
      actor="alice",
    )

    self.assertEqual(failed["error"], "submission_record_failed")
    self.assertEqual(recovered["effective_review_state"], "submitted")
    self.assertEqual(owner.r1fs.add_json.call_count, 1)

  def test_concurrent_duplicate_submission_allocates_one_revision(self):
    owner = _Owner()
    saved = save_rulebook_review_draft(
      owner,
      "job-1",
      answers=_complete_review_answers(),
      actor="alice",
      expected_review_revision=0,
    )

    def submit():
      return submit_rulebook_review(
        owner,
        "job-1",
        expected_review_revision=saved["review_revision"],
        expected_pass_nr=3,
        expected_profile_version="1.0.0",
        idempotency_key="submission-concurrent",
        actor="alice",
      )

    with ThreadPoolExecutor(max_workers=2) as executor:
      results = list(executor.map(lambda _: submit(), range(2)))

    self.assertEqual([result["status"] for result in results], ["ok", "ok"])
    self.assertEqual(owner.r1fs.add_json.call_count, 1)
    self.assertEqual(len(get_rulebook_review(owner, "job-1")["submissions"]), 1)

  def test_submit_rejects_stale_revision_pass_and_profile(self):
    owner = _Owner()
    saved = save_rulebook_review_draft(
      owner,
      "job-1",
      answers=_complete_review_answers(),
      actor="alice",
      expected_review_revision=0,
    )

    stale_revision = submit_rulebook_review(
      owner, "job-1", expected_review_revision=0, expected_pass_nr=3,
      expected_profile_version="1.0.0", idempotency_key="stale-revision", actor="alice",
    )
    stale_pass = submit_rulebook_review(
      owner, "job-1", expected_review_revision=saved["review_revision"], expected_pass_nr=2,
      expected_profile_version="1.0.0", idempotency_key="stale-pass", actor="alice",
    )
    stale_profile = submit_rulebook_review(
      owner, "job-1", expected_review_revision=saved["review_revision"], expected_pass_nr=3,
      expected_profile_version="0.9.0", idempotency_key="stale-profile", actor="alice",
    )

    self.assertEqual(stale_revision["error"], "review_revision_conflict")
    self.assertEqual(stale_pass["error"], "submission_pass_stale")
    self.assertEqual(stale_profile["error"], "submission_profile_stale")

  def test_reopen_and_resubmit_preserve_both_revisions(self):
    owner = _Owner()
    saved = save_rulebook_review_draft(
      owner, "job-1", answers=_complete_review_answers(), actor="alice", expected_review_revision=0,
    )
    first = submit_rulebook_review(
      owner, "job-1", expected_review_revision=saved["review_revision"], expected_pass_nr=3,
      expected_profile_version="1.0.0", idempotency_key="revision-1", actor="alice",
    )
    reopened = reopen_rulebook_review(
      owner, "job-1", expected_review_revision=saved["review_revision"], actor="alice",
    )
    second = submit_rulebook_review(
      owner, "job-1", expected_review_revision=reopened["review_revision"], expected_pass_nr=3,
      expected_profile_version="1.0.0", idempotency_key="revision-2", actor="alice",
    )

    self.assertEqual(first["submission"]["revision"], 1)
    self.assertEqual(reopened["effective_review_state"], "draft")
    self.assertEqual(reopened["review_revision"], 2)
    self.assertEqual(second["submission"]["revision"], 2)
    history = get_rulebook_review(owner, "job-1")["submissions"]
    self.assertEqual([item["revision"] for item in history], [2, 1])
    self.assertNotEqual(history[0]["cid"], history[1]["cid"])

  def test_two_revision_submission_smoke_retrieves_then_purges_every_snapshot(self):
    owner = _Owner(job_specs=_sample_job_specs())
    owner.records[(owner.cfg_instance_id, "job-1")] = owner.job_specs
    review_key = f"job-1:{DEFAULT_RULEBOOK_PROFILE_ID}"

    saved = save_rulebook_review_draft(
      owner, "job-1", answers=_complete_review_answers(), actor="alice", expected_review_revision=0,
    )
    first = submit_rulebook_review(
      owner, "job-1", expected_review_revision=saved["review_revision"], expected_pass_nr=3,
      expected_profile_version="1.0.0", idempotency_key="smoke-revision-1", actor="alice",
    )
    reopened = reopen_rulebook_review(
      owner, "job-1", expected_review_revision=saved["review_revision"], actor="alice",
    )
    second = submit_rulebook_review(
      owner, "job-1", expected_review_revision=reopened["review_revision"], expected_pass_nr=3,
      expected_profile_version="1.0.0", idempotency_key="smoke-revision-2", actor="bob",
    )

    first_cid = first["submission"]["cid"]
    second_cid = second["submission"]["cid"]
    self.assertEqual(owner.artifact_repo.get_json(first_cid)["submission"]["revision"], 1)
    self.assertEqual(owner.artifact_repo.get_json(second_cid)["submission"]["revision"], 2)
    self.assertEqual(
      [item["cid"] for item in get_rulebook_review(owner, "job-1")["submissions"]],
      [second_cid, first_cid],
    )

    result = purge_job(owner, "job-1")

    self.assertEqual(result["status"], "success")
    self.assertIsNone(owner.artifact_repo.get_json(first_cid))
    self.assertIsNone(owner.artifact_repo.get_json(second_cid))
    self.assertIn(first_cid, owner.artifact_repo.deleted)
    self.assertIn(second_cid, owner.artifact_repo.deleted)
    self.assertIsNone(owner.records[(f"{owner.cfg_instance_id}:rulebook_review", review_key)])
    self.assertIsNone(owner.records[(f"{owner.cfg_instance_id}:rulebook_review:audit", review_key)])
    self.assertIsNone(owner.records[(f"{owner.cfg_instance_id}:rulebook_review:submissions", review_key)])

  def test_newer_scan_evidence_marks_prior_submission_stale(self):
    owner = _Owner()
    saved = save_rulebook_review_draft(
      owner, "job-1", answers=_complete_review_answers(), actor="alice", expected_review_revision=0,
    )
    submit_rulebook_review(
      owner, "job-1", expected_review_revision=saved["review_revision"], expected_pass_nr=3,
      expected_profile_version="1.0.0", idempotency_key="stale-after-pass", actor="alice",
    )
    owner.archive["passes"].append({**_sample_pass_report(), "pass_nr": 4})

    current = get_rulebook_review(owner, "job-1")

    self.assertTrue(current["submissions"][0]["stale"])
    self.assertEqual(current["submissions"][0]["stale_reasons"], ["newer_scan_pass"])

  def test_formal_submission_redacts_sensitive_review_comments(self):
    owner = _Owner()
    answers = _complete_review_answers()
    answers["nis2.bcm.business_continuity"] = {
      "value": "unknown",
      "note": "password=supersecret observed at 10.0.0.4",
    }
    saved = save_rulebook_review_draft(
      owner, "job-1", answers=answers, actor="alice", expected_review_revision=0,
    )
    submitted = submit_rulebook_review(
      owner, "job-1", expected_review_revision=saved["review_revision"], expected_pass_nr=3,
      expected_profile_version="1.0.0", idempotency_key="redacted-submission", actor="alice",
    )

    serialized = json.dumps(owner.artifacts[submitted["submission"]["cid"]], sort_keys=True).lower()
    self.assertNotIn("supersecret", serialized)
    self.assertNotIn("10.0.0.4", serialized)
    self.assertIn("<redacted>", serialized)
    self.assertIn("ip:", serialized)

  def test_legacy_reviewed_records_surface_revision_zero_or_migration(self):
    owner = _Owner()
    updated = update_rulebook_review(
      owner,
      "job-1",
      answers=_complete_review_answers(),
      reviewer="legacy-reviewer",
      review_state="reviewed",
    )
    migration = get_rulebook_review(owner, "job-1")
    owner.job_specs["rulebook_assessments"] = {
      DEFAULT_RULEBOOK_PROFILE_ID: {
        "artifact_cid": "QmLegacyReviewed",
        "pass_nr": 3,
        "profile_version": "1.0.0",
        "schema_version": "1.0.0",
      },
    }
    referenced = get_rulebook_review(owner, "job-1")

    self.assertEqual(updated["review"]["review_state"], "reviewed")
    self.assertTrue(migration["migration_submission_required"])
    self.assertEqual(migration["effective_review_state"], "draft")
    self.assertEqual(referenced["effective_review_state"], "submitted")
    self.assertEqual(referenced["submissions"][0]["revision"], 0)
    self.assertTrue(referenced["submissions"][0]["legacy"])

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

  def test_ensure_replaces_legacy_same_pass_artifact_before_reuse(self):
    owner = _Owner(job_specs=_sample_job_specs(rulebook_assessments={
      DEFAULT_RULEBOOK_PROFILE_ID: {
        "artifact_cid": "QmLegacyRulebook",
        "pass_nr": 3,
        "latest_pass_nr": 3,
        "run_state": "succeeded",
        "schema_version": "1.0.0",
      },
    }))
    owner.artifacts["QmLegacyRulebook"] = {
      "schema": "redmesh.rulebook_assessment.v1",
      "schema_version": "1.0.0",
      "review_state": {"answers": {"q": {"note": "legacy draft"}}},
    }

    result = ensure_rulebook_assessment(owner, "job-1")

    self.assertFalse(result.get("cached", False))
    self.assertNotEqual(result["artifact_cid"], "QmLegacyRulebook")
    self.assertEqual(owner.artifacts[result["artifact_cid"]]["artifact_kind"], "generated_assessment")
    self.assertNotIn("legacy draft", json.dumps(owner.artifacts[result["artifact_cid"]]))

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
    owner.records[(f"{owner.cfg_instance_id}:rulebook_review:submissions", review_key)] = {
      "contract_version": "1.0.0",
      "latest_revision": 2,
      "submissions": [
        {"revision": 1, "cid": "QmSubmission1"},
        {"revision": 2, "cid": "QmSubmission2"},
      ],
      "pending": {"cid": "QmPendingSubmission"},
    }

    result = purge_job(owner, "job-1")

    self.assertEqual(result["status"], "success")
    self.assertIn("QmRulebookAssessment", owner.artifact_repo.deleted)
    self.assertIn("QmRulebookAssessmentOld", owner.artifact_repo.deleted)
    self.assertIn("QmSubmission1", owner.artifact_repo.deleted)
    self.assertIn("QmSubmission2", owner.artifact_repo.deleted)
    self.assertIn("QmPendingSubmission", owner.artifact_repo.deleted)
    self.assertIsNone(owner.records[(f"{owner.cfg_instance_id}:rulebook_review", review_key)])
    self.assertIsNone(owner.records[(f"{owner.cfg_instance_id}:rulebook_review:audit", review_key)])
    self.assertIsNone(owner.records[(f"{owner.cfg_instance_id}:rulebook_review:submissions", review_key)])

  def test_purge_fails_closed_for_submission_cid_shared_with_another_job(self):
    owner = _Owner(job_specs=_sample_job_specs(job_cid=""))
    owner.records[(owner.cfg_instance_id, "job-1")] = owner.job_specs
    hkey = f"{owner.cfg_instance_id}:rulebook_review:submissions"
    owner.records[(hkey, f"job-1:{DEFAULT_RULEBOOK_PROFILE_ID}")] = {
      "submissions": [{"revision": 1, "cid": "QmSharedSubmission"}],
    }
    owner.records[(hkey, f"job-2:{DEFAULT_RULEBOOK_PROFILE_ID}")] = {
      "submissions": [{"revision": 1, "cid": "QmSharedSubmission"}],
    }

    result = purge_job(owner, "job-1")

    self.assertEqual(result["status"], "partial")
    self.assertEqual(result["cids_deleted"], 0)
    self.assertNotIn("QmSharedSubmission", owner.artifact_repo.deleted)
    self.assertIsNotNone(owner.records[(owner.cfg_instance_id, "job-1")])


if __name__ == "__main__":
  unittest.main()
