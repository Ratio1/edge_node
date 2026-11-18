"""Step 4a S3: the triage write, keyed by (tenant, host, finding), one record per member, under the host's locks."""
import unittest
from copy import deepcopy
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.services import rulebook_assessment, triage
from extensions.business.cybersec.red_mesh.tenancy.assets import canonical_digest
from extensions.business.cybersec.red_mesh.tenancy.effects import EffectLedger, EffectState
from .test_execution_binding_models import binding_payload
from .test_triage_store import TENANT_A, TENANT_B, _Store

HOST = "192.0.2.10"


class _Repo:
  def __init__(self, owner):
    self.owner = owner

  def get_archive(self, job):
    return deepcopy(self.owner.archives.get(job.get("job_cid")))

  def get_json(self, cid):
    return deepcopy(self.owner.archives.get(cid))


class _Owner(_Store):
  ee_addr = "node-a"

  def __init__(self):
    super().__init__()
    self.archives = {}
    self.audit = []
    self.now = 1000.0

  def time(self):
    return self.now

  def _get_job_from_cstore(self, job_id):
    return self.hashes.get("inst", {}).get(job_id)

  def _get_artifact_repository(self):
    return _Repo(self)

  def _log_audit_event(self, event, details):
    self.audit.append((event, details))

  def P(self, *args, **kwargs):
    pass

  def add_job(self, job_id, tenant=TENANT_A, host=HOST, findings=("f1", "f2", "f3"), confidence="firm",
              namespace=None, launcher="node-a"):
    binding = binding_payload()
    target = {"kind": "network", "address": host}
    binding.update(tenant_id=tenant, asset_target=target, asset_target_digest=canonical_digest(target))
    if namespace:
      binding["namespace"] = namespace
    record = {"job_id": job_id, "job_status": "FINALIZED", "launcher": launcher, "job_cid": f"arch-{job_id}",
              "execution_binding": binding}
    self.hashes.setdefault("inst", {})[job_id] = record
    self.archives[f"arch-{job_id}"] = {"job_id": job_id, "job_config": {"execution_binding": deepcopy(binding)},
                                       "passes": [
      {"pass_nr": 1, "findings": [{"finding_id": f, "confidence": confidence} for f in findings]}]}
    return record

  def pending(self, job_id, profile=None):
    profile = profile or rulebook_assessment.list_rulebook_profiles()[0]["profile_id"]
    self.hashes.setdefault("inst:rulebook_review:submissions", {})[f"{job_id}:{profile}"] = {"pending": {"x": 1}}


def write(owner, job_id="job-1", ids="f1", status="false_positive", **kw):
  with patch.object(triage, "emit_finding_event") as emit:
    result = triage.update_finding_triage(owner, job_id, ids, status, **{"actor": "analyst", **kw})
  return result, emit


class TestTriageWrite(unittest.TestCase):
  def setUp(self):
    self.owner = _Owner()
    self.owner.add_job("job-1")
    self.hkey = f"inst:triage:t:{TENANT_A}"

  def test_one_finding_is_stored_by_tenant_and_host_with_audit_and_event(self):
    result, emit = write(self.owner, note="n")
    self.assertNotIn("error", result, result)
    stored = self.owner.hashes[self.hkey][f"{HOST}\x1ff1"]
    self.assertEqual((stored["status"], stored["tenant_id"], stored["host"], stored["job_id"], stored["actor"]),
                     ("false_positive", TENANT_A, HOST, "job-1", "analyst"))
    self.assertEqual(triage._job_repo(self.owner).get_host_triage_audit(TENANT_A, HOST, "f1")[0]["actor"], "analyst")
    self.assertEqual(emit.call_args.kwargs["event_action"], "triaged")
    self.assertEqual(self.owner.audit[0][0], "finding_triage_updated")
    self.assertNotIn("inst:triage", self.owner.hashes)  # nothing under the legacy keys

  def test_a_record_survives_a_rerun_and_is_read_for_the_new_job(self):
    write(self.owner, ids="f1")
    rerun = self.owner.add_job("job-2")  # the rerun: same tenant and host, new job id
    triage_map = triage.get_job_triage(self.owner, "job-2", checked_job=deepcopy(rerun))["triage"]
    self.assertEqual(triage_map["f1"]["status"], "false_positive")
    self.assertEqual(triage_map["f1"]["job_id"], "job-1")
    merged = triage.get_job_archive_with_triage(self.owner, "job-2", checked_job=deepcopy(rerun))["archive"]
    self.assertEqual(merged["passes"][0]["findings"][0]["triage"]["status"], "false_positive")

  def test_rollup_dismiss_writes_every_member_and_a_retry_is_idempotent(self):
    result, emit = write(self.owner, ids=["f1", "f2", "f3"])
    self.assertEqual([(r["finding_id"], r["outcome"]) for r in result["results"]],
                     [("f1", "updated"), ("f2", "updated"), ("f3", "updated")])
    self.assertTrue(result["complete"])
    self.assertEqual(emit.call_count, 3)
    again, emit = write(self.owner, ids=["f1", "f2", "f3"])
    self.assertEqual({r["outcome"] for r in again["results"]}, {"unchanged"})
    self.assertTrue(again["complete"])
    emit.assert_not_called()
    audit = self.owner.hashes[f"inst:triage:audit:{TENANT_A}"]
    self.assertEqual(len(audit), 3)  # one entry per member, none added by the retry

  def test_a_member_outside_the_archive_is_listed_and_the_set_is_not_complete(self):
    result, _ = write(self.owner, ids=["f1", "zzz"])
    self.assertEqual([r["outcome"] for r in result["results"]], ["updated", "not_found"])
    self.assertFalse(result["complete"])
    self.assertNotIn(f"{HOST}\x1fzzz", self.owner.hashes[self.hkey])

  def test_two_tenants_on_one_host_do_not_share_records(self):
    self.owner.add_job("job-b", tenant=TENANT_B)
    write(self.owner, job_id="job-b", ids="f1", status="remediated")
    write(self.owner, ids="f1")
    self.assertEqual(self.owner.hashes[f"inst:triage:t:{TENANT_B}"][f"{HOST}\x1ff1"]["status"], "remediated")
    self.assertEqual(self.owner.hashes[self.hkey][f"{HOST}\x1ff1"]["status"], "false_positive")

  def test_accepted_risk_needs_a_future_review_at_and_other_statuses_drop_it(self):
    for review_at in (None, 0, 500.0, "x", True):
      result, _ = write(self.owner, status="accepted_risk", review_at=review_at)
      self.assertEqual(result["error"], "validation_error", review_at)
    ok, _ = write(self.owner, status="accepted_risk", review_at=2000.0)
    self.assertEqual(ok["results"][0]["triage"]["review_at"], 2000.0)
    other, _ = write(self.owner, ids="f2", status="remediated", review_at=2000.0)
    self.assertNotIn("review_at", other["results"][0]["triage"])

  def test_invalid_input_is_refused_before_any_write(self):
    for ids in ([], "", ["a\x1fb"], [1], list(map(str, range(501)))):
      self.assertEqual(write(self.owner, ids=ids)[0]["error"], "validation_error")
    self.assertEqual(write(self.owner, status="wont_fix")[0]["error"], "validation_error")
    self.assertEqual(write(self.owner, status="false_positive", confirm=True)[0]["error"], "validation_error")
    self.assertNotIn(self.hkey, self.owner.hashes)

  def test_a_note_over_the_cap_is_refused_before_any_write(self):
    from extensions.business.cybersec.red_mesh.tenancy.tenant_assets import NOTES_MAX
    self.assertEqual(NOTES_MAX, 2000)
    result, _ = write(self.owner, note="x" * 2001)
    self.assertEqual(result["error"], "validation_error")
    self.assertNotIn(self.hkey, self.owner.hashes)
    ok, _ = write(self.owner, note="x" * 2000)
    self.assertNotIn("error", ok)

  def test_confirm_records_the_actor_on_a_tentative_finding_only(self):
    self.owner.add_job("job-t", findings=("t1",), confidence="tentative")
    result, _ = write(self.owner, job_id="job-t", ids="t1", status="open", confirm=True)
    stored = result["results"][0]["triage"]
    self.assertEqual((stored["confirmed"], stored["confirmed_by"], stored["status"]), (True, "analyst", "open"))
    firm, _ = write(self.owner, ids="f1", status="open", confirm=True)
    self.assertEqual(firm["results"][0]["outcome"], "not_tentative")
    self.assertNotIn(f"{HOST}\x1ff1", self.owner.hashes.get(self.hkey, {}))

  def test_bad_input_is_a_validation_error_even_while_a_submission_is_pending(self):
    self.owner.pending("job-1")
    for kw in ({"status": "wont_fix"}, {"status": "accepted_risk", "review_at": 1.0}, {"confirm": True},
               {"note": "x" * 2001}, {"ids": []}):
      self.assertEqual(write(self.owner, **kw)[0]["error"], "validation_error", kw)
    self.assertEqual(write(self.owner)[0]["error"], "submission_in_progress")

  def test_a_later_write_keeps_the_confirmation_unless_dismissed_as_false_positive(self):
    self.owner.add_job("job-t", findings=("t1",), confidence="tentative")
    write(self.owner, job_id="job-t", ids="t1", status="open", confirm=True)
    kept, _ = write(self.owner, job_id="job-t", ids="t1", status="remediated", actor="other", note="fixed")
    stored = kept["results"][0]["triage"]
    self.assertEqual((stored["status"], stored["confirmed"], stored["confirmed_by"]), ("remediated", True, "analyst"))
    again, _ = write(self.owner, job_id="job-t", ids="t1", status="remediated", actor="other", note="fixed")
    self.assertEqual(again["results"][0]["outcome"], "unchanged")
    dismissed, _ = write(self.owner, job_id="job-t", ids="t1", status="false_positive")
    stored = dismissed["results"][0]["triage"]
    self.assertNotIn("confirmed", stored)
    self.assertNotIn("confirmed_by", stored)

  def test_model_unbound_running_and_foreign_launcher_jobs_are_refused(self):
    model = {"kind": "model", "adapter": "openai_compatible",
             "endpointUrl": "https://api.example.com/v1/chat/completions", "model": "m"}
    record = self.owner.add_job("job-m")
    record["execution_binding"].update(asset_target=model, asset_target_digest=canonical_digest(model))
    self.assertEqual(write(self.owner, job_id="job-m")[0]["error"], "not_available")
    record["job_type"] = "model_test"
    self.assertEqual(write(self.owner, job_id="job-m")[0]["error"], "model_test_not_supported")
    self.owner.add_job("job-u")["execution_binding"] = None
    self.assertEqual(write(self.owner, job_id="job-u")[0]["error"], "not_available")
    self.owner.add_job("job-r")["job_cid"] = None
    self.assertEqual(write(self.owner, job_id="job-r")[0]["error"], "not_available")
    self.owner.add_job("job-l", launcher="node-z")
    refused = write(self.owner, job_id="job-l")[0]
    self.assertEqual((refused["error"], refused["status_code"]), ("job_launcher_mismatch", 409))
    self.assertEqual(write(self.owner, job_id="missing")[0]["error"], "not_found")
    self.assertNotIn(self.hkey, self.owner.hashes)

  def test_a_checked_snapshot_is_used_and_the_ledger_records_each_write(self):
    record = self.owner.hashes["inst"]["job-1"]
    checkpoints = []
    ledger = EffectLedger(on_checkpoint=lambda: checkpoints.append(1))
    with patch.object(triage, "emit_finding_event"):
      result = triage.update_finding_triage(self.owner, "job-1", ["f1", "f2"], "remediated", actor="a",
                                            checked_job=deepcopy(record), ledger=ledger)
    self.assertNotIn("error", result, result)
    self.assertEqual((len(checkpoints), ledger.state), (2, EffectState.PERSISTED))

  def test_a_failure_after_the_first_member_leaves_it_written_and_the_ledger_persisted(self):
    ledger = EffectLedger()
    real = triage.JobStateRepository.put_host_triage
    calls = []

    def flaky(repo, state):
      calls.append(state.finding_id)
      if len(calls) == 2:
        raise RuntimeError("store down")
      return real(repo, state)
    with patch.object(triage.JobStateRepository, "put_host_triage", flaky), patch.object(triage, "emit_finding_event"):
      with self.assertRaises(RuntimeError):
        triage.update_finding_triage(self.owner, "job-1", ["f1", "f2"], "remediated", actor="a", ledger=ledger)
    self.assertEqual(ledger.state, EffectState.PERSISTED)
    self.assertIn(f"{HOST}\x1ff1", self.owner.hashes[self.hkey])
    retry, _ = write(self.owner, ids=["f1", "f2"], status="remediated")
    self.assertEqual([r["outcome"] for r in retry["results"]], ["unchanged", "updated"])

  def _refuse_writes_to(self, hkey):
    """The store refuses (returns False) every write to `hkey`, as CStore does when it cannot store a key."""
    real = self.owner.chainstore_hset

    def refusing(**kwargs):
      if kwargs["hkey"] == hkey:
        return False
      return real(**kwargs)
    self.owner.chainstore_hset = refusing

  def test_a_refused_state_write_is_reported_and_nothing_follows_it(self):
    self.owner.hashes["inst"]["job-1"]["soc_event_status"] = {}
    self._refuse_writes_to(self.hkey)
    with patch.object(triage, "_write_job_record") as soc_write:
      result, emit = write(self.owner, ids=["f1", "f2"])
    self.assertEqual([(r["finding_id"], r["outcome"], r.get("retryable")) for r in result["results"]],
                     [("f1", "write_failed", True), ("f2", "write_failed", True)])
    self.assertFalse(result["complete"])
    emit.assert_not_called()
    soc_write.assert_not_called()
    self.assertEqual(self.owner.audit, [])
    self.assertNotIn(f"inst:triage:audit:{TENANT_A}", self.owner.hashes)

  def test_a_refused_audit_write_is_reported(self):
    self._refuse_writes_to(f"inst:triage:audit:{TENANT_A}")
    result, emit = write(self.owner, ids="f1")
    self.assertEqual([(r["outcome"], r.get("retryable")) for r in result["results"]], [("write_failed", True)])
    self.assertFalse(result["complete"])
    emit.assert_not_called()

  def test_a_refused_write_leaves_the_ledger_unpersisted(self):
    self._refuse_writes_to(self.hkey)
    ledger = EffectLedger()
    with patch.object(triage, "emit_finding_event"):
      triage.update_finding_triage(self.owner, "job-1", "f1", "remediated", actor="a", ledger=ledger)
    self.assertNotEqual(ledger.state, EffectState.PERSISTED)

  def _audit(self):
    return triage._job_repo(self.owner).get_host_triage_audit(TENANT_A, HOST, "f1")

  def test_a_retry_completes_an_audit_entry_lost_after_the_state_write_exactly_once(self):
    real = triage.JobStateRepository.append_host_triage_audit
    with patch.object(triage.JobStateRepository, "append_host_triage_audit", side_effect=RuntimeError("down")):
      with self.assertRaises(RuntimeError):
        write(self.owner, ids="f1", note="why")
    self.assertEqual(self.owner.hashes[self.hkey][f"{HOST}\x1ff1"]["status"], "false_positive")
    self.assertEqual(self._audit(), [])
    self.owner.now = 2000.0  # the retry comes later
    with patch.object(triage.JobStateRepository, "append_host_triage_audit", autospec=True, side_effect=real) as spy:
      retry, emit = write(self.owner, ids="f1", note="why")
    self.assertEqual(spy.call_count, 1)
    self.assertEqual([r["outcome"] for r in retry["results"]], ["updated"])
    self.assertTrue(retry["complete"])
    emit.assert_called_once()
    (entry,) = self._audit()
    self.assertEqual((entry["status"], entry["note"], entry["actor"], entry["timestamp"]),
                     ("false_positive", "why", "analyst", 1000.0))  # the change as made, not the retry time
    again, emit = write(self.owner, ids="f1", note="why")
    self.assertEqual([r["outcome"] for r in again["results"]], ["unchanged"])
    emit.assert_not_called()
    self.assertEqual(len(self._audit()), 1)

  def test_a_state_and_its_audit_entry_share_one_id(self):
    write(self.owner, ids="f1")
    stored = self.owner.hashes[self.hkey][f"{HOST}\x1ff1"]
    (field,) = self.owner.hashes[f"inst:triage:audit:{TENANT_A}"]
    self.assertTrue(field.endswith(f"\x1f{stored['audit_entry_id']}"))

  def test_a_record_without_an_audit_id_is_left_alone_on_an_unchanged_write(self):
    write(self.owner, ids="f1")
    del self.owner.hashes[self.hkey][f"{HOST}\x1ff1"]["audit_entry_id"]  # written by an older node
    self.owner.hashes[f"inst:triage:audit:{TENANT_A}"].clear()
    again, emit = write(self.owner, ids="f1")
    self.assertEqual([r["outcome"] for r in again["results"]], ["unchanged"])
    emit.assert_not_called()
    self.assertEqual(self._audit(), [])


if __name__ == "__main__":
  unittest.main()
