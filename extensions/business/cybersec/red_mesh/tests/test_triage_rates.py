"""RM-206: false-positive rate per confidence reason, joined to the writer job's raw archive."""
from copy import deepcopy
import unittest
from unittest.mock import patch
from uuid import uuid4

import pytest

from extensions.business.cybersec.red_mesh.models import FindingTriageState
from extensions.business.cybersec.red_mesh.services import triage
from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
from .test_deferred_mutation_native import triage_fixture, write as fixture_write
from .read_endpoint_fixtures import as_role
from .test_triage_store import TENANT_A, TENANT_B
from .test_triage_write import HOST, _Owner, _Repo

ENGAGEMENT_1 = "en_" + str(uuid4())
ENGAGEMENT_2 = "en_" + str(uuid4())


def finding(finding_id, reason="", confidence="tentative"):
  result = {"finding_id": finding_id, "confidence": confidence}
  if reason:
    result["confidence_reason"] = reason
  return result


def add_job(owner, job_id, findings, tenant=TENANT_A, host=HOST, engagement=None):
  record = owner.add_job(job_id, tenant=tenant, host=host)
  archive = owner.archives[f"arch-{job_id}"]
  archive["passes"][0]["findings"] = findings
  if engagement:
    record["execution_binding"]["engagement_id"] = engagement
    archive["job_config"]["execution_binding"]["engagement_id"] = engagement
  return record


def put(owner, job_id, finding_id, status="open", confirmed=None, tenant=TENANT_A, host=HOST, **extra):
  state = FindingTriageState(job_id=job_id, finding_id=finding_id, status=status, tenant_id=tenant, host=host,
                             confirmed=confirmed, confirmed_by="analyst" if confirmed else None).to_dict()
  owner.hashes.setdefault(f"inst:triage:t:{tenant}", {})[f"{host}\x1f{finding_id}"] = {**state, **extra}


def rates(owner, tenant=TENANT_A, engagement_id="", only=None):
  jobs = {key: deepcopy(record) for key, record in owner.hashes.get("inst", {}).items()
          if only is None or key in only}
  return triage.get_triage_rates(owner, tenant, engagement_id, checked_jobs=jobs)


def rows(result, engagement=None):
  scope = result["tenant"] if engagement is None else result["engagements"][engagement]
  return {(row["reason"], row["confidence"]): row for row in scope["by_reason"]}


class TestTriageRates(unittest.TestCase):
  def setUp(self):
    self.owner = _Owner()

  def test_counts_per_reason_and_confidence_with_rate_and_n(self):
    add_job(self.owner, "job-1", [finding(f"f{i}", "banner_only") for i in range(1, 7)]
            + [finding("g1", "eol_unassessed"), finding("g2", "eol_unassessed")])
    put(self.owner, "job-1", "f1", "false_positive")
    put(self.owner, "job-1", "f2", "false_positive")
    put(self.owner, "job-1", "f3", "remediated")
    put(self.owner, "job-1", "f4", "accepted_risk")
    put(self.owner, "job-1", "f5", "open")
    put(self.owner, "job-1", "f6", "reopened")
    put(self.owner, "job-1", "g1", "false_positive")
    result = rates(self.owner)
    banner = rows(result)[("banner_only", "tentative")]
    self.assertEqual({k: banner[k] for k in ("false_positive", "true_positive", "unreviewed", "n", "rate")},
                     {"false_positive": 2, "true_positive": 2, "unreviewed": 2, "n": 4, "rate": 0.5})
    eol = rows(result)[("eol_unassessed", "tentative")]
    self.assertEqual((eol["false_positive"], eol["n"], eol["rate"]), (1, 1, 1.0))
    self.assertEqual(result["tenant"]["unattributed"], 0)

  def test_rows_are_sorted_and_a_rate_is_null_without_reviewed_findings(self):
    add_job(self.owner, "job-1", [finding("f1", "inferred_version"), finding("f2", "banner_only")])
    put(self.owner, "job-1", "f1", "open")
    put(self.owner, "job-1", "f2", "open")
    result = rates(self.owner)
    self.assertEqual([r["reason"] for r in result["tenant"]["by_reason"]], ["banner_only", "inferred_version"])
    self.assertEqual([(r["n"], r["rate"]) for r in result["tenant"]["by_reason"]], [(0, None), (0, None)])

  def test_a_confirmed_record_counts_under_its_archived_reason_not_triage_confirmed(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")])
    put(self.owner, "job-1", "f1", "open", confirmed=True)
    result = rates(self.owner)
    self.assertEqual(list(rows(result)), [("banner_only", "tentative")])
    self.assertEqual(rows(result)[("banner_only", "tentative")]["true_positive"], 1)

  def test_a_finding_without_a_reason_goes_to_none(self):
    add_job(self.owner, "job-1", [finding("f1")])
    put(self.owner, "job-1", "f1", "false_positive")
    self.assertEqual(list(rows(rates(self.owner))), [("none", "tentative")])

  def test_a_purged_job_or_a_missing_finding_is_unattributed_in_the_tenant_total_only(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")], engagement=ENGAGEMENT_1)
    put(self.owner, "job-1", "f1", "false_positive")
    put(self.owner, "job-1", "gone", "false_positive")  # the archive holds no such finding
    put(self.owner, "job-purged", "f9", "remediated")  # the writer job is not in the snapshot
    result = rates(self.owner)
    self.assertEqual(result["tenant"]["unattributed"], 2)
    self.assertEqual(sum(r["n"] for r in result["tenant"]["by_reason"]), 1)
    self.assertNotIn("unattributed", result["engagements"][ENGAGEMENT_1])

  def test_unattributed_is_not_computed_when_an_engagement_narrows_the_read(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")], engagement=ENGAGEMENT_1)
    add_job(self.owner, "job-2", [finding("f2", "banner_only")], host="192.0.2.11", engagement=ENGAGEMENT_2)
    put(self.owner, "job-1", "f1", "false_positive")
    put(self.owner, "job-1", "gone", "false_positive")
    put(self.owner, "job-2", "gone", "false_positive", host="192.0.2.11")
    put(self.owner, "job-purged", "f9", "remediated")
    self.assertEqual(rates(self.owner)["tenant"]["unattributed"], 3)
    narrowed = rates(self.owner, engagement_id=ENGAGEMENT_1)
    self.assertIsNone(narrowed["tenant"]["unattributed"])
    self.assertEqual(rows(narrowed)[("banner_only", "tentative")]["n"], 1)

  def test_a_scope_mismatch_between_record_and_writer_job_is_unavailable(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")], host="192.0.2.77")
    put(self.owner, "job-1", "f1", "false_positive")  # keyed to HOST, written by a job of another host
    with self.assertRaises(TenantStoreError):
      rates(self.owner)

  def test_a_malformed_record_is_unavailable_never_skipped(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")])
    put(self.owner, "job-1", "f1", "false_positive")
    hash_ = self.owner.hashes[f"inst:triage:t:{TENANT_A}"]
    for bad in ({"job_id": "job-1"}, "text", {**hash_[f"{HOST}\x1ff1"], "finding_id": "other"},
                {**hash_[f"{HOST}\x1ff1"], "status": "bogus"}, {**hash_[f"{HOST}\x1ff1"], "tenant_id": TENANT_B}):
      with self.subTest(bad=bad):
        hash_[f"{HOST}\x1ff2"] = bad
        with self.assertRaises(TenantStoreError):
          rates(self.owner)

  def test_a_false_positive_write_after_a_confirmation_counts_once_as_false_positive(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")])
    with patch.object(triage, "emit_finding_event"):
      self.assertNotIn("error", triage.update_finding_triage(self.owner, "job-1", "f1", "open", actor="a", confirm=True))
      self.assertEqual(rows(rates(self.owner))[("banner_only", "tentative")]["true_positive"], 1)
      self.assertNotIn("error", triage.update_finding_triage(self.owner, "job-1", "f1", "false_positive", actor="a"))
    row = rows(rates(self.owner))[("banner_only", "tentative")]
    self.assertEqual((row["false_positive"], row["true_positive"], row["unreviewed"]), (1, 0, 0))

  def test_a_record_with_both_flags_counts_once_as_false_positive(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")])
    put(self.owner, "job-1", "f1", "false_positive", confirmed=True)
    row = rows(rates(self.owner))[("banner_only", "tentative")]
    self.assertEqual((row["false_positive"], row["true_positive"], row["n"]), (1, 0, 1))

  def test_the_other_tenants_hash_is_never_read_and_never_mixed(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")])
    add_job(self.owner, "job-b", [finding("f1", "banner_only")], tenant=TENANT_B)
    put(self.owner, "job-1", "f1", "false_positive")
    put(self.owner, "job-b", "f1", "remediated", tenant=TENANT_B)
    read = []
    original = self.owner.chainstore_hgetall
    self.owner.chainstore_hgetall = lambda hkey: read.append(hkey) or original(hkey)
    result = rates(self.owner, only={"job-1"})
    self.assertEqual(read, [f"inst:triage:t:{TENANT_A}"])
    self.assertEqual(rows(result)[("banner_only", "tentative")]["n"], 1)
    self.assertEqual(rows(result)[("banner_only", "tentative")]["false_positive"], 1)

  def test_a_writer_job_of_another_tenant_is_unavailable(self):
    add_job(self.owner, "job-b", [finding("f1", "banner_only")], tenant=TENANT_B)
    put(self.owner, "job-b", "f1", "false_positive")  # stored under tenant A, written by a tenant B job
    with self.assertRaises(TenantStoreError):
      rates(self.owner)

  def test_the_engagement_is_the_writer_jobs_and_narrows_the_jobs(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")], engagement=ENGAGEMENT_1)
    add_job(self.owner, "job-2", [finding("f2", "banner_only")], host="192.0.2.11", engagement=ENGAGEMENT_2)
    put(self.owner, "job-1", "f1", "false_positive")
    put(self.owner, "job-2", "f2", "remediated", host="192.0.2.11")
    result = rates(self.owner)
    self.assertEqual(set(result["engagements"]), {ENGAGEMENT_1, ENGAGEMENT_2})
    self.assertEqual(rows(result, ENGAGEMENT_1)[("banner_only", "tentative")]["rate"], 1.0)
    self.assertEqual(rows(result, ENGAGEMENT_2)[("banner_only", "tentative")]["rate"], 0.0)
    self.assertEqual(rows(result)[("banner_only", "tentative")]["n"], 2)
    narrowed = rates(self.owner, engagement_id=ENGAGEMENT_2)
    self.assertEqual(set(narrowed["engagements"]), {ENGAGEMENT_2})
    self.assertEqual(rows(narrowed)[("banner_only", "tentative")]["n"], 1)

  def test_more_than_128_writer_jobs_is_unavailable_not_partial(self):
    for number in range(129):
      add_job(self.owner, f"job-{number}", [finding("f", "banner_only")], host=f"192.0.2.{number}")
      put(self.owner, f"job-{number}", "f", "false_positive", host=f"192.0.2.{number}")
    with self.assertRaises(TenantStoreError):
      rates(self.owner)
    for number in range(128, 129):
      del self.owner.hashes[f"inst:triage:t:{TENANT_A}"][f"192.0.2.{number}\x1ff"]
    self.assertEqual(rows(rates(self.owner))[("banner_only", "tentative")]["n"], 128)

  def test_one_job_with_many_records_reads_its_archive_once(self):
    add_job(self.owner, "job-1", [finding(f"f{i}", "banner_only") for i in range(200)])
    for number in range(200):
      put(self.owner, "job-1", f"f{number}", "false_positive")
    with patch.object(_Repo, "get_json", autospec=True, side_effect=_Repo.get_json) as read:
      self.assertEqual(rows(rates(self.owner))[("banner_only", "tentative")]["n"], 200)
    self.assertEqual(read.call_count, 1)

  def test_a_model_test_writer_job_is_excluded(self):
    record = add_job(self.owner, "job-1", [finding("f1", "banner_only")])
    record["job_type"] = "model_test"
    put(self.owner, "job-1", "f1", "false_positive")
    result = rates(self.owner)
    self.assertEqual((result["tenant"]["by_reason"], result["tenant"]["unattributed"]), ([], 0))

  def test_legacy_job_keyed_records_are_not_counted(self):
    add_job(self.owner, "job-1", [finding("f1", "banner_only")])
    self.owner.hashes["inst:triage"] = {"job-1:f1": {"job_id": "job-1", "finding_id": "f1", "status": "false_positive"}}
    self.assertEqual(rates(self.owner)["tenant"]["by_reason"], [])

  def test_an_empty_tenant_has_no_rows(self):
    self.assertEqual(rates(self.owner), {"tenant": {"by_reason": [], "unattributed": 0}, "engagements": {}})


def test_a_record_naming_another_tenants_job_is_unattributed_and_that_archive_is_never_read():
  with triage_fixture() as fixture:
    _reasoned(fixture)
    foreign = {"job_id": "job-b", "target": HOST, "scan_type": "network", "job_status": "FINALIZED",
               "launcher": "node-a", "workers": {}, "pass_reports": [], "job_cid": "archive-b",
               "execution_binding": {**fixture.store.jobs["job-1"]["execution_binding"], "tenant_id": TENANT_B}}
    fixture.store.jobs["job-b"] = foreign
    fixture.artifacts["archive-b"] = {"job_id": "job-b", "passes": [{"findings": [
      {"finding_id": "finding-1", "confidence": "firm", "confidence_reason": "foreign"}]}]}
    assert "error" not in fixture_write(fixture, ("finding-1",))
    (key,) = [k for k in fixture.store.data if ":triage:t:" in k[0] and fixture.store.data[k] is not None]
    fixture.store.data[key] = {**fixture.store.data[key], "job_id": "job-b"}
    as_role(fixture, "tenant_user")
    result = fixture.Plugin.get_triage_rates(fixture.owner, request_actor=fixture.actor, tenant_id=fixture.tenant_id)
    assert result == {"tenant": {"by_reason": [], "unattributed": 1}, "engagements": {}}
    assert "archive-b" not in [cid for cid, _ in fixture.artifact_reads]


def _reasoned(fixture):
  fixture.artifacts["archive"]["passes"][0]["findings"] = [
    {"finding_id": "finding-1", "confidence": "tentative", "confidence_reason": "banner_only"},
    {"finding_id": "finding-2", "confidence": "tentative", "confidence_reason": "banner_only"}]


def test_endpoint_admits_reports_view_and_returns_the_rates():
  with triage_fixture() as fixture:
    _reasoned(fixture)
    assert "error" not in fixture_write(fixture, ("finding-1",))
    as_role(fixture, "tenant_user")  # reports:view, not findings:triage
    result = fixture.Plugin.get_triage_rates(fixture.owner, request_actor=fixture.actor, tenant_id=fixture.tenant_id)
    row = result["tenant"]["by_reason"][0]
    assert (row["reason"], row["confidence"], row["false_positive"], row["n"], row["rate"]) == (
      "banner_only", "tentative", 1, 1, 1.0)


def test_endpoint_denies_without_reports_view_and_is_unavailable_on_a_bad_record():
  with triage_fixture() as fixture:
    fixture.store.account("outsider", memberships=[])  # an active account with no role in the tenant
    result = fixture.Plugin.get_triage_rates(fixture.owner, request_actor={"account_id": "outsider"},
                                             tenant_id=fixture.tenant_id)
    assert result["success"] is False and result["status_code"] in (403, 404), result
    _reasoned(fixture)
    assert "error" not in fixture_write(fixture, ("finding-1",))
    (key,) = [k for k in fixture.store.data if ":triage:t:" in k[0] and fixture.store.data[k] is not None]
    fixture.store.data[key] = {"job_id": "job-1"}
    result = fixture.Plugin.get_triage_rates(fixture.owner, request_actor=fixture.actor, tenant_id=fixture.tenant_id)
    assert (result["success"], result["error"], result["status_code"]) == (False, "unavailable", 503)
