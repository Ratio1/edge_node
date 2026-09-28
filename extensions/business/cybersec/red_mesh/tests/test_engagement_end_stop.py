"""RM-095 (owner, 2026-09-28): a continuous job hard-stops when its engagement ends.

The engagement ends at `valid_until` or when it is revoked. The launcher checks it while a pass
runs (at most once a minute) and always before it starts the next pass; a job whose engagement
still covers it, a single-pass job, and a job launched without an engagement are left alone.
"""
from datetime import datetime, timezone
from types import SimpleNamespace
import unittest

from extensions.business.cybersec.red_mesh.services.finalization import maybe_finalize_pass
from extensions.business.cybersec.red_mesh.tenancy.administration import TenantStoreError

from . import test_tenant_engagements as engagements
from .conftest import mock_plugin_modules
from .test_tenant_execution_finalization import FinalizationOwner, execution_binding

INSIDE = datetime(2026, 10, 15, tzinfo=timezone.utc)


class TestEngagementEndReason(unittest.TestCase):
  """The service answer, through the real service and CStore store."""
  # Borrowed, not inherited, so the phase 2 tests are not collected twice.
  setUp_engagements = engagements.TestTenantEngagements.setUp
  new_tenant = engagements.TestTenantEngagements.new_tenant
  asset = engagements.TestTenantEngagements.asset
  fields = engagements.TestTenantEngagements.fields
  create = engagements.TestTenantEngagements.create

  def setUp(self):
    self.setUp_engagements()
    created = self.create()
    self.assertTrue(created["success"], created)
    self.engagement_id = created["data"]["engagementId"]

  def reason(self, instant=INSIDE, engagement_id=None):
    self.service.clock = lambda: instant
    return self.service.engagement_end_reason(self.tenant, engagement_id or self.engagement_id)

  def test_an_engagement_in_force_has_no_end_reason(self):
    self.assertIsNone(self.reason())
    self.assertIsNone(self.reason(datetime(2026, 10, 30, 23, 59, 59, tzinfo=timezone.utc)))

  def test_the_window_ends_at_valid_until(self):
    self.assertEqual(self.reason(datetime(2026, 10, 31, tzinfo=timezone.utc)), "engagement_expired")

  def test_a_revoked_engagement_has_ended(self):
    self.assertTrue(self.service.revoke_engagement(self.actor, self.tenant, self.engagement_id, "Contract ended")["success"])
    self.assertEqual(self.reason(), "engagement_revoked")

  def test_an_unknown_engagement_has_ended(self):
    self.assertEqual(self.reason(engagement_id="en_00000000-0000-4000-8000-000000000000"), "engagement_not_found")
    self.assertEqual(self.reason(engagement_id="not-an-id"), "engagement_not_found")


class TestPluginEngagementEndReason(unittest.TestCase):
  """The plugin seam never stops a job on a store it cannot read."""

  def plugin(self, answer):
    def engagement_end_reason(tenant_id, engagement_id):
      if isinstance(answer, Exception):
        raise answer
      self.asked = (tenant_id, engagement_id)
      return answer
    return SimpleNamespace(_execution_service=lambda: SimpleNamespace(engagement_end_reason=engagement_end_reason))

  def reason(self, answer, config=None, job=None):
    mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    job = job if job is not None else {"execution_binding": execution_binding()}
    config = config if config is not None else {"engagement_id": "en_1"}
    return PentesterApi01Plugin._engagement_end_reason(self.plugin(answer), job, config)

  def test_it_asks_about_the_bound_tenant_and_the_snapshot_engagement(self):
    self.assertEqual(self.reason("engagement_revoked"), "engagement_revoked")
    self.assertEqual(self.asked, (execution_binding()["tenant_id"], "en_1"))

  def test_an_unreadable_store_or_a_job_without_engagement_is_not_an_end(self):
    self.assertIsNone(self.reason(TenantStoreError("down")))
    self.assertIsNone(self.reason("engagement_expired", config={}))
    self.assertIsNone(self.reason("engagement_expired", job={}))


class EngagementOwner(FinalizationOwner):
  def __init__(self, *, continuous=True, reason=None, engaged=True):
    super().__init__(continuous=continuous)
    self.scan_jobs = {}
    self.now = 100
    self.reason = reason
    self.reason_checks = []
    self.audit = []
    if engaged:
      self.r1fs.values["config"]["engagement_id"] = "en_1"

  def time(self):
    return self.now

  def _log_audit_event(self, event, data):
    self.audit.append((event, data))

  def _engagement_end_reason(self, job_specs, config):
    self.reason_checks.append(config.get("engagement_id"))
    return self.reason

  def running_pass(self):
    self.job["workers"]["node-a"] = {"finished": False, "start_port": 443, "end_port": 443}
    return self


class TestContinuousJobStopsWhenTheEngagementEnds(unittest.TestCase):
  def assert_stopped_for(self, owner, reason):
    self.assertEqual(owner.job["job_status"], "STOPPED")
    self.assertIn("engagement_ended", [event["type"] for event in owner.job["timeline"]])
    self.assertIn(("continuous_stopped_engagement_ended",
                   {"job_id": "job-1", "engagement_id": "en_1", "reason": reason, "pass_nr": owner.job["job_pass"]}),
                  owner.audit)

  def test_a_running_pass_is_hard_stopped(self):
    owner = EngagementOwner(reason="engagement_expired").running_pass()
    maybe_finalize_pass(owner)
    self.assert_stopped_for(owner, "engagement_expired")
    self.assertTrue(owner.job["workers"]["node-a"]["canceled"])

  def test_the_next_pass_is_not_started(self):
    owner = EngagementOwner(reason="engagement_revoked")
    owner.job["next_pass_at"] = 50
    maybe_finalize_pass(owner)
    self.assert_stopped_for(owner, "engagement_revoked")
    self.assertEqual(owner.job["job_pass"], 1)

  def test_an_engagement_in_force_lets_the_next_pass_start(self):
    owner = EngagementOwner()
    owner.job["next_pass_at"] = 50
    maybe_finalize_pass(owner)
    self.assertEqual(owner.job["job_pass"], 2)
    self.assertEqual(owner.reason_checks, ["en_1"])

  def test_a_running_pass_is_checked_at_most_once_a_minute_but_always_before_a_new_pass(self):
    owner = EngagementOwner().running_pass()
    maybe_finalize_pass(owner)
    owner.reason = "engagement_expired"
    owner.now = 130
    maybe_finalize_pass(owner)
    self.assertEqual(owner.job["job_status"], "RUNNING")
    self.assertEqual(owner.reason_checks, ["en_1"])
    owner.now = 160
    maybe_finalize_pass(owner)
    self.assert_stopped_for(owner, "engagement_expired")

    due = EngagementOwner()
    due.job["next_pass_at"] = 50
    due.running_pass()
    maybe_finalize_pass(due)
    due.job["workers"]["node-a"] = {"finished": True, "report_cid": "worker-report", "start_port": 443, "end_port": 443}
    due.reason = "engagement_expired"
    due.now = 101
    maybe_finalize_pass(due)
    self.assert_stopped_for(due, "engagement_expired")

  def test_single_pass_jobs_and_jobs_without_an_engagement_are_left_alone(self):
    single = EngagementOwner(continuous=False, reason="engagement_expired").running_pass()
    maybe_finalize_pass(single)
    self.assertEqual(single.job["job_status"], "RUNNING")
    self.assertEqual(single.reason_checks, [])
    unengaged = EngagementOwner(engaged=False, reason="engagement_expired")
    unengaged.job["next_pass_at"] = 50
    maybe_finalize_pass(unengaged)
    self.assertEqual(unengaged.job["job_pass"], 2)


if __name__ == "__main__":
  unittest.main()
