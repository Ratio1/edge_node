"""A refused launch is audited, but only once the tenant is verified; the tenant audit read returns it."""
from contextlib import contextmanager
from datetime import datetime, timezone
from uuid import uuid4

from .read_endpoint_fixtures import read_endpoint_fixture

ROW_FIELDS = {"tenant_id", "engagement_id", "engagement_asset_id", "scan_type", "target", "reason", "actor"}


@contextmanager
def launch_fixture():
  """A real admission service and the real `_admit_execution`; the launch audit is a recording mock."""
  from .contract_fixture import CONTRACT_SHA256  # noqa: F401
  from .asset_fixture import pick
  from .test_api import TestPhase1ConfigCID
  from .test_tenant_execution import TestTenantExecution
  from .test_tenant_engagements import doc
  from extensions.business.cybersec.red_mesh.tenancy.identity import resolve_actor
  fixture = TestTenantExecution()
  fixture.setUp()
  try:
    fixture.ready()
    fixture.service.clock = lambda: datetime(2026, 10, 15, tzinfo=timezone.utc)
    engagement = fixture.service.create_engagement(
      fixture.actor, fixture.tenant, str(uuid4()), "Q4", "2026-10-01T00:00:00Z",
      "2026-10-31T00:00:00Z", {"client_name": "Example"}, [pick(fixture.net)],
      [doc("1" * 64, "QmEngagementRoeRef"), doc("2" * 64, "QmEngagementAuthRef")])
    assert engagement["success"], engagement
    TestPhase1ConfigCID._mock_plugin_modules()
    owner = TestPhase1ConfigCID._build_mock_plugin()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    TestPhase1ConfigCID._bind_launch_helpers(owner)
    owner._execution_service = lambda: fixture.service
    owner._resolve_launch_actor = lambda actor: resolve_actor(actor, fixture.service.accounts)
    owner._admit_execution = lambda *args, **kwargs: PentesterApi01Plugin._admit_execution(owner, *args, **kwargs)
    fixture.owner_plugin = owner
    fixture.Plugin = PentesterApi01Plugin
    fixture.engagement_id = engagement["data"]["engagementId"]
    fixture.kwargs = dict(actor=fixture.actor, tenant_id=fixture.tenant, selected_peers=["node-a"],
                          authorized=True, start_port=1, end_port=4)
    yield fixture
  finally:
    fixture.doCleanups()


def rows(owner):
  return [call[0][1] for call in owner._log_audit_event.call_args_list if call[0][0] == "launch_refused"]


def launch(fixture, **changes):
  args = {**fixture.kwargs, "engagement_id": fixture.engagement_id, "engagement_asset_id": "ea_1", **changes}
  return fixture.Plugin.launch_network_scan(fixture.owner_plugin, **args)


def test_each_audited_reason_writes_one_row_with_the_specified_fields_and_no_body():
  with launch_fixture() as fixture:
    owner = fixture.owner_plugin
    cases = [
      ("engagement_not_found", dict(engagement_id="en_" + str(uuid4()))),
      ("engagement_asset_not_locked", dict(engagement_asset_id="ea_2")),
      ("ineligible_node", dict(selected_peers=["node-zzz"])),
    ]
    for reason, changes in cases:
      owner._log_audit_event.reset_mock()
      result = launch(fixture, target="192.0.2.10", task_description="s3cret-body", **changes)
      assert result["error"] == reason, result
      logged = rows(owner)
      assert len(logged) == 1, (reason, logged)
      row = logged[0]
      assert set(row) == ROW_FIELDS
      assert row["reason"] == reason and row["scan_type"] == "network" and row["target"] == "192.0.2.10"
      assert row["tenant_id"] == fixture.tenant and row["actor"] == "creator"
      assert row["engagement_asset_id"] == changes.get("engagement_asset_id", "ea_1")
      assert "s3cret-body" not in repr(owner._log_audit_event.call_args_list)
    owner._log_audit_event.reset_mock()
    fixture.service.revoke_engagement(fixture.actor, fixture.tenant, fixture.engagement_id, "done")
    assert launch(fixture)["error"] == "engagement_revoked"
    assert [row["reason"] for row in rows(owner)] == ["engagement_revoked"]


def test_expired_engagement_is_audited():
  with launch_fixture() as fixture:
    fixture.service.clock = lambda: datetime(2026, 12, 1, tzinfo=timezone.utc)
    assert launch(fixture)["error"] == "engagement_expired"
    assert [row["reason"] for row in rows(fixture.owner_plugin)] == ["engagement_expired"]


def test_target_is_truncated():
  with launch_fixture() as fixture:
    launch(fixture, target="x" * 1000, engagement_asset_id="ea_2")
    assert len(rows(fixture.owner_plugin)[0]["target"]) == 256


def test_target_mismatch_is_audited_on_network_webapp_and_launch_test():
  with launch_fixture() as fixture:
    owner = fixture.owner_plugin
    common = dict(fixture.kwargs, engagement_id=fixture.engagement_id, engagement_asset_id="ea_1")
    result = fixture.Plugin.launch_network_scan(owner, **{**common, "target": "foreign.example"})
    assert result["error"] == "validation_error" or "mismatch" in repr(result)
    webapp = {key: value for key, value in common.items() if key not in ("start_port", "end_port")}
    result = fixture.Plugin.launch_webapp_scan(owner, **{**webapp, "target_url": "https://app.example.com/"})
    assert "mismatch" in repr(result)
    result = fixture.Plugin.launch_test(owner, **{**common, "scan_type": "webapp", "target": "foreign.example"})
    assert "mismatch" in repr(result)
    logged = rows(owner)
    assert [(row["reason"], row["scan_type"]) for row in logged] == [
      ("target_mismatch", "network"), ("target_mismatch", "webapp"), ("target_mismatch", "webapp")]
    assert logged[0]["target"] == "foreign.example"
    assert all(set(row) == ROW_FIELDS and row["tenant_id"] == fixture.tenant and row["actor"] == "creator"
               and row["engagement_asset_id"] == "ea_1" for row in logged)


def test_unverified_tenant_and_unaudited_denials_write_no_row():
  with launch_fixture() as fixture:
    owner = fixture.owner_plugin
    fixture.owner.account("outsider", memberships=[])
    # A non-member naming this tenant and an unknown engagement is refused at the tenant check
    # (`not_found`), never as `engagement_not_found`.
    result = launch(fixture, actor={"account_id": "outsider"}, engagement_id="en_" + str(uuid4()))
    assert result["error"] == "not_found"
    # A spoofed tenant id the actor does not belong to.
    assert launch(fixture, tenant_id="tn_00000000-0000-4000-8000-0000000000ff")["error"] == "not_found"
    # `engagement_required` and a role denial (Allow Pentester is off).
    assert launch(fixture, engagement_id=None)["error"] == "engagement_required"
    fixture.owner.account("pentester", memberships=[{"role": "tenant_pentester", "tenant_id": fixture.tenant}])
    assert launch(fixture, actor={"account_id": "pentester"})["error"] == "pentesting_disabled"
    assert rows(owner) == []


def test_admitted_launch_logs_only_scan_launched():
  with launch_fixture() as fixture:
    result = launch(fixture)
    assert result["job_config"]["engagement_id"] == fixture.engagement_id
    events = [call[0][0] for call in fixture.owner_plugin._log_audit_event.call_args_list]
    assert events == ["scan_launched"]


def test_tenant_audit_read_returns_only_that_tenants_refusals():
  with read_endpoint_fixture() as fixture:
    mine = {"event": "launch_refused", "tenant_id": fixture.tenant_id, "reason": "engagement_revoked"}
    theirs = {"event": "launch_refused", "tenant_id": "tn_other", "reason": "engagement_revoked"}
    untenanted = {"event": "launch_refused", "reason": "engagement_revoked"}
    fixture.owner._audit_log.extend([mine, theirs, untenanted])
    result = fixture.Plugin.get_audit_log(fixture.owner, 100, request_actor=fixture.actor,
                                          tenant_id=fixture.tenant_id)
    assert result["audit_log"] == [{"job_id": "job-1", "event": "visible"}, mine]
    assert result["total"] == 2

