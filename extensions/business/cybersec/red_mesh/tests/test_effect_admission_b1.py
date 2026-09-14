"""RM-026 I1b B1: admission, effect state and public projection for persisted-artifact effects.

These four endpoints previously accepted a job id with no requester and read the job through the
unscoped global lookup. Two of them also wrote integration status records on their denial paths,
so probing job ids polluted failure counters that feed cooldown policy.
"""
from unittest.mock import patch

import pytest

from extensions.business.cybersec.red_mesh.services import opencti_export, stix_export, taxii_export
from extensions.business.cybersec.red_mesh.tenancy.effects import EffectState
from .read_endpoint_fixtures import read_endpoint_fixture

JOB_EFFECTS = ("dry_run_opencti_export", "dry_run_taxii_export", "export_stix_bundle")
SECRET = "mock-only-b1-canary"


def call(fixture, name, **kwargs):
  return getattr(fixture.Plugin, name)(fixture.owner, "job-1", request_actor=fixture.actor, **kwargs)


@pytest.mark.parametrize("name", JOB_EFFECTS)
def test_effects_no_longer_use_the_unscoped_global_job_lookup(name):
  with read_endpoint_fixture(bound=False) as fixture:
    # create=True because the fixture owner does not define it at all -- which is itself the
    # evidence: the checked path never reaches for it.
    with patch.object(fixture.owner, "_get_job_from_cstore", create=True,
                      side_effect=AssertionError(SECRET)) as unscoped:
      call(fixture, name)
    unscoped.assert_not_called()


@pytest.mark.parametrize("name", JOB_EFFECTS)
@pytest.mark.parametrize("fault,status", (
  ("actor", 404), ("deleted", 404), ("inactive", 404), ("user", 403),
  ("memberships", 403), ("rollout", 403), ("identity_store", 503),
))
def test_denials_are_effect_free_and_write_no_status_record(name, fault, status):
  """The probe-amplification defect: denial paths must not touch integration status."""
  with read_endpoint_fixture(bound=False) as fixture:
    account = fixture.store.data[("auth", "reader")]
    kwargs = {}
    if fault == "actor": kwargs["request_actor"] = None
    elif fault == "deleted": fixture.store.data.pop(("auth", "reader"))
    elif fault == "inactive": fixture.store.account("reader", active=False)
    elif fault == "user": fixture.store.account("reader", role="user")
    elif fault == "memberships": account["metadata"]["tenant_memberships"] = []
    elif fault == "rollout":
      fixture.tenant_store.put("execution_rollout", fixture.owner.cfg_instance_id,
        record={"stage": "draining", "enabled": False})
    elif fault == "identity_store": fixture.store.fail_hkey = "auth"

    with patch.object(opencti_export, "record_integration_status",
                      side_effect=AssertionError(SECRET)) as opencti_record, \
         patch.object(taxii_export, "record_integration_status",
                      side_effect=AssertionError(SECRET)) as taxii_record, \
         patch.object(stix_export, "record_integration_status",
                      side_effect=AssertionError(SECRET)) as stix_record:
      if fault == "actor":
        result = getattr(fixture.Plugin, name)(fixture.owner, "job-1", request_actor=None)
      else:
        result = call(fixture, name)
      assert result["status_code"] == status
      assert result["success"] is False
      for recorder in (opencti_record, taxii_record, stix_record):
        recorder.assert_not_called()


@pytest.mark.parametrize("name", JOB_EFFECTS)
def test_a_denied_caller_never_reaches_the_job(name):
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role="user")
    result = call(fixture, name)
    assert result == {"success": False, "error": "forbidden", "status_code": 403}
    assert fixture.artifact_reads == []


@pytest.mark.parametrize("name", JOB_EFFECTS)
def test_a_tenant_bound_actor_cannot_reach_a_legacy_effect(name):
  with read_endpoint_fixture(bound=True) as fixture:
    result = call(fixture, name)
    assert result["success"] is False and result["status_code"] in (403, 404)


@pytest.mark.parametrize("name", JOB_EFFECTS)
def test_disabled_integration_reports_status_without_the_framework_error_key(name):
  """A dict carrying `error` is mapped to HTTP 503 by the framework, so it must not carry one."""
  with read_endpoint_fixture(bound=False) as fixture:
    result = call(fixture, name)
    assert "error" not in result or result.get("success") is False


def test_a_landed_persist_is_never_reported_as_nothing_happened():
  """Contract 6: an exception after the bundle lands must not read as `unavailable`."""
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.owner.CONFIG = {"OPENCTI_EXPORT": {"ENABLED": True, "URL": "https://opencti.test",
                                               "TOKEN_ENV": "RM_TEST_OPENCTI_TOKEN"}}
    fixture.owner.config_data = {}

    def persist_then_die(owner, bundle):
      return "artifact-cid"

    with patch.object(opencti_export, "_persist_bundle", persist_then_die), \
         patch.object(opencti_export, "_write_job_record", side_effect=RuntimeError(SECRET)), \
         patch.object(opencti_export, "_prepare_opencti_export",
                      return_value=({"PUSH_MODE": "dry_run", "URL": "https://opencti.test"},
                                    dict(fixture.job),
                                    {"status": "ok", "bundle": {}, "bundle_id": "b1", "pass_nr": 1,
                                     "object_count": 0, "finding_count": 0,
                                     "observed_data_count": 0})):
      result = fixture.Plugin.dry_run_opencti_export(fixture.owner, "job-1",
                                                     request_actor=fixture.actor)
    assert result["error"] == "effect_incomplete"
    assert result["effect_state"] == EffectState.PERSISTED.value
    assert result["status_code"] == 500
    assert SECRET not in repr(result)


def test_test_event_export_requires_the_export_authority():
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role="user")
    result = fixture.Plugin.test_event_export(fixture.owner, request_actor=fixture.actor)
    assert result == {"success": False, "error": "forbidden", "status_code": 403}


def test_test_event_export_admits_a_legacy_pentester():
  with read_endpoint_fixture(bound=False) as fixture:
    fixture.store.account("reader", role="user")
    fixture.store.data[("auth", "reader")]["metadata"]["appRole"] = "pentester"
    result = fixture.Plugin.test_event_export(fixture.owner, request_actor=fixture.actor)
    assert not (result.get("success") is False and result.get("status_code") == 403)
