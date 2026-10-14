"""RM-139 phase 4: automatic MISP push when a pass finishes.

The push runs on its own queue (one executor thread, per-job FIFO, one push in flight per job). The
worker only delivers; the launcher loop re-reads the job, merges `misp_export` and writes it, at the
top of maybe_finalize_pass before the job list is read. These tests drive the queue with a manual
executor so "in flight" is a state the test controls.
"""
import asyncio
import json
from concurrent.futures import Future
from copy import deepcopy
from unittest.mock import MagicMock, patch

import pytest

from extensions.business.cybersec.red_mesh.services import finalization
from extensions.business.cybersec.red_mesh.services import misp_auto_push
from extensions.business.cybersec.red_mesh.services import misp_export
from extensions.business.cybersec.red_mesh.services.misp_auto_push import (
  SYSTEM_ACTOR,
  enqueue_misp_auto_push,
  misp_auto_push_pending,
  poll_misp_auto_push,
  shutdown_misp_auto_push,
)
from extensions.business.cybersec.red_mesh.services.misp_config import DEFAULT_MISP_EXPORT_CONFIG
from extensions.business.cybersec.red_mesh.constants import MAX_CONTINUOUS_PASSES

from .read_endpoint_fixtures import read_endpoint_fixture
from . import test_api as api_fixtures
from .test_execution_binding_models import binding_payload
from .test_tenant_read_native import (  # noqa: F401  (read_native is a fixture)
  install, read_native, request, scheduler_comms,
)


MISP = {"ENABLED": True, "MISP_URL": "https://misp.example", "MISP_API_KEY": "mock-only-key"}


class ManualExecutor:
  """Holds submitted work until the test runs it, so a push stays in flight on demand."""

  def __init__(self):
    self.pending = []
    self.submitted = []
    self.shutdowns = []

  def submit(self, fn, *args):
    future = Future()
    self.pending.append((future, fn, args))
    self.submitted.append(args)
    return future

  def run_next(self):
    future, fn, args = self.pending.pop(0)
    try:
      future.set_result(fn(*args))
    except Exception as exc:  # the worker is meant never to raise
      future.set_exception(exc)

  def shutdown(self, wait=True, cancel_futures=False):
    self.shutdowns.append((wait, cancel_futures))
    for future, _fn, _args in self.pending:
      future.cancel()


class Repo:
  def __init__(self, jobs, log):
    self.jobs = jobs
    self.log = log

  def get_job(self, job_id):
    self.log.append(("get_job", job_id))
    return deepcopy(self.jobs.get(job_id))

  def list_jobs(self):
    self.log.append(("list_jobs", deepcopy(self.jobs)))
    return deepcopy(self.jobs)


class Owner:
  """Config read through the real resolver; job store in memory; writes recorded in order."""

  ee_addr = "launcher-node"

  def __init__(self, misp=None, override=None, override_error=None, jobs=None):
    self.cfg_misp_export = {**MISP, **(misp or {})} if misp is not False else {}
    self.override = override
    self.override_error = override_error
    self.log = []
    self.writes = []
    self.messages = []
    self.repo = Repo(jobs if jobs is not None else {}, self.log)
    self._misp_push_executor = ManualExecutor()

  def P(self, msg, **kwargs):
    self.messages.append(msg)

  def time(self):
    return 1000.0

  def _get_job_state_repository(self):
    return self.repo

  def _get_super_tenant_integration_override(self, integration_id):
    if self.override_error is not None:
      raise self.override_error
    return self.override

  def _write_job_record(self, job_id, job_specs, context=""):
    self.log.append(("write", context))
    self.writes.append((context, deepcopy(job_specs)))
    self.repo.jobs[job_id] = deepcopy(job_specs)
    return job_specs

  def _normalize_job_record(self, key, record, **kwargs):
    return key, record


def bound_job(job_id="job-1", **fields):
  return {"job_id": job_id, "job_status": "FINALIZED", "launcher": "launcher-node",
          "job_cid": "archive-cid", "execution_binding": binding_payload(), **fields}


def override(auto_export):
  return {"integration_id": "misp", "config": None, "sharing_groups": None, "auto_export": auto_export}


class FakeMisp:
  """Stands in for deliver_misp_event: creates an event, or updates the one the snapshot names."""

  def __init__(self, fail=None):
    self.created = []
    self.updated = []
    self.calls = []
    self.fail = fail

  def __call__(self, owner, job_id, pass_nr=None, *, job_specs, export_config, sharing_groups,
               checked_job, snapshot_mode, ledger=None):
    self.calls.append({"pass_nr": pass_nr, "snapshot": deepcopy(job_specs), "cfg": dict(export_config),
                       "checked": checked_job is job_specs, "mode": snapshot_mode})
    if self.fail is not None:
      if isinstance(self.fail, Exception):
        raise self.fail
      return {"status": "error", "error": self.fail, "retryable": True}
    existing = job_specs.get("misp_export") or {}
    if existing.get("event_uuid"):
      self.updated.append((existing["event_uuid"], pass_nr))
      uuid, event_id = existing["event_uuid"], existing["event_id"]
    else:
      uuid, event_id = f"event-{len(self.created) + 1}", 40 + len(self.created)
      self.created.append((uuid, pass_nr))
    passes = sorted(set(existing.get("passes_exported") or []) | {pass_nr})
    return {"status": "ok", "event_uuid": uuid, "event_id": event_id, "pass_nr": pass_nr,
            "meta": {"event_uuid": uuid, "event_id": event_id, "misp_url": export_config["MISP_URL"],
                     "last_exported_at": 1.0, "passes_exported": passes}}


@pytest.fixture
def fake_misp():
  fake = FakeMisp()
  with patch.object(misp_export, "deliver_misp_event", side_effect=fake), \
       patch.object(misp_auto_push, "emit_export_status_event") as emit:
    fake.emit = emit
    yield fake


def run_all(owner):
  """Run every push the queue starts, merging after each, as successive loop turns would."""
  while owner._misp_push_executor.pending:
    owner._misp_push_executor.run_next()
    poll_misp_auto_push(owner)


# ── Enqueue gate ──

class TestGate:

  def test_default_is_on_when_the_deeploy_block_leaves_it_out(self, fake_misp):
    assert DEFAULT_MISP_EXPORT_CONFIG["AUTO_EXPORT"] is True
    owner = Owner(jobs={"job-1": bound_job()})
    assert enqueue_misp_auto_push(owner, bound_job(), 1) is True
    run_all(owner)
    assert fake_misp.created == [("event-1", 1)]

  @pytest.mark.parametrize("misp,expected_reason", (
    ({"ENABLED": False}, "disabled"),
    ({"MISP_URL": ""}, "not configured"),
    ({"MISP_API_KEY": ""}, "not configured"),
    ({"AUTO_EXPORT": False}, "deeploy off"),
  ))
  def test_nothing_is_queued_when_the_effective_config_says_no(self, fake_misp, misp, expected_reason):
    owner = Owner(misp=misp, jobs={"job-1": bound_job()})
    assert enqueue_misp_auto_push(owner, bound_job(), 1) is False, expected_reason
    assert owner._misp_push_executor.submitted == [] and not misp_auto_push_pending(owner, "job-1")

  def test_sta_override_on_beats_a_deeploy_false(self, fake_misp):
    owner = Owner(misp={"AUTO_EXPORT": False}, override=override(True), jobs={"job-1": bound_job()})
    assert enqueue_misp_auto_push(owner, bound_job(), 1) is True
    run_all(owner)
    assert fake_misp.created == [("event-1", 1)]

  def test_sta_override_off_beats_the_default(self, fake_misp):
    owner = Owner(override=override(False), jobs={"job-1": bound_job()})
    assert enqueue_misp_auto_push(owner, bound_job(), 1) is False

  def test_cleared_override_falls_back_to_the_deeploy_value(self, fake_misp):
    owner = Owner(misp={"AUTO_EXPORT": False}, override=override(None), jobs={"job-1": bound_job()})
    assert enqueue_misp_auto_push(owner, bound_job(), 1) is False
    owner = Owner(override=override(None), jobs={"job-1": bound_job()})
    assert enqueue_misp_auto_push(owner, bound_job(), 1) is True

  def test_unreadable_override_skips_the_pass_and_never_touches_the_job(self, fake_misp):
    owner = Owner(override_error=RuntimeError("store down"), jobs={"job-1": bound_job()})
    assert enqueue_misp_auto_push(owner, bound_job(), 1) is False
    assert owner.writes == [] and owner._misp_push_executor.submitted == []
    assert any("integration config unavailable" in message for message in owner.messages)

  def test_an_already_exported_pass_is_skipped(self, fake_misp):
    job = bound_job(misp_export={"event_uuid": "e", "event_id": 1, "passes_exported": [1]})
    owner = Owner(jobs={"job-1": job})
    assert enqueue_misp_auto_push(owner, job, 1) is False
    assert fake_misp.calls == []

  def test_an_unbound_job_is_not_pushed(self, fake_misp):
    job = {"job_id": "job-1", "job_status": "FINALIZED"}
    owner = Owner(jobs={"job-1": job})
    assert enqueue_misp_auto_push(owner, job, 1) is False

  def test_the_worker_gets_the_job_snapshot_and_the_config_captured_at_enqueue(self, fake_misp):
    job = bound_job()
    owner = Owner(misp={"MIN_SEVERITY": "HIGH"}, jobs={"job-1": job})
    enqueue_misp_auto_push(owner, job, 1)
    owner.cfg_misp_export = {}  # a later config change does not reach a queued push
    run_all(owner)
    call = fake_misp.calls[0]
    assert call["checked"] and call["mode"] == "tenant_bound"
    assert call["snapshot"]["execution_binding"] == job["execution_binding"]
    assert call["cfg"]["MIN_SEVERITY"] == "HIGH" and call["cfg"]["MISP_URL"] == MISP["MISP_URL"]


# ── Merge on the loop thread ──

class TestMerge:

  def test_success_is_merged_with_the_system_actor(self, fake_misp):
    owner = Owner(jobs={"job-1": bound_job()})
    enqueue_misp_auto_push(owner, bound_job(), 1)
    run_all(owner)
    context, written = owner.writes[-1]
    assert context == "misp_auto_export"
    export = written["misp_export"]
    assert (export["event_uuid"], export["passes_exported"], export["status"], export["last_error"],
            export["trigger"], export["actor"], export["last_attempt_pass"]) == (
      "event-1", [1], "completed", None, "auto", SYSTEM_ACTOR, 1)
    assert written["job_status"] == "FINALIZED" and written["job_cid"] == "archive-cid"
    fake_misp.emit.assert_called_once()
    assert fake_misp.emit.call_args.kwargs["status"] == "completed"
    assert not misp_auto_push_pending(owner, "job-1")

  def test_two_passes_finalizing_while_a_push_is_in_flight_make_one_event(self, fake_misp):
    owner = Owner(jobs={"job-1": bound_job(job_status="RUNNING")})
    enqueue_misp_auto_push(owner, owner.repo.jobs["job-1"], 1)
    # Passes 2 and 3 finalize while pass 1 is still in flight.
    enqueue_misp_auto_push(owner, owner.repo.jobs["job-1"], 2)
    enqueue_misp_auto_push(owner, owner.repo.jobs["job-1"], 3)
    assert len(owner._misp_push_executor.submitted) == 1  # one in flight per job
    poll_misp_auto_push(owner)  # nothing done yet: nothing merged, nothing started
    assert owner.writes == [] and len(owner._misp_push_executor.submitted) == 1
    run_all(owner)
    assert fake_misp.created == [("event-1", 1)]
    assert fake_misp.updated == [("event-1", 2), ("event-1", 3)]
    assert owner.repo.jobs["job-1"]["misp_export"]["passes_exported"] == [1, 2, 3]

  def test_merge_keeps_passes_a_concurrent_write_recorded(self, fake_misp):
    owner = Owner(jobs={"job-1": bound_job()})
    enqueue_misp_auto_push(owner, bound_job(), 2)
    # A manual export of pass 1 landed after the worker took its snapshot.
    owner.repo.jobs["job-1"]["misp_export"] = {"event_uuid": "event-1", "event_id": 40,
                                               "passes_exported": [1]}
    run_all(owner)
    assert owner.repo.jobs["job-1"]["misp_export"]["passes_exported"] == [1, 2]

  def test_a_pass_exported_while_queued_is_skipped_at_start(self, fake_misp):
    owner = Owner(jobs={"job-1": bound_job()})
    enqueue_misp_auto_push(owner, bound_job(), 1)
    enqueue_misp_auto_push(owner, bound_job(), 2)
    owner.repo.jobs["job-1"]["misp_export"] = {"event_uuid": "x", "event_id": 1, "passes_exported": [2]}
    run_all(owner)
    assert [call["pass_nr"] for call in fake_misp.calls] == [1]

  def test_the_same_pass_is_not_queued_twice(self, fake_misp):
    owner = Owner(jobs={"job-1": bound_job()})
    assert enqueue_misp_auto_push(owner, bound_job(), 1) is True
    assert enqueue_misp_auto_push(owner, bound_job(), 1) is False

  @pytest.mark.parametrize("fail,code", (("push_failed", "push_failed"),
                                         ("sharing_group_rejected", "sharing_group_rejected"),
                                         (RuntimeError("boom"), "push_failed")))
  def test_failure_is_recorded_the_job_stays_finished_and_nothing_retries(self, fail, code):
    fake = FakeMisp(fail=fail)
    owner = Owner(jobs={"job-1": bound_job()})
    with patch.object(misp_export, "deliver_misp_event", side_effect=fake), \
         patch.object(misp_auto_push, "emit_export_status_event") as emit:
      enqueue_misp_auto_push(owner, bound_job(), 1)
      run_all(owner)
      for _ in range(3):
        poll_misp_auto_push(owner)
    job = owner.repo.jobs["job-1"]
    assert job["job_status"] == "FINALIZED"
    assert (job["misp_export"]["status"], job["misp_export"]["last_error"],
            job["misp_export"]["passes_exported"]) == ("failed", code, [])
    assert len(fake.calls) == 1 and owner._misp_push_executor.pending == []
    assert emit.call_args.kwargs["status"] == "failed"
    assert not misp_auto_push_pending(owner, "job-1")
    status = misp_export.get_misp_export_status(owner, "job-1", checked_job=job)
    assert (status["exported"], status["status"], status["last_error"], status["trigger"]) == (
      False, "failed", code, "auto")

  def test_worker_denials_become_recorded_codes(self):
    from extensions.business.cybersec.red_mesh.tenancy.administration import AdministrationDenied
    from extensions.business.cybersec.red_mesh.tenancy.ports import TenantStoreError
    for error, code in ((AdministrationDenied(409, "no_completed_passes"), "no_completed_passes"),
                        (TenantStoreError("x"), "unavailable"), (ValueError("x"), "push_failed")):
      with patch.object(misp_export, "deliver_misp_event", side_effect=error):
        assert misp_auto_push._push_worker(Owner(), "job-1", 1, bound_job(), dict(MISP), {}) == {
          "status": "error", "error": code}

  def test_a_failed_push_after_an_event_keeps_the_event(self, fake_misp):
    owner = Owner(jobs={"job-1": bound_job()})
    enqueue_misp_auto_push(owner, bound_job(), 1)
    run_all(owner)
    fake_misp.fail = "push_failed"
    enqueue_misp_auto_push(owner, owner.repo.jobs["job-1"], 2)
    run_all(owner)
    export = owner.repo.jobs["job-1"]["misp_export"]
    assert (export["event_uuid"], export["passes_exported"], export["status"]) == ("event-1", [1], "failed")

  def test_a_deleted_job_is_not_recreated(self, fake_misp):
    owner = Owner(jobs={"job-1": bound_job()})
    enqueue_misp_auto_push(owner, bound_job(), 1)
    del owner.repo.jobs["job-1"]
    run_all(owner)
    assert owner.writes == [] and "job-1" not in owner.repo.jobs


# ── The finalization loop ──

class TestFinalizationLoop:

  def test_merge_runs_before_the_job_list_even_while_analysis_yields(self, fake_misp):
    owner = Owner(jobs={"job-1": bound_job(job_status="RUNNING", launcher="other-node")})
    enqueue_misp_auto_push(owner, owner.repo.jobs["job-1"], 1)
    owner._misp_push_executor.run_next()
    def analysis_yields(owner_, all_jobs):
      owner.log.append(("analysis_poll",))
      return None, True  # automatic analysis in flight: the loop yields this turn
    with patch.object(finalization, "_poll_automatic_analysis", side_effect=analysis_yields):
      finalization.maybe_finalize_pass(owner)
    kinds = [entry[0] for entry in owner.log]
    assert kinds.index("write") < kinds.index("list_jobs")
    listed = next(entry[1] for entry in owner.log if entry[0] == "list_jobs")
    # Every loop write this turn starts from a record that already holds the merge.
    assert listed["job-1"]["misp_export"]["event_uuid"] == "event-1"
    assert kinds[-1] == "analysis_poll"  # merged even though the loop yielded right after

  def test_a_push_in_flight_neither_yields_nor_holds_other_jobs(self):
    case = api_fixtures.TestPhase2PassFinalization()
    Plugin = case._get_plugin_class()
    plugin, job_specs = case._build_finalize_plugin()
    case._configure_successful_pass_finalization(plugin, job_specs)
    in_flight = Future()
    plugin._misp_push_state = {"other-job": {"future": in_flight, "pass_nr": 1, "queue": []}}
    with patch.object(finalization, "enqueue_misp_auto_push") as enqueue:
      Plugin._maybe_finalize_pass(plugin)
    plugin._build_job_archive.assert_called_once()
    enqueue.assert_called_once_with(plugin, job_specs, 1)
    assert not in_flight.cancelled() and "other-job" in plugin._misp_push_state
    assert plugin._automatic_analysis_state is None

  @staticmethod
  def _finalize(run_mode="SINGLEPASS", job_pass=1, job_status="RUNNING", **setup):
    case = api_fixtures.TestPhase2PassFinalization()
    Plugin = case._get_plugin_class()
    plugin, job_specs = case._build_finalize_plugin(run_mode=run_mode, job_pass=job_pass)
    case._configure_successful_pass_finalization(plugin, job_specs)
    job_specs["job_status"] = job_status
    for name, value in setup.items():
      if name == "job":
        job_specs.update(value)
      else:
        setattr(plugin, name, value)
    with patch.object(finalization, "enqueue_misp_auto_push") as enqueue:
      Plugin._maybe_finalize_pass(plugin)
    return plugin, job_specs, enqueue

  @pytest.mark.parametrize("run_mode,job_pass,job_status", (
    ("SINGLEPASS", 1, "RUNNING"),                                   # singlepass archive
    ("CONTINUOUS_MONITORING", 2, "SCHEDULED_FOR_STOP"),             # scheduled stop
    ("CONTINUOUS_MONITORING", MAX_CONTINUOUS_PASSES, "RUNNING"),    # pass cap
    ("CONTINUOUS_MONITORING", 3, "RUNNING"),                        # continuous next pass
  ))
  def test_each_finished_pass_is_enqueued_once(self, run_mode, job_pass, job_status):
    plugin, job_specs, enqueue = self._finalize(run_mode, job_pass, job_status)
    enqueue.assert_called_once_with(plugin, job_specs, job_pass)
    assert job_specs["pass_reports"][-1]["pass_nr"] == job_pass

  def test_attestation_failure_is_not_pushed(self):
    plugin, job_specs, enqueue = self._finalize(job={"blockchain_attestation_enabled": True})
    assert job_specs["failure_class"] == "attestation_failed"
    enqueue.assert_not_called()

  def test_an_aborted_first_pass_is_not_pushed(self):
    plugin, job_specs, enqueue = self._finalize(
      _get_aggregated_report=MagicMock(return_value={"open_ports": [], "aborted": True,
                                                     "abort_reason": "login failed",
                                                     "abort_phase": "authentication"}))
    assert job_specs["failure_class"] == "scan_aborted"
    enqueue.assert_not_called()


# ── The finalized stub and a terminal job ──

class TestTerminalJob:

  def _archived(self):
    case = api_fixtures.TestPhase3Archive()
    Plugin = case._get_plugin_class()
    plugin, job_specs, _, _ = case._build_archive_plugin()
    type(plugin)._write_job_record = (
      lambda self, job_id, specs, context="", **kwargs: Plugin._write_job_record(
        self, job_id, specs, context=context, **kwargs))
    return Plugin, plugin, job_specs

  def test_archive_stub_keeps_misp_export(self):
    Plugin, plugin, job_specs = self._archived()
    job_specs["misp_export"] = {"event_uuid": "event-1", "event_id": 40, "passes_exported": [1]}
    Plugin._build_job_archive(plugin, "test-job", job_specs)
    stub = plugin.chainstore_hget("test-instance", "test-job")
    assert stub["job_cid"] == "QmArchiveCID"
    assert stub["misp_export"] == {"event_uuid": "event-1", "event_id": 40, "passes_exported": [1]}

  def test_a_terminal_job_is_not_cancelled_and_the_merge_lands_on_its_stub(self, fake_misp):
    Plugin, plugin, job_specs = self._archived()
    Plugin._build_job_archive(plugin, "test-job", job_specs)
    plugin.cfg_misp_export = dict(MISP)
    plugin._misp_push_executor = ManualExecutor()
    assert enqueue_misp_auto_push(plugin, job_specs, 1) is True
    run_all(plugin)
    stub = plugin.chainstore_hget("test-instance", "test-job")
    assert (stub["job_status"], stub["job_cid"]) == ("FINALIZED", "QmArchiveCID")
    assert stub["misp_export"]["passes_exported"] == [1] and stub["misp_export"]["trigger"] == "auto"
    assert not any(call.args[0] == "terminal_write_rejected" for call in plugin._log_audit_event.call_args_list)


# ── Manual export while an automatic push holds the job ──

IN_FLIGHT = {"success": False, "error": "misp_auto_export_in_flight", "status_code": 409}


def _accepted_event():
  from pymisp import MISPEvent
  event = MISPEvent()
  event.uuid, event.id = "manual-event", 7
  return event


class TestManualExport:

  def test_manual_export_is_refused_while_in_flight_and_works_after(self):
    with read_endpoint_fixture(bound=True, archived=False) as fixture:
      fixture.owner._misp_push_state = {"job-1": {"future": Future(), "pass_nr": 1, "queue": []}}
      cfg = {**DEFAULT_MISP_EXPORT_CONFIG, **MISP}
      with patch.object(misp_export, "get_misp_export_config", return_value=cfg), \
           patch.object(misp_export, "PyMISP") as client, \
           patch.object(misp_export, "emit_export_status_event"), \
           patch.object(misp_export, "_write_job_record") as write:
        client.return_value.add_event.return_value = _accepted_event()
        refused = fixture.Plugin.export_misp(fixture.owner, "job-1", None, fixture.actor, fixture.tenant_id)
        assert refused == IN_FLIGHT
        client.assert_not_called()
        write.assert_not_called()
        fixture.owner._misp_push_state = {}
        result = fixture.Plugin.export_misp(fixture.owner, "job-1", None, fixture.actor, fixture.tenant_id)
      assert result["status"] == "ok" and result["event_uuid"] == "manual-event", result
      client.return_value.add_event.assert_called_once()
      assert write.call_args.kwargs["context"] == "misp_export"

  @pytest.mark.parametrize("response_format", ("RAW", "WRAPPED"))
  def test_the_409_survives_the_guard(self, read_native, response_format):
    module, _ = read_native
    install(module)
    with read_endpoint_fixture(bound=True, archived=False) as fixture:
      fixture.owner._misp_push_state = {"job-1": {"future": None, "pass_nr": None, "queue": [{}]}}
      module.eng = scheduler_comms(fixture, response_format)
      body = {"job_id": "job-1", "request_actor": fixture.actor, "tenant_id": fixture.tenant_id}
      status, _headers, raw, _calls = asyncio.run(request(module, "export_misp", body))
      assert status == 409, raw
      assert json.loads(raw)["error"] == "misp_auto_export_in_flight", raw


# ── Plugin lifecycle ──

class TestLifecycle:

  def test_close_shuts_the_executor_down_and_drops_the_queue(self):
    owner = Owner()
    executor = owner._misp_push_executor
    owner._misp_push_state = {"job-1": {"future": Future(), "pass_nr": 1, "queue": []}}
    shutdown_misp_auto_push(owner)
    assert executor.shutdowns == [(False, True)]
    assert owner._misp_push_executor is None and not misp_auto_push_pending(owner, "job-1")

  def test_plugin_creates_and_closes_its_own_push_executor(self):
    Plugin = api_fixtures.TestPhase3Archive()._get_plugin_class()
    base = next(cls for cls in Plugin.__mro__[1:] if "on_close" in cls.__dict__)
    plugin = Plugin.__new__(Plugin)
    with patch.object(base, "on_init", create=True):
      try:
        Plugin.on_init(plugin)
      except Exception:
        pass  # later init steps need the plugin runtime; the push executor is created first
    executor = plugin._misp_push_executor
    assert executor._thread_name_prefix == "redmesh-misp-push" and executor._max_workers == 1
    assert plugin._misp_push_state == {}
    Plugin.on_close(plugin)
    assert executor._shutdown and plugin._misp_push_executor is None
