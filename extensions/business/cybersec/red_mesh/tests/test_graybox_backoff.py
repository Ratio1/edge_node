"""RM-273 Phase F: 429/503 backoff, circuit breaker, per-call deadline, kill switch.

No test sleeps for real: a fake clock stands in for `time` in the client and safety modules.
"""

import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.constants import GRAYBOX_BREAKER_THRESHOLD
from extensions.business.cybersec.red_mesh.graybox import http_client as http_client_mod
from extensions.business.cybersec.red_mesh.graybox import safety as safety_mod
from extensions.business.cybersec.red_mesh.graybox.budget import (
  RequestBudget, TargetThrottled,
)
from extensions.business.cybersec.red_mesh.graybox.findings import GrayboxFinding
from extensions.business.cybersec.red_mesh.graybox.http_client import GrayboxHttpClient
from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
from extensions.business.cybersec.red_mesh.graybox.safety import GrayboxAbort, SafetyControls
from extensions.business.cybersec.red_mesh.graybox.worker import GrayboxAbort as WorkerAbort
from extensions.business.cybersec.red_mesh.tests.test_discovery import _make_discovery
from extensions.business.cybersec.red_mesh.tests.test_worker import _make_worker


class FakeClock:
  def __init__(self):
    self.now = 1000.0
    self.sleeps = []
    self.on_sleep = None

  def time(self):
    return self.now

  monotonic = time

  def sleep(self, seconds):
    self.sleeps.append(seconds)
    self.now += seconds
    if self.on_sleep:
      self.on_sleep()


def _resp(status, retry_after=None):
  r = MagicMock()
  r.status_code = status
  r.headers = {"Retry-After": retry_after} if retry_after is not None else {}
  return r


def _setup(statuses, stop=None, **kwargs):
  clock = FakeClock()
  safety = SafetyControls(request_delay=0.0, target_is_local=True, stop_check=stop)
  budget = RequestBudget(remaining=50, total=50)
  client = GrayboxHttpClient("https://h", allowlist=["h"], request_budget=budget,
                             safety=safety, allow_private_targets=True, **kwargs)
  session = MagicMock()
  session.request.side_effect = list(statuses)
  return clock, safety, budget, client, session


def _run(clock, fn):
  with patch.object(http_client_mod, "time", clock), patch.object(safety_mod, "time", clock):
    return fn()


class TestBackoff(unittest.TestCase):

  def test_get_429_retries_once_after_retry_after(self):
    clock, _s, budget, client, session = _setup([_resp(429, "1"), _resp(200)])
    resp = _run(clock, lambda: client.request(session, "GET", "https://h/x"))
    self.assertEqual(resp.status_code, 200)
    self.assertEqual(session.request.call_count, 2)
    self.assertEqual(budget.total - budget.remaining, 2)
    self.assertEqual(sum(clock.sleeps), 1.0)  # the Retry-After wait

  def test_missing_retry_after_backs_off_1_then_2_then_gives_up(self):
    clock, _s, _b, client, session = _setup([_resp(503), _resp(503), _resp(503)])
    resp = _run(clock, lambda: client.request(session, "GET", "https://h/x"))
    self.assertEqual((resp.status_code, session.request.call_count), (503, 3))
    self.assertEqual(sum(clock.sleeps), 3.0)

  def test_post_is_never_replayed(self):
    clock, _s, budget, client, session = _setup([_resp(429, "1")])
    resp = _run(clock, lambda: client.request(session, "POST", "https://h/x"))
    self.assertEqual((resp.status_code, session.request.call_count), (429, 1))
    self.assertEqual(budget.total - budget.remaining, 1)

  def test_retry_after_above_cap_or_past_deadline_is_not_retried(self):
    clock, _s, _b, client, session = _setup([_resp(429, "31")])
    resp = _run(clock, lambda: client.request(session, "GET", "https://h/x"))
    self.assertEqual((resp.status_code, session.request.call_count, clock.sleeps), (429, 1, []))
    # Deadline (40 s here): the first 30 s wait fits, a second would pass it.
    clock, _s, _b, client, session = _setup([_resp(429, "30"), _resp(429, "30"), _resp(200)])
    with patch.object(http_client_mod, "GRAYBOX_BACKOFF_DEADLINE", 40):
      resp = _run(clock, lambda: client.request(session, "GET", "https://h/x"))
    self.assertEqual((resp.status_code, session.request.call_count), (429, 2))

  def test_opt_out_and_prepaid_are_not_retried(self):
    clock, _s, _b, client, session = _setup([_resp(429, "1")])
    resp = _run(clock, lambda: client.request(session, "GET", "https://h/x", throttle_retry=False))
    self.assertEqual((resp.status_code, session.request.call_count), (429, 1))
    self.assertNotIn("throttle_retry", session.request.call_args.kwargs)
    clock, safety, _b, client, session = _setup([_resp(429, "1")])

    def timed():
      with safety.prepaid():
        return client.request(session, "GET", "https://h/x")
    self.assertEqual(_run(clock, timed).status_code, 429)
    self.assertEqual(session.request.call_count, 1)


class TestRetryAfter(unittest.TestCase):

  def test_http_date_negative_and_naive_dates(self):
    clock = FakeClock()
    with patch.object(http_client_mod, "time", clock):
      parse = http_client_mod._retry_after_seconds
      self.assertEqual(parse("Mon, 01 Jan 1970 00:16:50 GMT"), 10.0)  # clock.now = 1000
      self.assertEqual(parse("Mon, 01 Jan 1970 00:16:50 -0000"), 10.0)  # naive date is UTC
      self.assertIsNone(parse("-5"))
      self.assertIsNone(parse("Mon, 01 Jan 1970 00:00:00 GMT"))  # in the past


class TestBreaker(unittest.TestCase):

  def test_five_throttles_open_it_and_a_reset_or_a_good_response_closes_the_count(self):
    clock, safety, _b, client, session = _setup(
      [_resp(429)] * GRAYBOX_BREAKER_THRESHOLD + [_resp(200)] * 3)
    for _ in range(GRAYBOX_BREAKER_THRESHOLD):
      _run(clock, lambda: client.request(session, "POST", "https://h/x"))
    sent = session.request.call_count
    with self.assertRaises(TargetThrottled):
      _run(clock, lambda: client.request(session, "POST", "https://h/x"))
    self.assertEqual(session.request.call_count, sent)
    self.assertEqual((safety.refusals, safety.last_refusal), (1, "target_throttled"))
    # Exempt hops still go out.
    _run(clock, lambda: client.request(session, "POST", "https://h/x", budget_exempt=True))
    self.assertEqual(session.request.call_count, sent + 1)
    safety.reset_breaker()
    _run(clock, lambda: client.request(session, "POST", "https://h/x"))
    # A non-throttle response resets the consecutive count.
    for _ in range(GRAYBOX_BREAKER_THRESHOLD - 1):
      safety.record_response(429)
    safety.record_response(200)
    safety.record_response(429)
    self.assertFalse(safety.breaker_open)


class TestKillSwitch(unittest.TestCase):

  def test_exempt_hop_is_never_retried(self):
    clock, _s, _b, client, session = _setup([_resp(429, "1"), _resp(200)])
    resp = _run(clock, lambda: client.request(session, "GET", "https://h/x", budget_exempt=True))
    self.assertEqual((resp.status_code, session.request.call_count, clock.sleeps), (429, 1, []))

  def test_the_throttle_that_opens_the_breaker_is_returned_even_with_a_stop_check(self):
    clock, safety, _b, client, session = _setup(
      [_resp(429)] * GRAYBOX_BREAKER_THRESHOLD, stop=lambda: False)
    for _ in range(GRAYBOX_BREAKER_THRESHOLD - 1):
      safety.record_response(429)
    resp = _run(clock, lambda: client.request(session, "GET", "https://h/x"))
    self.assertEqual((resp.status_code, session.request.call_count), (429, 1))
    self.assertTrue(safety.breaker_open)

  def test_stop_refuses_non_exempt_hops_and_sends_nothing(self):
    clock, safety, budget, client, session = _setup([_resp(200)], stop=lambda: True)
    with self.assertRaises(GrayboxAbort) as ctx:
      _run(clock, lambda: client.request(session, "GET", "https://h/x"))
    self.assertEqual(ctx.exception.reason_class, "stopped")
    session.request.assert_not_called()
    self.assertEqual(budget.remaining, 50)
    resp = _run(clock, lambda: client.request(session, "POST", "https://h/x", budget_exempt=True))
    self.assertEqual(resp.status_code, 200)

  def test_backoff_sleep_wakes_on_stop_within_a_poll(self):
    state = {"stop": False}
    clock, _s, _b, client, session = _setup(
      [_resp(429, "10"), _resp(200)], stop=lambda: state["stop"])
    clock.on_sleep = lambda: state.update(stop=clock.now >= 1001.0)
    with self.assertRaises(GrayboxAbort):
      _run(clock, lambda: client.request(session, "GET", "https://h/x"))
    self.assertLessEqual(clock.now - 1001.0, 0.25)
    self.assertEqual(session.request.call_count, 1)

  def test_stop_seen_while_pacing_sends_nothing(self):
    state = {"stop": False}
    clock, safety, budget, client, session = _setup([_resp(200)], stop=lambda: state["stop"])
    safety._request_delay = 1.0
    safety._last_request_at = clock.now
    clock.on_sleep = lambda: state.update(stop=True)
    with self.assertRaises(GrayboxAbort):
      _run(clock, lambda: client.request(session, "GET", "https://h/x"))
    session.request.assert_not_called()
    self.assertEqual(budget.total - budget.remaining, 1)  # charged, unsent: accepted


class _Probe(ProbeBase):
  def run(self):
    return self.findings


def _probe(safety):
  probe = _Probe.__new__(_Probe)
  probe.findings = []
  probe.safety = safety
  probe.request_budget = RequestBudget(remaining=5, total=5)
  probe._record_error = lambda name, msg: probe.findings.append(("error", name, msg))
  return probe


class TestRunGuarded(unittest.TestCase):

  def test_swallowed_target_throttled_downgrades_the_clean_verdict(self):
    safety = SafetyControls(request_delay=0.0, target_is_local=True)
    probe = _probe(safety)

    def family():
      try:
        for _ in range(GRAYBOX_BREAKER_THRESHOLD):
          safety.record_response(429)
        safety.check_admission()
      except TargetThrottled:
        pass
      probe.findings.append(GrayboxFinding(
        scenario_id="PT-A01-05", title="t", status="not_vulnerable", severity="INFO",
        owasp="A01:2021"))
    probe._run_guarded("family", family)
    finding = probe.findings[0]
    self.assertEqual(finding.status, "inconclusive")
    self.assertEqual(finding.evidence, ["reason=target_throttled"])
    self.assertIn(("error", "family", "target_throttled"), probe.findings)

  def test_abort_propagates_after_the_downgrade(self):
    safety = SafetyControls(request_delay=0.0, target_is_local=True, stop_check=lambda: True)
    probe = _probe(safety)

    def family():
      probe.findings.append(GrayboxFinding(
        scenario_id="PT-A01-05", title="t", status="not_vulnerable", severity="INFO",
        owasp="A01:2021"))
      safety.check_admission()
    with self.assertRaises(GrayboxAbort) as ctx:
      probe._run_guarded("family", family)
    self.assertEqual(ctx.exception.reason_class, "stopped")
    self.assertEqual(probe.findings[0].evidence, ["reason=stopped"])


class TestRefusalOutsideAProbe(unittest.TestCase):

  def test_throttled_crawl_keeps_the_routes_found_so_far(self):
    disc = _make_discovery(routes_html={"/": '<a href="/a">a</a><a href="/b">b</a>'})
    session = disc.auth.primary_session
    ok = session.get.side_effect

    def throttled_after_first(url, **kwargs):
      if "/a" in url or "/b" in url:
        raise TargetThrottled()
      return ok(url, **kwargs)
    session.get.side_effect = throttled_after_first
    result = disc.discover_result()
    self.assertIn("/", result.routes)
    self.assertNotIn("/a", result.routes)


class TestWorkerStop(unittest.TestCase):

  def test_a_stop_mid_probe_keeps_the_findings_collected_so_far(self):
    worker = _make_worker()
    worker.auth.ensure_sessions = MagicMock(return_value=True)
    worker.auth.primary_session = MagicMock()
    finding = GrayboxFinding(scenario_id="OK-1", title="t", status="vulnerable",
                             severity="LOW", owasp="")
    probe = MagicMock(findings=[finding])
    probe.run.side_effect = GrayboxAbort("stop requested", reason_class="stopped")
    probe_cls = MagicMock(return_value=probe, is_stateful=False, requires_auth=False,
                          requires_regular_session=False)
    probe_cls.from_context = None
    with patch.object(type(worker), "_import_probe", staticmethod(lambda _p: probe_cls)):
      with self.assertRaises(GrayboxAbort):
        worker._run_registered_probe(
          {"key": "_k", "cls": "x.Y"}, MagicMock(allow_stateful=True, to_kwargs=lambda: {}))
    stored = worker.state["graybox_results"][worker._port_key]["_k"]["findings"]
    self.assertEqual([f["scenario_id"] for f in stored], ["OK-1"])

  def test_abort_is_importable_from_worker(self):
    self.assertIs(WorkerAbort, GrayboxAbort)

  def test_a_stop_during_a_phase_cancels_the_job_instead_of_aborting(self):
    worker = _make_worker()
    worker.owner._require_worker_execution = MagicMock()
    worker._run_preflight_phase = MagicMock(
      side_effect=GrayboxAbort("stop requested", reason_class="stopped"))
    worker.auth.cleanup = MagicMock()
    worker.execute_job()
    self.assertTrue(worker.state["canceled"])
    self.assertFalse(worker.state["aborted"])
    self.assertTrue(worker.state["done"])


if __name__ == "__main__":
  unittest.main()
