"""RM-071 Phase 1: the request budget is charged at the HTTP client, not by probes.

Every count here is taken at the transport (the fake app's request log), i.e. what
actually left the scanner, and compared with what the shared budget recorded.
"""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudget
from extensions.business.cybersec.red_mesh.graybox.http_client import GrayboxHttpClient
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  GrayboxTargetConfig, AccessControlConfig, IdorEndpoint, AdminEndpoint,
  BusinessLogicConfig, WorkflowEndpoint, RecordEndpoint, InjectionConfig,
  SsrfEndpoint, ReflectiveEndpoint, JsonLookupEndpoint, MisconfigConfig,
  JwtEndpoint, ApiSecurityConfig, ApiObjectEndpoint, ApiPropertyEndpoint,
  ApiFunctionEndpoint, ApiResourceEndpoint, ApiBusinessFlow, ApiTokenEndpoint,
  ApiInventoryPaths,
)
from extensions.business.cybersec.red_mesh.graybox.probes.access_control import AccessControlProbes
from extensions.business.cybersec.red_mesh.graybox.probes.api_abuse import ApiAbuseProbes
from extensions.business.cybersec.red_mesh.graybox.probes.api_access import ApiAccessProbes
from extensions.business.cybersec.red_mesh.graybox.probes.api_auth import ApiAuthProbes
from extensions.business.cybersec.red_mesh.graybox.probes.base import ProbeBase
from extensions.business.cybersec.red_mesh.graybox.probes.business_logic import BusinessLogicProbes
from extensions.business.cybersec.red_mesh.graybox.probes.injection import InjectionProbes
from extensions.business.cybersec.red_mesh.graybox.probes.misconfig import MisconfigProbes
from extensions.business.cybersec.red_mesh.graybox.safety import SafetyControls
from extensions.business.cybersec.red_mesh.graybox.worker import GrayboxLocalWorker

from . import graybox_app_fixture as fx
from .test_worker import _make_job_config


def _config():
  """Every probe family configured, as in the RM-219 worker test."""
  return GrayboxTargetConfig(
    access_control=AccessControlConfig(
      idor_endpoints=[IdorEndpoint(path="/api/records/{id}/", test_ids=[2], owner_field="owner")],
      admin_endpoints=[AdminEndpoint(
        path="/manage/users/", method="GET", content_markers=["all users"])],
    ),
    misconfig=MisconfigConfig(jwt_endpoints=JwtEndpoint(
      token_path="/api/token/", protected_path="/api/me/", username="alice", password="pw")),
    injection=InjectionConfig(
      ssrf_endpoints=[SsrfEndpoint(path="/api/fetch/", param="url")],
      xss_endpoints=[ReflectiveEndpoint(path="/api/echo/", param="q")],
      ssti_endpoints=[ReflectiveEndpoint(path="/api/echo/", param="q")],
      cmd_endpoints=[ReflectiveEndpoint(path="/api/echo/", param="q")],
      header_endpoints=[ReflectiveEndpoint(path="/redirect/", param="next")],
      json_type_endpoints=[JsonLookupEndpoint(path="/api/records/1/", field="id")],
    ),
    business_logic=BusinessLogicConfig(
      workflow_endpoints=[WorkflowEndpoint(
        path="/admin/force-pay/", method="POST", expected_guard="403")],
      record_endpoints=[RecordEndpoint(path="/records/1/")],
    ),
    api_security=ApiSecurityConfig(
      object_endpoints=[ApiObjectEndpoint(
        path="/api/records/{id}/", test_ids=[2], owner_field="owner")],
      property_endpoints=[ApiPropertyEndpoint(path="/api/profile/{id}/", test_id=1)],
      function_endpoints=[
        ApiFunctionEndpoint(path="/api/admin/export/", method="GET", privilege="admin"),
        ApiFunctionEndpoint(path="/api/admin/users/7/promote/", method="POST",
                            privilege="admin", revert_path="/api/admin/users/7/demote/"),
      ],
      resource_endpoints=[ApiResourceEndpoint(path="/api/list/", rate_limit_expected=True)],
      business_flows=[ApiBusinessFlow(
        path="/api/auth/signup/", flow_name="signup",
        body_template={"email": "{test_account}"}, test_account="probe@example.test",
        allow_static_test_account_body=True, revert_path="/api/auth/signup/revert/")],
      token_endpoints=ApiTokenEndpoint(
        token_path="/api/token/", protected_path="/api/me/", logout_path="/api/auth/logout/"),
      inventory_paths=ApiInventoryPaths(
        current_version="/api/v1/", canonical_probe_path="/api/v1/me/",
        deprecated_paths=["/api/v0/"]),
    ),
    password_reset_path="/auth/password-reset/",
  )


def _worker():
  owner = MagicMock()
  cfg = _make_job_config(
    official_username="", official_password="", bearer_token="",
    bearer_refresh_token="", api_key="", regular_bearer_token="",
    regular_bearer_refresh_token="", regular_api_key="",
    regular_username="alice", regular_password="pw",
    allow_stateful_probes=True, weak_candidates=["guest:guest"],
    target_config=_config().to_dict(),
    engagement={"allow_private_targets": True},  # testapp.local resolves nowhere
  )
  return GrayboxLocalWorker(
    owner=owner, job_id="rm071", target_url=cfg.target_url,
    job_config=cfg, local_id="1", initiator="test-node")


def _probe_env(budget, *, app=None):
  """A real client over the fake app, and a logged-in session wrapped by it."""
  app = app or fx.FakeApp()
  client = GrayboxHttpClient(
    fx.BASE, request_budget=budget, allow_private_targets=True,
    safety=SafetyControls(request_delay=0.0, target_is_local=True))
  session = app.session_factory()
  session.cookies.set("sessionid", "valid")
  scoped = client.wrap_session(session)
  auth = MagicMock()
  auth.regular_session = auth.primary_session = scoped
  auth.official_session = None
  auth.admin_context = "absent"
  auth.primary_principal = "regular"
  auth.detected_csrf_field = "csrfmiddlewaretoken"
  auth.extract_csrf_value = lambda text, field: "tok"
  auth.make_anonymous_session = lambda: client.wrap_session(app.session_factory())
  return app, client, scoped, auth


class _RollbackProbe(ProbeBase):
  def run(self):
    return self.findings


class TestBudgetEqualsRequestsActuallySent(unittest.TestCase):

  def _scan(self):
    worker = _worker()
    app = fx.FakeApp()
    with patch("requests.Session", side_effect=app.session_factory), \
         patch("time.sleep"):
      worker.execute_job()
    return worker, app

  def test_budget_matches_the_transport_across_every_probe_family(self):
    worker, app = self._scan()
    budget = worker.request_budget
    results = worker.state["graybox_results"]
    emitted = {key for probes in results.values() for key in probes}
    for family in ("_graybox_access_control", "_graybox_misconfig", "_graybox_injection",
                   "_graybox_business_logic", "_graybox_api_access", "_graybox_api_auth",
                   "_graybox_api_config", "_graybox_api_data", "_graybox_api_abuse"):
      self.assertIn(family, emitted)
    self.assertEqual(budget.exhausted_count, 0, "budget too small for the measurement")
    self.assertGreater(len(app.log), 100)
    self.assertEqual(budget.total - budget.remaining, len(app.log))
    status = worker.get_status()["scan_metrics"]
    self.assertEqual(status["budget_total"] - status["budget_remaining"], len(app.log))


class TestRefusalIsNeverReadAsAClean(unittest.TestCase):

  def test_a_legacy_family_cut_off_mid_run_keeps_no_clean_verdict(self):
    budget = RequestBudget(remaining=3, total=3)
    app, _client, _session, auth = _probe_env(budget)
    probe = AccessControlProbes(
      target_url=fx.BASE, auth_manager=auth, target_config=_config(),
      safety=SafetyControls(request_delay=0.0, target_is_local=True),
      regular_username="alice", request_budget=budget)
    probe.run()
    self.assertEqual(len(app.log), 3)
    self.assertEqual(budget.remaining, 0)
    self.assertGreater(budget.exhausted_count, 0)
    self.assertEqual([f.scenario_id for f in probe.findings if f.status == "not_vulnerable"], [])
    self.assertTrue(any(f.scenario_id.startswith("ERR-") and f.error == "budget_exhausted"
                        for f in probe.findings))

  def test_a_swallowed_refusal_downgrades_the_clean_but_not_a_fetched_vulnerable(self):
    budget = RequestBudget(remaining=1, total=1)
    app, _client, session, auth = _probe_env(budget)
    probe = _RollbackProbe(
      target_url=fx.BASE, auth_manager=auth, target_config=MagicMock(),
      safety=SafetyControls(request_delay=0.0, target_is_local=True), request_budget=budget)
    probe.emit_clean("PT-A01-01", "earlier run", "A01:2021", ["ok"])

    def family():
      session.get(fx.BASE + "/api/me/")      # sent: the only request left
      try:
        session.get(fx.BASE + "/api/me/")    # refused, then swallowed like a probe's `except Exception`
      except Exception:
        pass
      probe.emit_vulnerable("PT-A01-02", "found", "HIGH", "A01:2021", [], ["endpoint=/api/me/"])
      probe.emit_clean("PT-A01-03", "unproven", "A01:2021", ["ok"])
    probe.run_safe("family", family)
    by_id = {f.scenario_id: f for f in probe.findings}
    self.assertEqual(by_id["PT-A01-01"].status, "not_vulnerable")  # before this run: untouched
    self.assertEqual(by_id["PT-A01-02"].status, "vulnerable")
    self.assertEqual(by_id["PT-A01-03"].status, "inconclusive")
    self.assertEqual(by_id["PT-A01-03"].evidence, ["reason=budget_exhausted"])
    self.assertEqual(by_id["ERR-family"].error, "budget_exhausted")
    self.assertEqual(len(app.log), 1)

  def _misconfig(self, budget, app, auth):
    return MisconfigProbes(
      target_url=fx.BASE, auth_manager=auth, target_config=_config(),
      safety=SafetyControls(request_delay=0.0, target_is_local=True),
      request_budget=budget)

  def test_login_burst_the_budget_cannot_cover_is_not_sent(self):
    budget = RequestBudget(remaining=5, total=5)
    app, _client, _session, auth = _probe_env(budget)
    probe = self._misconfig(budget, app, auth)
    probe.run_safe("login_rate_limiting", probe._test_login_rate_limiting)
    self.assertEqual(app.log, [])
    self.assertEqual([(f.scenario_id, f.status) for f in probe.findings],
                     [("PT-A02-07", "inconclusive")])

  def test_login_burst_cut_off_midway_is_inconclusive_not_vulnerable(self):
    budget = RequestBudget(remaining=16, total=16)
    app, _client, _session, auth = _probe_env(budget)
    handle = app.handle

    def drain_after_four(*args, **kwargs):
      if len(app.log) >= 4:
        budget.remaining = min(budget.remaining, 0)
      return handle(*args, **kwargs)
    app.handle = drain_after_four
    probe = self._misconfig(budget, app, auth)
    probe.run_safe("login_rate_limiting", probe._test_login_rate_limiting)
    statuses = {f.status for f in probe.findings if f.scenario_id == "PT-A02-07"}
    self.assertEqual(statuses, {"inconclusive"})
    self.assertGreater(budget.exhausted_count, 0)


class TestRollbackCompletesOnAnExhaustedBudget(unittest.TestCase):

  def test_the_revert_is_sent_when_the_budget_ends_after_verify(self):
    budget = RequestBudget(remaining=3, total=3)  # baseline + mutate + verify, nothing for revert
    app, _client, session, auth = _probe_env(budget)
    probe = _RollbackProbe(
      target_url=fx.BASE, auth_manager=auth, target_config=MagicMock(),
      safety=SafetyControls(request_delay=0.0, target_is_local=True),
      allow_stateful=True, request_budget=budget)
    url = fx.BASE + "/api/records/1/"
    probe.run_stateful(
      "PT-OAPI3-02",
      baseline_fn=lambda: session.get(url).status_code,
      mutate_fn=lambda b: session.patch(url, json={"role": "admin"}).status_code < 400,
      verify_fn=lambda b: session.get(url).status_code < 400,
      revert_fn=lambda b: session.patch(
        url, json={"role": "user"}, budget_exempt=True).status_code < 400,
      finding_kwargs={"title": "Mass assignment", "owasp": "API3:2023"},
    )
    self.assertEqual([m for _, m, _ in app.log], ["GET", "PATCH", "GET", "PATCH"])
    self.assertEqual(probe.findings[0].rollback_status, "reverted")
    self.assertEqual(budget.total - budget.remaining, len(app.log))
    self.assertEqual(budget.remaining, -1)

  def test_a_refusal_inside_mutate_still_runs_the_revert(self):
    budget = RequestBudget(remaining=1, total=1)
    app, _client, session, auth = _probe_env(budget)
    probe = _RollbackProbe(
      target_url=fx.BASE, auth_manager=auth, target_config=MagicMock(),
      safety=SafetyControls(request_delay=0.0, target_is_local=True),
      allow_stateful=True, request_budget=budget)
    url = fx.BASE + "/api/records/1/"

    def mutate(_):
      session.patch(url, json={"role": "admin"})
      session.get(url)  # refused: the PATCH above already landed
      return True
    probe.run_stateful(
      "PT-OAPI3-02",
      baseline_fn=lambda: None,
      mutate_fn=mutate,
      verify_fn=lambda b: False,
      revert_fn=lambda b: session.patch(
        url, json={"role": "user"}, budget_exempt=True).status_code < 400,
      finding_kwargs={"title": "Mass assignment", "owasp": "API3:2023"},
    )
    self.assertEqual([m for _, m, _ in app.log], ["PATCH", "PATCH"])
    self.assertEqual(probe.findings[0].rollback_status, "reverted")
    self.assertNotEqual(probe.findings[0].status, "vulnerable")


def _probe(cls, budget, auth, **kw):
  return cls(
    target_url=fx.BASE, auth_manager=auth, target_config=_config(),
    safety=SafetyControls(request_delay=0.0, target_is_local=True),
    request_budget=budget, **kw)


class TestRealRevertPathsAreExempt(unittest.TestCase):
  """Removing budget_exempt from a production revert site must fail one of these."""

  def _env(self):
    budget = RequestBudget(remaining=0, total=5)
    app, client, session, auth = _probe_env(budget)
    return budget, app, session, auth

  def test_access_control_restore_patch_and_reread(self):
    budget, app, _s, auth = self._env()
    probe = _probe(AccessControlProbes, budget, auth, regular_username="alice")
    restored = probe._restore_verified(
      fx.BASE + "/api/records/1/", {"title": "t"}, {}, "title", "t")
    self.assertTrue(restored)
    self.assertEqual([m for _, m, _ in app.log], ["PATCH", "GET"])
    self.assertEqual(budget.remaining, -2)

  def test_api_access_revert_function_endpoint(self):
    budget, app, session, auth = self._env()
    probe = _probe(ApiAccessProbes, budget, auth)
    ep = SimpleNamespace(revert_body={})
    probe._revert_function_endpoint(session, fx.BASE + "/api/admin/users/7/demote/", ep)
    self.assertEqual(len(app.log), 1)

  def test_api_abuse_flow_revert(self):
    budget, app, session, auth = self._env()
    probe = _probe(ApiAbuseProbes, budget, auth)
    flow = SimpleNamespace(revert_path="/api/auth/signup/revert/", revert_method="POST")
    self.assertTrue(probe._flow_revert(session, flow, {}))
    self.assertEqual(len(app.log), 1)

  def test_api_auth_token_reissue_on_rollback(self):
    budget, app, _s, auth = self._env()
    probe = _probe(ApiAuthProbes, budget, auth)
    token, _ = probe._obtain_token(rollback=True)
    self.assertTrue(token)
    self.assertEqual(len(app.log), 1)


class TestPacingStaysOutsideTimedWindows(unittest.TestCase):

  def test_blind_ssrf_elapsed_excludes_pacing(self):
    budget = RequestBudget(remaining=50, total=50)
    app, client, _s, auth = _probe_env(budget)
    client._safety = SafetyControls(request_delay=0.3, target_is_local=True)
    probe = InjectionProbes(
      target_url=fx.BASE, auth_manager=auth, target_config=_config(),
      safety=client._safety, request_budget=budget)
    clock = {"now": 1000.0}
    stamps = []

    def monotonic():
      stamps.append(clock["now"])
      return clock["now"]
    with patch("time.sleep", lambda d: clock.__setitem__("now", clock["now"] + d)), \
         patch("time.time", lambda: clock["now"]), patch("time.monotonic", monotonic):
      probe._test_ssrf()
    self.assertGreaterEqual(len(stamps), 4)
    for start, end in zip(stamps[0::2], stamps[1::2]):
      self.assertEqual(end - start, 0.0, "pacing sleep landed inside a timed request")
    self.assertGreater(clock["now"], 1000.0, "no pacing happened at all")


class TestRefusalInRefreshAndWeakAuth(unittest.TestCase):

  def test_refused_refresh_records_the_family_and_the_next_one_still_runs(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudgetExhausted
    worker = _worker()
    worker.auth = MagicMock()
    worker.auth.primary_session = worker.auth.regular_session = object()
    worker.auth.ensure_sessions.side_effect = [RequestBudgetExhausted(), True]
    ran = []

    class _Probe:
      is_stateful = False
      requires_regular_session = False
      requires_auth = True

      def __init__(self, **kw):
        pass

      def run(self):
        ran.append(1)
        return []
    worker._import_probe = lambda path: _Probe
    ctx = MagicMock()
    ctx.allow_stateful = True
    ctx.to_kwargs.return_value = {}
    entries = [{"key": "_graybox_a", "cls": "x.A"}, {"key": "_graybox_b", "cls": "x.B"}]
    for entry in entries:
      worker._run_registered_probe(entry, ctx)
    results = worker.state["graybox_results"][worker._port_key]
    self.assertEqual(results["_graybox_a"]["findings"][0]["error"], "budget_exhausted")
    self.assertIn("_graybox_b", results)
    self.assertEqual(ran, [1])

  def test_weak_auth_keeps_found_credentials_when_the_budget_ends(self):
    from extensions.business.cybersec.red_mesh.graybox.budget import RequestBudgetExhausted
    budget = RequestBudget(remaining=5, total=5)
    _app, _c, _s, auth = _probe_env(budget)
    good = MagicMock()
    auth.try_credentials.side_effect = [good, RequestBudgetExhausted()]
    auth.target_url = fx.BASE
    probe = _probe(BusinessLogicProbes, budget, auth)
    probe.safety = MagicMock()
    probe.safety.clamp_attempts.return_value = 5
    probe.run_weak_auth(["a:1", "b:2", "c:3"], 5)
    got = {(f.scenario_id, f.status) for f in probe.findings}
    self.assertEqual(got, {("PT-A07-01", "vulnerable"), ("PT-A07-01", "inconclusive")})


class TestRateLimitBurstIsAllOrNone(unittest.TestCase):

  def test_no_rate_limit_scenario_with_a_short_budget_sends_nothing(self):
    budget = RequestBudget(remaining=9, total=9)
    app, _c, _s, auth = _probe_env(budget)
    probe = _probe(ApiAbuseProbes, budget, auth)
    probe._test_no_rate_limit()
    self.assertEqual(app.log, [])
    self.assertEqual({(f.scenario_id, f.status) for f in probe.findings},
                     {("PT-OAPI4-03", "inconclusive")})


class TestDowngradedFindingIsNeutral(unittest.TestCase):

  def test_withdrawn_vulnerable_verdict_loses_title_and_location(self):
    budget = RequestBudget(remaining=1, total=1)
    app, _c, session, auth = _probe_env(budget)
    probe = _probe(MisconfigProbes, budget, auth)

    def family():
      try:
        session.get(fx.BASE + "/api/me/")
        session.get(fx.BASE + "/api/me/")
      except Exception:
        pass
      probe.emit_vulnerable("PT-A02-07", "Login rate limiting not enforced", "MEDIUM",
                            "A07:2021", ["CWE-307"], ["endpoint=http://x/login"],
                            url="http://x/login", parameter="p", method="POST")
    probe.run_safe("family", family)
    f = [f for f in probe.findings if f.scenario_id == "PT-A02-07"][0]
    self.assertEqual((f.status, f.severity, f.cwe, f.url, f.parameter, f.confidence),
                     ("inconclusive", "INFO", [], None, None, ""))
    self.assertNotIn("not enforced", f.title.lower())


if __name__ == "__main__":
  unittest.main()
