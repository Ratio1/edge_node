"""Runtime scenario manifest and assignment-gate tests."""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.constants import (
  GRAYBOX_PROBE_REGISTRY,
)
from extensions.business.cybersec.red_mesh.graybox.models import (
  DiscoveryResult,
)
from extensions.business.cybersec.red_mesh.graybox.models.target_config import (
  ApiSecurityConfig,
  ApiTokenEndpoint,
  AuthDescriptor,
  GrayboxTargetConfig,
)
from extensions.business.cybersec.red_mesh.graybox.probes.api_auth import (
  ApiAuthProbes,
  _forge_jwt,
)
from extensions.business.cybersec.red_mesh.graybox.scenario_catalog import (
  GRAYBOX_SCENARIO_CATALOG,
)
from extensions.business.cybersec.red_mesh.graybox.scenario_runtime import (
  GRAYBOX_ASSIGNMENT_MIRROR,
  GRAYBOX_ASSIGNMENT_SLICE,
  GRAYBOX_BUDGET_PER_SCAN,
  GRAYBOX_BUDGET_PER_WORKER,
  GrayboxWorkerAssignment,
  build_graybox_worker_assignments,
  compute_assignment_hash,
  rehash_worker_assignment_dict,
  runtime_scenario_ids,
  runtime_scenarios,
  summarize_graybox_worker_assignments,
  synthesize_legacy_mirror_assignment,
)
from extensions.business.cybersec.red_mesh.graybox.worker import (
  GrayboxLocalWorker,
)


EXPECTED_RUNTIME_IDS = (
  "PT-OAPI1-01",
  "PT-OAPI2-01",
  "PT-OAPI2-02",
  "PT-OAPI2-03",
  "PT-OAPI3-01",
  "PT-OAPI3-02",
  "PT-OAPI4-01",
  "PT-OAPI4-02",
  "PT-OAPI4-03",
  "PT-OAPI5-01",
  "PT-OAPI5-02",
  "PT-OAPI5-03",
  "PT-OAPI5-04",
  "PT-OAPI6-01",
  "PT-OAPI6-02",
  "PT-OAPI8-01",
  "PT-OAPI8-02",
  "PT-OAPI8-03",
  "PT-OAPI8-04",
  "PT-OAPI8-05",
  "PT-OAPI9-01",
  "PT-OAPI9-02",
  "PT-OAPI9-03",
  "PT-API7-01",
)


def _hs256_jwt(payload: dict, secret: str) -> str:
  return _forge_jwt({"alg": "HS256", "typ": "JWT"}, payload, secret=secret)


def _resp(status=200, json_body=None):
  r = MagicMock()
  r.status_code = status
  r.headers = {}
  if json_body is not None:
    r.json.return_value = json_body
  else:
    r.json.side_effect = ValueError("not json")
  r.text = ""
  return r


def _make_api_auth_probe(*, allowed_scenario_ids=None, unverified_api_auth=False):
  auth_descriptor = AuthDescriptor()
  if unverified_api_auth:
    auth_descriptor = AuthDescriptor(
      auth_type="bearer",
      allow_unverified_auth=True,
    )
  cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(
    auth=auth_descriptor,
    token_endpoints=ApiTokenEndpoint(
      token_path="/api/token/",
      protected_path="/api/me/",
      logout_path="/api/logout/",
      weak_secret_candidates=["changeme"],
    ),
  ))
  auth = MagicMock()
  auth.official_session = MagicMock()
  auth.regular_session = MagicMock()
  auth.verify_tls = True
  auth.make_anonymous_session = MagicMock(return_value=MagicMock())
  safety = MagicMock()
  safety.throttle = MagicMock()
  safety.sanitize_error = MagicMock(side_effect=lambda s: s)
  return ApiAuthProbes(
    target_url="http://api.example",
    auth_manager=auth,
    target_config=cfg,
    safety=safety,
    allow_stateful=True,
    allowed_scenario_ids=allowed_scenario_ids,
  )


def _make_worker(*, assigned_scenario_ids=None):
  owner = MagicMock()
  cfg = MagicMock()
  cfg.scan_type = "webapp"
  cfg.target_url = "http://testapp.local:8000"
  cfg.target_config = None
  cfg.verify_tls = True
  cfg.scan_min_delay = 0
  cfg.allow_stateful_probes = False
  cfg.app_routes = []
  cfg.excluded_features = []
  cfg.weak_candidates = []
  cfg.max_weak_attempts = 5
  cfg.official_username = "admin"
  cfg.official_password = "secret"
  cfg.regular_username = ""
  cfg.regular_password = ""
  cfg.bearer_token = ""
  cfg.bearer_refresh_token = ""
  cfg.api_key = ""
  cfg.regular_bearer_token = ""
  cfg.regular_bearer_refresh_token = ""
  cfg.regular_api_key = ""
  assignments, error = build_graybox_worker_assignments(["node-1"])
  if error is None:
    for key, value in assignments["node-1"].items():
      setattr(cfg, key, value)
  if assigned_scenario_ids is not None:
    cfg.assigned_scenario_ids = list(assigned_scenario_ids)
    cfg.assignment_hash = compute_assignment_hash(
      strategy=cfg.graybox_assignment_strategy,
      assigned_scenario_ids=cfg.assigned_scenario_ids,
      assigned_request_budget=cfg.assigned_request_budget,
      budget_scope=cfg.budget_scope,
      assignment_revision=cfg.assignment_revision,
      stateful_policy=cfg.stateful_policy,
    )

  with patch("extensions.business.cybersec.red_mesh.graybox.worker.SafetyControls"):
    with patch("extensions.business.cybersec.red_mesh.graybox.worker.AuthManager"):
      with patch("extensions.business.cybersec.red_mesh.graybox.worker.DiscoveryModule"):
        return GrayboxLocalWorker(
          owner=owner,
          job_id="job-1",
          target_url=cfg.target_url,
          job_config=cfg,
          local_id="1",
          initiator="launcher",
        )


class TestRuntimeScenarioManifest(unittest.TestCase):

  def test_manifest_order_is_stable(self):
    self.assertEqual(runtime_scenario_ids(), EXPECTED_RUNTIME_IDS)

  def test_manifest_covers_api_catalog_entries(self):
    catalog_ids = {
      entry["id"]
      for entry in GRAYBOX_SCENARIO_CATALOG
      if entry["id"].startswith("PT-OAPI") or entry["id"] == "PT-API7-01"
    }
    self.assertEqual(set(runtime_scenario_ids()), catalog_ids)

  def test_manifest_entries_are_unique_and_runnable(self):
    ids = runtime_scenario_ids()
    self.assertEqual(len(ids), len(set(ids)))

    registry = {entry["key"]: entry["cls"] for entry in GRAYBOX_PROBE_REGISTRY}
    for scenario in runtime_scenarios():
      self.assertGreater(scenario.estimated_budget, 0)
      self.assertIn(scenario.probe_key, registry)
      cls = GrayboxLocalWorker._import_probe(registry[scenario.probe_key])
      self.assertTrue(
        hasattr(cls, scenario.runner),
        f"{scenario.scenario_id} runner missing: {scenario.runner}",
      )


class TestGrayboxWorkerAssignments(unittest.TestCase):

  def test_slice_assignments_are_disjoint_and_budgeted_per_scan(self):
    assignments, error = build_graybox_worker_assignments(
      ["node-a", "node-b", "node-c"],
      strategy=GRAYBOX_ASSIGNMENT_SLICE,
      total_request_budget=30,
    )

    self.assertIsNone(error)
    assigned_sets = [
      set(assignments[node]["assigned_scenario_ids"])
      for node in ("node-a", "node-b", "node-c")
    ]
    for left_index, left in enumerate(assigned_sets):
      for right in assigned_sets[left_index + 1:]:
        self.assertFalse(left & right)
    union = set().union(*assigned_sets)
    self.assertEqual(union, set(runtime_scenario_ids()))
    self.assertEqual(
      {assignments[node]["budget_scope"] for node in assignments},
      {GRAYBOX_BUDGET_PER_SCAN},
    )
    self.assertEqual(
      sum(assignments[node]["assigned_request_budget"] for node in assignments),
      30,
    )

  def test_mirror_multi_worker_default_divides_budget(self):
    """B5: multi-worker MIRROR without opt-in divides the per-scan budget."""
    assignments, error = build_graybox_worker_assignments(
      ["node-a", "node-b", "node-c"],
      strategy=GRAYBOX_ASSIGNMENT_MIRROR,
      total_request_budget=30,
    )

    self.assertIsNone(error)
    expected = list(runtime_scenario_ids())
    for assignment in assignments.values():
      self.assertEqual(assignment["assigned_scenario_ids"], expected)
      self.assertEqual(assignment["budget_scope"], GRAYBOX_BUDGET_PER_SCAN)
    self.assertEqual(
      sum(a["assigned_request_budget"] for a in assignments.values()),
      30,
    )

  def test_mirror_multi_worker_per_worker_budget_with_explicit_opt_in(self):
    assignments, error = build_graybox_worker_assignments(
      ["node-a", "node-b", "node-c"],
      strategy=GRAYBOX_ASSIGNMENT_MIRROR,
      total_request_budget=30,
      allow_mirror_per_worker_budget=True,
    )

    self.assertIsNone(error)
    for assignment in assignments.values():
      self.assertEqual(assignment["assigned_request_budget"], 30)
      self.assertEqual(assignment["budget_scope"], GRAYBOX_BUDGET_PER_WORKER)

  def test_mirror_single_worker_keeps_per_worker_budget(self):
    """Single-worker MIRROR is meaningfully per-worker (no traffic multiplier)."""
    assignments, error = build_graybox_worker_assignments(
      ["node-a"],
      strategy=GRAYBOX_ASSIGNMENT_MIRROR,
      total_request_budget=30,
    )

    self.assertIsNone(error)
    a = assignments["node-a"]
    self.assertEqual(a["assigned_request_budget"], 30)
    self.assertEqual(a["budget_scope"], GRAYBOX_BUDGET_PER_WORKER)

  def test_mirror_stateful_multi_worker_requires_override(self):
    assignments, error = build_graybox_worker_assignments(
      ["node-a", "node-b"],
      strategy=GRAYBOX_ASSIGNMENT_MIRROR,
      allow_stateful=True,
    )

    self.assertIsNone(assignments)
    self.assertIn("MIRROR with stateful", error)

  def test_synthesize_legacy_mirror_for_assignmentless_worker(self):
    """B7: assignmentless worker entries get a synthesized MIRROR assignment."""
    worker_entry = {
      "start_port": 443,
      "end_port": 443,
      "finished": False,
    }
    job_config = {"target_config": {"api_security": {"max_total_requests": 25}}}
    compat = synthesize_legacy_mirror_assignment(job_config, worker_entry)
    self.assertIsNotNone(compat)
    self.assertEqual(compat["graybox_assignment_strategy"], GRAYBOX_ASSIGNMENT_MIRROR)
    self.assertEqual(compat["assigned_request_budget"], 25)
    self.assertEqual(compat["budget_scope"], GRAYBOX_BUDGET_PER_WORKER)
    self.assertEqual(compat["assignment_compat_mode"], "legacy_mirror")
    self.assertTrue(compat["assignment_hash"])

  def test_synthesize_legacy_mirror_refuses_partial_assignment(self):
    """A single new assignment field present must NOT trigger legacy compat."""
    worker_entry = {
      "start_port": 443,
      "end_port": 443,
      "graybox_assignment_strategy": "MIRROR",  # only one of the fields
    }
    self.assertIsNone(
      synthesize_legacy_mirror_assignment({}, worker_entry),
    )

  def test_synthesize_legacy_mirror_falls_back_to_default_budget(self):
    """No max_total_requests configured -> use the default budget."""
    compat = synthesize_legacy_mirror_assignment({}, {"start_port": 443, "end_port": 443})
    self.assertIsNotNone(compat)
    self.assertGreater(compat["assigned_request_budget"], 0)

  def test_rehash_after_revision_bump_yields_valid_assignment(self):
    """B6: bumping assignment_revision must also recompute assignment_hash."""
    assignments, error = build_graybox_worker_assignments(
      ["node-a"],
      strategy=GRAYBOX_ASSIGNMENT_MIRROR,
      total_request_budget=20,
    )
    self.assertIsNone(error)
    entry = dict(assignments["node-a"])
    original_hash = entry["assignment_hash"]
    self.assertTrue(original_hash)

    entry["assignment_revision"] += 1
    rehash_worker_assignment_dict(entry)
    self.assertNotEqual(entry["assignment_hash"], original_hash)

    # GrayboxWorkerAssignment.from_job_config validates by recomputing the
    # hash from the same payload — the rehashed entry must round-trip.
    from types import SimpleNamespace
    job_config = SimpleNamespace(scan_type="webapp", **entry)
    assignment = GrayboxWorkerAssignment.from_job_config(job_config)
    self.assertTrue(assignment.is_valid, assignment.validation_error)

  def test_summary_aggregates_consistent_worker_assignments(self):
    """B5: job-level summary surfaces strategy/budget/scope/scenarios for the dashboard."""
    assignments, error = build_graybox_worker_assignments(
      ["node-a", "node-b"],
      strategy=GRAYBOX_ASSIGNMENT_SLICE,
      total_request_budget=30,
    )
    self.assertIsNone(error)
    summary = summarize_graybox_worker_assignments(assignments)
    self.assertEqual(summary["graybox_assignment_strategy"], GRAYBOX_ASSIGNMENT_SLICE)
    self.assertEqual(summary["budget_scope"], GRAYBOX_BUDGET_PER_SCAN)
    self.assertEqual(summary["assigned_request_budget"], 30)
    self.assertEqual(summary["total_assigned_scenarios"], len(runtime_scenario_ids()))
    self.assertEqual(len(summary["worker_assignment_summary"]), 2)

  def test_summary_marks_mixed_when_workers_disagree(self):
    """Manual edits could break the launcher contract; summary records 'mixed' for visibility."""
    assignments = {
      "node-a": {
        "graybox_assignment_strategy": "SLICE",
        "assigned_request_budget": 15,
        "budget_scope": "per_scan",
        "assigned_scenario_ids": ["PT-OAPI1-01"],
      },
      "node-b": {
        "graybox_assignment_strategy": "MIRROR",
        "assigned_request_budget": 15,
        "budget_scope": "per_worker",
        "assigned_scenario_ids": ["PT-OAPI1-02"],
      },
    }
    summary = summarize_graybox_worker_assignments(assignments)
    self.assertEqual(summary["graybox_assignment_strategy"], "mixed")
    self.assertEqual(summary["budget_scope"], "mixed")

  def test_invalid_request_budget_fails_assignment(self):
    assignments, error = build_graybox_worker_assignments(
      ["node-a"],
      strategy=GRAYBOX_ASSIGNMENT_MIRROR,
      total_request_budget="abc",
    )
    self.assertIsNone(assignments)
    self.assertIn("positive integer", error)

    assignments, error = build_graybox_worker_assignments(
      ["node-a"],
      strategy=GRAYBOX_ASSIGNMENT_MIRROR,
      total_request_budget=0,
    )
    self.assertIsNone(assignments)
    self.assertIn("positive integer", error)


class TestScenarioAssignmentGates(unittest.TestCase):

  def test_unassigned_api_auth_scenarios_make_zero_http_calls(self):
    probe = _make_api_auth_probe(allowed_scenario_ids=("PT-OAPI2-02",))
    token = _hs256_jwt({"sub": "alice"}, "changeme")
    probe.auth.official_session.post.return_value = _resp(
      json_body={"token": token},
    )

    probe.run()

    self.assertEqual({f.scenario_id for f in probe.findings}, {"PT-OAPI2-02"})
    probe.auth.make_anonymous_session.assert_not_called()

  def test_unverified_api_auth_emits_inconclusive_without_http_calls(self):
    probe = _make_api_auth_probe(
      allowed_scenario_ids=("PT-OAPI2-01",),
      unverified_api_auth=True,
    )

    probe.run()

    self.assertEqual(len(probe.findings), 1)
    finding = probe.findings[0]
    self.assertEqual(finding.scenario_id, "PT-OAPI2-01")
    self.assertEqual(finding.status, "inconclusive")
    self.assertIn("reason=auth_unverified", finding.evidence)
    probe.auth.official_session.post.assert_not_called()
    probe.auth.make_anonymous_session.assert_not_called()

  def test_worker_context_carries_launcher_assignment(self):
    worker = _make_worker(assigned_scenario_ids=["PT-OAPI2-02"])
    context = worker._build_probe_kwargs(DiscoveryResult())

    self.assertEqual(context.allowed_scenario_ids, ("PT-OAPI2-02",))

  def test_invalid_assignment_aborts_before_target_preflight(self):
    worker = _make_worker()
    worker.assignment = GrayboxWorkerAssignment.invalid(
      "missing_assigned_scenario_ids",
    )
    worker.safety.validate_target.return_value = None
    worker.auth.preflight_check.return_value = None

    worker.execute_job()

    self.assertTrue(worker.state["aborted"])
    self.assertEqual(worker.state["abort_phase"], "preflight")
    self.assertIn("missing_assigned_scenario_ids", worker.state["abort_reason"])
    worker.safety.validate_target.assert_not_called()
    worker.auth.preflight_check.assert_not_called()


if __name__ == "__main__":
  unittest.main()
