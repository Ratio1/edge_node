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
  runtime_scenario_ids,
  runtime_scenarios,
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


def _make_api_auth_probe(*, allowed_scenario_ids=None):
  cfg = GrayboxTargetConfig(api_security=ApiSecurityConfig(
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
  cfg.assigned_scenario_ids = assigned_scenario_ids

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

  def test_worker_context_carries_launcher_assignment(self):
    worker = _make_worker(assigned_scenario_ids=["PT-OAPI2-02"])
    context = worker._build_probe_kwargs(DiscoveryResult())

    self.assertEqual(context.allowed_scenario_ids, ("PT-OAPI2-02",))


if __name__ == "__main__":
  unittest.main()
