"""Runtime scenario manifest for graybox API scheduling."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeScenario:
  scenario_id: str
  probe_key: str
  runner: str
  stateful: bool = False
  mutating: bool = False
  requires_regular: bool = False
  estimated_budget: int = 1
  single_writer_group: str = ""

  def to_dict(self) -> dict:
    return {
      "scenario_id": self.scenario_id,
      "probe_key": self.probe_key,
      "runner": self.runner,
      "stateful": self.stateful,
      "mutating": self.mutating,
      "requires_regular": self.requires_regular,
      "estimated_budget": self.estimated_budget,
      "single_writer_group": self.single_writer_group,
    }


API_RUNTIME_SCENARIOS = (
  RuntimeScenario(
    "PT-OAPI1-01", "_graybox_api_access", "_test_api_bola",
    requires_regular=True, estimated_budget=4,
  ),
  RuntimeScenario(
    "PT-OAPI2-01", "_graybox_api_auth", "_test_jwt_alg_none",
    estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI2-02", "_graybox_api_auth", "_test_jwt_weak_hmac",
    estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI2-03", "_graybox_api_auth",
    "_test_token_logout_invalidation",
    stateful=True, mutating=True, estimated_budget=3,
    single_writer_group="api_auth_token",
  ),
  RuntimeScenario(
    "PT-OAPI3-01", "_graybox_api_data",
    "_test_api_property_exposure",
    estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI3-02", "_graybox_api_data",
    "_test_api_property_tampering",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=3, single_writer_group="api_data_property",
  ),
  RuntimeScenario(
    "PT-OAPI4-01", "_graybox_api_abuse",
    "_test_no_pagination_cap", estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI4-02", "_graybox_api_abuse",
    "_test_oversized_payload", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI4-03", "_graybox_api_abuse",
    "_test_no_rate_limit", estimated_budget=5,
  ),
  RuntimeScenario(
    "PT-OAPI5-01", "_graybox_api_access",
    "_test_bfla_regular_as_admin",
    requires_regular=True, estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI5-02", "_graybox_api_access",
    "_test_bfla_anon_as_user", estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-OAPI5-03", "_graybox_api_access",
    "_test_bfla_method_override",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=3, single_writer_group="api_access_function",
  ),
  RuntimeScenario(
    "PT-OAPI5-04", "_graybox_api_access",
    "_test_bfla_regular_as_admin_mutating",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=3, single_writer_group="api_access_function",
  ),
  RuntimeScenario(
    "PT-OAPI6-01", "_graybox_api_abuse",
    "_test_flow_no_rate_limit",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=5, single_writer_group="api_abuse_flow",
  ),
  RuntimeScenario(
    "PT-OAPI6-02", "_graybox_api_abuse",
    "_test_flow_no_uniqueness",
    stateful=True, mutating=True, requires_regular=True,
    estimated_budget=2, single_writer_group="api_abuse_flow",
  ),
  RuntimeScenario(
    "PT-OAPI8-01", "_graybox_api_config",
    "_test_cors_misconfig", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI8-02", "_graybox_api_config",
    "_test_security_headers", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI8-03", "_graybox_api_config",
    "_test_debug_endpoint_exposed", estimated_budget=3,
  ),
  RuntimeScenario(
    "PT-OAPI8-04", "_graybox_api_config",
    "_test_verbose_error", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI8-05", "_graybox_api_config",
    "_test_unexpected_methods", estimated_budget=1,
  ),
  RuntimeScenario(
    "PT-OAPI9-01", "_graybox_api_config",
    "_test_openapi_exposed", estimated_budget=3,
  ),
  RuntimeScenario(
    "PT-OAPI9-02", "_graybox_api_config",
    "_test_version_sprawl", estimated_budget=3,
  ),
  RuntimeScenario(
    "PT-OAPI9-03", "_graybox_api_config",
    "_test_deprecated_live", estimated_budget=2,
  ),
  RuntimeScenario(
    "PT-API7-01", "_graybox_injection", "_test_ssrf",
    estimated_budget=2,
  ),
)


def runtime_scenarios() -> tuple[RuntimeScenario, ...]:
  return API_RUNTIME_SCENARIOS


def runtime_scenario_ids() -> tuple[str, ...]:
  return tuple(item.scenario_id for item in API_RUNTIME_SCENARIOS)


def runtime_scenarios_for_probe(probe_key: str) -> tuple[RuntimeScenario, ...]:
  return tuple(item for item in API_RUNTIME_SCENARIOS if item.probe_key == probe_key)


def runtime_scenario_by_id(scenario_id: str) -> RuntimeScenario | None:
  for item in API_RUNTIME_SCENARIOS:
    if item.scenario_id == scenario_id:
      return item
  return None
