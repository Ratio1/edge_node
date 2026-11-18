import unittest
from unittest.mock import patch

from extensions.business.cybersec.red_mesh.tests.e2e.run_e2e import (
  archive_passes,
  assert_pass_coverage,
  fetch_archive,
  is_failed_job_status,
  is_terminal_job_status,
  job_status_values as generic_job_status_values,
  wait_for_finalize,
)
from extensions.business.cybersec.red_mesh.tests.e2e.api_top10_e2e import (
  assert_llm_boundary,
  gateway_request_headers,
  job_status_values,
  llm_boundary_blob_from_archive,
  target_config_with_bearer_auth,
  target_confirmation_for_url,
)


def test_archive_passes_prefers_current_archive_schema():
  archive = {
    "passes": [{"pass_nr": 2}],
    "pass_reports": [{"pass_nr": 1}],
  }

  assert archive_passes(archive) == [{"pass_nr": 2}]


def test_archive_passes_keeps_legacy_pass_reports_fallback():
  archive = {"pass_reports": [{"pass_nr": 1}]}

  assert archive_passes(archive) == [{"pass_nr": 1}]


def test_archive_passes_handles_invalid_archives():
  assert archive_passes(None) == []
  assert archive_passes({"passes": "bad", "pass_reports": "bad"}) == []


class GenericE2eHarnessStatusTests(unittest.TestCase):
  def test_job_status_values_reads_listing_and_status_shapes(self):
    listing = {
      "result": {
        "job-1": {"job_status": "FINALIZED"},
      },
    }
    status = {
      "result": {
        "status": "completed",
      },
    }

    self.assertEqual(generic_job_status_values(listing, "job-1"), ["FINALIZED"])
    self.assertEqual(generic_job_status_values(status, "job-1"), ["completed"])
    self.assertTrue(is_terminal_job_status(listing, "job-1"))
    self.assertTrue(is_terminal_job_status(status, "job-1"))
    self.assertTrue(is_failed_job_status({"result": {"job-1": {"job_status": "FAILED"}}}, "job-1"))

  def test_wait_for_finalize_survives_transient_poll_timeout(self):
    calls = []

    def fake_http_get(url, timeout=15):
      calls.append((url, timeout))
      if url.endswith("/list_network_jobs") and len(calls) == 1:
        raise TimeoutError("local LLM busy")
      if url.endswith("/list_network_jobs"):
        return {"result": {"job-1": {"job_status": "FINALIZED", "duration": 1}}}
      return {"result": {"status": "completed"}}

    with patch(
      "extensions.business.cybersec.red_mesh.tests.e2e.run_e2e.http_get",
      side_effect=fake_http_get,
    ), patch(
      "extensions.business.cybersec.red_mesh.tests.e2e.run_e2e.time.sleep",
      return_value=None,
    ):
      job = wait_for_finalize(
        "http://rm",
        "job-1",
        timeout=30,
        poll_every=0,
        request_timeout=7,
      )

    self.assertEqual(job["status"], "completed")
    self.assertEqual(job["_harness_poll_failures"], 1)
    self.assertIn(("http://rm/list_network_jobs", 7), calls)

  def test_wait_for_finalize_fails_promptly_on_failed_job_status(self):
    def fake_http_get(url, timeout=15):
      return {"result": {"job-1": {"job_status": "FAILED"}}}

    with patch(
      "extensions.business.cybersec.red_mesh.tests.e2e.run_e2e.http_get",
      side_effect=fake_http_get,
    ):
      with self.assertRaisesRegex(RuntimeError, "failed with status"):
        wait_for_finalize(
          "http://rm",
          "job-1",
          timeout=30,
          poll_every=0,
        )

  def test_fetch_archive_retries_until_passes_are_readable(self):
    responses = [
      TimeoutError("api busy"),
      {"result": {"archive": {"passes": [{"pass_nr": 1}]}}},
    ]

    def fake_http_get(url, timeout=30):
      item = responses.pop(0)
      if isinstance(item, Exception):
        raise item
      return item

    with patch(
      "extensions.business.cybersec.red_mesh.tests.e2e.run_e2e.http_get",
      side_effect=fake_http_get,
    ), patch(
      "extensions.business.cybersec.red_mesh.tests.e2e.run_e2e.time.sleep",
      return_value=None,
    ):
      archive = fetch_archive(
        "http://rm",
        "job-1",
        timeout=30,
        poll_every=0,
        request_timeout=9,
      )

    self.assertEqual(archive["passes"], [{"pass_nr": 1}])


def test_api_top10_target_confirmation_uses_host_only():
  assert target_confirmation_for_url("http://localhost:30001") == "localhost"
  assert target_confirmation_for_url("https://api.example.com/app") == "api.example.com"
  assert target_confirmation_for_url("api.internal") == "api.internal"


def test_api_top10_target_config_layers_bearer_auth_without_mutating_fixture():
  fixture = {
    "api_security": {
      "object_endpoints": [{"path": "/api/users/{id}/"}],
    },
  }

  configured = target_config_with_bearer_auth(fixture)

  assert fixture["api_security"].get("auth") is None
  assert configured["api_security"]["object_endpoints"] == [{"path": "/api/users/{id}/"}]
  assert configured["api_security"]["auth"] == {
    "auth_type": "bearer",
    "bearer_token_header_name": "Authorization",
    "bearer_scheme": "Bearer",
    "authenticated_probe_path": "/api/v2/me/",
  }
  assert "gateway_auth" not in configured["api_security"]


def test_api_top10_target_config_layers_gateway_auth_when_key_is_configured():
  fixture = {
    "api_security": {
      "object_endpoints": [{"path": "/api/users/{id}/"}],
    },
  }

  configured = target_config_with_bearer_auth(
    fixture,
    gateway_header="X-Gateway-Key",
    gateway_api_key="secret-not-persisted-in-config",
  )

  assert fixture["api_security"].get("gateway_auth") is None
  assert configured["api_security"]["gateway_auth"] == {
    "auth_type": "api_key",
    "api_key_location": "header",
    "api_key_header_name": "X-Gateway-Key",
  }
  assert "secret-not-persisted-in-config" not in str(configured)


def test_api_top10_gateway_request_headers_only_adds_secret_when_present():
  assert gateway_request_headers("X-Gateway-Key", "") == {}
  assert gateway_request_headers("X-Gateway-Key", "gateway-secret") == {
    "X-Gateway-Key": "gateway-secret",
  }


def test_api_top10_llm_boundary_blob_uses_archive_report_fields():
  archive = {
    "job_config": {
      "target_config": {"api_security": {"auth": {"bearer_token": "not included"}}},
    },
    "passes": [
      {
        "findings": [
          {"scenario_id": "PT-OAPI2-01", "evidence": "Authorization: Bearer [REDACTED]"},
        ],
        "llm_analysis": {"summary": "clean"},
        "quick_summary": "No raw tokens.",
        "llm_report_sections": {"api_top10": "Redacted API finding."},
      },
    ],
  }

  blob = llm_boundary_blob_from_archive(archive)

  assert "not included" not in blob
  assert assert_llm_boundary(blob) == []
  assert assert_llm_boundary(blob + " Authorization: Bearer eyJabc.def.ghi")


class ApiTop10StatusTests(unittest.TestCase):
  def test_job_status_values_prioritizes_nested_terminal_statuses(self):
    resp = {
      "status": "network_tracked",
      "job": {"job_status": "FINALIZED"},
    }

    self.assertEqual(
      job_status_values(resp, "job-1"),
      ["FINALIZED", "network_tracked"],
    )

  def test_job_status_values_reads_job_keyed_responses(self):
    resp = {
      "RM-1": {"job_id": "job-1", "status": "completed"},
      "status": "network_tracked",
    }

    self.assertEqual(
      job_status_values(resp, "job-1"),
      ["completed", "network_tracked"],
    )


def _coverage_archive(**overrides):
  pass_report = {
    "worker_reports": {
      "node-A": {"ports_scanned": 20, "open_ports": [22, 25]},
      "node-B": {"ports_scanned": 10, "open_ports": [80]},
    },
    "worker_scan_metrics": {
      "node-A": {"threads": {"t0": {"ports_scanned": 10, "open_ports": [22]},
                             "t1": {"ports_scanned": 10, "open_ports": [25]}}},
      "node-B": {"threads": {"t0": {"ports_scanned": 10, "open_ports": [80]}}},
    },
  }
  archive = {"passes": [pass_report], "ui_aggregate": {"total_open_ports": [22, 25, 80]}}
  for path, value in overrides.items():
    target = archive
    *parents, leaf = path.split("/")
    for key in parents:
      target = target[int(key)] if isinstance(target, list) else target[key]
    target[leaf] = value
  return archive


def test_pass_coverage_passes_on_consistent_archive():
  assert assert_pass_coverage(_coverage_archive()) == []


def test_pass_coverage_flags_node_ports_scanned_below_thread_sum():
  failures = assert_pass_coverage(_coverage_archive(**{"passes/0/worker_reports/node-A/ports_scanned": 10}))
  assert len(failures) == 1 and "node-A: ports_scanned 10 != thread sum 20" in failures[0]


def test_pass_coverage_flags_node_open_ports_missing_a_thread():
  failures = assert_pass_coverage(_coverage_archive(
    **{"passes/0/worker_reports/node-A/open_ports": [22], "ui_aggregate/total_open_ports": [22, 80]}))
  assert any("node-A: open_ports [22] != thread union [22, 25]" in f for f in failures)


def test_pass_coverage_flags_ui_aggregate_missing_a_node():
  failures = assert_pass_coverage(_coverage_archive(**{"ui_aggregate/total_open_ports": [22, 25]}))
  assert len(failures) == 1 and "ui_aggregate.total_open_ports" in failures[0]


def test_pass_coverage_accepts_graybox_list_ports_scanned():
  archive = _coverage_archive(**{
    "passes/0/worker_reports/node-B/ports_scanned": [80],
    "passes/0/worker_scan_metrics/node-B/threads/t0/ports_scanned": [80],
  })
  assert assert_pass_coverage(archive) == []


def test_stopped_job_counts_as_failed():
  assert is_failed_job_status({"result": {"job_status": "STOPPED"}}, "job-1") is True
