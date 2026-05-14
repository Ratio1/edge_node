from extensions.business.cybersec.red_mesh.tests.e2e.run_e2e import archive_passes
from extensions.business.cybersec.red_mesh.tests.e2e.api_top10_e2e import (
  assert_llm_boundary,
  llm_boundary_blob_from_archive,
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


def test_api_top10_target_confirmation_uses_host_only():
  assert target_confirmation_for_url("http://localhost:30001") == "localhost"
  assert target_confirmation_for_url("https://api.example.com/app") == "api.example.com"
  assert target_confirmation_for_url("api.internal") == "api.internal"


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
