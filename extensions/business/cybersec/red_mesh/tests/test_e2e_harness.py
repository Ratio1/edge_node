from extensions.business.cybersec.red_mesh.tests.e2e.run_e2e import archive_passes


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
