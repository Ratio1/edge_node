# RedMesh Phase 2 Summary

Date: 2026-03-11
Phase: 2 - Reporting and Evidence Correctness

## Scope

This phase fixed the evidence-counting and archive-summary gaps that remained after graybox integration.

The focus was:
- correct finding counts in all backend consumers
- correct per-worker finding metadata in pass reports
- correct archive `UiAggregate` values for graybox scenario/discovery data
- consistent behavior across close, finalize, and archive-build paths

## What Was Done

### Shared counting logic

Added shared report helpers in `mixins/report.py`:
- `_count_nested_findings(section)`
- `_count_all_findings(report)`
- `_extract_graybox_ui_stats(aggregated, latest_pass=None)`
- `_dedupe_items(items)`

This removed duplicated counting logic and made graybox findings part of the same counting contract as:
- `service_info`
- `web_tests_info`
- `correlation_findings`
- `graybox_results`

### Close/finalize path fixes

Updated `pentester_api_01.py` to use `_count_all_findings()` in:
- `_close_job()` audit event generation
- `_maybe_finalize_pass()` worker metadata generation

This means:
- `scan_completed` audit events now count graybox findings
- `WorkerReportMeta.nr_findings` now includes graybox findings

### Archive aggregate fixes

Updated `_compute_ui_aggregate()` in `mixins/report.py` to accept `job_config` and populate graybox fields when `scan_type == "webapp"`:
- `scan_type`
- `total_routes_discovered`
- `total_forms_discovered`
- `total_scenarios`
- `total_scenarios_vulnerable`

Updated `_build_job_archive()` in `pentester_api_01.py` to pass `job_config` into `_compute_ui_aggregate()`.

Graybox summary values are derived from:
- discovery data stored under `_graybox_discovery`
- `graybox_results`
- pass `scan_metrics` when available

### Metrics aggregation improvement

Updated `_merge_worker_metrics()` in `mixins/live_progress.py` so graybox scenario counters are summed across workers/nodes:
- `scenarios_total`
- `scenarios_vulnerable`
- `scenarios_clean`
- `scenarios_inconclusive`
- `scenarios_error`

This keeps pass-level metrics more faithful for webapp scans.

## Issues Addressed

Resolved in this phase:
- `001-C1` `_close_job` audit finding count only walked `service_info`
- `001-H3` `_maybe_finalize_pass` worker metadata missed `graybox_results`
- `001-C2` `_compute_ui_aggregate` did not populate graybox fields
- `003-1` missing shared `_count_all_findings(report)` helper
- `003-2` pass metadata finding count drift
- `003-3` archived `UiAggregate` missing graybox scenario values

## Acceptance Criteria Check

### Audit events for webapp jobs include correct finding counts

Met.

Verified by:
- unit coverage for `_close_job()` audit count including graybox findings

### `WorkerReportMeta.nr_findings` is correct for webapp and network jobs

Met.

Verified by:
- pass-finalization test covering service + web + correlation + graybox findings in one node report

### Archived graybox jobs surface non-zero scenario statistics when appropriate

Met.

Verified by:
- archive build test asserting non-zero scenario/discovery values in `ui_aggregate`

### `UiAggregate.scan_type` is set for archived webapp jobs

Met.

Verified by:
- archive build test asserting `scan_type == "webapp"`

## Tests Added / Updated

Updated:
- `tests/test_api.py`
  - worker meta finding counts include graybox findings
  - UI aggregate includes graybox route/form/scenario values
  - archive UI aggregate includes graybox summary values
  - `_close_job` audit count includes graybox findings
- `tests/test_normalization.py`
  - `_count_all_findings()` walks all four finding sources

Also validated against existing suites:
- `tests/test_integration.py`
- `tests/test_jobconfig_webapp.py`
- `tests/test_worker.py`

## Verification Results

Command:

```bash
PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_api.py /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_integration.py /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_normalization.py /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_jobconfig_webapp.py /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_worker.py
```

Result:
- `146 passed`

## Result

After Phase 2:
- graybox findings are no longer undercounted in audit or pass metadata
- archive-level graybox summary values are precomputed correctly
- webapp evidence is represented more consistently across backend lifecycle stages
- the counting contract is centralized instead of duplicated in multiple paths

## Remaining Gaps Before Phase 3

Not addressed in this phase:
- launch API remains overloaded and scan-type branching is still concentrated in `launch_test()`
- feature discovery/validation is still not scan-type-aware
- webapp launch semantics still need separation from network distribution semantics

## Files Changed

- `extensions/business/cybersec/red_mesh/mixins/report.py`
- `extensions/business/cybersec/red_mesh/mixins/live_progress.py`
- `extensions/business/cybersec/red_mesh/pentester_api_01.py`
- `extensions/business/cybersec/red_mesh/tests/test_api.py`
- `extensions/business/cybersec/red_mesh/tests/test_normalization.py`
- `extensions/business/cybersec/red_mesh/docs/codex/2026-03-11-phase-2-summary.md`
