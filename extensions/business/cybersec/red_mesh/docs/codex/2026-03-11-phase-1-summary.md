# RedMesh Phase 1 Summary

Date: 2026-03-11
Phase: 1 - Contract Correctness and Graybox Identity Propagation

## Scope

This phase fixed the current cross-layer contract issues that caused graybox jobs to lose identity or expose the wrong identity across:
- backend running job listings
- backend finalized stubs
- backend progress payloads
- Navigator job normalization

## What Was Done

### Backend

Updated `pentester_api_01.py` to:
- persist `target_url` in `job_specs` at launch time
- return `job_status` from `get_job_progress()`
- include `scan_type` and `target_url` in running-job payloads returned by `list_network_jobs()`
- preserve `scan_type` and `target_url` when pruning a finalized job to `CStoreJobFinalized`

Updated `models/cstore.py` to:
- extend `CStoreJobFinalized` with:
  - `scan_type`
  - `target_url`

### Frontend

Updated `RedMesh-Navigator/lib/api/jobs.ts` to:
- export `normalizeJobFromSpecs()` for focused regression testing
- map `targetUrl` from `specs.target_url` instead of `specs.target`

Updated `RedMesh-Navigator/lib/services/redmeshApi.types.ts` to:
- add `target_url` to `JobSpecs`

## Issues Addressed

Resolved in this phase:
- `001-M1` `get_job_progress` returned the wrong status field
- `001-H2` running job listing omitted `scan_type`
- `001-L1` finalized stub lacked `scan_type` and `target_url`
- `003-5` running listing payload missing graybox identity
- `003-6` finalized payload missing graybox identity
- `004-FE-C1` Navigator mapped graybox `targetUrl` from `target` instead of `target_url`

## Tests Added / Updated

Backend:
- `tests/test_api.py`
  - finalized stub now asserts `scan_type` and `target_url`
  - running listing now asserts `scan_type` and `target_url`
  - progress endpoint now asserts returned status comes from `job_status`
- `tests/test_integration.py`
  - progress integration asserts `status`
  - listing integration asserts `scan_type` and `target_url` on running and finalized jobs

Frontend:
- `__tests__/jobs-api.test.ts`
  - added direct normalization coverage for running and finalized graybox jobs
- `__tests__/jobs-route.test.ts`
  - adjusted existing route test harness so targeted route tests run reliably in Jest

## Verification Results

Backend:
```bash
PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_api.py /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_integration.py
```

Result:
- `77 passed`

Frontend:
```bash
npm test -- --runInBand jobs-api.test.ts jobs-route.test.ts
```

Result:
- `2 test suites passed`
- `6 tests passed`

## Result

After Phase 1:
- running webapp jobs are self-describing in list responses
- finalized webapp jobs preserve scan identity in CStore stubs
- Navigator shows the correct graybox target URL instead of the host fallback
- progress responses expose a real job lifecycle status value

## Remaining Gaps Before Phase 2

Not addressed in this phase:
- graybox finding counts are still underreported in audit/finalization paths
- archived `UiAggregate` still does not fully populate graybox-specific scenario metrics
- evidence/report aggregation still needs the Phase 2 shared counting helper

## Files Changed

Backend:
- `extensions/business/cybersec/red_mesh/pentester_api_01.py`
- `extensions/business/cybersec/red_mesh/models/cstore.py`
- `extensions/business/cybersec/red_mesh/tests/test_api.py`
- `extensions/business/cybersec/red_mesh/tests/test_integration.py`

Frontend:
- `RedMesh-Navigator/lib/api/jobs.ts`
- `RedMesh-Navigator/lib/services/redmeshApi.types.ts`
- `RedMesh-Navigator/__tests__/jobs-api.test.ts`
- `RedMesh-Navigator/__tests__/jobs-route.test.ts`
