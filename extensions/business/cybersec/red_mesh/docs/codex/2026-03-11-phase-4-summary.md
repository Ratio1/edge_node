# Phase 4 Summary

Date: 2026-03-11

## Goal

Make feature discovery, catalog output, and launch-time feature validation scan-type-aware, and ensure the UI preserves backend feature categories correctly.

## Issues Addressed

- `001-C3` `_get_all_features` only discovered network worker methods
- `001-L3` webapp `enabled_features` stored network probe names
- `003-4` feature catalog / capability mismatch
- `006` capability model inconsistency between workers, API, and UI

## What Was Done

### Backend

- Added explicit capability discovery on both worker classes:
  - [pentest_worker.py](/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/worker/pentest_worker.py)
    - `FEATURE_PREFIXES`
    - `get_feature_prefixes()`
    - `get_supported_features()`
  - [graybox/worker.py](/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/graybox/worker.py)
    - `get_feature_prefixes()`
    - `get_supported_features()`
- Refactored feature discovery in [pentester_api_01.py](/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/pentester_api_01.py):
  - added `_coerce_scan_type()`
  - added `_get_supported_features()`
  - extended `_get_all_features(..., scan_type=...)`
  - added `_get_feature_catalog(scan_type)`
  - added `_validate_feature_catalog()`
- Startup now validates `FEATURE_CATALOG` against executable worker capabilities and fails fast if a catalog item references missing methods.
- Updated endpoint behavior:
  - `list_features(scan_type="")`
  - `get_feature_catalog(scan_type="all")`
- Updated launch-time feature resolution so:
  - network launches validate against network/service/web/correlation features
  - webapp launches validate against graybox features only
- Verified that webapp `enabled_features` now persists graybox method keys instead of network probe names.

### Frontend

- Fixed backend category preservation in:
  - [config route](/home/vitalii/remote-dev/repos/RedMesh-Navigator/app/api/config/route.ts)
  - [features route](/home/vitalii/remote-dev/repos/RedMesh-Navigator/app/api/features/route.ts)
- Navigator now preserves `graybox` and `correlation` categories from the backend catalog instead of narrowing them incorrectly in route adapters.

## Acceptance Criteria Check

- Graybox jobs only validate against graybox features.
  - Verified by launch-path test coverage and persisted webapp config assertions.
- Network jobs only validate against network/correlation/web features.
  - Verified by capability discovery including `_post_scan_*` and excluding graybox methods.
- Feature catalog output is consistent with executable probes.
  - Verified by scan-type-filtered catalog tests and startup validation.
- Startup fails loudly if the catalog references missing methods.
  - Verified by explicit failure test for invalid catalog entries.

## Tests Run

Backend:

```bash
PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_api.py \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_normalization.py \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_jobconfig_webapp.py \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_worker.py
```

Result: `131 passed`

Frontend:

```bash
npm test -- --runInBand config-route.test.ts jobs-api.test.ts jobs-route.test.ts
```

Result: `3 suites passed, 11 tests passed`

## Resulting State

- Capability discovery is now derived from worker classes instead of a network-only helper.
- The backend catalog is filtered by scan type and validated against actual executable methods.
- Webapp launches no longer persist irrelevant network feature names.
- Navigator preserves graybox categories from the backend catalog, which keeps config/UI consumers aligned with backend semantics.

## Remaining Follow-Up

- The frontend fallback catalog in [features.ts](/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/domain/features.ts) is still incomplete for graybox; that belongs to the later UI/feature-selection phase.
- [env.ts](/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/config/env.ts) still logs raw environment/config data and remains a security issue for the hardening phase.
