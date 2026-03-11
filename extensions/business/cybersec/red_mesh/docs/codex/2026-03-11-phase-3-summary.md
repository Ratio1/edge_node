# Phase 3 Summary

Date: 2026-03-11

## Goal

Split the mixed `launch_test()` flow into scan-type-specific launch paths, harden validation, and update Navigator to call the explicit backend endpoints while keeping backward compatibility.

## Issues Addressed

- `002` endpoint split analysis
- `001-C4` webapp config inherited bogus default `exceptions`
- `001-H1` webapp launch produced network-style sliced worker assignments
- `001-M2` mixed launch flow was network-centric and hard to reason about
- `001-M3` webapp launch semantics were mixed with irrelevant network fields
- `001-L2` validation behavior was inconsistent
- design debt called out in `006`

## What Was Done

### Backend

- Added scan-type-specific endpoints in [pentester_api_01.py](/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/pentester_api_01.py):
  - `launch_network_scan()`
  - `launch_webapp_scan()`
- Converted `launch_test()` into a compatibility router shim that dispatches by `scan_type`.
- Extracted shared launch helpers for:
  - structured validation payloads
  - exception parsing
  - peer resolution
  - common option normalization
  - network worker assignment
  - webapp worker assignment
  - final immutable config + CStore announcement
- Changed webapp launch behavior to:
  - require `target_url`
  - require official credentials
  - validate only `http`/`https` URLs
  - assign the same resolved target port to every selected peer
  - force deterministic mirror semantics
  - persist `exceptions=[]`
  - persist `nr_local_workers=1`
- Standardized endpoint-level validation failures to a structured payload:
  - `{"error": "validation_error", "message": "..."}`

### Frontend

- Added explicit API client methods in [redmeshApi.ts](/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/services/redmeshApi.ts):
  - `launchNetworkScan()`
  - `launchWebappScan()`
- Split request construction in [jobs.ts](/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/api/jobs.ts):
  - `createJobInputToNetworkLaunchRequest()`
  - `createJobInputToWebappLaunchRequest()`
- Updated `createJob()` to choose the backend endpoint by `scanType`.
- Preserved compatibility by leaving `launchTest()` available in the API client.

## Acceptance Criteria Check

- Webapp launches no longer persist bogus default `exceptions`.
  - Verified by backend test coverage.
- Webapp launches no longer produce degenerate sliced worker entries.
  - Verified by backend test coverage.
- Validation errors are structurally consistent.
  - Verified for missing authorization, invalid scan type, missing `target_url`, and invalid URL scheme.
- Network and webapp launch logic can be reasoned about independently.
  - Implemented via separate endpoint entry points and separate frontend request builders.

## Tests Run

Backend:

```bash
PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_api.py \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_normalization.py \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_jobconfig_webapp.py
```

Result: `91 passed`

Frontend:

```bash
npm test -- --runInBand jobs-api.test.ts jobs-route.test.ts
```

Result: `2 suites passed, 8 tests passed`

## Resulting State

- Backend launch semantics are now explicit by scan type.
- Navigator no longer sends graybox launches through the mixed legacy path.
- Existing callers can still use `launch_test()` during migration.
- The launch surface is materially easier to extend with scan-type-specific rules in later phases.

## Remaining Follow-Up

- Navigator still logs raw environment/config data during tests and runtime boot in [env.ts](/home/vitalii/remote-dev/repos/RedMesh-Navigator/lib/config/env.ts). That remains a security issue for the later hardening phase.
- Feature capability modeling is still network-centric in backend internals; that belongs to the next structural phase.
