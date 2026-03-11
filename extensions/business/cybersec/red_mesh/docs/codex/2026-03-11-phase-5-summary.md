# Phase 5 Summary

Date: 2026-03-11

## Goal

Make probe execution failures visible without aborting the entire worker pipeline, and make graybox probe/weak-auth metrics first-class in worker status and reporting.

## Issues Addressed

- `004-WRK-C1` crashing probe paths could degrade or abort execution silently
- `004-API-H3` failed probes were not visible enough in stored metrics
- `004-WRK-H1` graybox probe metrics were sparse
- `004-WRK-H4` graybox scenario counts were not carried into `scan_metrics`
- part of worker feature-control parity for disabled graybox and correlation probes

## What Was Done

### Backend

- Updated [graybox/worker.py](/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/graybox/worker.py):
  - `get_status()` now merges scenario counters into `scan_metrics`
  - each graybox probe now records one of:
    - `completed`
    - `failed`
    - `skipped:disabled`
    - `skipped:stateful_disabled`
    - `skipped:missing_auth`
    - `skipped:missing_regular_session`
  - per-probe exclusions now suppress only the matching graybox probe
  - weak-auth execution now records `completed`, `failed`, or `skipped:disabled`
  - stored findings now also feed `finding_distribution` metrics
- Updated [pentest_worker.py](/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/worker/pentest_worker.py):
  - service probe dispatch now catches per-port probe exceptions and records failed probe state instead of aborting the worker
  - web probe dispatch now does the same
  - correlation now records `completed`, `failed`, or `skipped:disabled`
- Added/extended tests in:
  - [test_worker.py](/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_worker.py)
  - [test_probes.py](/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_probes.py)

## Acceptance Criteria Check

- A single failing probe does not kill the whole worker pipeline.
  - Verified by graybox probe-isolation tests and per-probe exception handling in network workers.
- Failed probes are visible in stored metrics/report breakdown.
  - Verified by `probe_breakdown`, `probes_failed`, and disabled/failed status assertions.
- Graybox passes produce meaningful scan metrics and scenario counts.
  - Verified by `scan_metrics.scenarios_*` assertions in worker status tests.
- Feature toggles reliably suppress disabled functionality.
  - Verified for per-probe graybox exclusions, disabled weak-auth, and disabled correlation reporting.

## Tests Run

Backend:

```bash
PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_worker.py \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_integration.py \
  /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_probes.py
```

Result: `308 passed`

Warnings:

- Existing TLS/date deprecation warnings in probe tests remain:
  - `datetime.utcnow()` usage in TLS-related code/tests

## Resulting State

- Operators can now distinguish failed probes from clean probe results in worker metrics.
- Graybox worker metrics now describe scenario outcomes, not just phase timing.
- Disabled graybox and correlation behavior is explicitly surfaced instead of disappearing silently.
- Network probe crashes are isolated at the probe-call level and no longer imply whole-worker failure.

## Remaining Follow-Up

- Active fingerprinting feature-control parity is still incomplete and should be covered in the later worker feature-control phase.
- Frontend rendering/export parity for the richer graybox data remains in the next phase.
