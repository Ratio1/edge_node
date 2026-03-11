# Phase 8 Summary

Date: 2026-03-11
Phase: 8
Title: Architectural Reduction of Future Coupling

## Scope

Phase 8 focused on RedMesh backend architecture. Navigator code was not changed in this phase.

Primary goals:
- reduce responsibility concentration inside `pentester_api_01.py`
- move scan-type dispatch policy out of the API plugin into a dedicated strategy layer
- make job-state transitions explicit and validated
- add regression coverage around the extracted architectural seams

## What Was Changed

### 1. Extracted scan strategy metadata

Added:
- `/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/services/scan_strategy.py`
- `/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/services/__init__.py`

This new strategy layer now owns:
- scan-type coercion
- scan-type -> worker-class mapping
- scan-type -> feature-catalog categories mapping

Effect:
- `pentester_api_01.py` no longer owns the worker-dispatch table directly
- feature discovery and catalog validation are now driven by the extracted strategy model

### 2. Extracted local launch orchestration

Added:
- `/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/services/launch.py`

This service now owns:
- network local-worker batching and launch behavior
- webapp single-worker launch behavior
- scan-type-specific local dispatch selection

Updated `/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/pentester_api_01.py`:
- `_maybe_launch_jobs()` now delegates to `launch_local_jobs()`
- `_launch_job()` is retained only as a compatibility wrapper around the extracted service

Effect:
- launch/runtime dispatch policy is no longer embedded directly inside the main plugin loop

### 3. Introduced explicit job-state transition rules

Added:
- `/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/services/state_machine.py`

This module defines:
- allowed transitions between:
  - `RUNNING`
  - `COLLECTING`
  - `ANALYZING`
  - `FINALIZING`
  - `SCHEDULED_FOR_STOP`
  - `STOPPED`
  - `FINALIZED`
- helpers for:
  - transition validation
  - terminal-state checks
  - intermediate-state checks

Updated `/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/pentester_api_01.py`:
- pass finalization now uses `set_job_status()` instead of direct raw assignment
- stop paths now use the explicit transition helper
- terminal/intermediate skip logic now uses the extracted status helpers

### 4. Continuous-monitoring lifecycle correction

While implementing the explicit transition map, one real lifecycle bug was corrected:

- continuous-monitoring jobs previously advanced through `COLLECTING -> ANALYZING -> FINALIZING`, then scheduled the next pass without returning to `RUNNING`
- Phase 8 now transitions them back to `RUNNING` after pass finalization when the job is continuing

This improves:
- lifecycle clarity
- progress/reporting correctness
- future state-based reasoning in both API and UI layers

### 5. Regression coverage for extracted architecture

Added:
- `/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_state_machine.py`
- `/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_launch_service.py`

Updated:
- `/home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_api.py`

Coverage added for:
- valid and invalid job-state transitions
- continuous `FINALIZING -> RUNNING` transition
- extracted network launch service
- extracted webapp launch service
- actual `_maybe_finalize_pass()` behavior returning continuous jobs to `RUNNING`

## Acceptance Criteria Check

### `pentester_api_01.py` loses at least one major responsibility area

Met:
- local launch orchestration moved into `services/launch.py`
- scan strategy metadata moved into `services/scan_strategy.py`
- status transition rules moved into `services/state_machine.py`

### Scan-type branching becomes strategy-driven rather than repeated conditionals

Met in the key orchestration path:
- feature discovery and catalog filtering use scan strategy metadata
- local worker dispatch is centralized behind the launch service and strategy selection

### State transitions are explicit and validated

Met:
- job-state transitions now go through an explicit transition map for the finalized runtime path

### New finding-source additions require fewer touchpoints than today

Partially improved:
- this phase did not introduce a findings bundle abstraction
- but it did reduce coupling for scan-type and lifecycle changes, which was the highest-leverage structural risk in the current code

## Verification

Executed:

`PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_state_machine.py /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_launch_service.py /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_api.py`

Result:
- 74 tests passed

Executed:

`PYTHONPATH=/home/vitalii/remote-dev/repos/edge_node pytest /home/vitalii/remote-dev/repos/edge_node/extensions/business/cybersec/red_mesh/tests/test_integration.py`

Result:
- 26 tests passed

## Notes / Residual Risk

- `pentester_api_01.py` is still a large orchestrator; this phase reduced scope but did not complete the broader collaborator split proposed in the plan.
- Frontend adapter centralization was not changed in this phase. The structural risk addressed here was primarily backend orchestration and state management.

## Resulting State

After Phase 8:
- scan-type behavior is more explicit
- launch dispatch is less entangled with endpoint logic
- lifecycle transitions are no longer ad hoc
- continuous-monitoring jobs return to a correct steady-state status between passes

The next phase should expand regression guardrails across the remaining known failure modes.
