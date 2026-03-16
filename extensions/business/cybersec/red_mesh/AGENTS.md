# RedMesh Backend Agent Memory

Last updated: 2026-03-16T17:05:00Z

## Purpose

This file is the durable, append-only long-term memory for future agents working in the RedMesh backend implementation directory:

- [`extensions/business/cybersec/red_mesh/`](./)

Use it to preserve:
- code-level architecture facts
- backend-specific invariants
- important debugging references
- critical pitfalls
- timestamped memory entries for meaningful backend changes and major development stages

Do not rewrite history. Corrections belong in new log entries that reference earlier ones.

## Scope

This `AGENTS.md` is RedMesh-backend-specific.

Use the workspace-level memory for cross-repo planning and project-wide context:
- project-level RedMesh workspace `AGENTS.md`

Use this file for:
- backend implementation memory
- module boundaries
- orchestration and persistence invariants
- testing and debugging conventions
- significant backend change history

## Stable References

### Core Entry Points

- [`pentester_api_01.py`](./pentester_api_01.py)
- [`redmesh_llm_agent_api.py`](./redmesh_llm_agent_api.py)

### Core Subsystems

- [`services/`](./services)
- [`repositories/`](./repositories)
- [`models/`](./models)
- [`mixins/`](./mixins)
- [`worker/`](./worker)
- [`graybox/`](./graybox)

### Key Supporting Modules

- [`constants.py`](./constants.py)
- [`findings.py`](./findings.py)
- [`cve_db.py`](./cve_db.py)

### Tests

- [`tests/`](./tests)
- [`test_redmesh.py`](./test_redmesh.py)

### Historical Context

- [`.old_docs/HISTORY.md`](./.old_docs/HISTORY.md)

## Architecture Snapshot

RedMesh is a distributed pentest backend running on Ratio1 edge nodes. It coordinates scans across nodes, stores job state in CStore, persists large artifacts in R1FS, and exposes FastAPI endpoints consumed by Navigator and local operators.

High-level responsibilities:
- launch and coordinate network and graybox jobs
- distribute work across edge nodes
- track runtime progress
- aggregate worker reports
- finalize archives and derived metadata
- optionally run LLM analysis on aggregated reports
- expose audit, archive, report, progress, triage, and analysis APIs

### Current Major Boundaries

- `pentester_api_01.py`
  - main orchestration plugin
  - launch endpoints
  - process-loop coordination
  - API read paths

- `services/`
  - extracted lifecycle, query, launch, state-machine, control, finalization, resilience, and secret-handling logic

- `repositories/`
  - storage boundaries for CStore and R1FS-style artifacts

- `models/`
  - typed job/config/archive/report/triage structures

- `worker/`
  - network worker implementation and feature-specific probe modules

- `graybox/`
  - authenticated webapp scan models, runtime flow, auth lifecycle, safety gates, and probe families

- `mixins/`
  - live progress, reporting, risk scoring, attestation, and LLM behavior extracted from the main plugin

## Critical Invariants

### Storage and Ownership

- CStore job records are the shared orchestration state for distributed work.
- R1FS stores large immutable artifacts such as reports, configs, and archives.
- Finalized jobs are represented in CStore as stubs plus `job_cid`; archive payloads are authoritative for finalized history.
- Read paths for finalized data should prefer archive-backed retrieval over assuming live CStore detail still exists.

### Job Lifecycle

- Launcher node is responsible for distributed orchestration and finalization.
- Workers are selected per job and assigned explicit ranges/config.
- Aggregated analysis should run on the combined multi-worker report, not a single-worker report.
- A job should converge to an explicit terminal state; indefinite `RUNNING` due to a missing worker is a bug.

### Findings and Reports

- Structured findings are the backend contract; string-only vulnerability outputs are legacy history, not the target model.
- Severity, evidence, remediation, and typed finding metadata should remain normalized across network and graybox paths.
- Mutable analyst triage state must remain separate from immutable scan/archive records.

### Security and Secret Handling

- Archive/report redaction is not equivalent to secure secret persistence.
- Graybox secret storage boundaries are security-sensitive and should be treated as architecture, not cosmetic cleanup.
- Safe defaults matter for redaction, ICS-safe behavior, rate limiting, and authorization confirmation.

### Distributed Runtime State

- Shared job blobs are vulnerable to lost-update races if multiple nodes write unrelated fields concurrently.
- Worker-owned runtime state should prefer isolated records over concurrent writes into the same job document.
- Launcher-side reconciliation is safer than trusting many workers to merge shared orchestration state correctly.
- Nested config blocks should resolve through one shared shallow merge helper, with validation kept in subsystem-specific wrappers.

## Testing and Verification

Primary backend test commands:

```bash
cd edge_node
python -m pytest extensions/business/cybersec/red_mesh/test_redmesh.py -v
```

```bash
cd edge_node
python -m pytest extensions/business/cybersec/red_mesh/tests -v
```

Useful targeted runs:

```bash
cd edge_node
python -m pytest extensions/business/cybersec/red_mesh/tests/test_api.py -v
```

```bash
cd edge_node
python -m pytest extensions/business/cybersec/red_mesh/tests/test_regressions.py -v
```

```bash
cd edge_node
python -m pytest extensions/business/cybersec/red_mesh/tests/test_state_machine.py -v
```

## Debugging Conventions

- Prefer reading both live API state and persisted logs when investigating distributed-job issues.
- For finalized-job read bugs, verify whether the true source of truth is CStore stub data or archive data in R1FS.
- For stuck distributed jobs, inspect:
  - launcher job record
  - per-worker status/progress visibility
  - whether every assigned worker actually observed the job
  - whether missing workers were unhealthy at assignment time
- Distinguish clearly between:
  - scan execution failures
  - orchestration failures
  - archive/read-path failures
  - LLM post-processing failures

## Pitfalls

- `get_job_status` can look locally “complete” while the distributed job is still incomplete.
- Finalized jobs are pruned to CStore stubs; assuming live pass reports remain in CStore is incorrect.
- Shared CStore writes without guarded semantics can lose unrelated updates.
- LLM failure and analysis retrieval are separate problems; missing analysis text is not always a UI issue.
- Graybox and network paths now share more contracts than before; avoid fixing one while silently breaking the other.

## Mandatory BUILDER-CRITIC Loop

For every meaningful RedMesh backend modification, future agents must record and follow this loop in their work output and, for critical/fundamental changes, summarize the result in the Memory Log.

### 1. BUILDER

State:
- intent
- files or systems to change
- expected behavioral change

### 2. CRITIC

Adversarially try to break the change:
- wrong assumptions
- orchestration/storage mismatches
- regressions
- security impact
- distributed-state edge cases
- missing tests
- missing docs
- operational risks

### 3. BUILDER Response

Refine or defend the change:
- what changed after critique
- what remains risky
- exact verification commands
- actual verification results

Minimum bar:
- no meaningful RedMesh backend change is complete without a documented CRITIC pass
- no critical orchestration/storage change is complete without verification commands and results
- if verification cannot run, record that explicitly

## Memory Log (append-only)

Only append entries for critical or fundamental RedMesh backend changes, discoveries, or horizontal insights. Do not add routine edits.

### 2025-08-27 to 2025-10-04

- Stage: initial RedMesh backend creation and early productionization.
- Change: established the original distributed pentest backend with `pentester_api_01.py`, `PentestLocalWorker`, basic service probes, and early web checks.
- Change: added the first test suite and expanded protocol/web coverage beyond basic banner grabbing.
- Horizontal insight: RedMesh started as a network-first scanning backend and only later grew into a richer orchestration and analysis platform.

### 2025-12-08 to 2025-12-22

- Stage: distributed orchestration hardening and feature-catalog expansion.
- Change: added startup coordination fixes, chainstore handling fixes, and a major overhaul of multi-node job coordination.
- Change: introduced the feature catalog and explicit capability-driven execution model in [`constants.py`](./constants.py).
- Horizontal insight: the December 2025 update was the major transition from a simple scanner plugin to a configurable distributed scanning platform.

### 2026-01-28 to 2026-02-19

- Stage: worker-state fixes, LLM integration, deep probes, structured findings, and web architecture refactor.
- Change: fixed worker-entry handling from CStore, then added DeepSeek-backed LLM analysis through a dedicated agent path.
- Change: expanded deep service probes across SSH, FTP, Telnet, HTTP, TLS, databases, and infrastructure protocols.
- Change: split monolithic web logic into OWASP-aligned mixins and completed the migration to structured findings plus CVE matching.
- Horizontal insight: by 2026-02-19, structured findings became the core backend contract and should be treated as foundational rather than optional formatting.

### 2026-02-20

- Stage: security-control baseline added across backend and Navigator integration.
- Change: added credential redaction, ICS safe mode, rate limiting, scanner identity controls, audit logging, and authorization gating.
- Horizontal insight: RedMesh security controls affect the full path from UI input to backend runtime and archive persistence; future changes should be reviewed end-to-end, not only in the plugin code.

### 2026-03-07 to 2026-03-10

- Stage: observability and backend decomposition.
- Change: added live worker progress endpoints, per-thread metrics/ports visibility, node IP stamping, hard stop support, purge/delete flows, and improved progress loading.
- Change: refactored a growing monolith into more granular mixins, worker modules, and split tests.
- Horizontal insight: progress and observability became first-class runtime concerns, not just UI convenience features.

### 2026-03-10 to 2026-03-11

- Stage: graybox architecture introduction and typed execution boundaries.
- Change: introduced graybox core modules, auth/discovery/safety flows, worker/API integration, launch API split by scan type, feature capability modeling by scan type, and extracted launch strategies/state machine.
- Change: expanded graybox probes and tests, including access control, business logic, misconfiguration, and injection families.
- Horizontal insight: RedMesh is no longer only a distributed port scanner; it is a dual-mode backend with both network and authenticated webapp execution paths.
- Critical continuity rule: future agents must treat network and graybox paths as coupled contracts wherever findings, progress, launch state, and archive/read behavior overlap.

### 2026-03-12

- Stage: service extraction, repository/model boundaries, pass-cap hardening, and stronger storage design.
- Change: extracted query, launch, lifecycle, repository, and service boundaries from `pentester_api_01.py`.
- Change: enforced continuous-pass caps, normalized running-job state, introduced repository boundaries, and split graybox secrets from plain job config.
- Horizontal insight: after this stage, RedMesh backend work should prefer service/repository/model boundaries over adding more behavior directly to the monolithic plugin file.
- Critical continuity rule: storage-affecting work should flow through the typed repository/model/service boundaries unless there is a clear reason not to.

### 2026-03-13

- Stage: secret-boundary hardening, typed graybox artifacts, finding triage, resilience, and regression coverage.
- Change: hardened secret-storage boundaries, typed graybox runtime/probe/evidence flows, normalized graybox finding contracts, added finding triage state and CVSS metadata, and strengthened resilience/launch policy.
- Change: added regression and contract suites, hardened live progress metadata, hardened LLM failure handling, and preserved pass reports during finalization.
- Horizontal insight: RedMesh now has explicit architecture around evidence artifacts, triage state, and regression protection; future work should extend those contracts rather than bypass them.

### 2026-03-16

- Change: added this backend-local [`AGENTS.md`](./AGENTS.md) to keep RedMesh-specific implementation memory separate from workspace-level planning memory.
- Change: identified a distributed-job orchestration gap where an assigned worker can miss the initial CStore job announcement and the launcher can wait indefinitely.
- Change: added a companion implementation tracker for distributed job reconciliation in the shared RedMesh project docs.
- Horizontal insight: current launcher/worker orchestration is strong enough to distribute work, but not yet strong enough to guarantee convergence when a peer misses assignment visibility; future agents should treat worker-owned runtime state and launcher-side reconciliation as the preferred fix direction.

### 2026-03-16T17:05:00Z

- Change: extracted a generic nested-config resolver in [`services/config.py`](./services/config.py) and moved distributed job reconciliation config onto that shared path.
- Horizontal insight: RedMesh should centralize nested config block merge semantics, but keep validation local to each subsystem wrapper rather than introducing a broad deep-merge config framework prematurely.

### 2026-03-16T20:40:00Z

- Change: introduced a dedicated LLM payload-shaping boundary in [`mixins/llm_agent.py`](./mixins/llm_agent.py) so RedMesh no longer sends the full aggregated report directly to the LLM path.
- Change: added network and webapp-specific compact payload shaping, finding deduplication/ranking/capping, analysis-type budgets, and runtime payload-size observability.
- Verification: the known failing job `a3a357bc` dropped from `303,760` raw bytes to `21,559` shaped bytes for `security_assessment` and completed manually in `38.97s` on rm1 instead of timing out.
- Horizontal insight: RedMesh archive/report data and LLM reasoning data must remain separate contracts; future LLM work should extend the bounded payload model rather than re-coupling the agent to raw archived aggregates.
