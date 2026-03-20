# Edge Node Agent Manual + Long-Term Memory

This file is the authoritative operating manual for agents working in `/edge_node`.
It governs:
- repository purpose and runtime constraints
- module/file ownership
- safe-edit boundaries
- required verification commands
- handoff and escalation rules
- critical long-term memory

The operating model intentionally follows current agent practice:
- maximize a single agent before introducing delegation
- use structured task/handoff envelopes rather than prose-only delegation
- use evaluator/critic passes to challenge correctness before closing work

## Hard Rules
- Treat `AGENTS.md` as the first source of truth for repo-local agent behavior. If code and `AGENTS.md` disagree, inspect the code, fix the task, and update `AGENTS.md` when one of the review triggers below is met.
- Treat the `Memory Log` as a high-signal ledger, not a full activity history.
- Log only:
  - critical/fundamental changes with architectural, security, operational, or reliability impact
  - horizontal insights that affect multiple subsystems, onboarding, deployment, or runbook safety
- Do not log:
  - minor docs edits, wording tweaks, formatting, or cosmetic refactors
  - narrow/local changes without material behavioral or operational impact
- Keep the `Memory Log` append-only for qualifying entries.
- Cleanup/removal of ballast entries is allowed only during explicit curation requested by project owners.
- If an older entry is wrong, add a new correction entry that references the old entry ID.
- Use UTC timestamps in ISO-8601 format: `YYYY-MM-DDTHH:MM:SSZ`.
- Keep shell examples copy-pasteable.
- Prefer the narrowest safe write scope. Do not expand scope just to make the change feel cleaner.
- Environment feedback outranks stylistic feedback. Fix failing runtime/test evidence before discussing style.

## Stable Reference

### Repository Purpose
- This repo packages the Ratio1 edge-node runtime that joins the Ratio1 network, starts the upstream `naeural_core` engine, and exposes extension/plugin surfaces for business, data, and serving behavior.
- This repo is mostly an integration and extension layer, not the source of truth for core runtime contracts. `naeural_core` owns the underlying engine semantics.
- Runtime entrypoints are intentionally thin:
  - `device.py` boots `naeural_core.main.entrypoint.main(...)`
  - `constants.py` extends upstream admin pipeline/config behavior

### Runtime Constraints
- Primary runtime is container-first. Most operator flows assume Docker, mounted `_local_cache`, and env-driven configuration.
- Runtime state is persisted under `/edge_node/_local_cache`. Treat `_local_cache/**` as runtime data, not as normal source files.
- Secrets and operator credentials must remain env-driven via `EE_*` variables or deployment secret stores. Never hardcode live credentials.
- `device.py` is effectively frozen unless an explicit task requires entrypoint/process-lifecycle change and the change is justified against upstream `naeural_core`.
- `debug.sh` and debug compose do not currently use the same local image tag:
  - `debug.sh` builds `local_node`
  - `docker-compose/debug-docker-compose.yaml` expects `local_edge_node`
- Kubernetes manifests are not self-consistent enough to treat as production-safe without review; validate names, namespaces, PVCs, and mount paths before use.

### How To Run
- Local dev (single node, local image):
  - `./debug.sh`
  - Builds `Dockerfile_devnet` and runs with `--env-file=.env`.
- Local dev (compose, 3 local containers):
  - Build expected image tag first: `docker build -t local_edge_node -f Dockerfile_devnet .`
  - Start stack: `docker-compose -f docker-compose/debug-docker-compose.yaml up -d`
  - Stop stack: `docker-compose -f docker-compose/debug-docker-compose.yaml down`
  - Equivalent on Compose v2 setups: replace `docker-compose` with `docker compose`.
- Public image (single node):
  - `docker run -d --rm --name r1node --pull=always -v r1vol:/edge_node/_local_cache/ ratio1/edge_node:devnet`
  - For GPU hosts: add `--gpus all`.

### How To Inspect and Operate
- Node info: `docker exec r1node get_node_info`
- Node history: `docker exec r1node get_node_history`
- Current whitelist: `docker exec r1node get_allowed`
- Add allowed address: `docker exec r1node add_allowed <address> [alias]`
- Change alias: `docker exec r1node change_alias <new_alias>` then `docker restart r1node`
- Reset keys (interactive): `docker exec -it r1node reset_node_keys`

### Repo Map
- Runtime entrypoints:
  - `device.py`: delegates execution to `naeural_core.main.entrypoint.main(...)`.
  - `constants.py`: extends upstream admin pipeline and environment-driven config.
- Extensions:
  - `extensions/business/`: operational APIs and supervisors (`deeploy`, `dauth`, `oracle sync`, `tunnels`, `r1fs`, `container apps`, `cybersec`, `jeeves`, `liveness`, `ai4e`).
  - `extensions/data/`: listener/capture extensions.
  - `extensions/serving/`: serving backends, LLM/document embedding infrastructure, default inference adapters, model-testing helpers.
  - `extensions/utils/`: helper utilities.
- Plugins:
  - `plugins/business/`: tutorial apps, app-specific business plugins, test framework helpers.
  - `plugins/data/`: capture stream examples and test data integrations.
  - `plugins/serving/`: serving/inference examples and model testing scaffolding.
- Operations:
  - `cmds/`: in-container operational commands (`get_node_info`, `add_allowed`, `reset_node_keys`, etc.).
  - `docker/`: alternative Dockerfiles for CPU/RPi/Tegra variants.
  - `docker-compose/`: debug/prod multi-container compose files and Windows helpers.
  - `k8s/`: Kubernetes manifests.
  - `.github/workflows/`: active image build workflows.
  - `github_workflows/`: legacy/stale workflow copies; do not treat as active CI.
- Research and spikes:
  - `xperimental/`: non-production exploratory scripts and notes. Never assume changes here fix production paths unless promoted deliberately.

### Module And File Ownership
| Path / area | Primary owner role | Secondary reviewer | Notes |
| --- | --- | --- | --- |
| `device.py` | runtime-config actor | critic + integrator/test-executor | Frozen by default; explicit escalation required before change |
| `constants.py`, `.config*.json`, `.env.template`, `requirements.txt`, `Dockerfile_*`, `ver.py` | runtime-config actor | critic | Runtime packaging/config surface |
| `extensions/business/**`, `plugins/business/**` | business-extension actor | critic | Business APIs, supervisors, tutorial business plugins |
| `extensions/data/**`, `extensions/serving/**`, `extensions/utils/**`, `plugins/data/**`, `plugins/serving/**` | serving-data actor | critic | Data capture, serving, shared utils, serving tests |
| `cmds/**`, `docker/**`, `docker-compose/**`, `k8s/**`, `.github/workflows/**` | ops-infra actor | critic + integrator/test-executor | Operator-facing and deployment-sensitive |
| `README.md`, `AGENTS.md` | docs-memory curator | orchestrator + critic | Horizontal docs and durable memory |
| `_local_cache/**`, `__pycache__/**`, `docker-compose/win_single.zip`, minified bundles such as `extensions/business/ai4e/assets/bundle.js` | no routine owner | explicit escalation | Runtime/generated/binary outputs; avoid normal edits |

### Safe-Edit Boundaries
- Do not edit `device.py` unless the task explicitly requires entrypoint/process-lifecycle change and the handoff/escalation record explains why `constants.py` or `extensions/**` is insufficient.
- Do not edit `_local_cache/**`, live keys, or generated runtime artifacts as part of normal source work.
- Do not add credentials, tokens, wallet material, API secrets, or populated `.env` content to source-controlled files.
- Treat `cmds/reset_node_keys`, `cmds/reset_address`, `cmds/reset_supervisor`, and similar reset flows as sensitive. Review for accidental destructive behavior, operator confirmation, and restart semantics.
- Treat `.github/workflows/**`, `docker/**`, `docker-compose/**`, and `k8s/**` as operator-facing change surfaces. They require verification evidence, not just static reasoning.
- Treat `github_workflows/**` as legacy until explicitly reactivated. Updating only that folder does not change live CI behavior.
- Treat `xperimental/**` as non-authoritative. If production behavior depends on an `xperimental` proof, promote or port the change into the owned production path.
- Avoid hand-editing bundled/minified assets unless the source or generation process is unavailable and the handoff explicitly records that exception.

### Conventions
- Python style in this repo commonly uses 2-space indentation and `snake_case` names.
- Keep module-level `__VER__` where applicable to plugin-style modules.
- Extend configs via dict merge patterns, e.g. `CONFIG = {**BASE, **overrides}`.
- Keep sensitive values env-driven (`$EE_*`) in config JSON/Python defaults.
- Use `self.P(...)` logging style in plugin classes.
- Commit style expectation: Conventional Commits (`feat:`, `fix:`, `chore:`).

### Required Verification Commands
Run the narrowest command set that proves the changed concern. If a command is not runnable in the environment, record that explicitly in the handoff. If a required suite is already red on an untouched checkout, record the baseline failure, do not claim a pass, and add narrower non-regression evidence for the changed scope.

| Change area | Minimum required verification |
| --- | --- |
| `AGENTS.md`, `README.md`, repo governance docs | `sed -n '1,260p' AGENTS.md`; `rg -n "A2A|actor-critic|verification|AGENTS review" AGENTS.md` |
| `constants.py`, root configs, `device.py`, `requirements.txt` | `python3 -m py_compile device.py constants.py`; if Docker/runtime files changed: `docker build -t local_edge_node -f Dockerfile_devnet .` |
| `extensions/business/deeploy/**` | `python3 -m unittest extensions.business.deeploy.test_deeploy` |
| `extensions/business/container_apps/**` | `python3 -m unittest extensions.business.container_apps.test_worker_app_runner` |
| `extensions/business/cybersec/**` | `python3 -m unittest extensions.business.cybersec.red_mesh.test_redmesh` |
| `extensions/business/oracle_sync/**` | `python3 -m unittest extensions.business.oracle_sync.oracle_sync_test_01` |
| `plugins/**` or broad tutorial/plugin behavior | `python3 -m unittest discover -s plugins -p "*test*.py"` |
| `extensions/serving/**`, `plugins/serving/**`, LLM/model-testing helpers | `python3 -m unittest extensions.serving.model_testing.test_llm_servings` |
| `docker-compose/**` | `docker-compose -f docker-compose/debug-docker-compose.yaml config`; `docker-compose -f docker-compose/prod-docker-compose.yaml config` |
| `k8s/**` | `sed -n '1,240p' k8s/README.md`; `sed -n '1,240p' k8s/edgenode-deploy.yaml`; `sed -n '1,220p' k8s/edgenode-storage.yaml`; when `kubectl` is available, also run `kubectl apply --dry-run=client -f <file>` for each touched manifest |
| Cross-repo integration with `naeural_core` or `ratio1_sdk` | targeted tests in the sibling repo in addition to repo-local verification |

### Handoff And Escalation Rules
- Every meaningful task must name:
  - one owner role
  - one bounded write scope
  - one primary concern for the current loop
- Escalate immediately instead of retrying blindly when:
  - the task requires edits across ownership boundaries and the boundary is not already approved
  - `device.py`, operator reset flows, secrets handling, blockchain/payment semantics, or deployment paths are affected
  - verification requires unavailable infrastructure and the risk cannot be reduced locally
  - the same concern fails twice without new executable evidence
  - three loops have failed on the same task, even if the failures differ
- Cancellation must be explicit. State whether side effects occurred and whether rollback was applied, skipped, or impossible.
- Handoffs must use the structured envelope below. Free-form prose may explain context, but it does not replace the envelope.

## Agent Cards

### Orchestrator
- Role name: `orchestrator`
- Objective: scope work, assign owner roles, keep write scopes bounded, decide when to stay single-agent vs delegate, and enforce handoff/escalation policy
- Owned files / write scope: none by default; may update `AGENTS.md` or task notes for governance work
- Required inputs and context: user goal, affected paths, repo status, current `AGENTS.md`, last failing evidence
- Expected outputs / artifacts: task contract, chosen workflow, escalation decision, final handoff envelope
- Allowed tools: repo search/read, diff inspection, non-destructive verification, structured delegation
- Escalation triggers: ambiguous ownership, repeated failed loops, cross-boundary work, sensitive operator/runtime surfaces

### Runtime-Config Actor
- Role name: `runtime-config actor`
- Objective: maintain runtime packaging, startup configuration, env-driven behavior, and root entrypoint-adjacent files
- Owned files / write scope: `constants.py`, `.config*.json`, `.env.template`, `requirements.txt`, `Dockerfile_*`, `ver.py`; `device.py` only with explicit escalation approval
- Required inputs and context: runtime goal, env assumptions, upstream `naeural_core` contract, deployment path affected
- Expected outputs / artifacts: minimal patch, runtime verification evidence, config migration notes when needed
- Allowed tools: targeted file edits, Python compile checks, Docker build verification, non-destructive config inspection
- Escalation triggers: entrypoint/process-lifecycle changes, new secret material, changes that affect boot path or container image semantics

### Business-Extension Actor
- Role name: `business-extension actor`
- Objective: implement or fix business APIs, supervisors, and business-side plugins without leaking changes into unrelated runtime surfaces
- Owned files / write scope: `extensions/business/**`, `plugins/business/**`, business-specific tests in matching paths
- Required inputs and context: affected API/plugin contract, request/response semantics, operational failure evidence, relevant tests
- Expected outputs / artifacts: scoped patch, updated/regression tests, note of user-visible or operator-visible behavior change
- Allowed tools: targeted code edits, unit tests for touched modules, repo-local log/test inspection
- Escalation triggers: blockchain/payment effects, tunnel/auth changes, cross-repo dependency breakage, deployment/runbook impact

### Serving-Data Actor
- Role name: `serving-data actor`
- Objective: maintain data listeners, serving adapters, embedding/LLM helpers, and serving/data plugins
- Owned files / write scope: `extensions/data/**`, `extensions/serving/**`, `extensions/utils/**`, `plugins/data/**`, `plugins/serving/**`
- Required inputs and context: affected model/data path, interface contract, expected inputs/outputs, available test harnesses
- Expected outputs / artifacts: scoped patch, targeted serving/data verification, compatibility notes if model behavior changes
- Allowed tools: targeted code edits, unittest execution, fixture inspection, non-destructive repo search
- Escalation triggers: model download/runtime dependency changes, external service dependency changes, cross-boundary config edits

### Ops-Infra Actor
- Role name: `ops-infra actor`
- Objective: maintain operator commands, container builds, compose stacks, k8s manifests, and active CI workflows
- Owned files / write scope: `cmds/**`, `docker/**`, `docker-compose/**`, `k8s/**`, `.github/workflows/**`
- Required inputs and context: deployment path, operator command semantics, runtime volume/path expectations, target environment
- Expected outputs / artifacts: scoped infra patch, config/render validation, explicit operator-facing impact statement
- Allowed tools: targeted file edits, compose config validation, Docker build validation, manifest inspection, non-destructive shell checks
- Escalation triggers: destructive operator commands, secret handling, active path mismatch, production rollout semantics, missing environment required for proof

### Critic
- Role name: `critic`
- Objective: challenge correctness and safety before closure
- Owned files / write scope: read-only by default; may write review notes or requested small test-only reproductions if explicitly assigned
- Required inputs and context: actor intent, write scope, assumptions, diffs, failing/passing evidence, rollback plan
- Expected outputs / artifacts: findings ordered by severity, missing-test list, rollback/noise risk assessment, accept-or-block decision
- Allowed tools: repo read/search, diff inspection, test/log review, non-destructive verification
- Escalation triggers: unverifiable claims, rollback gap, safety/privacy risk, alert-noise risk, missing evidence for disputed behavior

### Integrator-Test-Executor
- Role name: `integrator/test-executor`
- Objective: resolve actor-vs-critic disagreement using executable evidence and close the loop with final verification
- Owned files / write scope: no code writes by default; may adjust tests or glue only when explicitly assigned a bounded scope
- Required inputs and context: actor patch, critic findings, exact commands to run, expected observable outcomes
- Expected outputs / artifacts: command results, decision grounded in evidence, final handoff envelope
- Allowed tools: test execution, diff inspection, non-destructive verification, targeted test-only edits when explicitly assigned
- Escalation triggers: contradictory evidence, nondeterministic failures, environment-dependent failures that cannot be reproduced safely

### Docs-Memory Curator
- Role name: `docs-memory curator`
- Objective: keep `AGENTS.md` and top-level operator docs authoritative, concise, and aligned with actual code/deploy behavior
- Owned files / write scope: `AGENTS.md`, `README.md`
- Required inputs and context: code-backed repo reality, current run/test paths, incident/runbook changes, new horizontal lessons
- Expected outputs / artifacts: authoritative doc update, review-trigger satisfaction, memory entry decision
- Allowed tools: repo read/search, doc edits, command validation, non-destructive verification
- Escalation triggers: source-of-truth conflict, doc change that hides a real code issue, proposed memory entry that is not actually critical

## Mandatory Execution Loops

Run one of these loops for every meaningful modification. A meaningful modification is any change beyond trivial typo-only edits.

### Single-Agent Loop
Use this by default. Multi-agent work is justified only when a bounded delegated task materially helps and does not blur ownership.

Loop:
1. `plan`
   - define one concern only
   - define owner role, write scope, assumptions, and verification target
2. `implement`
   - make the smallest change that addresses the concern
3. `test`
   - run the narrowest executable proof for the concern
4. `critique`
   - challenge the change in this order:
     - environment/runtime feedback
     - behavioral regressions
     - safety/privacy/alert-noise risk
     - rollback and operability
     - style/maintainability
5. `revise`
   - apply only changes justified by critique evidence
6. `verify`
   - rerun the minimum final proof and prepare the structured handoff

Rules:
- One concern per loop. Split unrelated fixes into separate loops.
- Do not replace failing evidence with speculation.
- If the same concern fails twice without new evidence, escalate.
- If three loops fail on the same task, stop and escalate with a handoff envelope.

### Actor-Critic Workflow
Use when the risk of silent regression is high or the change is operationally sensitive.

Workflow:
1. Actor states:
   - intent
   - bounded write scope
   - assumptions
   - planned tests
2. Actor implements and runs tests inside that scope.
3. Critic reviews for:
   - correctness
   - safety/privacy
   - alert-noise or operator-noise risk
   - rollback hazards
   - missing tests or missing runbook impact
4. Integrator/test-executor resolves disagreements with executable evidence, not authority or prose.
5. Actor revises only where the evidence justifies it.
6. Final verification and structured handoff close the task.

Rules:
- The actor owns implementation and tests inside the assigned scope.
- The critic does not widen scope casually; findings must stay tied to correctness and safety.
- If actor and critic disagree, the tie-breaker is executable evidence from the integrator/test-executor.
- If executable evidence cannot be obtained safely, escalate instead of arguing from taste.

## Mandatory BUILDER-CRITIC Record

For every meaningful modification, record this reasoning in the task notes, handoff, or final response:

### Step 1: BUILDER
BUILDER must state:
- Intent: what is being changed and why.
- Change scope: files/paths touched.
- Assumptions: dependencies, environment, invariants.

### Step 2: CRITIC
CRITIC must try to break the change by checking:
- assumption failures
- behavioral regressions
- security/privacy risks
- alert-noise or operator-noise risk
- edge cases and failure modes
- missing docs/tests or runbook impact

### Step 3: BUILDER Response
BUILDER must:
- address critic findings or justify accepted risk
- refine the change if needed
- list verification commands run and observed results with short evidence

### Step 4: Log It
Append a `Memory Log` entry only when the change or insight is critical or fundamental.

## A2A-Style Task Contract

Every delegated task must carry a structured contract. Model it like a task object, not an informal request.

Required fields:
- `task_id`: stable ID, e.g. `EN-20260317-001`
- `goal`: one sentence stating the concrete outcome
- `owner`: one role from the agent cards above
- `write_scope`: exact files or directories the owner may modify
- `constraints`: safety, runtime, style, or dependency boundaries
- `required_inputs`: code paths, failing evidence, operator context, or external assumptions
- `expected_artifacts`: patch, tests, logs, notes, migration/runbook changes
- `checkpoints`: when progress updates are required
- `terminal_state`: one of `completed`, `failed`, `canceled`, `blocked`, or `rejected`

Status rules:
- Use task states compatible with current A2A-style lifecycles:
  - `submitted`
  - `working`
  - `input-required`
  - `auth-required`
  - `completed`
  - `failed`
  - `canceled`
  - `rejected`
- Long-running tasks must emit a checkpoint on state change and at least every 30 minutes.
- Retries should be idempotent where possible:
  - reuse the same `task_id`
  - include an `attempt` number
  - record whether partial side effects already happened
- Cancellation must be explicit and safe:
  - set state to `canceled`
  - list side effects already applied
  - record rollback status as `done`, `not-needed`, or `not-possible`

Preferred payload template:

```yaml
task_id: EN-YYYYMMDD-###
attempt: 1
status: submitted
goal: <single concrete outcome>
owner: <role name>
write_scope:
  - <path>
constraints:
  - <boundary>
required_inputs:
  - <evidence or context>
expected_artifacts:
  - <artifact>
checkpoints:
  cadence: 30m
  on_state_change: true
terminal_state: completed
```

## Required Handoff Envelope

Every meaningful handoff or closure must include this envelope:

```yaml
task_id: EN-YYYYMMDD-###
current_status: working|input-required|completed|failed|canceled|blocked|rejected
owner: <role name>
changed_files:
  - <path>
tests_run:
  - command: <cmd>
    result: pass|fail|not-run
    evidence: <short evidence>
evidence_or_logs_reviewed:
  - <file, command, or log source>
open_risks:
  - <risk>
next_recommended_action: <single next step>
```

Rules:
- Use structured fields first, then short prose if needed.
- `changed_files` must be exact, not “many files”.
- `tests_run` must distinguish `not-run` from `fail`.
- `open_risks` must be explicit; do not hide uncertainty in narrative text.

## Lessons Learned

Use this section for reusable failures and validated fixes so later agents do not repeat the same mistakes. This section is durable and editable; it is not append-only like the `Memory Log`.

Current lessons:
- `debug.sh` and debug compose use different image tags. Fixing only one side will not repair local onboarding.
- `docker-compose/debug_start.bat` references `Dockerfile_dev`, which does not exist.
- `k8s/README.md` and the shipped manifests disagree on file names, namespaces, PVC names, and cache mount paths. Treat k8s changes as incident-prone until reconciled.
- `.github/workflows/` is active CI. `github_workflows/` is legacy ballast unless explicitly revived.
- `xperimental/**` is useful for investigation but does not count as a production fix.
- `device.py` already warns “do not modify this”; prefer `constants.py` or extension/plugin changes first.
- Some repo-local verification commands can be baseline-red because of environment or upstream import issues. Record baseline failures explicitly and prove non-regression with narrower evidence instead of silently skipping verification.

Template for future reusable lessons:
- Problem:
- Signal:
- Safe response:
- Validated fix:
- Avoid next time:

## Worked Examples

### Example: Single-Agent Task
Concern: fix a deeploy timeout cleanup bug in `extensions/business/deeploy/deeploy_manager_api.py`.

Loop:
1. Plan: owner is `business-extension actor`; scope is `extensions/business/deeploy/**`; verify with `python3 -m unittest extensions.business.deeploy.test_deeploy`.
2. Implement: patch only the pending-timeout path.
3. Test: run the deeploy unit test module.
4. Critique: check timeout cleanup, missing `now`, chainstore side effects, and regression risk for async endpoints before commenting on style.
5. Revise: add the smallest fix for the failed case.
6. Verify: rerun the deeploy tests and hand off with changed files, command result, and open risks.

### Example: Actor-Critic Task
Concern: change container app autoupdate behavior under `extensions/business/container_apps/**`.

Workflow:
1. Actor owns only `extensions/business/container_apps/**` and its tests.
2. Actor implements the autoupdate change and runs `python3 -m unittest extensions.business.container_apps.test_worker_app_runner`.
3. Critic checks restart loops, noisy restarts, rollback path, leaked credentials in repo URLs, and missing test cases.
4. Integrator/test-executor reruns the unit tests and any reproduction the critic requested.
5. If evidence supports the critic, actor revises; otherwise the finding is closed with test evidence.

### Example: A2A-Style Cross-Agent Handoff

Delegation payload:

```yaml
task_id: EN-20260317-014
attempt: 1
status: submitted
goal: Reconcile debug compose documentation with actual image-tag behavior.
owner: ops-infra actor
write_scope:
  - README.md
  - docker-compose/debug-docker-compose.yaml
constraints:
  - do not change runtime entrypoint files
  - do not assume k8s is authoritative
required_inputs:
  - debug.sh builds local_node
  - debug compose expects local_edge_node
expected_artifacts:
  - doc or config patch
  - compose validation evidence
checkpoints:
  cadence: 30m
  on_state_change: true
terminal_state: completed
```

Handoff envelope:

```yaml
task_id: EN-20260317-014
current_status: completed
owner: ops-infra actor
changed_files:
  - README.md
tests_run:
  - command: docker-compose -f docker-compose/debug-docker-compose.yaml config
    result: pass
    evidence: compose rendered with local_edge_node image
evidence_or_logs_reviewed:
  - debug.sh
  - docker-compose/debug-docker-compose.yaml
open_risks:
  - debug.sh still builds local_node unless separately changed
next_recommended_action: Decide whether to align debug.sh or keep the mismatch documented.
```

## AGENTS Review Triggers

Review and update `AGENTS.md` in the same change, or explicitly explain deferral, whenever:
- module boundaries change
- ownership/write-scope boundaries change
- safe-edit boundaries change
- verification commands change
- new incident semantics are introduced
- new operator commands are added
- new deployment paths are added
- active CI/workflow paths change
- a reusable lesson is discovered that would help later agents avoid the same failure

## Memory Log (critical-only; append-only for qualifying entries)

Entry format:
- `ID`: `ML-YYYYMMDD-###`
- `Timestamp`: UTC ISO-8601
- `Type`: discovery | decision | change | correction
- `Summary`:
- `Criticality`:
- `Details`:
- `Verification`:
- `Links`:

---

- ID: `ML-20260211-002`
- Timestamp: `2026-02-11T09:13:34Z`
- Type: `discovery`
- Summary: Found operational mismatches that can break onboarding.
- Criticality: Cross-cutting operations/onboarding risk across local dev, compose, and k8s paths.
- Details: `debug.sh` builds `local_node` while debug compose expects `local_edge_node`; `docker-compose/debug_start.bat` references missing `Dockerfile_dev`; multiple `k8s/` naming/namespace/PVC path mismatches exist.
- Verification: `rg -n "local_edge_node|local_node" -S`; `sed -n '1,120p' debug.sh`; `sed -n '1,160p' docker-compose/debug_start.bat`; `sed -n '1,220p' k8s/README.md`; `sed -n '1,220p' k8s/edgenode-deploy.yaml`; `sed -n '1,220p' k8s/edgenode-sa.yaml`; `sed -n '1,220p' k8s/edgenode-storage.yaml`
- Links: `debug.sh`, `docker-compose/debug-docker-compose.yaml`, `docker-compose/debug_start.bat`, `k8s/README.md`, `k8s/edgenode-deploy.yaml`

- ID: `ML-20260211-003`
- Timestamp: `2026-02-11T09:13:34Z`
- Type: `change`
- Summary: Replaced prior short AGENTS guidance with durable long-term memory structure and mandatory BUILDER-CRITIC loop.
- Criticality: Foundation process change governing agent behavior and decision quality.
- Details: Added stable sections for run/test, repo map, conventions, pitfalls; established append-only log protocol with correction semantics.
- Verification: `sed -n '1,260p' AGENTS.md`
- Links: `AGENTS.md`

- ID: `ML-20260212-009`
- Timestamp: `2026-02-12T14:32:58Z`
- Type: `change`
- Summary: Re-scoped AGENTS memory policy to critical-only logging and pruned prior ballast entries.
- Criticality: Fundamental governance change for long-term agent memory quality and signal-to-noise control.
- Details: Updated Hard Rules and BUILDER-CRITIC Step 4 to enforce critical/horizontal-only logging; removed non-critical historical entries (`ML-20260211-001`, `ML-20260211-004`, `ML-20260211-005`, `ML-20260211-006`, `ML-20260211-007`, `ML-20260211-008`) per owner request.
- Verification: `rg -n "critical-only|ballast|Criticality|ML-20260211-00[1245678]|ML-20260212-009" AGENTS.md`; `sed -n '1,260p' AGENTS.md`
- Links: `AGENTS.md`

- ID: `ML-20260224-001`
- Timestamp: `2026-02-24T00:50:16Z`
- Type: `change`
- Summary: Refactored Deeploy manager endpoints to use PostponedRequest polling instead of blocking waits.
- Criticality: Operational/runtime behavior change; long-running deploy endpoints no longer block the main plugin loop.
- Details: Added non-blocking response checks in deeploy mixin, deferred blockchain confirmations to postponed solver, and converted create/update/scale-up endpoints to return PostponedRequest while tracking pending state and timeouts.
- Verification: Not run (not requested).
- Links: `extensions/business/deeploy/deeploy_manager_api.py`, `extensions/business/deeploy/deeploy_mixin.py`

- ID: `ML-20260224-002`
- Timestamp: `2026-02-24T13:22:52Z`
- Type: `change`
- Summary: Restored blockchain update submissions for non-confirmable deeploy operations in async path.
- Criticality: Operational correctness for blockchain state updates when chainstore confirmations are disabled.
- Details: When response keys are absent, async create/update now submits node updates for non-confirmable jobs; scale-up submits confirmations using combined new/update nodes. Tests adjusted to override the mangled balance-check method without touching production behavior.
- Verification: Not run (not requested).
- Links: `extensions/business/deeploy/deeploy_manager_api.py`, `extensions/business/deeploy/test_deeploy.py`

- ID: `ML-20260224-003`
- Timestamp: `2026-02-24T14:01:46Z`
- Type: `change`
- Summary: Fixed pending deeploy timeout cleanup and scale-up confirmation node extraction.
- Criticality: Correctness in deferred deploy processing and confirmation logic.
- Details: Timeout handler now uses pending_id from state and handles missing `now`; scale-up finalization extracts nodes from status entries safely.
- Verification: Not run (not requested).
- Links: `extensions/business/deeploy/deeploy_manager_api.py`

- ID: `ML-20260317-001`
- Timestamp: `2026-03-17T21:14:35Z`
- Type: `change`
- Summary: Elevated `AGENTS.md` into the authoritative repo contract for ownership, safe-editing, verification, structured handoffs, and agent execution loops.
- Criticality: Foundation governance change affecting all future agent edits, delegations, reviews, and operator-facing documentation updates.
- Details: Added repo purpose/runtime constraints, ownership table, safe-edit boundaries, required verification matrix, role-based agent cards, A2A-style task contract, mandatory handoff envelope, single-agent loop, actor-critic workflow, reusable lessons-learned section, worked examples, and explicit AGENTS review triggers. Critic concerns addressed in the update: keep single-agent as default to avoid unnecessary delegation, require executable evidence for actor-vs-critic disputes, and keep memory logging critical-only instead of turning the file into an activity log.
- Verification: `sed -n '1,260p' AGENTS.md`; `rg -n "Module And File Ownership|Safe-Edit Boundaries|Required Verification Commands|Agent Cards|A2A-Style Task Contract|Actor-Critic|AGENTS Review Triggers|ML-20260317-001" AGENTS.md`
- Links: `AGENTS.md`
