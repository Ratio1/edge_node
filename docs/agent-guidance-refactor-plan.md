# Agent Guidance Refactor Plan

## Status

- Base revision: `318cb5a`
- Branch: `fix/agents-md`
- Effective autonomy: L1 (local edits, checks, and phase commits)
- Specification source: approved conversational plan from 2026-08-05

## Goal

Keep the root agent contract concise while restoring useful repository routing, conventions, role
cards, and execution workflows, and while making the referenced devcontainer guidance real.

## Phases

- [x] Add `docs/agent-workflows.md` with the eight condensed roles and the single-agent and
  actor-critic workflows. Commit this file together with the normalized plan record.
- [ ] Add `.devcontainer/README.md` with setup, rebuild, configuration, and verification guidance.
- [ ] Refine root `AGENTS.md` after both targets exist: remove duplication, retain a compact repository
  map and conventions, and link to both detailed documents.

## Acceptance Criteria

- Root `AGENTS.md` stays concise and contains no duplicate ownership table or detailed role cards.
- `_local_cache` appears once in root `AGENTS.md`, in guidance spanning at most two physical lines.
- The workflow guide defines Orchestrator, Runtime-Config Actor, Business-Extension Actor,
  Serving-Data Actor, Ops-Infra Actor, Critic, Integrator/Test-Executor, and Documentation Curator.
- Every role defines its objective, routing/write scope, expected evidence, and escalation triggers.
- Detailed single-agent and actor-critic workflows live outside root `AGENTS.md` and are linked from it.
- `.devcontainer/README.md` exists and matches the checked-in devcontainer configuration.
- The final change is documentation-only and passes link, content, and whitespace checks.
- Root `AGENTS.md` is no longer than 125 lines and contains neither detailed role cards nor a detailed
  execution-loop sequence.

Only the pre-PR role-card and execution-loop concepts are source material. Active-refactor history,
memory logs, A2A/task-envelope boilerplate, ownership and verification tables, and worked examples do
not return.

The devcontainer guide must document the `/edge_node` bind mount, root build context, fixed `r1edge`
container name and hostname, privileged/default-CPU behavior, mutable `latest` base image, root
`requirements.txt` installation, unused `.devcontainer/requirements.txt`, and build/up/exec checks.

## Checks

```bash
git diff --check 318cb5ac..HEAD
test -f docs/agent-workflows.md
test -f .devcontainer/README.md
rg -nF '[agent workflow reference](docs/agent-workflows.md)' AGENTS.md
rg -nF '[devcontainer guide](.devcontainer/README.md)' AGENTS.md
for heading in 'Orchestrator' 'Runtime-Config Actor' 'Business-Extension Actor' \
  'Serving-Data Actor' 'Ops-Infra Actor' 'Critic' 'Integrator/Test-Executor' \
  'Documentation Curator' 'Single-Agent Workflow' 'Actor-Critic Workflow'; do
  rg -nF "## $heading" docs/agent-workflows.md
done
! rg -n '^### (Orchestrator|Runtime-Config Actor|Business-Extension Actor|Serving-Data Actor|Ops-Infra Actor|Critic|Integrator/Test-Executor|Documentation Curator)$' AGENTS.md
test "$(rg -o '_local_cache' AGENTS.md | wc -l)" -eq 1
test "$(wc -l < AGENTS.md)" -le 125
devcontainer read-configuration --workspace-folder . --include-merged-configuration
git diff --name-only 318cb5ac..HEAD | diff -u <(printf '%s\n' \
  .devcontainer/README.md AGENTS.md docs/agent-guidance-refactor-plan.md \
  docs/agent-workflows.md | sort) -
```

## Execution Log

- 2026-08-05: Normalized the approved plan. Resolved `fix/agents-md` as the explicit task branch,
  `318cb5a` as the base revision, and L1 as the effective autonomy. No tracked or untracked changes
  were present before execution.
- 2026-08-05: Independent architecture review returned `REVISE`. Reordered the phases so root routing
  changes land only after both linked documents exist; enumerated role and devcontainer content;
  excluded stale historical/process material; and strengthened link, scope, structure, and size checks.
- 2026-08-05: Phase 1 added the workflow reference with all eight condensed roles and the default
  single-agent and higher-risk actor-critic workflows. Stale memory-log duties were replaced with a
  current Documentation Curator role; Ops-Infra ownership now includes `.devcontainer/**`.
