# Agent Workflows and Roles

This reference holds detailed execution guidance for coding agents working in `edge_node`. The root
[`AGENTS.md`](../AGENTS.md) remains the concise repository contract. Treat these as working roles: one
agent may move through several roles, and delegation is useful only when scope and ownership remain
clear.

## Orchestrator

- **Objective:** frame the requested outcome, choose the smallest reliable workflow, and keep work
  within approved repository and safety boundaries.
- **Routing/write scope:** read across the repository; assign bounded scopes; write governance or task
  notes only when those artifacts are part of the task.
- **Expected evidence:** explicit acceptance criteria, affected areas, branch state, verification plan,
  and final risk summary.
- **Escalate when:** ownership is ambiguous, the task crosses repositories or sensitive boundaries,
  or repeated attempts produce no new executable evidence.

## Runtime-Config Actor

- **Objective:** maintain startup configuration, packaging, environment-driven behavior, and
  entrypoint-adjacent runtime files.
- **Routing/write scope:** root configs, `constants.py`, `.env.template`, dependency manifests,
  Dockerfiles, and version metadata; modify `device.py` only when explicitly required.
- **Expected evidence:** compile or image-build results, configuration compatibility, and environment
  or migration assumptions.
- **Escalate when:** startup lifecycle, secret material, base-image behavior, or upstream
  `naeural_core` contracts are affected.

## Business-Extension Actor

- **Objective:** implement and maintain business APIs, supervisors, and production business plugins
  without leaking changes into unrelated runtime surfaces.
- **Routing/write scope:** `extensions/business/**`, matching tests, and `plugins/business/**` when a
  real production or tutorial contract explicitly requires it.
- **Expected evidence:** focused request/response or plugin tests and a note of user-visible or
  operator-visible behavior.
- **Escalate when:** auth, payments, blockchain state, tunnels, cross-repository contracts, or
  deployment behavior changes.

## Serving-Data Actor

- **Objective:** maintain capture integrations, serving adapters, shared extension utilities, and
  model or data plugins.
- **Routing/write scope:** `extensions/data/**`, `extensions/serving/**`, `extensions/utils/**`,
  `plugins/data/**`, `plugins/serving/**`, and matching tests.
- **Expected evidence:** focused serving or data tests, input/output contract checks, and runtime or
  model compatibility notes.
- **Escalate when:** external services, model artifacts, runtime dependencies, or cross-boundary
  configuration must change.

## Ops-Infra Actor

- **Objective:** maintain operator commands, development containers, image builds, compose stacks,
  Kubernetes manifests, and active CI workflows.
- **Routing/write scope:** `cmds/**`, `.devcontainer/**`, `docker/**`, `docker-compose/**`, `k8s/**`,
  and `.github/workflows/**`; treat `github_workflows/**` as legacy unless explicitly reactivated.
- **Expected evidence:** rendered configuration, build or dry-run results, operator impact, and a
  concrete rollback path.
- **Escalate when:** a command is destructive, secrets or publishing are involved, production rollout
  semantics change, or the required target environment is unavailable.

## Critic

- **Objective:** challenge whether a proposed or completed change is correct, safe, operable, and
  sufficiently verified.
- **Routing/write scope:** read-only by default; review the task scope, diff, tests, logs, docs, and
  rollback plan without widening the implementation casually.
- **Expected evidence:** severity-ordered findings, missing-test or missing-runbook risks, and an
  accept-or-block verdict tied to observable evidence.
- **Escalate when:** claims cannot be verified, rollback is unclear, or security, privacy, data-loss,
  deployment, or alert-noise risks remain unresolved.

## Integrator/Test-Executor

- **Objective:** resolve actor-versus-critic disagreements with executable evidence and close the
  verification loop.
- **Routing/write scope:** run tests and inspect diffs without code writes by default; change tests or
  integration glue only under an explicitly bounded scope.
- **Expected evidence:** exact commands, observed results, comparison with acceptance criteria, and a
  final evidence-backed decision.
- **Escalate when:** results conflict, failures are nondeterministic, or the required environment
  cannot be reproduced safely.

## Documentation Curator

- **Objective:** keep repository instructions and operator documentation concise, discoverable, and
  aligned with current code and deployment behavior.
- **Routing/write scope:** root and subsystem `AGENTS.md` files, `README.md` files, and focused durable
  references under `docs/`; do not turn them into task-history logs.
- **Expected evidence:** checked links, code-backed commands and claims, clear ownership of durable
  facts, and an intentional documentation diff.
- **Escalate when:** sources of truth disagree, a documentation edit would hide a code defect, or the
  proposed guidance is likely to become stale task history.

## Single-Agent Workflow

Use this workflow by default for every meaningful change. Keep one concern in each loop.

1. **Plan:** define the outcome, bounded write scope, assumptions, acceptance criteria, and narrowest
   useful verification.
2. **Implement:** make the smallest coherent change that addresses the concern.
3. **Test:** run the narrow check first, inspect the observed result, then broaden in proportion to
   regression risk.
4. **Critique:** challenge environment assumptions, behavior, security/privacy, operator noise,
   rollback, and maintainability—in that order.
5. **Revise:** change only what executable evidence or a concrete risk justifies.
6. **Verify:** rerun the final proof and hand off changed files, results, limitations, and open risks.

Do not replace a failing check with speculation. If the same concern fails twice without new evidence,
escalate. Stop after three unsuccessful loops rather than retrying blindly.

## Actor-Critic Workflow

Use this workflow when silent regression risk is high, the change is security- or operator-sensitive,
or an independent challenge materially improves confidence.

1. The actor states intent, scope, assumptions, invariants, rollback approach, and planned tests.
2. The actor implements and tests only inside that scope.
3. The critic independently reviews correctness, security/privacy, operator noise, rollback hazards,
   and missing tests or runbook impact.
4. The integrator/test-executor resolves disagreements with executable evidence rather than authority
   or preference.
5. The actor addresses supported findings and reruns the affected checks.
6. Final verification records the evidence, accepted residual risks, and completion verdict.

The critic may block on correctness or safety but should not widen scope for stylistic preferences. If
the deciding evidence cannot be obtained safely, escalate instead of treating uncertainty as a pass.
