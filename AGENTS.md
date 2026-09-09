# Edge Node agent guide

This is the root operating contract for coding agents in `edge_node`. Keep it limited to stable,
repository-specific rules; nearer `AGENTS.md` files override it. Use the
[agent workflow reference](docs/agent-workflows.md) for detailed roles and execution loops, and the
[devcontainer guide](.devcontainer/README.md) for container-specific setup and checks.

## Core context

`edge_node` packages the Ratio1 node runtime and owns repository-local extensions, plugins, commands,
and deployment surfaces. `naeural_core` owns the runtime engine and base plugin contracts;
`ratio1_sdk` provides the `ratio1` package and client/workload APIs. Local directories with those names
are independent checkouts: follow their instructions and commit there separately.

`device.py` is a deliberately thin entrypoint. Treat it as frozen unless startup behavior must change
and the work cannot live in `constants.py`, an extension, or an upstream project. Production behavior
normally belongs under `extensions/`; `plugins/` is primarily tutorial/example code unless a
production path imports it.

## Repository map

- Runtime entrypoints: `device.py` delegates to `naeural_core`; `constants.py` extends runtime config.
- Extensions: `extensions/business/` owns operational APIs; `extensions/data/`,
  `extensions/serving/`, and `extensions/utils/` own capture, serving, and shared extension behavior.
- Plugins: `plugins/business/`, `plugins/data/`, and `plugins/serving/` hold tutorial, sample, and test
  plugin surfaces unless production code explicitly imports them.
- Operations: `cmds/`, `.devcontainer/`, `docker/`, `docker-compose/`, `k8s/`, and
  `.github/workflows/`; `github_workflows/` is legacy unless explicitly reactivated.
- Research: `xperimental/` is non-authoritative until work is promoted into an owned production path.

## Workflow and routing

Use the single-agent workflow by default. Use the actor-critic workflow when silent regression risk is
high or work is security-, deployment-, or operator-sensitive. The linked workflow reference defines
both processes, role ownership, expected evidence, and escalation triggers.

- Devcontainer work: read the devcontainer guide, `devcontainer.json`, and `Dockerfile`; validate the
  resolved configuration, rebuild, and verify Python/imports in the resulting container.
- RedMesh backend work: first read `extensions/business/cybersec/red_mesh/AGENTS.md` and use its tests.
- Upstream behavior: change `naeural_core` or `ratio1_sdk` in their own repositories rather than
  hiding the requirement in an Edge compatibility shim; add Edge integration evidence when needed.
- Operator surfaces require explicit impact and rollback review. Active workflows may publish images
  or tags.

## Verification

Use the intended devcontainer/runtime container when host imports or test tooling are unavailable. Do
not install persistent host dependencies merely to make a check runnable. Record relevant image,
Python, and device assumptions for environment-sensitive work.

Common patterns:

```bash
python3 -m py_compile path/to/changed.py
python3 -m unittest discover -s path/to/tests -p 'test_*.py'
devcontainer build --workspace-folder .
```

- Match checks to the changed contract and inspect output for skipped work and handled failures.
- Add focused regression coverage for bugs when practical.
- If a broad suite is baseline-red, report the exact failure and prove the changed concern narrowly.
- Never weaken tests or production behavior to obtain green output.

## Repository conventions

- Use the existing two-space Python indentation and `snake_case` names.
- Keep module-level `__VER__` values where the surrounding plugin modules use them.
- Extend configs with existing dict-merge patterns such as `CONFIG = {**BASE, **overrides}`.
- Keep sensitive configuration environment-driven through `$EE_*` variables or deployment secrets.
- Use plugin logging conventions such as `self.P(...)` where present.
- Use focused Conventional Commit summaries (`feat:`, `fix:`, `docs:`, `chore:`, and similar).

## Implementation and safety boundaries

- Prefer repository-local extension points without duplicating upstream runtime or SDK behavior.
- Keep validation at API, storage, security, and other external boundaries.
- Never log or commit populated `.env` files, keys, wallet material, authorization documents, tokens,
  credentials, or customer targets.
- Treat `_local_cache/`, bytecode, model data, logs, and local dependency checkouts as runtime or local
  state; never edit or commit them as source.
- Live scans, deployments, blockchain writes, whitelist changes, `cmds/reset_*`, purge/delete actions,
  and container or volume removal require explicit scope and exact targets. Inspect first and prefer
  dry-run or preview paths.
- Do not modify `device.py`, active CI, publishing paths, or shared auth/security contracts as a
  drive-by fix.

## Git discipline

- Work on the branch named by the user or task. Do not switch, rebase, merge, push, or open a PR unless
  the current workflow authorizes it.
- Create new branches from an up-to-date `develop`, never `main`; never push to `main`.
- Never push directly to `develop` without explicit approval for that push.
- Preserve dirty state and stage exact paths; never use `git add -A` in a mixed worktree.
- Never commit dependency checkouts, caches, runtime data, generated files, secrets, or unrelated user
  changes.
- Never rewrite pushed/shared history or force-push without explicit approval.
- Before handoff, run `git diff --check`, inspect the staged diff, and report intentionally uncommitted
  work.

## Durable context and completion

- Keep this file free of task progress, detailed role cards, execution-loop detail, and memory logs.
- Put subsystem truths in the nearest README or `AGENTS.md`; prefer executable checks over reminders.
- For long work, maintain a concise task/plan artifact with scope, decisions, progress, validation, and
  restart instructions.
- A change is complete only when scope is delivered, the diff is intentional, relevant checks pass or
  are honestly bounded, failure modes are reviewed, and remaining risks are explicit.
