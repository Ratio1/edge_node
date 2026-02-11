# Edge Node Agent Manual + Long-Term Memory

This file is the durable operating manual for future agents working in `/edge_node`.
It has two goals:
1. Stable reference information that should remain useful across sessions.
2. Append-only memory of important discoveries, decisions, and changes.

## Hard Rules
- Treat this file as append-only memory for the `Memory Log` section.
- Never delete or rewrite prior memory entries.
- If an older entry is wrong, add a new correction entry that references the old entry ID.
- Use UTC timestamps in ISO-8601 format: `YYYY-MM-DDTHH:MM:SSZ`.
- Keep shell examples copy-pasteable.

## Stable Reference

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

### How To Test
- Tutorial-oriented unittest discovery (repo-local):
  - `python3 -m unittest discover -s plugins -p "*test*.py"`
- Focused cybersecurity tests:
  - `python3 -m unittest extensions.business.cybersec.red_mesh.test_redmesh`
- When touching cross-repo integration (`naeural_core`, `ratio1_sdk`), also run targeted tests in those sibling repos.

### Repo Map
- Runtime entrypoints:
  - `device.py`: delegates execution to `naeural_core.main.entrypoint.main(...)`.
  - `constants.py`: extends upstream admin pipeline and environment-driven config.
- Extensions:
  - `extensions/business/`: operational APIs and supervisors (deeploy, dauth, oracle sync, tunnels, r1fs, container apps, cybersec).
  - `extensions/data/`: listener/capture extensions (Jeeves listeners).
  - `extensions/serving/`: serving backends, LLM/document embedding infrastructure, default inference adapters.
  - `extensions/utils/`: utility helpers.
- Plugins:
  - `plugins/business/tutorials/`: examples/regressions for common pipeline behaviors.
  - `plugins/data/tutorials/`: capture stream examples.
  - `plugins/serving/`: serving pipeline/inference examples and test scaffolding.
- Operations:
  - `cmds/`: in-container operational commands (`get_node_info`, `add_allowed`, `reset_node_keys`, etc.).
  - `docker-compose/`: debug/prod multi-container compose files and Windows helpers.
  - `docker/`: alternative Dockerfiles for CPU/RPi/Tegra variants.
  - `k8s/`: Kubernetes manifests.
- Research and spikes:
  - `xperimental/`: non-production exploratory scripts and notes.

### Conventions
- Python style in this repo commonly uses 2-space indentation and `snake_case` names.
- Keep module-level `__VER__` where applicable to plugin-style modules.
- Extend configs via dict merge patterns, e.g. `CONFIG = {**BASE, **overrides}`.
- Keep sensitive values env-driven (`$EE_*`) in config JSON/Python defaults.
- Use `self.P(...)` logging style in plugin classes.
- Commit style expectation: Conventional Commits (`feat:`, `fix:`, `chore:`).

### Known Pitfalls
- Image tag mismatch:
  - `debug.sh` builds `local_node`, while `docker-compose/debug-docker-compose.yaml` expects `local_edge_node`.
- Stale Windows helper:
  - `docker-compose/debug_start.bat` references `Dockerfile_dev`, which does not exist (available: `Dockerfile_devnet`, `Dockerfile_mainnet`, `Dockerfile_testnet`).
- Kubernetes inconsistencies to verify before use:
  - `k8s/README.md` says `edgenode-deployment.yaml`, file is `k8s/edgenode-deploy.yaml`.
  - `k8s/edgenode-sa.yaml` binds ServiceAccount namespace `hyfy` while resources are under `ratio1`.
  - `k8s/edgenode-deploy.yaml` uses `claimName: edgenode-supervisor-pvc`, but `k8s/edgenode-storage.yaml` defines `edgenode-pvc`.
  - `k8s/edgenode-deploy.yaml` mounts `/edgenode/_local_cache` (note missing underscore compared to `/edge_node/...` used elsewhere).
- Legacy workflow folder:
  - `.github/workflows/` is active for GitHub Actions.
  - `github_workflows/` appears legacy and references filenames/paths that may be stale.

## Mandatory BUILDER-CRITIC Loop (Required)

Run this loop for every meaningful modification (code, config, docs, infra, tests).
A "meaningful modification" is any change beyond trivial typo-only edits.

### Step 1: BUILDER
BUILDER must state:
- Intent: what is being changed and why.
- Change scope: files/paths touched.
- Assumptions: dependencies, environment, invariants.

### Step 2: CRITIC (Adversarial)
CRITIC must try to break the change by checking:
- Assumption failures.
- Behavioral regressions.
- Security/privacy risks.
- Edge cases and failure modes.
- Missing docs/tests or operational runbook impact.

### Step 3: BUILDER Response
BUILDER must:
- Address CRITIC findings or justify accepted risk.
- Refine the change if needed.
- List verification commands run and observed results (pass/fail + short evidence).

### Step 4: Log It
Append a `Memory Log` entry with:
- Timestamp and entry ID.
- Summary of change and decision.
- CRITIC findings summary.
- Verification commands and outcomes.
- If correction: `Correction of: <entry_id>`.

## Memory Log (append-only)

Entry format:
- `ID`: `ML-YYYYMMDD-###`
- `Timestamp`: UTC ISO-8601
- `Type`: discovery | decision | change | correction
- `Summary`:
- `Details`:
- `Verification`:
- `Links`:

---

- ID: `ML-20260211-001`
- Timestamp: `2026-02-11T09:13:34Z`
- Type: `discovery`
- Summary: Repo-wide docs/ops audit performed to ground AGENTS/README rewrite.
- Details: Confirmed runtime entrypoints (`device.py`, `constants.py`), operational scripts (`cmds/`), compose variants (`docker-compose/`), and deployment artifacts (`docker/`, `k8s/`).
- Verification: `pwd && ls -la`; `find . -maxdepth 2 -type d | sort`; `find extensions -type f`; `find plugins -type f`
- Links: `device.py`, `constants.py`, `docker-compose/debug-docker-compose.yaml`, `cmds/get_node_info`

- ID: `ML-20260211-002`
- Timestamp: `2026-02-11T09:13:34Z`
- Type: `discovery`
- Summary: Found operational mismatches that can break onboarding.
- Details: `debug.sh` builds `local_node` while debug compose expects `local_edge_node`; `docker-compose/debug_start.bat` references missing `Dockerfile_dev`; multiple `k8s/` naming/namespace/PVC path mismatches exist.
- Verification: `rg -n "local_edge_node|local_node" -S`; `sed -n '1,120p' debug.sh`; `sed -n '1,160p' docker-compose/debug_start.bat`; `sed -n '1,220p' k8s/README.md`; `sed -n '1,220p' k8s/edgenode-deploy.yaml`; `sed -n '1,220p' k8s/edgenode-sa.yaml`; `sed -n '1,220p' k8s/edgenode-storage.yaml`
- Links: `debug.sh`, `docker-compose/debug-docker-compose.yaml`, `docker-compose/debug_start.bat`, `k8s/README.md`, `k8s/edgenode-deploy.yaml`

- ID: `ML-20260211-003`
- Timestamp: `2026-02-11T09:13:34Z`
- Type: `change`
- Summary: Replaced prior short AGENTS guidance with durable long-term memory structure and mandatory BUILDER-CRITIC loop.
- Details: Added stable sections for run/test, repo map, conventions, pitfalls; established append-only log protocol with correction semantics.
- Verification: `sed -n '1,260p' AGENTS.md`
- Links: `AGENTS.md`

- ID: `ML-20260211-004`
- Timestamp: `2026-02-11T09:19:14Z`
- Type: `change`
- Summary: Rewrote `README.md` to prioritize operator usability and ordered sections as requested.
- Details: Added explicit Need/Objective/Purpose, moved all practical usage content under `Usability & Features` (quickstart/examples/config/outputs/troubleshooting), and placed architecture/modules/deps/testing/security under `Technical Details`.
- Verification: `git diff -- README.md`; `sed -n '1,320p' README.md`
- Links: `README.md`

- ID: `ML-20260211-005`
- Timestamp: `2026-02-11T09:19:14Z`
- Type: `discovery`
- Summary: Verification run identified environment/tooling limits and current test signal.
- Details: In this workspace, `docker` exists but neither `docker compose` plugin nor `docker-compose` binary is available; compose syntax could not be validated by execution. `python3 -m unittest discover -s plugins -p "*test*.py"` returns `Ran 0 tests`. Focused RedMesh suite runs but currently fails (`34` tests run, `1` failure, `3` errors with missing `service_info`/`web_tests_info` keys).
- Verification: `command -v docker || true; command -v python3 || true`; `docker compose -f docker-compose/debug-docker-compose.yaml config`; `docker-compose -f docker-compose/debug-docker-compose.yaml config`; `python3 -m unittest discover -s plugins -p "*test*.py"`; `python3 -m unittest extensions.business.cybersec.red_mesh.test_redmesh`
- Links: `README.md`, `AGENTS.md`, `extensions/business/cybersec/red_mesh/test_redmesh.py`

- ID: `ML-20260211-006`
- Timestamp: `2026-02-11T09:20:06Z`
- Type: `change`
- Summary: Added Compose command compatibility note (`docker-compose` and Compose v2 `docker compose`) in stable docs.
- Details: Kept primary examples aligned to repo scripts (`docker-compose`) while explicitly documenting the Compose v2 equivalent to reduce operator ambiguity.
- Verification: `rg -n "docker-compose|docker compose" AGENTS.md README.md`
- Links: `AGENTS.md`, `README.md`
