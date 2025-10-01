# Repository Guidelines

## Project Structure & Module Organization
The edge node runtime is anchored by `device.py` and `constants.py`, which orchestrate Ratio1 pipelines via `naeural_core`. Domain extensions live under `extensions/`, split into `business/`, `data/`, and `serving/` packages that register plugins and configs. Operational helpers sit in `cmds/`, container recipes in `docker/` and `docker-compose/`, with tutorial engines in `plugins/` and sandboxes in `xperimental/`.

## Build, Test, and Development Commands
- `./debug.sh` builds `Dockerfile_devnet` and runs the node; adjust `.env` before invoking.
- `docker compose -f docker-compose/debug-docker-compose.yaml up -d` spins up a multi-service dev stack; tear it down with `docker compose down`.
- `python -m unittest discover -s plugins -p "*test*.py"` executes tutorial regressions; run it inside a virtualenv after `pip install -r requirements.txt`.

## Coding Style & Naming Conventions
Python modules use 2-space indentation, `snake_case` functions, and explicit `__VER__` constants for traceability; keep those patterns when adding code. Extend `CONFIG` dictionaries by unpacking base configs instead of mutating them, and keep environment keys uppercase to align with existing filters. Prefer readability, early returns, and explicit logging via `self.P(...)`; follow `sqlfluff` rules for SQL assets when applicable.

## Testing Guidelines
Target business workflows first: tutorial cases inside `plugins/business/tutorials/` and Oracle sync checks in `extensions/business/oracle_sync/`. Name new regression files `*test*.py` so they are discovered by the unittest command above, and rely on lightweight mocks instead of live network calls. For dockerized verification, attach to a running node (`docker exec -it r1node /bin/bash`) and replay scripts from `cmds/` to confirm end-to-end behavior.

## Commit & Pull Request Guidelines
Recent history follows Conventional Commits (`fix:`, `chore:`, `feat:`); keep subject lines under 72 characters and describe intent in the body when needed. Each pull request should bundle related module edits, note impacted services, and link Jira or GitHub issues where applicable. Include manual or automated test evidence in the PR description—command output, docker-compose logs, or screenshots for web plugins—so reviewers can replay results quickly.

## Security & Configuration Tips
Never commit populated `.env` files; document required keys and rely on secret stores. Validate tunnel and storage credentials with the helpers in `cmds/get_config_app`, and scrub logs of identifiers before sharing. When updating pipelines in `constants.py`, confirm sensitive env var names stay templated (`$VAR`) so container deployments inject them securely.
