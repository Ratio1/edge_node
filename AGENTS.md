# Repository Guidelines

## Project Structure & Module Organization
- Runtime entrypoints live in `device.py` and `constants.py`, orchestrating Ratio1 pipelines implemented in the upstream `naeural_core` package.
- Domain extensions under `extensions/` (`business/`, `data/`, `serving/`) wrap `naeural_core` plugins and configs; mirror their folder names when porting modules from `naeural_core`.
- Tutorials and sample engines are in `plugins/`; use `plugins/business/tutorials/` alongside the `ratio1_sdk/tutorials/` repository samples when validating workflows.
- Operational helpers sit in `cmds/`, container specs live in `docker/` and `docker-compose/`, and research spikes belong in `xperimental/`.

## Build, Test, and Development Commands
- `./debug.sh` builds `Dockerfile_devnet` and launches the node; sync `.env` with secrets documented in `ratio1_sdk/template.env` before running.
- `docker compose -f docker-compose/debug-docker-compose.yaml up -d` provisions the full dev stack; use `docker compose down` to clean up.
- `pip install -r requirements.txt` inside a virtualenv prepares local dependencies; add `pip install -e ../naeural_core ../ratio1_sdk` when testing cross-repo changes.
- `python -m unittest discover -s plugins -p "*test*.py"` executes tutorial regressions; mirror failing cases in `ratio1_sdk/tutorials/` as needed.

## Coding Style & Naming Conventions
- Python files use 2-space indentation, `snake_case` function names, and explicit `__VER__` constants (aligned with `naeural_core/__init__.__VER__`).
- Extend configuration via dict unpacking (`CONFIG = {**BASE_CONFIG, **local_overrides}`) and keep environment keys uppercase.
- Log through `self.P(...)`, matching `naeural_core.manager.ManagerMixin` patterns; run `sqlfluff` on SQL assets before committing.

## Testing Guidelines
- Prioritize business workflows in `plugins/business/tutorials/` and Oracle sync checks in `extensions/business/oracle_sync/`.
- Name new regression files `*test*.py` so they are auto-discovered; when editing shared pipeline logic, also run `pytest` (or `python -m unittest`) inside cloned `naeural_core` and targeted SDK tutorials.
- Prefer lightweight mocks to live services; for container checks, attach with `docker exec -it r1node /bin/bash` and replay scripts from `cmds/`.

## Commit & Pull Request Guidelines
- Follow Conventional Commits (`feat:`, `fix:`, `chore:`); keep subjects under 72 characters and describe intent in the body when needed.
- Group related module edits, note which services or SDK tutorials are impacted, and link Jira/GitHub issues across repositories.
- Provide evidence of manual or automated runs (command output, compose logs, SDK tutorial snippets) so reviewers can reproduce results quickly.

## Security & Configuration Tips
- Never commit populated `.env` files; document required secrets instead and re-use `ratio1_sdk/template.env` as reference.
- Validate tunnel and storage credentials with `cmds/get_config_app` helpers.
- When editing `constants.py`, keep sensitive env vars templated (`$VAR`) so container deployments inject values securely.
