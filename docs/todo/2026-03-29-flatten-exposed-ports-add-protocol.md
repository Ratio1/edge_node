# Flatten EXPOSED_PORTS Tunnel Config + Add Protocol Support

**Date:** 2026-03-29
**Status:** Planned
**Repos:** `edge_node` (backend), `deeploy-dapp` (frontend)

---

## Problem

The current `EXPOSED_PORTS` shape is heavier than necessary for tunnel settings, and extra tunnel commands still hardcode `http://127.0.0.1:{port}`.

Current user-facing shape:

```python
"3000": {
    "container_port": 3000,          # redundant in external config; dict key already identifies the port
    "is_main_port": True,
    "host_port": None,
    "tunnel": {
        "enabled": True,
        "engine": "cloudflare",
        "token": "cf-token"
    }
}
```

Current runtime reality:
- `EXPOSED_PORTS` is already the normalized config surface for CAR.
- Main tunnel protocol already exists globally through legacy Cloudflare config.
- Extra tunnels are custom CAR logic and still hardcode `http://`.
- Health checks are a separate readiness subsystem and should not be coupled to tunnel protocol.

## Goals

- Flatten the user-facing tunnel config inside `EXPOSED_PORTS`.
- Add per-port tunnel `protocol` support.
- Preserve backward compatibility for existing nested `tunnel` payloads and legacy CAR fields.
- Keep health check configuration separate from tunnel configuration.
- Add an explicit global way to disable health gating.

## Non-Goals

- No per-port health-check gating in this change.
- No removal of legacy `PORT`, `CLOUDFLARE_TOKEN`, `EXTRA_TUNNELS`, or `TUNNEL_ENGINE_PARAMETERS` support in this change.
- No assumption that `EXPOSED_PORTS` is unused; migration must be backward compatible.

## Proposed User-Facing EXPOSED_PORTS Shape

```python
"3000": {
    "is_main_port": True,
    "host_port": None,               # explicit host port mapping, None = auto-allocate
    "token": "cf-token",             # present = tunnel enabled, missing/None = no tunnel
    "protocol": "http",              # tunnel origin protocol, default "http"
    "engine": "cloudflare",          # default "cloudflare"
    "max_retries": None,             # override global TUNNEL_RESTART_MAX_RETRIES
    "backoff_initial": None,         # override global TUNNEL_RESTART_BACKOFF_INITIAL
    "backoff_max": None,             # override global TUNNEL_RESTART_BACKOFF_MAX
}
```

Notes:
- `container_port` should be removed from the external payload shape.
- Keeping `container_port` in the internal normalized runtime cache is acceptable if it simplifies current code paths.
- `token` replaces `tunnel.enabled + tunnel.token` at the external config layer.
- `engine` remains explicit for forward compatibility, but for this phase only `"cloudflare"` is supported at the per-port level.

## Backward Compatibility

Compatibility is required.

Backend must accept all of the following during migration:

1. Flat input:

```python
"3000": {
    "is_main_port": True,
    "token": "cf-token",
    "protocol": "tcp",
}
```

2. Existing nested input:

```python
"3000": {
    "is_main_port": True,
    "tunnel": {
        "enabled": True,
        "engine": "cloudflare",
        "token": "cf-token",
    }
}
```

3. Legacy CAR fields:
- `PORT`
- `CONTAINER_RESOURCES["ports"]`
- `CLOUDFLARE_TOKEN`
- `EXTRA_TUNNELS`
- `TUNNEL_ENGINE_PARAMETERS`

Normalization rules:
- Flat config becomes the canonical internal model.
- Nested `tunnel` config is still accepted and normalized into the flat internal tunnel fields.
- Explicit `EXPOSED_PORTS` still takes precedence over legacy fields.
- Frontend recovery/edit paths should continue to read both flat and nested shapes during migration.

Conflict resolution inside a single `EXPOSED_PORTS[port]` entry:
- Flat fields win over nested `tunnel` fields when both are present.
- Conflicting flat vs nested values should emit a deprecation warning in logs.
- Matching flat+nested values are tolerated during migration.
- If nested `tunnel.enabled` is `False` but flat `token` is present, flat `token` wins and the tunnel is considered enabled.
- Retry overrides are read from flat fields only.

Protocol precedence for the main tunnel:
- Flat main-port `protocol`
- Then legacy nested tunnel-derived protocol if nested tunnel protocol support is added during migration
- Then legacy `CLOUDFLARE_PROTOCOL` / `TUNNEL_ENGINE_PARAMETERS`
- Then default `"http"`

Engine rules for this phase:
- Per-port `engine` may be omitted or set to `"cloudflare"`.
- Any other per-port engine value should be rejected.
- If global `TUNNEL_ENGINE` is set to a non-Cloudflare engine, per-port Cloudflare tunnel settings are out of scope for this phase and should fail clearly rather than degrade silently.

## Rollout / Version Skew

This change crosses backend and frontend boundaries, so rollout order matters.

Required rollout policy:
- Ship backend compatibility support first.
- Only after backend support is deployed should the frontend default to writing the flat shape.
- During migration, the frontend should continue recovering both flat and nested shapes.

Recommended safety options:
- Feature-flag flat-shape writes in the frontend until the minimum supported backend version is deployed.
- If dual-write is considered, define it explicitly first; do not assume dual-write semantics implicitly.

Non-goal for this phase:
- No requirement that old backends must understand newly emitted flat payloads without the compatibility backend patch.

Planned migration end-state:
- Phase A: backend accepts flat + nested + legacy inputs; frontend reads both flat and nested.
- Phase B: frontend writes flat shape by default once backend rollout is complete.
- Phase C: nested `tunnel` input remains accepted but is considered deprecated.
- Phase D: optional later cleanup can remove nested input support in a separate breaking-change phase, not in this rollout.

## Supported Tunnel Protocols

Initial allowed set:

- `"http"` (default)
- `"https"`
- `"tcp"`
- `"ssh"`
- `"rdp"`
- `"smb"`

This field controls the tunnel origin URL scheme only. It does not automatically change health-check behavior.

Operability note:
- Non-HTTP protocols are not equivalent to “open this in a browser”.
- For Cloudflare-backed TCP/SSH/RDP/SMB style access, the user/client workflow may differ from the normal HTTPS tunnel case.
- The backend should avoid over-promising browser-URL semantics for non-HTTP exposed ports.

## Health Check Direction

Health checks stay separate from `EXPOSED_PORTS` tunnel config.

Current runtime model:
- Health gating is global for the app, not per port.
- Startup readiness resolves through `HEALTH_CHECK`, then enables main and extra tunnel startup.
- `HEALTH_CHECK.PORT` can target one configured container port, but there is still only one app-level readiness state.

Planned change:
- Add explicit `HEALTH_CHECK.MODE = "disabled"` (or `"none"`; pick one and use it consistently).
- Disabled health check should skip active probing and avoid blocking tunnel startup.
- Default behavior should remain centered on the main port only.

Implications:
- Do not add per-port `health_enabled` flags in this change.
- If per-port health is needed later, it should be designed as a separate nested `health_check` structure plus per-port readiness/tunnel gating.

Required semantics for disabled mode:
- `disabled` means the app becomes ready for tunnel startup as soon as the container is running.
- `disabled` bypasses active endpoint/TCP probing entirely.
- `disabled` should not wait for `HEALTH_CHECK.DELAY`.
- Semaphore readiness follows the same readiness decision as tunnel startup; no special alternate path should be introduced.
- Invalid health configuration should keep the current fallback behavior unless intentionally changed in code and docs together.

Health config validation requirements:
- `port`: integer or null
- `delay`: non-negative number
- `interval`: non-negative number
- `timeout`: non-negative number
- `on_failure`: one of the currently supported values
- `disabled` mode should ignore `delay`, `interval`, `timeout`, and `on_failure` operationally even if they are present in input

## Backend Changes

### `container_utils.py`

- **`_normalize_exposed_ports_value()`**
  - Accept both flat input and legacy nested `tunnel` input.
  - Normalize to a canonical internal tunnel config with `token`, `protocol`, `engine`, and optional retry overrides.
  - Validate protocol against the allowed set.
  - Preserve compatibility with current code paths that still read `container_port` from normalized state if needed.
  - Enforce clear validation rules for retry overrides:
    - `max_retries`: integer or null; `0` keeps existing “unlimited retries” semantics
    - `backoff_initial`: positive number or null
    - `backoff_max`: positive number or null
    - reject negative values
    - reject `backoff_max < backoff_initial` when both are set
    - reject retry override fields when no tunnel token is configured for that port
  - Enforce clear validation rules for engine:
    - allow missing engine
    - allow `"cloudflare"`
    - reject any other per-port engine value in this phase

- **`_build_exposed_ports_config_from_legacy()`**
  - Build flat tunnel fields from legacy main tunnel and `EXTRA_TUNNELS`.
  - Preserve existing precedence rules and warnings.

- **`_merge_legacy_exposed_port_entry()`**
  - Merge legacy config into the flat tunnel fields.
  - Continue rejecting conflicting definitions for the same port.

- **`_validate_extra_tunnels_config()`**
  - Stop storing extra tunnel runtime state as `{container_port: token}` only.
  - Build richer per-port runtime tunnel config objects so protocol and retry overrides are available later in the lifecycle.
  - The runtime object should be explicit enough to support:
    - token
    - protocol
    - engine
    - effective retry settings for that port

- **`_get_main_container_port()`**
  - May stop depending on normalized `container_port` values if convenient.
  - Internal retention of `container_port` is still acceptable; removing it from runtime cache is not required for this change.

### `container_app_runner.py`

- **Main tunnel**
  - **`_get_main_tunnel_config()`** should read the main port's normalized flat tunnel config.
  - **`get_cloudflare_token()`** should continue to prefer normalized main-port config.
  - **`get_cloudflare_protocol()`** should be overridden so the main tunnel can read protocol from normalized main-port config instead of only from legacy global config.
  - Main tunnel startup should follow the documented protocol precedence order and fail clearly on unsupported engine combinations.

- **Extra tunnels**
  - **`_build_tunnel_command(container_port, token, protocol="http")`** should use `f"{protocol}://127.0.0.1:{host_port}"`.
  - **`_start_extra_tunnel()`** should accept the richer per-port tunnel config, not just a token.
  - **`start_extra_tunnels()`** and **`_check_extra_tunnel_health()`** should work with the richer runtime config object.
  - Extra tunnel status/ping/log handling should no longer assume every tunnel is represented as a browser-friendly HTTPS URL.
  - Keep backward-compatible URL fields where they already exist, but add a more generic endpoint/access metadata field for non-HTTP protocols instead of overloading browser-URL semantics.

- **Retry overrides**
  - Per-port retry overrides affect more than tunnel startup.
  - The helper methods that calculate backoff and max-retry behavior must read effective values per port, with fallback to the existing global settings:
    - `TUNNEL_RESTART_MAX_RETRIES`
    - `TUNNEL_RESTART_BACKOFF_INITIAL`
    - `TUNNEL_RESTART_BACKOFF_MAX`
    - existing multiplier/reset-interval globals stay global unless there is an explicit reason to widen scope

- **Semaphore env**
  - Export `HOST_PROTOCOL` alongside `HOST_URL` for the main exposed port.
  - Keep legacy `HOST`, `PORT`, and `URL` semantics unchanged.
  - Document that for non-HTTP services, new consumers should prefer:
    - `HOST_PROTOCOL`
    - `HOST_IP`
    - `HOST_PORT`
  - Treat `URL` and `HOST_URL` as legacy convenience fields, not protocol-accurate universal connection descriptors.

### Health Check Integration

Health config remains global.

- Add `disabled`/`none` mode to `HEALTH_CHECK.MODE`.
- Disabled mode should bypass active readiness probing.
- Do not derive health-check URL scheme from port tunnel `protocol`.
- Existing `endpoint` mode should remain HTTP(S)-oriented and continue to use explicit `HEALTH_CHECK` inputs.
- Existing `tcp` mode remains the generic readiness probe for non-HTTP services.
- Validate `HEALTH_CHECK` values explicitly rather than relying only on runtime fallthrough behavior.

## Frontend Changes

### Type: `ExposedPortEntry`

```typescript
type ExposedPortEntry = {
    containerPort: number;
    isMainPort: boolean;
    token?: string;
    protocol?: string;
    engine?: string;
    maxRetries?: number;
    backoffInitial?: number;
    backoffMax?: number;
};
```

### UI: `ExposedPortsSection.tsx`

- Rename `cloudflareToken` input to `token`.
- Add protocol dropdown when tunnel token is present.
- Add an advanced section for per-port retry overrides.
- Continue recovering legacy nested `tunnel` data during edit hydration while the migration is in progress.

### Serialization

- Frontend should emit the flat shape for new writes.
- Frontend deserialization/recovery should continue accepting legacy nested `tunnel` shape during migration.
- Do not switch frontend default writes to flat shape until backend compatibility support is deployed.

### Schema

- Add optional `protocol`, `engine`, and retry override fields.
- Accept both flat and nested tunnel shapes during transition if schema constraints are enforced at the frontend boundary.
- Enforce the same retry validation constraints in frontend schema/tests to avoid drift from backend behavior.
- Enforce the same per-port engine restrictions in frontend schema/tests to avoid presenting unsupported options.

## Files Likely To Change

| File | Change |
|---|---|
| `extensions/business/container_apps/container_utils.py` | Flatten tunnel normalization, preserve compatibility, build richer per-port tunnel runtime config |
| `extensions/business/container_apps/container_app_runner.py` | Main/extra tunnel protocol support, main protocol override, per-port retry override plumbing, health mode disable support |
| `extensions/business/container_apps/tests/test_exposed_ports_model.py` | Flat shape assertions plus nested backward-compat coverage |
| `extensions/business/container_apps/tests/test_tunnel_runtime_behavior.py` | Protocol in tunnel commands, richer extra tunnel config, retry override behavior |
| `extensions/business/container_apps/tests/test_health_check_behavior.py` | Disabled health mode coverage and non-regression around default main-port behavior |
| `extensions/business/container_apps/tests/test_semaphore_exports.py` | `HOST_PROTOCOL` export and legacy-key non-regression |
| `AGENTS.md` | Update durable repo memory after rollout if the new flat tunnel shape becomes the documented normalized surface |
| `extensions/business/deeploy/tests/test_create_requests.py` | Preserve/accept flat shape and legacy nested shape |
| `extensions/business/deeploy/tests/test_update_requests.py` | Preserve/accept flat shape and legacy nested shape |
| `extensions/business/container_apps/README.md` | Update public config examples and migration notes |
| `deeploy-dapp` frontend files | Emit flat shape, recover both flat and nested shapes during migration |

## Verification

Backend:
1. `python3 -m unittest discover -s extensions/business/container_apps/tests -p "test_*.py"`
2. `python3 -m unittest discover -s extensions/business/deeploy/tests -p "test_*.py"`

Recommended focused backend gates:
3. `python3 -m unittest extensions.business.container_apps.tests.test_exposed_ports_model`
4. `python3 -m unittest extensions.business.container_apps.tests.test_tunnel_runtime_behavior`
5. `python3 -m unittest extensions.business.container_apps.tests.test_health_check_behavior`
6. `python3 -m unittest extensions.business.container_apps.tests.test_semaphore_exports`

Frontend (`deeploy-dapp`):
6. Existing dynamic env / exposed ports test scripts
7. `npm run lint`
8. `npx tsc --noEmit --incremental false`

## Implementation Notes

- Keep this change narrowly scoped to tunnel config flattening, protocol support, and global health disable support.
- Do not fold in a per-port health subsystem unless the runtime is also changed to support per-port readiness and per-port tunnel gating.
- Backward compatibility is part of the acceptance criteria for both backend and frontend migration paths.
- Before implementation starts, pick one exact spelling for the disabled health mode and use it consistently in backend, tests, docs, and frontend schema.
- After rollout, update durable docs (`AGENTS.md`, README, and any active operator-facing references) so the documented source of truth matches the shipped flat-shape behavior.
