# Container Apps

Container application plugins for running Docker containers with Cloudflare tunnel support.

## Table of Contents

- [Summary](#summary)
- [Plugins](#plugins)
- [Features](#features)
  - [Health Check Configuration](#health-check-configuration)
- [Configuration Reference](#configuration-reference)
  - [Local Env Overrides](#local-env-overrides)
  - [Reset](#reset)
  - [Volume Sync](#volume-sync)
  - [The Node's Docker Store](#the-nodes-docker-store)
- [Future Enhancements](#future-enhancements)
  - [Continuous Health Monitoring](#continuous-health-monitoring)
  - [Per-Port Health Checks](#per-port-health-checks)

---

## Summary

The Container Apps module provides plugins for managing Docker containers with integrated tunnel support. Key capabilities:

- **Container lifecycle management**: Start, stop, restart with configurable policies
- **Tunnel integration**: Automatic Cloudflare tunnel creation for exposed ports
- **Health probing**: Wait for app readiness before starting tunnels
- **Git integration**: Auto-restart on repository updates (WorkerAppRunner)

---

## Plugins

| Plugin | Description |
|--------|-------------|
| `ContainerAppRunnerPlugin` | Base plugin for running Docker containers with tunnel support |
| `WorkerAppRunnerPlugin` | Extends base with Git repository cloning and update monitoring |

---

## Features

- **Normalized exposed ports**: `EXPOSED_PORTS` is the forward-looking config surface for container port exposure and per-port tunnel settings.
- **Explicit semaphore networking keys**: container apps now publish `HOST_IP`, `HOST_PORT`, `CONTAINER_IP`, and `CONTAINER_PORT` in addition to legacy `HOST`, `PORT`, and `URL`.
- **UI-friendly dynamic env support**: Deeploy can compile `DYNAMIC_ENV_UI` fragments to backend `DYNAMIC_ENV` entries, including generic plugin semaphore lookups.
- **App-local control files**: apps can request local env overrides and fixed-volume resets through `/r1en_system`.

### Health Check Configuration

The plugin uses a consolidated `HEALTH_CHECK` configuration dict to determine when the application is ready before starting tunnels.

```python
"HEALTH_CHECK": {
    "MODE": "auto",        # "auto" | "tcp" | "endpoint" | "delay"
    "PATH": None,          # HTTP endpoint path (e.g., "/health", "/api/ready")
    "PORT": None,          # Container port for health check (None = use main PORT)
    "DELAY": 30,           # Seconds before first probe / full delay for "delay" mode
    "INTERVAL": 5,         # Seconds between probe attempts (tcp/endpoint modes)
    "TIMEOUT": 300,        # Max wait time in seconds (0 = unlimited)
    "ON_FAILURE": "start", # "start" | "skip" - behavior when timeout reached
}
```

**Health Check Modes:**

| Mode | Description |
|------|-------------|
| `"auto"` | Smart detection (default): uses "endpoint" if `PATH` is set, otherwise "tcp" if PORT is configured |
| `"tcp"` | TCP port check - works for any protocol (HTTP, WebSocket, gRPC, raw TCP). Simply checks if the port is accepting connections |
| `"endpoint"` | HTTP probe to `PATH` - expects 2xx response. Requires PATH to be configured |
| `"delay"` | Simple time-based delay using `DELAY` - no active probing |

**Configuration Options:**

| Key | Default | Description |
|-----|---------|-------------|
| `MODE` | "auto" | Health check strategy |
| `PATH` | None | HTTP endpoint path for "endpoint" mode |
| `PORT` | None | Container port (None = use main PORT) |
| `DELAY` | 30 | Initial delay before probing / full delay for "delay" mode |
| `INTERVAL` | 5 | Seconds between probe attempts |
| `TIMEOUT` | 300 | Max wait time (0 = unlimited, probe forever) |
| `ON_FAILURE` | "start" | Behavior on timeout: "start" (tunnel anyway) or "skip" (no tunnel) |

**Examples:**

```python
# TCP mode (default) - works for any protocol
"PORT": 3000,
"HEALTH_CHECK": {}
# → TCP probe to allocated host port until connection accepted

# Explicit TCP mode - useful for non-HTTP services (WebSocket, gRPC, etc.)
"PORT": 8080,
"HEALTH_CHECK": {"MODE": "tcp"}
# → TCP probe regardless of other settings

# HTTP endpoint mode - for apps with health endpoints
"PORT": 3000,
"HEALTH_CHECK": {"PATH": "/health"}
# → HTTP GET http://{localhost_ip}:{allocated_host_port}/health

# HTTP endpoint with custom timeout
"PORT": 3000,
"HEALTH_CHECK": {
    "PATH": "/api/health",
    "TIMEOUT": 300,  # Wait up to 5 minutes
}

# Unlimited timeout - probe forever until success
"PORT": 3000,
"HEALTH_CHECK": {
    "PATH": "/health",
    "TIMEOUT": 0,  # 0 = unlimited
}

# Health on different container port
"PORT": 3000,
"CONTAINER_RESOURCES": {"ports": [3000, 8080]},
"HEALTH_CHECK": {
    "PATH": "/api/health",
    "PORT": 8080,
}
# → HTTP GET http://{localhost_ip}:{host_port_for_8080}/api/health

# Simple delay mode (no probing)
"PORT": 3000,
"HEALTH_CHECK": {
    "MODE": "delay",
    "DELAY": 60,
}
# → Wait 60 seconds, then assume ready

# Skip tunnel on health failure
"PORT": 3000,
"HEALTH_CHECK": {
    "PATH": "/health",
    "TIMEOUT": 60,
    "ON_FAILURE": "skip",  # Don't start tunnel if health check fails
}
```

**Security (for "endpoint" mode):**
- Only host-local URLs allowed (no external URLs)
- Uses `get_localhost_ip()` for reliable host access across different Docker/network configurations
- Port must be a configured container port (validated against `ports_mapping`)
- Invalid port configuration triggers soft error (logs warning, falls back to "delay" mode)

---

## Configuration Reference

See `ContainerAppRunnerPlugin.CONFIG` for full configuration options.

### Exposed Ports

`EXPOSED_PORTS` is a dictionary keyed by internal container port:

```python
"EXPOSED_PORTS": {
    "3000": {
        "is_main_port": True,
        "host_port": None,
        "tunnel": {
            "enabled": True,
            "engine": "cloudflare",
            "token": "cf_token_for_3000",
        },
    },
    "3001": {
        "host_port": None,
        "tunnel": {
            "enabled": False,
        },
    },
}
```

Notes:

- `is_main_port` marks the port used for default health checks, semaphore networking exports, and the primary app URL.
- `host_port` is optional; when omitted, CAR allocates a host port automatically.
- `tunnel.enabled=true` currently requires `engine="cloudflare"` and a token.
- Legacy `PORT`, `CONTAINER_RESOURCES["ports"]`, `CLOUDFLARE_TOKEN`, and `EXTRA_TUNNELS` are still accepted as compatibility inputs and normalized internally to `EXPOSED_PORTS`.

### Dynamic Env and Semaphore Values

Deeploy accepts a UI-facing `DYNAMIC_ENV_UI` payload and compiles it to backend `DYNAMIC_ENV` entries:

- `static` -> `{"type": "static", "value": "..."}`
- `host_ip` -> `{"type": "host_ip"}`
- `container_ip(provider)` -> `{"type": "shmem", "path": [provider, "CONTAINER_IP"]}`
- `plugin_value(provider, key)` -> `{"type": "shmem", "path": [provider, key]}`

When a container app acts as the provider, new consumers should prefer these explicit exported keys:

- `HOST_IP`
- `HOST_PORT`
- `CONTAINER_IP`
- `CONTAINER_PORT`

Legacy `HOST`, `PORT`, and `URL` remain available for backward compatibility.

### Local Env Overrides

`ENV_OVERRIDES` lets an app add or override its own container environment
without changing Deeploy/config. The feature is enabled by default:

```python
"ENV_OVERRIDES": {
    "ENABLED": True,
}
```

Apps write one request to `/r1en_system/env-overrides/request.json`:

```json
{
  "schema_version": 1,
  "request_id": "env-001",
  "apply": "restart_now",
  "set": {
    "LOG_LEVEL": "trace",
    "FEATURE_FLAGS": ["fast", "debug"]
  },
  "remove": ["OLD_LOCAL_OVERRIDE"]
}
```

`apply` defaults to `"next_restart"` and also accepts `"restart_now"`.
`request_id` is correlation only; repeating the same request processes it again.
Unknown top-level fields are rejected; `clear_all` and secrets are not part of v1.

`set` accepts strings, numbers, booleans, arrays, and objects. Docker receives
strings: strings are unchanged, booleans become `true`/`false`, numbers become
decimal strings, and arrays/objects become compact JSON strings. `null` is
invalid; use `remove` instead. Variable names must match
`^[A-Za-z_][A-Za-z0-9_]*$`. CAR rejects reserved control/system variables,
including `R1EN_*`, `R1_*`, `EE_*`, `CONTAINER_NAME`, and CAR networking keys.

Overrides are stored host-private as `plugin_data/env_overrides.json`, survive
container restarts, CAR restarts, config updates, and reset requests, and are
applied after default env, semaphore env, config `ENV`, and `DYNAMIC_ENV`.
Invalid requests write `request.json.invalid` and `response.json` with
`status="error"`; successful requests write `response.json` with changed keys
and active override count, not a full effective env dump.

### Reset

`RESET` lets an app request a local destructive reset of CAR-managed fixed-size
app data volumes followed by a container restart. The feature is enabled by default:

```python
"RESET": {
    "ENABLED": True,
}
```

Apps write one request to `/r1en_system/reset/request.json`:

```json
{
  "schema_version": 1,
  "request_id": "reset-001",
  "mode": "volumes",
  "apply": "restart_now",
  "volumes": ["data"]
}
```

V1 supports only `mode="volumes"` and only `apply="restart_now"`; both fields
default to those values when omitted. `volumes` is optional; when omitted, CAR
resets all active `FIXED_SIZE_VOLUMES`. When present, entries must be logical
`FIXED_SIZE_VOLUMES` names, not paths. Unknown top-level request fields are
rejected.

Reset scope is deliberately narrow: v1 clears the contents inside selected
fixed-size volume mount roots without deleting the mount root itself. It does
not reset legacy `VOLUMES`, `FILE_VOLUMES`, `/r1en_system`, CAR plugin
metadata, or `plugin_data/env_overrides.json`. CAR validates the plan before
stopping the runtime and aborts without filesystem mutation if it cannot prove
the container stopped/removed. Invalid requests write `request.json.invalid`
and `response.json` with `status="error"`.

### Volume Sync

`SYNC` lets one CAR publish mounted application state to R1FS/ChainStore and
lets another CAR apply the latest snapshot for the same key. It is available on
`ContainerAppRunnerPlugin` and inherited runners such as `WorkerAppRunnerPlugin`.

```python
"SYNC": {
    "ENABLED": False,
    "KEY": None,                         # shared ChainStore key
    "TYPE": None,                        # "provider" | "consumer"
    "POLL_INTERVAL": 10,                 # provider/consumer tick cadence
    "HSYNC_POLL_INTERVAL": 60,           # consumer network refresh cadence, min 10
    "ALLOW_ONLINE_PROVIDER_CAPTURE": False,
    "CONSUMER_APPLY_MODE": "offline_restart",
}
```

Provider apps request a publish by writing JSON to
`/r1en_system/volume-sync/request.json`:

```json
{
  "archive_paths": ["/app/data/"],
  "metadata": {"epoch": 1},
  "runtime": {
    "provider_capture": "offline",
    "consumer_apply": "offline_restart"
  }
}
```

`archive_paths` must be a non-empty list of absolute paths inside CAR-managed
volumes. Offline capture rejects symlinks and unsupported special files. Online
provider capture can read from the live container filesystem, including
non-persistent paths, but only when the provider operator locally sets
`ALLOW_ONLINE_PROVIDER_CAPTURE=True`.

CAR writes provider results to `/r1en_system/volume-sync/response.json` and
consumer apply results to `/r1en_system/volume-sync/last_apply.json`. Invalid
requests are preserved as `request.json.invalid` with a sanitized error.
`/r1en_system` is CAR-owned control plane: the mount root and `volume-sync/`
directory are enforced as root-owned. Apps can write requests through the sticky
`01777` `volume-sync/` directory, but cannot own or replace the control
directory. CAR-owned result files are app-readable but not app-writable.

Consumer lifecycle is local policy. Providers may publish runtime metadata, but
consumers apply according to their own `CONSUMER_APPLY_MODE`:

| Mode | Behavior |
|------|----------|
| `offline_restart` | Stop container, apply snapshot, restart container. Default. |
| `online_no_restart` | Accepted for compatibility, but currently forced to `offline_restart` for filesystem safety. |
| `online_restart` | Accepted for compatibility, but currently forced to `offline_restart` for filesystem safety. |

Published manifests include `schema_version`, `archive_format`, `encryption`,
and `archive_paths`. Consumers validate these before downloading/applying a CID.
In `offline_restart` mode the consumer validates the ChainStore record,
downloads the CID, validates the tar, and prepares an apply plan before stopping
the container. Bad CIDs or corrupt archives are quarantined with retry backoff,
so a bad publish does not repeatedly stop a consumer. Offline provider capture
and offline consumer apply both abort without filesystem mutation if CAR cannot
confirm the container stopped/removed.

Consumer apply state is tracked in host-private plugin data. `last_apply.json`
is app-visible notification only; CAR deduplicates from durable internal apply
state and leaves the container stopped if rollback cannot prove the volume is
consistent.

Provider publishes require a positive `chainstore_hset` acknowledgement. If the
record is not confirmed, CAR reports an error, removes the just-uploaded CID
best-effort, and does not append sent history. Provider CID retirement may
remote-unpin old CIDs it published; consumer retirement only removes local
downloaded files and does not remote-unpin provider content.

Restored files and directories are owned by the target consumer volume root
owner/group, with unsafe special mode bits stripped. This keeps replicated state
modifiable for non-root app images whose fixed-size data volume is app-owned.

### The Node's Docker Store

Container apps run in the node's own Docker daemon, which the base image entrypoint starts. The node images
install `docker/daemon.json`, so that daemon keeps its store (images, containers, volumes) in
`/edge_node/_local_cache/_bin/docker/<Docker major>`, on the folder the host mounts into the node. The store
survives a node restart: an app starts from the stored image without a pull. On a node started without that
mount the directory is on the node container's own layer and is lost with that container, as before.

The store holds the environment every app was started with, its layers and its logs. It is under `_bin`
because the disk API of plugin code refuses that folder (the core's `RESTRICTED_LOCATIONS`), as it refused
`/var/lib/docker`, the place the store had before. Do not move it to a folder plugins can read or delete.

- **First start on such an image:** the store is empty and every app image is pulled once.
- **AUTOUPDATE:** an app starts from the stored image. The first update check (`AUTOUPDATE_INTERVAL` after
  the start) compares the registry's image with the one the container runs and restarts the app when the tag
  moved while the node was down, so such an app starts twice.
- **Leftover container:** a container with the app's name that an earlier run left is removed before every
  start. A container removed at that point, at a stop, a restart or an update goes with its anonymous
  volumes: the volumes Docker creates for a `VOLUME` of the image that no app volume covers. Data an app
  must keep belongs in a configured app volume. (The clean-up of a deleted deployment removes the container
  without them; they stay until the next sweep.)
- **Sweep:** one hour into each node run, one app removes from the store the stopped containers of earlier
  runs, the anonymous volumes no container holds and every image no container uses. An app without a
  container at that moment (stopped by hand, waiting for another app) pulls its image at its next start. An
  image loaded by hand that no container uses at that moment is removed too. The sweep is the first step of
  every app's lap, whatever state the app is in: apps that cannot start because the store filled the disk
  still free it, one hour into the node run after a restart. A node without any container app does not
  sweep and keeps what its last apps left, without adding to it.
- **Disk:** the images of the apps that have a container, plus what a run adds after its sweep (the previous
  image of each updated app, images and containers of apps removed since).
- **Docker major:** the directory is named after the Docker major that writes it, and each image build stops
  when the base image has another major. The directory name in `docker/daemon.json` and that build check
  change together; the store of the earlier major is then left on the host until it is removed.
- **Rollback:** an image without `docker/daemon.json` does not see this store. It pulls every app image
  into the node container's own layer, as before, while the store stays on the host: for that time the host
  needs free space for the app images a second time.
- **A daemon that does not start:** the node images start through `cmds/node_entrypoint`. It runs the base
  image entrypoint and, when that fails, logs "The inner Docker daemon did not start: removing its kept
  store.", removes the store directory and stops the container with exit code 1. The next start begins on an
  empty store, as every start did before the store was kept: nothing has to be removed on the host, and
  every app image is pulled again once (stopped containers and anonymous volumes in the store go with it).
  The script cannot tell why the daemon did not start, so any failed start empties the store: a store file
  dockerd refuses (seen only with a file damaged by hand), but also a node container started without
  privileges, an iptables fault, a wrong `DOCKERD_READY_TIMEOUT` or a daemon that takes longer than that
  time (120 s) to answer. A start with `EE_DD=0` starts no daemon and removes nothing. A container started
  with another entrypoint (`--entrypoint`, `entrypoint:` in a compose file) does not get this recovery.
- **One node per cache folder:** before it starts the daemon, `cmds/node_entrypoint` locks
  `_bin/docker/29.lock` (beside the store, not in it), and the node container holds that lock until it ends,
  also after a kill; nothing has to remove it. A second container of a node image started on the
  `_local_cache` of a running node, with or without `EE_DD=0`, logs "The kept Docker store is locked by
  another container on this cache folder, or could not be locked: not starting." and stops with exit code 1:
  it starts no daemon, removes nothing, and the running node goes on. The same line, after the shell's own
  error, stops a start when `flock` is missing. To run a command in a running node, use `docker exec`. A
  container started with another entrypoint takes no lock and removes nothing.
- **Copying a node's `_local_cache`** to another host: leave `_bin/docker` out; it holds only what can be
  pulled again.

---

## Future Enhancements

### Continuous Health Monitoring

**Status**: Planned

Currently, health probing only runs at startup to gate tunnel initialization. Once `_app_ready = True`, no further health checks occur. For production environments where apps can become unresponsive while the container stays running (memory leaks, deadlocks, etc.), continuous health monitoring could be added:

```python
"HEALTH_CHECK": {
    "PATH": "/health",
    "MONITOR_INTERVAL": 30,    # Seconds between health checks (0 = disabled)
    "MONITOR_MAX_FAILURES": 3, # Consecutive failures before restart
}
```

**Implementation approach:**
- Use HTTP endpoint probing for continuous monitoring (more thorough than TCP)
- TCP check confirms "port is open", HTTP check confirms "app is responding correctly"
- Track consecutive failures in `_health_monitor_failures` counter
- Trigger restart with `StopReason.HEALTH_CHECK_FAILED` after max failures
- Reset counter on successful probe
- Integrate with existing restart backoff system

**Flow:**
```
Phase 1: Startup Probing (existing)
├─ Wait DELAY
├─ Probe every INTERVAL (TCP or HTTP based on mode)
├─ Timeout after TIMEOUT (or probe forever if TIMEOUT=0)
└─ Success → _app_ready = True, enable tunnels

Phase 2: Continuous Monitoring (future)
├─ Requires PATH (HTTP-based monitoring)
├─ Probe every MONITOR_INTERVAL
├─ Track consecutive failures
├─ After MONITOR_MAX_FAILURES → restart
└─ Reset counter on success
```

---

### Per-Port Health Checks

**Status**: Planned

Currently, a single health check gates all tunnels (main + extra). For multi-service containers where different ports become ready at different times, per-port health configuration could be added:

```python
# Main port health
"HEALTH_CHECK": {"PATH": "/health"},  # For main PORT

# Extra tunnels with optional per-port health
"EXTRA_TUNNELS": {
    # Simple form (follows main tunnel timing)
    8080: "cf_token_xxx",

    # Extended form with own health check
    9090: {
        "token": "cf_token_yyy",
        "health_path": "/api/health",
        "health_delay": 30,  # Optional override
    }
}
```

**Implementation requirements:**
- Per-port readiness state tracking
- Per-port probe timing
- `_is_port_ready(port)` method
- Modified extra tunnel startup logic to check per-port readiness

---
