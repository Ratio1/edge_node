# Container Apps

Container application plugins for running Docker containers with Cloudflare tunnel support.

## Table of Contents

- [Summary](#summary)
- [Plugins](#plugins)
- [Features](#features)
  - [Health Check Configuration](#health-check-configuration)
- [Configuration Reference](#configuration-reference)
  - [Volume Sync](#volume-sync)
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

Consumer lifecycle is local policy. Providers may publish runtime metadata, but
consumers apply according to their own `CONSUMER_APPLY_MODE`:

| Mode | Behavior |
|------|----------|
| `offline_restart` | Stop container, apply snapshot, restart container. Default. |
| `online_no_restart` | Apply while the container remains running. |
| `online_restart` | Apply while running, then restart the container. |

Published manifests include `schema_version`, `archive_format`, `encryption`,
and `archive_paths`. Consumers validate these before downloading/applying a CID.

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
