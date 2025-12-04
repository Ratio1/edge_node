# Container Apps

Container application plugins for running Docker containers with Cloudflare tunnel support.

## Table of Contents

- [Summary](#summary)
- [Plugins](#plugins)
- [Features](#features)
  - [Health Probe Configuration](#health-probe-configuration)
  - [Tunnel Startup Gating](#tunnel-startup-gating)
- [Configuration Reference](#configuration-reference)
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

### Health Check Configuration

The plugin supports multiple health check modes to determine when the application is ready before starting tunnels.

| Config | Default | Description |
|--------|---------|-------------|
| `HEALTH_CHECK_MODE` | "auto" | Health check strategy: "auto", "tcp", "endpoint", or "delay" |
| `HEALTH_ENDPOINT_PATH` | None | Health check path for "endpoint" mode (e.g., "/health", "/api/ready") |
| `HEALTH_ENDPOINT_PORT` | None | Container port for health check (validated against configured ports). None = use main PORT |

**Health Check Modes:**

| Mode | Description |
|------|-------------|
| `"auto"` | Smart detection (default): uses "endpoint" if `HEALTH_ENDPOINT_PATH` is set, otherwise "tcp" if PORT is configured |
| `"tcp"` | TCP port check - works for any protocol (HTTP, WebSocket, gRPC, raw TCP). Simply checks if the port is accepting connections |
| `"endpoint"` | HTTP probe to `HEALTH_ENDPOINT_PATH` - expects 2xx response. Requires path to be configured |
| `"delay"` | Simple time-based delay using `TUNNEL_START_DELAY` - no active probing |

**Examples:**

```python
# TCP mode (default when no HEALTH_ENDPOINT_PATH) - works for any protocol
"PORT": 3000,
# HEALTH_CHECK_MODE defaults to "auto", which uses "tcp" since no path is set
# → TCP probe to allocated host port until connection accepted

# Explicit TCP mode - useful for non-HTTP services (WebSocket, gRPC, etc.)
"PORT": 8080,
"HEALTH_CHECK_MODE": "tcp",
# → TCP probe regardless of other settings

# HTTP endpoint mode - for apps with health endpoints
"PORT": 3000,
"HEALTH_ENDPOINT_PATH": "/health",
# HEALTH_CHECK_MODE="auto" detects path and uses "endpoint" mode
# → HTTP GET http://{localhost_ip}:{allocated_host_port}/health

# Health on different container port
"PORT": 3000,
"CONTAINER_RESOURCES": {"ports": [3000, 8080]},
"HEALTH_ENDPOINT_PATH": "/api/health",
"HEALTH_ENDPOINT_PORT": 8080,
# → HTTP GET http://{localhost_ip}:{host_port_for_8080}/api/health

# Explicit delay mode (legacy behavior)
"PORT": 3000,
"HEALTH_CHECK_MODE": "delay",
"TUNNEL_START_DELAY": 60,
# → Wait 60 seconds, then assume ready (no probing)
```

**Security (for "endpoint" mode):**
- Only host-local URLs allowed (no external URLs)
- Uses `get_localhost_ip()` for reliable host access across different Docker/network configurations
- Port must be a configured container port (validated against `ports_mapping`)
- Invalid port configuration triggers soft error (logs warning, falls back to "delay" mode)

### Tunnel Startup Gating

Tunnels can be gated to start only after the application is ready. These settings apply to "tcp" and "endpoint" health check modes:

| Config | Default | Description |
|--------|---------|-------------|
| `HEALTH_PROBE_DELAY` | 30 | Seconds to wait before first probe (allows app build time) |
| `HEALTH_PROBE_INTERVAL` | 5 | Seconds between probe attempts |
| `HEALTH_PROBE_TIMEOUT` | 120 | Max seconds to wait for app ready |
| `TUNNEL_START_DELAY` | 300 | Simple delay for "delay" mode (or fallback when probing disabled) |
| `TUNNEL_ON_HEALTH_FAILURE` | "start" | Behavior on timeout: "skip" (no tunnel) or "start" (tunnel anyway) |

---

## Configuration Reference

See `ContainerAppRunnerPlugin.CONFIG` for full configuration options.

---

## Future Enhancements

### Continuous Health Monitoring

**Status**: Planned

Currently, health probing only runs at startup to gate tunnel initialization. Once `_app_ready = True`, no further health checks occur. For production environments where apps can become unresponsive while the container stays running (memory leaks, deadlocks, etc.), continuous health monitoring could be added:

```python
# Enable continuous health monitoring after startup
"HEALTH_ENDPOINT_PATH": "/health",
"HEALTH_MONITOR_INTERVAL": 30,    # Seconds between health checks (0 = disabled)
"HEALTH_MONITOR_MAX_FAILURES": 3, # Consecutive failures before restart
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
├─ Wait HEALTH_PROBE_DELAY
├─ Probe every HEALTH_PROBE_INTERVAL (TCP or HTTP based on mode)
├─ Timeout after HEALTH_PROBE_TIMEOUT
└─ Success → _app_ready = True, enable tunnels

Phase 2: Continuous Monitoring (future)
├─ Requires HEALTH_ENDPOINT_PATH (HTTP-based monitoring)
├─ Probe every HEALTH_MONITOR_INTERVAL
├─ Track consecutive failures
├─ After HEALTH_MONITOR_MAX_FAILURES → restart
└─ Reset counter on success
```

---

### Per-Port Health Checks

**Status**: Planned

Currently, a single health check gates all tunnels (main + extra). For multi-service containers where different ports become ready at different times, per-port health configuration could be added:

```python
# Main port health
"HEALTH_ENDPOINT_PATH": "/health",  # For main PORT

# Extra tunnels with optional per-port health
"EXTRA_TUNNELS": {
    # Simple form (follows main tunnel timing)
    8080: "cf_token_xxx",

    # Extended form with own health check
    9090: {
        "token": "cf_token_yyy",
        "health_path": "/api/health",
        "health_probe_delay": 30,  # Optional override
    }
}
```

**Implementation requirements:**
- Per-port readiness state tracking
- Per-port probe timing
- `_is_port_ready(port)` method
- Modified extra tunnel startup logic to check per-port readiness

---
