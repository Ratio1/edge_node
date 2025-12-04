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

### Health Probe Configuration

Health endpoint configuration uses path-only values for security (SSRF prevention). URLs are always constructed as `http://{localhost_ip}:{host_port}{path}`, where `localhost_ip` is obtained via `self.log.get_localhost_ip()` for consistency with other host URLs in the codebase.

| Config | Default | Description |
|--------|---------|-------------|
| `HEALTH_ENDPOINT_PATH` | None | Health check path (e.g., "/health", "/api/ready") |
| `HEALTH_ENDPOINT_PORT` | None | Container port for health check (validated against configured ports). None = use main PORT |

**Examples:**

```python
# Simple - health on main port
"PORT": 3000,
"HEALTH_ENDPOINT_PATH": "/health",
# → http://{localhost_ip}:{allocated_host_port}/health

# Health on different container port
"PORT": 3000,
"CONTAINER_RESOURCES": {"ports": [3000, 8080]},
"HEALTH_ENDPOINT_PATH": "/api/health",
"HEALTH_ENDPOINT_PORT": 8080,
# → http://{localhost_ip}:{host_port_for_8080}/api/health

# Invalid - port not configured (soft error: logs warning, disables health probing)
"PORT": 3000,
"HEALTH_ENDPOINT_PORT": 9999,  # Warning: not a configured port, falls back to TUNNEL_START_DELAY
```

**Security:**
- Only host-local URLs allowed (no external URLs)
- Uses `get_localhost_ip()` for reliable host access across different Docker/network configurations
- Port must be a configured container port (validated against `ports_mapping`)
- Invalid port configuration triggers soft error (logs warning, falls back to `TUNNEL_START_DELAY`)

### Tunnel Startup Gating

Tunnels can be gated to start only after the application is ready:

| Config | Default | Description |
|--------|---------|-------------|
| `HEALTH_PROBE_DELAY` | 10 | Seconds to wait before first health probe |
| `HEALTH_PROBE_INTERVAL` | 2 | Seconds between probe attempts |
| `HEALTH_PROBE_TIMEOUT` | 300 | Max seconds to wait for app ready |
| `TUNNEL_START_DELAY` | 0 | Simple delay when no health path configured (or health probing disabled) |
| `TUNNEL_ON_HEALTH_FAILURE` | "skip" | Behavior on timeout: "skip" or "start" |

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
"HEALTH_CHECK_INTERVAL": 30,      # Seconds between health checks (0 = disabled)
"HEALTH_CHECK_MAX_FAILURES": 3,   # Consecutive failures before restart
```

**Implementation approach:**
- Reuse `_probe_health_endpoint()` from startup probing
- Track consecutive failures in `_health_check_failures` counter
- Trigger restart with `StopReason.HEALTH_CHECK_FAILED` after max failures
- Reset counter on successful probe
- Integrate with existing restart backoff system

**Flow:**
```
Phase 1: Startup Probing (existing)
├─ Wait HEALTH_PROBE_DELAY
├─ Probe every HEALTH_PROBE_INTERVAL
├─ Timeout after HEALTH_PROBE_TIMEOUT
└─ Success → _app_ready = True, enable tunnels

Phase 2: Continuous Monitoring (future)
├─ Probe every HEALTH_CHECK_INTERVAL
├─ Track consecutive failures
├─ After HEALTH_CHECK_MAX_FAILURES → restart
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
