# RedMesh v2.0 Implementation Plan
## Advanced Red Teaming & Continuous Monitoring Features

**Document Version:** 1.0
**Date:** 2025-12-05
**Target RedMesh Version:** 2.0.0

---

## Executive Summary

This document outlines the implementation plan for RedMesh v2.0, transforming it from a point-in-time distributed penetration testing framework into a sophisticated continuous security monitoring platform with advanced stealth capabilities. The plan incorporates industry best practices from 2025 red teaming methodologies, emphasizing operational security (OPSEC), temporal evasion, and distributed coordination.

### Key Objectives

1. Enable continuous monitoring with automated job chaining
2. Implement advanced temporal evasion ("Dune sand walking")
3. Provide flexible port range distribution strategies
4. Support granular test selection and exclusion
5. Enhance stealth through traffic pattern randomization
6. Maintain compliance with responsible disclosure and ethical testing standards

---

## Table of Contents

1. [Core Feature Requirements](#core-feature-requirements)
2. [Architecture Changes](#architecture-changes)
3. [Detailed Feature Specifications](#detailed-feature-specifications)
4. [Best Practices Integration](#best-practices-integration)
5. [Additional Proposed Features](#additional-proposed-features)
6. [Implementation Roadmap](#implementation-roadmap)
7. [Testing Strategy](#testing-strategy)
8. [Security & Ethical Considerations](#security--ethical-considerations)
9. [References](#references)

---

## Core Feature Requirements

### 1. Service Test Selection & Exclusion

**Current State:**
All `_service_info_*` and `_web_test_*` methods execute automatically for every open port.

**Required Changes:**

#### 1.1 Test Selection API
- Add `included_tests` parameter to job configuration (list of test method names)
- Add `excluded_tests` parameter to job configuration (list of test method names)
- Exclusions take precedence over inclusions
- If neither specified, run all tests (backward compatible)

#### 1.2 Test Categories
Organize tests into logical categories for easier selection:

**Service Info Tests:**
- `service_info_http` (ports 80, 8080)
- `service_info_https` (ports 443, 8443)
- `service_info_tls` (TLS handshake analysis)
- `service_info_ftp` (port 21)
- `service_info_ssh` (port 22)
- `service_info_smtp` (port 25)
- `service_info_dns` (port 53)
- `service_info_databases` (3306, 5432, 1433, 27017)
- `service_info_cache` (6379, 11211)
- `service_info_search` (9200)
- `service_info_legacy` (23, 445, 5900, 161, 502)
- `service_info_generic` (catch-all)

**Web Tests:**
- `web_test_recon` (common endpoints, homepage)
- `web_test_headers` (security headers, CORS, cookies)
- `web_test_injection` (SQL, XSS, path traversal)
- `web_test_api` (auth bypass, GraphQL, metadata)
- `web_test_redirect` (open redirect)
- `web_test_methods` (HTTP methods)

#### 1.3 Implementation Details

**File:** `redmesh_utils.py`

```python
def __init__(self, ..., included_tests=None, excluded_tests=None):
    # Store test filters
    self.included_tests = set(included_tests) if included_tests else None
    self.excluded_tests = set(excluded_tests) if excluded_tests else set()

def _should_run_test(self, test_method_name):
    """Determine if a test should be executed based on inclusion/exclusion rules."""
    if test_method_name in self.excluded_tests:
        return False
    if self.included_tests is None:
        return True
    return test_method_name in self.included_tests

def _gather_service_info(self):
    # Filter methods based on _should_run_test()
    service_info_methods = [
        method for method in dir(self)
        if method.startswith("_service_info_") and self._should_run_test(method)
    ]
    # ... rest of implementation

def _run_web_tests(self):
    # Filter methods based on _should_run_test()
    web_tests_methods = [
        method for method in dir(self)
        if method.startswith("_web_test_") and self._should_run_test(method)
    ]
    # ... rest of implementation
```

**File:** `pentester_api_01.py`

```python
@BasePlugin.endpoint
def launch_test(
    self,
    target: str = "",
    start_port: int = 1,
    end_port: int = 65535,
    exceptions: str = "64297",
    included_tests: str = "",  # NEW: comma-separated test names
    excluded_tests: str = "",  # NEW: comma-separated test names
):
    # Parse test filters
    included = [t.strip() for t in included_tests.split(",") if t.strip()] if included_tests else None
    excluded = [t.strip() for t in excluded_tests.split(",") if t.strip()] if excluded_tests else []

    job_specs = {
        # ... existing fields
        "included_tests": included,
        "excluded_tests": excluded,
    }
```

---

### 2. Worker Port Range Distribution Modes

**Current State:**
Port range is sliced and distributed among workers (each gets a unique subset).

**Required Changes:**

#### 2.1 Distribution Modes

Add `port_distribution_mode` parameter with two options:

1. **`SLICE` (default, current behavior):**
   - Divide port range among workers
   - Each worker scans unique subset
   - Faster completion, no redundancy

2. **`FULL` (new):**
   - All workers scan the entire port range
   - Independent scanning for validation
   - Redundancy and cross-verification
   - Useful for reliability testing and stealth (distributed sources)

#### 2.2 Implementation Details

**File:** `pentester_api_01.py`

```python
def _launch_job(
    self,
    job_id,
    target,
    start_port,
    end_port,
    network_worker_address,
    nr_local_workers=4,
    exceptions=None,
    port_distribution_mode="SLICE",  # NEW parameter
):
    ports = list(range(start_port, end_port + 1))
    ports = [p for p in ports if p not in (exceptions or [])]

    if port_distribution_mode.upper() == "SLICE":
        # Current implementation - slice ports
        batches = self._slice_ports(ports, nr_local_workers)
    elif port_distribution_mode.upper() == "FULL":
        # New implementation - all workers get full range
        batches = [ports] * nr_local_workers
    else:
        raise ValueError(f"Invalid port_distribution_mode: {port_distribution_mode}")

    # Launch workers with their respective port batches
    # ... rest of implementation

def _slice_ports(self, ports, nr_workers):
    """Slice ports into batches (current logic extracted)."""
    batches = []
    nr_ports = len(ports)
    nr_workers = max(1, min(nr_workers, nr_ports))
    base_chunk, remainder = divmod(nr_ports, nr_workers)
    start = 0
    for i in range(nr_workers):
        chunk = base_chunk + (1 if i < remainder else 0)
        end = start + chunk
        batch = ports[start:end]
        if batch:
            batches.append(batch)
        start = end
    return batches
```

**API Endpoint Update:**

```python
@BasePlugin.endpoint
def launch_test(
    self,
    target: str = "",
    start_port: int = 1,
    end_port: int = 65535,
    exceptions: str = "64297",
    port_distribution_mode: str = "SLICE",  # NEW parameter
):
    job_specs = {
        # ... existing fields
        "port_distribution_mode": port_distribution_mode,
    }
```

---

### 3. Single-Pass vs Continuous Monitoring

**Current State:**
Jobs run once and complete (single-pass only).

**Required Changes:**

#### 3.1 Operation Modes

Add `operation_mode` parameter with two options:

1. **`SINGLEPASS` (default, current behavior):**
   - Job runs once to completion
   - Results stored, job marked as done
   - No automatic restart

2. **`CONTINUOUS` (new):**
   - Job runs indefinitely in a loop
   - After completion, automatically chain new job
   - Each iteration generates intermediate report
   - Continues until manually stopped
   - Ideal for ongoing security monitoring

#### 3.2 Continuous Mode Behavior

**Job Lifecycle:**
```
[Init] → [Scan] → [Service Info] → [Web Tests] → [Report] → [Wait] → [Scan] → ...
                                                      ↓
                                              Cumulative tracking
```

**Key Features:**
- Each iteration is a complete scan cycle
- Intermediate reports stored with iteration number
- Cumulative change detection (new open ports, new services)
- Configurable inter-iteration delay
- Graceful shutdown on stop signal

#### 3.3 Implementation Details

**File:** `redmesh_utils.py`

```python
class PentestLocalWorker:
    def __init__(
        self,
        ...,
        operation_mode="SINGLEPASS",  # NEW
        continuous_delay_min=300,      # NEW: min seconds between iterations
        continuous_delay_max=600,      # NEW: max seconds between iterations
    ):
        self.operation_mode = operation_mode.upper()
        self.continuous_delay_min = continuous_delay_min
        self.continuous_delay_max = continuous_delay_max
        self.iteration_count = 0
        self.continuous_results = []  # Store results from each iteration

    def execute_job(self):
        """Enhanced to support continuous mode."""
        try:
            while True:
                self.iteration_count += 1
                self.P(f"Starting iteration {self.iteration_count} " +
                       f"(mode: {self.operation_mode})")

                # Reset state for new iteration
                self._reset_iteration_state()

                # Run standard workflow
                if not self._check_stopped():
                    self._scan_ports_step()
                if not self._check_stopped():
                    self._gather_service_info()
                    self.state["completed_tests"].append("service_info_completed")
                if not self._check_stopped():
                    self._run_web_tests()
                    self.state["completed_tests"].append("web_tests_completed")

                # Store iteration results
                iteration_result = self.get_status()
                iteration_result["iteration"] = self.iteration_count
                iteration_result["timestamp"] = self.owner.time()
                self.continuous_results.append(iteration_result)

                self.P(f"Iteration {self.iteration_count} completed. " +
                       f"Ports open: {self.state['open_ports']}")

                # Check if continuous mode
                if self.operation_mode == "SINGLEPASS":
                    self.state['done'] = True
                    break

                # Continuous mode: check for stop signal before next iteration
                if self.stop_event.is_set():
                    self.P("Continuous mode stopped by user request.")
                    self.state['done'] = True
                    self.state['canceled'] = True
                    break

                # Wait before next iteration with random delay
                delay = self._get_random_delay(
                    self.continuous_delay_min,
                    self.continuous_delay_max
                )
                self.P(f"Waiting {delay}s before iteration {self.iteration_count + 1}...")
                self.stop_event.wait(timeout=delay)

                if self.stop_event.is_set():
                    self.P("Continuous mode stopped during inter-iteration delay.")
                    self.state['done'] = True
                    self.state['canceled'] = True
                    break

            self.P(f"Job completed after {self.iteration_count} iteration(s).")

        except Exception as e:
            self.P(f"Exception in job execution: {e}:\n{traceback.format_exc()}",
                   color='r')
            self.state['done'] = True

    def _reset_iteration_state(self):
        """Reset state for new iteration while preserving continuous tracking."""
        self.state["ports_to_scan"] = list(self.initial_ports)
        self.state["open_ports"] = []
        self.state["ports_scanned"] = []
        self.state["service_info"] = {}
        self.state["web_tested"] = False
        self.state["web_tests_info"] = {}
        self.state["completed_tests"] = []

    def _get_random_delay(self, min_val, max_val):
        """Generate random delay for stealth."""
        import random
        return random.uniform(min_val, max_val)

    def get_status(self, for_aggregations=False):
        """Enhanced to include continuous mode metrics."""
        status = {
            # ... existing fields
            "operation_mode": self.operation_mode,
        }
        if self.operation_mode == "CONTINUOUS":
            status["iteration_count"] = self.iteration_count
            status["total_iterations"] = len(self.continuous_results)
        return status
```

**API Changes:**

```python
@BasePlugin.endpoint
def launch_test(
    self,
    # ... existing parameters
    operation_mode: str = "SINGLEPASS",       # NEW
    continuous_delay_min: int = 300,          # NEW: 5 minutes
    continuous_delay_max: int = 600,          # NEW: 10 minutes
):
    job_specs = {
        # ... existing fields
        "operation_mode": operation_mode,
        "continuous_delay_min": continuous_delay_min,
        "continuous_delay_max": continuous_delay_max,
    }
```

#### 3.4 Continuous Mode Reporting

**Enhanced Report Structure:**

```json
{
  "job_id": "abc123",
  "operation_mode": "CONTINUOUS",
  "iteration_count": 15,
  "current_iteration": {
    "iteration": 15,
    "timestamp": 1733423456.78,
    "open_ports": [22, 80, 443],
    "new_since_last": [443],
    "closed_since_last": [8080]
  },
  "historical_iterations": [
    {"iteration": 1, "timestamp": 1733400000.00, ...},
    {"iteration": 2, "timestamp": 1733400650.12, ...},
    ...
  ],
  "trends": {
    "port_stability_score": 0.87,
    "services_changed": 3,
    "new_vulnerabilities_found": 1
  }
}
```

---

### 4. Step Temporization - "Dune Sand Walking"

**Concept:**
Based on the novel "Dune" where characters walk with irregular patterns to avoid detection by sandworms. Applied to penetration testing: introduce random delays after random intervals to avoid pattern-based IDS detection.

**Current State:**
Operations execute as fast as possible with only socket timeout delays.

**Required Changes:**

#### 4.1 Temporal Randomization Strategy

**Port-Level Delays:**
- After scanning random(min_steps, max_steps) ports, wait random(min_wait, max_wait) seconds
- Applies to: port scanning, service info gathering, web tests
- Creates unpredictable traffic patterns
- Evades time-based signature detection

**Parameters:**
- `min_steps`: Minimum ports to process before delay (e.g., 5)
- `max_steps`: Maximum ports to process before delay (e.g., 20)
- `min_wait`: Minimum delay in seconds (e.g., 1.0)
- `max_wait`: Maximum delay in seconds (e.g., 5.0)

**Behavior:**
- Optional for `SINGLEPASS` mode
- Mandatory for `CONTINUOUS` mode (to avoid detection over time)

#### 4.2 Implementation Details

**File:** `redmesh_utils.py`

```python
import random

class PentestLocalWorker:
    def __init__(
        self,
        ...,
        enable_sand_walking=False,     # NEW
        min_steps=5,                   # NEW
        max_steps=20,                  # NEW
        min_wait=1.0,                  # NEW (seconds)
        max_wait=5.0,                  # NEW (seconds)
    ):
        self.enable_sand_walking = enable_sand_walking
        self.min_steps = min_steps
        self.max_steps = max_steps
        self.min_wait = min_wait
        self.max_wait = max_wait

        # Calculate next delay trigger
        self._steps_until_delay = self._calculate_next_delay_trigger()
        self._current_step_count = 0

    def _calculate_next_delay_trigger(self):
        """Calculate random number of steps before next delay."""
        if not self.enable_sand_walking:
            return float('inf')  # Never delay
        return random.randint(self.min_steps, self.max_steps)

    def _maybe_sand_walk_delay(self, operation_name="operation"):
        """Check if delay needed and execute if so."""
        if not self.enable_sand_walking:
            return

        self._current_step_count += 1

        if self._current_step_count >= self._steps_until_delay:
            # Time to delay
            delay = random.uniform(self.min_wait, self.max_wait)
            self.P(f"[Sand Walking] Delaying {delay:.2f}s after " +
                   f"{self._current_step_count} steps during {operation_name}")

            # Use stop_event.wait() for interruptible sleep
            self.stop_event.wait(timeout=delay)

            # Reset counter and calculate next trigger
            self._current_step_count = 0
            self._steps_until_delay = self._calculate_next_delay_trigger()

    def _scan_ports_step(self, batch_size=None, batch_nr=1):
        """Enhanced port scanning with sand walking delays."""
        # ... existing setup code

        for i, port in enumerate(ports_batch):
            if self.stop_event.is_set():
                return

            # Port scanning logic
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    self.state["open_ports"].append(port)
                    self.P(f"Port {port} is open on {target}.")
            except Exception as e:
                self.P(f"Exception scanning port {port} on {target}: {e}")
            finally:
                sock.close()

            self.state["ports_scanned"].append(port)
            self.state["ports_to_scan"].remove(port)

            # NEW: Sand walking delay check
            self._maybe_sand_walk_delay(operation_name="port_scan")

            # ... existing progress tracking code

    def _gather_service_info(self):
        """Enhanced service info with sand walking delays."""
        # ... existing setup code

        for method in service_info_methods:
            func = getattr(self, method)
            for port in open_ports:
                if self.stop_event.is_set():
                    continue

                info = func(target, port)
                # ... store info

                # NEW: Sand walking delay check
                self._maybe_sand_walk_delay(operation_name="service_info")

            self.state["completed_tests"].append(method)

    def _run_web_tests(self):
        """Enhanced web tests with sand walking delays."""
        # ... existing setup code

        for method in web_tests_methods:
            func = getattr(self, method)
            for port in ports_to_test:
                if self.stop_event.is_set():
                    return

                iter_result = func(target, port)
                # ... store results

                # NEW: Sand walking delay check
                self._maybe_sand_walk_delay(operation_name="web_tests")

            self.state["completed_tests"].append(method)
```

**API Changes:**

```python
@BasePlugin.endpoint
def launch_test(
    self,
    # ... existing parameters
    enable_sand_walking: bool = False,  # NEW
    min_steps: int = 5,                 # NEW
    max_steps: int = 20,                # NEW
    min_wait: float = 1.0,              # NEW
    max_wait: float = 5.0,              # NEW
):
    # Auto-enable sand walking for continuous mode
    if operation_mode.upper() == "CONTINUOUS":
        enable_sand_walking = True
        self.P("Sand walking automatically enabled for continuous mode")

    job_specs = {
        # ... existing fields
        "enable_sand_walking": enable_sand_walking,
        "min_steps": min_steps,
        "max_steps": max_steps,
        "min_wait": min_wait,
        "max_wait": max_wait,
    }
```

#### 4.3 Visualization of Sand Walking Pattern

```
Time →
Port Scans: [1][2][3][4][5][6][7]-----[8][9][10][11][12][13][14][15]--[16]...
            ←7 ports→ ←random delay→ ←8 ports→ ←random delay→ ←1 port→...

vs Traditional:
Port Scans: [1][2][3][4][5][6][7][8][9][10][11][12][13][14][15][16]...
            ←no delays, constant rate, easily detectable pattern→
```

---

## Best Practices Integration

### 5. Timing Templates (Inspired by Nmap)

**Rationale:**
Nmap's timing templates (T0-T5) provide proven stealth-to-speed tradeoffs. Integrate similar presets.

**Implementation:**

```python
TIMING_TEMPLATES = {
    "T0_PARANOID": {
        "socket_timeout": 5.0,
        "enable_sand_walking": True,
        "min_steps": 1,
        "max_steps": 1,      # Delay after every port
        "min_wait": 5.0,
        "max_wait": 10.0,
        "continuous_delay_min": 3600,   # 1 hour between iterations
        "continuous_delay_max": 7200,   # 2 hours
    },
    "T1_SNEAKY": {
        "socket_timeout": 3.0,
        "enable_sand_walking": True,
        "min_steps": 3,
        "max_steps": 10,
        "min_wait": 2.0,
        "max_wait": 5.0,
        "continuous_delay_min": 1800,   # 30 minutes
        "continuous_delay_max": 3600,   # 1 hour
    },
    "T2_POLITE": {
        "socket_timeout": 2.0,
        "enable_sand_walking": True,
        "min_steps": 10,
        "max_steps": 30,
        "min_wait": 0.5,
        "max_wait": 2.0,
        "continuous_delay_min": 600,    # 10 minutes
        "continuous_delay_max": 1200,   # 20 minutes
    },
    "T3_NORMAL": {
        "socket_timeout": 1.0,
        "enable_sand_walking": False,
        "continuous_delay_min": 300,    # 5 minutes
        "continuous_delay_max": 600,    # 10 minutes
    },
    "T4_AGGRESSIVE": {
        "socket_timeout": 0.5,
        "enable_sand_walking": False,
        "continuous_delay_min": 60,     # 1 minute
        "continuous_delay_max": 180,    # 3 minutes
    },
    "T5_INSANE": {
        "socket_timeout": 0.3,
        "enable_sand_walking": False,
        "continuous_delay_min": 30,     # 30 seconds
        "continuous_delay_max": 60,     # 1 minute
    },
}
```

**API Integration:**

```python
@BasePlugin.endpoint
def launch_test(
    self,
    # ... existing parameters
    timing_template: str = "T3_NORMAL",  # NEW
):
    # Apply template defaults
    template = TIMING_TEMPLATES.get(timing_template.upper())
    if template:
        # Override defaults with template values
        # Allow explicit parameters to override template
        pass
```

### 6. Jitter and Traffic Pattern Randomization

**Rationale:**
Consistent timing creates detectable signatures. Add random jitter to all timing parameters.

**Implementation:**

```python
def _apply_jitter(self, base_value, jitter_percent=10):
    """Add random jitter to timing value."""
    jitter = base_value * (jitter_percent / 100.0)
    return random.uniform(
        base_value - jitter,
        base_value + jitter
    )

# Example usage in socket operations
def _scan_ports_step(self, ...):
    # Apply jitter to timeout
    timeout = self._apply_jitter(self.socket_timeout)
    sock.settimeout(timeout)
```

### 7. Rate Limiting and Throttling

**Rationale:**
Prevent overwhelming targets and triggering rate-based defenses.

**Parameters:**
- `max_requests_per_second`: Global rate limit (default: unlimited)
- `max_requests_per_second_per_port`: Per-port limit (default: unlimited)

**Implementation:**

```python
import time
from collections import defaultdict

class PentestLocalWorker:
    def __init__(self, ..., max_rps=None, max_rps_per_port=None):
        self.max_rps = max_rps
        self.max_rps_per_port = max_rps_per_port
        self.last_request_time = 0
        self.port_request_times = defaultdict(list)

    def _throttle_global(self):
        """Enforce global rate limit."""
        if self.max_rps is None:
            return
        min_interval = 1.0 / self.max_rps
        elapsed = time.time() - self.last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self.last_request_time = time.time()

    def _throttle_per_port(self, port):
        """Enforce per-port rate limit."""
        if self.max_rps_per_port is None:
            return
        min_interval = 1.0 / self.max_rps_per_port
        times = self.port_request_times[port]
        if times:
            elapsed = time.time() - times[-1]
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
        self.port_request_times[port].append(time.time())
```

### 8. User-Agent and Request Header Randomization

**Rationale:**
Avoid fingerprinting of web requests. Randomize User-Agent and other headers.

**Implementation:**

```python
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    # Add more diverse user agents
]

def _get_random_headers(self):
    """Generate randomized HTTP headers."""
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8"]),
        "Accept-Encoding": "gzip, deflate, br",
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
    }

# Use in all requests
requests.get(url, headers=self._get_random_headers(), ...)
```

---

## Additional Proposed Features

### 9. Enhanced Reporting and Metrics

**9.1 Differential Reporting**

For continuous mode, track changes between iterations:

```python
def _compute_diff(self, prev_result, current_result):
    """Compute differences between iterations."""
    return {
        "new_open_ports": set(current_result["open_ports"]) - set(prev_result["open_ports"]),
        "closed_ports": set(prev_result["open_ports"]) - set(current_result["open_ports"]),
        "new_vulnerabilities": self._diff_vulnerabilities(prev_result, current_result),
        "changed_services": self._diff_services(prev_result, current_result),
    }
```

**9.2 Alerting Thresholds**

Notify when significant changes detected:

```python
alert_config = {
    "alert_on_new_port": True,
    "alert_on_new_vulnerability": True,
    "alert_threshold_ports": 3,  # Alert if 3+ new ports open
}
```

### 10. Scan Fingerprint Obfuscation

**10.1 Port Scan Order Randomization**

```python
def _scan_ports_step(self, ...):
    # Randomize port order to avoid sequential patterns
    ports_batch = list(ports_batch)
    random.shuffle(ports_batch)

    for port in ports_batch:
        # ... scan
```

**10.2 Decoy Traffic**

Inspired by Nmap's `-D` option, generate decoy requests from randomized source patterns:

```python
def _generate_decoy_request(self, target, port):
    """Send occasional decoy requests to obfuscate true scan pattern."""
    # Implementation would require low-level socket manipulation
    # This is an advanced feature for future consideration
    pass
```

### 11. Distributed Worker Coordination Enhancements

**11.1 Worker Health Monitoring**

Track worker status in continuous mode:

```python
def _update_worker_health(self):
    """Report worker health metrics to CStore."""
    health = {
        "worker_id": self.ee_addr,
        "status": "active",
        "iteration": self.iteration_count,
        "last_heartbeat": self.time(),
        "ports_scanned_total": len(self.state["ports_scanned"]),
    }
    self.chainstore_hset(
        hkey=f"{self.cfg_instance_id}:health",
        key=self.ee_addr,
        value=health
    )
```

**11.2 Load Balancing Awareness**

For FULL port distribution mode with multiple network workers, track which workers are actively scanning to balance load:

```python
def _get_active_workers(self, job_id):
    """Get list of workers actively working on this job."""
    job_specs = self._get_job_from_cstore(job_id)
    active = [
        worker_addr
        for worker_addr, worker_data in job_specs.get("workers", {}).items()
        if not worker_data.get("finished")
    ]
    return active
```

### 12. Error Handling and Resilience

**12.1 Network Failure Recovery**

Handle transient network errors gracefully:

```python
def _scan_with_retry(self, target, port, max_retries=3):
    """Scan port with exponential backoff retry."""
    for attempt in range(max_retries):
        try:
            # ... scanning logic
            return result
        except (socket.timeout, socket.error) as e:
            if attempt < max_retries - 1:
                backoff = (2 ** attempt) * random.uniform(0.5, 1.5)
                self.P(f"Retry {attempt+1}/{max_retries} for {target}:{port} " +
                       f"after {backoff:.2f}s")
                time.sleep(backoff)
            else:
                self.P(f"Failed to scan {target}:{port} after {max_retries} attempts",
                       color='r')
                return None
```

**12.2 Graceful Degradation**

Continue operation even if some tests fail:

```python
def _run_test_safely(self, test_func, target, port):
    """Execute test with exception handling."""
    try:
        return test_func(target, port)
    except Exception as e:
        self.P(f"Test {test_func.__name__} failed for {target}:{port}: {e}",
               color='y')
        return f"ERROR: {str(e)}"
```

### 13. Compliance and Ethical Testing Features

**13.1 Authorized Target Validation**

```python
def _validate_target_authorization(self, target):
    """Verify target is authorized for testing."""
    # Check against whitelist
    authorized_networks = self.cfg_authorized_networks or []
    # Implement CIDR matching, domain validation, etc.
    # Return True only if explicitly authorized
    pass

@BasePlugin.endpoint
def launch_test(self, target, ...):
    if not self._validate_target_authorization(target):
        raise ValueError(f"Target {target} not in authorized list. " +
                        "Add to AUTHORIZED_NETWORKS config.")
```

**13.2 Safe Mode**

Disable aggressive tests:

```python
SAFE_MODE_EXCLUDED_TESTS = [
    "_web_test_sql_injection",  # Might trigger WAF
    "_web_test_path_traversal", # Might access sensitive files
    # Add other potentially disruptive tests
]

def launch_test(self, ..., safe_mode=False):
    if safe_mode:
        excluded_tests = excluded_tests or []
        excluded_tests.extend(SAFE_MODE_EXCLUDED_TESTS)
```

### 14. Protocol-Specific Enhancements

**14.1 TLS/SSL Advanced Analysis**

Enhanced certificate validation and cipher suite analysis:

```python
def _service_info_tls_advanced(self, target, port):
    """Deep TLS analysis including cipher suites, certificate chain, etc."""
    # Implement full certificate chain validation
    # Test for weak ciphers (RC4, 3DES, etc.)
    # Check for certificate transparency logs
    # Validate OCSP/CRL
    pass
```

**14.2 Service-Specific Vulnerability Checks**

Expand service-specific tests:

```python
def _service_info_docker_api(self, target, port):
    """Detect exposed Docker API."""
    # Check port 2375, 2376
    pass

def _service_info_kubernetes_api(self, target, port):
    """Detect Kubernetes API server."""
    # Check port 6443, 8080
    pass
```

### 15. Performance Monitoring and Optimization

**15.1 Scan Performance Metrics**

```python
def get_performance_metrics(self):
    """Return performance statistics."""
    return {
        "total_ports_scanned": len(self.state["ports_scanned"]),
        "scan_rate_pps": self._calculate_scan_rate(),
        "average_port_time": self._calculate_avg_port_time(),
        "test_execution_times": self._get_test_timings(),
    }
```

**15.2 Adaptive Timeout**

Adjust socket timeout based on target responsiveness:

```python
def _adaptive_timeout(self, target):
    """Calculate optimal timeout based on RTT."""
    # Ping target to measure RTT
    # Set timeout to RTT * safety_factor
    pass
```

### 16. Integration and Extensibility

**16.1 Plugin Architecture for Custom Tests**

Allow external test modules:

```python
def _load_custom_tests(self, test_directory):
    """Load custom test modules from directory."""
    # Dynamically import Python modules
    # Register custom _service_info_* and _web_test_* methods
    pass
```

**16.2 Webhook Notifications**

Alert external systems on findings:

```python
def _send_webhook(self, event_type, data):
    """Send webhook notification."""
    if self.cfg_webhook_url:
        requests.post(self.cfg_webhook_url, json={
            "event": event_type,
            "timestamp": self.time(),
            "data": data,
        })
```

### 17. Reporting Formats

**17.1 Export Formats**

Support multiple output formats:

```python
@BasePlugin.endpoint
def export_report(self, job_id, format="json"):
    """Export report in various formats."""
    report = self._get_job_status(job_id)

    if format == "json":
        return report
    elif format == "html":
        return self._generate_html_report(report)
    elif format == "csv":
        return self._generate_csv_report(report)
    elif format == "markdown":
        return self._generate_markdown_report(report)
    elif format == "pdf":
        return self._generate_pdf_report(report)
```

**17.2 OWASP Mapping**

Tag findings with OWASP Top 10 categories:

```python
OWASP_MAPPINGS = {
    "_web_test_sql_injection": "A03:2021-Injection",
    "_web_test_xss": "A03:2021-Injection",
    "_web_test_security_headers": "A05:2021-Security Misconfiguration",
    # ... complete mappings
}

def _enrich_with_owasp(self, finding):
    """Add OWASP category to finding."""
    test_method = finding.get("test_method")
    finding["owasp_category"] = OWASP_MAPPINGS.get(test_method)
    return finding
```

---

## Architecture Changes

### File Structure Updates

```
extensions/business/cybersec/red_mesh/
├── pentester_api_01.py          [MODIFIED] - API endpoints with new parameters
├── redmesh_utils.py             [MODIFIED] - Enhanced PentestLocalWorker
├── service_mixin.py             [MODIFIED] - Enhanced service tests
├── web_mixin.py                 [MODIFIED] - Enhanced web tests
├── timing_templates.py          [NEW] - Timing template definitions
├── stealth_utils.py             [NEW] - Stealth and evasion utilities
├── continuous_monitor.py        [NEW] - Continuous monitoring logic
├── report_generator.py          [NEW] - Enhanced reporting
├── test_redmesh.py              [MODIFIED] - Updated tests
├── test_new_features.py         [NEW] - Tests for new features
└── TODO_B.md                    [THIS FILE]
```

### Configuration Changes

**Plugin Config Updates:**

```python
_CONFIG = {
    **BasePlugin.CONFIG,

    'PORT': None,
    'CHECK_JOBS_EACH': 5,
    'NR_LOCAL_WORKERS': 8,
    'WARMUP_DELAY': 30,

    # NEW: Timing and stealth
    'DEFAULT_TIMING_TEMPLATE': 'T3_NORMAL',
    'ENABLE_SAND_WALKING_BY_DEFAULT': False,

    # NEW: Continuous monitoring
    'CONTINUOUS_MODE_ENABLED': True,
    'DEFAULT_OPERATION_MODE': 'SINGLEPASS',

    # NEW: Security and compliance
    'AUTHORIZED_NETWORKS': [],  # CIDR blocks authorized for testing
    'SAFE_MODE_DEFAULT': True,
    'WEBHOOK_URL': None,

    # NEW: Performance
    'MAX_REQUESTS_PER_SECOND': None,
    'ENABLE_ADAPTIVE_TIMEOUT': False,

    'VALIDATION_RULES': {
        **BasePlugin.CONFIG['VALIDATION_RULES'],
    },
}
```

---

## Implementation Roadmap

### Phase 1: Core Features (Weeks 1-3)

**Week 1: Service Test Selection**
- [ ] Implement `_should_run_test()` filtering logic
- [ ] Add `included_tests` and `excluded_tests` parameters
- [ ] Update `_gather_service_info()` and `_run_web_tests()`
- [ ] Add API endpoint parameters
- [ ] Write unit tests
- [ ] Update documentation

**Week 2: Port Distribution Modes**
- [ ] Implement `_slice_ports()` (extract existing logic)
- [ ] Implement FULL distribution mode
- [ ] Add `port_distribution_mode` parameter
- [ ] Update `_launch_job()` logic
- [ ] Test with multiple workers
- [ ] Validate independent scanning behavior

**Week 3: Continuous Monitoring Foundation**
- [ ] Refactor `execute_job()` for iteration loop
- [ ] Implement `_reset_iteration_state()`
- [ ] Add `operation_mode` parameter
- [ ] Implement inter-iteration delays
- [ ] Add graceful shutdown handling
- [ ] Test continuous mode execution

### Phase 2: Stealth & Temporization (Weeks 4-5)

**Week 4: Sand Walking Implementation**
- [ ] Implement `_calculate_next_delay_trigger()`
- [ ] Implement `_maybe_sand_walk_delay()`
- [ ] Integrate delays into port scanning
- [ ] Integrate delays into service info gathering
- [ ] Integrate delays into web tests
- [ ] Add sand walking parameters to API
- [ ] Test delay patterns and randomization

**Week 5: Timing Templates**
- [ ] Define timing template constants
- [ ] Implement template application logic
- [ ] Add jitter functionality
- [ ] Integrate with sand walking
- [ ] Test all timing templates (T0-T5)
- [ ] Validate stealth vs. performance tradeoffs

### Phase 3: Advanced Features (Weeks 6-8)

**Week 6: Enhanced Reporting**
- [ ] Implement differential reporting for continuous mode
- [ ] Add iteration tracking and history
- [ ] Implement trend analysis
- [ ] Create report export formats (HTML, CSV, MD)
- [ ] Add OWASP mappings to findings
- [ ] Test reporting with continuous jobs

**Week 7: Stealth Enhancements**
- [ ] Implement User-Agent randomization
- [ ] Add HTTP header randomization
- [ ] Implement port scan order randomization
- [ ] Add rate limiting/throttling
- [ ] Implement retry logic with backoff
- [ ] Test evasion effectiveness

**Week 8: Compliance & Safety**
- [ ] Implement authorized target validation
- [ ] Add safe mode exclusions
- [ ] Implement webhook notifications
- [ ] Add worker health monitoring
- [ ] Enhance error handling
- [ ] Write compliance documentation

### Phase 4: Testing & Optimization (Weeks 9-10)

**Week 9: Comprehensive Testing**
- [ ] Write integration tests for all new features
- [ ] Test continuous mode for extended runs (24+ hours)
- [ ] Load testing with multiple workers
- [ ] Stealth testing against IDS systems
- [ ] Validate FULL port distribution mode
- [ ] Cross-platform testing (Linux, Windows, cloud)

**Week 10: Performance Optimization**
- [ ] Profile code for bottlenecks
- [ ] Optimize port scanning loops
- [ ] Optimize memory usage for continuous mode
- [ ] Implement adaptive timeout
- [ ] Add performance metrics collection
- [ ] Benchmark against baseline

### Phase 5: Documentation & Release (Week 11-12)

**Week 11: Documentation**
- [ ] Write API documentation for all new endpoints
- [ ] Create usage examples and tutorials
- [ ] Write best practices guide
- [ ] Document timing templates and use cases
- [ ] Create troubleshooting guide
- [ ] Update README and changelog

**Week 12: Release Preparation**
- [ ] Code review and refactoring
- [ ] Security audit of new features
- [ ] Finalize configuration defaults
- [ ] Prepare migration guide from v1.x
- [ ] Create release notes
- [ ] Deploy to staging for final validation

---

## Testing Strategy

### Unit Tests

**Test Coverage Requirements:**
- Minimum 85% code coverage for new features
- 100% coverage for critical security functions

**Key Test Cases:**

```python
class TestServiceSelection(unittest.TestCase):
    def test_include_only_web_tests(self):
        # Test included_tests parameter
        pass

    def test_exclude_specific_service(self):
        # Test excluded_tests parameter
        pass

    def test_exclusion_precedence(self):
        # Verify exclusions override inclusions
        pass

class TestPortDistribution(unittest.TestCase):
    def test_slice_mode_no_overlap(self):
        # Verify sliced ports don't overlap
        pass

    def test_full_mode_all_workers_same_range(self):
        # Verify FULL mode gives same ports to all
        pass

class TestContinuousMode(unittest.TestCase):
    def test_iteration_loop(self):
        # Test multiple iterations execute
        pass

    def test_state_reset_between_iterations(self):
        # Verify state resets properly
        pass

    def test_graceful_shutdown(self):
        # Test stop_event handling
        pass

class TestSandWalking(unittest.TestCase):
    def test_random_delay_triggers(self):
        # Verify delays occur randomly
        pass

    def test_delay_ranges(self):
        # Verify delays within min/max bounds
        pass

    def test_pattern_unpredictability(self):
        # Statistical test for randomness
        pass
```

### Integration Tests

**End-to-End Scenarios:**

1. **Single-pass with service exclusion:**
   - Launch job excluding database tests
   - Verify only selected tests execute
   - Validate report completeness

2. **Continuous monitoring with sand walking:**
   - Launch continuous job with T1_SNEAKY template
   - Run for 1 hour (multiple iterations)
   - Verify timing patterns are irregular
   - Check for proper iteration reports

3. **Distributed FULL mode:**
   - Launch job with 3 network workers
   - Use FULL port distribution
   - Verify all workers scan same ports
   - Check for independent findings

4. **Stealth evasion:**
   - Target system with IDS/IPS
   - Use T0_PARANOID template
   - Monitor for alerts (should be minimal)
   - Validate successful completion

### Performance Benchmarks

**Baseline Metrics:**

| Metric | Target | Measurement Method |
|--------|--------|-------------------|
| Port scan rate (T3) | 100-500 ports/sec | Time 1000 port scan |
| Port scan rate (T0) | 0.1-1 ports/sec | Time 100 port scan |
| Memory per worker | < 50MB | Monitor RSS during scan |
| Continuous mode uptime | > 7 days | Long-running test |
| Report generation time | < 5 seconds | Time get_job_status() |

### Security Testing

**Validation Requirements:**

1. **Stealth verification:**
   - Deploy against honeypot systems
   - Monitor logs for detection signatures
   - Measure time-to-detection for each template

2. **Authorized target enforcement:**
   - Attempt to scan unauthorized IP
   - Verify request is blocked
   - Check error message is clear

3. **Safe mode validation:**
   - Launch with safe_mode=True
   - Verify aggressive tests are skipped
   - Validate report notes safe mode

---

## Security & Ethical Considerations

### Responsible Disclosure

**RedMesh must be used ethically and legally:**

1. **Authorization Required:**
   - Only scan systems you own or have written permission to test
   - Maintain documentation of authorization
   - Configure AUTHORIZED_NETWORKS to prevent accidental misuse

2. **Public Edge Node Usage:**
   - RedMesh uses public Ratio1.ai Edge Nodes as scan sources
   - Targets may see requests from multiple public IP addresses
   - Include contact information in User-Agent or HTTP headers
   - Respect robots.txt and security.txt directives

3. **Rate Limiting Respect:**
   - Honor target rate limits and backoff requests
   - Use appropriate timing templates for production systems
   - Avoid denial of service conditions

### Compliance Considerations

**Regulatory Alignment:**

- **GDPR:** Ensure scan data doesn't capture personal information
- **PCI DSS 4.0:** Continuous testing aligns with requirement 11.3.2
- **SOC 2:** Document authorization and approval processes
- **HIPAA:** Avoid scanning healthcare systems without specific approval

### Network Ethics

**Best Practices:**

1. **Minimize Impact:**
   - Use T2_POLITE or slower for production systems
   - Schedule scans during maintenance windows
   - Monitor target system health

2. **Transparent Operation:**
   - Set identifiable User-Agent strings
   - Provide abuse contact information
   - Document scan purpose in logs

3. **Data Handling:**
   - Encrypt reports containing vulnerability data
   - Implement data retention policies
   - Secure CStore data with access controls

### Incident Response

**If RedMesh Triggers Alerts:**

1. **Immediate Actions:**
   - Stop job immediately
   - Contact target system owner
   - Provide scan details and purpose
   - Offer assistance with log analysis

2. **Documentation:**
   - Log all scan activities
   - Maintain authorization records
   - Document incident and resolution

---

## References

### Research & Best Practices

**Red Teaming & Stealth:**
- [Red Teaming methodologies focused on op-sec and stealth](https://security.stackexchange.com/questions/270430/red-teaming-methodologies-focused-on-op-sec-and-stealth)
- [Red Teaming in 2025: The Bleeding Edge](https://www.cycognito.com/learn/red-teaming/)
- [Red Teaming Tools 2025](https://www.cycognito.com/learn/red-teaming/red-teaming-tools.php)
- [Advanced Red Team Tactics](https://undercodetesting.com/advanced-red-team-tactics-exploiting-vulnerable-drivers-for-evasion/)
- [Red Team Reconnaissance Techniques](https://www.linode.com/docs/guides/red-team-reconnaissance-techniques/)

**Continuous Testing:**
- [Beyond Point-in-Time: The ROI Case for Continuous Pentesting](https://thehackernews.com/expert-insights/2025/12/beyond-point-in-time-roi-case-for.html)
- [Continuous Penetration Testing 2025](https://deepstrike.io/blog/continuous-penetration-testing)
- [Point-in-time vs. continuous penetration testing](https://www.bugcrowd.com/blog/point-in-time-vs-continuous-penetration-testing-a-comparison-guide/)

**Timing & Evasion:**
- [Nmap Timing Templates](https://nmap.org/book/performance-timing-templates.html)
- [Mastering Nmap Part 5: Timing & Performance Optimization](https://medium.com/@appsecvenue/mastering-nmap-part-5-in-2025-timing-performance-optimization-a2b98f187e0c)
- [Nmap Scan with Timing Parameters](https://www.hackingarticles.in/nmap-scan-with-timing-parameters/)
- [Advanced NMAP Scanning](https://securedebug.com/advanced-nmap-scanning-techiques-network-scan/)

**Distributed Scanning:**
- [Distributed port-scan attack in cloud environment](https://ieeexplore.ieee.org/document/6622595/)
- [Enhancing Network Visibility with Advanced Port Scanning](https://pmc.ncbi.nlm.nih.gov/articles/PMC10490701/)
- [Hiding in the AI Traffic: Abusing MCP for Red Teaming](https://arxiv.org/html/2511.15998)

**Penetration Testing Trends:**
- [Penetration Testing Trends 2025](https://www.getastra.com/blog/security-audit/penetration-testing-trends/)
- [Evolution of Penetration Testing Methodologies](https://www.uprootsecurity.com/blog/pentest-methodologies)
- [Pentesting Statistics 2025](https://zerothreat.ai/blog/emerging-penetration-testing-statistics)

### OWASP Resources

- **OWASP Top 10 2021:** https://owasp.org/Top10/
- **OWASP Testing Guide v4:** https://owasp.org/www-project-web-security-testing-guide/
- **OWASP API Security Top 10:** https://owasp.org/www-project-api-security/

### Standards & Compliance

- **PCI DSS v4.0:** https://www.pcisecuritystandards.org/
- **NIST Cybersecurity Framework:** https://www.nist.gov/cyberframework
- **ISO 27001:** https://www.iso.org/isoiec-27001-information-security.html

---

## Appendix A: Configuration Examples

### Example 1: Stealth Reconnaissance

```python
# Ultra-stealthy scan for sensitive production system
launch_test(
    target="production.example.com",
    start_port=1,
    end_port=1024,
    timing_template="T0_PARANOID",
    operation_mode="SINGLEPASS",
    port_distribution_mode="FULL",  # Multiple sources for obfuscation
    excluded_tests="_web_test_sql_injection,_web_test_path_traversal",
    safe_mode=True
)
```

### Example 2: Continuous Monitoring

```python
# 24/7 security monitoring
launch_test(
    target="staging.example.com",
    start_port=1,
    end_port=65535,
    timing_template="T2_POLITE",
    operation_mode="CONTINUOUS",
    continuous_delay_min=3600,   # 1 hour between scans
    continuous_delay_max=7200,   # 2 hours
    port_distribution_mode="SLICE",
)
```

### Example 3: Quick Infrastructure Audit

```python
# Fast, comprehensive scan
launch_test(
    target="dev.example.com",
    start_port=1,
    end_port=10000,
    timing_template="T4_AGGRESSIVE",
    operation_mode="SINGLEPASS",
    included_tests="_service_info_http,_service_info_https,_web_test_recon,_web_test_headers",
)
```

### Example 4: Database Security Focus

```python
# Database-only security check
launch_test(
    target="db.example.com",
    start_port=1,
    end_port=65535,
    timing_template="T3_NORMAL",
    included_tests="_service_info_3306,_service_info_5432,_service_info_1433,_service_info_27017",
    excluded_tests="_web_test_*",  # Skip web tests
)
```

---

## Appendix B: Migration Guide from v1.x to v2.0

### Breaking Changes

1. **None:** v2.0 is backward compatible with v1.x API calls
2. All new parameters have sensible defaults
3. Existing jobs continue to work unchanged

### New Capabilities

**For existing users, to adopt new features:**

1. **Add continuous monitoring:**
   ```python
   # Old (v1.x)
   launch_test(target="example.com", start_port=1, end_port=1000)

   # New (v2.0)
   launch_test(
       target="example.com",
       start_port=1,
       end_port=1000,
       operation_mode="CONTINUOUS"  # NEW
   )
   ```

2. **Improve stealth:**
   ```python
   # Add timing template
   launch_test(..., timing_template="T1_SNEAKY")
   ```

3. **Selective testing:**
   ```python
   # Exclude aggressive tests
   launch_test(..., excluded_tests="_web_test_sql_injection")
   ```

### Recommended Upgrades

**Priority 1: Add timing templates**
- Review current scan speeds
- Select appropriate template (T2_POLITE recommended for production)

**Priority 2: Enable continuous monitoring for critical assets**
- Start with 6-hour intervals
- Monitor for new vulnerabilities

**Priority 3: Implement service selection**
- Reduce scan time by 30-50%
- Focus on relevant attack surface

---

## Appendix C: Troubleshooting Guide

### Common Issues

**Issue: Continuous mode not chaining jobs**
- **Cause:** Job marked as done incorrectly
- **Solution:** Check `operation_mode` parameter, verify not in SINGLEPASS

**Issue: Sand walking delays too long**
- **Cause:** Incorrect timing template or parameters
- **Solution:** Use faster template (T3, T4) or reduce max_wait

**Issue: All tests skipped**
- **Cause:** Over-restrictive `excluded_tests` or empty `included_tests`
- **Solution:** Review test selection parameters

**Issue: Worker not reporting results**
- **Cause:** Network issue or worker crashed
- **Solution:** Check worker health endpoint, review logs

**Issue: Detection by IDS despite stealth settings**
- **Cause:** Target has advanced behavioral detection
- **Solution:** Use T0_PARANOID, increase delays, reduce parallelism

---

## Appendix D: Performance Tuning Matrix

| Use Case | Template | Port Dist | Workers | Expected Speed |
|----------|----------|-----------|---------|----------------|
| Production stealth | T0 | FULL | 2-3 | Hours per 1000 ports |
| Production safe | T2 | SLICE | 4-8 | Minutes per 1000 ports |
| Staging full | T3 | SLICE | 8-16 | Seconds per 1000 ports |
| Dev quick | T4 | SLICE | 16-32 | Sub-second per 1000 ports |
| Emergency audit | T5 | SLICE | 32+ | Fastest possible |

---

## Conclusion

This implementation plan transforms RedMesh from a capable distributed penetration testing framework into a world-class continuous security monitoring platform. The proposed features align with industry best practices for 2025, emphasizing:

1. **Stealth & Evasion:** Advanced temporal randomization prevents detection
2. **Flexibility:** Granular control over tests, timing, and distribution
3. **Continuous Assurance:** Shift from point-in-time to always-on monitoring
4. **Responsible Operation:** Built-in safeguards and ethical considerations
5. **Scalability:** Leverages Ratio1.ai Edge Network for distributed coordination

By implementing these features systematically over 12 weeks, RedMesh v2.0 will provide organizations with cutting-edge red teaming capabilities while maintaining the ethical and legal standards required for responsible security testing.

---

**Document Status:** DRAFT v1.0
**Next Review:** Upon approval to proceed with Phase 1
**Approvers:** Technical Lead, Security Team, Product Owner

