import time
import statistics

from .models.shared import ScanMetrics


class MetricsCollector:
  """Collects raw scan timing and outcome data during a worker scan."""

  def __init__(self):
    self._phase_starts = {}
    self._phase_ends = {}
    self._connection_outcomes = {"connected": 0, "timeout": 0, "refused": 0, "reset": 0, "error": 0}
    self._response_times = []
    self._port_scan_delays = []
    self._probe_results = {}
    self._scan_start = None
    self._ports_in_range = 0
    self._ports_scanned = 0
    self._ports_skipped = 0
    self._open_ports = []
    self._open_port_details = []  # [{"port": int, "protocol": str, "banner_confirmed": bool}]
    self._service_counts = {}
    self._banner_confirmed = 0
    self._banner_guessed = 0
    self._finding_counts = {}
    # For success rate over time windows
    self._connection_log = []  # [(timestamp, success_bool)]

  def start_scan(self, ports_in_range: int):
    self._scan_start = time.time()
    self._ports_in_range = ports_in_range

  def phase_start(self, phase: str):
    self._phase_starts[phase] = time.time()

  def phase_end(self, phase: str):
    self._phase_ends[phase] = time.time()

  def record_connection(self, outcome: str, response_time: float):
    self._connection_outcomes[outcome] = self._connection_outcomes.get(outcome, 0) + 1
    if response_time >= 0:
      self._response_times.append(response_time)
    self._connection_log.append((time.time(), outcome == "connected"))
    self._ports_scanned += 1

  def record_port_scan_delay(self, delay: float):
    self._port_scan_delays.append(delay)

  def record_probe(self, probe_name: str, result: str):
    self._probe_results[probe_name] = result

  def record_open_port(self, port: int, protocol: str = None, banner_confirmed: bool = False):
    self._open_ports.append(port)
    self._open_port_details.append({"port": port, "protocol": protocol or "unknown", "banner_confirmed": banner_confirmed})
    if banner_confirmed:
      self._banner_confirmed += 1
    else:
      self._banner_guessed += 1
    if protocol:
      self._service_counts[protocol] = self._service_counts.get(protocol, 0) + 1

  def record_finding(self, severity: str):
    self._finding_counts[severity] = self._finding_counts.get(severity, 0) + 1

  def _compute_stats(self, values: list) -> dict | None:
    if not values:
      return None
    sorted_v = sorted(values)
    n = len(sorted_v)
    mean = sum(sorted_v) / n
    median = sorted_v[n // 2] if n % 2 else (sorted_v[n // 2 - 1] + sorted_v[n // 2]) / 2
    stddev = statistics.stdev(sorted_v) if n > 1 else 0
    p95 = sorted_v[int(n * 0.95)] if n >= 20 else sorted_v[-1]
    p99 = sorted_v[int(n * 0.99)] if n >= 100 else sorted_v[-1]
    return {
      "min": round(sorted_v[0], 4),
      "max": round(sorted_v[-1], 4),
      "mean": round(mean, 4),
      "median": round(median, 4),
      "stddev": round(stddev, 4),
      "p95": round(p95, 4),
      "p99": round(p99, 4),
      "count": n,
    }

  def _compute_phase_durations(self) -> dict | None:
    durations = {}
    for phase, start in self._phase_starts.items():
      end = self._phase_ends.get(phase, time.time())
      durations[phase] = round(end - start, 2)
    return durations if durations else None

  def _compute_success_windows(self, window_size: float = 60.0) -> list | None:
    if not self._connection_log:
      return None
    windows = []
    start_time = self._connection_log[0][0]
    end_time = self._connection_log[-1][0]
    t = start_time
    while t < end_time:
      w_end = t + window_size
      entries = [(ts, ok) for ts, ok in self._connection_log if t <= ts < w_end]
      if entries:
        rate = sum(1 for _, ok in entries if ok) / len(entries)
        windows.append({
          "window_start": round(t - start_time, 1),
          "window_end": round(w_end - start_time, 1),
          "success_rate": round(rate, 3),
        })
      t = w_end
    return windows if windows else None

  def _detect_rate_limiting(self) -> bool:
    windows = self._compute_success_windows()
    if not windows or len(windows) < 3:
      return False
    # Detect: last 2 windows have significantly lower success rate than first 2
    first = sum(w["success_rate"] for w in windows[:2]) / 2
    last = sum(w["success_rate"] for w in windows[-2:]) / 2
    return first > 0.5 and last < first * 0.7

  def _detect_blocking(self) -> bool:
    windows = self._compute_success_windows()
    if not windows or len(windows) < 2:
      return False
    # Detect: any window with 0% success rate after a window with >50% success
    for i in range(1, len(windows)):
      if windows[i - 1]["success_rate"] > 0.5 and windows[i]["success_rate"] == 0:
        return True
    return False

  def _compute_port_distribution(self) -> dict | None:
    if not self._open_ports:
      return None
    well_known = sum(1 for p in self._open_ports if p <= 1023)
    registered = sum(1 for p in self._open_ports if 1024 <= p <= 49151)
    ephemeral = sum(1 for p in self._open_ports if p > 49151)
    return {"well_known": well_known, "registered": registered, "ephemeral": ephemeral}

  def _compute_coverage(self) -> dict | None:
    if self._ports_in_range == 0:
      return None
    pct = round(self._ports_scanned / self._ports_in_range * 100, 1) if self._ports_in_range else 0
    return {
      "ports_in_range": self._ports_in_range,
      "ports_scanned": self._ports_scanned,
      "ports_skipped": self._ports_skipped,
      "coverage_pct": pct,
      "open_ports_count": len(self._open_ports),
    }

  def build(self) -> ScanMetrics:
    """Build ScanMetrics from collected raw data. Safe to call at any time."""
    total_connections = sum(self._connection_outcomes.values())
    outcomes = dict(self._connection_outcomes)
    if total_connections > 0:
      outcomes["total"] = total_connections

    probes_attempted = len(self._probe_results)
    probes_completed = sum(1 for v in self._probe_results.values() if v == "completed")
    probes_skipped = sum(1 for v in self._probe_results.values() if v.startswith("skipped"))
    probes_failed = sum(1 for v in self._probe_results.values() if v == "failed")

    banner_total = self._banner_confirmed + self._banner_guessed
    return ScanMetrics(
      phase_durations=self._compute_phase_durations(),
      total_duration=round(time.time() - self._scan_start, 2) if self._scan_start else 0,
      port_scan_delays=self._compute_stats(self._port_scan_delays),
      connection_outcomes=outcomes if total_connections > 0 else None,
      response_times=self._compute_stats(self._response_times),
      slow_ports=None,
      success_rate_over_time=self._compute_success_windows(),
      rate_limiting_detected=self._detect_rate_limiting(),
      blocking_detected=self._detect_blocking(),
      coverage=self._compute_coverage(),
      probes_attempted=probes_attempted,
      probes_completed=probes_completed,
      probes_skipped=probes_skipped,
      probes_failed=probes_failed,
      probe_breakdown=dict(self._probe_results) if self._probe_results else None,
      port_distribution=self._compute_port_distribution(),
      service_distribution=dict(self._service_counts) if self._service_counts else None,
      finding_distribution=dict(self._finding_counts) if self._finding_counts else None,
      open_port_details=list(self._open_port_details) if self._open_port_details else None,
      banner_confirmation={"confirmed": self._banner_confirmed, "guessed": self._banner_guessed} if banner_total > 0 else None,
    )
