"""
Shared / foundational models used across all layers.

  TimelineEvent  — single timeline event
  RiskBreakdown  — risk score components
  ScanMetrics    — operational scan statistics
"""

from __future__ import annotations

from dataclasses import dataclass, asdict


def _strip_none(d: dict) -> dict:
  """Remove keys with None values for cleaner serialization."""
  return {k: v for k, v in d.items() if v is not None}


@dataclass(frozen=True)
class TimelineEvent:
  type: str                         # created | started | scan_completed | pass_completed | finalized | stopped | ...
  label: str
  date: float                       # unix timestamp
  actor: str = ""
  actor_type: str = "system"        # user | system | node
  meta: dict = None

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> TimelineEvent:
    return cls(
      type=d["type"],
      label=d["label"],
      date=d["date"],
      actor=d.get("actor", ""),
      actor_type=d.get("actor_type", "system"),
      meta=d.get("meta"),
    )


@dataclass(frozen=True)
class RiskBreakdown:
  findings_score: float = 0
  open_ports_score: float = 0
  breadth_score: float = 0
  credentials_penalty: float = 0
  raw_total: float = 0
  finding_counts: dict = None       # { "CRITICAL": 2, "HIGH": 5, ... }

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> RiskBreakdown:
    return cls(
      findings_score=d.get("findings_score", 0),
      open_ports_score=d.get("open_ports_score", 0),
      breadth_score=d.get("breadth_score", 0),
      credentials_penalty=d.get("credentials_penalty", 0),
      raw_total=d.get("raw_total", 0),
      finding_counts=d.get("finding_counts"),
    )


@dataclass(frozen=True)
class ScanMetrics:
  """
  Operational statistics collected during scanning.

  Attached to each report level (thread → node → pass → archive).
  Persisted in R1FS at every level for historical reference.

  Thread level collects raw data; aggregation levels carry computed
  distributions (percentiles, stddev) rather than raw arrays.
  """

  # ── Timing profile ──
  phase_durations: dict = None      # { "port_scan": 480.2, "fingerprint": 120.5,
                                    #   "service_probes": 95.1, "web_tests": 140.3,
                                    #   "correlation": 2.1 }  seconds per phase
  total_duration: float = 0

  # Port scan timing (actual inter-probe delays)
  port_scan_delays: dict = None     # { "min": 0.1, "max": 1.5, "mean": 0.78,
                                    #   "median": 0.72, "stddev": 0.31,
                                    #   "p95": 1.3, "p99": 1.48 }

  # ── Connection behavior ──
  connection_outcomes: dict = None  # { "connected": 847, "timeout": 142,
                                    #   "refused": 11, "reset": 0,
                                    #   "error": 0, "total": 1000 }
  response_times: dict = None       # { "min": 0.008, "max": 2.1, "mean": 0.045,
                                    #   "median": 0.032, "p95": 0.12, "p99": 0.45 }
                                    # TCP connection time distribution (seconds)
  slow_ports: list = None           # [ { "port": 443, "avg_ms": 2100,
                                    #     "reason": "possible_waf" } ]

  # ── Detection indicators ──
  success_rate_over_time: list = None  # [ { "window_start": 0, "window_end": 60,
                                       #     "success_rate": 0.98 }, ... ]
                                       # degrading rate = scan likely detected
  rate_limiting_detected: bool = False
  blocking_detected: bool = False

  # ── Coverage ──
  coverage: dict = None             # { "ports_in_range": 1000, "ports_scanned": 1000,
                                    #   "ports_skipped": 0, "coverage_pct": 100.0 }
  probes_attempted: int = 0
  probes_completed: int = 0
  probes_skipped: int = 0
  probes_failed: int = 0
  probe_breakdown: dict = None      # { "_service_info_http": "completed",
                                    #   "_web_test_xss": "skipped:no_http",
                                    #   "_service_info_modbus": "skipped:disabled" }

  # ── Discovery stats ──
  port_distribution: dict = None    # { "well_known": 4, "registered": 2, "ephemeral": 1 }
  service_distribution: dict = None # { "http": 3, "ssh": 1, "mysql": 1 }
  finding_distribution: dict = None # { "CRITICAL": 1, "HIGH": 3, "MEDIUM": 7, ... }

  # ── Open port details ──
  open_port_details: list = None    # [ { "port": 22, "protocol": "ssh", "banner_confirmed": True }, ... ]
  banner_confirmation: dict = None  # { "confirmed": 3, "guessed": 2 }

  def to_dict(self) -> dict:
    return _strip_none(asdict(self))

  @classmethod
  def from_dict(cls, d: dict) -> ScanMetrics:
    return cls(
      phase_durations=d.get("phase_durations"),
      total_duration=d.get("total_duration", 0),
      port_scan_delays=d.get("port_scan_delays"),
      connection_outcomes=d.get("connection_outcomes"),
      response_times=d.get("response_times"),
      slow_ports=d.get("slow_ports"),
      success_rate_over_time=d.get("success_rate_over_time"),
      rate_limiting_detected=d.get("rate_limiting_detected", False),
      blocking_detected=d.get("blocking_detected", False),
      coverage=d.get("coverage"),
      probes_attempted=d.get("probes_attempted", 0),
      probes_completed=d.get("probes_completed", 0),
      probes_skipped=d.get("probes_skipped", 0),
      probes_failed=d.get("probes_failed", 0),
      probe_breakdown=d.get("probe_breakdown"),
      port_distribution=d.get("port_distribution"),
      service_distribution=d.get("service_distribution"),
      finding_distribution=d.get("finding_distribution"),
      open_port_details=d.get("open_port_details"),
      banner_confirmation=d.get("banner_confirmation"),
    )
