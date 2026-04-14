"""
Abstract base for all RedMesh scan workers.

Defines the contract that pentester_api_01.py relies on:
threading model, state shape, status reporting, and metrics.
PentestLocalWorker (network) and GrayboxLocalWorker (webapp) both
inherit from this class.
"""

import threading
import uuid
from abc import ABC, abstractmethod

from .metrics_collector import MetricsCollector


class BaseLocalWorker(ABC):
  """
  Abstract base class for scan workers.

  Subclasses MUST:
  - Call super().__init__() to initialize shared state
  - Implement execute_job() with the scan pipeline
  - Implement get_status() for aggregation
  - Implement get_worker_specific_result_fields() for aggregation
  - Set self.initial_ports in __init__ before start() is called
  - Initialize self.state with at minimum the required keys (see below)

  The API (pentester_api_01.py) accesses:
  - self.thread.is_alive() to check completion
  - self.stop_event.is_set() to check cancellation
  - self.state["done"] / self.state["canceled"] for status
  - self.initiator for job routing
  - self.local_worker_id as dict key in scan_jobs
  - self.initial_ports for port count in progress
  - self.metrics.build().to_dict() for live metrics
  - self.get_status() for report aggregation
  - self.start() / self.stop() for lifecycle

  State dict required keys (subclass must include all of these):
    done: bool, canceled: bool, open_ports: list[int],
    ports_scanned: list[int], completed_tests: list[str],
    service_info: dict, web_tests_info: dict, port_protocols: dict,
    correlation_findings: list
  """

  def __init__(
    self,
    owner,
    job_id: str,
    initiator: str,
    local_id_prefix: str,
    target: str,
  ):
    """
    Initialize shared worker state.

    Parameters
    ----------
    owner : object
      Parent object providing logger P().
    job_id : str
      Job identifier.
    initiator : str
      Network address that announced the job.
    local_id_prefix : str
      Prefix for human-readable worker ID. The full ID is
      "RM-{prefix}-{uuid4[:4]}" and is used as the dict key in
      scan_jobs[job_id]. Both PentestLocalWorker and
      GrayboxLocalWorker use this same attribute name.
    target : str
      Scan target (IP for network, hostname for webapp).
    """
    self.owner = owner
    self.job_id = job_id
    self.initiator = initiator
    self.target = target
    self.local_worker_id = "RM-{}-{}".format(
      local_id_prefix, str(uuid.uuid4())[:4]
    )

    # Threading — set by start(), checked by API
    self.thread: threading.Thread | None = None
    self.stop_event: threading.Event | None = None

    # Metrics — accessed by _publish_live_progress via
    # worker.metrics.build().to_dict()
    self.metrics = MetricsCollector()

    # Subclass MUST set self.initial_ports in __init__ before start().
    # _publish_live_progress reads len(self.initial_ports).
    self.initial_ports: list[int] = []

    # Subclass MUST initialize self.state with at minimum the required keys.
    # The base class does NOT pre-populate — each subclass builds its
    # own state dict with scan-type-specific keys on top of these.
    self.state: dict = {}

  def start(self):
    """
    Create thread and stop_event, start execute_job in background.

    Called by pentester_api_01.py after construction.
    """
    self.stop_event = threading.Event()
    self.thread = threading.Thread(target=self.execute_job, daemon=True)
    self.thread.start()

  def stop(self):
    """
    Signal the worker to stop.

    Called by _check_running_jobs, stop_and_delete_job, hard stop.
    Sets stop_event so _check_stopped() returns True.
    Also sets state["canceled"] for backward compat with code that
    reads the flag directly instead of checking stop_event.

    Ordering guarantee: stop_event is set BEFORE state["canceled"].
    This ensures _check_stopped() sees the stop signal even if
    there's a context switch between the two assignments. The GIL
    makes dict writes atomic, so state["canceled"] is always
    consistent.
    """
    self.P(f"Stop requested for job {self.job_id} on worker {self.local_worker_id}")
    if self.stop_event:
      self.stop_event.set()
    self.state["canceled"] = True

  def _check_stopped(self) -> bool:
    """
    Check whether the worker should cease execution.

    Returns True if done or stop_event is set or canceled flag is set.
    Subclasses call this between phases to support graceful cancellation.
    """
    if self.state.get("done", False):
      return True
    if self.state.get("canceled", False):
      return True
    if self.stop_event is not None and self.stop_event.is_set():
      return True
    return False

  @abstractmethod
  def execute_job(self) -> None:
    """
    Run the scan pipeline. Called on the worker thread.

    Subclass MUST:
    - Set self.state["done"] = True when finished (in finally block)
    - Set self.state["canceled"] = True if _check_stopped() was True
    - Call self.metrics.start_scan() at the beginning
    - Call self.metrics.phase_start/phase_end for each phase
    - Append phase markers to self.state["completed_tests"]
    """
    ...

  @abstractmethod
  def get_status(self, for_aggregations: bool = False) -> dict:
    """
    Return a status snapshot for aggregation.

    Called by _maybe_close_jobs, _close_job, get_test_status.

    The returned dict MUST include:
    - job_id, initiator, target
    - open_ports (list), ports_scanned, completed_tests (list)
    - service_info (dict), web_tests_info (dict), port_protocols (dict)
    - correlation_findings (list)
    - scan_metrics (dict from self.metrics.build().to_dict())

    If not for_aggregations:
    - local_worker_id, progress, done, canceled
    """
    ...

  @staticmethod
  @abstractmethod
  def get_worker_specific_result_fields() -> dict:
    """
    Define aggregation strategy per result field.

    Called by _get_aggregated_report to know how to merge results
    from multiple workers of the same job.

    Returns dict mapping field name to aggregation type/callable:
    - list: union (deduplicate + sort)
    - dict: deep merge
    - sum: sum values
    - min/max: take min/max
    """
    ...

  def P(self, s, **kwargs):
    """Log a message with worker context prefix."""
    s = f"[{self.local_worker_id}:{self.target}] {s}"
    self.owner.P(s, **kwargs)
