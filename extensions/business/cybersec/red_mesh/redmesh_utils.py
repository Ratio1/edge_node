import uuid
import threading
import socket
import json
import ftplib
import requests
import traceback
import random

from copy import deepcopy

from .service_mixin import _ServiceInfoMixin
from .web_mixin import _WebTestsMixin


COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 445,
  502, 1433, 1521, 27017, 3306, 3389, 5432, 5900,
  8080, 8443, 9200, 11211
]

# EXCEPTIONS = [64297]

ALL_PORTS = [port for port in range(1, 65536)]

class PentestLocalWorker(
  _ServiceInfoMixin,
  _WebTestsMixin
):
  """
  Execute a pentest workflow against a target on a dedicated thread.

  The worker scans ports, gathers service banners, and performs lightweight web
  security probes. It maintains local state and exposes status for aggregation.

  Attributes
  ----------
  target : str
    Hostname or IP being scanned.
  job_id : str
    Identifier tying the worker to a network job.
  initiator : str
    Address that announced the job.
  local_worker_id : str
    Unique identifier per worker instance.
  state : dict
    Mutable status including ports scanned, open ports, and findings.
  """

  def __init__(
    self, 
    owner, 
    target, 
    job_id : str,
    initiator : str, 
    local_id_prefix : str,
    worker_target_ports=COMMON_PORTS,
    exceptions=None,
    included_tests=None,
    excluded_tests=None,
    port_order=None,
    pacing=None,
  ):
    """
    Initialize a pentest worker with target ports and exclusions.

    Parameters
    ----------
    owner : object
      Parent object providing logger `P`.
    target : str
      Hostname or IP to scan.
    job_id : str
      Identifier of the job.
    initiator : str
      Address that announced the job.
    local_id_prefix : str
      Prefix used to derive a human-friendly worker id.
    worker_target_ports : list[int], optional
      Ports assigned to this worker; defaults to common ports.
    exceptions : list[int], optional
      Ports to exclude from scanning.
    included_tests : list[str] | None, optional
      Whitelist of tests to run; None runs all.
    excluded_tests : list[str] | None, optional
      Blacklist of tests to skip.
    port_order : str, optional
      SEQUENTIAL or SHUFFLE for port iteration.
    pacing : dict | None, optional
      Stealth pauses: {"pause_interval": int, "pause_duration": float}; None disables pacing.

    Raises
    ------
    ValueError
      If no ports remain after applying exceptions.
    """
    self.included_tests = included_tests if included_tests is not None else getattr(owner, "cfg_included_tests", None)
    self.excluded_tests = excluded_tests if excluded_tests is not None else getattr(owner, "cfg_excluded_tests", [])
    self.port_order = port_order if port_order is not None else getattr(owner, "cfg_port_order", "SHUFFLE")
    self.pacing = pacing if pacing is not None else getattr(owner, "cfg_pacing", None)
    if exceptions is None:
      exceptions = []
    self.target = target
    self.job_id = job_id
    self.initiator = initiator
    self.local_worker_id = "RM-{}-{}".format(
      local_id_prefix, str(uuid.uuid4())[:4]
    )
    self.owner = owner

    # port handling
    if exceptions:
      self.P("Given exceptions: {}".format(exceptions))
    if set(exceptions or []) & set(worker_target_ports or []):
      self.P("Some target ports are in the exceptions list, adjusting...")
      self.exceptions = list(exceptions)
    else:
      if exceptions:
        self.P("Given exceptions not matching worker target ports. Skipping exceptions.")
      self.exceptions = []
    if worker_target_ports is None:
      worker_target_ports = ALL_PORTS      
    worker_target_ports = [p for p in worker_target_ports if p not in exceptions]
    if not worker_target_ports:
      raise ValueError("No ports available for worker after applying exceptions.")
    self.initial_ports = list(worker_target_ports)
    # end port handling

    # Initialize job state with default scanning parameters
    self.state = {
      "job_id" : self.job_id,
      "initiator" : self.initiator,
      "target": self.target,
      "ports_to_scan": list(worker_target_ports),
      "open_ports": [],
      "ports_scanned": [],
      
      "service_info": {},
      "web_tested": False,
      "web_tests_info": {},
      
      "completed_tests": [],
      "done": False,
      "canceled": False,
      "current_stage": "INITIALIZED",
    }
    # pacing state
    self.action_counter = 0
    self.next_pause_at = None
    if self.pacing:
      base_interval = float(self.pacing.get("pause_interval", 0) or 0)
      if base_interval > 0:
        self.next_pause_at = int(base_interval * random.uniform(0.8, 1.2))
    self.__features = self._get_all_features()
    self.P("Initialized worker {} on {} ports [{}-{}]...".format(
      self.local_worker_id,
      len(worker_target_ports),
      min(worker_target_ports),
      max(worker_target_ports)
    ))
    return

  def _get_all_features(self, categs=False):
    """
    Discover available probe methods on this worker.

    Parameters
    ----------
    categs : bool, optional
      If True, return dict by category; otherwise flat list.

    Returns
    -------
    dict | list
      Service and web test method names.
    """
    features = {} if categs else []
    PREFIXES = ["_service_info_", "_web_test_"]
    for prefix in PREFIXES:
      methods = [method for method in dir(self) if method.startswith(prefix)]
      if categs:
        features[prefix[1:-1]] = methods
      else:
        features.extend(methods)
    return features  

  def _should_run(self, test_name):
    """
    Check if a test should run based on include/exclude filters.
    """
    if self.included_tests is not None and test_name not in self.included_tests:
      return False
    if test_name in (self.excluded_tests or []):
      return False
    return True

  def _maybe_pause(self):
    """
    Pause execution based on pacing settings with jitter and stop awareness.

    Jitter ranges:
    - pause_interval: 0.8-1.2x → actual pause frequency is varied around the configured interval to break patterns
      e.g. pause_interval=10 means next pause after ~8-12 actions.
    - pause_duration: 0.5-1.5x → actual sleep time is varied around the configured duration to avoid fixed timing
      e.g. pause_duration=2.0 means sleep ~1.0-3.0 seconds.

    pause_interval controls how often we pause (every ~N actions); pause_duration
    controls how long each pause lasts.
    This is the “Dune sand walking” pacing: irregular, human-like delays to avoid
    predictable scan patterns.
    """
    if not self.pacing:
      return
    if self.next_pause_at is None:
      base_interval = float(self.pacing.get("pause_interval", 0) or 0)
      if base_interval <= 0:
        return
      self.next_pause_at = int(base_interval * random.uniform(0.8, 1.2))
    self.action_counter += 1
    if self.action_counter < self.next_pause_at:
      return

    previous_stage = self.state.get("current_stage", "SCANNING")
    base_duration = float(self.pacing.get("pause_duration", 0) or 0)
    if base_duration < 0:
      base_duration = 0
    duration = base_duration * random.uniform(0.5, 1.5)
    self.state["current_stage"] = "PAUSED"
    interrupted = self.stop_event.wait(timeout=duration)
    if interrupted:
      self.state["current_stage"] = "STOPPING"
    else:
      self.state["current_stage"] = previous_stage

    self.action_counter = 0
    base_interval = float(self.pacing.get("pause_interval", 0) or 0)
    if base_interval > 0:
      self.next_pause_at = int(base_interval * random.uniform(0.8, 1.2))
  
  @staticmethod
  def get_worker_specific_result_fields():
    """
    Define fields that require aggregation functions across workers.

    Returns
    -------
    dict
      Mapping of field name to aggregation callable/type.
    """
    return {
      "start_port" : min,
      "end_port" : max,
      "ports_scanned" : sum,      
      
      "open_ports" : list,
      "service_info" : dict,
      "web_tests_info" : dict,
      "completed_tests" : list,
    }
  
  
  def get_status(self, for_aggregations=False):    
    """
    Produce a status snapshot for this worker.

    Parameters
    ----------
    for_aggregations : bool, optional
      If True, omit volatile fields to simplify merges.

    Returns
    -------
    dict
      Worker status including progress and findings.
    """
    completed_tests = self.state.get("completed_tests", [])
    max_features = len(self.__features) + 1 # +1 from port scanning
    progress = f"{(len(completed_tests) / max_features) * 100 if self.__features else 0:.1f}%"
    
    dct_status = {
      # same data for all workers below
      "job_id": self.job_id,
      "initiator": self.initiator,
      "target": self.target,      
      "web_tested" : self.state["web_tested"],
    }
      # specific worker data
    if not for_aggregations:
      dct_status["local_worker_id"] = self.local_worker_id
      dct_status["progress"] = progress
      dct_status["done"] = self.state["done"]
      dct_status["canceled"] = self.state.get("canceled", False)

    dct_status["start_port"] = min(self.initial_ports)
    dct_status["end_port"] = max(self.initial_ports)
    dct_status["exceptions"] = self.exceptions
    dct_status["ports_scanned"] = len(self.state["ports_scanned"])
    dct_status["nr_open_ports"] = len(self.state["open_ports"])
    dct_status["open_ports"] = self.state["open_ports"]

    dct_status["service_info"] = self.state["service_info"]

    dct_status["web_tests_info"] = self.state["web_tests_info"]

    dct_status["completed_tests"] = self.state["completed_tests"]
    dct_status["current_stage"] = self.state.get("current_stage")

    return dct_status


  def P(self, s, **kwargs):
    """
    Log a message with worker context prefix.

    Parameters
    ----------
    s : str
      Message to emit.
    **kwargs
      Additional logging keyword arguments.

    Returns
    -------
    Any
      Result of owner logger.
    """
    s = f"[{self.local_worker_id}:{self.target}] {s}"
    self.owner.P(s, **kwargs)
    return


  def start(self):
    """
    Start the pentest job in a new thread.

    Returns
    -------
    None
    """
    # Event to signal early stopping
    self.stop_event = threading.Event()
    # Thread for running the job
    self.thread = threading.Thread(target=self.execute_job, daemon=True)
    self.thread.start()
    return


  def stop(self):
    """
    Signal the job to stop early.

    Returns
    -------
    None
    """
    self.P(f"Stop requested for job {self.job_id} on worker {self.local_worker_id}")
    self.stop_event.set()
    return
  
  
  def _check_stopped(self):
    """
    Determine whether the worker should cease execution.

    Returns
    -------
    bool
      True if done or stop event set.
    """
    return self.state["done"] or self.stop_event.is_set()


  def execute_job(self):
    """
    Run the full pentesting workflow: port scanning, service info gathering,
    and web vulnerability tests, until the job is complete or stopped.

    Returns
    -------
    None
    """
    try:
      self.state["current_stage"] = "SCANNING"
      self.P(f"Starting pentest job.")

      if not self._check_stopped():
        self._scan_ports_step()

      if not self._check_stopped():
        self.state["current_stage"] = "PROBING"
        self._gather_service_info()
        self.state["completed_tests"].append("service_info_completed")

      if not self._check_stopped():
        self.state["current_stage"] = "TESTING"
        self._run_web_tests()
        self.state["completed_tests"].append("web_tests_completed")

      self.state['done'] = True
      self.state["current_stage"] = "COMPLETED"
      self.P(f"Job completed. Ports open and checked: {self.state['open_ports']}")

      # If stopped before completion
      if self.stop_event.is_set():
        self.P(f"Job was stopped before completion.")
        self.state['canceled'] = True
    except Exception as e:
      self.P(f"Exception in job execution: {e}:\n{traceback.format_exc()}", color='r')
      self.state['done'] = True
      self.state["current_stage"] = "COMPLETED"
      
    
    return


  def _scan_ports_step(self, batch_size=None, batch_nr=1):
    """
    Scan a batch of ports from the remaining list to identify open ports.

    Parameters
    ----------
    batch_size : int, optional
      Number of ports per batch; scans all remaining when None.
    batch_nr : int, optional
      Batch index (used for logging).

    Returns
    -------
    None
    """
    REGISTER_PROGRESS_EACH = 500

    if len(self.state["ports_to_scan"]) == 0:
      self.P("No ports to scan.")
      return

    target = self.target
    ports = deepcopy(self.state["ports_to_scan"])
    if self.port_order == "SHUFFLE":
      random.shuffle(ports)
    if not ports:
      return
    if batch_size is None:
      ports_batch = ports
    else:
      start_batch = (batch_nr - 1) * batch_size
      ports_batch = ports[start_batch:start_batch + batch_size]
    nr_ports = len(ports_batch)
    self.P(f"Scanning {nr_ports} ports in batch {batch_nr}.")
    show_progress = False
    if len(ports_batch) > 1000:
      # Avoid noisy progress logs on tiny batches.
      show_progress = True
    for i, port in enumerate(ports_batch):
      if self.stop_event.is_set():
        return
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
      # endtry
      self.state["ports_scanned"].append(port)    
      self.state["ports_to_scan"].remove(port)  
      self._maybe_pause()
      if ((i + 1) % REGISTER_PROGRESS_EACH) == 0:
        scan_ports_step_progress = (i + 1) / nr_ports * 100
        str_progress = f"{scan_ports_step_progress:.0f}%"
        # now we assume that port scan is first step so we modify 1st stage continously 
        # and we do not append
        self.state["completed_tests"] = [f"scan_ports_step_{str_progress}"]
        if show_progress:
          self.P(f"Port scanning progress on {target}: {str_progress}")
    # end for each port in batch
    left_ports = self.state["ports_to_scan"]
    if not left_ports:
      self.P(f"[{target}] Port scanning completed. {len(self.state['open_ports'])} open ports.")
    else:
      self.P(f"[{target}] Port scanning not completed. Remaining ports: {left_ports}.")
    self.state["completed_tests"].append("scan_ports_step_completed")
    return


  def _gather_service_info(self):
    """
    Gather banner or basic information from each newly open port.

    Returns
    -------
    list
      Aggregated string findings per method (may be empty).
    """
    open_ports = self.state["open_ports"]
    if len(open_ports) == 0:
      self.P("No open ports to gather service info from.")
      return
    self.P(f"Gathering service info for {len(open_ports)} open ports.")
    self.state["current_stage"] = "PROBING"
    target = self.target
    service_info_methods = [
      method for method in dir(self)
      if method.startswith("_service_info_") and self._should_run(method)
    ]
    aggregated_info = []
    for method in service_info_methods:
      func = getattr(self, method)
      method_info = []
      for port in open_ports:
        if self.stop_event.is_set():
          continue
        info = func(target, port)
        if port not in self.state["service_info"]:
          self.state["service_info"][port] = {}
        self.state["service_info"][port][method] = info
        if info is not None:
          method_info.append(f"{method}: {port}: {info}")
        self._maybe_pause()
      if method_info:
        aggregated_info.extend(method_info)
        self.P(
          f"Method {method} findings:\n{json.dumps(method_info, indent=2)}"
        )
      self.state["completed_tests"].append(method)
    # end for each service info method
    return aggregated_info


  def _run_web_tests(self):
    """
    Perform basic web vulnerability tests if a web service is open.

    Returns
    -------
    list
      Collected findings per test method (may be empty).
    """
    open_ports = self.state["open_ports"]
    if len(open_ports) == 0:
      self.P("No open ports to run web tests on.")
      return
    self.state["current_stage"] = "TESTING"
    
    ports_to_test = list(open_ports)
    self.P(
      f"Running web tests on {len(ports_to_test)} ports."
    )
    target = self.target
    
    if not ports_to_test:
      self.state["web_tested"] = True
      return
    result = []
    web_tests_methods = [
      method for method in dir(self)
      if method.startswith("_web_test_") and self._should_run(method)
    ]
    for method in web_tests_methods:
      func = getattr(self, method)
      for port in ports_to_test:
        if self.stop_event.is_set():
          return      
        iter_result = func(target, port)
        if iter_result:
          result.append(f"{method}:{port} {iter_result}")
        if port not in self.state["web_tests_info"]:
          self.state["web_tests_info"][port] = {}
        self.state["web_tests_info"][port][method] = iter_result
        self._maybe_pause()
      # end for each port of current method
      self.state["completed_tests"].append(method) # register completed method for port    
    # end for each web test method
    self.state["web_tested"] = True
    return result
