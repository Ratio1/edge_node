import uuid
import random
import threading
import socket
import json
import ftplib
import requests
import traceback
import time

from copy import deepcopy

from .service_mixin import _ServiceInfoMixin
from .web_discovery_mixin import _WebDiscoveryMixin
from .web_hardening_mixin import _WebHardeningMixin
from .web_api_mixin import _WebApiExposureMixin
from .web_injection_mixin import _WebInjectionMixin
from .correlation_mixin import _CorrelationMixin
from .constants import (
  PROBE_PROTOCOL_MAP, WEB_PROTOCOLS,
  WELL_KNOWN_PORTS as _WELL_KNOWN_PORTS,
  FINGERPRINT_TIMEOUT, FINGERPRINT_MAX_BANNER, FINGERPRINT_HTTP_TIMEOUT,
  FINGERPRINT_NUDGE_TIMEOUT,
)


COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 161, 443, 445,
  502, 1433, 1521, 27017, 3306, 3389, 5432, 5900,
  8080, 8443, 9200, 11211
]

# EXCEPTIONS = [64297]

ALL_PORTS = [port for port in range(1, 65536)]

class PentestLocalWorker(
  _ServiceInfoMixin,
  _WebDiscoveryMixin,
  _WebHardeningMixin,
  _WebApiExposureMixin,
  _WebInjectionMixin,
  _CorrelationMixin,
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
    worker_target_ports=None,
    exceptions=None,
    excluded_features=None,
    enabled_features=None,
    scan_min_delay: float = 0.0,
    scan_max_delay: float = 0.0,
    ics_safe_mode: bool = True,
    rate_limit_enabled: bool = True,
    scanner_identity: str = "probe.redmesh.local",
    scanner_user_agent: str = "",
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
    excluded_features: list[str], optional
      List of feature method names to exclude.
    enabled_features: list[str], optional
      List of feature method names to enable (overrides exclusions).
    scan_min_delay : float, optional
      Minimum random delay (seconds) between operations (Dune sand walking).
    scan_max_delay : float, optional
      Maximum random delay (seconds) between operations (Dune sand walking).
    ics_safe_mode : bool, optional
      Halt probing when ICS/SCADA indicators are detected.
    rate_limit_enabled : bool, optional
      Enforce minimum 100ms delay between probes when sand walking is disabled.
    scanner_identity : str, optional
      EHLO domain for SMTP probes.
    scanner_user_agent : str, optional
      HTTP User-Agent header for web probes.

    Raises
    ------
    ValueError
      If no ports remain after applying exceptions.
    """
    if worker_target_ports is None:
      worker_target_ports = COMMON_PORTS
    if excluded_features is None:
      excluded_features = []
    if enabled_features is None:
      enabled_features = []
    if exceptions is None:
      exceptions = []

    self.target = target
    self.job_id = job_id
    self.initiator = initiator
    self.local_worker_id = "RM-{}-{}".format(
      local_id_prefix, str(uuid.uuid4())[:4]
    )
    self.owner = owner
    self.scan_min_delay = scan_min_delay
    self.scan_max_delay = scan_max_delay
    self.ics_safe_mode = ics_safe_mode
    self._ics_detected = False
    self.rate_limit_enabled = rate_limit_enabled
    self.scanner_identity = scanner_identity
    self.scanner_user_agent = scanner_user_agent

    self.P(f"Initializing pentest worker {self.local_worker_id} for target {self.target}...")
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
      
      "port_protocols": {},
      "port_banners": {},

      "completed_tests": [],
      "done": False,
      "canceled": False,

      "scan_metadata": {
        "os_claims": {},
        "internal_ips": [],
        "container_ids": [],
        "timezone_hints": [],
        "server_versions": {},
      },
      "correlation_findings": [],
    }
    self.__all_features = self._get_all_features()

    self.__excluded_features = excluded_features
    self.__enabled_features = enabled_features
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
      "port_protocols" : dict,
      "port_banners" : dict,
      "scan_metadata" : dict,
      "correlation_findings" : list,
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
    open_ports = self.state.get("open_ports", [])
    if open_ports:
      # Full work: port scan + fingerprint + all enabled features + 2 completion markers
      max_features = len(self.__enabled_features) + 4
    else:
      # No open ports: port scan + fingerprint + service_info_completed + web_tests_completed
      max_features = 4
    progress = f"{(len(completed_tests) / max_features) * 100:.1f}%"
    
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

    dct_status["port_protocols"] = self.state.get("port_protocols", {})
    dct_status["port_banners"] = self.state.get("port_banners", {})

    dct_status["scan_metadata"] = self.state.get("scan_metadata", {})
    dct_status["correlation_findings"] = self.state.get("correlation_findings", [])

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


  def _interruptible_sleep(self):
    """
    Sleep for a random interval (Dune sand walking).

    Returns
    -------
    bool
      True if stop was requested (should exit), False otherwise.
    """
    if self.scan_max_delay <= 0:
      if self.rate_limit_enabled:
        time.sleep(0.1)  # Minimum 100ms between probes
        return self.stop_event.is_set()
      return False  # Delays disabled, no rate limit
    delay = random.uniform(self.scan_min_delay, self.scan_max_delay)
    time.sleep(delay)
    # TODO: while elapsed < delay with sleep(0.1) could be used for more granular interruptible sleep
    # Check if stop was requested during sleep
    return self.stop_event.is_set()


  def execute_job(self):
    """
    Run the full pentesting workflow: port scanning, service info gathering,
    and web vulnerability tests, until the job is complete or stopped.

    Returns
    -------
    None
    """
    try:
      self.P(f"Starting pentest job.")

      if not self._check_stopped():
        self._scan_ports_step()

      if not self._check_stopped():
        self._fingerprint_ports()
        self.state["completed_tests"].append("fingerprint_completed")

      if not self._check_stopped():
        self._gather_service_info()
        self.state["completed_tests"].append("service_info_completed")

      if not self._check_stopped():
        self._run_web_tests()
        self.state["completed_tests"].append("web_tests_completed")

      if not self._check_stopped():
        self._post_scan_correlate()
        self.state["completed_tests"].append("correlation_completed")

      self.state['done'] = True
      self.P(f"Job completed. Ports open and checked: {self.state['open_ports']}")

      # If stopped before completion
      if self.stop_event.is_set():
        self.P(f"Job was stopped before completion.")
        self.state['canceled'] = True
    except Exception as e:
      self.P(f"Exception in job execution: {e}:\n{traceback.format_exc()}", color='r')
      self.state['done'] = True
      
    
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

      if ((i + 1) % REGISTER_PROGRESS_EACH) == 0:
        scan_ports_step_progress = (i + 1) / nr_ports * 100
        str_progress = f"{scan_ports_step_progress:.0f}%"
        # now we assume that port scan is first step so we modify 1st stage continously 
        # and we do not append
        self.state["completed_tests"] = [f"scan_ports_step_{str_progress}"]
        if show_progress:
          self.P(f"Port scanning progress on {target}: {str_progress}")

      # Dune sand walking - random delay after each port scan
      if self._interruptible_sleep():
        # TODO: LOGGING "returning early from loop 5/300 iteration"
        return  # Stop was requested during sleep
    #end for each port

    left_ports = self.state["ports_to_scan"]
    if not left_ports:
      self.P(f"[{target}] Port scanning completed. {len(self.state['open_ports'])} open ports.")
    else:
      self.P(f"[{target}] Port scanning not completed. Remaining ports: {left_ports}.")
    self.state["completed_tests"].append("scan_ports_step_completed")
    return


  def _fingerprint_ports(self):
    """
    Classify each open port by protocol using passive banner grabbing.

    For each open port the method attempts, in order:

    1. **Passive banner grab** — connect and recv without sending data.
    2. **Banner-based classification** — pattern-match known protocol greetings.
    3. **Well-known port lookup** — fall back to ``WELL_KNOWN_PORTS``.
    4. **Generic nudge probe** — send ``\\r\\n`` to elicit a response from
       services that wait for client input (honeypots, RPC, custom daemons).
    5. **Active HTTP probe** — minimal ``HEAD /`` request for silent HTTP servers.
    6. **Default** — mark the port as ``"unknown"``.

    Results are stored in ``state["port_protocols"]`` and
    ``state["port_banners"]``.

    Returns
    -------
    None
    """
    open_ports = self.state["open_ports"]
    if not open_ports:
      self.P("No open ports to fingerprint.")
      return

    target = self.target
    port_protocols = {}
    port_banners = {}

    self.P(f"Fingerprinting {len(open_ports)} open ports.")

    for port in open_ports:
      if self.stop_event.is_set():
        return

      protocol = None
      banner_text = ""

      # --- 1. Passive banner grab ---
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(FINGERPRINT_TIMEOUT)
        sock.connect((target, port))
        try:
          raw = sock.recv(FINGERPRINT_MAX_BANNER)
        except (socket.timeout, OSError):
          raw = b""
        sock.close()
      except Exception:
        raw = b""

      # --- Sanitize banner ---
      if raw:
        banner_text = ''.join(
          ch if 32 <= ord(ch) < 127 else '.' for ch in raw[:FINGERPRINT_MAX_BANNER].decode("utf-8", errors="replace")
        )

      # --- 2. Classify banner by content ---
      if raw:
        text = raw.decode("utf-8", errors="replace")
        text_upper = text.upper()

        if text.startswith("SSH-"):
          protocol = "ssh"
        elif text.startswith("220"):
          if "FTP" in text_upper:
            protocol = "ftp"
          elif "SMTP" in text_upper or "ESMTP" in text_upper:
            protocol = "smtp"
          else:
            protocol = _WELL_KNOWN_PORTS.get(port, "ftp")
        elif text.startswith("RFB "):
          protocol = "vnc"
        elif len(raw) >= 7 and raw[3:4] == b'\x00' and raw[4:5] == b'\x0a':
          # MySQL greeting: 3-byte payload len + seq=0x00 + protocol version 0x0a + version string
          # Verify version string at byte 5 is printable ASCII (e.g. "8.0.28\x00")
          # to avoid false positives on arbitrary binary data.
          _ver_end = raw.find(b'\x00', 5)
          if _ver_end > 5 and all(32 <= b < 127 for b in raw[5:_ver_end]):
            protocol = "mysql"
        elif "login:" in text.lower() or raw[0:1] == b'\xff':
          protocol = "telnet"
        elif text.startswith("HTTP/"):
          protocol = "http"
        elif text.startswith("+OK"):
          protocol = "pop3"
        elif text.startswith("* OK"):
          protocol = "imap"

      # --- 3. Well-known port lookup ---
      if protocol is None:
        protocol = _WELL_KNOWN_PORTS.get(port)

      # --- 4. Generic nudge probe ---
      # Some services (honeypots, RPC, custom daemons) don't speak first
      # but will respond to any input.  Send a minimal \r\n nudge.
      if protocol is None:
        try:
          nudge_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          nudge_sock.settimeout(FINGERPRINT_NUDGE_TIMEOUT)
          nudge_sock.connect((target, port))
          nudge_sock.sendall(b"\r\n")
          try:
            nudge_resp = nudge_sock.recv(FINGERPRINT_MAX_BANNER)
          except (socket.timeout, OSError):
            nudge_resp = b""
          nudge_sock.close()
        except Exception:
          nudge_resp = b""

        if nudge_resp:
          nudge_text = nudge_resp.decode("utf-8", errors="replace")
          if not banner_text:
            banner_text = ''.join(
              ch if 32 <= ord(ch) < 127 else '.'
              for ch in nudge_text[:FINGERPRINT_MAX_BANNER]
            )
          if nudge_text.startswith("HTTP/"):
            protocol = "http"
          elif "<html" in nudge_text.lower() or "<HTML" in nudge_text:
            protocol = "http"
          elif nudge_text.startswith("SSH-"):
            protocol = "ssh"
          elif nudge_text.startswith("+OK"):
            protocol = "pop3"
          elif nudge_text.startswith("* OK"):
            protocol = "imap"
          elif "login:" in nudge_text.lower() or nudge_resp[0:1] == b'\xff':
            protocol = "telnet"

      # --- 5. Active HTTP probe ---
      if protocol is None:
        try:
          http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          http_sock.settimeout(FINGERPRINT_HTTP_TIMEOUT)
          http_sock.connect((target, port))
          http_sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
          try:
            http_resp = http_sock.recv(FINGERPRINT_MAX_BANNER)
          except (socket.timeout, OSError):
            http_resp = b""
          http_sock.close()
          if http_resp:
            http_text = http_resp.decode("utf-8", errors="replace")
            if http_text.startswith("HTTP/"):
              protocol = "http"
            elif "<html" in http_text.lower() or "<HTML" in http_text:
              protocol = "http"
            if not banner_text:
              banner_text = ''.join(
                ch if 32 <= ord(ch) < 127 else '.'
                for ch in http_text[:FINGERPRINT_MAX_BANNER]
              )
        except Exception:
          pass

      # --- 5b. Modbus probe ---
      # If still unknown, try a Modbus device ID request.
      # Only runs after all text-based identification fails.
      if protocol is None:
        try:
          mb_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          mb_sock.settimeout(FINGERPRINT_NUDGE_TIMEOUT)
          mb_sock.connect((target, port))
          # Modbus Read Device Identification: MBAP header + function code 0x2B
          mb_sock.sendall(b'\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00')
          try:
            mb_resp = mb_sock.recv(256)
          except (socket.timeout, OSError):
            mb_resp = b""
          mb_sock.close()
          # Valid Modbus response: starts with transaction ID echoed back + protocol ID 0x0000
          if mb_resp and len(mb_resp) >= 7 and mb_resp[2:4] == b'\x00\x00':
            protocol = "modbus"
        except Exception:
          pass

      # --- 6. Default ---
      if protocol is None:
        protocol = "unknown"

      port_protocols[port] = protocol
      port_banners[port] = banner_text
      self.P(f"Port {port} fingerprinted as '{protocol}'.")

      # Dune sand walking - random delay between fingerprint probes
      if self._interruptible_sleep():
        return  # Stop was requested during sleep

    self.state["port_protocols"] = port_protocols
    self.state["port_banners"] = port_banners
    self.P(f"Fingerprinting complete: {port_protocols}")


  def _is_ics_finding(self, probe_result):
    """
    Check if a probe result contains ICS/SCADA indicators.

    Parameters
    ----------
    probe_result : dict
      Structured result from a service probe.

    Returns
    -------
    bool
      True if ICS keywords are found in any finding.
    """
    if not isinstance(probe_result, dict):
      return False
    for finding in probe_result.get("findings", []):
      title = (finding.get("title") or "").lower()
      evidence = (finding.get("evidence") or "").lower()
      combined = title + " " + evidence
      ics_keywords = [
        "modbus", "siemens", "simatic", "plc", "scada",
        "schneider", "allen-bradley", "bacnet", "dnp3",
        "iec 61850", "iec61850", "profinet", "s7comm",
      ]
      if any(kw in combined for kw in ics_keywords):
        return True
    return False


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
    target = self.target
    service_info_methods = [m for m in self.__enabled_features if m.startswith("_service_info_")]
    port_protocols = self.state.get("port_protocols", {})
    aggregated_info = []
    for method in service_info_methods:
      func = getattr(self, method)
      target_protocols = PROBE_PROTOCOL_MAP.get(method)  # None → run unconditionally
      method_info = []
      for port in open_ports:
        if self.stop_event.is_set():
          return
        # Route probe only to ports matching its target protocol
        # When port_protocols is empty (fingerprinting didn't run), skip filtering
        if target_protocols is not None and port_protocols:
          port_proto = port_protocols.get(port, "unknown")
          if port_proto not in target_protocols:
            continue
        info = func(target, port)
        if info is not None:
          if port not in self.state["service_info"]:
            self.state["service_info"][port] = {}
          self.state["service_info"][port][method] = info
          method_info.append(f"{method}: {port}: {info}")

          # ICS Safe Mode: halt further probes if ICS detected
          if self.ics_safe_mode and not self._ics_detected and self._is_ics_finding(info):
            self._ics_detected = True
            self.P(f"ICS device detected on {target}:{port} — halting aggressive probes (ICS Safe Mode)")
            from .findings import Finding, Severity, probe_result as _pr
            ics_halt = _pr(findings=[Finding(
              severity=Severity.HIGH,
              title="ICS device detected — scan halted (ICS Safe Mode)",
              description=f"Industrial control system indicators found on {target}:{port}. "
                          "Further probing halted to prevent potential disruption.",
              evidence=f"Triggered by probe {method} on port {port}",
              remediation="Isolate ICS devices on dedicated OT networks.",
              cwe_id="CWE-284",
              confidence="firm",
            )])
            self.state["service_info"][port]["_ics_safe_halt"] = ics_halt
            break  # Stop the method loop — no more probes on this target

        # Dune sand walking - random delay before each service probe
        if self._interruptible_sleep():
          return  # Stop was requested during sleep
      #end for each port of current method

      if method_info:
        aggregated_info.extend(method_info)
        self.P(
          f"Method {method} findings:\n{json.dumps(method_info, indent=2)}"
        )
      self.state["completed_tests"].append(method)

      # ICS Safe Mode: break outer loop if ICS was detected
      if self._ics_detected:
        break
    # end for each method
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
    
    port_protocols = self.state.get("port_protocols", {})
    if port_protocols:
      ports_to_test = [p for p in open_ports if port_protocols.get(p, "unknown") in WEB_PROTOCOLS]
    else:
      # Fingerprinting didn't run (e.g., direct test call) — fall back to all ports
      ports_to_test = list(open_ports)
    if not ports_to_test:
      self.P("No HTTP/HTTPS ports detected, skipping web tests.")
      self.state["web_tested"] = True
      return
    self.P(
      f"Running web tests on {len(ports_to_test)} ports."
    )
    target = self.target
    result = []
    web_tests_methods = [m for m in self.__enabled_features if m.startswith("_web_test_")]
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

        # Dune sand walking - random delay before each web test
        if self._interruptible_sleep():
          return  # Stop was requested during sleep
      # end for each port of current method
      self.state["completed_tests"].append(method) # register completed method for port    
    # end for each method
    self.state["web_tested"] = True
    return result
