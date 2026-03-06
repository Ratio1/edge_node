import uuid
import random
import struct
import threading
import socket
import json
import traceback
import time

from .service_mixin import _ServiceInfoMixin
from .correlation_mixin import _CorrelationMixin
from .constants import (
  PROBE_PROTOCOL_MAP, WEB_PROTOCOLS,
  WELL_KNOWN_PORTS as _WELL_KNOWN_PORTS,
  FINGERPRINT_TIMEOUT, FINGERPRINT_MAX_BANNER, FINGERPRINT_HTTP_TIMEOUT,
  FINGERPRINT_NUDGE_TIMEOUT, SCAN_PORT_TIMEOUT,
)
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
  _WebTestsMixin,
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
      "port_banner_confirmed": {},

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
      return self.stop_event.is_set()
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
        self._active_fingerprint_ports()
        self.state["completed_tests"].append("fingerprint_completed")

      if not self._check_stopped():
        self._gather_service_info()
        self.state["completed_tests"].append("service_info_completed")

      if not self._check_stopped() and not self._ics_detected:
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
    Scan a batch of ports to identify open ones and perform passive banner
    grabbing on each open port in the same TCP connection.

    For every open port the method reuses the established socket to attempt a
    passive ``recv``, classifies the banner, and stores protocol, banner, and
    confirmation flag immediately in worker state.  This eliminates the second
    TCP connection that was previously required by ``_fingerprint_ports``.

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
    ports_batch = self.state["ports_to_scan"]
    if batch_size is not None:
      start_batch = (batch_nr - 1) * batch_size
      ports_batch = ports_batch[start_batch:start_batch + batch_size]
    if not ports_batch:
      return
    nr_ports = len(ports_batch)
    self.P(f"Scanning {nr_ports} ports in batch {batch_nr}.")
    show_progress = nr_ports > 1000

    for i, port in enumerate(ports_batch):
      if self.stop_event.is_set():
        break
      sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
      sock.settimeout(SCAN_PORT_TIMEOUT)
      try:
        result = sock.connect_ex((target, port))
        if result == 0:
          self.state["open_ports"].append(port)
          self.P(f"Port {port} is open on {target}.")

          # --- Passive banner grab (merged from _fingerprint_ports) ---
          protocol = None
          banner_text = ""
          try:
            sock.settimeout(FINGERPRINT_TIMEOUT)
            raw = sock.recv(FINGERPRINT_MAX_BANNER)
          except (socket.timeout, OSError):
            raw = b""

          if raw:
            banner_text = ''.join(
              ch if 32 <= ord(ch) < 127 else '.'
              for ch in raw[:FINGERPRINT_MAX_BANNER].decode("utf-8", errors="replace")
            )

          # --- Classify banner by content ---
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
              _pkt_len = int.from_bytes(raw[0:3], 'little')
              if 10 <= _pkt_len <= 512:
                _ver_end = raw.find(b'\x00', 5)
                if _ver_end > 5 and all(32 <= b < 127 for b in raw[5:_ver_end]):
                  protocol = "mysql"
            elif "login:" in text.lower():
              protocol = "telnet"
            elif len(raw) >= 3 and raw[0:1] == b'\xff' and raw[1:2] in (b'\xfb', b'\xfc', b'\xfd', b'\xfe'):
              protocol = "telnet"
            elif text.startswith("HTTP/"):
              protocol = "http"
            elif text.startswith("+OK"):
              protocol = "pop3"
            elif text.startswith("* OK"):
              protocol = "imap"
            elif text.startswith("+PONG") or text.startswith("-ERR") or text.startswith("-NOAUTH") or text.startswith("$"):
              protocol = "redis"
            elif text.startswith("@RSYNCD:"):
              protocol = "rsync"
            elif text.startswith("STAT ") or text.startswith("ERROR") or text.startswith("CLIENT_ERROR"):
              protocol = "memcached"
            elif text.lstrip().startswith("{") and '"cluster_name"' in text:
              protocol = "http"

          # --- Well-known port fallback ---
          banner_confirmed = protocol is not None
          if protocol is None:
            protocol = _WELL_KNOWN_PORTS.get(port, "unknown")

          # --- Store results immediately ---
          self.state["port_protocols"][port] = protocol
          self.state["port_banners"][port] = banner_text
          self.state["port_banner_confirmed"][port] = banner_confirmed
      except Exception as e:
        self.P(f"Exception scanning port {port} on {target}: {e}")
      finally:
        sock.close()

      self.state["ports_scanned"].append(port)

      if ((i + 1) % REGISTER_PROGRESS_EACH) == 0:
        scan_ports_step_progress = (i + 1) / nr_ports * 100
        str_progress = f"{scan_ports_step_progress:.0f}%"
        self.state["completed_tests"] = [f"scan_ports_step_{str_progress}"]
        if show_progress:
          self.P(f"Port scanning progress on {target}: {str_progress}")

      # Dune sand walking - random delay after each port scan
      if self._interruptible_sleep():
        break
    #end for each port

    self.state["ports_to_scan"] = []
    if not self.stop_event.is_set():
      self.P(f"[{target}] Port scanning completed. {len(self.state['open_ports'])} open ports.")
      self.state["completed_tests"].append("scan_ports_step_completed")
    else:
      self.P(f"[{target}] Port scanning not completed (stopped).")
    return


  def _active_fingerprint_ports(self):
    """
    Run active protocol probes on open ports not identified by passive
    banner grabbing during the port scan step.

    Active probes include: generic nudge, HTTP HEAD, Modbus device ID,
    DNS query, Redis PING, PostgreSQL SSLRequest, and MongoDB isMaster.

    Results are written incrementally to ``state["port_protocols"]`` and
    ``state["port_banners"]`` after each port.  If a Modbus device is
    confirmed while ICS safe mode is enabled, ``_ics_detected`` is set
    and an ICS finding is recorded.

    Returns
    -------
    None
    """
    open_ports = self.state["open_ports"]
    if not open_ports:
      self.P("No open ports to fingerprint.")
      return

    target = self.target
    port_banner_confirmed = self.state.get("port_banner_confirmed", {})

    # Only run active probes on ports not already confirmed by banner
    ports_to_probe = [p for p in open_ports if not port_banner_confirmed.get(p, False)]

    if not ports_to_probe:
      self.P("All open ports already identified by banner. Skipping active fingerprinting.")
      return

    self.P(f"Active fingerprinting {len(ports_to_probe)} ports (of {len(open_ports)} open).")

    for port in ports_to_probe:
      if self.stop_event.is_set():
        return

      protocol = self.state["port_protocols"].get(port)
      banner_text = self.state["port_banners"].get(port, "")
      banner_confirmed = False

      # --- 4. Generic nudge probe ---
      # Some services (honeypots, RPC, custom daemons) don't speak first
      # but will respond to any input.  Send a minimal \r\n nudge.
      nudge_sock = None
      try:
        nudge_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        nudge_sock.settimeout(FINGERPRINT_NUDGE_TIMEOUT)
        nudge_sock.connect((target, port))
        nudge_sock.sendall(b"\r\n")
        try:
          nudge_resp = nudge_sock.recv(FINGERPRINT_MAX_BANNER)
        except (socket.timeout, OSError):
          nudge_resp = b""
      except Exception:
        nudge_resp = b""
      finally:
        if nudge_sock:
          nudge_sock.close()

      if nudge_resp:
        nudge_text = nudge_resp.decode("utf-8", errors="replace")
        if not banner_text:
          banner_text = ''.join(
            ch if 32 <= ord(ch) < 127 else '.'
            for ch in nudge_text[:FINGERPRINT_MAX_BANNER]
          )
        if nudge_text.startswith("HTTP/") or "<html" in nudge_text.lower() or "<HTML" in nudge_text:
          # If port was guessed as HTTPS, a plain-text HTTP error (400/497)
          # confirms it's a TLS port — keep "https" instead of downgrading.
          if protocol == "https":
            banner_confirmed = True
          else:
            protocol = "http"
            banner_confirmed = True
        elif nudge_text.startswith("SSH-"):
          protocol = "ssh"
          banner_confirmed = True
        elif nudge_text.startswith("+OK"):
          protocol = "pop3"
          banner_confirmed = True
        elif nudge_text.startswith("* OK"):
          protocol = "imap"
          banner_confirmed = True
        elif "login:" in nudge_text.lower():
          protocol = "telnet"
          banner_confirmed = True
        elif len(nudge_resp) >= 3 and nudge_resp[0:1] == b'\xff' and nudge_resp[1:2] in (b'\xfb', b'\xfc', b'\xfd', b'\xfe'):
          protocol = "telnet"
          banner_confirmed = True

      # --- 5. Active HTTP probe ---
      if protocol is None or not banner_confirmed:
        http_sock = None
        try:
          http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          http_sock.settimeout(FINGERPRINT_HTTP_TIMEOUT)
          http_sock.connect((target, port))
          http_sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode())
          try:
            http_resp = http_sock.recv(FINGERPRINT_MAX_BANNER)
          except (socket.timeout, OSError):
            http_resp = b""
          if http_resp:
            http_text = http_resp.decode("utf-8", errors="replace")
            if http_text.startswith("HTTP/") or "<html" in http_text.lower() or "<HTML" in http_text:
              # Preserve "https" when a TLS port responds to plain HTTP with an error.
              if protocol == "https":
                banner_confirmed = True
              else:
                protocol = "http"
                banner_confirmed = True
            if not banner_text:
              banner_text = ''.join(
                ch if 32 <= ord(ch) < 127 else '.'
                for ch in http_text[:FINGERPRINT_MAX_BANNER]
              )
        except Exception:
          pass
        finally:
          if http_sock:
            http_sock.close()

      # --- 5b. Modbus probe (guarded by ICS safe mode) ---
      if (protocol is None or not banner_confirmed) and not self._ics_detected:
        mb_sock = None
        try:
          mb_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          mb_sock.settimeout(FINGERPRINT_NUDGE_TIMEOUT)
          mb_sock.connect((target, port))
          mb_sock.sendall(b'\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01\x00')
          try:
            mb_resp = mb_sock.recv(256)
          except (socket.timeout, OSError):
            mb_resp = b""
          if (mb_resp and len(mb_resp) >= 8
              and mb_resp[2:4] == b'\x00\x00'
              and mb_resp[7:8] == b'\x2b'):
            protocol = "modbus"
            banner_confirmed = True
            if self.ics_safe_mode:
              self._ics_detected = True
              self.P(f"ICS device detected on {target}:{port} via Modbus probe — halting aggressive probes (ICS Safe Mode)")
              from .findings import Finding, Severity, probe_result as _pr
              ics_halt = _pr(findings=[Finding(
                severity=Severity.HIGH,
                title="ICS device detected — scan halted (ICS Safe Mode)",
                description=f"Industrial control system indicators found on {target}:{port}. "
                            "Further probing halted to prevent potential disruption.",
                evidence=f"Modbus device identification confirmed on port {port}",
                remediation="Isolate ICS devices on dedicated OT networks.",
                cwe_id="CWE-284",
                confidence="firm",
              )])
              if port not in self.state["service_info"]:
                self.state["service_info"][port] = {}
              self.state["service_info"][port]["_ics_safe_halt"] = ics_halt
        except Exception:
          pass
        finally:
          if mb_sock:
            mb_sock.close()

      # --- 5c. DNS probe ---
      if protocol is None or not banner_confirmed:
        dns_sock = None
        try:
          dns_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          dns_sock.settimeout(FINGERPRINT_NUDGE_TIMEOUT)
          dns_sock.connect((target, port))
          dns_query = (
            b'\x12\x34'
            b'\x01\x00'
            b'\x00\x01'
            b'\x00\x00'
            b'\x00\x00'
            b'\x00\x00'
            b'\x07version\x04bind\x00'
            b'\x00\x10'
            b'\x00\x03'
          )
          dns_sock.sendall(struct.pack(">H", len(dns_query)) + dns_query)
          try:
            dns_resp = dns_sock.recv(512)
          except (socket.timeout, OSError):
            dns_resp = b""
          if len(dns_resp) >= 4:
            dns_data = dns_resp[2:] if len(dns_resp) > 2 else dns_resp
            if len(dns_data) >= 4 and dns_data[0:2] == b'\x12\x34' and (dns_data[2] & 0x80):
              protocol = "dns"
              banner_confirmed = True
        except Exception:
          pass
        finally:
          if dns_sock:
            dns_sock.close()

      # --- 5d. Redis PING probe ---
      if protocol is None or not banner_confirmed:
        r_sock = None
        try:
          r_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          r_sock.settimeout(FINGERPRINT_NUDGE_TIMEOUT)
          r_sock.connect((target, port))
          r_sock.sendall(b"PING\r\n")
          try:
            r_resp = r_sock.recv(64)
          except (socket.timeout, OSError):
            r_resp = b""
          r_text = r_resp.decode("utf-8", errors="ignore")
          if r_text.startswith("+PONG") or r_text.startswith("-NOAUTH"):
            protocol = "redis"
            banner_confirmed = True
        except Exception:
          pass
        finally:
          if r_sock:
            r_sock.close()

      # --- 5e. PostgreSQL SSLRequest probe ---
      if protocol is None or not banner_confirmed:
        pg_sock = None
        try:
          pg_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          pg_sock.settimeout(FINGERPRINT_NUDGE_TIMEOUT)
          pg_sock.connect((target, port))
          pg_sock.sendall(b'\x00\x00\x00\x08\x04\xd2\x16\x2f')
          try:
            pg_resp = pg_sock.recv(16)
          except (socket.timeout, OSError):
            pg_resp = b""
          if pg_resp in (b'S', b'N'):
            protocol = "postgresql"
            banner_confirmed = True
          elif len(pg_resp) > 1 and pg_resp[0:1] in (b'S', b'N') and not pg_resp.startswith(b'SSH-'):
            protocol = "postgresql"
            banner_confirmed = True
        except Exception:
          pass
        finally:
          if pg_sock:
            pg_sock.close()

      # --- 5f. MongoDB wire protocol probe ---
      if protocol is None or not banner_confirmed:
        mg_sock = None
        try:
          mg_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
          mg_sock.settimeout(FINGERPRINT_NUDGE_TIMEOUT)
          mg_sock.connect((target, port))
          _mg_field = b'\x10isMaster\x00' + struct.pack('<i', 1)
          _mg_body = _mg_field + b'\x00'
          _mg_doc = struct.pack('<i', 4 + len(_mg_body)) + _mg_body
          collection = b'admin.$cmd\x00'
          _mg_msg = (struct.pack('<i', 0) + collection
                     + struct.pack('<i', 0) + struct.pack('<i', -1)
                     + _mg_doc)
          _mg_hdr = struct.pack('<iiii', 16 + len(_mg_msg), 1, 0, 2004)
          mg_sock.sendall(_mg_hdr + _mg_msg)
          try:
            mg_resp = mg_sock.recv(256)
          except (socket.timeout, OSError):
            mg_resp = b""
          if (len(mg_resp) >= 16
              and struct.unpack('<i', mg_resp[12:16])[0] == 1):
            protocol = "mongodb"
            banner_confirmed = True
        except Exception:
          pass
        finally:
          if mg_sock:
            mg_sock.close()

      # --- 6. Default ---
      if protocol is None:
        protocol = "unknown"

      # --- Incremental state update ---
      self.state["port_protocols"][port] = protocol
      self.state["port_banners"][port] = banner_text
      self.P(f"Port {port} fingerprinted as '{protocol}'.")

      # Dune sand walking - random delay between fingerprint probes
      if self._interruptible_sleep():
        return  # Stop was requested during sleep

    self.P(f"Active fingerprinting complete: {self.state['port_protocols']}")


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
      # ICS Safe Mode: skip all remaining probes if ICS already detected
      if self._ics_detected:
        break
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
        if iter_result is not None:
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
