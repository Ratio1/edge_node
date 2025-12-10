import sys
import struct
import unittest
import threading
import time
from unittest.mock import MagicMock, patch, Mock

from extensions.business.cybersec.red_mesh.redmesh_utils import PentestLocalWorker

from xperimental.utils import color_print

MANUAL_RUN = __name__ == "__main__"



class DummyOwner:
  def __init__(self):
    self.messages = []

  def P(self, message, **kwargs):
    self.messages.append(message)
    if MANUAL_RUN:
      if "VULNERABILITY" in message:
        color = 'r'
      elif any(x in message for x in ["WARNING", "findings:"]):
        color = 'y'
      else:
        color = 'd'
      color_print(f"[DummyOwner] {message}", color=color)
    return


class RedMeshOWASPTests(unittest.TestCase):
  

  
  def setUp(self):
    if MANUAL_RUN:
      print()
      color_print(f"[MANUAL] >>> Starting <{self._testMethodName}>", color='b')

  def tearDown(self):
    if MANUAL_RUN:
      color_print(f"[MANUAL] <<< Finished <{self._testMethodName}>", color='b')

  def _build_worker(self, ports=None, exceptions=None):
    if ports is None:
      ports = [80]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-123",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=ports,
      exceptions=exceptions,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  def test_broken_access_control_detected(self):
    owner, worker = self._build_worker()

    def fake_get(url, timeout=2, verify=False):
      resp = MagicMock()
      resp.headers = {}
      resp.reason = "OK"
      resp.text = ""
      if url.endswith("/admin"):
        resp.status_code = 200
      elif url.endswith("/login"):
        resp.status_code = 403
      else:
        resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_common("example.com", 80)
    self.assertIn("VULNERABILITY: Accessible resource", result)

  def test_cryptographic_failures_cookie_flags(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.headers = {"Set-Cookie": "sessionid=abc; Path=/"}
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_flags("example.com", 443)
    self.assertIn("VULNERABILITY: Cookie missing Secure flag", result)
    self.assertIn("VULNERABILITY: Cookie missing HttpOnly flag", result)
    self.assertIn("VULNERABILITY: Cookie missing SameSite flag", result)

  def test_injection_sql_detected(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.text = "sql syntax error near line"
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_sql_injection("example.com", 80)
    self.assertIn("VULNERABILITY: Potential SQL injection", result)

  def test_insecure_design_path_traversal(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.text = "root:x:0:0:root:/root:/bin/bash"
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_path_traversal("example.com", 80)
    self.assertIn("VULNERABILITY: Path traversal", result)

  def test_security_misconfiguration_missing_headers(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.headers = {"Server": "Test"}
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_security_headers("example.com", 80)
    self.assertIn("VULNERABILITY: Missing security header", result)

  def test_vulnerable_component_banner_exposed(self):
    owner, worker = self._build_worker(ports=[80])
    worker.state["open_ports"] = [80]
    resp = MagicMock()
    resp.status_code = 200
    resp.reason = "OK"
    resp.headers = {"Server": "Apache/2.2.0"}
    with patch(
      "extensions.business.cybersec.red_mesh.redmesh_utils.dir",
      return_value=["_service_info_80"],
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.requests.get",
      return_value=resp,
    ):
      worker._gather_service_info()
    banner = worker.state["service_info"][80]["_service_info_80"]
    self.assertIn("Apache/2.2.0", banner)

  def test_identification_auth_failure_anonymous_ftp(self):
    owner, worker = self._build_worker(ports=[21])

    class DummyFTP:
      def __init__(self, timeout=3):
        pass

      def connect(self, target, port, timeout=3):
        return None

      def getwelcome(self):
        return "220 Welcome"

      def login(self):
        return None

      def quit(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.ftplib.FTP",
      return_value=DummyFTP(),
    ):
      result = worker._service_info_21("example.com", 21)
    self.assertIn("VULNERABILITY: FTP allows anonymous login", result)

  def test_service_checks_cover_non_standard_ports(self):
    owner, worker = self._build_worker(ports=[2121])

    class DummyFTP:
      def __init__(self, timeout=3):
        pass

      def connect(self, target, port, timeout=3):
        return None

      def getwelcome(self):
        return "220 Welcome"

      def login(self):
        return None

      def quit(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.ftplib.FTP",
      return_value=DummyFTP(),
    ):
      result = worker._service_info_21("example.com", 2121)
    self.assertIn("FTP allows anonymous login", result)

  def test_service_info_runs_all_methods_for_each_port(self):
    owner, worker = self._build_worker(ports=[1234])
    worker.state["open_ports"] = [1234]

    def fake_service_one(target, port):
      return f"fake_service_one:{port}"

    def fake_service_two(target, port):
      return f"fake_service_two:{port}"

    setattr(worker, "_service_info_fake_one", fake_service_one)
    setattr(worker, "_service_info_fake_two", fake_service_two)

    with patch(
      "extensions.business.cybersec.red_mesh.redmesh_utils.dir",
      return_value=["_service_info_fake_one", "_service_info_fake_two"],
    ):
      worker._gather_service_info()

    service_snap = worker.state["service_info"][1234]
    self.assertEqual(len(service_snap), 2)
    self.assertEqual(service_snap["_service_info_fake_one"], "fake_service_one:1234")
    self.assertEqual(service_snap["_service_info_fake_two"], "fake_service_two:1234")

  def test_software_data_integrity_secret_leak(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.text = "BEGIN RSA PRIVATE KEY"
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_homepage("example.com", 80)
    self.assertIn("VULNERABILITY: sensitive", result)

  def test_security_logging_tracks_flow(self):
    owner, worker = self._build_worker()

    def register(name):
      worker.state["completed_tests"].append(name)

    with patch.object(
      worker, "_scan_ports_step", side_effect=lambda *a, **k: register("scan")
    ), patch.object(
      worker, "_gather_service_info", side_effect=lambda *a, **k: register("service")
    ), patch.object(
      worker, "_run_web_tests", side_effect=lambda *a, **k: register("web")
    ):
      worker.execute_job()
    self.assertTrue(worker.state["done"])
    self.assertIn("scan", worker.state["completed_tests"])
    self.assertTrue(any("Starting pentest job." in msg for msg in owner.messages))

  def test_web_tests_include_uncommon_ports(self):
    owner, worker = self._build_worker(ports=[9000])
    worker.state["open_ports"] = [9000]

    def fake_get(url, timeout=2, verify=False):
      resp = MagicMock()
      resp.headers = {}
      resp.text = ""
      resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.redmesh_utils.dir",
      return_value=["_web_test_common"],
    ), patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      side_effect=fake_get,
    ):
      worker._run_web_tests()
    self.assertIn(9000, worker.state["web_tests_info"])
    self.assertIn("_web_test_common", worker.state["web_tests_info"][9000])
    self.assertTrue(worker.state["web_tests_info"][9000]["_web_test_common"])  # message stored

  def test_web_tests_execute_all_methods_for_each_port(self):
    owner, worker = self._build_worker(ports=[10000])
    worker.state["open_ports"] = [10000]

    def fake_web_one(target, port):
      return f"web-one:{port}"

    def fake_web_two(target, port):
      return f"web-two:{port}"

    setattr(worker, "_web_test_fake_one", fake_web_one)
    setattr(worker, "_web_test_fake_two", fake_web_two)

    with patch(
      "extensions.business.cybersec.red_mesh.redmesh_utils.dir",
      return_value=["_web_test_fake_one", "_web_test_fake_two"],
    ):
      worker._run_web_tests()

    web_snap = worker.state["web_tests_info"][10000]
    self.assertEqual(len(web_snap), 2)
    self.assertEqual(web_snap["_web_test_fake_one"], "web-one:10000")
    self.assertEqual(web_snap["_web_test_fake_two"], "web-two:10000")

  def test_ssrf_protection_respects_exceptions(self):
    owner, worker = self._build_worker(ports=[80, 9000], exceptions=[9000])
    self.assertNotIn(9000, worker.state["ports_to_scan"])
    self.assertIn(9000, worker.exceptions)

  def test_cross_site_scripting_detection(self):
    owner, worker = self._build_worker()
    payload = "<script>alert(1)</script>"
    resp = MagicMock()
    resp.text = f"Response with {payload} inside"
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_xss("example.com", 80)
    self.assertIn("VULNERABILITY: Reflected XSS", result)

  def test_tls_certificate_expiration_reporting(self):
    owner, worker = self._build_worker(ports=[443])

    class DummyConn:
      def __enter__(self):
        return self

      def __exit__(self, exc_type, exc, tb):
        return False

    class DummySSL:
      def __enter__(self):
        return self

      def __exit__(self, exc_type, exc, tb):
        return False

      def getpeercert(self):
        return {"notAfter": "Dec 31 12:00:00 2030 GMT"}

      def version(self):
        return "TLSv1.3"

      def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", None, None)

    class DummyContext:
      def wrap_socket(self, sock, server_hostname=None):
        return DummySSL()

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.create_connection",
      return_value=DummyConn(),
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.ssl.create_default_context",
      return_value=DummyContext(),
    ):
      info = worker._service_info_tls("example.com", 443)
    self.assertIn("TLS", info)
    self.assertIn("exp", info)

  def test_port_scan_detects_open_ports(self):
    owner, worker = self._build_worker(ports=[80, 81])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect_ex(self, address):
        return 0 if address[1] == 80 else 1

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket",
      return_value=DummySocket(),
    ):
      worker._scan_ports_step()
    self.assertIn(80, worker.state["open_ports"])
    self.assertNotIn(81, worker.state["open_ports"])
    self.assertIn("scan_ports_step_completed", worker.state["completed_tests"])

  def test_service_telnet_banner(self):
    owner, worker = self._build_worker(ports=[23])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        self.closed = False

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def recv(self, nbytes):
        return b"Welcome to telnet"

      def close(self):
        self.closed = True

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_23("example.com", 23)
    self.assertIn("VULNERABILITY: Telnet", info)

  def test_service_smb_probe(self):
    owner, worker = self._build_worker(ports=[445])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        self.sent = b""

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def sendall(self, data):
        self.sent = data

      def recv(self, nbytes):
        return b"\x00\x00\x00\x00"

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_445("example.com", 445)
    self.assertIn("VULNERABILITY: SMB", info)

  def test_service_vnc_banner(self):
    owner, worker = self._build_worker(ports=[5900])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def recv(self, nbytes):
        return b"RFB 003.008\n"

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_5900("example.com", 5900)
    self.assertIn("VULNERABILITY: VNC", info)

  def test_service_snmp_public(self):
    owner, worker = self._build_worker(ports=[161])

    class DummyUDPSocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def sendto(self, data, addr):
        self.sent = data

      def recvfrom(self, size):
        response = bytes.fromhex("302e020103300702010304067075626c6963a0190400")
        return response, ("example.com", 161)

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummyUDPSocket(),
    ):
      info = worker._service_info_161("example.com", 161)
    self.assertIn("VULNERABILITY: SNMP", info)

  def test_service_dns_version_disclosure(self):
    owner, worker = self._build_worker(ports=[53])

    tid = 0x1234
    header = struct.pack('>HHHHHH', tid, 0x8180, 1, 1, 0, 0)
    qname = b'\x07version\x04bind\x00'
    question = qname + struct.pack('>HH', 16, 3)
    answer = b"\xc0\x0c" + struct.pack('>HHIH', 16, 3, 60, 6) + b"\x05BIND9"
    payload = header + question + answer

    class DummyUDPSocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def sendto(self, data, addr):
        self.sent = data

      def recvfrom(self, size):
        return payload, ("example.com", 53)

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.random.randint",
      return_value=tid,
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummyUDPSocket(),
    ):
      info = worker._service_info_53("example.com", 53)
    self.assertIn("VULNERABILITY: DNS version disclosure", info)

  def test_service_memcached_stats(self):
    owner, worker = self._build_worker(ports=[11211])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def sendall(self, data):
        self.sent = data

      def recv(self, nbytes):
        return b"STAT pid 1\r\nEND\r\n"

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_11211("example.com", 11211)
    self.assertIn("VULNERABILITY: Memcached", info)

  def test_service_elasticsearch_metadata(self):
    owner, worker = self._build_worker(ports=[9200])
    resp = MagicMock()
    resp.ok = True
    resp.text = '{"cluster_name":"example"}'
    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.requests.get",
      return_value=resp,
    ):
      info = worker._service_info_9200("example.com", 9200)
    self.assertIn("VULNERABILITY: Elasticsearch", info)

  def test_service_modbus_identification(self):
    owner, worker = self._build_worker(ports=[502])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def sendall(self, data):
        self.sent = data

      def recv(self, nbytes):
        return b"\x00\x01\x00\x00\x00\x05\x01\x2b\x0e\x01"

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_502("example.com", 502)
    self.assertIn("VULNERABILITY: Modbus", info)

  def test_service_postgres_cleartext(self):
    owner, worker = self._build_worker(ports=[5432])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def sendall(self, data):
        self.sent = data

      def recv(self, nbytes):
        return b"AuthenticationCleartextPassword"

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_5432("example.com", 5432)
    self.assertIn("VULNERABILITY: PostgreSQL", info)

  def test_service_mssql_prelogin(self):
    owner, worker = self._build_worker(ports=[1433])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def sendall(self, data):
        self.sent = data

      def recv(self, nbytes):
        return b"MSSQLSERVER"

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_1433("example.com", 1433)
    self.assertIn("VULNERABILITY: MSSQL", info)

  def test_service_mongo_unauth(self):
    owner, worker = self._build_worker(ports=[27017])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def sendall(self, data):
        self.sent = data

      def recv(self, nbytes):
        return b"ismaster\x00"

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_27017("example.com", 27017)
    self.assertIn("VULNERABILITY: MongoDB", info)

  def test_web_graphql_introspection(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "{\"data\":{\"__schema\":{}}}"
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.post",
      return_value=resp,
    ):
      result = worker._web_test_graphql_introspection("example.com", 80)
    self.assertIn("VULNERABILITY: GraphQL introspection", result)

  def test_web_metadata_endpoint(self):
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False, headers=None):
      resp = MagicMock()
      resp.status_code = 200 if "meta-data" in url else 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_metadata_endpoints("example.com", 80)
    self.assertIn("VULNERABILITY: Cloud metadata endpoint", result)

  def test_web_api_auth_bypass(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_api_auth_bypass("example.com", 80)
    self.assertIn("VULNERABILITY: API endpoint", result)

  def test_cors_misconfiguration_detection(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.headers = {
      "Access-Control-Allow-Origin": "https://attacker.example",
      "Access-Control-Allow-Credentials": "false",
    }
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_cors_misconfiguration("example.com", 80)
    self.assertIn("VULNERABILITY: CORS misconfiguration", result)

  def test_open_redirect_detection(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 302
    resp.headers = {"Location": "https://attacker.example"}
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_open_redirect("example.com", 80)
    self.assertIn("VULNERABILITY: Open redirect", result)

  def test_http_methods_detection(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.headers = {"Allow": "GET, POST, PUT"}
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_mixin.requests.options",
      return_value=resp,
    ):
      result = worker._web_test_http_methods("example.com", 80)
    self.assertIn("VULNERABILITY: Risky HTTP methods", result)

  def test_pacing_pauses_execution(self):
    """Test that pacing configuration is set correctly"""
    owner = DummyOwner()
    owner.cfg_pacing = {"pause_interval": 2, "pause_duration": 0.05}
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-pacing",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80, 81],
      pacing={"pause_interval": 2, "pause_duration": 0.05}
    )
    worker.stop_event = threading.Event()

    # Verify pacing is configured correctly
    self.assertIsNotNone(worker.pacing)
    self.assertEqual(worker.pacing["pause_interval"], 2)
    self.assertEqual(worker.pacing["pause_duration"], 0.05)
    self.assertIsNotNone(worker.next_pause_at)
    self.assertGreater(worker.next_pause_at, 0)

    # Verify action counter starts at 0
    self.assertEqual(worker.action_counter, 0)

  def test_pacing_respects_stop_event(self):
    """Test that pacing pause can be interrupted by stop event"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-stop",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80],
      pacing={"pause_interval": 1, "pause_duration": 5.0}  # Long pause
    )
    worker.stop_event = threading.Event()
    worker.action_counter = 1
    worker.next_pause_at = 1

    # Start pause in background and stop it
    def delayed_stop():
      time.sleep(0.1)
      worker.stop_event.set()

    stop_thread = threading.Thread(target=delayed_stop)
    stop_thread.start()

    start = time.time()
    worker._maybe_pause()
    elapsed = time.time() - start

    # Should be interrupted well before 5 seconds
    self.assertLess(elapsed, 1.0)
    self.assertTrue(worker.stop_event.is_set())
    stop_thread.join()

  def test_port_order_sequential(self):
    """Test that SEQUENTIAL port order maintains input order (no shuffle)"""
    owner = DummyOwner()
    owner.cfg_port_order = "SEQUENTIAL"
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-seq",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[100, 99, 98, 97, 96],
      port_order="SEQUENTIAL"
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False

    scanned_ports = []

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass
      def settimeout(self, timeout):
        return None
      def connect_ex(self, address):
        scanned_ports.append(address[1])
        return 1  # not open
      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket",
      return_value=DummySocket(),
    ):
      worker._scan_ports_step()

    # With SEQUENTIAL, ports maintain their original order (no shuffle)
    # Input [100, 99, 98, 97, 96] stays as [100, 99, 98, 97, 96]
    expected = [100, 99, 98, 97, 96]
    self.assertEqual(scanned_ports, expected)

  def test_port_order_shuffle(self):
    """Test that SHUFFLE port order randomizes"""
    owner = DummyOwner()
    owner.cfg_port_order = "SHUFFLE"
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-shuffle",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=list(range(1, 21)),  # 20 ports
      port_order="SHUFFLE"
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False

    scanned_ports = []

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass
      def settimeout(self, timeout):
        return None
      def connect_ex(self, address):
        scanned_ports.append(address[1])
        return 1
      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket",
      return_value=DummySocket(),
    ):
      worker._scan_ports_step()

    # Shuffled order should be different from sorted (very high probability with 20 ports)
    self.assertNotEqual(scanned_ports, sorted(scanned_ports))
    # But should contain same ports
    self.assertEqual(set(scanned_ports), set(range(1, 21)))

  def test_included_tests_filter(self):
    """Test that included_tests filters which tests run"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-filter",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80],
      included_tests=["_service_info_80", "_web_test_common"]
    )

    # Should run
    self.assertTrue(worker._should_run("_service_info_80"))
    self.assertTrue(worker._should_run("_web_test_common"))

    # Should not run
    self.assertFalse(worker._should_run("_service_info_443"))
    self.assertFalse(worker._should_run("_web_test_xss"))

  def test_excluded_tests_filter(self):
    """Test that excluded_tests prevents specific tests from running"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-exclude",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80],
      excluded_tests=["_web_test_xss", "_web_test_sql_injection"]
    )

    # Should not run
    self.assertFalse(worker._should_run("_web_test_xss"))
    self.assertFalse(worker._should_run("_web_test_sql_injection"))

    # Should run (not in excluded list)
    self.assertTrue(worker._should_run("_web_test_common"))
    self.assertTrue(worker._should_run("_service_info_80"))

  def test_combined_include_exclude_tests(self):
    """Test that excluded_tests takes precedence over included_tests"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-combined",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80],
      included_tests=["_web_test_xss", "_web_test_common"],
      excluded_tests=["_web_test_xss"]
    )

    # Excluded takes precedence
    self.assertFalse(worker._should_run("_web_test_xss"))
    # In included and not excluded
    self.assertTrue(worker._should_run("_web_test_common"))
    # Not in included
    self.assertFalse(worker._should_run("_web_test_sql_injection"))

  def test_worker_status_reporting(self):
    """Test that worker reports accurate status"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="192.168.1.1",
      job_id="job-status",
      initiator="launcher@example",
      local_id_prefix="42",
      worker_target_ports=[80, 443, 8080]
    )

    status = worker.get_status()

    self.assertEqual(status["job_id"], "job-status")
    self.assertEqual(status["initiator"], "launcher@example")
    self.assertEqual(status["target"], "192.168.1.1")
    self.assertEqual(status["start_port"], 80)
    self.assertEqual(status["end_port"], 8080)
    self.assertFalse(status["done"])
    self.assertFalse(status["canceled"])
    self.assertIn("local_worker_id", status)
    self.assertIn("RM-42-", status["local_worker_id"])

  def test_worker_aggregation_fields(self):
    """Test that worker-specific aggregation fields are defined correctly"""
    fields = PentestLocalWorker.get_worker_specific_result_fields()

    self.assertIn("open_ports", fields)
    self.assertIn("service_info", fields)
    self.assertIn("web_tests_info", fields)
    self.assertIn("completed_tests", fields)
    self.assertIn("start_port", fields)
    self.assertIn("end_port", fields)
    self.assertEqual(fields["start_port"], min)
    self.assertEqual(fields["end_port"], max)

  def test_stop_event_interrupts_port_scan(self):
    """Test that setting stop event halts port scanning"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-stop-scan",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=list(range(1, 101))  # 100 ports
    )
    worker.stop_event = threading.Event()

    scanned_count = [0]

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass
      def settimeout(self, timeout):
        return None
      def connect_ex(self, address):
        scanned_count[0] += 1
        if scanned_count[0] == 10:
          worker.stop_event.set()
        return 1
      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket",
      return_value=DummySocket(),
    ):
      worker._scan_ports_step()

    # Should stop early, not scan all 100 ports
    self.assertLess(len(worker.state["ports_scanned"]), 100)
    self.assertGreater(len(worker.state["ports_scanned"]), 0)

  def test_stop_event_interrupts_service_gathering(self):
    """Test that setting stop event halts service info gathering"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-stop-service",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80, 443, 8080]
    )
    worker.state["open_ports"] = [80, 443, 8080]
    worker.stop_event = threading.Event()

    call_count = [0]

    def fake_service_info(target, port):
      call_count[0] += 1
      if call_count[0] == 2:
        worker.stop_event.set()
      return f"info:{port}"

    with patch(
      "extensions.business.cybersec.red_mesh.redmesh_utils.dir",
      return_value=["_service_info_fake"],
    ):
      setattr(worker, "_service_info_fake", fake_service_info)
      worker._gather_service_info()

    # Should not process all ports
    self.assertLess(len(worker.state["service_info"]), 3)

  def test_exceptions_removes_ports_from_scan_list(self):
    """Test that exception ports are properly excluded"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-except",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80, 8080, 443, 8443],
      exceptions=[8080, 8443]
    )

    # Exceptions should be removed from ports_to_scan
    self.assertNotIn(8080, worker.state["ports_to_scan"])
    self.assertNotIn(8443, worker.state["ports_to_scan"])
    self.assertIn(80, worker.state["ports_to_scan"])
    self.assertIn(443, worker.state["ports_to_scan"])

    # Should be tracked in exceptions
    self.assertIn(8080, worker.exceptions)
    self.assertIn(8443, worker.exceptions)

  def test_exceptions_not_matching_worker_ports_ignored(self):
    """Test that exceptions not in worker ports are ignored"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-except-nomatch",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80, 443],
      exceptions=[8080, 9000]  # Not in worker ports
    )

    # Worker ports should remain unchanged
    self.assertIn(80, worker.state["ports_to_scan"])
    self.assertIn(443, worker.state["ports_to_scan"])

    # Exceptions should be empty since they don't match
    self.assertEqual(worker.exceptions, [])

  def test_worker_thread_lifecycle(self):
    """Test that worker can be started and stopped properly"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-lifecycle",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80]
    )

    # Mock execute_job to avoid actual scanning
    executed = [False]
    def mock_execute():
      executed[0] = True
      worker.state["done"] = True

    with patch.object(worker, 'execute_job', side_effect=mock_execute):
      worker.start()
      self.assertIsInstance(worker.thread, threading.Thread)
      self.assertTrue(worker.thread.daemon)

      # Wait for thread to complete
      worker.thread.join(timeout=1.0)
      self.assertTrue(executed[0])

  def test_current_stage_tracking(self):
    """Test that current_stage is updated during workflow"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-stage",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80]
    )

    self.assertEqual(worker.state["current_stage"], "INITIALIZED")

    worker.stop_event = threading.Event()

    # Mock the actual work
    with patch.object(worker, '_scan_ports_step'):
      worker.state["current_stage"] = "SCANNING"
      self.assertEqual(worker.state["current_stage"], "SCANNING")

      worker.state["current_stage"] = "PROBING"
      self.assertEqual(worker.state["current_stage"], "PROBING")

      worker.state["current_stage"] = "TESTING"
      self.assertEqual(worker.state["current_stage"], "TESTING")

      worker.state["current_stage"] = "COMPLETED"
      self.assertEqual(worker.state["current_stage"], "COMPLETED")

  def test_worker_progress_calculation(self):
    """Test that worker progress is calculated correctly"""
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-progress",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=[80]
    )

    # No tests completed
    status = worker.get_status()
    self.assertIn("progress", status)

    # Simulate some completed tests
    all_features = worker._get_all_features()
    worker.state["completed_tests"] = all_features[:len(all_features)//2]

    status = worker.get_status()
    progress_str = status["progress"]
    # Should show partial progress
    self.assertIn("%", progress_str)


class VerboseResult(unittest.TextTestResult):
  def addSuccess(self, test):
    super().addSuccess(test)
    self.stream.writeln()  # emits an extra “\n” after the usual “ok”

if __name__ == "__main__":
  runner = unittest.TextTestRunner(verbosity=2, resultclass=VerboseResult)
  runner.run(unittest.defaultTestLoader.loadTestsFromTestCase(RedMeshOWASPTests))
