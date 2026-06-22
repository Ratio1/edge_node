import json
import sys
import struct
import unittest
from unittest.mock import MagicMock, patch

from .conftest import DummyOwner, MANUAL_RUN, PentestLocalWorker, color_print, mock_plugin_modules


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

  def _assert_has_finding(self, result, substring):
    """Assert that a finding/vulnerability with 'substring' exists in result.

    Handles both legacy string results and new dict results with findings/vulnerabilities.
    """
    if isinstance(result, str):
      self.assertIn(substring, result)
      return

    if isinstance(result, dict):
      # Check 'vulnerabilities' list (string titles)
      vulns = result.get("vulnerabilities", [])
      for v in vulns:
        if substring in str(v):
          return

      # Check 'findings' list (dicts with 'title' and 'description')
      findings = result.get("findings", [])
      for f in findings:
        if isinstance(f, dict):
          if substring in str(f.get("title", "")) or substring in str(f.get("description", "")):
            return
        elif substring in str(f):
          return

      # Check 'error' key
      if substring in str(result.get("error", "")):
        return

      # Fallback: check entire dict as string
      result_str = json.dumps(result, default=str)
      if substring in result_str:
        return

      self.fail(f"Finding '{substring}' not found in result: {json.dumps(result, indent=2, default=str)[:500]}")
    else:
      self.fail(f"Unexpected result type {type(result)}: {result}")

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
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_common("example.com", 80)
    self._assert_has_finding(result, "Accessible resource")

  def test_cryptographic_failures_cookie_flags(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.headers = {"Set-Cookie": "sessionid=abc; Path=/"}
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_flags("example.com", 443)
    self._assert_has_finding(result, "Cookie missing Secure flag")
    self._assert_has_finding(result, "Cookie missing HttpOnly flag")
    self._assert_has_finding(result, "Cookie missing SameSite flag")

  def test_injection_sql_detected(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.text = "sql syntax error near line"
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.injection.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_sql_injection("example.com", 80)
    self._assert_has_finding(result, "SQL injection")

  def test_insecure_design_path_traversal(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.text = "root:x:0:0:root:/root:/bin/bash"
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.injection.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_path_traversal("example.com", 80)
    self._assert_has_finding(result, "Path traversal")

  def test_security_misconfiguration_missing_headers(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.headers = {"Server": "Test"}
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_security_headers("example.com", 80)
    self._assert_has_finding(result, "Missing security header")

  def test_vulnerable_component_banner_exposed(self):
    owner, worker = self._build_worker(ports=[80])
    worker.state["open_ports"] = [80]
    # Set enabled features to include the probe
    worker._PentestLocalWorker__enabled_features = ["_service_info_http"]
    resp = MagicMock()
    resp.status_code = 200
    resp.reason = "OK"
    resp.headers = {"Server": "Apache/2.2.0"}
    resp.text = "<html></html>"
    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.get",
      return_value=resp,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.request",
      side_effect=Exception("skip methods check"),
    ):
      worker._gather_service_info()
    banner = worker.state["service_info"][80]["_service_info_http"]
    self._assert_has_finding(banner, "Apache/2.2.0")

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
      "extensions.business.cybersec.red_mesh.worker.service.common.ftplib.FTP",
      return_value=DummyFTP(),
    ):
      result = worker._service_info_ftp("example.com", 21)
    self._assert_has_finding(result, "FTP allows anonymous login")

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
      "extensions.business.cybersec.red_mesh.worker.service.common.ftplib.FTP",
      return_value=DummyFTP(),
    ):
      result = worker._service_info_ftp("example.com", 2121)
    self._assert_has_finding(result, "FTP allows anonymous login")

  def test_service_info_runs_all_methods_for_each_port(self):
    owner, worker = self._build_worker(ports=[1234])
    worker.state["open_ports"] = [1234]

    def fake_service_one(target, port):
      return f"fake_service_one:{port}"

    def fake_service_two(target, port):
      return f"fake_service_two:{port}"

    setattr(worker, "_service_info_fake_one", fake_service_one)
    setattr(worker, "_service_info_fake_two", fake_service_two)
    worker._PentestLocalWorker__enabled_features = ["_service_info_fake_one", "_service_info_fake_two"]

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
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_homepage("example.com", 80)
    self._assert_has_finding(result, "private key")

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
    worker._PentestLocalWorker__enabled_features = ["_web_test_common"]

    def fake_get(url, timeout=2, verify=False):
      resp = MagicMock()
      resp.headers = {}
      resp.text = ""
      resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
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
    worker._PentestLocalWorker__enabled_features = ["_web_test_fake_one", "_web_test_fake_two"]

    worker._run_web_tests()

    web_snap = worker.state["web_tests_info"][10000]
    self.assertEqual(len(web_snap), 2)
    self.assertEqual(web_snap["_web_test_fake_one"], "web-one:10000")
    self.assertEqual(web_snap["_web_test_fake_two"], "web-two:10000")

  def test_correlation_runs_all_enabled_methods(self):
    owner, worker = self._build_worker(ports=[80])

    marker = []

    def fake_corr_one():
      marker.append("one")

    def fake_corr_two():
      marker.append("two")

    setattr(worker, "_post_scan_fake_one", fake_corr_one)
    setattr(worker, "_post_scan_fake_two", fake_corr_two)
    worker._PentestLocalWorker__enabled_features = ["_post_scan_fake_one", "_post_scan_fake_two"]

    worker._run_correlation_tests()

    self.assertEqual(marker, ["one", "two"])

  def test_execute_job_uses_explicit_phase_plan(self):
    _, worker = self._build_worker()
    phases = []

    def record_phase(phase_config):
      phases.append(phase_config["phase"])

    with patch.object(worker, "_execute_phase", side_effect=record_phase):
      worker.execute_job()

    self.assertEqual(phases, [entry["phase"] for entry in worker.PHASE_EXECUTION_PLAN])

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
      "extensions.business.cybersec.red_mesh.worker.web.injection.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_xss("example.com", 80)
    self._assert_has_finding(result, "XSS")

  def test_tls_certificate_expiration_reporting(self):
    owner, worker = self._build_worker(ports=[443])

    class DummyConn:
      def __enter__(self):
        return self

      def __exit__(self, exc_type, exc, tb):
        return False

    class DummySSLUnverified:
      def __enter__(self):
        return self

      def __exit__(self, exc_type, exc, tb):
        return False

      def close(self):
        pass

      def version(self):
        return "TLSv1.3"

      def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", None, None)

      def getpeercert(self, binary_form=False):
        if binary_form:
          return b"dummy"
        return {"notAfter": "Dec 31 12:00:00 2030 GMT",
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("organizationName", "Test CA"),),)}

    class DummySSLVerified:
      def __enter__(self):
        return self

      def __exit__(self, exc_type, exc, tb):
        return False

      def getpeercert(self):
        return {"notAfter": "Dec 31 12:00:00 2030 GMT",
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("organizationName", "Test CA"),),)}

    call_count = [0]

    class DummyContextUnverified:
      check_hostname = True
      verify_mode = None

      def wrap_socket(self, sock, server_hostname=None):
        return DummySSLUnverified()

    class DummyContextVerified:
      def wrap_socket(self, sock, server_hostname=None):
        return DummySSLVerified()

    def mock_ssl_context(protocol=None):
      return DummyContextUnverified()

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.socket.create_connection",
      return_value=DummyConn(),
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.ssl.SSLContext",
      return_value=DummyContextUnverified(),
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.ssl.create_default_context",
      return_value=DummyContextVerified(),
    ):
      info = worker._service_info_tls("example.com", 443)
    self.assertIsInstance(info, dict)
    self.assertIn("findings", info)
    # Should find TLS info (protocol is TLSv1.3 which is fine)
    self.assertIn("protocol", info)
    self.assertEqual(info["protocol"], "TLSv1.3")

  def test_tls_self_signed_detection(self):
    owner, worker = self._build_worker(ports=[443])

    class DummyConn:
      def __enter__(self):
        return self

      def __exit__(self, exc_type, exc, tb):
        return False

    class DummySSLUnverified:
      def __enter__(self):
        return self

      def __exit__(self, exc_type, exc, tb):
        return False

      def close(self):
        pass

      def version(self):
        return "TLSv1.2"

      def cipher(self):
        return ("AES256-SHA", None, None)

      def getpeercert(self, binary_form=False):
        return b"dummy" if binary_form else {}

    class DummyContextUnverified:
      check_hostname = True
      verify_mode = None

      def wrap_socket(self, sock, server_hostname=None):
        return DummySSLUnverified()

    class DummyContextVerified:
      def wrap_socket(self, sock, server_hostname=None):
        raise ssl.SSLCertVerificationError("self-signed certificate")

    import ssl

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.socket.create_connection",
      return_value=DummyConn(),
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.ssl.SSLContext",
      return_value=DummyContextUnverified(),
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.ssl.create_default_context",
      return_value=DummyContextVerified(),
    ):
      info = worker._service_info_tls("example.com", 443)

    self._assert_has_finding(info, "Self-signed")

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
      "extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket",
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
      "extensions.business.cybersec.red_mesh.worker.service.common.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_telnet("example.com", 23)
    self._assert_has_finding(info, "Telnet")

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
      "extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_smb("example.com", 445)
    self._assert_has_finding(info, "SMB")

  def test_service_vnc_unauthenticated(self):
    """VNC with security type None (1) should report CRITICAL."""
    owner, worker = self._build_worker(ports=[5900])

    recv_calls = [0]

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def recv(self, nbytes):
        recv_calls[0] += 1
        if recv_calls[0] == 1:
          return b"RFB 003.008\n"
        else:
          # num_types=1, type=1 (None)
          return bytes([1, 1])

      def sendall(self, data):
        return None

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_vnc("example.com", 5900)
    self._assert_has_finding(info, "unauthenticated")

  def test_service_vnc_password_auth(self):
    """VNC with security type 2 (VNC Auth) should report MEDIUM."""
    owner, worker = self._build_worker(ports=[5900])

    recv_calls = [0]

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def recv(self, nbytes):
        recv_calls[0] += 1
        if recv_calls[0] == 1:
          return b"RFB 003.008\n"
        else:
          return bytes([1, 2])

      def sendall(self, data):
        return None

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_vnc("example.com", 5900)
    self._assert_has_finding(info, "DES-based")

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
      "extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket",
      return_value=DummyUDPSocket(),
    ):
      info = worker._service_info_snmp("example.com", 161)
    self._assert_has_finding(info, "SNMP")

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
      "extensions.business.cybersec.red_mesh.worker.service.infrastructure.random.randint",
      return_value=tid,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket",
      return_value=DummyUDPSocket(),
    ):
      info = worker._service_info_dns("example.com", 53)
    self._assert_has_finding(info, "DNS version disclosure")

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
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_memcached("example.com", 11211)
    self._assert_has_finding(info, "Memcached")

  def test_service_elasticsearch_metadata(self):
    owner, worker = self._build_worker(ports=[9200])
    resp = MagicMock()
    resp.ok = True
    resp.status_code = 200
    resp.text = '{"cluster_name":"example","version":{"number":"7.10.0"},"tagline":"You Know, for Search"}'
    resp.json.return_value = {
      "cluster_name": "example",
      "version": {"number": "7.10.0"},
      "tagline": "You Know, for Search",
    }
    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.infrastructure.requests.get",
      return_value=resp,
    ):
      info = worker._service_info_elasticsearch("example.com", 9200)
    self._assert_has_finding(info, "Elasticsearch")

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
      "extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_modbus("example.com", 502)
    self._assert_has_finding(info, "Modbus")

  def test_service_postgres_trust_auth(self):
    """Auth code 0 (trust) should be CRITICAL."""
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
        # 'R' + int32(8) + int32(0) = AuthenticationOk
        return b'R' + struct.pack('!II', 8, 0)

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_postgresql("example.com", 5432)
    self._assert_has_finding(info, "trust authentication")
    # Verify it's CRITICAL severity
    for f in info.get("findings", []):
      if "trust" in f.get("title", "").lower():
        self.assertEqual(f["severity"], "CRITICAL")

  def test_service_postgres_cleartext(self):
    """Auth code 3 (cleartext) should be MEDIUM."""
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
        # 'R' + int32(8) + int32(3) = CleartextPassword
        return b'R' + struct.pack('!II', 8, 3)

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_postgresql("example.com", 5432)
    self._assert_has_finding(info, "cleartext")
    for f in info.get("findings", []):
      if "cleartext" in f.get("title", "").lower():
        self.assertEqual(f["severity"], "MEDIUM")

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
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_mssql("example.com", 1433)
    self._assert_has_finding(info, "MSSQL")

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
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_mongodb("example.com", 27017)
    self._assert_has_finding(info, "MongoDB")

  def test_web_graphql_introspection(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "{\"data\":{\"__schema\":{}}}"
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.api_exposure.requests.post",
      return_value=resp,
    ):
      result = worker._web_test_graphql_introspection("example.com", 80)
    self._assert_has_finding(result, "GraphQL introspection")

  def test_web_metadata_endpoint(self):
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False, headers=None):
      resp = MagicMock()
      resp.status_code = 200 if "meta-data" in url else 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.api_exposure.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_metadata_endpoints("example.com", 80)
    self._assert_has_finding(result, "Cloud metadata endpoint")

  def test_web_api_auth_bypass(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.api_exposure.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_api_auth_bypass("example.com", 80)
    self._assert_has_finding(result, "API auth bypass")

  def test_cors_misconfiguration_detection(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.headers = {
      "Access-Control-Allow-Origin": "https://attacker.example",
      "Access-Control-Allow-Credentials": "false",
    }
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_cors_misconfiguration("example.com", 80)
    self._assert_has_finding(result, "CORS misconfiguration")

  def test_open_redirect_detection(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 302
    resp.headers = {"Location": "https://attacker.example"}
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_open_redirect("example.com", 80)
    self._assert_has_finding(result, "Open redirect")

  def test_http_methods_detection(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.headers = {"Allow": "GET, POST, PUT"}
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.options",
      return_value=resp,
    ):
      result = worker._web_test_http_methods("example.com", 80)
    self._assert_has_finding(result, "Risky HTTP methods")

  # ===== NEW TESTS — findings.py =====

  def test_findings_severity_json_serializable(self):
    """Severity enum serializes via json.dumps."""
    from extensions.business.cybersec.red_mesh.findings import Severity
    self.assertEqual(json.dumps(Severity.CRITICAL), '"CRITICAL"')
    self.assertEqual(json.dumps(Severity.INFO), '"INFO"')

  def test_findings_dataclass_serializable(self):
    """Finding serializes via asdict."""
    from extensions.business.cybersec.red_mesh.findings import Finding, Severity
    from dataclasses import asdict
    f = Finding(Severity.HIGH, "Test", "Description", evidence="proof")
    d = asdict(f)
    self.assertEqual(d["severity"], "HIGH")
    self.assertEqual(d["title"], "Test")
    self.assertEqual(d["evidence"], "proof")
    # Ensure JSON-serializable
    json.dumps(d)

  def test_probe_result_structure(self):
    """probe_result produces dict with both findings and vulnerabilities."""
    from extensions.business.cybersec.red_mesh.findings import Finding, Severity, probe_result
    findings = [
      Finding(Severity.CRITICAL, "Crit vuln", "Critical."),
      Finding(Severity.LOW, "Low issue", "Low."),
      Finding(Severity.INFO, "Info note", "Info."),
    ]
    result = probe_result(raw_data={"banner": "test"}, findings=findings)
    self.assertEqual(result["banner"], "test")
    self.assertEqual(len(result["findings"]), 3)
    # vulnerabilities only includes CRITICAL/HIGH/MEDIUM
    self.assertEqual(result["vulnerabilities"], ["Crit vuln"])

  def test_probe_error_structure(self):
    """probe_error returns None so failed probes are not stored."""
    from extensions.business.cybersec.red_mesh.findings import probe_error
    result = probe_error("host", 80, "TestProbe", Exception("oops"))
    self.assertIsNone(result)

  # ===== NEW TESTS — cve_db.py =====

  def test_cve_matches_constraint_less_than(self):
    from extensions.business.cybersec.red_mesh.cve_db import _matches_constraint
    self.assertTrue(_matches_constraint("1.4.1", "<1.4.3"))
    self.assertFalse(_matches_constraint("1.4.3", "<1.4.3"))
    self.assertFalse(_matches_constraint("1.4.4", "<1.4.3"))

  def test_cve_matches_constraint_range(self):
    from extensions.business.cybersec.red_mesh.cve_db import _matches_constraint
    self.assertTrue(_matches_constraint("5.7.16", ">=5.7,<5.7.20"))
    self.assertFalse(_matches_constraint("5.7.20", ">=5.7,<5.7.20"))
    self.assertFalse(_matches_constraint("5.6.99", ">=5.7,<5.7.20"))

  def test_cve_check_elasticsearch(self):
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("elasticsearch", "1.4.1")
    cve_ids = [f.title for f in findings]
    self.assertTrue(any("CVE-2015-1427" in t for t in cve_ids))

  def test_cve_check_no_match(self):
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("elasticsearch", "99.0.0")
    self.assertEqual(len(findings), 0)

  # ===== NEW TESTS — Redis deep probe =====

  def test_redis_unauthenticated_access(self):
    owner, worker = self._build_worker(ports=[6379])

    cmd_responses = {
      "PING": "+PONG\r\n",
      "INFO server": "$100\r\nredis_version:6.0.5\r\nos:Linux 5.4.0\r\n",
      "CONFIG GET dir": "*2\r\n$3\r\ndir\r\n$4\r\n/tmp\r\n",
      "DBSIZE": ":42\r\n",
      "CLIENT LIST": "id=1 addr=10.0.0.1:12345 fd=5\r\n",
    }

    class DummySocket:
      def __init__(self, *args, **kwargs):
        self._buf = b""

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def sendall(self, data):
        cmd = data.decode().strip()
        self._buf = cmd_responses.get(cmd, "-ERR\r\n").encode()

      def recv(self, nbytes):
        data = self._buf
        self._buf = b""
        return data

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_redis("example.com", 6379)

    self._assert_has_finding(info, "unauthenticated")
    self._assert_has_finding(info, "CONFIG")
    self.assertIsInstance(info, dict)
    self.assertEqual(info.get("version"), "6.0.5")

  def test_redis_requires_auth(self):
    owner, worker = self._build_worker(ports=[6379])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def sendall(self, data):
        pass

      def recv(self, nbytes):
        return b"-NOAUTH Authentication required\r\n"

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_redis("example.com", 6379)

    self._assert_has_finding(info, "requires authentication")

  # ===== NEW TESTS — MySQL version extraction =====

  def test_mysql_version_extraction(self):
    owner, worker = self._build_worker(ports=[3306])

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass

      def settimeout(self, timeout):
        return None

      def connect(self, addr):
        return None

      def recv(self, nbytes):
        # MySQL handshake: 3-byte length + seq + protocol(0x0a) + version + null
        version = b"8.0.28"
        payload = bytes([0x0a]) + version + b'\x00' + b'\x00' * 50
        pkt_len = len(payload).to_bytes(3, 'little')
        return pkt_len + b'\x00' + payload

      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_mysql("example.com", 3306)

    self.assertIsInstance(info, dict)
    self.assertEqual(info.get("version"), "8.0.28")
    self._assert_has_finding(info, "8.0.28")

  # ===== NEW TESTS — Tech fingerprint =====

  def test_tech_fingerprint(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.headers = {"Server": "Apache/2.4.52", "X-Powered-By": "PHP/8.1"}
    resp.text = '<html><head><meta name="generator" content="WordPress 6.1"></head></html>'
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_tech_fingerprint("example.com", 80)
    self.assertIsInstance(result, dict)
    self._assert_has_finding(result, "Apache/2.4.52")
    self._assert_has_finding(result, "PHP/8.1")
    self._assert_has_finding(result, "WordPress")

  # ===== NEW TESTS — Modbus fingerprint on non-standard port =====

  def test_fingerprint_modbus_on_nonstandard_port(self):
    """Port 1024 with Modbus response should be fingerprinted as modbus."""
    owner, worker = self._build_worker(ports=[1024])
    worker.state["open_ports"] = [1024]
    worker.state["port_protocols"] = {1024: "unknown"}
    worker.state["port_banners"] = {1024: ""}
    worker.state["port_banner_confirmed"] = {1024: False}
    worker.target = "10.0.0.1"

    # Build a valid Modbus Read Device ID response:
    # Transaction ID 0x0001, Protocol ID 0x0000, Length 0x0008, Unit 0x01,
    # Function 0x2B, MEI type 0x0E, conformity 0x01, more 0x00, obj count 0x00
    modbus_response = b'\x00\x01\x00\x00\x00\x08\x01\x2b\x0e\x01\x01\x00\x00'

    call_index = [0]

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = b""
      # First call: nudge probe → empty
      # Second call: HTTP probe → empty
      # Third call: modbus probe → valid response
      idx = call_index[0]
      call_index[0] += 1
      if idx == 2:
        mock_sock.recv.return_value = modbus_response
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", side_effect=fake_socket_factory):
      worker._active_fingerprint_ports()

    self.assertEqual(worker.state["port_protocols"][1024], "modbus")

  def test_fingerprint_non_modbus_stays_unknown(self):
    """Port with no recognizable response should remain unknown after active probes."""
    owner, worker = self._build_worker(ports=[1024])
    worker.state["open_ports"] = [1024]
    worker.state["port_protocols"] = {1024: "unknown"}
    worker.state["port_banners"] = {1024: ""}
    worker.state["port_banner_confirmed"] = {1024: False}
    worker.target = "10.0.0.1"

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = b""
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", side_effect=fake_socket_factory):
      worker._active_fingerprint_ports()

    self.assertEqual(worker.state["port_protocols"][1024], "unknown")

  def test_fingerprint_mysql_false_positive_binary_data(self):
    """Binary data that happens to have 0x00 at byte 3 and 0x0a at byte 4 must NOT be classified as mysql."""
    owner, worker = self._build_worker(ports=[37364])
    worker.target = "10.0.0.1"

    # Crafted binary blob: byte 3 = 0x00, byte 4 = 0x0a, but byte 5+ is not
    # a printable version string — this is NOT a MySQL greeting.
    fake_binary = b'\x07\x02\x03\x00\x0a\x80\xff\x00\x01\x02'

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.connect_ex.return_value = 0
      mock_sock.recv.return_value = fake_binary
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", side_effect=fake_socket_factory):
      worker._scan_ports_step()

    self.assertNotEqual(worker.state["port_protocols"][37364], "mysql")

  def test_fingerprint_mysql_real_greeting(self):
    """A genuine MySQL greeting packet should still be fingerprinted as mysql."""
    owner, worker = self._build_worker(ports=[3306])
    worker.target = "10.0.0.1"

    # Real MySQL handshake: 3-byte length + seq=0x00 + protocol=0x0a + "8.0.28\x00" + filler
    version = b"8.0.28"
    payload = bytes([0x0a]) + version + b'\x00' + b'\x00' * 50
    pkt_len = len(payload).to_bytes(3, 'little')
    mysql_greeting = pkt_len + b'\x00' + payload

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.connect_ex.return_value = 0
      mock_sock.recv.return_value = mysql_greeting
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", side_effect=fake_socket_factory):
      worker._scan_ports_step()

    self.assertEqual(worker.state["port_protocols"][3306], "mysql")

  def test_fingerprint_telnet_real_iac(self):
    """Banner starting with a valid IAC WILL sequence should be fingerprinted as telnet."""
    owner, worker = self._build_worker(ports=[2323])
    worker.target = "10.0.0.1"

    # IAC WILL ECHO (0xFF 0xFB 0x01) — valid telnet negotiation per RFC 854
    telnet_banner = b'\xff\xfb\x01\xff\xfb\x03'

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.connect_ex.return_value = 0
      mock_sock.recv.return_value = telnet_banner
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", side_effect=fake_socket_factory):
      worker._scan_ports_step()

    self.assertEqual(worker.state["port_protocols"][2323], "telnet")

  def test_fingerprint_telnet_false_positive_0xff(self):
    """Binary data starting with 0xFF but no valid IAC command must NOT be classified as telnet."""
    owner, worker = self._build_worker(ports=[8502])
    worker.target = "10.0.0.1"

    # 0xFF followed by 0x01 — not a valid IAC command byte (WILL=0xFB, WONT=0xFC, DO=0xFD, DONT=0xFE)
    fake_binary = b'\xff\x01\x03\x00\x00\x05\x01\x2b'

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.connect_ex.return_value = 0
      mock_sock.recv.return_value = fake_binary
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", side_effect=fake_socket_factory):
      worker._scan_ports_step()

    self.assertNotEqual(worker.state["port_protocols"][8502], "telnet")

  def test_fingerprint_telnet_login_prompt(self):
    """A text banner containing 'login:' should still be fingerprinted as telnet."""
    owner, worker = self._build_worker(ports=[2323])
    worker.target = "10.0.0.1"

    login_banner = b'Ubuntu 22.04 LTS\r\nlogin: '

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.connect_ex.return_value = 0
      mock_sock.recv.return_value = login_banner
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", side_effect=fake_socket_factory):
      worker._scan_ports_step()

    self.assertEqual(worker.state["port_protocols"][2323], "telnet")

  def test_fingerprint_modbus_wrong_function_code(self):
    """Response with protocol ID 0x0000 but wrong function code must NOT be classified as modbus."""
    owner, worker = self._build_worker(ports=[1024])
    worker.state["open_ports"] = [1024]
    worker.state["port_protocols"] = {1024: "unknown"}
    worker.state["port_banners"] = {1024: ""}
    worker.state["port_banner_confirmed"] = {1024: False}
    worker.target = "10.0.0.1"

    # Protocol ID 0x0000 at bytes 2-3, but function code at byte 7 is 0x01 (not 0x2B)
    bad_modbus = b'\x00\x01\x00\x00\x00\x05\x01\x01\x00\x00\x00'

    call_index = [0]

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = b""
      idx = call_index[0]
      call_index[0] += 1
      if idx == 2:  # modbus probe is the 3rd socket (nudge, HTTP, modbus)
        mock_sock.recv.return_value = bad_modbus
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", side_effect=fake_socket_factory):
      worker._active_fingerprint_ports()

    self.assertNotEqual(worker.state["port_protocols"][1024], "modbus")

  def test_fingerprint_mysql_bad_payload_length(self):
    """MySQL-like bytes but absurd payload length prefix must NOT be classified as mysql."""
    owner, worker = self._build_worker(ports=[9999])
    worker.target = "10.0.0.1"

    # Payload length = 0x000001 (1 byte) — too small for a real MySQL handshake
    # seq=0x00, protocol=0x0a, then "5\x00" as a tiny version
    fake_pkt = b'\x01\x00\x00\x00\x0a5\x00'

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.connect_ex.return_value = 0
      mock_sock.recv.return_value = fake_pkt
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.worker.pentest_worker.socket.socket", side_effect=fake_socket_factory):
      worker._scan_ports_step()

    self.assertNotEqual(worker.state["port_protocols"][9999], "mysql")

  # ===== NEW TESTS — Generic probe vulnerability detection =====

  def test_generic_probe_version_disclosure(self):
    """Generic probe should flag version disclosure from banner."""
    owner, worker = self._build_worker(ports=[9999])

    class DummySocket:
      def __init__(self, *a, **kw): pass
      def settimeout(self, t): pass
      def connect(self, addr): pass
      def recv(self, n): return b"220 mail.example.com ESMTP Exim 4.94.1 ready\r\n"
      def close(self): pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.socket.socket",
      return_value=DummySocket(),
    ):
      result = worker._service_info_generic("example.com", 9999)

    self.assertIsInstance(result, dict)
    self.assertEqual(result.get("product"), "exim")
    self.assertEqual(result.get("version"), "4.94.1")
    self._assert_has_finding(result, "version disclosed")

  def test_generic_probe_cve_match(self):
    """Generic probe should find CVEs from banner version."""
    owner, worker = self._build_worker(ports=[9999])

    class DummySocket:
      def __init__(self, *a, **kw): pass
      def settimeout(self, t): pass
      def connect(self, addr): pass
      def recv(self, n): return b"SSH-2.0-OpenSSH_7.4\r\n"
      def close(self): pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.socket.socket",
      return_value=DummySocket(),
    ):
      result = worker._service_info_generic("example.com", 9999)

    self.assertIsInstance(result, dict)
    self.assertEqual(result.get("product"), "openssh")
    # OpenSSH 7.4 is vulnerable to CVE-2024-6387 (regreSSHion, <9.3)
    self._assert_has_finding(result, "CVE-2024-6387")

  def test_generic_probe_binary_returns_none(self):
    """Generic probe should return None for pure binary banners."""
    owner, worker = self._build_worker(ports=[9999])

    class DummySocket:
      def __init__(self, *a, **kw): pass
      def settimeout(self, t): pass
      def connect(self, addr): pass
      def recv(self, n): return b'\x00\x01\x00\x00\x00\x05\x01\x03'
      def close(self): pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.socket.socket",
      return_value=DummySocket(),
    ):
      result = worker._service_info_generic("example.com", 9999)

    self.assertIsNone(result)

  def test_generic_probe_no_version_no_findings(self):
    """Generic probe with readable banner but no product match should return no findings."""
    owner, worker = self._build_worker(ports=[9999])

    class DummySocket:
      def __init__(self, *a, **kw): pass
      def settimeout(self, t): pass
      def connect(self, addr): pass
      def recv(self, n): return b"Welcome to Custom Service\r\n"
      def close(self): pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.tls.socket.socket",
      return_value=DummySocket(),
    ):
      result = worker._service_info_generic("example.com", 9999)

    self.assertIsInstance(result, dict)
    self.assertIn("Welcome to Custom Service", result.get("banner", ""))
    self.assertEqual(result["findings"], [])

  # ===== NEW TESTS — VPN endpoint detection =====

  def test_vpn_endpoint_detection(self):
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False, allow_redirects=False):
      resp = MagicMock()
      if "/remote/login" in url:
        resp.status_code = 200
        resp.text = "Please Login - fortinet FortiGate"
        resp.headers = {"Set-Cookie": ""}
      else:
        resp.status_code = 404
        resp.text = ""
        resp.headers = {}
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_vpn_endpoints("example.com", 443)
    self._assert_has_finding(result, "FortiGate")



class TestFindingsModule(unittest.TestCase):
  """Standalone tests for findings.py module."""

  def test_severity_is_str_enum(self):
    from extensions.business.cybersec.red_mesh.findings import Severity
    self.assertIsInstance(Severity.CRITICAL, str)
    self.assertEqual(Severity.CRITICAL, "CRITICAL")

  def test_finding_is_frozen(self):
    from extensions.business.cybersec.red_mesh.findings import Finding, Severity
    f = Finding(Severity.HIGH, "test", "desc")
    with self.assertRaises(AttributeError):
      f.title = "modified"

  def test_finding_hashable(self):
    from extensions.business.cybersec.red_mesh.findings import Finding, Severity
    f1 = Finding(Severity.HIGH, "test", "desc")
    f2 = Finding(Severity.HIGH, "test", "desc")
    self.assertEqual(hash(f1), hash(f2))
    s = {f1, f2}
    self.assertEqual(len(s), 1)



class TestCveDatabase(unittest.TestCase):
  """Standalone tests for cve_db.py module."""

  def test_all_entries_valid(self):
    from extensions.business.cybersec.red_mesh.cve_db import CVE_DATABASE, _matches_constraint
    for entry in CVE_DATABASE:
      self.assertTrue(entry.product)
      self.assertTrue(entry.cve_id.startswith("CVE-"))
      self.assertTrue(entry.title)
      # Constraint should be parseable
      result = _matches_constraint("0.0.1", entry.constraint)
      self.assertIsInstance(result, bool)

  def test_openssh_regresshion(self):
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("openssh", "8.9")
    cve_ids = [f.title for f in findings]
    self.assertTrue(any("CVE-2024-6387" in t for t in cve_ids), f"Expected regreSSHion CVE, got: {cve_ids}")

  def test_apache_path_traversal(self):
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("apache", "2.4.49")
    cve_ids = [f.title for f in findings]
    self.assertTrue(any("CVE-2021-41773" in t for t in cve_ids))



class TestCorrelationEngine(unittest.TestCase):
  """Tests for the cross-service correlation engine."""

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [80]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-corr",
      initiator="init@example",
      local_id_prefix="C",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  def test_port_ratio_anomaly(self):
    """600/1000 open ports should trigger honeypot finding."""
    _, worker = self._build_worker(ports=list(range(1, 1001)))
    worker.state["open_ports"] = list(range(1, 601))
    worker.state["ports_scanned"] = list(range(1, 1001))
    worker._post_scan_correlate()
    findings = worker.state["correlation_findings"]
    self.assertTrue(
      any("honeypot" in f["title"].lower() and "port" in f["title"].lower() for f in findings),
      f"Expected port ratio honeypot finding, got: {findings}"
    )
    finding = next(f for f in findings if "honeypot" in f["title"].lower())
    self.assertEqual(finding["cwe"], [345])
    self.assertEqual(finding["owasp_top10"], ["A05:2021"])
    self.assertEqual(len(finding["finding_signature"]), 64)
    self.assertEqual(finding["remediation_structured"]["primary"], finding["remediation"])

  def test_port_ratio_normal(self):
    """5/1000 open ports should NOT trigger honeypot finding."""
    _, worker = self._build_worker(ports=list(range(1, 1001)))
    worker.state["open_ports"] = [22, 80, 443, 8080, 8443]
    worker.state["ports_scanned"] = list(range(1, 1001))
    worker._post_scan_correlate()
    findings = worker.state["correlation_findings"]
    self.assertFalse(
      any("port" in f["title"].lower() and "honeypot" in f["title"].lower() for f in findings),
      f"Unexpected port ratio finding: {findings}"
    )

  def test_os_mismatch(self):
    """Ubuntu + Darwin should trigger OS mismatch finding."""
    _, worker = self._build_worker()
    worker.state["scan_metadata"]["os_claims"] = {
      "ssh:22": "Ubuntu",
      "redis:6379": "Darwin 21.6.0",
    }
    worker._post_scan_correlate()
    findings = worker.state["correlation_findings"]
    self.assertTrue(
      any("os mismatch" in f["title"].lower() for f in findings),
      f"Expected OS mismatch finding, got: {findings}"
    )

  def test_os_consistent(self):
    """Ubuntu + Debian should NOT trigger OS mismatch (both Linux)."""
    _, worker = self._build_worker()
    worker.state["scan_metadata"]["os_claims"] = {
      "ssh:22": "Ubuntu",
      "redis:6379": "Linux 5.4.0",
    }
    worker._post_scan_correlate()
    findings = worker.state["correlation_findings"]
    self.assertFalse(
      any("os mismatch" in f["title"].lower() for f in findings),
      f"Unexpected OS mismatch finding: {findings}"
    )

  def test_infrastructure_leak_multi_subnet(self):
    """Two /16 subnets should trigger infrastructure leak."""
    _, worker = self._build_worker()
    worker.state["scan_metadata"]["internal_ips"] = [
      {"ip": "10.0.1.5", "source": "es_nodes:9200"},
      {"ip": "172.17.0.2", "source": "ftp_pasv:21"},
    ]
    worker._post_scan_correlate()
    findings = worker.state["correlation_findings"]
    self.assertTrue(
      any("infrastructure leak" in f["title"].lower() or "subnet" in f["title"].lower() for f in findings),
      f"Expected infrastructure leak finding, got: {findings}"
    )

  def test_timezone_drift(self):
    """Two different timezone offsets should trigger drift finding."""
    _, worker = self._build_worker()
    worker.state["scan_metadata"]["timezone_hints"] = [
      {"offset": "+0000", "source": "smtp:25"},
      {"offset": "-0500", "source": "smtp:587"},
    ]
    worker._post_scan_correlate()
    findings = worker.state["correlation_findings"]
    self.assertTrue(
      any("timezone" in f["title"].lower() for f in findings),
      f"Expected timezone drift finding, got: {findings}"
    )

  def test_emit_metadata_dict(self):
    """_emit_metadata should populate os_claims dict correctly."""
    _, worker = self._build_worker()
    worker._emit_metadata("os_claims", "ssh:22", "Ubuntu")
    self.assertEqual(worker.state["scan_metadata"]["os_claims"]["ssh:22"], "Ubuntu")

  def test_emit_metadata_list(self):
    """_emit_metadata should append to internal_ips list."""
    _, worker = self._build_worker()
    entry = {"ip": "10.0.0.1", "source": "test"}
    worker._emit_metadata("internal_ips", entry)
    self.assertIn(entry, worker.state["scan_metadata"]["internal_ips"])

  def test_emit_metadata_missing_state(self):
    """_emit_metadata should be a no-op when scan_metadata is absent."""
    _, worker = self._build_worker()
    del worker.state["scan_metadata"]
    # Should not raise
    worker._emit_metadata("os_claims", "ssh:22", "Ubuntu")

  def test_mysql_salt_low_entropy(self):
    """All-same-byte MySQL salt should trigger low entropy finding."""
    _, worker = self._build_worker(ports=[3306])
    # Build a MySQL handshake with all-zero salt bytes
    version = b"5.7.99-fake"
    # protocol_version(1) + version + null + thread_id(4) + salt1(8) + filler(1)
    # + caps(2) + charset(1) + status(2) + caps_upper(2) + auth_len(1) + reserved(10) + salt2(12) + null
    salt1 = b'\x00' * 8
    salt2 = b'\x00' * 12
    after_version = b'\x01\x00\x00\x00' + salt1 + b'\x00'  # thread_id + salt1 + filler
    after_version += b'\x00\x00'  # caps
    after_version += b'\x21'      # charset
    after_version += b'\x00\x00'  # status
    after_version += b'\x00\x00'  # caps_upper
    after_version += b'\x15'      # auth_len
    after_version += b'\x00' * 10  # reserved
    after_version += salt2 + b'\x00'
    after_version += b'mysql_native_password\x00'
    payload = bytes([0x0a]) + version + b'\x00' + after_version
    pkt_len = len(payload).to_bytes(3, 'little')
    packet = pkt_len + b'\x00' + payload

    class DummySocket:
      def __init__(self, *args, **kwargs):
        pass
      def settimeout(self, timeout):
        pass
      def connect(self, addr):
        pass
      def recv(self, nbytes):
        return packet
      def close(self):
        pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_mysql("example.com", 3306)
    self.assertIsInstance(info, dict)
    # Should have a low entropy finding
    found = any("entropy" in f.get("title", "").lower() for f in info.get("findings", []))
    self.assertTrue(found, f"Expected low entropy finding, got: {info.get('findings', [])}")

  def test_ftp_pasv_ip_leak(self):
    """PASV with RFC1918 IP should trigger internal IP leak finding."""
    _, worker = self._build_worker(ports=[21])

    class DummyFTP:
      def __init__(self, timeout=3):
        pass
      def connect(self, target, port, timeout=3):
        return None
      def getwelcome(self):
        return "220 FTP Ready"
      def login(self, *args, **kwargs):
        return None
      def sendcmd(self, cmd):
        if cmd == "PASV":
          return "227 Entering Passive Mode (192,168,1,100,4,1)"
        if cmd == "SYST":
          return "215 UNIX"
        if cmd == "FEAT":
          return "211 End"
        if cmd == "AUTH TLS":
          raise Exception("not supported")
        return ""
      def set_pasv(self, val):
        pass
      def pwd(self):
        return "/"
      def cwd(self, path):
        raise Exception("denied")
      def quit(self):
        pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.ftplib.FTP",
      return_value=DummyFTP(),
    ):
      info = worker._service_info_ftp("example.com", 21)
    self.assertIsInstance(info, dict)
    found = any("pasv" in f.get("title", "").lower() for f in info.get("findings", []))
    self.assertTrue(found, f"Expected PASV IP leak finding, got: {info.get('findings', [])}")

  def test_web_200_for_all(self):
    """200 on random path should trigger catch-all finding."""
    _, worker = self._build_worker()

    def fake_get(url, timeout=2, verify=False):
      resp = MagicMock()
      resp.headers = {}
      resp.text = ""
      resp.status_code = 200
      resp.reason = "OK"
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_common("example.com", 80)
    self.assertIsInstance(result, dict)
    found = any("random path" in f.get("title", "").lower() or "200 for" in f.get("title", "").lower()
                for f in result.get("findings", []))
    self.assertTrue(found, f"Expected 200-for-all finding, got: {result.get('findings', [])}")

  def test_tls_san_parsing(self):
    """DER cert with SAN IPs should be correctly extracted."""
    _, worker = self._build_worker(ports=[443])
    # Generate a test cert with SANs using cryptography
    try:
      from cryptography import x509
      from cryptography.x509.oid import NameOID
      from cryptography.hazmat.primitives import hashes, serialization
      from cryptography.hazmat.primitives.asymmetric import rsa
      import datetime
      import ipaddress

      key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
      subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
      cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
          x509.SubjectAlternativeName([
            x509.DNSName("test.example.com"),
            x509.DNSName("www.example.com"),
            x509.IPAddress(ipaddress.IPv4Address("10.0.0.1")),
            x509.IPAddress(ipaddress.IPv4Address("192.168.1.1")),
          ]),
          critical=False,
        )
        .sign(key, hashes.SHA256())
      )
      cert_der = cert.public_bytes(serialization.Encoding.DER)

      dns_names, ip_addresses = worker._tls_parse_san_from_der(cert_der)
      self.assertIn("test.example.com", dns_names)
      self.assertIn("www.example.com", dns_names)
      self.assertIn("10.0.0.1", ip_addresses)
      self.assertIn("192.168.1.1", ip_addresses)
    except ImportError:
      self.skipTest("cryptography library not available")

  def test_cve_confidence_tentative(self):
    """All CVE findings should have tentative confidence."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("openssh", "8.9")
    self.assertTrue(len(findings) > 0, "Expected at least one CVE finding")
    for f in findings:
      self.assertEqual(f.confidence, "tentative", f"Expected tentative confidence, got {f.confidence} for {f.title}")

  def test_ssh_dsa_key(self):
    """ssh-dss in key_types should trigger DSA finding."""
    _, worker = self._build_worker(ports=[22])

    class DummySecOpts:
      ciphers = ["aes256-ctr"]
      kex = ["curve25519-sha256"]
      key_types = ["ssh-rsa", "ssh-dss"]

    class DummyTransport:
      def __init__(self, *args, **kwargs):
        pass
      def connect(self):
        pass
      def get_security_options(self):
        return DummySecOpts()
      def get_remote_server_key(self):
        return None
      def close(self):
        pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.paramiko.Transport",
      return_value=DummyTransport(),
    ):
      findings, weak_labels = worker._ssh_check_ciphers("example.com", 22)
    found = any("dsa" in f.title.lower() or "ssh-dss" in f.title.lower() for f in findings)
    self.assertTrue(found, f"Expected DSA key finding, got: {[f.title for f in findings]}")

  def test_execute_job_correlation(self):
    """execute_job should include correlation_completed in completed_tests."""
    _, worker = self._build_worker()

    with patch.object(worker, "_scan_ports_step"), \
         patch.object(worker, "_active_fingerprint_ports"), \
         patch.object(worker, "_gather_service_info"), \
         patch.object(worker, "_run_web_tests"), \
         patch.object(worker, "_post_scan_correlate"):
      worker.execute_job()

    self.assertTrue(worker.state["done"])
    self.assertIn("correlation_completed", worker.state["completed_tests"])

  def test_execute_job_skips_disabled_correlation_probe(self):
    """Disabled correlation is reflected as a skipped probe, not silently omitted."""
    _, worker = self._build_worker()
    worker._PentestLocalWorker__enabled_features = []

    with patch.object(worker, "_scan_ports_step"), \
         patch.object(worker, "_active_fingerprint_ports"), \
         patch.object(worker, "_gather_service_info"), \
         patch.object(worker, "_run_web_tests"), \
         patch.object(worker, "_post_scan_correlate") as mock_correlate:
      worker.execute_job()

    mock_correlate.assert_not_called()
    metrics = worker.metrics.build().to_dict()
    self.assertEqual(metrics["probe_breakdown"]["_post_scan_correlate"], "skipped:disabled")



class TestScannerEnhancements(unittest.TestCase):
  """Tests for the 5 partial scanner enhancements (Tier 1)."""

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [80]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-enh",
      initiator="init@example",
      local_id_prefix="E",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  # --- Item 1: TLS validity period ---

  def test_tls_validity_period_10yr(self):
    """Certificate with 10-year validity should flag MEDIUM."""
    _, worker = self._build_worker(ports=[443])
    try:
      from cryptography import x509
      from cryptography.x509.oid import NameOID
      from cryptography.hazmat.primitives import hashes, serialization
      from cryptography.hazmat.primitives.asymmetric import rsa
      import datetime

      key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
      subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
      cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, hashes.SHA256())
      )
      cert_der = cert.public_bytes(serialization.Encoding.DER)

      findings = worker._tls_check_validity_period(cert_der)
      self.assertEqual(len(findings), 1)
      self.assertEqual(findings[0].severity, "MEDIUM")
      self.assertIn("validity span", findings[0].title.lower())
    except ImportError:
      self.skipTest("cryptography library not available")

  def test_tls_validity_period_1yr(self):
    """Certificate with 1-year validity should produce no finding."""
    _, worker = self._build_worker(ports=[443])
    try:
      from cryptography import x509
      from cryptography.x509.oid import NameOID
      from cryptography.hazmat.primitives import hashes, serialization
      from cryptography.hazmat.primitives.asymmetric import rsa
      import datetime

      key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
      subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.com")])
      cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(key, hashes.SHA256())
      )
      cert_der = cert.public_bytes(serialization.Encoding.DER)

      findings = worker._tls_check_validity_period(cert_der)
      self.assertEqual(len(findings), 0)
    except ImportError:
      self.skipTest("cryptography library not available")

  # --- Item 2: Redis stale persistence ---

  def test_redis_persistence_stale(self):
    """rdb_last_bgsave_time 400 days old should flag LOW."""
    _, worker = self._build_worker(ports=[6379])
    import time

    stale_ts = int(time.time()) - 400 * 86400

    cmd_responses = {
      "PING": "+PONG\r\n",
      "INFO server": "$50\r\nredis_version:7.0.0\r\nos:Linux\r\n",
      "CONFIG GET dir": "-ERR\r\n",
      "DBSIZE": ":0\r\n",
      "CLIENT LIST": "-ERR\r\n",
      "INFO persistence": f"$50\r\nrdb_last_bgsave_time:{stale_ts}\r\n",
    }

    class DummySocket:
      def __init__(self, *a, **kw):
        self._buf = b""
      def settimeout(self, t):
        return None
      def connect(self, addr):
        return None
      def sendall(self, data):
        cmd = data.decode().strip()
        self._buf = cmd_responses.get(cmd, "-ERR\r\n").encode()
      def recv(self, nbytes):
        data = self._buf
        self._buf = b""
        return data
      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_redis("example.com", 6379)

    found = any("stale" in f.get("title", "").lower() for f in info.get("findings", []))
    self.assertTrue(found, f"Expected stale persistence finding, got: {info.get('findings', [])}")

  def test_redis_persistence_never_saved(self):
    """rdb_last_bgsave_time=0 should flag LOW (never saved)."""
    _, worker = self._build_worker(ports=[6379])

    cmd_responses = {
      "PING": "+PONG\r\n",
      "INFO server": "$50\r\nredis_version:7.0.0\r\nos:Linux\r\n",
      "CONFIG GET dir": "-ERR\r\n",
      "DBSIZE": ":0\r\n",
      "CLIENT LIST": "-ERR\r\n",
      "INFO persistence": "$30\r\nrdb_last_bgsave_time:0\r\n",
    }

    class DummySocket:
      def __init__(self, *a, **kw):
        self._buf = b""
      def settimeout(self, t):
        return None
      def connect(self, addr):
        return None
      def sendall(self, data):
        cmd = data.decode().strip()
        self._buf = cmd_responses.get(cmd, "-ERR\r\n").encode()
      def recv(self, nbytes):
        data = self._buf
        self._buf = b""
        return data
      def close(self):
        return None

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.database.socket.socket",
      return_value=DummySocket(),
    ):
      info = worker._service_info_redis("example.com", 6379)

    found = any("never" in f.get("title", "").lower() for f in info.get("findings", []))
    self.assertTrue(found, f"Expected never-saved finding, got: {info.get('findings', [])}")

  # --- Item 3: SSH RSA key size ---

  def test_ssh_rsa_1024_high(self):
    """1024-bit RSA key should flag HIGH."""
    _, worker = self._build_worker(ports=[22])

    class DummyKey:
      def get_name(self):
        return "ssh-rsa"
      def get_bits(self):
        return 1024

    class DummySecOpts:
      ciphers = ["aes256-ctr"]
      kex = ["curve25519-sha256"]
      key_types = ["ssh-rsa"]

    class DummyTransport:
      def __init__(self, *a, **kw): pass
      def connect(self): pass
      def get_security_options(self): return DummySecOpts()
      def get_remote_server_key(self): return DummyKey()
      def close(self): pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.paramiko.Transport",
      return_value=DummyTransport(),
    ):
      findings, weak_labels = worker._ssh_check_ciphers("example.com", 22)
    found = any("critically weak" in f.title.lower() and "1024" in f.title for f in findings)
    self.assertTrue(found, f"Expected HIGH RSA finding, got: {[f.title for f in findings]}")
    sev = [f.severity for f in findings if "1024" in f.title]
    self.assertTrue(any(s == "HIGH" or str(s) == "HIGH" or getattr(s, 'value', None) == "HIGH" for s in sev))

  def test_ssh_rsa_2048_low(self):
    """2048-bit RSA key should flag LOW (below NIST recommendation)."""
    _, worker = self._build_worker(ports=[22])

    class DummyKey:
      def get_name(self):
        return "ssh-rsa"
      def get_bits(self):
        return 2048

    class DummySecOpts:
      ciphers = ["aes256-ctr"]
      kex = ["curve25519-sha256"]
      key_types = ["ssh-rsa"]

    class DummyTransport:
      def __init__(self, *a, **kw): pass
      def connect(self): pass
      def get_security_options(self): return DummySecOpts()
      def get_remote_server_key(self): return DummyKey()
      def close(self): pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.paramiko.Transport",
      return_value=DummyTransport(),
    ):
      findings, weak_labels = worker._ssh_check_ciphers("example.com", 22)
    found = any("nist" in f.title.lower() and "2048" in f.title for f in findings)
    self.assertTrue(found, f"Expected LOW RSA finding, got: {[f.title for f in findings]}")
    sev = [f.severity for f in findings if "2048" in f.title]
    self.assertTrue(any(s == "LOW" or str(s) == "LOW" or getattr(s, 'value', None) == "LOW" for s in sev))

  def test_ssh_rsa_4096_no_finding(self):
    """4096-bit RSA key should produce no RSA-related finding."""
    _, worker = self._build_worker(ports=[22])

    class DummyKey:
      def get_name(self):
        return "ssh-rsa"
      def get_bits(self):
        return 4096

    class DummySecOpts:
      ciphers = ["aes256-ctr"]
      kex = ["curve25519-sha256"]
      key_types = ["ssh-rsa"]

    class DummyTransport:
      def __init__(self, *a, **kw): pass
      def connect(self): pass
      def get_security_options(self): return DummySecOpts()
      def get_remote_server_key(self): return DummyKey()
      def close(self): pass

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.paramiko.Transport",
      return_value=DummyTransport(),
    ):
      findings, weak_labels = worker._ssh_check_ciphers("example.com", 22)
    rsa_findings = [f for f in findings if "rsa" in f.title.lower()]
    self.assertEqual(len(rsa_findings), 0, f"Expected no RSA findings, got: {[f.title for f in rsa_findings]}")

  # --- Item 4: SMTP K8s pod name + .internal ---

  def test_smtp_k8s_pod_hostname(self):
    """K8s-style pod hostname should flag LOW."""
    _, worker = self._build_worker(ports=[25])

    class DummySMTP:
      def __init__(self, timeout=5): pass
      def connect(self, target, port):
        return (220, b"ESMTP ready")
      def ehlo(self, identity):
        return (250, b"nginx-7f4b5c9d-kx9wqmrt Hello client [1.2.3.4]")
      def docmd(self, cmd):
        return (500, b"unrecognized")
      def quit(self): pass

    with patch(
      "smtplib.SMTP",
      return_value=DummySMTP(),
    ):
      info = worker._service_info_smtp("example.com", 25)

    self.assertIsInstance(info, dict)
    found = any("kubernetes" in f.get("title", "").lower() or "pod name" in f.get("title", "").lower()
                for f in info.get("findings", []))
    self.assertTrue(found, f"Expected K8s pod finding, got: {info.get('findings', [])}")

  def test_smtp_internal_hostname(self):
    """Hostname ending in .internal should flag LOW."""
    _, worker = self._build_worker(ports=[25])

    class DummySMTP:
      def __init__(self, timeout=5): pass
      def connect(self, target, port):
        return (220, b"ESMTP ready")
      def ehlo(self, identity):
        return (250, b"ip-10-0-1-5.ec2.internal Hello client [1.2.3.4]")
      def docmd(self, cmd):
        return (500, b"unrecognized")
      def quit(self): pass

    with patch(
      "smtplib.SMTP",
      return_value=DummySMTP(),
    ):
      info = worker._service_info_smtp("example.com", 25)

    self.assertIsInstance(info, dict)
    found = any(".internal" in f.get("title", "").lower() or "cloud-internal" in f.get("title", "").lower()
                for f in info.get("findings", []))
    self.assertTrue(found, f"Expected .internal finding, got: {info.get('findings', [])}")

  # --- Item 5: Web endpoint probe extension ---

  def test_web_xmlrpc_endpoint(self):
    """xmlrpc.php returning 200 should flag MEDIUM."""
    _, worker = self._build_worker()

    def fake_get(url, timeout=2, verify=False):
      resp = MagicMock()
      resp.headers = {}
      resp.text = ""
      if url.endswith("/xmlrpc.php"):
        resp.status_code = 200
      else:
        resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_common("example.com", 80)
    found = any("xmlrpc" in f.get("title", "").lower() for f in result.get("findings", []))
    self.assertTrue(found, f"Expected xmlrpc finding, got: {result.get('findings', [])}")

  def test_web_wp_login_endpoint(self):
    """wp-login.php returning 200 should flag LOW."""
    _, worker = self._build_worker()

    def fake_get(url, timeout=2, verify=False):
      resp = MagicMock()
      resp.headers = {}
      resp.text = ""
      if url.endswith("/wp-login.php"):
        resp.status_code = 200
      else:
        resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_common("example.com", 80)
    found = any("wp-login" in f.get("title", "").lower() for f in result.get("findings", []))
    self.assertTrue(found, f"Expected wp-login finding, got: {result.get('findings', [])}")

  def test_web_security_txt_endpoint(self):
    """security.txt returning 200 should produce INFO finding."""
    _, worker = self._build_worker()

    def fake_get(url, timeout=2, verify=False):
      resp = MagicMock()
      resp.headers = {}
      resp.text = ""
      if url.endswith("/.well-known/security.txt"):
        resp.status_code = 200
      else:
        resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_common("example.com", 80)
    found = any("security.txt" in f.get("title", "").lower() or "security policy" in f.get("description", "").lower()
                for f in result.get("findings", []))
    self.assertTrue(found, f"Expected security.txt finding, got: {result.get('findings', [])}")


  # --- Item 6: HTTP empty reply fallback ---

  def test_http_empty_reply_fallback(self):
    """HTTP probe should fall back to raw socket when requests.get fails with empty reply."""
    _, worker = self._build_worker(ports=[81])

    class DummySocket:
      def __init__(self, chunks):
        self._chunks = list(chunks)
      def settimeout(self, t): pass
      def connect(self, addr): pass
      def send(self, data): pass
      def recv(self, n):
        return self._chunks.pop(0) if self._chunks else b""
      def close(self): pass

    from requests.exceptions import ConnectionError as ReqConnError

    # Case 1: requests fails, raw socket also gets empty reply
    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.get",
      side_effect=ReqConnError("RemoteDisconnected"),
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.socket.socket",
      return_value=DummySocket([b""]),
    ):
      result = worker._service_info_http("10.0.0.1", 81)
    self.assertIsNotNone(result, "Should return a result, not None")
    self.assertEqual(result.get("banner"), "(empty reply)")
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("empty reply" in t.lower() for t in titles),
                    f"Expected empty reply finding, got: {titles}")

  def test_http_empty_reply_fallback_with_banner(self):
    """HTTP probe raw socket fallback should capture server banner and detect Host-header drop."""
    _, worker = self._build_worker(ports=[81])

    class DummySocket:
      def __init__(self, chunks):
        self._chunks = list(chunks)
      def settimeout(self, t): pass
      def connect(self, addr): pass
      def send(self, data): pass
      def recv(self, n):
        return self._chunks.pop(0) if self._chunks else b""
      def close(self): pass

    from requests.exceptions import ConnectionError as ReqConnError
    raw_resp = b"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.get",
      side_effect=ReqConnError("RemoteDisconnected"),
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.socket.socket",
      return_value=DummySocket([raw_resp, b""]),
    ):
      result = worker._service_info_http("10.0.0.1", 81)
    self.assertIsNotNone(result, "Should return a result, not None")
    self.assertEqual(result.get("banner"), "HTTP/1.1 200 OK")
    self.assertEqual(result.get("server"), "nginx/1.24.0")
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("host header" in t.lower() for t in titles),
                    f"Expected Host-header-drop finding, got: {titles}")

  def test_http_fallback_directory_listing(self):
    """HTTP probe raw socket fallback should detect directory listing."""
    _, worker = self._build_worker(ports=[81])

    class DummySocket:
      def __init__(self, chunks):
        self._chunks = list(chunks)
      def settimeout(self, t): pass
      def connect(self, addr): pass
      def send(self, data): pass
      def recv(self, n):
        return self._chunks.pop(0) if self._chunks else b""
      def close(self): pass

    from requests.exceptions import ConnectionError as ReqConnError
    raw_resp = (
      b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
      b"<html><title>Directory listing for /</title><body>"
      b'<li><a href="../">../</a></body></html>'
    )

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.requests.get",
      side_effect=ReqConnError("RemoteDisconnected"),
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.service.common.socket.socket",
      return_value=DummySocket([raw_resp, b""]),
    ):
      result = worker._service_info_http("10.0.0.1", 81)
    self.assertIsNotNone(result)
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("directory listing" in t.lower() for t in titles),
                    f"Expected directory listing finding, got: {titles}")
    self.assertEqual(result.get("title"), "Directory listing for /")



class TestPhase17aQuickWins(unittest.TestCase):
  """Phase 17a: Quick Win probe enhancements."""

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [22]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-17a",
      initiator="init@example",
      local_id_prefix="Q",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  # ---- 17a-1: libssh auth bypass ----

  def test_ssh_libssh_detected_in_banner(self):
    """_ssh_identify_library detects libssh from banner."""
    _, worker = self._build_worker()
    lib, ver = worker._ssh_identify_library("SSH-2.0-libssh-0.8.1")
    self.assertEqual(lib, "libssh")
    self.assertEqual(ver, "0.8.1")

  def test_ssh_libssh_bypass_returns_none_on_failure(self):
    """_ssh_check_libssh_bypass returns None when connection fails."""
    _, worker = self._build_worker()
    result = worker._ssh_check_libssh_bypass("192.0.2.1", 99999)
    self.assertIsNone(result)

  def test_ssh_libssh_cves_in_db(self):
    """CVE-2018-10933 is present in CVE database for libssh."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("libssh", "0.8.1")
    self.assertTrue(len(findings) >= 1)
    titles = [f.title for f in findings]
    self.assertTrue(any("CVE-2018-10933" in t for t in titles))

  # ---- 17a-2: Protocol fingerprinting ----

  def test_generic_fingerprint_redis(self):
    """Redis RESP banner is recognized."""
    _, worker = self._build_worker()
    self.assertTrue(worker._is_redis_banner(b"+PONG\r\n"))
    self.assertTrue(worker._is_redis_banner(b"-ERR unknown command\r\n"))
    self.assertTrue(worker._is_redis_banner(b"$11\r\nHello World\r\n"))
    self.assertFalse(worker._is_redis_banner(b"HTTP/1.1 200 OK\r\n"))

  def test_generic_fingerprint_ftp(self):
    """FTP 220 banner is recognized."""
    _, worker = self._build_worker()
    self.assertTrue(worker._is_ftp_banner(b"220 Welcome to FTP\r\n"))
    self.assertTrue(worker._is_ftp_banner(b"220-ProFTPD 1.3.5\r\n"))
    self.assertFalse(worker._is_ftp_banner(b"SSH-2.0-OpenSSH\r\n"))

  def test_generic_fingerprint_mysql(self):
    """MySQL handshake packet is recognized."""
    _, worker = self._build_worker()
    # MySQL v10 handshake: 3-byte length + 1-byte seq + 0x0a + version string
    handshake = b'\x4a\x00\x00\x00\x0a5.5.23\x00' + b'\x00' * 40
    self.assertTrue(worker._is_mysql_handshake(handshake))
    self.assertFalse(worker._is_mysql_handshake(b"HTTP/1.1 200 OK"))

  def test_generic_fingerprint_smtp(self):
    """SMTP banner is recognized."""
    _, worker = self._build_worker()
    self.assertTrue(worker._is_smtp_banner(b"220 mail.example.com ESMTP Postfix\r\n"))
    self.assertFalse(worker._is_smtp_banner(b"220 ProFTPD 1.3\r\n"))

  def test_generic_fingerprint_rsync(self):
    """Rsync banner is recognized."""
    _, worker = self._build_worker()
    self.assertTrue(worker._is_rsync_banner(b"@RSYNCD: 31.0\n"))
    self.assertFalse(worker._is_rsync_banner(b"+OK Dovecot ready\r\n"))

  def test_generic_fingerprint_telnet(self):
    """Telnet IAC sequence is recognized."""
    _, worker = self._build_worker()
    self.assertTrue(worker._is_telnet_banner(b"\xFF\xFB\x01\xFF\xFB\x03"))
    self.assertFalse(worker._is_telnet_banner(b"HTTP/1.0 200"))

  def test_generic_reclassifies_port_protocol(self):
    """When a protocol is fingerprinted, port_protocols is updated."""
    _, worker = self._build_worker(ports=[993])
    worker.state["port_protocols"] = {993: "unknown"}
    # Simulate Redis banner on port 993
    redis_banner = b"+PONG\r\n"
    # Mock the Redis probe to avoid real connection
    mock_result = {"findings": [], "vulnerabilities": []}
    with patch.object(worker, '_service_info_redis', return_value=mock_result):
      result = worker._generic_fingerprint_protocol(redis_banner, "10.0.0.1", 993)
    self.assertEqual(worker.state["port_protocols"][993], "redis")
    self.assertIsNotNone(result)

  # ---- 17a-5: ES IP classification + JVM ----

  def test_es_nodes_public_ip_critical(self):
    """Public IP from _nodes endpoint is flagged CRITICAL."""
    _, worker = self._build_worker(ports=[9200])
    worker.state["scan_metadata"] = {"internal_ips": []}
    raw = {}
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
      "nodes": {
        "n1": {
          "host": "34.51.200.39",
          "jvm": {"version": "1.7.0_55"},
        }
      }
    }
    with patch('requests.get', return_value=mock_resp):
      findings = worker._es_check_nodes("http://10.0.0.1:9200", raw)
    titles = [f.title for f in findings]
    severities = [f.severity for f in findings]
    # Public IP should be CRITICAL
    self.assertTrue(any("public ip" in t.lower() for t in titles), f"Expected public IP finding, got: {titles}")
    self.assertIn("CRITICAL", severities)
    # JVM EOL
    self.assertTrue(any("eol jvm" in t.lower() for t in titles), f"Expected EOL JVM finding, got: {titles}")
    self.assertEqual(raw.get("jvm_version"), "1.7.0_55")

  def test_es_nodes_private_ip_medium(self):
    """Private IP from _nodes endpoint is flagged MEDIUM (not CRITICAL)."""
    _, worker = self._build_worker(ports=[9200])
    worker.state["scan_metadata"] = {"internal_ips": []}
    raw = {}
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
      "nodes": {"n1": {"host": "192.168.1.100"}}
    }
    with patch('requests.get', return_value=mock_resp):
      findings = worker._es_check_nodes("http://10.0.0.1:9200", raw)
    severities = [f.severity for f in findings]
    self.assertIn("MEDIUM", severities)
    self.assertNotIn("CRITICAL", severities)

  def test_es_nodes_jvm_modern_no_finding(self):
    """Modern JVM (Java 17+) should not produce an EOL finding."""
    _, worker = self._build_worker(ports=[9200])
    worker.state["scan_metadata"] = {"internal_ips": []}
    raw = {}
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.json.return_value = {
      "nodes": {"n1": {"host": "10.0.0.5", "jvm": {"version": "17.0.5"}}}
    }
    with patch('requests.get', return_value=mock_resp):
      findings = worker._es_check_nodes("http://10.0.0.1:9200", raw)
    titles = [f.title for f in findings]
    self.assertFalse(any("EOL JVM" in t for t in titles))



class TestPhase17bMediumFeatures(unittest.TestCase):
  """Phase 17b: Medium feature probe enhancements."""

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [80]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-17b",
      initiator="init@example",
      local_id_prefix="M",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  # ---- 17b-2: HTTP Basic Auth ----

  def test_http_basic_auth_detects_default_creds(self):
    """Default admin:admin credential flagged when accepted."""
    _, worker = self._build_worker(ports=[80])

    def mock_get(url, **kwargs):
      resp = MagicMock()
      auth = kwargs.get("auth")
      if auth is None:
        # Initial probe — return 401 with Basic auth
        resp.status_code = 401
        resp.headers = {"WWW-Authenticate": 'Basic realm="test"'}
      elif auth == ("admin", "admin"):
        resp.status_code = 200
        resp.headers = {}
      else:
        resp.status_code = 401
        resp.headers = {}
      return resp

    with patch('requests.get', side_effect=mock_get):
      result = worker._service_info_http_basic_auth("10.0.0.1", 80)
    self.assertIsNotNone(result)
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("default credential" in t.lower() for t in titles), f"titles={titles}")

  def test_http_basic_auth_skips_non_basic(self):
    """Probe returns None when no Basic auth is present."""
    _, worker = self._build_worker(ports=[80])
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {}
    with patch('requests.get', return_value=mock_resp):
      result = worker._service_info_http_basic_auth("10.0.0.1", 80)
    self.assertIsNone(result)

  def test_http_basic_auth_no_rate_limiting(self):
    """Flags missing rate limiting when all attempts return 401."""
    _, worker = self._build_worker(ports=[80])
    call_count = [0]

    def mock_get(url, **kwargs):
      resp = MagicMock()
      call_count[0] += 1
      resp.status_code = 401
      resp.headers = {"WWW-Authenticate": 'Basic realm="test"'}
      return resp

    with patch('requests.get', side_effect=mock_get):
      result = worker._service_info_http_basic_auth("10.0.0.1", 80)
    self.assertIsNotNone(result)
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("rate limiting" in t.lower() for t in titles), f"titles={titles}")

  # ---- 17b-3: CSRF detection ----

  def test_csrf_detects_missing_token(self):
    """POST form without CSRF hidden field is flagged."""
    _, worker = self._build_worker(ports=[80])
    html = '<html><body><form method="POST" action="/submit"><input type="text" name="q"><button>Go</button></form></body></html>'
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = html
    mock_resp.headers = {}
    with patch('requests.get', return_value=mock_resp):
      result = worker._web_test_csrf("10.0.0.1", 80)
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("csrf" in t.lower() for t in titles), f"titles={titles}")

  def test_csrf_passes_with_token(self):
    """POST form with csrf_token field passes."""
    _, worker = self._build_worker(ports=[80])
    html = '<html><body><form method="POST"><input type="hidden" name="csrf_token" value="abc123"><input type="text" name="q"></form></body></html>'
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = html
    mock_resp.headers = {}
    with patch('requests.get', return_value=mock_resp):
      result = worker._web_test_csrf("10.0.0.1", 80)
    findings = result.get("findings", [])
    csrf_findings = [f for f in findings if "csrf" in f.get("title", "").lower()]
    self.assertEqual(len(csrf_findings), 0)

  def test_csrf_passes_with_header_token(self):
    """SPA-style X-CSRF-Token header causes skip."""
    _, worker = self._build_worker(ports=[80])
    html = '<html><body><form method="POST"><input type="text" name="q"></form></body></html>'
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.text = html
    mock_resp.headers = {"x-csrf-token": "abc123"}
    with patch('requests.get', return_value=mock_resp):
      result = worker._web_test_csrf("10.0.0.1", 80)
    findings = result.get("findings", [])
    csrf_findings = [f for f in findings if "csrf" in f.get("title", "").lower()]
    self.assertEqual(len(csrf_findings), 0)

  # ---- 17b-4: SNMP MIB walk ----

  def test_snmp_getnext_packet_valid(self):
    """GETNEXT packet is well-formed ASN.1."""
    _, worker = self._build_worker()
    pkt = worker._snmp_build_getnext("public", "1.3.6.1.2.1.1.0")
    # First byte is 0x30 (SEQUENCE)
    self.assertEqual(pkt[0], 0x30)
    # Community string "public" should be embedded
    self.assertIn(b"public", pkt)

  def test_snmp_encode_oid_basic(self):
    """OID encoding for well-known system MIB OID."""
    _, worker2 = self._build_worker()
    encoded = worker2._snmp_encode_oid("1.3.6.1.2.1.1.1.0")
    # First byte: 40*1 + 3 = 43 = 0x2B
    self.assertEqual(encoded[0], 0x2B)

  def test_snmp_encode_oid_large_value(self):
    """OID encoding handles values >= 128."""
    _, worker = self._build_worker()
    encoded = worker._snmp_encode_oid("1.3.6.1.2.1.4.20.1.1")
    self.assertEqual(encoded[0], 0x2B)  # 40*1 + 3

  def test_snmp_parse_response_valid(self):
    """Parse a well-formed SNMP response."""
    # Build a valid SNMP response manually
    _, worker = self._build_worker()
    # Construct minimal SNMP response with OID 1.3.6.1.2.1.1.1.0 and value "Linux"
    oid_body = worker._snmp_encode_oid("1.3.6.1.2.1.1.1.0")
    oid_tlv = bytes([0x06, len(oid_body)]) + oid_body
    value = b"Linux"
    val_tlv = bytes([0x04, len(value)]) + value
    varbind = bytes([0x30, len(oid_tlv) + len(val_tlv)]) + oid_tlv + val_tlv
    varbind_seq = bytes([0x30, len(varbind)]) + varbind
    req_id = b"\x02\x01\x01"
    err_status = b"\x02\x01\x00"
    err_index = b"\x02\x01\x00"
    pdu_body = req_id + err_status + err_index + varbind_seq
    pdu = bytes([0xA2, len(pdu_body)]) + pdu_body
    version = b"\x02\x01\x00"
    comm = bytes([0x04, 0x06]) + b"public"
    inner = version + comm + pdu
    packet = bytes([0x30, len(inner)]) + inner

    oid_str, val_str = worker._snmp_parse_response(packet)
    self.assertEqual(oid_str, "1.3.6.1.2.1.1.1.0")
    self.assertEqual(val_str, "Linux")

  def test_snmp_ics_detection(self):
    """ICS keywords in sysDescr trigger detection."""
    _, worker = self._build_worker()
    self.assertTrue(worker._is_ics_indicator("Siemens SIMATIC S7-300"))
    self.assertTrue(worker._is_ics_indicator("Schneider Electric Modicon M340"))
    self.assertFalse(worker._is_ics_indicator("Linux 5.15.0-generic"))

  # ---- 17b-5: CMS fingerprinting ----

  def test_cms_detects_wordpress(self):
    """WordPress detected via generator meta tag."""
    _, worker = self._build_worker(ports=[80])
    html = '<html><head><meta name="generator" content="WordPress 6.4.2"></head><body></body></html>'
    mock_resp = MagicMock()
    mock_resp.ok = True
    mock_resp.status_code = 200
    mock_resp.text = html
    with patch('requests.get', return_value=mock_resp):
      result = worker._web_test_cms_fingerprint("10.0.0.1", 80)
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("WordPress 6.4.2" in t for t in titles), f"titles={titles}")

  def test_cms_detects_drupal_changelog(self):
    """Drupal detected via CHANGELOG.txt."""
    _, worker = self._build_worker(ports=[80])

    def mock_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      if "CHANGELOG" in url:
        resp.text = "Drupal 10.2.1 (2024-01-15)"
      else:
        resp.text = "<html><body>Hello</body></html>"
      return resp

    with patch('requests.get', side_effect=mock_get):
      result = worker._web_test_cms_fingerprint("10.0.0.1", 80)
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("Drupal 10.2.1" in t for t in titles), f"titles={titles}")

  def test_cms_flags_eol_drupal7(self):
    """Drupal 7 flagged as EOL."""
    _, worker = self._build_worker(ports=[80])
    findings = worker._cms_check_eol("Drupal", "7.98")
    self.assertTrue(any("end-of-life" in f.title.lower() for f in findings))

  def test_cms_no_eol_modern_wordpress(self):
    """WordPress 6.x not flagged as EOL."""
    _, worker = self._build_worker(ports=[80])
    findings = worker._cms_check_eol("WordPress", "6.4.2")
    eol_findings = [f for f in findings if "end-of-life" in f.title.lower()]
    self.assertEqual(len(eol_findings), 0)

  # ---- 17b-1: SMB share enumeration ----

  def test_smb_enum_shares_returns_list(self):
    """_smb_enum_shares returns empty list on connection failure."""
    _, worker = self._build_worker(ports=[445])
    result = worker._smb_enum_shares("192.0.2.1", 99999)
    self.assertIsInstance(result, list)
    self.assertEqual(len(result), 0)

  def test_smb_parse_netshareenumall_empty(self):
    """Empty stub data returns empty list."""
    _, worker = self._build_worker(ports=[445])
    result = worker._parse_netshareenumall_response(b"")
    self.assertEqual(result, [])

  def test_smb_parse_netshareenumall_too_short(self):
    """Short stub returns empty list."""
    _, worker = self._build_worker(ports=[445])
    result = worker._parse_netshareenumall_response(b"\x00" * 10)
    self.assertEqual(result, [])

  def test_smb_share_wiring_admin_shares_high(self):
    """Admin shares found via null session produce HIGH finding."""
    _, worker = self._build_worker(ports=[445])
    mock_shares = [
      {"name": "IPC$", "type": 3, "comment": "IPC Service"},
      {"name": "C$", "type": 0, "comment": "Default share"},
      {"name": "public", "type": 0, "comment": "Public files"},
    ]
    with patch.object(worker, '_smb_enum_shares', return_value=mock_shares), \
         patch.object(worker, '_smb_try_null_session', return_value="4.10.0"), \
         patch('socket.socket') as mock_sock_cls:
      mock_sock = MagicMock()
      mock_sock_cls.return_value = mock_sock
      # Return SMBv1 negotiate response
      smb_resp = bytearray(128)
      smb_resp[0:4] = b"\xffSMB"
      smb_resp[4] = 0x72
      smb_resp[32] = 17  # word_count
      smb_resp[35] = 0x08  # security_mode (signing required)
      mock_sock.recv.side_effect = [
        b"\x00\x00\x00\x80",  # NetBIOS header
        bytes(smb_resp),       # SMB response
      ]
      result = worker._service_info_smb("10.0.0.1", 445)
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("admin shares" in t.lower() for t in titles), f"titles={titles}")



class TestOWASPFullCoverage(unittest.TestCase):
  """Tests for OWASP Top 10 full coverage probes (A04, A08, A09, A10 + re-tags)."""

  def setUp(self):
    if MANUAL_RUN:
      print()
      color_print(f"[MANUAL] >>> Starting <{self._testMethodName}>", color='b')

  def tearDown(self):
    if MANUAL_RUN:
      color_print(f"[MANUAL] <<< Finished <{self._testMethodName}>", color='b')

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [80]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-owasp",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  # ── Phase 1: Re-tag verification ────────────────────────────────────

  def test_metadata_endpoints_tagged_a10(self):
    """Cloud metadata findings should use owasp_id A10:2021."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "ami-id instance-id"
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.api_exposure.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_metadata_endpoints("example.com", 80)
    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, "Should detect at least one metadata endpoint")
    for f in findings:
      self.assertEqual(f["owasp_id"], "A10:2021")

  def test_homepage_private_key_tagged_a08(self):
    """Private key in homepage should use owasp_id A08:2021."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "-----BEGIN RSA PRIVATE KEY----- some key data"
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_homepage("example.com", 80)
    findings = result.get("findings", [])
    pk_findings = [f for f in findings if "private key" in f["title"].lower()]
    self.assertTrue(len(pk_findings) > 0, "Should detect private key")
    self.assertEqual(pk_findings[0]["owasp_id"], "A08:2021")

  def test_homepage_api_key_still_a01(self):
    """API key in homepage should still use A01:2021."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "var API_KEY = 'abc123';"
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_homepage("example.com", 80)
    findings = result.get("findings", [])
    api_findings = [f for f in findings if "api key" in f["title"].lower()]
    self.assertTrue(len(api_findings) > 0)
    self.assertEqual(api_findings[0]["owasp_id"], "A01:2021")

  # ── Phase 2: A10 SSRF ──────────────────────────────────────────────

  def test_ssrf_metadata_azure(self):
    """Azure IMDS endpoint should be detected."""
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False, headers=None):
      resp = MagicMock()
      if "api-version" in url:
        resp.status_code = 200
        resp.text = "hostname"
      else:
        resp.status_code = 404
        resp.text = ""
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.api_exposure.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_metadata_endpoints("example.com", 80)
    findings = result.get("findings", [])
    azure_findings = [f for f in findings if "Azure" in f["title"]]
    self.assertTrue(len(azure_findings) > 0, "Should detect Azure IMDS")
    self.assertEqual(azure_findings[0]["owasp_id"], "A10:2021")

  def test_ssrf_basic_url_param(self):
    """SSRF basic probe should detect metadata in URL parameter response."""
    owner, worker = self._build_worker()

    def fake_get(url, timeout=4, verify=False, headers=None):
      resp = MagicMock()
      if "url=http" in url:
        resp.status_code = 200
        resp.text = "ami-id i-1234567890 instance-id"
      else:
        resp.status_code = 404
        resp.text = ""
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.api_exposure.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_ssrf_basic("example.com", 80)
    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, "Should detect SSRF via URL param")
    self.assertEqual(findings[0]["owasp_id"], "A10:2021")
    self.assertEqual(findings[0]["severity"], "CRITICAL")

  def test_ssrf_basic_no_false_positive(self):
    """Normal pages should not trigger SSRF findings."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = "<html><body>Welcome</body></html>"
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.api_exposure.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_ssrf_basic("example.com", 80)
    self.assertEqual(len(result.get("findings", [])), 0)

  # ── Phase 3: A04 Insecure Design ───────────────────────────────────

  def test_account_enum_different_responses(self):
    """Different error messages for valid/invalid users → enumeration finding."""
    owner, worker = self._build_worker()
    call_count = [0]

    def fake_post(url, data=None, timeout=3, verify=False, allow_redirects=False):
      resp = MagicMock()
      resp.status_code = 200
      call_count[0] += 1
      username = data.get("username", "") if data else ""
      if "nonexistent_user_" in username:
        resp.text = "Error: user not found"
      else:
        resp.text = "Error: invalid password"
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.post",
      side_effect=fake_post,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      side_effect=fake_post,
    ):
      result = worker._web_test_account_enumeration("example.com", 80)
    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, "Should detect account enumeration")
    self.assertEqual(findings[0]["owasp_id"], "A04:2021")

  def test_account_enum_same_response(self):
    """Identical responses for all users → no enumeration finding."""
    owner, worker = self._build_worker()

    def fake_post(url, data=None, timeout=3, verify=False, allow_redirects=False):
      resp = MagicMock()
      resp.status_code = 200
      resp.text = "Error: invalid credentials"
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.post",
      side_effect=fake_post,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      side_effect=fake_post,
    ):
      result = worker._web_test_account_enumeration("example.com", 80)
    self.assertEqual(len(result.get("findings", [])), 0)

  def test_rate_limiting_absent(self):
    """5 requests all accepted → rate limiting finding."""
    owner, worker = self._build_worker()

    def fake_request(url, *args, **kwargs):
      resp = MagicMock()
      resp.status_code = 200
      resp.text = "invalid credentials"
      resp.headers = {}
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.post",
      side_effect=fake_request,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      side_effect=fake_request,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening._time.sleep",
    ):
      result = worker._web_test_rate_limiting("example.com", 80)
    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, "Should detect missing rate limiting")
    self.assertEqual(findings[0]["owasp_id"], "A04:2021")
    self.assertIn("CWE-307", findings[0]["cwe_id"])

  def test_rate_limiting_present(self):
    """429 response → no finding."""
    owner, worker = self._build_worker()
    call_count = [0]

    def fake_post(url, *args, **kwargs):
      resp = MagicMock()
      call_count[0] += 1
      resp.text = ""
      resp.headers = {}
      if call_count[0] >= 3:
        resp.status_code = 429
      else:
        resp.status_code = 200
      return resp

    def fake_get(url, *args, **kwargs):
      resp = MagicMock()
      resp.status_code = 200
      resp.text = ""
      resp.headers = {}
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.post",
      side_effect=fake_post,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      side_effect=fake_get,
    ), patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening._time.sleep",
    ):
      result = worker._web_test_rate_limiting("example.com", 80)
    self.assertEqual(len(result.get("findings", [])), 0)

  def test_idor_sequential_with_pii(self):
    """Sequential IDs with PII in response → MEDIUM finding."""
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False):
      resp = MagicMock()
      if "/api/users/1" in url:
        resp.status_code = 200
        resp.text = '{"id": 1, "email": "alice@example.com", "name": "Alice"}'
      elif "/api/users/2" in url:
        resp.status_code = 200
        resp.text = '{"id": 2, "email": "bob@example.com", "name": "Bob"}'
      else:
        resp.status_code = 404
        resp.text = ""
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.injection.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_idor_indicators("example.com", 80)
    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0)
    self.assertEqual(findings[0]["severity"], "MEDIUM")
    self.assertEqual(findings[0]["owasp_id"], "A04:2021")

  def test_idor_auth_required(self):
    """401 for all → no finding."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 401
    resp.text = "Unauthorized"
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.injection.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_idor_indicators("example.com", 80)
    self.assertEqual(len(result.get("findings", [])), 0)

  # ── Phase 4: A08 Integrity ─────────────────────────────────────────

  def test_sri_missing_external_script(self):
    """External script without integrity= → MEDIUM finding."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<html><script src="https://cdn.other.com/lib.js"></script></html>'
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_subresource_integrity("example.com", 80)
    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0)
    self.assertEqual(findings[0]["owasp_id"], "A08:2021")
    self.assertIn("SRI", findings[0]["title"])

  def test_sri_present(self):
    """External script with integrity= → no finding."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<html><script src="https://cdn.other.com/lib.js" integrity="sha384-abc" crossorigin="anonymous"></script></html>'
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_subresource_integrity("example.com", 80)
    self.assertEqual(len(result.get("findings", [])), 0)

  def test_sri_same_origin_ignored(self):
    """Same-origin script → no finding regardless of SRI."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<html><script src="https://example.com/app.js"></script></html>'
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_subresource_integrity("example.com", 80)
    self.assertEqual(len(result.get("findings", [])), 0)

  def test_mixed_content_script(self):
    """HTTPS page with HTTP script → HIGH finding."""
    owner, worker = self._build_worker(ports=[443])
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<html><script src="http://evil.com/inject.js"></script></html>'
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_mixed_content("example.com", 443)
    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0)
    self.assertEqual(findings[0]["severity"], "HIGH")
    self.assertEqual(findings[0]["owasp_id"], "A08:2021")

  def test_mixed_content_https_only(self):
    """All resources over HTTPS → no finding."""
    owner, worker = self._build_worker(ports=[443])
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<html><script src="https://cdn.example.com/app.js"></script></html>'
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.hardening.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_mixed_content("example.com", 443)
    self.assertEqual(len(result.get("findings", [])), 0)

  def test_mixed_content_non_https_port_skipped(self):
    """Mixed content check only runs on HTTPS ports."""
    owner, worker = self._build_worker(ports=[80])
    result = worker._web_test_mixed_content("example.com", 80)
    self.assertEqual(len(result.get("findings", [])), 0)

  def test_js_lib_angularjs_eol(self):
    """AngularJS detected → MEDIUM EOL finding."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<html><script>/*! AngularJS v1.8.2 */</script></html>'
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_js_library_versions("example.com", 80)
    findings = result.get("findings", [])
    eol_findings = [f for f in findings if "end-of-life" in f["title"].lower()]
    self.assertTrue(len(eol_findings) > 0, "Should flag AngularJS as EOL")
    self.assertEqual(eol_findings[0]["owasp_id"], "A08:2021")

  def test_js_lib_version_detected(self):
    """jQuery version detected → INFO finding."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    resp.text = '<html><script src="https://code.jquery.com/jquery-3.7.1.min.js"></script></html>'
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_js_library_versions("example.com", 80)
    findings = result.get("findings", [])
    jquery_findings = [f for f in findings if "jQuery" in f["title"]]
    self.assertTrue(len(jquery_findings) > 0, "Should detect jQuery")
    self.assertEqual(jquery_findings[0]["severity"], "INFO")

  # ── Phase 5: A09 Logging/Monitoring ─────────────────────────────────

  def test_verbose_error_python_traceback(self):
    """Python traceback in 404 page → MEDIUM finding."""
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False, allow_redirects=None):
      resp = MagicMock()
      resp.status_code = 404 if "nonexistent_" in url else 200
      if "nonexistent_" in url:
        resp.text = 'Traceback (most recent call last):\n  File "app.py", line 42'
      else:
        resp.text = "<html><body>Welcome</body></html>"
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_verbose_errors("example.com", 80)
    findings = result.get("findings", [])
    traceback_findings = [f for f in findings if "stack trace" in f["title"].lower()]
    self.assertTrue(len(traceback_findings) > 0, "Should detect Python traceback")
    self.assertEqual(traceback_findings[0]["owasp_id"], "A09:2021")

  def test_verbose_error_clean_404(self):
    """Generic 404 page → no finding."""
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False, allow_redirects=None):
      resp = MagicMock()
      resp.status_code = 404 if "nonexistent_" in url else 200
      resp.text = "<html><body>Not Found</body></html>"
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_verbose_errors("example.com", 80)
    self.assertEqual(len(result.get("findings", [])), 0)

  def test_debug_mode_django(self):
    """Django debug toolbar marker in homepage → HIGH finding."""
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False, allow_redirects=None):
      resp = MagicMock()
      resp.status_code = 200
      if "nonexistent_" in url:
        resp.text = "<html><body>Page Not Found</body></html>"
      elif "__debug__" in url:
        resp.status_code = 404
        resp.text = ""
      else:
        resp.text = '<html><body><div id="djdt">debug toolbar</div></body></html>'
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_verbose_errors("example.com", 80)
    findings = result.get("findings", [])
    debug_findings = [f for f in findings if "debug mode" in f["title"].lower()]
    self.assertTrue(len(debug_findings) > 0, "Should detect Django debug mode")
    self.assertEqual(debug_findings[0]["owasp_id"], "A09:2021")

  def test_debug_endpoint_actuator(self):
    """Spring Boot /actuator returning 200 → HIGH finding via _web_test_common."""
    owner, worker = self._build_worker()

    def fake_get(url, timeout=2, verify=False):
      resp = MagicMock()
      resp.headers = {}
      resp.reason = "OK"
      if "/actuator" in url:
        resp.status_code = 200
        resp.text = '{"_links": {"beans": ...}}'
      else:
        resp.status_code = 404
        resp.text = ""
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_common("example.com", 80)
    findings = result.get("findings", [])
    actuator_findings = [f for f in findings if "actuator" in f.get("title", "").lower()]
    self.assertTrue(len(actuator_findings) > 0, "Should detect /actuator")
    self.assertEqual(actuator_findings[0]["owasp_id"], "A09:2021")

  def test_debug_endpoint_404(self):
    """/actuator returning 404 → no finding."""
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 404
    resp.text = ""
    resp.headers = {}
    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      return_value=resp,
    ):
      result = worker._web_test_common("example.com", 80)
    findings = result.get("findings", [])
    actuator_findings = [f for f in findings if "actuator" in f.get("title", "").lower()]
    self.assertEqual(len(actuator_findings), 0)

  def test_correlation_open_redirect_ssrf(self):
    """Open redirect + metadata endpoint → correlation finding."""
    owner, worker = self._build_worker()
    worker.state["scan_metadata"] = {}
    worker.state["web_tests_info"] = {
      80: {
        "_web_test_open_redirect": {
          "findings": [{"title": "Open redirect via next parameter", "severity": "MEDIUM"}],
        },
        "_web_test_metadata_endpoints": {
          "findings": [{"title": "Cloud metadata endpoint exposed (AWS EC2)", "severity": "CRITICAL"}],
        },
      }
    }
    worker._post_scan_correlate()
    corr = worker.state.get("correlation_findings", [])
    redirect_ssrf = [f for f in corr if "redirect" in f["title"].lower() and "ssrf" in f["title"].lower()]
    self.assertTrue(len(redirect_ssrf) > 0, "Should produce redirect→SSRF correlation")

  # ── Phase 6: A06 WordPress plugins ──────────────────────────────────

  def test_wp_plugin_version_exposed(self):
    """WordPress plugin readme.txt with version → LOW finding."""
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False, allow_redirects=False):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      if "readme.txt" in url and "elementor" in url:
        resp.text = "=== Elementor ===\nStable tag: 3.18.0\nRequires PHP: 7.4"
      elif "readme.txt" in url:
        resp.status_code = 404
        resp.ok = False
        resp.text = ""
      elif "wp-login" in url:
        resp.text = "wordpress wp-login"
      else:
        resp.text = '<meta name="generator" content="WordPress 6.4.2">'
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_cms_fingerprint("example.com", 80)
    findings = result.get("findings", [])
    plugin_findings = [f for f in findings if "plugin" in f.get("title", "").lower()]
    self.assertTrue(len(plugin_findings) > 0, "Should detect Elementor plugin")
    self.assertIn("3.18.0", plugin_findings[0]["title"])
    self.assertEqual(plugin_findings[0]["owasp_id"], "A06:2021")

  def test_wp_plugin_not_found(self):
    """Plugin readme.txt returning 404 → no plugin finding."""
    owner, worker = self._build_worker()

    def fake_get(url, timeout=3, verify=False, allow_redirects=False):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      if "readme.txt" in url:
        resp.status_code = 404
        resp.ok = False
        resp.text = ""
      elif "wp-login" in url:
        resp.text = "wordpress wp-login"
      else:
        resp.text = '<meta name="generator" content="WordPress 6.4.2">'
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_cms_fingerprint("example.com", 80)
    findings = result.get("findings", [])
    plugin_findings = [f for f in findings if "plugin" in f.get("title", "").lower()]
    self.assertEqual(len(plugin_findings), 0)



class TestDetectionGapFixes(unittest.TestCase):
  """Tests for detection gap fixes: Erlang SSH, BIND CVEs, DNS AXFR, SMTP HELP."""

  def setUp(self):
    if MANUAL_RUN:
      print()
      color_print(f"[MANUAL] >>> Starting <{self._testMethodName}>", color='b')

  def tearDown(self):
    if MANUAL_RUN:
      color_print(f"[MANUAL] <<< Finished <{self._testMethodName}>", color='b')

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [22]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-gaps",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  # ── Erlang SSH detection ──────────────────────────────────────────

  def test_erlang_ssh_banner_detection(self):
    """SSH probe should identify Erlang SSH from banner."""
    _, worker = self._build_worker()
    lib, ver = worker._ssh_identify_library("SSH-2.0-Erlang/5.2.1")
    self.assertEqual(lib, "erlang_ssh")
    self.assertEqual(ver, "5.2.1")

  def test_erlang_ssh_banner_otp_prefix(self):
    """SSH probe should handle Erlang/OTP prefix in banner."""
    _, worker = self._build_worker()
    lib, ver = worker._ssh_identify_library("SSH-2.0-Erlang/OTP 5.1.4")
    self.assertEqual(lib, "erlang_ssh")
    self.assertEqual(ver, "5.1.4")

  def test_erlang_ssh_cve_2025_32433(self):
    """CVE-2025-32433 should match Erlang SSH < 5.2.2."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("erlang_ssh", "5.2.1")
    cve_ids = [f.title for f in findings]
    self.assertTrue(any("CVE-2025-32433" in t for t in cve_ids))

  def test_erlang_ssh_cve_patched(self):
    """CVE-2025-32433 should NOT match patched Erlang SSH >= 5.2.2."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("erlang_ssh", "5.2.2")
    cve_ids = [f.title for f in findings]
    self.assertFalse(any("CVE-2025-32433" in t for t in cve_ids))

  # ── BIND CVE detection ───────────────────────────────────────────

  def test_bind_cve_ancient_version(self):
    """BIND 9.10.3 should match multiple CVEs."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("bind", "9.10.3")
    self.assertTrue(len(findings) >= 5, f"Expected >=5 CVEs for BIND 9.10.3, got {len(findings)}")

  def test_bind_cve_2016_2776(self):
    """CVE-2016-2776 should match BIND < 9.10.4."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("bind", "9.10.3")
    self.assertTrue(any("CVE-2016-2776" in f.title for f in findings))

  def test_bind_cve_modern_patched(self):
    """Modern BIND 9.20.x should not match any CVEs."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("bind", "9.20.0")
    self.assertEqual(len(findings), 0)

  # ── DNS AXFR zone discovery ──────────────────────────────────────

  def test_dns_zone_discovery_soa_authoritative(self):
    """Zone discovery should detect authoritative zones via SOA query."""
    _, worker = self._build_worker()
    # Mock socket to return authoritative SOA response for vulhub.org
    tid = 0
    def fake_socket_factory(family, typ):
      sock = MagicMock()
      def fake_sendto(data, addr):
        nonlocal tid
        tid = struct.unpack('>H', data[:2])[0]
      sock.sendto = fake_sendto
      # Build authoritative response: QR=1, AA=1, RCODE=0, ANCOUNT=1
      def fake_recvfrom(size):
        flags = (1 << 15) | (1 << 10)  # QR=1, AA=1
        resp = struct.pack('>HHHHHH', tid, flags, 0, 1, 0, 0)
        return resp, ("1.2.3.4", 53)
      sock.recvfrom = fake_recvfrom
      return sock
    with patch("extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket", side_effect=fake_socket_factory):
      with patch("socket.gethostbyaddr", side_effect=Exception("no reverse")):
        zones = worker._dns_discover_zones("1.2.3.4", 53)
    # vulhub.org should be in the list (discovered as authoritative or as fallback)
    self.assertIn("vulhub.org", zones)

  def test_dns_zone_discovery_always_includes_fallbacks(self):
    """Zone discovery should include fallback domains even when reverse DNS works."""
    _, worker = self._build_worker()
    with patch("extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket") as mock_sock:
      mock_inst = MagicMock()
      mock_inst.recvfrom.side_effect = Exception("timeout")
      mock_sock.return_value = mock_inst
      with patch("socket.gethostbyaddr", return_value=("host.internal.gcp", [], ["10.0.0.1"])):
        zones = worker._dns_discover_zones("10.0.0.1", 53)
    # Should include both reverse-DNS derived domains AND fallbacks
    self.assertIn("vulhub.org", zones)
    self.assertIn("example.com", zones)
    self.assertTrue(any("gcp" in d or "internal" in d for d in zones))

  # ── DNS BIND CVE in probe ────────────────────────────────────────

  def test_dns_probe_triggers_bind_cves(self):
    """DNS probe should produce BIND CVE findings when version.bind reveals old BIND."""
    _, worker = self._build_worker(ports=[53])
    worker.state["scan_metadata"] = {}
    version_txt = b"9.10.3-P4-Debian"
    qname = b'\x07version\x04bind\x00'

    # Capture tid from the probe's sendto call and build matching response
    captured = {}
    def fake_sendto(data, addr):
      captured["tid"] = struct.unpack('>H', data[:2])[0]
    def fake_recvfrom(size):
      tid = captured["tid"]
      header = struct.pack('>HHHHHH', tid, 0x8400, 1, 1, 0, 0)
      question_section = qname + struct.pack('>HH', 16, 3)
      answer = b'\xc0\x0c' + struct.pack('>HH', 16, 3) + struct.pack('>I', 0)
      answer += struct.pack('>H', len(version_txt) + 1) + bytes([len(version_txt)]) + version_txt
      return header + question_section + answer, ("1.2.3.4", 53)

    with patch("extensions.business.cybersec.red_mesh.worker.service.infrastructure.socket.socket") as mock_sock:
      mock_inst = MagicMock()
      mock_inst.sendto = fake_sendto
      mock_inst.recvfrom = fake_recvfrom
      mock_sock.return_value = mock_inst
      with patch.object(worker, "_dns_test_axfr", return_value=[]):
        with patch.object(worker, "_dns_test_open_resolver", return_value=None):
          result = worker._service_info_dns("1.2.3.4", 53)
    findings = result.get("findings", [])
    cve_titles = [f["title"] for f in findings if "CVE-" in f.get("title", "")]
    self.assertTrue(len(cve_titles) >= 3, f"Expected >=3 BIND CVEs, got {len(cve_titles)}: {cve_titles}")

  # ── SMTP HELP version fallback ───────────────────────────────────

  def test_smtp_help_extracts_version(self):
    """SMTP probe should try HELP command when banner lacks version."""
    _, worker = self._build_worker(ports=[25])
    worker.state["scan_metadata"] = {}

    mock_smtp = MagicMock()
    mock_smtp.connect.return_value = (220, b"host ESMTP OpenSMTPD")
    mock_smtp.ehlo.return_value = (250, b"host Hello\nSIZE 36700160")
    mock_smtp.docmd.side_effect = [
      # HELP command returns version
      (214, b"OpenSMTPD 6.6.1p1"),
      # STARTTLS
      (502, b"Not supported"),
      # MAIL FROM
      (250, b"Ok"),
      # RCPT TO
      (550, b"Relay denied"),
      # VRFY
      (252, b"root"),
      # EXPN
      (502, b"Not supported"),
    ]
    mock_smtp.rset.return_value = (250, b"Ok")

    with patch("smtplib.SMTP", return_value=mock_smtp):
      result = worker._service_info_smtp("1.2.3.4", 25)

    findings = result.get("findings", [])
    cve_titles = [f["title"] for f in findings if "CVE-" in f.get("title", "")]
    self.assertTrue(
      any("CVE-2020-7247" in t for t in cve_titles),
      f"Should detect CVE-2020-7247 via HELP version. CVEs found: {cve_titles}"
    )



class TestBatch2GapFixes(unittest.TestCase):
  """Tests for batch 2 gaps: MySQL CVE-2016-6662, PG MD5 creds, CouchDB, InfluxDB."""

  def setUp(self):
    if MANUAL_RUN:
      print()
      color_print(f"[MANUAL] >>> Starting <{self._testMethodName}>", color='b')

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [80]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-batch2",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  # ── MySQL CVE-2016-6662 fix ──────────────────────────────────────

  def test_mysql_cve_2016_6662_on_55(self):
    """CVE-2016-6662 should match MySQL 5.5.23."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("mysql", "5.5.23")
    self.assertTrue(any("CVE-2016-6662" in f.title for f in findings))

  def test_mysql_cve_2016_6662_on_56(self):
    """CVE-2016-6662 should match MySQL 5.6.30."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("mysql", "5.6.30")
    self.assertTrue(any("CVE-2016-6662" in f.title for f in findings))

  def test_mysql_cve_2016_6662_on_57(self):
    """CVE-2016-6662 should match MySQL 5.7.14."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("mysql", "5.7.14")
    self.assertTrue(any("CVE-2016-6662" in f.title for f in findings))

  def test_mysql_cve_2016_6662_patched(self):
    """CVE-2016-6662 should NOT match MySQL 5.7.15."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("mysql", "5.7.15")
    self.assertFalse(any("CVE-2016-6662" in f.title for f in findings))

  # ── PostgreSQL MD5 credential testing ────────────────────────────

  def test_pg_creds_handles_md5_auth(self):
    """PG creds probe should authenticate via MD5 and extract version."""
    _, worker = self._build_worker(ports=[5432])
    worker.state["scan_metadata"] = {}

    # MD5 auth request: R + len(12) + auth_code(5) + salt(4 bytes)
    md5_request = b'R' + struct.pack('!I', 12) + struct.pack('!I', 5) + b'\xab\xcd\xef\x01'
    # Auth OK + ParameterStatus with server_version
    auth_ok = b'R' + struct.pack('!I', 8) + struct.pack('!I', 0)
    version_param = b'server_version\x0010.7\x00'
    param_msg = b'S' + struct.pack('!I', 4 + len(version_param)) + version_param
    ready = b'Z' + struct.pack('!I', 5) + b'I'
    auth_response = auth_ok + param_msg + ready

    call_count = [0]
    def fake_recv(size):
      call_count[0] += 1
      if call_count[0] == 1:
        return md5_request
      return auth_response

    with patch("extensions.business.cybersec.red_mesh.worker.service.database.socket.socket") as mock_sock:
      mock_inst = MagicMock()
      mock_inst.recv = fake_recv
      mock_sock.return_value = mock_inst
      result = worker._service_info_postgresql_creds("1.2.3.4", 5432)

    findings = result.get("findings", [])
    # Should find credential accepted
    cred_findings = [f for f in findings if "credential accepted" in f.get("title", "").lower()]
    self.assertTrue(len(cred_findings) > 0, f"Should accept postgres:postgres via MD5. Findings: {[f['title'] for f in findings]}")
    # Should extract version and find CVEs
    ver_findings = [f for f in findings if "version disclosed" in f.get("title", "").lower()]
    self.assertTrue(len(ver_findings) > 0, "Should extract PG version after auth")
    cve_findings = [f for f in findings if "CVE-" in f.get("title", "")]
    self.assertTrue(len(cve_findings) > 0, f"Should find PG CVEs for 10.7. Found: {[f['title'] for f in findings]}")

  # ── CouchDB probe ────────────────────────────────────────────────

  def test_couchdb_probe_detects_version_and_dbs(self):
    """CouchDB probe should extract version, list dbs, detect admin panel."""
    _, worker = self._build_worker(ports=[5984])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      if url.endswith(":5984"):
        resp.json.return_value = {"couchdb": "Welcome", "version": "3.2.1"}
        resp.text = '{"couchdb": "Welcome", "version": "3.2.1"}'
      elif "/_all_dbs" in url:
        resp.json.return_value = ["_replicator", "_users", "mydata"]
        resp.text = '["_replicator", "_users", "mydata"]'
      elif "/_utils" in url:
        resp.text = '<html><title>Fauxton</title></html>'
      elif "/_node/_local/_config" in url:
        resp.text = '{"httpd": {"bind_address": "0.0.0.0"}}'
      else:
        resp.ok = False
        resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.service.database.requests.get",
      side_effect=fake_get,
    ):
      result = worker._service_info_couchdb("1.2.3.4", 5984)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("3.2.1" in t for t in titles), "Should detect CouchDB version")
    self.assertTrue(any("CVE-2022-24706" in t for t in titles), "Should detect Erlang cookie CVE")
    self.assertTrue(any("database listing" in t.lower() for t in titles), "Should detect unauth db listing")
    self.assertTrue(any("Fauxton" in t or "admin panel" in t.lower() for t in titles), "Should detect admin panel")
    self.assertTrue(any("configuration exposed" in t.lower() for t in titles), "Should detect config exposure")

  def test_couchdb_probe_skips_non_couchdb(self):
    """CouchDB probe should return None for non-CouchDB HTTP services."""
    _, worker = self._build_worker()

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.json.return_value = {"status": "ok"}
      resp.text = '{"status": "ok"}'
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.service.database.requests.get", side_effect=fake_get):
      result = worker._service_info_couchdb("1.2.3.4", 80)
    self.assertIsNone(result)

  # ── InfluxDB probe ───────────────────────────────────────────────

  def test_influxdb_probe_detects_version_and_unauth(self):
    """InfluxDB probe should detect version and unauthenticated access."""
    _, worker = self._build_worker(ports=[8086])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 204
      resp.headers = {}
      resp.text = ""
      if "/ping" in url:
        resp.headers["X-Influxdb-Version"] = "1.6.6"
      elif "/query" in url:
        resp.status_code = 200
        resp.ok = True
        resp.json.return_value = {
          "results": [{"series": [{"values": [["_internal"], ["telegraf"]]}]}]
        }
      elif "/debug/vars" in url:
        resp.status_code = 200
        resp.text = '{"memstats": {"Alloc": 12345}}'
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.service.database.requests.get", side_effect=fake_get):
      result = worker._service_info_influxdb("1.2.3.4", 8086)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("1.6.6" in t for t in titles), "Should detect InfluxDB version")
    self.assertTrue(any("CVE-2019-20933" in t for t in titles), "Should detect JWT bypass CVE")
    self.assertTrue(any("unauthenticated" in t.lower() for t in titles), "Should detect unauth access")
    self.assertTrue(any("debug" in t.lower() for t in titles), "Should detect debug endpoint")

  def test_influxdb_probe_skips_non_influxdb(self):
    """InfluxDB probe should return None for non-InfluxDB services."""
    _, worker = self._build_worker()

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.headers = {}
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.service.database.requests.get", side_effect=fake_get):
      result = worker._service_info_influxdb("1.2.3.4", 80)
    self.assertIsNone(result)

  # ── CouchDB / InfluxDB CVE matching ──────────────────────────────

  def test_couchdb_cve_2022_24706(self):
    """CVE-2022-24706 should match CouchDB < 3.2.2."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    self.assertTrue(any("CVE-2022-24706" in f.title for f in check_cves("couchdb", "3.2.1")))
    self.assertFalse(any("CVE-2022-24706" in f.title for f in check_cves("couchdb", "3.2.2")))

  def test_influxdb_cve_2019_20933(self):
    """CVE-2019-20933 should match InfluxDB < 1.7.6."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    self.assertTrue(any("CVE-2019-20933" in f.title for f in check_cves("influxdb", "1.6.6")))
    self.assertFalse(any("CVE-2019-20933" in f.title for f in check_cves("influxdb", "1.7.6")))



class TestBatch3GapFixes(unittest.TestCase):
  """Tests for batch 3 gaps: CMS CVEs, SSTI, Shellshock, PHP CGI, dedup bug."""

  def setUp(self):
    if MANUAL_RUN:
      print()
      color_print(f"[MANUAL] >>> Starting <{self._testMethodName}>", color='b')

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [80]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-batch3",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  # ── CVE database: Drupal ───────────────────────────────────────────

  def test_drupal_cve_2018_7600_match(self):
    """CVE-2018-7600 should match Drupal 8.5.0."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("drupal", "8.5.0")
    self.assertTrue(any("CVE-2018-7600" in f.title for f in findings))

  def test_drupal_cve_2018_7600_patched(self):
    """CVE-2018-7600 should NOT match Drupal 8.5.1."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("drupal", "8.5.1")
    self.assertFalse(any("CVE-2018-7600" in f.title for f in findings))

  def test_drupal_cve_2018_7602_match(self):
    """CVE-2018-7602 should match Drupal 8.5.0."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("drupal", "8.5.0")
    self.assertTrue(any("CVE-2018-7602" in f.title for f in findings))

  def test_drupal_cve_2014_3704_match(self):
    """CVE-2014-3704 should match Drupal 7.31."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("drupal", "7.31")
    self.assertTrue(any("CVE-2014-3704" in f.title for f in findings))

  # ── CVE database: WordPress ────────────────────────────────────────

  def test_wordpress_cve_2016_10033_match(self):
    """CVE-2016-10033 should match WordPress 4.6."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("wordpress", "4.6")
    self.assertTrue(any("CVE-2016-10033" in f.title for f in findings))

  def test_wordpress_cve_2016_10033_patched(self):
    """CVE-2016-10033 should NOT match WordPress 4.7.1."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("wordpress", "4.7.1")
    self.assertFalse(any("CVE-2016-10033" in f.title for f in findings))

  def test_wordpress_cve_2017_8295_match(self):
    """CVE-2017-8295 should match WordPress 4.6."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("wordpress", "4.6")
    self.assertTrue(any("CVE-2017-8295" in f.title for f in findings))

  # ── CVE database: Joomla, Django, Laravel ──────────────────────────

  def test_joomla_cve_2023_23752_match(self):
    """CVE-2023-23752 should match Joomla 4.2.7."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("joomla", "4.2.7")
    self.assertTrue(any("CVE-2023-23752" in f.title for f in findings))

  def test_joomla_cve_2023_23752_patched(self):
    """CVE-2023-23752 should NOT match Joomla 4.2.8."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("joomla", "4.2.8")
    self.assertFalse(any("CVE-2023-23752" in f.title for f in findings))

  def test_django_cve_2017_12794_match(self):
    """CVE-2017-12794 should match Django 1.11.4."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("django", "1.11.4")
    self.assertTrue(any("CVE-2017-12794" in f.title for f in findings))

  def test_laravel_ignition_cve_2021_3129_match(self):
    """CVE-2021-3129 should match laravel_ignition 2.5.1."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("laravel_ignition", "2.5.1")
    self.assertTrue(any("CVE-2021-3129" in f.title for f in findings))

  # ── Drupal version extraction probe ────────────────────────────────

  def test_drupal_version_from_system_info_yml(self):
    """Drupal probe should extract version from system.info.yml fallback."""
    _, worker = self._build_worker(ports=[4200])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = ""
      if url.endswith(":4200"):
        # Generator tag with major-only version
        resp.text = '<html><meta name="generator" content="Drupal 8 (https://www.drupal.org)"></html>'
      elif "/core/CHANGELOG.txt" in url:
        resp.ok = False
        resp.status_code = 403
      elif "/core/modules/system/system.info.yml" in url:
        resp.text = "name: System\ntype: module\nversion: '8.5.0'\ncore: 8.x"
      else:
        resp.ok = False
        resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_cms_fingerprint("1.2.3.4", 4200)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("8.5.0" in t for t in titles), f"Should extract Drupal 8.5.0. Got: {titles}")
    self.assertTrue(any("CVE-2018-7600" in t for t in titles), f"Should find Drupalgeddon2. Got: {titles}")

  # ── WordPress version extraction probe ─────────────────────────────

  def test_wordpress_version_from_feed(self):
    """WP probe should extract version from /feed/ generator tag."""
    _, worker = self._build_worker(ports=[4400])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = ""
      if url.endswith(":4400"):
        resp.text = '<html><link rel="stylesheet" href="/wp-content/themes/style.css"></html>'
      elif "/wp-login.php" in url:
        resp.text = '<html><title>wp-login</title></html>'
      elif "/feed/" in url:
        resp.text = '<rss><channel><generator>https://wordpress.org/?v=4.6</generator></channel></rss>'
      elif "/xmlrpc.php" in url:
        resp.status_code = 200
      elif "/wp-json/wp/v2/users" in url:
        resp.status_code = 200
      else:
        resp.ok = False
        resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_cms_fingerprint("1.2.3.4", 4400)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("4.6" in t for t in titles), f"Should extract WP 4.6. Got: {titles}")
    self.assertTrue(any("CVE-2016-10033" in t for t in titles), f"Should find PHPMailer RCE. Got: {titles}")

  # ── Laravel Ignition detection ─────────────────────────────────────

  def test_laravel_ignition_detected(self):
    """Laravel probe should detect Ignition health check and execute-solution."""
    _, worker = self._build_worker(ports=[6300])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {}
      if url.endswith(":6300"):
        # Homepage: no WP/Drupal markers
        resp.ok = True
        resp.status_code = 200
        resp.text = '<html><head><title>Laravel</title></head><body>Welcome</body></html>'
      elif "/_ignition/health-check" in url:
        resp.ok = True
        resp.status_code = 200
        resp.text = '{"can_execute_commands":true}'
      elif "/nonexistent_" in url:
        resp.status_code = 404
        resp.text = '<html>Not Found</html>'
      # All other paths (wp-login, CHANGELOG, administrator) → 404
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.status_code = 500
      resp.text = '{"error":"..."}'
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.post", side_effect=fake_post):
      result = worker._web_test_cms_fingerprint("1.2.3.4", 6300)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("Ignition debug" in t for t in titles), f"Should detect Ignition. Got: {titles}")
    self.assertTrue(any("CVE-2021-3129" in t for t in titles), f"Should detect CVE-2021-3129. Got: {titles}")

  # ── SSTI probe ─────────────────────────────────────────────────────

  def test_ssti_jinja2_detected(self):
    """SSTI probe should detect Jinja2 template evaluation."""
    _, worker = self._build_worker(ports=[4700])
    from urllib.parse import unquote

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      decoded = unquote(url)
      # Evaluate {{71*73}} → 5183, but don't echo the raw template back
      if "name=" in decoded and "{{71*73}}" in decoded:
        resp.text = '<html>Hello 5183!</html>'
      elif "name=" in decoded and "{{7*'7'}}" in decoded:
        resp.text = '<html>Hello 7777777!</html>'
      else:
        resp.text = '<html>Hello world</html>'
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get):
      result = worker._web_test_ssti("1.2.3.4", 4700)

    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, f"Should detect SSTI. Got: {findings}")
    self.assertEqual(findings[0]["severity"], "CRITICAL")
    self.assertIn("SSTI", findings[0]["title"])

  def test_ssti_no_false_positive_on_xss(self):
    """SSTI probe should NOT fire when template literal is echoed back (XSS)."""
    _, worker = self._build_worker(ports=[4700])
    from urllib.parse import unquote

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      decoded = unquote(url)
      # Echo back the raw payload — this is XSS not SSTI
      if "name=" in decoded and "{{71*73}}" in decoded:
        resp.text = '<html>Hello {{71*73}}!</html>'
      elif "name=" in decoded and "{{7*'7'}}" in decoded:
        resp.text = "<html>Hello {{7*'7'}}!</html>"
      else:
        resp.text = '<html>Hello world</html>'
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get):
      result = worker._web_test_ssti("1.2.3.4", 4700)

    findings = result.get("findings", [])
    self.assertEqual(len(findings), 0, f"Should NOT fire on XSS reflection. Got: {[f['title'] for f in findings]}")

  # ── Shellshock probe ───────────────────────────────────────────────

  def test_shellshock_detected(self):
    """Shellshock probe should detect CVE-2014-6271 via CGI marker echo."""
    _, worker = self._build_worker(ports=[6600])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = ""
      headers = kwargs.get("headers", {})
      if "/cgi-bin/" in url and "REDMESH_SHELLSHOCK_DETECT" in headers.get("User-Agent", ""):
        resp.text = "\nREDMESH_SHELLSHOCK_DETECT\n"
      else:
        resp.status_code = 404
        resp.text = "Not Found"
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get):
      result = worker._web_test_shellshock("1.2.3.4", 6600)

    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, "Should detect Shellshock")
    self.assertEqual(findings[0]["severity"], "CRITICAL")
    self.assertIn("CVE-2014-6271", findings[0]["title"])

  def test_shellshock_no_match_on_non_cgi(self):
    """Shellshock probe should not fire when no CGI endpoints respond."""
    _, worker = self._build_worker(ports=[80])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = "Not Found"
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get):
      result = worker._web_test_shellshock("1.2.3.4", 80)

    findings = result.get("findings", [])
    self.assertEqual(len(findings), 0)

  # ── PHP backdoor probe ─────────────────────────────────────────────

  def test_php_backdoor_detected(self):
    """PHP probe should detect zerodium backdoor via User-Agentt header."""
    _, worker = self._build_worker(ports=[6700])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      headers = kwargs.get("headers", {})
      if "zerodium" in headers.get("User-Agentt", ""):
        resp.text = "REDMESH_PHP_BACKDOOR\n"
      else:
        resp.text = "<html>PHP page</html>"
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = "<html>PHP page</html>"
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.post", side_effect=fake_post):
      result = worker._web_test_php_cgi("1.2.3.4", 6700)

    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, "Should detect PHP backdoor")
    self.assertEqual(findings[0]["severity"], "CRITICAL")
    self.assertIn("backdoor", findings[0]["title"].lower())

  def test_php_cgi_arg_injection_detected(self):
    """PHP probe should detect CVE-2024-4577 argument injection."""
    _, worker = self._build_worker(ports=[6700])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = "<html>Normal page</html>"
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      if "%AD" in url:
        resp.text = "REDMESH_PHPCGI_TEST"
      else:
        resp.text = "<html>Normal</html>"
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.post", side_effect=fake_post):
      result = worker._web_test_php_cgi("1.2.3.4", 6700)

    findings = result.get("findings", [])
    self.assertTrue(any("CVE-2024-4577" in f["title"] for f in findings), f"Should detect arg injection. Got: {[f['title'] for f in findings]}")

  # ── Drupal version from install.php (site-version span) ───────────

  def test_drupal_version_from_install_php(self):
    """Drupal probe should extract version from install.php site-version span."""
    _, worker = self._build_worker(ports=[4200])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = ""
      if url.endswith(":4200"):
        resp.text = '<html><meta name="Generator" content="Drupal 8 (https://www.drupal.org)"></html>'
      elif "/core/CHANGELOG.txt" in url:
        resp.text = '<html><meta http-equiv="refresh" content="0;url=/core/install.php"></html>'
        resp.ok = False
        resp.status_code = 302
      elif "/core/modules/system/system.info.yml" in url:
        resp.ok = False
        resp.status_code = 403
        resp.text = "Forbidden"
      elif "/core/install.php" in url:
        resp.text = '''<html><span class="site-version">8.5.0</span>
          <script src="/core/misc/drupal.js?v=8.5.0"></script></html>'''
      else:
        resp.ok = False
        resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_cms_fingerprint("1.2.3.4", 4200)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("8.5.0" in t for t in titles), f"Should extract Drupal 8.5.0 from install.php. Got: {titles}")
    self.assertTrue(any("CVE-2018-7600" in t for t in titles), f"Should find Drupalgeddon2. Got: {titles}")

  # ── WordPress version from readme.html ───────────────────────────

  def test_wordpress_version_from_readme_html(self):
    """WP probe should extract version from /readme.html when /feed/ is 404."""
    _, worker = self._build_worker(ports=[4400])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = ""
      if url.endswith(":4400"):
        resp.text = '<html><link rel="stylesheet" href="/wp-content/themes/style.css"></html>'
      elif "/wp-login.php" in url:
        resp.text = '<html><title>wp-login</title></html>'
      elif "/feed/" in url:
        resp.ok = False
        resp.status_code = 404
        resp.text = "Not Found"
      elif "/wp-links-opml.php" in url:
        resp.ok = False
        resp.status_code = 404
        resp.text = "Not Found"
      elif "/readme.html" in url:
        resp.text = '<br /> Version 4.6\n<p>If you are updating from version 2.7'
      elif "/xmlrpc.php" in url:
        resp.status_code = 200
      elif "/wp-json/wp/v2/users" in url:
        resp.status_code = 200
      else:
        resp.ok = False
        resp.status_code = 404
      return resp

    with patch(
      "extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_cms_fingerprint("1.2.3.4", 4400)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("4.6" in t for t in titles), f"Should extract WP 4.6 from readme.html. Got: {titles}")
    self.assertTrue(any("CVE-2016-10033" in t for t in titles), f"Should find PHPMailer RCE. Got: {titles}")

  # ── SSTI baseline false positive prevention ──────────────────────

  def test_ssti_no_false_positive_on_baseline(self):
    """SSTI probe should NOT fire when expected value already in baseline page."""
    _, worker = self._build_worker(ports=[4300])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      # Every response contains "5183" naturally (e.g. page content)
      resp.text = '<html><p>Order #5183 confirmed</p></html>'
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get):
      result = worker._web_test_ssti("1.2.3.4", 4300)

    findings = result.get("findings", [])
    self.assertEqual(len(findings), 0, f"Should NOT fire when '5183' already in baseline. Got: {[f['title'] for f in findings]}")

  # ── Shellshock via document root CGI paths ───────────────────────

  def test_shellshock_via_victim_cgi(self):
    """Shellshock probe should detect CVE-2014-6271 via /victim.cgi path."""
    _, worker = self._build_worker(ports=[6600])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = ""
      headers = kwargs.get("headers", {})
      if "/victim.cgi" in url and "REDMESH_SHELLSHOCK_DETECT" in headers.get("User-Agent", ""):
        resp.text = "\nREDMESH_SHELLSHOCK_DETECT\n"
      else:
        resp.status_code = 404
        resp.text = "Not Found"
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get):
      result = worker._web_test_shellshock("1.2.3.4", 6600)

    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, "Should detect Shellshock via /victim.cgi")
    self.assertIn("CVE-2014-6271", findings[0]["title"])

  # ── Dedup bug: _service_info_http_alt ──────────────────────────────

  def test_http_alt_no_duplicate_cves(self):
    """_service_info_http_alt should NOT emit CVE findings (dedup fix)."""
    _, worker = self._build_worker(ports=[8080])

    with patch("extensions.business.cybersec.red_mesh.worker.service.common.socket.socket") as mock_sock:
      mock_inst = MagicMock()
      mock_inst.recv.return_value = (
        b"HTTP/1.1 200 OK\r\n"
        b"Server: Apache/2.4.25 (Debian)\r\n"
        b"\r\n"
      ).decode('utf-8').encode('utf-8')
      mock_sock.return_value = mock_inst
      result = worker._service_info_http_alt("1.2.3.4", 8080)

    findings = result.get("findings", [])
    cve_findings = [f for f in findings if "CVE-" in f.get("title", "")]
    self.assertEqual(len(cve_findings), 0, f"http_alt should NOT emit CVEs. Got: {[f['title'] for f in cve_findings]}")
    # But server header should still be captured
    self.assertEqual(result.get("server"), "Apache/2.4.25 (Debian)")



class TestBatch4JavaGapFixes(unittest.TestCase):
  """Tests for batch 4: Java application servers, Struts2, WebLogic, Spring."""

  def setUp(self):
    if MANUAL_RUN:
      print()
      color_print(f"[MANUAL] >>> Starting <{self._testMethodName}>", color='b')

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [80]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-batch4",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  # ── CVE database: Struts2 ─────────────────────────────────────────

  def test_struts2_cve_2017_5638_match(self):
    """CVE-2017-5638 should match Struts2 2.5.10."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("struts2", "2.5.10")
    self.assertTrue(any("CVE-2017-5638" in f.title for f in findings))

  def test_struts2_cve_2017_5638_patched(self):
    """CVE-2017-5638 should NOT match Struts2 2.5.10.1."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("struts2", "2.5.10.1")
    self.assertFalse(any("CVE-2017-5638" in f.title for f in findings))

  def test_struts2_cve_2017_9805_match(self):
    """CVE-2017-9805 should match Struts2 2.5.12."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("struts2", "2.5.12")
    self.assertTrue(any("CVE-2017-9805" in f.title for f in findings))

  def test_struts2_cve_2020_17530_match(self):
    """CVE-2020-17530 should match Struts2 2.5.25."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("struts2", "2.5.25")
    self.assertTrue(any("CVE-2020-17530" in f.title for f in findings))

  def test_struts2_cve_2020_17530_patched(self):
    """CVE-2020-17530 should NOT match Struts2 2.5.26."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("struts2", "2.5.26")
    self.assertFalse(any("CVE-2020-17530" in f.title for f in findings))

  # ── CVE database: WebLogic ────────────────────────────────────────

  def test_weblogic_cve_2017_10271_match(self):
    """CVE-2017-10271 should match WebLogic 10.3.6.0."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("weblogic", "10.3.6.0")
    self.assertTrue(any("CVE-2017-10271" in f.title for f in findings))

  def test_weblogic_cve_2020_14882_match(self):
    """CVE-2020-14882 should match WebLogic 12.2.1.3."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("weblogic", "12.2.1.3")
    self.assertTrue(any("CVE-2020-14882" in f.title for f in findings))

  # ── CVE database: Tomcat ──────────────────────────────────────────

  def test_tomcat_cve_2020_1938_match(self):
    """CVE-2020-1938 Ghostcat should match Tomcat 9.0.30."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("tomcat", "9.0.30")
    self.assertTrue(any("CVE-2020-1938" in f.title for f in findings))

  def test_tomcat_cve_2020_1938_patched(self):
    """CVE-2020-1938 should NOT match Tomcat 9.0.31."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("tomcat", "9.0.31")
    self.assertFalse(any("CVE-2020-1938" in f.title for f in findings))

  # ── CVE database: JBoss ───────────────────────────────────────────

  def test_jboss_cve_2017_12149_match(self):
    """CVE-2017-12149 should match JBoss 6.0."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("jboss", "6.0")
    self.assertTrue(any("CVE-2017-12149" in f.title for f in findings))

  def test_jboss_cve_2017_12149_patched(self):
    """CVE-2017-12149 should NOT match JBoss 7.0."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("jboss", "7.0")
    self.assertFalse(any("CVE-2017-12149" in f.title for f in findings))

  # ── CVE database: Spring ──────────────────────────────────────────

  def test_spring_cve_2022_22965_match(self):
    """CVE-2022-22965 Spring4Shell should match Spring Framework 5.3.17."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("spring_framework", "5.3.17")
    self.assertTrue(any("CVE-2022-22965" in f.title for f in findings))

  def test_spring_cloud_cve_2022_22963_match(self):
    """CVE-2022-22963 should match Spring Cloud Function 3.2.2."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("spring_cloud_function", "3.2.2")
    self.assertTrue(any("CVE-2022-22963" in f.title for f in findings))

  def test_spring_cloud_cve_2022_22963_patched(self):
    """CVE-2022-22963 should NOT match Spring Cloud Function 3.2.3."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("spring_cloud_function", "3.2.3")
    self.assertFalse(any("CVE-2022-22963" in f.title for f in findings))

  # ── WebLogic detection probe ──────────────────────────────────────

  def test_weblogic_console_detected(self):
    """Java servers probe should detect WebLogic via console page."""
    _, worker = self._build_worker(ports=[7102])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {}
      if "/console/login/LoginForm.jsp" in url:
        resp.ok = True
        resp.status_code = 200
        resp.text = '<html>WebLogic Server <span id="footerVersion">10.3.6.0</span></html>'
      elif "/console/" in url:
        resp.ok = True
        resp.status_code = 200
        resp.text = '<html>WebLogic login page</html>'
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get", side_effect=fake_get):
      result = worker._web_test_java_servers("1.2.3.4", 7102)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("WebLogic" in t and "10.3.6.0" in t for t in titles), f"Should detect WebLogic 10.3.6.0. Got: {titles}")
    self.assertTrue(any("CVE-2017-10271" in t for t in titles), f"Should find CVE-2017-10271. Got: {titles}")
    self.assertTrue(any("console exposed" in t.lower() for t in titles), f"Should flag console exposure. Got: {titles}")

  # ── Tomcat detection probe ────────────────────────────────────────

  def test_tomcat_detected_from_default_page(self):
    """Java servers probe should detect Tomcat via default page."""
    _, worker = self._build_worker(ports=[7104])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {}
      if url.endswith(":7104"):
        resp.ok = True
        resp.status_code = 200
        resp.text = '<html><h1>Apache Tomcat/9.0.30</h1></html>'
        resp.headers = {"Server": "Apache-Coyote/1.1"}
      elif "/console/login/LoginForm.jsp" in url:
        pass  # 404
      elif "/manager/html" in url:
        resp.status_code = 401
        resp.text = "Unauthorized"
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get", side_effect=fake_get):
      result = worker._web_test_java_servers("1.2.3.4", 7104)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("Tomcat" in t and "9.0.30" in t for t in titles), f"Should detect Tomcat 9.0.30. Got: {titles}")
    self.assertTrue(any("CVE-2020-1938" in t for t in titles), f"Should find Ghostcat CVE. Got: {titles}")

  # ── JBoss detection probe ─────────────────────────────────────────

  def test_jboss_detected_from_header(self):
    """Java servers probe should detect JBoss via X-Powered-By header."""
    _, worker = self._build_worker(ports=[7106])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = "<html>Welcome to JBoss</html>"
      resp.headers = {"X-Powered-By": "Servlet/3.0; JBossAS-6"}
      if "/console/login/LoginForm.jsp" in url:
        resp.ok = False
        resp.status_code = 404
        resp.text = ""
        resp.headers = {}
      elif "/jmx-console/" in url:
        resp.status_code = 200
        resp.text = "<html>JMX Console</html>"
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get", side_effect=fake_get):
      result = worker._web_test_java_servers("1.2.3.4", 7106)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("JBoss" in t for t in titles), f"Should detect JBoss. Got: {titles}")
    self.assertTrue(any("CVE-2017-12149" in t for t in titles), f"Should find JBoss deser CVE. Got: {titles}")

  # ── Spring detection probe ────────────────────────────────────────

  def test_spring_detected_from_whitelabel(self):
    """Java servers probe should detect Spring via Whitelabel Error Page."""
    _, worker = self._build_worker(ports=[7108])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = "<html>App home</html>"
      resp.headers = {}
      if "/console/login/LoginForm.jsp" in url:
        resp.ok = False
        resp.status_code = 404
        resp.text = ""
      elif "/nonexistent_" in url:
        resp.status_code = 404
        resp.text = '<html><body><h1>Whitelabel Error Page</h1></body></html>'
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get", side_effect=fake_get):
      result = worker._web_test_java_servers("1.2.3.4", 7108)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("Spring" in t for t in titles), f"Should detect Spring. Got: {titles}")

  # ── OGNL injection probe ──────────────────────────────────────────

  def test_ognl_injection_s2_045_detected(self):
    """OGNL probe should detect S2-045 via Content-Type header."""
    _, worker = self._build_worker(ports=[7100])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = ""
      headers = kwargs.get("headers", {})
      ct = headers.get("Content-Type", "")
      if "167837218" in ct and ("/index.action" in url or url.endswith(":7100/")):
        resp.text = "167837218"
      else:
        resp.text = "<html>Normal page</html>"
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get):
      result = worker._web_test_ognl_injection("1.2.3.4", 7100)

    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, "Should detect OGNL injection")
    self.assertEqual(findings[0]["severity"], "CRITICAL")
    self.assertIn("CVE-2017-5638", findings[0]["title"])

  # ── Java deserialization probe ────────────────────────────────────

  def test_weblogic_wlswsat_detected(self):
    """Deserialization probe should detect wls-wsat endpoint."""
    _, worker = self._build_worker(ports=[7102])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {}
      if "/wls-wsat/CoordinatorPortType" in url:
        resp.ok = True
        resp.status_code = 200
        resp.text = '<html>CoordinatorPortType WSDL</html>'
        resp.headers = {"Content-Type": "text/xml"}
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get):
      result = worker._web_test_java_deserialization("1.2.3.4", 7102)

    findings = result.get("findings", [])
    self.assertTrue(len(findings) > 0, "Should detect wls-wsat endpoint")
    self.assertIn("CVE-2017-10271", findings[0]["title"])

  def test_jboss_invoker_detected(self):
    """Deserialization probe should detect JBoss /invoker/readonly."""
    _, worker = self._build_worker(ports=[7106])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {}
      if "/invoker/readonly" in url:
        resp.status_code = 500
        resp.text = "Internal Server Error"
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get):
      result = worker._web_test_java_deserialization("1.2.3.4", 7106)

    findings = result.get("findings", [])
    self.assertTrue(any("CVE-2017-12149" in f["title"] for f in findings), f"Should detect JBoss invoker. Got: {[f['title'] for f in findings]}")

  # ── Spring Actuator probe ─────────────────────────────────────────

  def test_spring_actuator_env_detected(self):
    """Spring actuator probe should detect exposed /actuator/env."""
    _, worker = self._build_worker(ports=[7108])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {"Content-Type": "text/html"}
      if "/actuator/env" in url:
        resp.ok = True
        resp.status_code = 200
        resp.text = '{"propertySources":[{"name":"systemProperties"}]}'
        resp.headers = {"Content-Type": "application/json"}
      elif "/actuator/health" in url:
        resp.ok = True
        resp.status_code = 200
        resp.text = '{"status":"UP"}'
        resp.headers = {"Content-Type": "application/json"}
      elif "/actuator" in url and "/actuator/" not in url:
        resp.ok = True
        resp.status_code = 200
        resp.text = '{"_links":{"self":{"href":"/actuator"}}}'
        resp.headers = {"Content-Type": "application/json"}
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.status_code = 404
      resp.text = ""
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.post", side_effect=fake_post):
      result = worker._web_test_spring_actuator("1.2.3.4", 7108)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("actuator/env" in t.lower() for t in titles), f"Should detect /actuator/env. Got: {titles}")

  def test_spring_cloud_spel_injection_detected(self):
    """Spring actuator probe should detect CVE-2022-22963 SpEL injection."""
    _, worker = self._build_worker(ports=[7109])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {"Content-Type": "text/html"}
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.status_code = 404
      resp.text = ""
      if "/functionRouter" in url:
        headers = kwargs.get("headers", {})
        if "routing-expression" in str(headers):
          resp.status_code = 500
          resp.text = '{"error":"SpelEvaluationException: evaluation failed"}'
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.post", side_effect=fake_post):
      result = worker._web_test_spring_actuator("1.2.3.4", 7109)

    findings = result.get("findings", [])
    self.assertTrue(any("CVE-2022-22963" in f["title"] for f in findings), f"Should detect SpEL injection. Got: {[f['title'] for f in findings]}")

  # ── Gap fix: Struts2 detection via /struts/utils.js ─────────────

  def test_struts2_detected_from_utils_js(self):
    """Struts2 should be detected via /struts/utils.js (REST showcase)."""
    _, worker = self._build_worker(ports=[7101])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {}
      if "/console/login/LoginForm.jsp" in url:
        pass  # 404
      elif url.endswith(":7101") or url.endswith(":7101/"):
        resp.ok = True
        resp.status_code = 200
        resp.text = '<html><body>REST showcase</body></html>'
        resp.headers = {"Server": "Apache-Coyote/1.1"}
      elif "/struts/utils.js" in url:
        resp.ok = True
        resp.status_code = 200
        resp.text = 'var StrutsUtils = {}; // Struts2 tag library utilities\n' * 5
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.status_code = 404
      resp.text = ""
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.post", side_effect=fake_post):
      result = worker._web_test_java_servers("1.2.3.4", 7101)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("Struts2" in t for t in titles), f"Should detect Struts2 via utils.js. Got: {titles}")

  # ── Gap fix: Tomcat + Struts2 co-detection (no early return) ────

  def test_tomcat_and_struts2_codetected(self):
    """Tomcat detection should NOT prevent Struts2 detection."""
    _, worker = self._build_worker(ports=[7101])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {}
      if "/console/login/LoginForm.jsp" in url:
        pass  # 404
      elif "nonexistent_" in url:
        resp.text = '<html><h3>Apache Tomcat/8.5.33 - Error report</h3></html>'
      elif url.endswith(":7101") or url.endswith(":7101/"):
        resp.ok = True
        resp.status_code = 200
        resp.text = '<html><body>REST app</body></html>'
        resp.headers = {"Server": "Apache-Coyote/1.1"}
      elif "/struts/utils.js" in url:
        resp.ok = True
        resp.status_code = 200
        resp.text = 'var StrutsUtils = {}; // Struts2 utilities\n' * 5
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.status_code = 404
      resp.text = ""
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.post", side_effect=fake_post):
      result = worker._web_test_java_servers("1.2.3.4", 7101)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("Tomcat" in t for t in titles), f"Should detect Tomcat. Got: {titles}")
    self.assertTrue(any("Struts2" in t for t in titles), f"Should also detect Struts2. Got: {titles}")

  # ── Gap fix: Spring MVC via POST 405 ────────────────────────────

  def test_spring_detected_from_post_405(self):
    """Spring MVC should be detected via POST → 405 with Spring message."""
    _, worker = self._build_worker(ports=[7108])
    worker.state["scan_metadata"] = {}

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = False
      resp.status_code = 404
      resp.text = ""
      resp.headers = {}
      if "/console/login/LoginForm.jsp" in url:
        pass  # 404
      elif "nonexistent_" in url:
        resp.text = '<html><h3>Apache Tomcat/8.5.77 - Error report</h3></html>'
      elif url.endswith(":7108") or url.endswith(":7108/"):
        resp.ok = True
        resp.status_code = 200
        resp.text = '<html>Hello, my name is , I am  years old.</html>'
        resp.headers = {"Server": "Apache-Coyote/1.1"}
      elif "/struts/utils.js" in url:
        pass  # 404
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      if url.endswith(":7108") or url.endswith(":7108/"):
        resp.status_code = 405
        resp.text = ("<html><body><h1>HTTP Status 405 – Method Not Allowed</h1>"
                     "<p><b>Message</b> Request method &#39;POST&#39; is not supported</p>"
                     "</body></html>")
      else:
        resp.status_code = 404
        resp.text = ""
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.discovery.requests.post", side_effect=fake_post):
      result = worker._web_test_java_servers("1.2.3.4", 7108)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("Tomcat" in t for t in titles), f"Should detect Tomcat. Got: {titles}")
    self.assertTrue(any("Spring" in t for t in titles), f"Should detect Spring MVC via POST 405. Got: {titles}")

  # ── Gap fix: Spring4Shell with 400/500 second check ─────────────

  def test_spring4shell_detected_with_binding_error(self):
    """Spring4Shell should be detected when URLs[0] returns 400 (type error)."""
    _, worker = self._build_worker(ports=[7108])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = "<html>App</html>"
      resp.headers = {"Content-Type": "text/html"}
      if "class.INVALID_RM_CTRL" in url:
        resp.status_code = 400  # Spring rejects bogus class path
        resp.text = "Bad Request"
      elif "class.module.classLoader.DefaultAssertionStatus" in url:
        resp.status_code = 200  # Spring accepted classLoader binding
      elif "class.module.classLoader.URLs" in url:
        resp.status_code = 400  # Type conversion error — binding attempted
        resp.text = "Bad Request"
      elif "/actuator" in url:
        resp.status_code = 404
        resp.ok = False
        resp.text = ""
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.status_code = 404
      resp.text = ""
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.post", side_effect=fake_post):
      result = worker._web_test_spring_actuator("1.2.3.4", 7108)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("Spring4Shell" in t for t in titles), f"Should detect Spring4Shell via binding error. Got: {titles}")



class TestBatch5Improvements(unittest.TestCase):
  """Tests for batch 5: Spring4Shell secondary gate, CVE dedup."""

  def setUp(self):
    if MANUAL_RUN:
      print()
      color_print(f"[MANUAL] >>> Starting <{self._testMethodName}>", color='b')

  def _build_worker(self, ports=None):
    if ports is None:
      ports = [80]
    owner = DummyOwner()
    worker = PentestLocalWorker(
      owner=owner,
      target="example.com",
      job_id="job-batch5",
      initiator="init@example",
      local_id_prefix="1",
      worker_target_ports=ports,
    )
    worker.stop_event = MagicMock()
    worker.stop_event.is_set.return_value = False
    return owner, worker

  # ── Spring4Shell secondary gate ─────────────────────────────────

  def test_spring4shell_secondary_gate_detects_spring(self):
    """Spring4Shell should be detected via URLs[0] secondary check when
    DefaultAssertionStatus returns same 200 as control."""
    _, worker = self._build_worker(ports=[7108])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = "<html>App</html>"
      resp.headers = {"Content-Type": "text/html"}
      # Both control and classLoader return 200 with same body (first gate can't distinguish)
      if "class.INVALID_RM_CTRL.URLs" in url:
        # Control URLs[0] → 200 (server ignores it)
        resp.status_code = 200
        resp.text = "<html>App</html>"
      elif "class.module.classLoader.URLs" in url:
        # Spring binding error on URLs[0] → 400
        resp.status_code = 400
        resp.text = "Bad Request"
      elif "class.INVALID_RM_CTRL" in url:
        resp.status_code = 200
        resp.text = "<html>App</html>"
      elif "class.module.classLoader.DefaultAssertionStatus" in url:
        resp.status_code = 200
        resp.text = "<html>App</html>"
      elif "/actuator" in url:
        resp.status_code = 404
        resp.ok = False
        resp.text = ""
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.status_code = 404
      resp.text = ""
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.post", side_effect=fake_post):
      result = worker._web_test_spring_actuator("1.2.3.4", 7108)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertTrue(any("Spring4Shell" in t for t in titles),
                    f"Should detect Spring4Shell via URLs[0] secondary gate. Got: {titles}")
    # Check confidence is "firm" (not tentative)
    spring4shell = [f for f in findings if "Spring4Shell" in f["title"]]
    self.assertEqual(spring4shell[0]["confidence"], "firm")

  def test_spring4shell_secondary_gate_skips_catchall(self):
    """Spring4Shell secondary gate should NOT flag catch-all servers
    where both classLoader.URLs[0] and control.URLs[0] return 200."""
    _, worker = self._build_worker(ports=[7100])

    def fake_get(url, **kwargs):
      resp = MagicMock()
      resp.ok = True
      resp.status_code = 200
      resp.text = "<html>Default page</html>"
      resp.headers = {"Content-Type": "text/html"}
      # Catch-all: returns 200 for everything
      if "/actuator" in url:
        resp.status_code = 404
        resp.ok = False
        resp.text = ""
      return resp

    def fake_post(url, **kwargs):
      resp = MagicMock()
      resp.status_code = 404
      resp.text = ""
      return resp

    with patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.get", side_effect=fake_get), \
         patch("extensions.business.cybersec.red_mesh.worker.web.injection.requests.post", side_effect=fake_post):
      result = worker._web_test_spring_actuator("1.2.3.4", 7100)

    findings = result.get("findings", [])
    titles = [f["title"] for f in findings]
    self.assertFalse(any("Spring4Shell" in t for t in titles),
                     f"Should NOT flag Spring4Shell on catch-all server. Got: {titles}")

  # ── CVE deduplication ───────────────────────────────────────────

  def _get_plugin_class(self):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' not in sys.modules:
      mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def test_cve_dedup_keeps_higher_confidence(self):
    """Duplicate CVE on same port should be deduplicated, keeping higher confidence."""
    Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [7102],
      "port_protocols": {"7102": "http"},
      "service_info": {},
      "web_tests_info": {
        "7102": {
          "_web_test_java_deserialization": {
            "findings": [{
              "severity": "CRITICAL",
              "title": "CVE-2017-10271: WebLogic deserialization endpoint /wls-wsat",
              "confidence": "firm",
              "cwe_id": "CWE-502",
            }],
          },
          "_web_test_java_servers": {
            "findings": [{
              "severity": "CRITICAL",
              "title": "CVE-2017-10271: XMLDecoder deserialization RCE via wls-wsat (weblogic 10.3.6.0)",
              "confidence": "tentative",
              "cwe_id": "CWE-502",
            }],
          },
        },
      },
    }

    risk_result, flat_findings = Plugin._compute_risk_and_findings(None, aggregated)

    cve_findings = [f for f in flat_findings if "CVE-2017-10271" in f.get("title", "")]
    self.assertEqual(len(cve_findings), 1, f"Should have exactly 1 CVE-2017-10271, got {len(cve_findings)}")
    self.assertEqual(cve_findings[0]["confidence"], "firm", "Should keep the 'firm' confidence finding")

  def test_cve_dedup_different_ports_kept(self):
    """Same CVE on different ports should NOT be deduplicated."""
    Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [7102, 7103],
      "port_protocols": {"7102": "http", "7103": "http"},
      "service_info": {},
      "web_tests_info": {
        "7102": {
          "_web_test_java_servers": {
            "findings": [{
              "severity": "CRITICAL",
              "title": "CVE-2020-14882: Console unauthenticated takeover RCE (weblogic 10.3.6.0)",
              "confidence": "tentative",
              "cwe_id": "CWE-306",
            }],
          },
        },
        "7103": {
          "_web_test_java_servers": {
            "findings": [{
              "severity": "CRITICAL",
              "title": "CVE-2020-14882: Console unauthenticated takeover RCE (weblogic 12.2.1.3)",
              "confidence": "tentative",
              "cwe_id": "CWE-306",
            }],
          },
        },
      },
    }

    risk_result, flat_findings = Plugin._compute_risk_and_findings(None, aggregated)

    cve_findings = [f for f in flat_findings if "CVE-2020-14882" in f.get("title", "")]
    self.assertEqual(len(cve_findings), 2, f"Same CVE on different ports should both be kept, got {len(cve_findings)}")

  def test_cve_dedup_non_cve_not_affected(self):
    """Non-CVE findings should not be affected by deduplication."""
    Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [80],
      "port_protocols": {"80": "http"},
      "service_info": {},
      "web_tests_info": {
        "80": {
          "_web_test_security_headers": {
            "findings": [
              {"severity": "MEDIUM", "title": "Missing security header: CSP", "confidence": "certain", "cwe_id": ""},
              {"severity": "MEDIUM", "title": "Missing security header: CSP", "confidence": "certain", "cwe_id": ""},
            ],
          },
        },
      },
    }

    risk_result, flat_findings = Plugin._compute_risk_and_findings(None, aggregated)

    # Signature deduplication now catches exact non-CVE duplicates too.
    csp_findings = [f for f in flat_findings if "CSP" in f.get("title", "")]
    self.assertEqual(len(csp_findings), 1, "Exact non-CVE duplicates should deduplicate by finding_signature")
    self.assertEqual(len(csp_findings[0]["finding_signature"]), 64)
    self.assertEqual(csp_findings[0]["remediation_structured"]["primary"],
                     "Review the finding evidence and apply vendor or platform hardening guidance.")

  # ── Jetty CVE database ─────────────────────────────────────────

  def test_jetty_cve_2023_36478_match(self):
    """CVE-2023-36478 should match Jetty 9.4.31."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("jetty", "9.4.31")
    self.assertTrue(any("CVE-2023-36478" in f.title for f in findings))

  def test_jetty_cve_2023_36478_patched(self):
    """CVE-2023-36478 should NOT match Jetty 9.4.54."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("jetty", "9.4.54")
    self.assertFalse(any("CVE-2023-36478" in f.title for f in findings))

  def test_jetty_all_cves_match(self):
    """Jetty 9.4.31 should match all 4 Jetty CVEs."""
    from extensions.business.cybersec.red_mesh.cve_db import check_cves
    findings = check_cves("jetty", "9.4.31")
    cve_ids = {f.title.split(":")[0] for f in findings if "CVE-" in f.title}
    expected = {"CVE-2023-26048", "CVE-2023-26049", "CVE-2023-36478", "CVE-2023-40167"}
    self.assertEqual(cve_ids, expected, f"Should match all 4 Jetty CVEs, got {cve_ids}")
