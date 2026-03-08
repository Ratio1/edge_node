import json
import sys
import struct
import unittest
from unittest.mock import MagicMock, patch

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
      "extensions.business.cybersec.red_mesh.web_discovery_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_hardening_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_injection_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_injection_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_hardening_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.service_mixin.requests.get",
      return_value=resp,
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.requests.request",
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
      "extensions.business.cybersec.red_mesh.service_mixin.ftplib.FTP",
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
      "extensions.business.cybersec.red_mesh.service_mixin.ftplib.FTP",
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
      "extensions.business.cybersec.red_mesh.web_discovery_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_discovery_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_injection_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.create_connection",
      return_value=DummyConn(),
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.ssl.SSLContext",
      return_value=DummyContextUnverified(),
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.ssl.create_default_context",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.create_connection",
      return_value=DummyConn(),
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.ssl.SSLContext",
      return_value=DummyContextUnverified(),
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.ssl.create_default_context",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.random.randint",
      return_value=tid,
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.web_api_mixin.requests.post",
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
      "extensions.business.cybersec.red_mesh.web_api_mixin.requests.get",
      side_effect=fake_get,
    ):
      result = worker._web_test_metadata_endpoints("example.com", 80)
    self._assert_has_finding(result, "Cloud metadata endpoint")

  def test_web_api_auth_bypass(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_api_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_hardening_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_hardening_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_hardening_mixin.requests.options",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.web_discovery_mixin.requests.get",
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

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
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

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
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

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
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

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
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

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
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

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
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

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
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

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
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

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.web_discovery_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.ftplib.FTP",
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
      "extensions.business.cybersec.red_mesh.web_discovery_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.service_mixin.paramiko.Transport",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.paramiko.Transport",
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
      "extensions.business.cybersec.red_mesh.service_mixin.paramiko.Transport",
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
      "extensions.business.cybersec.red_mesh.service_mixin.paramiko.Transport",
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
      "extensions.business.cybersec.red_mesh.web_discovery_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_discovery_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_discovery_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.service_mixin.requests.get",
      side_effect=ReqConnError("RemoteDisconnected"),
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.requests.get",
      side_effect=ReqConnError("RemoteDisconnected"),
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
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
      "extensions.business.cybersec.red_mesh.service_mixin.requests.get",
      side_effect=ReqConnError("RemoteDisconnected"),
    ), patch(
      "extensions.business.cybersec.red_mesh.service_mixin.socket.socket",
      return_value=DummySocket([raw_resp, b""]),
    ):
      result = worker._service_info_http("10.0.0.1", 81)
    self.assertIsNotNone(result)
    titles = [f["title"] for f in result.get("findings", [])]
    self.assertTrue(any("directory listing" in t.lower() for t in titles),
                    f"Expected directory listing finding, got: {titles}")
    self.assertEqual(result.get("title"), "Directory listing for /")


class TestPhase1ConfigCID(unittest.TestCase):
  """Phase 1: Job Config CID — extract static config from CStore to R1FS."""

  def test_config_cid_roundtrip(self):
    """JobConfig.from_dict(config.to_dict()) preserves all fields."""
    from extensions.business.cybersec.red_mesh.models import JobConfig

    original = JobConfig(
      target="example.com",
      start_port=1,
      end_port=1024,
      exceptions=[22, 80],
      distribution_strategy="SLICE",
      port_order="SHUFFLE",
      nr_local_workers=4,
      enabled_features=["http_headers", "sql_injection"],
      excluded_features=["brute_force"],
      run_mode="SINGLEPASS",
      scan_min_delay=0.1,
      scan_max_delay=0.5,
      ics_safe_mode=True,
      redact_credentials=False,
      scanner_identity="test-scanner",
      scanner_user_agent="RedMesh/1.0",
      task_name="Test Scan",
      task_description="A test scan",
      monitor_interval=300,
      selected_peers=["peer1", "peer2"],
      created_by_name="tester",
      created_by_id="user-123",
      authorized=True,
    )
    d = original.to_dict()
    restored = JobConfig.from_dict(d)
    self.assertEqual(original, restored)

  def test_config_to_dict_has_required_fields(self):
    """to_dict() includes target, start_port, end_port, run_mode."""
    from extensions.business.cybersec.red_mesh.models import JobConfig

    config = JobConfig(
      target="10.0.0.1",
      start_port=1,
      end_port=65535,
      exceptions=[],
      distribution_strategy="SLICE",
      port_order="SEQUENTIAL",
      nr_local_workers=2,
      enabled_features=[],
      excluded_features=[],
      run_mode="CONTINUOUS_MONITORING",
    )
    d = config.to_dict()
    self.assertEqual(d["target"], "10.0.0.1")
    self.assertEqual(d["start_port"], 1)
    self.assertEqual(d["end_port"], 65535)
    self.assertEqual(d["run_mode"], "CONTINUOUS_MONITORING")

  def test_config_strip_none(self):
    """_strip_none removes None values from serialized config."""
    from extensions.business.cybersec.red_mesh.models import JobConfig

    config = JobConfig(
      target="example.com",
      start_port=1,
      end_port=100,
      exceptions=[],
      distribution_strategy="SLICE",
      port_order="SEQUENTIAL",
      nr_local_workers=2,
      enabled_features=[],
      excluded_features=[],
      run_mode="SINGLEPASS",
      selected_peers=None,
    )
    d = config.to_dict()
    self.assertNotIn("selected_peers", d)

  @classmethod
  def _mock_plugin_modules(cls):
    """Install mock modules so pentester_api_01 can be imported without naeural_core."""
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return  # Already imported successfully

    # Build a real class to avoid metaclass conflicts
    def endpoint_decorator(*args, **kwargs):
      if args and callable(args[0]):
        return args[0]
      def wrapper(fn):
        return fn
      return wrapper

    class FakeBasePlugin:
      CONFIG = {'VALIDATION_RULES': {}}
      endpoint = staticmethod(endpoint_decorator)

    mock_module = MagicMock()
    mock_module.FastApiWebAppPlugin = FakeBasePlugin

    modules_to_mock = {
      'naeural_core': MagicMock(),
      'naeural_core.business': MagicMock(),
      'naeural_core.business.default': MagicMock(),
      'naeural_core.business.default.web_app': MagicMock(),
      'naeural_core.business.default.web_app.fast_api_web_app': mock_module,
    }
    for mod_name, mod in modules_to_mock.items():
      sys.modules.setdefault(mod_name, mod)

  @classmethod
  def _build_mock_plugin(cls, job_id="test-job", time_val=1000000.0, r1fs_cid="QmFakeConfigCID"):
    """Build a mock plugin instance for launch_test testing."""
    plugin = MagicMock()
    plugin.ee_addr = "node-1"
    plugin.ee_id = "node-alias-1"
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_port_order = "SEQUENTIAL"
    plugin.cfg_excluded_features = []
    plugin.cfg_distribution_strategy = "SLICE"
    plugin.cfg_run_mode = "SINGLEPASS"
    plugin.cfg_monitor_interval = 60
    plugin.cfg_scanner_identity = ""
    plugin.cfg_scanner_user_agent = ""
    plugin.cfg_nr_local_workers = 2
    plugin.cfg_llm_agent_api_enabled = False
    plugin.cfg_ics_safe_mode = False
    plugin.cfg_scan_min_rnd_delay = 0
    plugin.cfg_scan_max_rnd_delay = 0
    plugin.uuid.return_value = job_id
    plugin.time.return_value = time_val
    plugin.json_dumps.return_value = "{}"
    plugin.r1fs = MagicMock()
    plugin.r1fs.add_json.return_value = r1fs_cid
    plugin.chainstore_hset = MagicMock()
    plugin.chainstore_hgetall.return_value = {}
    plugin.chainstore_peers = ["node-1"]
    plugin.cfg_chainstore_peers = ["node-1"]
    return plugin

  @classmethod
  def _extract_job_specs(cls, plugin, job_id):
    """Extract the job_specs dict from chainstore_hset calls."""
    for call in plugin.chainstore_hset.call_args_list:
      kwargs = call[1] if call[1] else {}
      if kwargs.get("key") == job_id:
        return kwargs["value"]
    return None

  def _launch(self, plugin, **kwargs):
    """Call launch_test with mocked base modules."""
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    defaults = dict(target="example.com", start_port=1, end_port=1024, exceptions="", authorized=True)
    defaults.update(kwargs)
    return PentesterApi01Plugin.launch_test(plugin, **defaults)

  def test_launch_builds_job_config_and_stores_cid(self):
    """launch_test() builds JobConfig, saves to R1FS, stores job_config_cid in CStore."""
    plugin = self._build_mock_plugin(job_id="test-job-1", r1fs_cid="QmFakeConfigCID123")
    self._launch(plugin)

    # Verify r1fs.add_json was called with a JobConfig dict
    self.assertTrue(plugin.r1fs.add_json.called)
    config_dict = plugin.r1fs.add_json.call_args_list[0][0][0]
    self.assertEqual(config_dict["target"], "example.com")
    self.assertEqual(config_dict["start_port"], 1)
    self.assertEqual(config_dict["end_port"], 1024)
    self.assertIn("run_mode", config_dict)

    # Verify CStore has job_config_cid
    job_specs = self._extract_job_specs(plugin, "test-job-1")
    self.assertIsNotNone(job_specs, "Expected chainstore_hset call for job_specs")
    self.assertEqual(job_specs["job_config_cid"], "QmFakeConfigCID123")

  def test_cstore_has_no_static_config(self):
    """After launch, CStore object has no exceptions, distribution_strategy, etc."""
    plugin = self._build_mock_plugin(job_id="test-job-2")
    self._launch(plugin)

    job_specs = self._extract_job_specs(plugin, "test-job-2")
    self.assertIsNotNone(job_specs)

    # These static config fields must NOT be in CStore
    removed_fields = [
      "exceptions", "distribution_strategy", "enabled_features",
      "excluded_features", "scan_min_delay", "scan_max_delay",
      "ics_safe_mode", "redact_credentials", "scanner_identity",
      "scanner_user_agent", "nr_local_workers", "task_description",
      "monitor_interval", "selected_peers", "created_by_name",
      "created_by_id", "authorized", "port_order",
    ]
    for field in removed_fields:
      self.assertNotIn(field, job_specs, f"CStore should not contain '{field}'")

  def test_cstore_has_listing_fields(self):
    """CStore has target, task_name, start_port, end_port, date_created."""
    plugin = self._build_mock_plugin(job_id="test-job-3", time_val=1700000000.0)
    self._launch(plugin, start_port=80, end_port=443, task_name="Web Scan")

    job_specs = self._extract_job_specs(plugin, "test-job-3")
    self.assertIsNotNone(job_specs)

    self.assertEqual(job_specs["target"], "example.com")
    self.assertEqual(job_specs["task_name"], "Web Scan")
    self.assertEqual(job_specs["start_port"], 80)
    self.assertEqual(job_specs["end_port"], 443)
    self.assertEqual(job_specs["date_created"], 1700000000.0)
    self.assertEqual(job_specs["risk_score"], 0)

  def test_pass_reports_initialized_empty(self):
    """CStore has pass_reports: [] (no pass_history)."""
    plugin = self._build_mock_plugin(job_id="test-job-4")
    self._launch(plugin, start_port=1, end_port=100)

    job_specs = self._extract_job_specs(plugin, "test-job-4")
    self.assertIsNotNone(job_specs)

    self.assertIn("pass_reports", job_specs)
    self.assertEqual(job_specs["pass_reports"], [])
    self.assertNotIn("pass_history", job_specs)

  def test_launch_fails_if_r1fs_unavailable(self):
    """If R1FS fails to store config, launch aborts with error."""
    plugin = self._build_mock_plugin(job_id="test-job-5", r1fs_cid=None)
    result = self._launch(plugin, start_port=1, end_port=100)

    self.assertIn("error", result)
    # CStore should NOT have been written with the job
    job_specs = self._extract_job_specs(plugin, "test-job-5")
    self.assertIsNone(job_specs)


class TestPhase2PassFinalization(unittest.TestCase):
  """Phase 2: Single Aggregation + Consolidated Pass Reports."""

  @classmethod
  def _mock_plugin_modules(cls):
    """Install mock modules so pentester_api_01 can be imported without naeural_core."""
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    TestPhase1ConfigCID._mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _build_finalize_plugin(self, job_id="test-job", job_pass=1, run_mode="SINGLEPASS",
                              llm_enabled=False, r1fs_returns=None):
    """Build a mock plugin pre-configured for _maybe_finalize_pass testing."""
    plugin = MagicMock()
    plugin.ee_addr = "launcher-node"
    plugin.ee_id = "launcher-alias"
    plugin.cfg_instance_id = "test-instance"
    plugin.cfg_llm_agent_api_enabled = llm_enabled
    plugin.cfg_llm_agent_api_host = "localhost"
    plugin.cfg_llm_agent_api_port = 8080
    plugin.cfg_llm_agent_api_timeout = 30
    plugin.cfg_llm_auto_analysis_type = "security_assessment"
    plugin.cfg_monitor_interval = 60
    plugin.cfg_monitor_jitter = 0
    plugin.cfg_attestation_min_seconds_between_submits = 300
    plugin.time.return_value = 1000100.0
    plugin.json_dumps.return_value = "{}"

    # R1FS mock
    plugin.r1fs = MagicMock()
    cid_counter = {"n": 0}
    def fake_add_json(data, show_logs=True):
      cid_counter["n"] += 1
      if r1fs_returns is not None:
        return r1fs_returns.get(cid_counter["n"], f"QmCID{cid_counter['n']}")
      return f"QmCID{cid_counter['n']}"
    plugin.r1fs.add_json.side_effect = fake_add_json

    # Job config in R1FS
    plugin.r1fs.get_json.return_value = {
      "target": "example.com", "start_port": 1, "end_port": 1024,
      "run_mode": run_mode, "enabled_features": [], "monitor_interval": 60,
    }

    # Build job_specs with two finished workers
    job_specs = {
      "job_id": job_id,
      "job_status": "RUNNING",
      "job_pass": job_pass,
      "run_mode": run_mode,
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "task_name": "Test",
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "risk_score": 0,
      "job_config_cid": "QmConfigCID",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 512, "finished": True, "report_cid": "QmReportA"},
        "worker-B": {"start_port": 513, "end_port": 1024, "finished": True, "report_cid": "QmReportB"},
      },
      "timeline": [{"type": "created", "label": "Created", "date": 1000000.0, "actor": "launcher-alias", "actor_type": "system", "meta": {}}],
      "pass_reports": [],
    }

    plugin.chainstore_hgetall.return_value = {job_id: job_specs}
    plugin.chainstore_hset = MagicMock()

    return plugin, job_specs

  def _sample_node_report(self, start_port=1, end_port=512, open_ports=None, findings=None):
    """Build a sample node report dict."""
    report = {
      "start_port": start_port,
      "end_port": end_port,
      "open_ports": open_ports or [80, 443],
      "ports_scanned": end_port - start_port + 1,
      "nr_open_ports": len(open_ports or [80, 443]),
      "service_info": {},
      "web_tests_info": {},
      "completed_tests": ["port_scan"],
      "port_protocols": {"80": "http", "443": "https"},
      "port_banners": {},
      "correlation_findings": [],
    }
    if findings:
      # Add findings under service_info for port 80
      report["service_info"] = {
        "80": {
          "_service_info_http": {
            "findings": findings,
          }
        }
      }
    return report

  def test_single_aggregation(self):
    """_collect_node_reports called exactly once per pass finalization."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    # Mock _collect_node_reports and _get_aggregated_report
    report_a = self._sample_node_report(1, 512, [80])
    report_b = self._sample_node_report(513, 1024, [443])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a, "worker-B": report_b})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80, 443], "service_info": {}, "web_tests_info": {},
      "completed_tests": ["port_scan"], "ports_scanned": 1024,
      "nr_open_ports": 2, "port_protocols": {"80": "http", "443": "https"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com", "monitor_interval": 60})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 25, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # _collect_node_reports called exactly once
    plugin._collect_node_reports.assert_called_once()

  def test_pass_report_cid_in_r1fs(self):
    """PassReport stored in R1FS with correct fields."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {"findings_score": 5}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # r1fs.add_json called twice: once for aggregated data, once for PassReport
    self.assertEqual(plugin.r1fs.add_json.call_count, 2)

    # Second call is the PassReport
    pass_report_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertEqual(pass_report_dict["pass_nr"], 1)
    self.assertIn("aggregated_report_cid", pass_report_dict)
    self.assertIn("worker_reports", pass_report_dict)
    self.assertEqual(pass_report_dict["risk_score"], 10)
    self.assertIn("risk_breakdown", pass_report_dict)
    self.assertIn("date_started", pass_report_dict)
    self.assertIn("date_completed", pass_report_dict)

  def test_aggregated_report_separate_cid(self):
    """aggregated_report_cid is a separate R1FS write from the PassReport."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(r1fs_returns={1: "QmAggCID", 2: "QmPassCID"})

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # First R1FS write = aggregated data, second = PassReport
    agg_dict = plugin.r1fs.add_json.call_args_list[0][0][0]
    pass_dict = plugin.r1fs.add_json.call_args_list[1][0][0]

    # The PassReport references the aggregated CID
    self.assertEqual(pass_dict["aggregated_report_cid"], "QmAggCID")

    # Aggregated data should have open_ports (from AggregatedScanData)
    self.assertIn("open_ports", agg_dict)

  def test_finding_id_deterministic(self):
    """Same input produces same finding_id; different title produces different id."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [80], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
      "service_info": {
        "80": {
          "_service_info_http": {
            "findings": [
              {"title": "SQL Injection", "severity": "HIGH", "cwe_id": "CWE-89", "confidence": "firm"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    risk1, findings1 = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    risk2, findings2 = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)

    self.assertEqual(findings1[0]["finding_id"], findings2[0]["finding_id"])

    # Different title → different finding_id
    aggregated2 = {
      "open_ports": [80], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
      "service_info": {
        "80": {
          "_service_info_http": {
            "findings": [
              {"title": "XSS Vulnerability", "severity": "HIGH", "cwe_id": "CWE-79", "confidence": "firm"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }
    _, findings3 = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated2)
    self.assertNotEqual(findings1[0]["finding_id"], findings3[0]["finding_id"])

  def test_finding_id_cwe_collision(self):
    """Same CWE, different title, same port+probe → different finding_ids."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [80], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"80": "http"},
      "service_info": {
        "80": {
          "_web_test_xss": {
            "findings": [
              {"title": "Reflected XSS in search", "severity": "HIGH", "cwe_id": "CWE-79", "confidence": "certain"},
              {"title": "Stored XSS in comment", "severity": "HIGH", "cwe_id": "CWE-79", "confidence": "certain"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    _, findings = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    self.assertEqual(len(findings), 2)
    self.assertNotEqual(findings[0]["finding_id"], findings[1]["finding_id"])

  def test_finding_enrichment_fields(self):
    """Each finding has finding_id, port, protocol, probe, category."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [443], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": {"443": "https"},
      "service_info": {
        "443": {
          "_service_info_ssl": {
            "findings": [
              {"title": "Weak TLS", "severity": "MEDIUM", "cwe_id": "CWE-326", "confidence": "certain"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    _, findings = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    self.assertEqual(len(findings), 1)
    f = findings[0]
    self.assertIn("finding_id", f)
    self.assertEqual(len(f["finding_id"]), 16)  # 16-char hex
    self.assertEqual(f["port"], 443)
    self.assertEqual(f["protocol"], "https")
    self.assertEqual(f["probe"], "_service_info_ssl")
    self.assertEqual(f["category"], "service")

  def test_port_protocols_none(self):
    """port_protocols is None → protocol defaults to 'unknown' (no crash)."""
    PentesterApi01Plugin = self._get_plugin_class()

    aggregated = {
      "open_ports": [22], "ports_scanned": 100, "nr_open_ports": 1,
      "port_protocols": None,
      "service_info": {
        "22": {
          "_service_info_ssh": {
            "findings": [
              {"title": "Weak SSH key", "severity": "LOW", "cwe_id": "CWE-320", "confidence": "firm"},
            ]
          }
        }
      },
      "web_tests_info": {},
      "correlation_findings": [],
    }

    _, findings = PentesterApi01Plugin._compute_risk_and_findings(None, aggregated)
    self.assertEqual(len(findings), 1)
    self.assertEqual(findings[0]["protocol"], "unknown")

  def test_llm_success_no_llm_failed(self):
    """LLM succeeds → llm_failed absent from serialized PassReport."""
    from extensions.business.cybersec.red_mesh.models import PassReport

    pr = PassReport(
      pass_nr=1, date_started=1000.0, date_completed=1100.0, duration=100.0,
      aggregated_report_cid="QmAgg",
      worker_reports={},
      risk_score=50,
      llm_analysis="# Analysis\nAll good.",
      quick_summary="No critical issues found.",
      llm_failed=None,  # success
    )
    d = pr.to_dict()
    self.assertNotIn("llm_failed", d)
    self.assertEqual(d["llm_analysis"], "# Analysis\nAll good.")

  def test_llm_failure_flag_and_timeline(self):
    """LLM fails → llm_failed: True, timeline event added."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin(llm_enabled=True)

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 10, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    # LLM returns None (failure)
    plugin._run_aggregated_llm_analysis = MagicMock(return_value=None)
    plugin._run_quick_summary_analysis = MagicMock(return_value=None)

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # Check PassReport has llm_failed=True
    pass_report_dict = plugin.r1fs.add_json.call_args_list[1][0][0]
    self.assertTrue(pass_report_dict.get("llm_failed"))

    # Check timeline event was emitted for llm_failed
    llm_failed_calls = [
      c for c in plugin._emit_timeline_event.call_args_list
      if c[0][1] == "llm_failed"
    ]
    self.assertEqual(len(llm_failed_calls), 1)
    # _emit_timeline_event(job_specs, "llm_failed", label, meta={"pass_nr": ...})
    call_kwargs = llm_failed_calls[0][1]  # keyword args
    meta = call_kwargs.get("meta", {})
    self.assertIn("pass_nr", meta)

  def test_aggregated_report_write_failure(self):
    """R1FS fails for aggregated → pass finalization skipped, no partial state."""
    PentesterApi01Plugin = self._get_plugin_class()
    # First R1FS write (aggregated) returns None = failure
    plugin, job_specs = self._build_finalize_plugin(r1fs_returns={1: None, 2: "QmPassCID"})

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # CStore should NOT have pass_reports appended
    self.assertEqual(len(job_specs["pass_reports"]), 0)
    # CStore hset should NOT have been called for finalization
    plugin.chainstore_hset.assert_not_called()

  def test_pass_report_write_failure(self):
    """R1FS fails for pass report → CStore pass_reports not appended."""
    PentesterApi01Plugin = self._get_plugin_class()
    # First R1FS write (aggregated) succeeds, second (pass report) fails
    plugin, job_specs = self._build_finalize_plugin(r1fs_returns={1: "QmAggCID", 2: None})

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 0, "breakdown": {}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # CStore should NOT have pass_reports appended
    self.assertEqual(len(job_specs["pass_reports"]), 0)
    # CStore hset should NOT have been called for finalization
    plugin.chainstore_hset.assert_not_called()

  def test_cstore_risk_score_updated(self):
    """After pass, risk_score on CStore matches pass result."""
    PentesterApi01Plugin = self._get_plugin_class()
    plugin, job_specs = self._build_finalize_plugin()

    report_a = self._sample_node_report(1, 512, [80])
    plugin._collect_node_reports = MagicMock(return_value={"worker-A": report_a})
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "completed_tests": [], "ports_scanned": 512, "nr_open_ports": 1,
      "port_protocols": {},
    })
    plugin._normalize_job_record = MagicMock(return_value=(job_specs["job_id"], job_specs))
    plugin._get_job_config = MagicMock(return_value={"target": "example.com"})
    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 42, "breakdown": {"findings_score": 30}}, []))
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._get_timeline_date = MagicMock(return_value=1000000.0)
    plugin._emit_timeline_event = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # CStore risk_score updated
    self.assertEqual(job_specs["risk_score"], 42)

    # PassReportRef in pass_reports has same risk_score
    self.assertEqual(len(job_specs["pass_reports"]), 1)
    ref = job_specs["pass_reports"][0]
    self.assertEqual(ref["risk_score"], 42)
    self.assertIn("report_cid", ref)
    self.assertEqual(ref["pass_nr"], 1)


class TestPhase4UiAggregate(unittest.TestCase):
  """Phase 4: UI Aggregate Computation."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    TestPhase1ConfigCID._mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _make_plugin(self):
    plugin = MagicMock()
    Plugin = self._get_plugin_class()
    plugin._count_services = lambda si: Plugin._count_services(plugin, si)
    plugin._compute_ui_aggregate = lambda passes, agg: Plugin._compute_ui_aggregate(plugin, passes, agg)
    plugin.SEVERITY_ORDER = Plugin.SEVERITY_ORDER
    plugin.CONFIDENCE_ORDER = Plugin.CONFIDENCE_ORDER
    return plugin, Plugin

  def _make_finding(self, severity="HIGH", confidence="firm", finding_id="abc123", title="Test"):
    return {"finding_id": finding_id, "severity": severity, "confidence": confidence, "title": title}

  def _make_pass(self, pass_nr=1, findings=None, risk_score=0, worker_reports=None):
    return {
      "pass_nr": pass_nr,
      "risk_score": risk_score,
      "risk_breakdown": {"findings_score": 10},
      "quick_summary": "Summary text",
      "findings": findings,
      "worker_reports": worker_reports or {
        "w1": {"start_port": 1, "end_port": 512, "open_ports": [80]},
      },
    }

  def _make_aggregated(self, open_ports=None, service_info=None):
    return {
      "open_ports": open_ports or [80, 443],
      "service_info": service_info or {
        "80": {"_service_info_http": {"findings": []}},
        "443": {"_service_info_https": {"findings": []}},
      },
    }

  def test_findings_count_uppercase_keys(self):
    """findings_count keys are UPPERCASE."""
    plugin, _ = self._make_plugin()
    findings = [
      self._make_finding(severity="CRITICAL", finding_id="f1"),
      self._make_finding(severity="HIGH", finding_id="f2"),
      self._make_finding(severity="HIGH", finding_id="f3"),
      self._make_finding(severity="MEDIUM", finding_id="f4"),
    ]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    fc = result.to_dict()["findings_count"]
    self.assertEqual(fc["CRITICAL"], 1)
    self.assertEqual(fc["HIGH"], 2)
    self.assertEqual(fc["MEDIUM"], 1)
    for key in fc:
      self.assertEqual(key, key.upper())

  def test_top_findings_max_10(self):
    """More than 10 CRITICAL+HIGH -> capped at 10."""
    plugin, _ = self._make_plugin()
    findings = [self._make_finding(severity="CRITICAL", finding_id=f"f{i}") for i in range(15)]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    self.assertEqual(len(result.to_dict()["top_findings"]), 10)

  def test_top_findings_sorted(self):
    """CRITICAL before HIGH, within same severity sorted by confidence."""
    plugin, _ = self._make_plugin()
    findings = [
      self._make_finding(severity="HIGH", confidence="certain", finding_id="f1", title="H-certain"),
      self._make_finding(severity="CRITICAL", confidence="tentative", finding_id="f2", title="C-tentative"),
      self._make_finding(severity="HIGH", confidence="tentative", finding_id="f3", title="H-tentative"),
      self._make_finding(severity="CRITICAL", confidence="certain", finding_id="f4", title="C-certain"),
    ]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    top = result.to_dict()["top_findings"]
    self.assertEqual(top[0]["title"], "C-certain")
    self.assertEqual(top[1]["title"], "C-tentative")
    self.assertEqual(top[2]["title"], "H-certain")
    self.assertEqual(top[3]["title"], "H-tentative")

  def test_top_findings_excludes_medium(self):
    """MEDIUM/LOW/INFO findings never in top_findings."""
    plugin, _ = self._make_plugin()
    findings = [
      self._make_finding(severity="MEDIUM", finding_id="f1"),
      self._make_finding(severity="LOW", finding_id="f2"),
      self._make_finding(severity="INFO", finding_id="f3"),
    ]
    p = self._make_pass(findings=findings)
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    d = result.to_dict()
    self.assertNotIn("top_findings", d)  # stripped by _strip_none (None)

  def test_finding_timeline_single_pass(self):
    """1 pass -> finding_timeline is None (stripped)."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(findings=[])
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    d = result.to_dict()
    self.assertNotIn("finding_timeline", d)  # None → stripped

  def test_finding_timeline_multi_pass(self):
    """3 passes with overlapping findings -> correct first_seen, last_seen, pass_count."""
    plugin, _ = self._make_plugin()
    f_persistent = self._make_finding(finding_id="persist1")
    f_transient = self._make_finding(finding_id="transient1")
    f_new = self._make_finding(finding_id="new1")
    passes = [
      self._make_pass(pass_nr=1, findings=[f_persistent, f_transient]),
      self._make_pass(pass_nr=2, findings=[f_persistent]),
      self._make_pass(pass_nr=3, findings=[f_persistent, f_new]),
    ]
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate(passes, agg)
    ft = result.to_dict()["finding_timeline"]
    self.assertEqual(ft["persist1"]["first_seen"], 1)
    self.assertEqual(ft["persist1"]["last_seen"], 3)
    self.assertEqual(ft["persist1"]["pass_count"], 3)
    self.assertEqual(ft["transient1"]["first_seen"], 1)
    self.assertEqual(ft["transient1"]["last_seen"], 1)
    self.assertEqual(ft["transient1"]["pass_count"], 1)
    self.assertEqual(ft["new1"]["first_seen"], 3)
    self.assertEqual(ft["new1"]["last_seen"], 3)
    self.assertEqual(ft["new1"]["pass_count"], 1)

  def test_zero_findings(self):
    """findings_count is {}, top_findings is [], total_findings is 0."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(findings=[])
    agg = self._make_aggregated()
    result = plugin._compute_ui_aggregate([p], agg)
    d = result.to_dict()
    self.assertEqual(d["total_findings"], 0)
    # findings_count and top_findings are None (stripped) when empty
    self.assertNotIn("findings_count", d)
    self.assertNotIn("top_findings", d)

  def test_open_ports_sorted_unique(self):
    """total_open_ports is deduped and sorted."""
    plugin, _ = self._make_plugin()
    p = self._make_pass(findings=[])
    agg = self._make_aggregated(open_ports=[443, 80, 443, 22, 80])
    result = plugin._compute_ui_aggregate([p], agg)
    self.assertEqual(result.to_dict()["total_open_ports"], [22, 80, 443])

  def test_count_services(self):
    """_count_services counts unique probe names across ports."""
    plugin, _ = self._make_plugin()
    service_info = {
      "80": {"_service_info_http": {}, "_web_test_xss": {}},
      "443": {"_service_info_https": {}, "_service_info_http": {}},
    }
    self.assertEqual(plugin._count_services(service_info), 3)
    self.assertEqual(plugin._count_services({}), 0)
    self.assertEqual(plugin._count_services(None), 0)


class TestPhase3Archive(unittest.TestCase):
  """Phase 3: Job Close & Archive."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    TestPhase1ConfigCID._mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _build_archive_plugin(self, job_id="test-job", pass_count=1, run_mode="SINGLEPASS",
                              job_status="FINALIZED", r1fs_write_fail=False, r1fs_verify_fail=False):
    """Build a mock plugin pre-configured for _build_job_archive testing."""
    plugin = MagicMock()
    plugin.ee_addr = "launcher-node"
    plugin.ee_id = "launcher-alias"
    plugin.cfg_instance_id = "test-instance"
    plugin.time.return_value = 1000200.0
    plugin.json_dumps.return_value = "{}"

    # R1FS mock
    plugin.r1fs = MagicMock()

    # Build pass report dicts and refs
    pass_reports_data = []
    pass_report_refs = []
    for i in range(1, pass_count + 1):
      pr = {
        "pass_nr": i,
        "date_started": 1000000.0 + (i - 1) * 100,
        "date_completed": 1000000.0 + i * 100,
        "duration": 100.0,
        "aggregated_report_cid": f"QmAgg{i}",
        "worker_reports": {
          "worker-A": {"report_cid": f"QmWorker{i}A", "start_port": 1, "end_port": 512, "ports_scanned": 512, "open_ports": [80], "nr_findings": 2},
        },
        "risk_score": 25 + i,
        "risk_breakdown": {"findings_score": 10},
        "findings": [
          {"finding_id": f"f{i}a", "severity": "HIGH", "confidence": "firm", "title": f"Finding {i}A"},
          {"finding_id": f"f{i}b", "severity": "MEDIUM", "confidence": "firm", "title": f"Finding {i}B"},
        ],
        "quick_summary": f"Summary for pass {i}",
      }
      pass_reports_data.append(pr)
      pass_report_refs.append({"pass_nr": i, "report_cid": f"QmPassReport{i}", "risk_score": 25 + i})

    # Job config
    job_config = {
      "target": "example.com", "start_port": 1, "end_port": 1024,
      "run_mode": run_mode, "enabled_features": [],
    }

    # Latest aggregated data
    latest_aggregated = {
      "open_ports": [80, 443], "service_info": {"80": {"_service_info_http": {}}},
      "web_tests_info": {}, "completed_tests": ["port_scan"], "ports_scanned": 1024,
    }

    # R1FS get_json: return the right data for each CID
    cid_map = {"QmConfigCID": job_config}
    for i, pr in enumerate(pass_reports_data):
      cid_map[f"QmPassReport{i+1}"] = pr
      cid_map[f"QmAgg{i+1}"] = latest_aggregated

    if r1fs_write_fail:
      plugin.r1fs.add_json.return_value = None
    else:
      archive_cid = "QmArchiveCID"
      plugin.r1fs.add_json.return_value = archive_cid
      if r1fs_verify_fail:
        # add_json succeeds but get_json for the archive CID returns None
        orig_map = dict(cid_map)
        def verify_fail_get(cid):
          if cid == archive_cid:
            return None
          return orig_map.get(cid)
        plugin.r1fs.get_json.side_effect = verify_fail_get
      else:
        # Verification succeeds — archive CID also returns data
        cid_map[archive_cid] = {"job_id": job_id}  # minimal archive for verification
        plugin.r1fs.get_json.side_effect = lambda cid: cid_map.get(cid)

    if not r1fs_write_fail and not r1fs_verify_fail:
      plugin.r1fs.get_json.side_effect = lambda cid: cid_map.get(cid)

    # Job specs (running state)
    job_specs = {
      "job_id": job_id,
      "job_status": job_status,
      "job_pass": pass_count,
      "run_mode": run_mode,
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "task_name": "Test",
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "risk_score": 25 + pass_count,
      "job_config_cid": "QmConfigCID",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 512, "finished": True, "report_cid": "QmReportA"},
      },
      "timeline": [
        {"type": "created", "label": "Created", "date": 1000000.0, "actor": "launcher-alias", "actor_type": "system", "meta": {}},
      ],
      "pass_reports": pass_report_refs,
    }

    plugin.chainstore_hset = MagicMock()

    # Bind real methods for archive building
    Plugin = self._get_plugin_class()
    plugin._compute_ui_aggregate = lambda passes, agg: Plugin._compute_ui_aggregate(plugin, passes, agg)
    plugin._count_services = lambda si: Plugin._count_services(plugin, si)
    plugin.SEVERITY_ORDER = Plugin.SEVERITY_ORDER
    plugin.CONFIDENCE_ORDER = Plugin.CONFIDENCE_ORDER

    return plugin, job_specs, pass_reports_data, job_config

  def test_archive_written_to_r1fs(self):
    """Archive stored in R1FS with job_id, job_config, passes, ui_aggregate."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, job_config = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # r1fs.add_json called with archive dict
    self.assertTrue(plugin.r1fs.add_json.called)
    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    self.assertEqual(archive_dict["job_id"], "test-job")
    self.assertEqual(archive_dict["job_config"]["target"], "example.com")
    self.assertEqual(len(archive_dict["passes"]), 1)
    self.assertIn("ui_aggregate", archive_dict)
    self.assertIn("total_open_ports", archive_dict["ui_aggregate"])

  def test_archive_duration_computed(self):
    """duration == date_completed - date_created, not 0."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    # date_created=1000000, time()=1000200 → duration=200
    self.assertEqual(archive_dict["duration"], 200.0)
    self.assertGreater(archive_dict["duration"], 0)

  def test_stub_has_job_cid_and_config_cid(self):
    """After prune, CStore stub has job_cid and job_config_cid."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # Extract the stub written to CStore
    hset_call = plugin.chainstore_hset.call_args
    stub = hset_call[1]["value"]
    self.assertEqual(stub["job_cid"], "QmArchiveCID")
    self.assertEqual(stub["job_config_cid"], "QmConfigCID")

  def test_stub_fields_match_model(self):
    """Stub has exactly CStoreJobFinalized fields."""
    from extensions.business.cybersec.red_mesh.models import CStoreJobFinalized
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    stub = plugin.chainstore_hset.call_args[1]["value"]
    # Verify it can be loaded into CStoreJobFinalized
    finalized = CStoreJobFinalized.from_dict(stub)
    self.assertEqual(finalized.job_id, "test-job")
    self.assertEqual(finalized.job_status, "FINALIZED")
    self.assertEqual(finalized.target, "example.com")
    self.assertEqual(finalized.pass_count, 1)
    self.assertEqual(finalized.worker_count, 1)
    self.assertEqual(finalized.start_port, 1)
    self.assertEqual(finalized.end_port, 1024)
    self.assertGreater(finalized.duration, 0)

  def test_pass_report_cids_cleaned_up(self):
    """After archive, individual pass CIDs deleted from R1FS."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # Check delete_file was called for pass report CID
    delete_calls = [c[0][0] for c in plugin.r1fs.delete_file.call_args_list]
    self.assertIn("QmPassReport1", delete_calls)

  def test_node_report_cids_preserved(self):
    """Worker report CIDs NOT deleted."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    delete_calls = [c[0][0] for c in plugin.r1fs.delete_file.call_args_list]
    self.assertNotIn("QmWorker1A", delete_calls)

  def test_aggregated_report_cids_preserved(self):
    """aggregated_report_cid per pass NOT deleted."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    delete_calls = [c[0][0] for c in plugin.r1fs.delete_file.call_args_list]
    self.assertNotIn("QmAgg1", delete_calls)

  def test_archive_write_failure_no_prune(self):
    """R1FS write fails -> CStore untouched, full running state retained."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(r1fs_write_fail=True)

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    # CStore should NOT have been pruned
    plugin.chainstore_hset.assert_not_called()
    # pass_reports still present in job_specs
    self.assertEqual(len(job_specs["pass_reports"]), 1)

  def test_archive_verify_failure_no_prune(self):
    """CID not retrievable -> CStore untouched."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(r1fs_verify_fail=True)

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    plugin.chainstore_hset.assert_not_called()

  def test_stuck_recovery(self):
    """FINALIZED without job_cid -> _build_job_archive retried via _maybe_finalize_pass."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(job_status="FINALIZED")
    # Simulate stuck state: FINALIZED but no job_cid
    job_specs["job_status"] = "FINALIZED"
    # No job_cid in specs

    plugin.chainstore_hgetall.return_value = {"test-job": job_specs}
    plugin._normalize_job_record = MagicMock(return_value=("test-job", job_specs))
    plugin._build_job_archive = MagicMock()

    Plugin._maybe_finalize_pass(plugin)

    plugin._build_job_archive.assert_called_once_with("test-job", job_specs)

  def test_idempotent_rebuild(self):
    """Calling _build_job_archive twice doesn't corrupt state."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin()

    Plugin._build_job_archive(plugin, "test-job", job_specs)
    first_stub = plugin.chainstore_hset.call_args[1]["value"]

    # Reset and call again (simulating a retry where data is still available)
    plugin.chainstore_hset.reset_mock()
    plugin.r1fs.add_json.reset_mock()
    new_archive_cid = "QmArchiveCID2"
    plugin.r1fs.add_json.return_value = new_archive_cid

    # Update get_json to also return data for the new archive CID
    orig_side_effect = plugin.r1fs.get_json.side_effect
    def extended_get(cid):
      if cid == new_archive_cid:
        return {"job_id": "test-job"}
      return orig_side_effect(cid)
    plugin.r1fs.get_json.side_effect = extended_get

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    second_stub = plugin.chainstore_hset.call_args[1]["value"]
    # Both produce valid stubs
    self.assertEqual(first_stub["job_id"], second_stub["job_id"])
    self.assertEqual(first_stub["pass_count"], second_stub["pass_count"])

  def test_multipass_archive(self):
    """Archive with 3 passes contains all pass data."""
    Plugin = self._get_plugin_class()
    plugin, job_specs, _, _ = self._build_archive_plugin(pass_count=3, run_mode="CONTINUOUS_MONITORING", job_status="STOPPED")

    Plugin._build_job_archive(plugin, "test-job", job_specs)

    archive_dict = plugin.r1fs.add_json.call_args[0][0]
    self.assertEqual(len(archive_dict["passes"]), 3)
    self.assertEqual(archive_dict["passes"][0]["pass_nr"], 1)
    self.assertEqual(archive_dict["passes"][2]["pass_nr"], 3)
    stub = plugin.chainstore_hset.call_args[1]["value"]
    self.assertEqual(stub["pass_count"], 3)
    self.assertEqual(stub["job_status"], "STOPPED")


class TestPhase5Endpoints(unittest.TestCase):
  """Phase 5: API Endpoints."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    TestPhase1ConfigCID._mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _build_finalized_stub(self, job_id="test-job"):
    """Build a CStoreJobFinalized-shaped dict."""
    return {
      "job_id": job_id,
      "job_status": "FINALIZED",
      "target": "example.com",
      "task_name": "Test",
      "risk_score": 42,
      "run_mode": "SINGLEPASS",
      "duration": 200.0,
      "pass_count": 1,
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "worker_count": 2,
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "date_completed": 1000200.0,
      "job_cid": "QmArchiveCID",
      "job_config_cid": "QmConfigCID",
    }

  def _build_running_job(self, job_id="run-job", pass_count=8):
    """Build a running job dict with N pass_reports."""
    pass_reports = [
      {"pass_nr": i, "report_cid": f"QmPass{i}", "risk_score": 10 + i}
      for i in range(1, pass_count + 1)
    ]
    return {
      "job_id": job_id,
      "job_status": "RUNNING",
      "job_pass": pass_count,
      "run_mode": "CONTINUOUS_MONITORING",
      "launcher": "launcher-node",
      "launcher_alias": "launcher-alias",
      "target": "example.com",
      "task_name": "Continuous Test",
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1000000.0,
      "risk_score": 18,
      "job_config_cid": "QmConfigCID",
      "workers": {
        "worker-A": {"start_port": 1, "end_port": 512, "finished": False},
        "worker-B": {"start_port": 513, "end_port": 1024, "finished": False},
      },
      "timeline": [
        {"type": "created", "label": "Created", "date": 1000000.0, "actor": "launcher", "actor_type": "system", "meta": {}},
        {"type": "started", "label": "Started", "date": 1000001.0, "actor": "launcher", "actor_type": "system", "meta": {}},
      ],
      "pass_reports": pass_reports,
    }

  def _build_plugin(self, jobs_dict):
    """Build a mock plugin with given jobs in CStore."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.ee_addr = "launcher-node"
    plugin.ee_id = "launcher-alias"
    plugin.cfg_instance_id = "test-instance"
    plugin.r1fs = MagicMock()

    plugin.chainstore_hgetall.return_value = dict(jobs_dict)
    plugin.chainstore_hget.side_effect = lambda hkey, key: jobs_dict.get(key)
    plugin._normalize_job_record = MagicMock(
      side_effect=lambda k, v: (k, v) if isinstance(v, dict) and v.get("job_id") else (None, None)
    )

    # Bind real methods so endpoint logic executes properly
    plugin._get_all_network_jobs = lambda: Plugin._get_all_network_jobs(plugin)
    plugin._get_job_from_cstore = lambda job_id: Plugin._get_job_from_cstore(plugin, job_id)
    return plugin

  def test_get_job_archive_finalized(self):
    """get_job_archive for finalized job returns archive with matching job_id."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    archive_data = {"job_id": "fin-job", "passes": [], "ui_aggregate": {}}
    plugin.r1fs.get_json.return_value = archive_data

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["job_id"], "fin-job")
    self.assertEqual(result["archive"]["job_id"], "fin-job")

  def test_get_job_archive_running(self):
    """get_job_archive for running job returns not_available error."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=2)
    plugin = self._build_plugin({"run-job": running})

    result = Plugin.get_job_archive(plugin, job_id="run-job")
    self.assertEqual(result["error"], "not_available")

  def test_get_job_archive_integrity_mismatch(self):
    """Corrupted job_cid pointing to wrong archive is rejected."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    # Archive has a different job_id
    plugin.r1fs.get_json.return_value = {"job_id": "other-job", "passes": []}

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["error"], "integrity_mismatch")

  def test_get_job_data_running_last_5(self):
    """Running job with 8 passes returns last 5 refs only."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=8)
    plugin = self._build_plugin({"run-job": running})

    result = Plugin.get_job_data(plugin, job_id="run-job")
    self.assertTrue(result["found"])
    refs = result["job"]["pass_reports"]
    self.assertEqual(len(refs), 5)
    # Should be the last 5 (pass_nr 4-8)
    self.assertEqual(refs[0]["pass_nr"], 4)
    self.assertEqual(refs[-1]["pass_nr"], 8)

  def test_get_job_data_finalized_returns_stub(self):
    """Finalized job returns stub as-is with job_cid."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    result = Plugin.get_job_data(plugin, job_id="fin-job")
    self.assertTrue(result["found"])
    self.assertEqual(result["job"]["job_cid"], "QmArchiveCID")
    self.assertEqual(result["job"]["pass_count"], 1)

  def test_list_jobs_finalized_as_is(self):
    """Finalized stubs returned unmodified with all CStoreJobFinalized fields."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("fin-job", result)
    job = result["fin-job"]
    self.assertEqual(job["job_cid"], "QmArchiveCID")
    self.assertEqual(job["pass_count"], 1)
    self.assertEqual(job["worker_count"], 2)
    self.assertEqual(job["risk_score"], 42)
    self.assertEqual(job["duration"], 200.0)

  def test_list_jobs_running_stripped(self):
    """Running jobs have counts but no timeline, workers, or pass_reports."""
    Plugin = self._get_plugin_class()
    running = self._build_running_job("run-job", pass_count=3)
    plugin = self._build_plugin({"run-job": running})

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("run-job", result)
    job = result["run-job"]
    # Should have counts
    self.assertEqual(job["pass_count"], 3)
    self.assertEqual(job["worker_count"], 2)
    # Should NOT have heavy fields
    self.assertNotIn("timeline", job)
    self.assertNotIn("workers", job)
    self.assertNotIn("pass_reports", job)

  def test_get_job_archive_not_found(self):
    """get_job_archive for non-existent job returns not_found."""
    Plugin = self._get_plugin_class()
    plugin = self._build_plugin({})

    result = Plugin.get_job_archive(plugin, job_id="missing-job")
    self.assertEqual(result["error"], "not_found")

  def test_get_job_archive_r1fs_failure(self):
    """get_job_archive when R1FS fails returns fetch_failed."""
    Plugin = self._get_plugin_class()
    stub = self._build_finalized_stub("fin-job")
    plugin = self._build_plugin({"fin-job": stub})
    plugin.r1fs.get_json.return_value = None

    result = Plugin.get_job_archive(plugin, job_id="fin-job")
    self.assertEqual(result["error"], "fetch_failed")


class TestPhase12LiveProgress(unittest.TestCase):
  """Phase 12: Live Worker Progress."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    TestPhase1ConfigCID._mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def test_worker_progress_model_roundtrip(self):
    """WorkerProgress.from_dict(wp.to_dict()) preserves all fields."""
    from extensions.business.cybersec.red_mesh.models import WorkerProgress
    wp = WorkerProgress(
      job_id="job-1",
      worker_addr="0xWorkerA",
      pass_nr=2,
      progress=45.5,
      phase="service_probes",
      ports_scanned=500,
      ports_total=1024,
      open_ports_found=[22, 80, 443],
      completed_tests=["fingerprint_completed", "service_info_completed"],
      updated_at=1700000000.0,
      live_metrics={"total_duration": 30.5},
    )
    d = wp.to_dict()
    wp2 = WorkerProgress.from_dict(d)
    self.assertEqual(wp2.job_id, "job-1")
    self.assertEqual(wp2.worker_addr, "0xWorkerA")
    self.assertEqual(wp2.pass_nr, 2)
    self.assertAlmostEqual(wp2.progress, 45.5)
    self.assertEqual(wp2.phase, "service_probes")
    self.assertEqual(wp2.ports_scanned, 500)
    self.assertEqual(wp2.ports_total, 1024)
    self.assertEqual(wp2.open_ports_found, [22, 80, 443])
    self.assertEqual(wp2.completed_tests, ["fingerprint_completed", "service_info_completed"])
    self.assertEqual(wp2.updated_at, 1700000000.0)
    self.assertEqual(wp2.live_metrics, {"total_duration": 30.5})

  def test_get_job_progress_filters_by_job(self):
    """get_job_progress returns only workers for the requested job."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"

    # Simulate two jobs' progress in the :live hset
    live_data = {
      "job-A:worker-1": {"job_id": "job-A", "progress": 50},
      "job-A:worker-2": {"job_id": "job-A", "progress": 75},
      "job-B:worker-3": {"job_id": "job-B", "progress": 30},
    }
    plugin.chainstore_hgetall.return_value = live_data

    result = Plugin.get_job_progress(plugin, job_id="job-A")
    self.assertEqual(result["job_id"], "job-A")
    self.assertEqual(len(result["workers"]), 2)
    self.assertIn("worker-1", result["workers"])
    self.assertIn("worker-2", result["workers"])
    self.assertNotIn("worker-3", result["workers"])

  def test_get_job_progress_empty(self):
    """get_job_progress for non-existent job returns empty workers dict."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.chainstore_hgetall.return_value = {}

    result = Plugin.get_job_progress(plugin, job_id="nonexistent")
    self.assertEqual(result["job_id"], "nonexistent")
    self.assertEqual(result["workers"], {})

  def test_publish_live_progress(self):
    """_publish_live_progress writes progress to CStore :live hset."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"
    plugin._last_progress_publish = 0
    plugin.time.return_value = 100.0

    # Mock a local worker with state
    worker = MagicMock()
    worker.state = {
      "ports_scanned": list(range(100)),
      "open_ports": [22, 80],
      "completed_tests": ["fingerprint_completed"],
      "done": False,
    }
    worker.initial_ports = list(range(1, 513))

    plugin.scan_jobs = {"job-1": {"worker-thread-1": worker}}

    # Mock CStore lookup for pass_nr
    plugin.chainstore_hget.return_value = {"job_pass": 3}

    Plugin._publish_live_progress(plugin)

    # Verify hset was called with correct key pattern
    plugin.chainstore_hset.assert_called_once()
    call_args = plugin.chainstore_hset.call_args
    self.assertEqual(call_args.kwargs["hkey"], "test-instance:live")
    self.assertEqual(call_args.kwargs["key"], "job-1:node-A")
    progress_data = call_args.kwargs["value"]
    self.assertEqual(progress_data["job_id"], "job-1")
    self.assertEqual(progress_data["worker_addr"], "node-A")
    self.assertEqual(progress_data["pass_nr"], 3)
    self.assertEqual(progress_data["phase"], "service_probes")
    self.assertEqual(progress_data["ports_scanned"], 100)
    self.assertEqual(progress_data["ports_total"], 512)
    self.assertIn(22, progress_data["open_ports_found"])
    self.assertIn(80, progress_data["open_ports_found"])

  def test_clear_live_progress(self):
    """_clear_live_progress deletes progress keys for all workers."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"

    Plugin._clear_live_progress(plugin, "job-1", ["worker-A", "worker-B"])

    self.assertEqual(plugin.chainstore_hset.call_count, 2)
    calls = plugin.chainstore_hset.call_args_list
    keys_deleted = {c.kwargs["key"] for c in calls}
    self.assertEqual(keys_deleted, {"job-1:worker-A", "job-1:worker-B"})
    for c in calls:
      self.assertIsNone(c.kwargs["value"])


class TestPhase14Purge(unittest.TestCase):
  """Phase 14: Job Deletion & Purge."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    TestPhase1ConfigCID._mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def _make_plugin(self):
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"
    return plugin

  def test_purge_finalized_collects_all_cids(self):
    """Finalized purge collects archive + config + aggregated_report + worker report CIDs."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    # CStore stub for a finalized job
    job_specs = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "job_cid": "cid-archive",
      "job_config_cid": "cid-config",
    }
    plugin.chainstore_hget.return_value = job_specs

    # Archive contains nested CIDs
    archive = {
      "passes": [
        {
          "aggregated_report_cid": "cid-agg-1",
          "worker_reports": {
            "worker-A": {"report_cid": "cid-wr-A"},
            "worker-B": {"report_cid": "cid-wr-B"},
          },
        },
      ],
    }
    plugin.r1fs.get_json.return_value = archive
    plugin.r1fs.delete_file.return_value = True
    plugin.chainstore_hgetall.return_value = {}

    # Normalize returns the specs as-is
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    # Verify all 5 CIDs were deleted
    deleted_cids = {c.args[0] for c in plugin.r1fs.delete_file.call_args_list}
    self.assertEqual(deleted_cids, {"cid-archive", "cid-config", "cid-agg-1", "cid-wr-A", "cid-wr-B"})
    self.assertEqual(result["cids_deleted"], 5)
    self.assertEqual(result["cids_total"], 5)

  def test_purge_finalized_no_pass_report_cids(self):
    """Finalized purge does NOT try to delete individual pass report CIDs (they are inside archive)."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "job_cid": "cid-archive",
      # No pass_reports key — finalized stubs don't have them
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin.r1fs.get_json.return_value = {"passes": []}
    plugin.r1fs.delete_file.return_value = True
    plugin.chainstore_hgetall.return_value = {}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    # Only archive CID should be deleted (no pass_reports, no config, no workers)
    deleted_cids = {c.args[0] for c in plugin.r1fs.delete_file.call_args_list}
    self.assertEqual(deleted_cids, {"cid-archive"})

  def test_purge_running_collects_all_cids(self):
    """Stopped (was running) purge collects config + worker CIDs + pass report CIDs + nested CIDs."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "STOPPED",
      "job_config_cid": "cid-config",
      "workers": {
        "node-A": {"finished": True, "canceled": True, "report_cid": "cid-wr-A"},
      },
      "pass_reports": [
        {"report_cid": "cid-pass-1"},
      ],
    }
    plugin.chainstore_hget.return_value = job_specs

    # Pass report contains nested CIDs
    pass_report = {
      "aggregated_report_cid": "cid-agg-1",
      "worker_reports": {
        "node-A": {"report_cid": "cid-pass-wr-A"},
      },
    }
    plugin.r1fs.get_json.return_value = pass_report
    plugin.r1fs.delete_file.return_value = True
    plugin.chainstore_hgetall.return_value = {}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    deleted_cids = {c.args[0] for c in plugin.r1fs.delete_file.call_args_list}
    self.assertEqual(deleted_cids, {"cid-config", "cid-wr-A", "cid-pass-1", "cid-agg-1", "cid-pass-wr-A"})

  def test_purge_r1fs_failure_keeps_cstore(self):
    """Partial R1FS failure leaves CStore intact and returns 'partial' status."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "job_cid": "cid-archive",
      "job_config_cid": "cid-config",
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin.r1fs.get_json.return_value = {"passes": []}

    # First CID deletes ok, second raises
    plugin.r1fs.delete_file.side_effect = [True, Exception("disk error")]

    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "partial")
    self.assertEqual(result["cids_deleted"], 1)
    self.assertEqual(result["cids_failed"], 1)
    self.assertEqual(result["cids_total"], 2)

    # CStore should NOT be tombstoned
    tombstone_calls = [
      c for c in plugin.chainstore_hset.call_args_list
      if c.kwargs.get("hkey") == "test-instance" and c.kwargs.get("value") is None
    ]
    self.assertEqual(len(tombstone_calls), 0)

  def test_purge_cleans_live_progress(self):
    """Purge deletes live progress keys for the job from :live hset."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "STOPPED",
      "workers": {"node-A": {"finished": True}},
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin.r1fs.delete_file.return_value = True

    # Live hset has keys for this job and another
    plugin.chainstore_hgetall.return_value = {
      "job-1:node-A": {"progress": 100},
      "job-1:node-B": {"progress": 50},
      "job-2:node-C": {"progress": 30},
    }
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    # Check that live progress keys for job-1 were deleted
    live_delete_calls = [
      c for c in plugin.chainstore_hset.call_args_list
      if c.kwargs.get("hkey") == "test-instance:live" and c.kwargs.get("value") is None
    ]
    deleted_keys = {c.kwargs["key"] for c in live_delete_calls}
    self.assertEqual(deleted_keys, {"job-1:node-A", "job-1:node-B"})
    # job-2 key should NOT be touched
    self.assertNotIn("job-2:node-C", deleted_keys)

  def test_purge_success_tombstones_cstore(self):
    """After all CIDs deleted, CStore key is tombstoned (set to None)."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()

    job_specs = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "job_cid": "cid-archive",
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin.r1fs.get_json.return_value = {"passes": []}
    plugin.r1fs.delete_file.return_value = True
    plugin.chainstore_hgetall.return_value = {}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    result = Plugin.purge_job(plugin, "job-1")
    self.assertEqual(result["status"], "success")

    # CStore tombstone: hset(hkey=instance_id, key=job_id, value=None)
    tombstone_calls = [
      c for c in plugin.chainstore_hset.call_args_list
      if c.kwargs.get("hkey") == "test-instance"
        and c.kwargs.get("key") == "job-1"
        and c.kwargs.get("value") is None
    ]
    self.assertEqual(len(tombstone_calls), 1)

  def test_stop_and_delete_delegates_to_purge(self):
    """stop_and_delete_job marks job stopped then delegates to purge_job."""
    Plugin = self._get_plugin_class()
    plugin = self._make_plugin()
    plugin.scan_jobs = {}

    job_specs = {
      "job_id": "job-1",
      "job_status": "RUNNING",
      "workers": {"node-A": {"finished": False}},
    }
    plugin.chainstore_hget.return_value = job_specs
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))

    # Mock purge_job to verify delegation
    purge_result = {"status": "success", "job_id": "job-1", "cids_deleted": 3, "cids_total": 3}
    plugin.purge_job = MagicMock(return_value=purge_result)

    result = Plugin.stop_and_delete_job(plugin, "job-1")

    # Verify job was marked stopped before purge
    hset_calls = [
      c for c in plugin.chainstore_hset.call_args_list
      if c.kwargs.get("hkey") == "test-instance" and c.kwargs.get("key") == "job-1"
    ]
    self.assertEqual(len(hset_calls), 1)
    saved_specs = hset_calls[0].kwargs["value"]
    self.assertEqual(saved_specs["job_status"], "STOPPED")
    self.assertTrue(saved_specs["workers"]["node-A"]["finished"])
    self.assertTrue(saved_specs["workers"]["node-A"]["canceled"])

    # Verify purge was called
    plugin.purge_job.assert_called_once_with("job-1")
    self.assertEqual(result, purge_result)


class TestPhase15Listing(unittest.TestCase):
  """Phase 15: Listing Endpoint Optimization."""

  @classmethod
  def _mock_plugin_modules(cls):
    if 'extensions.business.cybersec.red_mesh.pentester_api_01' in sys.modules:
      return
    TestPhase1ConfigCID._mock_plugin_modules()

  def _get_plugin_class(self):
    self._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    return PentesterApi01Plugin

  def test_list_finalized_returns_stub_fields(self):
    """Finalized jobs return exact CStoreJobFinalized fields."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"

    finalized_stub = {
      "job_id": "job-1",
      "job_status": "FINALIZED",
      "target": "10.0.0.1",
      "task_name": "scan-1",
      "risk_score": 75,
      "run_mode": "SINGLEPASS",
      "duration": 120.5,
      "pass_count": 1,
      "launcher": "0xLauncher",
      "launcher_alias": "node1",
      "worker_count": 2,
      "start_port": 1,
      "end_port": 1024,
      "date_created": 1700000000.0,
      "date_completed": 1700000120.0,
      "job_cid": "QmArchive123",
      "job_config_cid": "QmConfig456",
    }
    plugin.chainstore_hgetall.return_value = {"job-1": finalized_stub}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", finalized_stub))

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("job-1", result)
    entry = result["job-1"]

    # All CStoreJobFinalized fields present
    self.assertEqual(entry["job_id"], "job-1")
    self.assertEqual(entry["job_status"], "FINALIZED")
    self.assertEqual(entry["job_cid"], "QmArchive123")
    self.assertEqual(entry["job_config_cid"], "QmConfig456")
    self.assertEqual(entry["target"], "10.0.0.1")
    self.assertEqual(entry["risk_score"], 75)
    self.assertEqual(entry["duration"], 120.5)
    self.assertEqual(entry["pass_count"], 1)
    self.assertEqual(entry["worker_count"], 2)

  def test_list_running_stripped(self):
    """Running jobs have listing fields but no heavy data."""
    Plugin = self._get_plugin_class()
    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"

    running_spec = {
      "job_id": "job-2",
      "job_status": "RUNNING",
      "target": "10.0.0.2",
      "task_name": "scan-2",
      "risk_score": 0,
      "run_mode": "CONTINUOUS_MONITORING",
      "start_port": 1,
      "end_port": 65535,
      "date_created": 1700000000.0,
      "launcher": "0xLauncher",
      "launcher_alias": "node1",
      "job_pass": 3,
      "job_config_cid": "QmConfig789",
      "workers": {
        "addr-A": {"start_port": 1, "end_port": 32767, "finished": False, "report_cid": "QmBigReport1"},
        "addr-B": {"start_port": 32768, "end_port": 65535, "finished": False, "report_cid": "QmBigReport2"},
      },
      "timeline": [
        {"event": "created", "ts": 1700000000.0},
        {"event": "started", "ts": 1700000001.0},
      ],
      "pass_reports": [
        {"pass_nr": 1, "report_cid": "QmPass1"},
        {"pass_nr": 2, "report_cid": "QmPass2"},
      ],
      "redmesh_job_start_attestation": {"big": "blob"},
    }
    plugin.chainstore_hgetall.return_value = {"job-2": running_spec}
    plugin._normalize_job_record = MagicMock(return_value=("job-2", running_spec))

    result = Plugin.list_network_jobs(plugin)
    self.assertIn("job-2", result)
    entry = result["job-2"]

    # Listing essentials present
    self.assertEqual(entry["job_id"], "job-2")
    self.assertEqual(entry["job_status"], "RUNNING")
    self.assertEqual(entry["target"], "10.0.0.2")
    self.assertEqual(entry["task_name"], "scan-2")
    self.assertEqual(entry["run_mode"], "CONTINUOUS_MONITORING")
    self.assertEqual(entry["job_pass"], 3)
    self.assertEqual(entry["worker_count"], 2)
    self.assertEqual(entry["pass_count"], 2)

    # Heavy fields stripped
    self.assertNotIn("workers", entry)
    self.assertNotIn("timeline", entry)
    self.assertNotIn("pass_reports", entry)
    self.assertNotIn("redmesh_job_start_attestation", entry)
    self.assertNotIn("job_config_cid", entry)
    self.assertNotIn("report_cid", entry)


class TestPhase16ScanMetrics(unittest.TestCase):
  """Phase 16: Scan Metrics Collection."""

  def test_metrics_collector_empty_build(self):
    """build() with zero data returns ScanMetrics with defaults, no crash."""
    from extensions.business.cybersec.red_mesh.redmesh_utils import MetricsCollector
    mc = MetricsCollector()
    result = mc.build()
    d = result.to_dict()
    self.assertEqual(d.get("total_duration", 0), 0)
    self.assertEqual(d.get("rate_limiting_detected", False), False)
    self.assertEqual(d.get("blocking_detected", False), False)
    # No crash, sparse output
    self.assertNotIn("connection_outcomes", d)
    self.assertNotIn("response_times", d)

  def test_metrics_collector_records_connections(self):
    """After recording outcomes, connection_outcomes has correct counts."""
    from extensions.business.cybersec.red_mesh.redmesh_utils import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(100)
    mc.record_connection("connected", 0.05)
    mc.record_connection("connected", 0.03)
    mc.record_connection("timeout", 1.0)
    mc.record_connection("refused", 0.01)
    d = mc.build().to_dict()
    outcomes = d["connection_outcomes"]
    self.assertEqual(outcomes["connected"], 2)
    self.assertEqual(outcomes["timeout"], 1)
    self.assertEqual(outcomes["refused"], 1)
    self.assertEqual(outcomes["total"], 4)
    # Response times computed
    rt = d["response_times"]
    self.assertIn("mean", rt)
    self.assertIn("p95", rt)
    self.assertEqual(rt["count"], 4)

  def test_metrics_collector_records_probes(self):
    """After recording probes, probe_breakdown has entries."""
    from extensions.business.cybersec.red_mesh.redmesh_utils import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(10)
    mc.record_probe("_service_info_http", "completed")
    mc.record_probe("_service_info_ssh", "completed")
    mc.record_probe("_web_test_xss", "skipped:no_http")
    d = mc.build().to_dict()
    self.assertEqual(d["probes_attempted"], 3)
    self.assertEqual(d["probes_completed"], 2)
    self.assertEqual(d["probes_skipped"], 1)
    self.assertEqual(d["probe_breakdown"]["_service_info_http"], "completed")
    self.assertEqual(d["probe_breakdown"]["_web_test_xss"], "skipped:no_http")

  def test_metrics_collector_phase_durations(self):
    """start/end phases produce positive durations."""
    import time
    from extensions.business.cybersec.red_mesh.redmesh_utils import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(10)
    mc.phase_start("port_scan")
    time.sleep(0.01)
    mc.phase_end("port_scan")
    d = mc.build().to_dict()
    self.assertIn("phase_durations", d)
    self.assertGreater(d["phase_durations"]["port_scan"], 0)

  def test_metrics_collector_findings(self):
    """record_finding tracks severity distribution."""
    from extensions.business.cybersec.red_mesh.redmesh_utils import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(10)
    mc.record_finding("HIGH")
    mc.record_finding("HIGH")
    mc.record_finding("MEDIUM")
    mc.record_finding("INFO")
    d = mc.build().to_dict()
    fd = d["finding_distribution"]
    self.assertEqual(fd["HIGH"], 2)
    self.assertEqual(fd["MEDIUM"], 1)
    self.assertEqual(fd["INFO"], 1)

  def test_metrics_collector_coverage(self):
    """Coverage tracks ports scanned vs in range."""
    from extensions.business.cybersec.red_mesh.redmesh_utils import MetricsCollector
    mc = MetricsCollector()
    mc.start_scan(100)
    for i in range(50):
      mc.record_connection("connected" if i < 5 else "refused", 0.01)
    # Simulate finding 5 open ports with banner confirmation
    for i in range(5):
      mc.record_open_port(8000 + i, protocol="http" if i < 3 else "ssh", banner_confirmed=(i < 3))
    d = mc.build().to_dict()
    cov = d["coverage"]
    self.assertEqual(cov["ports_in_range"], 100)
    self.assertEqual(cov["ports_scanned"], 50)
    self.assertEqual(cov["coverage_pct"], 50.0)
    self.assertEqual(cov["open_ports_count"], 5)
    # Open port details
    self.assertEqual(len(d["open_port_details"]), 5)
    self.assertEqual(d["open_port_details"][0]["port"], 8000)
    self.assertEqual(d["open_port_details"][0]["protocol"], "http")
    self.assertTrue(d["open_port_details"][0]["banner_confirmed"])
    self.assertFalse(d["open_port_details"][3]["banner_confirmed"])
    # Banner confirmation
    self.assertEqual(d["banner_confirmation"]["confirmed"], 3)
    self.assertEqual(d["banner_confirmation"]["guessed"], 2)

  def test_scan_metrics_model_roundtrip(self):
    """ScanMetrics.from_dict(sm.to_dict()) preserves all fields."""
    from extensions.business.cybersec.red_mesh.models.shared import ScanMetrics
    sm = ScanMetrics(
      phase_durations={"port_scan": 10.5, "fingerprint": 3.2},
      total_duration=15.0,
      connection_outcomes={"connected": 50, "timeout": 5, "total": 55},
      response_times={"min": 0.01, "max": 1.0, "mean": 0.1, "median": 0.08, "stddev": 0.05, "p95": 0.5, "p99": 0.9, "count": 55},
      rate_limiting_detected=True,
      blocking_detected=False,
      coverage={"ports_in_range": 1000, "ports_scanned": 1000, "ports_skipped": 0, "coverage_pct": 100.0},
      probes_attempted=5,
      probes_completed=4,
      probes_skipped=1,
      probes_failed=0,
      probe_breakdown={"_service_info_http": "completed"},
      finding_distribution={"HIGH": 3, "MEDIUM": 2},
    )
    d = sm.to_dict()
    sm2 = ScanMetrics.from_dict(d)
    self.assertEqual(sm2.to_dict(), d)

  def test_scan_metrics_strip_none(self):
    """Empty/None fields stripped from serialization."""
    from extensions.business.cybersec.red_mesh.models.shared import ScanMetrics
    sm = ScanMetrics()
    d = sm.to_dict()
    self.assertNotIn("phase_durations", d)
    self.assertNotIn("connection_outcomes", d)
    self.assertNotIn("response_times", d)
    self.assertNotIn("slow_ports", d)
    self.assertNotIn("probe_breakdown", d)

  def test_merge_worker_metrics(self):
    """_merge_worker_metrics sums outcomes, coverage, findings; maxes duration; ORs flags."""
    TestPhase15Listing._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin
    m1 = {
      "connection_outcomes": {"connected": 30, "timeout": 5, "total": 35},
      "coverage": {"ports_in_range": 500, "ports_scanned": 500, "ports_skipped": 0, "coverage_pct": 100.0, "open_ports_count": 3},
      "finding_distribution": {"HIGH": 2, "MEDIUM": 1},
      "service_distribution": {"http": 2, "ssh": 1},
      "probe_breakdown": {"_service_info_http": "completed", "_web_test_xss": "completed"},
      "phase_durations": {"port_scan": 30.0, "fingerprint": 10.0, "service_probes": 15.0},
      "response_times": {"min": 0.01, "max": 0.5, "mean": 0.05, "median": 0.04, "stddev": 0.03, "p95": 0.2, "p99": 0.4, "count": 500},
      "probes_attempted": 3, "probes_completed": 3, "probes_skipped": 0, "probes_failed": 0,
      "total_duration": 60.0,
      "rate_limiting_detected": False, "blocking_detected": False,
      "open_port_details": [
        {"port": 22, "protocol": "ssh", "banner_confirmed": True},
        {"port": 80, "protocol": "http", "banner_confirmed": True},
        {"port": 443, "protocol": "http", "banner_confirmed": False},
      ],
      "banner_confirmation": {"confirmed": 2, "guessed": 1},
    }
    m2 = {
      "connection_outcomes": {"connected": 20, "timeout": 10, "total": 30},
      "coverage": {"ports_in_range": 500, "ports_scanned": 400, "ports_skipped": 100, "coverage_pct": 80.0, "open_ports_count": 2},
      "finding_distribution": {"HIGH": 1, "LOW": 3},
      "service_distribution": {"http": 1, "mysql": 1},
      "probe_breakdown": {"_service_info_http": "completed", "_service_info_mysql": "completed", "_web_test_xss": "failed"},
      "phase_durations": {"port_scan": 45.0, "fingerprint": 8.0, "service_probes": 20.0},
      "response_times": {"min": 0.02, "max": 0.8, "mean": 0.08, "median": 0.06, "stddev": 0.05, "p95": 0.3, "p99": 0.7, "count": 400},
      "probes_attempted": 3, "probes_completed": 2, "probes_skipped": 1, "probes_failed": 0,
      "total_duration": 75.0,
      "rate_limiting_detected": True, "blocking_detected": False,
      "open_port_details": [
        {"port": 80, "protocol": "http", "banner_confirmed": True},  # duplicate port 80
        {"port": 3306, "protocol": "mysql", "banner_confirmed": True},
      ],
      "banner_confirmation": {"confirmed": 2, "guessed": 0},
    }
    merged = PentesterApi01Plugin._merge_worker_metrics([m1, m2])
    # Sums
    self.assertEqual(merged["connection_outcomes"]["connected"], 50)
    self.assertEqual(merged["connection_outcomes"]["timeout"], 15)
    self.assertEqual(merged["connection_outcomes"]["total"], 65)
    self.assertEqual(merged["coverage"]["ports_in_range"], 1000)
    self.assertEqual(merged["coverage"]["ports_scanned"], 900)
    self.assertEqual(merged["coverage"]["ports_skipped"], 100)
    self.assertEqual(merged["coverage"]["coverage_pct"], 90.0)
    self.assertEqual(merged["coverage"]["open_ports_count"], 5)
    self.assertEqual(merged["finding_distribution"]["HIGH"], 3)
    self.assertEqual(merged["finding_distribution"]["LOW"], 3)
    self.assertEqual(merged["finding_distribution"]["MEDIUM"], 1)
    self.assertEqual(merged["probes_attempted"], 6)
    self.assertEqual(merged["probes_completed"], 5)
    self.assertEqual(merged["probes_skipped"], 1)
    # Service distribution summed
    self.assertEqual(merged["service_distribution"]["http"], 3)
    self.assertEqual(merged["service_distribution"]["ssh"], 1)
    self.assertEqual(merged["service_distribution"]["mysql"], 1)
    # Probe breakdown: union, worst status wins
    self.assertEqual(merged["probe_breakdown"]["_service_info_http"], "completed")
    self.assertEqual(merged["probe_breakdown"]["_service_info_mysql"], "completed")
    self.assertEqual(merged["probe_breakdown"]["_web_test_xss"], "failed")  # failed > completed
    # Phase durations: max per phase
    self.assertEqual(merged["phase_durations"]["port_scan"], 45.0)
    self.assertEqual(merged["phase_durations"]["fingerprint"], 10.0)
    self.assertEqual(merged["phase_durations"]["service_probes"], 20.0)
    # Response times: merged stats
    rt = merged["response_times"]
    self.assertEqual(rt["min"], 0.01)   # global min
    self.assertEqual(rt["max"], 0.8)    # global max
    self.assertEqual(rt["count"], 900)  # total count
    # Weighted mean: (0.05*500 + 0.08*400) / 900 ≈ 0.0633
    self.assertAlmostEqual(rt["mean"], 0.0633, places=3)
    self.assertEqual(rt["p95"], 0.3)    # max of per-thread p95
    self.assertEqual(rt["p99"], 0.7)    # max of per-thread p99
    # Max duration
    self.assertEqual(merged["total_duration"], 75.0)
    # OR flags
    self.assertTrue(merged["rate_limiting_detected"])
    self.assertFalse(merged["blocking_detected"])
    # Open port details: deduplicated by port, sorted
    opd = merged["open_port_details"]
    self.assertEqual(len(opd), 4)  # 22, 80, 443, 3306 (80 deduplicated)
    self.assertEqual(opd[0]["port"], 22)
    self.assertEqual(opd[1]["port"], 80)
    self.assertEqual(opd[2]["port"], 443)
    self.assertEqual(opd[3]["port"], 3306)
    # Banner confirmation: summed
    self.assertEqual(merged["banner_confirmation"]["confirmed"], 4)
    self.assertEqual(merged["banner_confirmation"]["guessed"], 1)


  def test_close_job_merges_thread_metrics(self):
    """16b: _close_job replaces generically-merged scan_metrics with properly summed metrics."""
    TestPhase15Listing._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-A"

    # Two mock workers with different scan_metrics
    worker1 = MagicMock()
    worker1.get_status.return_value = {
      "open_ports": [80], "service_info": {}, "scan_metrics": {
        "connection_outcomes": {"connected": 10, "timeout": 2, "total": 12},
        "total_duration": 30.0,
        "probes_attempted": 2, "probes_completed": 2, "probes_skipped": 0, "probes_failed": 0,
        "rate_limiting_detected": False, "blocking_detected": False,
      }
    }
    worker2 = MagicMock()
    worker2.get_status.return_value = {
      "open_ports": [443], "service_info": {}, "scan_metrics": {
        "connection_outcomes": {"connected": 8, "timeout": 5, "total": 13},
        "total_duration": 45.0,
        "probes_attempted": 2, "probes_completed": 1, "probes_skipped": 1, "probes_failed": 0,
        "rate_limiting_detected": True, "blocking_detected": False,
      }
    }
    plugin.scan_jobs = {"job-1": {"t1": worker1, "t2": worker2}}

    # _get_aggregated_report with merge_objects_deep would do last-writer-wins on leaf ints
    # Simulate that by returning worker2's metrics (wrong — should be summed)
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80, 443], "service_info": {},
      "scan_metrics": {
        "connection_outcomes": {"connected": 8, "timeout": 5, "total": 13},
        "total_duration": 45.0,
      }
    })
    # Use real static method for merge
    plugin._merge_worker_metrics = PentesterApi01Plugin._merge_worker_metrics

    saved_reports = []
    def capture_add_json(data, show_logs=False):
      saved_reports.append(data)
      return "QmReport123"
    plugin.r1fs.add_json.side_effect = capture_add_json

    job_specs = {"job_id": "job-1", "target": "10.0.0.1", "workers": {}}
    plugin.chainstore_hget.return_value = job_specs
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))
    plugin._get_job_config = MagicMock(return_value={"redact_credentials": False})
    plugin._redact_report = MagicMock(side_effect=lambda r: r)

    PentesterApi01Plugin._close_job(plugin, "job-1")

    # The report saved to R1FS should have properly merged metrics
    self.assertEqual(len(saved_reports), 1)
    sm = saved_reports[0].get("scan_metrics")
    self.assertIsNotNone(sm)
    # Connection outcomes should be summed, not last-writer-wins
    self.assertEqual(sm["connection_outcomes"]["connected"], 18)
    self.assertEqual(sm["connection_outcomes"]["timeout"], 7)
    self.assertEqual(sm["connection_outcomes"]["total"], 25)
    # Max duration
    self.assertEqual(sm["total_duration"], 45.0)
    # Probes summed
    self.assertEqual(sm["probes_attempted"], 4)
    self.assertEqual(sm["probes_completed"], 3)
    # OR flags
    self.assertTrue(sm["rate_limiting_detected"])

  def test_finalize_pass_attaches_pass_metrics(self):
    """16c: _maybe_finalize_pass merges node metrics into PassReport.scan_metrics."""
    TestPhase15Listing._mock_plugin_modules()
    from extensions.business.cybersec.red_mesh.pentester_api_01 import PentesterApi01Plugin

    plugin = MagicMock()
    plugin.cfg_instance_id = "test-instance"
    plugin.ee_addr = "node-launcher"
    plugin.cfg_llm_agent_api_enabled = False
    plugin.cfg_attestation_min_seconds_between_submits = 3600

    # Two workers, each with a report_cid
    workers = {
      "node-A": {"finished": True, "report_cid": "cid-report-A"},
      "node-B": {"finished": True, "report_cid": "cid-report-B"},
    }
    job_specs = {
      "job_id": "job-1",
      "job_status": "RUNNING",
      "target": "10.0.0.1",
      "run_mode": "SINGLEPASS",
      "launcher": "node-launcher",
      "workers": workers,
      "job_pass": 1,
      "pass_reports": [],
      "timeline": [{"event": "created", "ts": 1700000000.0}],
    }
    plugin.chainstore_hgetall.return_value = {"job-1": job_specs}
    plugin._normalize_job_record = MagicMock(return_value=("job-1", job_specs))
    plugin.time.return_value = 1700000120.0

    # Node reports with different metrics
    node_report_a = {
      "open_ports": [80], "service_info": {}, "web_tests_info": {},
      "correlation_findings": [], "start_port": 1, "end_port": 32767,
      "ports_scanned": 32767,
      "scan_metrics": {
        "connection_outcomes": {"connected": 5, "timeout": 1, "total": 6},
        "total_duration": 50.0,
        "probes_attempted": 3, "probes_completed": 3, "probes_skipped": 0, "probes_failed": 0,
        "rate_limiting_detected": False, "blocking_detected": False,
      }
    }
    node_report_b = {
      "open_ports": [443], "service_info": {}, "web_tests_info": {},
      "correlation_findings": [], "start_port": 32768, "end_port": 65535,
      "ports_scanned": 32768,
      "scan_metrics": {
        "connection_outcomes": {"connected": 3, "timeout": 4, "total": 7},
        "total_duration": 65.0,
        "probes_attempted": 3, "probes_completed": 2, "probes_skipped": 0, "probes_failed": 1,
        "rate_limiting_detected": False, "blocking_detected": True,
      }
    }

    node_reports_by_addr = {"node-A": node_report_a, "node-B": node_report_b}
    plugin._collect_node_reports = MagicMock(return_value=node_reports_by_addr)
    # _get_aggregated_report would use merge_objects_deep (wrong for metrics)
    # Return a dict with last-writer-wins metrics to simulate the bug
    plugin._get_aggregated_report = MagicMock(return_value={
      "open_ports": [80, 443], "service_info": {}, "web_tests_info": {},
      "scan_metrics": node_report_b["scan_metrics"],  # wrong — just node B's
    })
    # Use real static method for merge
    plugin._merge_worker_metrics = PentesterApi01Plugin._merge_worker_metrics

    # Capture what gets saved as pass report
    saved_pass_reports = []
    def capture_add_json(data, show_logs=False):
      saved_pass_reports.append(data)
      return f"QmPassReport{len(saved_pass_reports)}"
    plugin.r1fs.add_json.side_effect = capture_add_json

    plugin._compute_risk_and_findings = MagicMock(return_value=({"score": 25, "breakdown": {}}, []))
    plugin._get_job_config = MagicMock(return_value={})
    plugin._submit_redmesh_test_attestation = MagicMock(return_value=None)
    plugin._build_job_archive = MagicMock()
    plugin._clear_live_progress = MagicMock()
    plugin._emit_timeline_event = MagicMock()
    plugin._get_timeline_date = MagicMock(return_value=1700000000.0)
    plugin.Pd = MagicMock()

    PentesterApi01Plugin._maybe_finalize_pass(plugin)

    # Should have saved: aggregated_data (step 6) + pass_report (step 10)
    self.assertGreaterEqual(len(saved_pass_reports), 2)
    pass_report = saved_pass_reports[-1]  # Last one is the PassReport

    sm = pass_report.get("scan_metrics")
    self.assertIsNotNone(sm, "PassReport should have scan_metrics")
    # Connection outcomes summed across nodes
    self.assertEqual(sm["connection_outcomes"]["connected"], 8)
    self.assertEqual(sm["connection_outcomes"]["timeout"], 5)
    self.assertEqual(sm["connection_outcomes"]["total"], 13)
    # Max duration
    self.assertEqual(sm["total_duration"], 65.0)
    # Probes summed
    self.assertEqual(sm["probes_attempted"], 6)
    self.assertEqual(sm["probes_completed"], 5)
    self.assertEqual(sm["probes_failed"], 1)
    # OR flags
    self.assertFalse(sm["rate_limiting_detected"])
    self.assertTrue(sm["blocking_detected"])


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


class VerboseResult(unittest.TextTestResult):
  def addSuccess(self, test):
    super().addSuccess(test)
    self.stream.writeln()  # emits an extra "\n" after the usual "ok"

if __name__ == "__main__":
  runner = unittest.TextTestRunner(verbosity=2, resultclass=VerboseResult)
  suite = unittest.TestSuite()
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(RedMeshOWASPTests))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestFindingsModule))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestCveDatabase))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestCorrelationEngine))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestScannerEnhancements))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase1ConfigCID))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase2PassFinalization))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase4UiAggregate))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase3Archive))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase5Endpoints))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase12LiveProgress))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase14Purge))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase15Listing))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase16ScanMetrics))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase17aQuickWins))
  suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(TestPhase17bMediumFeatures))
  runner.run(suite)
