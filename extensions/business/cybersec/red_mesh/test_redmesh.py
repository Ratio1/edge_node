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
    self.assertIn("VULNERABILITY: Accessible resource", result)

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
    self.assertIn("VULNERABILITY: Cookie missing Secure flag", result)
    self.assertIn("VULNERABILITY: Cookie missing HttpOnly flag", result)
    self.assertIn("VULNERABILITY: Cookie missing SameSite flag", result)

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
    self.assertIn("VULNERABILITY: Missing security header", result)

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
    self.assertIn("VULNERABILITY: GraphQL introspection", result)

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
    self.assertIn("VULNERABILITY: Cloud metadata endpoint", result)

  def test_web_api_auth_bypass(self):
    owner, worker = self._build_worker()
    resp = MagicMock()
    resp.status_code = 200
    with patch(
      "extensions.business.cybersec.red_mesh.web_api_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_hardening_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_hardening_mixin.requests.get",
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
      "extensions.business.cybersec.red_mesh.web_hardening_mixin.requests.options",
      return_value=resp,
    ):
      result = worker._web_test_http_methods("example.com", 80)
    self.assertIn("VULNERABILITY: Risky HTTP methods", result)

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
    """probe_error returns correct structure."""
    from extensions.business.cybersec.red_mesh.findings import probe_error
    result = probe_error("host", 80, "TestProbe", Exception("oops"))
    self.assertIn("error", result)
    self.assertIn("TestProbe", result["error"])
    self.assertIn("findings", result)
    self.assertEqual(result["findings"], [])

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
  runner.run(suite)
