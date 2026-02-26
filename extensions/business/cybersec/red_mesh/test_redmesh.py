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
    worker.target = "10.0.0.1"

    # Build a valid Modbus Read Device ID response:
    # Transaction ID 0x0001, Protocol ID 0x0000, Length 0x0008, Unit 0x01,
    # Function 0x2B, MEI type 0x0E, conformity 0x01, more 0x00, obj count 0x00
    modbus_response = b'\x00\x01\x00\x00\x00\x08\x01\x2b\x0e\x01\x01\x00\x00'

    call_index = [0]

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = b""
      # First call: passive banner grab → empty (no banner)
      # Second call: nudge probe → empty
      # Third call: HTTP probe → empty
      # Fourth call: modbus probe → valid response
      idx = call_index[0]
      call_index[0] += 1
      if idx == 3:
        mock_sock.recv.return_value = modbus_response
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
      worker._fingerprint_ports()

    self.assertEqual(worker.state["port_protocols"][1024], "modbus")

  def test_fingerprint_non_modbus_stays_unknown(self):
    """Port with no recognizable response should remain unknown."""
    owner, worker = self._build_worker(ports=[1024])
    worker.state["open_ports"] = [1024]
    worker.target = "10.0.0.1"

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = b""
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
      worker._fingerprint_ports()

    self.assertEqual(worker.state["port_protocols"][1024], "unknown")

  def test_fingerprint_mysql_false_positive_binary_data(self):
    """Binary data that happens to have 0x00 at byte 3 and 0x0a at byte 4 must NOT be classified as mysql."""
    owner, worker = self._build_worker(ports=[37364])
    worker.state["open_ports"] = [37364]
    worker.target = "10.0.0.1"

    # Crafted binary blob: byte 3 = 0x00, byte 4 = 0x0a, but byte 5+ is not
    # a printable version string — this is NOT a MySQL greeting.
    fake_binary = b'\x07\x02\x03\x00\x0a\x80\xff\x00\x01\x02'

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = fake_binary
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
      worker._fingerprint_ports()

    self.assertNotEqual(worker.state["port_protocols"][37364], "mysql")

  def test_fingerprint_mysql_real_greeting(self):
    """A genuine MySQL greeting packet should still be fingerprinted as mysql."""
    owner, worker = self._build_worker(ports=[3306])
    worker.state["open_ports"] = [3306]
    worker.target = "10.0.0.1"

    # Real MySQL handshake: 3-byte length + seq=0x00 + protocol=0x0a + "8.0.28\x00" + filler
    version = b"8.0.28"
    payload = bytes([0x0a]) + version + b'\x00' + b'\x00' * 50
    pkt_len = len(payload).to_bytes(3, 'little')
    mysql_greeting = pkt_len + b'\x00' + payload

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = mysql_greeting
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
      worker._fingerprint_ports()

    self.assertEqual(worker.state["port_protocols"][3306], "mysql")

  def test_fingerprint_telnet_real_iac(self):
    """Banner starting with a valid IAC WILL sequence should be fingerprinted as telnet."""
    owner, worker = self._build_worker(ports=[2323])
    worker.state["open_ports"] = [2323]
    worker.target = "10.0.0.1"

    # IAC WILL ECHO (0xFF 0xFB 0x01) — valid telnet negotiation per RFC 854
    telnet_banner = b'\xff\xfb\x01\xff\xfb\x03'

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = telnet_banner
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
      worker._fingerprint_ports()

    self.assertEqual(worker.state["port_protocols"][2323], "telnet")

  def test_fingerprint_telnet_false_positive_0xff(self):
    """Binary data starting with 0xFF but no valid IAC command must NOT be classified as telnet."""
    owner, worker = self._build_worker(ports=[8502])
    worker.state["open_ports"] = [8502]
    worker.target = "10.0.0.1"

    # 0xFF followed by 0x01 — not a valid IAC command byte (WILL=0xFB, WONT=0xFC, DO=0xFD, DONT=0xFE)
    fake_binary = b'\xff\x01\x03\x00\x00\x05\x01\x2b'

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = fake_binary
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
      worker._fingerprint_ports()

    self.assertNotEqual(worker.state["port_protocols"][8502], "telnet")

  def test_fingerprint_telnet_login_prompt(self):
    """A text banner containing 'login:' should still be fingerprinted as telnet."""
    owner, worker = self._build_worker(ports=[2323])
    worker.state["open_ports"] = [2323]
    worker.target = "10.0.0.1"

    login_banner = b'Ubuntu 22.04 LTS\r\nlogin: '

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = login_banner
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
      worker._fingerprint_ports()

    self.assertEqual(worker.state["port_protocols"][2323], "telnet")

  def test_fingerprint_modbus_wrong_function_code(self):
    """Response with protocol ID 0x0000 but wrong function code must NOT be classified as modbus."""
    owner, worker = self._build_worker(ports=[1024])
    worker.state["open_ports"] = [1024]
    worker.target = "10.0.0.1"

    # Protocol ID 0x0000 at bytes 2-3, but function code at byte 7 is 0x01 (not 0x2B)
    bad_modbus = b'\x00\x01\x00\x00\x00\x05\x01\x01\x00\x00\x00'

    call_index = [0]

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = b""
      idx = call_index[0]
      call_index[0] += 1
      if idx == 3:  # modbus probe is the 4th socket
        mock_sock.recv.return_value = bad_modbus
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
      worker._fingerprint_ports()

    self.assertNotEqual(worker.state["port_protocols"][1024], "modbus")

  def test_fingerprint_mysql_bad_payload_length(self):
    """MySQL-like bytes but absurd payload length prefix must NOT be classified as mysql."""
    owner, worker = self._build_worker(ports=[9999])
    worker.state["open_ports"] = [9999]
    worker.target = "10.0.0.1"

    # Payload length = 0x000001 (1 byte) — too small for a real MySQL handshake
    # seq=0x00, protocol=0x0a, then "5\x00" as a tiny version
    fake_pkt = b'\x01\x00\x00\x00\x0a5\x00'

    def fake_socket_factory(*args, **kwargs):
      mock_sock = MagicMock()
      mock_sock.recv.return_value = fake_pkt
      return mock_sock

    with patch("extensions.business.cybersec.red_mesh.redmesh_utils.socket.socket", side_effect=fake_socket_factory):
      worker._fingerprint_ports()

    self.assertNotEqual(worker.state["port_protocols"][9999], "mysql")

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
    """All-same-byte MySQL salt should trigger honeypot finding."""
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
    """200 on random path should trigger honeypot finding."""
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
         patch.object(worker, "_fingerprint_ports"), \
         patch.object(worker, "_gather_service_info"), \
         patch.object(worker, "_run_web_tests"), \
         patch.object(worker, "_post_scan_correlate"):
      worker.execute_job()

    self.assertTrue(worker.state["done"])
    self.assertIn("correlation_completed", worker.state["completed_tests"])


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
  runner.run(suite)
