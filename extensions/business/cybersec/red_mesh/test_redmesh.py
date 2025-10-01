import sys
import unittest
from unittest.mock import MagicMock, patch

from extensions.business.cybersec.red_mesh.redmesh_utils import PentestLocalWorker


MANUAL_RUN = __name__ == "__main__"


class DummyOwner:
  def __init__(self):
    self.messages = []

  def P(self, message, **kwargs):
    self.messages.append(message)
    if MANUAL_RUN:
      print(f"[DummyOwner] {message}")


class RedMeshOWASPTests(unittest.TestCase):
  def setUp(self):
    if MANUAL_RUN:
      print(f"\n\n[MANUAL] >>> Starting {self._testMethodName}")

  def tearDown(self):
    if MANUAL_RUN:
      print(f"[MANUAL] <<< Finished {self._testMethodName}")

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
    self.assertIn("Accessible resource", result)

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
    self.assertIn("Secure flag", result)
    self.assertIn("HttpOnly", result)
    self.assertIn("SameSite", result)

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
    self.assertIn("SQL injection", result)

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
    self.assertIn("Path traversal", result)

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
    self.assertIn("Missing security header", result)

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
    self.assertIn("Anonymous login allowed", result)

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
    self.assertIn("Sensitive marker", result)

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
    self.assertIn("Reflected XSS", result)

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
    self.assertIn("Telnet banner", info)

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
    self.assertIn("SMB service responded", info)

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
    self.assertIn("VNC protocol banner", info)

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
    self.assertIn("CORS misconfiguration", result)

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
    self.assertIn("Open redirect", result)

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
    self.assertIn("Risky HTTP methods", result)


if __name__ == "__main__":
  unittest.main(verbosity=2)
