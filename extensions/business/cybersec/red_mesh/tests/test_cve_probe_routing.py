"""Probe routing: banner -> cve_db product key, and the CVE-2012-2122 gate (RM-168)."""
import struct
import unittest
from unittest.mock import MagicMock, patch

from .conftest import DummyOwner, PentestLocalWorker

DB = "extensions.business.cybersec.red_mesh.worker.service.database"
INFRA = "extensions.business.cybersec.red_mesh.worker.service.infrastructure"


def _worker(port):
  worker = PentestLocalWorker(
    owner=DummyOwner(), target="example.com", job_id="job-route",
    initiator="init@example", local_id_prefix="1", worker_target_ports=[port],
  )
  worker.stop_event = MagicMock()
  worker.stop_event.is_set.return_value = False
  worker.state["scan_metadata"] = {}
  return worker


def _mysql_greeting(version: bytes) -> bytes:
  payload = bytes([0x0a]) + version + b'\x00' + b'\x00' * 50
  return len(payload).to_bytes(3, 'little') + b'\x00' + payload


class _GreetingSocket:

  def __init__(self, version, forbid_send=False):
    self.version = version
    self.forbid_send = forbid_send
    self.connects = 0

  def settimeout(self, timeout):
    return None

  def connect(self, addr):
    self.connects += 1

  def recv(self, nbytes):
    return _mysql_greeting(self.version)

  def sendall(self, data):
    if self.forbid_send:
      raise AssertionError("active CVE-2012-2122 probe must not send authentication attempts")

  def close(self):
    return None


def _cve_ids(result):
  return {c for f in result.get("findings", []) for c in (f.get("cve") or [])}


class TestMysqlRouting(unittest.TestCase):

  def _probe(self, version):
    with patch(f"{DB}.socket.socket", return_value=_GreetingSocket(version)):
      return _worker(3306)._service_info_mysql("example.com", 3306)

  def test_mariadb_10_banner_gets_no_mysql_cves(self):
    result = self._probe(b"5.5.5-10.11.6-MariaDB")
    self.assertEqual(_cve_ids(result), set())
    self.assertNotIn("CVE-2016-6662", str(result))

  def test_mariadb_banner_routes_to_mariadb_key(self):
    with patch(f"{DB}.socket.socket", return_value=_GreetingSocket(b"5.5.5-10.11.6-MariaDB")), \
         patch(f"{DB}.check_cves", return_value=[]) as check:
      _worker(3306)._service_info_mysql("example.com", 3306)
    check.assert_called_once_with("mariadb", "10.11.6-MariaDB")

  def test_mariadb_without_fake_prefix_routes_to_mariadb_key(self):
    with patch(f"{DB}.socket.socket", return_value=_GreetingSocket(b"11.4.2-MariaDB")), \
         patch(f"{DB}.check_cves", return_value=[]) as check:
      _worker(3306)._service_info_mysql("example.com", 3306)
    self.assertEqual(check.call_args[0][0], "mariadb")

  def test_real_mysql_still_routes_to_mysql(self):
    with patch(f"{DB}.socket.socket", return_value=_GreetingSocket(b"5.7.14")), \
         patch(f"{DB}.check_cves", return_value=[]) as check:
      _worker(3306)._service_info_mysql("example.com", 3306)
    check.assert_called_once_with("mysql", "5.7.14")


class TestCve20122122Gate(unittest.TestCase):

  def _run(self, version, forbid_send):
    sock = _GreetingSocket(version, forbid_send=forbid_send)
    with patch(f"{DB}.socket.socket", return_value=sock):
      result = _worker(3306)._mysql_test_cve_2012_2122("example.com", 3306)
    return result, sock

  def test_mariadb_10_banner_does_not_start_auth_attempts(self):
    result, sock = self._run(b"5.5.5-10.11.6-MariaDB", forbid_send=True)
    self.assertIsNone(result)
    self.assertEqual(sock.connects, 1)  # version read only

  def test_gate_drops_mariadb_5x_below_5_5_23(self):
    # Known cost of the gate: a MariaDB 5.x server below 5.5.23 is affected by
    # CVE-2012-2122 but is no longer tested, because its banner is not MySQL.
    result, sock = self._run(b"5.5.22-MariaDB", forbid_send=True)
    self.assertIsNone(result)
    self.assertEqual(sock.connects, 1)

  def test_real_mysql_in_range_still_tested(self):
    _, sock = self._run(b"5.5.23", forbid_send=False)
    self.assertEqual(sock.connects, 2)  # version read, then the attempt loop


class TestDnsRouting(unittest.TestCase):

  def _probe(self, txt: bytes):
    worker = _worker(53)
    qname = b'\x07version\x04bind\x00'
    captured = {}

    def fake_sendto(data, addr):
      captured["tid"] = struct.unpack('>H', data[:2])[0]

    def fake_recvfrom(size):
      header = struct.pack('>HHHHHH', captured["tid"], 0x8400, 1, 1, 0, 0)
      answer = b'\xc0\x0c' + struct.pack('>HH', 16, 3) + struct.pack('>I', 0)
      answer += struct.pack('>H', len(txt) + 1) + bytes([len(txt)]) + txt
      return header + qname + struct.pack('>HH', 16, 3) + answer, ("1.2.3.4", 53)

    with patch(f"{INFRA}.socket.socket") as sock_cls:
      sock = MagicMock()
      sock.sendto = fake_sendto
      sock.recvfrom = fake_recvfrom
      sock_cls.return_value = sock
      with patch.object(worker, "_dns_test_axfr", return_value=[]), \
           patch.object(worker, "_dns_test_open_resolver", return_value=None), \
           patch(f"{INFRA}.check_cves", return_value=[]) as check:
        worker._service_info_dns("1.2.3.4", 53)
    return check

  def test_bind_answer_calls_bind_check(self):
    check = self._probe(b"9.10.3-P4-Debian")
    check.assert_called_once_with("bind", "9.10.3-P4")

  def test_bind_edition_is_kept(self):
    check = self._probe(b"9.18.24-S1")
    check.assert_called_once_with("bind", "9.18.24-S1")

  def test_dnsmasq_never_goes_to_bind(self):
    check = self._probe(b"dnsmasq-2.80")
    check.assert_called_once_with("dnsmasq", "2.80")

  def test_powerdns_never_goes_to_bind(self):
    check = self._probe(b"PowerDNS Authoritative Server 4.5.1")
    check.assert_called_once_with("powerdns", "4.5.1")

  def test_unbound_never_goes_to_bind(self):
    check = self._probe(b"unbound 1.13.1")
    check.assert_called_once_with("unbound", "1.13.1")

  def test_unknown_answer_calls_no_check(self):
    check = self._probe(b"Microsoft DNS 6.1.7601")
    check.assert_not_called()


if __name__ == "__main__":
  unittest.main()
