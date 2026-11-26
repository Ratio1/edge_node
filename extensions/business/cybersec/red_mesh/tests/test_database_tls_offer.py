"""PostgreSQL and MySQL/MariaDB listeners that offer no TLS (RM-264)."""
import socket
import struct
import unittest
from unittest.mock import MagicMock, patch

from .conftest import DummyOwner, PentestLocalWorker

DB = "extensions.business.cybersec.red_mesh.worker.service.database"
SSL_REQUEST = struct.pack('!II', 8, 80877103)
GSSENC_REQUEST = struct.pack('!II', 8, 80877104)
TITLE_PG = "PostgreSQL does not offer TLS (cleartext connections)"


def _worker(port):
  worker = PentestLocalWorker(
    owner=DummyOwner(), target="example.com", job_id="job-tls",
    initiator="init@example", local_id_prefix="1", worker_target_ports=[port],
  )
  worker.stop_event = MagicMock()
  worker.stop_event.is_set.return_value = False
  return worker


def _no_tls_findings(result):
  return [f for f in result["findings"] if "does not offer TLS" in f["title"]]


class _PgSocket:
  """Answers the SSLRequest / GSSENCRequest with a scripted reply; a StartupMessage with SASL auth."""

  def __init__(self, ssl_reply, gss_reply, log):
    self.replies = {SSL_REQUEST: ssl_reply, GSSENC_REQUEST: gss_reply}
    self.log = log
    self.pending = b""

  def settimeout(self, timeout):
    return None

  def connect(self, addr):
    self.log.append("connect")

  def sendall(self, data):
    self.log.append(data)
    self.pending = self.replies.get(data, b'R' + struct.pack('!II', 8, 10))

  def recv(self, nbytes):
    reply, self.pending = self.pending, b""
    if isinstance(reply, Exception):
      raise reply
    return reply

  def close(self):
    return None


class TestPostgresTlsOffer(unittest.TestCase):

  def _probe(self, ssl_reply, gss_reply=b'N'):
    log = []
    with patch(f"{DB}.socket.socket", side_effect=lambda *a, **k: _PgSocket(ssl_reply, gss_reply, log)):
      result = _worker(5432)._service_info_postgresql("example.com", 5432)
    return result, log

  def test_n_is_one_medium_cwe319_finding(self):
    result, log = self._probe(b'N')
    self.assertEqual(result["tls_offered"], "N")
    self.assertEqual(result["gss_offered"], "N")
    [finding] = _no_tls_findings(result)
    self.assertEqual(finding["title"], TITLE_PG)
    self.assertEqual(finding["severity"], "MEDIUM")
    self.assertEqual(finding["cwe_id"], "CWE-319")
    self.assertEqual(finding["confidence"], "certain")
    # One extra connection: SSLRequest then GSSENCRequest on it, no credential.
    self.assertEqual(log.count("connect"), 2)
    self.assertEqual(log[-2:], [SSL_REQUEST, GSSENC_REQUEST])

  def test_n_with_gss_encryption_drops_to_low(self):
    result, _ = self._probe(b'N', gss_reply=b'G')
    self.assertEqual(result["gss_offered"], "G")
    [finding] = _no_tls_findings(result)
    self.assertEqual(finding["severity"], "LOW")
    self.assertIn("'G'", finding["evidence"])

  def test_s_gives_no_finding_and_no_gss_request(self):
    result, log = self._probe(b'S')
    self.assertEqual(result["tls_offered"], "S")
    self.assertNotIn("gss_offered", result)
    self.assertEqual(_no_tls_findings(result), [])
    self.assertNotIn(GSSENC_REQUEST, log)

  def test_empty_or_garbage_reply_records_nothing(self):
    for reply in (b'', b'X', b'E'):
      with self.subTest(reply=reply):
        result, _ = self._probe(reply)
        self.assertNotIn("tls_offered", result)
        self.assertNotIn("gss_offered", result)
        self.assertEqual(_no_tls_findings(result), [])

  def test_n_then_gss_timeout_keeps_the_medium_finding(self):
    result, _ = self._probe(b'N', gss_reply=socket.timeout("timed out"))
    self.assertEqual(result["tls_offered"], "N")
    self.assertNotIn("gss_offered", result)
    [finding] = _no_tls_findings(result)
    self.assertEqual(finding["severity"], "MEDIUM")

  def test_non_postgres_startup_reply_skips_the_check(self):
    log = []

    class _ServerFirst(_PgSocket):
      def sendall(self, data):
        self.log.append(data)
        self.pending = b'N' if data in (SSL_REQUEST, GSSENC_REQUEST) else b'NOTICE banner\r\n'

    with patch(f"{DB}.socket.socket", side_effect=lambda *a, **k: _ServerFirst(b'N', b'N', log)):
      result = _worker(5432)._service_info_postgresql("example.com", 5432)
    self.assertNotIn(SSL_REQUEST, log)
    self.assertEqual(_no_tls_findings(result), [])

  def test_connection_error_on_tls_check_raises_nothing(self):
    sockets = iter([_PgSocket(b'N', b'N', []), OSError("refused")])

    def factory(*a, **k):
      item = next(sockets)
      if isinstance(item, Exception):
        raise item
      return item

    with patch(f"{DB}.socket.socket", side_effect=factory):
      result = _worker(5432)._service_info_postgresql("example.com", 5432)
    self.assertNotIn("tls_offered", result)
    self.assertEqual(_no_tls_findings(result), [])


def _mysql_greeting(version: bytes, capabilities=None, filler=0, truncate_after=None, declared_len=None) -> bytes:
  after = b'\x01\x00\x00\x00' + b'abcdefgh' + bytes([filler])
  if capabilities is not None:
    after += struct.pack('<H', capabilities) + b'\x21\x02\x00' + b'\x00' * 30
  payload = bytes([0x0a]) + version + b'\x00' + after
  if truncate_after is not None:
    payload = payload[:truncate_after]
  length = len(payload) if declared_len is None else declared_len
  return length.to_bytes(3, 'little') + b'\x00' + payload


class _GreetingSocket:

  def __init__(self, greeting):
    self.greeting = greeting

  def settimeout(self, timeout):
    return None

  def connect(self, addr):
    return None

  def sendall(self, data):
    raise AssertionError("the MySQL TLS check must not send anything")

  def recv(self, nbytes):
    return self.greeting

  def close(self):
    return None


class TestMysqlTlsOffer(unittest.TestCase):

  def _probe(self, greeting):
    with patch(f"{DB}.socket.socket", return_value=_GreetingSocket(greeting)):
      return _worker(3306)._service_info_mysql("example.com", 3306)

  def test_client_ssl_clear_is_one_medium_finding(self):
    result = self._probe(_mysql_greeting(b"8.0.28", capabilities=0xf7ff))
    self.assertEqual(result["capabilities"], 0xf7ff)
    self.assertIs(result["tls_offered"], False)
    [finding] = _no_tls_findings(result)
    self.assertEqual(finding["title"], "MySQL does not offer TLS (cleartext connections)")
    self.assertEqual(finding["severity"], "MEDIUM")
    self.assertEqual(finding["cwe_id"], "CWE-319")

  def test_mariadb_greeting_names_mariadb(self):
    result = self._probe(_mysql_greeting(b"5.5.5-10.11.6-MariaDB", capabilities=0xf7fe))
    [finding] = _no_tls_findings(result)
    self.assertEqual(finding["title"], "MariaDB does not offer TLS (cleartext connections)")

  def test_low_entropy_greeting_gives_firm_not_certain(self):
    greeting = _mysql_greeting(b"8.0.28", capabilities=0xf7ff).replace(b'abcdefgh', b'\x00' * 8)
    result = self._probe(greeting)
    [finding] = _no_tls_findings(result)
    self.assertEqual(finding["confidence"], "firm")

  def test_client_ssl_set_gives_no_finding(self):
    result = self._probe(_mysql_greeting(b"5.5.5-10.11.6-MariaDB", capabilities=0xffff))
    self.assertIs(result["tls_offered"], True)
    self.assertEqual(_no_tls_findings(result), [])

  def test_truncated_or_malformed_greeting_records_nothing(self):
    full = len(b"8.0.28") + 2 + 13  # protocol byte, version, NUL, thread id, salt, filler
    cases = {
      "ends before flags": _mysql_greeting(b"8.0.28", capabilities=0, truncate_after=full),
      "one flag byte": _mysql_greeting(b"8.0.28", capabilities=0, truncate_after=full + 1),
      "non-zero filler": _mysql_greeting(b"8.0.28", capabilities=0, filler=0x41),
      "header declares fewer bytes": _mysql_greeting(b"8.0.28", capabilities=0, declared_len=full),
    }
    for name, greeting in cases.items():
      with self.subTest(name):
        result = self._probe(greeting)
        self.assertNotIn("capabilities", result)
        self.assertNotIn("tls_offered", result)
        self.assertEqual(_no_tls_findings(result), [])


if __name__ == "__main__":
  unittest.main()
